mod config;
mod database;
mod error;
mod matching;
mod models;
mod orderbook;
mod redis_store;
mod routes;
mod settlement;
mod balance_service;
mod oracle;
mod market_resolution_policy;
mod market_lifecycle;
mod proof_batcher;
mod websocket;
mod metrics;
mod chain_types;
mod epoch_service;
mod proof_generation;
mod monitoring;
mod error_recovery;
mod rate_limiter;
mod user_rate_limiter;
mod poseidon_bn254;
mod evm_relayer;
mod market_oracle_service;
mod pm_claim_worker;
mod pm_settlement_worker;
mod prediction_market_relayer;
mod prediction_market_claims;
mod prediction_market_settlement;

use anyhow::Result;
use axum::{
    routing::{get, post, delete},
    Router,
};
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::{
    cors::CorsLayer,
    trace::TraceLayer,
    compression::CompressionLayer,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::{
    config::Config,
    database::Database,
    matching::MatchingEngine,
    orderbook::OrderBookManager,
    redis_store::RedisStore,
    settlement::SettlementEngine,
    balance_service::BalanceService,
    oracle::PythOracle,
    market_lifecycle::MarketLifecycleManager,
    websocket::WebSocketManager,
    metrics::Metrics,
    pm_claim_worker::PredictionMarketClaimWorker,
    pm_settlement_worker::PredictionMarketSettlementWorker,
    epoch_service::EpochService,
    proof_generation::{OrderMatchProver, ProverPipeline},
    prediction_market_relayer::PredictionMarketRelayer,
};

fn main() -> Result<()> {
    eprintln!("[startup] CLOB service entrypoint reached (sync)");
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| {
            eprintln!("[startup] Failed to build Tokio runtime: {}", e);
            anyhow::anyhow!(e)
        })?;

    runtime.block_on(async_main())
}

async fn async_main() -> Result<()> {
    eprintln!("[startup] Tokio runtime initialized, entering async main");
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "clob_service=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer().json())
        .init();

    // Bind listener ASAP using raw env to satisfy Cloud Run startup probe even before full config loads
    let host = std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port: u16 = std::env::var("PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(8080);
    let addr = format!("{}:{}", host, port);
    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(listener) => {
            tracing::info!("Bound TCP listener on {} (startup)", addr);
            listener
        }
        Err(err) => {
            eprintln!("[startup] Failed to bind {}: {}", addr, err);
            return Err(err.into());
        }
    };

    // Wait for critical env (e.g. REDIS_URL) briefly to avoid immediate exit before logs appear
    async fn wait_for_env(key: &str, attempts: u32, delay_ms: u64) -> Option<String> {
        for i in 1..=attempts {
            match std::env::var(key) {
                Ok(v) if !v.trim().is_empty() => return Some(v),
                _ => {
                    if i == attempts { break; }
                    tracing::warn!(attempt=i, key, "Env var not present yet, retrying");
                    tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                }
            }
        }
        None
    }

    if std::env::var("REDIS_URL").is_err() { // only wait if missing
        if let Some(val) = wait_for_env("REDIS_URL", 10, 500).await {
            tracing::info!("Acquired REDIS_URL after wait");
            // set again explicitly (already set by var read) but keep semantics clear
            std::env::set_var("REDIS_URL", val);
        } else {
            tracing::error!("REDIS_URL missing after wait window; continuing (Redis will fail)");
        }
    }

    // Load configuration (may depend on secrets/env); failures here should be logged
    let config = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[startup] Config::from_env failed: {}", e);
            tracing::error!(error=%e, "Failed to load configuration; keeping listener open for diagnostics");
            return Err(e);
        }
    };
    tracing::info!(maker_fee_ppm=config.maker_fee_ppm, taker_fee_ppm=config.taker_fee_ppm, "Starting CLOB service");

    // Initialize Valkey/Redis client (GCP Memorystore standalone, no TLS, no auth)
    let redis_client = redis::Client::open(config.redis_url.clone())
        .map_err(|e| anyhow::anyhow!("Invalid REDIS_URL: {}", e))?;
    let redis_conn = {
        let mut attempt: u32 = 0;
        let max_attempts: u32 = 10;
        loop {
            attempt += 1;
            match redis::aio::ConnectionManager::new(redis_client.clone()).await {
                Ok(conn) => {
                    tracing::info!(attempt, "Connected to Valkey/Redis");
                    break conn;
                }
                Err(err) => {
                    let backoff_ms = (std::cmp::min(attempt, 5) * 1000) as u64; // 1s..5s
                    tracing::warn!(attempt, backoff_ms, error = %err, "Failed to connect to Valkey, retrying");
                    if attempt >= max_attempts {
                        tracing::error!(attempt, error = %err, "Exceeded max Valkey connection attempts, exiting");
                        return Err(err.into());
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                }
            }
        }
    };
    let redis_store = Arc::new(RedisStore::new(redis_conn));

    // Optional PostgreSQL initialization for production persistence.
    let database = if let Some(database_url) = config.database_url.clone() {
        match Database::connect(&database_url).await {
            Ok(db) => {
                if let Err(e) = db.migrate().await {
                    tracing::error!(error = %e, "Database migration failed");
                    return Err(anyhow::anyhow!(e.to_string()));
                }
                tracing::info!("PostgreSQL database initialized");
                Some(Arc::new(db))
            }
            Err(e) => {
                tracing::error!(error = %e, "Database connection failed");
                return Err(anyhow::anyhow!(e.to_string()));
            }
        }
    } else {
        tracing::warn!("DATABASE_URL not set; running without PostgreSQL persistence layer");
        None
    };

    // Initialize core components
    let metrics = Arc::new(Metrics::new());
    let balance_service = Arc::new(BalanceService::new());
    let orderbook_manager = Arc::new(OrderBookManager::new(redis_store.clone(), metrics.clone()));
    let prediction_market_relayer = match PredictionMarketRelayer::from_env(
        config.prediction_market_vault_address.clone(),
    ) {
        Some(relayer) => {
            tracing::info!(
                vault = %relayer.vault_address(),
                "Prediction market relayer enabled"
            );
            Some(Arc::new(relayer))
        }
        None => {
            tracing::warn!(
                "Prediction market relayer disabled (set PREDICTION_MARKET_VAULT_ADDRESS/PM_VAULT_ADDRESS, HORIZEN_RPC_URL, and EVM_OPERATOR_PRIVATE_KEY to enable)"
            );
            None
        }
    };
    let settlement_engine = Arc::new(SettlementEngine::new(
        redis_store.clone(),
        balance_service.clone(),
        prediction_market_relayer.clone(),
        config.maker_fee_ppm,
        config.taker_fee_ppm,
    ));
    let matching_engine = Arc::new(MatchingEngine::new(
        orderbook_manager.clone(),
        settlement_engine.clone(),
        metrics.clone(),
    ));
    let ws_manager = Arc::new(WebSocketManager::new());
    let prover_pipeline = Arc::new(ProverPipeline::new(redis_store.clone(), 3));

    // Initialize Pyth oracle and market lifecycle manager (BTC/ETH/SOL × USDC/ZEN)
    let oracle = Arc::new(PythOracle::new());
    let lifecycle_manager = Arc::new(MarketLifecycleManager::new(
        oracle.clone(),
        redis_store.clone(),
        balance_service.clone(),
    ));



    // Initialize IP-based rate limiter (token bucket, configurable via env).
    let rl_rpm: u32 = std::env::var("RATE_LIMIT_RPM")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(600);
    let rl_burst: u32 = std::env::var("RATE_LIMIT_BURST")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(50);
    let ip_rate_limiter = rate_limiter::RateLimiter::new(rl_rpm, rl_burst);
    tracing::info!(rpm = rl_rpm, burst = rl_burst, "IP rate limiter initialized");

    // Build application state
    let app_state = Arc::new(AppState {
        config: config.clone(),
        matching_engine,
        orderbook_manager: orderbook_manager.clone(),
        settlement_engine,
        balance_service: balance_service.clone(),
        ws_manager: ws_manager.clone(),
        metrics: metrics.clone(),
        database,
        redis_store: redis_store.clone(),
        prover_pipeline: prover_pipeline.clone(),
        prediction_market_relayer: prediction_market_relayer.clone(),
    });

    // Build router
    let app = Router::new()
        // Health check
        .route("/health", get(routes::health::health_check))
        .route("/ready", get(routes::health::readiness_check))
        
        // Balance endpoints (test/demo)
        .route("/v1/balance/deposit", post(routes::balance::deposit_balance))
        .route("/v1/balance/:user_id/:market_id", get(routes::balance::get_balance))

        // Wallet endpoints
        .route("/v1/wallet/register", post(routes::wallet::register_wallet))
        .route("/v1/wallet/deploy", post(routes::wallet::deploy_smart_account))
        .route("/v1/wallet/:user_id", get(routes::wallet::get_wallet_info))

        // Prediction market vault relay endpoints
        .route("/v1/pm/lock-collateral", post(routes::pm::lock_collateral))
        .route("/v1/pm/unlock-collateral", post(routes::pm::unlock_collateral))
        .route("/v1/pm/settle-fill", post(routes::pm::settle_fill))
        .route("/v1/pm/claim-winnings", post(routes::pm::claim_winnings))
        .route("/v1/pm/claims", post(routes::pm::submit_claim))
        .route("/v1/pm/claims/:job_id", get(routes::pm::get_claim_status))
        .route("/v1/pm/private-index/:user_id", get(routes::pm::get_private_index))
        .route("/v1/pm/deposit-note", post(routes::pm::deposit_note))
        
        // Order endpoints
        .route("/v1/orders", post(routes::orders::create_order))
        .route("/v1/orders/:order_id", delete(routes::orders::cancel_order))
        .route("/v1/orders/:order_id", get(routes::orders::get_order))
        .route("/v1/orders/user/:user_id", get(routes::orders::get_user_orders))
        
        // Order book endpoints
        // NOTE: /v1/orderbook/:market_id and /v1/orderbook/:market_id/depth are intentionally
        // NOT exposed publicly. Revealing per-level sizes would allow observers to infer
        // position concentration, violating the hidden-orderbook privacy guarantee.
        // The matching engine reads order state internally only.
        
        // Trades endpoints
        // NOTE: aggregate market trades (/v1/trades/:market_id, /v1/trades/:market_id/history)
        // are intentionally NOT exposed publicly — fill sizes/prices reveal position info.
        // Users may only query their own fills.
        .route("/v1/trades/user/:user_id", get(routes::trades::get_user_trades))
        
        // Markets endpoints
        .route("/v1/markets", get(routes::markets::list_markets))
        .route("/v1/markets/:market_id/stats", get(routes::markets::get_market_stats))
        .route(
            "/v1/markets/:market_id/resolution-audit",
            get(routes::markets::get_market_resolution_audit),
        )
        
        // WebSocket
        .route("/v1/ws", get(routes::websocket::ws_handler))
        
        // Metrics
        .route("/metrics", get(routes::metrics::metrics_handler))
        
        // Apply middleware (outermost → innermost in application order)
        // Rate limiter middleware reads RateLimiter from request extensions;
        // the Extension layer below injects it so the middleware can find it.
        .route_layer(axum::middleware::from_fn(rate_limiter::rate_limit_middleware))
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(CorsLayer::permissive())
                .layer(CompressionLayer::new())
                .layer(axum::Extension(ip_rate_limiter))
        )
        .with_state(app_state.clone());

    // Start WebSocket broadcast task
    let ws_task = tokio::spawn(websocket::broadcast_task(
        ws_manager,
        orderbook_manager.clone(),
    ));

    // Start metrics server
    let metrics_clone = metrics.clone();
    let metrics_task = tokio::spawn(metrics::serve_metrics(metrics_clone));

    // Start epoch service (if PROOF_GENERATION_ENABLED=true)
    let epoch_task = if std::env::var("PROOF_GENERATION_ENABLED").unwrap_or_default() == "true" {
        tracing::info!("Proof generation enabled, starting epoch service");
        
        let prover = Arc::new(OrderMatchProver::new(
            redis_store.clone(),
        ));
        
        let epoch_duration = std::env::var("EPOCH_DURATION_SECS")
            .unwrap_or_else(|_| "3600".to_string())
            .parse()
            .unwrap_or(3600);
        
        let mut epoch_service = EpochService::new(
            orderbook_manager.clone(),
            prover,
            redis_store.clone(),
            metrics.clone(),
            epoch_duration,
        ).with_prover_pipeline(prover_pipeline.clone());
        
        Some(tokio::spawn(async move {
            if let Err(e) = epoch_service.start().await {
                tracing::error!(error = %e, "Epoch service failed");
            }
        }))
    } else {
        tracing::info!("Proof generation disabled (set PROOF_GENERATION_ENABLED=true to enable)");
        None
    };

    let pm_settlement_task = prediction_market_relayer.clone().map(|relayer| {
        let worker = PredictionMarketSettlementWorker::new(
            redis_store.clone(),
            prover_pipeline.clone(),
            relayer,
            std::env::var("PM_SETTLEMENT_WORKER_POLL_SECS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(2),
        );
        tokio::spawn(async move {
            if let Err(e) = worker.start().await {
                tracing::error!(error = %e, "Prediction market settlement worker failed");
            }
        })
    });

    let pm_claim_task = prediction_market_relayer.clone().map(|relayer| {
        let worker = PredictionMarketClaimWorker::new(
            redis_store.clone(),
            prover_pipeline.clone(),
            relayer,
            std::env::var("PM_CLAIM_WORKER_POLL_SECS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(2),
        );
        tokio::spawn(async move {
            if let Err(e) = worker.start().await {
                tracing::error!(error = %e, "Prediction market claim worker failed");
            }
        })
    });

    let relayer_task: Option<tokio::task::JoinHandle<()>> = None;

    // Start market lifecycle manager (if MARKET_LIFECYCLE_ENABLED=true)
    let lifecycle_task = if std::env::var("MARKET_LIFECYCLE_ENABLED").unwrap_or_default() == "true" {
        tracing::info!("🤖 Market Lifecycle Manager enabled - automated hourly markets starting");
        Some(tokio::spawn(lifecycle_manager.start()))
    } else {
        tracing::info!("Market Lifecycle Manager disabled (set MARKET_LIFECYCLE_ENABLED=true to enable)");
        None
    };

    // Start market oracle service (if MARKET_ORACLE_ENABLED=true)
    let market_oracle_task: Option<tokio::task::JoinHandle<()>> =
        if std::env::var("MARKET_ORACLE_ENABLED").unwrap_or_default() == "true" {
            match market_oracle_service::MarketOracleService::from_env(redis_store.clone()) {
                Some(svc) => {
                    tracing::info!(
                        "Market oracle service enabled — hourly BTC markets will be created on Horizen EVM"
                    );
                    Some(tokio::spawn(async move {
                        if let Err(e) = svc.start().await {
                            tracing::error!(error = %e, "Market oracle service failed");
                        }
                    }))
                }
                None => {
                    tracing::warn!(
                        "Market oracle service enabled but MARKET_FACTORY_ADDRESS / EVM vars missing (set HORIZEN_RPC_URL, EVM_OPERATOR_PRIVATE_KEY)"
                    );
                    None
                }
            }
        } else {
            tracing::info!(
                "Market oracle service disabled (set MARKET_ORACLE_ENABLED=true to enable)"
            );
            None
        };

    // Bind and serve
    tracing::info!("CLOB service listening on {}", addr);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    // Wait for background tasks
    ws_task.abort();
    metrics_task.abort();
    if let Some(task) = epoch_task {
        task.abort();
    }
    if let Some(task) = pm_settlement_task {
        task.abort();
    }
    if let Some(task) = pm_claim_task {
        task.abort();
    }
    if let Some(task) = relayer_task {
        task.abort();
    }
    if let Some(task) = lifecycle_task {
        task.abort();
    }
    if let Some(task) = market_oracle_task {
        task.abort();
    }

    Ok(())
}

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub matching_engine: Arc<MatchingEngine>,
    pub orderbook_manager: Arc<OrderBookManager>,
    pub settlement_engine: Arc<SettlementEngine>,
    pub balance_service: Arc<BalanceService>,
    pub ws_manager: Arc<WebSocketManager>,
    pub metrics: Arc<Metrics>,
    pub database: Option<Arc<Database>>,
    pub redis_store: Arc<RedisStore>,
    pub prover_pipeline: Arc<ProverPipeline>,
    pub prediction_market_relayer: Option<Arc<PredictionMarketRelayer>>,
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("Received Ctrl+C, starting graceful shutdown");
        },
        _ = terminate => {
            tracing::info!("Received SIGTERM, starting graceful shutdown");
        },
    }
}
