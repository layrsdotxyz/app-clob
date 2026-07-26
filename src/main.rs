mod auth;
mod balance_service;
mod chain_types;
mod circuit_breaker;
mod config;
mod database;
mod eip712;
mod epoch_service;
mod error;
mod error_recovery;
mod evm_relayer;
mod market_lifecycle;
mod market_oracle_service;
mod market_resolution_policy;
mod matching;
mod metrics;
mod models;
mod monitoring;
mod oracle;
mod orderbook;
mod pm_claim_worker;
mod pm_settlement_worker;
mod poseidon2;
mod poseidon_bn254;
mod prediction_market_claims;
mod prediction_market_relayer;
mod prediction_market_settlement;
mod privacy;
mod private_core;
mod proof_batcher;
mod proof_generation;
mod proof_observability;
mod rate_limiter;
mod redis_store;
mod routes;
mod settlement;
mod state;
mod user_rate_limiter;
mod websocket;
mod withdrawal_service;

use crate::state::AppState;

use anyhow::Result;
use axum::{
    routing::{delete, get, post},
    Router,
};
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::{compression::CompressionLayer, cors::CorsLayer, trace::TraceLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::{
    balance_service::BalanceService,
    config::Config,
    database::Database,
    epoch_service::EpochService,
    market_lifecycle::MarketLifecycleManager,
    matching::MatchingEngine,
    metrics::Metrics,
    oracle::PythOracle,
    orderbook::OrderBookManager,
    pm_claim_worker::PredictionMarketClaimWorker,
    pm_settlement_worker::PredictionMarketSettlementWorker,
    prediction_market_relayer::PredictionMarketRelayer,
    privacy::PrivacyStateService,
    proof_generation::{OrderMatchProver, ProverPipeline, ProverWorker},
    redis_store::RedisStore,
    settlement::SettlementEngine,
    websocket::WebSocketManager,
    withdrawal_service::WithdrawalService,
};

fn enforce_real_private_prover_configuration() -> Result<()> {
    let configured_mode = std::env::var("PRIVATE_PROVER_MODE")
        .unwrap_or_else(|_| "barretenberg".to_string())
        .trim()
        .to_lowercase();

    match configured_mode.as_str() {
        "barretenberg" | "honk" => {}
        "mock" => {
            anyhow::bail!(
                "PRIVATE_PROVER_MODE=mock is forbidden for clob-service startup; use the real Barretenberg/UltraHonk prover"
            );
        }
        other => {
            anyhow::bail!(
                "PRIVATE_PROVER_MODE='{}' is unsupported for clob-service startup; expected 'barretenberg' or 'honk'",
                other
            );
        }
    }

    let allow_mock = std::env::var("ALLOW_INSECURE_MOCK_PROVER")
        .map(|value| value.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if allow_mock {
        anyhow::bail!("ALLOW_INSECURE_MOCK_PROVER=true is forbidden for clob-service startup");
    }

    Ok(())
}

fn main() -> Result<()> {
    eprintln!("[startup] CLOB service entrypoint reached (sync)");
    enforce_real_private_prover_configuration()?;
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
                .unwrap_or_else(|_| "clob_service=info,tower_http=warn".into()),
        )
        .with(tracing_subscriber::fmt::layer().json())
        .init();

    // Bind listener ASAP so the ECS health check probe succeeds even before full config loads
    let host = std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);
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
                    if i == attempts {
                        break;
                    }
                    tracing::warn!(attempt = i, key, "Env var not present yet, retrying");
                    tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                }
            }
        }
        None
    }

    if std::env::var("REDIS_URL").is_err() {
        // only wait if missing
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
    tracing::info!(
        maker_fee_bps = config.maker_fee_bps,
        taker_fee_bps = config.taker_fee_bps,
        "Starting CLOB service"
    );

    // Initialize Valkey/Redis client (AWS ElastiCache standalone, no TLS, no auth)
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

    let allow_in_memory_only = std::env::var("ALLOW_IN_MEMORY_ONLY_CLOB")
        .unwrap_or_else(|_| "false".to_string())
        .eq_ignore_ascii_case("true");

    // PostgreSQL initialization for production persistence. Local/dev bypass is
    // explicit so CLOB cannot silently run Redis-only in normal environments.
    let database = if let Some(database_url) = config.database_url.clone() {
        match Database::connect(&database_url).await {
            Ok(db) => {
                if let Err(e) = db.migrate().await {
                    if allow_in_memory_only {
                        tracing::warn!(error = %e, "Database migration failed; ALLOW_IN_MEMORY_ONLY_CLOB=true so running without PostgreSQL persistence layer");
                        None
                    } else {
                        return Err(anyhow::anyhow!(
                            "Database migration failed and CLOB durability is required: {}",
                            e
                        ));
                    }
                } else {
                    tracing::info!("PostgreSQL database initialized");
                    Some(Arc::new(db))
                }
            }
            Err(e) => {
                if allow_in_memory_only {
                    tracing::warn!(error = %e, "Database connection failed; ALLOW_IN_MEMORY_ONLY_CLOB=true so running without PostgreSQL persistence layer");
                    None
                } else {
                    return Err(anyhow::anyhow!(
                        "Database connection failed and CLOB durability is required: {}",
                        e
                    ));
                }
            }
        }
    } else if allow_in_memory_only {
        tracing::warn!("DATABASE_URL not set; ALLOW_IN_MEMORY_ONLY_CLOB=true so running without PostgreSQL persistence layer");
        None
    } else {
        return Err(anyhow::anyhow!(
            "DATABASE_URL must be set for clob-service durability; set ALLOW_IN_MEMORY_ONLY_CLOB=true only for local/dev bypass"
        ));
    };

    // Initialize core components
    let metrics = Arc::new(Metrics::new());
    let balance_service = Arc::new(BalanceService::new(database.clone()));
    // Load persisted balances from DB into the in-memory service (best-effort on startup).
    balance_service.load_from_db().await;
    // Spawn the DB persistence worker so balance writes are durably flushed with retries.
    let persist_task = balance_service.start_persistence_worker();
    let orderbook_manager = Arc::new(OrderBookManager::new(
        redis_store.clone(),
        metrics.clone(),
        database.clone(),
    ));

    // Seed active markets on startup so /v1/markets always returns them regardless of order activity.
    // Override via SEED_MARKETS env var (comma-separated list of market IDs).
    let seed_market_ids: Vec<String> = std::env::var("SEED_MARKETS")
        .unwrap_or_else(|_| "BTC-USDC,ETH-USDC,SOL-USDC".to_string())
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    for mid in &seed_market_ids {
        orderbook_manager.seed_market(mid);
    }
    let db_market_seed_task = database.clone().map(|db| {
        let orderbook_manager = orderbook_manager.clone();
        tokio::spawn(async move {
            match db.list_active_prediction_market_metadata().await {
                Ok(markets) => {
                    let seeded = markets.len();
                    for market in markets {
                        orderbook_manager.seed_market(&market.market_id);
                    }
                    tracing::info!(count = seeded, "Seeded DB-backed prediction markets in background");
                }
                Err(error) => {
                    tracing::warn!(error = %error, "Failed to seed DB-backed prediction markets in background");
                }
            }
        })
    });

    let prediction_market_relayer = match PredictionMarketRelayer::from_env(
        config.pm_usdc_treasury_address.clone(),
    ) {
        Some(relayer) => {
            tracing::info!(
                treasury = %relayer.treasury_address(),
                "Prediction market relayer enabled"
            );
            Some(Arc::new(relayer))
        }
        None => {
            tracing::warn!(
                "Prediction market relayer disabled (set PM_USDC_TREASURY_ADDRESS or PREDICTION_MARKET_TREASURY_ADDRESS, plus HORIZEN_RPC_URL and EVM_OPERATOR_PRIVATE_KEY, to enable; vault aliases still work)"
            );
            None
        }
    };
    let ws_manager = Arc::new(WebSocketManager::new());
    let settlement_engine = Arc::new(SettlementEngine::new(
        redis_store.clone(),
        database.clone(),
        config.maker_fee_bps,
        config.taker_fee_bps,
        balance_service.clone(),
        ws_manager.clone(),
    ));
    let trade_persist_task = settlement_engine.clone().start_trade_persistence_worker();
    let prover_pipeline = Arc::new(ProverPipeline::new(redis_store.clone(), 3));
    let privacy_state = Arc::new(PrivacyStateService::new(redis_store.clone()));
    let matching_engine = Arc::new(
        MatchingEngine::new(
            orderbook_manager.clone(),
            settlement_engine.clone(),
            metrics.clone(),
        )
        .with_privacy_state(privacy_state.clone()),
    );

    // Initialize Pyth oracle and market lifecycle manager (BTC/ETH/SOL × USDC/ZEN)
    let oracle = Arc::new(PythOracle::new());
    let lifecycle_manager = Arc::new(MarketLifecycleManager::new(
        oracle.clone(),
        redis_store.clone(),
        balance_service.clone(),
        database.clone(),
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
    tracing::info!(
        rpm = rl_rpm,
        burst = rl_burst,
        "IP rate limiter initialized"
    );

    // Withdrawal service: delegates ZK proof + on-chain execution to vault-service.
    // Optional — gracefully disabled when VAULT_INTERNAL_URL is not set.
    let withdrawal_service = match std::env::var("VAULT_INTERNAL_URL") {
        Ok(vault_url) if !vault_url.trim().is_empty() => {
            let key = std::env::var("INTERNAL_SERVICE_KEY").unwrap_or_default();
            if key.is_empty() {
                tracing::warn!("VAULT_INTERNAL_URL set but INTERNAL_SERVICE_KEY is missing — withdrawal service disabled");
                None
            } else {
                tracing::info!(vault_url = %vault_url, "Withdrawal service enabled (vault-service delegation)");
                Some(Arc::new(WithdrawalService::new(
                    redis_store.clone(),
                    balance_service.clone(),
                    vault_url,
                    key,
                )))
            }
        }
        _ => {
            tracing::warn!("VAULT_INTERNAL_URL not set — withdrawal service disabled");
            None
        }
    };

    // Build application state
    let app_state = Arc::new(AppState {
        config: config.clone(),
        matching_engine,
        orderbook_manager: orderbook_manager.clone(),
        settlement_engine,
        balance_service: balance_service.clone(),
        ws_manager: ws_manager.clone(),
        metrics: metrics.clone(),
        database: database.clone(),
        redis_store: redis_store.clone(),
        prover_pipeline: prover_pipeline.clone(),
        privacy_state: privacy_state.clone(),
        prediction_market_relayer: prediction_market_relayer.clone(),
        withdrawal_service,
    });

    // Build router
    let app = Router::new()
        // Health check (always public)
        .route("/health", get(routes::health::health_check))
        .route("/ready", get(routes::health::readiness_check))
        // Markets endpoints (public)
        .route("/v1/markets", get(routes::markets::list_markets))
        .route(
            "/v1/markets/history",
            get(routes::markets::list_market_history),
        )
        .route(
            "/v1/markets/by-slug/:slug",
            get(routes::markets::get_market_by_slug),
        )
        .route(
            "/v1/markets/:market_id/stats",
            get(routes::markets::get_market_stats),
        )
        .route(
            "/v1/markets/:market_id/resolution-audit",
            get(routes::markets::get_market_resolution_audit),
        )
        // G10: Permissionless claim endpoint — proof is the authorisation, no JWT needed.
        .route("/v1/claims", post(routes::claims::submit_public_claim))
        // G13: Public orderbook — aggregated price levels only, no user or address data.
        .route(
            "/v1/orderbook/:market_id",
            get(routes::orderbook::get_orderbook),
        )
        .route(
            "/v1/orderbook/:market_id/depth",
            get(routes::orderbook::get_depth),
        )
        // G15: Public scan endpoint — no auth required; recipients scan locally.
        .route(
            "/v1/stealth/announcements",
            get(routes::stealth::list_announcements),
        )
        // WebSocket (auth is optional — public channels get anonymous trade ticks,
        // private user channel requires wallet address via ?address= query param)
        .route("/v1/ws", get(routes::websocket::ws_handler))
        // Metrics
        .route("/metrics", get(routes::metrics::metrics_handler))
        // ----------------------------------------------------------------
        // Protected routes — require valid Dynamic.xyz JWT
        // ----------------------------------------------------------------
        .merge(
            Router::new()
                // Wallet endpoints
                .route("/v1/wallet/register", post(routes::wallet::register_wallet))
                .route(
                    "/v1/wallet/deploy",
                    post(routes::wallet::deploy_smart_account),
                )
                .route("/v1/wallet/:user_id", get(routes::wallet::get_wallet_info))
                // Prediction market treasury relay endpoints
                .route("/v1/pm/lock-collateral", post(routes::pm::lock_collateral))
                .route(
                    "/v1/pm/unlock-collateral",
                    post(routes::pm::unlock_collateral),
                )
                .route("/v1/pm/settle-fill", post(routes::pm::settle_fill))
                .route("/v1/pm/claim-winnings", post(routes::pm::claim_winnings))
                .route("/v1/pm/claims", post(routes::pm::submit_claim))
                .route("/v1/pm/claims/:job_id", get(routes::pm::get_claim_status))
                .route(
                    "/v1/pm/private-index/:user_id",
                    get(routes::pm::get_private_index),
                )
                .route("/v1/pm/deposit-note", post(routes::pm::deposit_note))
                // Order endpoints
                .route("/v1/orders", post(routes::orders::create_order))
                .route("/v1/orders/commit", post(routes::orders::commit_order))
                .route("/v1/orders/reveal", post(routes::orders::reveal_order))
                .route("/v1/orders/:order_id", delete(routes::orders::cancel_order))
                .route("/v1/orders/:order_id", get(routes::orders::get_order))
                .route(
                    "/v1/orders/user/:user_id",
                    get(routes::orders::get_user_orders),
                )
                // Trades endpoints (user-scoped only — aggregate market trades are intentionally hidden)
                .route(
                    "/v1/trades/user/:user_id",
                    get(routes::trades::get_user_trades),
                )
                // Balance endpoints: deposit is operator-only (X-Operator-Key), get is self-scoped
                .route(
                    "/v1/balance/deposit",
                    post(routes::balance::deposit_balance),
                )
                .route(
                    "/v1/balance/proof",
                    post(routes::balance::submit_balance_proof),
                )
                .route(
                    "/v1/balance/:user_id",
                    get(routes::balance::get_user_balance),
                )
                .route(
                    "/v1/balance/:user_id/:market_id",
                    get(routes::balance::get_balance),
                )
                // Settlement endpoints
                .route(
                    "/v1/settlements/:job_id",
                    get(routes::settlements::get_settlement_job),
                )
                .route(
                    "/v1/settlements/:job_id/legs/:leg_role/witness",
                    post(routes::settlements::submit_leg_witness),
                )
                // G15: Auth-gated announce — operator or authenticated payer writes a
                // stealth announcement; the ephemeral key is stored with no recipient data.
                .route(
                    "/v1/stealth/announce",
                    post(routes::stealth::create_announcement),
                )
                // Withdrawal: ledger-side orchestration; proof and on-chain execution delegated to vault-service.
                .route(
                    "/v1/withdrawal",
                    post(routes::withdrawal::initiate_withdrawal),
                )
                .route(
                    "/v1/withdrawal/:withdrawal_id/status",
                    get(routes::withdrawal::get_withdrawal_status),
                )
                // Proof observability: inspect individual proof attempts and list by user.
                .route(
                    "/v1/proofs/:proof_id",
                    get(routes::proofs::get_proof_attempt),
                )
                .route(
                    "/v1/proofs/user/:user_id",
                    get(routes::proofs::list_user_proof_attempts),
                )
                .route_layer(axum::middleware::from_fn(auth::require_auth)),
        )
        // Admin endpoints — Bearer INTERNAL_SERVICE_KEY auth, no JWT
        .route(
            "/v1/admin/markets/:market_id/orderbook",
            delete(routes::orders::flush_market_orderbook),
        )
        // Apply middleware (outermost → innermost in application order)
        // Rate limiter middleware reads RateLimiter from request extensions;
        // the Extension layer below injects it so the middleware can find it.
        .route_layer(axum::middleware::from_fn(
            rate_limiter::rate_limit_middleware,
        ))
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(CorsLayer::permissive())
                .layer(CompressionLayer::new())
                .layer(axum::Extension(ip_rate_limiter)),
        )
        .with_state(app_state.clone());

    // Start WebSocket broadcast task
    let ws_task = tokio::spawn(websocket::broadcast_task(
        ws_manager.clone(),
        orderbook_manager.clone(),
    ));

    // Start metrics server
    let metrics_clone = metrics.clone();
    let metrics_task = tokio::spawn(metrics::serve_metrics(metrics_clone));

    // Start epoch service (if PROOF_GENERATION_ENABLED=true)
    let epoch_task = if std::env::var("PROOF_GENERATION_ENABLED").unwrap_or_default() == "true" {
        tracing::warn!(
            reason = %crate::proof_generation::ORDER_MATCH_UNSUPPORTED_MESSAGE,
            "Proof generation enabled, but the deprecated ORDER_MATCH prover is unavailable in this build"
        );

        let prover = Arc::new(OrderMatchProver::new(redis_store.clone()));

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
        )
        .with_prover_pipeline(prover_pipeline.clone());

        Some(tokio::spawn(async move {
            if let Err(e) = epoch_service.start().await {
                tracing::error!(error = %e, "Epoch service failed");
            }
        }))
    } else {
        tracing::info!("Proof generation disabled (set PROOF_GENERATION_ENABLED=true to enable)");
        None
    };

    // Start ProverWorker — consumes pm_deposit/settlement/claim jobs from the Redis prover queue.
    // Required for pm_settlement_worker and pm_claim_worker to generate on-chain proofs.
    let prover_worker_task = {
        let pp = prover_pipeline.clone();
        let ps = privacy_state.clone();
        let pw_metrics = metrics.clone();
        let poll_secs = std::env::var("PROVER_WORKER_POLL_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(1);
        tokio::spawn(async move {
            let mut backoff = 1u64;
            loop {
                let worker = ProverWorker::new(pp.clone(), ps.clone(), poll_secs)
                    .with_metrics(pw_metrics.clone());
                match worker.start().await {
                    Ok(()) => {
                        tracing::warn!(backoff, "ProverWorker exited cleanly, restarting");
                    }
                    Err(e) => {
                        tracing::error!(error = %e, backoff, "ProverWorker failed, restarting");
                    }
                }
                tokio::time::sleep(tokio::time::Duration::from_secs(backoff)).await;
                backoff = (backoff * 2).min(60);
            }
        })
    };

    let pm_settlement_task = prediction_market_relayer.clone().map(|relayer| {
        let rs = redis_store.clone();
        let pp = prover_pipeline.clone();
        let ws = ws_manager.clone();
        let poll_secs = std::env::var("PM_SETTLEMENT_WORKER_POLL_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(2);
        tokio::spawn(async move {
            let mut backoff = 1u64;
            loop {
                let worker = PredictionMarketSettlementWorker::new(
                    rs.clone(),
                    pp.clone(),
                    relayer.clone(),
                    ws.clone(),
                    poll_secs,
                );
                match worker.start().await {
                    Ok(()) => {
                        tracing::warn!(backoff, "PM settlement worker exited cleanly, restarting");
                    }
                    Err(e) => {
                        tracing::error!(error = %e, backoff, "PM settlement worker failed, restarting");
                    }
                }
                tokio::time::sleep(tokio::time::Duration::from_secs(backoff)).await;
                backoff = (backoff * 2).min(60);
            }
        })
    });

    let pm_claim_task = prediction_market_relayer.clone().map(|relayer| {
        let rs = redis_store.clone();
        let pp = prover_pipeline.clone();
        let poll_secs = std::env::var("PM_CLAIM_WORKER_POLL_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(2);
        tokio::spawn(async move {
            let mut backoff = 1u64;
            loop {
                let worker = PredictionMarketClaimWorker::new(
                    rs.clone(),
                    pp.clone(),
                    relayer.clone(),
                    poll_secs,
                );
                match worker.start().await {
                    Ok(()) => {
                        tracing::warn!(backoff, "PM claim worker exited cleanly, restarting");
                    }
                    Err(e) => {
                        tracing::error!(error = %e, backoff, "PM claim worker failed, restarting");
                    }
                }
                tokio::time::sleep(tokio::time::Duration::from_secs(backoff)).await;
                backoff = (backoff * 2).min(60);
            }
        })
    });

    let relayer_task: Option<tokio::task::JoinHandle<()>> = None;

    // Start market lifecycle manager (if MARKET_LIFECYCLE_ENABLED=true)
    let lifecycle_task = if std::env::var("MARKET_LIFECYCLE_ENABLED").unwrap_or_default() == "true"
    {
        tracing::info!("🤖 Market Lifecycle Manager enabled - automated hourly markets starting");
        Some(tokio::spawn(lifecycle_manager.start()))
    } else {
        tracing::info!(
            "Market Lifecycle Manager disabled (set MARKET_LIFECYCLE_ENABLED=true to enable)"
        );
        None
    };

    // Start market oracle service (if MARKET_ORACLE_ENABLED=true)
    let market_oracle_task: Option<tokio::task::JoinHandle<()>> = if std::env::var(
        "MARKET_ORACLE_ENABLED",
    )
    .unwrap_or_default()
        == "true"
    {
        match market_oracle_service::MarketOracleService::from_env(
            redis_store.clone(),
            database.clone(),
            orderbook_manager.clone(),
            balance_service.clone(),
        ) {
            Some(svc) => {
                tracing::info!(
                        "Market oracle service enabled — 15-min BTC/ETH/SOL markets will be created on Horizen EVM"
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
        tracing::info!("Market oracle service disabled (set MARKET_ORACLE_ENABLED=true to enable)");
        None
    };

    // Bind and serve
    tracing::info!("CLOB service listening on {}", addr);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    // Abort background tasks on shutdown.
    ws_task.abort();
    metrics_task.abort();
    prover_worker_task.abort();
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
    if let Some(task) = db_market_seed_task {
        task.abort();
    }
    if let Some(task) = trade_persist_task {
        task.abort();
    }
    // Close the persistence channel sender so the worker sees EOF and exits after
    // draining all queued writes. Without this, the sender stays alive inside
    // Arc<BalanceService> and the worker blocks on recv() until the timeout fires,
    // meaning queued balance changes (e.g. deposits) are never written to PostgreSQL.
    balance_service.close_persistence_channel();
    if let Some(task) = persist_task {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(10), task).await;
    }

    Ok(())
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
