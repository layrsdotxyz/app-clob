mod config;
mod error;
mod matching;
mod models;
mod orderbook;
mod redis_store;
mod routes;
mod settlement;
mod websocket;
mod metrics;
mod chain_types;
mod eip712;
mod settlement_client;

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
    matching::MatchingEngine,
    orderbook::OrderBookManager,
    redis_store::RedisStore,
    settlement::SettlementEngine,
    websocket::WebSocketManager,
    metrics::Metrics,
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
    tracing::info!(maker_fee_bps=config.maker_fee_bps, taker_fee_bps=config.taker_fee_bps, "Starting CLOB service");

    // Initialize Redis connection with retries so the container doesn't exit immediately on transient failures
    let redis_client = redis::Client::open(config.redis_url.clone())?;
    let redis_conn = {
        let mut attempt: u32 = 0;
        let max_attempts: u32 = 10;
        loop {
            attempt += 1;
            match redis::aio::ConnectionManager::new(redis_client.clone()).await {
                Ok(conn) => {
                    tracing::info!(attempt, "Connected to Redis");
                    break conn;
                }
                Err(err) => {
                    let backoff_ms = (std::cmp::min(attempt, 5) * 1000) as u64; // 1s..5s
                    tracing::warn!(attempt, backoff_ms, error = %err, "Failed to connect to Redis, retrying");
                    if attempt >= max_attempts {
                        tracing::error!(attempt, error = %err, "Exceeded max Redis connection attempts, exiting");
                        return Err(err.into());
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                }
            }
        }
    };
    let redis_store = Arc::new(RedisStore::new(redis_conn));

    // Initialize core components
    let metrics = Arc::new(Metrics::new());
    let orderbook_manager = Arc::new(OrderBookManager::new(redis_store.clone(), metrics.clone()));
    let settlement_engine = Arc::new(SettlementEngine::new(
        redis_store.clone(),
        config.maker_fee_bps,
        config.taker_fee_bps,
    ));
    let matching_engine = Arc::new(MatchingEngine::new(
        orderbook_manager.clone(),
        settlement_engine.clone(),
        metrics.clone(),
    ));
    let ws_manager = Arc::new(WebSocketManager::new());

    // Build application state
    let app_state = Arc::new(AppState {
        config: config.clone(),
        matching_engine,
        orderbook_manager: orderbook_manager.clone(),
        settlement_engine,
        ws_manager: ws_manager.clone(),
        metrics: metrics.clone(),
    });

    // Build router
    let app = Router::new()
        // Health check
        .route("/health", get(routes::health::health_check))
        .route("/ready", get(routes::health::readiness_check))
        
        // Order endpoints
        .route("/v1/orders", post(routes::orders::create_order))
        .route("/v1/orders/:order_id", delete(routes::orders::cancel_order))
        .route("/v1/orders/:order_id", get(routes::orders::get_order))
        .route("/v1/orders/user/:user_id", get(routes::orders::get_user_orders))
        
        // Order book endpoints
        .route("/v1/orderbook/:market_id", get(routes::orderbook::get_orderbook))
        .route("/v1/orderbook/:market_id/depth", get(routes::orderbook::get_depth))
        
        // Trades endpoints
        .route("/v1/trades/:market_id", get(routes::trades::get_recent_trades))
        .route("/v1/trades/:market_id/history", get(routes::trades::get_trade_history))
        .route("/v1/trades/user/:user_id", get(routes::trades::get_user_trades))
        
        // Markets endpoints
        .route("/v1/markets", get(routes::markets::list_markets))
        .route("/v1/markets/:market_id/stats", get(routes::markets::get_market_stats))
        
        // WebSocket
        .route("/v1/ws", get(routes::websocket::ws_handler))
        
        // Metrics
        .route("/metrics", get(routes::metrics::metrics_handler))
        
        // Apply middleware
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(CorsLayer::permissive())
                .layer(CompressionLayer::new())
        )
        .with_state(app_state.clone());

    // Start WebSocket broadcast task
    let ws_task = tokio::spawn(websocket::broadcast_task(
        ws_manager,
        orderbook_manager.clone(),
    ));

    // Start metrics server
    let metrics_task = tokio::spawn(metrics::serve_metrics(metrics));

    // Bind and serve
    tracing::info!("CLOB service listening on {}", addr);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    // Wait for background tasks
    ws_task.abort();
    metrics_task.abort();

    Ok(())
}

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub matching_engine: Arc<MatchingEngine>,
    pub orderbook_manager: Arc<OrderBookManager>,
    pub settlement_engine: Arc<SettlementEngine>,
    pub ws_manager: Arc<WebSocketManager>,
    pub metrics: Arc<Metrics>,
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
