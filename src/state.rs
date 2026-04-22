use std::sync::Arc;

use crate::{
    balance_service::BalanceService,
    config::Config,
    database::Database,
    matching::MatchingEngine,
    metrics::Metrics,
    orderbook::OrderBookManager,
    prediction_market_relayer::PredictionMarketRelayer,
    privacy::PrivacyStateService,
    proof_generation::ProverPipeline,
    redis_store::RedisStore,
    settlement::SettlementEngine,
    websocket::WebSocketManager,
};

/// Shared application state threaded through every Axum handler via `State<Arc<AppState>>`.
///
/// Moved to a dedicated module so the library crate (`src/lib.rs`) can re-export it,
/// enabling Router::oneshot integration tests in `tests/`.
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
    pub privacy_state: Arc<PrivacyStateService>,
    pub prediction_market_relayer: Option<Arc<PredictionMarketRelayer>>,
}

#[cfg(any(test, feature = "test-helpers"))]
/// Lazily-initialised shared `Metrics` instance for test environments.
///
/// Prometheus's default registry panics (`AlreadyReg`) if the same metric name
/// is registered twice in the same process. Using a `OnceLock` ensures every
/// `AppState::for_test` call reuses the single already-registered `Metrics`.
fn once_test_metrics() -> Arc<Metrics> {
    static METRICS: std::sync::OnceLock<Arc<Metrics>> = std::sync::OnceLock::new();
    METRICS.get_or_init(|| Arc::new(Metrics::new())).clone()
}

#[cfg(any(test, feature = "test-helpers"))]
impl AppState {
    /// Minimal test constructor — only populates the fields that the claims handler
    /// (`submit_public_claim`) and the trades handler (`get_recent_trades`) need.
    /// All other fields receive lightweight no-op stubs.
    pub async fn for_test(
        redis_store: Arc<RedisStore>,
        privacy_state: Arc<PrivacyStateService>,
        prediction_market_relayer: Option<Arc<PredictionMarketRelayer>>,
    ) -> Arc<Self> {
        use rust_decimal::Decimal;

        let metrics = once_test_metrics();
        let balance_service = Arc::new(BalanceService::new(None));
        let orderbook_manager = Arc::new(OrderBookManager::new(
            redis_store.clone(),
            metrics.clone(),
            None,
        ));
        let settlement_engine = Arc::new(SettlementEngine::new(
            redis_store.clone(),
            None,
            0,
            0,
            balance_service.clone(),
        ));
        let matching_engine = Arc::new(
            MatchingEngine::new(
                orderbook_manager.clone(),
                settlement_engine.clone(),
                metrics.clone(),
            )
            .with_privacy_state(privacy_state.clone()),
        );
        let ws_manager = Arc::new(WebSocketManager::new());
        let prover_pipeline = Arc::new(ProverPipeline::new(redis_store.clone(), 1));

        let config = Config {
            host: "127.0.0.1".to_string(),
            port: 0,
            redis_url: "redis://127.0.0.1/".to_string(),
            max_orders_per_user: 100,
            max_order_size: Decimal::from(1_000_000),
            maker_fee_bps: 0,
            taker_fee_bps: 0,
            min_order_size: Decimal::from(1),
            database_url: None,
            prediction_market_vault_address: None,
            zen_vault_address: None,
            zen_token_address: None,
            market_factory_address: None,
            market_oracle_enabled: false,
            market_lifecycle_enabled: false,
            enable_settlement: false,
            rpc_url: None,
            settlement_contract: None,
            settlement_private_key: None,
            chain_id: None,
            settlement_batch_size: 0,
            settlement_retry_attempts: 0,
        };

        Arc::new(Self {
            config,
            matching_engine,
            orderbook_manager,
            settlement_engine,
            balance_service,
            ws_manager,
            metrics,
            database: None,
            redis_store,
            prover_pipeline,
            privacy_state,
            prediction_market_relayer,
        })
    }
}
