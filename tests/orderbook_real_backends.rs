use anyhow::{anyhow, bail, Context, Result};
use clob_service::{
    balance_service::BalanceService,
    database::Database,
    error::ClobError,
    matching::MatchingEngine,
    metrics::Metrics,
    models::{Order, OrderSide, OrderStatus, OrderType, TimeInForce},
    orderbook::OrderBookManager,
    redis_store::RedisStore,
    settlement::SettlementEngine,
};
use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use sqlx::Row;
use std::{process::Command, sync::Arc, time::Duration};
use uuid::Uuid;

const REDIS_IMAGE: &str = "redis:7-alpine";
const POSTGRES_IMAGE: &str = "postgres:15-alpine";

struct CompatEnvGuard {
    saved: Vec<(&'static str, Option<String>)>,
}

impl CompatEnvGuard {
    fn new() -> Self {
        let keys = [
            "REDIS_COMPAT_DISABLE_SET_NX",
            "REDIS_COMPAT_DISABLE_SET_EX",
            "REDIS_COMPAT_DISABLE_EXISTS",
            "REDIS_COMPAT_DISABLE_KEYS",
            "REDIS_COMPAT_DISABLE_LISTS",
            "REDIS_COMPAT_DISABLE_SETS",
            "REDIS_COMPAT_DISABLE_SORTED_SETS",
            "REDIS_COMPAT_DISABLE_HASHES",
        ];

        let mut saved = Vec::with_capacity(keys.len());
        for key in keys {
            saved.push((key, std::env::var(key).ok()));
            std::env::remove_var(key);
        }

        Self { saved }
    }
}

impl Drop for CompatEnvGuard {
    fn drop(&mut self) {
        for (key, value) in &self.saved {
            if let Some(value) = value {
                std::env::set_var(key, value);
            } else {
                std::env::remove_var(key);
            }
        }
    }
}

struct DockerContainer {
    name: String,
}

impl DockerContainer {
    fn start_redis() -> Result<Self> {
        let name = format!("clob-test-redis-{}", Uuid::new_v4());
        run_docker(&["run", "--rm", "-d", "-P", "--name", &name, REDIS_IMAGE])?;
        Ok(Self { name })
    }

    fn start_postgres() -> Result<Self> {
        let name = format!("clob-test-postgres-{}", Uuid::new_v4());
        run_docker(&[
            "run",
            "--rm",
            "-d",
            "-P",
            "--name",
            &name,
            "-e",
            "POSTGRES_USER=postgres",
            "-e",
            "POSTGRES_PASSWORD=postgres",
            "-e",
            "POSTGRES_DB=clob_test",
            POSTGRES_IMAGE,
        ])?;
        Ok(Self { name })
    }

    fn host_port(&self, container_port: u16) -> Result<u16> {
        let output = run_docker(&["port", &self.name, &format!("{container_port}/tcp")])?;
        let port = output
            .lines()
            .next()
            .and_then(|line| line.rsplit_once(':').map(|(_, port)| port))
            .ok_or_else(|| anyhow!("docker port output missing host port for {}", self.name))?;

        port.parse::<u16>()
            .with_context(|| format!("invalid docker host port `{port}` for {}", self.name))
    }
}

impl Drop for DockerContainer {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.name])
            .status();
    }
}

struct RealBackends {
    _env_guard: CompatEnvGuard,
    _redis: DockerContainer,
    _postgres: DockerContainer,
    trade_persist_task: Option<tokio::task::JoinHandle<()>>,
    orderbook: Arc<OrderBookManager>,
    engine: MatchingEngine,
    balance_service: Arc<BalanceService>,
    database: Arc<Database>,
}

impl Drop for RealBackends {
    fn drop(&mut self) {
        if let Some(task) = self.trade_persist_task.take() {
            task.abort();
        }
    }
}

impl RealBackends {
    async fn start() -> Result<Self> {
        let env_guard = CompatEnvGuard::new();

        let redis = DockerContainer::start_redis()?;
        let redis_port = redis.host_port(6379)?;
        let redis_url = format!("redis://127.0.0.1:{redis_port}/");
        wait_for_redis(&redis_url).await?;

        let postgres = DockerContainer::start_postgres()?;
        let postgres_port = postgres.host_port(5432)?;
        let database_url =
            format!("postgresql://postgres:postgres@127.0.0.1:{postgres_port}/clob_test");
        let database = wait_for_database(&database_url).await?;
        database.migrate().await?;

        let client = redis::Client::open(redis_url.clone())
            .with_context(|| format!("open redis client {redis_url}"))?;
        let conn = redis::aio::ConnectionManager::new(client).await?;
        let store = Arc::new(RedisStore::new(conn));
        let metrics = Arc::new(Metrics::new());
        let orderbook = Arc::new(OrderBookManager::new(
            store.clone(),
            metrics.clone(),
            Some(database.clone()),
        ));
        let balance_service = Arc::new(BalanceService::new(None));
        let settlement = Arc::new(SettlementEngine::new(
            store,
            Some(database.clone()),
            0,
            0,
            balance_service.clone(),
            Arc::new(clob_service::websocket::WebSocketManager::new()),
        ));
        let trade_persist_task = settlement.clone().start_trade_persistence_worker();
        let engine = MatchingEngine::new(orderbook.clone(), settlement, metrics);

        Ok(Self {
            _env_guard: env_guard,
            _redis: redis,
            _postgres: postgres,
            trade_persist_task,
            orderbook,
            engine,
            balance_service,
            database,
        })
    }
}

fn run_docker(args: &[&str]) -> Result<String> {
    let output = Command::new("docker")
        .args(args)
        .output()
        .with_context(|| format!("failed to run docker {:?}", args))?;

    if !output.status.success() {
        bail!(
            "docker {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

async fn wait_for_redis(redis_url: &str) -> Result<()> {
    for _ in 0..60 {
        if let Ok(client) = redis::Client::open(redis_url.to_string()) {
            if let Ok(mut conn) = client.get_multiplexed_async_connection().await {
                let ping: redis::RedisResult<String> =
                    redis::cmd("PING").query_async(&mut conn).await;
                if ping.as_deref() == Ok("PONG") {
                    return Ok(());
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    bail!("timed out waiting for redis at {redis_url}")
}

async fn wait_for_database(database_url: &str) -> Result<Arc<Database>> {
    for _ in 0..60 {
        if let Ok(database) = Database::connect(database_url).await {
            if database.health_check().await.is_ok() {
                return Ok(Arc::new(database));
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    bail!("timed out waiting for postgres at {database_url}")
}

fn make_limit_order(
    user: &str,
    market: &str,
    side: OrderSide,
    price: Decimal,
    size: Decimal,
    tif: TimeInForce,
) -> Order {
    Order::new(
        user.to_string(),
        market.to_string(),
        side,
        OrderType::Limit,
        tif,
        price,
        size,
    )
}

async fn assert_order_row(
    database: &Database,
    order_id: Uuid,
    expected_wallet: &str,
    expected_status: &str,
    expected_amount: Decimal,
) -> Result<()> {
    let row = sqlx::query(
        "SELECT
            o.status,
            o.amount,
            u.evm_address,
            (SELECT COUNT(*) FROM orders WHERE order_id = $1) AS row_count
         FROM orders o
         JOIN users u ON u.user_id = o.user_id
         WHERE o.order_id = $1",
    )
    .bind(order_id.to_string())
    .fetch_one(database.pool())
    .await?;

    let row_count: i64 = row.get("row_count");
    let status: String = row.get("status");
    let amount: Decimal = row.get("amount");
    let wallet_address: String = row.get("evm_address");

    assert_eq!(
        row_count, 1,
        "order {} should upsert to exactly one row",
        order_id
    );
    assert_eq!(status, expected_status);
    assert_eq!(wallet_address, expected_wallet.to_lowercase());
    assert_eq!(amount.round_dp(6), expected_amount.round_dp(6));

    Ok(())
}

async fn count_trades_for_orders(database: &Database, order_a: Uuid, order_b: Uuid) -> Result<i64> {
    let row = sqlx::query(
        "SELECT COUNT(*) AS count
         FROM trades
         WHERE maker_order_id IN ($1, $2)
            OR taker_order_id IN ($1, $2)",
    )
    .bind(order_a)
    .bind(order_b)
    .fetch_one(database.pool())
    .await?;

    Ok(row.get("count"))
}

async fn count_fills_for_orders(database: &Database, order_a: Uuid, order_b: Uuid) -> Result<i64> {
    let row = sqlx::query(
        "SELECT COUNT(*) AS count
         FROM fills
         WHERE order_id IN ($1, $2)",
    )
    .bind(order_a)
    .bind(order_b)
    .fetch_one(database.pool())
    .await?;

    Ok(row.get("count"))
}

async fn wait_for_trade_persistence(
    database: &Database,
    order_a: Uuid,
    order_b: Uuid,
    expected_trades: i64,
    expected_fills: i64,
) -> Result<()> {
    for _ in 0..40 {
        let trade_count = count_trades_for_orders(database, order_a, order_b).await?;
        let fill_count = count_fills_for_orders(database, order_a, order_b).await?;

        if trade_count == expected_trades && fill_count == expected_fills {
            return Ok(());
        }

        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    bail!(
        "timed out waiting for trade persistence for orders {} and {}",
        order_a,
        order_b
    )
}

#[tokio::test]
#[ignore = "requires Docker (redis:7-alpine, postgres:15-alpine)"]
async fn real_redis_orderbook_scenarios_persist_orders_to_db() -> Result<()> {
    let backends = RealBackends::start().await?;
    let engine = &backends.engine;
    let orderbook = &backends.orderbook;
    let balances = &backends.balance_service;
    let database = &backends.database;

    // Scenario 1: resting maker GTC is fully filled by a crossing GTC taker.
    balances.deposit("maker-gtc", "USDC", dec!(1000));
    balances.deposit("taker-gtc", "USDC", dec!(1000));

    let market = "REAL-GTC-FILL";
    let maker = make_limit_order(
        "maker-gtc",
        market,
        OrderSide::Sell,
        dec!(0.60),
        dec!(100),
        TimeInForce::Gtc,
    );
    let maker_id = maker.id;
    let maker_result = engine.submit_order(maker).await?;
    assert_eq!(maker_result.order.status, OrderStatus::Open);

    let taker = make_limit_order(
        "taker-gtc",
        market,
        OrderSide::Buy,
        dec!(0.60),
        dec!(100),
        TimeInForce::Gtc,
    );
    let taker_id = taker.id;
    let taker_result = engine.submit_order(taker).await?;
    assert_eq!(taker_result.order.status, OrderStatus::Filled);
    assert_order_row(database, maker_id, "maker-gtc", "filled", dec!(0)).await?;
    assert_order_row(database, taker_id, "taker-gtc", "filled", dec!(0)).await?;
    wait_for_trade_persistence(database, maker_id, taker_id, 1, 2).await?;
    let gtc_book = orderbook.get_orderbook(market, 5).await?;
    assert!(gtc_book.bids.is_empty());
    assert!(gtc_book.asks.is_empty());

    // Scenario 2: partially-filled resting maker can still be cancelled and stays durable in DB.
    balances.deposit("maker-partial", "USDC", dec!(1000));
    balances.deposit("taker-partial", "USDC", dec!(1000));

    let market = "REAL-PARTIAL-CANCEL";
    let maker = make_limit_order(
        "maker-partial",
        market,
        OrderSide::Sell,
        dec!(0.61),
        dec!(100),
        TimeInForce::Gtc,
    );
    let maker_id = maker.id;
    engine.submit_order(maker).await?;

    let taker = make_limit_order(
        "taker-partial",
        market,
        OrderSide::Buy,
        dec!(0.61),
        dec!(40),
        TimeInForce::Gtc,
    );
    let taker_id = taker.id;
    let taker_result = engine.submit_order(taker).await?;
    assert_eq!(taker_result.order.status, OrderStatus::Filled);
    let maker_snapshot = orderbook.store.get_order(maker_id).await?.unwrap();
    assert_eq!(maker_snapshot.status, OrderStatus::Partial);
    assert_eq!(maker_snapshot.remaining, dec!(60));

    let cancelled = engine.cancel_order(maker_id, "maker-partial").await?;
    assert_eq!(cancelled.status, OrderStatus::Cancelled);
    assert_eq!(cancelled.remaining, dec!(60));
    assert_order_row(database, maker_id, "maker-partial", "cancelled", dec!(60)).await?;
    assert_order_row(database, taker_id, "taker-partial", "filled", dec!(0)).await?;
    wait_for_trade_persistence(database, maker_id, taker_id, 1, 2).await?;
    let partial_book = orderbook.get_orderbook(market, 5).await?;
    assert!(partial_book.bids.is_empty());
    assert!(partial_book.asks.is_empty());

    // Scenario 3: IOC consumes what it can and cancels the tail without resting in the book.
    balances.deposit("maker-ioc", "USDC", dec!(1000));
    balances.deposit("taker-ioc", "USDC", dec!(1000));

    let market = "REAL-IOC-TAIL";
    let maker = make_limit_order(
        "maker-ioc",
        market,
        OrderSide::Sell,
        dec!(0.62),
        dec!(40),
        TimeInForce::Gtc,
    );
    let maker_id = maker.id;
    engine.submit_order(maker).await?;

    let ioc = make_limit_order(
        "taker-ioc",
        market,
        OrderSide::Buy,
        dec!(0.62),
        dec!(100),
        TimeInForce::Ioc,
    );
    let ioc_id = ioc.id;
    let ioc_result = engine.submit_order(ioc).await?;
    assert_eq!(ioc_result.order.status, OrderStatus::Partial);
    assert_eq!(ioc_result.order.remaining, dec!(60));
    assert_order_row(database, maker_id, "maker-ioc", "filled", dec!(0)).await?;
    assert_order_row(database, ioc_id, "taker-ioc", "partial", dec!(60)).await?;
    wait_for_trade_persistence(database, maker_id, ioc_id, 1, 2).await?;
    let ioc_book = orderbook.get_orderbook(market, 5).await?;
    assert!(ioc_book.bids.is_empty());
    assert!(ioc_book.asks.is_empty());

    // Scenario 4: FOK rejects before any maker mutation and leaves no phantom trade rows.
    balances.deposit("maker-fok", "USDC", dec!(1000));
    balances.deposit("taker-fok", "USDC", dec!(1000));

    let market = "REAL-FOK-ROLLBACK";
    let maker = make_limit_order(
        "maker-fok",
        market,
        OrderSide::Sell,
        dec!(0.63),
        dec!(40),
        TimeInForce::Gtc,
    );
    let maker_id = maker.id;
    engine.submit_order(maker).await?;

    let fok = make_limit_order(
        "taker-fok",
        market,
        OrderSide::Buy,
        dec!(0.63),
        dec!(100),
        TimeInForce::Fok,
    );
    let fok_id = fok.id;
    let error = engine.submit_order(fok).await.unwrap_err();
    assert!(matches!(
        error,
        ClobError::InvalidOrder(message) if message.contains("FOK order cannot be completely filled")
    ));

    let maker_snapshot = orderbook.store.get_order(maker_id).await?.unwrap();
    assert_eq!(maker_snapshot.status, OrderStatus::Open);
    assert_eq!(maker_snapshot.remaining, dec!(40));
    assert_order_row(database, maker_id, "maker-fok", "open", dec!(40)).await?;
    assert_order_row(database, fok_id, "taker-fok", "rejected", dec!(100)).await?;
    wait_for_trade_persistence(database, maker_id, fok_id, 0, 0).await?;
    let fok_book = orderbook.get_orderbook(market, 5).await?;
    assert_eq!(fok_book.asks.len(), 1);
    assert_eq!(fok_book.asks[0].price.round_dp(2), dec!(0.63));
    assert_eq!(fok_book.asks[0].size, dec!(40));

    Ok(())
}
