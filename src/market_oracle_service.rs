// SPDX-License-Identifier: MIT
// Layrs - Market Oracle Service
//
// Every hour (aligned to UTC :00 boundaries) this service:
//   1. For each tracked asset (BTC, ETH, SOL):
//      a. Fetches the just-completed hour's close price from Pyth Hermes.
//      b. Resolves the pending market (created last hour) for that asset.
//      c. Creates a new hourly binary prediction market on Horizen EVM:
//             "Will <ASSET> be above $X at <next_hour> UTC?"
//
// Pyth is the single source of truth for both market creation and resolution.
// Feed IDs: BTC e62df..., ETH ff614..., SOL ef0d8..., ZEN d183f...
//
// questionHash encoding: keccak256(asset_name_bytes ++ abi.encode(expiry_ts))
//   e.g. keccak256(b"BTC" ++ abi.encode(1700000000))
//
// Environment variables consumed:
//   MARKET_ORACLE_ENABLED          – set to "true" to activate (default: false)
//   MARKET_FACTORY_ADDRESS         – EVM hex address of MarketFactory contract
//   MARKET_RESOLVER_ADDRESS        – EVM hex address of MarketResolver contract
//   MARKET_REGISTRY_ADDRESS        – EVM hex address of MarketRegistry contract
//   HORIZEN_RPC_URL                – Horizen EVM JSON-RPC endpoint
//   EVM_OPERATOR_PRIVATE_KEY       – operator private key (hex)
//   EVM_CHAIN_ID                   – chain ID (default: 2651420)

use ethers::{
    abi::{encode, Token},
    providers::{Http, Middleware, Provider},
    types::{Address, Bytes, U256},
    utils::keccak256,
};

use crate::{
    database::{Database, PersistedOracleMarket},
    error::{ClobError, ClobResult},
    evm_relayer::EvmRelayer,
    market_resolution_policy::{
        create_audit_record, evaluate_resolution_candidates, OraclePolicy,
        OracleResolutionAuditRecord, OracleResolutionDecision, OracleResolutionStatus,
    },
    oracle::PythOracle,
    orderbook::OrderBookManager,
    redis_store::RedisStore,
};
use rust_decimal::Decimal;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use tracing::{error, info, warn};

/// Assets for which hourly markets are created and resolved each tick.
const ORACLE_ASSETS: &[&str] = &["BTC", "ETH", "SOL"];

fn merge_recovery_backlog(
    persisted: Vec<PersistedOracleMarket>,
    cached_pending: Option<PersistedOracleMarket>,
) -> Vec<PersistedOracleMarket> {
    let mut seen_market_ids = HashSet::new();
    let mut merged = Vec::with_capacity(persisted.len() + usize::from(cached_pending.is_some()));

    for market in persisted {
        seen_market_ids.insert(market.on_chain_market_id);
        merged.push(market);
    }

    if let Some(market) = cached_pending {
        if !seen_market_ids.contains(&market.on_chain_market_id) {
            merged.push(market);
        }
    }

    merged
}

// ─── Service ─────────────────────────────────────────────────────────────────

pub struct MarketOracleService {
    /// EVM address of the deployed MarketFactory contract.
    factory_address: Address,
    /// EVM address of the deployed MarketResolver contract.
    resolver_address: Address,
    /// EVM address of the deployed MarketRegistry contract.
    registry_address: Address,
    /// EVM signing client for submitting transactions.
    relayer: Arc<EvmRelayer>,
    /// Read-only provider for view calls.
    provider: Arc<Provider<Http>>,
    /// Redis persistence for auditable oracle records.
    store: Arc<RedisStore>,
    /// PostgreSQL database for durable market records.
    database: Option<Arc<Database>>,
    /// Pyth oracle — single source of truth for price data.
    oracle: Arc<PythOracle>,
    /// Oracle resolution and dispute policy.
    policy: OraclePolicy,
    /// Next market ID to be assigned (mirrors MarketRegistry.nextMarketId).
    market_id_counter: u64,
    /// Per-asset pending market IDs that need resolving on the next tick.
    /// key = asset (e.g. "BTC"), value = on-chain marketId created last tick.
    pending_markets: HashMap<String, u64>,
    /// Shared orderbook manager — new markets are seeded here on creation.
    orderbook_manager: Arc<OrderBookManager>,
}

impl MarketOracleService {
    // ─── Construction ────────────────────────────────────────────────────────

    pub fn new(
        factory_address: Address,
        resolver_address: Address,
        registry_address: Address,
        relayer: Arc<EvmRelayer>,
        provider: Arc<Provider<Http>>,
        store: Arc<RedisStore>,
        database: Option<Arc<Database>>,
        oracle: Arc<PythOracle>,
        policy: OraclePolicy,
        orderbook_manager: Arc<OrderBookManager>,
    ) -> Self {
        Self {
            factory_address,
            resolver_address,
            registry_address,
            relayer,
            provider,
            store,
            database,
            oracle,
            policy,
            market_id_counter: 0,
            pending_markets: HashMap::new(),
            orderbook_manager,
        }
    }

    /// Build from environment variables.  Returns `None` when required vars are
    /// missing (so callers can treat the service as optional).
    pub fn from_env(store: Arc<RedisStore>, database: Option<Arc<Database>>, orderbook_manager: Arc<OrderBookManager>) -> Option<Self> {
        let factory_address_str = std::env::var("MARKET_FACTORY_ADDRESS").ok()?;
        if factory_address_str.is_empty() {
            return None;
        }
        let factory_address: Address = factory_address_str.parse().ok()?;

        let resolver_address_str = std::env::var("MARKET_RESOLVER_ADDRESS").ok()?;
        let resolver_address: Address = resolver_address_str.parse().ok()?;

        let registry_address_str = std::env::var("MARKET_REGISTRY_ADDRESS").ok()?;
        let registry_address: Address = registry_address_str.parse().ok()?;

        let relayer = EvmRelayer::from_env()?;
        let rpc_url = relayer.config.rpc_url.clone();
        let provider = Arc::new(Provider::<Http>::try_from(rpc_url.as_str()).ok()?);

        let oracle = Arc::new(PythOracle::new());
        let policy = OraclePolicy::from_env();

        Some(Self::new(factory_address, resolver_address, registry_address, Arc::new(relayer), provider, store, database, oracle, policy, orderbook_manager))
    }

    // ─── Main loop ───────────────────────────────────────────────────────────

    /// Run the oracle loop forever.  The first tick fires at the next UTC :00
    /// boundary plus a 30-second grace period so Pyth data is always finalized.
    pub async fn start(mut self) -> ClobResult<()> {
        let interval_secs: u64 = std::env::var("MARKET_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(900); // default: 15 minutes

        info!(
            assets = ?ORACLE_ASSETS,
            interval_secs,
            "Market oracle service starting — waiting for next interval boundary"
        );

        let initial_wait = secs_until_next_interval(interval_secs);
        if initial_wait > 0 {
            info!(secs = initial_wait, "Sleeping until next interval boundary");
            sleep(Duration::from_secs(initial_wait)).await;
        }

        const GRACE_SECS: u64 = 30;
        info!(secs = GRACE_SECS, "Applying grace period for Pyth data finality");
        sleep(Duration::from_secs(GRACE_SECS)).await;

        // Sync on-chain market count before the first tick.
        if let Err(e) = self.sync_from_chain().await {
            error!(
                error = %e,
                "Failed to sync state from chain — beginning from local zero state"
            );
        }

        loop {
            let now_ts = unix_now();
            let prev_interval_start = now_ts.saturating_sub(interval_secs);
            let next_interval_ts    = now_ts + interval_secs;

            info!(
                assets = ?ORACLE_ASSETS,
                prev_interval_start,
                next_interval_ts,
                pending_markets = ?self.pending_markets,
                "Oracle tick starting"
            );

            // Run a tick for each asset sequentially.
            // Each successful create increments market_id_counter by 1.
            for asset in ORACLE_ASSETS {
                let pending = self.pending_markets.get(*asset).copied();
                match self.tick_asset(asset, prev_interval_start, now_ts, next_interval_ts, pending).await {
                    Ok(new_market_id) => {
                        info!(
                            asset,
                            market_id = new_market_id,
                            "Oracle tick succeeded — market created"
                        );
                        self.pending_markets.insert(asset.to_string(), new_market_id);
                    }
                    Err(e) => {
                        error!(asset, error = %e, "Oracle asset tick failed — will retry next hour");
                        // pending entry intentionally preserved so resolve is retried next tick.
                    }
                }
            }

            // Sleep until the next interval boundary plus the grace period.
            let wait = secs_until_next_interval(interval_secs);
            sleep(Duration::from_secs(wait.max(1) + GRACE_SECS)).await;
        }
    }

    /// Read `MarketRegistry.nextMarketId()` to initialise `market_id_counter`.
    /// Per-asset pending state is still cached in memory, but expired unresolved
    /// markets are now recovered from the DB on each tick when persistence exists.
    async fn sync_from_chain(&mut self) -> ClobResult<()> {
        info!("Syncing market oracle state from Horizen EVM");

        let selector = &keccak256(b"nextMarketId()")[..4];
        let result = self.call_view_registry(
            Bytes::from(selector.to_vec()),
        ).await.map_err(|e| ClobError::Internal(format!("nextMarketId() call failed: {e}")))?;

        let count = if result.len() >= 32 {
            U256::from_big_endian(&result[..32]).as_u64()
        } else {
            0u64
        };
        self.market_id_counter = count;
        info!(
            on_chain_count = count,
            "On-chain market count read from registry — oracle counter initialised"
        );
        Ok(())
    }

    // ─── Per-asset tick ───────────────────────────────────────────────────────

    /// Execute one hour boundary tick for a single asset:
    ///   1. Fetch Pyth strike price for the just-completed hour.
    ///   2. Resolve the pending market (from last tick) if one exists.
    ///   3. Create a new market for the upcoming hour.
    ///
    /// Returns the on-chain marketId of the newly created market.
    async fn tick_asset(
        &mut self,
        asset: &str,
        prev_hour_start: u64,
        now_ts: u64,
        next_hour_ts: u64,
        pending_market_id: Option<u64>,
    ) -> ClobResult<u64> {
        // 1. Strike price = Pyth close price at the start of the just-completed hour.
        let close_price = self
            .fetch_pyth_price(asset, prev_hour_start)
            .await
            .map_err(|e| ClobError::Internal(format!("Pyth fetch failed for {asset}: {e}")))?;

        let strike_price = decimal_price_to_u128(close_price).ok_or_else(|| {
            ClobError::Internal(format!(
                "Pyth returned invalid strike price for {asset}: {}",
                close_price
            ))
        })?;

        // 2. Resolve any expired unresolved markets for this asset.
        let mut persisted_backlog: Vec<PersistedOracleMarket> = Vec::new();

        if let Some(db) = &self.database {
            match db.get_expired_active_pyth_markets(asset, now_ts).await {
                Ok(backlog) => {
                    persisted_backlog = backlog;
                }
                Err(error) => {
                    warn!(asset, error = %error, "Failed to load expired oracle backlog from DB — falling back to in-memory pending state");
                }
            }
        }

        let markets_to_resolve = merge_recovery_backlog(
            persisted_backlog,
            pending_market_id.map(|prev_id| PersistedOracleMarket {
                market_id: format!("{asset}-{prev_id}"),
                on_chain_market_id: prev_id,
                expiry_ts: prev_hour_start,
            }),
        );

        let price_decimal = scaled_u128_to_decimal(
            decimal_price_to_u128(close_price).unwrap_or(0),
        );

        for pending_market in markets_to_resolve {
            let prev_id = pending_market.on_chain_market_id;
            match self
                .resolve_pending_market(asset, prev_id, pending_market.expiry_ts, now_ts)
                .await
            {
                Ok(Some(ref tx)) => {
                    info!(
                        asset,
                        market_id = prev_id,
                        tx_hash = %tx,
                        "Market resolved on-chain"
                    );
                    if let Some(db) = &self.database {
                        if let Err(error) = db
                            .update_market_resolution(&pending_market.market_id, price_decimal, "resolved")
                            .await
                        {
                            warn!(
                                asset,
                                market_id = prev_id,
                                error = %error,
                                "Failed to persist market resolution to DB"
                            );
                        }
                    }
                }
                Ok(None) => info!(
                    asset,
                    market_id = prev_id,
                    "Market resolution deferred under oracle policy"
                ),
                Err(error) => warn!(
                    asset,
                    market_id = prev_id,
                    error = %error,
                    "Failed to resolve market — will retry next tick"
                ),
            }
        }

        // 3. Create a new market for the next hour.
        //    questionHash = keccak256(asset_name_bytes ++ abi.encode(expiry_ts))
        //    Front-ends reconstruct: "Will <ASSET> close above $strike at Unix {expiry_ts}?"
        let expected_id = self.market_id_counter;
        let question_hash = make_question_hash(asset, next_hour_ts);

        let tx_hash = self
            .create_market(question_hash, strike_price, next_hour_ts)
            .await
            .map_err(|e| ClobError::Internal(format!("createBinaryMarket failed for {asset}: {e}")))?;

        info!(
            asset,
            market_id = expected_id,
            strike_price,
            expiry_ts = next_hour_ts,
            tx_hash = %tx_hash,
            "New prediction market created on-chain"
        );

        // Persist new market to DB
        if let Some(db) = &self.database {
            let market_key = format!("{asset}-{expected_id}");
            let description = format!("Will {asset} close above ${close_price} at Unix {next_hour_ts}?");
            let strike_decimal = scaled_u128_to_decimal(strike_price);
            if let Err(e) = db.upsert_market(
                &market_key,
                &description,
                next_hour_ts,
                "active",
                None,
                Some(strike_decimal),
                None,
                None,
                Some("pyth"),
                Some(expected_id as i64),
            ).await {
                warn!(asset, market_id = expected_id, error = %e, "Failed to persist new market to DB");
            }
        }

        // Register the new market in the CLOB's active_markets so orders are accepted.
        let market_key = format!("{asset}-{expected_id}");
        self.orderbook_manager.seed_market(&market_key);
        info!(asset, market_id = expected_id, clob_market_key = %market_key, "Market seeded into CLOB active_markets");

        self.market_id_counter += 1;
        Ok(expected_id)
    }

    

    // ─── EVM contract helpers ─────────────────────────────────────────────────

    /// Call `createBinaryMarket(bytes32 questionHash, uint128 strikePrice, uint64 expiryTs)`.
    async fn create_market(
        &self,
        question_hash: [u8; 32],
        strike_price: u128,
        expiry_ts: u64,
    ) -> ClobResult<String> {
        // selector: keccak256("createBinaryMarket(bytes32,uint128,uint64)")[..4]
        let selector = &keccak256(b"createBinaryMarket(bytes32,uint128,uint64)")[..4];
        let tokens = vec![
            Token::FixedBytes(question_hash.to_vec()),
            Token::Uint(U256::from(strike_price)),
            Token::Uint(U256::from(expiry_ts)),
        ];
        let data = Bytes::from([selector, encode(&tokens).as_slice()].concat());
        self.relayer.send_tx(self.factory_address, data).await
    }

    /// Call `resolveBinaryMarket(uint64 marketId, uint128 finalPrice)` on the MarketResolver.
    async fn resolve_market(&self, market_id: u64, final_price: u128) -> ClobResult<String> {
        let selector = &keccak256(b"resolveBinaryMarket(uint64,uint128)")[..4];
        let tokens = vec![
            Token::Uint(U256::from(market_id)),
            Token::Uint(U256::from(final_price)),
        ];
        let data = Bytes::from([selector, encode(&tokens).as_slice()].concat());
        self.relayer.send_tx(self.resolver_address, data).await
    }

    async fn resolve_pending_market(
        &self,
        asset: &str,
        market_id: u64,
        expiry_ts: u64,
        now_ts: u64,
    ) -> ClobResult<Option<String>> {
        let market_key = format!("{asset}-{market_id}");
        let strike_price = self.get_market_strike_price(market_id).await?;
        let strike_decimal = scaled_u128_to_decimal(strike_price);
        let primary_price = self.fetch_pyth_price(asset, expiry_ts).await.ok();
        let age_secs = now_ts.saturating_sub(expiry_ts);
        let attempts = self.next_attempt_count(&market_key).await?;

        let decision = evaluate_resolution_candidates(
            age_secs,
            Some(strike_decimal),
            "pyth",
            primary_price,
            None,
            None,
            &self.policy,
        );

        let mut audit = create_audit_record(
            market_key.clone(),
            expiry_ts,
            Some(strike_decimal),
            "pyth",
            primary_price,
            None,
            None,
            attempts,
            &self.policy,
            &decision,
        );

        if self.is_market_invalidated(market_id).await? {
            audit.status = OracleResolutionStatus::Invalidated;
            audit.reason.get_or_insert_with(|| "market already invalidated on-chain".to_string());
            self.persist_audit_record(&audit).await?;
            return Ok(None);
        }

        if self.is_market_resolved(market_id).await? {
            audit.status = OracleResolutionStatus::Finalized;
            audit.reason.get_or_insert_with(|| "market already resolved on-chain".to_string());
            self.persist_audit_record(&audit).await?;
            return Ok(None);
        }

        match decision {
            OracleResolutionDecision::Resolve { price, source, .. } => {
                let final_price = decimal_price_to_u128(price).ok_or_else(|| {
                    ClobError::InvalidPrice(format!("failed to scale oracle price {}", price))
                })?;
                let tx_hash = self.resolve_market(market_id, final_price).await?;
                audit.status = OracleResolutionStatus::ResolvePublished;
                audit.final_price = Some(price.to_string());
                audit.published_tx_hash = Some(tx_hash.clone());
                audit.reason = Some(format!("resolved from {} under oracle policy", source));
                self.persist_audit_record(&audit).await?;
                Ok(Some(tx_hash))
            }
            OracleResolutionDecision::Pending { reason } => {
                audit.status = OracleResolutionStatus::PendingResolution;
                audit.reason = Some(reason);
                self.persist_audit_record(&audit).await?;
                Ok(None)
            }
            OracleResolutionDecision::Disputed { reason } => {
                audit.status = OracleResolutionStatus::Disputed;
                audit.reason = Some(reason);
                self.persist_audit_record(&audit).await?;
                Ok(None)
            }
            OracleResolutionDecision::Invalidate { reason } => {
                audit.status = OracleResolutionStatus::Disputed;
                audit.reason = Some(reason.clone());
                audit.operator_action = Some(
                    "manual operator invalidation is required because the contract only invalidates resolved markets"
                        .to_string(),
                );
                self.persist_audit_record(&audit).await?;
                Ok(None)
            }
        }
    }

    async fn next_attempt_count(&self, market_id: &str) -> ClobResult<u32> {
        let existing = self
            .store
            .get_optional(&format!("pm:oracle:audit:{}", market_id))
            .await?;
        Ok(existing
            .and_then(|payload| serde_json::from_str::<OracleResolutionAuditRecord>(&payload).ok())
            .map(|record| record.attempts.saturating_add(1))
            .unwrap_or(1))
    }

    async fn persist_audit_record(&self, audit: &OracleResolutionAuditRecord) -> ClobResult<()> {
        let payload = serde_json::to_string(audit)?;
        self.store.set(&audit.redis_key(), &payload).await?;
        self.store.append_json_array_value(&audit.history_key(), &payload).await?;
        Ok(())
    }

    async fn get_market_strike_price(&self, market_id: u64) -> ClobResult<u128> {
        // getBinaryMarket(uint64) returns BinaryMarket struct.
        // ABI layout: questionHash(bytes32) at slot 0, strikePrice(uint128) at slot 1 (bytes 32..64).
        let selector = &keccak256(b"getBinaryMarket(uint64)")[..4];
        let data = Bytes::from([
            selector,
            encode(&[Token::Uint(U256::from(market_id))]).as_slice(),
        ].concat());
        let result = self.call_view_resolver(data).await?;
        if result.len() < 64 {
            return Ok(0);
        }
        // BinaryMarket struct ABI layout: questionHash(bytes32), strikePrice(uint128), ...
        // strikePrice occupies slot 1 (bytes 32..64).
        Ok(U256::from_big_endian(&result[32..64]).as_u128())
    }

    async fn is_market_resolved(&self, market_id: u64) -> ClobResult<bool> {
        // `isResolved(uint64 marketId) returns (bool)` — on MarketResolver
        let selector = &keccak256(b"isResolved(uint64)")[..4];
        let data = Bytes::from([
            selector,
            encode(&[Token::Uint(U256::from(market_id))]).as_slice(),
        ].concat());
        let result = self.call_view_resolver(data).await?;
        Ok(result.last().copied().unwrap_or(0) != 0)
    }

    async fn is_market_invalidated(&self, market_id: u64) -> ClobResult<bool> {
        // `isInvalidated(uint64 marketId) returns (bool)` — on MarketResolver
        let selector = &keccak256(b"isInvalidated(uint64)")[..4];
        let data = Bytes::from([
            selector,
            encode(&[Token::Uint(U256::from(market_id))]).as_slice(),
        ].concat());
        let result = self.call_view_resolver(data).await?;
        Ok(result.last().copied().unwrap_or(0) != 0)
    }

    /// Low-level eth_call to the MarketResolver contract.
    async fn call_view_resolver(&self, data: Bytes) -> ClobResult<ethers::types::Bytes> {
        self.provider
            .call(
                &ethers::types::transaction::eip2718::TypedTransaction::Legacy(
                    ethers::types::TransactionRequest::new()
                        .to(self.resolver_address)
                        .data(data)
                ),
                None,
            )
            .await
            .map_err(|e| ClobError::Internal(format!("eth_call (resolver) failed: {e}")))
    }

    /// Low-level eth_call to the MarketRegistry contract.
    async fn call_view_registry(&self, data: Bytes) -> ClobResult<ethers::types::Bytes> {
        self.provider
            .call(
                &ethers::types::transaction::eip2718::TypedTransaction::Legacy(
                    ethers::types::TransactionRequest::new()
                        .to(self.registry_address)
                        .data(data)
                ),
                None,
            )
            .await
            .map_err(|e| ClobError::Internal(format!("eth_call (registry) failed: {e}")))
    }

    // ─── Pyth price helper ───────────────────────────────────────────────────

    /// Fetch the Pyth-published price for `asset` at `timestamp` with retries.
    async fn fetch_pyth_price(
        &self,
        asset: &str,
        timestamp: u64,
    ) -> Result<Decimal, Box<dyn std::error::Error + Send + Sync>> {
        const MAX_RETRIES: u32 = 3;
        let mut last_err: Box<dyn std::error::Error + Send + Sync> = "no attempts made".into();

        for attempt in 0..=MAX_RETRIES {
            if attempt > 0 {
                let delay_secs = 2u64.pow(attempt);
                warn!(attempt, delay_secs, asset, "Retrying Pyth price fetch");
                sleep(Duration::from_secs(delay_secs)).await;
            }
            match self.oracle.get_price_at_timestamp(asset, timestamp).await {
                Ok(price) => return Ok(price),
                Err(e) => {
                    error!(attempt, asset, error = %e, "Pyth price fetch failed");
                    last_err = e.to_string().into();
                }
            }
        }

        Err(last_err)
    }
}

#[cfg(test)]
mod tests {
    use super::merge_recovery_backlog;
    use crate::database::PersistedOracleMarket;

    #[test]
    fn merge_recovery_backlog_dedupes_cached_pending_when_db_has_same_market() {
        let merged = merge_recovery_backlog(
            vec![PersistedOracleMarket {
                market_id: "BTC-160".to_string(),
                on_chain_market_id: 160,
                expiry_ts: 1_714_148_100,
            }],
            Some(PersistedOracleMarket {
                market_id: "BTC-160".to_string(),
                on_chain_market_id: 160,
                expiry_ts: 1_714_148_100,
            }),
        );

        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].on_chain_market_id, 160);
    }

    #[test]
    fn merge_recovery_backlog_keeps_cached_pending_when_db_is_empty() {
        let merged = merge_recovery_backlog(
            Vec::new(),
            Some(PersistedOracleMarket {
                market_id: "ETH-161".to_string(),
                on_chain_market_id: 161,
                expiry_ts: 1_714_148_100,
            }),
        );

        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].market_id, "ETH-161");
    }
}

// ─── Free helpers ────────────────────────────────────────────────────────────

/// Build the on-chain questionHash for a binary market.
///
/// Encoding: keccak256(asset_name_bytes ++ abi.encode(expiry_ts))
///   e.g. keccak256(b"BTC" ++ abi.encode(1700000000))
///
/// Front-ends reconstruct the question text as:
///   "Will <ASSET> close above $<strike> at Unix <expiry_ts>?"
fn make_question_hash(asset: &str, expiry_ts: u64) -> [u8; 32] {
    let mut data = asset.as_bytes().to_vec();
    data.extend_from_slice(&encode(&[Token::Uint(U256::from(expiry_ts))]));
    keccak256(&data)
}

/// Current UNIX timestamp in seconds.
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Seconds until the next UTC boundary aligned to `interval_secs`.
fn secs_until_next_interval(interval_secs: u64) -> u64 {
    let now = unix_now();
    let secs_past = now % interval_secs;
    if secs_past == 0 {
        0
    } else {
        interval_secs - secs_past
    }
}

fn decimal_price_to_u128(price: Decimal) -> Option<u128> {
    if price <= Decimal::ZERO {
        return None;
    }
    let scaled = price * Decimal::from(100_000_000u64);
    rust_decimal::prelude::ToPrimitive::to_u128(&scaled.round())
}

fn scaled_u128_to_decimal(price: u128) -> Decimal {
    Decimal::from_i128_with_scale(price as i128, 8)
}

