// SPDX-License-Identifier: MIT
// Layrs - Market Oracle Service
//
// Every hour (aligned to UTC :00 boundaries) this service:
//   1. Fetches the just-completed hour's BTC-USD close price from Pyth Hermes.
//   2. Creates a new hourly binary prediction market on Horizen EVM:
//        "Will BTC be above $X at <next_hour> UTC?"
//   3. Resolves the market that expired at this hour boundary.
//
// Pyth is the single source of truth for both map streaming and market resolution.
// Feed IDs: BTC e62df..., ETH ff614..., SOL ef0d8..., ZEN d183f...
//
// Environment variables consumed:
//   MARKET_ORACLE_ENABLED          – set to "true" to activate (default: false)
//   MARKET_FACTORY_ADDRESS         – EVM hex address of MarketFactory contract
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
    error::{ClobError, ClobResult},
    evm_relayer::EvmRelayer,
    market_resolution_policy::{
        create_audit_record, evaluate_resolution_candidates, OraclePolicy,
        OracleResolutionAuditRecord, OracleResolutionDecision, OracleResolutionStatus,
    },
    oracle::PythOracle,
    redis_store::RedisStore,
};
use rust_decimal::Decimal;
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use tracing::{error, info, warn};

// ─── Service ─────────────────────────────────────────────────────────────────

pub struct MarketOracleService {
    /// EVM address of the deployed MarketFactory contract.
    factory_address: Address,
    /// EVM signing client for submitting transactions.
    relayer: Arc<EvmRelayer>,
    /// Read-only provider for view calls.
    provider: Arc<Provider<Http>>,
    /// Redis persistence for auditable oracle records.
    store: Arc<RedisStore>,
    /// Pyth oracle — single source of truth for price data.
    oracle: Arc<PythOracle>,
    /// Oracle resolution and dispute policy.
    policy: OraclePolicy,
    /// Count of markets created on-chain.  Synced from the contract at startup.
    market_id_counter: u64,
    /// The market created last tick that still needs resolving.
    pending_market_id: Option<u64>,
}

impl MarketOracleService {
    // ─── Construction ────────────────────────────────────────────────────────

    pub fn new(
        factory_address: Address,
        relayer: Arc<EvmRelayer>,
        provider: Arc<Provider<Http>>,
        store: Arc<RedisStore>,
        oracle: Arc<PythOracle>,
        policy: OraclePolicy,
    ) -> Self {
        Self {
            factory_address,
            relayer,
            provider,
            store,
            oracle,
            policy,
            market_id_counter: 0,
            pending_market_id: None,
        }
    }

    /// Build from environment variables.  Returns `None` when required vars are
    /// missing (so callers can treat the service as optional).
    pub fn from_env(store: Arc<RedisStore>) -> Option<Self> {
        let factory_address_str = std::env::var("MARKET_FACTORY_ADDRESS").ok()?;
        if factory_address_str.is_empty() {
            return None;
        }
        let factory_address: Address = factory_address_str.parse().ok()?;

        let relayer = EvmRelayer::from_env()?;
        let rpc_url = relayer.config.rpc_url.clone();
        let provider = Arc::new(Provider::<Http>::try_from(rpc_url.as_str()).ok()?);

        let oracle = Arc::new(PythOracle::new());
        let policy = OraclePolicy::from_env();

        Some(Self::new(factory_address, Arc::new(relayer), provider, store, oracle, policy))
    }

    // ─── Main loop ───────────────────────────────────────────────────────────

    /// Run the oracle loop forever.  The first tick fires at the next UTC :00
    /// boundary plus a grace period so Coinbase candle data is always available.
    pub async fn start(mut self) -> ClobResult<()> {
        info!("Market oracle service starting — waiting for next hour boundary");

        let initial_wait = secs_until_next_hour();
        if initial_wait > 0 {
            info!(secs = initial_wait, "Sleeping until next hour boundary");
            sleep(Duration::from_secs(initial_wait)).await;
        }

        // Grace period: Coinbase candle data may not be finalized immediately at
        // :00.  30 seconds ensures the completed hour's candle is available.
        const GRACE_SECS: u64 = 30;
        info!(secs = GRACE_SECS, "Applying grace period for Coinbase API finality");
        sleep(Duration::from_secs(GRACE_SECS)).await;

        // Sync on-chain market count and any unresolved pending market before the
        // first tick.  Safe after restarts: no markets are ever abandoned.
        if let Err(e) = self.sync_from_chain().await {
            error!(
                error = %e,
                "Failed to sync state from chain at startup — beginning from local zero state"
            );
        }

        loop {
            let now_ts = unix_now();
            let prev_hour_start = now_ts.saturating_sub(3600);
            let next_hour_ts    = now_ts + 3600;

            info!(
                hour = now_ts,
                prev_hour_start,
                next_hour_ts,
                pending_market = ?self.pending_market_id,
                "Oracle tick: fetching BTC close price"
            );

            let pending = self.pending_market_id;
            match self.tick(prev_hour_start, now_ts, next_hour_ts, pending).await {
                Ok(new_market_id) => {
                    info!(market_id = new_market_id, "Oracle tick succeeded — awaiting next hour");
                    self.pending_market_id = Some(new_market_id);
                }
                Err(e) => {
                    error!(error = %e, "Oracle tick failed — will retry next hour");
                    // pending_market_id intentionally preserved: retry resolve next tick.
                }
            }

            // Sleep until the next hour boundary plus the grace period.
            let wait = secs_until_next_hour();
            sleep(Duration::from_secs(wait.max(1) + GRACE_SECS)).await;
        }
    }

    /// Query `PredictionMarket.sol` to initialise `market_id_counter` and
    /// detect any unresolved market left by a previous process restart.
    async fn sync_from_chain(&mut self) -> ClobResult<()> {
        info!("Syncing market oracle state from Horizen EVM");

        // Call `marketCount()` — selector = keccak256("marketCount()")[:4]
        let selector = &keccak256(b"marketCount()")[..4];
        let result = self.provider.call(
            &ethers::types::transaction::eip2718::TypedTransaction::Legacy(
                ethers::types::TransactionRequest::new()
                    .to(self.factory_address)
                    .data(Bytes::from(selector.to_vec()))
            ),
            None,
        ).await.map_err(|e| ClobError::Internal(format!("marketCount() call failed: {e}")))?;

        let count = if result.len() >= 32 {
            U256::from_big_endian(&result[..32]).as_u64()
        } else {
            0u64
        };
        self.market_id_counter = count;
        info!(on_chain_count = count, "On-chain market count read");

        if count == 0 {
            self.pending_market_id = None;
            return Ok(());
        }

        let last_id = count - 1;
        let resolved = self.is_market_resolved(last_id).await.unwrap_or(false);

        if !resolved {
            info!(market_id = last_id, "Unresolved market detected — will resolve at next tick");
            self.pending_market_id = Some(last_id);
        } else {
            self.pending_market_id = None;
        }

        Ok(())
    }

    // ─── Single tick ─────────────────────────────────────────────────────────

    async fn tick(
        &mut self,
        prev_hour_start: u64,
        now_ts: u64,
        next_hour_ts: u64,
        pending_market_id: Option<u64>,
    ) -> ClobResult<u64> {
        let create_market_close = self
            .fetch_pyth_price("BTC", prev_hour_start)
            .await
            .map_err(|e| ClobError::Internal(format!("Pyth fetch failed: {e}")))?;
        let strike_price = decimal_price_to_u128(create_market_close).ok_or_else(|| {
            ClobError::Internal(format!(
                "Pyth returned invalid strike price value: {}",
                create_market_close
            ))
        })?;

        // 2. Resolve the previous market if there is one.
        if let Some(prev_id) = pending_market_id {
            match self.resolve_pending_market(prev_id, prev_hour_start, now_ts).await {
                Ok(Some(tx)) => info!(market_id = prev_id, tx_hash = %tx, "Market resolved on-chain"),
                Ok(None) => info!(market_id = prev_id, "Market resolution deferred under oracle policy"),
                Err(e) => warn!(market_id = prev_id, error = %e, "Failed to resolve market"),
            }
        }

        // 3. Create a new market for the upcoming hour.
        //    questionHash = keccak256(abi.encode(next_hour_ts)) — front-ends reconstruct:
        //    "Will BTC close above $strike at Unix {expiry_ts}?"
        let market_id = self.market_id_counter;
        let question_hash: [u8; 32] = keccak256(
            &encode(&[Token::Uint(U256::from(next_hour_ts))])
        );

        let tx_hash = self.create_market(question_hash, strike_price, next_hour_ts).await
            .map_err(|e| ClobError::Internal(format!("createMarket failed: {e}")))?;

        info!(
            market_id,
            strike_price,
            expiry_ts = next_hour_ts,
            tx_hash = %tx_hash,
            "New prediction market created on-chain"
        );

        self.market_id_counter += 1;
        Ok(market_id)
    }

    // ─── EVM contract helpers ─────────────────────────────────────────────────

    /// Call `createMarket(bytes32 questionHash, uint128 strikePrice, uint64 expiryTs)`.
    async fn create_market(
        &self,
        question_hash: [u8; 32],
        strike_price: u128,
        expiry_ts: u64,
    ) -> ClobResult<String> {
        // selector: keccak256("createMarket(bytes32,uint128,uint64)")[..4]
        let selector = &keccak256(b"createMarket(bytes32,uint128,uint64)")[..4];
        let tokens = vec![
            Token::FixedBytes(question_hash.to_vec()),
            Token::Uint(U256::from(strike_price)),
            Token::Uint(U256::from(expiry_ts)),
        ];
        let data = Bytes::from([selector, encode(&tokens).as_slice()].concat());
        self.relayer.send_tx(self.factory_address, data).await
    }

    /// Call `resolveMarket(uint64 marketId, uint128 finalPrice)`.
    async fn resolve_market(&self, market_id: u64, final_price: u128) -> ClobResult<String> {
        let selector = &keccak256(b"resolveMarket(uint64,uint128)")[..4];
        let tokens = vec![
            Token::Uint(U256::from(market_id)),
            Token::Uint(U256::from(final_price)),
        ];
        let data = Bytes::from([selector, encode(&tokens).as_slice()].concat());
        self.relayer.send_tx(self.factory_address, data).await
    }

    async fn resolve_pending_market(
        &self,
        market_id: u64,
        expiry_ts: u64,
        now_ts: u64,
    ) -> ClobResult<Option<String>> {
        let market_key = market_id.to_string();
        let strike_price = self.get_market_strike_price(market_id).await?;
        let strike_decimal = scaled_u128_to_decimal(strike_price);
        let primary_price = self.fetch_pyth_price("BTC", expiry_ts).await.ok();
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
        // getMarket(uint64) returns the full Market struct; strikePrice is the second field (u128).
        // Simpler: call the individual public getter — markets(uint64) returns the struct.
        // We call `getMarket(uint64)` and decode strikePrice from offset 32 (second 32-byte slot).
        let selector = &keccak256(b"getMarket(uint64)")[..4];
        let data = Bytes::from([
            selector,
            encode(&[Token::Uint(U256::from(market_id))]).as_slice(),
        ].concat());
        let result = self.call_view(data).await?;
        if result.len() < 64 {
            return Ok(0);
        }
        // Market struct ABI layout: questionHash(bytes32), strikePrice(uint128), ...
        // strikePrice occupies slot 1 (bytes 32..64).
        Ok(U256::from_big_endian(&result[32..64]).as_u128())
    }

    async fn is_market_resolved(&self, market_id: u64) -> ClobResult<bool> {
        // `isResolved(uint64 marketId) returns (bool)`
        let selector = &keccak256(b"isResolved(uint64)")[..4];
        let data = Bytes::from([
            selector,
            encode(&[Token::Uint(U256::from(market_id))]).as_slice(),
        ].concat());
        let result = self.call_view(data).await?;
        Ok(result.last().copied().unwrap_or(0) != 0)
    }

    async fn is_market_invalidated(&self, market_id: u64) -> ClobResult<bool> {
        // `isInvalidated(uint64 marketId) returns (bool)`
        let selector = &keccak256(b"isInvalidated(uint64)")[..4];
        let data = Bytes::from([
            selector,
            encode(&[Token::Uint(U256::from(market_id))]).as_slice(),
        ].concat());
        let result = self.call_view(data).await?;
        Ok(result.last().copied().unwrap_or(0) != 0)
    }

    /// Low-level eth_call to the PredictionMarket contract.
    async fn call_view(&self, data: Bytes) -> ClobResult<ethers::types::Bytes> {
        self.provider
            .call(
                &ethers::types::transaction::eip2718::TypedTransaction::Legacy(
                    ethers::types::TransactionRequest::new()
                        .to(self.factory_address)
                        .data(data)
                ),
                None,
            )
            .await
            .map_err(|e| ClobError::Internal(format!("eth_call failed: {e}")))
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

// ─── Free helpers ────────────────────────────────────────────────────────────

/// Current UNIX timestamp in seconds.
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Seconds until the next whole-hour UTC boundary.
fn secs_until_next_hour() -> u64 {
    let now = unix_now();
    let secs_past_hour = now % 3600;
    if secs_past_hour == 0 {
        0
    } else {
        3600 - secs_past_hour
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

