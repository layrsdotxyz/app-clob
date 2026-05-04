use crate::{
    balance_service::BalanceService,
    database::Database,
    error::{ClobError, ClobResult},
    models::*,
    prediction_market_settlement::{
        PredictionMarketSettlementJob, PredictionMarketSettlementLeg, PM_SETTLEMENT_JOB_PREFIX,
        PM_SETTLEMENT_QUEUE,
    },
    redis_store::RedisStore,
    websocket::WebSocketManager,
};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::task::JoinHandle;
use uuid::Uuid;

const TRADE_PERSIST_QUEUE_PENDING: &str = "trade:persist:queue:pending";
const TRADE_PERSIST_QUEUE_RETRY: &str = "trade:persist:queue:retry";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TradePersistenceJob {
    trade: Trade,
    maker_fill: Fill,
    taker_fill: Fill,
    attempt: u32,
}

/// Return an 8-character keccak256-based alias for a user ID.
///
/// Used exclusively in tracing/log fields so logs never contain raw wallet
/// addresses or user identifiers (G16). The alias is deterministic within a
/// process run — it does NOT use a secret key, so it provides pseudonymity
/// against casual log inspection, not cryptographic unlinkability.
/// For operator-level audit, full IDs are stored in PostgreSQL only.
pub fn user_alias(user_id: &str) -> String {
    use tiny_keccak::{Hasher, Keccak};
    let mut k = Keccak::v256();
    k.update(user_id.as_bytes());
    let mut out = [0u8; 32];
    k.finalize(&mut out);
    format!("{:02x}{:02x}{:02x}{:02x}", out[0], out[1], out[2], out[3])
}

pub struct SettlementEngine {
    store: Arc<RedisStore>,
    database: Option<Arc<Database>>,
    maker_fee_bps: u16,
    taker_fee_bps: u16,
    balance_service: Arc<BalanceService>,
    ws_manager: Arc<WebSocketManager>,
}

impl SettlementEngine {
    pub fn new(
        store: Arc<RedisStore>,
        database: Option<Arc<Database>>,
        maker_fee_bps: u16,
        taker_fee_bps: u16,
        balance_service: Arc<BalanceService>,
        ws_manager: Arc<WebSocketManager>,
    ) -> Self {
        Self { store, database, maker_fee_bps, taker_fee_bps, balance_service, ws_manager }
    }

    /// Read the current in-memory balance for `user_id` and push it to their WS channel.
    /// Called after every balance mutation so connected clients see instant updates.
    fn push_balance_update(&self, user_id: &str) {
        let total = self.balance_service.get_total_balance(user_id, "USDC");
        let reserved = self.balance_service.get_reserved_balance(user_id, "USDC");
        let available = self.balance_service.get_available_balance(user_id, "USDC");
        self.ws_manager.send_balance_update(
            user_id,
            &total.to_string(),
            &reserved.to_string(),
            &available.to_string(),
        );
    }

    /// Check that a valid balance proof soft-lock exists for the given nullifier hash (G11).
    ///
    /// The soft-lock is written by `POST /v1/balance/proof` with a 5-minute TTL.
    /// Returns `Err(InsufficientBalance)` when no lock is found, meaning the note's
    /// balance was never proven or the proof window has already expired.
    pub async fn check_balance_with_proof(&self, note_nullifier_hash: &str) -> ClobResult<()> {
        let key = format!("balance_proof:{}", note_nullifier_hash);
        match self.store.get_optional(&key).await? {
            Some(_) => Ok(()),
            None => Err(ClobError::InsufficientBalance {
                required: rust_decimal::Decimal::ZERO,
                available: rust_decimal::Decimal::ZERO,
            }),
        }
    }

    /// Check if user has sufficient balance for order
    pub async fn check_balance(
        &self,
        user_id: &str,
        market_id: &str,
        order: &Order,
    ) -> ClobResult<()> {
        let required = self.calculate_required_balance(order);
        let available = self.get_user_balance(user_id, market_id).await?;
        
        if available < required {
            return Err(ClobError::InsufficientBalance {
                required,
                available,
            });
        }
        
        // Reserve balance for order
        self.reserve_balance(user_id, market_id, required).await?;
        self.push_balance_update(user_id);

        Ok(())
    }

    /// Calculate required balance for order (size * price + estimated fees)
    fn calculate_required_balance(&self, order: &Order) -> Decimal {
        let notional = order.size * order.price;
        let fee = self.calculate_fee(order.size, order.price, false);
        notional + fee
    }

    /// Calculate fee for a fill
    pub fn calculate_fee(&self, size: Decimal, price: Decimal, is_maker: bool) -> Decimal {
        let notional = size * price;
        let fee_bps = if is_maker { self.maker_fee_bps } else { self.taker_fee_bps };
        notional * Decimal::from(fee_bps) / Decimal::from(10_000)
    }

    /// Settle a trade (update balances, record trade)
    pub async fn settle_trade(
        &self,
        trade: &Trade,
        maker_fill: &Fill,
        taker_fill: &Fill,
    ) -> ClobResult<()> {
        // Save trade to Redis (primary fast path)
        self.store.save_trade(trade).await?;

        if let Err(error) = self.update_balances_for_trade(trade, maker_fill, taker_fill).await {
            let _ = self.store.delete_trade(trade).await;
            return Err(error);
        }

        if let Err(error) = self.enqueue_trade_persistence(trade, maker_fill, taker_fill).await {
            let _ = self.rollback_trade(trade).await;
            let _ = self.store.delete_trade(trade).await;
            return Err(error);
        }

        if let Err(error) = self.store.update_market_stats(trade).await {
            tracing::error!(trade_id = %trade.id, error = %error, "Failed to update market stats after trade settlement");
        }

        // Record the buyer's long position for resolution payout (non-fatal).
        if let Err(error) = self.record_position_for_trade(trade).await {
            tracing::warn!(trade_id = %trade.id, error = %error, "Failed to record position — payout may be skipped for this fill");
        }

        tracing::info!(
            trade_id = %trade.id,
            maker_alias = %user_alias(&trade.maker_user_id),
            taker_alias = %user_alias(&trade.taker_user_id),
            price = %trade.price,
            size = %trade.size,
            "Trade settled"
        );

        Ok(())
    }

    /// Record the buyer's position in Redis for payout distribution at market resolution.
    ///
    /// Only applies to oracle-service binary sub-markets (suffix "-YES" or "-NO").
    /// The buyer is: the taker when trade.side == Buy, the maker when trade.side == Sell.
    async fn record_position_for_trade(&self, trade: &Trade) -> ClobResult<()> {
        let (parent_id, side) = if let Some(s) = trade.market_id.strip_suffix("-YES") {
            (s, "yes")
        } else if let Some(s) = trade.market_id.strip_suffix("-NO") {
            (s, "no")
        } else {
            return Ok(());
        };

        let pos_key = format!("positions:{}:{}", parent_id, side);

        let buyer_id = match trade.side {
            OrderSide::Buy => &trade.taker_user_id,
            OrderSide::Sell => &trade.maker_user_id,
        };

        self.store.increment_position(&pos_key, buyer_id, trade.size).await
    }

    pub fn start_trade_persistence_worker(self: Arc<Self>) -> Option<JoinHandle<()>> {
        self.database.as_ref()?;

        Some(tokio::spawn(async move {
            loop {
                let payload = match self.store.pop_queue(TRADE_PERSIST_QUEUE_RETRY).await {
                    Ok(Some(payload)) => Some(payload),
                    Ok(None) => match self.store.pop_queue(TRADE_PERSIST_QUEUE_PENDING).await {
                        Ok(payload) => payload,
                        Err(error) => {
                            tracing::error!(error = %error, "Trade persistence worker failed to pop pending queue entry");
                            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                            continue;
                        }
                    },
                    Err(error) => {
                        tracing::error!(error = %error, "Trade persistence worker failed to pop retry queue entry");
                        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                        continue;
                    }
                };

                let Some(payload) = payload else {
                    tokio::time::sleep(tokio::time::Duration::from_millis(250)).await;
                    continue;
                };

                let mut job: TradePersistenceJob = match serde_json::from_str(&payload) {
                    Ok(job) => job,
                    Err(error) => {
                        tracing::error!(error = %error, payload = %payload, "Trade persistence worker received invalid payload");
                        continue;
                    }
                };

                match self.persist_trade_bundle(&job).await {
                    Ok(()) => {
                        tracing::debug!(trade_id = %job.trade.id, attempt = job.attempt, "Trade persistence worker flushed trade + fills to DB");
                    }
                    Err(error) => {
                        job.attempt += 1;
                        let backoff_ms = 250u64.saturating_mul(1u64 << job.attempt.min(5));
                        tracing::warn!(
                            trade_id = %job.trade.id,
                            attempt = job.attempt,
                            backoff_ms,
                            error = %error,
                            "Trade persistence worker failed, requeueing"
                        );

                        tokio::time::sleep(tokio::time::Duration::from_millis(backoff_ms)).await;

                        match serde_json::to_string(&job) {
                            Ok(retry_payload) => {
                                if let Err(queue_error) = self
                                    .store
                                    .push_queue(TRADE_PERSIST_QUEUE_RETRY, &retry_payload)
                                    .await
                                {
                                    tracing::error!(
                                        trade_id = %job.trade.id,
                                        error = %queue_error,
                                        "Trade persistence worker failed to requeue payload"
                                    );
                                }
                            }
                            Err(serialize_error) => {
                                tracing::error!(
                                    trade_id = %job.trade.id,
                                    error = %serialize_error,
                                    "Trade persistence worker failed to serialize retry payload"
                                );
                            }
                        }
                    }
                }
            }
        }))
    }

    /// Rollback a trade (used for FOK cancellation — credits both sides back).
    pub async fn rollback_trade(&self, trade: &Trade) -> ClobResult<()> {
        let maker_cost = trade.price * trade.size * (Decimal::ONE + Decimal::from(self.maker_fee_bps) / Decimal::from(10_000));
        let taker_cost = trade.price * trade.size * (Decimal::ONE + Decimal::from(self.taker_fee_bps) / Decimal::from(10_000));
        self.balance_service.credit(&trade.maker_user_id, "USDC", maker_cost);
        self.balance_service.credit(&trade.taker_user_id, "USDC", taker_cost);
        self.push_balance_update(&trade.maker_user_id);
        self.push_balance_update(&trade.taker_user_id);
        tracing::debug!(
            trade_id = %trade.id,
            maker_alias = %user_alias(&trade.maker_user_id),
            taker_alias = %user_alias(&trade.taker_user_id),
            "Trade rolled back (FOK cancellation)"
        );
        Ok(())
    }

    /// Release reserved balance when an order is cancelled or expires (IOC/FOK).
    ///
    /// Uses `order.remaining` — not `order.size` — so that a partially-filled order
    /// only releases the unfilled portion rather than the original full reservation.
    pub async fn release_order_balance(&self, order: &Order) -> ClobResult<()> {
        let notional = order.remaining * order.price;
        let fee = self.calculate_fee(order.remaining, order.price, false);
        self.release_balance(&order.user_id, &order.market_id, notional + fee).await?;
        self.push_balance_update(&order.user_id);
        Ok(())
    }

    // ==================== PM Settlement Job Creation ====================

    /// Create and enqueue a `PredictionMarketSettlementJob` for a completed trade.
    ///
    /// Only runs for prediction-market trades (those with `market_id_uint` set).
    /// Each leg receives the user's circuit witness from `note_witness` on the
    /// order (if provided), which allows the snarkjs prover to generate the
    /// Groth16 proof for `private_transfer_settlement`.
    ///
    /// If neither order has a witness the job is stored with
    /// `settlement_status = "waiting_for_proof"` so that the client can supply
    /// the witness later via the `/v1/settlements/:job_id/witness` route.
    pub async fn enqueue_pm_settlement_job(
        &self,
        trade: &Trade,
        maker_order: &Order,
        taker_order: &Order,
        maker_fill: &Fill,
        taker_fill: &Fill,
    ) -> ClobResult<()> {
        // Only prediction-market trades carry a market_id_uint.
        let market_id_uint = match trade.market_id_uint {
            Some(m) => m,
            None => return Ok(()),
        };
        let market_id_onchain = market_id_uint.as_u64();

        let job_id = Uuid::new_v4().to_string();

        // For EVM ABI encoding, amounts are split into (low128, high128).
        // All realistic PM amounts fit in 128 bits so high == "0x0".
        fn to_low_high(d: Decimal) -> (String, String) {
            // Convert to u128 (saturating at max — actual amounts are well below 2^128).
            let raw = d
                .mantissa()
                .unsigned_abs()
                .min(u128::MAX as u128) as u128;
            (format!("0x{:x}", raw), "0x0".to_string())
        }

        // Only the party holding a ZK note (the real user) needs on-chain settlement.
        // The MM side is CLOB balance-service only — no note, no on-chain leg.
        let (user_order, user_fill, user_fill_index, user_role) =
            if taker_order.note_witness.is_some() {
                (taker_order, taker_fill, 1usize, "taker")
            } else if maker_order.note_witness.is_some() {
                (maker_order, maker_fill, 0usize, "maker")
            } else {
                // Neither side holds a ZK note — pure CLOB trade, no on-chain settlement.
                return Ok(());
            };

        let (user_pot_low, user_pot_high) = to_low_high(user_fill.size * user_fill.price);
        let (user_fee_low, user_fee_high) = to_low_high(user_fill.fee);
        let (payout_units_low, payout_units_high) = to_low_high(user_fill.size);
        let user_position_side = matches!(user_order.side, OrderSide::Buy);

        let vault_address = std::env::var("PM_TREASURY_ADDRESS")
            .or_else(|_| std::env::var("PREDICTION_MARKET_TREASURY_ADDRESS"))
            .or_else(|_| std::env::var("PM_VAULT_ADDRESS"))
            .or_else(|_| std::env::var("PREDICTION_MARKET_VAULT_ADDRESS"))
            .unwrap_or_default();

        let user_leg = PredictionMarketSettlementLeg {
            leg_role: user_role.to_string(),
            order_id: user_order.id.to_string(),
            user_id: user_order.user_id.clone(),
            side: user_order.side.clone(),
            fill_size: user_fill.size.to_string(),
            fill_price: user_fill.price.to_string(),
            fee_amount: user_fill.fee.to_string(),
            market_id_onchain,
            position_side: user_position_side,
            source_fill_index: user_fill_index,
            proof_input: user_order
                .note_witness
                .clone()
                .unwrap_or(serde_json::Value::Object(Default::default())),
            // Nullifiers come from the circuit's public output — "0x0" until proof runs.
            spent_note_nullifier_low: "0x0".to_string(),
            spent_note_nullifier_high: "0x0".to_string(),
            pot_contribution_low: user_pot_low,
            pot_contribution_high: user_pot_high,
            position_payout_units_low: payout_units_low,
            position_payout_units_high: payout_units_high,
            trade_fee_amount_low: user_fee_low,
            trade_fee_amount_high: user_fee_high,
            vault_address: vault_address.clone(),
            proof_job_id: None,
            relay_tx_hash: None,
            status: "pending".to_string(),
            last_error: None,
            proof_attempt_id: None,
        };

        let job = PredictionMarketSettlementJob {
            job_id: job_id.clone(),
            trade_id: trade.id.to_string(),
            market_id: trade.market_id.clone(),
            maker_order_id: maker_order.id.to_string(),
            taker_order_id: taker_order.id.to_string(),
            maker_user_id: maker_order.user_id.clone(),
            taker_user_id: taker_order.user_id.clone(),
            maker_side: maker_order.side.clone(),
            taker_side: taker_order.side.clone(),
            maker_note_nullifier_low: "0x0".to_string(),
            maker_note_nullifier_high: "0x0".to_string(),
            taker_note_nullifier_low: "0x0".to_string(),
            taker_note_nullifier_high: "0x0".to_string(),
            maker_fill_size: maker_fill.size.to_string(),
            taker_fill_size: taker_fill.size.to_string(),
            price: trade.price.to_string(),
            maker_fee: maker_fill.fee.to_string(),
            taker_fee: taker_fill.fee.to_string(),
            settlement_status: "pending_proof_generation".to_string(),
            relayer_configured: !std::env::var("PM_RELAYER_PRIVATE_KEY")
                .unwrap_or_default()
                .is_empty(),
            vault_address,
            legs: vec![user_leg],
            proof_job_id: None,
            settlement_txs: vec![],
            relayed_leg_count: 0,
            last_error: None,
        };

        let redis_key = format!("{}{}", PM_SETTLEMENT_JOB_PREFIX, job_id);
        self.store
            .set(&redis_key, &serde_json::to_string(&job)?)
            .await?;

        self.store.push_queue(PM_SETTLEMENT_QUEUE, &job_id).await?;
        tracing::info!(
            job_id = %job_id,
            trade_id = %trade.id,
            "PM settlement job created and queued"
        );

        // Store trade_id → job_id mapping so the worker can look up which job settled a trade
        let trade_job_key = format!("trade:settlement_job:{}", trade.id);
        if let Err(e) = self.store.set(&trade_job_key, &job_id).await {
            tracing::warn!(trade_id = %trade.id, error = %e, "Failed to store trade→settlement_job mapping");
        }

        Ok(())
    }

    // ==================== Balance Management ====================

    async fn get_user_balance(&self, user_id: &str, _market_id: &str) -> ClobResult<Decimal> {
        Ok(self.balance_service.get_available_balance(user_id, "USDC"))
    }

    async fn reserve_balance(
        &self,
        user_id: &str,
        _market_id: &str,
        amount: Decimal,
    ) -> ClobResult<()> {
        self.balance_service.reserve_balance(user_id, "USDC", amount)
    }

    async fn release_balance(
        &self,
        user_id: &str,
        _market_id: &str,
        amount: Decimal,
    ) -> ClobResult<()> {
        self.balance_service.release_balance(user_id, "USDC", amount)
    }

    async fn enqueue_trade_persistence(
        &self,
        trade: &Trade,
        maker_fill: &Fill,
        taker_fill: &Fill,
    ) -> ClobResult<()> {
        if self.database.is_none() {
            return Ok(());
        }

        let payload = serde_json::to_string(&TradePersistenceJob {
            trade: trade.clone(),
            maker_fill: maker_fill.clone(),
            taker_fill: taker_fill.clone(),
            attempt: 0,
        })?;

        self.store
            .push_queue(TRADE_PERSIST_QUEUE_PENDING, &payload)
            .await
    }

    async fn persist_trade_bundle(&self, job: &TradePersistenceJob) -> ClobResult<()> {
        let Some(db) = &self.database else {
            return Ok(());
        };

        db.save_trade(&job.trade).await?;
        db.save_fill(&job.maker_fill).await?;
        db.save_fill(&job.taker_fill).await?;
        Ok(())
    }

    async fn update_balances_for_trade(
        &self,
        trade: &Trade,
        maker_fill: &Fill,
        taker_fill: &Fill,
    ) -> ClobResult<()> {
        // Maker: release reserved (the order commitment), then debit the fill cost.
        // The reserved amount was size*price+fee; debit the actual fill cost+fee.
        let maker_cost = maker_fill.size * maker_fill.price + maker_fill.fee;
        self.balance_service.debit(&trade.maker_user_id, "USDC", maker_cost)?;

        // Taker: debit cost+fee (their reservation covers this).
        let taker_cost = taker_fill.size * taker_fill.price + taker_fill.fee;
        self.balance_service.debit(&trade.taker_user_id, "USDC", taker_cost)?;

        self.push_balance_update(&trade.maker_user_id);
        self.push_balance_update(&trade.taker_user_id);

        tracing::debug!(
            trade_id = %trade.id,
            maker_cost = %maker_cost,
            taker_cost = %taker_cost,
            "Balances updated for trade"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mini_redis::server;
    use rust_decimal_macros::dec;
    use tokio::sync::oneshot;

    async fn setup_settlement_engine(
        maker_fee_bps: u16,
        taker_fee_bps: u16,
    ) -> (SettlementEngine, Arc<BalanceService>, oneshot::Sender<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = oneshot::channel::<()>();

        tokio::spawn(async move {
            let _ = server::run(listener, async { let _ = rx.await; }).await;
        });

        let client = redis::Client::open(format!("redis://{}/", addr)).unwrap();
        let conn = redis::aio::ConnectionManager::new(client).await.unwrap();
        let store = Arc::new(RedisStore::new(conn));
        let balance_service = Arc::new(BalanceService::new(None));
        let engine = SettlementEngine::new(
            store,
            None,
            maker_fee_bps,
            taker_fee_bps,
            balance_service.clone(),
        );

        (engine, balance_service, tx)
    }

    #[tokio::test]
    async fn test_lifecycle_check_balance_reserves_notional_plus_taker_fee() {
        let (engine, balances, shutdown) = setup_settlement_engine(0, 20).await;
        balances.deposit("alice", "USDC", dec!(1000));

        let order = Order::new(
            "alice".to_string(),
            "BTC-1H".to_string(),
            OrderSide::Buy,
            OrderType::Limit,
            TimeInForce::Gtc,
            dec!(0.50),
            dec!(100),
        );

        engine.check_balance("alice", "BTC-1H", &order).await.unwrap();

        assert_eq!(balances.get_total_balance("alice", "USDC"), dec!(1000));
        assert_eq!(balances.get_reserved_balance("alice", "USDC"), dec!(50.1));
        assert_eq!(balances.get_available_balance("alice", "USDC"), dec!(949.9));

        let _ = shutdown.send(());
    }

    #[tokio::test]
    async fn test_lifecycle_release_order_balance_uses_remaining_size_only() {
        let (engine, balances, shutdown) = setup_settlement_engine(0, 0).await;
        balances.deposit("alice", "USDC", dec!(1000));

        let mut order = Order::new(
            "alice".to_string(),
            "BTC-1H".to_string(),
            OrderSide::Buy,
            OrderType::Limit,
            TimeInForce::Gtc,
            dec!(1),
            dec!(100),
        );

        engine.check_balance("alice", "BTC-1H", &order).await.unwrap();
        order.filled = dec!(40);
        order.remaining = dec!(60);

        engine.release_order_balance(&order).await.unwrap();

        assert_eq!(balances.get_total_balance("alice", "USDC"), dec!(1000));
        assert_eq!(balances.get_reserved_balance("alice", "USDC"), dec!(40));
        assert_eq!(balances.get_available_balance("alice", "USDC"), dec!(960));

        let _ = shutdown.send(());
    }

    #[tokio::test]
    async fn test_lifecycle_fok_rollback_recredits_both_sides() {
        let (engine, balances, shutdown) = setup_settlement_engine(0, 0).await;
        balances.deposit("maker", "USDC", dec!(1000));
        balances.deposit("taker", "USDC", dec!(1000));
        balances.reserve_balance("maker", "USDC", dec!(50)).unwrap();
        balances.reserve_balance("taker", "USDC", dec!(50)).unwrap();
        balances.debit("maker", "USDC", dec!(50)).unwrap();
        balances.debit("taker", "USDC", dec!(50)).unwrap();

        let trade = Trade {
            id: Uuid::new_v4(),
            market_id: "BTC-1H".to_string(),
            maker_order_id: Uuid::new_v4(),
            taker_order_id: Uuid::new_v4(),
            maker_user_id: "maker".to_string(),
            taker_user_id: "taker".to_string(),
            side: OrderSide::Buy,
            price: dec!(1),
            size: dec!(50),
            timestamp: chrono::Utc::now(),
            maker_address: None,
            taker_address: None,
            market_id_uint: None,
            settlement_tx: None,
        };

        engine.rollback_trade(&trade).await.unwrap();

        assert_eq!(balances.get_total_balance("maker", "USDC"), dec!(1000));
        assert_eq!(balances.get_total_balance("taker", "USDC"), dec!(1000));
        assert_eq!(balances.get_reserved_balance("maker", "USDC"), dec!(0));
        assert_eq!(balances.get_reserved_balance("taker", "USDC"), dec!(0));

        let _ = shutdown.send(());
    }
}
