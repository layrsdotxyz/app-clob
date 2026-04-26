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
};
use rust_decimal::Decimal;
use std::sync::Arc;
use uuid::Uuid;

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
}

impl SettlementEngine {
    pub fn new(
        store: Arc<RedisStore>,
        database: Option<Arc<Database>>,
        maker_fee_bps: u16,
        taker_fee_bps: u16,
        balance_service: Arc<BalanceService>,
    ) -> Self {
        Self { store, database, maker_fee_bps, taker_fee_bps, balance_service }
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

        // Update market stats
        self.store.update_market_stats(trade).await?;

        // Persist trade + fills to PostgreSQL (write-behind; log on failure, never abort trade)
        if let Some(db) = &self.database {
            if let Err(e) = db.save_trade(trade).await {
                tracing::error!(trade_id = %trade.id, error = %e, "Failed to persist trade to DB");
            }
            if let Err(e) = db.save_fill(maker_fill).await {
                tracing::error!(fill_id = %maker_fill.id, error = %e, "Failed to persist maker fill to DB");
            }
            if let Err(e) = db.save_fill(taker_fill).await {
                tracing::error!(fill_id = %taker_fill.id, error = %e, "Failed to persist taker fill to DB");
            }
        }

        // Update user balances
        self.update_balances_for_trade(trade, maker_fill, taker_fill).await?;

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

    /// Rollback a trade (used for FOK cancellation — credits both sides back).
    pub async fn rollback_trade(&self, trade: &Trade) -> ClobResult<()> {
        let maker_cost = trade.price * trade.size * (Decimal::ONE + Decimal::from(self.maker_fee_bps) / Decimal::from(10_000));
        let taker_cost = trade.price * trade.size * (Decimal::ONE + Decimal::from(self.taker_fee_bps) / Decimal::from(10_000));
        self.balance_service.credit(&trade.maker_user_id, &trade.market_id, maker_cost);
        self.balance_service.credit(&trade.taker_user_id, &trade.market_id, taker_cost);
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
        self.release_balance(&order.user_id, &order.market_id, notional + fee).await
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

        let (maker_pot_low, maker_pot_high) = to_low_high(maker_fill.size * maker_fill.price);
        let (maker_fee_low, maker_fee_high) = to_low_high(maker_fill.fee);
        let (taker_pot_low, taker_pot_high) = to_low_high(taker_fill.size * taker_fill.price);
        let (taker_fee_low, taker_fee_high) = to_low_high(taker_fill.fee);
        let (payout_units_low, payout_units_high) = to_low_high(maker_fill.size);

        // Determine whether each side is buying YES (Buy) or YES-inverse (Sell).
        let maker_position_side = matches!(maker_order.side, OrderSide::Buy);
        let taker_position_side = matches!(taker_order.side, OrderSide::Buy);

        let both_have_witness =
            maker_order.note_witness.is_some() && taker_order.note_witness.is_some();
        let settlement_status = if both_have_witness {
            "pending_proof_generation"
        } else {
            "waiting_for_proof"
        };

        let vault_address = std::env::var("PM_VAULT_ADDRESS").unwrap_or_default();

        let maker_leg = PredictionMarketSettlementLeg {
            leg_role: "maker".to_string(),
            order_id: maker_order.id.to_string(),
            user_id: maker_order.user_id.clone(),
            side: maker_order.side.clone(),
            fill_size: maker_fill.size.to_string(),
            fill_price: maker_fill.price.to_string(),
            fee_amount: maker_fill.fee.to_string(),
            market_id_onchain,
            position_side: maker_position_side,
            source_fill_index: 0,
            proof_input: maker_order
                .note_witness
                .clone()
                .unwrap_or(serde_json::Value::Object(Default::default())),
            // Nullifiers come from the circuit's public output — "0x0" until proof runs.
            spent_note_nullifier_low: "0x0".to_string(),
            spent_note_nullifier_high: "0x0".to_string(),
            pot_contribution_low: maker_pot_low,
            pot_contribution_high: maker_pot_high,
            position_payout_units_low: payout_units_low.clone(),
            position_payout_units_high: payout_units_high.clone(),
            trade_fee_amount_low: maker_fee_low,
            trade_fee_amount_high: maker_fee_high,
            vault_address: vault_address.clone(),
            proof_job_id: None,
            relay_tx_hash: None,
            status: "pending".to_string(),
            last_error: None,
        };

        let taker_leg = PredictionMarketSettlementLeg {
            leg_role: "taker".to_string(),
            order_id: taker_order.id.to_string(),
            user_id: taker_order.user_id.clone(),
            side: taker_order.side.clone(),
            fill_size: taker_fill.size.to_string(),
            fill_price: taker_fill.price.to_string(),
            fee_amount: taker_fill.fee.to_string(),
            market_id_onchain,
            position_side: taker_position_side,
            source_fill_index: 1,
            proof_input: taker_order
                .note_witness
                .clone()
                .unwrap_or(serde_json::Value::Object(Default::default())),
            spent_note_nullifier_low: "0x0".to_string(),
            spent_note_nullifier_high: "0x0".to_string(),
            pot_contribution_low: taker_pot_low,
            pot_contribution_high: taker_pot_high,
            position_payout_units_low: payout_units_low,
            position_payout_units_high: payout_units_high,
            trade_fee_amount_low: taker_fee_low,
            trade_fee_amount_high: taker_fee_high,
            vault_address: vault_address.clone(),
            proof_job_id: None,
            relay_tx_hash: None,
            status: "pending".to_string(),
            last_error: None,
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
            // Note nullifiers are populated from proof output, not known at job creation.
            maker_note_nullifier_low: "0x0".to_string(),
            maker_note_nullifier_high: "0x0".to_string(),
            taker_note_nullifier_low: "0x0".to_string(),
            taker_note_nullifier_high: "0x0".to_string(),
            maker_fill_size: maker_fill.size.to_string(),
            taker_fill_size: taker_fill.size.to_string(),
            price: trade.price.to_string(),
            maker_fee: maker_fill.fee.to_string(),
            taker_fee: taker_fill.fee.to_string(),
            settlement_status: settlement_status.to_string(),
            relayer_configured: !std::env::var("PM_RELAYER_PRIVATE_KEY")
                .unwrap_or_default()
                .is_empty(),
            vault_address,
            legs: vec![maker_leg, taker_leg],
            proof_job_id: None,
            settlement_txs: vec![],
            relayed_leg_count: 0,
            last_error: None,
        };

        let redis_key = format!("{}{}", PM_SETTLEMENT_JOB_PREFIX, job_id);
        self.store
            .set(&redis_key, &serde_json::to_string(&job)?)
            .await?;

        // Only queue for processing immediately if we have the witness data.
        if both_have_witness {
            self.store.push_queue(PM_SETTLEMENT_QUEUE, &job_id).await?;
            tracing::info!(
                job_id = %job_id,
                trade_id = %trade.id,
                "PM settlement job created and queued (witness provided)"
            );
        } else {
            tracing::info!(
                job_id = %job_id,
                trade_id = %trade.id,
                "PM settlement job created, awaiting client witness"
            );
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

        tracing::debug!(
            trade_id = %trade.id,
            maker_cost = %maker_cost,
            taker_cost = %taker_cost,
            "Balances updated for trade"
        );
        Ok(())
    }
}
