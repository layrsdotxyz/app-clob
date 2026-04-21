use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::models::OrderSide;

pub const PM_SETTLEMENT_QUEUE: &str = "pm:settlement:queue";
pub const PM_SETTLEMENT_JOB_PREFIX: &str = "pm:settlement:job:";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PredictionMarketSettlementLeg {
    pub leg_role: String,
    pub order_id: String,
    pub user_id: String,
    pub side: OrderSide,
    pub fill_size: String,
    pub fill_price: String,
    pub fee_amount: String,
    pub market_id_onchain: u64,
    pub position_side: bool,
    pub source_fill_index: usize,
    pub proof_input: Value,
    pub spent_note_nullifier_low: String,
    pub spent_note_nullifier_high: String,
    pub pot_contribution_low: String,
    pub pot_contribution_high: String,
    pub position_payout_units_low: String,
    pub position_payout_units_high: String,
    pub trade_fee_amount_low: String,
    pub trade_fee_amount_high: String,
    /// EVM vault contract address for this leg's order. Routes the settleFill
    /// call to the correct on-chain vault. Empty → use PM_VAULT_ADDRESS fallback.
    #[serde(default)]
    pub vault_address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_job_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relay_tx_hash: Option<String>,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PredictionMarketSettlementJob {
    pub job_id: String,
    pub trade_id: String,
    pub market_id: String,
    pub maker_order_id: String,
    pub taker_order_id: String,
    pub maker_user_id: String,
    pub taker_user_id: String,
    pub maker_side: OrderSide,
    pub taker_side: OrderSide,
    pub maker_note_nullifier_low: String,
    pub maker_note_nullifier_high: String,
    pub taker_note_nullifier_low: String,
    pub taker_note_nullifier_high: String,
    pub maker_fill_size: String,
    pub taker_fill_size: String,
    pub price: String,
    pub maker_fee: String,
    pub taker_fee: String,
    pub settlement_status: String,
    pub relayer_configured: bool,
    /// EVM vault contract address for this job (from the order's vault_address).
    /// Used for the single-proof (non-leg) settlement path.
    /// Empty → fall back to PM_VAULT_ADDRESS env var.
    #[serde(default)]
    pub vault_address: String,
    #[serde(default)]
    pub legs: Vec<PredictionMarketSettlementLeg>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_job_id: Option<String>,
    #[serde(default)]
    pub settlement_txs: Vec<String>,
    #[serde(default)]
    pub relayed_leg_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

impl PredictionMarketSettlementJob {
    pub fn redis_key(&self) -> String {
        format!("{}{}", PM_SETTLEMENT_JOB_PREFIX, self.job_id)
    }
}
