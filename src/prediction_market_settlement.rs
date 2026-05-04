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
    /// EVM treasury contract address for this leg's order. Routes the settleFill
    /// call to the correct on-chain treasury. Empty → use the PM treasury fallback.
    #[serde(default)]
    pub vault_address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_job_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relay_tx_hash: Option<String>,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// proof_observability record ID for debugging bb execute/prove failures.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_attempt_id: Option<String>,
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
    /// EVM treasury contract address for this job (from the order's compatibility field).
    /// Used for the single-proof (non-leg) settlement path.
    /// Empty → fall back to the PM treasury env vars.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::OrderSide;

    fn sample_leg() -> PredictionMarketSettlementLeg {
        PredictionMarketSettlementLeg {
            leg_role: "maker".to_string(),
            order_id: "order-abc".to_string(),
            user_id: "0xUser".to_string(),
            side: OrderSide::Buy,
            fill_size: "100".to_string(),
            fill_price: "50".to_string(),
            fee_amount: "1".to_string(),
            market_id_onchain: 1,
            position_side: true,
            source_fill_index: 0,
            proof_input: serde_json::Value::Null,
            spent_note_nullifier_low: "0".to_string(),
            spent_note_nullifier_high: "0".to_string(),
            pot_contribution_low: "0".to_string(),
            pot_contribution_high: "0".to_string(),
            position_payout_units_low: "0".to_string(),
            position_payout_units_high: "0".to_string(),
            trade_fee_amount_low: "0".to_string(),
            trade_fee_amount_high: "0".to_string(),
            vault_address: String::new(),
            proof_job_id: None,
            relay_tx_hash: None,
            status: "pending".to_string(),
            last_error: None,
            proof_attempt_id: None,
        }
    }

    fn sample_job() -> PredictionMarketSettlementJob {
        PredictionMarketSettlementJob {
            job_id: "job-123".to_string(),
            trade_id: "trade-456".to_string(),
            market_id: "mkt-1".to_string(),
            maker_order_id: "maker-order".to_string(),
            taker_order_id: "taker-order".to_string(),
            maker_user_id: "0xMaker".to_string(),
            taker_user_id: "0xTaker".to_string(),
            maker_side: OrderSide::Buy,
            taker_side: OrderSide::Sell,
            maker_note_nullifier_low: "0".to_string(),
            maker_note_nullifier_high: "0".to_string(),
            taker_note_nullifier_low: "0".to_string(),
            taker_note_nullifier_high: "0".to_string(),
            maker_fill_size: "100".to_string(),
            taker_fill_size: "100".to_string(),
            price: "50".to_string(),
            maker_fee: "1".to_string(),
            taker_fee: "1".to_string(),
            settlement_status: "waiting_for_proof".to_string(),
            relayer_configured: false,
            vault_address: String::new(),
            legs: vec![],
            proof_job_id: None,
            settlement_txs: vec![],
            relayed_leg_count: 0,
            last_error: None,
        }
    }

    #[test]
    fn queue_constant_value() {
        assert_eq!(PM_SETTLEMENT_QUEUE, "pm:settlement:queue");
    }

    #[test]
    fn job_prefix_constant_value() {
        assert_eq!(PM_SETTLEMENT_JOB_PREFIX, "pm:settlement:job:");
    }

    #[test]
    fn redis_key_has_correct_format() {
        let job = sample_job();
        assert_eq!(job.redis_key(), "pm:settlement:job:job-123");
    }

    #[test]
    fn redis_key_uses_job_id_field() {
        let mut job = sample_job();
        job.job_id = "unique-xyz".to_string();
        assert!(job.redis_key().ends_with("unique-xyz"));
        assert!(job.redis_key().starts_with(PM_SETTLEMENT_JOB_PREFIX));
    }

    #[test]
    fn job_serde_roundtrip() {
        let job = sample_job();
        let s = serde_json::to_string(&job).unwrap();
        let d: PredictionMarketSettlementJob = serde_json::from_str(&s).unwrap();
        assert_eq!(d.job_id, job.job_id);
        assert_eq!(d.market_id, job.market_id);
        assert_eq!(d.settlement_status, job.settlement_status);
        assert_eq!(d.relayed_leg_count, 0);
    }

    #[test]
    fn leg_serde_roundtrip() {
        let leg = sample_leg();
        let s = serde_json::to_string(&leg).unwrap();
        let d: PredictionMarketSettlementLeg = serde_json::from_str(&s).unwrap();
        assert_eq!(d.leg_role, leg.leg_role);
        assert_eq!(d.order_id, leg.order_id);
        assert_eq!(d.status, leg.status);
        assert_eq!(d.position_side, true);
    }

    #[test]
    fn job_optional_fields_omitted_when_none() {
        let job = sample_job();
        let v: serde_json::Value = serde_json::to_value(&job).unwrap();
        assert!(v.get("proof_job_id").is_none(), "proof_job_id should be absent");
        assert!(v.get("last_error").is_none(), "last_error should be absent");
    }

    #[test]
    fn leg_optional_fields_omitted_when_none() {
        let leg = sample_leg();
        let v: serde_json::Value = serde_json::to_value(&leg).unwrap();
        assert!(v.get("proof_job_id").is_none());
        assert!(v.get("relay_tx_hash").is_none());
        assert!(v.get("last_error").is_none());
    }

    #[test]
    fn job_with_legs_serde_roundtrip() {
        let mut job = sample_job();
        job.legs = vec![sample_leg()];
        let s = serde_json::to_string(&job).unwrap();
        let d: PredictionMarketSettlementJob = serde_json::from_str(&s).unwrap();
        assert_eq!(d.legs.len(), 1);
        assert_eq!(d.legs[0].leg_role, "maker");
    }

    #[test]
    fn job_settlement_txs_roundtrip() {
        let mut job = sample_job();
        job.settlement_txs = vec!["0xabc".to_string(), "0xdef".to_string()];
        let s = serde_json::to_string(&job).unwrap();
        let d: PredictionMarketSettlementJob = serde_json::from_str(&s).unwrap();
        assert_eq!(d.settlement_txs, vec!["0xabc", "0xdef"]);
    }

    #[test]
    fn vault_address_defaults_to_empty_string() {
        let raw = r#"{
            "job_id":"j","trade_id":"t","market_id":"m",
            "maker_order_id":"mo","taker_order_id":"to",
            "maker_user_id":"u1","taker_user_id":"u2",
            "maker_side":"BUY","taker_side":"SELL",
            "maker_note_nullifier_low":"0","maker_note_nullifier_high":"0",
            "taker_note_nullifier_low":"0","taker_note_nullifier_high":"0",
            "maker_fill_size":"0","taker_fill_size":"0",
            "price":"0","maker_fee":"0","taker_fee":"0",
            "settlement_status":"pending","relayer_configured":false
        }"#;
        let d: PredictionMarketSettlementJob = serde_json::from_str(raw).unwrap();
        assert_eq!(d.vault_address, "");
        assert!(d.legs.is_empty());
        assert!(d.settlement_txs.is_empty());
        assert_eq!(d.relayed_leg_count, 0);
    }
}
