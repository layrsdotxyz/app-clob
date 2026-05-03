use std::sync::Arc;

use num_bigint::BigUint;
use num_traits::{Num, ToPrimitive};
use serde::Deserialize;
use serde_json::json;
use tokio::time::{interval, Duration};
use tracing::{info, warn};

use crate::{
    error::{ClobError, ClobResult},
    prediction_market_relayer::PredictionMarketRelayer,
    prediction_market_settlement::{PredictionMarketSettlementJob, PM_SETTLEMENT_JOB_PREFIX, PM_SETTLEMENT_QUEUE},
    proof_generation::{ProverJobStatus, ProverJobType, ProverPipeline, parse_honk_proof_from_output, low_high_hex_to_bytes32, parse_u128_hex},
    redis_store::RedisStore,
    websocket::WebSocketManager,
};

pub struct PredictionMarketSettlementWorker {
    store: Arc<RedisStore>,
    prover_pipeline: Arc<ProverPipeline>,
    relayer: Arc<PredictionMarketRelayer>,
    ws_manager: Arc<WebSocketManager>,
    poll_interval: Duration,
}

impl PredictionMarketSettlementWorker {
    pub fn new(
        store: Arc<RedisStore>,
        prover_pipeline: Arc<ProverPipeline>,
        relayer: Arc<PredictionMarketRelayer>,
        ws_manager: Arc<WebSocketManager>,
        poll_interval_secs: u64,
    ) -> Self {
        Self {
            store,
            prover_pipeline,
            relayer,
            ws_manager,
            poll_interval: Duration::from_secs(if poll_interval_secs == 0 { 2 } else { poll_interval_secs }),
        }
    }

    pub async fn start(&self) -> ClobResult<()> {
        info!(
            poll_interval_secs = self.poll_interval.as_secs(),
            "Prediction market settlement worker started"
        );

        let mut ticker = interval(self.poll_interval);
        loop {
            ticker.tick().await;

            if let Err(e) = self.claim_new_jobs().await {
                warn!(error = %e, "PM settlement worker failed while claiming jobs");
            }
            if let Err(e) = self.advance_jobs().await {
                warn!(error = %e, "PM settlement worker failed while advancing jobs");
            }
        }
    }

    async fn claim_new_jobs(&self) -> ClobResult<()> {
        loop {
            let Some(job_id) = self.store.pop_queue(PM_SETTLEMENT_QUEUE).await? else {
                return Ok(());
            };

            let Some(mut job) = self.load_job(&job_id).await? else {
                warn!(job_id = %job_id, "PM settlement job missing from Redis");
                continue;
            };

            if job.proof_job_id.is_some() || job.settlement_status != "pending_proof_generation" {
                continue;
            }

            if !job.legs.is_empty() {
                let mut submitted_any = false;
                for leg_index in 0..job.legs.len() {
                    if job.legs[leg_index].proof_job_id.is_some() {
                        continue;
                    }

                    let proof_input = job.legs[leg_index].proof_input.clone();
                    let leg_role = job.legs[leg_index].leg_role.clone();

                    match self
                        .prover_pipeline
                        .submit_job(
                            ProverJobType::PrivateTransferSettlement,
                            "pm_settlement",
                            &proof_input,
                        )
                        .await
                    {
                        Ok(proof_job) => {
                            submitted_any = true;
                            job.legs[leg_index].proof_job_id = Some(proof_job.job_id.clone());
                            job.legs[leg_index].status = "proof_pending".to_string();
                            job.legs[leg_index].last_error = None;
                            info!(
                                settlement_job_id = %job.job_id,
                                leg_role = %leg_role,
                                prover_job_id = %proof_job.job_id,
                                "PM settlement leg proof job submitted"
                            );
                        }
                        Err(e) => {
                            job.legs[leg_index].status = "proof_submission_failed".to_string();
                            job.legs[leg_index].last_error = Some(e.to_string());
                            job.settlement_status = "proof_submission_failed".to_string();
                            job.last_error = Some(e.to_string());
                            self.save_job(&job).await?;
                            warn!(
                                settlement_job_id = %job.job_id,
                                leg_role = %leg_role,
                                error = %e,
                                "Failed to submit PM settlement leg proof job"
                            );
                            submitted_any = false;
                            break;
                        }
                    }
                }

                if submitted_any {
                    job.settlement_status = summarize_job_status(&job);
                    job.last_error = None;
                    self.save_job(&job).await?;
                }
                continue;
            }

            // Settlement jobs are always created with a maker leg and a taker leg
            // (see settlement.rs). A job that reaches here with no legs can only exist
            // due to a malformed Redis record. Submitting trade metadata as proof input
            // would produce wrong ZK witnesses — the pm_settlement circuit expects
            // owner_key_hash, input_amount, nullifier, receiver_commitment, etc. —
            // and bb execute would fail with an opaque wrong-input error downstream.
            let err = ClobError::Internal(
                "settlement job has no legs — cannot generate ZK proof without per-leg circuit inputs"
                    .to_string(),
            );
            job.settlement_status = "proof_submission_failed".to_string();
            job.last_error = Some(err.to_string());
            self.save_job(&job).await?;
            warn!(
                settlement_job_id = %job.job_id,
                "PM settlement job has no legs; cannot generate ZK proof — marking failed"
            );
        }
    }

    async fn advance_jobs(&self) -> ClobResult<()> {
        for key in self.store.scan_keys(&format!("{}*", PM_SETTLEMENT_JOB_PREFIX)).await? {
            let Some(payload) = self.store.get_optional(&key).await? else {
                continue;
            };
            let mut job: PredictionMarketSettlementJob = serde_json::from_str(&payload)?;

            if !job.legs.is_empty() {
                for idx in 0..job.legs.len() {
                    let status = job.legs[idx].status.clone();
                    match status.as_str() {
                        "proof_pending" => self.handle_leg_proof_pending(&mut job, idx).await?,
                        "relay_pending" | "relay_retry_pending" => self.handle_leg_relay_pending(&mut job, idx).await?,
                        _ => {}
                    }
                }
                job.settlement_status = summarize_job_status(&job);
                job.relayed_leg_count = job
                    .legs
                    .iter()
                    .filter(|leg| leg.status == "settled")
                    .count();
                job.last_error = job
                    .legs
                    .iter()
                    .rev()
                    .find_map(|leg| leg.last_error.clone());
                self.save_job(&job).await?;
                continue;
            }

            match job.settlement_status.as_str() {
                "proof_pending" => self.handle_proof_pending(&mut job).await?,
                "relay_pending" | "relay_retry_pending" => self.handle_relay_pending(&mut job).await?,
                _ => {}
            }
        }
        Ok(())
    }

    async fn handle_leg_proof_pending(
        &self,
        job: &mut PredictionMarketSettlementJob,
        leg_index: usize,
    ) -> ClobResult<()> {
        let Some(proof_job_id) = job.legs[leg_index].proof_job_id.clone() else {
            job.legs[leg_index].status = "proof_submission_failed".to_string();
            job.legs[leg_index].last_error = Some("missing proof job id".to_string());
            return Ok(());
        };

        let Some(prover_job) = self.prover_pipeline.get_job(&proof_job_id).await? else {
            job.legs[leg_index].status = "proof_submission_failed".to_string();
            job.legs[leg_index].last_error = Some(format!("proof job {} not found", proof_job_id));
            return Ok(());
        };

        match prover_job.status {
            ProverJobStatus::Pending | ProverJobStatus::Running => Ok(()),
            ProverJobStatus::Failed => {
                job.legs[leg_index].status = "proof_failed".to_string();
                job.legs[leg_index].last_error = prover_job.last_error.clone();
                Ok(())
            }
            ProverJobStatus::Completed => {
                job.legs[leg_index].status = "relay_pending".to_string();
                job.legs[leg_index].last_error = None;
                self.handle_leg_relay_pending(job, leg_index).await
            }
        }
    }

    async fn handle_leg_relay_pending(
        &self,
        job: &mut PredictionMarketSettlementJob,
        leg_index: usize,
    ) -> ClobResult<()> {
        let Some(proof_job_id) = job.legs[leg_index].proof_job_id.clone() else {
            return Err(ClobError::Internal("missing proof job id for PM settlement leg relay".to_string()));
        };
        let Some(output) = self.prover_pipeline.get_output(&proof_job_id).await? else {
            return Err(ClobError::ProofGenerationFailed(format!(
                "proof output missing for job {}",
                proof_job_id
            )));
        };

        let proof = parse_honk_proof_from_output(&output)?;
        let leg = job.legs[leg_index].clone();
        let vault_override: Option<&str> = if leg.vault_address.trim().is_empty() {
            None
        } else {
            Some(leg.vault_address.trim())
        };
        let tx_hash = self
            .relayer
            .settle_fill(
                leg.market_id_onchain,
                leg.position_side,
                low_high_hex_to_bytes32(&leg.spent_note_nullifier_low, &leg.spent_note_nullifier_high)?,
                parse_u128_hex(&leg.pot_contribution_low, "pot_contribution")?,
                parse_u128_hex(&leg.position_payout_units_low, "position_payout_units")?,
                parse_u128_hex(&leg.trade_fee_amount_low, "trade_fee_amount")?,
                &proof,
                vault_override,
            )
            .await;

        match tx_hash {
            Ok(tx_hash) => {
                job.legs[leg_index].relay_tx_hash = Some(tx_hash.clone());
                job.legs[leg_index].status = "settled".to_string();
                job.legs[leg_index].last_error = None;
                if !job.settlement_txs.iter().any(|existing| existing == &tx_hash) {
                    job.settlement_txs.push(tx_hash.clone());
                }

                // --- Post-leg-settlement side effects (best-effort) ---
                let leg = &job.legs[leg_index];

                // 1. Notify vault-service about the new Merkle leaf for this leg's output note.
                let vault_url = std::env::var("VAULT_INTERNAL_URL").unwrap_or_default();
                if !vault_url.is_empty() {
                    let url = format!("{}/v1/merkle/note", vault_url.trim_end_matches('/'));
                    let leg_vault = leg.vault_address.clone();
                    let tx_clone = tx_hash.clone();
                    let leg_role_clone = leg.leg_role.clone();
                    let job_id_clone = job.job_id.clone();
                    tokio::spawn(async move {
                        let client = reqwest::Client::new();
                        let body = serde_json::json!({
                            "vault_address": leg_vault,
                            "tx_hash": tx_clone,
                        });
                        match client.post(&url).json(&body).send().await {
                            Ok(resp) if resp.status().is_success() => {
                                tracing::info!(
                                    settlement_job_id = %job_id_clone,
                                    leg_role = %leg_role_clone,
                                    "Notified vault-service of PM leg fill leaf"
                                );
                            }
                            Ok(resp) => {
                                tracing::warn!(
                                    settlement_job_id = %job_id_clone,
                                    leg_role = %leg_role_clone,
                                    status = %resp.status(),
                                    "vault-service merkle/note returned non-success for leg"
                                );
                            }
                            Err(e) => {
                                tracing::warn!(
                                    settlement_job_id = %job_id_clone,
                                    leg_role = %leg_role_clone,
                                    error = %e,
                                    "Failed to notify vault-service of PM leg fill leaf"
                                );
                            }
                        }
                    });
                }

                // 2. Broadcast WebSocket fill event for this leg's user.
                let user_id = leg.user_id.clone();
                let side_str = format!("{:?}", leg.side).to_uppercase();
                let fill_size = leg.fill_size.clone();
                let market_id = job.market_id.clone();
                let trade_id = job.trade_id.clone();
                self.ws_manager.send_fill_event(
                    &user_id,
                    &market_id,
                    &fill_size,
                    &side_str,
                    &trade_id,
                    &tx_hash,
                );

                Ok(())
            }
            Err(e) => {
                job.legs[leg_index].status = "relay_retry_pending".to_string();
                job.legs[leg_index].last_error = Some(e.to_string());
                Ok(())
            }
        }
    }

    async fn handle_proof_pending(&self, job: &mut PredictionMarketSettlementJob) -> ClobResult<()> {
        let Some(proof_job_id) = job.proof_job_id.as_deref() else {
            job.settlement_status = "proof_submission_failed".to_string();
            job.last_error = Some("missing proof job id".to_string());
            self.save_job(job).await?;
            return Ok(());
        };

        let Some(prover_job) = self.prover_pipeline.get_job(proof_job_id).await? else {
            job.settlement_status = "proof_submission_failed".to_string();
            job.last_error = Some(format!("proof job {} not found", proof_job_id));
            self.save_job(job).await?;
            return Ok(());
        };

        match prover_job.status {
            ProverJobStatus::Pending | ProverJobStatus::Running => Ok(()),
            ProverJobStatus::Failed => {
                job.settlement_status = "proof_failed".to_string();
                job.last_error = prover_job.last_error.clone();
                self.save_job(job).await
            }
            ProverJobStatus::Completed => {
                job.settlement_status = "relay_pending".to_string();
                job.last_error = None;
                self.save_job(job).await?;
                self.handle_relay_pending(job).await
            }
        }
    }

    async fn handle_relay_pending(&self, job: &mut PredictionMarketSettlementJob) -> ClobResult<()> {
        let Some(proof_job_id) = job.proof_job_id.as_deref() else {
            return Err(ClobError::Internal("missing proof job id for relay step".to_string()));
        };
        let Some(output) = self.prover_pipeline.get_output(proof_job_id).await? else {
            return Err(ClobError::ProofGenerationFailed(format!(
                "proof output missing for job {}",
                proof_job_id
            )));
        };

        let legs = parse_settlement_output(&output)?;
        if legs.is_empty() {
            return Err(ClobError::ProofGenerationFailed(
                "proof output contained no PM settlement legs".to_string(),
            ));
        }

        // Parse a single HonkProof from the prover output (shared across all legs).
        let proof = parse_honk_proof_from_output(&output)?;

        // Use the vault_address from the settlement job for the non-leg path.
        let job_vault_override: Option<&str> = if job.vault_address.trim().is_empty() {
            None
        } else {
            Some(job.vault_address.trim())
        };

        for leg in legs.into_iter().skip(job.relayed_leg_count) {
            let tx_hash = self
                .relayer
                .settle_fill(
                    leg.market_id,
                    leg.position_side,
                    low_high_hex_to_bytes32(&leg.spent_note_nullifier_low, &leg.spent_note_nullifier_high)?,
                    parse_u128_hex(&leg.pot_contribution_low, "pot_contribution")?,
                    parse_u128_hex(&leg.position_payout_units_low, "position_payout_units")?,
                    parse_u128_hex(&leg.trade_fee_amount_low, "trade_fee_amount")?,
                    &proof,
                    job_vault_override,
                )
                .await;

            match tx_hash {
                Ok(tx_hash) => {
                    job.relayed_leg_count += 1;
                    job.settlement_txs.push(tx_hash);
                    job.settlement_status = "relay_pending".to_string();
                    job.last_error = None;
                    self.save_job(job).await?;
                }
                Err(e) => {
                    job.settlement_status = "relay_retry_pending".to_string();
                    job.last_error = Some(e.to_string());
                    self.save_job(job).await?;
                    return Ok(());
                }
            }
        }

        job.settlement_status = "settled".to_string();
        job.last_error = None;
        self.save_job(job).await?;
        info!(settlement_job_id = %job.job_id, tx_count = job.settlement_txs.len(), "PM settlement relayed on-chain");

        // --- Post-settlement side effects (best-effort, non-blocking) ---

        // 1. Register output note commitments with vault-service as Merkle leaves.
        let latest_tx = job.settlement_txs.last().cloned().unwrap_or_default();
        let vault_url = std::env::var("VAULT_INTERNAL_URL").unwrap_or_default();
        if !vault_url.is_empty() {
            let vault_addr = job.vault_address.clone();
            let tx_clone = latest_tx.clone();
            let job_id_clone = job.job_id.clone();
            let url = format!("{}/v1/merkle/note", vault_url.trim_end_matches('/'));
            tokio::spawn(async move {
                let client = reqwest::Client::new();
                // Maker leg: use maker nullifier high as a proxy commitment identifier (no explicit output commitment field on job).
                // We register one leaf per settled leg — the commitment is derived server-side by vault-service from the tx.
                let body = serde_json::json!({
                    "vault_address": vault_addr,
                    "tx_hash": tx_clone,
                });
                match client.post(&url).json(&body).send().await {
                    Ok(resp) if resp.status().is_success() => {
                        tracing::info!(
                            settlement_job_id = %job_id_clone,
                            "Notified vault-service of settled PM fill leaves"
                        );
                    }
                    Ok(resp) => {
                        tracing::warn!(
                            settlement_job_id = %job_id_clone,
                            status = %resp.status(),
                            "vault-service merkle/note returned non-success"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            settlement_job_id = %job_id_clone,
                            error = %e,
                            "Failed to notify vault-service of PM fill leaves"
                        );
                    }
                }
            });
        }

        // 2. Broadcast WebSocket fill events to maker and taker.
        let maker_side = format!("{:?}", job.maker_side).to_uppercase();
        let taker_side = format!("{:?}", job.taker_side).to_uppercase();
        self.ws_manager.send_fill_event(
            &job.maker_user_id,
            &job.market_id,
            &job.maker_fill_size,
            &maker_side,
            &job.trade_id,
            &latest_tx,
        );
        self.ws_manager.send_fill_event(
            &job.taker_user_id,
            &job.market_id,
            &job.taker_fill_size,
            &taker_side,
            &job.trade_id,
            &latest_tx,
        );

        Ok(())
    }

    async fn load_job(&self, job_id: &str) -> ClobResult<Option<PredictionMarketSettlementJob>> {
        let key = format!("{}{}", PM_SETTLEMENT_JOB_PREFIX, job_id);
        let payload = self.store.get_optional(&key).await?;
        payload
            .map(|value| serde_json::from_str::<PredictionMarketSettlementJob>(&value).map_err(ClobError::from))
            .transpose()
    }

    async fn save_job(&self, job: &PredictionMarketSettlementJob) -> ClobResult<()> {
        self.store
            .set(&job.redis_key(), &serde_json::to_string(job)?)
            .await
    }
}

/// Parsed from the prover output JSON — public signals only.
/// The proof itself is parsed by `parse_honk_proof_from_output`.
#[derive(Debug, Deserialize)]
struct SettlementProofOutput {
    #[serde(default)]
    public_signals: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
struct SettlementLeg {
    market_id: u64,
    position_side: bool,
    spent_note_nullifier_low: String,
    spent_note_nullifier_high: String,
    pot_contribution_low: String,
    pot_contribution_high: String,
    position_payout_units_low: String,
    position_payout_units_high: String,
    trade_fee_amount_low: String,
    trade_fee_amount_high: String,
}

struct SettlementPublicSignals {
    market_id: u64,
    position_side: bool,
    pot_contribution: BigUint,
    position_payout_units: BigUint,
    trade_fee_amount: BigUint,
    spent_note_nullifier: BigUint,
}

fn parse_settlement_output(output: &str) -> ClobResult<Vec<SettlementLeg>> {
    let envelope: SettlementProofOutput = serde_json::from_str(output).map_err(|_| {
        ClobError::ProofGenerationFailed("unsupported PM settlement proof output format".to_string())
    })?;
    let signals = parse_settlement_public_signals(&envelope.public_signals)?;

    Ok(vec![SettlementLeg {
        market_id: signals.market_id,
        position_side: signals.position_side,
        spent_note_nullifier_low: biguint_low_hex(&signals.spent_note_nullifier),
        spent_note_nullifier_high: biguint_high_hex(&signals.spent_note_nullifier),
        pot_contribution_low: biguint_low_hex(&signals.pot_contribution),
        pot_contribution_high: biguint_high_hex(&signals.pot_contribution),
        position_payout_units_low: biguint_low_hex(&signals.position_payout_units),
        position_payout_units_high: biguint_high_hex(&signals.position_payout_units),
        trade_fee_amount_low: biguint_low_hex(&signals.trade_fee_amount),
        trade_fee_amount_high: biguint_high_hex(&signals.trade_fee_amount),
    }])
}

fn parse_settlement_public_signals(public_signals: &[String]) -> ClobResult<SettlementPublicSignals> {
    if public_signals.len() != 12 {
        return Err(ClobError::ProofGenerationFailed(format!(
            "PM settlement proof output expected 12 public signals, got {}",
            public_signals.len()
        )));
    }

    let market_id = parse_biguint_signal(&public_signals[1], "market_id")?
        .to_u64()
        .ok_or_else(|| {
            ClobError::ProofGenerationFailed(
                "PM settlement market_id public signal does not fit into u64".to_string(),
            )
        })?;

    let side = parse_biguint_signal(&public_signals[2], "side")?;
    let position_side = match side.to_u8() {
        Some(0) => false,
        Some(1) => true,
        _ => {
            return Err(ClobError::ProofGenerationFailed(
                "PM settlement side public signal must be 0 or 1".to_string(),
            ));
        }
    };

    Ok(SettlementPublicSignals {
        market_id,
        position_side,
        pot_contribution: parse_biguint_signal(&public_signals[5], "potContribution")?,
        position_payout_units: parse_biguint_signal(&public_signals[6], "positionPayoutUnits")?,
        trade_fee_amount: parse_biguint_signal(&public_signals[7], "tradeFeeAmount")?,
        spent_note_nullifier: parse_biguint_signal(&public_signals[8], "spentNullifier")?,
    })
}

fn parse_biguint_signal(value: &str, label: &str) -> ClobResult<BigUint> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ClobError::ProofGenerationFailed(format!(
            "PM settlement {} public signal is empty",
            label
        )));
    }

    let parsed = if let Some(hex) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")) {
        BigUint::from_str_radix(hex, 16)
    } else {
        BigUint::from_str_radix(trimmed, 10)
    }
    .map_err(|e| {
        ClobError::ProofGenerationFailed(format!(
            "invalid PM settlement {} public signal {} ({})",
            label, trimmed, e
        ))
    })?;

    Ok(parsed)
}

fn biguint_low_hex(value: &BigUint) -> String {
    let mask = (BigUint::from(1u8) << 128usize) - BigUint::from(1u8);
    format!("0x{:x}", value & &mask)
}

fn biguint_high_hex(value: &BigUint) -> String {
    format!("0x{:x}", value >> 128usize)
}

fn summarize_job_status(job: &PredictionMarketSettlementJob) -> String {
    if job.legs.is_empty() {
        return job.settlement_status.clone();
    }
    if job.legs.iter().any(|leg| leg.status == "relay_retry_pending") {
        return "relay_retry_pending".to_string();
    }
    if job.legs.iter().any(|leg| leg.status == "proof_failed" || leg.status == "proof_submission_failed") {
        return "proof_failed".to_string();
    }
    if job.legs.iter().all(|leg| leg.status == "settled") {
        return "settled".to_string();
    }
    if job.legs.iter().any(|leg| leg.status == "relay_pending") {
        return "relay_pending".to_string();
    }
    if job.legs.iter().any(|leg| leg.status == "proof_pending") {
        return "proof_pending".to_string();
    }
    "pending_proof_generation".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::OrderSide;
    use serde_json::json;

    #[test]
    fn parses_settlement_leg_public_signals() {
        let legs = parse_settlement_output(
            &json!({
                "public_signals": [
                    "0",
                    "42",
                    "1",
                    "0",
                    "0",
                    "17",
                    "31",
                    "2",
                    "340282366920938463463374607431768211461",
                    "0",
                    "0",
                    "0"
                ]
            })
            .to_string(),
        )
        .unwrap();

        assert_eq!(legs.len(), 1);
        assert_eq!(legs[0].market_id, 42);
        assert!(legs[0].position_side);
        assert_eq!(legs[0].pot_contribution_low, "0x11");
        assert_eq!(legs[0].pot_contribution_high, "0x0");
        assert_eq!(legs[0].position_payout_units_low, "0x1f");
        assert_eq!(legs[0].trade_fee_amount_low, "0x2");
        assert_eq!(legs[0].spent_note_nullifier_low, "0x5");
        assert_eq!(legs[0].spent_note_nullifier_high, "0x1");
    }

    #[test]
    fn rejects_wrong_public_signal_length() {
        let err = parse_settlement_output(
            &json!({
                "public_signals": ["0", "42"]
            })
            .to_string(),
        )
        .unwrap_err();

        assert!(err.to_string().contains("expected 12 public signals"));
    }

    #[test]
    fn summarizes_leg_statuses() {
        let job = PredictionMarketSettlementJob {
            job_id: "job-1".to_string(),
            trade_id: "trade-1".to_string(),
            market_id: "42".to_string(),
            maker_order_id: "maker-order".to_string(),
            taker_order_id: "taker-order".to_string(),
            maker_user_id: "maker".to_string(),
            taker_user_id: "taker".to_string(),
            maker_side: OrderSide::Sell,
            taker_side: OrderSide::Buy,
            maker_note_nullifier_low: "0x1".to_string(),
            maker_note_nullifier_high: "0x0".to_string(),
            taker_note_nullifier_low: "0x2".to_string(),
            taker_note_nullifier_high: "0x0".to_string(),
            maker_fill_size: "1".to_string(),
            taker_fill_size: "1".to_string(),
            price: "0.4".to_string(),
            maker_fee: "0.01".to_string(),
            taker_fee: "0.01".to_string(),
            settlement_status: "pending_proof_generation".to_string(),
            relayer_configured: true,
            vault_address: String::new(),
            legs: vec![],
            proof_job_id: None,
            settlement_txs: vec![],
            relayed_leg_count: 0,
            last_error: None,
        };
        assert_eq!(summarize_job_status(&job), "pending_proof_generation");
    }
}

// parse_felt_vec / parse_felt replaced by proof_generation::low_high_hex_to_bytes32
// and proof_generation::parse_u128_hex for EVM ABI encoding.

#[allow(dead_code)]
fn _legacy_parse_felt_placeholder(value: &str, label: &str) -> ClobResult<()> {
    // Kept as tombstone only; removed Starknet dependency.
    let _ = (value, label);
    Ok(())
}

