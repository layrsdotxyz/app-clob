use std::sync::Arc;

use chrono::Utc;
use serde_json::Value;
use tokio::time::{interval, Duration};
use tracing::{info, warn};

use ethers::types::Address;

use crate::{
    error::{ClobError, ClobResult},
    prediction_market_claims::{PredictionMarketClaimJob, PM_CLAIM_JOB_PREFIX, PM_CLAIM_QUEUE},
    prediction_market_relayer::PredictionMarketRelayer,
    proof_generation::{ProverJobStatus, ProverJobType, ProverPipeline, parse_honk_proof_from_output},
    redis_store::RedisStore,
};

pub struct PredictionMarketClaimWorker {
    store: Arc<RedisStore>,
    prover_pipeline: Arc<ProverPipeline>,
    relayer: Arc<PredictionMarketRelayer>,
    poll_interval: Duration,
}

impl PredictionMarketClaimWorker {
    pub fn new(
        store: Arc<RedisStore>,
        prover_pipeline: Arc<ProverPipeline>,
        relayer: Arc<PredictionMarketRelayer>,
        poll_interval_secs: u64,
    ) -> Self {
        Self {
            store,
            prover_pipeline,
            relayer,
            poll_interval: Duration::from_secs(if poll_interval_secs == 0 { 2 } else { poll_interval_secs }),
        }
    }

    pub async fn start(&self) -> ClobResult<()> {
        info!(poll_interval_secs = self.poll_interval.as_secs(), "Prediction market claim worker started");
        let mut ticker = interval(self.poll_interval);

        loop {
            ticker.tick().await;
            if let Err(e) = self.claim_new_jobs().await {
                warn!(error = %e, "PM claim worker failed while claiming jobs");
            }
            if let Err(e) = self.advance_jobs().await {
                warn!(error = %e, "PM claim worker failed while advancing jobs");
            }
        }
    }

    async fn claim_new_jobs(&self) -> ClobResult<()> {
        loop {
            let Some(job_id) = self.store.pop_queue(PM_CLAIM_QUEUE).await? else {
                return Ok(());
            };

            let Some(mut job) = self.load_job(&job_id).await? else {
                warn!(job_id = %job_id, "PM claim job missing from Redis");
                continue;
            };

            if job.prover_job_id.is_some() || job.status != "pending_proof_generation" {
                continue;
            }

            let claim_input_key = claim_input_key(&job.job_id);
            let raw_input = self
                .store
                .get_optional(&claim_input_key)
                .await?
                .ok_or_else(|| ClobError::OrderNotFound(format!("missing claim input for job {}", job.job_id)))?;
            let input_payload: Value = serde_json::from_str(&raw_input)?;

            match self
                .prover_pipeline
                .submit_job(ProverJobType::PrivateMarketClaim, "pm_claim", &input_payload)
                .await
            {
                Ok(prover_job) => {
                    job.prover_job_id = Some(prover_job.job_id.clone());
                    job.status = "proof_pending".to_string();
                    job.last_error = None;
                    job.updated_at = Utc::now();
                    self.save_job(&job).await?;
                    info!(claim_job_id = %job.job_id, prover_job_id = %prover_job.job_id, "PM claim proof job submitted");
                }
                Err(e) => {
                    job.status = "proof_submission_failed".to_string();
                    job.last_error = Some(e.to_string());
                    job.updated_at = Utc::now();
                    self.save_job(&job).await?;
                }
            }
        }
    }

    async fn advance_jobs(&self) -> ClobResult<()> {
        for key in self.store.scan_keys(&format!("{}*", PM_CLAIM_JOB_PREFIX)).await? {
            let Some(payload) = self.store.get_optional(&key).await? else {
                continue;
            };
            let mut job: PredictionMarketClaimJob = serde_json::from_str(&payload)?;

            match job.status.as_str() {
                "proof_pending" => self.handle_proof_pending(&mut job).await?,
                "relay_pending" | "relay_retry_pending" => self.handle_relay_pending(&mut job).await?,
                _ => {}
            }
        }
        Ok(())
    }

    async fn handle_proof_pending(&self, job: &mut PredictionMarketClaimJob) -> ClobResult<()> {
        let Some(prover_job_id) = job.prover_job_id.as_deref() else {
            job.status = "proof_submission_failed".to_string();
            job.last_error = Some("missing prover job id".to_string());
            job.updated_at = Utc::now();
            return self.save_job(job).await;
        };

        let Some(prover_job) = self.prover_pipeline.get_job(prover_job_id).await? else {
            job.status = "proof_submission_failed".to_string();
            job.last_error = Some(format!("prover job {} not found", prover_job_id));
            job.updated_at = Utc::now();
            return self.save_job(job).await;
        };

        match prover_job.status {
            ProverJobStatus::Pending | ProverJobStatus::Running => Ok(()),
            ProverJobStatus::Failed => {
                job.status = "proof_failed".to_string();
                job.last_error = prover_job.last_error.clone();
                job.updated_at = Utc::now();
                self.save_job(job).await
            }
            ProverJobStatus::Completed => {
                job.status = "relay_pending".to_string();
                job.last_error = None;
                job.updated_at = Utc::now();
                self.save_job(job).await?;
                self.handle_relay_pending(job).await
            }
        }
    }

    async fn handle_relay_pending(&self, job: &mut PredictionMarketClaimJob) -> ClobResult<()> {
        let Some(prover_job_id) = job.prover_job_id.as_deref() else {
            return Err(ClobError::Internal("missing prover job id for claim relay".to_string()));
        };
        let output = self
            .prover_pipeline
            .get_output(prover_job_id)
            .await?
            .ok_or_else(|| ClobError::ProofGenerationFailed(format!("proof output missing for {}", prover_job_id)))?;
        let proof = parse_honk_proof_from_output(&output)?;;

        let vault_override: Option<&str> = if job.vault_address.trim().is_empty() {
            None
        } else {
            Some(job.vault_address.trim())
        };
        match self
            .relayer
            .claim_winnings(parse_recipient(&job.recipient)?, &proof, vault_override)
            .await
        {
            Ok(tx_hash) => {
                job.claim_tx_hash = Some(tx_hash);
                job.status = "claimed".to_string();
                job.last_error = None;
                job.updated_at = Utc::now();
                self.save_job(job).await?;
                info!(claim_job_id = %job.job_id, "PM claim relayed on-chain");
                Ok(())
            }
            Err(e) => {
                job.status = "relay_retry_pending".to_string();
                job.last_error = Some(e.to_string());
                job.updated_at = Utc::now();
                self.save_job(job).await
            }
        }
    }

    async fn load_job(&self, job_id: &str) -> ClobResult<Option<PredictionMarketClaimJob>> {
        let payload = self.store.get_optional(&format!("{}{}", PM_CLAIM_JOB_PREFIX, job_id)).await?;
        payload
            .map(|value| serde_json::from_str::<PredictionMarketClaimJob>(&value).map_err(ClobError::from))
            .transpose()
    }

    async fn save_job(&self, job: &PredictionMarketClaimJob) -> ClobResult<()> {
        self.store.set(&job.redis_key(), &serde_json::to_string(job)?).await
    }
}

pub fn claim_input_key(job_id: &str) -> String {
    format!("pm:claim:input:{}", job_id)
}

/// Parse the EVM recipient address from a hex string (with or without 0x prefix).
fn parse_recipient(recipient: &str) -> ClobResult<Address> {
    recipient
        .parse::<Address>()
        .map_err(|e| ClobError::InvalidHex(format!("invalid recipient address '{}': {}", recipient, e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── claim_input_key ──────────────────────────────────────────────────────

    #[test]
    fn test_claim_input_key_format() {
        let key = claim_input_key("job-abc-123");
        assert_eq!(key, "pm:claim:input:job-abc-123");
    }

    #[test]
    fn test_claim_input_key_empty_job_id() {
        let key = claim_input_key("");
        assert_eq!(key, "pm:claim:input:");
    }

    #[test]
    fn test_claim_input_key_uuid_format() {
        let job_id = "550e8400-e29b-41d4-a716-446655440000";
        let key = claim_input_key(job_id);
        assert_eq!(key, format!("pm:claim:input:{}", job_id));
    }

    // ─── parse_recipient ──────────────────────────────────────────────────────

    #[test]
    fn test_parse_recipient_valid_with_0x() {
        let result = parse_recipient("0x742d35Cc6634C0532925a3b844Bc454e4438f44e");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_recipient_zero_address() {
        let result = parse_recipient("0x0000000000000000000000000000000000000000");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_recipient_garbage_string() {
        let result = parse_recipient("not-an-address");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("invalid recipient address"), "{msg}");
    }

    #[test]
    fn test_parse_recipient_too_short() {
        let result = parse_recipient("0x1234");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_recipient_empty_string() {
        let result = parse_recipient("");
        assert!(result.is_err());
    }
}
