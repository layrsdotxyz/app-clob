use serde_json::json;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::time::{interval, Duration};
use tracing::{error, info, warn};

use crate::{
    error::{ClobError, ClobResult},
    metrics::Metrics,
    privacy::{PrivacyStateService, TransitionStatus},
    proof_generation::{
        groth16_verifier::verify_snarkjs_proof,
        parse_snarkjs_proof, ProverJob, ProverJobStatus, ProverJobType, ProverPipeline,
    },
    withdrawal_service::WithdrawalService,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProverMode {
    Snarkjs,
    Mock,
}

impl ProverMode {
    fn from_env() -> Self {
        match std::env::var("PRIVATE_PROVER_MODE")
            .unwrap_or_else(|_| "snarkjs".to_string())
            .to_lowercase()
            .as_str()
        {
            "mock" => Self::Mock,
            _ => Self::Snarkjs,
        }
    }
}

/// Background worker that consumes private prover jobs and updates transition status.
pub struct ProverWorker {
    pipeline: Arc<ProverPipeline>,
    privacy_state: Arc<PrivacyStateService>,
    poll_interval: Duration,
    mode: ProverMode,
    /// Optional withdrawal service — executes on-chain withdrawal after PrivateWithdraw proof succeeds.
    withdrawal_service: Option<Arc<WithdrawalService>>,
    /// Optional Prometheus metrics — records job counts and queue depth.
    metrics: Option<Arc<Metrics>>,
}

impl ProverWorker {
    pub fn new(
        pipeline: Arc<ProverPipeline>,
        privacy_state: Arc<PrivacyStateService>,
        poll_interval_secs: u64,
    ) -> Self {
        Self {
            pipeline,
            privacy_state,
            poll_interval: Duration::from_secs(if poll_interval_secs == 0 {
                1
            } else {
                poll_interval_secs
            }),
            mode: ProverMode::from_env(),
            withdrawal_service: None,
            metrics: None,
        }
    }

    /// Attach a withdrawal service (optional — enables on-chain execution after PrivateWithdraw attestation).
    pub fn with_withdrawal_service(mut self, ws: Arc<WithdrawalService>) -> Self {
        self.withdrawal_service = Some(ws);
        self
    }

    /// Attach Prometheus metrics (optional — records job counts and queue depth).
    pub fn with_metrics(mut self, metrics: Arc<Metrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    pub async fn start(&self) -> ClobResult<()> {
        info!(
            poll_interval_secs = self.poll_interval.as_secs(),
            mode = ?self.mode,
            "Private prover worker started"
        );

        // Startup guard: refuse to run in mock mode unless explicitly acknowledged.
        if self.mode == ProverMode::Mock {
            let allow = std::env::var("ALLOW_INSECURE_MOCK_PROVER")
                .unwrap_or_else(|_| "false".to_string())
                .to_lowercase()
                == "true";
            if !allow {
                return Err(ClobError::Internal(
                    "Private prover worker is in mock mode but ALLOW_INSECURE_MOCK_PROVER is not \
                     set to 'true'. This is blocked to prevent accidental mock deployment in \
                     production. Set ALLOW_INSECURE_MOCK_PROVER=true for local/dev use only."
                        .to_string(),
                ));
            }
            warn!("⚠️  ALLOW_INSECURE_MOCK_PROVER=true — ZK proofs are SIMULATED. DO NOT use in production.");
        }

        let mut ticker = interval(self.poll_interval);

        loop {
            ticker.tick().await;

            // Update queue depth gauge every tick.
            if let Some(m) = &self.metrics {
                if let Ok(depth) = self.pipeline.queue_depth().await {
                    m.set_prover_queue_depth(depth);
                }
            }

            let next_job = self.pipeline.claim_next_job().await?;
            let Some(job) = next_job else {
                continue;
            };

            if let Err(e) = self.process_job(job).await {
                warn!(error = %e, "Prover job processing failed");
            }
        }
    }

    async fn process_job(&self, job: ProverJob) -> ClobResult<()> {
        // Record metric: job claimed for processing.
        if let Some(m) = &self.metrics {
            m.record_prover_job_claimed(&job.circuit_name);
        }

        let input = self
            .pipeline
            .get_input(&job.job_id)
            .await?
            .unwrap_or_else(|| "{}".to_string());

        match self.generate_proof_output(&job, &input).await {
            Ok(output) => {
                self.pipeline.mark_completed(&job.job_id, &output).await?;

                // Proof generation success ≠ on-chain verification.
                // LayrsVault root updates are proof-gated on-chain and must occur via
                // the contract entrypoints (deposit/withdraw), not via operator publishing.
                let proof_generated = true;

                let transition = self
                    .privacy_state
                    .find_transition_by_proof_job_id(&job.job_id)
                    .await?;

                if let Some(t) = &transition {
                    self.privacy_state
                        .update_transition_status(&t.transition_id, TransitionStatus::Attested)
                        .await?;
                }

                if matches!(job.job_type, ProverJobType::PrivateWithdraw) {
                    if proof_generated {
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&input) {
                            if let Some(commitment) = v.get("commitment").and_then(|x| x.as_str()) {
                                let _ = self.privacy_state.mark_note_spent(commitment).await;
                            }
                        }

                        // Execute on-chain withdrawal now that the ZK proof is verified
                        if let Some(ws) = &self.withdrawal_service {
                            let ws_clone = Arc::clone(ws);
                            let input_clone = input.clone();
                            let output_clone = output.clone();
                            tokio::spawn(async move {
                                if let Err(e) = ws_clone
                                    .execute_after_attestation(&input_clone, &output_clone)
                                    .await
                                {
                                    warn!(error = %e, "execute_after_attestation failed");
                                }
                            });
                        }
                    }
                }

                info!(job_id = %job.job_id, circuit = %job.circuit_name, "Prover job completed");
                if let Some(m) = &self.metrics {
                    m.record_prover_job_completed(&job.circuit_name);
                }
            }
            Err(e) => {
                self.pipeline.mark_failed(&job.job_id, &e).await?;

                if let Some(updated_job) = self.pipeline.get_job(&job.job_id).await? {
                    if updated_job.status == ProverJobStatus::Failed {
                        if let Some(transition) = self
                            .privacy_state
                            .find_transition_by_proof_job_id(&job.job_id)
                            .await?
                        {
                            self.privacy_state
                                .update_transition_status(&transition.transition_id, TransitionStatus::Failed)
                                .await?;
                        }
                    }
                }

                error!(job_id = %job.job_id, error = %e, "Prover job errored");
                if let Some(m) = &self.metrics {
                    m.record_prover_job_failed(&job.circuit_name);
                }
            }
        }

        Ok(())
    }

    async fn generate_proof_output(&self, job: &ProverJob, input: &str) -> Result<String, String> {
        let input_value: serde_json::Value =
            serde_json::from_str(input).map_err(|e| format!("invalid prover input json: {}", e))?;

        if job.circuit_name.is_empty() {
            return Err("missing circuit name".to_string());
        }

        match self.mode {
            ProverMode::Mock => {
                let allow = std::env::var("ALLOW_INSECURE_MOCK_PROVER")
                    .unwrap_or_else(|_| "false".to_string())
                    .to_lowercase()
                    == "true";

                if !allow {
                    return Err("mock prover is disabled in production; set ALLOW_INSECURE_MOCK_PROVER=true only for local/dev".to_string());
                }

                let output = json!({
                    "proof_format": "phase2a-placeholder",
                    "job_id": job.job_id,
                    "job_type": job.job_type,
                    "circuit": job.circuit_name,
                    "generated_at": chrono::Utc::now(),
                    "public_inputs": input_value,
                });

                serde_json::to_string(&output).map_err(|e| e.to_string())
            }
            ProverMode::Snarkjs => self.generate_snarkjs_output(job, &input_value).await,
        }
    }

    async fn generate_snarkjs_output(
        &self,
        job: &ProverJob,
        input_value: &serde_json::Value,
    ) -> Result<String, String> {
        let (wasm_path, zkey_path) = self.artifact_paths(job)?;
        let vk_path = self.vk_path(job)?;
        let dir = tempdir().map_err(|e| e.to_string())?;

        let input_path = dir.path().join("input.json");
        let proof_path = dir.path().join("proof.json");
        let public_path = dir.path().join("public.json");

        std::fs::write(
            &input_path,
            serde_json::to_string_pretty(input_value).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;

        let snarkjs_bin = std::env::var("SNARKJS_BIN")
            .unwrap_or_else(|_| "snarkjs".to_string());

        let output = std::process::Command::new(&snarkjs_bin)
            .arg("groth16")
            .arg("fullprove")
            .arg(&input_path)
            .arg(&wasm_path)
            .arg(&zkey_path)
            .arg(&proof_path)
            .arg(&public_path)
            .output()
            .map_err(|e| format!("failed to execute snarkjs ({}): {}", snarkjs_bin, e))?;

        if !output.status.success() {
            return Err(format!(
                "snarkjs fullprove failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        let evm_proof = parse_snarkjs_proof(&proof_path, &public_path)
            .map_err(|e| e.to_string())?;

        // Server-side proof verification: re-verify with arkworks before accepting.
        // This ensures invalid proofs are rejected at the service boundary rather
        // than propagating to the chain or being stored as valid transitions.
        verify_snarkjs_proof(&vk_path, &evm_proof).map_err(|e| {
            format!("groth16 server-side verification failed for circuit '{}': {}", job.circuit_name, e)
        })?;

        info!(
            job_id = %job.job_id,
            circuit = %job.circuit_name,
            "groth16 server-side proof verification passed"
        );

        let proof_json = std::fs::read_to_string(&proof_path).map_err(|e| e.to_string())?;

        let output = json!({
            "proof_format": "groth16",
            "job_id": job.job_id,
            "job_type": job.job_type,
            "circuit": job.circuit_name,
            "generated_at": chrono::Utc::now(),
            "proof": serde_json::from_str::<serde_json::Value>(&proof_json).unwrap_or_default(),
            "public_signals": evm_proof.pub_signals,
            "pa": evm_proof.pa,
            "pb": evm_proof.pb,
            "pc": evm_proof.pc,
        });

        serde_json::to_string(&output).map_err(|e| e.to_string())
    }

    fn artifact_paths(&self, job: &ProverJob) -> Result<(String, String), String> {
        let (wasm_key, zkey_key) = match job.job_type {
            ProverJobType::PrivateDeposit => ("PRIVATE_DEPOSIT_WASM", "PRIVATE_DEPOSIT_ZKEY"),
            ProverJobType::PrivateOrderCommitment => (
                "PRIVATE_ORDER_COMMITMENT_WASM",
                "PRIVATE_ORDER_COMMITMENT_ZKEY",
            ),
            ProverJobType::PrivateTransferSettlement => (
                "PRIVATE_TRANSFER_SETTLEMENT_WASM",
                "PRIVATE_TRANSFER_SETTLEMENT_ZKEY",
            ),
            ProverJobType::PrivateMarketClaim => (
                "PRIVATE_MARKET_CLAIM_WASM",
                "PRIVATE_MARKET_CLAIM_ZKEY",
            ),
            ProverJobType::PrivateWithdraw => ("PRIVATE_WITHDRAW_WASM", "PRIVATE_WITHDRAW_ZKEY"),
            ProverJobType::PrivateYieldDistribution => (
                "PRIVATE_YIELD_DISTRIBUTION_WASM",
                "PRIVATE_YIELD_DISTRIBUTION_ZKEY",
            ),
        };

        let wasm = std::env::var(wasm_key)
            .map_err(|_| format!("{} is required for snarkjs prover mode", wasm_key))?;
        let zkey = std::env::var(zkey_key)
            .map_err(|_| format!("{} is required for snarkjs prover mode", zkey_key))?;

        if !std::path::Path::new(&wasm).exists() {
            return Err(format!("wasm artifact not found: {}", wasm));
        }
        if !std::path::Path::new(&zkey).exists() {
            return Err(format!("zkey artifact not found: {}", zkey));
        }

        Ok((wasm, zkey))
    }

    fn vk_path(&self, job: &ProverJob) -> Result<String, String> {
        let vk_key = match job.job_type {
            ProverJobType::PrivateDeposit => "PRIVATE_DEPOSIT_VK",
            ProverJobType::PrivateOrderCommitment => "PRIVATE_ORDER_COMMITMENT_VK",
            ProverJobType::PrivateTransferSettlement => "PRIVATE_TRANSFER_SETTLEMENT_VK",
            ProverJobType::PrivateMarketClaim => "PRIVATE_MARKET_CLAIM_VK",
            ProverJobType::PrivateWithdraw => "PRIVATE_WITHDRAW_VK",
            ProverJobType::PrivateYieldDistribution => "PRIVATE_YIELD_DISTRIBUTION_VK",
        };

        let vk = std::env::var(vk_key)
            .map_err(|_| format!("{} is required for groth16 calldata generation", vk_key))?;

        if !std::path::Path::new(&vk).exists() {
            return Err(format!("vk artifact not found: {}", vk));
        }

        Ok(vk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{privacy::PrivacyStateService, redis_store::RedisStore};
    use mini_redis::server;
    use tokio::sync::oneshot;

    async fn setup_worker() -> (ProverWorker, oneshot::Sender<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = oneshot::channel::<()>();

        tokio::spawn(async move {
            let _ = server::run(listener, async {
                let _ = rx.await;
            })
            .await;
        });

        let client = redis::Client::open(format!("redis://{}/", addr)).unwrap();
        let conn = redis::aio::ConnectionManager::new(client).await.unwrap();
        let store = Arc::new(RedisStore::new(conn));

        let pipeline = Arc::new(ProverPipeline::new(store.clone(), 2));
        let state = Arc::new(PrivacyStateService::new(store));
        let mut worker = ProverWorker::new(pipeline, state, 1);
        worker.mode = ProverMode::Mock;

        (worker, tx)
    }

    #[tokio::test]
    async fn test_mock_mode_rejected_by_default() {
        std::env::remove_var("ALLOW_INSECURE_MOCK_PROVER");
        let (worker, shutdown) = setup_worker().await;

        let job = ProverJob {
            job_id: "j1".to_string(),
            job_type: ProverJobType::PrivateDeposit,
            circuit_name: "private_deposit".to_string(),
            input_key: "k".to_string(),
            status: ProverJobStatus::Pending,
            attempts: 0,
            last_error: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        let err = worker
            .generate_proof_output(&job, r#"{"x":1}"#)
            .await
            .unwrap_err();
        assert!(err.contains("mock prover is disabled"));

        let _ = shutdown.send(());
    }

    #[tokio::test]
    async fn test_artifact_path_validation() {
        let (worker, shutdown) = setup_worker().await;
        let job = ProverJob {
            job_id: "j2".to_string(),
            job_type: ProverJobType::PrivateWithdraw,
            circuit_name: "private_withdraw".to_string(),
            input_key: "k2".to_string(),
            status: ProverJobStatus::Pending,
            attempts: 0,
            last_error: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        std::env::remove_var("PRIVATE_WITHDRAW_WASM");
        std::env::remove_var("PRIVATE_WITHDRAW_ZKEY");
        let err = worker.artifact_paths(&job).unwrap_err();
        assert!(err.contains("PRIVATE_WITHDRAW_WASM"));

        let _ = shutdown.send(());
    }
}
