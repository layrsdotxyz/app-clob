use serde_json::json;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::time::{interval, Duration};
use tracing::{error, info, warn};

use crate::{
    error::{ClobError, ClobResult},
    metrics::Metrics,
    privacy::{PrivacyStateService, TransitionStatus},
    proof_generation::{ProverJob, ProverJobStatus, ProverJobType, ProverPipeline},
    withdrawal_service::WithdrawalService,
};

#[derive(Debug, Clone, PartialEq, Eq)]
enum ProverMode {
    /// Barretenberg UltraHonk: `bb execute` + `bb prove --scheme ultra_honk`.
    /// Output: `proof.bin` (raw proof bytes) + `public_inputs` (hex bytes32 values).
    /// Env vars required: `*_CIRCUIT_JSON` (Noir compiled .json), `*_VK` (bb VK dir).
    /// Binary env var: `BB_BIN` (default: "bb").
    Barretenberg,
    Mock,
    Unsupported(String),
}

impl ProverMode {
    fn from_env() -> Self {
        let configured = std::env::var("PRIVATE_PROVER_MODE")
            .unwrap_or_else(|_| "barretenberg".to_string())
            .to_lowercase();

        match configured.as_str() {
            "mock" => Self::Mock,
            "barretenberg" | "honk" => Self::Barretenberg,
            other => Self::Unsupported(other.to_string()),
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

        if let ProverMode::Unsupported(mode) = &self.mode {
            return Err(ClobError::Internal(format!(
                "PRIVATE_PROVER_MODE='{}' is no longer supported. Use 'barretenberg' for the Noir/UltraHonk prover or 'mock' for local development. The legacy snarkjs/Groth16 backend path has been removed.",
                mode
            )));
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
                        if let Some(ws) = &self.withdrawal_service {
                            // Await on-chain withdrawal inline — NOT fire-and-forget.
                            // The note is only marked spent AFTER on-chain confirmation so
                            // that a failed or incomplete tx leaves the note intact and retryable.
                            match ws.execute_after_attestation(&input, &output).await {
                                Ok(()) => {
                                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&input) {
                                        if let Some(commitment) = v.get("commitment").and_then(|x| x.as_str()) {
                                            if let Err(e) = self.privacy_state.mark_note_spent(commitment).await {
                                                tracing::error!(
                                                    job_id = %job.job_id,
                                                    error = %e,
                                                    "On-chain withdrawal succeeded but failed to mark note spent — note may be double-spendable"
                                                );
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    // Note is intentionally NOT marked spent — the proof job succeeded
                                    // and the transition is Attested, but the chain tx failed.
                                    // The user can re-submit the withdrawal to retry.
                                    tracing::error!(
                                        job_id = %job.job_id,
                                        error = %e,
                                        "execute_after_attestation failed — on-chain withdrawal did not execute. \
                                         Note has NOT been marked spent; re-submit withdrawal to retry."
                                    );
                                }
                            }
                        } else {
                            // No withdrawal service configured — mark note spent immediately
                            // (local/dev mode with no on-chain step).
                            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&input) {
                                if let Some(commitment) = v.get("commitment").and_then(|x| x.as_str()) {
                                    let _ = self.privacy_state.mark_note_spent(commitment).await;
                                }
                            }
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

        match &self.mode {
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
            ProverMode::Barretenberg => self.generate_barretenberg_output(job, &input_value).await,
            ProverMode::Unsupported(mode) => Err(format!(
                "unsupported prover mode '{}': only 'barretenberg' and 'mock' are accepted",
                mode
            )),
        }
    }

    /// Generate a UltraHonk proof using the Barretenberg CLI (`bb`).
    ///
    /// Flow:
    ///   1. Write input TOML to a temp dir (format: `key = value` per Noir Prover.toml)
    ///   2. `bb execute -b <circuit.json> -i <input.toml> -o <witness_dir>` → witness.gz
    ///   3. `bb prove --scheme ultra_honk -b <circuit.json> -w <witness_dir>/witness.gz -o <out_dir>`
    ///      → <out_dir>/proof (binary), <out_dir>/public_inputs (hex bytes32 per line)
    ///   4. Optionally verify: `bb verify --scheme ultra_honk -k <vk_dir>/vk -p <proof> -i <public_inputs>`
    ///   5. Return JSON with proof_format="ultra_honk", proof_hex, public_inputs (hex bytes32 string[])
    async fn generate_barretenberg_output(
        &self,
        job: &ProverJob,
        input_value: &serde_json::Value,
    ) -> Result<String, String> {
        let circuit_json = self.circuit_json_path(job)?;
        let vk_dir       = self.bb_vk_dir(job)?;
        let bb_bin = std::env::var("BB_BIN").unwrap_or_else(|_| "bb".to_string());
        let circuit_name = job.circuit_name.clone();
        let job_id = job.job_id.clone();
        let job_type = job.job_type.clone();
        let input_value = input_value.clone();
        let circuit_name_for_blocking = circuit_name.clone();
        let vk_dir_for_blocking = vk_dir.clone();

        // Barretenberg proof generation shells out to external binaries and performs
        // synchronous filesystem work. Keep that off the Tokio worker threads so
        // health checks are not starved while proofs are running.
        let (proof_hex, public_inputs, verified_vk) = tokio::task::spawn_blocking(move || -> Result<(String, Vec<String>, bool), String> {
            let dir = tempdir().map_err(|e| e.to_string())?;

            // ─ 1. Write Prover.toml ──────────────────────────────────────────
            let toml_path = dir.path().join("Prover.toml");
            let toml_str = json_to_prover_toml(&input_value)
                .map_err(|e| format!("failed to build Prover.toml: {}", e))?;
            std::fs::write(&toml_path, &toml_str).map_err(|e| e.to_string())?;

            // ─ 2. Execute circuit → witness ──────────────────────────────────
            let witness_dir = dir.path().join("witness");
            std::fs::create_dir_all(&witness_dir).map_err(|e| e.to_string())?;

            let exec_out = std::process::Command::new(&bb_bin)
                .arg("execute")
                .arg("-b").arg(&circuit_json)
                .arg("-i").arg(&toml_path)
                .arg("-o").arg(&witness_dir)
                .output()
                .map_err(|e| format!("failed to run bb execute ({}): {}", bb_bin, e))?;

            if !exec_out.status.success() {
                return Err(format!(
                    "bb execute failed for circuit '{}': {}",
                    circuit_name_for_blocking,
                    String::from_utf8_lossy(&exec_out.stderr)
                ));
            }

            let witness_path = witness_dir.join("witness.gz");
            if !witness_path.exists() {
                return Err(format!(
                    "bb execute did not produce witness.gz for circuit '{}'",
                    circuit_name_for_blocking
                ));
            }

            // ─ 3. Prove ──────────────────────────────────────────────────────
            let proof_dir = dir.path().join("proof_out");
            std::fs::create_dir_all(&proof_dir).map_err(|e| e.to_string())?;

            let prove_out = std::process::Command::new(&bb_bin)
                .arg("prove")
                .arg("--scheme").arg("ultra_honk")
                .arg("-b").arg(&circuit_json)
                .arg("-w").arg(&witness_path)
                .arg("-o").arg(&proof_dir)
                .output()
                .map_err(|e| format!("failed to run bb prove ({}): {}", bb_bin, e))?;

            if !prove_out.status.success() {
                return Err(format!(
                    "bb prove failed for circuit '{}': {}",
                    circuit_name_for_blocking,
                    String::from_utf8_lossy(&prove_out.stderr)
                ));
            }

            // ─ 4. Read proof bytes ───────────────────────────────────────────
            let proof_bytes = std::fs::read(proof_dir.join("proof"))
                .map_err(|e| format!("failed to read proof file: {}", e))?;
            let proof_hex = hex::encode(&proof_bytes);

            // ─ 5. Read public inputs ─────────────────────────────────────────
            let pi_text = std::fs::read_to_string(proof_dir.join("public_inputs"))
                .map_err(|e| format!("failed to read public_inputs file: {}", e))?;
            let public_inputs: Vec<String> = pi_text
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(|l| {
                    let s = l.trim();
                    let hex_part = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
                    format!("0x{:0>64}", hex_part.to_lowercase())
                })
                .collect();

            // ─ 6. Server-side verify ─────────────────────────────────────────
            let vk_path = std::path::Path::new(&vk_dir_for_blocking).join("vk");
            let verified_vk = if vk_path.exists() {
                let verify_out = std::process::Command::new(&bb_bin)
                    .arg("verify")
                    .arg("--scheme").arg("ultra_honk")
                    .arg("-k").arg(&vk_path)
                    .arg("-p").arg(proof_dir.join("proof"))
                    .output()
                    .map_err(|e| format!("failed to run bb verify: {}", e))?;

                if !verify_out.status.success() {
                    return Err(format!(
                        "bb verify failed for circuit '{}' — proof is invalid: {}",
                        circuit_name_for_blocking,
                        String::from_utf8_lossy(&verify_out.stderr)
                    ));
                }
                true
            } else {
                false
            };

            Ok((proof_hex, public_inputs, verified_vk))
        })
        .await
        .map_err(|e| format!("spawn_blocking: {e}"))??;

        if verified_vk {
            info!(
                job_id   = %job_id,
                circuit  = %circuit_name,
                "UltraHonk server-side proof verification passed"
            );
        } else {
            let vk_path = std::path::Path::new(&vk_dir).join("vk");
            warn!(
                circuit = %circuit_name,
                vk_dir  = %vk_dir,
                "VK not found at {:?} — skipping server-side verify. Run build_honk_verifiers.sh.",
                vk_path
            );
        }

        let output = json!({
            "proof_format": "ultra_honk",
            "job_id":        job_id,
            "job_type":      job_type,
            "circuit":       circuit_name,
            "generated_at":  chrono::Utc::now(),
            "proof_hex":     proof_hex,
            "public_inputs": public_inputs,
        });

        serde_json::to_string(&output).map_err(|e| e.to_string())
    }

    /// Return the path to the compiled Noir circuit JSON for Barretenberg.
    /// Env vars: `PRIVATE_DEPOSIT_CIRCUIT_JSON`, `PRIVATE_TRANSFER_SETTLEMENT_CIRCUIT_JSON`, etc.
    fn circuit_json_path(&self, job: &ProverJob) -> Result<String, String> {
        let key = match job.job_type {
            ProverJobType::PrivateDeposit             => "PRIVATE_DEPOSIT_CIRCUIT_JSON",
            ProverJobType::PrivateOrderCommitment     => "PRIVATE_ORDER_COMMITMENT_CIRCUIT_JSON",
            ProverJobType::PrivateTransferSettlement  => "PRIVATE_TRANSFER_SETTLEMENT_CIRCUIT_JSON",
            ProverJobType::PrivateMarketClaim         => "PRIVATE_MARKET_CLAIM_CIRCUIT_JSON",
            ProverJobType::PrivateWithdraw            => "PRIVATE_WITHDRAW_CIRCUIT_JSON",
            ProverJobType::PrivateYieldDistribution   => "PRIVATE_YIELD_DISTRIBUTION_CIRCUIT_JSON",
        };
        let path = std::env::var(key)
            .map_err(|_| format!("{} is required for Barretenberg prover mode", key))?;
        if !std::path::Path::new(&path).exists() {
            return Err(format!("circuit JSON not found: {}", path));
        }
        Ok(path)
    }

    /// Return the directory containing the UltraHonk VK file (`vk`) for each circuit.
    /// Env vars: `PRIVATE_DEPOSIT_BB_VK_DIR`, etc.
    /// Returns an empty string if the env var is unset — caller skips server-side verify.
    fn bb_vk_dir(&self, job: &ProverJob) -> Result<String, String> {
        let key = match job.job_type {
            ProverJobType::PrivateDeposit             => "PRIVATE_DEPOSIT_BB_VK_DIR",
            ProverJobType::PrivateOrderCommitment     => "PRIVATE_ORDER_COMMITMENT_BB_VK_DIR",
            ProverJobType::PrivateTransferSettlement  => "PRIVATE_TRANSFER_SETTLEMENT_BB_VK_DIR",
            ProverJobType::PrivateMarketClaim         => "PRIVATE_MARKET_CLAIM_BB_VK_DIR",
            ProverJobType::PrivateWithdraw            => "PRIVATE_WITHDRAW_BB_VK_DIR",
            ProverJobType::PrivateYieldDistribution   => "PRIVATE_YIELD_DISTRIBUTION_BB_VK_DIR",
        };
        Ok(std::env::var(key).unwrap_or_default())
    }
}

/// Convert a JSON object (serde_json::Value) into a Noir `Prover.toml` string.
///
/// Supported conversions:
/// - Strings and numbers → `key = "value"`
/// - Booleans           → `key = "true"` / `key = "false"`
/// - Arrays             → `key = ["v0", "v1", ...]`
/// - Nested objects     → `[key]\nfield = "value"` (TOML table)
fn json_to_prover_toml(v: &serde_json::Value) -> Result<String, String> {
    let obj = v
        .as_object()
        .ok_or_else(|| "prover input must be a JSON object".to_string())?;

    let mut lines = Vec::new();

    for (key, val) in obj {
        match val {
            serde_json::Value::String(s) => {
                lines.push(format!("{} = {:?}", key, s));
            }
            serde_json::Value::Number(n) => {
                lines.push(format!("{} = {:?}", key, n.to_string()));
            }
            serde_json::Value::Bool(b) => {
                lines.push(format!("{} = {:?}", key, b.to_string()));
            }
            serde_json::Value::Array(arr) => {
                let elems: Result<Vec<String>, String> = arr
                    .iter()
                    .map(|item| match item {
                        serde_json::Value::String(s) => Ok(format!("{:?}", s)),
                        serde_json::Value::Number(n) => Ok(format!("{:?}", n.to_string())),
                        serde_json::Value::Bool(b) => Ok(format!("{:?}", b.to_string())),
                        other => Err(format!(
                            "unsupported array element type for key {}: {:?}",
                            key, other
                        )),
                    })
                    .collect();
                lines.push(format!("{} = [{}]", key, elems?.join(", ")));
            }
            serde_json::Value::Object(inner) => {
                lines.push(format!("[{}]", key));
                for (ikey, ival) in inner {
                    match ival {
                        serde_json::Value::String(s) => {
                            lines.push(format!("{} = {:?}", ikey, s));
                        }
                        serde_json::Value::Number(n) => {
                            lines.push(format!("{} = {:?}", ikey, n.to_string()));
                        }
                        other => {
                            return Err(format!(
                                "unsupported nested value type for {}.{}: {:?}",
                                key, ikey, other
                            ))
                        }
                    }
                }
            }
            serde_json::Value::Null => {
                // skip null values
            }
        }
    }

    Ok(lines.join("\n"))
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
    async fn test_circuit_json_path_validation() {
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

        std::env::remove_var("PRIVATE_WITHDRAW_CIRCUIT_JSON");
        let err = worker.circuit_json_path(&job).unwrap_err();
        assert!(err.contains("PRIVATE_WITHDRAW_CIRCUIT_JSON"));

        let _ = shutdown.send(());
    }
}
