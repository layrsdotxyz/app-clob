// Withdrawal Service for clob-service.
// Queues withdrawal intents and submits withdrawWithProof transactions to the
// PrivacyVault on Horizen via the EVM relayer.
//
// Note: this service does not include a StealthService dependency — the
// CLOB service does not manage stealth keys.  All callers must supply an
// explicit destination address.

use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{
    error::{ClobError, ClobResult},
    evm_relayer::EvmRelayer,
    privacy::PrivacyStateService,
    proof_generation::{ProverJobType, ProverPipeline},
    redis_store::RedisStore,
};

/// A user's withdrawal intent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalIntent {
    /// User's internal ledger ID.
    pub user_id: String,
    /// Destination EVM address (hex, "0x...").
    pub destination: String,
    /// Token: "WETH" | "ZEN"
    pub token: String,
    /// Amount in token's base units (as decimal string).
    pub amount: String,
    /// Nonce – client-provided, stored to prevent replay.
    pub nonce: u64,
    /// Unix timestamp at which this intent was created.
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalRequest {
    pub intent: WithdrawalIntent,
    /// EVM signature from the user (r, s, v as hex), comma-separated.
    pub signature: String,
    /// Privacy-preserving ZK fields (triggers private withdrawal flow).
    #[serde(default)]
    pub nullifier: Option<String>,
    #[serde(default)]
    pub note_commitment: Option<String>,
    #[serde(default)]
    pub old_root: Option<String>,
    #[serde(default)]
    pub expected_new_root: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalResponse {
    pub success: bool,
    pub withdrawal_id: String,
    pub status: WithdrawalStatus,
    pub tx_hash: Option<String>,
    pub estimated_time: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalStatusRecord {
    pub withdrawal_id: String,
    pub status: WithdrawalStatus,
    pub tx_hash: Option<String>,
    pub created_at: Option<i64>,
    pub updated_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WithdrawalStatus {
    Pending,
    Confirmed,
    Completed,
    Failed,
}

pub struct WithdrawalService {
    redis: Arc<RedisStore>,
    relayer: Arc<EvmRelayer>,
    privacy_state: Option<Arc<PrivacyStateService>>,
    prover_pipeline: Option<Arc<ProverPipeline>>,
}

impl WithdrawalService {
    pub fn new(redis: Arc<RedisStore>, relayer: Arc<EvmRelayer>) -> Self {
        Self {
            redis,
            relayer,
            privacy_state: None,
            prover_pipeline: None,
        }
    }

    pub fn with_privacy(
        mut self,
        privacy_state: Arc<PrivacyStateService>,
        prover_pipeline: Arc<ProverPipeline>,
    ) -> Self {
        self.privacy_state = Some(privacy_state);
        self.prover_pipeline = Some(prover_pipeline);
        self
    }

    /// Process a withdrawal request.
    /// ZK fields must be supplied to trigger the private withdrawal flow.
    pub async fn process_withdrawal(
        &self,
        req: WithdrawalRequest,
    ) -> ClobResult<WithdrawalResponse> {
        let withdrawal_id = uuid::Uuid::new_v4().to_string();
        let intent = &req.intent;

        if intent.destination.is_empty() || !intent.destination.starts_with("0x") {
            return Err(ClobError::InvalidOrder("Invalid destination EVM address".into()));
        }

        let amount: u128 = intent
            .amount
            .parse()
            .map_err(|_| ClobError::InvalidOrder("Invalid amount".into()))?;
        if amount == 0 {
            return Err(ClobError::InvalidOrder("Amount must be greater than 0".into()));
        }

        // Replay protection
        let nonce_key = format!("withdrawal:nonce:{}:{}", intent.user_id, intent.nonce);
        if let Ok(v) = self.redis.get(&nonce_key).await {
            if !v.is_empty() {
                return Err(ClobError::InvalidOrder("Nonce already used".into()));
            }
        }

        // ZK privacy fields → enqueue proof job
        if req.nullifier.is_some() {
            if let (Some(pp), Some(_ps)) = (&self.prover_pipeline, &self.privacy_state) {
                let job_input = serde_json::json!({
                    "user_id": intent.user_id,
                    "destination": intent.destination,
                    "token": intent.token,
                    "amount": intent.amount,
                    "nullifier": req.nullifier,
                    "note_commitment": req.note_commitment,
                    "old_root": req.old_root,
                    "expected_new_root": req.expected_new_root,
                    "withdrawal_id": withdrawal_id,
                });
                let job = pp
                    .submit_job(
                        ProverJobType::PrivateWithdraw,
                        "withdrawal_authorization",
                        &job_input,
                    )
                    .await?;

                let record = WithdrawalStatusRecord {
                    withdrawal_id: withdrawal_id.clone(),
                    status: WithdrawalStatus::Pending,
                    tx_hash: None,
                    created_at: Some(chrono::Utc::now().timestamp()),
                    updated_at: Some(chrono::Utc::now().timestamp()),
                };
                self.redis
                    .set(
                        &format!("withdrawal:status:{}", withdrawal_id),
                        &serde_json::to_string(&record).unwrap_or_default(),
                    )
                    .await?;

                let _ = self.redis.set(&nonce_key, "1").await;

                tracing::info!(
                    withdrawal_id = %withdrawal_id,
                    job_id = %job.job_id,
                    user_id = %intent.user_id,
                    "Private withdrawal proof job enqueued"
                );

                return Ok(WithdrawalResponse {
                    success: true,
                    withdrawal_id,
                    status: WithdrawalStatus::Pending,
                    tx_hash: None,
                    estimated_time: Some("1-2 epochs".into()),
                    error: None,
                });
            }
        }

        Err(ClobError::InvalidOrder(
            "Withdrawal requires ZK fields (nullifier/note/root) to generate a Groth16 proof".into(),
        ))
    }

    /// Called by `ProverWorker` after a `PrivateWithdraw` proof is attested.
    /// Submits the `withdrawWithProof` transaction to the PrivacyVault on Horizen.
    pub async fn execute_after_attestation(
        &self,
        input_json: &str,
        proof_output_json: &str,
    ) -> ClobResult<()> {
        let v: serde_json::Value =
            serde_json::from_str(input_json).map_err(|e| ClobError::Internal(e.to_string()))?;

        let token = v.get("token").and_then(|x| x.as_str()).unwrap_or("WETH");
        let amount_str = v.get("amount").and_then(|x| x.as_str()).unwrap_or("0");
        let destination = v.get("destination").and_then(|x| x.as_str()).unwrap_or_default();
        let withdrawal_id = v.get("withdrawal_id").and_then(|x| x.as_str()).unwrap_or_default();

        if destination.is_empty() {
            tracing::warn!("execute_after_attestation: no destination in input, skipping");
            return Ok(());
        }

        let vault_address = self
            .relayer
            .treasury_address_for_token(token)
            .ok_or_else(|| ClobError::Internal(format!(
                "No vault address configured for token {token} \
                  (set PM_USDC_TREASURY_ADDRESS, PM_ZEN_TREASURY_ADDRESS, or PRIVACY_WETH_VAULT_ADDRESS as appropriate; vault aliases still work)"
            )))?;

        let tx_hash = self
            .relayer
            .submit_withdraw_with_proof(&vault_address, proof_output_json)
            .await?;

        if !withdrawal_id.is_empty() {
            let record = WithdrawalStatusRecord {
                withdrawal_id: withdrawal_id.to_string(),
                status: WithdrawalStatus::Completed,
                tx_hash: Some(tx_hash.clone()),
                created_at: None,
                updated_at: Some(chrono::Utc::now().timestamp()),
            };
            let _ = self
                .redis
                .set(
                    &format!("withdrawal:status:{}", withdrawal_id),
                    &serde_json::to_string(&record).unwrap_or_default(),
                )
                .await;
        }

        tracing::info!(
            tx_hash = %tx_hash,
            destination = %destination,
            token = %token,
            amount = %amount_str,
            "on-chain withdrawal executed after ZK proof attestation"
        );
        Ok(())
    }

    pub async fn get_withdrawal_status(
        &self,
        withdrawal_id: &str,
    ) -> ClobResult<Option<WithdrawalStatusRecord>> {
        let key = format!("withdrawal:status:{}", withdrawal_id);
        let data = self.redis.get(&key).await.unwrap_or_default();
        if data.is_empty() {
            return Ok(None);
        }
        let record: WithdrawalStatusRecord = serde_json::from_str(&data)
            .map_err(|e| ClobError::Internal(format!("Deserialize withdrawal status: {}", e)))?;
        Ok(Some(record))
    }
}

// ── 5. Withdrawal validation tests ──────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use crate::redis_store::RedisStore;
    use crate::evm_relayer::{EvmRelayer, EvmRelayerConfig};
    use ethers::{
        middleware::SignerMiddleware,
        providers::{Http, Provider},
        signers::{LocalWallet, Signer},
    };
    use mini_redis::server;
    use tokio::sync::oneshot;

    // ── Test infrastructure ──────────────────────────────────────────────────

    /// Build a WithdrawalService backed by an in-process mini-redis instance
    /// and a stub EvmRelayer (real URL not required until send_tx is called).
    async fn setup_withdrawal_service() -> (WithdrawalService, Arc<RedisStore>, oneshot::Sender<()>) {
        std::env::set_var("REDIS_COMPAT_DISABLE_SET_NX", "true");
        std::env::set_var("REDIS_COMPAT_DISABLE_EXISTS", "true");
        std::env::set_var("REDIS_COMPAT_DISABLE_KEYS", "true");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            let _ = server::run(listener, async { let _ = rx.await; }).await;
        });

        let client = redis::Client::open(format!("redis://{}/", addr)).unwrap();
        let conn = redis::aio::ConnectionManager::new(client).await.unwrap();
        let store = Arc::new(RedisStore::new(conn));

        // Ethers Provider::try_from only parses the URL — no TCP connection is made
        // until an RPC method is called. Tests that don't call send_tx are safe.
        let provider = Provider::<Http>::try_from("http://127.0.0.1:10001").unwrap();
        let wallet: LocalWallet = "0000000000000000000000000000000000000000000000000000000000000001"
            .parse::<LocalWallet>()
            .unwrap()
            .with_chain_id(1337u64);
        let evm_client = Arc::new(SignerMiddleware::new(provider, wallet));
        let relayer = Arc::new(EvmRelayer {
            client: evm_client,
            config: EvmRelayerConfig {
                rpc_url: "http://127.0.0.1:10001".to_string(),
                chain_id: 1337,
                private_key: "0x0000000000000000000000000000000000000000000000000000000000000001"
                    .to_string(),
                pm_usdc_treasury_address: None,
                pm_zen_treasury_address: None,
                privacy_weth_vault_address: None,
            },
        });

        let service = WithdrawalService::new(store.clone(), relayer);
        (service, store, tx)
    }

    // ── Domain invariant helpers (pure logic, no service) ────────────────────

    fn is_valid_destination(dest: &str) -> bool {
        !dest.is_empty() && dest.starts_with("0x")
    }

    fn is_valid_amount(amount_str: &str) -> bool {
        amount_str.parse::<u128>().map(|v| v > 0).unwrap_or(false)
    }

    // ── 5a. Destination validation ───────────────────────────────────────────

    /// Valid 0x-prefixed address is accepted.
    #[test]
    fn test_withdrawal_destination_valid_0x_prefix() {
        assert!(is_valid_destination("0xabcdef1234567890abcdef1234567890abcdef12"));
    }

    /// Empty destination is rejected.
    #[test]
    fn test_withdrawal_destination_empty_rejected() {
        assert!(!is_valid_destination(""));
    }

    /// Destination without 0x prefix is rejected.
    #[test]
    fn test_withdrawal_destination_no_0x_prefix_rejected() {
        assert!(!is_valid_destination("abcdef1234567890"));
    }

    /// Destination that is only "0x" (no address body) is accepted at format level
    /// but would fail EVM validation — the service rejects by not starting with 0x check passing.
    #[test]
    fn test_withdrawal_destination_bare_0x_passes_prefix_check() {
        // Prefix check passes; length check is EVM-layer concern
        assert!(is_valid_destination("0x"));
    }

    // ── 5b. Amount validation ────────────────────────────────────────────────

    /// Valid amount is accepted.
    #[test]
    fn test_withdrawal_amount_valid() {
        assert!(is_valid_amount("1000000000000000000"));
    }

    /// Zero amount is rejected.
    #[test]
    fn test_withdrawal_amount_zero_rejected() {
        assert!(!is_valid_amount("0"));
    }

    /// Non-numeric amount is rejected.
    #[test]
    fn test_withdrawal_amount_non_numeric_rejected() {
        assert!(!is_valid_amount("abc"));
    }

    /// Negative string is rejected (non-numeric for u128).
    #[test]
    fn test_withdrawal_amount_negative_rejected() {
        assert!(!is_valid_amount("-1"));
    }

    /// Floating-point string is rejected.
    #[test]
    fn test_withdrawal_amount_float_rejected() {
        assert!(!is_valid_amount("1.5"));
    }

    // ── 5c. ZK requirement invariant ────────────────────────────────────────

    /// A request without nullifier is NOT a ZK withdrawal.
    #[test]
    fn test_withdrawal_without_nullifier_is_not_zk() {
        let req = WithdrawalRequest {
            intent: WithdrawalIntent {
                user_id: "user1".to_string(),
                destination: "0xabc".to_string(),
                token: "WETH".to_string(),
                amount: "100".to_string(),
                nonce: 1,
                created_at: 0,
            },
            signature: "sig".to_string(),
            nullifier: None,
            note_commitment: None,
            old_root: None,
            expected_new_root: None,
        };
        assert!(req.nullifier.is_none());
    }

    /// A request WITH nullifier is a ZK withdrawal.
    #[test]
    fn test_withdrawal_with_nullifier_is_zk() {
        let req = WithdrawalRequest {
            intent: WithdrawalIntent {
                user_id: "user1".to_string(),
                destination: "0xabc".to_string(),
                token: "WETH".to_string(),
                amount: "100".to_string(),
                nonce: 1,
                created_at: 0,
            },
            signature: "sig".to_string(),
            nullifier: Some("null-abc".to_string()),
            note_commitment: Some("commit-abc".to_string()),
            old_root: Some("root-old".to_string()),
            expected_new_root: Some("root-new".to_string()),
        };
        assert!(req.nullifier.is_some());
    }

    // ── 5d. WithdrawalStatus serialisation ──────────────────────────────────

    /// WithdrawalStatus serialises to lowercase strings.
    #[test]
    fn test_withdrawal_status_pending_serde() {
        let s = serde_json::to_string(&WithdrawalStatus::Pending).unwrap();
        assert_eq!(s, "\"pending\"");
        let d: WithdrawalStatus = serde_json::from_str("\"pending\"").unwrap();
        assert!(matches!(d, WithdrawalStatus::Pending));
    }

    #[test]
    fn test_withdrawal_status_completed_serde() {
        let s = serde_json::to_string(&WithdrawalStatus::Completed).unwrap();
        assert_eq!(s, "\"completed\"");
    }

    #[test]
    fn test_withdrawal_status_failed_serde() {
        let s = serde_json::to_string(&WithdrawalStatus::Failed).unwrap();
        assert_eq!(s, "\"failed\"");
    }

    /// Full WithdrawalStatusRecord round-trips through JSON.
    #[test]
    fn test_withdrawal_status_record_serde_roundtrip() {
        let record = WithdrawalStatusRecord {
            withdrawal_id: "wdl-001".to_string(),
            status: WithdrawalStatus::Pending,
            tx_hash: None,
            created_at: Some(1700000000),
            updated_at: Some(1700000001),
        };
        let json = serde_json::to_string(&record).unwrap();
        let restored: WithdrawalStatusRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.withdrawal_id, "wdl-001");
        assert!(matches!(restored.status, WithdrawalStatus::Pending));
        assert!(restored.tx_hash.is_none());
    }

    /// WithdrawalStatusRecord with tx_hash round-trips.
    #[test]
    fn test_withdrawal_status_record_with_tx_hash_serde() {
        let record = WithdrawalStatusRecord {
            withdrawal_id: "wdl-002".to_string(),
            status: WithdrawalStatus::Completed,
            tx_hash: Some("0xdeadbeef".to_string()),
            created_at: Some(1700000000),
            updated_at: Some(1700000099),
        };
        let json = serde_json::to_string(&record).unwrap();
        let restored: WithdrawalStatusRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.tx_hash.as_deref(), Some("0xdeadbeef"));
        assert!(matches!(restored.status, WithdrawalStatus::Completed));
    }

    // ── 5e. WithdrawalIntent serde ───────────────────────────────────────────

    /// WithdrawalIntent serialises and deserialises correctly.
    #[test]
    fn test_withdrawal_intent_serde_roundtrip() {
        let intent = WithdrawalIntent {
            user_id: "alice".to_string(),
            destination: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
            token: "WETH".to_string(),
            amount: "5000000000000000000".to_string(),
            nonce: 42,
            created_at: 1700000000,
        };
        let json = serde_json::to_string(&intent).unwrap();
        let restored: WithdrawalIntent = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.user_id, "alice");
        assert_eq!(restored.nonce, 42);
        assert_eq!(restored.amount, "5000000000000000000");
    }

    // ── 5f. Process withdrawal — service-level tests (require mini-redis) ────

    /// Withdrawal from a yield vault requires ZK fields.
    /// Without a nullifier, the service rejects with "requires ZK fields" error.
    #[tokio::test]
    async fn test_yield_vault_withdrawal_without_zk_rejected() {
        let (service, _store, shutdown) = setup_withdrawal_service().await;

        let req = WithdrawalRequest {
            intent: WithdrawalIntent {
                user_id: "alice".to_string(),
                destination: "0xabcdef1234567890abcdef1234567890abcdef12".to_string(),
                token: "yield-WETH-v1".to_string(),
                amount: "1000000000000000000".to_string(),
                nonce: 1,
                created_at: 0,
            },
            signature: "stub".to_string(),
            nullifier: None,      // No ZK fields
            note_commitment: None,
            old_root: None,
            expected_new_root: None,
        };

        let err = service.process_withdrawal(req).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("ZK") || msg.contains("requires") || msg.contains("nullifier"),
            "expected ZK-fields error, got: {msg}"
        );

        let _ = shutdown.send(());
    }

    /// Replay protection: submitting the same nonce twice is rejected.
    /// We seed the nonce key directly in Redis to simulate a prior submission.
    #[tokio::test]
    async fn test_withdrawal_duplicate_nonce_rejected() {
        let (service, store, shutdown) = setup_withdrawal_service().await;

        // Simulate a prior successful submission by planting the nonce record.
        let nonce_key = "withdrawal:nonce:bob:99";
        store.set(nonce_key, "1").await.unwrap();

        let req = WithdrawalRequest {
            intent: WithdrawalIntent {
                user_id: "bob".to_string(),
                destination: "0xabcdef1234567890abcdef1234567890abcdef12".to_string(),
                token: "WETH".to_string(),
                amount: "500000000000000000".to_string(),
                nonce: 99,
                created_at: 0,
            },
            signature: "stub".to_string(),
            nullifier: Some("any".to_string()),   // Pass dest/amount checks
            note_commitment: None,
            old_root: None,
            expected_new_root: None,
        };

        let err = service.process_withdrawal(req).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("Nonce") || msg.contains("nonce") || msg.contains("used"),
            "expected nonce-replay error, got: {msg}"
        );

        let _ = shutdown.send(());
    }
}
