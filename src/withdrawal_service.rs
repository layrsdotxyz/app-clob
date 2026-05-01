// Withdrawal Service for clob-service.
//
// Thin orchestration layer: validates ledger balance, locks it, delegates
// ZK proof generation and on-chain execution to vault-service, then releases
// the lock based on vault-service's outcome.
//
// vault-service is the sole service that generates ZK proofs and submits
// on-chain transactions. clob-service never touches the EVM directly.

use chrono::Utc;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::sync::Arc;

use crate::{
    balance_service::BalanceService,
    error::{ClobError, ClobResult},
    redis_store::RedisStore,
};

// ── Public types ──────────────────────────────────────────────────────────────

/// A user's withdrawal intent — what they want to withdraw.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalIntent {
    pub user_id: String,
    /// Destination EVM address (hex, "0x...").
    pub destination: String,
    /// Token symbol: "WETH" | "USDC" | "ZEN"
    pub token: String,
    /// Amount in token's smallest unit (as a decimal string).
    pub amount: String,
    /// Client-provided nonce — stored for replay protection.
    pub nonce: u64,
    pub created_at: i64,
}

/// Full withdrawal request from the user, including ZK witness fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalRequest {
    pub intent: WithdrawalIntent,
    /// EVM signature from the user.
    pub signature: String,
    // ZK witness fields — forwarded opaque to vault-service.
    // clob-service does not interpret these; vault-service owns all ZK logic.
    #[serde(default)]
    pub nullifier: Option<String>,
    #[serde(default)]
    pub note_commitment: Option<String>,
    #[serde(default)]
    pub old_root: Option<String>,
    #[serde(default)]
    pub expected_new_root: Option<String>,
    /// Optional rollover payload — forwarded opaque to vault-service.
    #[serde(default)]
    pub rollover: Option<serde_json::Value>,
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WithdrawalStatus {
    Pending,
    Confirmed,
    Completed,
    Failed,
}

// ── Internal types ────────────────────────────────────────────────────────────

/// Tracking record persisted in Redis by clob-service.
/// Contains only ledger fields — no ZK witness data is stored here.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClobWithdrawalTracking {
    withdrawal_id: String,
    user_id: String,
    locked_amount: String,
    token: String,
    status: WithdrawalStatus,
    tx_hash: Option<String>,
    created_at: i64,
}

/// Payload sent to vault-service POST /internal/v1/withdraw.
#[derive(Debug, Clone, Serialize)]
struct InternalWithdrawRequest {
    withdrawal_id: String,
    clob_authorization: ClobAuthorization,
    withdrawal_params: WithdrawalParams,
}

/// clob-service's ledger attestation — "I have checked and locked this amount".
#[derive(Debug, Clone, Serialize)]
struct ClobAuthorization {
    user_id: String,
    authorized_amount: String,
    token: String,
    locked_at: i64,
}

/// ZK and routing fields forwarded to vault-service (opaque to clob-service).
#[derive(Debug, Clone, Serialize)]
struct WithdrawalParams {
    destination: String,
    nullifier: Option<String>,
    note_commitment: Option<String>,
    old_root: Option<String>,
    expected_new_root: Option<String>,
    rollover: Option<serde_json::Value>,
}

// ── Service ───────────────────────────────────────────────────────────────────

pub struct WithdrawalService {
    redis: Arc<RedisStore>,
    balance_service: Arc<BalanceService>,
    vault_url: String,
    internal_service_key: String,
    http_client: reqwest::Client,
}

impl WithdrawalService {
    pub fn new(
        redis: Arc<RedisStore>,
        balance_service: Arc<BalanceService>,
        vault_url: String,
        internal_service_key: String,
    ) -> Self {
        Self {
            redis,
            balance_service,
            vault_url,
            internal_service_key,
            http_client: reqwest::Client::new(),
        }
    }

    /// Process a user withdrawal request.
    ///
    /// Flow:
    /// 1. Validate request fields (no side effects on failure).
    /// 2. Check ledger balance and reserve the amount.
    /// 3. POST to vault-service to start proof generation.
    /// 4. On vault-service error: release the reservation, return error.
    /// 5. On success: store tracking record, return status=pending.
    pub async fn process_withdrawal(&self, req: WithdrawalRequest) -> ClobResult<WithdrawalResponse> {
        let intent = &req.intent;

        // ── 1. Pre-lock validation (zero side effects) ────────────────────────
        if intent.destination.is_empty() || !intent.destination.starts_with("0x") {
            return Err(ClobError::InvalidOrder(
                "Invalid destination EVM address".into(),
            ));
        }
        let amount = Decimal::from_str(&intent.amount)
            .map_err(|_| ClobError::InvalidOrder("Invalid amount".into()))?;
        if amount <= Decimal::ZERO {
            return Err(ClobError::InvalidOrder(
                "Amount must be greater than 0".into(),
            ));
        }

        // ── 2. Replay protection (pre-lock) ───────────────────────────────────
        let nonce_key = format!("withdrawal:nonce:{}:{}", intent.user_id, intent.nonce);
        let existing = self.redis.get(&nonce_key).await.unwrap_or_default();
        if !existing.is_empty() {
            return Err(ClobError::InvalidOrder("Nonce already used".into()));
        }

        // ── 3. Reserve balance ────────────────────────────────────────────────
        // From this point onward any error path must release the reservation.
        self.balance_service
            .reserve_balance(&intent.user_id, &intent.token, amount)?;

        // Mark nonce consumed *after* reservation succeeds so a balance failure
        // doesn't permanently burn the nonce.
        let _ = self.redis.set(&nonce_key, "1").await;

        // ── 4. Delegate to vault-service ──────────────────────────────────────
        let withdrawal_id = uuid::Uuid::new_v4().to_string();
        let internal_req = InternalWithdrawRequest {
            withdrawal_id: withdrawal_id.clone(),
            clob_authorization: ClobAuthorization {
                user_id: intent.user_id.clone(),
                authorized_amount: intent.amount.clone(),
                token: intent.token.clone(),
                locked_at: Utc::now().timestamp(),
            },
            withdrawal_params: WithdrawalParams {
                destination: intent.destination.clone(),
                // ZK fields forwarded opaque — clob-service does not interpret them.
                nullifier: req.nullifier,
                note_commitment: req.note_commitment,
                old_root: req.old_root,
                expected_new_root: req.expected_new_root,
                rollover: req.rollover,
            },
        };

        let vault_result = self
            .http_client
            .post(format!("{}/internal/v1/withdraw", self.vault_url))
            .bearer_auth(&self.internal_service_key)
            .json(&internal_req)
            .send()
            .await;

        match vault_result {
            Ok(resp) if resp.status().is_success() => {
                // ── 5. Store tracking record ──────────────────────────────────
                // Only ledger fields — no ZK data stored here.
                let tracking = ClobWithdrawalTracking {
                    withdrawal_id: withdrawal_id.clone(),
                    user_id: intent.user_id.clone(),
                    locked_amount: intent.amount.clone(),
                    token: intent.token.clone(),
                    status: WithdrawalStatus::Pending,
                    tx_hash: None,
                    created_at: Utc::now().timestamp(),
                };
                let _ = self
                    .redis
                    .set(
                        &format!("clob:withdrawal:{}", withdrawal_id),
                        &serde_json::to_string(&tracking).unwrap_or_default(),
                    )
                    .await;

                tracing::info!(
                    withdrawal_id = %withdrawal_id,
                    user_id = %intent.user_id,
                    token = %intent.token,
                    "Withdrawal delegated to vault-service"
                );

                Ok(WithdrawalResponse {
                    success: true,
                    withdrawal_id,
                    status: WithdrawalStatus::Pending,
                    tx_hash: None,
                    estimated_time: Some("1-2 epochs".into()),
                    error: None,
                })
            }
            Ok(resp) => {
                // Vault rejected — release lock immediately.
                let status = resp.status();
                let _ = self
                    .balance_service
                    .release_balance(&intent.user_id, &intent.token, amount);
                Err(ClobError::Internal(format!(
                    "vault-service rejected withdrawal with status {status}"
                )))
            }
            Err(e) => {
                // Network failure — release lock.
                let _ = self
                    .balance_service
                    .release_balance(&intent.user_id, &intent.token, amount);
                Err(ClobError::Internal(format!(
                    "vault-service unreachable: {e}"
                )))
            }
        }
    }

    /// Poll vault-service for the current status of a withdrawal.
    ///
    /// On `completed`: calls `BalanceService::debit` which simultaneously
    /// releases the reservation and reduces the total balance.
    /// On `failed`: calls `release_balance` to restore full availability.
    pub async fn poll_withdrawal_status(
        &self,
        withdrawal_id: &str,
    ) -> ClobResult<Option<WithdrawalStatusRecord>> {
        let tracking_key = format!("clob:withdrawal:{}", withdrawal_id);
        let data = self.redis.get(&tracking_key).await.unwrap_or_default();
        if data.is_empty() {
            return Ok(None);
        }

        let mut tracking: ClobWithdrawalTracking = serde_json::from_str(&data)
            .map_err(|e| ClobError::Internal(format!("Deserialize tracking: {e}")))?;

        // Skip polling if already terminal.
        if matches!(
            tracking.status,
            WithdrawalStatus::Completed | WithdrawalStatus::Failed
        ) {
            return Ok(Some(self.to_status_record(&tracking)));
        }

        // Poll vault-service for an updated status.
        let vault_resp = self
            .http_client
            .get(format!(
                "{}/internal/v1/withdraw/{}/status",
                self.vault_url, withdrawal_id
            ))
            .bearer_auth(&self.internal_service_key)
            .send()
            .await;

        if let Ok(resp) = vault_resp {
            if let Ok(body) = resp.json::<serde_json::Value>().await {
                let status_str = body
                    .get("status")
                    .and_then(|s| s.as_str())
                    .unwrap_or("pending");

                let amount =
                    Decimal::from_str(&tracking.locked_amount).unwrap_or(Decimal::ZERO);

                match status_str {
                    "completed" => {
                        let tx_hash = body
                            .get("tx_hash")
                            .and_then(|t| t.as_str())
                            .map(|s| s.to_string());
                        // debit() = release reservation + reduce total balance.
                        let _ = self
                            .balance_service
                            .debit(&tracking.user_id, &tracking.token, amount);
                        tracking.status = WithdrawalStatus::Completed;
                        tracking.tx_hash = tx_hash;
                        let _ = self
                            .redis
                            .set(
                                &tracking_key,
                                &serde_json::to_string(&tracking).unwrap_or_default(),
                            )
                            .await;
                    }
                    "failed" => {
                        // Release reservation only — total is unchanged.
                        let _ = self
                            .balance_service
                            .release_balance(&tracking.user_id, &tracking.token, amount);
                        tracking.status = WithdrawalStatus::Failed;
                        let _ = self
                            .redis
                            .set(
                                &tracking_key,
                                &serde_json::to_string(&tracking).unwrap_or_default(),
                            )
                            .await;
                    }
                    _ => {}
                }
            }
        }

        Ok(Some(self.to_status_record(&tracking)))
    }

    /// Read the last known withdrawal status from local Redis without a vault-service call.
    pub async fn get_withdrawal_status(
        &self,
        withdrawal_id: &str,
    ) -> ClobResult<Option<WithdrawalStatusRecord>> {
        let tracking_key = format!("clob:withdrawal:{}", withdrawal_id);
        let data = self.redis.get(&tracking_key).await.unwrap_or_default();
        if data.is_empty() {
            return Ok(None);
        }
        let tracking: ClobWithdrawalTracking = serde_json::from_str(&data)
            .map_err(|e| ClobError::Internal(format!("Deserialize tracking: {e}")))?;
        Ok(Some(self.to_status_record(&tracking)))
    }

    fn to_status_record(&self, t: &ClobWithdrawalTracking) -> WithdrawalStatusRecord {
        WithdrawalStatusRecord {
            withdrawal_id: t.withdrawal_id.clone(),
            status: t.status.clone(),
            tx_hash: t.tx_hash.clone(),
            created_at: Some(t.created_at),
            updated_at: Some(Utc::now().timestamp()),
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{balance_service::BalanceService, redis_store::RedisStore};
    use axum::{
        extract::{Path, State},
        http::{HeaderMap, StatusCode},
        response::IntoResponse,
        routing::{get, post},
        Json, Router,
    };
    use mini_redis::server;
    use rust_decimal_macros::dec;
    use serde_json::{json, Value};
    use std::sync::Mutex;
    use tokio::sync::oneshot;

    // ── Mock vault-service ────────────────────────────────────────────────────

    #[derive(Clone)]
    struct MockVaultState {
        received_requests: Arc<Mutex<Vec<Value>>>,
        post_status: u16,
        status_payload: Arc<Mutex<Value>>,
        expected_bearer: String,
    }

    async fn mock_vault_post(
        State(s): State<MockVaultState>,
        headers: HeaderMap,
        body: String,
    ) -> impl IntoResponse {
        let bearer_ok = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(|t| t == s.expected_bearer)
            .unwrap_or(false);

        if !bearer_ok || s.post_status == 401 {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "unauthorized"})),
            )
                .into_response();
        }
        if s.post_status == 403 {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "forbidden"})),
            )
                .into_response();
        }
        if s.post_status == 500 {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "server error"})),
            )
                .into_response();
        }

        if let Ok(v) = serde_json::from_str::<Value>(&body) {
            let withdrawal_id = v
                .get("withdrawal_id")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            s.received_requests.lock().unwrap().push(v);
            return (
                StatusCode::OK,
                Json(json!({"withdrawal_id": withdrawal_id, "status": "pending"})),
            )
                .into_response();
        }
        (StatusCode::BAD_REQUEST, Json(json!({"error": "bad json"}))).into_response()
    }

    async fn mock_vault_status(
        State(s): State<MockVaultState>,
        headers: HeaderMap,
        Path(_id): Path<String>,
    ) -> impl IntoResponse {
        let bearer_ok = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(|t| t == s.expected_bearer)
            .unwrap_or(false);

        if !bearer_ok {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "unauthorized"})),
            )
                .into_response();
        }
        let payload = s.status_payload.lock().unwrap().clone();
        (StatusCode::OK, Json(payload)).into_response()
    }

    /// Spin up a local Axum server that simulates vault-service's internal endpoints.
    /// `post_status`: HTTP status code to return on POST (200 = success).
    /// `status_payload`: JSON body to return on GET status.
    async fn setup_mock_vault(
        post_status: u16,
        status_payload: Value,
        expected_bearer: &str,
    ) -> (String, Arc<Mutex<Vec<Value>>>, oneshot::Sender<()>) {
        let received = Arc::new(Mutex::new(Vec::<Value>::new()));
        let state = MockVaultState {
            received_requests: received.clone(),
            post_status,
            status_payload: Arc::new(Mutex::new(status_payload)),
            expected_bearer: expected_bearer.to_string(),
        };
        let app = Router::new()
            .route("/internal/v1/withdraw", post(mock_vault_post))
            .route(
                "/internal/v1/withdraw/:id/status",
                get(mock_vault_status),
            )
            .with_state(state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = rx.await;
                })
                .await;
        });
        (format!("http://{addr}"), received, tx)
    }

    /// Construct a WithdrawalService backed by mini-redis, pointing at `vault_url`.
    async fn setup_service(
        vault_url: &str,
        bearer: &str,
    ) -> (WithdrawalService, Arc<BalanceService>, oneshot::Sender<()>) {
        std::env::set_var("REDIS_COMPAT_DISABLE_SET_NX", "true");
        std::env::set_var("REDIS_COMPAT_DISABLE_EXISTS", "true");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (redis_tx, redis_rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            let _ = server::run(listener, async {
                let _ = redis_rx.await;
            })
            .await;
        });

        let client = redis::Client::open(format!("redis://{}/", addr)).unwrap();
        let conn = redis::aio::ConnectionManager::new(client).await.unwrap();
        let store = Arc::new(RedisStore::new(conn));
        let balance_service = Arc::new(BalanceService::new(None));

        let service = WithdrawalService::new(
            store,
            balance_service.clone(),
            vault_url.to_string(),
            bearer.to_string(),
        );
        (service, balance_service, redis_tx)
    }

    fn make_request(user_id: &str, token: &str, amount: &str, nonce: u64) -> WithdrawalRequest {
        WithdrawalRequest {
            intent: WithdrawalIntent {
                user_id: user_id.to_string(),
                destination: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
                token: token.to_string(),
                amount: amount.to_string(),
                nonce,
                created_at: 0,
            },
            signature: "0xsig".to_string(),
            nullifier: Some("0xnullifier".to_string()),
            note_commitment: Some("0xcommitment".to_string()),
            old_root: Some("0xroot".to_string()),
            expected_new_root: Some("0xnewroot".to_string()),
            rollover: None,
        }
    }

    // ── Happy path ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_happy_path_reserves_balance_returns_pending() {
        let (vault_url, _received, vault_shutdown) =
            setup_mock_vault(200, json!({"status": "pending"}), "test-key").await;
        let (service, balances, redis_shutdown) =
            setup_service(&vault_url, "test-key").await;

        balances.deposit("alice", "USDC", dec!(1000));
        let resp = service
            .process_withdrawal(make_request("alice", "USDC", "500", 1))
            .await
            .unwrap();

        assert!(resp.success);
        assert!(matches!(resp.status, WithdrawalStatus::Pending));
        assert!(!resp.withdrawal_id.is_empty());
        // Balance locked, not yet debited.
        assert_eq!(balances.get_total_balance("alice", "USDC"), dec!(1000));
        assert_eq!(balances.get_reserved_balance("alice", "USDC"), dec!(500));
        assert_eq!(balances.get_available_balance("alice", "USDC"), dec!(500));

        let _ = vault_shutdown.send(());
        let _ = redis_shutdown.send(());
    }

    #[tokio::test]
    async fn test_happy_path_rollover_fields_forwarded_intact_to_vault() {
        let (vault_url, received, vault_shutdown) =
            setup_mock_vault(200, json!({"status": "pending"}), "test-key").await;
        let (service, balances, redis_shutdown) =
            setup_service(&vault_url, "test-key").await;

        balances.deposit("bob", "USDC", dec!(1000));
        let rollover = json!({
            "residual_amount": "250",
            "new_note_commitment": "0xcafe",
            "authorizer_signature": "0xdeadbeef"
        });
        let mut req = make_request("bob", "USDC", "750", 2);
        req.rollover = Some(rollover);

        service.process_withdrawal(req).await.unwrap();

        let reqs = received.lock().unwrap();
        assert_eq!(reqs.len(), 1, "vault must receive exactly one request");
        let params = &reqs[0]["withdrawal_params"];
        assert_eq!(params["rollover"]["residual_amount"], "250");
        assert_eq!(params["rollover"]["new_note_commitment"], "0xcafe");
        assert_eq!(params["rollover"]["authorizer_signature"], "0xdeadbeef");
        // ZK fields forwarded.
        assert_eq!(params["nullifier"], "0xnullifier");
        assert_eq!(params["note_commitment"], "0xcommitment");

        let _ = vault_shutdown.send(());
        let _ = redis_shutdown.send(());
    }

    #[tokio::test]
    async fn test_happy_path_poll_completed_debits_total_balance() {
        let status_payload = json!({"status": "completed", "tx_hash": "0xabc123"});
        let (vault_url, _received, vault_shutdown) =
            setup_mock_vault(200, status_payload, "test-key").await;
        let (service, balances, redis_shutdown) =
            setup_service(&vault_url, "test-key").await;

        balances.deposit("carol", "USDC", dec!(1000));
        let resp = service
            .process_withdrawal(make_request("carol", "USDC", "400", 3))
            .await
            .unwrap();

        let status = service
            .poll_withdrawal_status(&resp.withdrawal_id)
            .await
            .unwrap()
            .unwrap();

        assert!(matches!(status.status, WithdrawalStatus::Completed));
        assert_eq!(status.tx_hash.as_deref(), Some("0xabc123"));
        // Total debited, reservation cleared.
        assert_eq!(balances.get_total_balance("carol", "USDC"), dec!(600));
        assert_eq!(balances.get_reserved_balance("carol", "USDC"), dec!(0));
        assert_eq!(balances.get_available_balance("carol", "USDC"), dec!(600));

        let _ = vault_shutdown.send(());
        let _ = redis_shutdown.send(());
    }

    // ── Pre-lock adverse paths (zero side effects expected) ───────────────────

    #[tokio::test]
    async fn test_insufficient_balance_rejected_vault_not_called() {
        let (vault_url, received, vault_shutdown) =
            setup_mock_vault(200, json!({"status": "pending"}), "test-key").await;
        let (service, balances, redis_shutdown) =
            setup_service(&vault_url, "test-key").await;

        balances.deposit("dave", "USDC", dec!(100));
        let err = service
            .process_withdrawal(make_request("dave", "USDC", "500", 4))
            .await
            .unwrap_err();

        let msg = err.to_string().to_lowercase();
        assert!(
            msg.contains("insufficient") || msg.contains("balance"),
            "expected balance error, got: {err}"
        );
        assert_eq!(
            received.lock().unwrap().len(),
            0,
            "vault must not be called"
        );
        assert_eq!(balances.get_available_balance("dave", "USDC"), dec!(100));

        let _ = vault_shutdown.send(());
        let _ = redis_shutdown.send(());
    }

    #[tokio::test]
    async fn test_zero_amount_rejected_before_lock() {
        let (vault_url, received, vault_shutdown) =
            setup_mock_vault(200, json!({"status": "pending"}), "test-key").await;
        let (service, balances, redis_shutdown) =
            setup_service(&vault_url, "test-key").await;

        balances.deposit("eve", "USDC", dec!(1000));
        let err = service
            .process_withdrawal(make_request("eve", "USDC", "0", 5))
            .await
            .unwrap_err();

        assert!(
            err.to_string().contains("greater than 0") || err.to_string().contains("Amount"),
            "expected amount error, got: {err}"
        );
        assert_eq!(received.lock().unwrap().len(), 0);
        assert_eq!(balances.get_reserved_balance("eve", "USDC"), dec!(0));

        let _ = vault_shutdown.send(());
        let _ = redis_shutdown.send(());
    }

    #[tokio::test]
    async fn test_invalid_destination_rejected_before_lock() {
        let (vault_url, received, vault_shutdown) =
            setup_mock_vault(200, json!({"status": "pending"}), "test-key").await;
        let (service, balances, redis_shutdown) =
            setup_service(&vault_url, "test-key").await;

        balances.deposit("frank", "USDC", dec!(1000));
        let mut req = make_request("frank", "USDC", "500", 6);
        req.intent.destination = "not-a-valid-address".to_string();

        let err = service.process_withdrawal(req).await.unwrap_err();
        assert!(
            err.to_string().contains("destination")
                || err.to_string().contains("address")
                || err.to_string().contains("Invalid"),
            "expected address error, got: {err}"
        );
        assert_eq!(received.lock().unwrap().len(), 0);
        assert_eq!(balances.get_reserved_balance("frank", "USDC"), dec!(0));

        let _ = vault_shutdown.send(());
        let _ = redis_shutdown.send(());
    }

    // ── Post-lock adverse paths (lock MUST be released) ───────────────────────

    #[tokio::test]
    async fn test_vault_returns_500_releases_lock() {
        let (vault_url, _received, vault_shutdown) =
            setup_mock_vault(500, json!({}), "test-key").await;
        let (service, balances, redis_shutdown) =
            setup_service(&vault_url, "test-key").await;

        balances.deposit("grace", "USDC", dec!(1000));
        let err = service
            .process_withdrawal(make_request("grace", "USDC", "600", 7))
            .await
            .unwrap_err();

        assert!(
            err.to_string().contains("500")
                || err.to_string().contains("rejected")
                || err.to_string().contains("vault"),
            "expected vault error, got: {err}"
        );
        assert_eq!(
            balances.get_available_balance("grace", "USDC"),
            dec!(1000),
            "lock must be released"
        );
        assert_eq!(balances.get_reserved_balance("grace", "USDC"), dec!(0));

        let _ = vault_shutdown.send(());
        let _ = redis_shutdown.send(());
    }

    #[tokio::test]
    async fn test_vault_returns_401_releases_lock() {
        // Correct key on server side; wrong key used by service → triggers 401.
        let (vault_url, _received, vault_shutdown) =
            setup_mock_vault(200, json!({}), "correct-key").await;
        let (service, balances, redis_shutdown) =
            setup_service(&vault_url, "wrong-key").await;

        balances.deposit("henry", "USDC", dec!(1000));
        let err = service
            .process_withdrawal(make_request("henry", "USDC", "300", 8))
            .await
            .unwrap_err();

        assert!(
            err.to_string().contains("401")
                || err.to_string().contains("rejected")
                || err.to_string().contains("vault"),
            "expected auth error, got: {err}"
        );
        assert_eq!(balances.get_available_balance("henry", "USDC"), dec!(1000));
        assert_eq!(balances.get_reserved_balance("henry", "USDC"), dec!(0));

        let _ = vault_shutdown.send(());
        let _ = redis_shutdown.send(());
    }

    #[tokio::test]
    async fn test_vault_returns_403_releases_lock() {
        let (vault_url, _received, vault_shutdown) =
            setup_mock_vault(403, json!({}), "test-key").await;
        let (service, balances, redis_shutdown) =
            setup_service(&vault_url, "test-key").await;

        balances.deposit("iris", "USDC", dec!(1000));
        let _ = service
            .process_withdrawal(make_request("iris", "USDC", "200", 9))
            .await
            .unwrap_err();

        assert_eq!(balances.get_available_balance("iris", "USDC"), dec!(1000));
        assert_eq!(balances.get_reserved_balance("iris", "USDC"), dec!(0));

        let _ = vault_shutdown.send(());
        let _ = redis_shutdown.send(());
    }

    #[tokio::test]
    async fn test_vault_unreachable_releases_lock() {
        // Bind then immediately drop the listener — port becomes unavailable.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_url = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);

        let (service, balances, redis_shutdown) =
            setup_service(&dead_url, "test-key").await;

        balances.deposit("jack", "USDC", dec!(1000));
        let err = service
            .process_withdrawal(make_request("jack", "USDC", "500", 10))
            .await
            .unwrap_err();

        assert!(
            err.to_string().contains("unreachable")
                || err.to_string().contains("error")
                || err.to_string().contains("vault"),
            "expected network error, got: {err}"
        );
        assert_eq!(
            balances.get_available_balance("jack", "USDC"),
            dec!(1000),
            "lock must be released on network failure"
        );
        assert_eq!(balances.get_reserved_balance("jack", "USDC"), dec!(0));

        let _ = redis_shutdown.send(());
    }

    #[tokio::test]
    async fn test_vault_proof_fails_on_poll_releases_lock() {
        let status_payload =
            json!({"status": "failed", "error": "proof generation failed"});
        let (vault_url, _received, vault_shutdown) =
            setup_mock_vault(200, status_payload, "test-key").await;
        let (service, balances, redis_shutdown) =
            setup_service(&vault_url, "test-key").await;

        balances.deposit("kate", "USDC", dec!(1000));
        let resp = service
            .process_withdrawal(make_request("kate", "USDC", "700", 11))
            .await
            .unwrap();

        // Reservation exists while pending.
        assert_eq!(balances.get_reserved_balance("kate", "USDC"), dec!(700));

        let status = service
            .poll_withdrawal_status(&resp.withdrawal_id)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(status.status, WithdrawalStatus::Failed));

        // Reservation released; total unchanged.
        assert_eq!(balances.get_total_balance("kate", "USDC"), dec!(1000));
        assert_eq!(balances.get_reserved_balance("kate", "USDC"), dec!(0));
        assert_eq!(balances.get_available_balance("kate", "USDC"), dec!(1000));

        let _ = vault_shutdown.send(());
        let _ = redis_shutdown.send(());
    }

    // ── Idempotency ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_duplicate_nonce_rejected_balance_locked_once() {
        let (vault_url, received, vault_shutdown) =
            setup_mock_vault(200, json!({"status": "pending"}), "test-key").await;
        let (service, balances, redis_shutdown) =
            setup_service(&vault_url, "test-key").await;

        balances.deposit("lena", "USDC", dec!(2000));

        // First submission succeeds.
        service
            .process_withdrawal(make_request("lena", "USDC", "500", 12))
            .await
            .unwrap();

        // Second with same nonce is rejected.
        let err = service
            .process_withdrawal(make_request("lena", "USDC", "500", 12))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("Nonce")
                || err.to_string().contains("nonce")
                || err.to_string().contains("used"),
            "expected nonce replay error, got: {err}"
        );

        // Vault called exactly once.
        assert_eq!(received.lock().unwrap().len(), 1);
        // Only 500 locked, not 1000.
        assert_eq!(balances.get_reserved_balance("lena", "USDC"), dec!(500));
        assert_eq!(balances.get_available_balance("lena", "USDC"), dec!(1500));

        let _ = vault_shutdown.send(());
        let _ = redis_shutdown.send(());
    }

    // ── Status serde ─────────────────────────────────────────────────────────

    #[test]
    fn test_withdrawal_status_serialises_lowercase() {
        assert_eq!(
            serde_json::to_string(&WithdrawalStatus::Pending).unwrap(),
            "\"pending\""
        );
        assert_eq!(
            serde_json::to_string(&WithdrawalStatus::Completed).unwrap(),
            "\"completed\""
        );
        assert_eq!(
            serde_json::to_string(&WithdrawalStatus::Failed).unwrap(),
            "\"failed\""
        );
    }

    #[test]
    fn test_withdrawal_status_record_roundtrips() {
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
    }
}
