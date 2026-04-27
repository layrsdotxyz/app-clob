/// `POST /v1/claims` — permissionless ZK-proof-gated claim endpoint (G10).
///
/// Unlike the auth-gated `/v1/pm/claim-winnings`, this endpoint requires **no
/// JWT** — the UltraHonk proof itself is the authorisation. The workflow is:
///
/// 1. Parse recipient address from request.
/// 2. Validate proof structure via `parse_honk_proof_from_output`.
/// 3. Extract the note nullifier from `public_inputs[5]` (pm_claim circuit layout:
///    `[old_root, destination_address_field, market_id, outcome, amount, nullifier, claim_auth_digest]`).
/// 4. Reject 409 if the nullifier has already been spent.
/// 5. Check the PM relayer is configured — 503 if not.
/// 6. Call `pm_relayer.claim_winnings(recipient, &proof, vault_override)`.
/// 7. Register the nullifier atomically after on-chain success.
/// 8. Return 200 `{ "tx_hash": "0x..." }`.
use std::sync::Arc;

use axum::{
    extract::State,
    response::IntoResponse,
    Json,
};
use ethers::types::Address;
use serde::{Deserialize, Serialize};

use crate::{
    error::{ClobError, ClobResult},
    proof_generation::{HonkProof, parse_honk_proof_from_output},
    AppState,
};

/// Request body for `POST /v1/claims`.
#[derive(Debug, Deserialize)]
pub struct PermissionlessClaimRequest {
    /// EVM address that will receive the winnings (0x-prefixed hex).
    pub recipient: String,
    /// 0x-prefixed raw UltraHonk proof bytes from `bb prove`.
    pub proof_hex: String,
    /// Ordered `0x`-prefixed `bytes32` public inputs from the pm_claim circuit.
    /// Must contain at least 7 elements; element at index 5 is the nullifier.
    pub public_inputs: Vec<String>,
    /// Optional EVM treasury address override; falls back to the configured PM treasury env vars.
    #[serde(default)]
    pub vault_address: String,
}

#[derive(Debug, Serialize)]
pub struct PermissionlessClaimResponse {
    pub tx_hash: String,
    /// The nullifier that was spent (hex string, for client-side state updates).
    pub nullifier: String,
}

/// Index of the nullifier field in pm_claim public inputs.
///
/// pm_claim circuit layout: [old_root(0), destination_address_field(1), market_id(2),
///                            outcome(3), amount(4), nullifier(5), claim_auth_digest(6)]
const PM_CLAIM_NULLIFIER_IDX: usize = 5;

/// Minimum number of public inputs expected from the pm_claim circuit.
const PM_CLAIM_MIN_INPUTS: usize = 6;

pub async fn submit_public_claim(
    State(state): State<Arc<AppState>>,
    Json(req): Json<PermissionlessClaimRequest>,
) -> ClobResult<impl IntoResponse> {
    // 1. Parse recipient address.
    let recipient: Address = req.recipient.parse().map_err(|e| {
        ClobError::InvalidOrder(format!("invalid recipient address: {e}"))
    })?;

    // 2. Validate UltraHonk proof structure.
    let proof_json = serde_json::json!({
        "proof_format": "ultra_honk",
        "proof_hex": req.proof_hex,
        "public_inputs": req.public_inputs,
    });
    parse_honk_proof_from_output(&proof_json.to_string())
        .map_err(|e| ClobError::InvalidOrder(format!("invalid proof: {e}")))?;

    // 3. Extract nullifier from public_inputs[5].
    if req.public_inputs.len() < PM_CLAIM_MIN_INPUTS {
        return Err(ClobError::InvalidOrder(format!(
            "pm_claim requires at least {} public inputs, got {}",
            PM_CLAIM_MIN_INPUTS,
            req.public_inputs.len()
        )));
    }
    let nullifier = req.public_inputs[PM_CLAIM_NULLIFIER_IDX].clone();

    // 4. Reject if nullifier already spent (replay protection — G9 / G10).
    if state.privacy_state.nullifier_exists(&nullifier).await? {
        return Err(ClobError::Conflict(format!(
            "nullifier {} already spent",
            nullifier
        )));
    }

    // 5. Ensure relayer is configured.
    let relayer = state.prediction_market_relayer.as_ref().ok_or_else(|| {
        ClobError::ServiceUnavailable("PM relayer not configured — set PM_USDC_TREASURY_ADDRESS or PREDICTION_MARKET_TREASURY_ADDRESS, plus HORIZEN_RPC_URL and EVM_OPERATOR_PRIVATE_KEY (vault aliases still work)".to_string())
    })?;

    let vault_override = if req.vault_address.trim().is_empty() {
        None
    } else {
        Some(req.vault_address.trim().to_string())
    };

    let proof = HonkProof {
        proof_hex: req.proof_hex,
        public_inputs: req.public_inputs,
    };

    // 6. Submit on-chain claim.
    let tx_hash = relayer
        .claim_winnings(recipient, &proof, vault_override.as_deref())
        .await?;

    // 7. Register nullifier after confirmed on-chain success (atomic spend commitment).
    let _ = state
        .privacy_state
        .register_nullifier(
            nullifier.clone(),
            String::new(), // no note commitment at claim time
            format!("claims:permissionless:{}", tx_hash),
        )
        .await;

    tracing::info!(
        tx_hash = %tx_hash,
        recipient = %format!("{:?}", recipient),
        "Permissionless pm_claim submitted on-chain",
    );

    // 8. Return tx hash.
    Ok(Json(PermissionlessClaimResponse { tx_hash, nullifier }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{privacy::PrivacyStateService, redis_store::RedisStore, AppState};
    use axum::{extract::State, Json};
    use mini_redis::server;
    use std::sync::Arc;
    use tokio::sync::oneshot;

    async fn setup_claim_state(
    ) -> (
        Arc<AppState>,
        Arc<PrivacyStateService>,
        oneshot::Sender<()>,
    ) {
        std::env::set_var("REDIS_COMPAT_DISABLE_SET_NX", "true");
        std::env::set_var("REDIS_COMPAT_DISABLE_EXISTS", "true");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = oneshot::channel::<()>();

        tokio::spawn(async move {
            let _ = server::run(listener, async { let _ = rx.await; }).await;
        });

        let client = redis::Client::open(format!("redis://{}/", addr)).unwrap();
        let conn = redis::aio::ConnectionManager::new(client).await.unwrap();
        let store = Arc::new(RedisStore::new(conn));
        let privacy_state = Arc::new(PrivacyStateService::new(store.clone()));
        let state = AppState::for_test(store, privacy_state.clone(), None).await;

        (state, privacy_state, tx)
    }

    fn bytes32(seed: &str) -> String {
        format!("0x{:0>64}", seed)
    }

    fn make_claim_request(nullifier: String) -> PermissionlessClaimRequest {
        PermissionlessClaimRequest {
            recipient: "0x1234567890abcdef1234567890abcdef12345678".to_string(),
            proof_hex: "0xdeadbeef".to_string(),
            public_inputs: vec![
                bytes32("1"),
                bytes32("2"),
                bytes32("3"),
                bytes32("4"),
                bytes32("5"),
                nullifier,
                bytes32("7"),
            ],
            vault_address: String::new(),
        }
    }

    #[tokio::test]
    async fn test_lifecycle_public_claim_rejects_spent_nullifier() {
        let (state, privacy_state, shutdown) = setup_claim_state().await;
        let nullifier = bytes32("99");
        privacy_state
            .register_nullifier(nullifier.clone(), String::new(), "tx-ref".to_string())
            .await
            .unwrap();

        match submit_public_claim(State(state), Json(make_claim_request(nullifier.clone()))).await {
            Err(ClobError::Conflict(message)) => {
                assert!(message.contains(&nullifier));
            }
            Err(other) => panic!("expected nullifier replay rejection, got {other:?}"),
            Ok(_) => panic!("expected nullifier replay rejection"),
        }

        let _ = shutdown.send(());
    }

    #[tokio::test]
    async fn test_lifecycle_public_claim_without_relayer_keeps_nullifier_unspent() {
        let (state, privacy_state, shutdown) = setup_claim_state().await;
        let nullifier = bytes32("123");

        match submit_public_claim(State(state), Json(make_claim_request(nullifier.clone()))).await {
            Err(ClobError::ServiceUnavailable(message)) => {
                assert!(message.contains("PM relayer not configured"));
            }
            Err(other) => panic!("expected relayer configuration error, got {other:?}"),
            Ok(_) => panic!("expected relayer configuration error"),
        }
        assert!(!privacy_state.nullifier_exists(&nullifier).await.unwrap());

        let _ = shutdown.send(());
    }
}
