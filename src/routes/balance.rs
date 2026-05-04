use axum::{extract::{Extension, Query, State}, http::{HeaderMap, StatusCode}, Json};
use chrono::Utc;
use uuid::Uuid;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::str::FromStr;
use tempfile::tempdir;
use ethers::types::U256;

use crate::{auth::AuthenticatedUser, proof_generation::HonkProof, AppState};

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(crate) enum AmountValue {
    String(String),
    Number(i64),
    Float(f64),
}

impl AmountValue {
    fn to_decimal(&self) -> Result<Decimal, String> {
        match self {
            AmountValue::String(s) => Decimal::from_str(s).map_err(|e| e.to_string()),
            AmountValue::Number(n) => Ok(Decimal::from(*n)),
            AmountValue::Float(f) => Decimal::try_from(*f).map_err(|e| e.to_string()),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct DepositRequest {
    pub user_id: String,
    pub market_id: String,
    pub amount: AmountValue,
}

#[derive(Debug, Serialize)]
pub struct DepositResponse {
    pub success: bool,
    pub user_id: String,
    pub market_id: String,
    pub new_balance: String,
}

/// Internal operator endpoint — credits a user's balance after an on-chain deposit is
/// confirmed by the vault-service deposit listener.
///
/// Requires `X-Operator-Key` header matching the `OPERATOR_BRIDGE_KEY` env var.
/// In local dev, bypassed when `DYNAMIC_AUTH_BYPASS=true`.
pub async fn deposit_balance(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<DepositRequest>,
) -> Result<Json<DepositResponse>, StatusCode> {
    // Operator-only: verify X-Operator-Key.
    let bypass = std::env::var("DYNAMIC_AUTH_BYPASS").as_deref() == Ok("true");
    if !bypass {
        let expected = std::env::var("OPERATOR_BRIDGE_KEY").unwrap_or_default();
        if expected.is_empty() {
            // Key not configured — deny to prevent accidental open access.
            tracing::error!("OPERATOR_BRIDGE_KEY is not set; refusing deposit_balance call");
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        let provided = headers
            .get("x-operator-key")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if provided != expected {
            return Err(StatusCode::UNAUTHORIZED);
        }
    }

    if req.user_id.trim().is_empty() || req.market_id.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let amount = req.amount.to_decimal()
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    // Normalize wallet addresses to lowercase so deposits and order-time
    // balance lookups (which go through `auth.rs` → also lowercased) always
    // share the same key. Mixed EIP-55 checksum casing would otherwise produce
    // a separate balance bucket the matching engine never sees.
    let user_id = req.user_id.trim().to_lowercase();

    // Balance is stored under the global "USDC" token key regardless of which market
    // the deposit references. The matching engine always checks the "USDC" bucket, so
    // depositing to any other key would produce a balance the order check never sees.
    state.balance_service.deposit(&user_id, "USDC", amount);

    let new_balance = state.balance_service.get_total_balance(&user_id, "USDC");
    let reserved = state.balance_service.get_reserved_balance(&user_id, "USDC");
    let available = state.balance_service.get_available_balance(&user_id, "USDC");
    state.ws_manager.send_balance_update(
        &user_id,
        &new_balance.to_string(),
        &reserved.to_string(),
        &available.to_string(),
    );

    Ok(Json(DepositResponse {
        success: true,
        user_id,
        market_id: req.market_id,
        new_balance: new_balance.to_string(),
    }))
}

#[derive(Debug, Serialize)]
pub struct BalanceSufficiencyResponse {
    pub user_id: String,
    pub market_id: String,
    /// True when a non-expired balance proof soft-lock exists for the given
    /// `nullifier_hash` query parameter (G1 / G11).
    pub has_active_proof: bool,
}

#[derive(Debug, Deserialize)]
pub struct BalanceQuery {
    pub nullifier_hash: Option<String>,
}

/// Get balance proof sufficiency for a user in a market (G1/G11).
///
/// Self-scoped: the authenticated caller may only query their own state.
/// Pass `?nullifier_hash=<hash>` to check whether a valid proof soft-lock
/// exists for that note. Without the query param `has_active_proof` is false.
pub async fn get_balance(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthenticatedUser>,
    axum::extract::Path((user_id, market_id)): axum::extract::Path<(String, String)>,
    Query(query): Query<BalanceQuery>,
) -> Result<Json<BalanceSufficiencyResponse>, StatusCode> {
    // Self-scope enforcement: only the owning wallet may read its own state.
    if auth.user_id.to_lowercase() != user_id.to_lowercase() {
        return Err(StatusCode::FORBIDDEN);
    }

    let has_active_proof = match &query.nullifier_hash {
        Some(nullifier_hash) if !nullifier_hash.is_empty() => {
            let key = format!("balance_proof:{}", nullifier_hash);
            state
                .redis_store
                .get_optional(&key)
                .await
                .unwrap_or(None)
                .is_some()
        }
        _ => false,
    };

    Ok(Json(BalanceSufficiencyResponse {
        user_id,
        market_id,
        has_active_proof,
    }))
}

#[derive(Debug, Serialize)]
pub struct UserBalanceResponse {
    pub usdc_total: String,
    pub usdc_reserved: String,
    pub usdc_available: String,
}

/// GET /v1/balance/:user_id
///
/// Returns the user's current USDC balance (total, reserved, available).
/// Reads directly from the in-memory DashMap — always reflects the current
/// state including open order reserves and recent fills.
/// Self-scoped: the authenticated caller may only query their own balance.
pub async fn get_user_balance(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthenticatedUser>,
    axum::extract::Path(user_id): axum::extract::Path<String>,
) -> Result<Json<UserBalanceResponse>, StatusCode> {
    if auth.user_id.to_lowercase() != user_id.to_lowercase() {
        return Err(StatusCode::FORBIDDEN);
    }
    let uid = user_id.to_lowercase();
    let total = state.balance_service.get_total_balance(&uid, "USDC");
    let reserved = state.balance_service.get_reserved_balance(&uid, "USDC");
    let available = state.balance_service.get_available_balance(&uid, "USDC");
    Ok(Json(UserBalanceResponse {
        usdc_total: total.to_string(),
        usdc_reserved: reserved.to_string(),
        usdc_available: available.to_string(),
    }))
}

// ─── ZK balance proof submission ─────────────────────────────────────────────

/// TTL for balance proof soft-lock records (5 minutes).
const BALANCE_PROOF_TTL_SECS: u64 = 300;

/// Request body for `POST /v1/balance/proof`.
///
/// The client submits a UltraHonk balance proof to register intent to place a
/// privacy-preserving order. The server validates structure, checks the nullifier
/// for double-use, and records a soft-lock keyed on the nullifier hash.
#[derive(Debug, Deserialize)]
pub struct BalanceProofRequest {
    /// Hash of the note nullifier — must not already be registered.
    pub note_nullifier_hash: String,
    /// `balance_proof_digest` from the proof's public inputs.
    pub balance_proof_digest: String,
    /// Commitment to the order this proof is being used for.
    pub order_commitment: String,
    /// Target market.
    pub market_id: String,
    /// 0x-prefixed raw proof bytes from `bb prove`.
    pub honk_proof_hex: String,
    /// Ordered `0x`-prefixed `bytes32` public inputs.
    pub public_inputs: Vec<String>,
    /// Optional full circuit witness (snarkjs-format input object) for
    /// server-side ZK proof generation at settlement time. When provided it is
    /// stored in Redis keyed by `pending_witness:{user_id}:{market_id}` so that
    /// `create_order` can attach it to the `Order` without the frontend having
    /// to resend the (potentially large) witness in the order request itself.
    #[serde(default)]
    pub note_witness: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct BalanceProofResponse {
    pub balance_proof_id: String,
    pub status: String,
}

/// Cryptographically verify a UltraHonk balance proof using `bb verify`.
///
/// Requires env vars:
///   BALANCE_PROOF_BB_VK_DIR — path to directory containing the `vk` file
///                             produced by `bb write_vk` for pm_balance_proof.
///   BB_BIN                  — path to the `bb` binary (default: "bb").
///
/// The proof bytes (binary) are decoded from the 0x-prefixed hex sent by the
/// client and written to a temp file. `bb verify` embeds public inputs inside
/// the UltraHonk proof binary, so no separate public inputs file is needed.
/// Returns Ok(true) when verification ran, Ok(false) when skipped (not configured).
async fn verify_honk_balance_proof(honk_proof_hex: &str) -> Result<bool, String> {
    let vk_dir = match std::env::var("BALANCE_PROOF_BB_VK_DIR") {
        Ok(v) if !v.is_empty() => v,
        _ => {
            tracing::warn!(
                "BALANCE_PROOF_BB_VK_DIR not set — skipping server-side bb verify. \
                 Set this env var to enable cryptographic balance proof verification."
            );
            return Ok(false);
        }
    };
    let bb_bin = std::env::var("BB_BIN").unwrap_or_else(|_| "bb".to_string());

    let proof_hex = honk_proof_hex.trim_start_matches("0x");
    let proof_bytes = hex::decode(proof_hex)
        .map_err(|e| format!("invalid proof hex: {e}"))?;

    let tmp = tempdir().map_err(|e| format!("tempdir: {e}"))?;
    let proof_path = tmp.path().join("proof");
    std::fs::write(&proof_path, &proof_bytes)
        .map_err(|e| format!("write proof: {e}"))?;

    let vk_path  = format!("{}/vk", vk_dir);
    let proof_str = proof_path.to_str().unwrap().to_owned();

    let result = tokio::task::spawn_blocking(move || {
        std::process::Command::new(&bb_bin)
            .arg("verify")
            .arg("--scheme").arg("ultra_honk")
            .arg("-k").arg(&vk_path)
            .arg("-p").arg(&proof_str)
            .output()
    })
    .await
    .map_err(|e| format!("spawn_blocking: {e}"))?
    .map_err(|e| format!("bb verify exec: {e}"))?;

    // tmp dir (and proof file) are dropped here after bb exits.
    drop(tmp);

    if !result.status.success() {
        let stderr = String::from_utf8_lossy(&result.stderr);
        return Err(format!("proof cryptographically invalid: {stderr}"));
    }

    Ok(true)
}

fn parse_u256_from_hex(s: &str) -> Result<U256, String> {
    let stripped = s.trim_start_matches("0x").trim_start_matches("0X");
    U256::from_str_radix(stripped, 16).map_err(|e| format!("invalid U256 hex '{s}': {e}"))
}

/// POST /v1/balance/proof
///
/// Validates UltraHonk proof structure, runs `bb verify` for cryptographic
/// correctness, checks nullifier freshness, then records a 5-minute soft-lock.
pub async fn submit_balance_proof(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthenticatedUser>,
    Json(req): Json<BalanceProofRequest>,
) -> Result<Json<BalanceProofResponse>, (StatusCode, Json<serde_json::Value>)> {
    let reject = |msg: &str| {
        let body = serde_json::json!({ "error": msg });
        (StatusCode::UNPROCESSABLE_ENTITY, Json(body))
    };

    if req.note_nullifier_hash.is_empty()
        || req.balance_proof_digest.is_empty()
        || req.order_commitment.is_empty()
        || req.market_id.is_empty()
    {
        return Err(reject("all fields are required"));
    }

    // Structural parse — catches obviously malformed payloads before bb verify.
    let proof_json = serde_json::json!({
        "proof_format": "ultra_honk",
        "proof_hex": req.honk_proof_hex,
        "public_inputs": req.public_inputs,
    });
    crate::proof_generation::parse_honk_proof_from_output(&proof_json.to_string())
        .map_err(|e| reject(&format!("invalid proof structure: {e}")))?;

    // Cryptographic verification — rejects fake/invalid proofs before they can
    // enter the matching engine and cause stuck settlements.
    // Skipped (with a warning) when BALANCE_PROOF_BB_VK_DIR is not configured.
    match verify_honk_balance_proof(&req.honk_proof_hex).await {
        Ok(true)  => tracing::info!("balance proof cryptographically verified via bb"),
        Ok(false) => { /* warned inside verify_honk_balance_proof */ }
        Err(e)    => return Err(reject(&format!("proof verification failed: {e}"))),
    }

    // Double-spend check.
    let spent = state
        .privacy_state
        .nullifier_exists(&req.note_nullifier_hash)
        .await
        .map_err(|e| reject(&e.to_string()))?;
    if spent {
        return Err(reject(&format!(
            "nullifier {} already spent",
            req.note_nullifier_hash
        )));
    }

    // Record a 5-minute soft-lock keyed on the nullifier hash.
    let balance_proof_id = Uuid::new_v4().to_string();
    let now = Utc::now().timestamp();
    let lock_expiry_ts = (now + BALANCE_PROOF_TTL_SECS as i64) as u64;
    let soft_lock = serde_json::json!({
        "balance_proof_id": balance_proof_id,
        "user_id": auth.user_id,
        "order_commitment": req.order_commitment,
        "market_id": req.market_id,
        "balance_proof_digest": req.balance_proof_digest,
        "created_at": now,
        "expires_at": lock_expiry_ts,
    });
    let lock_key = format!("balance_proof:{}", req.note_nullifier_hash);
    let _ = state
        .redis_store
        .set_with_expiry(&lock_key, &soft_lock.to_string(), BALANCE_PROOF_TTL_SECS)
        .await;

    // If the client supplied a circuit witness, park it in Redis so that
    // `create_order` can attach it to the Order without requiring the
    // (potentially large) witness to be resent in the order request body.
    // TTL matches the balance-proof soft-lock (5 minutes); consumed on first use.
    if let Some(witness) = &req.note_witness {
        match serde_json::to_string(witness) {
            Ok(witness_json) => {
                let witness_key = format!("pending_witness:{}:{}", auth.user_id, req.market_id);
                let _ = state
                    .redis_store
                    .set_with_expiry(&witness_key, &witness_json, BALANCE_PROOF_TTL_SECS)
                    .await;
                tracing::debug!(
                    user_id = %auth.user_id,
                    market_id = %req.market_id,
                    "Stored pending note_witness for order submission"
                );
            }
            Err(e) => {
                tracing::warn!("Failed to serialize note_witness for Redis storage: {e}");
            }
        }
    }

    // Fire-and-forget on-chain lockCollateral — settleFill requires noteLockExpiry != 0.
    // required_amount is public_inputs[2] per pm_balance_proof.nr circuit layout.
    if let Some(relayer) = state.prediction_market_relayer.clone() {
        let order_commitment_hex = req.order_commitment.clone();
        let proof = HonkProof {
            proof_hex: req.honk_proof_hex.clone(),
            public_inputs: req.public_inputs.clone(),
        };
        let required_amount_hex = req.public_inputs.get(2).cloned().unwrap_or_default();
        tokio::spawn(async move {
            let order_commitment = match crate::prediction_market_relayer::decode_bytes32_pub(
                &order_commitment_hex, "order_commitment"
            ) {
                Ok(v) => v,
                Err(e) => { tracing::warn!("lockCollateral: bad order_commitment: {e}"); return; }
            };
            let required_amount = match parse_u256_from_hex(&required_amount_hex) {
                Ok(v) => v,
                Err(e) => { tracing::warn!("lockCollateral: bad required_amount: {e}"); return; }
            };
            if let Err(e) = relayer.lock_collateral(
                order_commitment, required_amount, lock_expiry_ts, &proof, None
            ).await {
                tracing::warn!("lockCollateral on-chain failed: {e}");
            } else {
                tracing::info!("lockCollateral on-chain succeeded for commitment {order_commitment_hex}");
            }
        });
    }

    Ok(Json(BalanceProofResponse {
        balance_proof_id,
        status: "accepted".to_string(),
    }))
}
