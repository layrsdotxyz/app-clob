use axum::{extract::{Extension, Query, State}, http::{HeaderMap, StatusCode}, Json};
use chrono::Utc;
use uuid::Uuid;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::str::FromStr;

use crate::{auth::AuthenticatedUser, AppState};

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

    state.balance_service.deposit(&req.user_id, &req.market_id, amount);

    let new_balance = state.balance_service.get_total_balance(&req.user_id, &req.market_id);

    Ok(Json(DepositResponse {
        success: true,
        user_id: req.user_id,
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
}

#[derive(Debug, Serialize)]
pub struct BalanceProofResponse {
    pub balance_proof_id: String,
    pub status: String,
}

/// POST /v1/balance/proof
///
/// Validates the UltraHonk proof format and nullifier freshness, then records a
/// 5-minute soft-lock so the accounting layer knows this balance note is committed.
/// The proof is NOT verified on-chain here — that happens during settlement.
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

    // Validate UltraHonk proof structure without executing the prover.
    let proof_json = serde_json::json!({
        "proof_format": "ultra_honk",
        "proof_hex": req.honk_proof_hex,
        "public_inputs": req.public_inputs,
    });
    crate::proof_generation::parse_honk_proof_from_output(&proof_json.to_string())
        .map_err(|e| reject(&format!("invalid proof: {e}")))?;

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

    // Record a soft-lock so the same note cannot be submitted twice simultaneously.
    let balance_proof_id = Uuid::new_v4().to_string();
    let now = Utc::now().timestamp();
    let soft_lock = serde_json::json!({
        "balance_proof_id": balance_proof_id,
        "user_id": auth.user_id,
        "order_commitment": req.order_commitment,
        "market_id": req.market_id,
        "balance_proof_digest": req.balance_proof_digest,
        "created_at": now,
        "expires_at": now + BALANCE_PROOF_TTL_SECS as i64,
    });
    let lock_key = format!("balance_proof:{}", req.note_nullifier_hash);
    // Ignore errors here — the soft-lock is advisory; the hard constraint is
    // nullifier registration at reveal time.
    let _ = state
        .redis_store
        .set_with_expiry(&lock_key, &soft_lock.to_string(), BALANCE_PROOF_TTL_SECS)
        .await;

    Ok(Json(BalanceProofResponse {
        balance_proof_id,
        status: "accepted".to_string(),
    }))
}
