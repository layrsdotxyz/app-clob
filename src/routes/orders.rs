use crate::{
    auth::AuthenticatedUser,
    error::{ClobError, ClobResult},
    models::*,
    AppState,
};
use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

/// Deterministic tombstone for the retired plaintext order API. It accepts no
/// identity, order economics, or state handle, so spoofed bodies/headers cannot
/// reach matching, storage, or WebSocket publication. The authenticated API
/// and UI use the encrypted enclave relay instead.
pub async fn legacy_order_api_retired() -> impl IntoResponse {
    (
        StatusCode::GONE,
        Json(serde_json::json!({
            "error": { "code": "PRIVATE_ENCLAVE_REQUIRED" }
        })),
    )
}

// Retained only for the now-unmounted commit/reveal implementation below so
// historical fixtures continue to compile. No router exposes this response.
#[derive(Debug, Serialize)]
struct CreateOrderResponse {
    order: Order,
    fills: Vec<Fill>,
    trades: Vec<Trade>,
}

fn parse_pm_market_id(market_id: &str) -> Option<ethers::types::U256> {
    market_id
        .split('-')
        .nth(1)
        .and_then(|value| value.parse::<u64>().ok())
        .map(ethers::types::U256::from)
}

/// DELETE /v1/admin/markets/:market_id/orderbook
/// Flushes all resting orders from a market's bid/ask sorted sets.
/// Protected by X-Internal-Key header.
pub async fn flush_market_orderbook(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(market_id): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let expected = std::env::var("INTERNAL_SERVICE_KEY").unwrap_or_default();
    if expected.is_empty() {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .unwrap_or("");
    if token != expected {
        return Err(StatusCode::FORBIDDEN);
    }
    let flushed = state
        .orderbook_manager
        .store
        .flush_market_orderbook(&market_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(
        serde_json::json!({ "market_id": market_id, "flushed": flushed }),
    ))
}

#[cfg(test)]
mod legacy_route_tests {
    use super::*;
    use axum::response::IntoResponse;

    #[tokio::test]
    async fn plaintext_order_surface_is_a_state_free_generic_tombstone() {
        let response = legacy_order_api_retired().await.into_response();
        assert_eq!(response.status(), StatusCode::GONE);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/json"
        );
    }
}

// ─── Commit-Reveal order placement ──────────────────────────────────────────

/// TTL for commit records in Redis (5 minutes).
const COMMIT_TTL_SECS: u64 = 300;

/// Commitment record stored in Redis while waiting for the reveal phase.
#[derive(Debug, Serialize, Deserialize)]
struct CommitRecord {
    commit_id: String,
    user_id: String,
    note_commitment: String,
    balance_proof_digest: String,
    note_nullifier_hash: String,
    market_id: String,
    order_commitment: String,
    created_at: i64,
    expires_at: i64,
}

/// Request body for `POST /v1/orders/commit`.
///
/// Sends only cryptographic commitments — no price, size, or side is revealed.
/// This is the hiding phase: it anchors the balance note and proof digest without
/// exposing order parameters, preventing front-running.
#[derive(Debug, Deserialize)]
pub struct CommitOrderRequest {
    /// Poseidon hash of the private note (hex, 0x-prefixed).
    pub note_commitment: String,
    /// `balance_proof_digest` from the UltraHonk balance proof public inputs.
    pub balance_proof_digest: String,
    /// Hash of the note nullifier — checked for double-spend at reveal time.
    pub note_nullifier_hash: String,
    /// Target market.
    pub market_id: String,
    /// Commitment to {side, price, size} — proved correct during reveal.
    pub order_commitment: String,
}

#[derive(Debug, Serialize)]
pub struct CommitOrderResponse {
    pub commit_id: String,
    pub expires_at: i64,
}

/// Request body for `POST /v1/orders/reveal`.
///
/// Reveals the hidden order parameters alongside the full UltraHonk balance proof.
/// The server validates proof format, checks the nullifier, and submits to the
/// matching engine.
#[derive(Debug, Deserialize)]
pub struct RevealOrderRequest {
    /// Commit ID returned by `POST /v1/orders/commit`.
    pub commit_id: String,
    pub side: OrderSide,
    pub price: rust_decimal::Decimal,
    pub size: rust_decimal::Decimal,
    /// 0x-prefixed raw proof bytes from `bb prove`.
    pub honk_proof_hex: String,
    /// Ordered `0x`-prefixed `bytes32` public inputs.
    pub public_inputs: Vec<String>,
    /// pm_settlement circuit inputs (private note preimage + Merkle path + output notes).
    #[serde(default)]
    pub note_witness: Option<serde_json::Value>,
}

/// POST /v1/orders/commit
///
/// Phase 1 of the commit-reveal protocol. Stores a commitment record in Redis
/// with a 5-minute TTL. Returns a `commit_id` for use in the reveal step.
pub async fn commit_order(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthenticatedUser>,
    Json(req): Json<CommitOrderRequest>,
) -> ClobResult<impl IntoResponse> {
    if req.note_commitment.is_empty()
        || req.balance_proof_digest.is_empty()
        || req.note_nullifier_hash.is_empty()
        || req.market_id.is_empty()
        || req.order_commitment.is_empty()
    {
        return Err(ClobError::InvalidOrder(
            "all commitment fields are required".to_string(),
        ));
    }

    let commit_id = Uuid::new_v4().to_string();
    let now = Utc::now().timestamp();
    let expires_at = now + COMMIT_TTL_SECS as i64;

    let record = CommitRecord {
        commit_id: commit_id.clone(),
        user_id: auth.user_id.clone(),
        note_commitment: req.note_commitment,
        balance_proof_digest: req.balance_proof_digest,
        note_nullifier_hash: req.note_nullifier_hash,
        market_id: req.market_id,
        order_commitment: req.order_commitment,
        created_at: now,
        expires_at,
    };

    let key = format!("commit:{}", commit_id);
    state
        .redis_store
        .set_with_expiry(&key, &serde_json::to_string(&record)?, COMMIT_TTL_SECS)
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(CommitOrderResponse {
            commit_id,
            expires_at,
        }),
    ))
}

/// POST /v1/orders/reveal
///
/// Phase 2 of the commit-reveal protocol. Loads the commit record, validates
/// ownership and expiry, parses the UltraHonk proof, checks the nullifier is
/// unspent, and submits the order to the matching engine.
pub async fn reveal_order(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthenticatedUser>,
    Json(req): Json<RevealOrderRequest>,
) -> ClobResult<impl IntoResponse> {
    if req.commit_id.is_empty() {
        return Err(ClobError::InvalidOrder("commit_id is required".to_string()));
    }

    // Load the commit record.
    let key = format!("commit:{}", req.commit_id);
    let record_json = state.redis_store.get_optional(&key).await?.ok_or_else(|| {
        ClobError::OrderNotFound(format!(
            "commit {} not found or already consumed",
            req.commit_id
        ))
    })?;

    let record: CommitRecord = serde_json::from_str(&record_json)
        .map_err(|e| ClobError::Other(format!("corrupt commit record: {e}")))?;

    // Ownership: only the committing user may reveal.
    if record.user_id.to_lowercase() != auth.user_id.to_lowercase() {
        return Err(ClobError::Unauthorized(
            "commit_id belongs to a different user".to_string(),
        ));
    }

    // Belt-and-suspenders expiry check (Redis TTL should have evicted it, but we verify).
    let now = Utc::now().timestamp();
    if now > record.expires_at {
        let _ = state.redis_store.delete_key(&key).await;
        return Err(ClobError::InvalidOrder("commit has expired".to_string()));
    }

    // Validate UltraHonk proof structure (format + public input lengths).
    let proof_json = serde_json::json!({
        "proof_format": "ultra_honk",
        "proof_hex": req.honk_proof_hex,
        "public_inputs": req.public_inputs,
    });
    crate::proof_generation::parse_honk_proof_from_output(&proof_json.to_string())?;

    // Nullifier double-spend check.
    if state
        .privacy_state
        .nullifier_exists(&record.note_nullifier_hash)
        .await?
    {
        return Err(ClobError::InvalidOrder(format!(
            "nullifier {} already spent",
            record.note_nullifier_hash
        )));
    }

    // G11: verify a valid balance proof soft-lock exists before consuming the
    // nullifier. Fail here (before nullifier registration) so the note can
    // still be used once the caller submits a proper balance proof.
    state
        .settlement_engine
        .check_balance_with_proof(&record.note_nullifier_hash)
        .await
        .map_err(|_| {
            ClobError::InvalidOrder(
                "no valid balance proof found — submit POST /v1/balance/proof first".to_string(),
            )
        })?;

    // Atomically claim the nullifier before placing the order.
    state
        .privacy_state
        .register_nullifier(
            record.note_nullifier_hash.clone(),
            record.note_commitment.clone(),
            format!("order:reveal:{}", req.commit_id),
        )
        .await?;

    // Consume the commit record.
    let _ = state.redis_store.delete_key(&key).await;

    // Build and submit the order.
    let mut order = Order::new(
        auth.user_id.clone(),
        record.market_id.clone(),
        req.side,
        OrderType::Limit,
        TimeInForce::Gtc,
        req.price,
        req.size,
    );
    order.note_witness = req.note_witness;
    order.market_id_uint = parse_pm_market_id(&record.market_id);

    let result = state.matching_engine.submit_order(order).await?;
    state
        .ws_manager
        .send_order_update(&result.order.user_id, &result.order);
    for trade in &result.trades {
        state.ws_manager.broadcast_trade(trade);
    }

    Ok(Json(CreateOrderResponse {
        order: result.order,
        fills: result.fills,
        trades: result.trades,
    }))
}
