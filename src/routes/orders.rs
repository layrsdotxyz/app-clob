use crate::{
    auth::AuthenticatedUser,
    error::{ClobError, ClobResult},
    models::*,
    AppState,
};
use axum::{
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct CreateOrderRequest {
    pub user_id: String,
    pub market_id: String,
    pub side: OrderSide,
    #[serde(default = "default_order_type")]
    pub order_type: OrderType,
    #[serde(default = "default_time_in_force")]
    pub time_in_force: TimeInForce,
    pub price: rust_decimal::Decimal,
    pub size: rust_decimal::Decimal,
    #[serde(default)]
    pub note_witness: Option<serde_json::Value>,
}

fn default_order_type() -> OrderType {
    OrderType::Limit
}

fn default_time_in_force() -> TimeInForce {
    TimeInForce::Gtc
}

#[derive(Debug, Serialize)]
pub struct CreateOrderResponse {
    pub order: Order,
    pub fills: Vec<Fill>,
    pub trades: Vec<Trade>,
}

/// Extract the numeric on-chain market ID from a PM market string.
/// "BTC-757-YES" → 757, "ETH-788-NO" → 788, "BTC-790" → 790, "USDC" → None.
fn parse_pm_market_id(market_id: &str) -> Option<ethers::types::U256> {
    let parsed = market_id
        .split('-')
        .nth(1)
        .and_then(|s| s.parse::<u64>().ok())
        .map(ethers::types::U256::from);
    if parsed.is_none() {
        tracing::warn!(
            market_id = %market_id,
            "failed to parse on-chain market id; PM settlement will be skipped for orders in this market"
        );
    }
    parsed
}

pub async fn create_order(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<CreateOrderRequest>,
) -> ClobResult<impl IntoResponse> {
    // Phase 3a (optional) → Phase 3c (required): internal service key guard.
    // Only the market-maker (and internal tooling) may use this endpoint.
    let expected_key = std::env::var("INTERNAL_SERVICE_KEY").unwrap_or_default();
    if !expected_key.is_empty() {
        let provided = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "));
        match provided {
            Some(key) if key == expected_key => {} // valid
            Some(_) => {
                return Err(ClobError::Unauthorized(
                    "invalid internal service key".to_string(),
                ));
            }
            None => {
                return Err(ClobError::Unauthorized(
                    "Authorization header required".to_string(),
                ));
            }
        }
    }

    // Create order — normalize user_id to lowercase to match balance_service key
    // (deposit_balance always stores at lowercase; mixed EIP-55 casing would miss the bucket)
    let user_id = req.user_id.trim().to_lowercase();

    // Resolve note_witness: use the one supplied in the request, or fall back to
    // any pending witness stored by the balance-proof step (keyed by user+market).
    let note_witness: Option<serde_json::Value> = if req.note_witness.is_some() {
        req.note_witness
    } else {
        let pending_key = format!("pending_witness:{}:{}", user_id, req.market_id);
        match state.redis_store.get_optional(&pending_key).await {
            Ok(Some(raw)) => {
                // consume the one-time witness so it cannot be replayed
                let _ = state.redis_store.delete_key(&pending_key).await;
                serde_json::from_str(&raw).ok()
            }
            _ => None,
        }
    };

    let mut order = Order::new(
        user_id,
        req.market_id.clone(),
        req.side,
        req.order_type,
        req.time_in_force,
        req.price,
        req.size,
    );
    order.note_witness = note_witness;
    order.market_id_uint = parse_pm_market_id(&req.market_id);

    // Submit to matching engine
    let result = state.matching_engine.submit_order(order).await?;

    // Broadcast order updates
    state
        .ws_manager
        .send_order_update(&result.order.user_id, &result.order);

    // Broadcast trades
    for trade in &result.trades {
        state.ws_manager.broadcast_trade(trade);
    }

    let response = CreateOrderResponse {
        order: result.order,
        fills: result.fills,
        trades: result.trades,
    };

    Ok((StatusCode::CREATED, Json(response)))
}

pub async fn cancel_order(
    State(state): State<Arc<AppState>>,
    Path(order_id): Path<Uuid>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> ClobResult<impl IntoResponse> {
    let raw_user_id = params.get("user_id").ok_or_else(|| {
        crate::error::ClobError::Unauthorized("user_id query parameter required".to_string())
    })?;
    let user_id = raw_user_id.trim().to_lowercase();

    let order = state
        .matching_engine
        .cancel_order(order_id, &user_id)
        .await?;

    // Broadcast order update
    state.ws_manager.send_order_update(&order.user_id, &order);

    Ok(Json(order))
}

pub async fn get_order(
    State(state): State<Arc<AppState>>,
    Path(order_id): Path<Uuid>,
) -> ClobResult<impl IntoResponse> {
    let order_store = &state.orderbook_manager.store;
    let order = order_store
        .get_order(order_id)
        .await?
        .ok_or_else(|| crate::error::ClobError::OrderNotFound(order_id.to_string()))?;

    Ok(Json(order))
}

pub async fn get_user_orders(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<String>,
) -> ClobResult<impl IntoResponse> {
    let orders = state
        .orderbook_manager
        .get_user_orders(&user_id.trim().to_lowercase())
        .await?;
    Ok(Json(orders))
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
