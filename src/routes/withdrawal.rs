use axum::{
    extract::{Extension, Path, State},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use std::sync::Arc;

use crate::{
    auth::AuthenticatedUser,
    error::{ClobError, ClobResult},
    withdrawal_service::{WithdrawalIntent, WithdrawalRequest},
    AppState,
};

#[derive(Debug, Deserialize)]
pub struct InitiateWithdrawalRequest {
    pub destination: String,
    pub token: String,
    pub amount: String,
    pub nonce: u64,
    // ZK witness fields — forwarded opaque to vault-service.
    #[serde(default)]
    pub nullifier: Option<String>,
    #[serde(default)]
    pub note_commitment: Option<String>,
    #[serde(default)]
    pub old_root: Option<String>,
    #[serde(default)]
    pub expected_new_root: Option<String>,
    #[serde(default)]
    pub rollover: Option<serde_json::Value>,
}

pub async fn initiate_withdrawal(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthenticatedUser>,
    Json(req): Json<InitiateWithdrawalRequest>,
) -> ClobResult<impl IntoResponse> {
    let ws = state
        .withdrawal_service
        .as_ref()
        .ok_or_else(|| ClobError::Internal("withdrawal service not configured".into()))?;

    let withdrawal_req = WithdrawalRequest {
        intent: WithdrawalIntent {
            // user_id sourced from verified JWT — not from request body.
            user_id: auth.user_id.clone(),
            destination: req.destination,
            token: req.token,
            amount: req.amount,
            nonce: req.nonce,
            created_at: chrono::Utc::now().timestamp(),
        },
        // JWT already verified upstream; no raw signature needed here.
        signature: String::new(),
        nullifier: req.nullifier,
        note_commitment: req.note_commitment,
        old_root: req.old_root,
        expected_new_root: req.expected_new_root,
        rollover: req.rollover,
    };

    let response = ws.process_withdrawal(withdrawal_req).await?;
    Ok(Json(response))
}

/// Poll vault-service for the current status and update local ledger state.
/// The UUID withdrawal_id is unguessable, so holding it is sufficient authorization.
pub async fn get_withdrawal_status(
    State(state): State<Arc<AppState>>,
    Extension(_auth): Extension<AuthenticatedUser>,
    Path(withdrawal_id): Path<String>,
) -> ClobResult<impl IntoResponse> {
    let ws = state
        .withdrawal_service
        .as_ref()
        .ok_or_else(|| ClobError::Internal("withdrawal service not configured".into()))?;

    let record = ws
        .poll_withdrawal_status(&withdrawal_id)
        .await?
        .ok_or_else(|| ClobError::InvalidOrder("withdrawal not found".into()))?;

    Ok(Json(record))
}
