use crate::{error::ClobResult, proof_observability, AppState};
use axum::{
    extract::{Path, Query, State},
    response::IntoResponse,
    Json,
};
use std::{collections::HashMap, sync::Arc};

/// GET /v1/proofs/:proof_id
pub async fn get_proof_attempt(
    State(state): State<Arc<AppState>>,
    Path(proof_id): Path<String>,
) -> ClobResult<impl IntoResponse> {
    let attempt = proof_observability::get_attempt(&state.redis_store, &proof_id).await?;
    Ok(Json(attempt))
}

/// GET /v1/proofs/user/:user_id?type=pm_settlement
pub async fn list_user_proof_attempts(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> ClobResult<impl IntoResponse> {
    let filter_type = params.get("type").map(String::as_str);
    let attempts =
        proof_observability::list_user_attempts(&state.redis_store, &user_id, filter_type).await?;
    Ok(Json(attempts))
}
