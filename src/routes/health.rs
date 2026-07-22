use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde_json::json;
use std::sync::Arc;

use crate::AppState;

pub async fn health_check() -> impl IntoResponse {
    Json(json!({
        "status": "healthy",
        "service": "clob-service",
        "timestamp": chrono::Utc::now().to_rfc3339(),
    }))
}

pub async fn readiness_check(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let redis_ok = state.redis_store.ping().await.is_ok();
    let status = if redis_ok { "ready" } else { "not_ready" };
    let http_status = if redis_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        http_status,
        Json(json!({
            "status": status,
            "checks": {
                "redis": if redis_ok { "ok" } else { "error" },
                "matching_engine": "ok",
            }
        })),
    )
}
