use axum::{response::IntoResponse, Json};
use serde_json::json;

pub async fn health_check() -> impl IntoResponse {
    Json(json!({
        "status": "healthy",
        "service": "clob-service",
        "timestamp": chrono::Utc::now().to_rfc3339(),
    }))
}

pub async fn readiness_check() -> impl IntoResponse {
    // TODO: Check Redis connection, etc.
    Json(json!({
        "status": "ready",
        "checks": {
            "redis": "ok",
            "matching_engine": "ok",
        }
    }))
}
