use crate::AppState;
use axum::{extract::State, response::IntoResponse};
use std::sync::Arc;

pub async fn metrics_handler(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    match state.metrics.render() {
        Ok(metrics) => (
            axum::http::StatusCode::OK,
            [("Content-Type", "text/plain; version=0.0.4")],
            metrics,
        ),
        Err(e) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            [("Content-Type", "text/plain")],
            format!("Error rendering metrics: {}", e),
        ),
    }
}
