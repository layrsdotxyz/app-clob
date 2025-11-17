use crate::AppState;
use axum::{
    extract::{ws::WebSocketUpgrade, State},
    response::IntoResponse,
};
use std::sync::Arc;

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_socket(socket, state))
}

async fn handle_socket(
    socket: axum::extract::ws::WebSocket,
    state: Arc<AppState>,
) {
    // TODO: Extract user_id from auth headers or query params
    let user_id = None;
    
    state.ws_manager.handle_connection(socket, user_id).await;
}
