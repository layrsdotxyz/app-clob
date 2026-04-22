use crate::AppState;
use axum::{
    extract::{ws::WebSocketUpgrade, Query, State},
    response::IntoResponse,
};
use serde::Deserialize;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct WsQuery {
    /// Optional wallet address for user channel access. Passed as `?address=<wallet>`
    /// since browser WebSocket cannot set custom headers.
    /// Provided by Dynamic's `primaryWallet.address` when `isConnected` is true.
    pub address: Option<String>,
}

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    Query(query): Query<WsQuery>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_socket(socket, state, query.address))
}

async fn handle_socket(
    socket: axum::extract::ws::WebSocket,
    state: Arc<AppState>,
    address: Option<String>,
) {
    // Use wallet address as user_id if provided; fall back to public-only channel.
    let user_id = address.filter(|a| !a.is_empty());
    state.ws_manager.handle_connection(socket, user_id).await;
}
