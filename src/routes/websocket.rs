use crate::AppState;
use axum::{
    extract::{ws::WebSocketUpgrade, Query, State},
    response::IntoResponse,
};
use serde::Deserialize;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct WsQuery {
    /// Optional JWT token for user channel access. Passed as `?token=<jwt>` since
    /// browser WebSocket cannot set custom headers.
    pub token: Option<String>,
}

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    Query(query): Query<WsQuery>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_socket(socket, state, query.token))
}

async fn handle_socket(
    socket: axum::extract::ws::WebSocket,
    state: Arc<AppState>,
    token: Option<String>,
) {
    // Try to authenticate user from the query-string token.
    // An unauthenticated user can still subscribe to public channels.
    let user_id = if let Some(ref t) = token {
        verify_ws_token(t).await
    } else {
        None
    };

    state.ws_manager.handle_connection(socket, user_id).await;
}

/// Lightweight JWT verification for WebSocket — reuses the same JWKS cache as
/// the HTTP auth middleware. Returns `None` on any failure (fail-open for WS
/// public channels).
async fn verify_ws_token(token: &str) -> Option<String> {
    use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Claims {
        sub: String,
    }

    let env_id = std::env::var("DYNAMIC_ENVIRONMENT_ID").ok()?;
    if env_id.is_empty() {
        return None;
    }

    let header = decode_header(token).ok()?;

    // Re-use the shared JWKS cache from auth.rs via the same statics
    let jwks = crate::auth::get_jwks_for_ws(&env_id).await.ok()?;

    let jwk = match header.kid.as_deref() {
        Some(kid) => jwks.find(kid)?.clone(),
        None => jwks.keys.first()?.clone(),
    };

    let decoding_key = DecodingKey::from_jwk(&jwk).ok()?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_aud = false;
    validation.set_issuer(&[format!("app.dynamicauth.com/{}", env_id)]);

    decode::<Claims>(token, &decoding_key, &validation)
        .ok()
        .map(|td| td.claims.sub)
}
