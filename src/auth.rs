//! JWT authentication middleware for Dynamic.xyz tokens.
//!
//! Protected routes require a valid `Authorization: Bearer <jwt>` header signed
//! by the Dynamic.xyz project corresponding to the `DYNAMIC_ENVIRONMENT_ID` env var.
//!
//! # Bypass
//! Set `DYNAMIC_AUTH_BYPASS=true` to skip verification during local development.
//! This MUST NOT be set in production.
//!
//! # JWKS caching
//! The JWKS key set is fetched at most once per hour and cached in a static
//! `OnceLock<RwLock<...>>` so every request does not incur a round-trip.

use std::{
    env,
    sync::OnceLock,
    time::{Duration, Instant},
};

use axum::{
    extract::Request,
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Json, Response},
};
use jsonwebtoken::{decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use tokio::sync::RwLock;

// ---------------------------------------------------------------------------
// JWKS cache
// ---------------------------------------------------------------------------

struct JwksCache {
    set: JwkSet,
    fetched_at: Instant,
}

static JWKS_CACHE: OnceLock<RwLock<Option<JwksCache>>> = OnceLock::new();

fn jwks_cache() -> &'static RwLock<Option<JwksCache>> {
    JWKS_CACHE.get_or_init(|| RwLock::new(None))
}

const JWKS_TTL: Duration = Duration::from_secs(3600);

async fn fetch_jwks(env_id: &str) -> Result<JwkSet, String> {
    let url = format!(
        "https://app.dynamicauth.com/api/v0/sdk/{}/.well-known/jwks",
        env_id
    );
    let resp = reqwest::get(&url)
        .await
        .map_err(|e| format!("JWKS fetch: {}", e))?;
    if !resp.status().is_success() {
        return Err(format!("JWKS endpoint returned {}", resp.status()));
    }
    let body = resp.text().await.map_err(|e| format!("JWKS read: {}", e))?;
    serde_json::from_str::<JwkSet>(&body)
        .map_err(|e| format!("JWKS parse: {} — body: {}", e, &body[..body.len().min(300)]))
}

/// Public re-export for the WebSocket handler so it can reuse the same cache.
pub async fn get_jwks_for_ws(env_id: &str) -> Result<JwkSet, String> {
    get_jwks(env_id).await
}

async fn get_jwks(env_id: &str) -> Result<JwkSet, String> {
    // Fast path: return cached set if still fresh
    {
        let guard = jwks_cache().read().await;
        if let Some(cached) = guard.as_ref() {
            if cached.fetched_at.elapsed() < JWKS_TTL {
                return Ok(cached.set.clone());
            }
        }
    }

    // Slow path: fetch and replace cache
    let fresh = fetch_jwks(env_id).await?;
    {
        let mut guard = jwks_cache().write().await;
        *guard = Some(JwksCache {
            set: fresh.clone(),
            fetched_at: Instant::now(),
        });
    }
    Ok(fresh)
}

// ---------------------------------------------------------------------------
// JWT claims
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct DynamicClaims {
    /// User DID, e.g. `did:privy:…` or a bare UUID — Dynamic varies by version.
    pub sub: String,
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

/// Axum middleware that enforces Dynamic.xyz JWT authentication.
///
/// Injects `AuthenticatedUser` as a request extension on success so downstream
/// handlers can retrieve it with `Extension(user): Extension<AuthenticatedUser>`.
pub async fn require_auth(mut req: Request, next: Next) -> Result<Response, Response> {
    let env_id = env::var("DYNAMIC_ENVIRONMENT_ID").unwrap_or_default();

    if env_id.is_empty() {
        // Auth env var missing — check if bypass is explicitly allowed
        if env::var("DYNAMIC_AUTH_BYPASS").as_deref() == Ok("true") {
            tracing::warn!(path = %req.uri().path(), "DYNAMIC_AUTH_BYPASS active; skipping auth");
            req.extensions_mut().insert(AuthenticatedUser {
                user_id: "bypass-user".to_string(),
            });
            return Ok(next.run(req).await);
        }
        tracing::error!("DYNAMIC_ENVIRONMENT_ID not set and bypass is off; rejecting request");
        return Err(auth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Auth service not configured",
        ));
    }

    let token = match extract_bearer(&req) {
        Some(t) => t.to_string(),
        None => return Err(auth_error(StatusCode::UNAUTHORIZED, "Missing Authorization header")),
    };

    // Decode JWT header to find the `kid`
    let header = match decode_header(&token) {
        Ok(h) => h,
        Err(_) => return Err(auth_error(StatusCode::UNAUTHORIZED, "Malformed JWT header")),
    };

    // Fetch (or return cached) JWKS
    let jwks = match get_jwks(&env_id).await {
        Ok(j) => j,
        Err(e) => {
            tracing::error!(error = %e, "Failed to fetch Dynamic.xyz JWKS");
            return Err(auth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Auth service temporarily unavailable",
            ));
        }
    };

    // Locate the signing key (clone to release borrow on `jwks`)
    let jwk = match header.kid.as_deref() {
        Some(kid) => match jwks.find(kid).cloned() {
            Some(k) => k,
            None => {
                // `kid` not in cache — try a fresh fetch once
                let fresh = match fetch_jwks(&env_id).await {
                    Ok(f) => f,
                    Err(_) => return Err(auth_error(StatusCode::UNAUTHORIZED, "Unknown signing key")),
                };
                let key = match fresh.find(kid).cloned() {
                    Some(k) => k,
                    None => return Err(auth_error(StatusCode::UNAUTHORIZED, "Unknown signing key")),
                };
                // Update cache
                let mut guard = jwks_cache().write().await;
                *guard = Some(JwksCache { set: fresh, fetched_at: Instant::now() });
                key
            }
        },
        None => match jwks.keys.first().cloned() {
            Some(k) => k,
            None => return Err(auth_error(StatusCode::UNAUTHORIZED, "No JWKS keys available")),
        },
    };

    let decoding_key = match DecodingKey::from_jwk(&jwk) {
        Ok(k) => k,
        Err(_) => return Err(auth_error(StatusCode::UNAUTHORIZED, "Invalid signing key")),
    };

    // Build validation: verify signature and expiry; issuer must contain env_id.
    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_aud = false; // Dynamic.xyz audience varies by project config
    validation.set_issuer(&[format!("app.dynamicauth.com/{}", env_id)]);

    let token_data = match decode::<DynamicClaims>(&token, &decoding_key, &validation) {
        Ok(td) => td,
        Err(e) => {
            tracing::warn!(error = %e, "JWT verification failed");
            return Err(auth_error(StatusCode::UNAUTHORIZED, "Invalid or expired token"));
        }
    };

    req.extensions_mut().insert(AuthenticatedUser {
        user_id: token_data.claims.sub,
    });

    Ok(next.run(req).await)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn extract_bearer(req: &Request) -> Option<&str> {
    req.headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}

fn auth_error(status: StatusCode, message: &str) -> Response {
    (status, Json(serde_json::json!({ "error": message }))).into_response()
}

// ---------------------------------------------------------------------------
// User type injected into request extensions
// ---------------------------------------------------------------------------

/// The authenticated caller, extracted from a valid Dynamic.xyz JWT.
/// Available in protected handlers via `Extension(user): Extension<AuthenticatedUser>`.
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub user_id: String,
}
