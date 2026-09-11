//! Parent boundary for the clean direct runtime.  A Privy-verified BFF mints
//! short-lived signed sessions; the browser never supplies an auth subject or enclave frame.
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use layrs_direct_execution_v1::{
    request_hash, sha256, sign, DirectAction, DirectRequest, RuntimeRequest, RuntimeResponse,
    SealedEpoch,
};
use serde::{Deserialize, Serialize};
use std::{
    env, io,
    net::Ipv4Addr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};
use tokio_vsock::{VsockAddr, VsockStream};
const ENCLOSURE_PORT: u32 = 5_003;
const MAX_FRAME_BYTES: usize = 1024 * 1024;
const SESSION_AUDIENCE: &str = "layrs.direct-execution.v1";
#[derive(Clone)]
struct AppState {
    enclave_cid: u32,
    session_key: Vec<u8>,
    isolated_test: bool,
}
#[derive(Deserialize)]
struct AttestationQuery {
    nonce: String,
}
#[derive(Deserialize)]
struct BalanceQuery {
    bucket: Option<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CustomerCommand {
    identity_commitment: String,
    action: CustomerAction,
}
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
enum CustomerAction {
    PlaceOrder {
        order_id: String,
        market_id: String,
        reserve_atomic: String,
    },
    CancelOrder {
        order_id: String,
    },
    ReserveWithdrawal {
        destination: String,
        amount_atomic: String,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionClaims {
    subject_hash: String,
    audience: String,
    expires_at_unix: u64,
    response_key: String,
    signature: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EncryptedResponse {
    algorithm: &'static str,
    nonce: String,
    ciphertext: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    SealedEpoch::load_with_evidence(
        env::var("LAYRS_OPENING_EPOCH_PATH")?,
        env::var("LAYRS_OPENING_EVIDENCE_PATH")?,
    )?;
    let session_key = env::var("LAYRS_DIRECT_SESSION_HMAC_KEY_HEX")
        .ok()
        .and_then(|value| hex::decode(value).ok())
        .filter(|key| key.len() >= 32)
        // A dormant image can answer health, status, and attestation without a
        // session secret. Customer routes fail closed until an isolated test or
        // later governed activation injects the BFF verification key.
        .unwrap_or_default();
    let state = AppState {
        enclave_cid: env::var("LAYRS_ENCLAVE_CID")
            .unwrap_or_else(|_| "16".into())
            .parse()?,
        session_key,
        isolated_test: env::var("LAYRS_DIRECT_ISOLATED_TEST").as_deref() == Ok("true"),
    };
    let port = env::var("PORT").unwrap_or_else(|_| "8443".into()).parse()?;
    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/attestation", get(attestation))
        .route("/v1/runtime/status", get(status))
        .route("/v1/direct/commands", post(command))
        .route("/v1/direct/balances/:identity", get(balance))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
async fn attestation(
    State(state): State<AppState>,
    Query(query): Query<AttestationQuery>,
) -> impl IntoResponse {
    let nonce = match URL_SAFE_NO_PAD.decode(query.nonce) {
        Ok(value) if (16..=512).contains(&value.len()) => value,
        _ => return (StatusCode::BAD_REQUEST, "INVALID_NONCE").into_response(),
    };
    match exchange(&state, RuntimeRequest::Attestation { nonce }).await { Ok(RuntimeResponse::Attestation { document, binding }) => Json(serde_json::json!({"attestationDocument": URL_SAFE_NO_PAD.encode(document), "binding": binding})).into_response(), Ok(RuntimeResponse::Error { code }) => (StatusCode::BAD_GATEWAY, code).into_response(), _ => (StatusCode::BAD_GATEWAY, "UNEXPECTED_RESPONSE").into_response() }
}
async fn status(State(state): State<AppState>) -> impl IntoResponse {
    match exchange(&state, RuntimeRequest::Status).await {
        Ok(RuntimeResponse::Status { status }) => Json(status).into_response(),
        Ok(RuntimeResponse::Error { code }) => (StatusCode::BAD_GATEWAY, code).into_response(),
        _ => (StatusCode::BAD_GATEWAY, "UNEXPECTED_RESPONSE").into_response(),
    }
}
async fn command(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CustomerCommand>,
) -> impl IntoResponse {
    let claims = match authenticated(&headers, &state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let request_id = match headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty() && value.len() <= 200)
    {
        Some(value) => value.to_string(),
        None => return (StatusCode::BAD_REQUEST, "IDEMPOTENCY_KEY_REQUIRED").into_response(),
    };
    let action = match body.action {
        CustomerAction::PlaceOrder {
            order_id,
            market_id,
            reserve_atomic,
        } => DirectAction::PlaceOrder {
            order_id,
            market_id,
            reserve_atomic,
        },
        CustomerAction::CancelOrder { order_id } => DirectAction::CancelOrder { order_id },
        CustomerAction::ReserveWithdrawal {
            destination,
            amount_atomic,
        } => {
            if !state.isolated_test {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CUSTODY_ADAPTER_NOT_ENABLED",
                )
                    .into_response();
            }
            DirectAction::ReserveWithdrawal {
                destination,
                amount_atomic,
                custody_reference: format!(
                    "mock-custody:{}",
                    sha256(format!("{}:{}", claims.subject_hash, request_id).as_bytes())
                ),
            }
        }
    };
    let mut request = DirectRequest {
        account_id: claims.subject_hash.clone(),
        identity_commitment: body.identity_commitment,
        request_id,
        request_hash: String::new(),
        action,
    };
    request.request_hash = request_hash(&request);
    match exchange(&state, RuntimeRequest::Execute { request }).await {
        Ok(RuntimeResponse::Execute { result }) => encrypted(&claims, &result),
        Ok(RuntimeResponse::Error { code }) => {
            (StatusCode::UNPROCESSABLE_ENTITY, code).into_response()
        }
        _ => (StatusCode::BAD_GATEWAY, "ENCLOSURE_UNAVAILABLE").into_response(),
    }
}
async fn balance(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(identity): Path<String>,
    Query(query): Query<BalanceQuery>,
) -> impl IntoResponse {
    let claims = match authenticated(&headers, &state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    match exchange(
        &state,
        RuntimeRequest::Balance {
            account_id: claims.subject_hash.clone(),
            identity_commitment: identity,
            bucket: query.bucket.unwrap_or_else(|| "USER_AVAILABLE".into()),
        },
    )
    .await
    {
        Ok(RuntimeResponse::Balance { amount_atomic }) => encrypted(
            &claims,
            &serde_json::json!({"asset":"USDC", "amountAtomic": amount_atomic}),
        ),
        Ok(RuntimeResponse::Error { code }) => (StatusCode::FORBIDDEN, code).into_response(),
        _ => (StatusCode::BAD_GATEWAY, "ENCLOSURE_UNAVAILABLE").into_response(),
    }
}
fn authenticated(
    headers: &HeaderMap,
    state: &AppState,
) -> Result<SessionClaims, axum::response::Response> {
    if state.session_key.len() < 32 {
        return Err((StatusCode::SERVICE_UNAVAILABLE, "AUTH_NOT_CONFIGURED").into_response());
    }
    let encoded = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "AUTH_REQUIRED").into_response())?;
    let claims: SessionClaims = URL_SAFE_NO_PAD
        .decode(encoded)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "INVALID_SESSION").into_response())?;
    let mut unsigned = claims.clone();
    unsigned.signature.clear();
    let bytes = serde_json::to_vec(&unsigned)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "INVALID_SESSION").into_response())?;
    if claims.audience != SESSION_AUDIENCE
        || claims.subject_hash.len() != 64
        || claims.expires_at_unix <= now_unix()
        || !constant_time_eq(&sign(&state.session_key, &bytes), &claims.signature)
        || URL_SAFE_NO_PAD
            .decode(&claims.response_key)
            .map_or(true, |key| key.len() != 32)
    {
        return Err((StatusCode::UNAUTHORIZED, "INVALID_SESSION").into_response());
    }
    Ok(claims)
}
fn encrypted<T: Serialize>(claims: &SessionClaims, body: &T) -> axum::response::Response {
    let key = match URL_SAFE_NO_PAD.decode(&claims.response_key) {
        Ok(value) if value.len() == 32 => value,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "SESSION_ENCRYPTION_KEY_INVALID",
            )
                .into_response()
        }
    };
    let bytes = match serde_json::to_vec(body) {
        Ok(value) => value,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "RESPONSE_ENCODING_FAILED",
            )
                .into_response()
        }
    };
    let digest = sha256(format!("{}:{}", claims.subject_hash, bytes.len()).as_bytes());
    let nonce_bytes = match hex::decode(&digest[..24]) {
        Ok(value) => value,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "RESPONSE_ENCRYPTION_FAILED",
            )
                .into_response()
        }
    };
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    match cipher.encrypt(Nonce::from_slice(&nonce_bytes), bytes.as_ref()) {
        Ok(ciphertext) => Json(EncryptedResponse {
            algorithm: "CHACHA20_POLY1305",
            nonce: URL_SAFE_NO_PAD.encode(nonce_bytes),
            ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
        })
        .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "RESPONSE_ENCRYPTION_FAILED",
        )
            .into_response(),
    }
}
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or(0)
}
fn constant_time_eq(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.as_bytes()
            .iter()
            .zip(b.as_bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}
async fn exchange(state: &AppState, request: RuntimeRequest) -> io::Result<RuntimeResponse> {
    timeout(Duration::from_secs(10), async {
        let mut stream =
            VsockStream::connect(VsockAddr::new(state.enclave_cid, ENCLOSURE_PORT)).await?;
        write_frame(&mut stream, &serde_cbor::to_vec(&request).map_err(invalid)?).await?;
        serde_cbor::from_slice(&read_frame(&mut stream).await?).map_err(invalid)
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "enclave timeout"))?
}
fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}
async fn read_frame(stream: &mut VsockStream) -> io::Result<Vec<u8>> {
    let length = stream.read_u32().await? as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(invalid("invalid frame"));
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}
async fn write_frame(stream: &mut VsockStream, bytes: &[u8]) -> io::Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err(invalid("invalid frame"));
    }
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(bytes).await?;
    stream.flush().await
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signed_session_rejects_tampering() {
        let key = vec![9; 32];
        let mut claims = SessionClaims {
            subject_hash: "a".repeat(64),
            audience: SESSION_AUDIENCE.into(),
            expires_at_unix: now_unix() + 60,
            response_key: URL_SAFE_NO_PAD.encode([3u8; 32]),
            signature: String::new(),
        };
        claims.signature = sign(&key, &serde_json::to_vec(&claims).unwrap());
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            format!(
                "Bearer {}",
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
            )
            .parse()
            .unwrap(),
        );
        let state = AppState {
            enclave_cid: 16,
            session_key: key,
            isolated_test: true,
        };
        assert!(authenticated(&headers, &state).is_ok());
        headers.insert("authorization", "Bearer bad".parse().unwrap());
        assert!(authenticated(&headers, &state).is_err());
    }
}
