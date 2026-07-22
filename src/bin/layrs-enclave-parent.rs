use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use axum::{
    extract::{DefaultBodyLimit, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Semaphore,
    time::timeout,
};
use tokio_vsock::{VsockAddr, VsockStream};
use tower_http::{
    request_id::MakeRequestUuid, request_id::PropagateRequestIdLayer,
    request_id::SetRequestIdLayer, timeout::TimeoutLayer,
};
use x25519_dalek::{PublicKey, StaticSecret};

const MAX_FRAME_BYTES: usize = 1_048_576;
const VSOCK_PORT: u32 = 5_003;

#[derive(Clone)]
struct AppState {
    enclave_cid: u32,
    permits: Arc<Semaphore>,
    operator_token_hash: [u8; 32],
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
enum WireRequest {
    Attestation {
        nonce: Vec<u8>,
    },
    Encrypted {
        client_public_key: [u8; 32],
        nonce: [u8; 12],
        ciphertext: Vec<u8>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
enum WireResponse {
    Attestation {
        document: Vec<u8>,
        transport_public_key: [u8; 32],
        receipt_public_key: [u8; 32],
    },
    Encrypted {
        nonce: [u8; 12],
        ciphertext: Vec<u8>,
    },
    Error {
        code: String,
    },
}

#[derive(Deserialize)]
struct AttestationQuery {
    nonce: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AttestationResponse {
    attestation_document: String,
    request_nonce: String,
    transport_public_key: String,
    receipt_public_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PrivateEnvelope {
    protocol_version: String,
    client_public_key: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PrivateResponseEnvelope {
    protocol_version: &'static str,
    client_public_key: String,
    nonce: String,
    ciphertext: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cid = required_u32("LAYRS_ENCLAVE_CID")?;
    if cid < 4 {
        return Err("LAYRS_ENCLAVE_CID must be a non-reserved CID".into());
    }
    let port = optional_u16("PORT", 8_443)?;
    let concurrency = optional_usize("LAYRS_PARENT_MAX_CONCURRENCY", 256)?;
    let state = AppState {
        enclave_cid: cid,
        permits: Arc::new(Semaphore::new(concurrency)),
        operator_token_hash: Sha256::digest(required_string("LAYRS_PARENT_OPERATOR_TOKEN")?).into(),
    };
    let app = Router::new()
        .route(
            "/healthz",
            get(|| async { Json(serde_json::json!({ "status": "ok" })) }),
        )
        .route("/v1/attestation", get(attestation))
        .route("/v1/private/relay", post(relay))
        .route("/v1/operator/relay", post(operator_relay))
        .layer(DefaultBodyLimit::max(MAX_FRAME_BYTES))
        .layer(TimeoutLayer::new(Duration::from_secs(12)))
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::new(
            header::HeaderName::from_static("x-request-id"),
            MakeRequestUuid,
        ))
        .with_state(state);
    let address = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(address).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn operator_relay(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(envelope): Json<serde_json::Value>,
) -> Response {
    let supplied = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or_default();
    if !constant_time_equal(
        &Sha256::digest(supplied.as_bytes()),
        &state.operator_token_hash,
    ) {
        return gateway_error(StatusCode::UNAUTHORIZED, "UNAUTHORIZED").into_response();
    }
    if !envelope.is_object() {
        return gateway_error(StatusCode::BAD_REQUEST, "INVALID_OPERATOR_ENVELOPE").into_response();
    }
    let attestation_nonce = rand::random::<[u8; 32]>().to_vec();
    let enclave_public_key = match exchange(
        &state,
        WireRequest::Attestation {
            nonce: attestation_nonce,
        },
    )
    .await
    {
        Ok(WireResponse::Attestation {
            transport_public_key,
            ..
        }) => transport_public_key,
        _ => {
            return gateway_error(StatusCode::SERVICE_UNAVAILABLE, "ENCLAVE_UNAVAILABLE")
                .into_response()
        }
    };
    let plaintext = match serde_json::to_vec(
        &serde_json::json!({ "type": "OPERATOR", "envelope": envelope }),
    ) {
        Ok(value) => value,
        Err(_) => {
            return gateway_error(StatusCode::BAD_REQUEST, "INVALID_OPERATOR_ENVELOPE")
                .into_response()
        }
    };
    match encrypted_exchange(&state, enclave_public_key, &plaintext).await {
        Ok(value) => (
            StatusCode::OK,
            [(header::CACHE_CONTROL, "no-store")],
            Json(value),
        )
            .into_response(),
        Err(error) => error.into_response(),
    }
}

async fn encrypted_exchange(
    state: &AppState,
    enclave_public_key: [u8; 32],
    plaintext: &[u8],
) -> Result<serde_json::Value, ApiError> {
    let client_secret = StaticSecret::random();
    let client_public_key = PublicKey::from(&client_secret).to_bytes();
    let shared = client_secret.diffie_hellman(&PublicKey::from(enclave_public_key));
    let mut key_hash = Sha256::new();
    key_hash.update(b"layrs.enclave-transport.v1\0");
    key_hash.update(shared.as_bytes());
    let key: [u8; 32] = key_hash.finalize().into();
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "ENCRYPTION_FAILED"))?;
    let nonce = rand::random::<[u8; 12]>();
    let mut request_aad = b"layrs.enclave-request.v1\0".to_vec();
    request_aad.extend_from_slice(&client_public_key);
    request_aad.extend_from_slice(&enclave_public_key);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad: &request_aad,
            },
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "ENCRYPTION_FAILED"))?;
    match exchange(
        state,
        WireRequest::Encrypted {
            client_public_key,
            nonce,
            ciphertext,
        },
    )
    .await?
    {
        WireResponse::Encrypted { nonce, ciphertext } => {
            let mut response_aad = b"layrs.enclave-response.v1\0".to_vec();
            response_aad.extend_from_slice(&client_public_key);
            response_aad.extend_from_slice(&enclave_public_key);
            let decoded = cipher
                .decrypt(
                    Nonce::from_slice(&nonce),
                    aes_gcm::aead::Payload {
                        msg: &ciphertext,
                        aad: &response_aad,
                    },
                )
                .map_err(|_| {
                    ApiError::new(
                        StatusCode::BAD_GATEWAY,
                        "ENCLAVE_RESPONSE_DECRYPTION_FAILED",
                    )
                })?;
            serde_json::from_slice(&decoded)
                .map_err(|_| ApiError::new(StatusCode::BAD_GATEWAY, "INVALID_ENCLAVE_RESPONSE"))
        }
        WireResponse::Error { code } => Err(ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, code)),
        _ => Err(ApiError::new(
            StatusCode::BAD_GATEWAY,
            "UNEXPECTED_ENCLAVE_RESPONSE",
        )),
    }
}

async fn attestation(
    State(state): State<AppState>,
    Query(query): Query<AttestationQuery>,
) -> Response {
    let nonce = match decode_bounded(&query.nonce, 16, 512, "INVALID_ATTESTATION_NONCE") {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    let request_nonce = URL_SAFE_NO_PAD.encode(&nonce);
    match exchange(&state, WireRequest::Attestation { nonce }).await {
        Ok(WireResponse::Attestation {
            document,
            transport_public_key,
            receipt_public_key,
        }) => {
            let mut response = Json(AttestationResponse {
                attestation_document: URL_SAFE_NO_PAD.encode(document),
                request_nonce,
                transport_public_key: URL_SAFE_NO_PAD.encode(transport_public_key),
                receipt_public_key: URL_SAFE_NO_PAD.encode(receipt_public_key),
            })
            .into_response();
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }
        Ok(WireResponse::Error { code }) => {
            gateway_error(StatusCode::BAD_GATEWAY, &code).into_response()
        }
        Ok(_) => {
            gateway_error(StatusCode::BAD_GATEWAY, "UNEXPECTED_ENCLAVE_RESPONSE").into_response()
        }
        Err(error) => error.into_response(),
    }
}

async fn relay(State(state): State<AppState>, Json(envelope): Json<PrivateEnvelope>) -> Response {
    if envelope.protocol_version != "layrs.v1" {
        return gateway_error(StatusCode::BAD_REQUEST, "UNSUPPORTED_PROTOCOL").into_response();
    }
    let client_public_key: [u8; 32] =
        match decode_fixed(&envelope.client_public_key, "INVALID_CLIENT_KEY") {
            Ok(value) => value,
            Err(error) => return error.into_response(),
        };
    let nonce: [u8; 12] = match decode_fixed(&envelope.nonce, "INVALID_ENVELOPE_NONCE") {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    let ciphertext = match decode_bounded(
        &envelope.ciphertext,
        17,
        MAX_FRAME_BYTES - 512,
        "INVALID_CIPHERTEXT",
    ) {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    match exchange(
        &state,
        WireRequest::Encrypted {
            client_public_key,
            nonce,
            ciphertext,
        },
    )
    .await
    {
        Ok(WireResponse::Encrypted { nonce, ciphertext }) => Json(PrivateResponseEnvelope {
            protocol_version: "layrs.v1",
            client_public_key: envelope.client_public_key,
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
        })
        .into_response(),
        Ok(WireResponse::Error { code }) => {
            gateway_error(StatusCode::UNPROCESSABLE_ENTITY, &code).into_response()
        }
        Ok(_) => {
            gateway_error(StatusCode::BAD_GATEWAY, "UNEXPECTED_ENCLAVE_RESPONSE").into_response()
        }
        Err(error) => error.into_response(),
    }
}

async fn exchange(state: &AppState, request: WireRequest) -> Result<WireResponse, ApiError> {
    let _permit = state
        .permits
        .try_acquire()
        .map_err(|_| ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "PARENT_SATURATED"))?;
    timeout(Duration::from_secs(10), async {
        let mut stream = VsockStream::connect(VsockAddr::new(state.enclave_cid, VSOCK_PORT))
            .await
            .map_err(|_| ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "ENCLAVE_UNAVAILABLE"))?;
        let encoded = serde_json::to_vec(&request)
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "ENCODE_FAILED"))?;
        write_frame(&mut stream, &encoded)
            .await
            .map_err(|_| ApiError::new(StatusCode::BAD_GATEWAY, "VSOCK_WRITE_FAILED"))?;
        let response = read_frame(&mut stream)
            .await
            .map_err(|_| ApiError::new(StatusCode::BAD_GATEWAY, "VSOCK_READ_FAILED"))?;
        serde_json::from_slice(&response)
            .map_err(|_| ApiError::new(StatusCode::BAD_GATEWAY, "INVALID_ENCLAVE_RESPONSE"))
    })
    .await
    .map_err(|_| ApiError::new(StatusCode::GATEWAY_TIMEOUT, "ENCLAVE_TIMEOUT"))?
}

async fn read_frame(stream: &mut VsockStream) -> io::Result<Vec<u8>> {
    let length = stream.read_u32().await? as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid frame"));
    }
    let mut bytes = vec![0u8; length];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}

async fn write_frame(stream: &mut VsockStream, bytes: &[u8]) -> io::Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid frame"));
    }
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(bytes).await?;
    stream.flush().await
}

fn decode_fixed<const N: usize>(value: &str, code: &'static str) -> Result<[u8; N], ApiError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, code))?;
    decoded
        .try_into()
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, code))
}

fn decode_bounded(
    value: &str,
    minimum: usize,
    maximum: usize,
    code: &'static str,
) -> Result<Vec<u8>, ApiError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, code))?;
    if decoded.len() < minimum || decoded.len() > maximum {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, code));
    }
    Ok(decoded)
}

fn required_u32(name: &str) -> Result<u32, Box<dyn std::error::Error>> {
    Ok(std::env::var(name)
        .map_err(|_| format!("{name} is required"))?
        .parse()?)
}
fn required_string(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let value = std::env::var(name).map_err(|_| format!("{name} is required"))?;
    if value.len() < 32 {
        return Err(format!("{name} must contain at least 32 bytes").into());
    }
    Ok(value)
}
fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0u8, |diff, (a, b)| diff | (a ^ b))
            == 0
}
fn optional_u16(name: &str, default: u16) -> Result<u16, Box<dyn std::error::Error>> {
    Ok(std::env::var(name).map_or(Ok(default), |value| value.parse())?)
}
fn optional_usize(name: &str, default: usize) -> Result<usize, Box<dyn std::error::Error>> {
    let value = std::env::var(name).map_or(Ok(default), |value| value.parse())?;
    if value == 0 || value > 4_096 {
        return Err(format!("invalid {name}").into());
    }
    Ok(value)
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    code: String,
}
impl ApiError {
    fn new(status: StatusCode, code: impl Into<String>) -> Self {
        Self {
            status,
            code: code.into(),
        }
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        gateway_error(self.status, &self.code).into_response()
    }
}
fn gateway_error(status: StatusCode, code: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        status,
        Json(serde_json::json!({ "error": { "code": code } })),
    )
}
