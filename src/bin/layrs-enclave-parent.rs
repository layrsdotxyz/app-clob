use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use axum::{
    extract::{DefaultBodyLimit, Query, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clob_service::private_core::{
    EnclaveReceipt, EncryptedJournalRecord, EncryptedSnapshot, SignedAuditFillArtifact,
};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Semaphore,
    time::timeout,
};
use tokio_vsock::{VsockAddr, VsockListener, VsockStream, VMADDR_CID_ANY};
use tower_http::{
    request_id::MakeRequestUuid, request_id::PropagateRequestIdLayer,
    request_id::SetRequestIdLayer, timeout::TimeoutLayer,
};

const MAX_FRAME_BYTES: usize = 1_048_576;
const VSOCK_PORT: u32 = 5_003;
const EGRESS_VSOCK_PORT: u32 = 5_004;
const EGRESS_PREFACE: &[u8] = b"LAYRS_EGRESS_V1\n";

#[derive(Clone)]
struct AppState {
    enclave_cid: u32,
    permits: Arc<Semaphore>,
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
        journal_artifacts: Vec<EncryptedJournalRecord>,
        snapshot_artifacts: Vec<EncryptedSnapshot>,
        receipt_artifacts: Vec<EnclaveReceipt>,
        audit_artifacts: Vec<SignedAuditFillArtifact>,
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
    journal_artifacts: Vec<EncryptedJournalRecord>,
    snapshot_artifacts: Vec<EncryptedSnapshot>,
    receipt_artifacts: Vec<EnclaveReceipt>,
    audit_artifacts: Vec<SignedAuditFillArtifact>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cid = required_u32("LAYRS_ENCLAVE_CID")?;
    if cid < 4 {
        return Err("LAYRS_ENCLAVE_CID must be a non-reserved CID".into());
    }
    let port = optional_u16("PORT", 8_443)?;
    let concurrency = optional_usize("LAYRS_PARENT_MAX_CONCURRENCY", 256)?;
    let egress_listener = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, EGRESS_VSOCK_PORT))?;
    let egress_permits = Arc::new(Semaphore::new(concurrency.min(64)));
    tokio::spawn(run_egress_proxy(
        egress_listener,
        cid,
        Arc::clone(&egress_permits),
    ));
    let state = AppState {
        enclave_cid: cid,
        permits: Arc::new(Semaphore::new(concurrency)),
    };
    let app = Router::new()
        .route(
            "/healthz",
            get(|| async { Json(serde_json::json!({ "status": "ok" })) }),
        )
        .route("/v1/attestation", get(attestation))
        .route("/v1/private/relay", post(relay))
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

async fn run_egress_proxy(listener: VsockListener, enclave_cid: u32, permits: Arc<Semaphore>) {
    while let Ok((stream, peer)) = listener.accept().await {
        if peer.cid() != enclave_cid {
            continue;
        }
        let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
            continue;
        };
        tokio::spawn(async move {
            let _permit = permit;
            let _ = proxy_approved_egress(stream).await;
        });
    }
}

async fn proxy_approved_egress(mut enclave: VsockStream) -> io::Result<()> {
    let mut preface = vec![0u8; EGRESS_PREFACE.len()];
    timeout(Duration::from_secs(2), enclave.read_exact(&mut preface))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "egress preface timeout"))??;
    let selector = enclave.read_u8().await?;
    if preface != EGRESS_PREFACE || selector != 1 {
        enclave.write_u8(1).await?;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "egress target is not allowlisted",
        ));
    }
    // The target is selected by a fixed numeric capability, never by enclave-supplied DNS or IP.
    let mut upstream = timeout(
        Duration::from_secs(5),
        TcpStream::connect(("clob.polymarket.com", 443)),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "egress connect timeout"))??;
    enclave.write_u8(0).await?;
    enclave.flush().await?;
    timeout(
        Duration::from_secs(5 * 60),
        copy_bidirectional(&mut enclave, &mut upstream),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "egress tunnel idle timeout"))??;
    Ok(())
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
        Ok(WireResponse::Encrypted {
            nonce,
            ciphertext,
            journal_artifacts,
            snapshot_artifacts,
            receipt_artifacts,
            audit_artifacts,
        }) => Json(PrivateResponseEnvelope {
            protocol_version: "layrs.v1",
            client_public_key: envelope.client_public_key,
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
            journal_artifacts,
            snapshot_artifacts,
            receipt_artifacts,
            audit_artifacts,
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
