use std::{
    io,
    net::{Shutdown, SocketAddr},
    sync::Arc,
    time::Duration,
};

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
    SignedTaskQualificationArtifact,
};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::{OwnedSemaphorePermit, Semaphore},
    time::timeout,
};
use tokio_vsock::{VsockAddr, VsockListener, VsockStream, VMADDR_CID_ANY};
use tower_http::{
    compression::CompressionLayer, request_id::MakeRequestUuid,
    request_id::PropagateRequestIdLayer, request_id::SetRequestIdLayer, timeout::TimeoutLayer,
};
use uuid::Uuid;

// Provisioning restores the latest encrypted private-core snapshot through the same
// ciphertext-only relay used by ordinary private commands. Keep the decoded frame
// bounded independently from the HTTP JSON envelope: base64 expands a maximum-sized
// ciphertext by 4/3 before Axum decodes it. Production checkpoint JSON currently
// reaches about 91 MiB before outer envelope expansion, so keep a finite internal
// bound with matching HTTP headroom rather than failing recovery as state grows.
const MAX_FRAME_BYTES: usize = 256 * 1024 * 1024;
const MAX_HTTP_BODY_BYTES: usize = 384 * 1024 * 1024;
const VSOCK_PORT: u32 = 5_003;
const EGRESS_VSOCK_PORT: u32 = 5_004;
const EGRESS_PREFACE: &[u8] = b"LAYRS_EGRESS_V1\n";
const ENCLAVE_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const ENCLAVE_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(90);
const DEFAULT_PARENT_QUEUE_WAIT: Duration = Duration::from_secs(3);

#[derive(Clone)]
struct AppState {
    enclave_cid: u32,
    permits: Arc<Semaphore>,
    waiting_permits: Arc<Semaphore>,
    queue_wait: Duration,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
enum WireRequest {
    Attestation {
        nonce: Vec<u8>,
    },
    EncryptedUser {
        client_public_key: [u8; 32],
        nonce: [u8; 12],
        #[serde(with = "serde_bytes")]
        ciphertext: Vec<u8>,
        request_context: EncryptedRequestContext,
    },
    EncryptedOperator {
        client_public_key: [u8; 32],
        nonce: [u8; 12],
        #[serde(with = "serde_bytes")]
        ciphertext: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EncryptedRequestContext {
    idempotency_key: String,
    expected_action: ExpectedEncryptedAction,
    expected_session_tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expected_order_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expected_position_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expected_command_commitment: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum ExpectedEncryptedAction {
    #[serde(rename = "SUBMIT_ORDER")]
    Submit,
    #[serde(rename = "REPLACE_ORDER")]
    Replace,
    #[serde(rename = "CANCEL_ORDER")]
    Cancel,
    #[serde(rename = "CANCEL_ALL_ORDERS")]
    CancelAll,
    #[serde(rename = "PREVIEW_POSITION_CLOSE")]
    PreviewPositionClose,
    #[serde(rename = "CLOSE_POSITION")]
    ClosePosition,
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
        #[serde(with = "serde_bytes")]
        ciphertext: Vec<u8>,
        journal_artifacts: Vec<EncryptedJournalRecord>,
        snapshot_artifacts: Vec<EncryptedSnapshot>,
        receipt_artifacts: Vec<EnclaveReceipt>,
        audit_artifacts: Vec<SignedAuditFillArtifact>,
        task_artifacts: Vec<SignedTaskQualificationArtifact>,
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
    request_context: EncryptedRequestContext,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PrivateOperatorEnvelope {
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
    task_artifacts: Vec<SignedTaskQualificationArtifact>,
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cid = required_u32("LAYRS_ENCLAVE_CID")?;
    if cid < 4 {
        return Err("LAYRS_ENCLAVE_CID must be a non-reserved CID".into());
    }
    let port = optional_u16("PORT", 8_443)?;
    // Enclave state transitions are serialized behind a single mutex. A large
    // parent-side queue cannot increase throughput; it only turns one slow
    // checkpoint into hundreds of doomed requests and can exhaust enclave memory.
    let concurrency = optional_usize("LAYRS_PARENT_MAX_CONCURRENCY", 8)?;
    // Smooth short portfolio/readback bursts without turning the HTTP parent
    // into an unbounded in-memory queue while the enclave serializes state.
    let maximum_waiters = optional_usize("LAYRS_PARENT_MAX_WAITERS", 32)?;
    let queue_wait = Duration::from_millis(optional_u64(
        "LAYRS_PARENT_QUEUE_WAIT_MILLIS",
        DEFAULT_PARENT_QUEUE_WAIT.as_millis() as u64,
        100,
        10_000,
    )?);
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
        waiting_permits: Arc::new(Semaphore::new(maximum_waiters)),
        queue_wait,
    };
    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/attestation", get(attestation))
        .route("/v1/private/relay", post(relay))
        .route("/v1/private/operator-relay", post(operator_relay))
        .layer(DefaultBodyLimit::max(MAX_HTTP_BODY_BYTES))
        // Snapshot artifacts are ciphertext and are serialized as JSON byte
        // arrays on the parent boundary. Compression prevents a valid private
        // command from filling the parent-to-API socket or exceeding the API's
        // ten-second relay deadline as the encrypted journal grows. Undici and
        // browsers negotiate and decode gzip transparently; the wire schema is
        // deliberately unchanged and the enclave/EIF is not involved.
        .layer(CompressionLayer::new())
        // Restore requests carry the durable encrypted checkpoint and may require
        // materially longer than an ordinary command. Public callers retain their
        // own shorter deadline; this internal relay stays bounded at two minutes.
        .layer(TimeoutLayer::new(Duration::from_secs(120)))
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
    if !valid_request_context(&envelope.request_context) {
        return gateway_error(StatusCode::BAD_REQUEST, "INVALID_COMMAND_CONTEXT").into_response();
    }
    match exchange(
        &state,
        WireRequest::EncryptedUser {
            client_public_key,
            nonce,
            ciphertext,
            request_context: envelope.request_context,
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
            task_artifacts,
        }) => Json(PrivateResponseEnvelope {
            protocol_version: "layrs.v1",
            client_public_key: envelope.client_public_key,
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
            journal_artifacts,
            snapshot_artifacts,
            receipt_artifacts,
            audit_artifacts,
            task_artifacts,
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

async fn operator_relay(
    State(state): State<AppState>,
    Json(envelope): Json<PrivateOperatorEnvelope>,
) -> Response {
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
        WireRequest::EncryptedOperator {
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
            task_artifacts,
        }) => Json(PrivateResponseEnvelope {
            protocol_version: "layrs.v1",
            client_public_key: envelope.client_public_key,
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
            journal_artifacts,
            snapshot_artifacts,
            receipt_artifacts,
            audit_artifacts,
            task_artifacts,
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

fn valid_request_context(context: &EncryptedRequestContext) -> bool {
    valid_idempotency_key(&context.idempotency_key)
        && match context.expected_action {
            ExpectedEncryptedAction::Submit | ExpectedEncryptedAction::CancelAll => {
                context.expected_order_id.is_none()
                    && context.expected_position_id.is_none()
                    && context.expected_command_commitment.is_none()
            }
            ExpectedEncryptedAction::Replace | ExpectedEncryptedAction::Cancel => {
                context.expected_order_id.is_some()
                    && context.expected_position_id.is_none()
                    && context.expected_command_commitment.is_none()
            }
            ExpectedEncryptedAction::PreviewPositionClose
            | ExpectedEncryptedAction::ClosePosition => {
                context.expected_order_id.is_none()
                    && context.expected_position_id.as_ref().is_some_and(|value| {
                        value.len() == 68
                            && value.starts_with("pos_")
                            && value[4..].bytes().all(|byte| byte.is_ascii_hexdigit())
                    })
                    && context
                        .expected_command_commitment
                        .as_ref()
                        .is_some_and(|value| {
                            value.len() == 66
                                && value.starts_with("0x")
                                && value[2..].bytes().all(|byte| {
                                    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
                                })
                        })
            }
        }
        && (1..=8).contains(&context.expected_session_tags.len())
        && context.expected_session_tags.iter().all(|tag| {
            URL_SAFE_NO_PAD
                .decode(tag)
                .is_ok_and(|decoded| decoded.len() == 32)
        })
}

async fn exchange(state: &AppState, request: WireRequest) -> Result<WireResponse, ApiError> {
    let _permit = acquire_exchange_permit(state).await?;
    timeout(ENCLAVE_EXCHANGE_TIMEOUT, async {
        let mut stream = VsockStream::connect(VsockAddr::new(state.enclave_cid, VSOCK_PORT))
            .await
            .map_err(|_| ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "ENCLAVE_UNAVAILABLE"))?;
        // The HTTP envelope is JSON, but the private parent-to-enclave hop must
        // remain compact. JSON expands Vec<u8> into decimal arrays and caused a
        // valid production checkpoint to exceed the bounded 64 MiB vsock frame.
        // CBOR preserves the same tagged WireRequest while serde_bytes keeps
        // byte vectors compact instead of expanding them into decimal arrays.
        let encoded = serde_cbor::to_vec(&request)
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "ENCODE_FAILED"))?;
        write_frame(&mut stream, &encoded)
            .await
            .map_err(|_| ApiError::new(StatusCode::BAD_GATEWAY, "VSOCK_WRITE_FAILED"))?;
        let response = read_frame(&mut stream)
            .await
            .map_err(|_| ApiError::new(StatusCode::BAD_GATEWAY, "VSOCK_READ_FAILED"))?;
        serde_cbor::from_slice(&response)
            .map_err(|_| ApiError::new(StatusCode::BAD_GATEWAY, "INVALID_ENCLAVE_RESPONSE"))
    })
    .await
    .map_err(|_| ApiError::new(StatusCode::GATEWAY_TIMEOUT, "ENCLAVE_TIMEOUT"))?
}

async fn acquire_exchange_permit(state: &AppState) -> Result<OwnedSemaphorePermit, ApiError> {
    if let Ok(permit) = Arc::clone(&state.permits).try_acquire_owned() {
        return Ok(permit);
    }
    let _waiting = Arc::clone(&state.waiting_permits)
        .try_acquire_owned()
        .map_err(|_| ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "PARENT_SATURATED"))?;
    timeout(state.queue_wait, Arc::clone(&state.permits).acquire_owned())
        .await
        .map_err(|_| ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "PARENT_SATURATED"))?
        .map_err(|_| ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "PARENT_UNAVAILABLE"))
}

async fn healthz(State(state): State<AppState>) -> Response {
    match timeout(
        ENCLAVE_CONNECT_TIMEOUT,
        VsockStream::connect(VsockAddr::new(state.enclave_cid, VSOCK_PORT)),
    )
    .await
    {
        Ok(Ok(stream)) => {
            let _ = stream.shutdown(Shutdown::Both);
            Json(serde_json::json!({ "status": "ok", "enclave": "reachable" })).into_response()
        }
        _ => gateway_error(StatusCode::SERVICE_UNAVAILABLE, "ENCLAVE_UNAVAILABLE").into_response(),
    }
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

fn valid_idempotency_key(value: &str) -> bool {
    (8..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use base64::Engine;
    use tokio::sync::Semaphore;
    use uuid::Uuid;

    use super::{
        acquire_exchange_permit, valid_idempotency_key, valid_request_context, AppState,
        EncryptedRequestContext, ExpectedEncryptedAction, WireRequest, ENCLAVE_EXCHANGE_TIMEOUT,
        MAX_FRAME_BYTES, MAX_HTTP_BODY_BYTES, URL_SAFE_NO_PAD,
    };

    #[test]
    fn relay_frame_limit_supports_checkpoint_restore_payloads() {
        const { assert!(MAX_FRAME_BYTES >= 256 * 1024 * 1024) };
    }

    #[test]
    fn exchange_timeout_remains_bounded_below_http_deadline() {
        assert!(ENCLAVE_EXCHANGE_TIMEOUT.as_secs() > 10);
        assert!(ENCLAVE_EXCHANGE_TIMEOUT.as_secs() < 120);
    }

    #[test]
    fn http_limit_covers_base64_expansion_of_maximum_ciphertext() {
        const BASE64_BYTES: usize = MAX_FRAME_BYTES.div_ceil(3) * 4;
        const JSON_ENVELOPE_HEADROOM: usize = 4 * 1024;
        const { assert!(MAX_HTTP_BODY_BYTES >= BASE64_BYTES + JSON_ENVELOPE_HEADROOM) };
    }

    #[test]
    fn vsock_wire_encoding_does_not_expand_checkpoint_ciphertext() {
        let ciphertext = vec![0xabu8; 20 * 1024 * 1024];
        let request = WireRequest::EncryptedUser {
            client_public_key: [7; 32],
            nonce: [9; 12],
            ciphertext,
            request_context: EncryptedRequestContext {
                idempotency_key: "order:create:1234".into(),
                expected_action: ExpectedEncryptedAction::Submit,
                expected_session_tags: vec![URL_SAFE_NO_PAD.encode([8u8; 32])],
                expected_order_id: None,
                expected_position_id: None,
                expected_command_commitment: None,
            },
        };
        let encoded = serde_cbor::to_vec(&request).expect("wire request encodes");
        assert!(encoded.len() < 21 * 1024 * 1024);
        assert!(encoded.len() < MAX_FRAME_BYTES);
        let decoded: WireRequest = serde_cbor::from_slice(&encoded).expect("wire request decodes");
        match decoded {
            WireRequest::EncryptedUser { ciphertext, .. } => {
                assert_eq!(ciphertext.len(), 20 * 1024 * 1024);
                assert_eq!(ciphertext[0], 0xab);
            }
            _ => panic!("unexpected wire request variant"),
        }
    }

    #[test]
    fn command_context_idempotency_is_strictly_bounded_and_opaque() {
        assert!(valid_idempotency_key("order:create:1234"));
        assert!(!valid_idempotency_key("short"));
        assert!(!valid_idempotency_key("order.create.1234"));
        assert!(!valid_idempotency_key("order create 1234"));
        assert!(!valid_idempotency_key(&"x".repeat(129)));
        let valid = EncryptedRequestContext {
            idempotency_key: "order:create:1234".into(),
            expected_action: ExpectedEncryptedAction::Submit,
            expected_session_tags: vec![URL_SAFE_NO_PAD.encode([9u8; 32])],
            expected_order_id: None,
            expected_position_id: None,
            expected_command_commitment: None,
        };
        assert!(valid_request_context(&valid));
        let cancel = EncryptedRequestContext {
            idempotency_key: "order:cancel:1234".into(),
            expected_action: ExpectedEncryptedAction::Cancel,
            expected_session_tags: vec![URL_SAFE_NO_PAD.encode([8u8; 32])],
            expected_order_id: Some(Uuid::new_v4()),
            expected_position_id: None,
            expected_command_commitment: None,
        };
        assert!(valid_request_context(&cancel));
        assert_eq!(
            serde_json::to_value(&cancel).unwrap()["expectedAction"],
            "CANCEL_ORDER"
        );
        let cancel_all = EncryptedRequestContext {
            idempotency_key: "orders:cancel-all:1234".into(),
            expected_action: ExpectedEncryptedAction::CancelAll,
            expected_session_tags: vec![URL_SAFE_NO_PAD.encode([7u8; 32])],
            expected_order_id: None,
            expected_position_id: None,
            expected_command_commitment: None,
        };
        assert!(valid_request_context(&cancel_all));
        assert_eq!(
            serde_json::to_value(&cancel_all).unwrap()["expectedAction"],
            "CANCEL_ALL_ORDERS"
        );
        let position_id = format!("pos_{}", "ab".repeat(32));
        for expected_action in [
            ExpectedEncryptedAction::PreviewPositionClose,
            ExpectedEncryptedAction::ClosePosition,
        ] {
            let position = EncryptedRequestContext {
                idempotency_key: "position:close:1234".into(),
                expected_action,
                expected_session_tags: vec![URL_SAFE_NO_PAD.encode([6u8; 32])],
                expected_order_id: None,
                expected_position_id: Some(position_id.clone()),
                expected_command_commitment: Some(format!("0x{}", "11".repeat(32))),
            };
            assert!(valid_request_context(&position));
        }
        assert!(!valid_request_context(&EncryptedRequestContext {
            expected_order_id: Some(Uuid::new_v4()),
            ..cancel_all
        }));
        assert!(!valid_request_context(&EncryptedRequestContext {
            idempotency_key: "order:cancel:1234".into(),
            expected_action: ExpectedEncryptedAction::Cancel,
            expected_session_tags: vec![URL_SAFE_NO_PAD.encode([8u8; 32])],
            expected_order_id: None,
            expected_position_id: None,
            expected_command_commitment: None,
        }));
        assert!(!valid_request_context(&EncryptedRequestContext {
            expected_session_tags: Vec::new(),
            ..valid.clone()
        }));
        assert!(!valid_request_context(&EncryptedRequestContext {
            expected_session_tags: vec!["not-a-tag".into()],
            ..valid
        }));
    }

    #[test]
    fn private_relay_envelope_requires_command_context() {
        let without_context = serde_json::json!({
            "protocolVersion": "layrs.v1",
            "clientPublicKey": URL_SAFE_NO_PAD.encode([1u8; 32]),
            "nonce": URL_SAFE_NO_PAD.encode([2u8; 12]),
            "ciphertext": URL_SAFE_NO_PAD.encode([3u8; 32]),
        });
        assert!(serde_json::from_value::<super::PrivateEnvelope>(without_context).is_err());
    }

    #[test]
    fn operator_relay_is_explicit_and_rejects_user_context() {
        let operator = serde_json::json!({
            "protocolVersion": "layrs.v1",
            "clientPublicKey": URL_SAFE_NO_PAD.encode([1u8; 32]),
            "nonce": URL_SAFE_NO_PAD.encode([2u8; 12]),
            "ciphertext": URL_SAFE_NO_PAD.encode([3u8; 32]),
        });
        assert!(serde_json::from_value::<super::PrivateOperatorEnvelope>(operator.clone()).is_ok());
        let mut with_context = operator;
        with_context.as_object_mut().unwrap().insert(
            "requestContext".into(),
            serde_json::json!({ "idempotencyKey": "order:create:1234" }),
        );
        assert!(serde_json::from_value::<super::PrivateOperatorEnvelope>(with_context).is_err());
    }

    #[tokio::test]
    async fn short_parent_bursts_wait_for_an_exchange_permit() {
        let state = AppState {
            enclave_cid: 16,
            permits: Arc::new(Semaphore::new(1)),
            waiting_permits: Arc::new(Semaphore::new(1)),
            queue_wait: Duration::from_millis(100),
        };
        let occupied = Arc::clone(&state.permits).acquire_owned().await.unwrap();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            drop(occupied);
        });
        assert!(acquire_exchange_permit(&state).await.is_ok());
    }

    #[tokio::test]
    async fn parent_wait_queue_remains_bounded() {
        let state = AppState {
            enclave_cid: 16,
            permits: Arc::new(Semaphore::new(1)),
            waiting_permits: Arc::new(Semaphore::new(1)),
            queue_wait: Duration::from_millis(10),
        };
        let _occupied = Arc::clone(&state.permits).acquire_owned().await.unwrap();
        let _waiting = Arc::clone(&state.waiting_permits)
            .acquire_owned()
            .await
            .unwrap();
        let error = acquire_exchange_permit(&state).await.unwrap_err();
        assert_eq!(error.status, axum::http::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(error.code, "PARENT_SATURATED");
    }
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
fn optional_u64(
    name: &str,
    default: u64,
    minimum: u64,
    maximum: u64,
) -> Result<u64, Box<dyn std::error::Error>> {
    let value = std::env::var(name).map_or(Ok(default), |value| value.parse())?;
    if value < minimum || value > maximum {
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
