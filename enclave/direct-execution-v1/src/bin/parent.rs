use std::{env, io, net::Ipv4Addr, time::Duration};

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use layrs_direct_execution_v1::{DirectRequest, RuntimeRequest, RuntimeResponse, SealedEpoch};
use serde::Deserialize;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};
use tokio_vsock::{VsockAddr, VsockStream};

const ENCLOSURE_PORT: u32 = 5_003;
const MAX_FRAME_BYTES: usize = 1024 * 1024;

#[derive(Clone)]
struct AppState {
    enclave_cid: u32,
}
#[derive(Deserialize)]
struct AttestationQuery {
    nonce: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    SealedEpoch::load_with_evidence(
        env::var("LAYRS_OPENING_EPOCH_PATH")?,
        env::var("LAYRS_OPENING_EVIDENCE_PATH")?,
    )?;
    let state = AppState {
        enclave_cid: env::var("LAYRS_ENCLAVE_CID")
            .unwrap_or_else(|_| "16".into())
            .parse()?,
    };
    let port = env::var("PORT").unwrap_or_else(|_| "8443".into()).parse()?;
    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/attestation", get(attestation))
        .route("/v1/runtime/status", get(status))
        .route("/v1/runtime/direct-test", post(direct_test))
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
    match exchange(&state, RuntimeRequest::Attestation { nonce }).await {
        Ok(RuntimeResponse::Attestation { document, binding }) => Json(serde_json::json!({"attestationDocument": URL_SAFE_NO_PAD.encode(document), "binding": binding})).into_response(),
        Ok(RuntimeResponse::Error { code }) => (StatusCode::BAD_GATEWAY, code).into_response(),
        _ => (StatusCode::BAD_GATEWAY, "UNEXPECTED_RESPONSE").into_response(),
    }
}

async fn status(State(state): State<AppState>) -> impl IntoResponse {
    match exchange(&state, RuntimeRequest::Status).await {
        Ok(RuntimeResponse::Status { status }) => Json(status).into_response(),
        Ok(RuntimeResponse::Error { code }) => (StatusCode::BAD_GATEWAY, code).into_response(),
        _ => (StatusCode::BAD_GATEWAY, "UNEXPECTED_RESPONSE").into_response(),
    }
}

async fn direct_test(
    State(state): State<AppState>,
    Json(request): Json<DirectRequest>,
) -> impl IntoResponse {
    match exchange(&state, RuntimeRequest::DirectTest { request }).await {
        Ok(response) => Json(response).into_response(),
        Err(_) => (StatusCode::BAD_GATEWAY, "ENCLOSURE_UNAVAILABLE").into_response(),
    }
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
