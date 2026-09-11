use std::{env, io, sync::Arc};

use aws_nitro_enclaves_nsm_api::{
    api::{Request as NsmRequest, Response as NsmResponse},
    driver::{nsm_exit, nsm_init, nsm_process_request},
};
use layrs_direct_execution_v1::{
    runtime_binding, DirectRuntime, RuntimeMode, RuntimeRequest, RuntimeResponse, SealedEpoch,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Mutex,
};
use tokio_vsock::{VsockAddr, VsockListener, VsockStream, VMADDR_CID_ANY};

const PORT: u32 = 5_003;
const MAX_FRAME_BYTES: usize = 1024 * 1024;

struct EnclaveState {
    nsm_fd: i32,
    runtime: DirectRuntime,
    identity_count: usize,
}

impl Drop for EnclaveState {
    fn drop(&mut self) {
        nsm_exit(self.nsm_fd);
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let epoch = SealedEpoch::load_with_evidence(
        env::var("LAYRS_OPENING_EPOCH_PATH")?,
        env::var("LAYRS_OPENING_EVIDENCE_PATH")?,
    )?;
    let identity_count = epoch.identity_count();
    let nsm_fd = nsm_init();
    if nsm_fd < 0 {
        return Err("Nitro Secure Module is unavailable".into());
    }
    let state = Arc::new(Mutex::new(EnclaveState {
        nsm_fd,
        runtime: DirectRuntime::new(epoch, RuntimeMode::Dormant),
        identity_count,
    }));
    let listener = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, PORT))?;
    loop {
        let (stream, _) = listener.accept().await?;
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let _ = serve(stream, state).await;
        });
    }
}

async fn serve(mut stream: VsockStream, state: Arc<Mutex<EnclaveState>>) -> io::Result<()> {
    let request: RuntimeRequest =
        serde_cbor::from_slice(&read_frame(&mut stream).await?).map_err(invalid)?;
    let response = match request {
        RuntimeRequest::Attestation { nonce } => attest(&state, nonce).await,
        RuntimeRequest::Status => {
            let state = state.lock().await;
            RuntimeResponse::Status {
                status: runtime_binding(state.identity_count),
            }
        }
        RuntimeRequest::DirectTest { request } => {
            let mut state = state.lock().await;
            match state.runtime.execute(request) {
                Ok(result) => RuntimeResponse::DirectTest { result },
                Err(error) => RuntimeResponse::Error {
                    code: error.to_string(),
                },
            }
        }
    };
    write_frame(
        &mut stream,
        &serde_cbor::to_vec(&response).map_err(invalid)?,
    )
    .await
}

async fn attest(state: &Arc<Mutex<EnclaveState>>, nonce: Vec<u8>) -> RuntimeResponse {
    if !(16..=512).contains(&nonce.len()) {
        return RuntimeResponse::Error {
            code: "INVALID_NONCE".into(),
        };
    }
    let state = state.lock().await;
    let binding = runtime_binding(state.identity_count);
    let user_data = match serde_json::to_vec(&binding) {
        Ok(value) => value,
        Err(_) => {
            return RuntimeResponse::Error {
                code: "BINDING_ENCODE_FAILED".into(),
            }
        }
    };
    match nsm_process_request(
        state.nsm_fd,
        NsmRequest::Attestation {
            user_data: Some(user_data.into()),
            nonce: Some(nonce.into()),
            public_key: None,
        },
    ) {
        NsmResponse::Attestation { document } => RuntimeResponse::Attestation { document, binding },
        _ => RuntimeResponse::Error {
            code: "ATTESTATION_FAILED".into(),
        },
    }
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
