use std::{
    env, io,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use aws_nitro_enclaves_nsm_api::{
    api::{Request as NsmRequest, Response as NsmResponse},
    driver::{nsm_exit, nsm_init, nsm_process_request},
};
use layrs_direct_execution_v1::{
    runtime_binding, DirectRuntime, InMemoryDirectStateStore, RuntimeMode, RuntimeRequest,
    RuntimeResponse, SealedEpoch, WriterGrant,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::Mutex,
};
use tokio_vsock::{VsockAddr, VsockListener, VMADDR_CID_ANY};

const PORT: u32 = 5_003;
const MAX_FRAME_BYTES: usize = 1024 * 1024;

struct EnclaveState {
    nsm_fd: i32,
    runtime: DirectRuntime,
    epoch: SealedEpoch,
    mode: RuntimeMode,
    receipt_key: Vec<u8>,
    identity_count: usize,
    state_key: Vec<u8>,
    commit_ack_key: Vec<u8>,
    recovery_complete: bool,
}

impl Drop for EnclaveState {
    fn drop(&mut self) {
        if self.nsm_fd >= 0 {
            nsm_exit(self.nsm_fd);
        }
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
    let mode = match env::var("LAYRS_DIRECT_EXECUTION_MODE").as_deref() {
        Ok("isolated-test") if env::var("LAYRS_DIRECT_ISOLATED_TEST").as_deref() == Ok("true") => {
            RuntimeMode::IsolatedTest
        }
        Ok("dormant") | Err(_) => RuntimeMode::Dormant,
        Ok("production-enabled") if verified_writer_grant() => RuntimeMode::ProductionEnabled,
        // An arbitrary deployment flag cannot create a writer. Step 6 requires
        // a separately signed and unexpired old-writer-fence grant.
        _ => return Err("invalid or unauthorized direct-execution mode".into()),
    };
    let receipt_key = env::var("LAYRS_DIRECT_RECEIPT_KEY_HEX")
        .ok()
        .and_then(|value| hex::decode(value).ok())
        .unwrap_or_else(|| vec![0u8; 32]);
    let state_key = protected_key("LAYRS_DIRECT_STATE_KEY_HEX", mode)?;
    let commit_ack_key = protected_key("LAYRS_DIRECT_COMMIT_ACK_KEY_HEX", mode)?;
    let state = Arc::new(Mutex::new(EnclaveState {
        nsm_fd,
        runtime: DirectRuntime::new(epoch.clone(), mode, receipt_key.clone())?,
        epoch,
        mode,
        receipt_key,
        identity_count,
        state_key,
        commit_ack_key,
        recovery_complete: false,
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

fn protected_key(name: &str, mode: RuntimeMode) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    match env::var(name)
        .ok()
        .and_then(|value| hex::decode(value).ok())
    {
        Some(value) if value.len() == 32 => Ok(value),
        // A dormant runtime cannot perform a financial command.  It remains
        // usable for status/attestation before the protected key-release path
        // is configured, while an enabled isolated/production writer fails
        // closed at boot without the key.
        None if mode == RuntimeMode::Dormant => Ok(vec![0u8; 32]),
        _ => Err(format!("{name} must be exactly 32 bytes").into()),
    }
}

fn verified_writer_grant() -> bool {
    let grant = env::var("LAYRS_DIRECT_WRITER_GRANT_JSON")
        .ok()
        .and_then(|value| serde_json::from_str::<WriterGrant>(&value).ok());
    let key = env::var("LAYRS_DIRECT_GOVERNANCE_KEY_HEX")
        .ok()
        .and_then(|value| hex::decode(value).ok())
        .filter(|value| value.len() >= 32);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or(0);
    matches!((grant, key), (Some(grant), Some(key)) if grant.verify(&key, now))
}

async fn serve<S>(mut stream: S, state: Arc<Mutex<EnclaveState>>) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request: RuntimeRequest =
        serde_cbor::from_slice(&read_frame(&mut stream).await?).map_err(invalid)?;
    let response = match request {
        RuntimeRequest::Attestation { nonce } => attest(&state, nonce).await,
        RuntimeRequest::Status => {
            let state = state.lock().await;
            RuntimeResponse::Status {
                status: runtime_binding(
                    state.identity_count,
                    state.recovery_complete && state.runtime.writer_enabled(),
                ),
            }
        }
        RuntimeRequest::Execute { request } => {
            return execute_direct(&mut stream, state, request).await
        }
        RuntimeRequest::DurabilityAck { .. } => RuntimeResponse::Error {
            code: "UNEXPECTED_DURABILITY_ACK".into(),
        },
        RuntimeRequest::RecoverCommitted { artifacts } => recover_committed(state, artifacts).await,
        RuntimeRequest::Balance {
            account_id,
            identity_commitment,
            bucket,
        } => {
            let state = state.lock().await;
            if !state.recovery_complete {
                RuntimeResponse::Error {
                    code: "DIRECT_STATE_RECOVERY_REQUIRED".into(),
                }
            } else if !state.runtime.owns(&account_id, &identity_commitment) {
                RuntimeResponse::Error {
                    code: "IDENTITY_DENIED".into(),
                }
            } else {
                RuntimeResponse::Balance {
                    amount_atomic: state
                        .runtime
                        .balance(&identity_commitment, "USDC", &bucket)
                        .to_string(),
                }
            }
        }
    };
    write_frame(
        &mut stream,
        &serde_cbor::to_vec(&response).map_err(invalid)?,
    )
    .await
}

async fn recover_committed(
    state: Arc<Mutex<EnclaveState>>,
    artifacts: Vec<layrs_direct_execution_v1::DirectStateArtifact>,
) -> RuntimeResponse {
    let mut state = state.lock().await;
    if state.recovery_complete {
        return RuntimeResponse::Error {
            code: "DIRECT_STATE_RECOVERY_ALREADY_COMPLETE".into(),
        };
    }
    let store = match InMemoryDirectStateStore::from_artifacts(artifacts) {
        Ok(store) => store,
        Err(error) => {
            return RuntimeResponse::Error {
                code: format!("DIRECT_STATE_RECOVERY_FAILED:{error}"),
            }
        }
    };
    let runtime = match DirectRuntime::restore_committed(
        state.epoch.clone(),
        state.mode,
        state.receipt_key.clone(),
        &state.state_key,
        &store,
    ) {
        Ok(runtime) => runtime,
        Err(error) => {
            return RuntimeResponse::Error {
                code: format!("DIRECT_STATE_RECOVERY_FAILED:{error}"),
            }
        }
    };
    let response = RuntimeResponse::RecoveryComplete {
        recovered_sequence: runtime.committed_sequence(),
        recovered_state_hash: runtime.committed_state_hash(),
    };
    state.runtime = runtime;
    state.recovery_complete = true;
    response
}

/// This is the only persistence callback in direct execution.  The mutex is
/// deliberately held across the bounded request/ACK exchange so two commands
/// cannot derive competing successors from one committed root.  The candidate
/// remains a local value until its exact, HMAC-bound acknowledgement verifies.
async fn execute_direct<S>(
    stream: &mut S,
    state: Arc<Mutex<EnclaveState>>,
    request: layrs_direct_execution_v1::DirectRequest,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut state = state.lock().await;
    if !state.recovery_complete {
        return write_response(
            stream,
            RuntimeResponse::Error {
                code: "DIRECT_STATE_RECOVERY_REQUIRED".into(),
            },
        )
        .await;
    }
    if let Some(result) = state.runtime.existing_result(&request).map_err(invalid)? {
        return write_response(stream, RuntimeResponse::Execute { result }).await;
    }
    let candidate = match state.runtime.prepare_candidate(request, &state.state_key) {
        Ok(candidate) => candidate,
        Err(error) => {
            return write_response(
                stream,
                RuntimeResponse::Error {
                    code: error.to_string(),
                },
            )
            .await
        }
    };
    write_response(
        stream,
        RuntimeResponse::CommitCandidate {
            artifact: candidate.artifact.clone(),
        },
    )
    .await?;
    let ack: RuntimeRequest =
        serde_cbor::from_slice(&read_frame(stream).await?).map_err(invalid)?;
    let RuntimeRequest::DurabilityAck { ack } = ack else {
        return write_response(
            stream,
            RuntimeResponse::Error {
                code: "DURABILITY_ACK_REQUIRED".into(),
            },
        )
        .await;
    };
    if !ack.verify_for(&candidate.artifact, &state.commit_ack_key) {
        return write_response(
            stream,
            RuntimeResponse::Error {
                code: "INVALID_DURABILITY_ACK".into(),
            },
        )
        .await;
    }
    let result = candidate.result.clone();
    let state_key = state.state_key.clone();
    if let Err(error) = state.runtime.adopt_candidate(candidate, &state_key) {
        return write_response(
            stream,
            RuntimeResponse::Error {
                code: error.to_string(),
            },
        )
        .await;
    }
    write_response(stream, RuntimeResponse::Execute { result }).await
}

async fn write_response<S>(stream: &mut S, response: RuntimeResponse) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    write_frame(stream, &serde_cbor::to_vec(&response).map_err(invalid)?).await
}

async fn attest(state: &Arc<Mutex<EnclaveState>>, nonce: Vec<u8>) -> RuntimeResponse {
    if !(16..=512).contains(&nonce.len()) {
        return RuntimeResponse::Error {
            code: "INVALID_NONCE".into(),
        };
    }
    let state = state.lock().await;
    let binding = runtime_binding(state.identity_count, state.runtime.writer_enabled());
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

async fn read_frame<S>(stream: &mut S) -> io::Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let length = stream.read_u32().await? as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(invalid("invalid frame"));
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}

async fn write_frame<S>(stream: &mut S, bytes: &[u8]) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
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
    use layrs_direct_execution_v1::{
        artifact_hash, request_hash, DirectAction, DirectRequest, DurabilityAck,
        FilesystemImmutableArtifactStore,
    };
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    const SUBJECT: &str = "88fff7d9668cf8b00cd7faa0680d05c6415221e6ab28c5be7fa71e047054d8fc";
    const IDENTITY: &str = "0bafc03d08d4951d769d58284db85c7ac2ee3c79de87ec680f58edc03017c418";
    static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(0);

    fn epoch_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../../.codex-review-bundles/unified-direct-execution-20260905/new-epoch-20260911/OPENING_EPOCH_STATE_20260911.json")
    }
    fn request(id: &str) -> DirectRequest {
        let mut request = DirectRequest {
            account_id: SUBJECT.into(),
            identity_commitment: IDENTITY.into(),
            request_id: id.into(),
            request_hash: String::new(),
            action: DirectAction::ReserveWithdrawal {
                destination: "0xCCB96357dEB4cbF0808208d55916774f0B51a908".into(),
                amount_atomic: "1000000".into(),
                custody_reference: "isolated-vsock-custody-finality".into(),
            },
        };
        request.request_hash = request_hash(&request);
        request
    }
    fn state() -> Arc<Mutex<EnclaveState>> {
        let epoch = SealedEpoch::load(epoch_path()).unwrap();
        let mode = RuntimeMode::IsolatedTest;
        let receipt_key = vec![7; 32];
        Arc::new(Mutex::new(EnclaveState {
            nsm_fd: -1,
            runtime: DirectRuntime::new(epoch.clone(), mode, receipt_key.clone()).unwrap(),
            epoch,
            mode,
            receipt_key,
            identity_count: 438,
            state_key: vec![8; 32],
            commit_ack_key: vec![9; 32],
            recovery_complete: false,
        }))
    }
    async fn recover(
        state: Arc<Mutex<EnclaveState>>,
        artifacts: Vec<layrs_direct_execution_v1::DirectStateArtifact>,
    ) -> RuntimeResponse {
        let (mut parent, enclave) = tokio::io::duplex(MAX_FRAME_BYTES * 2);
        let server = tokio::spawn(serve(enclave, state));
        write_frame(
            &mut parent,
            &serde_cbor::to_vec(&RuntimeRequest::RecoverCommitted { artifacts }).unwrap(),
        )
        .await
        .unwrap();
        let response = serde_cbor::from_slice(&read_frame(&mut parent).await.unwrap()).unwrap();
        server.await.unwrap().unwrap();
        response
    }
    async fn begin(
        state: Arc<Mutex<EnclaveState>>,
        request: DirectRequest,
    ) -> (
        tokio::io::DuplexStream,
        tokio::task::JoinHandle<io::Result<()>>,
    ) {
        let (mut parent, enclave) = tokio::io::duplex(MAX_FRAME_BYTES * 2);
        let server = tokio::spawn(serve(enclave, state));
        write_frame(
            &mut parent,
            &serde_cbor::to_vec(&RuntimeRequest::Execute { request }).unwrap(),
        )
        .await
        .unwrap();
        (parent, server)
    }
    async fn candidate(
        parent: &mut tokio::io::DuplexStream,
    ) -> layrs_direct_execution_v1::DirectStateArtifact {
        let response: RuntimeResponse =
            serde_cbor::from_slice(&read_frame(parent).await.unwrap()).unwrap();
        match response {
            RuntimeResponse::CommitCandidate { artifact } => artifact,
            other => panic!("expected commit candidate, got {other:?}"),
        }
    }
    fn artifact_dir() -> PathBuf {
        std::env::temp_dir().join(format!(
            "layrs-vsock-commit-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT_TEST_DIR.fetch_add(1, Ordering::SeqCst),
        ))
    }
    async fn commit_through_parent_callback(
        state: Arc<Mutex<EnclaveState>>,
        request: DirectRequest,
        store: &FilesystemImmutableArtifactStore,
    ) -> RuntimeResponse {
        let (mut parent, server) = begin(state, request).await;
        let artifact = candidate(&mut parent).await;
        let restored = store.persist_readback(&artifact).unwrap();
        let ack = DurabilityAck::issue(&restored, &[9; 32]);
        write_frame(
            &mut parent,
            &serde_cbor::to_vec(&RuntimeRequest::DurabilityAck { ack }).unwrap(),
        )
        .await
        .unwrap();
        let terminal = serde_cbor::from_slice(&read_frame(&mut parent).await.unwrap()).unwrap();
        server.await.unwrap().unwrap();
        terminal
    }
    async fn execute_without_ack(
        state: Arc<Mutex<EnclaveState>>,
        request: DirectRequest,
    ) -> layrs_direct_execution_v1::DirectStateArtifact {
        let (mut parent, server) = begin(state, request).await;
        let artifact = candidate(&mut parent).await;
        drop(parent);
        assert!(server.await.unwrap().is_err());
        artifact
    }
    async fn execute_response(
        state: Arc<Mutex<EnclaveState>>,
        request: DirectRequest,
    ) -> RuntimeResponse {
        let (mut parent, server) = begin(state, request).await;
        let response = serde_cbor::from_slice(&read_frame(&mut parent).await.unwrap()).unwrap();
        server.await.unwrap().unwrap();
        response
    }

    #[tokio::test]
    async fn vsock_callback_persists_readbacks_binds_ack_then_adopts() {
        let state = state();
        assert!(matches!(
            recover(Arc::clone(&state), Vec::new()).await,
            RuntimeResponse::RecoveryComplete {
                recovered_sequence: 0,
                ..
            }
        ));
        let (mut parent, server) = begin(Arc::clone(&state), request("vsock-success")).await;
        let artifact = candidate(&mut parent).await;
        // The handler holds the committed-state mutex while it waits; no
        // observer can see the cloned candidate as authoritative.
        assert!(state.try_lock().is_err());
        let store = FilesystemImmutableArtifactStore::new(artifact_dir());
        let restored = store.persist_readback(&artifact).unwrap();
        assert_eq!(restored, artifact);
        assert_eq!(artifact_hash(&restored), artifact_hash(&artifact));
        let ack = DurabilityAck::issue(&restored, &[9; 32]);
        assert!(ack.verify_for(&artifact, &[9; 32]));
        write_frame(
            &mut parent,
            &serde_cbor::to_vec(&RuntimeRequest::DurabilityAck { ack }).unwrap(),
        )
        .await
        .unwrap();
        let terminal: RuntimeResponse =
            serde_cbor::from_slice(&read_frame(&mut parent).await.unwrap()).unwrap();
        assert!(matches!(terminal, RuntimeResponse::Execute { .. }));
        server.await.unwrap().unwrap();
        let state = state.lock().await;
        assert_eq!(
            state.runtime.balance(IDENTITY, "USDC", "USER_AVAILABLE"),
            4_000_000
        );
        assert_eq!(
            state.runtime.balance(IDENTITY, "USDC", "USER_SETTLED"),
            1_000_000
        );
    }

    #[tokio::test]
    async fn vsock_callback_rejects_missing_or_invalid_ack_without_adoption() {
        let state = state();
        assert!(matches!(
            recover(Arc::clone(&state), Vec::new()).await,
            RuntimeResponse::RecoveryComplete {
                recovered_sequence: 0,
                ..
            }
        ));
        let (mut parent, server) = begin(Arc::clone(&state), request("vsock-invalid-ack")).await;
        let artifact = candidate(&mut parent).await;
        let mut ack = DurabilityAck::issue(&artifact, &[9; 32]);
        ack.state_hash = "f".repeat(64); // validly framed but not candidate-bound
        write_frame(
            &mut parent,
            &serde_cbor::to_vec(&RuntimeRequest::DurabilityAck { ack }).unwrap(),
        )
        .await
        .unwrap();
        let terminal: RuntimeResponse =
            serde_cbor::from_slice(&read_frame(&mut parent).await.unwrap()).unwrap();
        assert!(
            matches!(terminal, RuntimeResponse::Error { ref code } if code == "INVALID_DURABILITY_ACK")
        );
        server.await.unwrap().unwrap();
        let state = state.lock().await;
        assert_eq!(
            state.runtime.balance(IDENTITY, "USDC", "USER_AVAILABLE"),
            5_000_000
        );
        assert_eq!(state.runtime.balance(IDENTITY, "USDC", "USER_SETTLED"), 0);
    }

    #[tokio::test]
    async fn vsock_callback_persistence_failure_cannot_adopt_candidate() {
        let state = state();
        assert!(matches!(
            recover(Arc::clone(&state), Vec::new()).await,
            RuntimeResponse::RecoveryComplete {
                recovered_sequence: 0,
                ..
            }
        ));
        let (mut parent, server) = begin(Arc::clone(&state), request("vsock-no-ack")).await;
        let artifact = candidate(&mut parent).await;
        // This is the same create-if-absent/readback adapter the parent uses;
        // a non-directory root is an isolated, deterministic write failure.
        let failed_store = FilesystemImmutableArtifactStore::new("/dev/null/layrs-vsock-failure");
        assert!(failed_store.persist_readback(&artifact).is_err());
        drop(parent); // parent persistence/connection failure: no ACK exists
        assert!(server.await.unwrap().is_err());
        let state = state.lock().await;
        assert_eq!(
            state.runtime.balance(IDENTITY, "USDC", "USER_AVAILABLE"),
            5_000_000
        );
        assert_eq!(state.runtime.balance(IDENTITY, "USDC", "USER_SETTLED"), 0);
    }

    #[tokio::test]
    async fn parent_enclave_restart_recovers_committed_state_and_replays_once() {
        let store = FilesystemImmutableArtifactStore::new(artifact_dir());
        let first = state();
        assert!(matches!(
            recover(Arc::clone(&first), Vec::new()).await,
            RuntimeResponse::RecoveryComplete {
                recovered_sequence: 0,
                ..
            }
        ));
        let command = request("restart-replay");
        assert!(matches!(
            commit_through_parent_callback(Arc::clone(&first), command.clone(), &store).await,
            RuntimeResponse::Execute { .. }
        ));
        assert_eq!(
            first
                .lock()
                .await
                .runtime
                .balance(IDENTITY, "USDC", "USER_AVAILABLE"),
            4_000_000
        );
        assert_eq!(store.load_committed().unwrap().len(), 1);

        // Fresh parent/enclave runtime: parent supplies only the immutable
        // archive set; enclave verifies and restores it before command input.
        let restarted = state();
        let artifacts = store.load_committed().unwrap();
        assert!(matches!(
            recover(Arc::clone(&restarted), artifacts).await,
            RuntimeResponse::RecoveryComplete {
                recovered_sequence: 1,
                ..
            }
        ));
        assert_eq!(
            restarted
                .lock()
                .await
                .runtime
                .balance(IDENTITY, "USDC", "USER_AVAILABLE"),
            4_000_000
        );
        let replay = execute_response(Arc::clone(&restarted), command).await;
        assert!(matches!(replay, RuntimeResponse::Execute { .. }));
        assert_eq!(
            restarted
                .lock()
                .await
                .runtime
                .balance(IDENTITY, "USDC", "USER_AVAILABLE"),
            4_000_000
        );
        assert_eq!(
            restarted
                .lock()
                .await
                .runtime
                .balance(IDENTITY, "USDC", "USER_SETTLED"),
            1_000_000
        );
        assert_eq!(store.load_committed().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn restart_before_ack_does_not_recover_candidate() {
        let store = FilesystemImmutableArtifactStore::new(artifact_dir());
        let first = state();
        assert!(matches!(
            recover(Arc::clone(&first), Vec::new()).await,
            RuntimeResponse::RecoveryComplete {
                recovered_sequence: 0,
                ..
            }
        ));
        let artifact = execute_without_ack(Arc::clone(&first), request("restart-before-ack")).await;
        assert_eq!(artifact.sequence, 1);
        assert!(store.load_committed().unwrap().is_empty());

        let restarted = state();
        assert!(matches!(
            recover(Arc::clone(&restarted), store.load_committed().unwrap()).await,
            RuntimeResponse::RecoveryComplete {
                recovered_sequence: 0,
                ..
            }
        ));
        assert_eq!(
            restarted
                .lock()
                .await
                .runtime
                .balance(IDENTITY, "USDC", "USER_AVAILABLE"),
            5_000_000
        );
    }

    #[tokio::test]
    async fn restart_after_ack_before_terminal_response_recovers_committed_state() {
        let store = FilesystemImmutableArtifactStore::new(artifact_dir());
        let first = state();
        assert!(matches!(
            recover(Arc::clone(&first), Vec::new()).await,
            RuntimeResponse::RecoveryComplete {
                recovered_sequence: 0,
                ..
            }
        ));
        let (mut parent, server) = begin(Arc::clone(&first), request("restart-after-ack")).await;
        let artifact = candidate(&mut parent).await;
        let restored = store.persist_readback(&artifact).unwrap();
        write_frame(
            &mut parent,
            &serde_cbor::to_vec(&RuntimeRequest::DurabilityAck {
                ack: DurabilityAck::issue(&restored, &[9; 32]),
            })
            .unwrap(),
        )
        .await
        .unwrap();
        // The ACK has been accepted, but the parent loses its connection
        // before it can consume the terminal receipt.
        drop(parent);
        let _ = server.await.unwrap();

        let restarted = state();
        assert!(matches!(
            recover(Arc::clone(&restarted), store.load_committed().unwrap()).await,
            RuntimeResponse::RecoveryComplete {
                recovered_sequence: 1,
                ..
            }
        ));
        assert_eq!(
            restarted
                .lock()
                .await
                .runtime
                .balance(IDENTITY, "USDC", "USER_AVAILABLE"),
            4_000_000
        );
        assert_eq!(
            restarted
                .lock()
                .await
                .runtime
                .balance(IDENTITY, "USDC", "USER_SETTLED"),
            1_000_000
        );
    }

    #[tokio::test]
    async fn missing_or_corrupt_latest_artifact_fails_closed_before_command() {
        for corrupt in [false, true] {
            let store = FilesystemImmutableArtifactStore::new(artifact_dir());
            let first = state();
            assert!(matches!(
                recover(Arc::clone(&first), Vec::new()).await,
                RuntimeResponse::RecoveryComplete {
                    recovered_sequence: 0,
                    ..
                }
            ));
            assert!(matches!(
                commit_through_parent_callback(
                    Arc::clone(&first),
                    request(if corrupt {
                        "corrupt-latest"
                    } else {
                        "missing-latest"
                    }),
                    &store
                )
                .await,
                RuntimeResponse::Execute { .. }
            ));
            let artifact_path = std::fs::read_dir(store.root())
                .unwrap()
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .find(|path| path.to_string_lossy().ends_with(".artifact.cbor"))
                .unwrap();
            if corrupt {
                std::fs::write(&artifact_path, [0u8, 1, 2]).unwrap();
            } else {
                std::fs::remove_file(&artifact_path).unwrap();
            }
            // The parent-side archive loader refuses to hand a partial chain to
            // a new enclave.  Without a successful RecoverCommitted exchange,
            // the runtime rejects an otherwise valid financial command.
            assert!(store.load_committed().is_err());
            let restarted = state();
            let response = execute_response(
                Arc::clone(&restarted),
                request(if corrupt {
                    "corrupt-command"
                } else {
                    "missing-command"
                }),
            )
            .await;
            assert!(
                matches!(response, RuntimeResponse::Error { ref code } if code == "DIRECT_STATE_RECOVERY_REQUIRED")
            );
            assert_eq!(
                restarted
                    .lock()
                    .await
                    .runtime
                    .balance(IDENTITY, "USDC", "USER_AVAILABLE"),
                5_000_000
            );
        }
    }
}
