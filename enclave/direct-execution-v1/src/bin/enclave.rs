use std::{
    env, io,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use aws_nitro_enclaves_nsm_api::{
    api::{Request as NsmRequest, Response as NsmResponse},
    driver::{nsm_exit, nsm_init, nsm_process_request},
};
use hmac::{Hmac, Mac};
use layrs_direct_execution_v1::{
    runtime_binding, DirectRuntime, InMemoryDirectStateStore, RuntimeMeasurementBinding,
    RuntimeMode, RuntimeRequest, RuntimeResponse, SealedEpoch, WriterGrant, EPOCH_ID,
    TRANSACTION_MODEL,
};
use openssl::{
    cms::CmsContentInfo,
    pkey::{PKey, Private},
    rsa::Rsa,
};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::Mutex,
};
use tokio_vsock::{VsockAddr, VsockListener, VMADDR_CID_ANY};
use zeroize::Zeroize;

const PORT: u32 = 5_003;
// Startup recovery carries the verified immutable lineage in one parent-only
// VSOCK frame. The opening epoch plus several encrypted successors already
// exceeds 1 MiB; keep a finite 64 MiB ceiling so valid recovery remains
// possible without turning bootstrap transport into a persisted workflow.
const MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;

struct EnclaveState {
    nsm_fd: i32,
    runtime: DirectRuntime,
    epoch: SealedEpoch,
    mode: RuntimeMode,
    receipt_key: Vec<u8>,
    state_key: Vec<u8>,
    commit_ack_key: Vec<u8>,
    recovery_complete: bool,
    pending_governed_bootstrap: Option<PendingGovernedBootstrap>,
    writer_grant_commitment: Option<String>,
    writer_grant_expires_at_unix: Option<u64>,
    key_release_artifact_hash: Option<String>,
}

struct PendingGovernedBootstrap {
    recipient_private_key: PKey<Private>,
    grant: WriterGrant,
    binding: RuntimeMeasurementBinding,
    requested_mode: RuntimeMode,
    kms_key_id: String,
    encryption_context: std::collections::BTreeMap<String, String>,
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
    let nsm_fd = nsm_init();
    if nsm_fd < 0 {
        return Err("Nitro Secure Module is unavailable".into());
    }
    // An EIF never inherits the parent's process environment. It always
    // starts dormant and can become authorized only through the governed,
    // attestation-bound VSOCK bootstrap below. Isolated tests retain their
    // explicitly named bootstrap request.
    let mode = RuntimeMode::Dormant;
    let receipt_key = vec![0u8; 32];
    let state_key = vec![0u8; 32];
    let commit_ack_key = vec![0u8; 32];
    let state = Arc::new(Mutex::new(EnclaveState {
        nsm_fd,
        runtime: DirectRuntime::new(epoch.clone(), mode, receipt_key.clone())?,
        epoch,
        mode,
        receipt_key,
        state_key,
        commit_ack_key,
        recovery_complete: false,
        pending_governed_bootstrap: None,
        writer_grant_commitment: None,
        writer_grant_expires_at_unix: None,
        key_release_artifact_hash: None,
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
                    state.runtime.identity_count(),
                    state.recovery_complete && state.runtime.writer_enabled(),
                    state.recovery_complete && state.runtime.admission_enabled(),
                    state.writer_grant_commitment.clone(),
                    state.writer_grant_expires_at_unix,
                    state.key_release_artifact_hash.clone(),
                ),
            }
        }
        RuntimeRequest::BeginGovernedBootstrap {
            grant,
            binding,
            kms_key_id,
            requested_mode,
        } => begin_governed_bootstrap(state, grant, binding, kms_key_id, requested_mode).await,
        RuntimeRequest::CompleteGovernedBootstrap {
            writer_grant_commitment,
            key_release_artifact_hash,
            ciphertext_for_recipient,
            commit_ack_key,
        } => {
            complete_governed_bootstrap(
                state,
                writer_grant_commitment,
                key_release_artifact_hash,
                ciphertext_for_recipient,
                commit_ack_key,
            )
            .await
        }
        RuntimeRequest::BootstrapIsolated {
            receipt_key,
            state_key,
            commit_ack_key,
        } => bootstrap_isolated(state, receipt_key, state_key, commit_ack_key).await,
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

async fn begin_governed_bootstrap(
    state: Arc<Mutex<EnclaveState>>,
    grant: WriterGrant,
    binding: RuntimeMeasurementBinding,
    kms_key_id: String,
    requested_mode: String,
) -> RuntimeResponse {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or(0);
    let signature_valid = grant.verify(now, &binding);
    begin_governed_bootstrap_with_attestor(
        state,
        grant,
        binding,
        kms_key_id,
        requested_mode,
        now,
        signature_valid,
        |nsm_fd, user_data, recipient_public_key| match nsm_process_request(
            nsm_fd,
            NsmRequest::Attestation {
                user_data: Some(user_data.into()),
                nonce: None,
                public_key: Some(recipient_public_key.into()),
            },
        ) {
            NsmResponse::Attestation { document } => Ok(document),
            _ => Err("KEY_RELEASE_ATTESTATION_FAILED".into()),
        },
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn begin_governed_bootstrap_with_attestor<F>(
    state: Arc<Mutex<EnclaveState>>,
    grant: WriterGrant,
    binding: RuntimeMeasurementBinding,
    kms_key_id: String,
    requested_mode: String,
    now: u64,
    signature_valid: bool,
    attestor: F,
) -> RuntimeResponse
where
    F: FnOnce(i32, Vec<u8>, Vec<u8>) -> Result<Vec<u8>, String>,
{
    let mode = match requested_mode.as_str() {
        "admission-enabled" => RuntimeMode::AdmissionOnly,
        "production-enabled" => RuntimeMode::ProductionEnabled,
        _ => {
            return RuntimeResponse::Error {
                code: "WRITER_GRANT_SCOPE_INVALID".into(),
            }
        }
    };
    if !signature_valid
        || grant.environment != "production"
        || grant.runtime != TRANSACTION_MODEL
        || grant.authorization_scope != requested_mode
        || grant.epoch_id != EPOCH_ID
        || grant.opening_epoch_sha256 != layrs_direct_execution_v1::EPOCH_STATE_SHA256
        || grant.opening_evidence_manifest_sha256
            != layrs_direct_execution_v1::EVIDENCE_MANIFEST_SHA256
        || grant.expires_at_unix <= now
        || !binding.valid()
        || grant.runtime_measurement != binding
        || grant.key_release_kms_key_id != kms_key_id
    {
        return RuntimeResponse::Error {
            code: "WRITER_GRANT_INVALID".into(),
        };
    }
    let grant_commitment = grant.commitment();
    let mut state = state.lock().await;
    if state.writer_grant_commitment.is_some() {
        return RuntimeResponse::Error {
            code: "WRITER_GRANT_REPLAY".into(),
        };
    }
    if state.mode != RuntimeMode::Dormant
        || state.recovery_complete
        || state.pending_governed_bootstrap.is_some()
    {
        return RuntimeResponse::Error {
            code: "GOVERNED_BOOTSTRAP_UNAVAILABLE".into(),
        };
    }
    let (recipient_private_key, recipient_public_key) = match generate_recipient_key() {
        Ok(value) => value,
        Err(code) => return RuntimeResponse::Error { code },
    };
    let mut encryption_context = std::collections::BTreeMap::new();
    encryption_context.insert("layrs-runtime".into(), TRANSACTION_MODEL.into());
    encryption_context.insert("layrs-epoch".into(), EPOCH_ID.into());
    encryption_context.insert("layrs-writer-grant".into(), grant_commitment.clone());
    let user_data = match serde_json::to_vec(&serde_json::json!({
        "protocol": "layrs.direct-execution.key-release.v1",
        "writerGrantCommitment": grant_commitment,
        "requestedMode": requested_mode,
        "kmsKeyIdSha256": hex::encode(Sha256::digest(kms_key_id.as_bytes())),
        "runtimeMeasurementSha256": hex::encode(Sha256::digest(serde_json::to_vec(&binding).unwrap_or_default())),
    })) {
        Ok(value) => value,
        Err(_) => {
            return RuntimeResponse::Error {
                code: "GOVERNED_BOOTSTRAP_BINDING_FAILED".into(),
            }
        }
    };
    let attestation_document = match attestor(state.nsm_fd, user_data, recipient_public_key) {
        Ok(document) if !document.is_empty() => document,
        _ => {
            return RuntimeResponse::Error {
                code: "KEY_RELEASE_ATTESTATION_FAILED".into(),
            }
        }
    };
    state.pending_governed_bootstrap = Some(PendingGovernedBootstrap {
        recipient_private_key,
        grant,
        binding,
        requested_mode: mode,
        kms_key_id: kms_key_id.clone(),
        encryption_context: encryption_context.clone(),
    });
    RuntimeResponse::GovernedKeyRecipient {
        attestation_document,
        writer_grant_commitment: grant_commitment,
        kms_key_id,
        encryption_context,
    }
}

async fn complete_governed_bootstrap(
    state: Arc<Mutex<EnclaveState>>,
    writer_grant_commitment: String,
    key_release_artifact_hash: String,
    ciphertext_for_recipient: Vec<u8>,
    commit_ack_key: Vec<u8>,
) -> RuntimeResponse {
    complete_governed_bootstrap_with_decryptor(
        state,
        writer_grant_commitment,
        key_release_artifact_hash,
        ciphertext_for_recipient,
        commit_ack_key,
        decrypt_recipient_key,
    )
    .await
}

async fn complete_governed_bootstrap_with_decryptor<F>(
    state: Arc<Mutex<EnclaveState>>,
    writer_grant_commitment: String,
    key_release_artifact_hash: String,
    ciphertext_for_recipient: Vec<u8>,
    commit_ack_key: Vec<u8>,
    decryptor: F,
) -> RuntimeResponse
where
    F: FnOnce(PKey<Private>, &[u8]) -> Result<Vec<u8>, String>,
{
    if writer_grant_commitment.len() != 64
        || key_release_artifact_hash.len() != 64
        || !writer_grant_commitment
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || !key_release_artifact_hash
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || ciphertext_for_recipient.is_empty()
        || ciphertext_for_recipient.len() > 65_536
        || commit_ack_key.len() != 32
    {
        return RuntimeResponse::Error {
            code: "KEY_RELEASE_RESPONSE_INVALID".into(),
        };
    }
    let mut state = state.lock().await;
    let Some(pending) = state.pending_governed_bootstrap.take() else {
        return RuntimeResponse::Error {
            code: "NO_PENDING_GOVERNED_BOOTSTRAP".into(),
        };
    };
    if pending.grant.commitment() != writer_grant_commitment
        || pending.grant.key_release_kms_key_id != pending.kms_key_id
        || pending.binding != pending.grant.runtime_measurement
        || pending
            .encryption_context
            .get("layrs-writer-grant")
            .map(String::as_str)
            != Some(writer_grant_commitment.as_str())
    {
        return RuntimeResponse::Error {
            code: "KEY_RELEASE_BINDING_MISMATCH".into(),
        };
    }
    let mut root_key = match decryptor(pending.recipient_private_key, &ciphertext_for_recipient) {
        Ok(value) if value.len() == 32 => value,
        Ok(mut value) => {
            value.zeroize();
            return RuntimeResponse::Error {
                code: "KEY_RELEASE_MATERIAL_INVALID".into(),
            };
        }
        Err(code) => return RuntimeResponse::Error { code },
    };
    let receipt_key = derive_runtime_key(&root_key, b"receipt-v1");
    let state_key = derive_runtime_key(&root_key, b"state-v1");
    root_key.zeroize();
    let runtime = match DirectRuntime::new(
        state.epoch.clone(),
        pending.requested_mode,
        receipt_key.clone(),
    ) {
        Ok(runtime) => runtime,
        Err(error) => {
            return RuntimeResponse::Error {
                code: error.to_string(),
            }
        }
    };
    state.runtime = runtime;
    state.mode = pending.requested_mode;
    state.receipt_key = receipt_key;
    state.state_key = state_key;
    state.commit_ack_key = commit_ack_key;
    state.writer_grant_expires_at_unix = Some(pending.grant.expires_at_unix);
    state.writer_grant_commitment = Some(writer_grant_commitment.clone());
    state.key_release_artifact_hash = Some(key_release_artifact_hash);
    RuntimeResponse::GovernedBootstrapComplete {
        writer_grant_commitment,
    }
}

fn derive_runtime_key(root_key: &[u8], purpose: &[u8]) -> Vec<u8> {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(root_key).expect("HMAC accepts a 32-byte root key");
    mac.update(b"layrs.direct-execution.runtime-key.v1\0");
    mac.update(EPOCH_ID.as_bytes());
    mac.update(&[0]);
    mac.update(purpose);
    mac.finalize().into_bytes().to_vec()
}

fn generate_recipient_key() -> Result<(PKey<Private>, Vec<u8>), String> {
    let rsa = Rsa::generate(2048).map_err(|_| "RECIPIENT_KEY_GENERATION_FAILED".to_string())?;
    let private_key =
        PKey::from_rsa(rsa).map_err(|_| "RECIPIENT_KEY_GENERATION_FAILED".to_string())?;
    let public_key = private_key
        .public_key_to_der()
        .map_err(|_| "RECIPIENT_KEY_ENCODING_FAILED".to_string())?;
    Ok((private_key, public_key))
}

fn decrypt_recipient_key(
    private_key: PKey<Private>,
    ciphertext_for_recipient: &[u8],
) -> Result<Vec<u8>, String> {
    let cms = CmsContentInfo::from_der(ciphertext_for_recipient)
        .map_err(|_| "KMS_RECIPIENT_DECRYPT_FAILED".to_string())?;
    cms.decrypt_without_cert_check(&private_key)
        .map_err(|_| "KMS_RECIPIENT_DECRYPT_FAILED".to_string())
}

/// The parent environment is outside an EIF.  For an explicitly isolated
/// test, pass the three ephemeral keys across the existing VSOCK channel once,
/// before any recovery or financial request.  The bootstrap never changes a
/// ledger state and cannot enable a production writer.
async fn bootstrap_isolated(
    state: Arc<Mutex<EnclaveState>>,
    receipt_key: Vec<u8>,
    state_key: Vec<u8>,
    commit_ack_key: Vec<u8>,
) -> RuntimeResponse {
    if receipt_key.len() != 32 || state_key.len() != 32 || commit_ack_key.len() != 32 {
        return RuntimeResponse::Error {
            code: "INVALID_ISOLATED_BOOTSTRAP".into(),
        };
    }
    let mut state = state.lock().await;
    // The parent can restart while the enclave keeps running.  Replaying the
    // isolated bootstrap with exactly the same keys is therefore an
    // idempotent transport setup operation, not a ledger transition.  A
    // different key set is always rejected: it must never replace keys after
    // recovery or enable a different parent to take over this runtime.
    if state.mode == RuntimeMode::IsolatedTest {
        return if state.receipt_key == receipt_key
            && state.state_key == state_key
            && state.commit_ack_key == commit_ack_key
        {
            RuntimeResponse::BootstrapComplete
        } else {
            RuntimeResponse::Error {
                code: "ISOLATED_BOOTSTRAP_REJECTED".into(),
            }
        };
    }
    if state.mode != RuntimeMode::Dormant || state.recovery_complete {
        return RuntimeResponse::Error {
            code: "ISOLATED_BOOTSTRAP_REJECTED".into(),
        };
    }
    let runtime = match DirectRuntime::new(
        state.epoch.clone(),
        RuntimeMode::IsolatedTest,
        receipt_key.clone(),
    ) {
        Ok(runtime) => runtime,
        Err(error) => {
            return RuntimeResponse::Error {
                code: error.to_string(),
            }
        }
    };
    state.runtime = runtime;
    state.mode = RuntimeMode::IsolatedTest;
    state.receipt_key = receipt_key;
    state.state_key = state_key;
    state.commit_ack_key = commit_ack_key;
    RuntimeResponse::BootstrapComplete
}

async fn recover_committed(
    state: Arc<Mutex<EnclaveState>>,
    artifacts: Vec<layrs_direct_execution_v1::DirectStateArtifact>,
) -> RuntimeResponse {
    let mut state = state.lock().await;
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
    // Parent restart is a transport event, not a ledger event.  It must be
    // able to submit the immutable archive again and prove it describes the
    // already authoritative in-enclave state.  A different, missing, or
    // corrupt archive fails closed; it can never replace an adopted state.
    if state.recovery_complete {
        return if runtime.committed_sequence() == state.runtime.committed_sequence()
            && runtime.committed_state_hash() == state.runtime.committed_state_hash()
        {
            response
        } else {
            RuntimeResponse::Error {
                code: "DIRECT_STATE_RECOVERY_MISMATCH".into(),
            }
        };
    }
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
    let binding = runtime_binding(
        state.runtime.identity_count(),
        state.runtime.writer_enabled(),
        state.runtime.admission_enabled(),
        state.writer_grant_commitment.clone(),
        state.writer_grant_expires_at_unix,
        state.key_release_artifact_hash.clone(),
    );
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
        artifact_hash, identity_commitment_for, request_hash, DirectAction, DirectRequest,
        DurabilityAck, FeeProfileId, FilesystemImmutableArtifactStore, GovernedMarketRegistration,
        MarketConfig, MarketExecution, OrderAction, Outcome, TimeInForce, EPOCH_ID,
        TRANSACTION_MODEL,
    };
    use openssl::{
        asn1::Asn1Time,
        cms::CMSOptions,
        hash::MessageDigest,
        stack::Stack,
        symm::Cipher,
        x509::{X509NameBuilder, X509},
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
        request_for(
            SUBJECT,
            IDENTITY,
            id,
            DirectAction::ReserveWithdrawal {
                destination: "0xCCB96357dEB4cbF0808208d55916774f0B51a908".into(),
                amount_atomic: "1000000".into(),
                custody_reference: "isolated-vsock-custody-finality".into(),
            },
        )
    }
    fn request_for(
        account_id: &str,
        identity_commitment: &str,
        id: &str,
        action: DirectAction,
    ) -> DirectRequest {
        let mut request = DirectRequest {
            account_id: account_id.into(),
            identity_commitment: identity_commitment.into(),
            request_id: id.into(),
            request_hash: String::new(),
            action,
        };
        request.request_hash = request_hash(&request);
        request
    }
    fn market_registration(id: &str, market_id: &str) -> DirectRequest {
        request_for(
            "governance",
            "governance",
            id,
            DirectAction::RegisterMarket {
                registration: GovernedMarketRegistration {
                    registration_id: id.into(),
                    epoch_id: EPOCH_ID.into(),
                    runtime: TRANSACTION_MODEL.into(),
                    market: MarketConfig {
                        market_id: market_id.into(),
                        settlement_asset: "USDC".into(),
                        settlement_decimals: 6,
                        public_settlement_chain: Some("horizen".into()),
                        opens_at_millis: 1,
                        closes_at_millis: 10_000_000,
                        minimum_quantity_micros: 1,
                        maximum_quantity_micros: 10_000_000,
                        minimum_order_notional_micros: 1,
                        maximum_order_notional_micros: 10_000_000,
                        maximum_user_position_micros: 20_000_000,
                        maximum_pending_bootstrap_notional_micros: 10_000_000,
                        tick_size_micros: 100,
                        oracle_feed_id: 9002,
                        fee_profile_id: FeeProfileId::LayrsCryptoV2,
                        execution: MarketExecution::NativeClob,
                    },
                    expires_at_unix: 9_000,
                    governance_key_id: "isolated".into(),
                    signing_algorithm: "isolated".into(),
                    signature: "isolated-market-release".into(),
                },
                now_unix: 1,
            },
        )
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
            state_key: vec![8; 32],
            commit_ack_key: vec![9; 32],
            recovery_complete: false,
            pending_governed_bootstrap: None,
            writer_grant_commitment: None,
            writer_grant_expires_at_unix: None,
            key_release_artifact_hash: None,
        }))
    }
    fn dormant_state() -> Arc<Mutex<EnclaveState>> {
        let epoch = SealedEpoch::load(epoch_path()).unwrap();
        Arc::new(Mutex::new(EnclaveState {
            nsm_fd: -1,
            runtime: DirectRuntime::new(epoch.clone(), RuntimeMode::Dormant, vec![0; 32]).unwrap(),
            epoch,
            mode: RuntimeMode::Dormant,
            receipt_key: vec![0; 32],
            state_key: vec![0; 32],
            commit_ack_key: vec![0; 32],
            recovery_complete: false,
            pending_governed_bootstrap: None,
            writer_grant_commitment: None,
            writer_grant_expires_at_unix: None,
            key_release_artifact_hash: None,
        }))
    }
    fn measurement_binding() -> RuntimeMeasurementBinding {
        RuntimeMeasurementBinding {
            ami_id: "ami-0123456789abcdef0".into(),
            eif_sha256: "a".repeat(64),
            pcr0: "b".repeat(96),
            pcr1: "c".repeat(96),
            pcr2: "d".repeat(96),
            source_commit: "writer-grant-bootstrap-test".into(),
            enclave_sha256: "e".repeat(64),
            parent_sha256: "f".repeat(64),
        }
    }
    fn writer_grant(binding: &RuntimeMeasurementBinding) -> WriterGrant {
        WriterGrant {
            activation_id: "production-bootstrap-test-1".into(),
            environment: "production".into(),
            authorization_scope: "production-enabled".into(),
            epoch_id: EPOCH_ID.into(),
            runtime: TRANSACTION_MODEL.into(),
            opening_epoch_sha256: layrs_direct_execution_v1::EPOCH_STATE_SHA256.into(),
            opening_evidence_manifest_sha256: layrs_direct_execution_v1::EVIDENCE_MANIFEST_SHA256
                .into(),
            runtime_measurement: binding.clone(),
            old_writer_fence_evidence_sha256: "1".repeat(64),
            key_release_kms_key_id: "arn:aws:kms:us-east-1:111122223333:key/direct-runtime".into(),
            expires_at_unix: 2_000,
            governance_key_id: layrs_direct_execution_v1::GOVERNANCE_KEY_ID.into(),
            signing_algorithm: layrs_direct_execution_v1::GOVERNANCE_SIGNING_ALGORITHM.into(),
            signature: "deterministic-test-signature".into(),
        }
    }
    async fn begin_test_bootstrap(
        state: Arc<Mutex<EnclaveState>>,
        grant: WriterGrant,
        binding: RuntimeMeasurementBinding,
        now: u64,
        signature_valid: bool,
    ) -> RuntimeResponse {
        let kms_key_id = grant.key_release_kms_key_id.clone();
        begin_governed_bootstrap_with_attestor(
            state,
            grant,
            binding,
            kms_key_id,
            "production-enabled".into(),
            now,
            signature_valid,
            |_, user_data, public_key| {
                assert!(!user_data.is_empty());
                assert!(!public_key.is_empty());
                Ok(vec![0xa5; 128])
            },
        )
        .await
    }
    async fn complete_test_bootstrap(
        state: Arc<Mutex<EnclaveState>>,
        grant: &WriterGrant,
        decrypts: bool,
    ) -> RuntimeResponse {
        complete_governed_bootstrap_with_decryptor(
            state,
            grant.commitment(),
            "2".repeat(64),
            vec![0x42; 128],
            vec![0x33; 32],
            move |_, _| {
                if decrypts {
                    Ok(vec![0x44; 32])
                } else {
                    Err("KMS_RECIPIENT_DECRYPT_FAILED".into())
                }
            },
        )
        .await
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
    async fn isolated_bootstrap_is_idempotent_only_for_the_same_keys() {
        let epoch = SealedEpoch::load(epoch_path()).unwrap();
        let state = Arc::new(Mutex::new(EnclaveState {
            nsm_fd: -1,
            runtime: DirectRuntime::new(epoch.clone(), RuntimeMode::Dormant, vec![0; 32]).unwrap(),
            epoch,
            mode: RuntimeMode::Dormant,
            receipt_key: vec![0; 32],
            state_key: Vec::new(),
            commit_ack_key: Vec::new(),
            recovery_complete: false,
            pending_governed_bootstrap: None,
            writer_grant_commitment: None,
            writer_grant_expires_at_unix: None,
            key_release_artifact_hash: None,
        }));
        assert!(matches!(
            bootstrap_isolated(Arc::clone(&state), vec![7; 32], vec![8; 32], vec![9; 32]).await,
            RuntimeResponse::BootstrapComplete
        ));
        assert!(matches!(
            bootstrap_isolated(Arc::clone(&state), vec![7; 32], vec![8; 32], vec![9; 32]).await,
            RuntimeResponse::BootstrapComplete
        ));
        assert!(matches!(
            bootstrap_isolated(state, vec![7; 32], vec![8; 32], vec![1; 32]).await,
            RuntimeResponse::Error { ref code } if code == "ISOLATED_BOOTSTRAP_REJECTED"
        ));
    }

    #[tokio::test]
    async fn governed_bootstrap_a_valid_grant_accepts_then_l_releases_only_after_checks() {
        let binding = measurement_binding();
        let grant = writer_grant(&binding);
        let state = dormant_state();
        assert!(matches!(
            begin_test_bootstrap(Arc::clone(&state), grant.clone(), binding, 1_000, true).await,
            RuntimeResponse::GovernedKeyRecipient { .. }
        ));
        {
            let state = state.lock().await;
            assert_eq!(state.mode, RuntimeMode::Dormant);
            assert_eq!(state.state_key, vec![0; 32]);
            assert!(state.writer_grant_commitment.is_none());
        }
        assert!(matches!(
            complete_test_bootstrap(Arc::clone(&state), &grant, true).await,
            RuntimeResponse::GovernedBootstrapComplete { .. }
        ));
        let state = state.lock().await;
        assert_eq!(state.mode, RuntimeMode::ProductionEnabled);
        assert!(state.runtime.writer_enabled());
        assert_ne!(state.state_key, vec![0; 32]);
        assert_eq!(state.commit_ack_key, vec![0x33; 32]);
        assert_eq!(
            state.writer_grant_commitment.as_deref(),
            Some(grant.commitment().as_str())
        );
    }

    #[tokio::test]
    async fn governed_bootstrap_b_through_e_rejects_mismatched_expired_and_tampered_grants() {
        let binding = measurement_binding();
        let grant = writer_grant(&binding);

        let mut wrong_pcr = binding.clone();
        wrong_pcr.pcr0 = "9".repeat(96);
        assert!(matches!(
            begin_test_bootstrap(
                dormant_state(),
                grant.clone(),
                wrong_pcr,
                1_000,
                true
            )
            .await,
            RuntimeResponse::Error { ref code } if code == "WRITER_GRANT_INVALID"
        ));

        let mut wrong_epoch = grant.clone();
        wrong_epoch.epoch_id = "wrong-epoch".into();
        assert!(matches!(
            begin_test_bootstrap(
                dormant_state(),
                wrong_epoch,
                binding.clone(),
                1_000,
                true
            )
            .await,
            RuntimeResponse::Error { ref code } if code == "WRITER_GRANT_INVALID"
        ));

        assert!(matches!(
            begin_test_bootstrap(
                dormant_state(),
                grant.clone(),
                binding.clone(),
                grant.expires_at_unix,
                true
            )
            .await,
            RuntimeResponse::Error { ref code } if code == "WRITER_GRANT_INVALID"
        ));

        assert!(matches!(
            begin_test_bootstrap(dormant_state(), grant, binding, 1_000, false).await,
            RuntimeResponse::Error { ref code } if code == "WRITER_GRANT_INVALID"
        ));
    }

    #[tokio::test]
    async fn governed_bootstrap_f_through_l_is_replay_safe_restart_safe_and_fail_closed() {
        let binding = measurement_binding();
        let grant = writer_grant(&binding);
        let state = dormant_state();

        // G/K: without a grant, no release request exists and the writer is
        // independently dormant.
        assert!(!state.lock().await.runtime.writer_enabled());
        assert!(state.lock().await.pending_governed_bootstrap.is_none());

        assert!(matches!(
            begin_test_bootstrap(
                Arc::clone(&state),
                grant.clone(),
                binding.clone(),
                1_000,
                true
            )
            .await,
            RuntimeResponse::GovernedKeyRecipient { .. }
        ));
        // H: a failed recipient decrypt consumes the ephemeral attempt but
        // never changes mode or installs keys.
        assert!(matches!(
            complete_test_bootstrap(Arc::clone(&state), &grant, false).await,
            RuntimeResponse::Error { ref code } if code == "KMS_RECIPIENT_DECRYPT_FAILED"
        ));
        assert_eq!(state.lock().await.mode, RuntimeMode::Dormant);
        assert!(state.lock().await.writer_grant_commitment.is_none());

        // A fresh enclave retry can complete, representing enclave restart.
        let restarted = dormant_state();
        assert!(matches!(
            begin_test_bootstrap(
                Arc::clone(&restarted),
                grant.clone(),
                binding.clone(),
                1_000,
                true
            )
            .await,
            RuntimeResponse::GovernedKeyRecipient { .. }
        ));
        assert!(matches!(
            complete_test_bootstrap(Arc::clone(&restarted), &grant, true).await,
            RuntimeResponse::GovernedBootstrapComplete { .. }
        ));

        // F/J: replay into the live enclave is rejected. A restarted parent
        // can query the exact commitment and recognize the already-authorized
        // enclave without replacing keys or state.
        assert!(matches!(
            begin_test_bootstrap(
                Arc::clone(&restarted),
                grant.clone(),
                binding,
                1_000,
                true
            )
            .await,
            RuntimeResponse::Error { ref code } if code == "WRITER_GRANT_REPLAY"
        ));
        let restarted = restarted.lock().await;
        assert_eq!(
            restarted.writer_grant_commitment.as_deref(),
            Some(grant.commitment().as_str())
        );
        assert!(restarted.runtime.writer_enabled());
    }

    #[test]
    fn kms_recipient_cms_unwraps_only_with_enclave_private_key() {
        let (private_key, _) = generate_recipient_key().unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "layrs-direct-test")
            .unwrap();
        let name = name.build();
        let mut certificate = X509::builder().unwrap();
        certificate.set_version(2).unwrap();
        certificate.set_subject_name(&name).unwrap();
        certificate.set_issuer_name(&name).unwrap();
        certificate.set_pubkey(&private_key).unwrap();
        certificate
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        certificate
            .set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        certificate
            .sign(&private_key, MessageDigest::sha256())
            .unwrap();
        let certificate = certificate.build();
        let mut recipients = Stack::new().unwrap();
        recipients.push(certificate).unwrap();
        let expected = [0x77u8; 32];
        let cms = CmsContentInfo::encrypt(
            &recipients,
            &expected,
            Cipher::aes_256_cbc(),
            CMSOptions::BINARY,
        )
        .unwrap()
        .to_der()
        .unwrap();
        let actual = decrypt_recipient_key(private_key, &cms).unwrap();
        assert_eq!(actual, expected);

        let (wrong_private_key, _) = generate_recipient_key().unwrap();
        assert!(decrypt_recipient_key(wrong_private_key, &cms).is_err());
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
    async fn vsock_admission_and_native_clob_trade_survive_restart_and_replay_once() {
        const MARKET: &str = "layrs:v5:BTC:USDC:15m:vsock-fixture";
        const NEW_SUBJECT: &str =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        const NEW_WALLET: &str = "0x2222222222222222222222222222222222222222";
        let new_identity = identity_commitment_for(NEW_SUBJECT, NEW_WALLET);
        let store = FilesystemImmutableArtifactStore::new(artifact_dir());
        let first = state();
        assert!(matches!(
            recover(Arc::clone(&first), Vec::new()).await,
            RuntimeResponse::RecoveryComplete {
                recovered_sequence: 0,
                ..
            }
        ));
        for command in [
            request_for(
                NEW_SUBJECT,
                &new_identity,
                "vsock-admit",
                DirectAction::AdmitIdentity {
                    wallet_address: NEW_WALLET.into(),
                },
            ),
            request_for(
                NEW_SUBJECT,
                &new_identity,
                "vsock-credit",
                DirectAction::CreditDeposit {
                    amount_atomic: "5000000".into(),
                    custody_reference: "isolated-vsock-final-deposit".into(),
                },
            ),
            market_registration("vsock-market", MARKET),
            request_for(
                SUBJECT,
                IDENTITY,
                "vsock-maker",
                DirectAction::PlaceOrder {
                    order_id: "55555555-6666-4777-8888-999999999999".into(),
                    market_id: MARKET.into(),
                    outcome: Outcome::Up,
                    action: OrderAction::Buy,
                    price_micros: 400_000,
                    quantity_micros: "1000000".into(),
                    time_in_force: TimeInForce::Gtc,
                    expires_at_millis: None,
                    now_millis: 1_000,
                },
            ),
        ] {
            assert!(matches!(
                commit_through_parent_callback(Arc::clone(&first), command, &store).await,
                RuntimeResponse::Execute { .. }
            ));
        }
        let trade = request_for(
            NEW_SUBJECT,
            &new_identity,
            "vsock-trade",
            DirectAction::PlaceOrder {
                order_id: "66666666-7777-4888-9999-aaaaaaaaaaaa".into(),
                market_id: MARKET.into(),
                outcome: Outcome::Down,
                action: OrderAction::Buy,
                price_micros: 600_000,
                quantity_micros: "1000000".into(),
                time_in_force: TimeInForce::Gtc,
                expires_at_millis: None,
                now_millis: 2_000,
            },
        );
        let terminal =
            commit_through_parent_callback(Arc::clone(&first), trade.clone(), &store).await;
        let RuntimeResponse::Execute { result: expected } = terminal else {
            panic!("expected terminal trade result");
        };
        assert_eq!(expected.receipt.execution.as_ref().unwrap().trades.len(), 1);
        assert_eq!(store.load_committed().unwrap().len(), 5);

        let restarted = state();
        assert!(matches!(
            recover(Arc::clone(&restarted), store.load_committed().unwrap()).await,
            RuntimeResponse::RecoveryComplete {
                recovered_sequence: 5,
                ..
            }
        ));
        let replay = execute_response(Arc::clone(&restarted), trade).await;
        assert_eq!(replay, RuntimeResponse::Execute { result: expected });
        assert_eq!(store.load_committed().unwrap().len(), 5);
    }

    #[tokio::test]
    async fn parent_reconnect_reverifies_same_committed_archive_without_state_transition() {
        let store = FilesystemImmutableArtifactStore::new(artifact_dir());
        let running = state();
        assert!(matches!(
            recover(Arc::clone(&running), Vec::new()).await,
            RuntimeResponse::RecoveryComplete {
                recovered_sequence: 0,
                ..
            }
        ));
        assert!(matches!(
            commit_through_parent_callback(
                Arc::clone(&running),
                request("parent-reconnect"),
                &store
            )
            .await,
            RuntimeResponse::Execute { .. }
        ));
        assert!(matches!(
            recover(Arc::clone(&running), store.load_committed().unwrap()).await,
            RuntimeResponse::RecoveryComplete {
                recovered_sequence: 1,
                ..
            }
        ));
        assert_eq!(
            running
                .lock()
                .await
                .runtime
                .balance(IDENTITY, "USDC", "USER_AVAILABLE"),
            4_000_000
        );
        // A parent that cannot present the committed head must not regain a
        // serving connection by silently falling back to the opening state.
        assert!(matches!(
            recover(running, Vec::new()).await,
            RuntimeResponse::Error { ref code } if code == "DIRECT_STATE_RECOVERY_MISMATCH"
        ));
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
