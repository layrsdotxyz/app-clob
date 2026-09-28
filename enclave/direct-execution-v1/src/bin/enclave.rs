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
    direct_frame::{CHECKPOINT_FRAME_OVERSIZED, MAX_FRAME_BYTES},
    journal::{derive_journal_signing_key, journal_verifying_key},
    runtime_binding, runtime_binding_commitment, quest_receipt_public_key, quest_receipt_attestation_commitment, DirectRuntime, InMemoryDirectStateStore,
    RuntimeMeasurementBinding, RuntimeMode, RuntimeRequest, RuntimeResponse, SealedEpoch,
    v71::DirectV71Runtime,
    WriterGrant, EPOCH_ID, TRANSACTION_MODEL,
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

struct EnclaveState {
    // Serialize state transitions without blocking reads of committed state.
    transition_gate: Arc<Mutex<()>>,
    nsm_fd: i32,
    runtime: DirectRuntime,
    v71_runtime: Option<DirectV71Runtime>,
    epoch: SealedEpoch,
    mode: RuntimeMode,
    receipt_key: Vec<u8>,
    state_key: Vec<u8>,
    commit_ack_key: Vec<u8>,
    recovery_complete: bool,
    restore_candidate: Option<DirectRuntime>,
    v71_restore_candidate: Option<DirectV71Runtime>,
    committed_restore_frontier: Option<layrs_direct_execution_v1::CommittedRestoreFrontier>,
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
        transition_gate: Arc::new(Mutex::new(())),
        nsm_fd,
        runtime: DirectRuntime::new(epoch.clone(), mode, receipt_key.clone())?,
        v71_runtime: None,
        epoch,
        mode,
        receipt_key,
        state_key,
        commit_ack_key,
        recovery_complete: false,
        restore_candidate: None,
        v71_restore_candidate: None,
        committed_restore_frontier: None,
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
        RuntimeRequest::QuestReceiptAttestation { nonce } => attest_quest_receipt_key(&state,nonce).await,
        RuntimeRequest::PublicQuestReceipt { participant_account,receipt_account,request_id,nonce } => {
            public_quest_receipt(&state,&participant_account,&receipt_account,&request_id,&nonce).await
        },
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
        RuntimeRequest::ExecuteJournal {
            request,
            request_proof,
            archived,
        } => {
            return execute_journal(&mut stream, state, request, request_proof, archived).await
        }
        RuntimeRequest::DurabilityAck { .. } => RuntimeResponse::Error {
            code: "UNEXPECTED_DURABILITY_ACK".into(),
        },
        RuntimeRequest::JournalDurabilityAck { .. } => RuntimeResponse::Error {
            code: "UNEXPECTED_JOURNAL_DURABILITY_ACK".into(),
        },
        RuntimeRequest::BeginJournalRestore { checkpoint } => {
            begin_journal_restore(state, checkpoint).await
        }
        RuntimeRequest::AppendJournalRestore { record } => {
            append_journal_restore(state, record).await
        }
        RuntimeRequest::FinishJournalRestore {
            expected_sequence,
            expected_record_hash,
            expected_transition_root,
            expected_request_index_root,
            expected_financial_state_root,
        } => {
            finish_journal_restore(
                state,
                expected_sequence,
                expected_record_hash,
                expected_transition_root,
                expected_request_index_root,
                expected_financial_state_root,
            )
            .await
        }
        RuntimeRequest::SealJournalCheckpoint => {
            seal_journal_checkpoint(state).await
        }
        RuntimeRequest::SealV70Migration => seal_v70_migration(state).await,
        RuntimeRequest::ActivateV71Migration { bundle } => {
            activate_v71_migration(state, bundle).await
        }
        RuntimeRequest::RecoverCommitted { artifacts } => recover_committed(state, artifacts).await,
        RuntimeRequest::BeginCommittedRestore => begin_committed_restore(state).await,
        RuntimeRequest::BeginCheckpointRestore { checkpoint } => begin_checkpoint_restore(state, checkpoint).await,
        RuntimeRequest::SealCheckpoint { artifact, receipt_records, artifact_hashes } => {
            let bytes = match seal_checkpoint_with(&state, move |runtime, key|
                runtime.seal_checkpoint(artifact, receipt_records, artifact_hashes, key)).await {
                RuntimeResponse::CheckpointSealed { checkpoint } => checkpoint_sealed_frame(checkpoint, MAX_FRAME_BYTES)?,
                other => serde_cbor::to_vec(&other).map_err(invalid)?,
            };
            return write_frame(&mut stream, &bytes).await;
        },
        RuntimeRequest::AppendCommittedRestore { artifact } => append_committed_restore(state,artifact).await,
        RuntimeRequest::FinishCommittedRestore { expected_sequence,expected_state_hash } => finish_committed_restore(state,expected_sequence,expected_state_hash).await,
        RuntimeRequest::Balance {
            account_id,
            identity_commitment,
            asset,
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
                        .balance(&identity_commitment, &asset, &bucket)
                        .to_string(),
                }
            }
        }
        RuntimeRequest::Portfolio {
            account_id,
            identity_commitment,
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
                match state.runtime.portfolio(&identity_commitment) {
                    Ok(portfolio) => RuntimeResponse::Portfolio { portfolio },
                    Err(_) => RuntimeResponse::Error {
                        code: "IDENTITY_DENIED".into(),
                    },
                }
            }
        }
        RuntimeRequest::MarketStatus { market_id } => {
            let state = state.lock().await;
            if !state.recovery_complete {
                RuntimeResponse::Error {
                    code: "DIRECT_STATE_RECOVERY_REQUIRED".into(),
                }
            } else {
                RuntimeResponse::MarketStatus {
                    market: state.runtime.market_status(&market_id),
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
    let _transition = transition(&state).await;
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
    let _transition = transition(&state).await;
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
    state.committed_restore_frontier = pending.grant.committed_restore_frontier;
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
    let _transition = transition(&state).await;
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
    let _transition = transition(&state).await;
    let mut state = state.lock().await;
    if state.v71_runtime.is_some() || state.v71_restore_candidate.is_some() {
        return RuntimeResponse::Error {
            code: "JOURNAL_FORMAT_MISMATCH".into(),
        };
    }
    if state.committed_restore_frontier.as_ref().is_some_and(|frontier| !artifacts.iter().any(|artifact|
        artifact.sequence == frontier.sequence && artifact.state_hash == frontier.state_hash
        && layrs_direct_execution_v1::artifact_hash(artifact) == frontier.artifact_hash)) {
        return RuntimeResponse::Error { code: "RESTORE_BELOW_GOVERNED_FRONTIER".into() };
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

async fn begin_committed_restore(state: Arc<Mutex<EnclaveState>>) -> RuntimeResponse {
    let _transition = transition(&state).await;
    let mut state=state.lock().await;
    if state.restore_candidate.is_some() || state.v71_restore_candidate.is_some() {
        return RuntimeResponse::Error {code:"RESTORE_ALREADY_IN_PROGRESS".into()};
    }
    if state.v71_runtime.is_some() {
        return RuntimeResponse::Error { code: "JOURNAL_FORMAT_MISMATCH".into() };
    }
    match DirectRuntime::new(state.epoch.clone(),state.mode,state.receipt_key.clone()) {
        Ok(runtime)=>{let response=RuntimeResponse::RestoreProgress {recovered_sequence:0,recovered_state_hash:runtime.committed_state_hash()};state.restore_candidate=Some(runtime);response},
        Err(_)=>RuntimeResponse::Error {code:"RESTORE_BEGIN_FAILED".into()},
    }
}
async fn append_committed_restore(state: Arc<Mutex<EnclaveState>>,artifact:layrs_direct_execution_v1::DirectStateArtifact)->RuntimeResponse {
    let _transition = transition(&state).await;
    let mut state=state.lock().await;
    let Some(candidate)=state.restore_candidate.take() else {return RuntimeResponse::Error {code:"RESTORE_NOT_STARTED".into()};};
    if state.committed_restore_frontier.as_ref().is_some_and(|frontier|
        artifact.sequence == frontier.sequence && (artifact.state_hash != frontier.state_hash
            || layrs_direct_execution_v1::artifact_hash(&artifact) != frontier.artifact_hash)) {
        return RuntimeResponse::Error { code: "RESTORE_GOVERNED_FRONTIER_MISMATCH".into() };
    }
    match candidate.restore_next_committed(&artifact,&state.state_key) {
        Ok(candidate)=>{let response=RuntimeResponse::RestoreProgress {recovered_sequence:candidate.committed_sequence(),recovered_state_hash:candidate.committed_state_hash()};state.restore_candidate=Some(candidate);response},
        Err(_)=>RuntimeResponse::Error {code:"RESTORE_SUCCESSOR_INVALID".into()},
    }
}
async fn begin_checkpoint_restore(state: Arc<Mutex<EnclaveState>>, checkpoint: layrs_direct_execution_v1::DirectCheckpoint) -> RuntimeResponse {
    let _transition = transition(&state).await;
    let mut state = state.lock().await;
    if state.restore_candidate.is_some() || state.v71_restore_candidate.is_some() {
        return RuntimeResponse::Error { code: "CHECKPOINT_RESTORE_STARTUP_ONLY".into() };
    }
    if state.v71_runtime.is_some() {
        return RuntimeResponse::Error { code: "JOURNAL_FORMAT_MISMATCH".into() };
    }
    if state.committed_restore_frontier.as_ref().is_some_and(|frontier| !frontier.accepts_checkpoint(&checkpoint)) {
        return RuntimeResponse::Error { code: "CHECKPOINT_BELOW_GOVERNED_FRONTIER".into() };
    }
    let candidate = DirectRuntime::new(state.epoch.clone(), state.mode, state.receipt_key.clone())
        .and_then(|runtime| runtime.restore_checkpoint(&checkpoint, &state.state_key));
    match candidate {
        Ok(candidate) => {
            let response = RuntimeResponse::RestoreProgress { recovered_sequence: candidate.committed_sequence(), recovered_state_hash: candidate.committed_state_hash() };
            state.restore_candidate = Some(candidate); response
        },
        Err(_) => RuntimeResponse::Error { code: "CHECKPOINT_AUTHENTICATION_FAILED".into() },
    }
}
async fn finish_committed_restore(state: Arc<Mutex<EnclaveState>>,expected_sequence:u64,expected_state_hash:String)->RuntimeResponse {
    let _transition = transition(&state).await;
    let mut state=state.lock().await;
    let Some(candidate)=state.restore_candidate.take() else {return RuntimeResponse::Error {code:"RESTORE_NOT_STARTED".into()};};
    if candidate.committed_sequence()!=expected_sequence || candidate.committed_state_hash()!=expected_state_hash
        || state.committed_restore_frontier.as_ref().is_some_and(|frontier| expected_sequence < frontier.sequence)
        || (state.recovery_complete && (candidate.committed_sequence()!=state.runtime.committed_sequence() || candidate.committed_state_hash()!=state.runtime.committed_state_hash())) {
        return RuntimeResponse::Error {code:"RESTORE_FINAL_HEAD_MISMATCH".into()};
    }
    state.runtime=candidate;state.recovery_complete=true;
    RuntimeResponse::RecoveryComplete {recovered_sequence:expected_sequence,recovered_state_hash:expected_state_hash}
}

async fn begin_journal_restore(
    state: Arc<Mutex<EnclaveState>>,
    checkpoint: layrs_direct_execution_v1::v71_checkpoint::DirectV71Checkpoint,
) -> RuntimeResponse {
    let _transition = transition(&state).await;
    let mut state = state.lock().await;
    if state.restore_candidate.is_some() || state.v71_restore_candidate.is_some() {
        return RuntimeResponse::Error {
            code: "RESTORE_ALREADY_IN_PROGRESS".into(),
        };
    }
    let signing_key = match derive_journal_signing_key(&state.state_key) {
        Ok(key) => key,
        Err(_) => {
            return RuntimeResponse::Error {
                code: "JOURNAL_KEY_INVALID".into(),
            }
        }
    };
    let verification_key = match journal_verifying_key(&signing_key) {
        Ok(key) => key,
        Err(_) => {
            return RuntimeResponse::Error {
                code: "JOURNAL_KEY_INVALID".into(),
            }
        }
    };
    let restored = DirectRuntime::new(state.epoch.clone(), state.mode, state.receipt_key.clone())
        .map_err(|_| ())
        .and_then(|runtime| {
            DirectV71Runtime::restore_checkpoint(
                runtime,
                &checkpoint,
                &state.state_key,
                &verification_key,
            )
            .map_err(|_| ())
        });
    match restored {
        Ok(candidate) => {
            let response = RuntimeResponse::JournalRestoreProgress {
                sequence: candidate.sequence(),
                record_hash: candidate.record_hash().into(),
                transition_root: candidate.transition_root().into(),
                request_index_root: candidate.request_index_root().into(),
                receipt: None,
            };
            state.v71_restore_candidate = Some(candidate);
            response
        }
        Err(_) => RuntimeResponse::Error {
            code: "JOURNAL_CHECKPOINT_AUTHENTICATION_FAILED".into(),
        },
    }
}

async fn seal_v70_migration(state: Arc<Mutex<EnclaveState>>) -> RuntimeResponse {
    let snapshot = {
        let state = state.lock().await;
        if !state.recovery_complete
            || state.v71_runtime.is_some()
            || state.restore_candidate.is_some()
            || state.v71_restore_candidate.is_some()
        {
            None
        } else {
            Some((
                state.runtime.clone(),
                zeroize::Zeroizing::new(state.state_key.clone()),
            ))
        }
    };
    let Some((runtime, state_key)) = snapshot else {
        return RuntimeResponse::Error {
            code: "V70_MIGRATION_REQUIRES_VERIFIED_HEAD".into(),
        };
    };
    let signing_key = match derive_journal_signing_key(&state_key) {
        Ok(key) => zeroize::Zeroizing::new(key),
        Err(_) => {
            return RuntimeResponse::Error {
                code: "JOURNAL_KEY_INVALID".into(),
            }
        }
    };
    match tokio::task::spawn_blocking(move || {
        layrs_direct_execution_v1::migration::V70MigrationBundle::seal(
            &runtime,
            &state_key,
            signing_key.as_ref(),
        )
    })
    .await
    {
        Ok(Ok(bundle)) => RuntimeResponse::V70MigrationSealed { bundle },
        _ => RuntimeResponse::Error {
            code: "V70_MIGRATION_SEAL_FAILED".into(),
        },
    }
}

async fn activate_v71_migration(
    state: Arc<Mutex<EnclaveState>>,
    bundle: layrs_direct_execution_v1::migration::V70MigrationBundle,
) -> RuntimeResponse {
    let _transition = transition(&state).await;
    // Hold only the transition gate while authenticating the potentially
    // large migration bundle. Read-only portfolio/status calls continue to
    // observe the verified v70 head until the final constant-time swap.
    let (runtime, state_key, writer_epoch) = {
        let state = state.lock().await;
        if !state.recovery_complete
            || state.v71_runtime.is_some()
            || state.restore_candidate.is_some()
            || state.v71_restore_candidate.is_some()
        {
            return RuntimeResponse::Error {
                code: "V71_MIGRATION_ACTIVATION_UNAVAILABLE".into(),
            };
        }
        let writer_epoch = if state.mode == RuntimeMode::IsolatedTest {
            "isolated-writer-1".to_string()
        } else {
            match state.writer_grant_commitment.clone() {
                Some(epoch) => epoch,
                None => {
                    return RuntimeResponse::Error {
                        code: "V71_WRITER_EPOCH_UNAUTHORIZED".into(),
                    }
                }
            }
        };
        (
            state.runtime.clone(),
            zeroize::Zeroizing::new(state.state_key.clone()),
            writer_epoch,
        )
    };
    let signing_key = match derive_journal_signing_key(&state_key) {
        Ok(key) => key,
        Err(_) => {
            return RuntimeResponse::Error {
                code: "JOURNAL_KEY_INVALID".into(),
            }
        }
    };
    let verification_key = match journal_verifying_key(&signing_key) {
        Ok(key) => key,
        Err(_) => {
            return RuntimeResponse::Error {
                code: "JOURNAL_KEY_INVALID".into(),
            }
        }
    };
    let migrated = tokio::task::spawn_blocking(move || {
        DirectV71Runtime::from_v70_migration(
            runtime,
            &bundle,
            writer_epoch,
            &state_key,
            &verification_key,
        )
    })
    .await;
    let runtime = match migrated {
        Ok(Ok(runtime)) => runtime,
        _ => {
            return RuntimeResponse::Error {
                code: "V71_MIGRATION_AUTHENTICATION_FAILED".into(),
            }
        }
    };
    let financial_state_root = match runtime.financial_state_root() {
        Ok(root) => root,
        Err(_) => {
            return RuntimeResponse::Error {
                code: "V71_MIGRATION_STATE_INVALID".into(),
            }
        }
    };
    let response = RuntimeResponse::V71MigrationActivated {
        writer_epoch: runtime.writer_epoch().into(),
        sequence: runtime.sequence(),
        record_hash: runtime.record_hash().into(),
        transition_root: runtime.transition_root().into(),
        request_index_root: runtime.request_index_root().into(),
        financial_state_root,
    };
    let mut state = state.lock().await;
    if !state.recovery_complete
        || state.v71_runtime.is_some()
        || state.restore_candidate.is_some()
        || state.v71_restore_candidate.is_some()
    {
        return RuntimeResponse::Error {
            code: "V71_MIGRATION_ACTIVATION_UNAVAILABLE".into(),
        };
    }
    state.runtime = runtime.financial_runtime().clone();
    state.v71_runtime = Some(runtime);
    response
}

async fn append_journal_restore(
    state: Arc<Mutex<EnclaveState>>,
    record: layrs_direct_execution_v1::journal::DirectJournalRecord,
) -> RuntimeResponse {
    let _transition = transition(&state).await;
    let mut state = state.lock().await;
    let Some(candidate) = state.v71_restore_candidate.take() else {
        return RuntimeResponse::Error {
            code: "JOURNAL_RESTORE_NOT_STARTED".into(),
        };
    };
    let signing_key = match derive_journal_signing_key(&state.state_key) {
        Ok(key) => key,
        Err(_) => {
            return RuntimeResponse::Error {
                code: "JOURNAL_KEY_INVALID".into(),
            }
        }
    };
    let verification_key = match journal_verifying_key(&signing_key) {
        Ok(key) => key,
        Err(_) => {
            return RuntimeResponse::Error {
                code: "JOURNAL_KEY_INVALID".into(),
            }
        }
    };
    match candidate.restore_next_with_result(&record, &state.state_key, &verification_key) {
        Ok((candidate, result)) => {
            let response = RuntimeResponse::JournalRestoreProgress {
                sequence: candidate.sequence(),
                record_hash: candidate.record_hash().into(),
                transition_root: candidate.transition_root().into(),
                request_index_root: candidate.request_index_root().into(),
                receipt: Some(result.receipt),
            };
            state.v71_restore_candidate = Some(candidate);
            response
        }
        Err(_) => RuntimeResponse::Error {
            code: "JOURNAL_SUCCESSOR_INVALID".into(),
        },
    }
}

#[allow(clippy::too_many_arguments)]
async fn finish_journal_restore(
    state: Arc<Mutex<EnclaveState>>,
    expected_sequence: u64,
    expected_record_hash: String,
    expected_transition_root: String,
    expected_request_index_root: String,
    expected_financial_state_root: String,
) -> RuntimeResponse {
    let _transition = transition(&state).await;
    let mut state = state.lock().await;
    let Some(candidate) = state.v71_restore_candidate.take() else {
        return RuntimeResponse::Error {
            code: "JOURNAL_RESTORE_NOT_STARTED".into(),
        };
    };
    let financial_state_root = match candidate.financial_state_root() {
        Ok(root) => root,
        Err(_) => {
            return RuntimeResponse::Error {
                code: "JOURNAL_RESTORE_FINAL_HEAD_MISMATCH".into(),
            }
        }
    };
    if candidate.sequence() != expected_sequence
        || candidate.record_hash() != expected_record_hash
        || candidate.transition_root() != expected_transition_root
        || candidate.request_index_root() != expected_request_index_root
        || financial_state_root != expected_financial_state_root
    {
        return RuntimeResponse::Error {
            code: "JOURNAL_RESTORE_FINAL_HEAD_MISMATCH".into(),
        };
    }
    if let Some(current) = &state.v71_runtime {
        if current.sequence() != candidate.sequence()
            || current.record_hash() != candidate.record_hash()
            || current.transition_root() != candidate.transition_root()
            || current.request_index_root() != candidate.request_index_root()
            || current.financial_state_root().ok().as_deref()
                != Some(financial_state_root.as_str())
        {
            return RuntimeResponse::Error {
                code: "JOURNAL_STATE_RECOVERY_MISMATCH".into(),
            };
        }
    }
    state.runtime = candidate.financial_runtime().clone();
    state.v71_runtime = Some(candidate);
    state.recovery_complete = true;
    RuntimeResponse::JournalRestoreComplete {
        writer_epoch: state
            .v71_runtime
            .as_ref()
            .expect("journal runtime was installed")
            .writer_epoch()
            .into(),
        sequence: expected_sequence,
        record_hash: expected_record_hash,
        transition_root: expected_transition_root,
        request_index_root: expected_request_index_root,
        financial_state_root,
    }
}

async fn seal_journal_checkpoint(state: Arc<Mutex<EnclaveState>>) -> RuntimeResponse {
    let snapshot = {
        let state = state.lock().await;
        if !state.recovery_complete
            || state.restore_candidate.is_some()
            || state.v71_restore_candidate.is_some()
        {
            None
        } else {
            state.v71_runtime.clone().map(|runtime| {
                (
                    runtime,
                    zeroize::Zeroizing::new(state.state_key.clone()),
                )
            })
        }
    };
    let Some((runtime, state_key)) = snapshot else {
        return RuntimeResponse::Error {
            code: "JOURNAL_CHECKPOINT_REQUIRES_VERIFIED_HEAD".into(),
        };
    };
    let signing_key = match derive_journal_signing_key(&state_key) {
        Ok(key) => zeroize::Zeroizing::new(key),
        Err(_) => {
            return RuntimeResponse::Error {
                code: "JOURNAL_KEY_INVALID".into(),
            }
        }
    };
    match tokio::task::spawn_blocking(move || {
        runtime.seal_checkpoint(&state_key, signing_key.as_ref())
    })
    .await
    {
        Ok(Ok(checkpoint)) => RuntimeResponse::JournalCheckpointSealed { checkpoint },
        _ => RuntimeResponse::Error {
            code: "JOURNAL_CHECKPOINT_HEAD_INVALID".into(),
        },
    }
}

async fn seal_checkpoint_with<F>(state: &Arc<Mutex<EnclaveState>>, seal: F) -> RuntimeResponse
where F: FnOnce(&DirectRuntime, &[u8]) -> Result<layrs_direct_execution_v1::DirectCheckpoint, layrs_direct_execution_v1::RuntimeError> + Send + 'static {
    let snapshot = {
        let committed = state.lock().await;
        if !committed.recovery_complete
            || committed.restore_candidate.is_some()
            || committed.v71_restore_candidate.is_some()
            || committed.v71_runtime.is_some()
        { None }
        else { Some((committed.runtime.clone(), zeroize::Zeroizing::new(committed.state_key.clone()))) }
    };
    match snapshot {
        None => RuntimeResponse::Error { code: "CHECKPOINT_REQUIRES_VERIFIED_HEAD".into() },
        Some((runtime, key)) => match tokio::task::spawn_blocking(move || seal(&runtime, &key)).await {
            Ok(Ok(checkpoint)) => RuntimeResponse::CheckpointSealed { checkpoint },
            _ => RuntimeResponse::Error { code: "CHECKPOINT_HEAD_INVALID".into() },
        },
    }
}

/// Returns a sealed checkpoint only when it also fits the startup
/// BeginCheckpointRestore frame, which is larger than this response. A
/// persisted checkpoint that restart cannot carry would fail recovery closed.
fn checkpoint_sealed_frame(checkpoint: layrs_direct_execution_v1::DirectCheckpoint, limit: usize) -> io::Result<Vec<u8>> {
    let oversized = || serde_cbor::to_vec(&RuntimeResponse::Error { code: CHECKPOINT_FRAME_OVERSIZED.into() }).map_err(invalid);
    let restore = RuntimeRequest::BeginCheckpointRestore { checkpoint };
    let mut restore_bytes = ByteCount(0);
    serde_cbor::to_writer(&mut restore_bytes, &restore).map_err(invalid)?;
    if restore_bytes.0 > limit { return oversized(); }
    let RuntimeRequest::BeginCheckpointRestore { checkpoint } = restore else { return Err(invalid("checkpoint frame")); };
    let bytes = serde_cbor::to_vec(&RuntimeResponse::CheckpointSealed { checkpoint }).map_err(invalid)?;
    if bytes.len() > limit { return oversized(); }
    Ok(bytes)
}

/// Measures an encoding without allocating a second copy of the checkpoint.
struct ByteCount(usize);
impl io::Write for ByteCount {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self.0.saturating_add(bytes.len());
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

async fn transition(state: &Arc<Mutex<EnclaveState>>) -> tokio::sync::OwnedMutexGuard<()> {
    let gate = Arc::clone(&state.lock().await.transition_gate);
    gate.lock_owned().await
}

/// Only the transition gate spans preparation and the immutable-storage ACK.
/// Readers see the last committed state; the candidate is never exposed before
/// the exact HMAC-bound acknowledgement and all adoption checks succeed.
async fn execute_direct<S>(
    stream: &mut S,
    state: Arc<Mutex<EnclaveState>>,
    request: layrs_direct_execution_v1::DirectRequest,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let _transition = transition(&state).await;
    let (mut runtime, state_key, commit_ack_key) = {
        let committed = state.lock().await;
        if !committed.recovery_complete
            || committed.restore_candidate.is_some()
            || committed.v71_restore_candidate.is_some()
        {
            drop(committed);
            return write_response(stream, RuntimeResponse::Error { code: "DIRECT_STATE_RECOVERY_REQUIRED".into() }).await;
        }
        if committed.v71_runtime.is_some() {
            drop(committed);
            return write_response(stream, RuntimeResponse::Error { code: "JOURNAL_FORMAT_MISMATCH".into() }).await;
        }
        if let Some(result) = committed.runtime.existing_result(&request).map_err(invalid)? {
            drop(committed);
            return write_response(stream, RuntimeResponse::Execute { result }).await;
        }
        (committed.runtime.clone(), zeroize::Zeroizing::new(committed.state_key.clone()),
            zeroize::Zeroizing::new(committed.commit_ack_key.clone()))
    };
    let (snapshot, state_key, prepared) = tokio::task::spawn_blocking(move || {
        let candidate = runtime.prepare_candidate(request, &state_key);
        (runtime, state_key, candidate)
    }).await.map_err(invalid)?;
    runtime = snapshot;
    let candidate = match prepared {
        Ok(candidate) => candidate,
        Err(error) => return write_response(stream, RuntimeResponse::Error { code: error.to_string() }).await,
    };
    write_response(stream, RuntimeResponse::CommitCandidate { artifact: candidate.artifact.clone() }).await?;
    let ack: RuntimeRequest = serde_cbor::from_slice(&read_frame(stream).await?).map_err(invalid)?;
    let RuntimeRequest::DurabilityAck { ack } = ack else {
        return write_response(stream, RuntimeResponse::Error { code: "DURABILITY_ACK_REQUIRED".into() }).await;
    };
    if !ack.verify_for(&candidate.artifact, &commit_ack_key) {
        return write_response(stream, RuntimeResponse::Error { code: "INVALID_DURABILITY_ACK".into() }).await;
    }
    let result = candidate.result.clone();
    // Adoption still verifies the encrypted candidate; expensive
    // hashing/decryption happens off the shared read lock and async executor.
    let adopted = tokio::task::spawn_blocking(move || {
        runtime.adopt_candidate(candidate, &state_key).map(|()| runtime)
    }).await.map_err(invalid)?;
    match adopted {
        Ok(runtime) => {
            let previous = { let mut committed = state.lock().await;
                std::mem::replace(&mut committed.runtime, runtime) };
            drop(previous);
        },
        Err(error) => return write_response(stream, RuntimeResponse::Error { code: error.to_string() }).await,
    }
    write_response(stream, RuntimeResponse::Execute { result }).await
}

async fn execute_journal<S>(
    stream: &mut S,
    state: Arc<Mutex<EnclaveState>>,
    request: layrs_direct_execution_v1::DirectRequest,
    request_proof: layrs_direct_execution_v1::request_index::SparseRequestProof,
    archived: Option<layrs_direct_execution_v1::v71::ArchivedTerminalRecord>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let _transition = transition(&state).await;
    let (mut runtime, state_key, commit_ack_key, signing_key) = {
        let committed = state.lock().await;
        if !committed.recovery_complete
            || committed.restore_candidate.is_some()
            || committed.v71_restore_candidate.is_some()
        {
            drop(committed);
            return write_response(
                stream,
                RuntimeResponse::Error {
                    code: "DIRECT_STATE_RECOVERY_REQUIRED".into(),
                },
            )
            .await;
        }
        let Some(runtime) = committed.v71_runtime.clone() else {
            drop(committed);
            return write_response(
                stream,
                RuntimeResponse::Error {
                    code: "JOURNAL_FORMAT_MISMATCH".into(),
                },
            )
            .await;
        };
        let signing_key = derive_journal_signing_key(&committed.state_key).map_err(invalid)?;
        (
            runtime,
            zeroize::Zeroizing::new(committed.state_key.clone()),
            zeroize::Zeroizing::new(committed.commit_ack_key.clone()),
            zeroize::Zeroizing::new(signing_key),
        )
    };

    if request_proof.leaf.is_some() {
        let Some(archived) = archived else {
            return write_response(
                stream,
                RuntimeResponse::Error {
                    code: "ARCHIVED_TERMINAL_REQUIRED".into(),
                },
            )
            .await;
        };
        let verification_key = journal_verifying_key(signing_key.as_ref()).map_err(invalid)?;
        let replayed = tokio::task::spawn_blocking(move || {
            runtime.replay_archived(
                &request,
                &request_proof,
                &archived,
                &state_key,
                &verification_key,
            )
        })
        .await
        .map_err(invalid)?;
        return match replayed {
            Ok(result) => write_response(stream, RuntimeResponse::Execute { result }).await,
            Err(error) => {
                write_response(
                    stream,
                    RuntimeResponse::Error {
                        code: error.to_string(),
                    },
                )
                .await
            }
        };
    }
    if archived.is_some() {
        return write_response(
            stream,
            RuntimeResponse::Error {
                code: "UNEXPECTED_ARCHIVED_TERMINAL".into(),
            },
        )
        .await;
    }

    let (candidate_runtime, prepared) = tokio::task::spawn_blocking(move || {
        let prepared =
            runtime.prepare_candidate(request, &request_proof, &state_key, signing_key.as_ref());
        (runtime, prepared)
    })
    .await
    .map_err(invalid)?;
    runtime = candidate_runtime;
    let candidate = match prepared {
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
        RuntimeResponse::JournalCandidate {
            record: candidate.record().clone(),
            terminal_leaf: candidate.terminal_leaf().clone(),
        },
    )
    .await?;
    let ack: RuntimeRequest = serde_cbor::from_slice(&read_frame(stream).await?).map_err(invalid)?;
    let RuntimeRequest::JournalDurabilityAck { ack } = ack else {
        return write_response(
            stream,
            RuntimeResponse::Error {
                code: "JOURNAL_DURABILITY_ACK_REQUIRED".into(),
            },
        )
        .await;
    };
    if !ack.verify_for(candidate.record(), &commit_ack_key) {
        return write_response(
            stream,
            RuntimeResponse::Error {
                code: "INVALID_JOURNAL_DURABILITY_ACK".into(),
            },
        )
        .await;
    }
    let result = candidate.result().clone();
    let adopted = runtime.adopt_candidate(candidate);
    if let Err(error) = adopted {
        return write_response(
            stream,
            RuntimeResponse::Error {
                code: error.to_string(),
            },
        )
        .await;
    }
    let financial = runtime.financial_runtime().clone();
    let mut committed = state.lock().await;
    committed.runtime = financial;
    committed.v71_runtime = Some(runtime);
    drop(committed);
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
    let binding_commitment = runtime_binding_commitment(&binding);
    match nsm_process_request(
        state.nsm_fd,
        NsmRequest::Attestation {
            // Fixed 32-byte commitment. The complete binding is returned next
            // to the document and is accepted only when its recomputed,
            // domain-separated hash equals these attested bytes.
            user_data: Some(binding_commitment.to_vec().into()),
            nonce: Some(nonce.into()),
            public_key: None,
        },
    ) {
        NsmResponse::Attestation { document } => RuntimeResponse::Attestation {
            document,
            binding,
            binding_commitment,
        },
        _ => RuntimeResponse::Error {
            code: "ATTESTATION_FAILED".into(),
        },
    }
}

fn quest_evidence_gate(state:&EnclaveState)->Result<(),&'static str> {
    if !state.recovery_complete||state.restore_candidate.is_some() {return Err("DIRECT_STATE_RECOVERY_REQUIRED");}
    if !state.runtime.writer_enabled() {return Err("DIRECT_WRITER_DISABLED");}
    let now=SystemTime::now().duration_since(UNIX_EPOCH).ok().map(|duration|duration.as_secs());
    if state.mode==RuntimeMode::ProductionEnabled && !state.writer_grant_expires_at_unix.zip(now).is_some_and(|(expiry,now)|expiry>now) {
        return Err("DIRECT_AUTHORIZATION_EXPIRED");
    }
    Ok(())
}
async fn public_quest_receipt(state:&Arc<Mutex<EnclaveState>>,participant:&str,owner:&str,request:&str,nonce:&[u8])->RuntimeResponse {
    let state=state.lock().await;
    if let Err(code)=quest_evidence_gate(&state) {return RuntimeResponse::Error{code:code.into()};}
    // Bound lookup frames before consulting private committed state. No
    // arbitrary payload or caller-selected financial fields are accepted.
    let hash=|value:&str|value.len()==64&&value.bytes().all(|byte|byte.is_ascii_digit()||(b'a'..=b'f').contains(&byte));
    if nonce.len()!=32||!hash(participant)||!hash(owner)||request.is_empty()||request.len()>128||!request.bytes().all(|byte|byte.is_ascii_alphanumeric()||b"-_:".contains(&byte)) {
        return RuntimeResponse::Error{code:"INVALID_PRIVACY_RECEIPT_REQUEST".into()};
    }
    match state.runtime.quest_receipt_witness(participant,owner,request,nonce) {
        Ok(witness)=>RuntimeResponse::PublicQuestReceipt{witness},
        Err(_)=>RuntimeResponse::Error{code:"PRIVACY_RECEIPT_UNAVAILABLE".into()},
    }
}
async fn attest_quest_receipt_key(state:&Arc<Mutex<EnclaveState>>,nonce:Vec<u8>)->RuntimeResponse {
    attest_quest_receipt_key_with(state,nonce,|fd,commitment,nonce,key|match nsm_process_request(fd,NsmRequest::Attestation {
        user_data:Some(commitment.to_vec().into()),nonce:Some(nonce.into()),public_key:Some(key.into()),
    }) {
        NsmResponse::Attestation{document}=>Ok(document), _=>Err(()),
    }).await
}
async fn attest_quest_receipt_key_with<F>(state:&Arc<Mutex<EnclaveState>>,nonce:Vec<u8>,attestor:F)->RuntimeResponse
where F:FnOnce(i32,[u8;32],Vec<u8>,Vec<u8>)->Result<Vec<u8>,()> {
    if !(16..=512).contains(&nonce.len()) {return RuntimeResponse::Error{code:"INVALID_NONCE".into()};}
    let state=state.lock().await;
    if let Err(code)=quest_evidence_gate(&state) {return RuntimeResponse::Error{code:code.into()};}
    let binding=runtime_binding(state.runtime.identity_count(),state.runtime.writer_enabled(),state.runtime.admission_enabled(),state.writer_grant_commitment.clone(),state.writer_grant_expires_at_unix,state.key_release_artifact_hash.clone());
    let Ok(public_key)=quest_receipt_public_key(&state.receipt_key) else {return RuntimeResponse::Error{code:"ATTESTATION_FAILED".into()};};
    let Ok(binding_commitment)=quest_receipt_attestation_commitment(&binding,&public_key) else {return RuntimeResponse::Error{code:"ATTESTATION_FAILED".into()};};
    match attestor(state.nsm_fd,binding_commitment,nonce,public_key.clone()) {
        Ok(document) if !document.is_empty()=>RuntimeResponse::QuestReceiptAttestation{document,binding,binding_commitment,public_key},
        _=>RuntimeResponse::Error{code:"ATTESTATION_FAILED".into()},
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
        DirectResolutionOutcome, DurabilityAck, FeeProfileId, FilesystemImmutableArtifactStore,
        GovernedMarketRegistration, GovernedMarketResolution, MarketConfig, MarketExecution,
        OrderAction, Outcome, TimeInForce, EPOCH_ID, TRANSACTION_MODEL,
    };
    use openssl::{
        asn1::Asn1Time,
        cms::CMSOptions,
        hash::MessageDigest,
        stack::Stack,
        symm::Cipher,
        x509::{X509NameBuilder, X509},
    };
    const TEST_VSOCK_BUFFER_BYTES: usize = 64 * 1024;

    #[tokio::test]
    async fn frame_limit_round_trips_exact_limit_and_rejects_one_over() {
        assert_eq!(MAX_FRAME_BYTES, 768 * 1024 * 1024);
        let expected = vec![0x5a; MAX_FRAME_BYTES];
        let (mut writer, mut reader) = tokio::io::duplex(TEST_VSOCK_BUFFER_BYTES);
        let write = tokio::spawn(async move { write_frame(&mut writer, &expected).await });
        let observed = read_frame(&mut reader).await.unwrap();
        write.await.unwrap().unwrap();
        assert_eq!(observed.len(), MAX_FRAME_BYTES);
        assert!(observed.iter().all(|byte| *byte == 0x5a));

        let (mut writer, mut reader) = tokio::io::duplex(8);
        writer.write_u32((MAX_FRAME_BYTES + 1) as u32).await.unwrap();
        assert_eq!(read_frame(&mut reader).await.unwrap_err().kind(), io::ErrorKind::InvalidData);
        // Zeroed and never read: rejected before any byte reaches the stream.
        let oversized = vec![0u8; MAX_FRAME_BYTES + 1];
        let (mut writer, _reader) = tokio::io::duplex(8);
        assert_eq!(write_frame(&mut writer, &oversized).await.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }
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
                // Deliberately matches a Privy auth-wallet mapping in the
                // sealed epoch. The packaged VSOCK path must accept it only as
                // the caller's explicit action destination, never auto-select
                // it from authentication state.
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
        let financial_wallet_address = match &action {
            DirectAction::CreditDeposit { .. } => {
                Some("0xfefefefefefefefefefefefefefefefefefefefe".into())
            }
            DirectAction::ReserveWithdrawal { destination, .. }
            | DirectAction::RecordWithdrawalReverted { destination, .. } => {
                Some(destination.to_ascii_lowercase())
            }
            _ => None,
        };
        let mut request = DirectRequest {
            account_id: account_id.into(),
            identity_commitment: identity_commitment.into(),
            request_id: id.into(),
            request_hash: String::new(),
            financial_wallet_address,
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
    fn market_resolution(id: &str, market_id: &str) -> DirectRequest {
        request_for(
            "governance",
            "governance",
            id,
            DirectAction::ResolveMarket {
                resolution: GovernedMarketResolution {
                    resolution_id: id.into(),
                    epoch_id: EPOCH_ID.into(),
                    runtime: TRANSACTION_MODEL.into(),
                    market_id: market_id.into(),
                    outcome: DirectResolutionOutcome::Up,
                    evidence_sha256: "a".repeat(64),
                    resolved_at_millis: 10_000_000,
                    expires_at_unix: 20_000,
                    governance_key_id: "isolated".into(),
                    signing_algorithm: "isolated".into(),
                    signature: "isolated-market-resolution".into(),
                },
                now_unix: 10_000,
            },
        )
    }
    fn state() -> Arc<Mutex<EnclaveState>> {
        let epoch = SealedEpoch::load(epoch_path()).unwrap();
        let mode = RuntimeMode::IsolatedTest;
        let receipt_key = vec![7; 32];
        Arc::new(Mutex::new(EnclaveState {
            transition_gate: Arc::new(Mutex::new(())),
            nsm_fd: -1,
            runtime: DirectRuntime::new(epoch.clone(), mode, receipt_key.clone()).unwrap(),
            v71_runtime: None,
            epoch,
            mode,
            receipt_key,
            state_key: vec![8; 32],
            commit_ack_key: vec![9; 32],
            recovery_complete: false,
            restore_candidate: None,
            v71_restore_candidate: None,
            committed_restore_frontier: None,
            pending_governed_bootstrap: None,
            writer_grant_commitment: None,
            writer_grant_expires_at_unix: None,
            key_release_artifact_hash: None,
        }))
    }
    fn dormant_state() -> Arc<Mutex<EnclaveState>> {
        let epoch = SealedEpoch::load(epoch_path()).unwrap();
        Arc::new(Mutex::new(EnclaveState {
            transition_gate: Arc::new(Mutex::new(())),
            nsm_fd: -1,
            runtime: DirectRuntime::new(epoch.clone(), RuntimeMode::Dormant, vec![0; 32]).unwrap(),
            v71_runtime: None,
            epoch,
            mode: RuntimeMode::Dormant,
            receipt_key: vec![0; 32],
            state_key: vec![0; 32],
            commit_ack_key: vec![0; 32],
            recovery_complete: false,
            restore_candidate: None,
            v71_restore_candidate: None,
            committed_restore_frontier: None,
            pending_governed_bootstrap: None,
            writer_grant_commitment: None,
            writer_grant_expires_at_unix: None,
            key_release_artifact_hash: None,
        }))
    }
    #[tokio::test]
    async fn quest_key_attestation_refuses_invalid_nonce_unrecovered_dormant_and_expired_writer() {
        let live=state();
        let forbidden=|_:i32,_:[u8;32],_:Vec<u8>,_:Vec<u8>|->Result<Vec<u8>,()>{panic!("unauthorized attestation invoked NSM");};
        for nonce in [vec![0;15],vec![0;513]] {
            assert_eq!(attest_quest_receipt_key_with(&live,nonce,forbidden).await,RuntimeResponse::Error{code:"INVALID_NONCE".into()});
        }
        assert_eq!(attest_quest_receipt_key_with(&live,vec![1;16],forbidden).await,RuntimeResponse::Error{code:"DIRECT_STATE_RECOVERY_REQUIRED".into()});
        let dormant=dormant_state();dormant.lock().await.recovery_complete=true;
        assert_eq!(attest_quest_receipt_key_with(&dormant,vec![1;16],forbidden).await,RuntimeResponse::Error{code:"DIRECT_WRITER_DISABLED".into()});
        {let mut state=live.lock().await;state.recovery_complete=true;state.mode=RuntimeMode::ProductionEnabled;state.writer_grant_expires_at_unix=Some(1);}
        assert_eq!(attest_quest_receipt_key_with(&live,vec![1;16],forbidden).await,RuntimeResponse::Error{code:"DIRECT_AUTHORIZATION_EXPIRED".into()});
        {let mut state=live.lock().await;state.mode=RuntimeMode::IsolatedTest;state.restore_candidate=Some(state.runtime.clone());}
        assert_eq!(attest_quest_receipt_key_with(&live,vec![1;16],forbidden).await,RuntimeResponse::Error{code:"DIRECT_STATE_RECOVERY_REQUIRED".into()});
    }
    #[tokio::test]
    async fn quest_key_attestation_binds_only_public_key_and_nonce_without_ledger_mutation() {
        let live=state();recover(Arc::clone(&live),Vec::new()).await;
        let before={let state=live.lock().await;(state.runtime.committed_state_hash(),state.runtime.committed_sequence())};
        let expected_key=quest_receipt_public_key(&[7;32]).unwrap();
        let nonce=vec![42;32];
        let result=attest_quest_receipt_key_with(&live,nonce.clone(),|_,commitment,actual_nonce,key| {
            assert_eq!(key,expected_key);assert_eq!(actual_nonce,nonce);
            assert_ne!(commitment,runtime_binding_commitment(&runtime_binding(421,true,true,None,None,None)));
            Ok(b"synthetic-unit-test-attestation-not-a-Nitro-document".to_vec())
        }).await;
        let RuntimeResponse::QuestReceiptAttestation{binding,binding_commitment,public_key,..}=result else {panic!("expected receipt-key attestation");};
        assert_eq!(public_key,expected_key);
        assert_eq!(binding_commitment,quest_receipt_attestation_commitment(&binding,&public_key).unwrap());
        let mut changed=binding.clone();changed.writer_enabled=false;
        assert_ne!(binding_commitment,quest_receipt_attestation_commitment(&changed,&public_key).unwrap());
        assert_ne!(binding_commitment,quest_receipt_attestation_commitment(&binding,&[0;32]).unwrap());
        assert_eq!(before,{let state=live.lock().await;(state.runtime.committed_state_hash(),state.runtime.committed_sequence())});
        assert_eq!(attest_quest_receipt_key_with(&live,vec![1;16],|_,_,_,_|Ok(Vec::new())).await,RuntimeResponse::Error{code:"ATTESTATION_FAILED".into()});
    }
    #[tokio::test]
    async fn vsock_public_receipt_requires_committed_recovered_owned_activity() {
        let live=state();
        assert_eq!(public_quest_receipt(&live,SUBJECT,SUBJECT,"new-admission",&[42;32]).await,RuntimeResponse::Error{code:"DIRECT_STATE_RECOVERY_REQUIRED".into()});
        recover(Arc::clone(&live),Vec::new()).await;
        let subject="a".repeat(64);let wallet="0x1111111111111111111111111111111111111111";
        let identity=identity_commitment_for(&subject,wallet);
        let store=FilesystemImmutableArtifactStore::new(artifact_dir());
        let admission=request_for(&subject,&identity,"new-admission",DirectAction::AdmitIdentity{wallet_address:wallet.into()});
        let RuntimeResponse::Execute{..}=commit_through_parent_callback(Arc::clone(&live),admission,&store).await else {panic!("admission was not committed");};
        let request=RuntimeRequest::PublicQuestReceipt{participant_account:subject.clone(),receipt_account:subject.clone(),request_id:"new-admission".into(),nonce:vec![42;32]};
        let response=runtime_response(Arc::clone(&live),request.clone()).await;
        let RuntimeResponse::PublicQuestReceipt{witness}=response.clone() else {panic!("expected owned witness");};
        let receipt=&witness.receipt;
        assert_eq!(witness.lookup.participant_account,subject);
        assert_eq!(witness.lookup.request_id,"new-admission");
        assert_eq!(witness.lookup.nonce,hex::encode([42;32]));
        assert!(layrs_direct_execution_v1::verify_public_quest_receipt(&receipt,&quest_receipt_public_key(&[7;32]).unwrap()));
        assert_eq!(public_quest_receipt(&live,SUBJECT,&subject,"new-admission",&[42;32]).await,RuntimeResponse::Error{code:"PRIVACY_RECEIPT_UNAVAILABLE".into()});
        assert_eq!(public_quest_receipt(&live,&subject,&subject,&"x".repeat(129),&[42;32]).await,RuntimeResponse::Error{code:"INVALID_PRIVACY_RECEIPT_REQUEST".into()});
        let restarted=state();recover(Arc::clone(&restarted),store.load_committed().unwrap()).await;
        assert_eq!(runtime_response(restarted,request).await,response);
        assert_eq!(store.load_committed().unwrap().len(),1);
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
            key_release_predecessor: None,
            committed_restore_frontier: None,
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
        let (mut parent, enclave) = tokio::io::duplex(TEST_VSOCK_BUFFER_BYTES);
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
    #[tokio::test]
    async fn checkpoint_restore_starts_at_verified_head_and_adopts_only_after_exact_tip() {
        let running = state(); let store = FilesystemImmutableArtifactStore::new(artifact_dir());
        recover(Arc::clone(&running), vec![]).await;
        for id in ["checkpoint-one", "checkpoint-two", "checkpoint-three"] {
            assert!(matches!(commit_through_parent_callback(Arc::clone(&running), request(id), &store).await, RuntimeResponse::Execute { .. }));
        }
        let artifacts = store.load_committed().unwrap();
        let records = artifacts.iter().cloned().map(|mut record| { record.ciphertext.clear(); record }).collect();
        let hashes = artifacts.iter().map(layrs_direct_execution_v1::artifact_hash).collect();
        let checkpoint = running.lock().await.runtime.seal_checkpoint(artifacts.last().unwrap().clone(), records, hashes, &[8;32]).unwrap();
        let root = checkpoint.artifact.state_hash.clone();
        let restarted = state();
        assert!(matches!(begin_checkpoint_restore(Arc::clone(&restarted), checkpoint.clone()).await, RuntimeResponse::RestoreProgress { recovered_sequence: 3, .. }));
        assert!(!restarted.lock().await.recovery_complete);
        assert!(matches!(execute_response(Arc::clone(&restarted), request("checkpoint-one")).await, RuntimeResponse::Error { .. }));
        assert!(matches!(finish_committed_restore(Arc::clone(&restarted), 4, root.clone()).await, RuntimeResponse::Error { .. }));
        assert!(!restarted.lock().await.recovery_complete);
        assert!(matches!(begin_checkpoint_restore(Arc::clone(&restarted), checkpoint.clone()).await, RuntimeResponse::RestoreProgress { recovered_sequence: 3, .. }));
        assert!(matches!(finish_committed_restore(Arc::clone(&restarted), 3, root.clone()).await, RuntimeResponse::RecoveryComplete { recovered_sequence: 3, .. }));
        assert_eq!(restarted.lock().await.runtime.committed_state_hash(), running.lock().await.runtime.committed_state_hash());
        let replay = execute_response(Arc::clone(&restarted), request("checkpoint-one")).await;
        assert_eq!(replay, execute_response(Arc::clone(&running), request("checkpoint-one")).await);
        // Reconnecting parent is allowed, but cannot change adopted state.
        assert!(matches!(begin_checkpoint_restore(Arc::clone(&restarted), checkpoint).await, RuntimeResponse::RestoreProgress { recovered_sequence: 3, .. }));
        assert!(matches!(finish_committed_restore(Arc::clone(&restarted), 3, root).await, RuntimeResponse::RecoveryComplete { .. }));
    }
    #[tokio::test]
    async fn checkpoint_restore_rejects_rollback_below_governed_frontier_and_corrupt_snapshot() {
        let running = state(); let store = FilesystemImmutableArtifactStore::new(artifact_dir());
        recover(Arc::clone(&running), vec![]).await;
        commit_through_parent_callback(Arc::clone(&running), request("checkpoint-old"), &store).await;
        let first = store.load_committed().unwrap();
        let mut compact = first[0].clone(); compact.ciphertext.clear();
        let checkpoint = running.lock().await.runtime.seal_checkpoint(first[0].clone(), vec![compact], vec![layrs_direct_execution_v1::artifact_hash(&first[0])], &[8;32]).unwrap();
        let restarted = state();
        restarted.lock().await.committed_restore_frontier = Some(layrs_direct_execution_v1::CommittedRestoreFrontier { sequence: 2, state_hash: "a".repeat(64), artifact_hash: "b".repeat(64) });
        assert!(matches!(begin_checkpoint_restore(Arc::clone(&restarted), checkpoint.clone()).await, RuntimeResponse::Error { code } if code == "CHECKPOINT_BELOW_GOVERNED_FRONTIER"));
        restarted.lock().await.committed_restore_frontier = None;
        let mut corrupt = checkpoint; corrupt.artifact.ciphertext[0] ^= 1;
        assert!(matches!(begin_checkpoint_restore(Arc::clone(&restarted), corrupt).await, RuntimeResponse::Error { code } if code == "CHECKPOINT_AUTHENTICATION_FAILED"));
        assert!(!restarted.lock().await.recovery_complete);
        assert!(restarted.lock().await.restore_candidate.is_none());
        assert_eq!(restarted.lock().await.runtime.committed_sequence(), 0);
    }
    #[tokio::test]
    async fn sealed_checkpoint_is_refused_unless_its_restore_frame_fits() {
        let running = state(); let store = FilesystemImmutableArtifactStore::new(artifact_dir());
        recover(Arc::clone(&running), vec![]).await;
        commit_through_parent_callback(Arc::clone(&running), request("checkpoint-frame"), &store).await;
        let first = store.load_committed().unwrap();
        let mut compact = first[0].clone(); compact.ciphertext.clear();
        let checkpoint = running.lock().await.runtime.seal_checkpoint(first[0].clone(), vec![compact], vec![layrs_direct_execution_v1::artifact_hash(&first[0])], &[8;32]).unwrap();
        let restore = serde_cbor::to_vec(&RuntimeRequest::BeginCheckpointRestore { checkpoint: checkpoint.clone() }).unwrap().len();
        let sealed = serde_cbor::to_vec(&RuntimeResponse::CheckpointSealed { checkpoint: checkpoint.clone() }).unwrap().len();
        // The restart frame is the binding constraint, not the seal response.
        assert!(sealed < restore);

        let fits: RuntimeResponse = serde_cbor::from_slice(&checkpoint_sealed_frame(checkpoint.clone(), restore).unwrap()).unwrap();
        assert_eq!(fits, RuntimeResponse::CheckpointSealed { checkpoint: checkpoint.clone() });
        let refused: RuntimeResponse = serde_cbor::from_slice(&checkpoint_sealed_frame(checkpoint, restore - 1).unwrap()).unwrap();
        assert_eq!(refused, RuntimeResponse::Error { code: CHECKPOINT_FRAME_OVERSIZED.into() });
        // Refusal is transport-only; committed state is unchanged.
        assert!(running.lock().await.recovery_complete);
        assert_eq!(running.lock().await.runtime.committed_sequence(), 1);
    }
    #[tokio::test]
    async fn streamed_restore_verifies_every_successor_and_final_head_before_adoption() {
        let running=state();let store=FilesystemImmutableArtifactStore::new(artifact_dir());
        assert!(matches!(recover(Arc::clone(&running),vec![]).await,RuntimeResponse::RecoveryComplete{..}));
        for id in ["stream-one","stream-two","stream-three"] {
            assert!(matches!(commit_through_parent_callback(Arc::clone(&running),request(id),&store).await,RuntimeResponse::Execute{..}));
        }
        let artifacts=store.load_committed().unwrap();let expected=artifacts.last().unwrap().state_hash.clone();
        let restarted=state();assert!(matches!(begin_committed_restore(Arc::clone(&restarted)).await,RuntimeResponse::RestoreProgress{..}));
        assert!(matches!(execute_response(Arc::clone(&restarted),request("blocked-during-restore")).await,RuntimeResponse::Error{..}));
        assert!(matches!(append_committed_restore(Arc::clone(&restarted),artifacts[1].clone()).await,RuntimeResponse::Error{..}));
        assert!(!restarted.lock().await.recovery_complete);
        assert!(matches!(finish_committed_restore(Arc::clone(&restarted),3,expected.clone()).await,RuntimeResponse::Error{..}));
        assert!(matches!(begin_committed_restore(Arc::clone(&restarted)).await,RuntimeResponse::RestoreProgress{..}));
        for artifact in artifacts.iter().cloned(){assert!(matches!(append_committed_restore(Arc::clone(&restarted),artifact).await,RuntimeResponse::RestoreProgress{..}));}
        assert!(matches!(finish_committed_restore(Arc::clone(&restarted),2,expected.clone()).await,RuntimeResponse::Error{..}));
        assert!(!restarted.lock().await.recovery_complete);
        assert!(matches!(begin_committed_restore(Arc::clone(&restarted)).await,RuntimeResponse::RestoreProgress{..}));
        for artifact in artifacts.iter().cloned(){assert!(matches!(append_committed_restore(Arc::clone(&restarted),artifact).await,RuntimeResponse::RestoreProgress{..}));}
        assert!(matches!(finish_committed_restore(Arc::clone(&restarted),3,expected.clone()).await,RuntimeResponse::RecoveryComplete{recovered_sequence:3,..}));
        assert_eq!(restarted.lock().await.runtime.committed_state_hash(),expected);
        assert!(matches!(execute_response(Arc::clone(&restarted),request("stream-one")).await,RuntimeResponse::Execute{..}));
        let mut corrupt=artifacts[0].clone();corrupt.ciphertext[0]^=1;
        assert!(matches!(begin_committed_restore(Arc::clone(&restarted)).await,RuntimeResponse::RestoreProgress{..}));
        assert!(matches!(append_committed_restore(Arc::clone(&restarted),corrupt).await,RuntimeResponse::Error{..}));
        assert_eq!(restarted.lock().await.runtime.committed_state_hash(),expected);
    }
    async fn begin(
        state: Arc<Mutex<EnclaveState>>,
        request: DirectRequest,
    ) -> (
        tokio::io::DuplexStream,
        tokio::task::JoinHandle<io::Result<()>>,
    ) {
        let (mut parent, enclave) = tokio::io::duplex(TEST_VSOCK_BUFFER_BYTES);
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
    async fn activate_empty_journal(state: &Arc<Mutex<EnclaveState>>) {
        let mut state = state.lock().await;
        let runtime = DirectV71Runtime::new_empty(state.runtime.clone(), "isolated-writer-1".into())
            .unwrap();
        state.v71_runtime = Some(runtime);
        state.recovery_complete = true;
    }
    async fn commit_journal_through_parent_callback(
        state: Arc<Mutex<EnclaveState>>,
        request: DirectRequest,
        proof: layrs_direct_execution_v1::request_index::SparseRequestProof,
    ) -> (
        RuntimeResponse,
        layrs_direct_execution_v1::journal::DirectJournalRecord,
        layrs_direct_execution_v1::request_index::TerminalRequestLeaf,
    ) {
        let (mut parent, enclave) = tokio::io::duplex(TEST_VSOCK_BUFFER_BYTES);
        let server = tokio::spawn(serve(enclave, state));
        write_frame(
            &mut parent,
            &serde_cbor::to_vec(&RuntimeRequest::ExecuteJournal {
                request,
                request_proof: proof,
                archived: None,
            })
            .unwrap(),
        )
        .await
        .unwrap();
        let candidate: RuntimeResponse =
            serde_cbor::from_slice(&read_frame(&mut parent).await.unwrap()).unwrap();
        let RuntimeResponse::JournalCandidate {
            record,
            terminal_leaf,
        } = candidate
        else {
            panic!("expected journal candidate, got {candidate:?}");
        };
        let ack = layrs_direct_execution_v1::journal::JournalDurabilityAck::issue(
            &record,
            &[9; 32],
        )
        .unwrap();
        write_frame(
            &mut parent,
            &serde_cbor::to_vec(&RuntimeRequest::JournalDurabilityAck { ack }).unwrap(),
        )
        .await
        .unwrap();
        let terminal = serde_cbor::from_slice(&read_frame(&mut parent).await.unwrap()).unwrap();
        server.await.unwrap().unwrap();
        (terminal, record, terminal_leaf)
    }

    #[tokio::test]
    async fn journal_commit_requires_exact_ack_and_replays_without_a_successor() {
        let live = state();
        activate_empty_journal(&live).await;
        let command = request("journal-request-1");
        let empty = layrs_direct_execution_v1::request_index::SparseRequestProof::empty_tree();
        let (terminal, record, leaf) = commit_journal_through_parent_callback(
            Arc::clone(&live),
            command.clone(),
            empty.clone(),
        )
        .await;
        let RuntimeResponse::Execute { result } = terminal else {
            panic!("journal command did not commit");
        };
        {
            let state = live.lock().await;
            assert_eq!(state.v71_runtime.as_ref().unwrap().sequence(), 1);
            assert_eq!(state.runtime.committed_sequence(), 0);
        }

        let membership = layrs_direct_execution_v1::request_index::SparseRequestProof {
            leaf: Some(leaf),
            siblings: empty.siblings,
        };
        let replay = runtime_response(
            Arc::clone(&live),
            RuntimeRequest::ExecuteJournal {
                request: command,
                request_proof: membership,
                archived: Some(
                    layrs_direct_execution_v1::v71::ArchivedTerminalRecord::Journal { record },
                ),
            },
        )
        .await;
        assert_eq!(replay, RuntimeResponse::Execute { result });
        assert_eq!(live.lock().await.v71_runtime.as_ref().unwrap().sequence(), 1);

        assert!(matches!(
            runtime_response(
                live,
                RuntimeRequest::Execute {
                    request: request("v70-after-v71")
                }
            )
            .await,
            RuntimeResponse::Error { ref code } if code == "JOURNAL_FORMAT_MISMATCH"
        ));
    }

    #[tokio::test]
    async fn invalid_journal_ack_adopts_nothing_and_exact_retry_reseals_same_record() {
        let live = state();
        activate_empty_journal(&live).await;
        let command = request("journal-invalid-ack");
        let proof = layrs_direct_execution_v1::request_index::SparseRequestProof::empty_tree();
        let (mut parent, enclave) = tokio::io::duplex(TEST_VSOCK_BUFFER_BYTES);
        let server = tokio::spawn(serve(enclave, Arc::clone(&live)));
        write_frame(
            &mut parent,
            &serde_cbor::to_vec(&RuntimeRequest::ExecuteJournal {
                request: command.clone(),
                request_proof: proof.clone(),
                archived: None,
            })
            .unwrap(),
        )
        .await
        .unwrap();
        let response: RuntimeResponse =
            serde_cbor::from_slice(&read_frame(&mut parent).await.unwrap()).unwrap();
        let RuntimeResponse::JournalCandidate { record: first, .. } = response else {
            panic!("expected journal candidate");
        };
        let mut ack = layrs_direct_execution_v1::journal::JournalDurabilityAck::issue(
            &first,
            &[9; 32],
        )
        .unwrap();
        ack.signature = "0".repeat(64);
        write_frame(
            &mut parent,
            &serde_cbor::to_vec(&RuntimeRequest::JournalDurabilityAck { ack }).unwrap(),
        )
        .await
        .unwrap();
        let rejected: RuntimeResponse =
            serde_cbor::from_slice(&read_frame(&mut parent).await.unwrap()).unwrap();
        assert!(matches!(rejected, RuntimeResponse::Error { ref code } if code == "INVALID_JOURNAL_DURABILITY_ACK"));
        server.await.unwrap().unwrap();
        assert_eq!(live.lock().await.v71_runtime.as_ref().unwrap().sequence(), 0);

        let (terminal, retry, _) =
            commit_journal_through_parent_callback(live, command, proof).await;
        assert_eq!(retry, first);
        assert!(matches!(terminal, RuntimeResponse::Execute { .. }));
    }

    #[tokio::test]
    async fn journal_checkpoint_plus_tail_restores_exact_head_before_adoption() {
        let live = state();
        activate_empty_journal(&live).await;
        let sealed = runtime_response(Arc::clone(&live), RuntimeRequest::SealJournalCheckpoint).await;
        let RuntimeResponse::JournalCheckpointSealed { checkpoint } = sealed else {
            panic!("journal checkpoint was not sealed");
        };
        let command = request("journal-restored-tail");
        let proof = layrs_direct_execution_v1::request_index::SparseRequestProof::empty_tree();
        let (terminal, record, _) =
            commit_journal_through_parent_callback(Arc::clone(&live), command, proof).await;
        assert!(matches!(terminal, RuntimeResponse::Execute { .. }));
        let (sequence, record_hash, transition_root, request_index_root, financial_state_root) = {
            let state = live.lock().await;
            let runtime = state.v71_runtime.as_ref().unwrap();
            (
                runtime.sequence(),
                runtime.record_hash().to_string(),
                runtime.transition_root().to_string(),
                runtime.request_index_root().to_string(),
                runtime.financial_state_root().unwrap(),
            )
        };

        let restarted = state();
        assert!(matches!(
            runtime_response(
                Arc::clone(&restarted),
                RuntimeRequest::BeginJournalRestore { checkpoint }
            )
            .await,
            RuntimeResponse::JournalRestoreProgress { sequence: 0, receipt: None, .. }
        ));
        assert!(matches!(
            runtime_response(
                Arc::clone(&restarted),
                RuntimeRequest::AppendJournalRestore { record }
            )
            .await,
            RuntimeResponse::JournalRestoreProgress { sequence: 1, receipt: Some(_), .. }
        ));
        let complete = runtime_response(
            Arc::clone(&restarted),
            RuntimeRequest::FinishJournalRestore {
                expected_sequence: sequence,
                expected_record_hash: record_hash,
                expected_transition_root: transition_root,
                expected_request_index_root: request_index_root,
                expected_financial_state_root: financial_state_root,
            },
        )
        .await;
        assert!(matches!(
            complete,
            RuntimeResponse::JournalRestoreComplete { sequence: 1, .. }
        ));
        let restarted = restarted.lock().await;
        assert!(restarted.recovery_complete);
        assert_eq!(restarted.v71_runtime.as_ref().unwrap().sequence(), 1);
    }

    #[tokio::test]
    async fn v70_migration_rejects_tampering_then_activates_and_replays_exact_result() {
        let live = state();
        recover(Arc::clone(&live), Vec::new()).await;
        let subject = "a".repeat(64);
        let wallet = "0x1111111111111111111111111111111111111111";
        let identity = identity_commitment_for(&subject, wallet);
        let command = request_for(
            &subject,
            &identity,
            "migration-admission",
            DirectAction::AdmitIdentity {
                wallet_address: wallet.into(),
            },
        );
        let store = FilesystemImmutableArtifactStore::new(artifact_dir());
        let expected =
            commit_through_parent_callback(Arc::clone(&live), command.clone(), &store).await;
        assert!(matches!(expected, RuntimeResponse::Execute { .. }));
        let source = {
            let state = live.lock().await;
            (
                state.runtime.committed_sequence(),
                state.runtime.committed_state_hash(),
            )
        };

        let sealed = runtime_response(Arc::clone(&live), RuntimeRequest::SealV70Migration).await;
        let RuntimeResponse::V70MigrationSealed { bundle } = sealed else {
            panic!("v70 migration was not sealed");
        };
        assert_eq!(bundle.manifest.source_sequence, source.0);
        assert_eq!(bundle.manifest.source_state_hash, source.1);

        let mut tampered = bundle.clone();
        tampered.manifest.signature = "0".repeat(128);
        assert!(matches!(
            runtime_response(
                Arc::clone(&live),
                RuntimeRequest::ActivateV71Migration { bundle: tampered }
            )
            .await,
            RuntimeResponse::Error { ref code }
                if code == "V71_MIGRATION_AUTHENTICATION_FAILED"
        ));
        {
            let state = live.lock().await;
            assert_eq!(state.runtime.committed_sequence(), source.0);
            assert_eq!(state.runtime.committed_state_hash(), source.1);
            assert!(state.v71_runtime.is_none());
        }

        let activated = runtime_response(
            Arc::clone(&live),
            RuntimeRequest::ActivateV71Migration {
                bundle: bundle.clone(),
            },
        )
        .await;
        assert!(matches!(
            activated,
            RuntimeResponse::V71MigrationActivated { sequence: 1, .. }
        ));
        {
            let state = live.lock().await;
            assert_eq!(state.runtime.committed_sequence(), 0);
            assert_eq!(state.v71_runtime.as_ref().unwrap().sequence(), 1);
        }

        let tree = layrs_direct_execution_v1::request_index::SparseRequestTree::from_leaves(
            &bundle.leaves,
        )
        .unwrap();
        let proof = tree.proof(&command.account_id, &command.request_id).unwrap();
        let replay = runtime_response(
            Arc::clone(&live),
            RuntimeRequest::ExecuteJournal {
                request: command,
                request_proof: proof,
                archived: Some(
                    layrs_direct_execution_v1::v71::ArchivedTerminalRecord::Migration {
                        record: bundle.records[0].clone(),
                    },
                ),
            },
        )
        .await;
        assert_eq!(replay, expected);
        assert_eq!(live.lock().await.v71_runtime.as_ref().unwrap().sequence(), 1);
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
    async fn runtime_response(
        state: Arc<Mutex<EnclaveState>>,
        request: RuntimeRequest,
    ) -> RuntimeResponse {
        let (mut parent, enclave) = tokio::io::duplex(TEST_VSOCK_BUFFER_BYTES);
        let server = tokio::spawn(serve(enclave, state));
        write_frame(&mut parent, &serde_cbor::to_vec(&request).unwrap())
            .await
            .unwrap();
        let response = serde_cbor::from_slice(&read_frame(&mut parent).await.unwrap()).unwrap();
        server.await.unwrap().unwrap();
        response
    }

    #[tokio::test]
    async fn isolated_bootstrap_is_idempotent_only_for_the_same_keys() {
        let epoch = SealedEpoch::load(epoch_path()).unwrap();
        let state = Arc::new(Mutex::new(EnclaveState {
            transition_gate: Arc::new(Mutex::new(())),
            nsm_fd: -1,
            runtime: DirectRuntime::new(epoch.clone(), RuntimeMode::Dormant, vec![0; 32]).unwrap(),
            v71_runtime: None,
            epoch,
            mode: RuntimeMode::Dormant,
            receipt_key: vec![0; 32],
            state_key: Vec::new(),
            commit_ack_key: Vec::new(),
            recovery_complete: false,
            restore_candidate: None,
            v71_restore_candidate: None,
            committed_restore_frontier: None,
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
        // Reads remain responsive while storage is pending, but can only see
        // the original committed balance, never the private candidate.
        { let committed = state.try_lock().expect("storage wait must not block reads");
          assert_eq!(committed.runtime.balance(IDENTITY, "USDC", "USER_AVAILABLE"), 5_000_000);
          assert!(committed.transition_gate.try_lock().is_err()); }
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
    async fn checkpoint_sealing_does_not_hold_committed_read_lock_or_block_executor() {
        let running = state();recover(Arc::clone(&running), vec![]).await;
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let checkpoint_state = Arc::clone(&running);
        let sealing = tokio::spawn(async move {
            seal_checkpoint_with(&checkpoint_state, move |_,_| {
                started_tx.send(()).unwrap();
                release_rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
                Err(layrs_direct_execution_v1::RuntimeError::StateArtifact)
            }).await
        });
        started_rx.await.unwrap();
        let response = tokio::time::timeout(std::time::Duration::from_millis(250),
            runtime_response(Arc::clone(&running), RuntimeRequest::Status)).await;
        release_tx.send(()).unwrap();
        assert!(matches!(response.unwrap(), RuntimeResponse::Status { .. }));
        assert!(matches!(sealing.await.unwrap(), RuntimeResponse::Error { code } if code == "CHECKPOINT_HEAD_INVALID"));
        assert_eq!(running.lock().await.runtime.committed_sequence(), 0);
    }

    #[tokio::test]
    async fn storage_wait_keeps_status_and_balance_responsive_but_serializes_successors() {
        let running = state();
        recover(Arc::clone(&running), vec![]).await;
        let (mut parent, server) = begin(Arc::clone(&running), request("responsive-first")).await;
        let first = candidate(&mut parent).await;
        let (mut next, next_server) = begin(Arc::clone(&running), request("responsive-second")).await;
        // A second write cannot prepare a competing successor before ACK.
        assert!(tokio::time::timeout(std::time::Duration::from_millis(50), next.read_u8()).await.is_err());
        for _ in 0..10 {
            let response = tokio::time::timeout(std::time::Duration::from_millis(250),
                runtime_response(Arc::clone(&running), RuntimeRequest::Status)).await.unwrap();
            assert!(matches!(response, RuntimeResponse::Status { .. }));
            let response = tokio::time::timeout(std::time::Duration::from_millis(250),
                runtime_response(Arc::clone(&running), RuntimeRequest::Balance {
                    account_id: SUBJECT.into(), identity_commitment: IDENTITY.into(), asset: "USDC".into(), bucket: "USER_AVAILABLE".into(),
                })).await.unwrap();
            assert!(matches!(response, RuntimeResponse::Balance { amount_atomic } if amount_atomic == "5000000"));
        }
        write_frame(&mut parent, &serde_cbor::to_vec(&RuntimeRequest::DurabilityAck {
            ack: DurabilityAck::issue(&first, &[9; 32]),
        }).unwrap()).await.unwrap();
        let terminal: RuntimeResponse = serde_cbor::from_slice(&read_frame(&mut parent).await.unwrap()).unwrap();
        assert!(matches!(terminal, RuntimeResponse::Execute { .. }));
        server.await.unwrap().unwrap();
        let second = candidate(&mut next).await;
        assert_eq!(second.sequence, first.sequence + 1);
        assert_eq!(second.prior_state_hash, first.state_hash);
        drop(next);assert!(next_server.await.unwrap().is_err());
        assert_eq!(running.lock().await.runtime.committed_sequence(), first.sequence);
        assert_eq!(running.lock().await.runtime.balance(IDENTITY,"USDC","USER_AVAILABLE"), 4_000_000);
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
        let portfolio = runtime_response(
            Arc::clone(&restarted),
            RuntimeRequest::Portfolio {
                account_id: NEW_SUBJECT.into(),
                identity_commitment: new_identity.clone(),
            },
        )
        .await;
        let RuntimeResponse::Portfolio { portfolio } = portfolio else {
            panic!("expected private portfolio response");
        };
        assert_eq!(portfolio.registered_market_ids, vec![MARKET]);
        assert_eq!(portfolio.positions.len(), 1);
        assert_eq!(portfolio.positions[0].outcome, Outcome::Down);

        let resolved = commit_through_parent_callback(
            Arc::clone(&restarted),
            market_resolution("vsock-resolution", MARKET),
            &store,
        )
        .await;
        let RuntimeResponse::Execute { result: resolved } = resolved else {
            panic!("expected terminal resolution result");
        };
        assert_eq!(resolved.effect, "MARKET_RESOLVED");
        assert_eq!(
            resolved
                .receipt
                .resolution
                .as_ref()
                .unwrap()
                .gross_payout_atomic,
            "1000000"
        );
        assert_eq!(store.load_committed().unwrap().len(), 6);

        let after_resolution_restart = state();
        assert!(matches!(
            recover(
                Arc::clone(&after_resolution_restart),
                store.load_committed().unwrap()
            )
            .await,
            RuntimeResponse::RecoveryComplete {
                recovered_sequence: 6,
                ..
            }
        ));
        let replay = execute_response(
            Arc::clone(&after_resolution_restart),
            market_resolution("vsock-resolution", MARKET),
        )
        .await;
        assert_eq!(replay, RuntimeResponse::Execute { result: resolved });
        assert_eq!(store.load_committed().unwrap().len(), 6);
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
