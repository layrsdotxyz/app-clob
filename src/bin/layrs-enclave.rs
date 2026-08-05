use std::{
    collections::{HashSet, VecDeque},
    io,
    sync::Arc,
};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use aws_nitro_enclaves_nsm_api::{
    api::{Request as NsmRequest, Response as NsmResponse},
    driver::{nsm_exit, nsm_init, nsm_process_request},
};
use clob_service::audit_signer::{
    AuditBatchRequest, AuditSignerBundle, EnclaveAuditSigner, SignedAuditSettlementTransaction,
};
use clob_service::chain_signer::{
    BridgeApprovalRequest, BridgeApprovalSignature, ChainSignerBundle, EnclaveChainSigner,
    MarketResolutionTransaction, PoolWithdrawalTransaction,
};
use clob_service::polymarket_enclave::{
    EnclavePolymarketClient, PolymarketSecretBundle, SignedVenueRedemptionTransaction,
    VenueConfirmation, VenueOrderIntent, VenueRedemptionTransactionIntent, VenueSide,
};
use clob_service::private_core::{
    exact_condition_resolution_signing_payload, polymarket_resolution_signing_payload,
    resolution_signing_payload, AccountKey, BootstrapExecutionState, CommandResult, CoreResponse,
    EnclaveReceipt, EncryptedJournalRecord, EncryptedSnapshot, ExactConditionResolutionStatement,
    ExternalFlowDirection, JournalKey, MarketConfig, MarketExecution,
    PolymarketResolutionStatement, PrivateTradingCore, ReceiptSigner, ResolutionStatement,
    SignedAuditFillArtifact, SignedExactConditionResolution, SignedPolymarketResolution,
    SignedResolution, SignedResolutionEvidence, SignedTaskQualificationArtifact, SystemResponse,
    UserCommand, UserCommandAction, WithdrawalAuthorization,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use openssl::{
    cms::CmsContentInfo,
    md::Md,
    pkey::{PKey, Private},
    pkey_ctx::PkeyCtx,
    rsa::{Padding, Rsa},
    symm::{decrypt as symm_decrypt, Cipher},
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Mutex,
};
use tokio_vsock::{VsockAddr, VsockListener, VsockStream, VMADDR_CID_ANY};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

const PORT: u32 = 5_003;
// Must match or exceed the parent relay cap. Provisioning restores encrypted
// checkpoints over this vsock channel; JSON byte-array encoding expands a
// ~1 MiB archived snapshot into a multi-MiB operator command.
const MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;
const MAX_TRANSPORT_REPLAY_ENTRIES: usize = 262_144;
const MAX_OPERATOR_REPLAY_ENTRIES: usize = 100_000;

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
enum WireRequest {
    Attestation {
        nonce: Vec<u8>,
    },
    Encrypted {
        client_public_key: [u8; 32],
        nonce: [u8; 12],
        #[serde(with = "serde_bytes")]
        ciphertext: Vec<u8>,
    },
}

#[derive(Debug, Serialize)]
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
        code: &'static str,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OperatorEnvelope {
    nonce: [u8; 32],
    command: OperatorCommand,
    signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
enum OperatorCommand {
    ProvisionStatus,
    BeginProvision {
        kms_key_id: String,
        kms_ciphertext_blob: Option<Vec<u8>>,
        oracle_public_key: [u8; 32],
        snapshot: Option<EncryptedSnapshot>,
        minimum_anchored_sequence: u64,
    },
    CompleteProvision {
        ciphertext_for_recipient: Vec<u8>,
    },
    PolymarketStatus,
    BeginPolymarketProvision {
        kms_key_id: String,
        kms_ciphertext_blob: Vec<u8>,
        bundle_nonce: [u8; 12],
        bundle_ciphertext: Vec<u8>,
    },
    CompletePolymarketProvision {
        ciphertext_for_recipient: Vec<u8>,
    },
    ChainSignerStatus,
    BeginChainSignerProvision {
        kms_key_id: String,
        kms_ciphertext_blob: Vec<u8>,
        bundle_nonce: [u8; 12],
        bundle_ciphertext: Vec<u8>,
    },
    CompleteChainSignerProvision {
        ciphertext_for_recipient: Vec<u8>,
    },
    AuditSignerStatus,
    BeginAuditSignerProvision {
        kms_key_id: String,
        kms_ciphertext_blob: Vec<u8>,
        bundle_nonce: [u8; 12],
        bundle_ciphertext: Vec<u8>,
    },
    CompleteAuditSignerProvision {
        ciphertext_for_recipient: Vec<u8>,
    },
    SignAuditBatch {
        request: AuditBatchRequest,
    },
    SignPoolWithdrawal {
        idempotency_key: String,
        authorization: WithdrawalAuthorization,
        nonce: u64,
        gas_limit: u64,
        max_fee_per_gas_wei: String,
        max_priority_fee_per_gas_wei: String,
        now_millis: i64,
    },
    SignBridgeApproval {
        request: BridgeApprovalRequest,
        now_millis: i64,
    },
    SignMarketResolution {
        chain: String,
        market_id: String,
        outcome: clob_service::private_core::ResolutionOutcome,
        evidence: SignedResolutionEvidence,
        reason_uri: String,
        nonce: u64,
        gas_limit: u64,
        max_fee_per_gas_wei: String,
        max_priority_fee_per_gas_wei: String,
        now_millis: i64,
    },
    SignResolutionEvidence {
        evidence: UnsignedResolutionEvidence,
        now_millis: i64,
    },
    ExecuteBootstrap {
        idempotency_key: String,
        execution_id: uuid::Uuid,
        timestamp_seconds: u64,
        now_millis: i64,
    },
    ReconcileBootstrap {
        idempotency_key: String,
        execution_id: uuid::Uuid,
        timestamp_seconds: u64,
        now_millis: i64,
    },
    SignPolymarketRedemption {
        market_id: String,
        outcome: clob_service::private_core::ResolutionOutcome,
        nonce: u64,
        gas_limit: u64,
        gas_price_wei: String,
        now_millis: i64,
    },
    BootstrapExecutionStatus {
        execution_id: uuid::Uuid,
        identity_commitment: [u8; 32],
    },
    MarketStatus {
        market_id: String,
    },
    ResolutionStatus {
        market_id: String,
    },
    ResolutionReadiness {
        market_id: String,
        now_millis: i64,
    },
    TradingFreezeStatus,
    AggregateDepth {
        market_id: String,
        outcome: clob_service::private_core::Outcome,
        now_millis: i64,
        #[serde(with = "clob_service::private_core::decimal_u128")]
        minimum_level_quantity_micros: u128,
    },
    SetTradingFreeze {
        idempotency_key: String,
        frozen: bool,
        reason_commitment: [u8; 32],
        now_millis: i64,
    },
    ExportSnapshot,
    RegisterMarket {
        idempotency_key: String,
        market: MarketConfig,
        now_millis: i64,
    },
    RegisterSession {
        idempotency_key: String,
        session_id: String,
        identity_commitment: [u8; 32],
        public_key: [u8; 32],
        expires_at_millis: i64,
        now_millis: i64,
    },
    ExternalFlow {
        idempotency_key: String,
        account: AccountKey,
        #[serde(with = "clob_service::private_core::decimal_u128")]
        amount: u128,
        direction: ExternalFlowDirection,
        evidence_hash: [u8; 32],
        now_millis: i64,
    },
    CreditDeposit {
        idempotency_key: String,
        identity_commitment: [u8; 32],
        asset: String,
        #[serde(with = "clob_service::private_core::decimal_u128")]
        amount_atomic: u128,
        evidence_hash: [u8; 32],
        now_millis: i64,
    },
    AccrueReward {
        idempotency_key: String,
        identity_commitment: [u8; 32],
        chain: String,
        reward_token: String,
        #[serde(with = "clob_service::private_core::decimal_u128")]
        amount_atomic: u128,
        evidence_hash: [u8; 32],
        now_millis: i64,
    },
    FinalizeWithdrawal {
        idempotency_key: String,
        identity_commitment: [u8; 32],
        asset: String,
        #[serde(with = "clob_service::private_core::decimal_u128")]
        amount_atomic: u128,
        evidence_hash: [u8; 32],
        now_millis: i64,
    },
    ReleaseWithdrawal {
        idempotency_key: String,
        identity_commitment: [u8; 32],
        asset: String,
        #[serde(with = "clob_service::private_core::decimal_u128")]
        amount_atomic: u128,
        evidence_hash: [u8; 32],
        now_millis: i64,
    },
    ResolveMarket {
        idempotency_key: String,
        signed: SignedResolution,
        now_millis: i64,
    },
    ResolveExactConditionMarket {
        idempotency_key: String,
        signed: SignedExactConditionResolution,
        now_millis: i64,
    },
    ResolvePolymarketMarket {
        idempotency_key: String,
        signed: SignedPolymarketResolution,
        now_millis: i64,
    },
    MarkBootstrapSubmitted {
        idempotency_key: String,
        execution_id: uuid::Uuid,
        venue_order_id: String,
        now_millis: i64,
    },
    ConfirmBootstrapFill {
        idempotency_key: String,
        execution_id: uuid::Uuid,
        fill_price_micros: u64,
        evidence_hash: [u8; 32],
        now_millis: i64,
    },
    FailBootstrapExecution {
        idempotency_key: String,
        execution_id: uuid::Uuid,
        failure_code: String,
        evidence_hash: [u8; 32],
        now_millis: i64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "statement",
    rename_all = "SCREAMING_SNAKE_CASE"
)]
enum UnsignedResolutionEvidence {
    Pyth(ResolutionStatement),
    ExactCondition(ExactConditionResolutionStatement),
    Polymarket(PolymarketResolutionStatement),
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
enum PlainRequest {
    Operator {
        envelope: OperatorEnvelope,
    },
    User {
        command: UserCommand,
        now_millis: i64,
    },
    AggregateDepth {
        market_id: String,
        outcome: clob_service::private_core::Outcome,
        now_millis: i64,
        #[serde(with = "clob_service::private_core::decimal_u128")]
        minimum_level_quantity_micros: u128,
    },
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
enum PlainResponse {
    Provisioned,
    ProvisionStatus {
        state: &'static str,
    },
    PolymarketStatus {
        state: &'static str,
    },
    ChainSignerStatus {
        state: &'static str,
        verifier_public_key: Option<[u8; 32]>,
        bridge_approval_signers: Option<std::collections::BTreeMap<String, String>>,
        reward_claim_signers: Option<std::collections::BTreeMap<String, String>>,
    },
    AuditSignerStatus {
        state: &'static str,
    },
    KmsRecipientRequest {
        attestation_document: Vec<u8>,
        kms_key_id: String,
        kms_ciphertext_blob: Option<Vec<u8>>,
        operation: &'static str,
        key_encryption_algorithm: &'static str,
    },
    System {
        response: SystemResponse,
    },
    PoolWithdrawalSigned {
        transaction: PoolWithdrawalTransaction,
        response: Option<SystemResponse>,
    },
    BridgeApprovalSigned {
        approval: BridgeApprovalSignature,
    },
    MarketResolutionSigned {
        transaction: MarketResolutionTransaction,
    },
    ResolutionEvidenceSigned {
        evidence: SignedResolutionEvidence,
        verifier_public_key: [u8; 32],
    },
    AuditBatchSigned {
        transaction: SignedAuditSettlementTransaction,
    },
    PolymarketRedemptionSigned {
        transaction: SignedVenueRedemptionTransaction,
        expected_redemption_amount_atomic: String,
    },
    User {
        response: Box<CoreResponse>,
    },
    Depth {
        bids: Vec<(u64, String)>,
        asks: Vec<(u64, String)>,
    },
    Snapshot {
        snapshot: EncryptedSnapshot,
    },
    BootstrapPending {
        execution_id: uuid::Uuid,
    },
    BootstrapExecutionStatus {
        execution_id: uuid::Uuid,
        state: BootstrapExecutionState,
    },
    MarketStatus {
        market: Option<MarketConfig>,
    },
    ResolutionStatus {
        resolution: Option<clob_service::private_core::MarketResolution>,
    },
    ResolutionReadiness {
        readiness: clob_service::private_core::MarketSettlementReadiness,
    },
    TradingFreezeStatus {
        frozen: bool,
    },
    Error {
        code: String,
    },
}

struct EnclaveState {
    nsm_fd: i32,
    enclave_measurement_sha384: [u8; 48],
    transport_secret: StaticSecret,
    transport_public_key: [u8; 32],
    receipt_signer: Option<ReceiptSigner>,
    receipt_public_key: [u8; 32],
    operator_public_key: VerifyingKey,
    operator_nonces: ReplayCache<32>,
    transport_nonces: ReplayCache<44>,
    core: Option<PrivateTradingCore>,
    pending_provision: Option<PendingProvision>,
    pending_polymarket_provision: Option<PendingPolymarketProvision>,
    polymarket: Option<EnclavePolymarketClient>,
    pending_chain_signer_provision: Option<PendingChainSignerProvision>,
    chain_signer: Option<EnclaveChainSigner>,
    pending_audit_signer_provision: Option<PendingAuditSignerProvision>,
    audit_signer: Option<EnclaveAuditSigner>,
}

struct ReplayCache<const N: usize> {
    seen: HashSet<[u8; N]>,
    order: VecDeque<[u8; N]>,
    capacity: usize,
}

impl<const N: usize> ReplayCache<N> {
    fn new(capacity: usize) -> Self {
        Self {
            seen: HashSet::with_capacity(capacity.min(16_384)),
            order: VecDeque::with_capacity(capacity.min(16_384)),
            capacity,
        }
    }

    fn contains(&self, key: &[u8; N]) -> bool {
        self.seen.contains(key)
    }

    fn remember(&mut self, key: [u8; N]) -> bool {
        if self.capacity == 0 || self.seen.contains(&key) {
            return false;
        }
        while self.order.len() >= self.capacity {
            if let Some(evicted) = self.order.pop_front() {
                self.seen.remove(&evicted);
            } else {
                break;
            }
        }
        self.order.push_back(key);
        self.seen.insert(key)
    }
}

struct PendingProvision {
    recipient_private_key: PKey<Private>,
    oracle_public_key: [u8; 32],
    snapshot: Option<EncryptedSnapshot>,
    minimum_anchored_sequence: u64,
}

struct PendingPolymarketProvision {
    recipient_private_key: PKey<Private>,
    bundle_nonce: [u8; 12],
    bundle_ciphertext: Vec<u8>,
}

struct PendingChainSignerProvision {
    recipient_private_key: PKey<Private>,
    bundle_nonce: [u8; 12],
    bundle_ciphertext: Vec<u8>,
}

struct PendingAuditSignerProvision {
    recipient_private_key: PKey<Private>,
    bundle_nonce: [u8; 12],
    bundle_ciphertext: Vec<u8>,
}

impl Drop for EnclaveState {
    fn drop(&mut self) {
        nsm_exit(self.nsm_fd);
    }
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let operator_public_key = compile_time_operator_key()?;
    let nsm_fd = nsm_init();
    if nsm_fd < 0 {
        return Err("Nitro Secure Module is unavailable".into());
    }
    let measurement_sha384 = read_pcr0(nsm_fd)?;
    let transport_secret = StaticSecret::random();
    let transport_public_key = PublicKey::from(&transport_secret).to_bytes();
    let receipt_signer = ReceiptSigner::generate(measurement_sha384);
    let receipt_public_key = receipt_signer.verifying_key();
    let state = Arc::new(Mutex::new(EnclaveState {
        nsm_fd,
        enclave_measurement_sha384: measurement_sha384,
        transport_secret,
        transport_public_key,
        receipt_signer: Some(receipt_signer),
        receipt_public_key,
        operator_public_key,
        operator_nonces: ReplayCache::new(MAX_OPERATOR_REPLAY_ENTRIES),
        transport_nonces: ReplayCache::new(MAX_TRANSPORT_REPLAY_ENTRIES),
        core: None,
        pending_provision: None,
        pending_polymarket_provision: None,
        polymarket: None,
        pending_chain_signer_provision: None,
        chain_signer: None,
        pending_audit_signer_provision: None,
        audit_signer: None,
    }));

    let listener = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, PORT))?;
    loop {
        let (stream, _) = listener.accept().await?;
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let _ = serve_connection(stream, state).await;
        });
    }
}

async fn serve_connection(
    mut stream: VsockStream,
    state: Arc<Mutex<EnclaveState>>,
) -> io::Result<()> {
    let frame = read_frame(&mut stream).await?;
    let request: WireRequest = serde_cbor::from_slice(&frame)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let response = match request {
        WireRequest::Attestation { nonce } => create_attestation(&state, nonce).await,
        WireRequest::Encrypted {
            client_public_key,
            nonce,
            ciphertext,
        } => handle_encrypted(&state, client_public_key, nonce, ciphertext).await,
    };
    let encoded = serde_cbor::to_vec(&response)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    write_frame(&mut stream, &encoded).await
}

async fn create_attestation(state: &Arc<Mutex<EnclaveState>>, nonce: Vec<u8>) -> WireResponse {
    if nonce.len() < 16 || nonce.len() > 512 {
        return WireResponse::Error {
            code: "INVALID_NONCE",
        };
    }
    let state = state.lock().await;
    let mut binding = Vec::with_capacity(88);
    binding.extend_from_slice(b"layrs.enclave-key-binding.v1\0");
    binding.extend_from_slice(&state.transport_public_key);
    binding.extend_from_slice(&state.receipt_public_key);
    match nsm_process_request(
        state.nsm_fd,
        NsmRequest::Attestation {
            user_data: Some(binding.into()),
            nonce: Some(nonce.into()),
            public_key: Some(state.transport_public_key.to_vec().into()),
        },
    ) {
        NsmResponse::Attestation { document } => WireResponse::Attestation {
            document,
            transport_public_key: state.transport_public_key,
            receipt_public_key: state.receipt_public_key,
        },
        _ => WireResponse::Error {
            code: "ATTESTATION_FAILED",
        },
    }
}

async fn handle_encrypted(
    state: &Arc<Mutex<EnclaveState>>,
    client_public_key: [u8; 32],
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
) -> WireResponse {
    let mut state = state.lock().await;
    let mut replay_key = [0u8; 44];
    replay_key[..32].copy_from_slice(&client_public_key);
    replay_key[32..].copy_from_slice(&nonce);
    if state.transport_nonces.contains(&replay_key) {
        return WireResponse::Error {
            code: "REPLAY_REJECTED",
        };
    }
    let key = transport_key(&state.transport_secret, client_public_key);
    let cipher = Aes256Gcm::new_from_slice(&key).expect("AES-256 key size is fixed");
    let mut plaintext = match cipher.decrypt(
        Nonce::from_slice(&nonce),
        aes_gcm::aead::Payload {
            msg: &ciphertext,
            aad: request_aad(&client_public_key, &state.transport_public_key).as_slice(),
        },
    ) {
        Ok(value) => value,
        Err(_) => {
            return WireResponse::Error {
                code: "DECRYPTION_FAILED",
            }
        }
    };
    let request: PlainRequest = match serde_json::from_slice(&plaintext) {
        Ok(value) => value,
        Err(_) => {
            return WireResponse::Error {
                code: "INVALID_REQUEST",
            }
        }
    };
    plaintext.zeroize();
    if !state.transport_nonces.remember(replay_key) {
        return WireResponse::Error {
            code: "REPLAY_REJECTED",
        };
    }
    let response = dispatch(&mut state, request).await;
    // These sidecars contain only AEAD ciphertext and its integrity/chain metadata. They let the
    // untrusted parent persist state transitions without learning the encrypted response body.
    let journal_artifacts = match &response {
        PlainResponse::User { response } => vec![response.encrypted_record.clone()],
        PlainResponse::System { response } => vec![response.encrypted_record.clone()],
        PlainResponse::PoolWithdrawalSigned {
            response: Some(response),
            ..
        } => vec![response.encrypted_record.clone()],
        _ => Vec::new(),
    };
    let snapshot_artifacts = match &response {
        PlainResponse::Snapshot { snapshot } => vec![snapshot.clone()],
        _ if !journal_artifacts.is_empty() => match state
            .core
            .as_ref()
            .and_then(|core| core.export_encrypted_snapshot().ok())
        {
            Some(snapshot) => vec![snapshot],
            None => {
                return WireResponse::Error {
                    code: "SNAPSHOT_EXPORT_FAILED",
                }
            }
        },
        _ => Vec::new(),
    };
    let receipt_artifacts = match &response {
        PlainResponse::User { response } => vec![response.receipt.clone()],
        PlainResponse::System { response } => vec![response.receipt.clone()],
        PlainResponse::PoolWithdrawalSigned {
            response: Some(response),
            ..
        } => {
            vec![response.receipt.clone()]
        }
        _ => Vec::new(),
    };
    let audit_artifacts = match &response {
        PlainResponse::User { response } => response.audit_fills.clone(),
        PlainResponse::System { response } => response.audit_fills.clone(),
        PlainResponse::PoolWithdrawalSigned {
            response: Some(response),
            ..
        } => response.audit_fills.clone(),
        _ => Vec::new(),
    };
    let task_artifacts = match &response {
        PlainResponse::User { response } => response.task_qualifications.clone(),
        _ => Vec::new(),
    };
    let encoded = match serde_json::to_vec(&response) {
        Ok(value) => value,
        Err(_) => {
            return WireResponse::Error {
                code: "ENCODING_FAILED",
            }
        }
    };
    let mut response_nonce = [0u8; 12];
    OsRng.fill_bytes(&mut response_nonce);
    match cipher.encrypt(
        Nonce::from_slice(&response_nonce),
        aes_gcm::aead::Payload {
            msg: &encoded,
            aad: response_aad(&client_public_key, &state.transport_public_key).as_slice(),
        },
    ) {
        Ok(ciphertext) => WireResponse::Encrypted {
            nonce: response_nonce,
            ciphertext,
            journal_artifacts,
            snapshot_artifacts,
            receipt_artifacts,
            audit_artifacts,
            task_artifacts,
        },
        Err(_) => WireResponse::Error {
            code: "ENCRYPTION_FAILED",
        },
    }
}

fn serialize_depth(levels: Vec<(u64, u128)>) -> Vec<(u64, String)> {
    levels
        .into_iter()
        .map(|(price_micros, quantity_micros)| (price_micros, quantity_micros.to_string()))
        .collect()
}

async fn dispatch(state: &mut EnclaveState, request: PlainRequest) -> PlainResponse {
    let result: Result<PlainResponse, String> = match request {
        PlainRequest::Operator { envelope } => dispatch_operator(state, envelope).await,
        PlainRequest::User {
            command,
            now_millis,
        } => (|| -> Result<PlainResponse, String> {
            let core = state
                .core
                .as_ref()
                .ok_or_else(|| "NOT_PROVISIONED".to_string())?;
            ensure_market_execution_available(core, &command.action, state.polymarket.is_some())?;
            let mut response = state
                .core
                .as_mut()
                .ok_or_else(|| "NOT_PROVISIONED".to_string())
                .and_then(|core| {
                    core.execute(command, now_millis)
                        .map_err(|error| error.to_string())
                })?;
            if let CommandResult::RewardClaimAuthorized { intent } = &response.result {
                let signer = state
                    .chain_signer
                    .as_ref()
                    .ok_or_else(|| "CHAIN_SIGNER_NOT_PROVISIONED".to_string())?;
                response.reward_claim_authorization = Some(signer.sign_reward_claim(intent)?);
            }
            Ok(PlainResponse::User {
                response: Box::new(response),
            })
        })(),
        PlainRequest::AggregateDepth {
            market_id,
            outcome,
            now_millis,
            minimum_level_quantity_micros,
        } => state
            .core
            .as_ref()
            .ok_or_else(|| "NOT_PROVISIONED".into())
            .map(|core| {
                let (bids, asks) = core.aggregate_depth(
                    &market_id,
                    outcome,
                    now_millis,
                    minimum_level_quantity_micros,
                );
                PlainResponse::Depth {
                    bids: serialize_depth(bids),
                    asks: serialize_depth(asks),
                }
            }),
    };
    result.unwrap_or_else(|code| PlainResponse::Error { code })
}

fn is_polymarket_execution(execution: &MarketExecution) -> bool {
    matches!(execution, MarketExecution::PolymarketBootstrap { .. })
}

fn ensure_market_execution_available(
    core: &PrivateTradingCore,
    action: &UserCommandAction,
    polymarket_ready: bool,
) -> Result<(), String> {
    let UserCommandAction::SubmitOrder { order } = action else {
        return Ok(());
    };
    let market = core.market_config(&order.market_id);
    if !polymarket_ready
        && market
            .as_ref()
            .is_some_and(|config| is_polymarket_execution(&config.execution))
    {
        // Reject before PrivateTradingCore::execute reserves cash or claim
        // collateral. A missing external-venue bundle must never turn into
        // an indefinitely pending user hold.
        return Err("POLYMARKET_OPERATOR_UNAVAILABLE".to_string());
    }
    Ok(())
}

async fn dispatch_operator(
    state: &mut EnclaveState,
    envelope: OperatorEnvelope,
) -> Result<PlainResponse, String> {
    if state.operator_nonces.contains(&envelope.nonce) {
        return Err("OPERATOR_REPLAY_REJECTED".into());
    }
    let signature_bytes: [u8; 64] = envelope
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| "INVALID_OPERATOR_SIGNATURE".to_string())?;
    state
        .operator_public_key
        .verify(
            &operator_payload(envelope.nonce, &envelope.command)?,
            &Signature::from_bytes(&signature_bytes),
        )
        .map_err(|_| "INVALID_OPERATOR_SIGNATURE".to_string())?;
    if !state.operator_nonces.remember(envelope.nonce) {
        return Err("OPERATOR_REPLAY_REJECTED".into());
    }

    match envelope.command {
        OperatorCommand::ProvisionStatus => Ok(PlainResponse::ProvisionStatus {
            state: if state.core.is_some() {
                "READY"
            } else if state.pending_provision.is_some() {
                "PENDING"
            } else {
                "UNPROVISIONED"
            },
        }),
        OperatorCommand::BeginProvision {
            kms_key_id,
            kms_ciphertext_blob,
            oracle_public_key,
            snapshot,
            minimum_anchored_sequence,
        } => {
            if state.core.is_some() {
                return Err("ALREADY_PROVISIONED".into());
            }
            if kms_key_id.is_empty()
                || kms_key_id.len() > 2_048
                || !kms_key_id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b":/_-".contains(&byte))
                || kms_ciphertext_blob
                    .as_ref()
                    .is_some_and(|blob| blob.is_empty() || blob.len() > 65_536)
            {
                return Err("INVALID_KMS_CIPHERTEXT".into());
            }
            VerifyingKey::from_bytes(&oracle_public_key)
                .map_err(|_| "INVALID_ORACLE_PUBLIC_KEY".to_string())?;
            let (recipient_private_key, recipient_public_key) = generate_recipient_key()?;
            let mut binding = Vec::with_capacity(128);
            binding.extend_from_slice(b"layrs.kms-recipient.v1\0");
            binding.extend_from_slice(&Sha256::digest(kms_key_id.as_bytes()));
            binding.extend_from_slice(&Sha256::digest(
                kms_ciphertext_blob.as_deref().unwrap_or_default(),
            ));
            binding.extend_from_slice(&oracle_public_key);
            let attestation_document = match nsm_process_request(
                state.nsm_fd,
                NsmRequest::Attestation {
                    user_data: Some(binding.into()),
                    nonce: None,
                    public_key: Some(recipient_public_key.into()),
                },
            ) {
                NsmResponse::Attestation { document } => document,
                _ => return Err("KMS_RECIPIENT_ATTESTATION_FAILED".into()),
            };
            state.pending_provision = Some(PendingProvision {
                recipient_private_key,
                oracle_public_key,
                snapshot,
                minimum_anchored_sequence,
            });
            Ok(PlainResponse::KmsRecipientRequest {
                attestation_document,
                kms_key_id,
                operation: if kms_ciphertext_blob.is_some() {
                    "DECRYPT"
                } else {
                    "GENERATE_DATA_KEY"
                },
                kms_ciphertext_blob,
                key_encryption_algorithm: "RSAES_OAEP_SHA_256",
            })
        }
        OperatorCommand::CompleteProvision {
            ciphertext_for_recipient,
        } => {
            if state.core.is_some() {
                return Err("ALREADY_PROVISIONED".into());
            }
            if ciphertext_for_recipient.is_empty() || ciphertext_for_recipient.len() > 4_096 {
                return Err("INVALID_RECIPIENT_CIPHERTEXT".into());
            }
            let pending = state
                .pending_provision
                .take()
                .ok_or_else(|| "NO_PENDING_PROVISION".to_string())?;
            let mut plaintext =
                decrypt_recipient_key(pending.recipient_private_key, &ciphertext_for_recipient)?;
            let journal_key: [u8; 32] = match plaintext.as_slice().try_into() {
                Ok(key) => key,
                Err(_) => {
                    plaintext.zeroize();
                    return Err("INVALID_KMS_KEY_MATERIAL".into());
                }
            };
            plaintext.zeroize();
            let key = JournalKey::from_bytes(journal_key);
            let mut receipt_seed = key.derive(b"receipt-signing-key-v1");
            let signer = ReceiptSigner::from_seed(receipt_seed, state.enclave_measurement_sha384);
            receipt_seed.zeroize();
            state.receipt_public_key = signer.verifying_key();
            state.receipt_signer = None;
            state.core = Some(match pending.snapshot {
                Some(snapshot) => PrivateTradingCore::restore_encrypted_snapshot(
                    key,
                    signer,
                    &snapshot,
                    pending.minimum_anchored_sequence,
                )
                .map_err(|error| error.to_string())?,
                None => PrivateTradingCore::new_with_oracle(key, signer, pending.oracle_public_key)
                    .map_err(|error| error.to_string())?,
            });
            Ok(PlainResponse::Provisioned)
        }
        OperatorCommand::PolymarketStatus => Ok(PlainResponse::PolymarketStatus {
            state: if state.polymarket.is_some() {
                "READY"
            } else if state.pending_polymarket_provision.is_some() {
                "PENDING"
            } else {
                "UNPROVISIONED"
            },
        }),
        OperatorCommand::BeginPolymarketProvision {
            kms_key_id,
            kms_ciphertext_blob,
            bundle_nonce,
            bundle_ciphertext,
        } => {
            if state.polymarket.is_some() {
                return Err("POLYMARKET_ALREADY_PROVISIONED".into());
            }
            validate_kms_reference(&kms_key_id, Some(&kms_ciphertext_blob))?;
            if bundle_ciphertext.len() < 17 || bundle_ciphertext.len() > 65_536 {
                return Err("INVALID_POLYMARKET_BUNDLE_CIPHERTEXT".into());
            }
            let (recipient_private_key, recipient_public_key) = generate_recipient_key()?;
            let mut binding = Vec::with_capacity(128);
            binding.extend_from_slice(b"layrs.polymarket-kms-recipient.v1\0");
            binding.extend_from_slice(&Sha256::digest(kms_key_id.as_bytes()));
            binding.extend_from_slice(&Sha256::digest(&kms_ciphertext_blob));
            binding.extend_from_slice(&Sha256::digest(&bundle_ciphertext));
            binding.extend_from_slice(&bundle_nonce);
            let attestation_document = match nsm_process_request(
                state.nsm_fd,
                NsmRequest::Attestation {
                    user_data: Some(binding.into()),
                    nonce: None,
                    public_key: Some(recipient_public_key.into()),
                },
            ) {
                NsmResponse::Attestation { document } => document,
                _ => return Err("KMS_RECIPIENT_ATTESTATION_FAILED".into()),
            };
            state.pending_polymarket_provision = Some(PendingPolymarketProvision {
                recipient_private_key,
                bundle_nonce,
                bundle_ciphertext,
            });
            Ok(PlainResponse::KmsRecipientRequest {
                attestation_document,
                kms_key_id,
                kms_ciphertext_blob: Some(kms_ciphertext_blob),
                operation: "DECRYPT",
                key_encryption_algorithm: "RSAES_OAEP_SHA_256",
            })
        }
        OperatorCommand::CompletePolymarketProvision {
            ciphertext_for_recipient,
        } => {
            if state.polymarket.is_some() {
                return Err("POLYMARKET_ALREADY_PROVISIONED".into());
            }
            if ciphertext_for_recipient.is_empty() || ciphertext_for_recipient.len() > 4_096 {
                return Err("INVALID_RECIPIENT_CIPHERTEXT".into());
            }
            let pending = state
                .pending_polymarket_provision
                .take()
                .ok_or_else(|| "NO_PENDING_POLYMARKET_PROVISION".to_string())?;
            let mut wrapping_key =
                decrypt_recipient_key(pending.recipient_private_key, &ciphertext_for_recipient)?;
            if wrapping_key.len() != 32 {
                wrapping_key.zeroize();
                return Err("INVALID_KMS_KEY_MATERIAL".into());
            }
            let bundle_cipher = Aes256Gcm::new_from_slice(&wrapping_key)
                .map_err(|_| "INVALID_KMS_KEY_MATERIAL".to_string())?;
            let mut plaintext = match bundle_cipher.decrypt(
                Nonce::from_slice(&pending.bundle_nonce),
                aes_gcm::aead::Payload {
                    msg: &pending.bundle_ciphertext,
                    aad: b"layrs.polymarket-secret-bundle.v1",
                },
            ) {
                Ok(value) => value,
                Err(_) => {
                    wrapping_key.zeroize();
                    return Err("POLYMARKET_BUNDLE_DECRYPT_FAILED".into());
                }
            };
            wrapping_key.zeroize();
            let parsed = serde_json::from_slice::<PolymarketSecretBundle>(&plaintext);
            plaintext.zeroize();
            let bundle = parsed.map_err(|_| "INVALID_POLYMARKET_SECRET_BUNDLE".to_string())?;
            state.polymarket = Some(EnclavePolymarketClient::new(bundle)?);
            Ok(PlainResponse::PolymarketStatus { state: "READY" })
        }
        OperatorCommand::ChainSignerStatus => Ok(PlainResponse::ChainSignerStatus {
            state: if state.chain_signer.is_some() {
                "READY"
            } else if state.pending_chain_signer_provision.is_some() {
                "PENDING"
            } else {
                "UNPROVISIONED"
            },
            verifier_public_key: state
                .chain_signer
                .as_ref()
                .map(|signer| signer.resolution_verifying_key()),
            bridge_approval_signers: state
                .chain_signer
                .as_ref()
                .map(EnclaveChainSigner::bridge_approval_signers),
            reward_claim_signers: state
                .chain_signer
                .as_ref()
                .map(EnclaveChainSigner::reward_claim_signers),
        }),
        OperatorCommand::BeginChainSignerProvision {
            kms_key_id,
            kms_ciphertext_blob,
            bundle_nonce,
            bundle_ciphertext,
        } => {
            if state.chain_signer.is_some() {
                return Err("CHAIN_SIGNER_ALREADY_PROVISIONED".into());
            }
            validate_kms_reference(&kms_key_id, Some(&kms_ciphertext_blob))?;
            if bundle_ciphertext.len() < 17 || bundle_ciphertext.len() > 65_536 {
                return Err("INVALID_CHAIN_SIGNER_BUNDLE_CIPHERTEXT".into());
            }
            let (recipient_private_key, recipient_public_key) = generate_recipient_key()?;
            let mut binding = Vec::with_capacity(128);
            binding.extend_from_slice(b"layrs.chain-signer-kms-recipient.v1\0");
            binding.extend_from_slice(&Sha256::digest(kms_key_id.as_bytes()));
            binding.extend_from_slice(&Sha256::digest(&kms_ciphertext_blob));
            binding.extend_from_slice(&Sha256::digest(&bundle_ciphertext));
            binding.extend_from_slice(&bundle_nonce);
            let attestation_document = match nsm_process_request(
                state.nsm_fd,
                NsmRequest::Attestation {
                    user_data: Some(binding.into()),
                    nonce: None,
                    public_key: Some(recipient_public_key.into()),
                },
            ) {
                NsmResponse::Attestation { document } => document,
                _ => return Err("KMS_RECIPIENT_ATTESTATION_FAILED".into()),
            };
            state.pending_chain_signer_provision = Some(PendingChainSignerProvision {
                recipient_private_key,
                bundle_nonce,
                bundle_ciphertext,
            });
            Ok(PlainResponse::KmsRecipientRequest {
                attestation_document,
                kms_key_id,
                kms_ciphertext_blob: Some(kms_ciphertext_blob),
                operation: "DECRYPT",
                key_encryption_algorithm: "RSAES_OAEP_SHA_256",
            })
        }
        OperatorCommand::CompleteChainSignerProvision {
            ciphertext_for_recipient,
        } => {
            if state.chain_signer.is_some() {
                return Err("CHAIN_SIGNER_ALREADY_PROVISIONED".into());
            }
            if ciphertext_for_recipient.is_empty() || ciphertext_for_recipient.len() > 4_096 {
                return Err("INVALID_RECIPIENT_CIPHERTEXT".into());
            }
            let pending = state
                .pending_chain_signer_provision
                .take()
                .ok_or_else(|| "NO_PENDING_CHAIN_SIGNER_PROVISION".to_string())?;
            let mut wrapping_key =
                decrypt_recipient_key(pending.recipient_private_key, &ciphertext_for_recipient)?;
            if wrapping_key.len() != 32 {
                wrapping_key.zeroize();
                return Err("INVALID_KMS_KEY_MATERIAL".into());
            }
            let bundle_cipher = Aes256Gcm::new_from_slice(&wrapping_key)
                .map_err(|_| "INVALID_KMS_KEY_MATERIAL".to_string())?;
            let mut plaintext = match bundle_cipher.decrypt(
                Nonce::from_slice(&pending.bundle_nonce),
                aes_gcm::aead::Payload {
                    msg: &pending.bundle_ciphertext,
                    aad: b"layrs.chain-signer-secret-bundle.v1",
                },
            ) {
                Ok(value) => value,
                Err(_) => {
                    wrapping_key.zeroize();
                    return Err("CHAIN_SIGNER_BUNDLE_DECRYPT_FAILED".into());
                }
            };
            wrapping_key.zeroize();
            let parsed = serde_json::from_slice::<ChainSignerBundle>(&plaintext);
            plaintext.zeroize();
            state.chain_signer =
                Some(EnclaveChainSigner::new(parsed.map_err(|_| {
                    "INVALID_CHAIN_SIGNER_SECRET_BUNDLE".to_string()
                })?)?);
            Ok(PlainResponse::ChainSignerStatus {
                state: "READY",
                verifier_public_key: state
                    .chain_signer
                    .as_ref()
                    .map(|signer| signer.resolution_verifying_key()),
                bridge_approval_signers: state
                    .chain_signer
                    .as_ref()
                    .map(EnclaveChainSigner::bridge_approval_signers),
                reward_claim_signers: state
                    .chain_signer
                    .as_ref()
                    .map(EnclaveChainSigner::reward_claim_signers),
            })
        }
        OperatorCommand::SignPoolWithdrawal {
            idempotency_key,
            authorization,
            nonce,
            gas_limit,
            max_fee_per_gas_wei,
            max_priority_fee_per_gas_wei,
            now_millis,
        } => {
            verify_withdrawal_authorization(&authorization, state.receipt_public_key)?;
            let core = state
                .core
                .as_mut()
                .ok_or_else(|| "NOT_PROVISIONED".to_string())?;
            core.validate_withdrawal_intent(&authorization.intent)
                .map_err(|error| error.to_string())?;
            let signer = state
                .chain_signer
                .as_ref()
                .ok_or_else(|| "CHAIN_SIGNER_NOT_PROVISIONED".to_string())?;
            let transaction = signer
                .sign_pool_withdrawal(
                    &authorization.intent.chain,
                    &authorization.intent.asset,
                    &authorization.intent.destination,
                    &authorization.intent.amount_atomic,
                    nonce,
                    gas_limit,
                    &max_fee_per_gas_wei,
                    &max_priority_fee_per_gas_wei,
                )
                .await?;
            let raw = hex::decode(transaction.raw_transaction_hex.trim_start_matches("0x"))
                .map_err(|_| "INVALID_SIGNED_WITHDRAWAL_TRANSACTION".to_string())?;
            let commitment: [u8; 32] = Sha256::digest(raw).into();
            if let Some((prior_commitment, prior_raw)) =
                core.prepared_withdrawal(authorization.intent.withdrawal_id)
            {
                if prior_commitment != commitment || prior_raw != transaction.raw_transaction_hex {
                    return Err("WITHDRAWAL_TRANSACTION_CONFLICT".into());
                }
                return Ok(PlainResponse::PoolWithdrawalSigned {
                    transaction,
                    response: None,
                });
            }
            let response = core
                .record_prepared_withdrawal(
                    idempotency_key,
                    authorization.intent.withdrawal_id,
                    commitment,
                    transaction.raw_transaction_hex.clone(),
                    now_millis,
                )
                .map_err(|error| error.to_string())?;
            Ok(PlainResponse::PoolWithdrawalSigned {
                transaction,
                response: Some(response),
            })
        }
        OperatorCommand::SignBridgeApproval {
            request,
            now_millis,
        } => {
            let approval = state
                .chain_signer
                .as_ref()
                .ok_or_else(|| "CHAIN_SIGNER_NOT_PROVISIONED".to_string())?
                .sign_bridge_approval(&request, now_millis)?;
            Ok(PlainResponse::BridgeApprovalSigned { approval })
        }
        OperatorCommand::SignResolutionEvidence {
            evidence,
            now_millis,
        } => {
            let signer = state
                .chain_signer
                .as_ref()
                .ok_or_else(|| "CHAIN_SIGNER_NOT_PROVISIONED".to_string())?;
            let (market_id, outcome, signed) = match evidence {
                UnsignedResolutionEvidence::Pyth(statement) => {
                    let outcome = clob_service::private_core::derive_resolution_outcome(
                        statement.opening.median_price_e8,
                        statement.closing.median_price_e8,
                    );
                    let payload = resolution_signing_payload(&statement)
                        .map_err(|error| error.to_string())?;
                    let market_id = statement.market_id.clone();
                    let signed = SignedResolutionEvidence::Pyth(SignedResolution {
                        statement,
                        signature: signer.sign_resolution_payload(&payload),
                    });
                    (market_id, outcome, signed)
                }
                UnsignedResolutionEvidence::ExactCondition(statement) => {
                    let outcome = statement.outcome;
                    let payload = exact_condition_resolution_signing_payload(&statement)
                        .map_err(|error| error.to_string())?;
                    let market_id = statement.market_id.clone();
                    let signed =
                        SignedResolutionEvidence::ExactCondition(SignedExactConditionResolution {
                            statement,
                            signature: signer.sign_resolution_payload(&payload),
                        });
                    (market_id, outcome, signed)
                }
                UnsignedResolutionEvidence::Polymarket(statement) => {
                    let outcome = statement.outcome;
                    let payload = polymarket_resolution_signing_payload(&statement)
                        .map_err(|error| error.to_string())?;
                    let market_id = statement.market_id.clone();
                    let signed = SignedResolutionEvidence::Polymarket(SignedPolymarketResolution {
                        statement,
                        signature: signer.sign_resolution_payload(&payload),
                    });
                    (market_id, outcome, signed)
                }
            };
            state
                .core
                .as_ref()
                .ok_or_else(|| "NOT_PROVISIONED".to_string())?
                .validate_onchain_resolution_authorization(&market_id, outcome, &signed, now_millis)
                .map_err(|error| error.to_string())?;
            Ok(PlainResponse::ResolutionEvidenceSigned {
                evidence: signed,
                verifier_public_key: signer.resolution_verifying_key(),
            })
        }
        OperatorCommand::SignMarketResolution {
            chain,
            market_id,
            outcome,
            evidence,
            reason_uri,
            nonce,
            gas_limit,
            max_fee_per_gas_wei,
            max_priority_fee_per_gas_wei,
            now_millis,
        } => {
            state
                .core
                .as_ref()
                .ok_or_else(|| "NOT_PROVISIONED".to_string())?
                .validate_onchain_resolution_authorization(
                    &market_id, outcome, &evidence, now_millis,
                )
                .map_err(|error| error.to_string())?;
            let outcome_name = match outcome {
                clob_service::private_core::ResolutionOutcome::Up => "UP",
                clob_service::private_core::ResolutionOutcome::Down => "DOWN",
                clob_service::private_core::ResolutionOutcome::Push => "PUSH",
            };
            let transaction = state
                .chain_signer
                .as_ref()
                .ok_or_else(|| "CHAIN_SIGNER_NOT_PROVISIONED".to_string())?
                .sign_market_resolution(
                    &chain,
                    &market_id,
                    outcome_name,
                    &reason_uri,
                    nonce,
                    gas_limit,
                    &max_fee_per_gas_wei,
                    &max_priority_fee_per_gas_wei,
                )
                .await?;
            Ok(PlainResponse::MarketResolutionSigned { transaction })
        }
        OperatorCommand::AuditSignerStatus => Ok(PlainResponse::AuditSignerStatus {
            state: if state.audit_signer.is_some() {
                "READY"
            } else if state.pending_audit_signer_provision.is_some() {
                "PENDING"
            } else {
                "UNPROVISIONED"
            },
        }),
        OperatorCommand::BeginAuditSignerProvision {
            kms_key_id,
            kms_ciphertext_blob,
            bundle_nonce,
            bundle_ciphertext,
        } => {
            if state.audit_signer.is_some() {
                return Err("AUDIT_SIGNER_ALREADY_PROVISIONED".into());
            }
            validate_kms_reference(&kms_key_id, Some(&kms_ciphertext_blob))?;
            if bundle_ciphertext.len() < 17 || bundle_ciphertext.len() > 65_536 {
                return Err("INVALID_AUDIT_SIGNER_BUNDLE_CIPHERTEXT".into());
            }
            let (recipient_private_key, recipient_public_key) = generate_recipient_key()?;
            let mut binding = Vec::with_capacity(128);
            binding.extend_from_slice(b"layrs.audit-signer-kms-recipient.v1\0");
            binding.extend_from_slice(&Sha256::digest(kms_key_id.as_bytes()));
            binding.extend_from_slice(&Sha256::digest(&kms_ciphertext_blob));
            binding.extend_from_slice(&Sha256::digest(&bundle_ciphertext));
            binding.extend_from_slice(&bundle_nonce);
            let attestation_document = match nsm_process_request(
                state.nsm_fd,
                NsmRequest::Attestation {
                    user_data: Some(binding.into()),
                    nonce: None,
                    public_key: Some(recipient_public_key.into()),
                },
            ) {
                NsmResponse::Attestation { document } => document,
                _ => return Err("KMS_RECIPIENT_ATTESTATION_FAILED".into()),
            };
            state.pending_audit_signer_provision = Some(PendingAuditSignerProvision {
                recipient_private_key,
                bundle_nonce,
                bundle_ciphertext,
            });
            Ok(PlainResponse::KmsRecipientRequest {
                attestation_document,
                kms_key_id,
                kms_ciphertext_blob: Some(kms_ciphertext_blob),
                operation: "DECRYPT",
                key_encryption_algorithm: "RSAES_OAEP_SHA_256",
            })
        }
        OperatorCommand::CompleteAuditSignerProvision {
            ciphertext_for_recipient,
        } => {
            if state.audit_signer.is_some() {
                return Err("AUDIT_SIGNER_ALREADY_PROVISIONED".into());
            }
            if ciphertext_for_recipient.is_empty() || ciphertext_for_recipient.len() > 4_096 {
                return Err("INVALID_RECIPIENT_CIPHERTEXT".into());
            }
            let pending = state
                .pending_audit_signer_provision
                .take()
                .ok_or_else(|| "NO_PENDING_AUDIT_SIGNER_PROVISION".to_string())?;
            let mut wrapping_key =
                decrypt_recipient_key(pending.recipient_private_key, &ciphertext_for_recipient)?;
            if wrapping_key.len() != 32 {
                wrapping_key.zeroize();
                return Err("INVALID_KMS_KEY_MATERIAL".into());
            }
            let bundle_cipher = Aes256Gcm::new_from_slice(&wrapping_key)
                .map_err(|_| "INVALID_KMS_KEY_MATERIAL".to_string())?;
            let mut plaintext = match bundle_cipher.decrypt(
                Nonce::from_slice(&pending.bundle_nonce),
                aes_gcm::aead::Payload {
                    msg: &pending.bundle_ciphertext,
                    aad: b"layrs.audit-signer-secret-bundle.v1",
                },
            ) {
                Ok(value) => value,
                Err(_) => {
                    wrapping_key.zeroize();
                    return Err("AUDIT_SIGNER_BUNDLE_DECRYPT_FAILED".into());
                }
            };
            wrapping_key.zeroize();
            let parsed = serde_json::from_slice::<AuditSignerBundle>(&plaintext);
            plaintext.zeroize();
            state.audit_signer =
                Some(EnclaveAuditSigner::new(parsed.map_err(|_| {
                    "INVALID_AUDIT_SIGNER_SECRET_BUNDLE".to_string()
                })?)?);
            Ok(PlainResponse::AuditSignerStatus { state: "READY" })
        }
        OperatorCommand::SignAuditBatch { request } => {
            let signer = state
                .audit_signer
                .as_ref()
                .ok_or_else(|| "AUDIT_SIGNER_NOT_PROVISIONED".to_string())?;
            let transaction = signer
                .sign_batch_transaction(request, state.receipt_public_key)
                .await?;
            Ok(PlainResponse::AuditBatchSigned { transaction })
        }
        OperatorCommand::ExecuteBootstrap {
            idempotency_key,
            execution_id,
            timestamp_seconds,
            now_millis,
        } => {
            let client = state
                .polymarket
                .as_ref()
                .ok_or_else(|| "POLYMARKET_NOT_PROVISIONED".to_string())?;
            let intent = state
                .core
                .as_ref()
                .ok_or_else(|| "NOT_PROVISIONED".to_string())?
                .bootstrap_venue_intent(execution_id)
                .map_err(|error| error.to_string())?;
            let venue = VenueOrderIntent {
                token_id: intent.token_id,
                side: match intent.action {
                    clob_service::private_core::OrderAction::Buy => VenueSide::Buy,
                    clob_service::private_core::OrderAction::Sell => VenueSide::Sell,
                },
                quantity_atomic: intent.quantity_micros,
                limit_price_micros: intent.limit_price_micros,
                fee_rate_bps: 0,
                negative_risk: intent.negative_risk,
                order_salt: intent.order_salt,
            };
            let (submitted, _) = client.submit_fok(&venue, timestamp_seconds).await?;
            let response = state
                .core
                .as_mut()
                .expect("core was checked before venue I/O")
                .mark_bootstrap_submitted(
                    idempotency_key,
                    execution_id,
                    submitted.order_id,
                    now_millis,
                )
                .map_err(|error| error.to_string())?;
            Ok(PlainResponse::System { response })
        }
        OperatorCommand::BootstrapExecutionStatus {
            execution_id,
            identity_commitment,
        } => state
            .core
            .as_ref()
            .ok_or_else(|| "NOT_PROVISIONED".to_string())?
            .bootstrap_execution_state_for_identity(execution_id, identity_commitment)
            .map(|execution_state| PlainResponse::BootstrapExecutionStatus {
                execution_id,
                state: execution_state,
            })
            .map_err(|error| error.to_string()),
        OperatorCommand::MarketStatus { market_id } => Ok(PlainResponse::MarketStatus {
            market: state
                .core
                .as_ref()
                .ok_or_else(|| "NOT_PROVISIONED".to_string())?
                .market_config(&market_id),
        }),
        OperatorCommand::ResolutionStatus { market_id } => Ok(PlainResponse::ResolutionStatus {
            resolution: state
                .core
                .as_ref()
                .ok_or_else(|| "NOT_PROVISIONED".to_string())?
                .market_resolution(&market_id),
        }),
        OperatorCommand::ResolutionReadiness {
            market_id,
            now_millis,
        } => state
            .core
            .as_ref()
            .ok_or_else(|| "NOT_PROVISIONED".to_string())?
            .market_settlement_readiness(&market_id, now_millis)
            .map(|readiness| PlainResponse::ResolutionReadiness { readiness })
            .map_err(|error| error.to_string()),
        OperatorCommand::TradingFreezeStatus => Ok(PlainResponse::TradingFreezeStatus {
            frozen: state
                .core
                .as_ref()
                .ok_or_else(|| "NOT_PROVISIONED".to_string())?
                .trading_frozen(),
        }),
        OperatorCommand::AggregateDepth {
            market_id,
            outcome,
            now_millis,
            minimum_level_quantity_micros,
        } => {
            let (bids, asks) = state
                .core
                .as_ref()
                .ok_or_else(|| "NOT_PROVISIONED".to_string())?
                .aggregate_depth(
                    &market_id,
                    outcome,
                    now_millis,
                    minimum_level_quantity_micros,
                );
            Ok(PlainResponse::Depth {
                bids: serialize_depth(bids),
                asks: serialize_depth(asks),
            })
        }
        OperatorCommand::ReconcileBootstrap {
            idempotency_key,
            execution_id,
            timestamp_seconds,
            now_millis,
        } => {
            let core = state
                .core
                .as_ref()
                .ok_or_else(|| "NOT_PROVISIONED".to_string())?;
            let order_id = core
                .bootstrap_venue_order_id(execution_id)
                .map_err(|error| error.to_string())?;
            let view = core
                .bootstrap_execution_view(execution_id)
                .map_err(|error| error.to_string())?;
            let confirmation = state
                .polymarket
                .as_ref()
                .ok_or_else(|| "POLYMARKET_NOT_PROVISIONED".to_string())?
                .confirmed_fill(&order_id, view.quantity_micros, timestamp_seconds)
                .await?;
            match confirmation {
                VenueConfirmation::Pending => Ok(PlainResponse::BootstrapPending { execution_id }),
                VenueConfirmation::Confirmed {
                    fill_price_micros,
                    evidence_hash,
                } => {
                    let response = state
                        .core
                        .as_mut()
                        .expect("core was checked before venue I/O")
                        .confirm_bootstrap_fill(
                            idempotency_key,
                            execution_id,
                            fill_price_micros,
                            evidence_hash,
                            now_millis,
                        )
                        .map_err(|error| error.to_string())?;
                    Ok(PlainResponse::System { response })
                }
                VenueConfirmation::Rejected {
                    failure_code,
                    evidence_hash,
                } => {
                    let response = state
                        .core
                        .as_mut()
                        .expect("core was checked before venue I/O")
                        .fail_bootstrap_execution(
                            idempotency_key,
                            execution_id,
                            failure_code,
                            evidence_hash,
                            now_millis,
                        )
                        .map_err(|error| error.to_string())?;
                    Ok(PlainResponse::System { response })
                }
            }
        }
        OperatorCommand::SignPolymarketRedemption {
            market_id,
            outcome,
            nonce,
            gas_limit,
            gas_price_wei,
            now_millis,
        } => {
            let redemption = state
                .core
                .as_ref()
                .ok_or_else(|| "NOT_PROVISIONED".to_string())?
                .polymarket_redemption_intent(&market_id, outcome, now_millis)
                .map_err(|error| error.to_string())?;
            let transaction = state
                .polymarket
                .as_ref()
                .ok_or_else(|| "POLYMARKET_NOT_PROVISIONED".to_string())?
                .sign_redemption_transaction(&VenueRedemptionTransactionIntent {
                    condition_id: redemption.condition_id,
                    up_outcome_index: redemption.up_outcome_index,
                    down_outcome_index: redemption.down_outcome_index,
                    nonce,
                    gas_limit,
                    gas_price_wei,
                })
                .await?;
            Ok(PlainResponse::PolymarketRedemptionSigned {
                transaction,
                expected_redemption_amount_atomic: redemption
                    .expected_redemption_amount_atomic
                    .to_string(),
            })
        }
        command => {
            let core = state
                .core
                .as_mut()
                .ok_or_else(|| "NOT_PROVISIONED".to_string())?;
            let response = match command {
                OperatorCommand::SetTradingFreeze {
                    idempotency_key,
                    frozen,
                    reason_commitment,
                    now_millis,
                } => {
                    core.set_trading_freeze(idempotency_key, frozen, reason_commitment, now_millis)
                }
                OperatorCommand::RegisterMarket {
                    idempotency_key,
                    market,
                    now_millis,
                } => core.register_market(idempotency_key, market, now_millis),
                OperatorCommand::RegisterSession {
                    idempotency_key,
                    session_id,
                    identity_commitment,
                    public_key,
                    expires_at_millis,
                    now_millis,
                } => core.register_session(
                    idempotency_key,
                    session_id,
                    identity_commitment,
                    public_key,
                    expires_at_millis,
                    now_millis,
                ),
                OperatorCommand::ExternalFlow {
                    idempotency_key,
                    account,
                    amount,
                    direction,
                    evidence_hash,
                    now_millis,
                } => core.apply_external_flow(
                    idempotency_key,
                    account,
                    amount,
                    direction,
                    evidence_hash,
                    now_millis,
                ),
                OperatorCommand::CreditDeposit {
                    idempotency_key,
                    identity_commitment,
                    asset,
                    amount_atomic,
                    evidence_hash,
                    now_millis,
                } => core.apply_user_external_flow(
                    idempotency_key,
                    identity_commitment,
                    asset,
                    clob_service::private_core::AccountBucket::UserAvailable,
                    amount_atomic,
                    ExternalFlowDirection::Inflow,
                    evidence_hash,
                    now_millis,
                ),
                OperatorCommand::AccrueReward {
                    idempotency_key,
                    identity_commitment,
                    chain,
                    reward_token,
                    amount_atomic,
                    evidence_hash,
                    now_millis,
                } => core.accrue_private_reward(
                    idempotency_key,
                    identity_commitment,
                    chain,
                    reward_token,
                    amount_atomic,
                    evidence_hash,
                    now_millis,
                ),
                OperatorCommand::FinalizeWithdrawal {
                    idempotency_key,
                    identity_commitment,
                    asset,
                    amount_atomic,
                    evidence_hash,
                    now_millis,
                } => core.apply_user_external_flow(
                    idempotency_key,
                    identity_commitment,
                    asset,
                    clob_service::private_core::AccountBucket::UserWithdrawalHold,
                    amount_atomic,
                    ExternalFlowDirection::Outflow,
                    evidence_hash,
                    now_millis,
                ),
                OperatorCommand::ReleaseWithdrawal {
                    idempotency_key,
                    identity_commitment,
                    asset,
                    amount_atomic,
                    evidence_hash,
                    now_millis,
                } => core.release_user_withdrawal(
                    idempotency_key,
                    identity_commitment,
                    asset,
                    amount_atomic,
                    evidence_hash,
                    now_millis,
                ),
                OperatorCommand::ResolveMarket {
                    idempotency_key,
                    signed,
                    now_millis,
                } => core.resolve_market(idempotency_key, signed, now_millis),
                OperatorCommand::ResolveExactConditionMarket {
                    idempotency_key,
                    signed,
                    now_millis,
                } => core.resolve_exact_condition_market(idempotency_key, signed, now_millis),
                OperatorCommand::ResolvePolymarketMarket {
                    idempotency_key,
                    signed,
                    now_millis,
                } => core.resolve_polymarket_market(idempotency_key, signed, now_millis),
                OperatorCommand::MarkBootstrapSubmitted {
                    idempotency_key,
                    execution_id,
                    venue_order_id,
                    now_millis,
                } => core.mark_bootstrap_submitted(
                    idempotency_key,
                    execution_id,
                    venue_order_id,
                    now_millis,
                ),
                OperatorCommand::ConfirmBootstrapFill {
                    idempotency_key,
                    execution_id,
                    fill_price_micros,
                    evidence_hash,
                    now_millis,
                } => core.confirm_bootstrap_fill(
                    idempotency_key,
                    execution_id,
                    fill_price_micros,
                    evidence_hash,
                    now_millis,
                ),
                OperatorCommand::FailBootstrapExecution {
                    idempotency_key,
                    execution_id,
                    failure_code,
                    evidence_hash,
                    now_millis,
                } => core.fail_bootstrap_execution(
                    idempotency_key,
                    execution_id,
                    failure_code,
                    evidence_hash,
                    now_millis,
                ),
                OperatorCommand::ExportSnapshot => {
                    return core
                        .export_encrypted_snapshot()
                        .map(|snapshot| PlainResponse::Snapshot { snapshot })
                        .map_err(|error| error.to_string());
                }
                OperatorCommand::BeginProvision { .. }
                | OperatorCommand::CompleteProvision { .. }
                | OperatorCommand::ProvisionStatus
                | OperatorCommand::PolymarketStatus
                | OperatorCommand::BeginPolymarketProvision { .. }
                | OperatorCommand::CompletePolymarketProvision { .. }
                | OperatorCommand::SignPolymarketRedemption { .. }
                | OperatorCommand::ChainSignerStatus
                | OperatorCommand::BeginChainSignerProvision { .. }
                | OperatorCommand::CompleteChainSignerProvision { .. }
                | OperatorCommand::SignPoolWithdrawal { .. }
                | OperatorCommand::SignBridgeApproval { .. }
                | OperatorCommand::SignResolutionEvidence { .. }
                | OperatorCommand::SignMarketResolution { .. }
                | OperatorCommand::AuditSignerStatus
                | OperatorCommand::BeginAuditSignerProvision { .. }
                | OperatorCommand::CompleteAuditSignerProvision { .. }
                | OperatorCommand::SignAuditBatch { .. }
                | OperatorCommand::ExecuteBootstrap { .. }
                | OperatorCommand::BootstrapExecutionStatus { .. }
                | OperatorCommand::MarketStatus { .. }
                | OperatorCommand::ResolutionStatus { .. }
                | OperatorCommand::ResolutionReadiness { .. }
                | OperatorCommand::TradingFreezeStatus
                | OperatorCommand::AggregateDepth { .. }
                | OperatorCommand::ReconcileBootstrap { .. } => unreachable!(),
            }
            .map_err(|error| error.to_string())?;
            Ok(PlainResponse::System { response })
        }
    }
}

fn operator_payload(nonce: [u8; 32], command: &OperatorCommand) -> Result<Vec<u8>, String> {
    let encoded =
        serde_json::to_vec(command).map_err(|_| "INVALID_OPERATOR_COMMAND".to_string())?;
    let mut payload = Vec::with_capacity(encoded.len() + 64);
    payload.extend_from_slice(b"layrs.enclave-operator.v1\0");
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&(encoded.len() as u64).to_be_bytes());
    payload.extend_from_slice(&encoded);
    Ok(payload)
}

fn verify_withdrawal_authorization(
    authorization: &WithdrawalAuthorization,
    receipt_public_key: [u8; 32],
) -> Result<(), String> {
    let signature: [u8; 64] = authorization
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| "INVALID_WITHDRAWAL_AUTHORIZATION".to_string())?;
    let encoded = serde_json::to_vec(&authorization.intent)
        .map_err(|_| "INVALID_WITHDRAWAL_AUTHORIZATION".to_string())?;
    let mut payload = Vec::with_capacity(encoded.len() + 64);
    payload.extend_from_slice(b"layrs.withdrawal-authorization.v1\0");
    payload.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
    payload.extend_from_slice(&encoded);
    VerifyingKey::from_bytes(&receipt_public_key)
        .map_err(|_| "INVALID_WITHDRAWAL_AUTHORIZATION".to_string())?
        .verify(&payload, &Signature::from_bytes(&signature))
        .map_err(|_| "INVALID_WITHDRAWAL_AUTHORIZATION".to_string())
}

fn validate_kms_reference(kms_key_id: &str, ciphertext: Option<&[u8]>) -> Result<(), String> {
    if kms_key_id.is_empty()
        || kms_key_id.len() > 2_048
        || !kms_key_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b":/_-".contains(&byte))
        || ciphertext.is_some_and(|blob| blob.is_empty() || blob.len() > 65_536)
    {
        return Err("INVALID_KMS_CIPHERTEXT".into());
    }
    Ok(())
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
    match decrypt_kms_recipient_enveloped_data(&private_key, ciphertext_for_recipient) {
        Ok(plaintext) => Ok(plaintext),
        Err(_) => {
            let cms = CmsContentInfo::from_der(ciphertext_for_recipient)
                .map_err(|_| "KMS_RECIPIENT_DECRYPT_FAILED".to_string())?;
            cms.decrypt_without_cert_check(&private_key)
                .map_err(|_| "KMS_RECIPIENT_DECRYPT_FAILED".to_string())
        }
    }
}

const OID_PKCS7_ENVELOPED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x03];
const OID_PKCS7_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01];
const OID_RSAES_OAEP: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x07];
const OID_AES_256_CBC: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a];

fn decrypt_kms_recipient_enveloped_data(
    private_key: &PKey<Private>,
    ciphertext_for_recipient: &[u8],
) -> Result<Vec<u8>, String> {
    let parts = parse_kms_recipient_enveloped_data(ciphertext_for_recipient)?;
    let mut content_key = rsa_oaep_sha256_decrypt(private_key, &parts.encrypted_content_key)?;
    if content_key.len() != 32 || parts.iv.len() != 16 || parts.ciphertext.is_empty() {
        content_key.zeroize();
        return Err("KMS_RECIPIENT_DECRYPT_FAILED".into());
    }
    let plaintext = symm_decrypt(
        Cipher::aes_256_cbc(),
        &content_key,
        Some(&parts.iv),
        &parts.ciphertext,
    )
    .map_err(|_| "KMS_RECIPIENT_DECRYPT_FAILED".to_string());
    content_key.zeroize();
    plaintext
}

struct KmsRecipientParts {
    encrypted_content_key: Vec<u8>,
    iv: Vec<u8>,
    ciphertext: Vec<u8>,
}

fn parse_kms_recipient_enveloped_data(input: &[u8]) -> Result<KmsRecipientParts, String> {
    if input.is_empty() || input.len() > 65_536 {
        return Err("KMS_RECIPIENT_DECRYPT_FAILED".into());
    }
    let mut top = BerReader::new(input);
    let content_info = top.read_expected(0x30)?;
    if !top.is_empty() {
        return Err("KMS_RECIPIENT_DECRYPT_FAILED".into());
    }

    let mut content_info = BerReader::new(content_info.content);
    expect_oid(
        content_info.read_expected(0x06)?.content,
        OID_PKCS7_ENVELOPED_DATA,
    )?;
    let explicit_content = content_info.read_expected(0xa0)?;
    if !content_info.is_empty() {
        return Err("KMS_RECIPIENT_DECRYPT_FAILED".into());
    }

    let mut explicit_content = BerReader::new(explicit_content.content);
    let enveloped_data = explicit_content.read_expected(0x30)?;
    if !explicit_content.is_empty() {
        return Err("KMS_RECIPIENT_DECRYPT_FAILED".into());
    }

    let mut enveloped_data = BerReader::new(enveloped_data.content);
    expect_single_byte_integer(enveloped_data.read_expected(0x02)?.content, 2)?;
    if enveloped_data.peek_tag() == Some(0xa0) {
        let _ = enveloped_data.read()?;
    }

    let recipient_infos = enveloped_data.read_expected(0x31)?;
    let mut recipient_infos = BerReader::new(recipient_infos.content);
    let recipient_info = recipient_infos.read_expected(0x30)?;
    if !recipient_infos.is_empty() {
        return Err("KMS_RECIPIENT_DECRYPT_FAILED".into());
    }
    let mut recipient_info = BerReader::new(recipient_info.content);
    expect_single_byte_integer(recipient_info.read_expected(0x02)?.content, 2)?;
    let _recipient_identifier = recipient_info.read()?;
    let key_encryption_algorithm = recipient_info.read_expected(0x30)?;
    let mut key_encryption_algorithm = BerReader::new(key_encryption_algorithm.content);
    expect_oid(
        key_encryption_algorithm.read_expected(0x06)?.content,
        OID_RSAES_OAEP,
    )?;
    let encrypted_content_key = recipient_info.read_expected(0x04)?.content.to_vec();
    if encrypted_content_key.is_empty() || !recipient_info.is_empty() {
        return Err("KMS_RECIPIENT_DECRYPT_FAILED".into());
    }

    let encrypted_content_info = enveloped_data.read_expected(0x30)?;
    let mut encrypted_content_info = BerReader::new(encrypted_content_info.content);
    expect_oid(
        encrypted_content_info.read_expected(0x06)?.content,
        OID_PKCS7_DATA,
    )?;
    let content_encryption_algorithm = encrypted_content_info.read_expected(0x30)?;
    let mut content_encryption_algorithm = BerReader::new(content_encryption_algorithm.content);
    expect_oid(
        content_encryption_algorithm.read_expected(0x06)?.content,
        OID_AES_256_CBC,
    )?;
    let iv = content_encryption_algorithm
        .read_expected(0x04)?
        .content
        .to_vec();
    if iv.len() != 16 || !content_encryption_algorithm.is_empty() {
        return Err("KMS_RECIPIENT_DECRYPT_FAILED".into());
    }
    let encrypted_content = encrypted_content_info.read()?;
    let ciphertext = match encrypted_content.tag {
        0x80 => encrypted_content.content.to_vec(),
        0xa0 | 0x24 => collect_octet_string_fragments(encrypted_content.content)?,
        0x04 => encrypted_content.content.to_vec(),
        _ => return Err("KMS_RECIPIENT_DECRYPT_FAILED".into()),
    };
    if ciphertext.is_empty() || !encrypted_content_info.is_empty() {
        return Err("KMS_RECIPIENT_DECRYPT_FAILED".into());
    }
    Ok(KmsRecipientParts {
        encrypted_content_key,
        iv,
        ciphertext,
    })
}

fn rsa_oaep_sha256_decrypt(
    private_key: &PKey<Private>,
    ciphertext: &[u8],
) -> Result<Vec<u8>, String> {
    let mut context =
        PkeyCtx::new(private_key).map_err(|_| "KMS_RECIPIENT_DECRYPT_FAILED".to_string())?;
    context
        .decrypt_init()
        .map_err(|_| "KMS_RECIPIENT_DECRYPT_FAILED".to_string())?;
    context
        .set_rsa_padding(Padding::PKCS1_OAEP)
        .map_err(|_| "KMS_RECIPIENT_DECRYPT_FAILED".to_string())?;
    context
        .set_rsa_oaep_md(Md::sha256())
        .map_err(|_| "KMS_RECIPIENT_DECRYPT_FAILED".to_string())?;
    context
        .set_rsa_mgf1_md(Md::sha256())
        .map_err(|_| "KMS_RECIPIENT_DECRYPT_FAILED".to_string())?;
    let mut plaintext = Vec::new();
    context
        .decrypt_to_vec(ciphertext, &mut plaintext)
        .map_err(|_| "KMS_RECIPIENT_DECRYPT_FAILED".to_string())?;
    Ok(plaintext)
}

fn collect_octet_string_fragments(input: &[u8]) -> Result<Vec<u8>, String> {
    let mut reader = BerReader::new(input);
    let mut output = Vec::new();
    while !reader.is_empty() {
        let fragment = reader.read()?;
        match fragment.tag {
            0x04 | 0x80 => output.extend_from_slice(fragment.content),
            0x24 | 0xa0 => {
                output.extend_from_slice(&collect_octet_string_fragments(fragment.content)?)
            }
            _ => return Err("KMS_RECIPIENT_DECRYPT_FAILED".into()),
        }
    }
    if output.is_empty() {
        return Err("KMS_RECIPIENT_DECRYPT_FAILED".into());
    }
    Ok(output)
}

fn expect_oid(actual: &[u8], expected: &[u8]) -> Result<(), String> {
    if actual == expected {
        Ok(())
    } else {
        Err("KMS_RECIPIENT_DECRYPT_FAILED".into())
    }
}

fn expect_single_byte_integer(actual: &[u8], expected: u8) -> Result<(), String> {
    if actual == [expected] {
        Ok(())
    } else {
        Err("KMS_RECIPIENT_DECRYPT_FAILED".into())
    }
}

struct BerReader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> BerReader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn is_empty(&self) -> bool {
        self.offset == self.input.len()
    }

    fn peek_tag(&self) -> Option<u8> {
        self.input.get(self.offset).copied()
    }

    fn read_expected(&mut self, expected_tag: u8) -> Result<BerElement<'a>, String> {
        let element = self.read()?;
        if element.tag == expected_tag {
            Ok(element)
        } else {
            Err("KMS_RECIPIENT_DECRYPT_FAILED".into())
        }
    }

    fn read(&mut self) -> Result<BerElement<'a>, String> {
        let bounds = ber_element_bounds(self.input, self.offset)?;
        self.offset = bounds.total_end;
        Ok(BerElement {
            tag: bounds.tag,
            content: &self.input[bounds.content_start..bounds.content_end],
        })
    }
}

struct BerElement<'a> {
    tag: u8,
    content: &'a [u8],
}

struct BerBounds {
    tag: u8,
    content_start: usize,
    content_end: usize,
    total_end: usize,
}

fn ber_element_bounds(input: &[u8], offset: usize) -> Result<BerBounds, String> {
    let tag = *input
        .get(offset)
        .ok_or_else(|| "KMS_RECIPIENT_DECRYPT_FAILED".to_string())?;
    if tag & 0x1f == 0x1f {
        return Err("KMS_RECIPIENT_DECRYPT_FAILED".into());
    }
    let length_offset = offset
        .checked_add(1)
        .ok_or_else(|| "KMS_RECIPIENT_DECRYPT_FAILED".to_string())?;
    let first_length = *input
        .get(length_offset)
        .ok_or_else(|| "KMS_RECIPIENT_DECRYPT_FAILED".to_string())?;
    let content_start = length_offset
        .checked_add(1)
        .ok_or_else(|| "KMS_RECIPIENT_DECRYPT_FAILED".to_string())?;
    if first_length == 0x80 {
        if tag & 0x20 == 0 {
            return Err("KMS_RECIPIENT_DECRYPT_FAILED".into());
        }
        let content_end = find_indefinite_content_end(input, content_start)?;
        let total_end = content_end
            .checked_add(2)
            .ok_or_else(|| "KMS_RECIPIENT_DECRYPT_FAILED".to_string())?;
        return Ok(BerBounds {
            tag,
            content_start,
            content_end,
            total_end,
        });
    }
    let (length, content_start) = if first_length & 0x80 == 0 {
        (first_length as usize, content_start)
    } else {
        let length_bytes = (first_length & 0x7f) as usize;
        if length_bytes == 0 || length_bytes > 4 {
            return Err("KMS_RECIPIENT_DECRYPT_FAILED".into());
        }
        let start = content_start;
        let end = start
            .checked_add(length_bytes)
            .ok_or_else(|| "KMS_RECIPIENT_DECRYPT_FAILED".to_string())?;
        if end > input.len() {
            return Err("KMS_RECIPIENT_DECRYPT_FAILED".into());
        }
        let mut parsed = 0usize;
        for byte in &input[start..end] {
            parsed = parsed
                .checked_mul(256)
                .and_then(|value| value.checked_add(*byte as usize))
                .ok_or_else(|| "KMS_RECIPIENT_DECRYPT_FAILED".to_string())?;
        }
        (parsed, end)
    };
    let content_end = content_start
        .checked_add(length)
        .ok_or_else(|| "KMS_RECIPIENT_DECRYPT_FAILED".to_string())?;
    if content_end > input.len() {
        return Err("KMS_RECIPIENT_DECRYPT_FAILED".into());
    }
    Ok(BerBounds {
        tag,
        content_start,
        content_end,
        total_end: content_end,
    })
}

fn find_indefinite_content_end(input: &[u8], mut offset: usize) -> Result<usize, String> {
    loop {
        if offset.checked_add(2).is_some_and(|end| end <= input.len())
            && input[offset] == 0
            && input[offset + 1] == 0
        {
            return Ok(offset);
        }
        let bounds = ber_element_bounds(input, offset)?;
        if bounds.total_end <= offset {
            return Err("KMS_RECIPIENT_DECRYPT_FAILED".into());
        }
        offset = bounds.total_end;
    }
}

fn transport_key(secret: &StaticSecret, client_public_key: [u8; 32]) -> [u8; 32] {
    let shared = secret.diffie_hellman(&PublicKey::from(client_public_key));
    let mut hash = Sha256::new();
    hash.update(b"layrs.enclave-transport.v1\0");
    hash.update(shared.as_bytes());
    hash.finalize().into()
}

fn request_aad(client: &[u8; 32], enclave: &[u8; 32]) -> Vec<u8> {
    let mut aad = b"layrs.enclave-request.v1\0".to_vec();
    aad.extend_from_slice(client);
    aad.extend_from_slice(enclave);
    aad
}

fn response_aad(client: &[u8; 32], enclave: &[u8; 32]) -> Vec<u8> {
    let mut aad = b"layrs.enclave-response.v1\0".to_vec();
    aad.extend_from_slice(client);
    aad.extend_from_slice(enclave);
    aad
}

fn compile_time_operator_key() -> Result<VerifyingKey, Box<dyn std::error::Error>> {
    let encoded = option_env!("LAYRS_OPERATOR_PUBLIC_KEY_HEX")
        .ok_or("LAYRS_OPERATOR_PUBLIC_KEY_HEX must be set while building the EIF")?;
    let bytes = hex::decode(encoded)?;
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "operator public key must be 32 bytes")?;
    Ok(VerifyingKey::from_bytes(&key)?)
}

fn read_pcr0(nsm_fd: i32) -> Result<[u8; 48], Box<dyn std::error::Error>> {
    match nsm_process_request(nsm_fd, NsmRequest::DescribePCR { index: 0 }) {
        NsmResponse::DescribePCR { data, .. } => data
            .try_into()
            .map_err(|_| "PCR0 must be a SHA-384 measurement".into()),
        _ => Err("unable to read PCR0".into()),
    }
}

async fn read_frame(stream: &mut VsockStream) -> io::Result<Vec<u8>> {
    let length = stream.read_u32().await? as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid frame length",
        ));
    }
    let mut frame = vec![0u8; length];
    stream.read_exact(&mut frame).await?;
    Ok(frame)
}

async fn write_frame(stream: &mut VsockStream, value: &[u8]) -> io::Result<()> {
    if value.is_empty() || value.len() > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid frame length",
        ));
    }
    stream.write_u32(value.len() as u32).await?;
    stream.write_all(value).await?;
    stream.shutdown().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_cache_rejects_duplicate_keys() {
        let mut cache = ReplayCache::<4>::new(8);
        let key = [7u8; 4];

        assert!(!cache.contains(&key));
        assert!(cache.remember(key));
        assert!(cache.contains(&key));
        assert!(!cache.remember(key));
    }

    #[test]
    fn replay_cache_evicts_oldest_key_instead_of_bricking() {
        let mut cache = ReplayCache::<2>::new(2);
        let first = [1u8, 1];
        let second = [2u8, 2];
        let third = [3u8, 3];

        assert!(cache.remember(first));
        assert!(cache.remember(second));
        assert!(cache.remember(third));

        assert!(!cache.contains(&first));
        assert!(cache.contains(&second));
        assert!(cache.contains(&third));
        assert!(cache.remember(first));
    }

    #[test]
    fn replay_cache_zero_capacity_fails_closed() {
        let mut cache = ReplayCache::<2>::new(0);
        assert!(!cache.remember([1u8, 1]));
    }

    #[test]
    fn relay_frame_limit_supports_checkpoint_restore_payloads() {
        const { assert!(MAX_FRAME_BYTES >= 64 * 1024 * 1024) };
    }

    #[test]
    fn external_execution_readiness_gate_targets_only_polymarket_markets() {
        assert!(!is_polymarket_execution(&MarketExecution::NativeClob));
        assert!(is_polymarket_execution(
            &MarketExecution::PolymarketBootstrap {
                condition_id: "0xcondition".into(),
                up_token_id: "1".into(),
                down_token_id: "2".into(),
                up_outcome_index: 0,
                down_outcome_index: 1,
                neg_risk: false,
            }
        ));
    }

    #[test]
    fn unavailable_polymarket_rejects_before_creating_a_user_hold() {
        use clob_service::private_core::{
            BookOrder, JournalKey, OrderAction, Outcome, TimeInForce,
        };

        let mut core = PrivateTradingCore::new(
            JournalKey::from_bytes([81u8; 32]),
            ReceiptSigner::generate([82u8; 48]),
        );
        let market_id = "layrs:v4:SPORTS:readiness-gate:abababababababab";
        core.register_market(
            "sys:market:readiness-gate".into(),
            MarketConfig {
                market_id: market_id.into(),
                settlement_asset: "USDC".into(),
                settlement_decimals: 6,
                public_settlement_chain: Some("horizen".into()),
                opens_at_millis: 900,
                closes_at_millis: 2_000,
                minimum_quantity_micros: 1,
                maximum_quantity_micros: 10_000_000,
                minimum_order_notional_micros: 1_000_000,
                maximum_order_notional_micros: 10_000_000,
                maximum_user_position_micros: 10_000_000,
                maximum_pending_bootstrap_notional_micros: 100_000_000,
                tick_size_micros: 1_000,
                oracle_feed_id: 1,
                execution: MarketExecution::PolymarketBootstrap {
                    condition_id: format!("0x{}", "ab".repeat(32)),
                    up_token_id: "1".into(),
                    down_token_id: "2".into(),
                    up_outcome_index: 0,
                    down_outcome_index: 1,
                    neg_risk: false,
                },
            },
            800,
        )
        .expect("register market");
        let action = UserCommandAction::SubmitOrder {
            order: BookOrder::new(
                "private-user",
                market_id,
                Outcome::Up,
                OrderAction::Buy,
                500_000,
                2_000_000,
                TimeInForce::Fok,
                None,
            ),
        };
        let root_before = core.state_root();

        assert_eq!(
            ensure_market_execution_available(&core, &action, false),
            Err("POLYMARKET_OPERATOR_UNAVAILABLE".into())
        );
        assert_eq!(core.state_root(), root_before);
        assert!(ensure_market_execution_available(&core, &action, true).is_ok());
    }

    #[test]
    fn decrypts_kms_style_cms_enveloped_data() {
        let rsa = Rsa::generate(2048).expect("rsa key");
        let key_pair = PKey::from_rsa(rsa).expect("pkey");
        let content_key = [0x42u8; 32];
        let iv = [0x24u8; 16];
        let plaintext = b"layrs attested kms recipient plaintext";

        let encrypted_content_key = {
            let mut context = PkeyCtx::new(&key_pair).expect("pkey ctx");
            context.encrypt_init().expect("encrypt init");
            context
                .set_rsa_padding(Padding::PKCS1_OAEP)
                .expect("oaep padding");
            context.set_rsa_oaep_md(Md::sha256()).expect("oaep sha256");
            context.set_rsa_mgf1_md(Md::sha256()).expect("mgf1 sha256");
            let mut encrypted = Vec::new();
            context
                .encrypt_to_vec(&content_key, &mut encrypted)
                .expect("rsa oaep encrypt");
            encrypted
        };

        let ciphertext =
            openssl::symm::encrypt(Cipher::aes_256_cbc(), &content_key, Some(&iv), plaintext)
                .expect("aes encrypt");
        let cms = kms_style_cms_fixture(&encrypted_content_key, &iv, &ciphertext);

        let decrypted = decrypt_kms_recipient_enveloped_data(&key_pair, &cms).expect("decrypt cms");
        assert_eq!(decrypted, plaintext);
    }

    fn kms_style_cms_fixture(
        encrypted_content_key: &[u8],
        iv: &[u8],
        ciphertext: &[u8],
    ) -> Vec<u8> {
        sequence(vec![
            oid(OID_PKCS7_ENVELOPED_DATA),
            tlv(
                0xa0,
                sequence(vec![
                    integer(2),
                    set(vec![sequence(vec![
                        integer(2),
                        tlv(0x80, vec![0x01, 0x02, 0x03, 0x04]),
                        sequence(vec![oid(OID_RSAES_OAEP)]),
                        octet(encrypted_content_key),
                    ])]),
                    sequence(vec![
                        oid(OID_PKCS7_DATA),
                        sequence(vec![oid(OID_AES_256_CBC), octet(iv)]),
                        tlv(0x80, ciphertext.to_vec()),
                    ]),
                ]),
            ),
        ])
    }

    fn sequence(children: Vec<Vec<u8>>) -> Vec<u8> {
        tlv(0x30, concat(children))
    }

    fn set(children: Vec<Vec<u8>>) -> Vec<u8> {
        tlv(0x31, concat(children))
    }

    fn integer(value: u8) -> Vec<u8> {
        tlv(0x02, vec![value])
    }

    fn oid(value: &[u8]) -> Vec<u8> {
        tlv(0x06, value.to_vec())
    }

    fn octet(value: &[u8]) -> Vec<u8> {
        tlv(0x04, value.to_vec())
    }

    fn concat(children: Vec<Vec<u8>>) -> Vec<u8> {
        children.into_iter().flatten().collect()
    }

    fn tlv(tag: u8, content: Vec<u8>) -> Vec<u8> {
        let mut output = vec![tag];
        encode_length(content.len(), &mut output);
        output.extend_from_slice(&content);
        output
    }

    fn encode_length(length: usize, output: &mut Vec<u8>) {
        if length < 128 {
            output.push(length as u8);
            return;
        }
        let encoded = length.to_be_bytes();
        let first = encoded
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(encoded.len() - 1);
        let significant = &encoded[first..];
        output.push(0x80 | significant.len() as u8);
        output.extend_from_slice(significant);
    }
}
