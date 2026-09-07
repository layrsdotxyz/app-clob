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
    api::{AttestationDoc, Digest as NsmDigest, Request as NsmRequest, Response as NsmResponse},
    driver::{nsm_exit, nsm_init, nsm_process_request},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
#[cfg(not(feature = "standalone-enclave-runtime"))]
use clob_service::access_capability::AccessCapability;
use clob_service::audit_signer::{
    AuditBatchRequest, AuditSignerBundle, EnclaveAuditSigner, SignedAuditSettlementTransaction,
};
use clob_service::chain_signer::{
    BridgeApprovalRequest, BridgeApprovalSignature, ChainSignerBundle, EnclaveChainSigner,
    MarketResolutionTransaction, PoolWithdrawalTransaction,
};
use clob_service::polymarket_enclave::{
    EnclavePolymarketClient, PolymarketSecretBundle, PreparedPolymarketOrder,
    SignedVenueRedemptionTransaction, VenueConfirmation, VenueOrderIntent, VenueOrderObservation,
    VenueRedemptionTransactionIntent, VenueSide,
};
use clob_service::private_core::{
    binance_resolution_signing_payload, command_result_commitment,
    exact_condition_resolution_signing_payload, polymarket_resolution_signing_payload,
    resolution_signing_payload, AccountKey, BinanceResolutionStatement, BootstrapExecutionState,
    BootstrapPreparedVenueOrder, CommandReceiptState, CommandResult, CoreResponse,
    CustodyReconciliationSnapshot, EnclaveReceipt, EncryptedJournalRecord, EncryptedSnapshot,
    ExactConditionResolutionStatement, ExactTerminalSnapshotRestoreReport, ExternalFlowDirection,
    FeeProfileId, JournalKey, MarketConfig, MarketExecution, OrderStatus,
    PolymarketResolutionStatement, PrivateTradingCore, ReceiptSigner, RecoveryBridgeArtifact,
    ResolutionStatement, SignedAuditFillArtifact, SignedBinanceResolution,
    SignedExactConditionResolution, SignedPolymarketResolution, SignedResolution,
    SignedResolutionEvidence, SignedTaskQualificationArtifact, SystemResponse, UserCommand,
    UserCommandAction, WithdrawalAuthorization, EXACT_LIVE_976_RELEASE_COMMIT,
    INCIDENT_TERMINAL_CIPHERTEXT_SHA256_HEX, INCIDENT_TERMINAL_JOURNAL_HEAD_HEX,
    INCIDENT_TERMINAL_SEQUENCE, INCIDENT_TERMINAL_STATE_ROOT_HEX,
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
use uuid::Uuid;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

#[cfg(feature = "standalone-enclave-runtime")]
#[path = "../access_capability.rs"]
mod standalone_access_capability;
#[cfg(feature = "standalone-enclave-runtime")]
use standalone_access_capability::AccessCapability;

const PORT: u32 = 5_003;
// Must match or exceed the parent relay cap. Provisioning restores encrypted
// checkpoints over this vsock channel; JSON byte-array encoding expands a
// archived snapshots into materially larger operator commands. Keep this aligned
// with the bounded parent relay so a valid durable checkpoint is recoverable.
const MAX_FRAME_BYTES: usize = 256 * 1024 * 1024;
const MAX_TRANSPORT_REPLAY_ENTRIES: usize = 262_144;
const MAX_OPERATOR_REPLAY_ENTRIES: usize = 100_000;
const TRUSTED_TIME_ATTESTATION_DOMAIN: &[u8] = b"layrs.nsm-trusted-time.v1\0";
const MIN_PRIVATE_RESPONSE_BYTES: usize = 4 * 1024;
const MAX_PRIVATE_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

#[cfg(not(test))]
const RECOVERY_ENVIRONMENT: &str = env!(
    "LAYRS_RECOVERY_ENVIRONMENT",
    "LAYRS_RECOVERY_ENVIRONMENT must be embedded in every non-test enclave build"
);
#[cfg(test)]
const RECOVERY_ENVIRONMENT: &str = "test";

fn recovery_environment() -> &'static str {
    RECOVERY_ENVIRONMENT
}

const INCIDENT_RECOVERY_POLICY_BYTES: &[u8] =
    include_bytes!("../../enclave/recovery-policies/2026-08-25-seq161919.json");
const INCIDENT_RECOVERY_POLICY_SHA256_HEX: &str =
    "64f95c19acaf1cc760c28b598fcd7609101f756a706357ec8ec7b7c2d1cc3d95";
const INCIDENT_ID: &str = "layrs-seq161891-recovery-20260825";
const INCIDENT_SNAPSHOT_BUCKET: &str = "layrs-production-082223548516-us-east-1-immutable";
const INCIDENT_SNAPSHOT_KEY: &str = "enclave/snapshot/00000000000000161919-cb284d9b13bc8b17d20c75d44e4e3b68a1d29dec3a7a5b9fd80871f340ea8da9.json";
const INCIDENT_SNAPSHOT_VERSION_ID: &str = "nHXxPKfOHWlyZ1UzcYeBjFpXLzq2c1Bu";
const INCIDENT_SNAPSHOT_SIZE_BYTES: u64 = 39_930_295;
const INCIDENT_SNAPSHOT_BODY_SHA256_HEX: &str =
    "9283a32007d96c2ba670bf093191d8e619af22da888bea4ece559c659e68d290";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IncidentTerminalRecoveryPolicy {
    schema_version: String,
    incident_id: String,
    source_release_commit: String,
    restore_sequence: u64,
    rollback_floor: u64,
    state_root: String,
    journal_head: String,
    snapshot: IncidentPolicySnapshot,
    source_provenance: IncidentSourceProvenance,
    historical_journal_replay_required: bool,
    historical_fill_completeness_certified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IncidentPolicySnapshot {
    bucket: String,
    key: String,
    version_id: String,
    size_bytes: u64,
    body_sha256: String,
    ciphertext_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IncidentSourceProvenance {
    eif_sha384: String,
    pcr0: String,
    pcr1: String,
    pcr2: String,
    source_ami_id: String,
    copied_parent_ami_id: String,
    parent_binary_sha384: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IncidentSnapshotDescriptor {
    bucket: String,
    key: String,
    version_id: String,
    size_bytes: u64,
    body_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct IncidentTerminalCertificationReport {
    schema_version: String,
    incident_id: String,
    incident_policy_sha256: String,
    snapshot_bucket: String,
    snapshot_key: String,
    snapshot_version_id: String,
    snapshot_size_bytes: u64,
    snapshot_body_sha256: String,
    certifier_release_manifest_sha256: String,
    artifact_equal: bool,
    policy_equal: bool,
    source_release_equal: bool,
    certifier_pcr0_equal: bool,
    #[serde(flatten)]
    terminal_state: ExactTerminalSnapshotRestoreReport,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct IncidentTerminalCertificationEnvelope {
    certificate: IncidentTerminalCertificationReport,
    certificate_sha256: String,
    artifact_binding_sha256: String,
    attestation_document_sha256: String,
    attestation_document: Vec<u8>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
enum WireRequest {
    Attestation {
        nonce: Vec<u8>,
    },
    EncryptedUser {
        access_capability: Option<AccessCapability>,
        client_public_key: [u8; 32],
        nonce: [u8; 12],
        #[serde(with = "serde_bytes")]
        ciphertext: Vec<u8>,
        request_context: EncryptedRequestContext,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        writer_authorization: Option<DurableWriterAuthorization>,
    },
    EncryptedOperator {
        client_public_key: [u8; 32],
        nonce: [u8; 12],
        #[serde(with = "serde_bytes")]
        ciphertext: Vec<u8>,
        writer_authorization: Option<DurableWriterAuthorization>,
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
    expected_execution_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expected_withdrawal_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expected_transfer_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expected_command_commitment: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DurableWriterAuthorization {
    protocol_version: String,
    environment: String,
    epoch: u64,
    lease_id: Uuid,
    not_before_millis: i64,
    expires_at_millis: i64,
    actor_domain: String,
    command_idempotency_key: String,
    command_commitment_sha256: [u8; 32],
    request_context_sha256: [u8; 32],
    request_envelope_sha256: [u8; 32],
    signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
enum EncryptedOuterContext {
    User(EncryptedRequestContext),
    Operator,
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
    #[serde(rename = "COMPLETE_SET")]
    CompleteSet,
    #[serde(rename = "PORTFOLIO")]
    Portfolio,
    #[serde(rename = "REWARDS")]
    Rewards,
    #[serde(rename = "REQUEST_REWARD_CLAIM")]
    RequestRewardClaim,
    #[serde(rename = "BOOTSTRAP_STATUS")]
    BootstrapStatus,
    #[serde(rename = "CANCEL_BOOTSTRAP")]
    CancelBootstrap,
    #[serde(rename = "REQUEST_WITHDRAWAL")]
    RequestWithdrawal,
    #[serde(rename = "TRANSFER_FUNDS")]
    TransferFunds,
}

fn is_s08_semantic_action(action: ExpectedEncryptedAction) -> bool {
    matches!(
        action,
        ExpectedEncryptedAction::Submit
            | ExpectedEncryptedAction::Replace
            | ExpectedEncryptedAction::Cancel
            | ExpectedEncryptedAction::CancelAll
            | ExpectedEncryptedAction::ClosePosition
    )
}

#[derive(Debug, Clone, Serialize)]
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
        recovery_artifacts: Vec<RecoveryBridgeArtifact>,
        preparation_artifacts: Vec<DurableCommandPreparation>,
        rejection_artifacts: Vec<DurableCommandRejection>,
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
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
// The authenticated operator wire schema is release-bound. Boxing the durable
// successor fields would change that schema, so retain the representation and
// acknowledge the decode-only enum size here.
#[allow(clippy::large_enum_variant)]
enum OperatorCommand {
    RecoverWithdrawalAuthorization {
        withdrawal_id: uuid::Uuid,
        session_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        terminal_record: Option<EncryptedJournalRecord>,
        now_millis: i64,
    },
    PreparedCommandStatus {
        preparation_id: [u8; 32],
        enclave_sequence: u64,
        state_root: [u8; 32],
    },
    InspectPendingPreparation {
        idempotency_key: String,
    },
    AbortSupersededPreparation {
        idempotency_key: String,
        preparation_id: [u8; 32],
        pending_enclave_sequence: u64,
        pending_state_root: [u8; 32],
        live_enclave_sequence: u64,
        live_state_root: [u8; 32],
        live_journal_head: [u8; 32],
    },
    FinalizePreparedCommand {
        preparation: DurableCommandPreparation,
        snapshot: EncryptedSnapshot,
        /// Governed roll-forward authorization for an irrevocable manifest
        /// prepared by the immediately prior EIF generation. This field is
        /// inside the signed operator command and must equal the immutable
        /// preparation measurement byte-for-byte.
        authorized_preparation_measurement_sha384: Vec<u8>,
        target_enclave_measurement_sha384: Vec<u8>,
        snapshot_schema: String,
        transition_policy_sha256: [u8; 32],
    },
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
    BeginIncidentTerminalRestore {
        kms_key_id: String,
        kms_ciphertext_blob: Vec<u8>,
        snapshot_descriptor: IncidentSnapshotDescriptor,
        #[serde(with = "serde_bytes")]
        snapshot_body: Vec<u8>,
        external_challenge: [u8; 32],
        certifier_release_manifest_sha256: [u8; 32],
        #[serde(with = "serde_bytes")]
        expected_certifier_pcr0_sha384: Vec<u8>,
    },
    CompleteIncidentTerminalRestore {
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
    SubmitPreparedBootstrap {
        idempotency_key: String,
        execution_id: uuid::Uuid,
        timestamp_seconds: u64,
        now_millis: i64,
    },
    AuthorizeBootstrapSubmission {
        idempotency_key: String,
        execution_id: uuid::Uuid,
        now_millis: i64,
    },
    ObserveBootstrapSubmission {
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
    CustodyReconciliationSnapshot {
        checkpoint_commitment: [u8; 32],
        chain_finality_commitments: Vec<[u8; 32]>,
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
    AcknowledgeRecoveryArchive {
        idempotency_key: String,
        command_idempotency_key: String,
        result_digest: [u8; 32],
        archive_row_commitment: [u8; 32],
        environment: String,
        recovery_artifact: RecoveryBridgeArtifact,
        now_millis: i64,
    },
    RecoveryArchiveAckStatus {
        command_idempotency_key: String,
        result_digest: [u8; 32],
        archive_row_commitment: [u8; 32],
        environment: String,
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
    RegisterTransferAccount {
        idempotency_key: String,
        identity_commitment: [u8; 32],
        now_millis: i64,
    },
    TransferAccountStatus {
        identity_commitment: [u8; 32],
    },
    DelegatedPortfolioRead {
        request_id: uuid::Uuid,
        identity_commitment: [u8; 32],
        response_public_key: [u8; 32],
        projection: DelegatedReadProjection,
        api_key_id: uuid::Uuid,
        capability_jti: uuid::Uuid,
        capability_token_sha256: [u8; 32],
        capability_environment: String,
        capability_audience: String,
        capability_scope: String,
        issued_at_millis: i64,
        expires_at_millis: i64,
        revocation_checked_at_millis: i64,
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
    VaultStrategyTransition {
        idempotency_key: String,
        evidence_hash: [u8; 32],
        vault_commitment: [u8; 32],
        strategy_commitment: [u8; 32],
        operation_commitment: [u8; 32],
        asset: String,
        #[serde(with = "clob_service::private_core::decimal_u128")]
        amount_atomic: u128,
        transition: clob_service::private_core::VaultStrategyTransition,
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
        source_id_hash: [u8; 32],
        program_id: String,
        program_type: String,
        policy_id: String,
        policy_version: u32,
        fee_policy_version: String,
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
    ResolveBinanceMarket {
        idempotency_key: String,
        signed: SignedBinanceResolution,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum DelegatedReadProjection {
    Balances,
    Positions,
    ActiveOrders,
}

impl DelegatedReadProjection {
    fn required_scope(self) -> &'static str {
        match self {
            Self::Balances => "balances:read",
            Self::Positions => "positions:read",
            Self::ActiveOrders => "orders:read",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Balances => "BALANCES",
            Self::Positions => "POSITIONS",
            Self::ActiveOrders => "ACTIVE_ORDERS",
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DelegatedReadPlaintext<T> {
    protocol_version: &'static str,
    request_id: uuid::Uuid,
    projection: &'static str,
    enclave_sequence: String,
    as_of_millis: i64,
    items: T,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct EncryptedDelegatedRead {
    protocol_version: &'static str,
    request_id: uuid::Uuid,
    projection: &'static str,
    enclave_sequence: String,
    as_of_millis: i64,
    expires_at_millis: i64,
    ephemeral_public_key: [u8; 32],
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
    ciphertext_sha256: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "statement",
    rename_all = "SCREAMING_SNAKE_CASE"
)]
enum UnsignedResolutionEvidence {
    Pyth(ResolutionStatement),
    Binance(BinanceResolutionStatement),
    ExactCondition(ExactConditionResolutionStatement),
    Polymarket(PolymarketResolutionStatement),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
// Keep the authenticated wire schema byte-for-byte stable. Boxing the operator
// envelope would change the request representation for no runtime benefit in
// this short-lived decode path, so acknowledge the Rust 1.94 size lint here.
#[allow(clippy::large_enum_variant)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DurableCommandPreparation {
    protocol_version: String,
    environment: String,
    enclave_measurement_sha384: Vec<u8>,
    preparation_id: [u8; 32],
    actor_domain: String,
    command_binding_sha256: [u8; 32],
    command_commitment_sha256: [u8; 32],
    request_context_sha256: [u8; 32],
    request_envelope_sha256: [u8; 32],
    command_idempotency_key: String,
    writer_epoch: u64,
    writer_lease_id: Uuid,
    prior_enclave_sequence: u64,
    enclave_sequence: u64,
    prior_state_root: [u8; 32],
    prior_journal_head: [u8; 32],
    state_root: [u8; 32],
    journal_record_hash: [u8; 32],
    snapshot_ciphertext_hash: [u8; 32],
    response_envelope_sha256: [u8; 32],
    response_envelope_bytes: u64,
    response_status: u16,
    response_content_type: String,
    receipt_id: String,
    prepared_at_millis: i64,
    expires_at_millis: i64,
    signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DurableCommandRejection {
    protocol_version: String,
    environment: String,
    enclave_measurement_sha384: Vec<u8>,
    actor_domain: String,
    command_binding_sha256: [u8; 32],
    command_commitment_sha256: [u8; 32],
    request_context_sha256: [u8; 32],
    request_envelope_sha256: [u8; 32],
    command_idempotency_key: String,
    response_envelope_sha256: [u8; 32],
    response_envelope_bytes: u64,
    error_digest_sha256: [u8; 32],
    #[serde(skip_serializing_if = "Option::is_none")]
    command_receipt: Option<EnclaveReceipt>,
    occurred_at_millis: i64,
    signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SignedPendingPreparationInspection {
    protocol_version: String,
    environment: String,
    enclave_measurement_sha384: Vec<u8>,
    request_idempotency_key: String,
    preparation_id: Option<[u8; 32]>,
    pending_prior_enclave_sequence: Option<u64>,
    pending_enclave_sequence: Option<u64>,
    pending_prior_state_root: Option<[u8; 32]>,
    pending_state_root: Option<[u8; 32]>,
    live_enclave_sequence: u64,
    live_state_root: [u8; 32],
    live_journal_head: [u8; 32],
    observed_at_millis: i64,
    signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SignedPreparationSupersession {
    protocol_version: String,
    environment: String,
    enclave_measurement_sha384: Vec<u8>,
    request_idempotency_key: String,
    preparation_id: [u8; 32],
    pending_prior_enclave_sequence: u64,
    pending_enclave_sequence: u64,
    pending_prior_state_root: [u8; 32],
    pending_state_root: [u8; 32],
    live_enclave_sequence: u64,
    live_state_root: [u8; 32],
    live_journal_head: [u8; 32],
    superseded_at_millis: i64,
    signature: Vec<u8>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
enum PlainResponse {
    PreparedCommandStatus {
        state: &'static str,
    },
    PendingPreparationInspection {
        inspection: SignedPendingPreparationInspection,
    },
    PreparedCommandSuperseded {
        certificate: SignedPreparationSupersession,
    },
    PreparedCommandFinalized {
        preparation_id: [u8; 32],
        enclave_sequence: u64,
        state_root: [u8; 32],
    },
    Provisioned,
    IncidentTerminalRestoreCertified {
        envelope: IncidentTerminalCertificationEnvelope,
    },
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
    TransferAccountStatus {
        transfer_account: String,
        registered: bool,
    },
    DelegatedPortfolioRead {
        envelope: EncryptedDelegatedRead,
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
    CustodyReconciliationSnapshot {
        snapshot: CustodyReconciliationSnapshot,
    },
    TradingFreezeStatus {
        frozen: bool,
    },
    RecoveryArchiveAckStatus {
        acknowledged: bool,
    },
    Error {
        code: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        receipt: Option<EnclaveReceipt>,
        #[serde(skip_serializing_if = "Option::is_none")]
        receipt_state: Option<CommandReceiptState>,
        #[serde(skip_serializing_if = "Option::is_none")]
        receipt_disclosure_nonce: Option<[u8; 32]>,
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
    transport_nonces: TransportReplayCache,
    core: Option<PrivateTradingCore>,
    pending_preparation: Option<PendingPreparedTransition>,
    last_preparation_supersession: Option<SignedPreparationSupersession>,
    minimum_writer_epoch: u64,
    writer_lease_id: Option<Uuid>,
    pending_provision: Option<PendingProvision>,
    pending_incident_terminal_restore: Option<PendingIncidentTerminalRestore>,
    incident_restore_floor: Option<u64>,
    pending_polymarket_provision: Option<PendingPolymarketProvision>,
    polymarket: Option<EnclavePolymarketClient>,
    pending_chain_signer_provision: Option<PendingChainSignerProvision>,
    chain_signer: Option<EnclaveChainSigner>,
    pending_audit_signer_provision: Option<PendingAuditSignerProvision>,
    audit_signer: Option<EnclaveAuditSigner>,
}

struct PendingPreparedTransition {
    core: PrivateTradingCore,
    preparation: DurableCommandPreparation,
    replay_key: [u8; 44],
    response: PreparedResponseBundle,
    writer_epoch: u64,
    writer_lease_id: Uuid,
}

#[derive(Clone)]
struct PreparedResponseBundle {
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
    journal_artifacts: Vec<EncryptedJournalRecord>,
    snapshot_artifacts: Vec<EncryptedSnapshot>,
    receipt_artifacts: Vec<EnclaveReceipt>,
    audit_artifacts: Vec<SignedAuditFillArtifact>,
    task_artifacts: Vec<SignedTaskQualificationArtifact>,
    recovery_artifacts: Vec<RecoveryBridgeArtifact>,
    preparation_artifacts: Vec<DurableCommandPreparation>,
    rejection_artifacts: Vec<DurableCommandRejection>,
}

impl PreparedResponseBundle {
    fn wire_response(&self) -> WireResponse {
        WireResponse::Encrypted {
            nonce: self.nonce,
            ciphertext: self.ciphertext.clone(),
            journal_artifacts: self.journal_artifacts.clone(),
            snapshot_artifacts: self.snapshot_artifacts.clone(),
            receipt_artifacts: self.receipt_artifacts.clone(),
            audit_artifacts: self.audit_artifacts.clone(),
            task_artifacts: self.task_artifacts.clone(),
            recovery_artifacts: self.recovery_artifacts.clone(),
            preparation_artifacts: self.preparation_artifacts.clone(),
            rejection_artifacts: self.rejection_artifacts.clone(),
        }
    }
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

    fn forget(&mut self, key: &[u8; N]) {
        self.seen.remove(key);
        self.order.retain(|candidate| candidate != key);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransportReplayDecision {
    New,
    ExactRetry,
    Conflict,
}

struct TransportReplayCache {
    seen: std::collections::HashMap<[u8; 44], [u8; 32]>,
    order: VecDeque<[u8; 44]>,
    capacity: usize,
}

impl TransportReplayCache {
    fn new(capacity: usize) -> Self {
        Self {
            seen: std::collections::HashMap::new(),
            order: VecDeque::new(),
            capacity,
        }
    }

    fn check_or_remember(&mut self, key: [u8; 44], ciphertext: &[u8]) -> TransportReplayDecision {
        let digest: [u8; 32] = Sha256::digest(ciphertext).into();
        if let Some(prior) = self.seen.get(&key) {
            return if prior == &digest {
                TransportReplayDecision::ExactRetry
            } else {
                TransportReplayDecision::Conflict
            };
        }
        if self.capacity == 0 {
            return TransportReplayDecision::Conflict;
        }
        while self.order.len() >= self.capacity {
            if let Some(evicted) = self.order.pop_front() {
                self.seen.remove(&evicted);
            }
        }
        self.order.push_back(key);
        self.seen.insert(key, digest);
        TransportReplayDecision::New
    }

    fn forget(&mut self, key: &[u8; 44]) {
        self.seen.remove(key);
        self.order.retain(|candidate| candidate != key);
    }
}

struct PendingProvision {
    recipient_private_key: PKey<Private>,
    oracle_public_key: [u8; 32],
    snapshot: Option<EncryptedSnapshot>,
    minimum_anchored_sequence: u64,
}

struct PendingIncidentTerminalRestore {
    recipient_private_key: PKey<Private>,
    snapshot: EncryptedSnapshot,
    snapshot_descriptor: IncidentSnapshotDescriptor,
    policy_sha256: [u8; 32],
    snapshot_body_sha256: [u8; 32],
    external_challenge: [u8; 32],
    certifier_release_manifest_sha256: [u8; 32],
    expected_certifier_pcr0_sha384: [u8; 48],
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
        transport_nonces: TransportReplayCache::new(MAX_TRANSPORT_REPLAY_ENTRIES),
        core: None,
        pending_preparation: None,
        last_preparation_supersession: None,
        minimum_writer_epoch: 0,
        writer_lease_id: None,
        pending_provision: None,
        pending_incident_terminal_restore: None,
        incident_restore_floor: None,
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
        WireRequest::EncryptedUser {
            access_capability,
            client_public_key,
            nonce,
            ciphertext,
            request_context,
            writer_authorization,
        } => {
            handle_encrypted(
                &state,
                access_capability,
                client_public_key,
                nonce,
                ciphertext,
                EncryptedOuterContext::User(request_context),
                writer_authorization,
            )
            .await
        }
        WireRequest::EncryptedOperator {
            client_public_key,
            nonce,
            ciphertext,
            writer_authorization,
        } => {
            handle_encrypted(
                &state,
                None,
                client_public_key,
                nonce,
                ciphertext,
                EncryptedOuterContext::Operator,
                writer_authorization,
            )
            .await
        }
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
    access_capability: Option<AccessCapability>,
    client_public_key: [u8; 32],
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
    request_context: EncryptedOuterContext,
    writer_authorization: Option<DurableWriterAuthorization>,
) -> WireResponse {
    let mut state = state.lock().await;
    let mut rollback_core: Option<PrivateTradingCore> = None;
    let mut rollback_operator_nonce: Option<[u8; 32]> = None;
    let mut exact_recovery = false;
    let mut replay_key = [0u8; 44];
    replay_key[..32].copy_from_slice(&client_public_key);
    replay_key[32..].copy_from_slice(&nonce);
    let transport_replay = state
        .transport_nonces
        .check_or_remember(replay_key, &ciphertext);
    if transport_replay == TransportReplayDecision::Conflict {
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
            aad: request_aad(
                &client_public_key,
                &state.transport_public_key,
                access_capability,
            )
            .as_slice(),
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
    let command_binding_sha256: [u8; 32] = match serde_json::to_vec(&request) {
        Ok(value) => Sha256::digest(value).into(),
        Err(_) => {
            return WireResponse::Error {
                code: "INVALID_REQUEST",
            }
        }
    };
    let request_context_sha256 = match request_context_hash(&request_context) {
        Ok(value) => value,
        Err(()) => {
            return WireResponse::Error {
                code: "INVALID_REQUEST",
            }
        }
    };
    let request_envelope_sha256 = request_envelope_hash(client_public_key, nonce, &ciphertext);
    let (actor_domain, command_idempotency_key) = command_durable_binding(&request);
    let user_rejection_command = match (&request, &request_context) {
        (PlainRequest::User { command, .. }, EncryptedOuterContext::User(context)) => Some((
            command.command_id.clone(),
            command.idempotency_key.clone(),
            is_s08_semantic_action(context.expected_action),
        )),
        _ => None,
    };
    let durable_command_commitment = match &request_context {
        EncryptedOuterContext::User(context) => context
            .expected_command_commitment
            .as_deref()
            .and_then(|value| value.strip_prefix("0x"))
            .and_then(|value| hex::decode(value).ok())
            .and_then(|value| value.try_into().ok())
            .unwrap_or(command_binding_sha256),
        EncryptedOuterContext::Operator => match &request {
            PlainRequest::Operator { envelope } => operator_command_hash(&envelope.command),
            _ => command_binding_sha256,
        },
    };
    let requires_recovery_artifact = matches!(
        &request,
        PlainRequest::User { command, .. }
            if matches!(command.action, UserCommandAction::SubmitOrder { .. })
    );
    plaintext.zeroize();
    if access_capability.is_some_and(|claimed| expected_access_capability(&request) != claimed) {
        return WireResponse::Error {
            code: "ACCESS_CAPABILITY_MISMATCH",
        };
    }
    // Consume a successfully decrypted transport nonce even when the outer API
    // context is wrong. This prevents the generic mismatch response becoming
    // an oracle that can be probed repeatedly against one private command.
    if validate_request_context(&request, &request_context).is_err() {
        return WireResponse::Error {
            code: "PRIVATE_COMMAND_CONTEXT_MISMATCH",
        };
    }
    let direct_execution = direct_execution_request(&state, &request);
    let writer_trusted_now_millis = if request_requires_writer_authorization(&request)
        && !direct_execution
    {
        let Some(authorization) = writer_authorization.as_ref() else {
            return WireResponse::Error {
                code: "DURABLE_WRITER_AUTHORIZATION_REQUIRED",
            };
        };
        let now = match trusted_nsm_now_millis(state.nsm_fd, &state.enclave_measurement_sha384) {
            Ok(value) => value,
            Err(()) => {
                return WireResponse::Error {
                    code: "TRUSTED_TIME_UNAVAILABLE",
                }
            }
        };
        if let Err(code) = verify_writer_authorization(
            &mut state,
            authorization,
            &actor_domain,
            &command_idempotency_key,
            durable_command_commitment,
            request_context_sha256,
            request_envelope_sha256,
            now,
        ) {
            return WireResponse::Error { code };
        }
        Some(now)
    } else if direct_execution {
        match trusted_nsm_now_millis(state.nsm_fd, &state.enclave_measurement_sha384) {
            Ok(value) => Some(value),
            Err(()) => {
                return WireResponse::Error {
                    code: "TRUSTED_TIME_UNAVAILABLE",
                }
            }
        }
    } else {
        None
    };
    if transport_replay == TransportReplayDecision::ExactRetry
        && state
            .pending_preparation
            .as_ref()
            .is_some_and(|pending| pending.replay_key == replay_key)
    {
        if let Some(authorization) = writer_authorization.as_ref() {
            let needs_rebind = state.pending_preparation.as_ref().is_some_and(|pending| {
                authorization.epoch > pending.writer_epoch
                    || authorization.epoch == pending.writer_epoch
                        && authorization.lease_id != pending.writer_lease_id
            });
            if needs_rebind {
                let Some(rebound_at_millis) = writer_trusted_now_millis else {
                    return WireResponse::Error {
                        code: "TRUSTED_TIME_UNAVAILABLE",
                    };
                };
                let rebound_expires_at_millis = rebound_at_millis
                    .saturating_add(30_000)
                    .min(authorization.expires_at_millis);
                if rebound_expires_at_millis <= rebound_at_millis {
                    return WireResponse::Error {
                        code: "DURABLE_WRITER_AUTHORIZATION_INVALID",
                    };
                }
                let Some(signer) = state.receipt_signer.clone() else {
                    return WireResponse::Error {
                        code: "RECEIPT_SIGNER_UNAVAILABLE",
                    };
                };
                let pending = state
                    .pending_preparation
                    .as_mut()
                    .expect("pending preparation was checked");
                rebind_durable_preparation(
                    &mut pending.preparation,
                    authorization,
                    rebound_at_millis,
                    rebound_expires_at_millis,
                    &signer,
                );
                pending.response.preparation_artifacts = vec![pending.preparation.clone()];
                pending.writer_epoch = authorization.epoch;
                pending.writer_lease_id = authorization.lease_id;
            }
            if authorization.epoch >= state.minimum_writer_epoch {
                state.minimum_writer_epoch = authorization.epoch;
                state.writer_lease_id = Some(authorization.lease_id);
            }
        }
        return state
            .pending_preparation
            .as_ref()
            .expect("pending preparation was checked")
            .response
            .wire_response();
    }
    if state.pending_preparation.is_some()
        && !durable_control_request(&request)
        && !direct_execution
    {
        return WireResponse::Error {
            code: "DURABLE_PREPARATION_IN_PROGRESS",
        };
    }
    if let Some(authorization) = writer_authorization.as_ref() {
        if authorization.epoch > state.minimum_writer_epoch {
            state.minimum_writer_epoch = authorization.epoch;
            state.writer_lease_id = Some(authorization.lease_id);
        }
    }
    // Exact committed position-close retries are recovered before consulting the
    // clock. This preserves idempotent lost-response recovery during a temporary
    // NSM failure. A different command sharing the key fails inside ciphertext.
    let recovered = match &request {
        PlainRequest::User { command, .. } => state
            .core
            .as_ref()
            .map(|core| core.recover_exact_user_command(command))
            .transpose(),
        _ => Ok(None),
    };
    let mut response = match recovered {
        Ok(Some(Some(mut response))) => {
            // The original encrypted journal record was already committed. Do
            // not emit it as a new persistence sidecar on a response recovery.
            response.encrypted_record = None;
            exact_recovery = true;
            PlainResponse::User {
                response: Box::new(response),
            }
        }
        Ok(_) if transport_replay == TransportReplayDecision::ExactRetry => {
            return WireResponse::Error {
                code: "REPLAY_REJECTED",
            };
        }
        Ok(_) => {
            // User-provided wall time is never an authorization input. A fresh
            // timestamp is obtained directly from the Nitro Secure Module for
            // every new encrypted user command. The parent cannot delay, rewrite,
            // replay, or forge this in-enclave NSM exchange.
            let verified_now_millis = if matches!(
                request,
                PlainRequest::User { .. } | PlainRequest::Operator { .. }
            ) {
                match writer_trusted_now_millis.or_else(|| {
                    trusted_nsm_now_millis(state.nsm_fd, &state.enclave_measurement_sha384).ok()
                }) {
                    Some(value) => Some(value),
                    None => {
                        return WireResponse::Error {
                            code: "TRUSTED_TIME_UNAVAILABLE",
                        }
                    }
                }
            } else {
                None
            };
            // Execute a new private command against an isolated candidate.
            // Until the padded response, recovery proof, and encrypted
            // snapshot are all constructible, the live core remains
            // rollbackable to this exact pre-command clone.
            if matches!(
                request,
                PlainRequest::User { .. } | PlainRequest::Operator { .. }
            ) {
                rollback_core = state.core.clone();
            }
            if let PlainRequest::Operator { envelope } = &request {
                rollback_operator_nonce = Some(envelope.nonce);
            }
            dispatch(&mut state, request, verified_now_millis).await
        }
        Err(error) => PlainResponse::Error {
            code: error.to_string(),
            receipt: None,
            receipt_state: None,
            receipt_disclosure_nonce: None,
        },
    };
    // A user dispatch may fail after the core tentatively committed (for
    // example, reward-claim signing after execute). No error response may leave
    // that mutation live without its encrypted journal/snapshot sidecars.
    if matches!(response, PlainResponse::Error { .. }) {
        if let Some(core) = rollback_core.take() {
            state.core = Some(core);
            state.transport_nonces.forget(&replay_key);
            if let Some(nonce) = rollback_operator_nonce.take() {
                state.operator_nonces.forget(&nonce);
            }
        }
    }
    // A verified user command which fails before a journal transition still
    // receives a signed, result-bound v3 receipt. The unchanged root and
    // `journal_committed=false` make the terminal rejection distinguishable
    // from a journaled FOK/validation outcome while preserving privacy.
    if let (
        Some((command_id, idempotency_key, semantic_receipt)),
        PlainResponse::Error {
            code,
            receipt,
            receipt_state,
            receipt_disclosure_nonce,
        },
    ) = (&user_rejection_command, &mut response)
    {
        if let (Some(core), Some(signer), Some(now_millis)) = (
            state.core.as_ref(),
            state.receipt_signer.as_ref(),
            writer_trusted_now_millis,
        ) {
            let root = core.state_root();
            let error_digest: [u8; 32] = Sha256::digest(code.as_bytes()).into();
            let disclosure_nonce =
                signer.result_disclosure_nonce(durable_command_commitment, core.sequence(), root);
            let semantic = serde_json::json!({ "code": code, "type": "ERROR" });
            let result_commitment = if *semantic_receipt {
                let Ok(commitment) = command_result_commitment(
                    CommandReceiptState::Rejected,
                    disclosure_nonce,
                    &semantic,
                ) else {
                    return WireResponse::Error {
                        code: "RECEIPT_RESULT_COMMITMENT_FAILED",
                    };
                };
                Some(commitment)
            } else {
                None
            };
            let mut evidence = Sha256::new();
            evidence.update(b"layrs.rejected-command-evidence.v1\0");
            evidence.update(command_binding_sha256);
            evidence.update(durable_command_commitment);
            evidence.update(error_digest);
            evidence.update(root);
            *receipt = Some(signer.sign(
                command_id.clone(),
                idempotency_key.clone(),
                Some(durable_command_commitment),
                Some(false),
                result_commitment,
                semantic_receipt.then_some(false),
                None,
                core.sequence(),
                root,
                root,
                evidence.finalize().into(),
                now_millis,
            ));
            // The disclosure fields never leave the encrypted response.
            *receipt_state = semantic_receipt.then_some(CommandReceiptState::Rejected);
            *receipt_disclosure_nonce = semantic_receipt.then_some(disclosure_nonce);
        }
    }
    // These sidecars contain only AEAD ciphertext and its integrity/chain metadata. They let the
    // untrusted parent persist state transitions without learning the encrypted response body.
    let journal_artifacts = match &response {
        PlainResponse::User { response } => response.encrypted_record.clone().into_iter().collect(),
        PlainResponse::System { response } => vec![response.encrypted_record.clone()],
        PlainResponse::PoolWithdrawalSigned {
            response: Some(response),
            ..
        } => vec![response.encrypted_record.clone()],
        _ => Vec::new(),
    };
    let snapshot_artifacts = match &response {
        PlainResponse::Snapshot { snapshot } => vec![snapshot.clone()],
        _ if !journal_artifacts.is_empty() || exact_recovery => match state
            .core
            .as_ref()
            .and_then(|core| core.export_encrypted_snapshot().ok())
        {
            Some(snapshot) => vec![snapshot],
            None => {
                if let Some(core) = rollback_core.take() {
                    state.core = Some(core);
                    state.transport_nonces.forget(&replay_key);
                    if let Some(nonce) = rollback_operator_nonce.take() {
                        state.operator_nonces.forget(&nonce);
                    }
                }
                return WireResponse::Error {
                    code: "SNAPSHOT_EXPORT_FAILED",
                };
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
    let preparation_supersession = match &response {
        PlainResponse::PreparedCommandSuperseded { certificate } => Some(certificate.clone()),
        _ => None,
    };
    let encoded = match serde_json::to_vec(&response)
        .and_then(|value| pad_private_response(value).map_err(serde_json::Error::io))
    {
        Ok(value) => value,
        Err(_) => {
            if let Some(core) = rollback_core.take() {
                state.core = Some(core);
                state.transport_nonces.forget(&replay_key);
                if let Some(nonce) = rollback_operator_nonce.take() {
                    state.operator_nonces.forget(&nonce);
                }
            }
            return WireResponse::Error {
                code: "ENCODING_FAILED",
            };
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
        Ok(ciphertext) => {
            let mut envelope_hash = Sha256::new();
            envelope_hash.update(b"layrs.private-response-envelope.v1\0");
            envelope_hash.update(("layrs.v1".len() as u32).to_be_bytes());
            envelope_hash.update(b"layrs.v1");
            envelope_hash.update(client_public_key);
            envelope_hash.update(response_nonce);
            envelope_hash.update((ciphertext.len() as u64).to_be_bytes());
            envelope_hash.update(&ciphertext);
            let response_envelope_sha256: [u8; 32] = envelope_hash.finalize().into();
            let recovery_artifacts: Vec<_> = match &response {
                PlainResponse::User { response } => state
                    .core
                    .as_ref()
                    .and_then(|core| {
                        core.signed_recovery_bridge_artifact(
                            &response.receipt.idempotency_key,
                            recovery_environment(),
                            response_envelope_sha256,
                            ciphertext.len() as u64,
                        )
                    })
                    .into_iter()
                    .collect(),
                _ => Vec::new(),
            };
            if recovery_artifact_failure_required(
                requires_recovery_artifact,
                !recovery_artifacts.is_empty(),
                matches!(response, PlainResponse::User { .. }),
            ) {
                if let Some(core) = rollback_core.take() {
                    state.core = Some(core);
                    state.transport_nonces.forget(&replay_key);
                    if let Some(nonce) = rollback_operator_nonce.take() {
                        state.operator_nonces.forget(&nonce);
                    }
                }
                return WireResponse::Error {
                    code: "RECOVERY_ARTIFACT_FAILED",
                };
            }
            let mut preparation_artifacts = Vec::new();
            let mut rejection_artifacts = Vec::new();
            if !journal_artifacts.is_empty() && !direct_execution {
                let Some(snapshot) = snapshot_artifacts.first() else {
                    return rollback_wire_error(
                        &mut state,
                        &mut rollback_core,
                        &mut rollback_operator_nonce,
                        &replay_key,
                        "SNAPSHOT_EXPORT_FAILED",
                    );
                };
                let Some(record) = journal_artifacts.first() else {
                    return rollback_wire_error(
                        &mut state,
                        &mut rollback_core,
                        &mut rollback_operator_nonce,
                        &replay_key,
                        "JOURNAL_ARTIFACT_REQUIRED",
                    );
                };
                let Some(receipt) = receipt_artifacts.first() else {
                    return rollback_wire_error(
                        &mut state,
                        &mut rollback_core,
                        &mut rollback_operator_nonce,
                        &replay_key,
                        "RECEIPT_ARTIFACT_REQUIRED",
                    );
                };
                let Ok(prepared_at_millis) =
                    trusted_nsm_now_millis(state.nsm_fd, &state.enclave_measurement_sha384)
                else {
                    return rollback_wire_error(
                        &mut state,
                        &mut rollback_core,
                        &mut rollback_operator_nonce,
                        &replay_key,
                        "TRUSTED_TIME_UNAVAILABLE",
                    );
                };
                let Some(signer) = state.receipt_signer.as_ref() else {
                    return rollback_wire_error(
                        &mut state,
                        &mut rollback_core,
                        &mut rollback_operator_nonce,
                        &replay_key,
                        "RECEIPT_SIGNER_UNAVAILABLE",
                    );
                };
                let Some(writer) = writer_authorization.as_ref() else {
                    return rollback_wire_error(
                        &mut state,
                        &mut rollback_core,
                        &mut rollback_operator_nonce,
                        &replay_key,
                        "DURABLE_WRITER_AUTHORIZATION_REQUIRED",
                    );
                };
                if prepared_at_millis >= writer.expires_at_millis {
                    return rollback_wire_error(
                        &mut state,
                        &mut rollback_core,
                        &mut rollback_operator_nonce,
                        &replay_key,
                        "DURABLE_WRITER_AUTHORIZATION_EXPIRED",
                    );
                }
                let preparation = build_durable_preparation(
                    signer,
                    state.enclave_measurement_sha384,
                    &actor_domain,
                    command_binding_sha256,
                    durable_command_commitment,
                    request_context_sha256,
                    request_envelope_sha256,
                    &command_idempotency_key,
                    writer,
                    record,
                    snapshot,
                    receipt,
                    response_envelope_sha256,
                    ciphertext.len() as u64,
                    prepared_at_millis,
                );
                let Some(candidate) = state.core.take() else {
                    return rollback_wire_error(
                        &mut state,
                        &mut rollback_core,
                        &mut rollback_operator_nonce,
                        &replay_key,
                        "NOT_PROVISIONED",
                    );
                };
                let Some(prior) = rollback_core.take() else {
                    state.core = Some(candidate);
                    return WireResponse::Error {
                        code: "DURABLE_PREPARATION_FAILED",
                    };
                };
                state.core = Some(prior);
                preparation_artifacts.push(preparation.clone());
                let bundle = PreparedResponseBundle {
                    nonce: response_nonce,
                    ciphertext: ciphertext.clone(),
                    journal_artifacts: journal_artifacts.clone(),
                    snapshot_artifacts: snapshot_artifacts.clone(),
                    receipt_artifacts: receipt_artifacts.clone(),
                    audit_artifacts: audit_artifacts.clone(),
                    task_artifacts: task_artifacts.clone(),
                    recovery_artifacts: recovery_artifacts.clone(),
                    preparation_artifacts: preparation_artifacts.clone(),
                    rejection_artifacts: Vec::new(),
                };
                state.pending_preparation = Some(PendingPreparedTransition {
                    core: candidate,
                    preparation,
                    replay_key,
                    response: bundle,
                    writer_epoch: writer.epoch,
                    writer_lease_id: writer.lease_id,
                });
            }
            if journal_artifacts.is_empty() && !direct_execution {
                if let PlainResponse::Error { code, receipt, .. } = &response {
                    if actor_domain == "USER" || actor_domain == "OPERATOR" {
                        let Some(signer) = state.receipt_signer.as_ref() else {
                            return rollback_wire_error(
                                &mut state,
                                &mut rollback_core,
                                &mut rollback_operator_nonce,
                                &replay_key,
                                "RECEIPT_SIGNER_UNAVAILABLE",
                            );
                        };
                        let Ok(occurred_at_millis) =
                            trusted_nsm_now_millis(state.nsm_fd, &state.enclave_measurement_sha384)
                        else {
                            return rollback_wire_error(
                                &mut state,
                                &mut rollback_core,
                                &mut rollback_operator_nonce,
                                &replay_key,
                                "TRUSTED_TIME_UNAVAILABLE",
                            );
                        };
                        let mut rejection = DurableCommandRejection {
                            protocol_version: "layrs.durable-command-rejection.v1".into(),
                            environment: recovery_environment().into(),
                            enclave_measurement_sha384: state.enclave_measurement_sha384.to_vec(),
                            actor_domain: actor_domain.clone(),
                            command_binding_sha256,
                            command_commitment_sha256: durable_command_commitment,
                            request_context_sha256,
                            request_envelope_sha256,
                            command_idempotency_key: command_idempotency_key.clone(),
                            response_envelope_sha256,
                            response_envelope_bytes: ciphertext.len() as u64,
                            error_digest_sha256: Sha256::digest(code.as_bytes()).into(),
                            command_receipt: receipt.clone(),
                            occurred_at_millis,
                            signature: Vec::new(),
                        };
                        rejection.signature = signer.sign_domain_payload(
                            b"layrs.durable-command-rejection.v1\0",
                            &rejection,
                        );
                        rejection_artifacts.push(rejection);
                    }
                }
            }
            if let Some(certificate) = preparation_supersession {
                if !state.pending_preparation.as_ref().is_some_and(|pending| {
                    pending.preparation.preparation_id == certificate.preparation_id
                }) {
                    return rollback_wire_error(
                        &mut state,
                        &mut rollback_core,
                        &mut rollback_operator_nonce,
                        &replay_key,
                        "DURABLE_SUPERSESSION_PREPARATION_CHANGED",
                    );
                }
                state.pending_preparation = None;
                // Preserve exactly one signed result so a transport failure
                // after the clear cannot turn an idempotent retry into
                // DURABLE_PREPARATION_NOT_FOUND. The certificate is returned
                // only when every caller-supplied anchor matches exactly.
                state.last_preparation_supersession = Some(certificate);
            }
            WireResponse::Encrypted {
                nonce: response_nonce,
                ciphertext,
                journal_artifacts,
                snapshot_artifacts,
                receipt_artifacts,
                audit_artifacts,
                task_artifacts,
                recovery_artifacts,
                preparation_artifacts,
                rejection_artifacts,
            }
        }
        Err(_) => {
            if let Some(core) = rollback_core.take() {
                state.core = Some(core);
                state.transport_nonces.forget(&replay_key);
                if let Some(nonce) = rollback_operator_nonce.take() {
                    state.operator_nonces.forget(&nonce);
                }
            }
            WireResponse::Error {
                code: "ENCRYPTION_FAILED",
            }
        }
    }
}

/// Pads encrypted responses to power-of-two size classes.
///
/// JSON permits trailing whitespace, so clients decode the same payload while
/// an untrusted parent/network observer cannot distinguish private core error
/// variants by their exact ciphertext length. The minimum class covers every
/// privacy-safe error response; larger successful responses reveal only a
/// coarse bounded class rather than individual order/fill/economic fields.
fn pad_private_response(mut encoded: Vec<u8>) -> io::Result<Vec<u8>> {
    let padded_len = encoded
        .len()
        .max(MIN_PRIVATE_RESPONSE_BYTES)
        .checked_next_power_of_two()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "private response too large"))?;
    if padded_len > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "private response too large",
        ));
    }
    encoded.resize(padded_len, b' ');
    Ok(encoded)
}

fn rollback_wire_error(
    state: &mut EnclaveState,
    rollback_core: &mut Option<PrivateTradingCore>,
    rollback_operator_nonce: &mut Option<[u8; 32]>,
    replay_key: &[u8; 44],
    code: &'static str,
) -> WireResponse {
    if let Some(core) = rollback_core.take() {
        state.core = Some(core);
    }
    state.transport_nonces.forget(replay_key);
    if let Some(nonce) = rollback_operator_nonce.take() {
        state.operator_nonces.forget(&nonce);
    }
    WireResponse::Error { code }
}

fn recovery_artifact_failure_required(
    submit_order_requires_recovery_artifact: bool,
    has_recovery_artifact: bool,
    response_is_journaled_user_command: bool,
) -> bool {
    // SubmitOrder response recovery bridges are mandatory only after the core
    // has produced a journaled user response. Pre-journal validation failures
    // are emitted as signed durable rejections below; masking them here as an
    // unsigned RECOVERY_ARTIFACT_FAILED leaves the coordinator unable to
    // terminalize the command safely.
    submit_order_requires_recovery_artifact
        && response_is_journaled_user_command
        && !has_recovery_artifact
}

fn request_envelope_hash(
    client_public_key: [u8; 32],
    nonce: [u8; 12],
    ciphertext: &[u8],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"layrs.private-command-envelope.v1\0");
    hash.update(("layrs.v1".len() as u32).to_be_bytes());
    hash.update(b"layrs.v1");
    hash.update(client_public_key);
    hash.update(nonce);
    hash.update((ciphertext.len() as u64).to_be_bytes());
    hash.update(ciphertext);
    hash.finalize().into()
}

fn request_context_hash(context: &EncryptedOuterContext) -> Result<[u8; 32], ()> {
    let value = match context {
        EncryptedOuterContext::User(context) => serde_json::to_value(context).map_err(|_| ())?,
        EncryptedOuterContext::Operator => serde_json::Value::String("OPERATOR".into()),
    };
    let encoded = canonical_json(&value)?.into_bytes();
    let mut hash = Sha256::new();
    hash.update(b"layrs.private-command-context.v1\0");
    hash.update((encoded.len() as u32).to_be_bytes());
    hash.update(encoded);
    Ok(hash.finalize().into())
}

fn operator_command_hash(command: &OperatorCommand) -> [u8; 32] {
    let value =
        serde_json::to_value(command).expect("operator command serialization is infallible");
    let encoded = canonical_json(&value).expect("operator command canonicalization is infallible");
    let mut hash = Sha256::new();
    hash.update(b"layrs.operator-command.v1\0");
    hash.update((encoded.len() as u32).to_be_bytes());
    hash.update(encoded.as_bytes());
    hash.finalize().into()
}

fn canonical_json(value: &serde_json::Value) -> Result<String, ()> {
    match value {
        serde_json::Value::Object(fields) => {
            let mut keys: Vec<_> = fields.keys().collect();
            keys.sort_unstable();
            let mut output = String::from("{");
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                output.push_str(&serde_json::to_string(key).map_err(|_| ())?);
                output.push(':');
                output.push_str(&canonical_json(fields.get(key).ok_or(())?)?);
            }
            output.push('}');
            Ok(output)
        }
        serde_json::Value::Array(values) => {
            let mut output = String::from("[");
            for (index, item) in values.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                output.push_str(&canonical_json(item)?);
            }
            output.push(']');
            Ok(output)
        }
        _ => serde_json::to_string(value).map_err(|_| ()),
    }
}

fn command_durable_binding(request: &PlainRequest) -> (String, String) {
    match request {
        PlainRequest::User { command, .. } => ("USER".into(), command.idempotency_key.clone()),
        PlainRequest::Operator { envelope } => {
            let encoded = serde_json::to_value(&envelope.command)
                .expect("operator command serialization is infallible");
            let supplied = encoded
                .get("idempotency_key")
                .and_then(serde_json::Value::as_str)
                .filter(|value| {
                    (8..=128).contains(&value.len())
                        && value.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'_' | b'-')
                        })
                });
            let key = supplied.map(str::to_owned).unwrap_or_else(|| {
                let command_type = encoded
                    .get("type")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("COMMAND")
                    .to_ascii_lowercase();
                format!(
                    "operator:{command_type}:{}",
                    hex::encode(operator_command_hash(&envelope.command))
                )
            });
            ("OPERATOR".into(), key)
        }
        PlainRequest::AggregateDepth { .. } => ("READ_ONLY".into(), "read-only".into()),
    }
}

fn durable_control_request(request: &PlainRequest) -> bool {
    match request {
        // A read-only user command observes state.core, which remains the last
        // committed core while a candidate is pending. It emits no journal or
        // snapshot and therefore cannot interfere with prepare/finalize.
        PlainRequest::User { command, .. } => readonly_user_action(&command.action),
        PlainRequest::Operator { envelope } => matches!(
            envelope.command,
            OperatorCommand::PreparedCommandStatus { .. }
                | OperatorCommand::InspectPendingPreparation { .. }
                | OperatorCommand::AbortSupersededPreparation { .. }
                | OperatorCommand::FinalizePreparedCommand { .. }
                | OperatorCommand::DelegatedPortfolioRead { .. }
        ),
        PlainRequest::AggregateDepth { .. } => false,
    }
}

/// Quest-only migration seam. This is embedded into the EIF at build time and
/// is disabled unless the release build explicitly opts in. The decrypted
/// command and the enclave's registered market definition are both checked so
/// the untrusted parent cannot route a non-BTC mutation through this path.
fn direct_execution_request(state: &EnclaveState, request: &PlainRequest) -> bool {
    if !matches!(option_env!("LAYRS_DIRECT_BTC_EXECUTION_ENABLED"), Some("1")) {
        return false;
    }
    match request {
        PlainRequest::User { command, .. } => state.core.as_ref().is_some_and(|core| {
            direct_btc_order_action(core, &command.action)
                || direct_base_usdc_withdrawal(&command.action)
        }),
        // Direct SubmitOrder responses reserve a bounded recovery capsule. The
        // existing signed archive proof remains mandatory, but its exact ACK
        // must not depend on Durable Command or the window would eventually
        // stop accepting otherwise healthy direct orders.
        PlainRequest::Operator { envelope } => direct_quest_operator_command(&envelope.command),
        PlainRequest::AggregateDepth { .. } => false,
    }
}

/// The quest browser must establish its authenticated private session before
/// it can construct a BTC order. Keep this allowlist separate from the
/// market-scoped order allowlist: these are the only operator commands allowed
/// to bypass an unrelated occupied Durable preparation.
fn direct_quest_operator_command(command: &OperatorCommand) -> bool {
    match command {
        OperatorCommand::AcknowledgeRecoveryArchive { .. }
        | OperatorCommand::RegisterSession { .. }
        | OperatorCommand::RegisterTransferAccount { .. }
        | OperatorCommand::TransferAccountStatus { .. } => true,
        // Crypto rollover must not inherit a protocol-wide Durable preparation.
        // Keep this escape hatch narrower than the general operator surface:
        // only the immutable recurring-crypto namespaces and their exact
        // registration shapes may execute directly.
        OperatorCommand::MarketStatus { market_id } => recurring_crypto_window(market_id).is_some(),
        OperatorCommand::RegisterMarket {
            idempotency_key,
            market,
            now_millis,
        } => direct_crypto_market_registration(idempotency_key, market, *now_millis),
        OperatorCommand::AggregateDepth {
            market_id,
            now_millis,
            minimum_level_quantity_micros,
            ..
        } => direct_crypto_public_depth(market_id, *now_millis, *minimum_level_quantity_micros),
        OperatorCommand::CreditDeposit {
            idempotency_key,
            identity_commitment,
            asset,
            amount_atomic,
            evidence_hash,
            ..
        } => direct_base_usdc_deposit_credit(
            idempotency_key,
            identity_commitment,
            asset,
            *amount_atomic,
            evidence_hash,
        ),
        OperatorCommand::FinalizeWithdrawal {
            idempotency_key,
            identity_commitment,
            asset,
            amount_atomic,
            evidence_hash,
            ..
        } => direct_base_usdc_withdrawal_terminal(
            "withdrawal-final:",
            idempotency_key,
            identity_commitment,
            asset,
            *amount_atomic,
            evidence_hash,
        ),
        OperatorCommand::ReleaseWithdrawal {
            idempotency_key,
            identity_commitment,
            asset,
            amount_atomic,
            evidence_hash,
            ..
        } => direct_base_usdc_withdrawal_terminal(
            "withdrawal-release:",
            idempotency_key,
            identity_commitment,
            asset,
            *amount_atomic,
            evidence_hash,
        ),
        OperatorCommand::SignPoolWithdrawal {
            idempotency_key,
            authorization,
            nonce,
            gas_limit,
            max_fee_per_gas_wei,
            max_priority_fee_per_gas_wei,
            now_millis,
        } => direct_base_usdc_withdrawal_signing(
            idempotency_key,
            authorization,
            *nonce,
            *gas_limit,
            max_fee_per_gas_wei,
            max_priority_fee_per_gas_wei,
            *now_millis,
        ),
        OperatorCommand::ResolutionStatus { market_id }
        | OperatorCommand::ResolutionReadiness { market_id, .. } => {
            recurring_crypto_window(market_id).is_some()
        }
        OperatorCommand::SignResolutionEvidence { evidence, .. } => {
            recurring_crypto_window(unsigned_resolution_market_id(evidence)).is_some()
        }
        OperatorCommand::ResolveBinanceMarket { signed, .. } => {
            recurring_crypto_window(&signed.statement.market_id).is_some()
        }
        _ => false,
    }
}

fn direct_base_usdc_withdrawal(action: &UserCommandAction) -> bool {
    let UserCommandAction::RequestWithdrawal {
        withdrawal_id,
        chain,
        asset,
        amount_atomic,
        destination,
    } = action
    else {
        return false;
    };
    !withdrawal_id.is_nil()
        && chain == "base"
        && asset == "USDC"
        && *amount_atomic > 0
        && valid_evm_destination(destination)
}

fn direct_base_usdc_withdrawal_terminal(
    prefix: &str,
    idempotency_key: &str,
    identity_commitment: &[u8; 32],
    asset: &str,
    amount_atomic: u128,
    evidence_hash: &[u8; 32],
) -> bool {
    let Some(withdrawal_id) = idempotency_key.strip_prefix(prefix) else {
        return false;
    };
    Uuid::parse_str(withdrawal_id).is_ok_and(|value| !value.is_nil())
        && identity_commitment != &[0; 32]
        && asset == "USDC"
        && amount_atomic > 0
        && evidence_hash != &[0; 32]
}

fn direct_base_usdc_withdrawal_signing(
    idempotency_key: &str,
    authorization: &WithdrawalAuthorization,
    nonce: u64,
    gas_limit: u64,
    max_fee_per_gas_wei: &str,
    max_priority_fee_per_gas_wei: &str,
    now_millis: i64,
) -> bool {
    let Some(withdrawal_id) = idempotency_key.strip_prefix("withdrawal-sign:") else {
        return false;
    };
    let Ok(withdrawal_id) = Uuid::parse_str(withdrawal_id) else {
        return false;
    };
    let intent = &authorization.intent;
    let Ok(amount_atomic) = intent.amount_atomic.parse::<u128>() else {
        return false;
    };
    let Ok(max_fee) = max_fee_per_gas_wei.parse::<u128>() else {
        return false;
    };
    let Ok(priority_fee) = max_priority_fee_per_gas_wei.parse::<u128>() else {
        return false;
    };
    !withdrawal_id.is_nil()
        && withdrawal_id == intent.withdrawal_id
        && intent.protocol_version == "layrs.withdrawal.v1"
        && !intent.session_id.is_empty()
        && intent.chain == "base"
        && intent.asset == "USDC"
        && amount_atomic > 0
        && valid_evm_destination(&intent.destination)
        && !intent.receipt_id.is_empty()
        && intent.state_root != [0; 32]
        && now_millis > 0
        && now_millis < intent.expires_at_millis
        && intent.expires_at_millis.saturating_sub(now_millis) <= 15 * 60_000
        && nonce <= i64::MAX as u64
        && (21_000..=2_000_000).contains(&gas_limit)
        && max_fee > 0
        && priority_fee <= max_fee
}

fn valid_evm_destination(destination: &str) -> bool {
    destination.len() == 42
        && destination.starts_with("0x")
        && destination[2..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
}

fn unsigned_resolution_market_id(evidence: &UnsignedResolutionEvidence) -> &str {
    match evidence {
        UnsignedResolutionEvidence::Pyth(statement) => &statement.market_id,
        UnsignedResolutionEvidence::Binance(statement) => &statement.market_id,
        UnsignedResolutionEvidence::ExactCondition(statement) => &statement.market_id,
        UnsignedResolutionEvidence::Polymarket(statement) => &statement.market_id,
    }
}

/// Quest deposits have already been finalized on Base and reconciled to the
/// pool before the coordinator signs this command. Permit only the normal
/// deposit idempotency shape, non-empty account/evidence commitments and the
/// public API's five-USDC minimum. Other funding mutations remain fenced.
fn direct_base_usdc_deposit_credit(
    idempotency_key: &str,
    identity_commitment: &[u8; 32],
    asset: &str,
    amount_atomic: u128,
    evidence_hash: &[u8; 32],
) -> bool {
    let Some(transfer_id) = idempotency_key.strip_prefix("deposit:") else {
        return false;
    };
    let Ok(transfer_id) = Uuid::parse_str(transfer_id) else {
        return false;
    };
    !transfer_id.is_nil()
        && identity_commitment != &[0; 32]
        && asset == "USDC"
        && amount_atomic >= 5_000_000
        && evidence_hash != &[0; 32]
}

fn direct_crypto_public_depth(
    market_id: &str,
    now_millis: i64,
    minimum_level_quantity_micros: u128,
) -> bool {
    let Some((_, timeframe, window_start_millis)) = recurring_crypto_window(market_id) else {
        return false;
    };
    let maximum_window_millis = match timeframe {
        "5m" => 300_000,
        "15m" => 900_000,
        "1h" => 3_600_000,
        "4h" => 14_400_000,
        "1d" => 86_400_000,
        "1w" => 604_800_000,
        "1mo" => 2_678_400_000,
        _ => return false,
    };
    // Preserve the production public-depth privacy floor even if the
    // untrusted parent attempts to lower its configured threshold.
    minimum_level_quantity_micros >= 5_000_000
        && now_millis >= window_start_millis
        && now_millis < window_start_millis.saturating_add(maximum_window_millis)
}

fn direct_crypto_market_registration(
    idempotency_key: &str,
    market: &MarketConfig,
    now_millis: i64,
) -> bool {
    let Some((asset, timeframe, window_start_millis)) = recurring_crypto_window(&market.market_id)
    else {
        return false;
    };
    let content_hash = idempotency_key.strip_prefix("market:");
    content_hash.is_some_and(|value| {
        value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
    }) && market.opens_at_millis == window_start_millis
        && valid_recurring_window_duration(
            timeframe,
            market.closes_at_millis.checked_sub(market.opens_at_millis),
        )
        && now_millis == market.opens_at_millis
        && valid_recurring_asset_config(asset, market)
        && market.public_settlement_chain.as_deref() == Some("horizen")
        && market.fee_profile_id == FeeProfileId::LayrsCryptoV2
        && matches!(market.execution, MarketExecution::NativeClob)
}

fn recurring_crypto_window(market_id: &str) -> Option<(&str, &str, i64)> {
    let segments = market_id.split(':').collect::<Vec<_>>();
    let (asset, timeframe, epoch) = match segments.as_slice() {
        ["layrs", "v4", "ZEN", timeframe, epoch] => ("ZEN", *timeframe, *epoch),
        ["layrs", "v5", asset @ ("BTC" | "ETH" | "SOL" | "ZEC" | "HYPE"), "USDC", timeframe, epoch] => {
            (*asset, *timeframe, *epoch)
        }
        _ => return None,
    };
    let timeframe_matches = match asset {
        "ZEN" => matches!(timeframe, "15m" | "1h" | "4h" | "1d" | "1w" | "1mo"),
        _ => matches!(timeframe, "5m" | "15m" | "1h" | "1d" | "1w" | "1mo"),
    };
    if !timeframe_matches {
        return None;
    }
    let epoch_seconds = epoch.parse::<i64>().ok()?;
    if epoch_seconds < 0 {
        return None;
    }
    Some((asset, timeframe, epoch_seconds.checked_mul(1_000)?))
}

fn valid_recurring_window_duration(timeframe: &str, duration_millis: Option<i64>) -> bool {
    match (timeframe, duration_millis) {
        ("5m", Some(300_000))
        | ("15m", Some(900_000))
        | ("1h", Some(3_600_000))
        | ("4h", Some(14_400_000))
        | ("1d", Some(86_400_000))
        | ("1w", Some(604_800_000)) => true,
        ("1mo", Some(duration)) => (2_419_200_000..=2_678_400_000).contains(&duration),
        _ => false,
    }
}

fn valid_recurring_asset_config(asset: &str, market: &MarketConfig) -> bool {
    let expected_feed = match asset {
        "ZEN" => 9_001,
        "BTC" => 9_002,
        "ETH" => 9_003,
        "SOL" => 9_004,
        "ZEC" => 9_005,
        "HYPE" => 9_006,
        _ => return false,
    };
    if market.oracle_feed_id != expected_feed {
        return false;
    }
    if asset == "ZEN" {
        market.settlement_asset == "ZEN"
            && market.settlement_decimals == 18
            && market.minimum_quantity_micros == 250_000
            && market.maximum_quantity_micros == 100_000_000
            && market.minimum_order_notional_micros == 250_000
            && market.maximum_order_notional_micros == 100_000_000
            && market.maximum_user_position_micros == 250_000_000
            && market.maximum_pending_bootstrap_notional_micros == 100_000_000
            && market.tick_size_micros == 1_000
    } else {
        market.settlement_asset == "USDC"
            && market.settlement_decimals == 6
            && market.minimum_quantity_micros == 1_000
            && market.maximum_quantity_micros == 1_000_000_000
            && market.minimum_order_notional_micros == 1_000_000
            && market.maximum_order_notional_micros == 1_000_000_000
            && market.maximum_user_position_micros == 2_500_000_000
            && market.maximum_pending_bootstrap_notional_micros == 1_000_000_000
            && market.tick_size_micros == 1_000
    }
}

fn direct_btc_order_action(core: &PrivateTradingCore, action: &UserCommandAction) -> bool {
    let market = |market_id: &str| registered_btc_usdc_market(core, market_id);
    match action {
        UserCommandAction::SubmitOrder { order } => market(&order.market_id),
        UserCommandAction::ReplaceOrder {
            market_id,
            replacement,
            ..
        } => market_id == &replacement.market_id && market(market_id),
        UserCommandAction::CancelOrder { market_id, .. } => market(market_id),
        UserCommandAction::CancelAllOrders {
            filter: clob_service::private_core::CancelAllOrdersFilter::Market { market_id },
        } => market(market_id),
        _ => false,
    }
}

fn registered_btc_usdc_market(core: &PrivateTradingCore, market_id: &str) -> bool {
    let mut segments = market_id.split(':');
    let structurally_btc = matches!(
        (
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next()
        ),
        (
            Some("layrs"),
            Some("v5"),
            Some("BTC"),
            Some("USDC"),
            Some(_)
        )
    );
    structurally_btc
        && core.market_config(market_id).is_some_and(|market| {
            market.market_id == market_id && market.settlement_asset == "USDC"
        })
}

fn request_requires_writer_authorization(request: &PlainRequest) -> bool {
    match request {
        // These actions are implemented by PrivateCore::execute_readonly: they
        // do not advance the sequence, consume a session nonce, modify the
        // ledger/book, or emit a journal. Requiring the global writer fence
        // made a portfolio read wait behind unrelated durable mutations.
        PlainRequest::User { command, .. } => !readonly_user_action(&command.action),
        PlainRequest::Operator { envelope } => matches!(
            &envelope.command,
            OperatorCommand::SetTradingFreeze { .. }
                | OperatorCommand::AcknowledgeRecoveryArchive { .. }
                | OperatorCommand::RegisterMarket { .. }
                | OperatorCommand::RegisterSession { .. }
                | OperatorCommand::RegisterTransferAccount { .. }
                | OperatorCommand::ExternalFlow { .. }
                | OperatorCommand::CreditDeposit { .. }
                | OperatorCommand::AccrueReward { .. }
                | OperatorCommand::FinalizeWithdrawal { .. }
                | OperatorCommand::ReleaseWithdrawal { .. }
                | OperatorCommand::ResolveMarket { .. }
                | OperatorCommand::ResolveBinanceMarket { .. }
                | OperatorCommand::ResolveExactConditionMarket { .. }
                | OperatorCommand::ResolvePolymarketMarket { .. }
                | OperatorCommand::ExecuteBootstrap { .. }
                | OperatorCommand::AuthorizeBootstrapSubmission { .. }
                | OperatorCommand::SubmitPreparedBootstrap { .. }
                | OperatorCommand::ObserveBootstrapSubmission { .. }
                | OperatorCommand::ReconcileBootstrap { .. }
                | OperatorCommand::SignPoolWithdrawal { .. }
                | OperatorCommand::InspectPendingPreparation { .. }
                | OperatorCommand::AbortSupersededPreparation { .. }
                | OperatorCommand::FinalizePreparedCommand { .. }
        ),
        PlainRequest::AggregateDepth { .. } => false,
    }
}

fn readonly_user_action(action: &UserCommandAction) -> bool {
    matches!(
        action,
        UserCommandAction::Portfolio
            | UserCommandAction::Rewards
            | UserCommandAction::BootstrapStatus { .. }
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_writer_authorization(
    state: &mut EnclaveState,
    authorization: &DurableWriterAuthorization,
    actor_domain: &str,
    command_idempotency_key: &str,
    command_commitment_sha256: [u8; 32],
    request_context_sha256: [u8; 32],
    request_envelope_sha256: [u8; 32],
    trusted_now_millis: i64,
) -> Result<(), &'static str> {
    if authorization.protocol_version != "layrs.durable-writer-authorization.v1"
        || authorization.environment != recovery_environment()
        || authorization.epoch == 0
        || authorization.actor_domain != actor_domain
        || authorization.command_idempotency_key != command_idempotency_key
        || authorization.command_commitment_sha256 != command_commitment_sha256
        || authorization.request_context_sha256 != request_context_sha256
        || authorization.request_envelope_sha256 != request_envelope_sha256
        || authorization.not_before_millis > trusted_now_millis.saturating_add(2_000)
        || trusted_now_millis >= authorization.expires_at_millis
        || authorization.expires_at_millis <= authorization.not_before_millis
        || authorization.expires_at_millis - authorization.not_before_millis > 180_000
    {
        return Err("DURABLE_WRITER_AUTHORIZATION_INVALID");
    }
    let signature: [u8; 64] = authorization
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| "DURABLE_WRITER_AUTHORIZATION_INVALID")?;
    let mut unsigned = authorization.clone();
    unsigned.signature.clear();
    let encoded =
        serde_json::to_vec(&unsigned).map_err(|_| "DURABLE_WRITER_AUTHORIZATION_INVALID")?;
    let mut payload = Vec::with_capacity(encoded.len() + 64);
    payload.extend_from_slice(b"layrs.durable-writer-authorization.v1\0");
    payload.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
    payload.extend_from_slice(&encoded);
    state
        .operator_public_key
        .verify(&payload, &Signature::from_bytes(&signature))
        .map_err(|_| "DURABLE_WRITER_AUTHORIZATION_INVALID")?;
    if authorization.epoch < state.minimum_writer_epoch
        || authorization.epoch == state.minimum_writer_epoch
            && state
                .writer_lease_id
                .is_some_and(|lease| lease != authorization.lease_id)
    {
        return Err("DURABLE_WRITER_FENCE_STALE");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_durable_preparation(
    signer: &ReceiptSigner,
    enclave_measurement_sha384: [u8; 48],
    actor_domain: &str,
    command_binding_sha256: [u8; 32],
    command_commitment_sha256: [u8; 32],
    request_context_sha256: [u8; 32],
    request_envelope_sha256: [u8; 32],
    command_idempotency_key: &str,
    writer_authorization: &DurableWriterAuthorization,
    record: &EncryptedJournalRecord,
    snapshot: &EncryptedSnapshot,
    receipt: &EnclaveReceipt,
    response_envelope_sha256: [u8; 32],
    response_envelope_bytes: u64,
    prepared_at_millis: i64,
) -> DurableCommandPreparation {
    let mut preparation = DurableCommandPreparation {
        protocol_version: "layrs.durable-command-preparation.v1".into(),
        environment: recovery_environment().into(),
        enclave_measurement_sha384: enclave_measurement_sha384.to_vec(),
        preparation_id: [0; 32],
        actor_domain: actor_domain.into(),
        command_binding_sha256,
        command_commitment_sha256,
        request_context_sha256,
        request_envelope_sha256,
        command_idempotency_key: command_idempotency_key.into(),
        writer_epoch: writer_authorization.epoch,
        writer_lease_id: writer_authorization.lease_id,
        prior_enclave_sequence: record.sequence.saturating_sub(1),
        enclave_sequence: record.sequence,
        prior_state_root: receipt.prior_state_root,
        prior_journal_head: record.prior_record_hash,
        state_root: record.state_root,
        journal_record_hash: record.record_hash,
        snapshot_ciphertext_hash: snapshot.ciphertext_hash,
        response_envelope_sha256,
        response_envelope_bytes,
        response_status: 200,
        response_content_type: "application/json".into(),
        receipt_id: receipt.receipt_id.clone(),
        prepared_at_millis,
        expires_at_millis: prepared_at_millis.saturating_add(30_000),
        signature: Vec::new(),
    };
    preparation.preparation_id = durable_preparation_id(&preparation);
    preparation.signature =
        signer.sign_domain_payload(b"layrs.durable-command-preparation.v1\0", &preparation);
    preparation
}

fn durable_preparation_id(preparation: &DurableCommandPreparation) -> [u8; 32] {
    let mut unsigned = preparation.clone();
    unsigned.preparation_id = [0; 32];
    unsigned.signature.clear();
    let encoded = serde_json::to_vec(&unsigned).expect("preparation serialization is infallible");
    let mut hash = Sha256::new();
    hash.update(b"layrs.durable-command-preparation-id.v1\0");
    hash.update((encoded.len() as u32).to_be_bytes());
    hash.update(encoded);
    hash.finalize().into()
}

fn pending_preparation_is_superseded(
    preparation: &DurableCommandPreparation,
    live_enclave_sequence: u64,
    live_state_root: [u8; 32],
) -> bool {
    // A durable decision whose candidate is still the only possible next
    // state is irrevocable and must be finalized. Supersession is provable
    // only after the committed core has reached the candidate sequence on a
    // different root, or has advanced beyond it. This is the exact condition
    // under which FINALIZE_PREPARED_COMMAND would reject the stale candidate
    // with a head mismatch.
    live_enclave_sequence > preparation.enclave_sequence
        || (live_enclave_sequence == preparation.enclave_sequence
            && live_state_root != preparation.state_root)
}

#[allow(clippy::too_many_arguments)]
fn preparation_supersession_matches_request(
    certificate: &SignedPreparationSupersession,
    request_idempotency_key: &str,
    preparation_id: [u8; 32],
    pending_enclave_sequence: u64,
    pending_state_root: [u8; 32],
    live_enclave_sequence: u64,
    live_state_root: [u8; 32],
    live_journal_head: [u8; 32],
) -> bool {
    certificate.request_idempotency_key == request_idempotency_key
        && certificate.preparation_id == preparation_id
        && certificate.pending_enclave_sequence == pending_enclave_sequence
        && certificate.pending_state_root == pending_state_root
        && certificate.live_enclave_sequence == live_enclave_sequence
        && certificate.live_state_root == live_state_root
        && certificate.live_journal_head == live_journal_head
}

fn rebind_durable_preparation(
    preparation: &mut DurableCommandPreparation,
    authorization: &DurableWriterAuthorization,
    prepared_at_millis: i64,
    expires_at_millis: i64,
    signer: &ReceiptSigner,
) {
    preparation.writer_epoch = authorization.epoch;
    preparation.writer_lease_id = authorization.lease_id;
    // This is still the exact uncommitted candidate: only its governed writer
    // fence and bounded persistence window are renewed. Financial execution
    // and the successor snapshot are never repeated.
    preparation.prepared_at_millis = prepared_at_millis;
    preparation.expires_at_millis = expires_at_millis;
    preparation.preparation_id = durable_preparation_id(preparation);
    preparation.signature.clear();
    preparation.signature =
        signer.sign_domain_payload(b"layrs.durable-command-preparation.v1\0", preparation);
}

fn verify_durable_preparation(
    receipt_public_key: &[u8; 32],
    authorized_preparation_measurement_sha384: &[u8],
    preparation: &DurableCommandPreparation,
    snapshot: &EncryptedSnapshot,
) -> Result<(), String> {
    if preparation.protocol_version != "layrs.durable-command-preparation.v1"
        || preparation.environment != recovery_environment()
        || preparation.enclave_measurement_sha384.as_slice()
            != authorized_preparation_measurement_sha384
        || preparation.writer_epoch == 0
        || preparation.preparation_id != durable_preparation_id(preparation)
        || preparation.enclave_sequence != preparation.prior_enclave_sequence.saturating_add(1)
        || preparation.response_status != 200
        || preparation.response_content_type != "application/json"
        || preparation.response_envelope_bytes < MIN_PRIVATE_RESPONSE_BYTES as u64
        || preparation.response_envelope_bytes > MAX_PRIVATE_RESPONSE_BYTES as u64
        || preparation.prepared_at_millis >= preparation.expires_at_millis
        || snapshot.sequence != preparation.enclave_sequence
        || snapshot.state_root != preparation.state_root
        || snapshot.journal_head != preparation.journal_record_hash
        || snapshot.ciphertext_hash != preparation.snapshot_ciphertext_hash
    {
        return Err("DURABLE_PREPARATION_INVALID".into());
    }
    let signature: [u8; 64] = preparation
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| "DURABLE_PREPARATION_INVALID".to_string())?;
    let mut unsigned = preparation.clone();
    unsigned.signature.clear();
    let encoded =
        serde_json::to_vec(&unsigned).map_err(|_| "DURABLE_PREPARATION_INVALID".to_string())?;
    let mut payload = Vec::with_capacity(encoded.len() + 64);
    payload.extend_from_slice(b"layrs.durable-command-preparation.v1\0");
    payload.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
    payload.extend_from_slice(&encoded);
    VerifyingKey::from_bytes(receipt_public_key)
        .map_err(|_| "DURABLE_PREPARATION_INVALID".to_string())?
        .verify(&payload, &Signature::from_bytes(&signature))
        .map_err(|_| "DURABLE_PREPARATION_INVALID".to_string())
}

fn enclave_transition_policy_hash(source: &[u8], target: &[u8], schema: &str) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"layrs.enclave-generation-transition.v1\0");
    hash.update((source.len() as u32).to_be_bytes());
    hash.update(source);
    hash.update((target.len() as u32).to_be_bytes());
    hash.update(target);
    hash.update((schema.len() as u32).to_be_bytes());
    hash.update(schema.as_bytes());
    hash.finalize().into()
}

fn configured_transition_policy_hash() -> Option<[u8; 32]> {
    option_env!("LAYRS_ENCLAVE_TRANSITION_POLICY_SHA256")
        .and_then(|value| hex::decode(value).ok())
        .and_then(|value| value.try_into().ok())
}

fn decode_exact_hex<const N: usize>(value: &str) -> Result<[u8; N], String> {
    hex::decode(value)
        .map_err(|_| "INCIDENT_RECOVERY_POLICY_INVALID".to_string())?
        .try_into()
        .map_err(|_| "INCIDENT_RECOVERY_POLICY_INVALID".to_string())
}

fn incident_recovery_policy_sha256() -> Result<[u8; 32], String> {
    let actual: [u8; 32] = Sha256::digest(INCIDENT_RECOVERY_POLICY_BYTES).into();
    let expected = decode_exact_hex(INCIDENT_RECOVERY_POLICY_SHA256_HEX)?;
    if actual != expected {
        return Err("INCIDENT_RECOVERY_POLICY_INVALID".into());
    }
    Ok(actual)
}

fn exact_incident_recovery_policy() -> Result<IncidentTerminalRecoveryPolicy, String> {
    let policy: IncidentTerminalRecoveryPolicy =
        serde_json::from_slice(INCIDENT_RECOVERY_POLICY_BYTES)
            .map_err(|_| "INCIDENT_RECOVERY_POLICY_INVALID".to_string())?;
    validate_incident_recovery_policy_fields(&policy)?;
    Ok(policy)
}

fn validate_incident_recovery_policy_fields(
    policy: &IncidentTerminalRecoveryPolicy,
) -> Result<(), String> {
    if policy.schema_version != "layrs.incident-terminal-recovery-policy.v1"
        || policy.incident_id != INCIDENT_ID
        || policy.source_release_commit != EXACT_LIVE_976_RELEASE_COMMIT
        || policy.restore_sequence != INCIDENT_TERMINAL_SEQUENCE
        || policy.rollback_floor != INCIDENT_TERMINAL_SEQUENCE
        || policy.state_root != INCIDENT_TERMINAL_STATE_ROOT_HEX
        || policy.journal_head != INCIDENT_TERMINAL_JOURNAL_HEAD_HEX
        || policy.snapshot.bucket != INCIDENT_SNAPSHOT_BUCKET
        || policy.snapshot.key != INCIDENT_SNAPSHOT_KEY
        || policy.snapshot.version_id != INCIDENT_SNAPSHOT_VERSION_ID
        || policy.snapshot.size_bytes != INCIDENT_SNAPSHOT_SIZE_BYTES
        || policy.snapshot.body_sha256 != INCIDENT_SNAPSHOT_BODY_SHA256_HEX
        || policy.snapshot.ciphertext_sha256 != INCIDENT_TERMINAL_CIPHERTEXT_SHA256_HEX
        || policy.source_provenance.eif_sha384
            != "4c23589c8f0a09e509584e5263fedd1368827c4b48388b2519b7a4b217c82991ddf06c6380f3086db4e28c75223a8a9f"
        || policy.source_provenance.pcr0
            != "d144679b70ac6ea9d84130e6d27112b1cd6fc0870d93dd5d595644283df2c20cc2cd6d8cb7cf49e1b643d6245336e2ad"
        || policy.source_provenance.pcr1
            != "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493"
        || policy.source_provenance.pcr2
            != "f36c630bc592645bf86bb5ef4252c51e0dcb7d0e24af2f842dfff49fc22b0e3fd56bbb0f2d0eeff367587d0aa6605fb8"
        || policy.source_provenance.source_ami_id != "ami-069ef36debc518fc9"
        || policy.source_provenance.copied_parent_ami_id != "ami-03241294e5c3b3990"
        || policy.source_provenance.parent_binary_sha384
            != "2fc8185a132856d8bb71d955c4cdfba2dcea78144ff82fa1f9052749a2c3947e75bdbb3e6672ca2f72b1bf4a58e67283"
        || policy.historical_journal_replay_required
        || policy.historical_fill_completeness_certified
    {
        return Err("INCIDENT_RECOVERY_POLICY_INVALID".into());
    }
    Ok(())
}

fn ensure_generic_provisioning_allowed() -> Result<(), String> {
    incident_recovery_policy_sha256()?;
    exact_incident_recovery_policy()?;
    Ok(())
}

fn validate_incident_terminal_input(
    descriptor: &IncidentSnapshotDescriptor,
    snapshot_body: &[u8],
) -> Result<([u8; 32], [u8; 32], EncryptedSnapshot), String> {
    let policy_sha256 = incident_recovery_policy_sha256()?;
    let policy = exact_incident_recovery_policy()?;
    if descriptor.bucket != policy.snapshot.bucket
        || descriptor.key != policy.snapshot.key
        || descriptor.version_id != policy.snapshot.version_id
        || descriptor.size_bytes != policy.snapshot.size_bytes
        || descriptor.body_sha256 != policy.snapshot.body_sha256
        || snapshot_body.len() as u64 != policy.snapshot.size_bytes
    {
        return Err("INCIDENT_SNAPSHOT_DESCRIPTOR_MISMATCH".into());
    }
    let snapshot_body_sha256: [u8; 32] = Sha256::digest(snapshot_body).into();
    if snapshot_body_sha256 != decode_exact_hex(&policy.snapshot.body_sha256)? {
        return Err("INCIDENT_SNAPSHOT_BODY_MISMATCH".into());
    }
    let snapshot: EncryptedSnapshot = serde_json::from_slice(snapshot_body)
        .map_err(|_| "INCIDENT_SNAPSHOT_ENVELOPE_INVALID".to_string())?;
    if snapshot.sequence != INCIDENT_TERMINAL_SEQUENCE
        || snapshot.state_root != decode_exact_hex(&policy.state_root)?
        || snapshot.journal_head != decode_exact_hex(&policy.journal_head)?
        || snapshot.ciphertext_hash != decode_exact_hex(&policy.snapshot.ciphertext_sha256)?
        || Sha256::digest(&snapshot.ciphertext).as_slice() != snapshot.ciphertext_hash
    {
        return Err("INCIDENT_SNAPSHOT_CHECKPOINT_MISMATCH".into());
    }
    Ok((policy_sha256, snapshot_body_sha256, snapshot))
}

fn incident_artifact_binding(
    policy_sha256: [u8; 32],
    snapshot_body_sha256: [u8; 32],
    descriptor: &IncidentSnapshotDescriptor,
    certifier_release_manifest_sha256: [u8; 32],
    certifier_pcr0_sha384: [u8; 48],
    external_challenge: [u8; 32],
    certificate_sha256: [u8; 32],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"layrs.incident-terminal-certification.v1\0");
    hash.update(policy_sha256);
    hash.update(snapshot_body_sha256);
    for value in [&descriptor.bucket, &descriptor.key, &descriptor.version_id] {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value.as_bytes());
    }
    hash.update(descriptor.size_bytes.to_be_bytes());
    hash.update(certifier_release_manifest_sha256);
    hash.update(certifier_pcr0_sha384);
    hash.update(external_challenge);
    hash.update(certificate_sha256);
    hash.finalize().into()
}

fn verify_enclave_generation_transition(
    source: &[u8],
    target: &[u8],
    current: &[u8; 48],
    schema: &str,
    supplied_policy: [u8; 32],
) -> Result<(), String> {
    if source.len() != 48
        || target != current.as_slice()
        || schema != "layrs.private-core-snapshot.s07.v1"
    {
        return Err("DURABLE_ENCLAVE_TRANSITION_INVALID".into());
    }
    let expected = enclave_transition_policy_hash(source, target, schema);
    if supplied_policy != expected {
        return Err("DURABLE_ENCLAVE_TRANSITION_INVALID".into());
    }
    if source != target && configured_transition_policy_hash() != Some(expected) {
        // Cross-PCR roll-forward is disabled unless the target EIF embeds the
        // exact reviewed source/target/schema policy commitment. Same-PCR
        // recovery remains available without a transition policy.
        return Err("DURABLE_ENCLAVE_TRANSITION_NOT_AUTHORIZED".into());
    }
    Ok(())
}

fn validate_request_context(
    request: &PlainRequest,
    context: &EncryptedOuterContext,
) -> Result<(), ()> {
    let (PlainRequest::User { command, .. }, EncryptedOuterContext::User(context)) =
        (request, context)
    else {
        return if matches!(
            (request, context),
            (
                PlainRequest::Operator { .. },
                EncryptedOuterContext::Operator
            )
        ) {
            Ok(())
        } else {
            Err(())
        };
    };
    let (
        actual_action,
        order_id,
        position_id,
        execution_id,
        withdrawal_id,
        transfer_id,
        session_tag,
    ) = match &command.action {
        UserCommandAction::SubmitOrder { .. } => (
            ExpectedEncryptedAction::Submit,
            None,
            None,
            None,
            None,
            None,
            None,
        ),
        UserCommandAction::ReplaceOrder { order_id, .. } => (
            ExpectedEncryptedAction::Replace,
            Some(*order_id),
            None,
            None,
            None,
            None,
            None,
        ),
        UserCommandAction::CancelOrder { order_id, .. } => (
            ExpectedEncryptedAction::Cancel,
            Some(*order_id),
            None,
            None,
            None,
            None,
            None,
        ),
        UserCommandAction::CancelAllOrders { .. } => (
            ExpectedEncryptedAction::CancelAll,
            None,
            None,
            None,
            None,
            None,
            None,
        ),
        UserCommandAction::PreviewPositionClose {
            position_id,
            session_tag,
            ..
        } => (
            ExpectedEncryptedAction::PreviewPositionClose,
            None,
            Some(position_id.as_str()),
            None,
            None,
            None,
            Some(session_tag.as_str()),
        ),
        UserCommandAction::ClosePosition {
            position_id,
            session_tag,
            ..
        } => (
            ExpectedEncryptedAction::ClosePosition,
            None,
            Some(position_id.as_str()),
            None,
            None,
            None,
            Some(session_tag.as_str()),
        ),
        UserCommandAction::CompleteSet { .. } => (
            ExpectedEncryptedAction::CompleteSet,
            None,
            None,
            None,
            None,
            None,
            None,
        ),
        UserCommandAction::Portfolio => (
            ExpectedEncryptedAction::Portfolio,
            None,
            None,
            None,
            None,
            None,
            None,
        ),
        UserCommandAction::Rewards => (
            ExpectedEncryptedAction::Rewards,
            None,
            None,
            None,
            None,
            None,
            None,
        ),
        UserCommandAction::RequestRewardClaim { .. } => (
            ExpectedEncryptedAction::RequestRewardClaim,
            None,
            None,
            None,
            None,
            None,
            None,
        ),
        UserCommandAction::BootstrapStatus { execution_id } => (
            ExpectedEncryptedAction::BootstrapStatus,
            None,
            None,
            Some(*execution_id),
            None,
            None,
            None,
        ),
        UserCommandAction::CancelBootstrap { execution_id } => (
            ExpectedEncryptedAction::CancelBootstrap,
            None,
            None,
            Some(*execution_id),
            None,
            None,
            None,
        ),
        UserCommandAction::RequestWithdrawal { withdrawal_id, .. } => (
            ExpectedEncryptedAction::RequestWithdrawal,
            None,
            None,
            None,
            Some(*withdrawal_id),
            None,
            None,
        ),
        UserCommandAction::TransferFunds { transfer_id, .. } => (
            ExpectedEncryptedAction::TransferFunds,
            None,
            None,
            None,
            None,
            Some(*transfer_id),
            None,
        ),
    };
    validate_bound_user_command_context(
        &command.idempotency_key,
        &command.session.request.session_id,
        actual_action,
        order_id,
        position_id,
        execution_id,
        withdrawal_id,
        transfer_id,
        session_tag,
        command.session.request.request_hash,
        context,
    )
}

fn trusted_nsm_now_millis(nsm_fd: i32, expected_pcr0: &[u8; 48]) -> Result<i64, ()> {
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    let response = nsm_process_request(
        nsm_fd,
        NsmRequest::Attestation {
            user_data: Some(TRUSTED_TIME_ATTESTATION_DOMAIN.to_vec().into()),
            nonce: Some(nonce.to_vec().into()),
            public_key: None,
        },
    );
    let NsmResponse::Attestation { document } = response else {
        return Err(());
    };
    parse_nsm_attestation_timestamp(
        &document,
        &nonce,
        TRUSTED_TIME_ATTESTATION_DOMAIN,
        expected_pcr0,
    )
}

/// Parses the timestamp from a document returned directly by the NSM device.
///
/// The caller must only pass bytes obtained synchronously from
/// `nsm_process_request`; accepting an arbitrary parent-provided document here
/// would require full certificate-chain and COSE signature verification. The
/// fresh nonce and purpose-specific user data additionally bind the document to
/// this exact clock read and prevent accidental reuse of another attestation.
fn parse_nsm_attestation_timestamp(
    document: &[u8],
    expected_nonce: &[u8],
    expected_user_data: &[u8],
    expected_pcr0: &[u8; 48],
) -> Result<i64, ()> {
    use serde_cbor::Value;

    let value: Value = serde_cbor::from_slice(document).map_err(|_| ())?;
    // NSM emits the standard untagged COSE_Sign1 array. Accept the optional
    // tag-18 wrapper as well, while rejecting every other tagged/value shape.
    let fields = match value {
        Value::Array(fields) => fields,
        Value::Tag(18, inner) => match *inner {
            Value::Array(fields) => fields,
            _ => return Err(()),
        },
        _ => return Err(()),
    };
    if fields.len() != 4 {
        return Err(());
    }
    let Value::Bytes(protected) = &fields[0] else {
        return Err(());
    };
    if !matches!(&fields[1], Value::Map(_)) {
        return Err(());
    }
    let Value::Map(protected) = serde_cbor::from_slice::<Value>(protected).map_err(|_| ())? else {
        return Err(());
    };
    if protected.get(&Value::Integer(1)) != Some(&Value::Integer(-35)) {
        return Err(());
    }
    let Value::Bytes(signature) = &fields[3] else {
        return Err(());
    };
    if signature.is_empty() {
        return Err(());
    }
    let Value::Bytes(payload) = &fields[2] else {
        return Err(());
    };
    let attestation = AttestationDoc::from_binary(payload).map_err(|_| ())?;
    if attestation.module_id.is_empty()
        || attestation.digest != NsmDigest::SHA384
        || attestation.nonce.as_ref().map(|value| value.as_ref()) != Some(expected_nonce)
        || attestation.user_data.as_ref().map(|value| value.as_ref()) != Some(expected_user_data)
        || attestation.pcrs.get(&0).map(|value| value.as_ref()) != Some(expected_pcr0.as_slice())
    {
        return Err(());
    }
    i64::try_from(attestation.timestamp).map_err(|_| ())
}

#[allow(clippy::too_many_arguments)]
fn validate_bound_user_command_context(
    idempotency_key: &str,
    session_id: &str,
    actual_action: ExpectedEncryptedAction,
    actual_order_id: Option<Uuid>,
    actual_position_id: Option<&str>,
    actual_execution_id: Option<Uuid>,
    actual_withdrawal_id: Option<Uuid>,
    actual_transfer_id: Option<Uuid>,
    actual_session_tag: Option<&str>,
    actual_command_commitment: [u8; 32],
    context: &EncryptedRequestContext,
) -> Result<(), ()> {
    let computed_session_tag = api_session_request_tag(idempotency_key, session_id);
    if idempotency_key != context.idempotency_key
        || !(1..=8).contains(&context.expected_session_tags.len())
        || context
            .expected_session_tags
            .iter()
            .collect::<HashSet<_>>()
            .len()
            != context.expected_session_tags.len()
        || !context
            .expected_session_tags
            .iter()
            .any(|tag| tag == &computed_session_tag)
    {
        return Err(());
    }
    let position_action = matches!(
        actual_action,
        ExpectedEncryptedAction::PreviewPositionClose | ExpectedEncryptedAction::ClosePosition
    );
    if position_action && actual_session_tag != Some(computed_session_tag.as_str()) {
        return Err(());
    }
    let Some(expected) = context.expected_command_commitment.as_deref() else {
        return Err(());
    };
    let Some(encoded) = expected.strip_prefix("0x") else {
        return Err(());
    };
    let mut decoded = [0u8; 32];
    if hex::decode_to_slice(encoded, &mut decoded).is_err() || decoded != actual_command_commitment
    {
        return Err(());
    }
    if context.expected_action != actual_action {
        return Err(());
    }
    let targets_match = match actual_action {
        ExpectedEncryptedAction::Submit
        | ExpectedEncryptedAction::CancelAll
        | ExpectedEncryptedAction::CompleteSet
        | ExpectedEncryptedAction::Portfolio
        | ExpectedEncryptedAction::Rewards
        | ExpectedEncryptedAction::RequestRewardClaim => {
            context.expected_order_id.is_none()
                && context.expected_position_id.is_none()
                && context.expected_execution_id.is_none()
                && context.expected_withdrawal_id.is_none()
                && context.expected_transfer_id.is_none()
        }
        ExpectedEncryptedAction::Replace | ExpectedEncryptedAction::Cancel => {
            context.expected_order_id == actual_order_id
                && actual_order_id.is_some()
                && context.expected_position_id.is_none()
                && context.expected_execution_id.is_none()
                && context.expected_withdrawal_id.is_none()
                && context.expected_transfer_id.is_none()
        }
        ExpectedEncryptedAction::PreviewPositionClose | ExpectedEncryptedAction::ClosePosition => {
            context.expected_order_id.is_none()
                && context.expected_position_id.as_deref() == actual_position_id
                && actual_position_id.is_some()
                && context.expected_execution_id.is_none()
                && context.expected_withdrawal_id.is_none()
                && context.expected_transfer_id.is_none()
        }
        ExpectedEncryptedAction::BootstrapStatus | ExpectedEncryptedAction::CancelBootstrap => {
            context.expected_order_id.is_none()
                && context.expected_position_id.is_none()
                && context.expected_execution_id == actual_execution_id
                && actual_execution_id.is_some()
                && context.expected_withdrawal_id.is_none()
                && context.expected_transfer_id.is_none()
        }
        ExpectedEncryptedAction::RequestWithdrawal => {
            context.expected_order_id.is_none()
                && context.expected_position_id.is_none()
                && context.expected_execution_id.is_none()
                && context.expected_withdrawal_id == actual_withdrawal_id
                && actual_withdrawal_id.is_some()
                && context.expected_transfer_id.is_none()
        }
        ExpectedEncryptedAction::TransferFunds => {
            context.expected_order_id.is_none()
                && context.expected_position_id.is_none()
                && context.expected_execution_id.is_none()
                && context.expected_withdrawal_id.is_none()
                && context.expected_transfer_id == actual_transfer_id
                && actual_transfer_id.is_some()
        }
    };
    targets_match.then_some(()).ok_or(())
}

#[cfg(test)]
fn validate_user_command_context(
    idempotency_key: &str,
    session_id: &str,
    actual_action: ExpectedEncryptedAction,
    actual_order_id: Option<Uuid>,
    actual_position_id: Option<&str>,
    context: &EncryptedRequestContext,
) -> Result<(), ()> {
    let session_tag = api_session_request_tag(idempotency_key, session_id);
    let actual_commitment = context
        .expected_command_commitment
        .as_deref()
        .and_then(|value| value.strip_prefix("0x"))
        .and_then(|value| {
            let mut decoded = [0u8; 32];
            hex::decode_to_slice(value, &mut decoded)
                .ok()
                .map(|_| decoded)
        })
        .unwrap_or([0u8; 32]);
    validate_bound_user_command_context(
        idempotency_key,
        session_id,
        actual_action,
        actual_order_id,
        actual_position_id,
        None,
        None,
        None,
        matches!(
            actual_action,
            ExpectedEncryptedAction::PreviewPositionClose | ExpectedEncryptedAction::ClosePosition
        )
        .then_some(session_tag.as_str()),
        actual_commitment,
        context,
    )
}

fn api_session_request_tag(idempotency_key: &str, session_id: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"layrs.api-session-context.v1\0");
    digest.update(idempotency_key.as_bytes());
    digest.update(b"\0");
    digest.update(session_id.as_bytes());
    URL_SAFE_NO_PAD.encode(digest.finalize())
}

fn serialize_depth(levels: Vec<(u64, u128)>) -> Vec<(u64, String)> {
    levels
        .into_iter()
        .map(|(price_micros, quantity_micros)| (price_micros, quantity_micros.to_string()))
        .collect()
}

async fn dispatch(
    state: &mut EnclaveState,
    request: PlainRequest,
    verified_now_millis: Option<i64>,
) -> PlainResponse {
    let result: Result<PlainResponse, String> = match request {
        PlainRequest::Operator { envelope } => {
            dispatch_operator(state, envelope, verified_now_millis).await
        }
        PlainRequest::User {
            command,
            now_millis: untrusted_client_now_millis,
        } => (|| -> Result<PlainResponse, String> {
            // Read and deliberately discard the client-carried field so the
            // wire remains backward compatible without ever authorizing time.
            let _ = untrusted_client_now_millis;
            let now_millis =
                verified_now_millis.ok_or_else(|| "TRUSTED_TIME_UNAVAILABLE".to_string())?;
            let core = state
                .core
                .as_ref()
                .ok_or_else(|| "NOT_PROVISIONED".to_string())?;
            ensure_market_execution_available(core, &command.action, state.polymarket.is_some())?;
            let recovery_command = command.clone();
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
                let authorization = signer.sign_reward_claim(intent)?;
                state
                    .core
                    .as_mut()
                    .ok_or_else(|| "NOT_PROVISIONED".to_string())?
                    .attach_reward_claim_authorization(&recovery_command, authorization.clone())
                    .map_err(|error| error.to_string())?;
                response.reward_claim_authorization = Some(authorization);
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
    result.unwrap_or_else(|code| PlainResponse::Error {
        code,
        receipt: None,
        receipt_state: None,
        receipt_disclosure_nonce: None,
    })
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
    verified_now_millis: Option<i64>,
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
    if direct_bootstrap_outcome_command(&envelope.command) {
        return Err("DIRECT_BOOTSTRAP_OUTCOME_MUTATION_FORBIDDEN".into());
    }

    match envelope.command {
        OperatorCommand::RecoverWithdrawalAuthorization {
            withdrawal_id,
            session_id,
            terminal_record,
            now_millis,
        } => {
            let core = state
                .core
                .as_ref()
                .ok_or_else(|| "NOT_PROVISIONED".to_string())?;
            let response = if let Some(record) = terminal_record {
                core.recover_terminal_withdrawal_authorization(
                    &record,
                    withdrawal_id,
                    &session_id,
                    now_millis,
                )
                .map_err(|error| error.to_string())?
            } else {
                core.recover_withdrawal_authorization(withdrawal_id, &session_id)
                    .map_err(|error| error.to_string())?
                    .ok_or_else(|| "WITHDRAWAL_RECOVERY_NOT_FOUND".to_string())?
            };
            Ok(PlainResponse::User {
                response: Box::new(response),
            })
        }
        OperatorCommand::PreparedCommandStatus {
            preparation_id,
            enclave_sequence,
            state_root,
        } => {
            let status = if state.core.as_ref().is_some_and(|core| {
                core.sequence() == enclave_sequence && core.state_root() == state_root
            }) {
                "FINALIZED"
            } else if state.pending_preparation.as_ref().is_some_and(|pending| {
                pending.preparation.preparation_id == preparation_id
                    && pending.preparation.enclave_sequence == enclave_sequence
                    && pending.preparation.state_root == state_root
            }) {
                "PREPARED"
            } else {
                "UNKNOWN"
            };
            Ok(PlainResponse::PreparedCommandStatus { state: status })
        }
        OperatorCommand::InspectPendingPreparation { idempotency_key } => {
            let observed_at_millis =
                verified_now_millis.ok_or_else(|| "TRUSTED_TIME_UNAVAILABLE".to_string())?;
            let core = state
                .core
                .as_ref()
                .ok_or_else(|| "NOT_PROVISIONED".to_string())?;
            let pending = state.pending_preparation.as_ref();
            let mut inspection = SignedPendingPreparationInspection {
                protocol_version: "layrs.pending-preparation-inspection.v1".into(),
                environment: recovery_environment().into(),
                enclave_measurement_sha384: state.enclave_measurement_sha384.to_vec(),
                request_idempotency_key: idempotency_key,
                preparation_id: pending.map(|value| value.preparation.preparation_id),
                pending_prior_enclave_sequence: pending
                    .map(|value| value.preparation.prior_enclave_sequence),
                pending_enclave_sequence: pending.map(|value| value.preparation.enclave_sequence),
                pending_prior_state_root: pending.map(|value| value.preparation.prior_state_root),
                pending_state_root: pending.map(|value| value.preparation.state_root),
                live_enclave_sequence: core.sequence(),
                live_state_root: core.state_root(),
                live_journal_head: core.journal_head(),
                observed_at_millis,
                signature: Vec::new(),
            };
            let signer = state
                .receipt_signer
                .as_ref()
                .ok_or_else(|| "RECEIPT_SIGNER_UNAVAILABLE".to_string())?;
            inspection.signature = signer
                .sign_domain_payload(b"layrs.pending-preparation-inspection.v1\0", &inspection);
            Ok(PlainResponse::PendingPreparationInspection { inspection })
        }
        OperatorCommand::AbortSupersededPreparation {
            idempotency_key,
            preparation_id,
            pending_enclave_sequence,
            pending_state_root,
            live_enclave_sequence,
            live_state_root,
            live_journal_head,
        } => {
            if let Some(previous) = state.last_preparation_supersession.as_ref() {
                if previous.request_idempotency_key == idempotency_key {
                    if preparation_supersession_matches_request(
                        previous,
                        &idempotency_key,
                        preparation_id,
                        pending_enclave_sequence,
                        pending_state_root,
                        live_enclave_sequence,
                        live_state_root,
                        live_journal_head,
                    ) {
                        return Ok(PlainResponse::PreparedCommandSuperseded {
                            certificate: previous.clone(),
                        });
                    }
                    return Err("DURABLE_SUPERSESSION_IDEMPOTENCY_CONFLICT".into());
                }
            }
            let superseded_at_millis =
                verified_now_millis.ok_or_else(|| "TRUSTED_TIME_UNAVAILABLE".to_string())?;
            let core = state
                .core
                .as_ref()
                .ok_or_else(|| "NOT_PROVISIONED".to_string())?;
            if core.sequence() != live_enclave_sequence
                || core.state_root() != live_state_root
                || core.journal_head() != live_journal_head
            {
                return Err("DURABLE_SUPERSESSION_LIVE_HEAD_CHANGED".into());
            }
            let pending = state
                .pending_preparation
                .as_ref()
                .ok_or_else(|| "DURABLE_PREPARATION_NOT_FOUND".to_string())?;
            if pending.preparation.preparation_id != preparation_id
                || pending.preparation.enclave_sequence != pending_enclave_sequence
                || pending.preparation.state_root != pending_state_root
            {
                return Err("DURABLE_SUPERSESSION_PREPARATION_MISMATCH".into());
            }
            if !pending_preparation_is_superseded(
                &pending.preparation,
                live_enclave_sequence,
                live_state_root,
            ) {
                return Err("DURABLE_PREPARATION_NOT_SUPERSEDED".into());
            }
            let mut certificate = SignedPreparationSupersession {
                protocol_version: "layrs.preparation-supersession.v1".into(),
                environment: recovery_environment().into(),
                enclave_measurement_sha384: state.enclave_measurement_sha384.to_vec(),
                request_idempotency_key: idempotency_key,
                preparation_id,
                pending_prior_enclave_sequence: pending.preparation.prior_enclave_sequence,
                pending_enclave_sequence,
                pending_prior_state_root: pending.preparation.prior_state_root,
                pending_state_root,
                live_enclave_sequence,
                live_state_root,
                live_journal_head,
                superseded_at_millis,
                signature: Vec::new(),
            };
            let signer = state
                .receipt_signer
                .as_ref()
                .ok_or_else(|| "RECEIPT_SIGNER_UNAVAILABLE".to_string())?;
            certificate.signature =
                signer.sign_domain_payload(b"layrs.preparation-supersession.v1\0", &certificate);
            // The pending candidate is cleared only after the encrypted
            // certificate has been constructed successfully in
            // `handle_encrypted`. Until then this is a read-only proof step.
            Ok(PlainResponse::PreparedCommandSuperseded { certificate })
        }
        OperatorCommand::FinalizePreparedCommand {
            preparation,
            snapshot,
            authorized_preparation_measurement_sha384,
            target_enclave_measurement_sha384,
            snapshot_schema,
            transition_policy_sha256,
        } => {
            verify_enclave_generation_transition(
                &authorized_preparation_measurement_sha384,
                &target_enclave_measurement_sha384,
                &state.enclave_measurement_sha384,
                &snapshot_schema,
                transition_policy_sha256,
            )?;
            verify_durable_preparation(
                &state.receipt_public_key,
                &authorized_preparation_measurement_sha384,
                &preparation,
                &snapshot,
            )?;
            let core = state
                .core
                .as_ref()
                .ok_or_else(|| "NOT_PROVISIONED".to_string())?;
            if core.sequence() == preparation.enclave_sequence
                && core.state_root() == preparation.state_root
            {
                if let Some(pending) = state.pending_preparation.take() {
                    if pending.preparation != preparation {
                        state.pending_preparation = Some(pending);
                        return Err("DURABLE_FINALIZE_PREPARATION_MISMATCH".into());
                    }
                }
                return Ok(PlainResponse::PreparedCommandFinalized {
                    preparation_id: preparation.preparation_id,
                    enclave_sequence: preparation.enclave_sequence,
                    state_root: preparation.state_root,
                });
            }
            if core.sequence() != preparation.prior_enclave_sequence
                || core.state_root() != preparation.prior_state_root
            {
                return Err("DURABLE_FINALIZE_HEAD_MISMATCH".into());
            }
            let candidate = match state.pending_preparation.take() {
                Some(pending)
                    if pending.preparation == preparation
                        && pending.writer_epoch == preparation.writer_epoch
                        && pending.writer_lease_id == preparation.writer_lease_id =>
                {
                    pending.core
                }
                Some(pending) => {
                    state.pending_preparation = Some(pending);
                    return Err("DURABLE_FINALIZE_PREPARATION_MISMATCH".into());
                }
                None => core
                    .restore_successor_snapshot(&snapshot)
                    .map_err(|_| "DURABLE_FINALIZE_SNAPSHOT_INVALID".to_string())?,
            };
            if candidate.sequence() != preparation.enclave_sequence
                || candidate.state_root() != preparation.state_root
            {
                return Err("DURABLE_FINALIZE_CANDIDATE_MISMATCH".into());
            }
            state.core = Some(candidate);
            Ok(PlainResponse::PreparedCommandFinalized {
                preparation_id: preparation.preparation_id,
                enclave_sequence: preparation.enclave_sequence,
                state_root: preparation.state_root,
            })
        }
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
            // The incident terminal-restore command remains available and
            // exact-policy bound, but normal production restarts must still be
            // able to provision from the durable bootstrap key plus the latest
            // authorized snapshot. Disabling generic provisioning here makes a
            // healthy enclave load-balancer target permanently unusable for
            // normal private order flow.
            ensure_generic_provisioning_allowed()?;
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
            let mut journal_key: [u8; 32] = match plaintext.as_slice().try_into() {
                Ok(key) => key,
                Err(_) => {
                    plaintext.zeroize();
                    return Err("INVALID_KMS_KEY_MATERIAL".into());
                }
            };
            plaintext.zeroize();
            let key = JournalKey::from_bytes(journal_key);
            journal_key.zeroize();
            let mut receipt_seed = key.derive(b"receipt-signing-key-v1");
            let signer = ReceiptSigner::from_seed(receipt_seed, state.enclave_measurement_sha384);
            receipt_seed.zeroize();
            state.receipt_public_key = signer.verifying_key();
            // Durable preparation signatures must survive an EIF restart. The
            // signer is deterministically derived from the KMS-unsealed journal
            // key, and this wrapper clone never leaves enclave memory.
            state.receipt_signer = Some(signer.clone());
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
        OperatorCommand::BeginIncidentTerminalRestore {
            kms_key_id,
            kms_ciphertext_blob,
            snapshot_descriptor,
            mut snapshot_body,
            external_challenge,
            certifier_release_manifest_sha256,
            expected_certifier_pcr0_sha384,
        } => {
            if state.core.is_some()
                || state.pending_provision.is_some()
                || state.pending_incident_terminal_restore.is_some()
            {
                snapshot_body.zeroize();
                return Err("INCIDENT_RESTORE_ALREADY_STARTED".into());
            }
            if kms_key_id.is_empty()
                || kms_key_id.len() > 2_048
                || !kms_key_id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b":/_-".contains(&byte))
                || kms_ciphertext_blob.is_empty()
                || kms_ciphertext_blob.len() > 65_536
                || external_challenge == [0; 32]
                || certifier_release_manifest_sha256 == [0; 32]
            {
                snapshot_body.zeroize();
                return Err("INCIDENT_RESTORE_REQUEST_INVALID".into());
            }
            let expected_certifier_pcr0_sha384: [u8; 48] = match expected_certifier_pcr0_sha384
                .as_slice()
                .try_into()
            {
                Ok(value) if value != [0; 48] && value == state.enclave_measurement_sha384 => value,
                _ => {
                    snapshot_body.zeroize();
                    return Err("INCIDENT_RESTORE_REQUEST_INVALID".into());
                }
            };
            let validated = validate_incident_terminal_input(&snapshot_descriptor, &snapshot_body);
            snapshot_body.zeroize();
            let (policy_sha256, snapshot_body_sha256, snapshot) = validated?;

            let (recipient_private_key, recipient_public_key) = generate_recipient_key()?;
            let mut binding = Vec::with_capacity(320);
            binding.extend_from_slice(b"layrs.incident-kms-recipient.v1\0");
            binding.extend_from_slice(&policy_sha256);
            binding.extend_from_slice(&snapshot_body_sha256);
            binding.extend_from_slice(&Sha256::digest(snapshot_descriptor.bucket.as_bytes()));
            binding.extend_from_slice(&Sha256::digest(snapshot_descriptor.key.as_bytes()));
            binding.extend_from_slice(&Sha256::digest(snapshot_descriptor.version_id.as_bytes()));
            binding.extend_from_slice(&snapshot_descriptor.size_bytes.to_be_bytes());
            binding.extend_from_slice(&Sha256::digest(kms_key_id.as_bytes()));
            binding.extend_from_slice(&Sha256::digest(&kms_ciphertext_blob));
            binding.extend_from_slice(&certifier_release_manifest_sha256);
            binding.extend_from_slice(&expected_certifier_pcr0_sha384);
            binding.extend_from_slice(&external_challenge);
            let attestation_document = match nsm_process_request(
                state.nsm_fd,
                NsmRequest::Attestation {
                    user_data: Some(binding.into()),
                    nonce: Some(external_challenge.to_vec().into()),
                    public_key: Some(recipient_public_key.into()),
                },
            ) {
                NsmResponse::Attestation { document } => document,
                _ => return Err("INCIDENT_KMS_RECIPIENT_ATTESTATION_FAILED".into()),
            };
            state.pending_incident_terminal_restore = Some(PendingIncidentTerminalRestore {
                recipient_private_key,
                snapshot,
                snapshot_descriptor,
                policy_sha256,
                snapshot_body_sha256,
                external_challenge,
                certifier_release_manifest_sha256,
                expected_certifier_pcr0_sha384,
            });
            Ok(PlainResponse::KmsRecipientRequest {
                attestation_document,
                kms_key_id,
                operation: "DECRYPT",
                kms_ciphertext_blob: Some(kms_ciphertext_blob),
                key_encryption_algorithm: "RSAES_OAEP_SHA_256",
            })
        }
        OperatorCommand::CompleteIncidentTerminalRestore {
            ciphertext_for_recipient,
        } => {
            if state.core.is_some() {
                return Err("INCIDENT_RESTORE_ALREADY_CERTIFIED".into());
            }
            if ciphertext_for_recipient.is_empty() || ciphertext_for_recipient.len() > 4_096 {
                return Err("INVALID_RECIPIENT_CIPHERTEXT".into());
            }
            let pending = state
                .pending_incident_terminal_restore
                .take()
                .ok_or_else(|| "NO_PENDING_INCIDENT_RESTORE".to_string())?;
            if pending.expected_certifier_pcr0_sha384 != state.enclave_measurement_sha384 {
                return Err("INCIDENT_CERTIFIER_PCR_MISMATCH".into());
            }
            let mut plaintext =
                decrypt_recipient_key(pending.recipient_private_key, &ciphertext_for_recipient)?;
            let mut journal_key: [u8; 32] = match plaintext.as_slice().try_into() {
                Ok(key) => key,
                Err(_) => {
                    plaintext.zeroize();
                    return Err("INVALID_KMS_KEY_MATERIAL".into());
                }
            };
            plaintext.zeroize();
            let key = JournalKey::from_bytes(journal_key);
            journal_key.zeroize();
            let mut receipt_seed = key.derive(b"receipt-signing-key-v1");
            let signer = ReceiptSigner::from_seed(receipt_seed, state.enclave_measurement_sha384);
            receipt_seed.zeroize();
            let (restored, terminal_state) =
                PrivateTradingCore::restore_exact_incident_terminal_snapshot(
                    key,
                    signer.clone(),
                    &pending.snapshot,
                )
                .map_err(|_| "INCIDENT_TERMINAL_RESTORE_FAILED".to_string())?;
            let certificate = IncidentTerminalCertificationReport {
                schema_version: "layrs.incident-terminal-certification.v1".into(),
                incident_id: INCIDENT_ID.into(),
                incident_policy_sha256: hex::encode(pending.policy_sha256),
                snapshot_bucket: pending.snapshot_descriptor.bucket.clone(),
                snapshot_key: pending.snapshot_descriptor.key.clone(),
                snapshot_version_id: pending.snapshot_descriptor.version_id.clone(),
                snapshot_size_bytes: pending.snapshot_descriptor.size_bytes,
                snapshot_body_sha256: hex::encode(pending.snapshot_body_sha256),
                certifier_release_manifest_sha256: hex::encode(
                    pending.certifier_release_manifest_sha256,
                ),
                artifact_equal: true,
                policy_equal: true,
                source_release_equal: true,
                certifier_pcr0_equal: true,
                terminal_state,
            };
            let certificate_bytes = serde_json::to_vec(&certificate)
                .map_err(|_| "INCIDENT_CERTIFICATE_ENCODING_FAILED".to_string())?;
            let certificate_sha256: [u8; 32] = Sha256::digest(&certificate_bytes).into();
            let artifact_binding_sha256 = incident_artifact_binding(
                pending.policy_sha256,
                pending.snapshot_body_sha256,
                &pending.snapshot_descriptor,
                pending.certifier_release_manifest_sha256,
                state.enclave_measurement_sha384,
                pending.external_challenge,
                certificate_sha256,
            );
            let attestation_document = match nsm_process_request(
                state.nsm_fd,
                NsmRequest::Attestation {
                    user_data: Some(certificate_sha256.to_vec().into()),
                    nonce: Some(artifact_binding_sha256.to_vec().into()),
                    public_key: None,
                },
            ) {
                NsmResponse::Attestation { document } => document,
                _ => return Err("INCIDENT_CERTIFICATE_ATTESTATION_FAILED".into()),
            };
            let attestation_document_sha256 = Sha256::digest(&attestation_document);
            state.receipt_public_key = signer.verifying_key();
            state.receipt_signer = Some(signer);
            state.core = Some(restored);
            state.incident_restore_floor = Some(INCIDENT_TERMINAL_SEQUENCE);
            Ok(PlainResponse::IncidentTerminalRestoreCertified {
                envelope: IncidentTerminalCertificationEnvelope {
                    certificate,
                    certificate_sha256: hex::encode(certificate_sha256),
                    artifact_binding_sha256: hex::encode(artifact_binding_sha256),
                    attestation_document_sha256: hex::encode(attestation_document_sha256),
                    attestation_document,
                },
            })
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
                UnsignedResolutionEvidence::Binance(statement) => {
                    let market_id = statement.market_id.clone();
                    let payload = binance_resolution_signing_payload(&statement)
                        .map_err(|error| error.to_string())?;
                    let outcome = if let Some(outcome) = statement.outcome {
                        outcome
                    } else {
                        let opening = statement
                            .opening
                            .as_ref()
                            .ok_or_else(|| "INVALID_BINANCE_RESOLUTION_EVIDENCE".to_string())?;
                        let closing = statement
                            .closing
                            .as_ref()
                            .ok_or_else(|| "INVALID_BINANCE_RESOLUTION_EVIDENCE".to_string())?;
                        clob_service::private_core::derive_resolution_outcome(
                            opening.median_price_e8,
                            closing.median_price_e8,
                        )
                    };
                    let signed = SignedResolutionEvidence::Binance(SignedBinanceResolution {
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
            now_millis,
            ..
        } => {
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
            let prepared = state
                .polymarket
                .as_ref()
                .ok_or_else(|| "POLYMARKET_NOT_PROVISIONED".to_string())?
                .prepare_fok(&venue)
                .await?;
            let response = state
                .core
                .as_mut()
                .ok_or_else(|| "NOT_PROVISIONED".to_string())?
                .mark_bootstrap_venue_intent_durable(
                    idempotency_key,
                    execution_id,
                    BootstrapPreparedVenueOrder {
                        deterministic_order_id: prepared.deterministic_order_id,
                        exact_request_body: prepared.exact_request_body,
                        request_body_sha256: prepared.request_body_sha256,
                        credential_generation_sha256: prepared.credential_generation_sha256,
                    },
                    now_millis,
                )
                .map_err(|error| error.to_string())?;
            Ok(PlainResponse::System { response })
        }
        OperatorCommand::AuthorizeBootstrapSubmission {
            idempotency_key,
            execution_id,
            now_millis,
        } => {
            let response = state
                .core
                .as_mut()
                .ok_or_else(|| "NOT_PROVISIONED".to_string())?
                .authorize_bootstrap_submission_attempt(idempotency_key, execution_id, now_millis)
                .map_err(|error| error.to_string())?;
            Ok(PlainResponse::System { response })
        }
        OperatorCommand::SubmitPreparedBootstrap {
            idempotency_key,
            execution_id,
            timestamp_seconds,
            now_millis,
        } => {
            let client = state
                .polymarket
                .as_ref()
                .ok_or_else(|| "POLYMARKET_NOT_PROVISIONED".to_string())?;
            let prepared = state
                .core
                .as_ref()
                .ok_or_else(|| "NOT_PROVISIONED".to_string())?
                .bootstrap_prepared_venue_order(execution_id)
                .map_err(|error| error.to_string())?;
            let (submitted, _) = client
                .submit_prepared_fok(
                    &PreparedPolymarketOrder {
                        deterministic_order_id: prepared.deterministic_order_id,
                        exact_request_body: prepared.exact_request_body,
                        request_body_sha256: prepared.request_body_sha256,
                        credential_generation_sha256: prepared.credential_generation_sha256,
                    },
                    timestamp_seconds,
                )
                .await?;
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
        OperatorCommand::ObserveBootstrapSubmission {
            idempotency_key,
            execution_id,
            timestamp_seconds,
            now_millis,
        } => {
            let order_id = state
                .core
                .as_ref()
                .ok_or_else(|| "NOT_PROVISIONED".to_string())?
                .bootstrap_venue_order_id(execution_id)
                .map_err(|error| error.to_string())?;
            match state
                .polymarket
                .as_ref()
                .ok_or_else(|| "POLYMARKET_NOT_PROVISIONED".to_string())?
                .observe_order(&order_id, timestamp_seconds)
                .await?
            {
                VenueOrderObservation::Found => {
                    let response = state
                        .core
                        .as_mut()
                        .expect("core checked")
                        .mark_bootstrap_submitted(
                            idempotency_key,
                            execution_id,
                            order_id,
                            now_millis,
                        )
                        .map_err(|error| error.to_string())?;
                    Ok(PlainResponse::System { response })
                }
                VenueOrderObservation::AuthoritativelyAbsent => {
                    Ok(PlainResponse::BootstrapPending { execution_id })
                }
            }
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
        OperatorCommand::CustodyReconciliationSnapshot {
            checkpoint_commitment,
            chain_finality_commitments,
        } => state
            .core
            .as_ref()
            .ok_or_else(|| "NOT_PROVISIONED".to_string())?
            .custody_reconciliation_snapshot(checkpoint_commitment, chain_finality_commitments)
            .map(|snapshot| PlainResponse::CustodyReconciliationSnapshot { snapshot })
            .map_err(|error| error.to_string()),
        OperatorCommand::TransferAccountStatus {
            identity_commitment,
        } => {
            let status = state
                .core
                .as_ref()
                .ok_or_else(|| "NOT_PROVISIONED".to_string())?
                .transfer_account_status(identity_commitment);
            Ok(PlainResponse::TransferAccountStatus {
                transfer_account: status.transfer_account,
                registered: status.registered,
            })
        }
        OperatorCommand::DelegatedPortfolioRead {
            request_id,
            identity_commitment,
            response_public_key,
            projection,
            api_key_id,
            capability_jti,
            capability_token_sha256,
            capability_environment,
            capability_audience,
            capability_scope,
            issued_at_millis,
            expires_at_millis,
            revocation_checked_at_millis,
            now_millis,
        } => {
            validate_delegated_read_authorization(
                projection,
                &capability_environment,
                &capability_audience,
                &capability_scope,
                issued_at_millis,
                expires_at_millis,
                revocation_checked_at_millis,
                now_millis,
            )?;
            let core = state
                .core
                .as_ref()
                .ok_or_else(|| "NOT_PROVISIONED".to_string())?;
            let snapshot = core.portfolio_snapshot_for_identity(identity_commitment, now_millis);
            let items = match projection {
                DelegatedReadProjection::Balances => serde_json::to_value(snapshot.balances),
                DelegatedReadProjection::Positions => serde_json::to_value(snapshot.positions),
                DelegatedReadProjection::ActiveOrders => serde_json::to_value(
                    snapshot
                        .orders
                        .into_iter()
                        .filter(|order| {
                            matches!(
                                order.status,
                                OrderStatus::Open | OrderStatus::PartiallyFilled
                            )
                        })
                        .collect::<Vec<_>>(),
                ),
            }
            .map_err(|_| "DELEGATED_READ_ENCODING_FAILED".to_string())?;
            let plaintext = DelegatedReadPlaintext {
                protocol_version: "layrs.delegated-private-read.v1",
                request_id,
                projection: projection.label(),
                enclave_sequence: core.sequence().to_string(),
                as_of_millis: snapshot.as_of_millis,
                items,
            };
            let envelope = encrypt_delegated_read(
                &plaintext,
                response_public_key,
                projection,
                api_key_id,
                capability_jti,
                capability_token_sha256,
                expires_at_millis,
            )?;
            Ok(PlainResponse::DelegatedPortfolioRead { envelope })
        }
        OperatorCommand::TradingFreezeStatus => Ok(PlainResponse::TradingFreezeStatus {
            frozen: state
                .core
                .as_ref()
                .ok_or_else(|| "NOT_PROVISIONED".to_string())?
                .trading_frozen(),
        }),
        OperatorCommand::RecoveryArchiveAckStatus {
            command_idempotency_key,
            result_digest,
            archive_row_commitment,
            environment,
        } => {
            if environment != recovery_environment() {
                return Err("RECOVERY_ARCHIVE_ENVIRONMENT_MISMATCH".into());
            }
            Ok(PlainResponse::RecoveryArchiveAckStatus {
                acknowledged: state
                    .core
                    .as_ref()
                    .ok_or_else(|| "NOT_PROVISIONED".to_string())?
                    .recovery_archive_acknowledged(
                        &command_idempotency_key,
                        result_digest,
                        archive_row_commitment,
                    ),
            })
        }
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
                OperatorCommand::AcknowledgeRecoveryArchive {
                    idempotency_key,
                    command_idempotency_key,
                    result_digest,
                    archive_row_commitment,
                    environment,
                    recovery_artifact,
                    now_millis,
                } => {
                    if environment != recovery_environment() {
                        return Err("RECOVERY_ARCHIVE_ENVIRONMENT_MISMATCH".into());
                    }
                    let expected_artifact = core.signed_recovery_bridge_artifact(
                        &command_idempotency_key,
                        &environment,
                        recovery_artifact.response_envelope_sha256,
                        recovery_artifact.response_envelope_bytes,
                    );
                    if expected_artifact.as_ref() != Some(&recovery_artifact)
                        || recovery_artifact.result_digest != result_digest
                    {
                        return Err("RECOVERY_ARCHIVE_PROOF_INVALID".into());
                    }
                    core.acknowledge_recovery_archive(
                        idempotency_key,
                        command_idempotency_key,
                        result_digest,
                        archive_row_commitment,
                        now_millis,
                    )
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
                OperatorCommand::RegisterTransferAccount {
                    idempotency_key,
                    identity_commitment,
                    now_millis,
                } => {
                    core.register_transfer_account(idempotency_key, identity_commitment, now_millis)
                }
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
                OperatorCommand::VaultStrategyTransition {
                    idempotency_key,
                    evidence_hash,
                    vault_commitment,
                    strategy_commitment,
                    operation_commitment,
                    asset,
                    amount_atomic,
                    transition,
                    now_millis,
                } => core.apply_vault_strategy_transition(
                    idempotency_key,
                    evidence_hash,
                    vault_commitment,
                    strategy_commitment,
                    operation_commitment,
                    asset,
                    amount_atomic,
                    transition,
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
                    source_id_hash,
                    program_id,
                    program_type,
                    policy_id,
                    policy_version,
                    fee_policy_version,
                    now_millis,
                } => core.accrue_private_reward(
                    idempotency_key,
                    identity_commitment,
                    chain,
                    reward_token,
                    amount_atomic,
                    evidence_hash,
                    source_id_hash,
                    program_id,
                    program_type,
                    policy_id,
                    policy_version,
                    fee_policy_version,
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
                OperatorCommand::ResolveBinanceMarket {
                    idempotency_key,
                    signed,
                    now_millis,
                } => core.resolve_binance_market(idempotency_key, signed, now_millis),
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
                OperatorCommand::MarkBootstrapSubmitted { .. }
                | OperatorCommand::ConfirmBootstrapFill { .. }
                | OperatorCommand::FailBootstrapExecution { .. } => {
                    return Err("DIRECT_BOOTSTRAP_OUTCOME_MUTATION_FORBIDDEN".into());
                }
                OperatorCommand::ExportSnapshot => {
                    return core
                        .export_encrypted_snapshot()
                        .map(|snapshot| PlainResponse::Snapshot { snapshot })
                        .map_err(|error| error.to_string());
                }
                OperatorCommand::BeginProvision { .. }
                | OperatorCommand::BeginIncidentTerminalRestore { .. }
                | OperatorCommand::RecoverWithdrawalAuthorization { .. }
                | OperatorCommand::PreparedCommandStatus { .. }
                | OperatorCommand::InspectPendingPreparation { .. }
                | OperatorCommand::AbortSupersededPreparation { .. }
                | OperatorCommand::FinalizePreparedCommand { .. }
                | OperatorCommand::CompleteProvision { .. }
                | OperatorCommand::CompleteIncidentTerminalRestore { .. }
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
                | OperatorCommand::AuthorizeBootstrapSubmission { .. }
                | OperatorCommand::SubmitPreparedBootstrap { .. }
                | OperatorCommand::ObserveBootstrapSubmission { .. }
                | OperatorCommand::BootstrapExecutionStatus { .. }
                | OperatorCommand::MarketStatus { .. }
                | OperatorCommand::ResolutionStatus { .. }
                | OperatorCommand::ResolutionReadiness { .. }
                | OperatorCommand::CustodyReconciliationSnapshot { .. }
                | OperatorCommand::TransferAccountStatus { .. }
                | OperatorCommand::DelegatedPortfolioRead { .. }
                | OperatorCommand::TradingFreezeStatus
                | OperatorCommand::RecoveryArchiveAckStatus { .. }
                | OperatorCommand::AggregateDepth { .. }
                | OperatorCommand::ReconcileBootstrap { .. } => unreachable!(),
            }
            .map_err(|error| error.to_string())?;
            Ok(PlainResponse::System { response })
        }
    }
}

fn direct_bootstrap_outcome_command(command: &OperatorCommand) -> bool {
    matches!(
        command,
        OperatorCommand::MarkBootstrapSubmitted { .. }
            | OperatorCommand::ConfirmBootstrapFill { .. }
            | OperatorCommand::FailBootstrapExecution { .. }
    )
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

const DELEGATED_READ_MAX_LIFETIME_MILLIS: i64 = 5 * 60_000;
const DELEGATED_READ_MIN_LIFETIME_MILLIS: i64 = 30_000;
const DELEGATED_READ_CLOCK_SKEW_MILLIS: i64 = 5_000;
const DELEGATED_READ_MAX_REVOCATION_AGE_MILLIS: i64 = 10_000;
// Reserve the 16-byte GCM tag so the complete ciphertext remains within the
// public API and Cloudflare 1 MiB response boundary.
const DELEGATED_READ_MAX_PLAINTEXT_BYTES: usize = 1_048_576 - 16;

#[allow(clippy::too_many_arguments)]
fn validate_delegated_read_authorization(
    projection: DelegatedReadProjection,
    environment: &str,
    audience: &str,
    scope: &str,
    issued_at_millis: i64,
    expires_at_millis: i64,
    revocation_checked_at_millis: i64,
    now_millis: i64,
) -> Result<(), String> {
    let expected_audience = match environment {
        "development" => "https://api-dev.layrs.xyz/mcp",
        "staging" => "https://api-staging.layrs.xyz/mcp",
        "production" => "https://api.layrs.xyz/mcp",
        _ => return Err("DELEGATED_READ_CONTEXT_MISMATCH".into()),
    };
    if audience != expected_audience || scope != projection.required_scope() {
        return Err("DELEGATED_READ_CONTEXT_MISMATCH".into());
    }
    let lifetime = expires_at_millis
        .checked_sub(issued_at_millis)
        .ok_or_else(|| "DELEGATED_READ_EXPIRED".to_string())?;
    if !(DELEGATED_READ_MIN_LIFETIME_MILLIS..=DELEGATED_READ_MAX_LIFETIME_MILLIS)
        .contains(&lifetime)
        || issued_at_millis > now_millis.saturating_add(DELEGATED_READ_CLOCK_SKEW_MILLIS)
        || expires_at_millis <= now_millis
    {
        return Err("DELEGATED_READ_EXPIRED".into());
    }
    if revocation_checked_at_millis < issued_at_millis
        || revocation_checked_at_millis
            > now_millis.saturating_add(DELEGATED_READ_CLOCK_SKEW_MILLIS)
        || now_millis.saturating_sub(revocation_checked_at_millis)
            > DELEGATED_READ_MAX_REVOCATION_AGE_MILLIS
    {
        return Err("DELEGATED_READ_REVOCATION_STALE".into());
    }
    Ok(())
}

fn encrypt_delegated_read<T: Serialize>(
    plaintext: &DelegatedReadPlaintext<T>,
    response_public_key: [u8; 32],
    projection: DelegatedReadProjection,
    api_key_id: uuid::Uuid,
    capability_jti: uuid::Uuid,
    capability_token_sha256: [u8; 32],
    expires_at_millis: i64,
) -> Result<EncryptedDelegatedRead, String> {
    if capability_token_sha256 == [0u8; 32] {
        return Err("INVALID_DELEGATED_READ_CAPABILITY".into());
    }
    let ephemeral_secret = StaticSecret::random();
    let ephemeral_public_key = PublicKey::from(&ephemeral_secret).to_bytes();
    let shared = ephemeral_secret.diffie_hellman(&PublicKey::from(response_public_key));
    if shared.as_bytes() == &[0u8; 32] {
        return Err("INVALID_DELEGATED_READ_RESPONSE_KEY".into());
    }
    let mut key: [u8; 32] = {
        let mut hash = Sha256::new();
        hash.update(b"layrs.delegated-private-read.key.v1\0");
        hash.update(shared.as_bytes());
        hash.update(plaintext.request_id.as_bytes());
        hash.update(api_key_id.as_bytes());
        hash.update(capability_jti.as_bytes());
        hash.update(capability_token_sha256);
        hash.update(response_public_key);
        hash.update(ephemeral_public_key);
        hash.finalize().into()
    };
    let aad = delegated_read_aad(
        plaintext.request_id,
        projection,
        api_key_id,
        capability_jti,
        capability_token_sha256,
        response_public_key,
        ephemeral_public_key,
        expires_at_millis,
    );
    let mut encoded =
        serde_json::to_vec(plaintext).map_err(|_| "DELEGATED_READ_ENCODING_FAILED".to_string())?;
    if encoded.len() > DELEGATED_READ_MAX_PLAINTEXT_BYTES {
        encoded.zeroize();
        key.zeroize();
        return Err("DELEGATED_READ_RESPONSE_TOO_LARGE".into());
    }
    let cipher = Aes256Gcm::new_from_slice(&key).expect("AES-256 key size is fixed");
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher.encrypt(
        Nonce::from_slice(&nonce),
        aes_gcm::aead::Payload {
            msg: &encoded,
            aad: &aad,
        },
    );
    encoded.zeroize();
    key.zeroize();
    let ciphertext = ciphertext.map_err(|_| "DELEGATED_READ_ENCRYPTION_FAILED".to_string())?;
    let ciphertext_sha256 = Sha256::digest(&ciphertext).into();
    Ok(EncryptedDelegatedRead {
        protocol_version: "layrs.delegated-private-read-envelope.v1",
        request_id: plaintext.request_id,
        projection: plaintext.projection,
        enclave_sequence: plaintext.enclave_sequence.clone(),
        as_of_millis: plaintext.as_of_millis,
        expires_at_millis,
        ephemeral_public_key,
        nonce,
        ciphertext,
        ciphertext_sha256,
    })
}

#[allow(clippy::too_many_arguments)]
fn delegated_read_aad(
    request_id: uuid::Uuid,
    projection: DelegatedReadProjection,
    api_key_id: uuid::Uuid,
    capability_jti: uuid::Uuid,
    capability_token_sha256: [u8; 32],
    response_public_key: [u8; 32],
    ephemeral_public_key: [u8; 32],
    expires_at_millis: i64,
) -> Vec<u8> {
    let mut aad = b"layrs.delegated-private-read.aad.v1\0".to_vec();
    aad.extend_from_slice(request_id.as_bytes());
    aad.extend_from_slice(projection.label().as_bytes());
    aad.push(0);
    aad.extend_from_slice(api_key_id.as_bytes());
    aad.extend_from_slice(capability_jti.as_bytes());
    aad.extend_from_slice(&capability_token_sha256);
    aad.extend_from_slice(&response_public_key);
    aad.extend_from_slice(&ephemeral_public_key);
    aad.extend_from_slice(&expires_at_millis.to_be_bytes());
    aad
}

fn request_aad(
    client: &[u8; 32],
    enclave: &[u8; 32],
    access_capability: Option<AccessCapability>,
) -> Vec<u8> {
    let mut aad = b"layrs.enclave-request.v1\0".to_vec();
    aad.extend_from_slice(client);
    aad.extend_from_slice(enclave);
    if let Some(capability) = access_capability {
        aad.extend_from_slice(b"\0layrs.access-capability.v1\0");
        aad.extend_from_slice(capability.aad_label());
    }
    aad
}

fn expected_access_capability(request: &PlainRequest) -> AccessCapability {
    match request {
        PlainRequest::User { command, .. } => expected_user_access_capability(&command.action),
        PlainRequest::AggregateDepth { .. } => AccessCapability::PublicData,
        PlainRequest::Operator { .. } => AccessCapability::PrivateApiMutations,
    }
}

fn expected_user_access_capability(action: &UserCommandAction) -> AccessCapability {
    match action {
        UserCommandAction::SubmitOrder { .. } | UserCommandAction::ReplaceOrder { .. } => {
            AccessCapability::NewOrders
        }
        UserCommandAction::CancelOrder { .. }
        | UserCommandAction::CancelAllOrders { .. }
        | UserCommandAction::CancelBootstrap { .. } => AccessCapability::OrderCancellation,
        UserCommandAction::ClosePosition { .. } => AccessCapability::PositionReduction,
        UserCommandAction::CompleteSet { direction, .. } => match direction {
            clob_service::private_core::CompleteSetDirection::Mint => AccessCapability::NewOrders,
            clob_service::private_core::CompleteSetDirection::Burn => {
                AccessCapability::PositionReduction
            }
        },
        UserCommandAction::Portfolio
        | UserCommandAction::Rewards
        | UserCommandAction::PreviewPositionClose { .. }
        | UserCommandAction::BootstrapStatus { .. } => AccessCapability::AccountRead,
        UserCommandAction::RequestRewardClaim { .. } => AccessCapability::Redemptions,
        UserCommandAction::RequestWithdrawal { .. } => AccessCapability::Withdrawals,
        UserCommandAction::TransferFunds { .. } => AccessCapability::PrivateApiMutations,
    }
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
    use clob_service::private_core::{
        ExactTerminalCategoryCounts, ExactTerminalCategoryDigests, ExactTerminalCategoryEquality,
        FeeProfileId,
    };
    use serde_cbor::Value;
    use std::collections::BTreeMap;

    fn exact_incident_descriptor() -> IncidentSnapshotDescriptor {
        IncidentSnapshotDescriptor {
            bucket: INCIDENT_SNAPSHOT_BUCKET.into(),
            key: INCIDENT_SNAPSHOT_KEY.into(),
            version_id: INCIDENT_SNAPSHOT_VERSION_ID.into(),
            size_bytes: INCIDENT_SNAPSHOT_SIZE_BYTES,
            body_sha256: INCIDENT_SNAPSHOT_BODY_SHA256_HEX.into(),
        }
    }

    fn empty_terminal_state_report() -> ExactTerminalSnapshotRestoreReport {
        ExactTerminalSnapshotRestoreReport {
            source_release_commit: EXACT_LIVE_976_RELEASE_COMMIT.into(),
            restored_sequence: INCIDENT_TERMINAL_SEQUENCE,
            restored_state_root: INCIDENT_TERMINAL_STATE_ROOT_HEX.into(),
            restored_journal_head: INCIDENT_TERMINAL_JOURNAL_HEAD_HEX.into(),
            snapshot_ciphertext_sha256: INCIDENT_TERMINAL_CIPHERTEXT_SHA256_HEX.into(),
            aggregate_bucket_totals: Vec::new(),
            aggregate_asset_totals: Vec::new(),
            category_counts: ExactTerminalCategoryCounts {
                user_count: 0,
                registered_session_count: 0,
                sequenced_session_count: 0,
                ledger_record_count: 0,
                position_cost_basis_count: 0,
                order_count: 0,
                market_count: 0,
                resolution_count: 0,
                processed_command_count: 0,
                system_key_count: 0,
                aggregate_bucket_total_count: 0,
                aggregate_asset_total_count: 0,
            },
            category_digests: ExactTerminalCategoryDigests {
                users_and_sessions_sha256: "00".repeat(32),
                available_balances_sha256: "00".repeat(32),
                order_holds_sha256: "00".repeat(32),
                withdrawal_holds_sha256: "00".repeat(32),
                positions_and_cost_basis_sha256: "00".repeat(32),
                order_books_sha256: "00".repeat(32),
                snapshot_fill_state_sha256: "00".repeat(32),
                resolutions_sha256: "00".repeat(32),
                rewards_sha256: "00".repeat(32),
                fees_sha256: "00".repeat(32),
                markets_sha256: "00".repeat(32),
                replay_state_sha256: "00".repeat(32),
                custody_qualified_totals_sha256: "00".repeat(32),
                composite_user_state_sha256: "00".repeat(32),
            },
            category_equality: ExactTerminalCategoryEquality {
                users_and_sessions_equal: true,
                available_balances_equal: true,
                order_holds_equal: true,
                withdrawal_holds_equal: true,
                positions_and_cost_basis_equal: true,
                order_books_equal: true,
                snapshot_fill_state_equal: true,
                resolutions_equal: true,
                rewards_equal: true,
                fees_equal: true,
                markets_equal: true,
                replay_state_equal: true,
                custody_qualified_totals_equal: true,
                composite_user_state_equal: true,
            },
            sequence_equal: true,
            state_root_equal: true,
            journal_head_equal: true,
            aggregate_totals_equal: true,
            aggregate_totals_zero_delta: true,
            restore_floor_persisted: true,
            no_external_state_mutation_performed: true,
            pool_cash_opening_required: false,
            historical_journal_replay_performed: false,
            historical_fill_completeness_certified: false,
        }
    }

    #[test]
    fn terminal_certificate_has_one_unambiguous_allowlisted_release_field() {
        let report = IncidentTerminalCertificationReport {
            schema_version: "layrs.incident-terminal-certification.v1".into(),
            incident_id: INCIDENT_ID.into(),
            incident_policy_sha256: INCIDENT_RECOVERY_POLICY_SHA256_HEX.into(),
            snapshot_bucket: INCIDENT_SNAPSHOT_BUCKET.into(),
            snapshot_key: INCIDENT_SNAPSHOT_KEY.into(),
            snapshot_version_id: INCIDENT_SNAPSHOT_VERSION_ID.into(),
            snapshot_size_bytes: INCIDENT_SNAPSHOT_SIZE_BYTES,
            snapshot_body_sha256: INCIDENT_SNAPSHOT_BODY_SHA256_HEX.into(),
            certifier_release_manifest_sha256: "11".repeat(32),
            artifact_equal: true,
            policy_equal: true,
            source_release_equal: true,
            certifier_pcr0_equal: true,
            terminal_state: empty_terminal_state_report(),
        };

        let encoded = serde_json::to_string(&report).unwrap();
        assert_eq!(encoded.matches("\"sourceReleaseCommit\"").count(), 1);
        assert!(!encoded.contains("certifierPcr0Sha384"));
        let value: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        assert_eq!(value["sourceReleaseCommit"], EXACT_LIVE_976_RELEASE_COMMIT);
        assert_eq!(value["restoredSequence"], INCIDENT_TERMINAL_SEQUENCE);
        let mut actual_keys: Vec<_> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        actual_keys.sort_unstable();
        let mut expected_keys = vec![
            "aggregateAssetTotals",
            "aggregateBucketTotals",
            "aggregateTotalsEqual",
            "aggregateTotalsZeroDelta",
            "artifactEqual",
            "categoryCounts",
            "categoryDigests",
            "categoryEquality",
            "certifierPcr0Equal",
            "certifierReleaseManifestSha256",
            "historicalFillCompletenessCertified",
            "historicalJournalReplayPerformed",
            "incidentId",
            "incidentPolicySha256",
            "journalHeadEqual",
            "noExternalStateMutationPerformed",
            "policyEqual",
            "poolCashOpeningRequired",
            "restoreFloorPersisted",
            "restoredJournalHead",
            "restoredSequence",
            "restoredStateRoot",
            "schemaVersion",
            "sequenceEqual",
            "snapshotBodySha256",
            "snapshotBucket",
            "snapshotCiphertextSha256",
            "snapshotKey",
            "snapshotSizeBytes",
            "snapshotVersionId",
            "sourceReleaseCommit",
            "sourceReleaseEqual",
            "stateRootEqual",
        ];
        expected_keys.sort_unstable();
        assert_eq!(actual_keys, expected_keys);
    }

    #[test]
    fn incident_policy_bytes_and_every_provenance_field_are_exact() {
        assert_eq!(
            hex::encode(incident_recovery_policy_sha256().unwrap()),
            INCIDENT_RECOVERY_POLICY_SHA256_HEX
        );
        let policy = exact_incident_recovery_policy().unwrap();
        assert_eq!(policy.restore_sequence, INCIDENT_TERMINAL_SEQUENCE);
        assert_eq!(policy.rollback_floor, INCIDENT_TERMINAL_SEQUENCE);
        assert!(!policy.historical_journal_replay_required);
        assert!(!policy.historical_fill_completeness_certified);

        let mut wrong_release = policy.clone();
        wrong_release.source_release_commit = "00".repeat(20);
        assert!(validate_incident_recovery_policy_fields(&wrong_release).is_err());
        let mut wrong_version = policy.clone();
        wrong_version.snapshot.version_id.push('x');
        assert!(validate_incident_recovery_policy_fields(&wrong_version).is_err());
        let mut wrong_source_eif = policy.clone();
        wrong_source_eif.source_provenance.eif_sha384 = "00".repeat(48);
        assert!(validate_incident_recovery_policy_fields(&wrong_source_eif).is_err());
        let mut wrong_source_pcr = policy.clone();
        wrong_source_pcr.source_provenance.pcr0 = "00".repeat(48);
        assert!(validate_incident_recovery_policy_fields(&wrong_source_pcr).is_err());
        let mut wrong_source_ami = policy.clone();
        wrong_source_ami.source_provenance.source_ami_id = "ami-00000000000000000".into();
        assert!(validate_incident_recovery_policy_fields(&wrong_source_ami).is_err());
        let mut wrong_copied_ami = policy.clone();
        wrong_copied_ami.source_provenance.copied_parent_ami_id = "ami-00000000000000000".into();
        assert!(validate_incident_recovery_policy_fields(&wrong_copied_ami).is_err());
        let mut journal_required = policy;
        journal_required.historical_journal_replay_required = true;
        assert!(validate_incident_recovery_policy_fields(&journal_required).is_err());
    }

    #[test]
    fn incident_descriptor_substitution_fails_before_snapshot_parse() {
        let body = [];
        let exact = exact_incident_descriptor();
        assert_eq!(
            validate_incident_terminal_input(&exact, &body).unwrap_err(),
            "INCIDENT_SNAPSHOT_DESCRIPTOR_MISMATCH"
        );
        for substituted in [
            IncidentSnapshotDescriptor {
                bucket: "layrs-production-substituted".into(),
                ..exact.clone()
            },
            IncidentSnapshotDescriptor {
                key: "enclave/snapshot/substituted.json".into(),
                ..exact.clone()
            },
            IncidentSnapshotDescriptor {
                version_id: "substituted".into(),
                ..exact.clone()
            },
            IncidentSnapshotDescriptor {
                size_bytes: INCIDENT_SNAPSHOT_SIZE_BYTES - 1,
                ..exact.clone()
            },
            IncidentSnapshotDescriptor {
                body_sha256: "00".repeat(32),
                ..exact
            },
        ] {
            assert_eq!(
                validate_incident_terminal_input(&substituted, &body).unwrap_err(),
                "INCIDENT_SNAPSHOT_DESCRIPTOR_MISMATCH"
            );
        }
    }

    #[test]
    fn incident_operator_command_rejects_unknown_fields() {
        let command = serde_json::json!({
            "type": "BEGIN_INCIDENT_TERMINAL_RESTORE",
            "kms_key_id": "alias/layrs/production/journal",
            "kms_ciphertext_blob": [1, 2, 3],
            "snapshot_descriptor": exact_incident_descriptor(),
            "snapshot_body": [],
            "external_challenge": vec![1u8; 32],
            "certifier_release_manifest_sha256": vec![2u8; 32],
            "expected_certifier_pcr0_sha384": vec![3u8; 48],
            "unexpected": true
        });
        assert!(serde_json::from_value::<OperatorCommand>(command).is_err());
    }

    #[test]
    fn generic_provisioning_remains_allowed_with_incident_restore_policy_embedded() {
        ensure_generic_provisioning_allowed().unwrap();
    }

    #[test]
    fn terminal_attestation_binding_changes_for_replay_or_substitution() {
        let descriptor = exact_incident_descriptor();
        let baseline = incident_artifact_binding(
            [1; 32],
            [2; 32],
            &descriptor,
            [3; 32],
            [4; 48],
            [5; 32],
            [6; 32],
        );
        assert_ne!(
            baseline,
            incident_artifact_binding(
                [1; 32],
                [2; 32],
                &descriptor,
                [3; 32],
                [4; 48],
                [7; 32],
                [6; 32],
            )
        );
        let mut substituted = descriptor;
        substituted.version_id = "substituted".into();
        assert_ne!(
            baseline,
            incident_artifact_binding(
                [1; 32],
                [2; 32],
                &substituted,
                [3; 32],
                [4; 48],
                [5; 32],
                [6; 32],
            )
        );
    }

    #[test]
    fn position_close_preview_is_transition_only_for_success_and_rejection() {
        assert!(!is_s08_semantic_action(
            ExpectedEncryptedAction::PreviewPositionClose
        ));
        assert!(is_s08_semantic_action(
            ExpectedEncryptedAction::ClosePosition
        ));
    }

    #[test]
    fn encrypted_wire_request_requires_command_context() {
        let without_context = serde_json::json!({
            "type": "ENCRYPTED_USER",
            "client_public_key": vec![1u8; 32],
            "nonce": vec![2u8; 12],
            "ciphertext": vec![3u8; 32],
        });
        assert!(serde_json::from_value::<WireRequest>(without_context).is_err());
    }

    #[test]
    fn encrypted_outer_context_cannot_cross_user_operator_boundary() {
        let operator = PlainRequest::Operator {
            envelope: OperatorEnvelope {
                nonce: [0x42; 32],
                command: OperatorCommand::ProvisionStatus,
                signature: vec![0x24; 64],
            },
        };
        let user_context = EncryptedRequestContext {
            idempotency_key: "order:submit:context-boundary".into(),
            expected_action: ExpectedEncryptedAction::Submit,
            expected_order_id: None,
            expected_position_id: None,
            expected_execution_id: None,
            expected_withdrawal_id: None,
            expected_transfer_id: None,
            expected_session_tags: vec![],
            expected_command_commitment: Some(format!("0x{}", "11".repeat(32))),
        };

        assert!(
            validate_request_context(&operator, &EncryptedOuterContext::User(user_context))
                .is_err()
        );
        assert!(validate_request_context(&operator, &EncryptedOuterContext::Operator).is_ok());
    }

    #[test]
    fn durable_request_hashes_match_browser_and_backend_vectors() {
        let mut public_key = [0u8; 32];
        for (index, byte) in public_key.iter_mut().enumerate() {
            *byte = index as u8;
        }
        let mut nonce = [0u8; 12];
        for (index, byte) in nonce.iter_mut().enumerate() {
            *byte = 0x20 + index as u8;
        }
        let ciphertext: Vec<u8> = (0x2c..0x4c).collect();
        assert_eq!(
            hex::encode(request_envelope_hash(public_key, nonce, &ciphertext)),
            "31f3da8fd6f8ba84ed6232257c240157bc473aadaa4be9f5a4959e6ac3f5264f",
        );

        let context = EncryptedOuterContext::User(EncryptedRequestContext {
            idempotency_key: "private:durable:01234567".into(),
            expected_action: ExpectedEncryptedAction::Submit,
            expected_session_tags: vec!["tag-b".into(), "tag-a".into()],
            expected_order_id: None,
            expected_position_id: None,
            expected_execution_id: None,
            expected_withdrawal_id: None,
            expected_transfer_id: None,
            expected_command_commitment: Some(format!("0x{}", "ab".repeat(32))),
        });
        assert_eq!(
            hex::encode(request_context_hash(&context).unwrap()),
            "dbe0409fbd2913f38e8566fb4c21f8239e08c7992f28332b8be00687e422a5ec",
        );
    }

    #[test]
    fn durable_preparation_signature_binds_every_successor_artifact() {
        let measurement = [0x31; 48];
        let signer = ReceiptSigner::generate(measurement);
        let record = EncryptedJournalRecord {
            sequence: 8,
            nonce: [1; 12],
            prior_record_hash: [2; 32],
            state_root: [3; 32],
            ciphertext: vec![4; 32],
            record_hash: [5; 32],
        };
        let snapshot = EncryptedSnapshot {
            sequence: 8,
            journal_head: [5; 32],
            state_root: [3; 32],
            nonce: [6; 12],
            ciphertext: vec![7; 48],
            ciphertext_hash: [8; 32],
        };
        let receipt = EnclaveReceipt {
            protocol_version: "layrs.v2".into(),
            receipt_id: format!("receipt_{}", "09".repeat(32)),
            command_id: "command-8".into(),
            idempotency_key: "private:durable:preparation-8".into(),
            command_commitment_sha256: Some([10; 32]),
            publication_eligible: Some(true),
            result_commitment_sha256: None,
            journal_committed: None,
            reviewer_event: None,
            enclave_sequence: 8,
            prior_state_root: [11; 32],
            state_root: [3; 32],
            journal_hash: [5; 32],
            enclave_measurement_sha384: measurement.to_vec(),
            occurred_at_millis: 1_787_000_000_000,
            signature: vec![12; 64],
        };
        let writer = DurableWriterAuthorization {
            protocol_version: "layrs.durable-writer-authorization.v1".into(),
            environment: "test".into(),
            epoch: 7,
            lease_id: Uuid::from_u128(7),
            not_before_millis: 1_787_000_000_000,
            expires_at_millis: 1_787_000_180_000,
            actor_domain: "USER".into(),
            command_idempotency_key: receipt.idempotency_key.clone(),
            command_commitment_sha256: [10; 32],
            request_context_sha256: [14; 32],
            request_envelope_sha256: [15; 32],
            signature: vec![0; 64],
        };
        let preparation = build_durable_preparation(
            &signer,
            measurement,
            "USER",
            [13; 32],
            [10; 32],
            [14; 32],
            [15; 32],
            &receipt.idempotency_key,
            &writer,
            &record,
            &snapshot,
            &receipt,
            [16; 32],
            MIN_PRIVATE_RESPONSE_BYTES as u64,
            1_787_000_000_000,
        );
        assert!(verify_durable_preparation(
            &signer.verifying_key(),
            &measurement,
            &preparation,
            &snapshot,
        )
        .is_ok());

        let mut rebound = preparation.clone();
        let mut successor_writer = writer.clone();
        successor_writer.epoch += 1;
        successor_writer.lease_id = Uuid::from_u128(8);
        successor_writer.expires_at_millis = preparation.expires_at_millis + 210_000;
        let financial_successor = (
            rebound.state_root,
            rebound.journal_record_hash,
            rebound.snapshot_ciphertext_hash,
            rebound.response_envelope_sha256,
        );
        rebind_durable_preparation(
            &mut rebound,
            &successor_writer,
            preparation.expires_at_millis + 60_000,
            preparation.expires_at_millis + 90_000,
            &signer,
        );
        assert_eq!(rebound.writer_epoch, 8);
        assert_eq!(rebound.writer_lease_id, Uuid::from_u128(8));
        assert!(rebound.prepared_at_millis > preparation.expires_at_millis);
        assert_ne!(rebound.preparation_id, preparation.preparation_id);
        assert_eq!(
            financial_successor,
            (
                rebound.state_root,
                rebound.journal_record_hash,
                rebound.snapshot_ciphertext_hash,
                rebound.response_envelope_sha256
            )
        );
        assert!(verify_durable_preparation(
            &signer.verifying_key(),
            &measurement,
            &rebound,
            &snapshot,
        )
        .is_ok());

        let mut forged = preparation.clone();
        forged.command_commitment_sha256[0] ^= 1;
        assert!(verify_durable_preparation(
            &signer.verifying_key(),
            &measurement,
            &forged,
            &snapshot,
        )
        .is_err());

        let mut forked_snapshot = snapshot.clone();
        forked_snapshot.state_root[0] ^= 1;
        assert!(verify_durable_preparation(
            &signer.verifying_key(),
            &measurement,
            &preparation,
            &forked_snapshot,
        )
        .is_err());
        assert!(verify_durable_preparation(
            &signer.verifying_key(),
            &[0x32; 48],
            &preparation,
            &snapshot,
        )
        .is_err());
    }

    #[test]
    fn enclave_generation_transition_is_manifest_bound_and_fail_closed() {
        let source = [0x31; 48];
        let target = [0x32; 48];
        let schema = "layrs.private-core-snapshot.s07.v1";
        let same = enclave_transition_policy_hash(&target, &target, schema);
        assert!(
            verify_enclave_generation_transition(&target, &target, &target, schema, same).is_ok()
        );

        let cross = enclave_transition_policy_hash(&source, &target, schema);
        assert_eq!(
            verify_enclave_generation_transition(&source, &target, &target, schema, cross)
                .unwrap_err(),
            "DURABLE_ENCLAVE_TRANSITION_NOT_AUTHORIZED"
        );
        let mut forged = cross;
        forged[0] ^= 1;
        assert_eq!(
            verify_enclave_generation_transition(&source, &target, &target, schema, forged)
                .unwrap_err(),
            "DURABLE_ENCLAVE_TRANSITION_INVALID"
        );
    }

    #[test]
    fn direct_bootstrap_outcome_mutations_are_tombstoned() {
        let execution_id = uuid::Uuid::from_u128(7);
        assert!(direct_bootstrap_outcome_command(
            &OperatorCommand::MarkBootstrapSubmitted {
                idempotency_key: "bootstrap:forged:submitted".into(),
                execution_id,
                venue_order_id: "forged".into(),
                now_millis: 1,
            }
        ));
        assert!(direct_bootstrap_outcome_command(
            &OperatorCommand::ConfirmBootstrapFill {
                idempotency_key: "bootstrap:forged:fill".into(),
                execution_id,
                fill_price_micros: 500_000,
                evidence_hash: [1u8; 32],
                now_millis: 1,
            }
        ));
        assert!(direct_bootstrap_outcome_command(
            &OperatorCommand::FailBootstrapExecution {
                idempotency_key: "bootstrap:forged:failure".into(),
                execution_id,
                failure_code: "FORGED".into(),
                evidence_hash: [2u8; 32],
                now_millis: 1,
            }
        ));
    }

    #[test]
    fn capability_is_bound_into_request_aad() {
        let legacy = request_aad(&[1; 32], &[2; 32], None);
        let read = request_aad(&[1; 32], &[2; 32], Some(AccessCapability::AccountRead));
        let order = request_aad(&[1; 32], &[2; 32], Some(AccessCapability::NewOrders));
        assert_ne!(legacy, read);
        assert_ne!(read, order);
        assert!(read.ends_with(b"accountRead"));
    }

    #[test]
    fn enclave_derives_capability_from_decrypted_action() {
        assert_eq!(
            expected_user_access_capability(&UserCommandAction::Portfolio),
            AccessCapability::AccountRead
        );
        assert_eq!(
            expected_user_access_capability(&UserCommandAction::CancelOrder {
                market_id: "layrs:v5:TEST:capability:abababababababab".into(),
                order_id: uuid::Uuid::nil(),
            }),
            AccessCapability::OrderCancellation
        );
        assert_eq!(
            expected_user_access_capability(&UserCommandAction::CompleteSet {
                market_id: "layrs:v5:TEST:capability:abababababababab".into(),
                quantity_micros: 1,
                direction: clob_service::private_core::CompleteSetDirection::Burn,
            }),
            AccessCapability::PositionReduction
        );
        assert_eq!(
            expected_user_access_capability(&UserCommandAction::CompleteSet {
                market_id: "layrs:v5:TEST:capability:abababababababab".into(),
                quantity_micros: 1,
                direction: clob_service::private_core::CompleteSetDirection::Mint,
            }),
            AccessCapability::NewOrders
        );
    }

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
    fn transport_replay_accepts_only_byte_identical_retry_and_rejects_conflict() {
        let mut cache = TransportReplayCache::new(2);
        let key = [0x41; 44];
        assert_eq!(
            cache.check_or_remember(key, b"ciphertext-one"),
            TransportReplayDecision::New,
        );
        assert_eq!(
            cache.check_or_remember(key, b"ciphertext-one"),
            TransportReplayDecision::ExactRetry,
        );
        assert_eq!(
            cache.check_or_remember(key, b"ciphertext-two"),
            TransportReplayDecision::Conflict,
        );
        cache.forget(&key);
        assert_eq!(
            cache.check_or_remember(key, b"ciphertext-two"),
            TransportReplayDecision::New,
        );
    }

    fn synthetic_nsm_document(
        nonce: &[u8],
        user_data: &[u8],
        pcr0: [u8; 48],
        timestamp: u64,
    ) -> Vec<u8> {
        let mut pcrs = BTreeMap::new();
        pcrs.insert(0, pcr0.to_vec());
        wrap_synthetic_attestation(
            AttestationDoc::new(
                "synthetic-nsm".into(),
                NsmDigest::SHA384,
                timestamp,
                pcrs,
                vec![7u8; 32],
                vec![vec![8u8; 32]],
                Some(user_data.to_vec()),
                Some(nonce.to_vec()),
                None,
            ),
            vec![9u8; 96],
        )
    }

    fn wrap_synthetic_attestation(attestation: AttestationDoc, signature: Vec<u8>) -> Vec<u8> {
        let payload = attestation.to_binary();
        let protected = serde_cbor::to_vec(&Value::Map(BTreeMap::from([(
            Value::Integer(1),
            Value::Integer(-35),
        )])))
        .unwrap();
        serde_cbor::to_vec(&Value::Tag(
            18,
            Box::new(Value::Array(vec![
                Value::Bytes(protected),
                Value::Map(BTreeMap::new()),
                Value::Bytes(payload),
                Value::Bytes(signature),
            ])),
        ))
        .unwrap()
    }

    #[test]
    fn nsm_time_parser_requires_exact_nonce_domain_pcr_and_es384() {
        let nonce = [3u8; 32];
        let pcr0 = [4u8; 48];
        let document = synthetic_nsm_document(
            &nonce,
            TRUSTED_TIME_ATTESTATION_DOMAIN,
            pcr0,
            1_787_000_000_123,
        );
        assert_eq!(
            parse_nsm_attestation_timestamp(
                &document,
                &nonce,
                TRUSTED_TIME_ATTESTATION_DOMAIN,
                &pcr0,
            ),
            Ok(1_787_000_000_123),
        );
        let Value::Tag(18, inner) = serde_cbor::from_slice::<Value>(&document).unwrap() else {
            panic!("synthetic document must be tagged");
        };
        let untagged = serde_cbor::to_vec(&*inner).unwrap();
        assert_eq!(
            parse_nsm_attestation_timestamp(
                &untagged,
                &nonce,
                TRUSTED_TIME_ATTESTATION_DOMAIN,
                &pcr0,
            ),
            Ok(1_787_000_000_123),
        );
        assert!(parse_nsm_attestation_timestamp(
            &document,
            &[5u8; 32],
            TRUSTED_TIME_ATTESTATION_DOMAIN,
            &pcr0,
        )
        .is_err());
        assert!(
            parse_nsm_attestation_timestamp(&document, &nonce, b"wrong-purpose", &pcr0,).is_err()
        );
        assert!(parse_nsm_attestation_timestamp(
            &document,
            &nonce,
            TRUSTED_TIME_ATTESTATION_DOMAIN,
            &[6u8; 48],
        )
        .is_err());

        let Value::Tag(18, inner) = serde_cbor::from_slice::<Value>(&document).unwrap() else {
            panic!("synthetic document must be tagged");
        };
        let Value::Array(mut fields) = *inner else {
            panic!("synthetic document must contain Sign1");
        };
        fields[0] = Value::Bytes(
            serde_cbor::to_vec(&Value::Map(BTreeMap::from([(
                Value::Integer(1),
                Value::Integer(-7),
            )])))
            .unwrap(),
        );
        let wrong_alg =
            serde_cbor::to_vec(&Value::Tag(18, Box::new(Value::Array(fields)))).unwrap();
        assert!(parse_nsm_attestation_timestamp(
            &wrong_alg,
            &nonce,
            TRUSTED_TIME_ATTESTATION_DOMAIN,
            &pcr0,
        )
        .is_err());
    }

    #[test]
    fn nsm_time_parser_rejects_untagged_or_malformed_documents() {
        let nonce = [3u8; 32];
        let pcr0 = [4u8; 48];
        let mut invalid_unprotected = serde_cbor::from_slice::<Value>(&synthetic_nsm_document(
            &nonce,
            TRUSTED_TIME_ATTESTATION_DOMAIN,
            pcr0,
            1_000,
        ))
        .unwrap();
        let Value::Tag(18, inner) = &mut invalid_unprotected else {
            panic!("synthetic document must be tagged");
        };
        let Value::Array(fields) = inner.as_mut() else {
            panic!("synthetic document must contain Sign1");
        };
        fields[1] = Value::Null;
        for document in [
            serde_cbor::to_vec(&Value::Array(Vec::new())).unwrap(),
            serde_cbor::to_vec(&Value::Tag(18, Box::new(Value::Array(Vec::new())))).unwrap(),
            serde_cbor::to_vec(&invalid_unprotected).unwrap(),
            vec![0xff],
        ] {
            assert!(parse_nsm_attestation_timestamp(
                &document,
                &nonce,
                TRUSTED_TIME_ATTESTATION_DOMAIN,
                &pcr0,
            )
            .is_err());
        }
    }

    #[test]
    fn nsm_time_parser_rejects_invalid_attestation_semantics_and_overflow() {
        let nonce = [3u8; 32];
        let pcr0 = [4u8; 48];
        let mut pcrs = BTreeMap::new();
        pcrs.insert(0, pcr0.to_vec());
        let attestation = |module_id: &str, digest, timestamp, pcrs: BTreeMap<usize, Vec<u8>>| {
            AttestationDoc::new(
                module_id.into(),
                digest,
                timestamp,
                pcrs,
                vec![7u8; 32],
                vec![vec![8u8; 32]],
                Some(TRUSTED_TIME_ATTESTATION_DOMAIN.to_vec()),
                Some(nonce.to_vec()),
                None,
            )
        };
        let invalid = [
            wrap_synthetic_attestation(
                attestation("", NsmDigest::SHA384, 1_000, pcrs.clone()),
                vec![9u8; 96],
            ),
            wrap_synthetic_attestation(
                attestation("synthetic-nsm", NsmDigest::SHA256, 1_000, pcrs.clone()),
                vec![9u8; 96],
            ),
            wrap_synthetic_attestation(
                attestation("synthetic-nsm", NsmDigest::SHA384, 1_000, BTreeMap::new()),
                vec![9u8; 96],
            ),
            wrap_synthetic_attestation(
                attestation("synthetic-nsm", NsmDigest::SHA384, u64::MAX, pcrs.clone()),
                vec![9u8; 96],
            ),
            wrap_synthetic_attestation(
                attestation("synthetic-nsm", NsmDigest::SHA384, 1_000, pcrs),
                Vec::new(),
            ),
        ];
        for document in invalid {
            assert!(parse_nsm_attestation_timestamp(
                &document,
                &nonce,
                TRUSTED_TIME_ATTESTATION_DOMAIN,
                &pcr0,
            )
            .is_err());
        }
    }

    #[test]
    fn private_error_responses_have_one_length_class_and_remain_valid_json() {
        let codes = [
            "position owner mismatch",
            "insufficient protected liquidity for position close",
            "position close quote is stale",
        ];
        let encoded = codes.map(|code| {
            pad_private_response(
                serde_json::to_vec(&PlainResponse::Error {
                    code: code.into(),
                    receipt: None,
                    receipt_state: None,
                    receipt_disclosure_nonce: None,
                })
                .unwrap(),
            )
            .unwrap()
        });
        assert!(encoded
            .iter()
            .all(|value| value.len() == MIN_PRIVATE_RESPONSE_BYTES));
        for (value, expected) in encoded.iter().zip(codes) {
            let parsed: serde_json::Value = serde_json::from_slice(value).unwrap();
            assert_eq!(parsed["type"], "ERROR");
            assert_eq!(parsed["code"], expected);
        }
    }

    #[test]
    fn submit_order_recovery_artifact_gate_does_not_mask_signed_rejections() {
        assert!(!recovery_artifact_failure_required(true, false, false));
        assert!(!recovery_artifact_failure_required(true, true, true));
        assert!(!recovery_artifact_failure_required(false, false, true));
        assert!(recovery_artifact_failure_required(true, false, true));
    }

    #[test]
    fn api_order_context_binds_inner_idempotency_and_action() {
        let expected_tag = api_session_request_tag("order:create:1234", "session:user-a");
        let context = EncryptedRequestContext {
            idempotency_key: "order:create:1234".into(),
            expected_action: ExpectedEncryptedAction::Submit,
            expected_session_tags: vec![expected_tag],
            expected_order_id: None,
            expected_position_id: None,
            expected_execution_id: None,
            expected_withdrawal_id: None,
            expected_transfer_id: None,
            expected_command_commitment: Some(format!("0x{}", "22".repeat(32))),
        };
        assert!(validate_user_command_context(
            "order:create:1234",
            "session:user-a",
            ExpectedEncryptedAction::Submit,
            None,
            None,
            &context
        )
        .is_ok());
        assert!(validate_user_command_context(
            "order:create:5678",
            "session:user-a",
            ExpectedEncryptedAction::Submit,
            None,
            None,
            &context
        )
        .is_err());
        assert!(validate_user_command_context(
            "order:create:1234",
            "session:user-b",
            ExpectedEncryptedAction::Submit,
            None,
            None,
            &context
        )
        .is_err());
        assert!(validate_user_command_context(
            "order:create:1234",
            "session:user-a",
            ExpectedEncryptedAction::Replace,
            Some(Uuid::nil()),
            None,
            &context
        )
        .is_err());

        let order_id = Uuid::new_v4();
        let replace = EncryptedRequestContext {
            idempotency_key: "order:replace:1234".into(),
            expected_action: ExpectedEncryptedAction::Replace,
            expected_session_tags: vec![api_session_request_tag(
                "order:replace:1234",
                "session:user-a",
            )],
            expected_order_id: Some(order_id),
            expected_position_id: None,
            expected_execution_id: None,
            expected_withdrawal_id: None,
            expected_transfer_id: None,
            expected_command_commitment: Some(format!("0x{}", "33".repeat(32))),
        };
        assert!(validate_user_command_context(
            "order:replace:1234",
            "session:user-a",
            ExpectedEncryptedAction::Replace,
            Some(order_id),
            None,
            &replace,
        )
        .is_ok());
        assert!(validate_user_command_context(
            "order:replace:1234",
            "session:user-a",
            ExpectedEncryptedAction::Replace,
            Some(Uuid::new_v4()),
            None,
            &replace,
        )
        .is_err());

        let cancel = EncryptedRequestContext {
            idempotency_key: "order:cancel:1234".into(),
            expected_action: ExpectedEncryptedAction::Cancel,
            expected_session_tags: vec![api_session_request_tag(
                "order:cancel:1234",
                "session:user-a",
            )],
            expected_order_id: Some(order_id),
            expected_position_id: None,
            expected_execution_id: None,
            expected_withdrawal_id: None,
            expected_transfer_id: None,
            expected_command_commitment: Some(format!("0x{}", "44".repeat(32))),
        };
        assert!(validate_user_command_context(
            "order:cancel:1234",
            "session:user-a",
            ExpectedEncryptedAction::Cancel,
            Some(order_id),
            None,
            &cancel,
        )
        .is_ok());
        assert!(validate_user_command_context(
            "order:cancel:1234",
            "session:user-a",
            ExpectedEncryptedAction::Cancel,
            Some(Uuid::new_v4()),
            None,
            &cancel,
        )
        .is_err());

        let cancel_all = EncryptedRequestContext {
            idempotency_key: "orders:cancel-all:1234".into(),
            expected_action: ExpectedEncryptedAction::CancelAll,
            expected_session_tags: vec![api_session_request_tag(
                "orders:cancel-all:1234",
                "session:user-a",
            )],
            expected_order_id: None,
            expected_position_id: None,
            expected_execution_id: None,
            expected_withdrawal_id: None,
            expected_transfer_id: None,
            expected_command_commitment: Some(format!("0x{}", "55".repeat(32))),
        };
        assert!(validate_user_command_context(
            "orders:cancel-all:1234",
            "session:user-a",
            ExpectedEncryptedAction::CancelAll,
            None,
            None,
            &cancel_all,
        )
        .is_ok());
        assert!(validate_user_command_context(
            "orders:cancel-all:1234",
            "session:user-a",
            ExpectedEncryptedAction::Cancel,
            Some(order_id),
            None,
            &cancel_all,
        )
        .is_err());
        assert!(validate_user_command_context(
            "order:cancel:1234",
            "session:user-a",
            ExpectedEncryptedAction::Replace,
            Some(order_id),
            None,
            &cancel,
        )
        .is_err());

        let position_id = format!("pos_{}", "ab".repeat(32));
        let close = EncryptedRequestContext {
            idempotency_key: "position:close:1234".into(),
            expected_action: ExpectedEncryptedAction::ClosePosition,
            expected_session_tags: vec![api_session_request_tag(
                "position:close:1234",
                "session:user-a",
            )],
            expected_order_id: None,
            expected_position_id: Some(position_id.clone()),
            expected_execution_id: None,
            expected_withdrawal_id: None,
            expected_transfer_id: None,
            expected_command_commitment: Some(format!("0x{}", "11".repeat(32))),
        };
        assert!(validate_user_command_context(
            "position:close:1234",
            "session:user-a",
            ExpectedEncryptedAction::ClosePosition,
            None,
            Some(&position_id),
            &close,
        )
        .is_ok());
        assert!(validate_user_command_context(
            "position:close:1234",
            "session:user-a",
            ExpectedEncryptedAction::ClosePosition,
            None,
            Some("pos_wrong"),
            &close,
        )
        .is_err());

        let exact_tag = api_session_request_tag("position:close:1234", "session:user-a");
        assert!(validate_bound_user_command_context(
            "position:close:1234",
            "session:user-a",
            ExpectedEncryptedAction::ClosePosition,
            None,
            Some(&position_id),
            None,
            None,
            None,
            Some(&exact_tag),
            [0x11; 32],
            &close,
        )
        .is_ok());
        assert!(validate_bound_user_command_context(
            "position:close:1234",
            "session:user-a",
            ExpectedEncryptedAction::ClosePosition,
            None,
            Some(&position_id),
            None,
            None,
            None,
            Some("wrong-session-tag"),
            [0x11; 32],
            &close,
        )
        .is_err());
        assert!(validate_bound_user_command_context(
            "position:close:1234",
            "session:user-a",
            ExpectedEncryptedAction::ClosePosition,
            None,
            Some(&position_id),
            None,
            None,
            None,
            Some(&exact_tag),
            [0x22; 32],
            &close,
        )
        .is_err());
    }

    #[test]
    fn every_private_user_action_is_bound_to_commitment_session_and_target() {
        let idempotency_key = "private:all-actions:1234";
        let session_id = "session:user-a";
        let session_tag = api_session_request_tag(idempotency_key, session_id);
        let commitment = [0x55; 32];
        let execution_id = Uuid::new_v4();
        let withdrawal_id = Uuid::new_v4();
        let transfer_id = Uuid::new_v4();
        let cases = [
            (ExpectedEncryptedAction::CompleteSet, None, None, None),
            (ExpectedEncryptedAction::Portfolio, None, None, None),
            (ExpectedEncryptedAction::Rewards, None, None, None),
            (
                ExpectedEncryptedAction::RequestRewardClaim,
                None,
                None,
                None,
            ),
            (
                ExpectedEncryptedAction::BootstrapStatus,
                Some(execution_id),
                None,
                None,
            ),
            (
                ExpectedEncryptedAction::CancelBootstrap,
                Some(execution_id),
                None,
                None,
            ),
            (
                ExpectedEncryptedAction::RequestWithdrawal,
                None,
                Some(withdrawal_id),
                None,
            ),
            (
                ExpectedEncryptedAction::TransferFunds,
                None,
                None,
                Some(transfer_id),
            ),
        ];
        for (action, expected_execution_id, expected_withdrawal_id, expected_transfer_id) in cases {
            let context = EncryptedRequestContext {
                idempotency_key: idempotency_key.into(),
                expected_action: action,
                expected_session_tags: vec![session_tag.clone()],
                expected_order_id: None,
                expected_position_id: None,
                expected_execution_id,
                expected_withdrawal_id,
                expected_transfer_id,
                expected_command_commitment: Some(format!("0x{}", "55".repeat(32))),
            };
            assert!(validate_bound_user_command_context(
                idempotency_key,
                session_id,
                action,
                None,
                None,
                expected_execution_id,
                expected_withdrawal_id,
                expected_transfer_id,
                None,
                commitment,
                &context,
            )
            .is_ok());
            assert!(validate_bound_user_command_context(
                idempotency_key,
                session_id,
                action,
                None,
                None,
                expected_execution_id,
                expected_withdrawal_id,
                expected_transfer_id,
                None,
                [0x56; 32],
                &context,
            )
            .is_err());
        }
    }

    #[test]
    fn every_order_action_requires_the_exact_command_commitment() {
        let idempotency_key = "private:order-actions:1234";
        let session_id = "session:user-a";
        let session_tag = api_session_request_tag(idempotency_key, session_id);
        let commitment = [0x66; 32];
        let order_id = Uuid::new_v4();
        for (action, expected_order_id) in [
            (ExpectedEncryptedAction::Submit, None),
            (ExpectedEncryptedAction::Replace, Some(order_id)),
            (ExpectedEncryptedAction::Cancel, Some(order_id)),
            (ExpectedEncryptedAction::CancelAll, None),
        ] {
            let context = EncryptedRequestContext {
                idempotency_key: idempotency_key.into(),
                expected_action: action,
                expected_session_tags: vec![session_tag.clone()],
                expected_order_id,
                expected_position_id: None,
                expected_execution_id: None,
                expected_withdrawal_id: None,
                expected_transfer_id: None,
                expected_command_commitment: Some(format!("0x{}", "66".repeat(32))),
            };
            assert!(validate_bound_user_command_context(
                idempotency_key,
                session_id,
                action,
                expected_order_id,
                None,
                None,
                None,
                None,
                None,
                commitment,
                &context,
            )
            .is_ok());
            assert!(validate_bound_user_command_context(
                idempotency_key,
                session_id,
                action,
                expected_order_id,
                None,
                None,
                None,
                None,
                None,
                commitment,
                &EncryptedRequestContext {
                    expected_command_commitment: None,
                    ..context.clone()
                },
            )
            .is_err());
            assert!(validate_bound_user_command_context(
                idempotency_key,
                session_id,
                action,
                expected_order_id,
                None,
                None,
                None,
                None,
                None,
                [0x67; 32],
                &context,
            )
            .is_err());
        }
    }

    #[test]
    fn relay_frame_limit_supports_checkpoint_restore_payloads() {
        const { assert!(MAX_FRAME_BYTES >= 256 * 1024 * 1024) };
    }

    #[test]
    fn delegated_read_authorization_is_scope_audience_expiry_and_revocation_bound() {
        let now = 1_700_000_000_000i64;
        assert!(validate_delegated_read_authorization(
            DelegatedReadProjection::Balances,
            "production",
            "https://api.layrs.xyz/mcp",
            "balances:read",
            now - 1_000,
            now + 60_000,
            now,
            now,
        )
        .is_ok());
        assert_eq!(
            validate_delegated_read_authorization(
                DelegatedReadProjection::Positions,
                "production",
                "https://api.layrs.xyz/mcp",
                "balances:read",
                now - 1_000,
                now + 60_000,
                now,
                now,
            ),
            Err("DELEGATED_READ_CONTEXT_MISMATCH".into())
        );
        assert_eq!(
            validate_delegated_read_authorization(
                DelegatedReadProjection::Balances,
                "production",
                "https://api-staging.layrs.xyz/mcp",
                "balances:read",
                now - 1_000,
                now + 60_000,
                now,
                now,
            ),
            Err("DELEGATED_READ_CONTEXT_MISMATCH".into())
        );
        assert_eq!(
            validate_delegated_read_authorization(
                DelegatedReadProjection::Balances,
                "production",
                "https://api.layrs.xyz/mcp",
                "balances:read",
                now - 61_000,
                now - 1,
                now - 1_000,
                now,
            ),
            Err("DELEGATED_READ_EXPIRED".into())
        );
        assert_eq!(
            validate_delegated_read_authorization(
                DelegatedReadProjection::Balances,
                "production",
                "https://api.layrs.xyz/mcp",
                "balances:read",
                now - 30_000,
                now + 30_000,
                now - DELEGATED_READ_MAX_REVOCATION_AGE_MILLIS - 1,
                now,
            ),
            Err("DELEGATED_READ_REVOCATION_STALE".into())
        );
    }

    #[test]
    fn delegated_read_envelope_decrypts_only_with_the_recipient_key_and_bound_context() {
        let recipient_secret = StaticSecret::random();
        let recipient_public = PublicKey::from(&recipient_secret).to_bytes();
        let request_id = uuid::Uuid::from_u128(1);
        let capability_jti = uuid::Uuid::from_u128(2);
        let api_key_id = uuid::Uuid::from_u128(3);
        let capability_digest = [9u8; 32];
        let expires_at_millis = 1_700_000_060_000;
        let plaintext = DelegatedReadPlaintext {
            protocol_version: "layrs.delegated-private-read.v1",
            request_id,
            projection: "BALANCES",
            enclave_sequence: "17".into(),
            as_of_millis: 1_700_000_000_000,
            items: serde_json::json!([{"asset":"USDC","amountAtomic":"5000000"}]),
        };
        let envelope = encrypt_delegated_read(
            &plaintext,
            recipient_public,
            DelegatedReadProjection::Balances,
            api_key_id,
            capability_jti,
            capability_digest,
            expires_at_millis,
        )
        .expect("envelope");
        let shared =
            recipient_secret.diffie_hellman(&PublicKey::from(envelope.ephemeral_public_key));
        let key: [u8; 32] = {
            let mut hash = Sha256::new();
            hash.update(b"layrs.delegated-private-read.key.v1\0");
            hash.update(shared.as_bytes());
            hash.update(request_id.as_bytes());
            hash.update(api_key_id.as_bytes());
            hash.update(capability_jti.as_bytes());
            hash.update(capability_digest);
            hash.update(recipient_public);
            hash.update(envelope.ephemeral_public_key);
            hash.finalize().into()
        };
        let aad = delegated_read_aad(
            request_id,
            DelegatedReadProjection::Balances,
            api_key_id,
            capability_jti,
            capability_digest,
            recipient_public,
            envelope.ephemeral_public_key,
            expires_at_millis,
        );
        let decoded = Aes256Gcm::new_from_slice(&key)
            .unwrap()
            .decrypt(
                Nonce::from_slice(&envelope.nonce),
                aes_gcm::aead::Payload {
                    msg: &envelope.ciphertext,
                    aad: &aad,
                },
            )
            .expect("recipient decrypts");
        let value: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(value["enclaveSequence"], "17");
        assert_eq!(value["items"][0]["amountAtomic"], "5000000");

        let mut wrong_aad = aad;
        wrong_aad[0] ^= 1;
        assert!(Aes256Gcm::new_from_slice(&key)
            .unwrap()
            .decrypt(
                Nonce::from_slice(&envelope.nonce),
                aes_gcm::aead::Payload {
                    msg: &envelope.ciphertext,
                    aad: &wrong_aad
                },
            )
            .is_err());
    }

    #[test]
    fn delegated_read_envelope_rejects_an_oversized_private_projection() {
        let recipient_public = PublicKey::from(&StaticSecret::random()).to_bytes();
        let plaintext = DelegatedReadPlaintext {
            protocol_version: "layrs.delegated-private-read.v1",
            request_id: uuid::Uuid::from_u128(11),
            projection: "BALANCES",
            enclave_sequence: "1".into(),
            as_of_millis: 1_700_000_000_000,
            items: "x".repeat(DELEGATED_READ_MAX_PLAINTEXT_BYTES),
        };
        assert!(matches!(
            encrypt_delegated_read(
                &plaintext,
                recipient_public,
                DelegatedReadProjection::Balances,
                uuid::Uuid::from_u128(12),
                uuid::Uuid::from_u128(13),
                [14u8; 32],
                1_700_000_060_000,
            ),
            Err(code) if code == "DELEGATED_READ_RESPONSE_TOO_LARGE"
        ));
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
                fee_profile_id: FeeProfileId::LegacyProfitV1,
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
    fn classifies_only_non_journaled_user_actions_as_read_only() {
        for action in [
            UserCommandAction::Portfolio,
            UserCommandAction::Rewards,
            UserCommandAction::BootstrapStatus {
                execution_id: Uuid::nil(),
            },
        ] {
            assert!(readonly_user_action(&action));
        }
        for action in [
            UserCommandAction::CancelBootstrap {
                execution_id: Uuid::nil(),
            },
            UserCommandAction::CancelOrder {
                market_id: "layrs:v4:test".into(),
                order_id: Uuid::nil(),
            },
        ] {
            assert!(!readonly_user_action(&action));
        }
    }

    #[test]
    fn direct_order_gate_accepts_only_registered_v5_btc_usdc_market_mutations() {
        use clob_service::private_core::{
            BookOrder, JournalKey, OrderAction, Outcome, TimeInForce,
        };

        let mut core = PrivateTradingCore::new(
            JournalKey::from_bytes([91u8; 32]),
            ReceiptSigner::generate([92u8; 48]),
        );
        let btc_market = "layrs:v5:BTC:USDC:15m:quest-gate";
        core.register_market(
            "sys:direct-btc-market".into(),
            MarketConfig {
                market_id: btc_market.into(),
                settlement_asset: "USDC".into(),
                settlement_decimals: 6,
                public_settlement_chain: Some("horizen".into()),
                opens_at_millis: 1,
                closes_at_millis: 10_000,
                minimum_quantity_micros: 1,
                maximum_quantity_micros: 10_000_000,
                minimum_order_notional_micros: 1,
                maximum_order_notional_micros: 10_000_000,
                maximum_user_position_micros: 10_000_000,
                maximum_pending_bootstrap_notional_micros: 10_000_000,
                tick_size_micros: 1_000,
                oracle_feed_id: 9002,
                fee_profile_id: FeeProfileId::LegacyProfitV1,
                execution: MarketExecution::NativeExactCondition {
                    condition_id: format!("0x{}", "51".repeat(32)),
                    up_outcome_index: 0,
                    down_outcome_index: 1,
                },
            },
            0,
        )
        .expect("register BTC market");
        let order = BookOrder::new(
            "private-user",
            btc_market,
            Outcome::Up,
            OrderAction::Buy,
            500_000,
            1_000_000,
            TimeInForce::Gtc,
            None,
        );
        assert!(direct_btc_order_action(
            &core,
            &UserCommandAction::SubmitOrder {
                order: order.clone()
            }
        ));
        assert!(direct_btc_order_action(
            &core,
            &UserCommandAction::CancelOrder {
                market_id: btc_market.into(),
                order_id: order.order_id,
            }
        ));
        assert!(!direct_btc_order_action(
            &core,
            &UserCommandAction::SubmitOrder {
                order: BookOrder {
                    market_id: "layrs:v5:ETH:USDC:15m:quest-gate".into(),
                    ..order.clone()
                }
            }
        ));
        assert!(!direct_btc_order_action(
            &core,
            &UserCommandAction::RequestWithdrawal {
                withdrawal_id: Uuid::nil(),
                chain: "base".into(),
                asset: "USDC".into(),
                amount_atomic: 1,
                destination: "0x0000000000000000000000000000000000000001".into(),
            }
        ));
    }

    #[test]
    fn direct_withdrawal_gate_accepts_only_valid_base_usdc_user_requests() {
        let withdrawal_id = Uuid::from_u128(41);
        assert!(direct_base_usdc_withdrawal(
            &UserCommandAction::RequestWithdrawal {
                withdrawal_id,
                chain: "base".into(),
                asset: "USDC".into(),
                amount_atomic: 3_706_250,
                destination: "0xE570c6cb9A7D3E46bCA321115019B9e91ad64f7c".into(),
            }
        ));
        for action in [
            UserCommandAction::RequestWithdrawal {
                withdrawal_id: Uuid::nil(),
                chain: "base".into(),
                asset: "USDC".into(),
                amount_atomic: 1,
                destination: "0xE570c6cb9A7D3E46bCA321115019B9e91ad64f7c".into(),
            },
            UserCommandAction::RequestWithdrawal {
                withdrawal_id,
                chain: "horizen".into(),
                asset: "USDC".into(),
                amount_atomic: 1,
                destination: "0xE570c6cb9A7D3E46bCA321115019B9e91ad64f7c".into(),
            },
            UserCommandAction::RequestWithdrawal {
                withdrawal_id,
                chain: "base".into(),
                asset: "ZEN".into(),
                amount_atomic: 1,
                destination: "0xE570c6cb9A7D3E46bCA321115019B9e91ad64f7c".into(),
            },
            UserCommandAction::RequestWithdrawal {
                withdrawal_id,
                chain: "base".into(),
                asset: "USDC".into(),
                amount_atomic: 0,
                destination: "0xE570c6cb9A7D3E46bCA321115019B9e91ad64f7c".into(),
            },
            UserCommandAction::RequestWithdrawal {
                withdrawal_id,
                chain: "base".into(),
                asset: "USDC".into(),
                amount_atomic: 1,
                destination: "0xnot-an-address".into(),
            },
        ] {
            assert!(!direct_base_usdc_withdrawal(&action));
        }
    }

    #[test]
    fn direct_quest_operator_gate_allows_only_session_setup_crypto_and_valid_deposit_credit() {
        let identity_commitment = [7u8; 32];
        assert!(direct_quest_operator_command(
            &OperatorCommand::RegisterSession {
                idempotency_key: "session:test".into(),
                session_id: "session_test".into(),
                identity_commitment,
                public_key: [8u8; 32],
                expires_at_millis: 10_000,
                now_millis: 1,
            }
        ));
        assert!(direct_quest_operator_command(
            &OperatorCommand::RegisterTransferAccount {
                idempotency_key: "transfer-account:session_test".into(),
                identity_commitment,
                now_millis: 1,
            }
        ));
        assert!(direct_quest_operator_command(
            &OperatorCommand::TransferAccountStatus {
                identity_commitment
            }
        ));
        assert!(direct_quest_operator_command(
            &OperatorCommand::CreditDeposit {
                idempotency_key: "deposit:e26d2af6-8edd-5b9c-a2f8-1065d5872063".into(),
                identity_commitment,
                asset: "USDC".into(),
                amount_atomic: 5_000_000,
                evidence_hash: [9; 32],
                now_millis: 1,
            }
        ));
        for command in [
            OperatorCommand::FinalizeWithdrawal {
                idempotency_key: "withdrawal-final:e26d2af6-8edd-5b9c-a2f8-1065d5872063".into(),
                identity_commitment,
                asset: "USDC".into(),
                amount_atomic: 1,
                evidence_hash: [9; 32],
                now_millis: 1,
            },
            OperatorCommand::ReleaseWithdrawal {
                idempotency_key: "withdrawal-release:e26d2af6-8edd-5b9c-a2f8-1065d5872063".into(),
                identity_commitment,
                asset: "USDC".into(),
                amount_atomic: 1,
                evidence_hash: [9; 32],
                now_millis: 1,
            },
            OperatorCommand::ResolutionStatus {
                market_id: "layrs:v5:BTC:USDC:1h:1788390000".into(),
            },
            OperatorCommand::ResolutionReadiness {
                market_id: "layrs:v5:BTC:USDC:1h:1788390000".into(),
                now_millis: 1_788_393_600_000,
            },
        ] {
            assert!(direct_quest_operator_command(&command));
        }
        let withdrawal_id = Uuid::from_u128(42);
        let withdrawal_authorization = WithdrawalAuthorization {
            intent: clob_service::private_core::WithdrawalIntent {
                protocol_version: "layrs.withdrawal.v1".into(),
                withdrawal_id,
                session_id: "session_quest_withdrawal".into(),
                chain: "base".into(),
                asset: "USDC".into(),
                amount_atomic: "2970620".into(),
                destination: "0xE570c6cb9A7D3E46bCA321115019B9e91ad64f7c".into(),
                receipt_id: "receipt_quest_withdrawal".into(),
                enclave_sequence: 7,
                state_root: [4; 32],
                expires_at_millis: 1_000_000,
                recovery_proof: None,
            },
            signature: vec![5; 64],
        };
        assert!(direct_quest_operator_command(
            &OperatorCommand::SignPoolWithdrawal {
                idempotency_key: format!("withdrawal-sign:{withdrawal_id}"),
                authorization: withdrawal_authorization.clone(),
                nonce: 3,
                gas_limit: 180_000,
                max_fee_per_gas_wei: "2".into(),
                max_priority_fee_per_gas_wei: "1".into(),
                now_millis: 100_000,
            }
        ));
        assert!(!direct_quest_operator_command(
            &OperatorCommand::SignPoolWithdrawal {
                idempotency_key: format!("withdrawal-sign:{}", Uuid::from_u128(43)),
                authorization: withdrawal_authorization,
                nonce: 3,
                gas_limit: 180_000,
                max_fee_per_gas_wei: "2".into(),
                max_priority_fee_per_gas_wei: "1".into(),
                now_millis: 100_000,
            }
        ));
        for command in [
            OperatorCommand::CreditDeposit {
                idempotency_key: "deposit:not-a-uuid".into(),
                identity_commitment,
                asset: "USDC".into(),
                amount_atomic: 5_000_000,
                evidence_hash: [9; 32],
                now_millis: 1,
            },
            OperatorCommand::CreditDeposit {
                idempotency_key: "deposit:c8876513-c918-5a5f-aef9-4f6a5f3aae7b".into(),
                identity_commitment,
                asset: "ZEN".into(),
                amount_atomic: 5_000_000,
                evidence_hash: [9; 32],
                now_millis: 1,
            },
            OperatorCommand::CreditDeposit {
                idempotency_key: "deposit:c8876513-c918-5a5f-aef9-4f6a5f3aae7b".into(),
                identity_commitment: [0; 32],
                asset: "USDC".into(),
                amount_atomic: 5_000_000,
                evidence_hash: [9; 32],
                now_millis: 1,
            },
            OperatorCommand::CreditDeposit {
                idempotency_key: "deposit:c8876513-c918-5a5f-aef9-4f6a5f3aae7b".into(),
                identity_commitment,
                asset: "USDC".into(),
                amount_atomic: 4_999_999,
                evidence_hash: [9; 32],
                now_millis: 1,
            },
            OperatorCommand::CreditDeposit {
                idempotency_key: "deposit:c8876513-c918-5a5f-aef9-4f6a5f3aae7b".into(),
                identity_commitment,
                asset: "USDC".into(),
                amount_atomic: 5_000_000,
                evidence_hash: [0; 32],
                now_millis: 1,
            },
        ] {
            assert!(!direct_quest_operator_command(&command));
        }
        let opens_at_millis = 1_788_390_000_000;
        let btc_market = MarketConfig {
            market_id: "layrs:v5:BTC:USDC:1h:1788390000".into(),
            settlement_asset: "USDC".into(),
            settlement_decimals: 6,
            public_settlement_chain: Some("horizen".into()),
            opens_at_millis,
            closes_at_millis: opens_at_millis + 3_600_000,
            minimum_quantity_micros: 1_000,
            maximum_quantity_micros: 1_000_000_000,
            minimum_order_notional_micros: 1_000_000,
            maximum_order_notional_micros: 1_000_000_000,
            maximum_user_position_micros: 2_500_000_000,
            maximum_pending_bootstrap_notional_micros: 1_000_000_000,
            tick_size_micros: 1_000,
            oracle_feed_id: 9_002,
            fee_profile_id: FeeProfileId::LayrsCryptoV2,
            execution: MarketExecution::NativeClob,
        };
        assert!(direct_quest_operator_command(
            &OperatorCommand::MarketStatus {
                market_id: btc_market.market_id.clone(),
            }
        ));
        assert!(direct_quest_operator_command(
            &OperatorCommand::RegisterMarket {
                idempotency_key: format!("market:{}", "ab".repeat(32)),
                market: btc_market.clone(),
                now_millis: opens_at_millis,
            }
        ));
        assert!(direct_quest_operator_command(
            &OperatorCommand::AggregateDepth {
                market_id: btc_market.market_id.clone(),
                outcome: clob_service::private_core::Outcome::Up,
                now_millis: opens_at_millis + 1_000,
                minimum_level_quantity_micros: 5_000_000,
            }
        ));
        assert!(!direct_quest_operator_command(
            &OperatorCommand::AggregateDepth {
                market_id: btc_market.market_id.clone(),
                outcome: clob_service::private_core::Outcome::Up,
                now_millis: opens_at_millis + 1_000,
                minimum_level_quantity_micros: 4_999_999,
            }
        ));
        let zen_market = MarketConfig {
            market_id: "layrs:v4:ZEN:4h:1788390000".into(),
            settlement_asset: "ZEN".into(),
            settlement_decimals: 18,
            public_settlement_chain: Some("horizen".into()),
            opens_at_millis,
            closes_at_millis: opens_at_millis + 14_400_000,
            minimum_quantity_micros: 250_000,
            maximum_quantity_micros: 100_000_000,
            minimum_order_notional_micros: 250_000,
            maximum_order_notional_micros: 100_000_000,
            maximum_user_position_micros: 250_000_000,
            maximum_pending_bootstrap_notional_micros: 100_000_000,
            tick_size_micros: 1_000,
            oracle_feed_id: 9_001,
            fee_profile_id: FeeProfileId::LayrsCryptoV2,
            execution: MarketExecution::NativeClob,
        };
        assert!(direct_quest_operator_command(
            &OperatorCommand::RegisterMarket {
                idempotency_key: format!("market:{}", "cd".repeat(32)),
                market: zen_market,
                now_millis: opens_at_millis,
            }
        ));
        let mut wrong_feed = btc_market.clone();
        wrong_feed.oracle_feed_id = 9_003;
        assert!(!direct_quest_operator_command(
            &OperatorCommand::RegisterMarket {
                idempotency_key: format!("market:{}", "ef".repeat(32)),
                market: wrong_feed,
                now_millis: opens_at_millis,
            }
        ));
        let mut unsupported_window = btc_market;
        unsupported_window.market_id = "layrs:v5:BTC:USDC:4h:1788390000".into();
        unsupported_window.closes_at_millis = opens_at_millis + 14_400_000;
        assert!(!direct_quest_operator_command(
            &OperatorCommand::RegisterMarket {
                idempotency_key: format!("market:{}", "12".repeat(32)),
                market: unsupported_window,
                now_millis: opens_at_millis,
            }
        ));
        assert!(!direct_quest_operator_command(
            &OperatorCommand::ProvisionStatus
        ));
    }

    #[test]
    fn read_only_user_requests_bypass_writer_and_can_observe_committed_pending_state() {
        use clob_service::private_core::{SessionRequest, SignedSessionRequest};

        let request = |action| PlainRequest::User {
            command: UserCommand {
                command_id: "cmd:read-fairness".into(),
                idempotency_key: "idem:read-fairness".into(),
                session: SignedSessionRequest {
                    request: SessionRequest {
                        session_id: "session:read-fairness".into(),
                        sequence: 1,
                        issued_at_millis: 1,
                        expires_at_millis: 10,
                        request_hash: [0u8; 32],
                    },
                    signature: vec![0u8; 64],
                },
                action,
            },
            now_millis: 1,
        };
        let portfolio = request(UserCommandAction::Portfolio);
        assert!(durable_control_request(&portfolio));
        assert!(!request_requires_writer_authorization(&portfolio));

        let cancellation = request(UserCommandAction::CancelOrder {
            market_id: "layrs:v4:test".into(),
            order_id: Uuid::nil(),
        });
        assert!(!durable_control_request(&cancellation));
        assert!(request_requires_writer_authorization(&cancellation));
    }

    fn durable_preparation_fixture() -> DurableCommandPreparation {
        DurableCommandPreparation {
            protocol_version: "layrs.durable-command-preparation.v1".into(),
            environment: "test".into(),
            enclave_measurement_sha384: vec![1; 48],
            preparation_id: [2; 32],
            actor_domain: "OPERATOR".into(),
            command_binding_sha256: [3; 32],
            command_commitment_sha256: [4; 32],
            request_context_sha256: [5; 32],
            request_envelope_sha256: [6; 32],
            command_idempotency_key: "recovery:test:0001".into(),
            writer_epoch: 7,
            writer_lease_id: Uuid::from_u128(8),
            prior_enclave_sequence: 40,
            enclave_sequence: 41,
            prior_state_root: [9; 32],
            prior_journal_head: [10; 32],
            state_root: [11; 32],
            journal_record_hash: [12; 32],
            snapshot_ciphertext_hash: [13; 32],
            response_envelope_sha256: [14; 32],
            response_envelope_bytes: 4_096,
            response_status: 200,
            response_content_type: "application/json".into(),
            receipt_id: "receipt_test_0001".into(),
            prepared_at_millis: 1_000,
            expires_at_millis: 31_000,
            signature: vec![15; 64],
        }
    }

    #[test]
    fn preparation_supersession_requires_a_conflicting_or_later_live_head() {
        let preparation = durable_preparation_fixture();
        assert!(!pending_preparation_is_superseded(
            &preparation,
            preparation.prior_enclave_sequence,
            preparation.prior_state_root,
        ));
        assert!(!pending_preparation_is_superseded(
            &preparation,
            preparation.enclave_sequence,
            preparation.state_root,
        ));
        assert!(pending_preparation_is_superseded(
            &preparation,
            preparation.enclave_sequence,
            [16; 32],
        ));
        assert!(pending_preparation_is_superseded(
            &preparation,
            preparation.enclave_sequence + 1,
            [17; 32],
        ));
    }

    #[test]
    fn preparation_supersession_replay_requires_every_exact_anchor() {
        let certificate = SignedPreparationSupersession {
            protocol_version: "layrs.preparation-supersession.v1".into(),
            environment: "test".into(),
            enclave_measurement_sha384: vec![1; 48],
            request_idempotency_key: "abort:test:0001".into(),
            preparation_id: [2; 32],
            pending_prior_enclave_sequence: 40,
            pending_enclave_sequence: 41,
            pending_prior_state_root: [3; 32],
            pending_state_root: [4; 32],
            live_enclave_sequence: 45,
            live_state_root: [5; 32],
            live_journal_head: [6; 32],
            superseded_at_millis: 1_000,
            signature: vec![7; 64],
        };
        let matches = |request_idempotency_key: &str,
                       preparation_id: [u8; 32],
                       pending_enclave_sequence: u64,
                       pending_state_root: [u8; 32],
                       live_enclave_sequence: u64,
                       live_state_root: [u8; 32],
                       live_journal_head: [u8; 32]| {
            preparation_supersession_matches_request(
                &certificate,
                request_idempotency_key,
                preparation_id,
                pending_enclave_sequence,
                pending_state_root,
                live_enclave_sequence,
                live_state_root,
                live_journal_head,
            )
        };
        assert!(matches(
            "abort:test:0001",
            [2; 32],
            41,
            [4; 32],
            45,
            [5; 32],
            [6; 32],
        ));
        assert!(!matches(
            "abort:test:0002",
            [2; 32],
            41,
            [4; 32],
            45,
            [5; 32],
            [6; 32],
        ));
        assert!(!matches(
            "abort:test:0001",
            [2; 32],
            41,
            [4; 32],
            46,
            [5; 32],
            [6; 32],
        ));
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
