//! Parent boundary for the clean direct runtime.  A Privy-verified BFF mints
//! short-lived signed sessions; the browser never supplies an auth subject or enclave frame.
use aws_sdk_kms::{
    primitives::Blob as KmsBlob,
    types::{DataKeySpec, KeyEncryptionMechanism, RecipientInfo},
    Client as KmsClient,
};
use aws_sdk_s3::{
    primitives::ByteStream,
    types::{CompletedMultipartUpload, CompletedPart, ObjectLockMode, ServerSideEncryption},
    Client as S3Client,
};
use aws_smithy_types::{
    retry::RetryConfig,
    timeout::TimeoutConfig,
    DateTime,
};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use bytes::Bytes;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use hmac::{Hmac, Mac};
use layrs_direct_execution_v1::{
    direct_frame::{CHECKPOINT_FRAME_OVERSIZED, MAX_FRAME_BYTES},
    artifact_hash, identity_commitment_for, reference_for, relay_reference_for, relay_result_hash,valid_layrs_withdrawal_destination,
    relay_reverted_result_hash, request_hash, sha256, sign, DirectAction, DirectReceipt,
    DirectRequest, DirectResult, DirectStateArtifact, DurabilityAck, ExternalEffectIntent,
    ExternalEffectRecovery, FilesystemImmutableArtifactStore, FilesystemImmutableIntentStore,
    GovernedBalanceRecovery, GovernedKeyReleaseArtifact, GovernedMarketRegistration,
    GovernedMarketResolution, ImmutableExternalEffectIntentStore, OrderAction, Outcome,
    ProjectionBalanceRow, ProjectionIdentityRow, ProjectionWalletRow, RelayWithdrawalBinding,
    RuntimeMeasurementBinding, RuntimeRequest, RuntimeResponse, SealedEpoch, TimeInForce,
    WriterGrant, EPOCH_ID, MAX_V70_LINEAGE_RECORDS, POSTGRES_PROJECTION_DDL,
};
use layrs_direct_execution_v1::journal::{
    canonical_receipt_hash, canonical_result_hash, DirectJournalRecord, JournalDurabilityAck,
    DIRECT_JOURNAL_PROTOCOL,
};
use layrs_direct_execution_v1::migration::{
    MigratedTerminalRecord, V70MigrationBundle, V70_MIGRATION_MANIFEST_PROTOCOL,
};
use layrs_direct_execution_v1::request_index::{TerminalRequestLeaf, TerminalResultLocator};
use layrs_direct_execution_v1::receipt_snapshot::DirectReceiptSnapshot;
use layrs_direct_execution_v1::request_index_snapshot::{
    DirectRequestIndexSnapshot, DirectRequestIndexState,
};
use layrs_direct_execution_v1::v71_checkpoint::{DirectV71Checkpoint, DIRECT_V71_CHECKPOINT_PROTOCOL};
use layrs_direct_execution_v1::v71::ArchivedTerminalRecord;
use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    pkcs8::DecodePrivateKey,
};
use postgres_native_tls::MakeTlsConnector;
use reqwest::header::{HeaderMap as ReqwestHeaderMap, HeaderValue, ACCEPT};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use sha3::{Digest as KeccakDigest, Keccak256};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    env,
    fs::{self, OpenOptions},
    future::Future,
    io,
    net::IpAddr,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex as StdMutex,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Mutex, OwnedMutexGuard},
    time::timeout,
};
use tokio_postgres::{Client, NoTls};
use tokio_vsock::{VsockAddr, VsockStream};
const ENCLOSURE_PORT: u32 = 5_003;
const ENCLOSURE_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);
const CHECKPOINT_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
/// Process exit status that tells systemd the enclave holds stale state from a
/// previous parent and must be recreated before the parent starts again.
const ENCLAVE_RESET_EXIT_STATUS: i32 = 3;
const ARCHIVE_OPERATION_TIMEOUT: Duration = Duration::from_secs(60);
const WRITE_PATH_STALL_THRESHOLD: Duration = Duration::from_secs(60);

async fn bounded_enclave_stage<T, F>(duration: Duration, operation: F) -> io::Result<T>
where
    F: Future<Output = io::Result<T>>,
{
    timeout(duration, operation)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "ENCLOSURE_TIMEOUT"))?
}

async fn bounded_archive_operation<T, E, F>(
    duration: Duration,
    operation: F,
) -> Result<Result<T, E>, String>
where
    F: Future<Output = Result<T, E>>,
{
    timeout(duration, operation)
        .await
        .map_err(|_| "ARCHIVE_TIMEOUT".to_string())
}

async fn preflight_then_bootstrap<P, B>(preflight: P, bootstrap: B) -> io::Result<()>
where
    P: Future<Output = io::Result<()>>,
    B: Future<Output = io::Result<()>>,
{
    preflight.await?;
    bootstrap.await
}
// Fixed encrypted-download window, not a verification bypass.
const RESTORE_PREFETCH_WIDTH: usize = 4;
fn restore_prefetch_ranges(total: usize) -> Vec<std::ops::Range<usize>> {
    (0..total).step_by(RESTORE_PREFETCH_WIDTH).map(|start|start..start.saturating_add(RESTORE_PREFETCH_WIDTH).min(total)).collect()
}
const SESSION_AUDIENCE: &str = "layrs.direct-execution.v1";
const DIRECT_SESSION_KEY_DERIVATION_DOMAIN: &[u8] = b"layrs.direct-session.v1\0";
const BASE_USDC_ADDRESS: &str = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
const ERC20_TRANSFER_TOPIC: &str =
    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const POOL_WITHDRAW_TOPIC: &str =
    "0xcbcdbdf10631a43cc99c80acace8232649421c3f4f73919f16013d47c83a687a";
const USER_OPERATION_EVENT_TOPIC: &str =
    "0x49628fd1471006c1482da88028e9ce4dbb080b815c9b0344d39e5a8e6ec1419f";
#[path = "../zen_custody.rs"]
mod zen_custody;
use zen_custody::ZenCustodyAdapter;
#[path = "../usdc_custody.rs"]
mod usdc_custody;
use usdc_custody::UsdcCustodyAdapter;
#[path = "../usdc_wallet_link.rs"]
mod usdc_wallet_link;
use usdc_wallet_link::{WalletLinkAuthority,WalletLinkGrant};
#[path = "../usdc_bus_custody.rs"]
mod usdc_bus_custody;
use usdc_bus_custody::{UsdcBusCustodyAdapter,BusDepositProof,BusDepositFinalizationProof};
#[derive(Clone)]
struct AppState {
    enclave_cid: u32,
    session_key: Vec<u8>,
    isolated_test: bool,
    projection: Option<Projection>,
    local_used_sessions: Arc<Mutex<HashSet<(String, String)>>>,
    artifact_store: Option<ArchiveStore>,
    commit_ack_key: Vec<u8>,
    custody: Option<PrivyBaseCustodyAdapter>,
    zen_custody: Option<ZenCustodyAdapter>,
    usdc_custody: Option<UsdcCustodyAdapter>,
    usdc_link_authority: Option<WalletLinkAuthority>,
    usdc_bus_custody: Option<UsdcBusCustodyAdapter>,
    /// Serializes only the bounded synchronous request and an unresolved
    /// external intent.  It is process memory, never durable workflow state.
    financial_gate: Arc<FinancialGate>,
    last_commit_at: Arc<AtomicU64>,
    health: Arc<ParentHealth>,
    committed_state_root: Arc<Mutex<Option<String>>>,
    unresolved_external_effects: Arc<Mutex<BTreeMap<String, ExternalEffectIntent>>>,
    governed_bootstrap: Option<GovernedBootstrapConfig>,
    persistence_format: PersistenceFormat,
    /// Set only after a verified v71 restore or same-process shadow promotion.
    /// This is a format selector, not command/workflow persistence.
    hot_v71_enabled: Arc<AtomicBool>,
    journal_request_index: Arc<Mutex<Option<DirectRequestIndexState>>>,
    journal_receipts:
        Arc<Mutex<Option<BTreeMap<(String, String), (u64, DirectReceipt)>>>>,
    journal_migration: Arc<Mutex<Option<V70MigrationBundle>>>,
    journal_checkpoint_sequence: Arc<AtomicU64>,
    /// Authenticated v71 transition roots retained for restart-safe intent
    /// lineage checks. Checkpoints are never sealed with an unresolved effect,
    /// so checkpoint plus tail always covers every recoverable intent root.
    journal_transition_roots: Arc<Mutex<Option<BTreeMap<u64, String>>>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PersistenceFormat {
    V70,
    V71,
    V71Hot,
    /// v70 persistence over a sparse rollback archive that begins at the
    /// governed grant's exact committed frontier. Never selected implicitly.
    V70RollbackBaseline,
}

impl PersistenceFormat {
    fn parse(value: Option<&str>) -> Result<Self, &'static str> {
        match value {
            None | Some("v70") => Ok(Self::V70),
            Some("v71") => Ok(Self::V71),
            Some("v71-hot") => Ok(Self::V71Hot),
            Some("v70-rollback-baseline") => Ok(Self::V70RollbackBaseline),
            Some(_) => Err("invalid direct persistence format"),
        }
    }
}

impl AppState {
    fn effective_persistence_format(&self) -> PersistenceFormat {
        match self.persistence_format {
            PersistenceFormat::V71 => PersistenceFormat::V71,
            PersistenceFormat::V71Hot if self.hot_v71_enabled.load(Ordering::Acquire) => {
                PersistenceFormat::V71
            }
            PersistenceFormat::V71Hot => PersistenceFormat::V70,
            other => other,
        }
    }
}

/// Health is sampled once in the background, never by competing NLB requests.
/// A successful commit is stronger liveness evidence than a delayed status read.
#[derive(Default)]
struct ParentHealth {
    restored: AtomicBool,
    last_response_at: AtomicU64,
}
const HEALTH_FRESHNESS_SECONDS: u64 = 45;

impl ParentHealth {
    fn observe(&self, now: u64) { self.last_response_at.store(now, Ordering::Release); }
    fn check(&self, now: u64, last_commit: u64, stalled_waiter: bool, grant_expired: bool) -> Result<(), &'static str> {
        if !self.restored.load(Ordering::Acquire) { return Err("DIRECT_STATE_RECOVERY_REQUIRED"); }
        if grant_expired { return Err("WRITER_AUTHORIZATION_EXPIRED"); }
        let commit_recent = last_commit != 0 && now.checked_sub(last_commit).is_some_and(|age| age < WRITE_PATH_STALL_THRESHOLD.as_secs());
        if stalled_waiter && !commit_recent { return Err("WRITE_PATH_STALLED"); }
        let last = self.last_response_at.load(Ordering::Acquire).max(last_commit);
        if last == 0 || !now.checked_sub(last).is_some_and(|age| age <= HEALTH_FRESHNESS_SECONDS) {
            return Err("ENCLOSURE_UNAVAILABLE");
        }
        Ok(())
    }
}

fn start_health_observer(state: AppState) {
    tokio::spawn(async move {
        loop {
            if let Ok(RuntimeResponse::Status { .. }) = exchange(&state, RuntimeRequest::Status).await {
                state.health.observe(now_unix());
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });
}

/// Removes a cancelled lock wait, so it cannot become a permanent false stall.
struct FinancialWaitRegistration<'a> { gate: &'a FinancialGate, id: u64 }
impl Drop for FinancialWaitRegistration<'_> {
    fn drop(&mut self) { self.gate.waiters.lock().expect("financial waiter tracker poisoned").remove(&self.id); }
}

/// Tracks contention without putting the health endpoint behind the write
/// mutex it is meant to supervise. Waiting registrations live only for the
/// duration of `lock`, and the returned owned guard can safely move into a
/// cancellation-independent task.
struct FinancialGate {
    inner: Arc<Mutex<()>>,
    next_waiter_id: AtomicU64,
    waiters: StdMutex<BTreeMap<u64, u64>>,
}

impl FinancialGate {
    fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(())),
            next_waiter_id: AtomicU64::new(1),
            waiters: StdMutex::new(BTreeMap::new()),
        }
    }

    async fn lock(&self, stage: &'static str) -> OwnedMutexGuard<()> {
        let waiter_id = self.next_waiter_id.fetch_add(1, Ordering::Relaxed);
        self.waiters
            .lock()
            .expect("financial waiter tracker poisoned")
            .insert(waiter_id, now_unix());
        eprintln!("FINANCIAL_GATE_AWAIT stage={stage}");
        let waiting = FinancialWaitRegistration { gate: self, id: waiter_id };
        let guard = Arc::clone(&self.inner).lock_owned().await;
        drop(waiting);
        eprintln!("FINANCIAL_GATE_ACQUIRED stage={stage}");
        guard
    }

    fn snapshot(&self, now: u64) -> (usize, Option<u64>) {
        let waiters = self
            .waiters
            .lock()
            .expect("financial waiter tracker poisoned");
        let oldest = waiters.values().min().copied();
        (waiters.len(), oldest.map(|started| now.saturating_sub(started)))
    }

    fn stalled(&self, now: u64) -> bool {
        self.snapshot(now)
            .1
            .is_some_and(|age| age >= WRITE_PATH_STALL_THRESHOLD.as_secs())
    }
}

#[derive(Clone)]
struct GovernedBootstrapConfig {
    grant: WriterGrant,
    binding: RuntimeMeasurementBinding,
    kms_key_id: String,
    requested_mode: String,
}

#[derive(Clone)]
enum ArchiveStore {
    Filesystem(FilesystemImmutableArtifactStore),
    S3(S3ImmutableArtifactStore),
}

#[derive(Clone)]
struct S3ImmutableArtifactStore {
    client: S3Client,
    bucket: String,
    prefix: String,
    kms_key_id: String,
    retention_seconds: i64,
    // Receipt-only cache built after full encrypted-chain verification. It is
    // never a state-restore input and never contains private ledger plaintext.
    verified_receipt_records: Arc<Mutex<Option<Vec<DirectStateArtifact>>>>,
    verified_artifact_hashes: Arc<Mutex<Vec<String>>>,
    prepared_restore: Arc<Mutex<Option<PreparedArchiveRestore>>>,
    prepared_journal_restore: Arc<Mutex<Option<PreparedJournalRestore>>>,
    checkpoint_refresh_gate: Arc<Mutex<CheckpointRefresh>>,
    // v71 append eligibility. Always `Unrestored` until the v71 restore path
    // exists; live v70 never reads or advances it.
    journal: Arc<Mutex<JournalWriterState>>,
    journal_role: JournalRole,
}

#[derive(Clone, Debug, PartialEq)]
struct ResolvedArchiveHead {
    key: String,
    sequence: u64,
    artifact_hash: String,
}

#[derive(Clone)]
struct PreparedArchiveRestore {
    keys: Vec<String>,
    heads: Vec<ResolvedArchiveHead>,
    checkpoint_keys: Vec<String>,
}

#[derive(Clone)]
struct PreparedJournalRestore {
    checkpoint: DirectV71Checkpoint,
    tail: Vec<DirectJournalRecord>,
    index_snapshot: DirectRequestIndexSnapshot,
    receipt_snapshot: DirectReceiptSnapshot,
    migration: Option<V70MigrationBundle>,
}

const V71_CUTOVER_MARKER_PROTOCOL: &str = "layrs.direct-execution.v71-cutover.v1";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct V71CutoverMarker {
    protocol: String,
    epoch_id: String,
    writer_epoch: String,
    sequence: u64,
    record_hash: String,
    transition_root: String,
    request_index_root: String,
    financial_state_root: String,
}

impl V71CutoverMarker {
    fn from_head(head: &StagedV71Head) -> Self {
        Self {
            protocol: V71_CUTOVER_MARKER_PROTOCOL.into(),
            epoch_id: EPOCH_ID.into(),
            writer_epoch: head.writer_epoch.clone(),
            sequence: head.sequence,
            record_hash: head.record_hash.clone(),
            transition_root: head.transition_root.clone(),
            request_index_root: head.request_index_root.clone(),
            financial_state_root: head.financial_state_root.clone(),
        }
    }

    fn valid(&self) -> bool {
        self.protocol == V71_CUTOVER_MARKER_PROTOCOL
            && self.epoch_id == EPOCH_ID
            && !self.writer_epoch.is_empty()
            && self.sequence > 0
            && [
                &self.record_hash,
                &self.transition_root,
                &self.request_index_root,
                &self.financial_state_root,
            ]
            .into_iter()
            .all(|digest| {
                digest.len() == 64
                    && digest
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
    }
}

const CHECKPOINT_REFRESH_INTERVAL: Duration = Duration::from_secs(5 * 60);
const CHECKPOINT_OVERSIZED: &str = "checkpoint frame oversized";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CheckpointRefreshOutcome {
    Persisted,
    Failed,
    Skipped,
}
#[derive(Default)]
struct CheckpointRefresh {
    running: bool,
    requested: bool,
    disabled: bool,
    next_start: Option<tokio::time::Instant>,
}
impl CheckpointRefresh {
    fn request(&mut self) -> bool {
        if self.disabled { return false; }
        self.requested = true;
        if self.running { false } else { self.running = true; true }
    }
    fn delay(&self, now: tokio::time::Instant) -> Duration {
        self.next_start.map(|next| next.saturating_duration_since(now)).unwrap_or_default()
    }
    fn begin(&mut self, now: tokio::time::Instant) {
        self.requested = false;
        self.next_start = Some(now + CHECKPOINT_REFRESH_INTERVAL);
    }
    fn finish(&mut self, outcome: CheckpointRefreshOutcome) -> bool {
        self.running = match outcome {
            // Retain work arriving during a refresh, and retry a failed refresh
            // even if trading becomes quiet. Original journals remain authoritative.
            CheckpointRefreshOutcome::Persisted => self.requested,
            CheckpointRefreshOutcome::Failed => true,
            // Retrying cannot shrink an oversized checkpoint. Return to idle;
            // later commits remain disabled until restart or upgrade.
            CheckpointRefreshOutcome::Skipped => {
                self.requested = false;
                self.disabled = true;
                false
            }
        };
        self.running
    }
}
/// Finite diagnostic label; storage and transport error text is never echoed.
fn checkpoint_seal_reason(error: &str) -> &'static str {
    match error {
        CHECKPOINT_OVERSIZED => "oversized",
        "checkpoint seal transport failed" => "transport",
        "checkpoint seal rejected" => "head_validation",
        "checkpoint head mismatch" => "archive_head",
        "journal checkpoint external effect pending" => "external_effect_pending",
        "journal checkpoint head unavailable" => "journal_head",
        "journal checkpoint cache unavailable" => "journal_cache",
        _ => "archive_read_or_write",
    }
}
/// Background checkpoint refresh. Exits when idle. Its seal closure takes the
/// financial gate so full-state checkpoint and commit buffers never overlap.
async fn refresh_checkpoints<F, Fut>(gate: &Mutex<CheckpointRefresh>, mut seal: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<(), String>>,
{
    loop {
        let delay = gate.lock().await.delay(tokio::time::Instant::now());
        tokio::time::sleep(delay).await;
        gate.lock().await.begin(tokio::time::Instant::now());
        let outcome = match seal().await {
            Ok(()) => CheckpointRefreshOutcome::Persisted,
            Err(error) if error == CHECKPOINT_OVERSIZED => {
                eprintln!("VERIFIED_ARCHIVE_CHECKPOINT_REFRESH_SKIPPED reason=oversized");
                CheckpointRefreshOutcome::Skipped
            }
            Err(error) => {
                let reason = checkpoint_seal_reason(&error);
                eprintln!("VERIFIED_ARCHIVE_CHECKPOINT_REFRESH_PENDING reason={reason}");
                CheckpointRefreshOutcome::Failed
            }
        };
        if !gate.lock().await.finish(outcome) { break; }
    }
}

/// Runs only the exact-head snapshot phase while commits are excluded. The
/// caller owns any immutable persistence after this returns, so a slow S3 PUT
/// cannot extend the financial-gate hold.
async fn checkpoint_snapshot_under_gate<T, F, Fut>(
    gate: &FinancialGate,
    snapshot: F,
) -> (Result<T, String>, Duration, Duration)
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<T, String>>,
{
    let wait_started = Instant::now();
    let guard = gate.lock("checkpoint_snapshot").await;
    let wait = wait_started.elapsed();
    let hold_started = Instant::now();
    let result = snapshot().await;
    let hold = hold_started.elapsed();
    drop(guard);
    (result, wait, hold)
}

/// Direct, synchronous adapter for the existing Base pool-ledger Privy
/// wallet.  It has no local task state: all recovery derives from the
/// immutable intent and Privy's own reference lookup plus Base finality.
#[derive(Clone)]
struct PrivyBaseCustodyAdapter {
    client: reqwest::Client,
    app_id: String,
    app_secret: String,
    wallet_id: String,
    wallet_address: String,
    authorization_key_pem: String,
    rpc_url: String,
    pool_address: String,
    confirmations: u64,
    api_base_url: String,
    relay_api_key: Option<String>,
    relay_api_base_url: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DepositFinality {
    Pending,
    Finalized,
    Reverted,
    Conflict,
}

impl PrivyBaseCustodyAdapter {
    fn from_environment() -> Result<Option<Self>, String> {
        match env::var("LAYRS_DIRECT_CUSTODY_PROVIDER").as_deref() {
            Err(_) | Ok("") => Ok(None),
            Ok("privy-base-existing-pool-ledger") => {
                let required =
                    |name: &str| env::var(name).map_err(|_| format!("{name} is required"));
                let wallet_address =
                    canonical_evm_address(&required("LAYRSV2_BASE_POOL_LEDGER_PRIVY_ADDRESS")?)?;
                let pool_address = canonical_evm_address(&required("LAYRSV2_BASE_POOL_ADDRESS")?)?;
                // Reuse the established Base finality setting.  There is no
                // direct-runtime default: accepting a weaker confirmation
                // threshold than the operational custody path would weaken
                // the withdrawal invariant.
                let confirmations = required("LAYRSV2_BASE_CONFIRMATIONS")?
                    .parse::<u64>()
                    .map_err(|_| "invalid Base confirmation count")?;
                if confirmations == 0 {
                    return Err("invalid Base confirmation count".into());
                }
                let mut default_headers = ReqwestHeaderMap::new();
                // Match the existing operational Privy client exactly.  This
                // is a provider routing contract, not a new credential or a
                // weaker authorization scheme.
                default_headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
                Ok(Some(Self {
                    client: reqwest::Client::builder()
                        .https_only(true)
                        .timeout(Duration::from_secs(15))
                        .user_agent("layrsv2-public-api/1.0")
                        .default_headers(default_headers)
                        .build()
                        .map_err(|_| "custody HTTP client unavailable")?,
                    app_id: required("LAYRSV2_PRIVY_APP_ID")?,
                    app_secret: required("LAYRSV2_PRIVY_APP_SECRET")?,
                    wallet_id: required("LAYRSV2_BASE_POOL_LEDGER_PRIVY_WALLET_ID")?,
                    wallet_address,
                    authorization_key_pem: required(
                        "LAYRSV2_BASE_POOL_LEDGER_PRIVY_AUTH_PRIVATE_KEY_PEM",
                    )?
                    .replace("\\n", "\n"),
                    rpc_url: required("LAYRSV2_BASE_RPC_URL")?,
                    pool_address,
                    confirmations,
                    api_base_url: env::var("LAYRS_DIRECT_PRIVY_API_BASE_URL")
                        .unwrap_or_else(|_| "https://api.privy.io".into())
                        .trim_end_matches('/')
                        .into(),
                    relay_api_key: env::var("LAYRSV2_RELAY_API_KEY")
                        .ok()
                        .filter(|value| !value.trim().is_empty()),
                    relay_api_base_url: env::var("LAYRSV2_RELAY_BASE_URL")
                        .unwrap_or_else(|_| "https://api.relay.link".into())
                        .trim_end_matches('/')
                        .into(),
                }))
            }
            Ok(_) => Err("unsupported direct custody provider".into()),
        }
    }

    async fn settle(
        &self,
        intent: &ExternalEffectIntent,
        now: u64,
    ) -> Result<layrs_direct_execution_v1::ExternalEffectRecovery, String> {
        self.validate_intent(intent)?;
        let observation = self.observe(intent).await?;
        match intent.recovery_action(now, observation) {
            layrs_direct_execution_v1::ExternalEffectRecovery::SubmitWithStableReference => {
                self.submit_once(intent).await?;
                let observed = self.observe(intent).await?;
                Ok(match observed {
                    // The provider may not index a just-accepted sponsored
                    // transaction immediately.  Never issue a second send in
                    // this request; wait for the same stable reference.
                    layrs_direct_execution_v1::ExternalEffectObservation::NotFound => {
                        ExternalEffectRecovery::AwaitExternalFinality
                    }
                    observed => intent.recovery_action(now, observed),
                })
            }
            decision => Ok(decision),
        }
    }

    /// Historical reconciliation must have no path to submit_once, even if
    /// the provider temporarily loses its reference index.
    async fn observe_terminal_only(&self, intent: &ExternalEffectIntent) -> Result<ExternalEffectRecovery, String> {
        self.validate_intent(intent)?;
        let outcome = intent.recovery_action(now_unix(), self.observe(intent).await?);
        observed_terminal_recovery(outcome)
    }

    fn validate_intent(&self, intent: &ExternalEffectIntent) -> Result<(), String> {
        intent
            .verify()
            .map_err(|_| "external-effect intent invalid")?;
        if intent.chain != "base"
            || intent.asset != "USDC"
            || intent.provider_wallet_id != self.wallet_id
            || intent.custody_target != self.pool_address
        {
            return Err("existing Base custody adapter cannot settle this intent".into());
        }
        Ok(())
    }

    async fn observe(
        &self,
        intent: &ExternalEffectIntent,
    ) -> Result<layrs_direct_execution_v1::ExternalEffectObservation, String> {
        let url = format!("{}/v1/transactions", self.api_base_url);
        let response = self
            .client
            .get(url)
            .query(&[("reference_id", intent.external_effect_reference.as_str())])
            .header("authorization", self.basic_authorization())
            .header("privy-app-id", &self.app_id)
            .send()
            .await
            .map_err(|_| "custody provider lookup failed")?;
        if !response.status().is_success() {
            return Err("custody provider lookup rejected".into());
        }
        let body: Value = response
            .json()
            .await
            .map_err(|_| "custody provider lookup malformed")?;
        let records = body
            .as_array()
            .or_else(|| body.get("data").and_then(Value::as_array))
            .or_else(|| body.get("transactions").and_then(Value::as_array))
            .ok_or("custody provider lookup malformed")?;
        let matching: Vec<&Value> = records
            .iter()
            .filter(|record| {
                record.get("wallet_id").and_then(Value::as_str) == Some(self.wallet_id.as_str())
                    && record.get("caip2").and_then(Value::as_str) == Some("eip155:8453")
                    && record.get("reference_id").and_then(Value::as_str)
                        == Some(intent.external_effect_reference.as_str())
            })
            .collect();
        if matching.is_empty() {
            return Ok(layrs_direct_execution_v1::ExternalEffectObservation::NotFound);
        }
        if matching.len() != 1 {
            return Ok(layrs_direct_execution_v1::ExternalEffectObservation::Conflict);
        }
        let record = matching[0];
        let id = record
            .get("id")
            .and_then(Value::as_str)
            .ok_or("custody provider transaction ID missing")?
            .to_owned();
        let status = record
            .get("status")
            .and_then(Value::as_str)
            .ok_or("custody provider status missing")?;
        let transaction_hash = record
            .get("transaction_hash")
            .and_then(Value::as_str)
            .filter(|value| valid_transaction_hash(value))
            .map(str::to_owned);
        let sponsored = record.get("sponsored").and_then(Value::as_bool) == Some(true);
        let user_operation_hash = record
            .get("user_operation_hash")
            .and_then(Value::as_str)
            .filter(|value| valid_transaction_hash(value))
            .map(str::to_owned);
        match status {
            "pending" | "broadcasted" => Ok(
                layrs_direct_execution_v1::ExternalEffectObservation::Pending {
                    provider_transaction_id: id,
                },
            ),
            "confirmed" | "finalized" => match transaction_hash {
                Some(transaction_hash) => {
                    self.authoritative_finality(
                        intent,
                        id,
                        transaction_hash,
                        sponsored,
                        user_operation_hash,
                    )
                    .await
                }
                None => Ok(
                    layrs_direct_execution_v1::ExternalEffectObservation::Pending {
                        provider_transaction_id: id,
                    },
                ),
            },
            "execution_reverted" => match transaction_hash {
                Some(transaction_hash) => {
                    self.authoritative_finality(
                        intent,
                        id,
                        transaction_hash,
                        sponsored,
                        user_operation_hash,
                    )
                    .await
                }
                None => Ok(layrs_direct_execution_v1::ExternalEffectObservation::Conflict),
            },
            "failed" | "replaced" | "provider_error" => {
                Ok(layrs_direct_execution_v1::ExternalEffectObservation::Conflict)
            }
            _ => Ok(layrs_direct_execution_v1::ExternalEffectObservation::Conflict),
        }
    }

    async fn submit_once(&self, intent: &ExternalEffectIntent) -> Result<(), String> {
        let data = pool_withdraw_calldata(&intent.destination, &intent.amount_atomic)?;
        let body = json!({
            "method": "eth_sendTransaction",
            "caip2": "eip155:8453",
            "chain_type": "ethereum",
            "sponsor": true,
            "reference_id": intent.external_effect_reference,
            "params": { "transaction": {
                "from": self.wallet_address,
                "to": intent.custody_target,
                "value": "0x0",
                "chain_id": 8453,
                "data": data,
                "gas_limit": quantity(intent.gas_limit.parse::<u128>().map_err(|_| "intent gas limit invalid")?),
                "nonce": quantity(intent.transaction_nonce.parse::<u128>().map_err(|_| "intent nonce invalid")?),
                "max_fee_per_gas": quantity(intent.max_fee_per_gas.parse::<u128>().map_err(|_| "intent fee invalid")?),
                "max_priority_fee_per_gas": quantity(intent.max_priority_fee_per_gas.parse::<u128>().map_err(|_| "intent priority fee invalid")?),
            }}
        });
        let url = format!("{}/v1/wallets/{}/rpc", self.api_base_url, self.wallet_id);
        let response = self
            .client
            .post(&url)
            .headers(self.privy_authorization_headers(
                &url,
                &body,
                &intent.provider_idempotency_key,
            )?)
            .json(&body)
            .send()
            .await
            .map_err(|_| "custody provider submission failed")?;
        if !response.status().is_success() {
            return Err("custody provider submission rejected".into());
        }
        let response: Value = response
            .json()
            .await
            .map_err(|_| "custody provider submission malformed")?;
        let data = response
            .get("data")
            .ok_or("custody provider submission malformed")?;
        if data.get("caip2").and_then(Value::as_str) != Some("eip155:8453")
            || data.get("transaction_id").and_then(Value::as_str).is_none()
            || data.get("reference_id").and_then(Value::as_str)
                != Some(intent.external_effect_reference.as_str())
        {
            return Err("custody provider submission binding mismatch".into());
        }
        Ok(())
    }

    async fn transaction_parameters(&self) -> Result<(u128, u128, u128, u128), String> {
        let chain = self
            .rpc("eth_chainId", json!([]))
            .await?
            .as_str()
            .and_then(parse_quantity)
            .ok_or("Base RPC chain ID malformed")?;
        if chain != 8453 {
            return Err("Base RPC chain ID mismatch".into());
        }
        let nonce = self
            .rpc(
                "eth_getTransactionCount",
                json!([self.wallet_address, "pending"]),
            )
            .await?
            .as_str()
            .and_then(parse_quantity)
            .ok_or("Base RPC nonce malformed")?;
        let block = self
            .rpc("eth_getBlockByNumber", json!(["latest", false]))
            .await?;
        let base_fee = block
            .get("baseFeePerGas")
            .and_then(Value::as_str)
            .and_then(parse_quantity)
            .or_else(|| None)
            .ok_or("Base RPC fee data missing")?;
        let priority = match self.rpc("eth_maxPriorityFeePerGas", json!([])).await {
            Ok(value) => value
                .as_str()
                .and_then(parse_quantity)
                .unwrap_or(1_000_000_000),
            Err(_) => 1_000_000_000,
        };
        Ok((
            nonce,
            180_000,
            base_fee.saturating_mul(2).saturating_add(priority),
            priority,
        ))
    }

    async fn authoritative_finality(
        &self,
        intent: &ExternalEffectIntent,
        provider_transaction_id: String,
        transaction_hash: String,
        sponsored: bool,
        user_operation_hash: Option<String>,
    ) -> Result<layrs_direct_execution_v1::ExternalEffectObservation, String> {
        let transaction = self
            .rpc("eth_getTransactionByHash", json!([transaction_hash]))
            .await?;
        if transaction.is_null() {
            return Ok(
                layrs_direct_execution_v1::ExternalEffectObservation::Pending {
                    provider_transaction_id,
                },
            );
        }
        if !sponsored {
            let expected_data = pool_withdraw_calldata(&intent.destination, &intent.amount_atomic)?;
            if transaction
                .get("from")
                .and_then(Value::as_str)
                .and_then(|value| canonical_evm_address(value).ok())
                .as_deref()
                != Some(self.wallet_address.as_str())
                || transaction
                    .get("to")
                    .and_then(Value::as_str)
                    .and_then(|value| canonical_evm_address(value).ok())
                    .as_deref()
                    != Some(self.pool_address.as_str())
                || transaction
                    .get("input")
                    .and_then(Value::as_str)
                    .map(|value| value.eq_ignore_ascii_case(&expected_data))
                    != Some(true)
            {
                return Ok(layrs_direct_execution_v1::ExternalEffectObservation::Conflict);
            }
        }
        let receipt = self
            .rpc("eth_getTransactionReceipt", json!([transaction_hash]))
            .await?;
        if receipt.is_null() {
            return Ok(
                layrs_direct_execution_v1::ExternalEffectObservation::Pending {
                    provider_transaction_id,
                },
            );
        }
        let block_number = receipt
            .get("blockNumber")
            .and_then(Value::as_str)
            .and_then(parse_quantity)
            .ok_or("Base receipt block number malformed")?;
        let block_hash = receipt
            .get("blockHash")
            .and_then(Value::as_str)
            .filter(|value| valid_transaction_hash(value))
            .ok_or("Base receipt block hash malformed")?;
        let status = receipt
            .get("status")
            .and_then(Value::as_str)
            .ok_or("Base receipt status malformed")?;
        let head = self
            .rpc("eth_blockNumber", json!([]))
            .await?
            .as_str()
            .and_then(parse_quantity)
            .ok_or("Base RPC head malformed")?;
        if head
            .checked_sub(block_number)
            .and_then(|value| value.checked_add(1))
            .unwrap_or(0)
            < u128::from(self.confirmations)
        {
            return Ok(
                layrs_direct_execution_v1::ExternalEffectObservation::Pending {
                    provider_transaction_id,
                },
            );
        }
        // A receipt must be bound to its reported block hash before it can be
        // terminally transcribed into a private artifact.
        if block_hash.len() != 66 {
            return Ok(layrs_direct_execution_v1::ExternalEffectObservation::Conflict);
        }
        match status {
            "0x1"
                if !sponsored
                    || sponsored_withdrawal_receipt_matches(
                        intent,
                        &self.wallet_address,
                        &self.pool_address,
                        user_operation_hash.as_deref(),
                        &receipt,
                    ) =>
            {
                if intent.relay.is_some() {
                    return self
                        .relay_destination_finality(
                            intent,
                            provider_transaction_id,
                            transaction_hash,
                        )
                        .await;
                }
                Ok(
                    layrs_direct_execution_v1::ExternalEffectObservation::Finalized {
                        provider_transaction_id,
                        transaction_hash,
                    },
                )
            }
            "0x0" => Ok(
                layrs_direct_execution_v1::ExternalEffectObservation::Reverted {
                    provider_transaction_id,
                    transaction_hash,
                },
            ),
            _ => Ok(layrs_direct_execution_v1::ExternalEffectObservation::Conflict),
        }
    }

    /// Relay intake on Base is not withdrawal finality.  Once the intake leg
    /// has authoritative Base finality, synchronously observe Relay's
    /// provider-owned request and bind the destination result.  This function
    /// creates no job or persisted lifecycle; restart calls the same lookup
    /// from the write-once external-effect intent.
    async fn relay_destination_finality(
        &self,
        intent: &ExternalEffectIntent,
        provider_transaction_id: String,
        intake_transaction_hash: String,
    ) -> Result<layrs_direct_execution_v1::ExternalEffectObservation, String> {
        let relay = intent
            .relay
            .as_ref()
            .ok_or("Relay binding missing from external-effect intent")?;
        let api_key = self
            .relay_api_key
            .as_deref()
            .ok_or("Relay authoritative observation is not configured")?;
        let status: Value = self
            .client
            .get(format!("{}/intents/status/v3", self.relay_api_base_url))
            .query(&[("requestId", relay.request_id.as_str())])
            .header("x-api-key", api_key)
            .send()
            .await
            .map_err(|_| "Relay status lookup failed")?
            .error_for_status()
            .map_err(|_| "Relay status lookup rejected")?
            .json()
            .await
            .map_err(|_| "Relay status lookup malformed")?;
        let details: Value = self
            .client
            .get(format!("{}/requests/v3", self.relay_api_base_url))
            .query(&[("id", relay.request_id.as_str())])
            .header("x-api-key", api_key)
            .send()
            .await
            .map_err(|_| "Relay request lookup failed")?
            .error_for_status()
            .map_err(|_| "Relay request lookup rejected")?
            .json()
            .await
            .map_err(|_| "Relay request lookup malformed")?;
        let forwarding = if relay_hashes(status.get("inTxHashes"))
            .iter().any(|hash| hash.eq_ignore_ascii_case(&intake_transaction_hash)) {
            None
        } else if let Some(hash) = relay_forwarding_candidate(intent, &self.pool_address, &intake_transaction_hash, &status, &details) {
            // GET/RPC observation only. Never submit or repeat either transfer.
            let deposit_receipt = self.rpc("eth_getTransactionReceipt", json!([intake_transaction_hash])).await?;
            let deposit_number = deposit_receipt.get("blockNumber").and_then(Value::as_str).ok_or("Relay deposit receipt pending")?;
            let deposit_block = self.rpc("eth_getBlockByNumber", json!([deposit_number, false])).await?;
            let receipt = self.rpc("eth_getTransactionReceipt", json!([hash])).await?;
            let block_number = receipt.get("blockNumber").and_then(Value::as_str).ok_or("Relay forwarding receipt pending")?;
            let block = self.rpc("eth_getBlockByNumber", json!([block_number, false])).await?;
            let head = self.rpc("eth_blockNumber", json!([])).await?.as_str().and_then(parse_quantity).ok_or("Base head malformed")?;
            if !relay_forwarding_is_canonical(intent, &self.pool_address, &intake_transaction_hash, &hash, &deposit_receipt, &deposit_block, &receipt, &block, head, self.confirmations) {
                return Ok(layrs_direct_execution_v1::ExternalEffectObservation::Conflict);
            }
            Some(VerifiedRelayForwarding { deposit_hash: intake_transaction_hash.clone(), forwarding_hash: hash })
        } else { None };
        classify_relay_destination_finality_with_forwarding(
            intent,
            provider_transaction_id,
            intake_transaction_hash,
            &status,
            &details,
            forwarding.as_ref(),
        )
    }

    /// Verify one inbound Base USDC transfer from the authenticated embedded
    /// wallet into the existing pool custody address. This is a synchronous
    /// chain observation only: it creates no job, queue, lease, or database
    /// command state. The enclave consumes the transaction hash exactly once.
    async fn deposit_finality(
        &self,
        source_wallet: &str,
        transaction_hash: &str,
        amount_atomic: &str,
    ) -> Result<DepositFinality, String> {
        let source_wallet = canonical_evm_address(source_wallet)?;
        if !valid_transaction_hash(transaction_hash) {
            return Err("deposit transaction hash invalid".into());
        }
        let amount = amount_atomic
            .parse::<u128>()
            .ok()
            .filter(|value| *value > 0)
            .ok_or("deposit amount invalid")?;
        let transaction = self
            .rpc("eth_getTransactionByHash", json!([transaction_hash]))
            .await?;
        if transaction.is_null() {
            return Ok(DepositFinality::Pending);
        }
        let receipt = self
            .rpc("eth_getTransactionReceipt", json!([transaction_hash]))
            .await?;
        if receipt.is_null() {
            return Ok(DepositFinality::Pending);
        }
        let head = self
            .rpc("eth_blockNumber", json!([]))
            .await?
            .as_str()
            .and_then(parse_quantity)
            .ok_or("Base RPC head malformed")?;
        classify_base_deposit(
            &source_wallet,
            &self.pool_address,
            transaction_hash,
            amount,
            self.confirmations,
            &transaction,
            &receipt,
            head,
        )
    }

    async fn rpc(&self, method: &str, params: Value) -> Result<Value, String> {
        let response = self
            .client
            .post(&self.rpc_url)
            .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
            .send()
            .await
            .map_err(|_| "Base RPC unavailable")?;
        let success = response.status().is_success();
        let body: Value = response.json().await.map_err(|_| "Base RPC malformed")?;
        if !success || body.get("error").is_some() {
            return Err("Base RPC rejected request".into());
        }
        body.get("result")
            .cloned()
            .ok_or("Base RPC result missing".into())
    }

    fn basic_authorization(&self) -> String {
        format!(
            "Basic {}",
            STANDARD.encode(format!("{}:{}", self.app_id, self.app_secret))
        )
    }
    fn privy_authorization_headers(
        &self,
        url: &str,
        body: &Value,
        idempotency_key: &str,
    ) -> Result<reqwest::header::HeaderMap, String> {
        let expiry = now_unix_millis()
            .checked_add(60_000)
            .ok_or("clock invalid")?
            .to_string();
        let headers = json!({"privy-app-id": self.app_id, "privy-request-expiry": expiry, "privy-idempotency-key": idempotency_key});
        let payload = json!({"version":1,"method":"POST","url":url,"body":body,"headers":headers});
        let signing_key = SigningKey::from_pkcs8_pem(&self.authorization_key_pem)
            .map_err(|_| "existing Privy authorization key invalid")?;
        let signature: Signature = signing_key.sign(canonical_json(&payload).as_bytes());
        let mut result = reqwest::header::HeaderMap::new();
        result.insert(
            "authorization",
            self.basic_authorization()
                .parse()
                .map_err(|_| "custody authorization invalid")?,
        );
        result.insert("content-type", "application/json".parse().unwrap());
        result.insert("accept", "application/json".parse().unwrap());
        result.insert(
            "privy-app-id",
            self.app_id.parse().map_err(|_| "custody app ID invalid")?,
        );
        result.insert(
            "privy-request-expiry",
            expiry.parse().map_err(|_| "custody expiry invalid")?,
        );
        result.insert(
            "privy-idempotency-key",
            idempotency_key
                .parse()
                .map_err(|_| "custody idempotency key invalid")?,
        );
        result.insert(
            "privy-authorization-signature",
            STANDARD
                .encode(signature.to_der().as_bytes())
                .parse()
                .map_err(|_| "custody signature invalid")?,
        );
        Ok(result)
    }
}

#[cfg(test)]
fn classify_relay_destination_finality(
    intent: &ExternalEffectIntent,
    provider_transaction_id: String,
    intake_transaction_hash: String,
    status: &Value,
    details: &Value,
) -> Result<layrs_direct_execution_v1::ExternalEffectObservation, String> {
    classify_relay_destination_finality_with_forwarding(intent, provider_transaction_id, intake_transaction_hash, status, details, None)
}

/// Constructed only after canonical Base forwarding verification. It does not
/// replace the original custody hash in the immutable intent or ledger result.
struct VerifiedRelayForwarding { deposit_hash: String, forwarding_hash: String }

fn relay_forwarding_candidate(intent: &ExternalEffectIntent, pool_address: &str, deposit_hash: &str, status: &Value, details: &Value) -> Option<String> {
    let relay = intent.relay.as_ref()?;
    if status.get("status")?.as_str()? != "success" { return None; }
    let requests = details.get("requests")?.as_array()?;
    if requests.len() != 1 { return None; }
    let request = &requests[0];
    let deposit = request.get("depositAddress")?;
    if request.get("id")?.as_str()? != relay.request_id
        || deposit.get("type")?.as_str()? != "strict"
        || !deposit.get("address")?.as_str()?.eq_ignore_ascii_case(&relay.deposit_address)
        || !deposit.get("depositor")?.as_str()?.eq_ignore_ascii_case(pool_address)
        || !deposit.get("depositTxHash")?.as_str()?.eq_ignore_ascii_case(deposit_hash) { return None; }
    let hashes = relay_hashes(status.get("inTxHashes"));
    if hashes.len() != 1 || !valid_transaction_hash(&hashes[0]) || hashes[0].eq_ignore_ascii_case(deposit_hash)
        || !relay_request_has_intake(request, 8453, &hashes[0]) { return None; }
    Some(hashes[0].clone())
}

#[allow(clippy::too_many_arguments)]
fn relay_forwarding_is_canonical(intent: &ExternalEffectIntent, pool: &str, deposit_hash: &str, hash: &str, deposit_receipt: &Value, deposit_block: &Value, receipt: &Value, block: &Value, head: u128, confirmations: u64) -> bool {
    let Some(relay) = intent.relay.as_ref() else { return false; };
    let Some(amount) = intent.amount_atomic.parse::<u128>().ok().filter(|n| *n > 0) else { return false; };
    let number = receipt.get("blockNumber").and_then(Value::as_str).and_then(parse_quantity);
    let deposit_number = deposit_receipt.get("blockNumber").and_then(Value::as_str).and_then(parse_quantity);
    if receipt.get("status").and_then(Value::as_str) != Some("0x1")
        || !receipt.get("transactionHash").and_then(Value::as_str).is_some_and(|h| h.eq_ignore_ascii_case(hash))
        || receipt.get("blockHash").and_then(Value::as_str).is_none()
        || receipt.get("blockHash") != block.get("hash")
        || number.is_none() || number != block.get("number").and_then(Value::as_str).and_then(parse_quantity)
        || deposit_receipt.get("status").and_then(Value::as_str) != Some("0x1")
        || !deposit_receipt.get("transactionHash").and_then(Value::as_str).is_some_and(|h| h.eq_ignore_ascii_case(deposit_hash))
        || !deposit_receipt.get("blockHash").and_then(Value::as_str).is_some_and(valid_transaction_hash)
        || deposit_receipt.get("blockHash") != deposit_block.get("hash")
        || deposit_number != deposit_block.get("number").and_then(Value::as_str).and_then(parse_quantity)
        || deposit_number.is_none() || deposit_number > number
        || head.checked_sub(number.unwrap()).and_then(|n| n.checked_add(1)).unwrap_or(0) < u128::from(confirmations.max(1)) { return false; }
    // Prove the original pool payment as well as forwarding. Provider metadata
    // cannot substitute another payment or a deposit orphaned by a reorg.
    let pool_topic = address_topic(pool);
    let sender = address_topic(&relay.deposit_address);
    let deposits = deposit_receipt.get("logs").and_then(Value::as_array).into_iter().flatten().filter(|log| {
        log.get("removed").and_then(Value::as_bool) != Some(true)
            && log.get("address").and_then(Value::as_str).is_some_and(|a| a.eq_ignore_ascii_case(BASE_USDC_ADDRESS))
            && log.get("transactionHash").and_then(Value::as_str).is_some_and(|h| h.eq_ignore_ascii_case(deposit_hash))
            && log.get("blockHash") == deposit_receipt.get("blockHash")
            && log.get("topics").and_then(Value::as_array).is_some_and(|t| t.len() == 3
                && t[0].as_str().is_some_and(|v| v.eq_ignore_ascii_case(ERC20_TRANSFER_TOPIC))
                && t[1].as_str().is_some_and(|v| v.eq_ignore_ascii_case(&pool_topic))
                && t[2].as_str().is_some_and(|v| v.eq_ignore_ascii_case(&sender)))
            && log.get("data").and_then(Value::as_str).and_then(parse_quantity) == Some(amount)
    }).count();
    if deposits != 1 { return false; }
    let matching = receipt.get("logs").and_then(Value::as_array).into_iter().flatten().filter(|log| {
        log.get("removed").and_then(Value::as_bool) != Some(true)
            && log.get("address").and_then(Value::as_str).is_some_and(|a| a.eq_ignore_ascii_case(BASE_USDC_ADDRESS))
            && log.get("transactionHash").and_then(Value::as_str).is_some_and(|h| h.eq_ignore_ascii_case(hash))
            && log.get("blockHash") == receipt.get("blockHash")
            && log.get("topics").and_then(Value::as_array).is_some_and(|t| t.len() == 3
                && t[0].as_str().is_some_and(|v| v.eq_ignore_ascii_case(ERC20_TRANSFER_TOPIC))
                && t[1].as_str().is_some_and(|v| v.eq_ignore_ascii_case(&sender))
                && t[2].as_str().is_some_and(|v| v.len() == 66 && v.starts_with("0x") && v[2..].bytes().all(|b| b.is_ascii_hexdigit())
                    && !v.eq_ignore_ascii_case(&sender) && !v.eq_ignore_ascii_case(&format!("0x{}", "00".repeat(32)))))
            && log.get("data").and_then(Value::as_str).and_then(parse_quantity) == Some(amount)
    }).count();
    matching == 1
}

fn classify_relay_destination_finality_with_forwarding(
    intent: &ExternalEffectIntent,
    provider_transaction_id: String,
    intake_transaction_hash: String,
    status: &Value,
    details: &Value,
    forwarding: Option<&VerifiedRelayForwarding>,
) -> Result<layrs_direct_execution_v1::ExternalEffectObservation, String> {
    let relay = intent
        .relay
        .as_ref()
        .ok_or("Relay binding missing from external-effect intent")?;
    relay
        .verify(&intent.amount_atomic)
        .map_err(|_| "Relay binding invalid")?;
    if !valid_transaction_hash(&intake_transaction_hash) {
        return Err("Relay intake transaction hash invalid".into());
    }
    let status_name = status
        .get("status")
        .and_then(Value::as_str)
        .ok_or("Relay status missing")?;
    if let Some(request_id) = status.get("requestId").and_then(Value::as_str) {
        if !request_id.eq_ignore_ascii_case(&relay.request_id) {
            return Ok(layrs_direct_execution_v1::ExternalEffectObservation::Conflict);
        }
    }
    let origin_chain = status.get("originChainId").and_then(Value::as_u64);
    let destination_chain = status.get("destinationChainId").and_then(Value::as_u64);
    if origin_chain.is_some_and(|chain| chain != 8453)
        || destination_chain.is_some_and(|chain| chain != relay.destination_chain_id)
    {
        return Ok(layrs_direct_execution_v1::ExternalEffectObservation::Conflict);
    }
    let status_intake_hashes = relay_hashes(status.get("inTxHashes"));
    let forwarded = forwarding.is_some_and(|proof| proof.deposit_hash.eq_ignore_ascii_case(&intake_transaction_hash)
        && status_intake_hashes.len() == 1 && status_intake_hashes[0].eq_ignore_ascii_case(&proof.forwarding_hash));
    if !status_intake_hashes.is_empty()
        && !status_intake_hashes
            .iter()
            .any(|hash| hash.eq_ignore_ascii_case(&intake_transaction_hash))
        && !forwarded
    {
        return Ok(layrs_direct_execution_v1::ExternalEffectObservation::Conflict);
    }
    if matches!(
        status_name,
        "waiting" | "depositing" | "pending" | "submitted" | "delayed"
    ) {
        return Ok(
            layrs_direct_execution_v1::ExternalEffectObservation::Pending {
                provider_transaction_id,
            },
        );
    }
    let requests = details
        .get("requests")
        .and_then(Value::as_array)
        .ok_or("Relay request details malformed")?;
    if requests.len() != 1 {
        return Ok(layrs_direct_execution_v1::ExternalEffectObservation::Conflict);
    }
    let request = &requests[0];
    if request
        .get("id")
        .and_then(Value::as_str)
        .is_none_or(|id| !id.eq_ignore_ascii_case(&relay.request_id))
        || request
            .get("recipient")
            .and_then(Value::as_str)
            .is_none_or(|recipient| {
                !relay_address_eq(recipient, &relay.recipient, relay.destination_chain_id)
            })
        || request
            .pointer("/depositAddress/address")
            .and_then(Value::as_str)
            .is_none_or(|address| !address.eq_ignore_ascii_case(&relay.deposit_address))
        || !relay_route_quote_matches(request, relay, &intent.amount_atomic)
        || !(relay_request_has_intake(request, 8453, &intake_transaction_hash)
            || forwarded && forwarding.is_some_and(|proof| request.pointer("/depositAddress/depositTxHash").and_then(Value::as_str)
                .is_some_and(|h| h.eq_ignore_ascii_case(&proof.deposit_hash))
                && relay_request_has_intake(request, 8453, &proof.forwarding_hash)))
    {
        return Ok(layrs_direct_execution_v1::ExternalEffectObservation::Conflict);
    }
    match status_name {
        "success" => {
            if request.get("status").and_then(Value::as_str) != Some("success") {
                return Ok(layrs_direct_execution_v1::ExternalEffectObservation::Conflict);
            }
            let status_destination_hashes = relay_hashes(status.get("txHashes"));
            let request_destination_hashes =
                relay_destination_hashes(request, relay.destination_chain_id);
            if status_destination_hashes.len() != 1
                || request_destination_hashes.len() != 1
                || status_destination_hashes[0] != request_destination_hashes[0]
            {
                return Ok(layrs_direct_execution_v1::ExternalEffectObservation::Conflict);
            }
            let destination_amount_atomic = relay_actual_destination_amount(request, relay)?;
            let minimum = relay
                .minimum_destination_amount_atomic
                .parse::<u128>()
                .map_err(|_| "Relay minimum amount invalid")?;
            if destination_amount_atomic
                .parse::<u128>()
                .ok()
                .is_none_or(|amount| amount < minimum)
            {
                return Ok(layrs_direct_execution_v1::ExternalEffectObservation::Conflict);
            }
            let result_hash = relay_result_hash(
                intent,
                &intake_transaction_hash,
                &request_destination_hashes[0],
                &destination_amount_atomic,
            )
            .ok_or("Relay result binding unavailable")?;
            Ok(
                layrs_direct_execution_v1::ExternalEffectObservation::RelayFinalized {
                    provider_transaction_id,
                    intake_transaction_hash,
                    relay_request_id: relay.request_id.clone(),
                    destination_transaction_hash: request_destination_hashes[0].clone(),
                    destination_amount_atomic,
                    result_hash,
                },
            )
        }
        "refund" | "refunded" | "failure" => {
            let request_status = request.get("status").and_then(Value::as_str);
            if !matches!(request_status, Some("refund" | "refunded" | "failure")) {
                return Ok(layrs_direct_execution_v1::ExternalEffectObservation::Conflict);
            }
            let result_hash = relay_reverted_result_hash(
                relay,
                &intent.external_effect_reference,
                &intake_transaction_hash,
                status_name,
            );
            Ok(
                layrs_direct_execution_v1::ExternalEffectObservation::RelayReverted {
                    provider_transaction_id,
                    intake_transaction_hash,
                    relay_request_id: relay.request_id.clone(),
                    terminal_status: status_name.into(),
                    result_hash,
                },
            )
        }
        _ => Ok(layrs_direct_execution_v1::ExternalEffectObservation::Conflict),
    }
}

fn relay_hashes(value: Option<&Value>) -> Vec<String> {
    let mut hashes = value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter(|hash| valid_relay_transaction_hash(hash))
        .map(|hash| {
            if hash.starts_with("0x") {
                hash.to_ascii_lowercase()
            } else {
                hash.to_owned()
            }
        })
        .collect::<Vec<_>>();
    hashes.sort();
    hashes.dedup();
    hashes
}

fn relay_request_has_intake(request: &Value, origin_chain_id:u64, intake_transaction_hash: &str) -> bool {
    request
        .pointer("/data/inTxs")
        .and_then(Value::as_array)
        .is_some_and(|transactions| {
            transactions.iter().any(|transaction| {
                transaction.get("chainId").and_then(Value::as_u64) == Some(origin_chain_id)
                    && transaction.get("status").and_then(Value::as_str) == Some("success")
                    && transaction
                        .get("txHash")
                        .and_then(Value::as_str)
                        .is_some_and(|hash| hash.eq_ignore_ascii_case(intake_transaction_hash))
            })
        })
}

fn relay_destination_hashes(request: &Value, destination_chain_id: u64) -> Vec<String> {
    let values = request
        .pointer("/data/outTxs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|transaction| {
            transaction.get("chainId").and_then(Value::as_u64) == Some(destination_chain_id)
                && transaction.get("status").and_then(Value::as_str) == Some("success")
        })
        .filter_map(|transaction| transaction.get("txHash").and_then(Value::as_str))
        .collect::<Vec<_>>();
    relay_hashes(Some(&Value::Array(
        values
            .into_iter()
            .map(|value| Value::String(value.into()))
            .collect(),
    )))
}

fn relay_route_quote_matches(
    request: &Value,
    relay: &RelayWithdrawalBinding,
    source_amount_atomic: &str,
) -> bool {
    let origin = request.pointer("/data/route/quoted/origin/inputCurrency");
    let destination = request.pointer("/data/route/quoted/destination/outputCurrency");
    relay_currency_matches(origin, 8453, BASE_USDC_ADDRESS, source_amount_atomic)
        && relay_currency_matches(
            destination,
            relay.destination_chain_id,
            &relay.destination_currency,
            &relay.quoted_destination_amount_atomic,
        )
}

fn relay_actual_destination_amount(
    request: &Value,
    relay: &RelayWithdrawalBinding,
) -> Result<String, String> {
    let output = request
        .pointer("/data/route/actual/destination/outputCurrency")
        .ok_or("Relay actual destination result missing")?;
    let amount = output
        .get("amount")
        .and_then(Value::as_str)
        .ok_or("Relay actual destination amount missing")?;
    if !relay_currency_matches(
        Some(output),
        relay.destination_chain_id,
        &relay.destination_currency,
        amount,
    ) || amount
        .parse::<u128>()
        .ok()
        .filter(|value| *value > 0)
        .is_none()
    {
        return Err("Relay actual destination result mismatch".into());
    }
    Ok(amount.into())
}

fn relay_currency_matches(
    value: Option<&Value>,
    chain_id: u64,
    currency: &str,
    amount: &str,
) -> bool {
    value.is_some_and(|value| {
        value.pointer("/currency/chainId").and_then(Value::as_u64) == Some(chain_id)
            && value
                .pointer("/currency/address")
                .and_then(Value::as_str)
                .is_some_and(|address| relay_address_eq(address, currency, chain_id))
            && value.get("amount").and_then(Value::as_str) == Some(amount)
    })
}

fn relay_address_eq(left: &str, right: &str, chain_id: u64) -> bool {
    if chain_id == 792_703_809 {
        left == right
    } else {
        left.eq_ignore_ascii_case(right)
    }
}

fn valid_relay_transaction_hash(value: &str) -> bool {
    valid_transaction_hash(value)
        || ((64..=96).contains(&value.len())
            && value.bytes().all(|byte| {
                matches!(byte,
                b'1'..=b'9' | b'A'..=b'H' | b'J'..=b'N' | b'P'..=b'Z'
                | b'a'..=b'k' | b'm'..=b'z')
            }))
}

fn canonical_evm_address(value: &str) -> Result<String, String> {
    if value.len() == 42
        && value.starts_with("0x")
        && value[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        Ok(value.to_ascii_lowercase())
    } else {
        Err("invalid EVM address".into())
    }
}
fn valid_transaction_hash(value: &str) -> bool {
    value.len() == 66
        && value.starts_with("0x")
        && value[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
}
fn parse_quantity(value: &str) -> Option<u128> {
    value
        .strip_prefix("0x")
        .and_then(|value| u128::from_str_radix(value, 16).ok())
}
fn quantity(value: u128) -> String {
    format!("0x{value:x}")
}
fn pool_withdraw_calldata(destination: &str, amount_atomic: &str) -> Result<String, String> {
    let destination = canonical_evm_address(destination)?;
    let amount = amount_atomic
        .parse::<u128>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or("invalid withdrawal amount")?;
    let mut hasher = Keccak256::new();
    hasher.update(b"withdraw(address,uint256)");
    let selector = hasher.finalize();
    Ok(format!(
        "0x{}{:0>64}{:0>64}",
        hex::encode(&selector[..4]),
        &destination[2..],
        format!("{amount:x}")
    ))
}

fn erc20_transfer_calldata(destination: &str, amount: u128) -> Result<String, String> {
    let destination = canonical_evm_address(destination)?;
    Ok(format!(
        "0xa9059cbb{:0>64}{amount:0>64x}",
        &destination[2..]
    ))
}

fn address_topic(address: &str) -> String {
    format!("0x{:0>64}", &address[2..].to_ascii_lowercase())
}

/// Privy gas sponsorship wraps the authorized pool call in an ERC-4337
/// transaction, so the outer transaction is sent by the bundler to the Entry
/// Point rather than directly by the operational wallet to the pool.  Bind
/// finality to the provider-owned user-operation hash and to the exact
/// successful inner financial effect instead of weakening the direct-call
/// checks above.
fn sponsored_withdrawal_receipt_matches(
    intent: &ExternalEffectIntent,
    operational_wallet: &str,
    pool_address: &str,
    user_operation_hash: Option<&str>,
    receipt: &Value,
) -> bool {
    let Some(user_operation_hash) = user_operation_hash else {
        return false;
    };
    let Some(logs) = receipt.get("logs").and_then(Value::as_array) else {
        return false;
    };
    let Ok(amount) = intent.amount_atomic.parse::<u128>() else {
        return false;
    };
    let wallet_topic = address_topic(operational_wallet);
    let pool_topic = address_topic(pool_address);
    let destination_topic = address_topic(&intent.destination);
    let mut matching_user_operations = 0usize;
    let mut matching_transfers = 0usize;
    let mut matching_withdrawals = 0usize;
    for log in logs {
        let address = log
            .get("address")
            .and_then(Value::as_str)
            .and_then(|value| canonical_evm_address(value).ok());
        let topics = log.get("topics").and_then(Value::as_array);
        let data = log.get("data").and_then(Value::as_str);
        let topic = |index: usize| {
            topics
                .and_then(|values| values.get(index))
                .and_then(Value::as_str)
        };
        if topic(0).is_some_and(|value| value.eq_ignore_ascii_case(USER_OPERATION_EVENT_TOPIC))
            && topic(1).is_some_and(|value| value.eq_ignore_ascii_case(user_operation_hash))
            && topic(2).is_some_and(|value| value.eq_ignore_ascii_case(&wallet_topic))
            && data
                .and_then(|value| value.strip_prefix("0x"))
                .filter(|value| value.len() >= 128)
                .and_then(|value| u128::from_str_radix(&value[64..128], 16).ok())
                == Some(1)
        {
            matching_user_operations += 1;
        }
        if address.as_deref() == Some(BASE_USDC_ADDRESS)
            && topic(0).is_some_and(|value| value.eq_ignore_ascii_case(ERC20_TRANSFER_TOPIC))
            && topic(1).is_some_and(|value| value.eq_ignore_ascii_case(&pool_topic))
            && topic(2).is_some_and(|value| value.eq_ignore_ascii_case(&destination_topic))
            && data.and_then(parse_quantity) == Some(amount)
        {
            matching_transfers += 1;
        }
        if address.as_deref() == Some(pool_address)
            && topic(0).is_some_and(|value| value.eq_ignore_ascii_case(POOL_WITHDRAW_TOPIC))
            && topic(1).is_some_and(|value| value.eq_ignore_ascii_case(&destination_topic))
            && topic(2).is_some_and(|value| value.eq_ignore_ascii_case(&wallet_topic))
            && data.and_then(parse_quantity) == Some(amount)
        {
            matching_withdrawals += 1;
        }
    }
    matching_user_operations == 1 && matching_transfers == 1 && matching_withdrawals == 1
}

#[allow(clippy::too_many_arguments)]
fn classify_base_deposit(
    source_wallet: &str,
    pool_address: &str,
    transaction_hash: &str,
    amount: u128,
    confirmations: u64,
    transaction: &Value,
    receipt: &Value,
    head: u128,
) -> Result<DepositFinality, String> {
    let expected_input = erc20_transfer_calldata(pool_address, amount)?;
    if transaction
        .get("from")
        .and_then(Value::as_str)
        .and_then(|value| canonical_evm_address(value).ok())
        .as_deref()
        != Some(source_wallet)
        || transaction
            .get("to")
            .and_then(Value::as_str)
            .and_then(|value| canonical_evm_address(value).ok())
            .as_deref()
            != Some(BASE_USDC_ADDRESS)
        || transaction
            .get("input")
            .and_then(Value::as_str)
            .map(|value| value.eq_ignore_ascii_case(&expected_input))
            != Some(true)
        || transaction
            .get("value")
            .and_then(Value::as_str)
            .and_then(parse_quantity)
            != Some(0)
        || receipt
            .get("transactionHash")
            .and_then(Value::as_str)
            .map(|value| value.eq_ignore_ascii_case(transaction_hash))
            != Some(true)
        || receipt.get("blockHash").and_then(Value::as_str)
            != transaction.get("blockHash").and_then(Value::as_str)
    {
        return Ok(DepositFinality::Conflict);
    }
    match receipt.get("status").and_then(Value::as_str) {
        Some("0x0") => return Ok(DepositFinality::Reverted),
        Some("0x1") => {}
        _ => return Ok(DepositFinality::Conflict),
    }
    let expected_from_topic = address_topic(source_wallet);
    let expected_to_topic = address_topic(pool_address);
    let exact_transfer = receipt
        .get("logs")
        .and_then(Value::as_array)
        .is_some_and(|logs| {
            logs.iter().any(|log| {
                log.get("address")
                    .and_then(Value::as_str)
                    .is_some_and(|value| value.eq_ignore_ascii_case(BASE_USDC_ADDRESS))
                    && log
                        .get("topics")
                        .and_then(Value::as_array)
                        .is_some_and(|topics| {
                            topics.len() >= 3
                                && topics[0].as_str().is_some_and(|value| {
                                    value.eq_ignore_ascii_case(ERC20_TRANSFER_TOPIC)
                                })
                                && topics[1].as_str().is_some_and(|value| {
                                    value.eq_ignore_ascii_case(&expected_from_topic)
                                })
                                && topics[2].as_str().is_some_and(|value| {
                                    value.eq_ignore_ascii_case(&expected_to_topic)
                                })
                        })
                    && log
                        .get("data")
                        .and_then(Value::as_str)
                        .and_then(parse_quantity)
                        == Some(amount)
            })
        });
    if !exact_transfer {
        return Ok(DepositFinality::Conflict);
    }
    let block_number = receipt
        .get("blockNumber")
        .and_then(Value::as_str)
        .and_then(parse_quantity)
        .ok_or("Base deposit receipt block number malformed")?;
    if head
        .checked_sub(block_number)
        .and_then(|value| value.checked_add(1))
        .unwrap_or(0)
        < u128::from(confirmations)
    {
        return Ok(DepositFinality::Pending);
    }
    Ok(DepositFinality::Finalized)
}
fn canonical_json(value: &Value) -> String {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            serde_json::to_string(value).expect("canonical scalar serializes")
        }
        Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",")
        ),
        Value::Object(values) => format!(
            "{{{}}}",
            values
                .iter()
                .map(|(key, value)| format!(
                    "{}:{}",
                    serde_json::to_string(key).expect("canonical key serializes"),
                    canonical_json(value)
                ))
                .collect::<Vec<_>>()
                .join(",")
        ),
    }
}

impl ArchiveStore {
    async fn from_environment(
        local_filesystem_permitted: bool,
    ) -> Result<Option<Self>, Box<dyn std::error::Error>> {
        match env::var("LAYRS_DIRECT_ARCHIVE_BACKEND").as_deref() {
            Ok("s3-object-lock") => Ok(Some(Self::S3(
                S3ImmutableArtifactStore::from_environment().await?,
            ))),
            // A package started in dormant mode can expose only health and
            // attestation.  It cannot execute a financial request, so its
            // predeclared local directory is safe for sealed-epoch recovery.
            // An enabled writer must always use the immutable S3/Object-Lock
            // archive below.
            Ok("filesystem") if local_filesystem_permitted => {
                Ok(env::var("LAYRS_DIRECT_ARTIFACT_DIR")
                    .ok()
                    .filter(|value| !value.is_empty())
                    .map(PathBuf::from)
                    .map(FilesystemImmutableArtifactStore::new)
                    .map(Self::Filesystem))
            }
            Ok("filesystem") => {
                Err("filesystem archive is prohibited outside isolated test".into())
            }
            Ok(_) => Err("invalid direct archive backend".into()),
            Err(_) if local_filesystem_permitted => Ok(env::var("LAYRS_DIRECT_ARTIFACT_DIR")
                .ok()
                .filter(|value| !value.is_empty())
                .map(PathBuf::from)
                .map(FilesystemImmutableArtifactStore::new)
                .map(Self::Filesystem)),
            Err(_) => Err("production direct archive backend is required".into()),
        }
    }
    async fn persist_readback(
        &self,
        artifact: &DirectStateArtifact,
    ) -> Result<DirectStateArtifact, String> {
        match self {
            Self::Filesystem(store) => store
                .persist_readback(artifact)
                .map_err(|error| error.to_string()),
            Self::S3(store) => store.persist_readback(artifact).await,
        }
    }
    async fn load_committed(&self) -> Result<Vec<DirectStateArtifact>, String> {
        match self {
            Self::Filesystem(store) => store.load_committed().map_err(|error| error.to_string()),
            Self::S3(store) => store.load_committed().await,
        }
    }
    async fn committed_receipts(
        &self,
        state: &AppState,
    ) -> Result<Vec<(u64, DirectReceipt)>, String> {
        // Presence means v71 restore/cutover completed. On the first v71 boot,
        // startup intentionally reconciles the v70 lineage before activating
        // the journal, so the absent cache must still fall back to v70.
        let cache = state.journal_receipts.lock().await;
        if let Some(cache) = cache.as_ref() {
            return ordered_journal_receipts(cache);
        }
        drop(cache);
        self.load_committed().await.map(|records| {
            records
                .into_iter()
                .map(|record| (record.sequence, record.receipt))
                .collect()
        })
    }
    async fn prepare_restore_before_grant(&self, state: &AppState) -> Result<(), String> {
        match self {
            Self::Filesystem(_)
                if state.persistence_format == PersistenceFormat::V70RollbackBaseline =>
            {
                Err("v70 rollback baseline requires the S3 archive".into())
            }
            // Filesystem archives are confined to isolated tests/dormant
            // packages and do not consume a governed production grant.
            Self::Filesystem(_) => Ok(()),
            Self::S3(store)
                if state.persistence_format == PersistenceFormat::V70RollbackBaseline =>
            {
                store
                    .prepare_sparse_rollback_restore(sparse_rollback_frontier(state)?)
                    .await
                    .map(|_| ())
            }
            Self::S3(store) => {
                let journal_ready = match state.persistence_format {
                    PersistenceFormat::V70 => false,
                    PersistenceFormat::V71 => store.prepare_journal_restore().await?,
                    PersistenceFormat::V71Hot => store.prepare_hot_journal_restore().await?,
                    PersistenceFormat::V70RollbackBaseline => {
                        return Err("v70 rollback baseline restore dispatch invalid".into())
                    }
                };
                if journal_ready {
                    state.hot_v71_enabled.store(true, Ordering::Release);
                    Ok(())
                } else {
                    store.prepare_restore(state).await.map(|_| ())
                }
            }
        }
    }
    async fn receipt_sequence(
        &self,
        state: &AppState,
        receipt: &DirectReceipt,
    ) -> Result<i64, ProjectionError> {
        if state.effective_persistence_format() == PersistenceFormat::V71 {
            let cache = state.journal_receipts.lock().await;
            let cache = cache.as_ref().ok_or(ProjectionError::Database)?;
            let mut matching = cache
                .values()
                .filter(|(_, candidate)| candidate.receipt_id == receipt.receipt_id);
            let (sequence, candidate) = matching.next().ok_or(ProjectionError::Database)?;
            if matching.next().is_some() || candidate != receipt {
                return Err(ProjectionError::Database);
            }
            return i64::try_from(*sequence).map_err(|_| ProjectionError::Database);
        }
        match self {
            Self::S3(store) => {
                let records = store.verified_receipt_records.lock().await;
                verified_receipt_sequence(records.as_deref().ok_or(ProjectionError::Database)?, receipt)
            }
            Self::Filesystem(store) => verified_receipt_sequence(
                &store.load_committed().map_err(|_| ProjectionError::Database)?, receipt),
        }
    }
    async fn persist_intent_readback(
        &self,
        intent: &ExternalEffectIntent,
    ) -> Result<ExternalEffectIntent, String> {
        match self {
            Self::Filesystem(store) => {
                FilesystemImmutableIntentStore::new(store.root().join("external-effect-intents"))
                    .put_if_absent_readback(intent)
                    .map_err(|error| error.to_string())
            }
            Self::S3(store) => store.persist_intent_readback(intent).await,
        }
    }
    async fn load_intents(&self) -> Result<Vec<ExternalEffectIntent>, String> {
        match self {
            Self::Filesystem(store) => {
                FilesystemImmutableIntentStore::new(store.root().join("external-effect-intents"))
                    .load_all()
                    .map_err(|error| error.to_string())
            }
            Self::S3(store) => store.load_intents().await,
        }
    }

    async fn persist_extra_payout(&self, evidence: &ExtraPayoutEvidence) -> Result<(), String> {
        let bytes = serde_json::to_vec(evidence).map_err(|_| "extra payout evidence encoding failed")?;
        match self {
            Self::S3(store) => store.write_once(&format!("{}/external-effect-reconciliations/{}.json", store.prefix, evidence.intent_hash), bytes).await,
            Self::Filesystem(store) => {
                let directory = store.root().join("external-effect-reconciliations");
                fs::create_dir_all(&directory).map_err(|_| "extra payout directory unavailable")?;
                let path = directory.join(format!("{}.json", evidence.intent_hash));
                match OpenOptions::new().write(true).create_new(true).open(&path) {
                    Ok(mut file) => {
                        std::io::Write::write_all(&mut file, &bytes).and_then(|_| file.sync_all()).map_err(|_| "extra payout evidence persistence failed")?;
                    }
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {},
                    Err(_) => return Err("extra payout evidence persistence failed".into()),
                }
                if fs::read(path).map_err(|_| "extra payout readback failed")? != bytes { return Err("extra payout immutable evidence conflict".into()); }
                Ok(())
            }
        }
    }
    async fn load_key_release(
        &self,
        activation_id: &str,
    ) -> Result<Option<GovernedKeyReleaseArtifact>, String> {
        match self {
            Self::Filesystem(store) => {
                let path = store
                    .root()
                    .join("authorization")
                    .join(format!("{activation_id}.cbor"));
                match fs::read(path) {
                    Ok(bytes) => serde_cbor::from_slice(&bytes)
                        .map(Some)
                        .map_err(|_| "key-release artifact decode failed".into()),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
                    Err(_) => Err("key-release artifact read failed".into()),
                }
            }
            Self::S3(store) => store.load_key_release(activation_id).await,
        }
    }
    async fn persist_key_release(
        &self,
        artifact: &GovernedKeyReleaseArtifact,
    ) -> Result<GovernedKeyReleaseArtifact, String> {
        match self {
            Self::Filesystem(store) => {
                let directory = store.root().join("authorization");
                fs::create_dir_all(&directory).map_err(|_| "key-release directory unavailable")?;
                let path = directory.join(format!("{}.cbor", artifact.activation_id));
                let bytes = serde_cbor::to_vec(artifact)
                    .map_err(|_| "key-release artifact encoding failed")?;
                match OpenOptions::new().create_new(true).write(true).open(&path) {
                    Ok(mut file) => {
                        std::io::Write::write_all(&mut file, &bytes)
                            .and_then(|_| file.sync_all())
                            .map_err(|_| "key-release artifact write failed")?;
                    }
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(_) => return Err("key-release artifact immutable write failed".into()),
                }
                let restored: GovernedKeyReleaseArtifact = serde_cbor::from_slice(
                    &fs::read(path).map_err(|_| "key-release artifact readback failed")?,
                )
                .map_err(|_| "key-release artifact decode failed")?;
                if restored != *artifact {
                    return Err("key-release artifact conflict".into());
                }
                Ok(restored)
            }
            Self::S3(store) => store.persist_key_release(artifact).await,
        }
    }
}

fn receipt_only_record(artifact: &DirectStateArtifact) -> DirectStateArtifact {
    let mut record = artifact.clone();
    // clear() leaves the entire snapshot allocation alive. This cache is only
    // receipt metadata; release the encrypted snapshot allocation completely.
    record.ciphertext = Vec::new();
    record
}

fn archive_head_key(prefix: &str, sequence: u64) -> String {
    format!("{prefix}/heads/{sequence:020}.cbor")
}

fn archive_key_sequence(key: &str, namespace: &str, hash_required: bool) -> Result<u64, String> {
    let name = key
        .strip_prefix(namespace)
        .and_then(|s| s.strip_suffix(".cbor"))
        .ok_or("archive key namespace invalid")?;
    let (seq, hash) = match name.split_once('-') {
        Some((seq, hash)) => (seq, Some(hash)),
        None => (name, None),
    };
    if seq.len() != 20
        || !seq.bytes().all(|b| b.is_ascii_digit())
        || hash_required && hash.is_none()
        || hash.is_some_and(|hash| {
            hash.len() != 64
                || !hash
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
    {
        return Err("archive key format invalid".into());
    }
    seq.parse().map_err(|_| "archive sequence overflow".into())
}

// v71 parent journal helpers (V71_PARENT_JOURNAL_PLAN.md section 3.3). Pure and
// I/O-free; nothing on the v70 path calls them until the v71 append/restore
// path is wired.

/// Parent-side cap on one encoded journal record. A single create-only PUT
/// carries it, so it stays well below the 16 MiB bound and the VSOCK frame.
#[cfg_attr(not(test), allow(dead_code))]
const MAX_JOURNAL_RECORD_BYTES: usize = 8 * 1024 * 1024;
const _: () = assert!(MAX_JOURNAL_RECORD_BYTES < 16 * 1024 * 1024);
const _: () = assert!(MAX_JOURNAL_RECORD_BYTES <= MAX_FRAME_BYTES);

/// Last durable journal record as proven by restore or the preceding commit.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Debug, PartialEq, Eq)]
struct JournalHead {
    writer_epoch: String,
    sequence: u64,
    record_hash: String,
    transition_root: String,
    request_index_root: String,
    financial_state_root: String,
}

/// In-process v71 append eligibility. Only `Eligible` may PUT, and a latch is
/// never cleared in-process: recovery is a restart plus full restore.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Debug, PartialEq, Eq)]
enum JournalWriterState {
    Unrestored,
    Eligible(JournalHead),
    Latched(&'static str),
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JournalRole {
    Writer,
    Shadow,
}

#[cfg_attr(not(test), allow(dead_code))]
fn latch_journal_state(state: &mut JournalWriterState, code: &'static str) {
    // Keep the first cause; a latched writer never becomes eligible again.
    if !matches!(state, JournalWriterState::Latched(_)) {
        *state = JournalWriterState::Latched(code);
    }
    eprintln!("JOURNAL_LATCHED reason={code}");
}

/// Every fence written against `writer_epoch` lives under this prefix,
/// whatever head sequence it fences at.
#[cfg_attr(not(test), allow(dead_code))]
fn journal_fence_prefix(prefix: &str, writer_epoch: &str) -> String {
    format!(
        "{prefix}/journal-v71/fences/{}/",
        sha256(writer_epoch.as_bytes())
    )
}

/// v71 records occupy the v70 head slot so both formats contend for one
/// create-only key per sequence.
#[cfg_attr(not(test), allow(dead_code))]
fn journal_record_key(prefix: &str, sequence: u64) -> String {
    archive_head_key(prefix, sequence)
}

fn journal_cutover_marker_key(prefix: &str) -> String {
    format!("{prefix}/journal-v71/cutover.cbor")
}

/// Strict inverse of `journal_record_key`. Legacy `{seq}-{hash}` head names,
/// unpadded, foreign, overflowing, zero, or otherwise noncanonical keys are
/// never valid journal records.
#[cfg_attr(not(test), allow(dead_code))]
fn journal_record_key_sequence(key: &str, prefix: &str) -> Result<u64, String> {
    let namespace = format!("{prefix}/heads/");
    if key
        .strip_prefix(namespace.as_str())
        .is_some_and(|name| name.contains('-'))
    {
        return Err("journal record key legacy suffix".into());
    }
    let sequence = archive_key_sequence(key, &namespace, false)?;
    if sequence == 0 || journal_record_key(prefix, sequence) != key {
        return Err("journal record key noncanonical".into());
    }
    Ok(sequence)
}

#[cfg_attr(not(test), allow(dead_code))]
fn journal_checkpoint_key(prefix: &str, sequence: u64, bytes: &[u8]) -> String {
    format!(
        "{prefix}/journal-v71/checkpoints/{sequence:020}-{}.cbor",
        sha256(bytes)
    )
}

fn journal_parent_snapshot_key(
    prefix: &str,
    namespace: &str,
    sequence: u64,
    request_index_root: &str,
    bytes: &[u8],
) -> String {
    format!(
        "{prefix}/journal-v71/{namespace}/{sequence:020}-{request_index_root}-{}.cbor",
        sha256(bytes)
    )
}

fn journal_parent_snapshot_key_parts(
    key: &str,
    namespace: &str,
) -> Result<(u64, String, String), String> {
    let name = key
        .strip_prefix(namespace)
        .and_then(|name| name.strip_suffix(".cbor"))
        .ok_or("journal parent snapshot key format invalid")?;
    let mut parts = name.split('-');
    let sequence = parts
        .next()
        .ok_or("journal parent snapshot key format invalid")?;
    let root = parts
        .next()
        .ok_or("journal parent snapshot key format invalid")?;
    let hash = parts
        .next()
        .ok_or("journal parent snapshot key format invalid")?;
    if parts.next().is_some()
        || sequence.len() != 20
        || !sequence.bytes().all(|byte| byte.is_ascii_digit())
        || ![root, hash].into_iter().all(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
    {
        return Err("journal parent snapshot key format invalid".into());
    }
    let sequence = sequence
        .parse::<u64>()
        .map_err(|_| "journal parent snapshot key sequence overflow")?;
    if !name.starts_with(&format!("{sequence:020}-")) {
        return Err("journal parent snapshot key format invalid".into());
    }
    Ok((sequence, root.into(), hash.into()))
}

/// Most journal records a restore may replay after its checkpoint. A longer
/// tail fails closed; it never falls back to an older checkpoint or genesis.
#[cfg_attr(not(test), allow(dead_code))]
const MAX_V71_RESTORE_TAIL_RECORDS: usize = 1000;
/// Aggregate ciphertext retained by the parent while preparing one restore.
/// The record-count bound alone permits 1,000 individually valid 8 MiB
/// records, which can exhaust an 8 GiB host before enclave replay starts.
const MAX_V71_RESTORE_TAIL_BYTES: usize = 256 * 1024 * 1024;
/// Checkpoint often enough that three consecutive failed intervals still leave
/// room below the bounded 1,000-record restore tail.
const V71_CHECKPOINT_INTERVAL_RECORDS: u64 = 250;

fn journal_checkpoint_due(sequence: u64, last_checkpoint: u64) -> bool {
    sequence.saturating_sub(last_checkpoint) >= V71_CHECKPOINT_INTERVAL_RECORDS
}

fn advance_journal_tail_bytes(total: usize, next: usize) -> Result<usize, &'static str> {
    total
        .checked_add(next)
        .filter(|sum| *sum <= MAX_V71_RESTORE_TAIL_BYTES)
        .ok_or("journal tail exceeds byte bound")
}

#[cfg_attr(not(test), allow(dead_code))]
fn journal_migration_key(prefix: &str, source_sequence: u64, bytes: &[u8]) -> String {
    format!(
        "{prefix}/journal-v71/migrations/{source_sequence:020}-{}.cbor",
        sha256(bytes)
    )
}

/// Strict inverse of the content-addressed `{namespace}{seq:020}-{sha256}.cbor`
/// journal keys. Returns `(sequence, content_hash)`; anything else is an error.
#[cfg_attr(not(test), allow(dead_code))]
fn journal_content_key_parts(key: &str, namespace: &str) -> Result<(u64, String), String> {
    let (sequence, hash) = key
        .strip_prefix(namespace)
        .and_then(|name| name.strip_suffix(".cbor"))
        .and_then(|name| name.split_once('-'))
        .ok_or("journal content key format invalid")?;
    if sequence.len() != 20
        || !sequence.bytes().all(|b| b.is_ascii_digit())
        || hash.len() != 64
        || !hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("journal content key format invalid".into());
    }
    let sequence = sequence
        .parse::<u64>()
        .map_err(|_| "journal content key sequence overflow")?;
    if format!("{namespace}{sequence:020}-{hash}.cbor") != key {
        return Err("journal content key noncanonical".into());
    }
    Ok((sequence, hash.to_string()))
}

/// One listed v71 checkpoint object, identified only by its key.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Debug, PartialEq, Eq)]
struct JournalCheckpointCandidate {
    sequence: u64,
    content_hash: String,
    key: String,
}

/// Every listed checkpoint key must be canonical and each sequence must have
/// exactly one checkpoint. Returned in ascending sequence order.
#[cfg_attr(not(test), allow(dead_code))]
fn validate_journal_checkpoint_keys(
    keys: &[String],
    prefix: &str,
) -> Result<Vec<JournalCheckpointCandidate>, String> {
    let namespace = format!("{prefix}/journal-v71/checkpoints/");
    let mut candidates = Vec::with_capacity(keys.len());
    for key in keys {
        let (sequence, content_hash) = journal_content_key_parts(key, &namespace)?;
        candidates.push(JournalCheckpointCandidate {
            sequence,
            content_hash,
            key: key.clone(),
        });
    }
    candidates.sort_by(|a, b| a.key.cmp(&b.key));
    if candidates
        .windows(2)
        .any(|pair| pair[0].sequence == pair[1].sequence)
    {
        return Err("journal checkpoint duplicate sequence".into());
    }
    Ok(candidates)
}

/// Plan section 4 step 2: the candidate must extend `head` exactly. Returns
/// the canonical CBOR bytes to PUT. Any failure must not touch storage.
#[cfg_attr(not(test), allow(dead_code))]
fn precheck_journal_candidate(
    head: &JournalHead,
    record: &DirectJournalRecord,
) -> Result<Vec<u8>, &'static str> {
    if record.protocol != DIRECT_JOURNAL_PROTOCOL {
        return Err("journal candidate protocol invalid");
    }
    if record.epoch_id != EPOCH_ID {
        return Err("journal candidate epoch invalid");
    }
    if record.writer_epoch != head.writer_epoch {
        return Err("journal candidate writer epoch mismatch");
    }
    let next = head
        .sequence
        .checked_add(1)
        .ok_or("journal candidate sequence overflow")?;
    if record.sequence != next {
        return Err("journal candidate sequence mismatch");
    }
    if record.previous_record_hash != head.record_hash {
        return Err("journal candidate previous record mismatch");
    }
    if record.previous_transition_root != head.transition_root {
        return Err("journal candidate previous transition root mismatch");
    }
    if record.previous_request_index_root != head.request_index_root {
        return Err("journal candidate previous request index root mismatch");
    }
    let bytes = serde_cbor::to_vec(record).map_err(|_| "journal candidate encoding failed")?;
    if bytes.len() > MAX_JOURNAL_RECORD_BYTES {
        return Err("journal candidate oversized");
    }
    let decoded: DirectJournalRecord =
        serde_cbor::from_slice(&bytes).map_err(|_| "journal candidate encoding failed")?;
    if decoded != *record {
        return Err("journal candidate encoding noncanonical");
    }
    Ok(bytes)
}

/// Tail keys listed after `after` must be canonical record keys for exactly
/// `after+1..=after+n`, with no gap or duplicate, and `n <= max`.
#[cfg_attr(not(test), allow(dead_code))]
fn validate_journal_tail_keys(
    keys: &[String],
    prefix: &str,
    after: u64,
    max: usize,
) -> Result<Vec<(u64, String)>, String> {
    if keys.len() > max {
        return Err("journal tail exceeds bound".into());
    }
    let mut tail = Vec::with_capacity(keys.len());
    let mut previous = after;
    for key in keys {
        let sequence = journal_record_key_sequence(key, prefix)?;
        let expected = previous
            .checked_add(1)
            .ok_or("journal tail sequence overflow")?;
        if sequence == previous {
            return Err("journal tail duplicate key".into());
        }
        if sequence != expected {
            return Err("journal tail sequence gap".into());
        }
        tail.push((sequence, key.clone()));
        previous = sequence;
    }
    Ok(tail)
}

/// The enclave terminal after a durable append must be the exact result the
/// record committed to, under the same canonical hashes the journal uses.
#[cfg_attr(not(test), allow(dead_code))]
fn verify_terminal_matches_record(result: &DirectResult, record: &DirectJournalRecord) -> bool {
    canonical_result_hash(result).is_ok_and(|hash| hash == record.result_hash)
        && canonical_receipt_hash(result).is_ok_and(|hash| hash == record.receipt_hash)
        && result.receipt.request_hash == record.request_hash
}

/// Resolve legacy duplicate heads by walking backward from the unique tip.
/// The only admissible twin is the one whose state hash is the canonical
/// successor's prior-state hash. No timestamp or listing order is authority.
fn resolve_archive_heads(
    entries: Vec<(ResolvedArchiveHead, Option<(String, String)>)>,
) -> Result<(Vec<ResolvedArchiveHead>, Vec<ResolvedArchiveHead>), String> {
    let mut by_sequence: BTreeMap<u64, Vec<(ResolvedArchiveHead, Option<(String, String)>)>> =
        BTreeMap::new();
    for (head, linkage) in entries {
        if head.sequence == 0 {
            return Err("archive head content sequence mismatch".into());
        }
        by_sequence
            .entry(head.sequence)
            .or_default()
            .push((head, linkage));
    }
    if by_sequence.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }
    let last = *by_sequence
        .keys()
        .next_back()
        .ok_or("archive head missing")?;
    if by_sequence.len() != last as usize || by_sequence.keys().copied().ne(1..=last) {
        return Err("archive head sequence gap".into());
    }
    let mut canonical = Vec::with_capacity(last as usize);
    let mut orphans = Vec::new();
    let mut successor: Option<(ResolvedArchiveHead, Option<(String, String)>)> = None;
    for sequence in (1..=last).rev() {
        let mut candidates = by_sequence
            .remove(&sequence)
            .ok_or("archive head sequence gap")?;
        let selected = if candidates.len() == 1 {
            candidates.remove(0)
        } else if let Some(successor) = &successor {
            let successor_prior = successor
                .1
                .as_ref()
                .map(|(prior, _)| prior)
                .ok_or("archive duplicate successor linkage unavailable")?;
            let matches = candidates
                .iter()
                .enumerate()
                .filter(|(_, (_, linkage))| {
                    linkage
                        .as_ref()
                        .is_some_and(|(_, state)| state == successor_prior)
                })
                .map(|(index, _)| index)
                .collect::<Vec<_>>();
            if matches.len() != 1 {
                return Err("archive duplicate head is not uniquely resolved by successor".into());
            }
            candidates.remove(matches[0])
        } else {
            return Err("archive terminal duplicate head is unresolvable".into());
        };
        orphans.extend(candidates.into_iter().map(|(head, _)| head));
        successor = Some(selected.clone());
        canonical.push(selected.0);
    }
    canonical.reverse();
    orphans.sort_by_key(|head| head.sequence);
    Ok((canonical, orphans))
}

fn resolved_head_from_artifact(
    key: String,
    artifact: DirectStateArtifact,
    prefix: &str,
) -> Result<(ResolvedArchiveHead, Option<(String, String)>), String> {
    let head_prefix = format!("{prefix}/heads/");
    let sequence = archive_key_sequence(&key, &head_prefix, false)?;
    if sequence == 0 || artifact.sequence != sequence {
        return Err("archive head content sequence mismatch".into());
    }
    let hash = artifact_hash(&artifact);
    if let Some(name_hash) = key
        .strip_prefix(&head_prefix)
        .and_then(|name| name.strip_suffix(".cbor"))
        .and_then(|name| name.split_once('-').map(|(_, hash)| hash))
    {
        if name_hash != hash {
            return Err("archive head content address mismatch".into());
        }
    }
    Ok((
        ResolvedArchiveHead {
            key,
            sequence,
            artifact_hash: hash,
        },
        Some((artifact.prior_state_hash, artifact.state_hash)),
    ))
}

// Artifact persistence precedes immutable head persistence. A failed candidate
// can therefore coexist with a different, head-backed artifact at the same
// sequence. Never replay that candidate or delete it. Only the canonical
// successor-linked heads select committed artifacts.
fn committed_archive_keys(
    candidates: &[String],
    heads: &[ResolvedArchiveHead],
    prefix: &str,
) -> Result<Vec<String>, String> {
    let artifact_prefix = format!("{prefix}/artifacts/");
    let mut available = HashSet::with_capacity(candidates.len());
    for key in candidates {
        let seq = archive_key_sequence(key, &artifact_prefix, true)?;
        if seq == 0 || seq > heads.len() as u64 || !available.insert(key.as_str()) {
            return Err("archive unheaded tail or duplicate candidate".into());
        }
    }
    let mut selected = Vec::with_capacity(heads.len());
    for (index, head) in heads.iter().enumerate() {
        if head.sequence != index as u64 + 1 {
            return Err("archive head sequence gap".into());
        }
        let key = format!(
            "{artifact_prefix}{:020}-{}.cbor",
            head.sequence, head.artifact_hash
        );
        if !available.contains(key.as_str()) {
            return Err("archive committed artifact missing".into());
        }
        selected.push(key);
    }
    Ok(selected)
}

/// The checkpoint must cover an exact prefix of the independently listed,
/// immutable artifact AND head namespaces. A stale checkpoint is valid only
/// when every later successor is subsequently verified; it is not the tip.
fn validate_checkpoint_archive(
    checkpoint: &layrs_direct_execution_v1::DirectCheckpoint,
    keys: &[String],
    heads: &[ResolvedArchiveHead],
    prefix: &str,
) -> Result<usize, String> {
    let sequence = usize::try_from(checkpoint.artifact.sequence)
        .map_err(|_| "checkpoint sequence overflow")?;
    if sequence == 0
        || sequence > keys.len()
        || keys.len() != heads.len()
        || checkpoint.receipt_records.len() != sequence
    {
        return Err("checkpoint frontier outside immutable archive".into());
    }
    for (index, record) in checkpoint.receipt_records.iter().enumerate() {
        if record.sequence != index as u64 + 1
            || checkpoint.artifact_hashes.len() != sequence
            || keys[index]
                != format!(
                    "{prefix}/artifacts/{:020}-{}.cbor",
                    record.sequence, checkpoint.artifact_hashes[index]
                )
            || heads[index].sequence != record.sequence
            || heads[index].artifact_hash != checkpoint.artifact_hashes[index]
        {
            return Err("checkpoint prefix differs from immutable archive".into());
        }
    }
    if receipt_only_record(&checkpoint.artifact)
        != *checkpoint
            .receipt_records
            .last()
            .ok_or("checkpoint head missing")?
    {
        return Err("checkpoint terminal head mismatch".into());
    }
    Ok(sequence)
}

/// Room for the request envelope around the bundle and record encodings.
const V70_ROLLBACK_FRAME_ENVELOPE_BYTES: usize = 4096;

/// Descriptor of a materialized v70 rollback package. A governed rollback
/// grant's committed restore frontier must name exactly this head.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Debug, PartialEq, Eq)]
struct V70RollbackPackage {
    prefix: String,
    sequence: u64,
    state_hash: String,
    artifact_hash: String,
    checkpoint_key: String,
}

/// The rollback prefix is supplied explicitly and must be canonical and
/// disjoint from the authoritative archive, never nested in either direction.
#[cfg_attr(not(test), allow(dead_code))]
fn validate_v70_rollback_prefix(authoritative: &str, fresh: &str) -> Result<(), &'static str> {
    if fresh.is_empty()
        || fresh.len() > 512
        || !fresh
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'/'))
        || fresh
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err("v70 rollback prefix invalid");
    }
    if fresh == authoritative
        || fresh.starts_with(&format!("{authoritative}/"))
        || authoritative.starts_with(&format!("{fresh}/"))
    {
        return Err("v70 rollback prefix overlaps authoritative archive");
    }
    Ok(())
}

/// The complete seal request must fit one enclave frame.
#[cfg_attr(not(test), allow(dead_code))]
fn advance_v70_rollback_frame_bytes(total: usize, next: usize) -> Result<usize, &'static str> {
    total
        .checked_add(next)
        .filter(|sum| {
            sum.checked_add(V70_ROLLBACK_FRAME_ENVELOPE_BYTES)
                .is_some_and(|framed| framed <= MAX_FRAME_BYTES)
        })
        .ok_or("v70 rollback request exceeds frame bound")
}

/// The enclave-sealed rollback checkpoint must cover exactly `head_sequence`
/// and its compact lineage must be the parent's authenticated receipt order.
/// Returns the one full head artifact key, the one head pointer, and the exact
/// committed frontier that the governed rollback grant must name; the sparse
/// archive validator must accept the checkpoint over exactly those objects.
#[cfg_attr(not(test), allow(dead_code))]
fn validate_v70_rollback_checkpoint(
    checkpoint: &layrs_direct_execution_v1::DirectCheckpoint,
    head_sequence: u64,
    receipts: &[(u64, DirectReceipt)],
    prefix: &str,
) -> Result<
    (
        String,
        ResolvedArchiveHead,
        layrs_direct_execution_v1::CommittedRestoreFrontier,
    ),
    String,
> {
    let sequence = usize::try_from(head_sequence).map_err(|_| "v70 rollback sequence overflow")?;
    if sequence == 0
        || sequence > MAX_V70_LINEAGE_RECORDS
        || checkpoint.protocol != "layrs.direct-execution.checkpoint.v1"
        || checkpoint.bootstrap_certificate.is_some()
        || checkpoint.signature.is_empty()
        || checkpoint.artifact.epoch_id != EPOCH_ID
        || checkpoint.artifact.sequence != head_sequence
        || checkpoint.artifact.ciphertext.is_empty()
        || checkpoint.artifact.ciphertext_hash != sha256(&checkpoint.artifact.ciphertext)
        || checkpoint.receipt_records.len() != sequence
        || checkpoint.artifact_hashes.len() != sequence
        || receipts.len() != sequence
    {
        return Err("v70 rollback checkpoint header invalid".into());
    }
    let head_hash = artifact_hash(&checkpoint.artifact);
    let mut prior = &checkpoint.opening_state_hash;
    for (index, (record, (receipt_sequence, receipt))) in
        checkpoint.receipt_records.iter().zip(receipts).enumerate()
    {
        let expected = index as u64 + 1;
        let content_hash = if expected == head_sequence {
            head_hash.clone()
        } else {
            artifact_hash(record)
        };
        if record.epoch_id != EPOCH_ID
            || record.sequence != expected
            || record.prior_state_hash != *prior
            || !record.ciphertext.is_empty()
            || record.request_hash != record.receipt.request_hash
            || *receipt_sequence != expected
            || record.receipt != *receipt
            || checkpoint.artifact_hashes[index] != content_hash
        {
            return Err("v70 rollback checkpoint lineage mismatch".into());
        }
        prior = &record.state_hash;
    }
    let frontier = layrs_direct_execution_v1::CommittedRestoreFrontier {
        sequence: head_sequence,
        state_hash: checkpoint.artifact.state_hash.clone(),
        artifact_hash: head_hash.clone(),
    };
    let key = format!("{prefix}/artifacts/{head_sequence:020}-{head_hash}.cbor");
    let head = ResolvedArchiveHead {
        key: archive_head_key(prefix, head_sequence),
        sequence: head_sequence,
        artifact_hash: head_hash,
    };
    if validate_sparse_checkpoint_archive(
        checkpoint,
        &frontier,
        std::slice::from_ref(&key),
        std::slice::from_ref(&head),
        prefix,
    )? != 1
    {
        return Err("v70 rollback checkpoint frontier mismatch".into());
    }
    Ok((key, head, frontier))
}

/// Sparse counterpart of `validate_checkpoint_archive` for an archive that
/// begins at a governed rollback baseline. The exact committed frontier must
/// accept the checkpoint, and every sequence from the baseline through the
/// checkpoint must be backed by the listed artifact and head, which start at
/// the baseline. Returns how many listed sequences the checkpoint covers.
fn validate_sparse_checkpoint_archive(
    checkpoint: &layrs_direct_execution_v1::DirectCheckpoint,
    frontier: &layrs_direct_execution_v1::CommittedRestoreFrontier,
    keys: &[String],
    heads: &[ResolvedArchiveHead],
    prefix: &str,
) -> Result<usize, String> {
    let sequence = checkpoint.artifact.sequence;
    if !frontier.accepts_checkpoint(checkpoint)
        || keys.is_empty()
        || keys.len() != heads.len()
        || checkpoint.receipt_records.len() as u64 != sequence
        || checkpoint.artifact_hashes.len() as u64 != sequence
        || checkpoint.artifact_hashes.last() != Some(&artifact_hash(&checkpoint.artifact))
    {
        return Err("sparse checkpoint outside governed baseline".into());
    }
    let covered = usize::try_from(sequence - frontier.sequence + 1)
        .map_err(|_| "checkpoint sequence overflow")?;
    if covered > keys.len() {
        return Err("checkpoint frontier outside immutable archive".into());
    }
    for offset in 0..covered {
        let expected = frontier.sequence + offset as u64;
        let index = expected as usize - 1;
        let hash = &checkpoint.artifact_hashes[index];
        if checkpoint.receipt_records[index].sequence != expected
            || keys[offset] != format!("{prefix}/artifacts/{expected:020}-{hash}.cbor")
            || heads[offset].sequence != expected
            || heads[offset].artifact_hash != *hash
        {
            return Err("checkpoint prefix differs from immutable archive".into());
        }
    }
    if receipt_only_record(&checkpoint.artifact)
        != *checkpoint
            .receipt_records
            .last()
            .ok_or("checkpoint head missing")?
    {
        return Err("checkpoint terminal head mismatch".into());
    }
    Ok(covered)
}

/// The rollback-baseline mode is usable only with the governed grant's exact
/// committed frontier. It has no isolated-test or genesis fallback.
fn sparse_rollback_frontier(
    state: &AppState,
) -> Result<&layrs_direct_execution_v1::CommittedRestoreFrontier, String> {
    state
        .governed_bootstrap
        .as_ref()
        .and_then(|config| config.grant.committed_restore_frontier.as_ref())
        .filter(|frontier| frontier.valid())
        .ok_or_else(|| "v70 rollback baseline requires the governed committed frontier".into())
}

impl S3ImmutableArtifactStore {
    fn checkpoint_key(&self, checkpoint: &layrs_direct_execution_v1::DirectCheckpoint) -> Result<String, String> {
        let bytes = serde_cbor::to_vec(checkpoint).map_err(|_| "checkpoint encoding failed")?;
        Ok(format!("{}/checkpoints/{:020}-{}-{}.cbor", self.prefix, checkpoint.artifact.sequence, checkpoint.artifact.state_hash, sha256(&bytes)))
    }
    async fn build_current_checkpoint(&self, state: &AppState) -> Result<Option<layrs_direct_execution_v1::DirectCheckpoint>, String> {
        let records = self.load_committed().await?;
        let Some(head) = records.last() else { return Ok(None); };
        let artifact_hashes = self.verified_artifact_hashes.lock().await.clone();
        let hash = artifact_hashes.last().ok_or("checkpoint archive hashes missing")?;
        let key = format!("{}/artifacts/{:020}-{hash}.cbor", self.prefix, head.sequence);
        let artifact: DirectStateArtifact = serde_cbor::from_slice(&self.read(&key).await?)
            .map_err(|_| "checkpoint head decode failed")?;
        if receipt_only_record(&artifact) != *head { return Err("checkpoint head mismatch".into()); }
        let response = exchange_with_timeout(state, RuntimeRequest::SealCheckpoint { artifact, receipt_records: records, artifact_hashes }, CHECKPOINT_EXCHANGE_TIMEOUT)
            .await.map_err(|error| if frame_oversized(&error) { CHECKPOINT_OVERSIZED } else { "checkpoint seal transport failed" })?;
        let checkpoint = match response {
            RuntimeResponse::CheckpointSealed { checkpoint } => checkpoint,
            RuntimeResponse::Error { code } if code == CHECKPOINT_FRAME_OVERSIZED => return Err(CHECKPOINT_OVERSIZED.into()),
            _ => return Err("checkpoint seal rejected".into()),
        };
        Ok(Some(checkpoint))
    }
    async fn persist_checkpoint(&self, checkpoint: layrs_direct_execution_v1::DirectCheckpoint) -> Result<(), String> {
        let sequence = checkpoint.artifact.sequence;
        let key = self.checkpoint_key(&checkpoint)?;
        self.write_once(&key, serde_cbor::to_vec(&checkpoint).map_err(|_| "checkpoint encoding failed")?).await?;
        eprintln!("VERIFIED_ARCHIVE_CHECKPOINT_PERSISTED {sequence}");
        Ok(())
    }
    /// Captures one exact v71 head under the financial gate, then releases the
    /// gate before immutable storage I/O. Parent acceleration snapshots are
    /// written first; the enclave-authenticated checkpoint is the publication
    /// marker, so a crash can leave only harmless orphan snapshots.
    async fn seal_current_journal_checkpoint(&self, state: &AppState) -> Result<(), String> {
        let guard = state
            .financial_gate
            .lock("journal_checkpoint_capture")
            .await;
        if !state.unresolved_external_effects.lock().await.is_empty() {
            return Err("journal checkpoint external effect pending".into());
        }
        let head = match &*self.journal.lock().await {
            JournalWriterState::Eligible(head) => head.clone(),
            JournalWriterState::Unrestored | JournalWriterState::Latched(_) => {
                return Err("journal checkpoint head unavailable".into())
            }
        };
        let last_checkpoint = state.journal_checkpoint_sequence.load(Ordering::Acquire);
        if !journal_checkpoint_due(head.sequence, last_checkpoint) {
            return Ok(());
        }
        let response = exchange_with_timeout(
            state,
            RuntimeRequest::SealJournalCheckpoint,
            CHECKPOINT_EXCHANGE_TIMEOUT,
        )
        .await
        .map_err(|_| "journal checkpoint seal transport failed")?;
        let checkpoint = match response {
            RuntimeResponse::JournalCheckpointSealed { checkpoint }
                if checkpoint.writer_epoch == head.writer_epoch
                    && checkpoint.sequence == head.sequence
                    && checkpoint.record_hash == head.record_hash
                    && checkpoint.transition_root == head.transition_root
                    && checkpoint.request_index_root == head.request_index_root
                    && checkpoint.financial_state_root == head.financial_state_root =>
            {
                checkpoint
            }
            RuntimeResponse::Error { .. } => {
                return Err("journal checkpoint seal rejected".into())
            }
            _ => return Err("journal checkpoint seal mismatch".into()),
        };
        let index = state
            .journal_request_index
            .lock()
            .await
            .as_ref()
            .cloned()
            .ok_or("journal checkpoint cache unavailable")?;
        let receipts = state
            .journal_receipts
            .lock()
            .await
            .as_ref()
            .cloned()
            .ok_or("journal checkpoint cache unavailable")?;
        drop(guard);

        let index_snapshot = index
            .snapshot(checkpoint.sequence, &checkpoint.request_index_root)
            .map_err(|_| "journal checkpoint request index invalid")?;
        let receipt_snapshot = DirectReceiptSnapshot::from_receipts(
            &index_snapshot,
            receipts.into_values(),
        )
        .map_err(|_| "journal checkpoint receipts invalid")?;
        verify_journal_checkpoint_non_writer(state, &checkpoint).await?;
        self.publish_journal_checkpoint(&checkpoint, &index_snapshot, &receipt_snapshot)
            .await?;
        state
            .journal_checkpoint_sequence
            .fetch_max(checkpoint.sequence, Ordering::AcqRel);
        eprintln!(
            "VERIFIED_JOURNAL_CHECKPOINT_PERSISTED {}",
            checkpoint.sequence
        );
        Ok(())
    }

    async fn schedule_journal_checkpoint(&self, state: &AppState) {
        let sequence = match &*self.journal.lock().await {
            JournalWriterState::Eligible(head) => head.sequence,
            JournalWriterState::Unrestored | JournalWriterState::Latched(_) => return,
        };
        if !journal_checkpoint_due(
            sequence,
            state.journal_checkpoint_sequence.load(Ordering::Acquire),
        ) {
            return;
        }
        if self.checkpoint_refresh_gate.lock().await.request() {
            let store = self.clone();
            let state = state.clone();
            tokio::spawn(async move {
                let (store, state) = (&store, &state);
                refresh_checkpoints(&store.checkpoint_refresh_gate, move || {
                    store.seal_current_journal_checkpoint(state)
                })
                .await;
            });
        }
    }
    /// Before opening the listener, collapse a restored tail that has reached
    /// checkpoint cadence. One synchronous attempt prevents the next commit
    /// from crossing the restore bound. Failure remains non-fatal and starts
    /// the existing five-minute background retry, so availability is preserved.
    async fn catch_up_restored_journal_checkpoint(&self, state: &AppState) {
        let sequence = match &*self.journal.lock().await {
            JournalWriterState::Eligible(head) => head.sequence,
            JournalWriterState::Unrestored | JournalWriterState::Latched(_) => return,
        };
        if !journal_checkpoint_due(
            sequence,
            state.journal_checkpoint_sequence.load(Ordering::Acquire),
        ) {
            return;
        }
        if let Err(error) = self.seal_current_journal_checkpoint(state).await {
            let reason = checkpoint_seal_reason(&error);
            eprintln!("VERIFIED_JOURNAL_STARTUP_CHECKPOINT_PENDING reason={reason}");
            self.schedule_journal_checkpoint(state).await;
        }
    }
    #[cfg(test)]
    async fn seal_current_checkpoint(&self, state: &AppState) -> Result<(), String> {
        let Some(checkpoint) = self.build_current_checkpoint(state).await? else { return Ok(()); };
        self.persist_checkpoint(checkpoint).await
    }
    /// Hold the financial gate only while selecting/reading an exact immutable
    /// head and obtaining its enclave seal. The content-addressed checkpoint
    /// remains valid if commits advance while its S3 write completes.
    async fn seal_current_checkpoint_serialized(&self, state: &AppState) -> Result<(), String> {
        let (checkpoint, wait, hold) = checkpoint_snapshot_under_gate(&state.financial_gate, || {
            self.build_current_checkpoint(state)
        }).await;
        let checkpoint = checkpoint?;
        let sequence = checkpoint.as_ref().map(|value| value.artifact.sequence).unwrap_or_default();
        eprintln!(
            "VERIFIED_ARCHIVE_CHECKPOINT_GATE_RELEASED sequence={sequence} wait_ms={} hold_ms={}",
            wait.as_millis(),
            hold.as_millis()
        );
        let Some(checkpoint) = checkpoint else { return Ok(()); };
        self.persist_checkpoint(checkpoint).await
    }
    /// Runs only after the final encrypted head is verified and adopted. The
    /// immutable archive stays authoritative and the prior checkpoint stays in
    /// place, so a failed seal is diagnosed but never fails the restore.
    async fn schedule_restored_checkpoint(&self, state: &AppState) {
        if self.checkpoint_refresh_gate.lock().await.request() {
            let store = self.clone();
            let state = state.clone();
            tokio::spawn(async move {
                let (store, state) = (&store, &state);
                refresh_checkpoints(&store.checkpoint_refresh_gate, move || {
                    store.seal_current_checkpoint_serialized(state)
                })
                .await;
            });
        }
    }
    async fn from_environment() -> Result<Self, Box<dyn std::error::Error>> {
        let bucket = env::var("LAYRS_DIRECT_ARCHIVE_BUCKET")?;
        let prefix = env::var("LAYRS_DIRECT_ARCHIVE_PREFIX")?;
        let kms_key_id = env::var("LAYRS_DIRECT_ARCHIVE_KMS_KEY_ID")?;
        let retention_seconds =
            env::var("LAYRS_DIRECT_ARCHIVE_RETENTION_SECONDS")?.parse::<i64>()?;
        if bucket.is_empty()
            || prefix.is_empty()
            || kms_key_id.is_empty()
            || retention_seconds < 86_400
        {
            return Err("invalid immutable archive configuration".into());
        }
        let timeout_config = TimeoutConfig::builder()
            .operation_attempt_timeout(ARCHIVE_OPERATION_TIMEOUT)
            .operation_timeout(ARCHIVE_OPERATION_TIMEOUT)
            .build();
        let retry_config = RetryConfig::standard().with_max_attempts(3);
        let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .timeout_config(timeout_config)
            .retry_config(retry_config)
            .load()
            .await;
        let client = S3Client::new(&sdk_config);
        client
            .get_object_lock_configuration()
            .bucket(&bucket)
            .send()
            .await?;
        Ok(Self {
            client,
            bucket,
            prefix: prefix.trim_end_matches('/').into(),
            kms_key_id,
            retention_seconds,
            verified_receipt_records: Arc::new(Mutex::new(None)),
            verified_artifact_hashes: Arc::new(Mutex::new(Vec::new())),
            prepared_restore: Arc::new(Mutex::new(None)),
            prepared_journal_restore: Arc::new(Mutex::new(None)),
            checkpoint_refresh_gate: Arc::new(Mutex::new(CheckpointRefresh::default())),
            journal: Arc::new(Mutex::new(JournalWriterState::Unrestored)),
            journal_role: JournalRole::Writer,
        })
    }
    fn artifact_key(&self, artifact: &DirectStateArtifact) -> String {
        format!(
            "{}/artifacts/{:020}-{}.cbor",
            self.prefix,
            artifact.sequence,
            artifact_hash(artifact)
        )
    }
    fn head_key(&self, artifact: &DirectStateArtifact) -> String {
        archive_head_key(&self.prefix, artifact.sequence)
    }
    fn intent_key(&self, intent: &ExternalEffectIntent) -> String {
        format!(
            "{}/external-effect-intents/{}.cbor",
            self.prefix, intent.intent_hash
        )
    }
    fn key_release_key(&self, activation_id: &str) -> String {
        format!("{}/authorization/{}.cbor", self.prefix, activation_id)
    }
    async fn read(&self, key: &str) -> Result<Bytes, String> {
        // SDK request retries do not retry a response stream after headers.
        // Discard an incomplete body and GET the same immutable key again;
        // no partial bytes ever reach the encrypted successor verifier.
        let mut timed_out = false;
        for attempt in 0..5 {
            let result=timeout(Duration::from_secs(60),async {
                let response=self.client.get_object().bucket(&self.bucket).key(key)
                    .send().await.map_err(|_|"archive read failed")?;
                let length=response.content_length.filter(|length|*length>0 && *length<=MAX_FRAME_BYTES as i64)
                    .ok_or("archive read size invalid")?;
                let bytes=response.body.collect().await.map_err(|_|"archive read body failed")?.into_bytes();
                if bytes.len()!=length as usize {return Err("archive read body length mismatch");}
                Ok(bytes)
            }).await;
            match result {
                Ok(Ok(bytes)) => return Ok(bytes),
                Err(_) => timed_out = true,
                Ok(Err(_)) => {}
            }
            if attempt<4 {
                eprintln!("ARCHIVE_READ_RETRY {}/5",attempt+2);
                tokio::time::sleep(Duration::from_millis(100u64<<attempt)).await;
            }
        }
        Err(if timed_out { "ARCHIVE_TIMEOUT" } else { "archive complete read retries exhausted" }.into())
    }
    async fn write_once(&self, key: &str, bytes: Vec<u8>) -> Result<(), String> {
        let until = DateTime::from_secs(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| "clock invalid")?
                .as_secs() as i64
                + self.retention_seconds,
        );
        eprintln!("FINANCIAL_AWAIT_BEGIN stage=archive_put");
        let put = bounded_archive_operation(
            ARCHIVE_OPERATION_TIMEOUT,
            self.client
                .put_object()
                .bucket(&self.bucket)
                .key(key)
                .body(ByteStream::from(bytes.clone()))
                .if_none_match("*")
                .server_side_encryption(ServerSideEncryption::AwsKms)
                .ssekms_key_id(&self.kms_key_id)
                .object_lock_mode(ObjectLockMode::Compliance)
                .object_lock_retain_until_date(until)
                .send(),
        )
        .await?;
        eprintln!("FINANCIAL_AWAIT_END stage=archive_put");
        let restored = self.read(key).await?;
        if put.is_err() && restored != bytes {
            return Err(if key.contains("/heads/") {
                "ARCHIVE_SEQUENCE_CONFLICT"
            } else {
                "archive immutable write failed"
        }
            .into());
        }
        if restored != bytes {
            return Err("archive readback mismatch".into());
        }
        Ok(())
    }
    /// True if any fence exists for `writer_epoch`. `ListObjectsV2` is
    /// strongly consistent, so a fence durable before this call is seen.
    /// Every error, timeout, or malformed/ambiguous page is `Err`, which
    /// callers must treat as fenced.
    #[cfg_attr(not(test), allow(dead_code))]
    async fn writer_fenced(&self, writer_epoch: &str) -> Result<bool, String> {
        let fence_prefix = journal_fence_prefix(&self.prefix, writer_epoch);
        let page = bounded_archive_operation(
            ARCHIVE_OPERATION_TIMEOUT,
            self.client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(&fence_prefix)
                .max_keys(1)
                .send(),
        )
        .await?
        .map_err(|_| "journal fence listing failed")?;
        let contents = page.contents();
        if page
            .key_count
            .is_some_and(|count| usize::try_from(count).ok() != Some(contents.len()))
        {
            return Err("journal fence listing ambiguous".into());
        }
        for object in contents {
            let key = object.key().ok_or("journal fence key missing")?;
            if key.len() <= fence_prefix.len() || !key.starts_with(&fence_prefix) {
                return Err("journal fence key foreign".into());
            }
        }
        if contents.is_empty() && page.is_truncated.unwrap_or(false) {
            return Err("journal fence listing ambiguous".into());
        }
        Ok(!contents.is_empty())
    }
    #[cfg_attr(not(test), allow(dead_code))]
    async fn latch_journal(&self, code: &'static str) {
        latch_journal_state(&mut *self.journal.lock().await, code);
    }
    async fn establish_journal_head(&self, head: JournalHead) -> Result<(), String> {
        if self.journal_role != JournalRole::Writer {
            return Err("JOURNAL_SHADOW_WRITE_UNSUPPORTED".into());
        }
        if self.writer_fenced(&head.writer_epoch).await? {
            self.latch_journal("JOURNAL_WRITER_FENCED").await;
            return Err("JOURNAL_WRITER_FENCED".into());
        }
        let mut journal = self.journal.lock().await;
        match &*journal {
            JournalWriterState::Unrestored => {
                *journal = JournalWriterState::Eligible(head);
                Ok(())
            }
            JournalWriterState::Eligible(existing) if existing == &head => Ok(()),
            JournalWriterState::Eligible(_) | JournalWriterState::Latched(_) => {
                latch_journal_state(&mut journal, "JOURNAL_HEAD_ESTABLISHMENT_CONFLICT");
                Err("JOURNAL_HEAD_ESTABLISHMENT_CONFLICT".into())
            }
        }
    }
    /// Plan section 4 steps 1-6. The journal lock is held from the eligibility
    /// check through the post-PUT fence listing, so nothing else can PUT or
    /// advance the head meanwhile. Only an exact readback followed by an empty,
    /// error-free fence listing advances the head; every other outcome latches.
    #[cfg_attr(not(test), allow(dead_code))]
    async fn append_journal_record(
        &self,
        record: &DirectJournalRecord,
    ) -> Result<JournalHead, String> {
        // A shadow store must never use authoritative heads. Until the shadow
        // prefix guard exists, shadow appends are refused outright.
        if self.journal_role != JournalRole::Writer {
            return Err("JOURNAL_SHADOW_APPEND_UNSUPPORTED".into());
        }
        let mut journal = self.journal.lock().await;
        let head = match &*journal {
            JournalWriterState::Eligible(head) => head.clone(),
            JournalWriterState::Latched(_) => return Err("JOURNAL_LATCHED".into()),
            JournalWriterState::Unrestored => return Err("JOURNAL_UNRESTORED".into()),
        };
        let checked = precheck_journal_candidate(&head, record).and_then(|bytes| {
            let record_hash = record
                .record_hash()
                .map_err(|_| "journal candidate hash failed")?;
            Ok((bytes, record_hash))
        });
        let (bytes, record_hash) = match checked {
            Ok(checked) => checked,
            Err(reason) => {
                eprintln!("JOURNAL_CANDIDATE_REJECTED reason={reason}");
                latch_journal_state(&mut journal, "JOURNAL_CANDIDATE_OUT_OF_ORDER");
                return Err("JOURNAL_CANDIDATE_OUT_OF_ORDER".into());
            }
        };
        let key = journal_record_key(&self.prefix, record.sequence);
        if let Err(error) = self.write_once(&key, bytes).await {
            // Timeout or read exhaustion leaves the slot unknown; a conflict
            // means another writer holds it. Neither may be retried here.
            let code = match error.as_str() {
                "ARCHIVE_SEQUENCE_CONFLICT" => "ARCHIVE_SEQUENCE_CONFLICT",
                "ARCHIVE_TIMEOUT" => "ARCHIVE_TIMEOUT",
                _ => "JOURNAL_APPEND_UNVERIFIED",
            };
            latch_journal_state(&mut journal, code);
            return Err(error);
        }
        // Strictly after the PUT returned (plan section 5, N1).
        match self.writer_fenced(&head.writer_epoch).await {
            Ok(false) => {}
            Ok(true) => {
                latch_journal_state(&mut journal, "JOURNAL_WRITER_FENCED");
                return Err("JOURNAL_WRITER_FENCED".into());
            }
            Err(error) => {
                eprintln!("JOURNAL_FENCE_UNAVAILABLE error={error}");
                latch_journal_state(&mut journal, "JOURNAL_FENCE_UNAVAILABLE");
                return Err("JOURNAL_FENCE_UNAVAILABLE".into());
            }
        }
        let next = JournalHead {
            writer_epoch: head.writer_epoch,
            sequence: record.sequence,
            record_hash,
            transition_root: record.transition_root.clone(),
            request_index_root: record.request_index_root.clone(),
            financial_state_root: record.financial_state_root.clone(),
        };
        *journal = JournalWriterState::Eligible(next.clone());
        Ok(next)
    }
    async fn persist_v71_cutover_marker(
        &self,
        head: &StagedV71Head,
    ) -> Result<(), String> {
        if self.journal_role != JournalRole::Writer {
            return Err("JOURNAL_SHADOW_WRITE_UNSUPPORTED".into());
        }
        let marker = V71CutoverMarker::from_head(head);
        if !marker.valid() {
            return Err("V71_CUTOVER_MARKER_INVALID".into());
        }
        let bytes = serde_cbor::to_vec(&marker)
            .map_err(|_| "V71_CUTOVER_MARKER_ENCODING_FAILED")?;
        self.write_once(&journal_cutover_marker_key(&self.prefix), bytes)
            .await
    }

    async fn load_v71_cutover_marker(&self) -> Result<Option<V71CutoverMarker>, String> {
        let key = journal_cutover_marker_key(&self.prefix);
        let page = bounded_archive_operation(
            ARCHIVE_OPERATION_TIMEOUT,
            self.client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(&key)
                .max_keys(2)
                .send(),
        )
        .await?
        .map_err(|_| "V71_CUTOVER_MARKER_LIST_FAILED")?;
        let contents = page.contents();
        if page.is_truncated.unwrap_or(false)
            || contents.len() > 1
            || page
                .key_count
                .is_some_and(|count| usize::try_from(count).ok() != Some(contents.len()))
        {
            return Err("V71_CUTOVER_MARKER_LIST_AMBIGUOUS".into());
        }
        if contents.is_empty() {
            return Ok(None);
        }
        if contents[0].key() != Some(key.as_str()) {
            return Err("V71_CUTOVER_MARKER_KEY_INVALID".into());
        }
        let marker: V71CutoverMarker = serde_cbor::from_slice(&self.read(&key).await?)
            .map_err(|_| "V71_CUTOVER_MARKER_DECODE_FAILED")?;
        if !marker.valid() {
            return Err("V71_CUTOVER_MARKER_INVALID".into());
        }
        Ok(Some(marker))
    }

    async fn prepare_hot_journal_restore(&self) -> Result<bool, String> {
        let Some(marker) = self.load_v71_cutover_marker().await? else {
            return Ok(false);
        };
        if !self.prepare_journal_restore().await? {
            return Err("V71_CUTOVER_MARKER_WITHOUT_JOURNAL".into());
        }
        let prepared = self.prepared_journal_restore.lock().await;
        let prepared = prepared
            .as_ref()
            .ok_or("V71_CUTOVER_JOURNAL_UNPREPARED")?;
        let (writer_epoch, sequence, record_hash, transition_root, request_index_root, financial_state_root) =
            match prepared.tail.last() {
                Some(record) => (
                    record.writer_epoch.as_str(),
                    record.sequence,
                    record
                        .record_hash()
                        .map_err(|_| "V71_CUTOVER_TAIL_HASH_INVALID")?,
                    record.transition_root.as_str(),
                    record.request_index_root.as_str(),
                    record.financial_state_root.as_str(),
                ),
                None => (
                    prepared.checkpoint.writer_epoch.as_str(),
                    prepared.checkpoint.sequence,
                    prepared.checkpoint.record_hash.clone(),
                    prepared.checkpoint.transition_root.as_str(),
                    prepared.checkpoint.request_index_root.as_str(),
                    prepared.checkpoint.financial_state_root.as_str(),
                ),
            };
        if marker.writer_epoch != writer_epoch
            || marker.sequence != sequence
            || marker.record_hash != record_hash
            || marker.transition_root != transition_root
            || marker.request_index_root != request_index_root
            || marker.financial_state_root != financial_state_root
        {
            return Err("V71_CUTOVER_MARKER_HEAD_MISMATCH".into());
        }
        Ok(true)
    }
    /// Create-only, content-addressed persistence of an enclave-sealed v70
    /// migration bundle. The bundle may be production-sized, so it uses the
    /// multipart path; the result is accepted only after an exact readback.
    #[cfg_attr(not(test), allow(dead_code))]
    async fn persist_v70_migration_bundle(&self, bundle: &V70MigrationBundle) -> Result<String, String> {
        if self.journal_role != JournalRole::Writer {
            return Err("JOURNAL_SHADOW_WRITE_UNSUPPORTED".into());
        }
        if bundle.manifest.protocol != V70_MIGRATION_MANIFEST_PROTOCOL
            || bundle.manifest.epoch_id != EPOCH_ID
        {
            return Err("journal migration bundle header invalid".into());
        }
        let bytes = serde_cbor::to_vec(bundle).map_err(|_| "journal migration bundle encoding failed")?;
        // `read` cannot return more than one frame, so a larger object could
        // never be read back or restored; refuse it before any PUT.
        if bytes.len() > MAX_FRAME_BYTES {
            return Err("journal migration bundle oversized".into());
        }
        let key = journal_migration_key(&self.prefix, bundle.manifest.source_sequence, &bytes);
        let readback = self.write_once_large(&key, bytes.clone()).await?;
        if readback != bytes
            || serde_cbor::from_slice::<V70MigrationBundle>(&readback).ok().as_ref() != Some(bundle)
        {
            return Err("journal migration bundle readback mismatch".into());
        }
        Ok(key)
    }
    /// Restores the single immutable migration bundle that anchors all
    /// migrated terminal-result locators. Multiple objects are ambiguous and
    /// therefore fail closed rather than selecting by listing order.
    async fn load_v70_migration_bundle(&self) -> Result<Option<V70MigrationBundle>, String> {
        let namespace = format!("{}/journal-v71/migrations/", self.prefix);
        let keys = self
            .list_journal_keys(&namespace, None, 2, ARCHIVE_OPERATION_TIMEOUT)
            .await?;
        let Some(key) = keys.first() else {
            return Ok(None);
        };
        if keys.len() != 1 {
            return Err("journal migration bundle ambiguous".into());
        }
        let (source_sequence, content_hash) = journal_content_key_parts(key, &namespace)?;
        let bytes = self.read(key).await?;
        if bytes.len() > MAX_FRAME_BYTES || sha256(&bytes) != content_hash {
            return Err("journal migration bundle content address mismatch".into());
        }
        let bundle: V70MigrationBundle = serde_cbor::from_slice(&bytes)
            .map_err(|_| "journal migration bundle decode failed")?;
        if serde_cbor::to_vec(&bundle).ok().as_deref() != Some(bytes.as_ref())
            || bundle.manifest.protocol != V70_MIGRATION_MANIFEST_PROTOCOL
            || bundle.manifest.epoch_id != EPOCH_ID
            || bundle.manifest.source_sequence != source_sequence
        {
            return Err("journal migration bundle invalid".into());
        }
        Ok(Some(bundle))
    }

    /// Loads exactly the record named by a terminal journal locator. The
    /// enclave subsequently verifies its signature and encrypted result.
    async fn load_journal_record(&self, sequence: u64) -> Result<DirectJournalRecord, String> {
        if sequence == 0 {
            return Err("journal replay record sequence invalid".into());
        }
        let key = journal_record_key(&self.prefix, sequence);
        let bytes = self.read(&key).await?;
        if bytes.len() > MAX_JOURNAL_RECORD_BYTES {
            return Err("journal replay record oversized".into());
        }
        let record: DirectJournalRecord = serde_cbor::from_slice(&bytes)
            .map_err(|_| "journal replay record decode failed")?;
        if serde_cbor::to_vec(&record).ok().as_deref() != Some(bytes.as_ref())
            || record.protocol != DIRECT_JOURNAL_PROTOCOL
            || record.epoch_id != EPOCH_ID
            || record.sequence != sequence
        {
            return Err("journal replay record invalid".into());
        }
        Ok(record)
    }
    /// A separate store over the same bucket, KMS key, and retention for a
    /// rollback prefix. Its journal is permanently latched, so no v71 append
    /// can ever target it.
    #[cfg_attr(not(test), allow(dead_code))]
    fn v70_rollback_target(&self, prefix: &str) -> Self {
        Self {
            client: self.client.clone(),
            bucket: self.bucket.clone(),
            prefix: prefix.into(),
            kms_key_id: self.kms_key_id.clone(),
            retention_seconds: self.retention_seconds,
            verified_receipt_records: Arc::new(Mutex::new(None)),
            verified_artifact_hashes: Arc::new(Mutex::new(Vec::new())),
            prepared_restore: Arc::new(Mutex::new(None)),
            prepared_journal_restore: Arc::new(Mutex::new(None)),
            checkpoint_refresh_gate: Arc::new(Mutex::new(CheckpointRefresh::default())),
            journal: Arc::new(Mutex::new(JournalWriterState::Latched(
                "V70_ROLLBACK_TARGET",
            ))),
            journal_role: JournalRole::Writer,
        }
    }
    /// Read-only: the exact migration bundle and every canonical v71 record
    /// from the migration source through `head`. A gap, an extra record past
    /// the head, a noncanonical body, broken linkage, a head mismatch, or a
    /// count or frame overflow fails closed.
    #[cfg_attr(not(test), allow(dead_code))]
    async fn load_v70_rollback_inputs(
        &self,
        head: &JournalHead,
        restored: &V70MigrationBundle,
    ) -> Result<(V70MigrationBundle, Vec<DirectJournalRecord>), String> {
        let bundle = self
            .load_v70_migration_bundle()
            .await?
            .ok_or("v70 rollback migration bundle missing")?;
        if bundle != *restored {
            return Err("v70 rollback migration bundle differs from restored lineage".into());
        }
        let source = bundle.manifest.source_sequence;
        if source == 0 || source > head.sequence || head.sequence > MAX_V70_LINEAGE_RECORDS as u64 {
            return Err("v70 rollback lineage outside bound".into());
        }
        let count = usize::try_from(head.sequence - source)
            .map_err(|_| "v70 rollback lineage outside bound")?;
        let mut frame_bytes = advance_v70_rollback_frame_bytes(
            0,
            serde_cbor::to_vec(&bundle)
                .map_err(|_| "v70 rollback migration bundle encoding failed")?
                .len(),
        )?;
        // A record past the head exceeds `count` and fails the listing.
        let keys = self
            .list_journal_keys(
                &format!("{}/heads/", self.prefix),
                Some(&journal_record_key(&self.prefix, source)),
                count,
                ARCHIVE_OPERATION_TIMEOUT,
            )
            .await?;
        let keys = validate_journal_tail_keys(&keys, &self.prefix, source, count)?;
        if keys.len() != count {
            return Err("v70 rollback journal incomplete".into());
        }
        let mut previous_record_hash = bundle
            .manifest
            .manifest_hash()
            .map_err(|_| "v70 rollback migration manifest hash failed")?;
        let mut previous_request_index_root = bundle.manifest.request_index_root.clone();
        let mut previous_transition_root = None;
        let mut records = Vec::with_capacity(count);
        for (sequence, _) in keys {
            let record = self.load_journal_record(sequence).await?;
            frame_bytes = advance_v70_rollback_frame_bytes(
                frame_bytes,
                serde_cbor::to_vec(&record)
                    .map_err(|_| "v70 rollback record encoding failed")?
                    .len(),
            )?;
            // The enclave authenticates the migration anchor's transition
            // root; every later link is also checked here.
            if record.previous_record_hash != previous_record_hash
                || record.previous_request_index_root != previous_request_index_root
                || previous_transition_root
                    .as_ref()
                    .is_some_and(|root| record.previous_transition_root != *root)
            {
                return Err("v70 rollback record predecessor mismatch".into());
            }
            previous_record_hash = record
                .record_hash()
                .map_err(|_| "v70 rollback record hash failed")?;
            previous_request_index_root = record.request_index_root.clone();
            previous_transition_root = Some(record.transition_root.clone());
            records.push(record);
        }
        if previous_record_hash != head.record_hash
            || previous_request_index_root != head.request_index_root
            || records.last().is_some_and(|record| {
                record.transition_root != head.transition_root
                    || record.financial_state_root != head.financial_state_root
            })
        {
            return Err("v70 rollback journal head mismatch".into());
        }
        Ok((bundle, records))
    }
    /// Materializes a validated rollback checkpoint as a sparse retained-v70
    /// baseline under this store's prefix: exactly the full encrypted head
    /// artifact, its head pointer, and then the checkpoint, which is the
    /// restore discovery marker, so an interrupted attempt never exposes one.
    /// Each object is create-only with exact readback, and the prefix must
    /// then list exactly these three objects.
    #[cfg_attr(not(test), allow(dead_code))]
    async fn write_v70_rollback_package(
        &self,
        checkpoint: &layrs_direct_execution_v1::DirectCheckpoint,
        key: &str,
        head: &ResolvedArchiveHead,
    ) -> Result<String, String> {
        let bytes = serde_cbor::to_vec(checkpoint)
            .map_err(|_| "v70 rollback checkpoint encoding failed")?;
        if bytes.len() > MAX_FRAME_BYTES
            || serde_cbor::from_slice::<layrs_direct_execution_v1::DirectCheckpoint>(&bytes)
                .ok()
                .as_ref()
                != Some(checkpoint)
        {
            return Err("v70 rollback checkpoint encoding invalid".into());
        }
        let checkpoint_key = self.checkpoint_key(checkpoint)?;
        let artifact_bytes = serde_cbor::to_vec(&checkpoint.artifact)
            .map_err(|_| "v70 rollback artifact encoding failed")?;
        if self.write_once_large(key, artifact_bytes.clone()).await? != artifact_bytes {
            return Err("archive readback mismatch".into());
        }
        self.write_once(&head.key, head.artifact_hash.clone().into_bytes())
            .await?;
        if self
            .write_once_large(&checkpoint_key, bytes.clone())
            .await?
            != bytes
        {
            return Err("archive readback mismatch".into());
        }
        let mut expected = vec![key.to_string(), head.key.clone(), checkpoint_key.clone()];
        expected.sort();
        if self
            .list_journal_keys(
                &format!("{}/", self.prefix),
                None,
                3,
                ARCHIVE_OPERATION_TIMEOUT,
            )
            .await?
            != expected
        {
            return Err("v70 rollback package listing mismatch".into());
        }
        Ok(checkpoint_key)
    }
    /// Explicit rollback-baseline restore listing. The archive must begin at
    /// the exact governed committed frontier with one baseline artifact, head
    /// pointer, and checkpoint, followed only by contiguous v70 successors
    /// and their checkpoints. Anything below the baseline, a missing or
    /// mismatched baseline object, a second baseline object, or a
    /// noncanonical key fails closed. The normal `prepare_restore` is
    /// unchanged and still rejects such an archive.
    async fn prepare_sparse_rollback_restore(
        &self,
        frontier: &layrs_direct_execution_v1::CommittedRestoreFrontier,
    ) -> Result<PreparedArchiveRestore, String> {
        if !frontier.valid() {
            return Err("governed checkpoint frontier invalid".into());
        }
        let base = frontier.sequence;
        let candidates = self.list_restore_keys("artifacts").await?;
        let raw_heads = self.list_restore_keys("heads").await?;
        let checkpoint_keys = self.list_restore_keys("checkpoints").await?;
        let mut heads = Vec::with_capacity(raw_heads.len());
        for (offset, key) in raw_heads.into_iter().enumerate() {
            let sequence = base
                .checked_add(offset as u64)
                .ok_or("archive sequence overflow")?;
            if key != archive_head_key(&self.prefix, sequence) {
                return Err("sparse rollback head outside baseline lineage".into());
            }
            let hash = String::from_utf8(self.read(&key).await?.to_vec())
                .map_err(|_| "archive sequence head hash invalid")?;
            if hash.len() != 64
                || !hash
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err("archive sequence head hash invalid".into());
            }
            heads.push(ResolvedArchiveHead {
                key,
                sequence,
                artifact_hash: hash,
            });
        }
        let last = heads
            .last()
            .ok_or("sparse rollback baseline head missing")?
            .sequence;
        if heads[0].artifact_hash != frontier.artifact_hash {
            return Err("sparse rollback baseline differs from governed frontier".into());
        }
        let artifact_prefix = format!("{}/artifacts/", self.prefix);
        let mut available = HashSet::with_capacity(candidates.len());
        let mut at_base = 0;
        for key in &candidates {
            let sequence = archive_key_sequence(key, &artifact_prefix, true)?;
            if sequence < base || sequence > last || !available.insert(key.as_str()) {
                return Err("sparse rollback artifact outside baseline lineage".into());
            }
            at_base += usize::from(sequence == base);
        }
        let keys = heads
            .iter()
            .map(|head| {
                format!(
                    "{artifact_prefix}{:020}-{}.cbor",
                    head.sequence, head.artifact_hash
                )
            })
            .collect::<Vec<_>>();
        if keys.iter().any(|key| !available.contains(key.as_str())) {
            return Err("archive committed artifact missing".into());
        }
        if at_base != 1 {
            return Err("sparse rollback artifact outside baseline lineage".into());
        }
        let baseline_bytes = self.read(&keys[0]).await?;
        let baseline: DirectStateArtifact = serde_cbor::from_slice(&baseline_bytes)
            .map_err(|_| "sparse rollback baseline artifact decode failed")?;
        if serde_cbor::to_vec(&baseline).ok().as_deref() != Some(baseline_bytes.as_ref())
            || baseline.epoch_id != EPOCH_ID
            || baseline.sequence != base
            || baseline.state_hash != frontier.state_hash
            || artifact_hash(&baseline) != frontier.artifact_hash
        {
            return Err("sparse rollback baseline artifact mismatch".into());
        }
        let checkpoint_namespace = format!("{}/checkpoints/", self.prefix);
        let mut baseline_checkpoints = 0;
        for key in &checkpoint_keys {
            let (sequence, state_hash, _) =
                journal_parent_snapshot_key_parts(key, &checkpoint_namespace)
                    .map_err(|_| "sparse rollback checkpoint key invalid")?;
            if sequence < base || sequence > last {
                return Err("sparse rollback checkpoint outside baseline lineage".into());
            }
            if sequence == base {
                if state_hash != frontier.state_hash {
                    return Err("sparse rollback checkpoint outside baseline lineage".into());
                }
                baseline_checkpoints += 1;
            }
        }
        if baseline_checkpoints != 1 {
            return Err("sparse rollback baseline checkpoint missing or ambiguous".into());
        }
        let prepared = PreparedArchiveRestore {
            keys,
            heads,
            checkpoint_keys,
        };
        *self.prepared_restore.lock().await = Some(prepared.clone());
        Ok(prepared)
    }
    /// Rollback-baseline counterpart of `restore_streamed`. The retained v70
    /// enclave receives the same unchanged checkpoint, append, and finish
    /// requests; only the parent's archive listing starts at the baseline.
    /// `exchange` is the enclave transport.
    async fn restore_sparse_rollback_with<F, Fut>(
        &self,
        state: &AppState,
        frontier: &layrs_direct_execution_v1::CommittedRestoreFrontier,
        mut exchange: F,
    ) -> Result<(), String>
    where
        F: FnMut(RuntimeRequest) -> Fut,
        Fut: Future<Output = io::Result<RuntimeResponse>>,
    {
        let PreparedArchiveRestore {
            keys,
            heads,
            checkpoint_keys,
        } = self
            .prepared_restore
            .lock()
            .await
            .take()
            .ok_or("archive restore was not validated before governed bootstrap")?;
        let key = checkpoint_keys
            .last()
            .ok_or("sparse rollback baseline checkpoint missing or ambiguous")?;
        let checkpoint: layrs_direct_execution_v1::DirectCheckpoint =
            serde_cbor::from_slice(&self.read(key).await?)
                .map_err(|_| "checkpoint decode failed; genesis fallback forbidden")?;
        if self.checkpoint_key(&checkpoint)? != *key {
            return Err("checkpoint content address mismatch".into());
        }
        let start =
            validate_sparse_checkpoint_archive(&checkpoint, frontier, &keys, &heads, &self.prefix)?;
        let mut records = checkpoint.receipt_records.clone();
        let mut artifact_hashes = checkpoint.artifact_hashes.clone();
        let checkpoint_sequence = checkpoint.artifact.sequence;
        let checkpoint_state_hash = checkpoint.artifact.state_hash.clone();
        let begin = exchange(RuntimeRequest::BeginCheckpointRestore { checkpoint })
            .await
            .map_err(|_| "checkpoint restore transport failed")?;
        let RuntimeResponse::RestoreProgress {
            recovered_sequence,
            recovered_state_hash: mut root,
        } = begin
        else {
            return Err("restore begin rejected; genesis fallback forbidden".into());
        };
        if recovered_sequence != checkpoint_sequence || root != checkpoint_state_hash {
            return Err("restore checkpoint sequence mismatch".into());
        }
        for index in start..keys.len() {
            let head = &heads[index];
            let (bytes, head_bytes) =
                tokio::try_join!(self.read(&keys[index]), self.read(&head.key))?;
            if head_bytes != head.artifact_hash.as_bytes() {
                return Err("archive encrypted artifact/head byte mismatch".into());
            }
            let artifact: DirectStateArtifact =
                serde_cbor::from_slice(&bytes).map_err(|_| "artifact decode failed")?;
            if artifact.sequence != head.sequence
                || artifact.prior_state_hash != root
                || keys[index] != self.artifact_key(&artifact)
                || head.artifact_hash != artifact_hash(&artifact)
            {
                return Err("archive encrypted successor/head mismatch".into());
            }
            root = artifact.state_hash.clone();
            let sequence = artifact.sequence;
            records.push(receipt_only_record(&artifact));
            artifact_hashes.push(head.artifact_hash.clone());
            let response = exchange(RuntimeRequest::AppendCommittedRestore { artifact })
                .await
                .map_err(|_| "restore successor transport failed")?;
            if !matches!(response, RuntimeResponse::RestoreProgress { recovered_sequence, ref recovered_state_hash } if recovered_sequence == sequence && *recovered_state_hash == root)
            {
                return Err("restore encrypted successor rejected".into());
            }
        }
        let expected_sequence = heads[heads.len() - 1].sequence;
        let result = exchange(RuntimeRequest::FinishCommittedRestore {
            expected_sequence,
            expected_state_hash: root.clone(),
        })
        .await
        .map_err(|_| "restore finish transport failed")?;
        if !matches!(result, RuntimeResponse::RecoveryComplete { recovered_sequence, ref recovered_state_hash } if recovered_sequence == expected_sequence && *recovered_state_hash == root)
        {
            return Err("restore final encrypted head rejected".into());
        }
        *self.verified_receipt_records.lock().await = Some(records);
        *self.verified_artifact_hashes.lock().await = artifact_hashes;
        *state.committed_state_root.lock().await = Some(root);
        self.schedule_restored_checkpoint(state).await;
        eprintln!(
            "VERIFIED_SPARSE_ROLLBACK_RESTORE_COMPLETE baseline={} head={expected_sequence}",
            frontier.sequence
        );
        Ok(())
    }
    /// Create-only, content-addressed persistence of an enclave-sealed v71
    /// checkpoint; `write_once` performs the exact readback.
    #[cfg_attr(not(test), allow(dead_code))]
    async fn persist_journal_checkpoint(&self, checkpoint: &DirectV71Checkpoint) -> Result<String, String> {
        if self.journal_role != JournalRole::Writer {
            return Err("JOURNAL_SHADOW_WRITE_UNSUPPORTED".into());
        }
        if checkpoint.protocol != DIRECT_V71_CHECKPOINT_PROTOCOL || checkpoint.epoch_id != EPOCH_ID {
            return Err("journal checkpoint header invalid".into());
        }
        let bytes = serde_cbor::to_vec(checkpoint).map_err(|_| "journal checkpoint encoding failed")?;
        if bytes.len() > MAX_FRAME_BYTES {
            return Err("journal checkpoint oversized".into());
        }
        let key = journal_checkpoint_key(&self.prefix, checkpoint.sequence, &bytes);
        self.write_once(&key, bytes).await?;
        Ok(key)
    }
    async fn persist_journal_parent_snapshots(
        &self,
        checkpoint: &DirectV71Checkpoint,
        index: &DirectRequestIndexSnapshot,
        receipts: &DirectReceiptSnapshot,
    ) -> Result<(String, String), String> {
        if self.journal_role != JournalRole::Writer {
            return Err("JOURNAL_SHADOW_WRITE_UNSUPPORTED".into());
        }
        index
            .verify(checkpoint.sequence, &checkpoint.request_index_root)
            .map_err(|_| "journal request index snapshot invalid")?;
        receipts
            .verify(index)
            .map_err(|_| "journal receipt snapshot invalid")?;
        let index_bytes = serde_cbor::to_vec(index)
            .map_err(|_| "journal request index snapshot encoding failed")?;
        let receipt_bytes = serde_cbor::to_vec(receipts)
            .map_err(|_| "journal receipt snapshot encoding failed")?;
        if index_bytes.len() > MAX_FRAME_BYTES || receipt_bytes.len() > MAX_FRAME_BYTES {
            return Err("journal parent snapshot oversized".into());
        }
        let index_key = journal_parent_snapshot_key(
            &self.prefix,
            "request-index",
            checkpoint.sequence,
            &checkpoint.request_index_root,
            &index_bytes,
        );
        let receipt_key = journal_parent_snapshot_key(
            &self.prefix,
            "receipts",
            checkpoint.sequence,
            &checkpoint.request_index_root,
            &receipt_bytes,
        );
        let index_readback = self.write_once_large(&index_key, index_bytes.clone()).await?;
        if index_readback != index_bytes {
            return Err("journal request index snapshot readback mismatch".into());
        }
        let receipt_readback = self
            .write_once_large(&receipt_key, receipt_bytes.clone())
            .await?;
        if receipt_readback != receipt_bytes {
            return Err("journal receipt snapshot readback mismatch".into());
        }
        Ok((index_key, receipt_key))
    }
    /// Publish the authenticated checkpoint only after both disposable parent
    /// snapshots are durable. The checkpoint object is the sole restore
    /// discovery marker; orphan snapshots from an interrupted attempt are safe.
    async fn publish_journal_checkpoint(
        &self,
        checkpoint: &DirectV71Checkpoint,
        index: &DirectRequestIndexSnapshot,
        receipts: &DirectReceiptSnapshot,
    ) -> Result<String, String> {
        self.persist_journal_parent_snapshots(checkpoint, index, receipts)
            .await?;
        self.persist_journal_checkpoint(checkpoint).await
    }
    /// Paginated listing of `namespace` (a full key prefix ending in `/`),
    /// optionally strictly after `start_after`, of at most `max` keys. Each
    /// page is time-bounded. A timeout, error, key-count mismatch, empty
    /// truncated page, missing or repeated token, foreign or out-of-range key,
    /// duplicate, or more than `max` keys is `Err`. Sorted on success.
    #[cfg_attr(not(test), allow(dead_code))]
    async fn list_journal_keys(
        &self,
        namespace: &str,
        start_after: Option<&str>,
        max: usize,
        page_timeout: Duration,
    ) -> Result<Vec<String>, String> {
        let mut token: Option<String> = None;
        let mut seen_tokens = HashSet::new();
        let mut keys = Vec::new();
        loop {
            let page = bounded_archive_operation(
                page_timeout,
                self.client
                    .list_objects_v2()
                    .bucket(&self.bucket)
                    .prefix(namespace)
                    .set_start_after(start_after.map(str::to_string))
                    .set_continuation_token(token.clone())
                    .send(),
            )
            .await?
            .map_err(|_| "journal listing failed")?;
            let contents = page.contents();
            if page
                .key_count
                .is_some_and(|count| usize::try_from(count).ok() != Some(contents.len()))
            {
                return Err("journal listing ambiguous".into());
            }
            for object in contents {
                let key = object.key().ok_or("journal listing key missing")?;
                if key.len() <= namespace.len() || !key.starts_with(namespace) {
                    return Err("journal listing key foreign".into());
                }
                if start_after.is_some_and(|after| key <= after) {
                    return Err("journal listing key out of range".into());
                }
                keys.push(key.to_string());
            }
            if keys.len() > max {
                return Err("journal listing exceeds bound".into());
            }
            if !page.is_truncated.unwrap_or(false) {
                break;
            }
            if contents.is_empty() {
                return Err("journal listing ambiguous".into());
            }
            let next = page
                .next_continuation_token()
                .filter(|token| !token.is_empty())
                .ok_or("journal pagination token missing")?
                .to_string();
            if !seen_tokens.insert(next.clone()) {
                return Err("journal pagination token repeated".into());
            }
            token = Some(next);
        }
        keys.sort();
        if keys.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err("journal listing duplicate key".into());
        }
        Ok(keys)
    }
    /// All v71 checkpoint candidates, ascending, under the same finite bound
    /// as the v70 restore listing. One malformed key fails the whole listing.
    #[cfg_attr(not(test), allow(dead_code))]
    async fn list_journal_checkpoint_candidates(
        &self,
    ) -> Result<Vec<JournalCheckpointCandidate>, String> {
        let namespace = format!("{}/journal-v71/checkpoints/", self.prefix);
        let keys = self
            .list_journal_keys(&namespace, None, MAX_V70_LINEAGE_RECORDS, ARCHIVE_OPERATION_TIMEOUT)
            .await?;
        validate_journal_checkpoint_keys(&keys, &self.prefix)
    }
    /// Loads only the newest checkpoint. Its bytes must match the key's
    /// content address and decode canonically to a checkpoint for the keyed
    /// sequence. Any failure is final: an older checkpoint is never used.
    #[cfg_attr(not(test), allow(dead_code))]
    async fn load_newest_journal_checkpoint(
        &self,
    ) -> Result<Option<(JournalCheckpointCandidate, DirectV71Checkpoint)>, String> {
        let Some(newest) = self.list_journal_checkpoint_candidates().await?.pop() else {
            return Ok(None);
        };
        let bytes = self.read(&newest.key).await?;
        if sha256(&bytes) != newest.content_hash {
            return Err("journal checkpoint content address mismatch; older fallback forbidden".into());
        }
        let checkpoint: DirectV71Checkpoint = serde_cbor::from_slice(&bytes)
            .map_err(|_| "journal checkpoint decode failed; older fallback forbidden")?;
        if serde_cbor::to_vec(&checkpoint).ok().as_deref() != Some(bytes.as_ref())
            || checkpoint.protocol != DIRECT_V71_CHECKPOINT_PROTOCOL
            || checkpoint.epoch_id != EPOCH_ID
            || checkpoint.sequence != newest.sequence
        {
            return Err("journal checkpoint invalid; older fallback forbidden".into());
        }
        Ok(Some((newest, checkpoint)))
    }
    /// Canonical record keys for exactly `after+1..=after+n`, `n` at most
    /// `MAX_V71_RESTORE_TAIL_RECORDS`. Legacy `{seq}-{hash}` names above
    /// `after` sort after the start key, so they are always seen and rejected.
    #[cfg_attr(not(test), allow(dead_code))]
    async fn list_journal_tail(&self, after: u64) -> Result<Vec<(u64, String)>, String> {
        self.list_journal_tail_with_timeout(after, ARCHIVE_OPERATION_TIMEOUT).await
    }
    #[cfg_attr(not(test), allow(dead_code))]
    async fn list_journal_tail_with_timeout(
        &self,
        after: u64,
        page_timeout: Duration,
    ) -> Result<Vec<(u64, String)>, String> {
        let namespace = format!("{}/heads/", self.prefix);
        let start_after = journal_record_key(&self.prefix, after);
        let keys = self
            .list_journal_keys(
                &namespace,
                Some(&start_after),
                MAX_V71_RESTORE_TAIL_RECORDS,
                page_timeout,
            )
            .await?;
        validate_journal_tail_keys(&keys, &self.prefix, after, MAX_V71_RESTORE_TAIL_RECORDS)
    }
    /// Reads the bounded tail after `checkpoint` in sequence order. Each body
    /// must decode canonically to a record at its key's sequence that links to
    /// its predecessor's record hash, transition root, and request-index root,
    /// starting from the checkpoint. A v70 head body above the checkpoint fails decode.
    #[cfg_attr(not(test), allow(dead_code))]
    async fn load_journal_tail(
        &self,
        checkpoint: &DirectV71Checkpoint,
    ) -> Result<Vec<DirectJournalRecord>, String> {
        let keys = self.list_journal_tail(checkpoint.sequence).await?;
        let mut previous_record_hash = checkpoint.record_hash.clone();
        let mut previous_transition_root = checkpoint.transition_root.clone();
        let mut previous_request_index_root = checkpoint.request_index_root.clone();
        let mut records = Vec::with_capacity(keys.len());
        let mut total_bytes = 0usize;
        for (sequence, key) in keys {
            let bytes = self.read(&key).await?;
            if bytes.len() > MAX_JOURNAL_RECORD_BYTES {
                return Err("journal tail record oversized".into());
            }
            total_bytes = advance_journal_tail_bytes(total_bytes, bytes.len())?;
            let record: DirectJournalRecord = serde_cbor::from_slice(&bytes)
                .map_err(|_| "journal tail record decode failed")?;
            if serde_cbor::to_vec(&record).ok().as_deref() != Some(bytes.as_ref()) {
                return Err("journal tail record noncanonical".into());
            }
            if record.protocol != DIRECT_JOURNAL_PROTOCOL || record.epoch_id != EPOCH_ID {
                return Err("journal tail record header invalid".into());
            }
            if record.sequence != sequence {
                return Err("journal tail record sequence mismatch".into());
            }
            if record.previous_record_hash != previous_record_hash
                || record.previous_transition_root != previous_transition_root
                || record.previous_request_index_root != previous_request_index_root
            {
                return Err("journal tail record predecessor mismatch".into());
            }
            previous_record_hash = record
                .record_hash()
                .map_err(|_| "journal tail record hash failed")?;
            previous_transition_root = record.transition_root.clone();
            previous_request_index_root = record.request_index_root.clone();
            records.push(record);
        }
        Ok(records)
    }
    async fn load_journal_parent_snapshot_bytes(
        &self,
        namespace_name: &str,
        checkpoint: &DirectV71Checkpoint,
    ) -> Result<Vec<u8>, String> {
        let namespace = format!("{}/journal-v71/{namespace_name}/", self.prefix);
        let exact_prefix = format!(
            "{namespace}{:020}-{}-",
            checkpoint.sequence, checkpoint.request_index_root
        );
        let keys = self
            .list_journal_keys(
                &exact_prefix,
                None,
                2,
                ARCHIVE_OPERATION_TIMEOUT,
            )
            .await?;
        if keys.len() != 1 {
            return Err("journal parent snapshot missing or ambiguous".into());
        }
        let (sequence, root, content_hash) =
            journal_parent_snapshot_key_parts(&keys[0], &namespace)?;
        if sequence != checkpoint.sequence || root != checkpoint.request_index_root {
            return Err("journal parent snapshot checkpoint mismatch".into());
        }
        let bytes = self.read(&keys[0]).await?;
        if sha256(&bytes) != content_hash {
            return Err("journal parent snapshot content address mismatch".into());
        }
        Ok(bytes.to_vec())
    }
    async fn prepare_journal_restore(&self) -> Result<bool, String> {
        let Some((_, checkpoint)) = self.load_newest_journal_checkpoint().await? else {
            return Ok(false);
        };
        let tail = self.load_journal_tail(&checkpoint).await?;
        let index_bytes = self
            .load_journal_parent_snapshot_bytes("request-index", &checkpoint)
            .await?;
        let index_snapshot: DirectRequestIndexSnapshot = serde_cbor::from_slice(&index_bytes)
            .map_err(|_| "journal request index snapshot decode failed")?;
        if serde_cbor::to_vec(&index_snapshot).ok().as_deref() != Some(index_bytes.as_slice()) {
            return Err("journal request index snapshot noncanonical".into());
        }
        index_snapshot
            .verify(checkpoint.sequence, &checkpoint.request_index_root)
            .map_err(|_| "journal request index snapshot invalid")?;
        let receipt_bytes = self
            .load_journal_parent_snapshot_bytes("receipts", &checkpoint)
            .await?;
        let receipt_snapshot: DirectReceiptSnapshot = serde_cbor::from_slice(&receipt_bytes)
            .map_err(|_| "journal receipt snapshot decode failed")?;
        if serde_cbor::to_vec(&receipt_snapshot).ok().as_deref()
            != Some(receipt_bytes.as_slice())
        {
            return Err("journal receipt snapshot noncanonical".into());
        }
        receipt_snapshot
            .verify(&index_snapshot)
            .map_err(|_| "journal receipt snapshot invalid")?;
        let has_migrated_results = index_snapshot.leaves.iter().any(|leaf| {
            matches!(leaf.locator, TerminalResultLocator::Migration { .. })
        });
        let migration = if has_migrated_results {
            let bundle = self
                .load_v70_migration_bundle()
                .await?
                .ok_or("journal migration bundle missing")?;
            if !migration_matches_restored_index(&bundle, &index_snapshot) {
                return Err("journal migration bundle does not match request index".into());
            }
            Some(bundle)
        } else {
            None
        };
        *self.prepared_journal_restore.lock().await = Some(PreparedJournalRestore {
            checkpoint,
            tail,
            index_snapshot,
            receipt_snapshot,
            migration,
        });
        Ok(true)
    }
    async fn restore_journal_streamed(&self, state: &AppState) -> Result<(), String> {
        let prepared = self
            .prepared_journal_restore
            .lock()
            .await
            .take()
            .ok_or("journal restore was not validated before governed bootstrap")?;
        let PreparedJournalRestore {
            checkpoint,
            tail,
            index_snapshot,
            receipt_snapshot,
            migration,
        } = prepared;
        let mut index = DirectRequestIndexState::from_snapshot(
            index_snapshot.clone(),
            checkpoint.sequence,
            &checkpoint.request_index_root,
        )
        .map_err(|_| "journal request index snapshot invalid")?;
        let mut receipts = receipt_snapshot
            .clone()
            .into_receipts(&index_snapshot)
            .map_err(|_| "journal receipt snapshot invalid")?
            .into_iter()
            .map(|record| {
                (
                    (
                        record.receipt.account_id.clone(),
                        record.receipt.request_id.clone(),
                    ),
                    (record.sequence, record.receipt),
                )
            })
            .collect::<JournalReceiptCache>();
        let begin = exchange(
            state,
            RuntimeRequest::BeginJournalRestore {
                checkpoint: checkpoint.clone(),
            },
        )
        .await
        .map_err(|_| "journal restore begin transport failed")?;
        if !matches!(begin, RuntimeResponse::JournalRestoreProgress {
            sequence,
            ref record_hash,
            ref transition_root,
            ref request_index_root,
            receipt: None,
        } if sequence == checkpoint.sequence
            && record_hash == &checkpoint.record_hash
            && transition_root == &checkpoint.transition_root
            && request_index_root == &checkpoint.request_index_root)
        {
            return Err("journal restore begin rejected".into());
        }
        let mut head = JournalHead {
            writer_epoch: checkpoint.writer_epoch.clone(),
            sequence: checkpoint.sequence,
            record_hash: checkpoint.record_hash.clone(),
            transition_root: checkpoint.transition_root.clone(),
            request_index_root: checkpoint.request_index_root.clone(),
            financial_state_root: checkpoint.financial_state_root.clone(),
        };
        let mut transition_roots = BTreeMap::from([(
            checkpoint.sequence,
            checkpoint.transition_root.clone(),
        )]);
        for record in tail {
            let response = exchange(
                state,
                RuntimeRequest::AppendJournalRestore {
                    record: record.clone(),
                },
            )
            .await
            .map_err(|_| "journal restore successor transport failed")?;
            let receipt = match response {
                RuntimeResponse::JournalRestoreProgress {
                    sequence,
                    record_hash,
                    transition_root,
                    request_index_root,
                    receipt: Some(receipt),
                } if sequence == record.sequence
                    && record_hash
                        == record
                            .record_hash()
                            .map_err(|_| "journal restore record hash failed")?
                    && transition_root == record.transition_root
                    && request_index_root == record.request_index_root
                    && receipt.account_id == record.account_id
                    && receipt.request_id == record.request_id
                    && receipt.request_hash == record.request_hash
                    && sha256(
                        &serde_cbor::to_vec(&receipt)
                            .map_err(|_| "journal restore receipt encoding failed")?,
                    ) == record.receipt_hash => receipt,
                _ => return Err("journal restore successor rejected".into()),
            };
            let leaf = TerminalRequestLeaf {
                account_id: record.account_id.clone(),
                request_id: record.request_id.clone(),
                request_hash: record.request_hash.clone(),
                result_hash: record.result_hash.clone(),
                receipt_hash: record.receipt_hash.clone(),
                locator: TerminalResultLocator::Journal {
                    writer_epoch: record.writer_epoch.clone(),
                    sequence: record.sequence,
                },
            };
            index
                .insert(
                    leaf,
                    &record.previous_request_index_root,
                    &record.request_index_root,
                )
                .map_err(|_| "journal restore request index advance failed")?;
            if receipts
                .insert(
                    (receipt.account_id.clone(), receipt.request_id.clone()),
                    (record.sequence, receipt),
                )
                .is_some()
            {
                return Err("journal restore duplicate receipt".into());
            }
            head = JournalHead {
                writer_epoch: record.writer_epoch.clone(),
                sequence: record.sequence,
                record_hash: record
                    .record_hash()
                    .map_err(|_| "journal restore record hash failed")?,
                transition_root: record.transition_root,
                request_index_root: record.request_index_root,
                financial_state_root: record.financial_state_root,
            };
            if transition_roots
                .insert(head.sequence, head.transition_root.clone())
                .is_some()
            {
                return Err("journal restore duplicate transition root sequence".into());
            }
        }
        let fence = state
            .governed_bootstrap
            .as_ref()
            .map(|config| config.grant.old_writer_fence_evidence_sha256.clone());
        let finish = exchange(
            state,
            RuntimeRequest::FinishJournalRestore {
                expected_sequence: head.sequence,
                expected_record_hash: head.record_hash.clone(),
                expected_transition_root: head.transition_root.clone(),
                expected_request_index_root: head.request_index_root.clone(),
                expected_financial_state_root: head.financial_state_root.clone(),
                writer_fence_evidence_sha256: fence,
            },
        )
        .await
        .map_err(|_| "journal restore finish transport failed")?;
        let writer_epoch = match finish {
            RuntimeResponse::JournalRestoreComplete {
                writer_epoch,
                sequence,
                record_hash,
                transition_root,
                request_index_root,
                financial_state_root,
            } if sequence == head.sequence
                && record_hash == head.record_hash
                && transition_root == head.transition_root
                && request_index_root == head.request_index_root
                && financial_state_root == head.financial_state_root => writer_epoch,
            _ => return Err("journal restore final head rejected".into()),
        };
        head.writer_epoch = writer_epoch;
        self.establish_journal_head(head.clone()).await?;
        *state.journal_request_index.lock().await = Some(index);
        *state.journal_receipts.lock().await = Some(receipts);
        *state.journal_migration.lock().await = migration;
        *state.journal_transition_roots.lock().await = Some(transition_roots);
        state
            .journal_checkpoint_sequence
            .store(checkpoint.sequence, Ordering::Release);
        *state.committed_state_root.lock().await = Some(head.transition_root);
        eprintln!("VERIFIED_JOURNAL_RESTORE_COMPLETE {}", head.sequence);
        Ok(())
    }
    /// Immutable put of a large artifact as one multipart upload whose parts
    /// are sent concurrently.  The completed object is still conditional
    /// (`If-None-Match: *`), KMS-encrypted and Object-Lock protected exactly
    /// like `write_once`, and it is still read back in full before any
    /// acknowledgement.  Any failure that is not an existing-object conflict
    /// falls back to the proven single-put path, so this can only be faster,
    /// never weaker.  Returns the bytes that were read back.
    async fn write_once_large(&self, key: &str, bytes: Vec<u8>) -> Result<Bytes, String> {
        const PART_BYTES: usize = 16 * 1024 * 1024;
        if bytes.len() <= PART_BYTES {
            self.write_once(key, bytes.clone()).await?;
            return Ok(Bytes::from(bytes));
        }
        let until = DateTime::from_secs(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| "clock invalid")?
                .as_secs() as i64
                + self.retention_seconds,
        );
        eprintln!("FINANCIAL_AWAIT_BEGIN stage=archive_multipart_put bytes={}", bytes.len());
        let started = std::time::Instant::now();
        let multipart: Result<(), String> = async {
            let created = bounded_archive_operation(
                ARCHIVE_OPERATION_TIMEOUT,
                self.client
                    .create_multipart_upload()
                    .bucket(&self.bucket)
                    .key(key)
                    .server_side_encryption(ServerSideEncryption::AwsKms)
                    .ssekms_key_id(&self.kms_key_id)
                    .object_lock_mode(ObjectLockMode::Compliance)
                    .object_lock_retain_until_date(until)
                    .send(),
            )
            .await?
            .map_err(|error| format!("archive multipart create failed: {error}"))?;
            let upload_id = created
                .upload_id()
                .ok_or("archive multipart id missing")?
                .to_string();
            let abort = |reason: String| {
                let client = self.client.clone();
                let bucket = self.bucket.clone();
                let key = key.to_string();
                let upload_id = upload_id.clone();
                async move {
                    let _ = client
                        .abort_multipart_upload()
                        .bucket(bucket)
                        .key(key)
                        .upload_id(upload_id)
                        .send()
                        .await;
                    reason
                }
            };
            let mut uploads = Vec::new();
            for (index, chunk) in bytes.chunks(PART_BYTES).enumerate() {
                let client = self.client.clone();
                let bucket = self.bucket.clone();
                let key = key.to_string();
                let upload_id = upload_id.clone();
                let part_number = index as i32 + 1;
                let body = chunk.to_vec();
                uploads.push(tokio::spawn(async move {
                    client
                        .upload_part()
                        .bucket(bucket)
                        .key(key)
                        .upload_id(upload_id)
                        .part_number(part_number)
                        .body(ByteStream::from(body))
                        .send()
                        .await
                        .map_err(|error| format!("archive multipart part {part_number} failed: {error}"))
                        .and_then(|output| {
                            output
                                .e_tag()
                                .map(|tag| (part_number, tag.to_string()))
                                .ok_or_else(|| format!("archive multipart part {part_number} etag missing"))
                        })
                }));
            }
            let mut parts = Vec::with_capacity(uploads.len());
            for upload in uploads {
                match bounded_archive_operation(ARCHIVE_OPERATION_TIMEOUT, upload).await {
                    Ok(Ok(Ok(part))) => parts.push(part),
                    Ok(Ok(Err(error))) => return Err(abort(error).await),
                    Ok(Err(_)) => return Err(abort("archive multipart part task failed".into()).await),
                    Err(error) => return Err(abort(error).await),
                }
            }
            parts.sort_by_key(|(number, _)| *number);
            let completed = CompletedMultipartUpload::builder()
                .set_parts(Some(
                    parts
                        .into_iter()
                        .map(|(number, tag)| CompletedPart::builder().part_number(number).e_tag(tag).build())
                        .collect(),
                ))
                .build();
            let complete = bounded_archive_operation(
                ARCHIVE_OPERATION_TIMEOUT,
                self.client
                    .complete_multipart_upload()
                    .bucket(&self.bucket)
                    .key(key)
                    .upload_id(&upload_id)
                    .multipart_upload(completed)
                    .if_none_match("*")
                    .send(),
            )
            .await;
            match complete {
                Ok(Ok(_)) => Ok(()),
                Ok(Err(error)) => Err(abort(format!("archive multipart complete failed: {error}")).await),
                Err(error) => Err(abort(error).await),
            }
        }
        .await;
        eprintln!(
            "FINANCIAL_AWAIT_END stage=archive_multipart_put elapsed_ms={} ok={}",
            started.elapsed().as_millis(),
            multipart.is_ok()
        );
        if let Err(error) = &multipart {
            // Never trust a failed multipart as durable; the fallback single
            // put is itself conditional and read back, so an object that was
            // in fact completed is detected as an identical existing object.
            eprintln!("ARCHIVE_MULTIPART_FALLBACK reason={}", error.replace('\n', " "));
            self.write_once(key, bytes.clone()).await?;
            return Ok(Bytes::from(bytes));
        }
        eprintln!("FINANCIAL_AWAIT_BEGIN stage=archive_readback");
        let restored = self.read(key).await?;
        eprintln!("FINANCIAL_AWAIT_END stage=archive_readback");
        if restored != bytes {
            return Err("archive readback mismatch".into());
        }
        Ok(restored)
    }
    async fn persist_readback(
        &self,
        artifact: &DirectStateArtifact,
    ) -> Result<DirectStateArtifact, String> {
        let bytes = serde_cbor::to_vec(artifact).map_err(|_| "artifact encoding failed")?;
        // The artifact must be durable before its head exists.  The head is a
        // few bytes, so it follows the verified artifact read-back directly;
        // the artifact bytes are decoded from that same read-back rather than
        // being downloaded a second time.
        let readback = self
            .write_once_large(&self.artifact_key(artifact), bytes)
            .await?;
        self.write_once(
            &self.head_key(artifact),
            artifact_hash(artifact).into_bytes(),
        )
        .await?;
        let restored: DirectStateArtifact =
            serde_cbor::from_slice(&readback).map_err(|_| "artifact decode failed")?;
        if restored != *artifact || artifact_hash(&restored) != artifact_hash(artifact) {
            return Err("artifact integrity mismatch".into());
        }
        if let Some(records)=self.verified_receipt_records.lock().await.as_mut() {
            if !records.iter().any(|record|record.sequence==artifact.sequence) {
                records.push(receipt_only_record(&restored));
                self.verified_artifact_hashes.lock().await.push(artifact_hash(&restored));
            }
        }
        Ok(restored)
    }
    async fn load_committed(&self) -> Result<Vec<DirectStateArtifact>, String> {
        self.verified_receipt_records.lock().await.clone().ok_or("verified archive receipt cache unavailable".into())
    }
    async fn list_restore_keys(&self, namespace: &str) -> Result<Vec<String>, String> {
        let mut token = None;
        let mut seen_tokens = HashSet::new();
        let mut keys = Vec::new();
        loop {
            let page = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(format!("{}/{namespace}/", self.prefix))
                .set_continuation_token(token)
                .send()
                .await
                .map_err(|_| "archive listing failed")?;
            for object in page.contents() {
                keys.push(
                    object
                        .key()
                        .ok_or("archive object key missing")?
                        .to_string(),
                );
            }
            if keys.len() > MAX_V70_LINEAGE_RECORDS {
                return Err("archive exceeds finite restore bound".into());
            }
            if !page.is_truncated.unwrap_or(false) {
                break;
            }
            let next = page
                .next_continuation_token()
                .filter(|s| !s.is_empty())
                .ok_or("archive pagination token missing")?
                .to_string();
            if !seen_tokens.insert(next.clone()) {
                return Err("archive pagination token repeated".into());
            }
            token = Some(next);
        }
        keys.sort();
        if keys.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err("archive duplicate key".into());
        }
        Ok(keys)
    }
    async fn prepare_restore(&self, state: &AppState) -> Result<PreparedArchiveRestore, String> {
        let candidates = self.list_restore_keys("artifacts").await?;
        let raw_heads = self.list_restore_keys("heads").await?;
        let head_prefix = format!("{}/heads/", self.prefix);
        let mut counts: BTreeMap<u64, usize> = BTreeMap::new();
        for key in &raw_heads {
            *counts
                .entry(archive_key_sequence(key, &head_prefix, false)?)
                .or_default() += 1;
        }
        let mut linkage_sequences = HashSet::new();
        for (&sequence, &count) in &counts {
            if count > 1 {
                linkage_sequences.insert(sequence);
                if let Some(successor) = sequence.checked_add(1) {
                    linkage_sequences.insert(successor);
                }
            }
        }
        let mut entries = Vec::with_capacity(raw_heads.len());
        for key in raw_heads {
            let sequence = archive_key_sequence(&key, &head_prefix, false)?;
            let name = key
                .strip_prefix(&head_prefix)
                .and_then(|name| name.strip_suffix(".cbor"))
                .ok_or("archive head namespace invalid")?;
            let hash = if let Some((_, hash)) = name.split_once('-') {
                hash.to_string()
            } else {
                let bytes = self.read(&key).await?;
                let hash = std::str::from_utf8(&bytes)
                    .map_err(|_| "archive sequence head hash invalid")?
                    .to_string();
                if hash.len() != 64
                    || !hash
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err("archive sequence head hash invalid".into());
                }
                hash
            };
            let head = ResolvedArchiveHead {
                key: key.clone(),
                sequence,
                artifact_hash: hash.clone(),
            };
            if linkage_sequences.contains(&sequence) {
                let artifact_key = format!("{}/artifacts/{sequence:020}-{hash}.cbor", self.prefix);
                let artifact: DirectStateArtifact =
                    serde_cbor::from_slice(&self.read(&artifact_key).await?)
                        .map_err(|_| "archive head artifact decode failed")?;
                let (resolved, linkage) = resolved_head_from_artifact(key, artifact, &self.prefix)?;
                entries.push((resolved, linkage));
            } else {
                entries.push((head, None));
            }
        }
        let (heads, orphans) = resolve_archive_heads(entries)?;
        for orphan in orphans {
            eprintln!(
                "ARCHIVE_ORPHAN_HEAD seq={} hash={}",
                orphan.sequence, orphan.artifact_hash
            );
        }
        let keys = committed_archive_keys(&candidates, &heads, &self.prefix)?;
        if let Some(frontier) = state
            .governed_bootstrap
            .as_ref()
            .and_then(|config| config.grant.committed_restore_frontier.as_ref())
        {
            if !frontier.valid() {
                return Err("governed checkpoint frontier invalid".into());
            }
            let index = frontier.sequence as usize - 1;
            if keys.get(index)
                != Some(&format!(
                    "{}/artifacts/{:020}-{}.cbor",
                    self.prefix, frontier.sequence, frontier.artifact_hash
                ))
                || heads.get(index).is_none_or(|head| {
                    head.sequence != frontier.sequence
                        || head.artifact_hash != frontier.artifact_hash
                })
            {
                return Err("immutable archive below governed checkpoint frontier".into());
            }
        }
        let checkpoint_keys = self.list_restore_keys("checkpoints").await?;
        if checkpoint_keys.is_empty() && !keys.is_empty() && !state.isolated_test {
            return Err("authenticated checkpoint required for existing production history; genesis fallback forbidden".into());
        }
        let prepared = PreparedArchiveRestore {
            keys,
            heads,
            checkpoint_keys,
        };
        *self.prepared_restore.lock().await = Some(prepared.clone());
        Ok(prepared)
    }
    async fn restore_streamed(&self, state: &AppState) -> Result<(), String> {
        if !state.isolated_test
            && state
                .governed_bootstrap
                .as_ref()
                .and_then(|config| config.grant.committed_restore_frontier.as_ref())
                .is_none()
        {
            return Err("governed checkpoint frontier required for production cutover".into());
        }
        let prepared = match self.prepared_restore.lock().await.take() {
            Some(prepared) => prepared,
            None if state.isolated_test => self.prepare_restore(state).await?,
            None => {
                return Err("archive restore was not validated before governed bootstrap".into())
            }
        };
        let PreparedArchiveRestore {
            keys,
            heads,
            checkpoint_keys,
        } = prepared;
        let (start, mut records, begin) = if let Some(key) = checkpoint_keys.last() {
            let checkpoint: layrs_direct_execution_v1::DirectCheckpoint =
                serde_cbor::from_slice(&self.read(key).await?)
                    .map_err(|_| "checkpoint decode failed; genesis fallback forbidden")?;
            if self.checkpoint_key(&checkpoint)? != *key {
                return Err("checkpoint content address mismatch".into());
            }
            let start = validate_checkpoint_archive(&checkpoint, &keys, &heads, &self.prefix)?;
            let records = checkpoint.receipt_records.clone();
            let begin = exchange(state, RuntimeRequest::BeginCheckpointRestore { checkpoint })
                .await
                .map_err(|_| "checkpoint restore transport failed")?;
            (start, records, begin)
        } else {
            (
                0,
                Vec::with_capacity(keys.len()),
                exchange(state, RuntimeRequest::BeginCommittedRestore)
                    .await
                    .map_err(|_| "restore begin transport failed")?,
            )
        };
        let RuntimeResponse::RestoreProgress {
            recovered_sequence,
            recovered_state_hash: mut root,
        } = begin
        else {
            return Err("restore begin rejected; genesis fallback forbidden".into());
        };
        if recovered_sequence != start as u64 {
            return Err("restore checkpoint sequence mismatch".into());
        }
        eprintln!("VERIFIED_ARCHIVE_RESTORE_START {start}/{}", keys.len());
        for window in restore_prefetch_ranges(keys.len() - start) {
            let mut downloads = Vec::with_capacity(window.len());
            for offset in window {
                let index = start + offset;
                let store = self.clone();
                let key = keys[index].clone();
                let head = heads[index].clone();
                downloads.push((
                    index,
                    tokio::spawn(async move {
                        let (bytes, head_bytes) =
                            tokio::try_join!(store.read(&key), store.read(&head.key))?;
                        let legacy_head = head
                            .key
                            .strip_prefix(&format!("{}/heads/", store.prefix))
                            .and_then(|name| name.strip_suffix(".cbor"))
                            .is_some_and(|name| name.contains('-'));
                        if (legacy_head && bytes != head_bytes)
                            || (!legacy_head && head_bytes != head.artifact_hash.as_bytes())
                        {
                            return Err("archive encrypted artifact/head byte mismatch".to_string());
                        }
                        serde_cbor::from_slice::<DirectStateArtifact>(&bytes)
                            .map_err(|_| "artifact decode failed".to_string())
                    }),
                ));
            }
            // Await in key order, regardless of download completion order.
            // Each native append must verify before the next append is sent.
            for (index, download) in downloads {
                let artifact = download
                    .await
                    .map_err(|_| "bounded archive download failed")??;
                if artifact.sequence != index as u64 + 1
                    || artifact.prior_state_hash != root
                    || keys[index] != self.artifact_key(&artifact)
                    || heads[index].sequence != artifact.sequence
                    || heads[index].artifact_hash != artifact_hash(&artifact)
                {
                    return Err("archive encrypted successor/head mismatch".into());
                }
                root = artifact.state_hash.clone();
                let sequence = artifact.sequence;
                records.push(receipt_only_record(&artifact));
                let response = exchange(state, RuntimeRequest::AppendCommittedRestore { artifact })
                    .await
                    .map_err(|_| "restore successor transport failed")?;
                if !matches!(response,RuntimeResponse::RestoreProgress {recovered_sequence,recovered_state_hash} if recovered_sequence==sequence && recovered_state_hash==root)
                {
                    return Err("restore encrypted successor rejected".into());
                }
                if sequence % 250 == 0 {
                    eprintln!(
                        "VERIFIED_ARCHIVE_RESTORE_PROGRESS {sequence}/{}",
                        keys.len()
                    );
                }
            }
        }
        let result = exchange(
            state,
            RuntimeRequest::FinishCommittedRestore {
                expected_sequence: keys.len() as u64,
                expected_state_hash: root.clone(),
            },
        )
        .await
        .map_err(|_| "restore finish transport failed")?;
        if !matches!(result,RuntimeResponse::RecoveryComplete {recovered_sequence,recovered_state_hash} if recovered_sequence==keys.len() as u64 && recovered_state_hash==root)
        {
            return Err("restore final encrypted head rejected".into());
        }
        *self.verified_receipt_records.lock().await = Some(records);
        *self.verified_artifact_hashes.lock().await = heads
            .iter()
            .map(|head| head.artifact_hash.clone())
            .collect();
        *state.committed_state_root.lock().await = Some(root);
        // Seed the optimization without delaying restored service. A corrupt
        // existing checkpoint is never silently bypassed above; only creation
        // of a fresh recovery optimization is detached and non-fatal.
        self.schedule_restored_checkpoint(state).await;
        eprintln!("VERIFIED_ARCHIVE_RESTORE_COMPLETE {}", keys.len());
        Ok(())
    }
    async fn persist_intent_readback(
        &self,
        intent: &ExternalEffectIntent,
    ) -> Result<ExternalEffectIntent, String> {
        intent
            .verify()
            .map_err(|_| "external-effect intent invalid")?;
        let bytes =
            serde_cbor::to_vec(intent).map_err(|_| "external-effect intent encoding failed")?;
        let key = self.intent_key(intent);
        self.write_once(&key, bytes.clone()).await?;
        let restored: ExternalEffectIntent = serde_cbor::from_slice(&self.read(&key).await?)
            .map_err(|_| "external-effect intent decode failed")?;
        if restored != *intent {
            return Err("external-effect intent readback mismatch".into());
        }
        restored
            .verify()
            .map_err(|_| "external-effect intent integrity mismatch")?;
        Ok(restored)
    }
    async fn load_intents(&self) -> Result<Vec<ExternalEffectIntent>, String> {
        let listing = self
            .client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(format!("{}/external-effect-intents/", self.prefix))
            .send()
            .await
            .map_err(|_| "external-effect intent listing failed")?;
        if listing.is_truncated.unwrap_or(false) {
            return Err("external-effect intent listing exceeds bounded recovery set".into());
        }
        let mut intents = std::collections::BTreeMap::new();
        for object in listing.contents() {
            let key = object.key().ok_or("external-effect intent key missing")?;
            let intent: ExternalEffectIntent = serde_cbor::from_slice(&self.read(key).await?)
                .map_err(|_| "external-effect intent decode failed")?;
            intent
                .verify()
                .map_err(|_| "external-effect intent integrity mismatch")?;
            if key != self.intent_key(&intent)
                || intents.insert(intent.intent_hash.clone(), intent).is_some()
            {
                return Err("duplicate or conflicting external-effect intent".into());
            }
        }
        Ok(intents.into_values().collect())
    }
    async fn load_key_release(
        &self,
        activation_id: &str,
    ) -> Result<Option<GovernedKeyReleaseArtifact>, String> {
        let key = self.key_release_key(activation_id);
        let listing = self
            .client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(&key)
            .send()
            .await
            .map_err(|_| "key-release artifact listing failed")?;
        let matching: Vec<_> = listing
            .contents()
            .iter()
            .filter(|object| object.key() == Some(key.as_str()))
            .collect();
        if matching.is_empty() {
            return Ok(None);
        }
        if matching.len() != 1 {
            return Err("duplicate key-release artifacts".into());
        }
        serde_cbor::from_slice(&self.read(&key).await?)
            .map(Some)
            .map_err(|_| "key-release artifact decode failed".into())
    }
    async fn persist_key_release(
        &self,
        artifact: &GovernedKeyReleaseArtifact,
    ) -> Result<GovernedKeyReleaseArtifact, String> {
        let key = self.key_release_key(&artifact.activation_id);
        let bytes =
            serde_cbor::to_vec(artifact).map_err(|_| "key-release artifact encoding failed")?;
        self.write_once(&key, bytes).await?;
        let restored: GovernedKeyReleaseArtifact = serde_cbor::from_slice(&self.read(&key).await?)
            .map_err(|_| "key-release artifact decode failed")?;
        if restored != *artifact || restored.artifact_hash() != artifact.artifact_hash() {
            return Err("key-release artifact readback mismatch".into());
        }
        Ok(restored)
    }
}

#[derive(Clone)]
struct Projection {
    client: Arc<Mutex<Client>>,
}
#[derive(Deserialize)]
struct AttestationQuery {
    nonce: String,
}
#[derive(Deserialize)]
struct BalanceQuery {
    bucket: Option<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CustomerCommand {
    identity_commitment: String,
    action: CustomerAction,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MarketRegistrationCommand {
    registration: GovernedMarketRegistration,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MarketResolutionCommand {
    resolution: GovernedMarketResolution,
}
#[derive(Deserialize)]
#[serde(
    tag = "type",
    rename_all = "SCREAMING_SNAKE_CASE",
    rename_all_fields = "camelCase"
)]
enum CustomerAction {
    CreditDeposit {
        transaction_hash: String,
        amount_atomic: String,
    },
    CreditZenDeposit { transaction_hash: String, amount_atomic: String },
    CreditHorizenUsdcDeposit { transaction_hash: String, amount_atomic: String },
    CreditArbitrumUsdcBusDeposit {operation_id:String,amount_atomic:String,proof:BusDepositProof},
    FinalizeArbitrumUsdcBusDeposit {operation_id:String,amount_atomic:String,proof:BusDepositFinalizationProof},
    BeginUsdcBusWithdrawal { destination_chain:String,asset:String,destination: String, amount_atomic: String },
    VerifyUsdcBusWithdrawal {withdrawal_id:String,destination_chain:String,asset:String,destination:String,amount_atomic:String,proof:Value},
    VerifyZenWithdrawal {withdrawal_id:String,destination_chain:String,asset:String,destination:String,amount_atomic:String},
    LinkFinancialWallet {grant:WalletLinkGrant,signature:String},
    ReserveZenWithdrawal { destination_chain: String, destination: String, amount_atomic: String },
    PlaceOrder {
        order_id: String,
        market_id: String,
        outcome: Outcome,
        action: OrderAction,
        price_micros: u64,
        quantity_micros: String,
        time_in_force: TimeInForce,
        expires_at_millis: Option<i64>,
        now_millis: i64,
    },
    CancelOrder {
        order_id: String,
    },
    RedeemCompleteSet {
        market_id: String,
        quantity_micros: String,
    },
    ReserveWithdrawal {
        destination: String,
        amount_atomic: String,
        #[serde(default)]
        relay_route: Option<RelayWithdrawalBinding>,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionClaims {
    /// Identifier generated by the Privy-verifying BFF.  It is command scoped
    /// and persisted for replay detection; it is never a raw Privy ID.
    session_id: String,
    subject_hash: String,
    privy_user_id_hash: String,
    audience: String,
    epoch_id: String,
    epoch_state_sha256: String,
    /// Privy's embedded wallet remains an authentication/identity binding
    /// only. For a direct Base withdrawal, the BFF copies the independently
    /// customer-provided destination into this signed field without requiring
    /// ownership proof. The parent requires it to equal the action destination
    /// so a signed session for destination A cannot authorize destination B.
    wallet_address: String,
    #[serde(default)]
    financial_wallet_address: Option<String>,
    identity_commitment: String,
    expires_at_unix: u64,
    response_key: String,
    signature: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EncryptedResponse {
    algorithm: &'static str,
    nonce: String,
    ciphertext: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let epoch = SealedEpoch::load_with_evidence(
        env::var("LAYRS_OPENING_EPOCH_PATH")?,
        env::var("LAYRS_OPENING_EVIDENCE_PATH")?,
    )?;
    let session_key = env::var("LAYRS_DIRECT_SESSION_HMAC_KEY_HEX")
        .ok()
        .and_then(|value| hex::decode(value).ok())
        .filter(|key| key.len() >= 32)
        .or_else(|| {
            // The direct BFF and parent already require the existing Privy app
            // secret.  A domain-separated derivation avoids minting or
            // repurposing another operational key, and binds assertions to
            // this runtime's fixed opening epoch.  The parent never receives
            // raw Privy JWTs.
            env::var("LAYRSV2_PRIVY_APP_SECRET")
                .ok()
                .filter(|secret| secret.len() >= 32)
                .map(|secret| derive_direct_session_key(secret.as_bytes()))
        })
        // A dormant image can answer health, status, and attestation without a
        // session secret. Customer routes fail closed until an isolated test or
        // later governed activation injects the BFF verification key.
        .unwrap_or_default();
    let isolated_test = env::var("LAYRS_DIRECT_ISOLATED_TEST").as_deref() == Ok("true");
    let execution_mode = env::var("LAYRS_DIRECT_EXECUTION_MODE").ok();
    let dormant = matches!(execution_mode.as_deref(), None | Some("dormant"));
    let financial_enabled = execution_mode.as_deref() == Some("production-enabled");
    let persistence_format = PersistenceFormat::parse(
        env::var("LAYRS_DIRECT_PERSISTENCE_FORMAT").ok().as_deref(),
    )?;
    let projection = match env::var("LAYRS_DIRECT_PROJECTION_DATABASE_URL") {
        Ok(url) => Some(Projection::connect(&url, &epoch, isolated_test).await?),
        // This is restricted to a named isolated-package fixture.  It permits
        // the parent/enclave/artifact restart test to run without inventing a
        // second database fixture; production always requires its projection.
        Err(_)
            if isolated_test
                && env::var("LAYRS_DIRECT_ISOLATED_NO_PROJECTION").as_deref() == Ok("true") =>
        {
            None
        }
        Err(_) if isolated_test => {
            return Err("isolated direct execution requires an isolated projection database".into())
        }
        Err(_) => None,
    };
    let governed_bootstrap = if matches!(
        execution_mode.as_deref(),
        Some("admission-enabled" | "production-enabled")
    ) {
        let grant: WriterGrant = env::var("LAYRS_DIRECT_WRITER_GRANT_JSON")
            .ok()
            .and_then(|value| serde_json::from_str(&value).ok())
            .ok_or("production writer grant is required")?;
        let binding: RuntimeMeasurementBinding =
            env::var("LAYRS_DIRECT_APPROVED_RUNTIME_BINDING_JSON")
                .ok()
                .and_then(|value| serde_json::from_str(&value).ok())
                .ok_or("approved runtime binding is required")?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_secs())
            .unwrap_or(0);
        if !grant.verify(now, &binding) {
            return Err("production writer grant signature is invalid".into());
        }
        let kms_key_id = env::var("LAYRS_DIRECT_KEY_RELEASE_KMS_KEY_ID")
            .map_err(|_| "production key-release KMS reference is required")?;
        if kms_key_id != grant.key_release_kms_key_id {
            return Err("production key-release KMS reference mismatch".into());
        }
        projection
            .as_ref()
            .ok_or("production projection is required")?
            .verify_governed_runtime_mode(&grant, financial_enabled)
            .await
            .map_err(|_| "runtime authorization and writer fence verification failed")?;
        Some(GovernedBootstrapConfig {
            grant,
            binding,
            kms_key_id,
            requested_mode: execution_mode.clone().unwrap_or_default(),
        })
    } else {
        None
    };
    let artifact_store = ArchiveStore::from_environment(isolated_test || dormant).await?;
    if matches!(
        persistence_format,
        PersistenceFormat::V71 | PersistenceFormat::V71Hot
    )
        && !matches!(artifact_store, Some(ArchiveStore::S3(_)))
    {
        return Err("v71 persistence requires the S3 Object Lock archive".into());
    }
    if persistence_format == PersistenceFormat::V70RollbackBaseline
        && (!matches!(artifact_store, Some(ArchiveStore::S3(_)))
            || governed_bootstrap
                .as_ref()
                .and_then(|config| config.grant.committed_restore_frontier.as_ref())
                .is_none())
    {
        return Err(
            "v70 rollback baseline requires the S3 archive and a governed committed frontier"
                .into(),
        );
    }
    let state = AppState {
        enclave_cid: env::var("LAYRS_ENCLAVE_CID")
            .unwrap_or_else(|_| "16".into())
            .parse()?,
        session_key: session_key.clone(),
        isolated_test,
        projection,
        local_used_sessions: Arc::new(Mutex::new(HashSet::new())),
        // Filesystem storage is accepted only for an explicitly isolated test
        // or a dormant package.  The production-enabled path remains S3 with
        // Object Lock and KMS only.
        artifact_store,
        commit_ack_key: env::var("LAYRS_DIRECT_COMMIT_ACK_KEY_HEX")
            .ok()
            .and_then(|value| hex::decode(value).ok())
            .filter(|value| value.len() == 32)
            .unwrap_or_default(),
        // A read-only runtime must not construct a custody adapter at all.
        // This removes both execution capability and any reason to load an
        // operational payout signer before the separately governed canary.
        custody: if financial_enabled {
            PrivyBaseCustodyAdapter::from_environment()
                .map_err(|error| format!("direct custody configuration invalid: {error}"))?
        } else {
            None
        },
        zen_custody: if financial_enabled {
            ZenCustodyAdapter::from_environment(&session_key).map_err(|error| format!("ZEN custody configuration invalid:{error}"))?
        } else { None },
        usdc_custody: if financial_enabled {
            UsdcCustodyAdapter::from_environment().map_err(|_|"USDC custody configuration invalid")?
        } else {None},
        usdc_bus_custody: if financial_enabled {UsdcBusCustodyAdapter::from_environment()?} else {None},
        usdc_link_authority: if financial_enabled {
            WalletLinkAuthority::from_environment().map_err(|_|"USDC linking authority configuration invalid")?
        } else {None},
        financial_gate: Arc::new(FinancialGate::new()),
        last_commit_at: Arc::new(AtomicU64::new(0)),
        health: Arc::new(ParentHealth::default()),
        committed_state_root: Arc::new(Mutex::new(None)),
        unresolved_external_effects: Arc::new(Mutex::new(BTreeMap::new())),
        governed_bootstrap,
        persistence_format,
        hot_v71_enabled: Arc::new(AtomicBool::new(false)),
        journal_request_index: Arc::new(Mutex::new(None)),
        journal_receipts: Arc::new(Mutex::new(None)),
        journal_migration: Arc::new(Mutex::new(None)),
        journal_checkpoint_sequence: Arc::new(AtomicU64::new(0)),
        journal_transition_roots: Arc::new(Mutex::new(None)),
    };
    // A Nitro EIF does not inherit the parent's systemd environment.  The
    // isolated test key material therefore crosses the existing VSOCK channel
    // once, before recovery; production never uses this bootstrap.
    bootstrap_isolated_enclave(&state).await?;
    // A Nitro enclave keeps its private state across parent restarts.  An
    // enclave that already carries a writer grant or a completed recovery
    // belongs to a previous parent process: re-bootstrapping it is a grant
    // replay and re-restoring it is rejected, so every retry on that host
    // would fail.  Exit with a dedicated status; the unit's ExecStopPost
    // restarts the enclave, and the next parent start meets a fresh one.
    if !state.isolated_test {
        if let Ok(RuntimeResponse::Status { status }) = exchange(&state, RuntimeRequest::Status).await {
            if status.writer_grant_commitment.is_some() || status.writer_enabled || status.admission_enabled {
                eprintln!("ENCLAVE_STALE_STATE_RESET_REQUIRED");
                std::process::exit(ENCLAVE_RESET_EXIT_STATUS);
            }
        }
    }
    preflight_then_bootstrap(
        async {
            if let Some(store) = state.artifact_store.as_ref() {
                store
                    .prepare_restore_before_grant(&state)
                    .await
                    .map_err(invalid)?;
            }
            Ok(())
        },
        bootstrap_governed_enclave(&state),
    )
    .await?;
    // The HTTP parent never accepts a financial command until it has supplied
    // the immutable archive's complete, head-verified recovery set and the
    // enclave has independently reconstructed it.  PostgreSQL is excluded.
    recover_enclave(&state).await?;
    // Reconciliation consumes only the fully verified immutable receipt
    // lineage, then proves the resulting disposable projection equal to the
    // recovered private state. PostgreSQL never supplies balance guesses.
    reconcile_projection_from_archive(&state).await?;
    verify_recovered_projection(&state).await?;
    recover_external_effect_intents(&state).await?;
    verify_recovered_projection(&state).await?;
    if let Ok(run_id) = env::var("LAYRS_DIRECT_V71_SHADOW_RUN_ID") {
        if state.effective_persistence_format() != PersistenceFormat::V70 {
            eprintln!("V71_SHADOW_NOT_STARTED reason=AUTHORITATIVE_FORMAT_NOT_V70");
        } else {
            match exchange(
                &state,
                RuntimeRequest::BeginV71Shadow {
                    run_id: run_id.clone(),
                },
            )
            .await
            {
                Ok(RuntimeResponse::V71ShadowStatus {
                    phase,
                    source_sequence,
                    ..
                }) if phase == "PENDING" => {
                    eprintln!(
                        "V71_SHADOW_STARTED run_id={} source_sequence={}",
                        run_id, source_sequence
                    );
                }
                Ok(RuntimeResponse::Error { code }) => {
                    eprintln!("V71_SHADOW_NOT_STARTED reason={code}");
                }
                Ok(_) => eprintln!("V71_SHADOW_NOT_STARTED reason=UNEXPECTED_RESPONSE"),
                Err(_) => eprintln!("V71_SHADOW_NOT_STARTED reason=TRANSPORT_FAILED"),
            }
        }
    }
    if state.persistence_format == PersistenceFormat::V71Hot
        && state.effective_persistence_format() == PersistenceFormat::V70
        && env::var("LAYRS_DIRECT_V71_AUTO_PROMOTE").as_deref() == Ok("true")
    {
        if let Ok(run_id) = env::var("LAYRS_DIRECT_V71_SHADOW_RUN_ID") {
            let promotion_state = state.clone();
            tokio::spawn(async move {
                if let Err(reason) =
                    stage_and_promote_v71_shadow(promotion_state, run_id).await
                {
                    eprintln!("V71_HOT_PROMOTION_ABORTED reason={reason}");
                }
            });
        } else {
            eprintln!("V71_HOT_PROMOTION_NOT_STARTED reason=SHADOW_RUN_ID_MISSING");
        }
    }
    if state.persistence_format == PersistenceFormat::V71
        && state.journal_request_index.lock().await.is_none()
    {
        activate_v71_from_restored_v70(&state).await?;
    }
    if let Some(ArchiveStore::S3(store)) = state.artifact_store.as_ref() {
        if state.effective_persistence_format() == PersistenceFormat::V71 {
            store.catch_up_restored_journal_checkpoint(&state).await;
        }
    }
    // Observe already-admitted Base withdrawals independently of the browser.
    // This observer has no submission capability and shares the financial lock.
    state.health.restored.store(true, Ordering::Release);
    // Startup recovery has already verified the enclave and projection. A
    // bounded initial observation covers the first background probe.
    state.health.observe(now_unix());
    start_health_observer(state.clone());
    start_base_withdrawal_observer(state.clone());
    start_v70_rollback_handoff(state.clone());
    let port = env::var("PORT").unwrap_or_else(|_| "8443".into()).parse()?;
    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/attestation", get(attestation))
        .route("/v1/privacy/receipt-key-attestation", get(quest_receipt_attestation))
        .route("/v1/runtime/status", get(status))
        .route("/v1/operator/markets", post(register_market))
        .route("/v1/operator/markets/resolve", post(resolve_market))
        .route("/v1/operator/markets/:market_id", get(market_status))
        .route(
            "/v1/operator/balance-recoveries",
            post(apply_balance_recovery),
        )
        .route("/v1/direct/admissions", post(admit_identity))
        .route("/v1/direct/commands", post(command))
        .route("/v1/direct/balances/:identity", get(balance))
        .route("/v1/direct/portfolio/:identity", get(portfolio))
        .route("/v1/direct/privacy/receipts", post(quest_receipt))
        .with_state(state);
    // The packaged and dormant runtime is loopback-only.  A governed BFF
    // deployment may opt in to a VPC listener only when production mode is
    // explicitly enabled; its security group is the other enforcement layer.
    let bind_address = runtime_bind_address(
        env::var("LAYRS_DIRECT_BIND_ADDRESS").ok().as_deref(),
        env::var("LAYRS_DIRECT_EXECUTION_MODE").ok().as_deref(),
        env::var("LAYRS_DIRECT_READ_ONLY_VPC_BIND").as_deref() == Ok("true"),
    )?;
    let listener = tokio::net::TcpListener::bind((bind_address, port)).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn derive_direct_session_key(privy_app_secret: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(privy_app_secret)
        .expect("HMAC accepts arbitrary key material");
    mac.update(DIRECT_SESSION_KEY_DERIVATION_DOMAIN);
    mac.update(EPOCH_ID.as_bytes());
    mac.update(&[0]);
    mac.update(layrs_direct_execution_v1::EPOCH_STATE_SHA256.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

fn runtime_bind_address(
    requested: Option<&str>,
    mode: Option<&str>,
    read_only_vpc_bind: bool,
) -> Result<IpAddr, &'static str> {
    let address = requested
        .unwrap_or("127.0.0.1")
        .parse::<IpAddr>()
        .map_err(|_| "invalid direct runtime bind address")?;
    // The governed read-only BFF needs a VPC path to obtain encrypted balance
    // responses.  It is explicitly limited to a dormant enclave: direct
    // execution rejects every mutation before a candidate, custody call, or
    // artifact can be created.  Any writable listener still requires the
    // WriterGrant-gated production-enabled mode.
    let read_only_listener = mode == Some("dormant") && read_only_vpc_bind;
    if !address.is_loopback()
        && !matches!(mode, Some("admission-enabled" | "production-enabled"))
        && !read_only_listener
    {
        return Err("non-loopback direct runtime listener requires production-enabled mode");
    }
    Ok(address)
}

fn direct_writer_route_enabled(isolated_test: bool, mode: Option<&str>) -> bool {
    isolated_test || mode == Some("production-enabled")
}

fn direct_admission_route_enabled(isolated_test: bool, mode: Option<&str>) -> bool {
    isolated_test || matches!(mode, Some("admission-enabled" | "production-enabled"))
}

async fn attestation(
    State(state): State<AppState>,
    Query(query): Query<AttestationQuery>,
) -> impl IntoResponse {
    let nonce = match URL_SAFE_NO_PAD.decode(query.nonce) {
        Ok(value) if (16..=512).contains(&value.len()) => value,
        _ => return (StatusCode::BAD_REQUEST, "INVALID_NONCE").into_response(),
    };
    let request_nonce = URL_SAFE_NO_PAD.encode(&nonce);
    match exchange(&state, RuntimeRequest::Attestation { nonce }).await {
        Ok(RuntimeResponse::Attestation {
            document,
            binding,
            binding_commitment,
        }) => Json(serde_json::json!({
            "attestationDocument": URL_SAFE_NO_PAD.encode(document),
            "requestNonce": request_nonce,
            "binding": binding,
            "bindingCommitmentSha256": hex::encode(binding_commitment),
        }))
        .into_response(),
        Ok(RuntimeResponse::Error { code }) => (StatusCode::BAD_GATEWAY, code).into_response(),
        _ => (StatusCode::BAD_GATEWAY, "UNEXPECTED_RESPONSE").into_response(),
    }
}
async fn status(State(state): State<AppState>) -> impl IntoResponse {
    match exchange(&state, RuntimeRequest::Status).await {
        Ok(RuntimeResponse::Status { status }) => {
            let now = now_unix();
            let (lock_waiters, oldest_lock_wait_seconds) = state.financial_gate.snapshot(now);
            let mut value = match serde_json::to_value(status) {
                Ok(Value::Object(value)) => value,
                _ => return (StatusCode::BAD_GATEWAY, "STATUS_ENCODING_FAILED").into_response(),
            };
            value.insert(
                "writePath".into(),
                json!({
                    "lastCommitAt": match state.last_commit_at.load(Ordering::Acquire) { 0 => None, value => Some(value) },
                    "lockWaiters": lock_waiters,
                    "oldestLockWaitSeconds": oldest_lock_wait_seconds,
                    "stalled": state.financial_gate.stalled(now),
                }),
            );
            Json(Value::Object(value)).into_response()
        }
        Ok(RuntimeResponse::Error { code }) => (StatusCode::BAD_GATEWAY, code).into_response(),
        _ => (StatusCode::BAD_GATEWAY, "UNEXPECTED_RESPONSE").into_response(),
    }
}
async fn healthz(State(state): State<AppState>) -> impl IntoResponse {
    let now = now_unix();
    let expired = state.governed_bootstrap.as_ref().is_some_and(|config| config.grant.expires_at_unix <= now);
    match state.health.check(now, state.last_commit_at.load(Ordering::Acquire), state.financial_gate.stalled(now), expired) {
        Ok(()) => (StatusCode::OK, "ok"),
        Err(code) => (StatusCode::SERVICE_UNAVAILABLE, code),
    }
}
async fn quest_receipt_attestation(State(state):State<AppState>,Query(query):Query<AttestationQuery>)->impl IntoResponse {
    let nonce=match URL_SAFE_NO_PAD.decode(query.nonce) {
        Ok(nonce) if (16..=512).contains(&nonce.len())=>nonce,
        _=>return (StatusCode::BAD_REQUEST,"INVALID_NONCE").into_response(),
    };
    let request_nonce=URL_SAFE_NO_PAD.encode(&nonce);
    match exchange(&state,RuntimeRequest::QuestReceiptAttestation{nonce}).await {
        Ok(RuntimeResponse::QuestReceiptAttestation{document,binding,binding_commitment,public_key})=>Json(json!({
            "protocol":layrs_direct_execution_v1::QUEST_RECEIPT_PROTOCOL,
            "attestationDocument":URL_SAFE_NO_PAD.encode(document),"requestNonce":request_nonce,
            "binding":binding,"bindingCommitmentSha256":hex::encode(binding_commitment),"publicKey":hex::encode(public_key),
        })).into_response(),
        Ok(RuntimeResponse::Error{code})=>(StatusCode::SERVICE_UNAVAILABLE,code).into_response(),
        _=>(StatusCode::BAD_GATEWAY,"ENCLOSURE_UNAVAILABLE").into_response(),
    }
}
#[derive(Debug,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
struct QuestReceiptQuery { receipt_account_id:String, request_id:String, nonce:String }
fn quest_receipt_frame(claims:&SessionClaims,query:QuestReceiptQuery)->Result<RuntimeRequest,()> {
    let owner=&query.receipt_account_id;
    if query.nonce.len()!=64||!query.nonce.bytes().all(|byte|byte.is_ascii_digit()||(b'a'..=b'f').contains(&byte))
        ||owner.len()!=64||!owner.bytes().all(|byte|byte.is_ascii_digit()||(b'a'..=b'f').contains(&byte))
        ||query.request_id.is_empty()||query.request_id.len()>128
        ||!query.request_id.bytes().all(|byte|byte.is_ascii_alphanumeric()||b"-_:".contains(&byte)) {return Err(());}
    Ok(RuntimeRequest::PublicQuestReceipt{participant_account:claims.subject_hash.clone(),receipt_account:query.receipt_account_id,request_id:query.request_id,nonce:hex::decode(query.nonce).map_err(|_|())?})
}
async fn journal_quest_receipt_frame(
    state:&AppState,
    request:RuntimeRequest,
)->Result<(RuntimeRequest,OwnedMutexGuard<()>),(StatusCode,&'static str)> {
    let RuntimeRequest::PublicQuestReceipt {participant_account,receipt_account,request_id,nonce}=request else {
        return Err((StatusCode::BAD_REQUEST,"INVALID_PRIVACY_RECEIPT_REQUEST"));
    };
    let store=match state.artifact_store.as_ref() {
        Some(ArchiveStore::S3(store))=>store,
        _=>return Err((StatusCode::SERVICE_UNAVAILABLE,"JOURNAL_RECEIPT_UNAVAILABLE")),
    };
    // Locate and fetch immutable history before taking the financial gate. A
    // later commit can extend the tree but cannot replace this terminal leaf.
    let leaf={
        let index=state.journal_request_index.lock().await;
        let index=index.as_ref().ok_or((StatusCode::SERVICE_UNAVAILABLE,"JOURNAL_RECEIPT_UNAVAILABLE"))?;
        index.proof(&receipt_account,&request_id)
            .map_err(|_|(StatusCode::SERVICE_UNAVAILABLE,"JOURNAL_RECEIPT_UNAVAILABLE"))?
            .leaf.ok_or((StatusCode::FORBIDDEN,"PRIVACY_RECEIPT_UNAVAILABLE"))?
    };
    let archived=archived_terminal_for_leaf(state,store,&leaf).await
        .map_err(|_|(StatusCode::SERVICE_UNAVAILABLE,"JOURNAL_RECEIPT_UNAVAILABLE"))?;
    // Rebuild the proof at the exact enclave head and hold only for the
    // bounded in-memory proof plus enclave read. S3 latency never blocks a
    // trade, while a concurrent commit cannot make the proof stale.
    let guard=state.financial_gate.lock("quest_receipt_journal").await;
    let request_proof={
        let index=state.journal_request_index.lock().await;
        let index=index.as_ref().ok_or((StatusCode::SERVICE_UNAVAILABLE,"JOURNAL_RECEIPT_UNAVAILABLE"))?;
        let proof=index.proof(&receipt_account,&request_id)
            .map_err(|_|(StatusCode::SERVICE_UNAVAILABLE,"JOURNAL_RECEIPT_UNAVAILABLE"))?;
        if proof.leaf.as_ref()!=Some(&leaf) {
            return Err((StatusCode::SERVICE_UNAVAILABLE,"JOURNAL_RECEIPT_UNAVAILABLE"));
        }
        proof
    };
    Ok((RuntimeRequest::PublicQuestReceiptJournal {
        participant_account,receipt_account,request_id,nonce,request_proof,archived,
    },guard))
}
async fn quest_receipt(State(state):State<AppState>,headers:HeaderMap,Json(query):Json<QuestReceiptQuery>)->impl IntoResponse {
    let claims=match authenticated(&headers,&state) {Ok(claims)=>claims,Err(response)=>return response};
    // Participant identity is always taken from the verified short-lived BFF
    // session. An affected maker may witness a taker's committed fill only if
    // the enclave's signed projection proves that participant was affected.
    let request=match quest_receipt_frame(&claims,query) {Ok(request)=>request,Err(_)=>return (StatusCode::BAD_REQUEST,"INVALID_PRIVACY_RECEIPT_REQUEST").into_response()};
    let (request,_journal_guard)=if state.effective_persistence_format()==PersistenceFormat::V71 {
        match journal_quest_receipt_frame(&state,request).await {
            Ok((request,guard))=>(request,Some(guard)),
            Err((status,code))=>return (status,code).into_response(),
        }
    } else {(request,None)};
    match exchange(&state,request).await {
        Ok(RuntimeResponse::PublicQuestReceipt{witness})=>encrypted_quest_witness(&claims,&witness),
        Ok(RuntimeResponse::Error{code})=>(StatusCode::FORBIDDEN,code).into_response(),
        _=>(StatusCode::BAD_GATEWAY,"ENCLOSURE_UNAVAILABLE").into_response(),
    }
}
async fn command(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CustomerCommand>,
) -> impl IntoResponse {
    let claims = match authenticated(&headers, &state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    // Do not let a read-only deployment reach candidate creation, custody, or
    // archive persistence merely because a BFF can reach its VPC listener.
    // Dormant state remains independently enforced inside the enclave.
    if !direct_writer_route_enabled(
        state.isolated_test,
        env::var("LAYRS_DIRECT_EXECUTION_MODE").ok().as_deref(),
    ) {
        return (StatusCode::SERVICE_UNAVAILABLE, "WRITER_DISABLED").into_response();
    }
    let request_id = match headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty() && value.len() <= 200)
    {
        Some(value) => value.to_string(),
        None => return (StatusCode::BAD_REQUEST, "IDEMPOTENCY_KEY_REQUIRED").into_response(),
    };
    if body.identity_commitment != claims.identity_commitment {
        return (StatusCode::FORBIDDEN, "DIRECT_IDENTITY_BINDING_DENIED").into_response();
    }
    let _financial_guard = state.financial_gate.lock("customer_command").await;
    let external_effect_pending = !state.unresolved_external_effects.lock().await.is_empty();
    eprintln!("FINANCIAL_AWAIT_BEGIN stage=command_prepare");
    let action = match body.action {
        CustomerAction::VerifyUsdcBusWithdrawal {withdrawal_id,destination_chain,asset,destination,amount_atomic,proof} => {
            let Some(custody)=&state.usdc_bus_custody else {return (StatusCode::SERVICE_UNAVAILABLE,"USDC_BUS_CUSTODY_NOT_ENABLED").into_response();};
            if request_id!=format!("usdc-bus-settle:{withdrawal_id}")
                ||usdc_bus_reservation_action(&withdrawal_id,claims.financial_wallet_address.as_deref(),&claims.wallet_address,&destination_chain,&asset,&destination,&amount_atomic).is_err() {
                return (StatusCode::FORBIDDEN,"USDC_BUS_SETTLEMENT_BINDING_DENIED").into_response();
            }
            match custody.settlement(&destination_chain,&destination,&amount_atomic,&proof).await {
                Ok(Some(reference))=>DirectAction::SettleUsdcBusWithdrawal {withdrawal_id,destination_chain,asset,destination,amount_atomic,custody_reference:reference},
                Ok(None)=>return (StatusCode::SERVICE_UNAVAILABLE,"USDC_BUS_DESTINATION_FINALITY_PENDING").into_response(),
                Err(error)=>return match error.as_str() {
                    "USDC Bus custody proof conflict"=>(StatusCode::CONFLICT,"USDC_BUS_CUSTODY_PROOF_CONFLICT").into_response(),
                    "USDC Bus token cached"=>(StatusCode::SERVICE_UNAVAILABLE,"USDC_BUS_TOKEN_RECOVERY_PENDING").into_response(),
                    "USDC Bus RPC reorg"=>(StatusCode::SERVICE_UNAVAILABLE,"USDC_BUS_FINALITY_RECHECK_REQUIRED").into_response(),
                    _=>(StatusCode::SERVICE_UNAVAILABLE,"USDC_BUS_CUSTODY_PROOF_UNAVAILABLE").into_response(),
                },
            }
        }
        CustomerAction::VerifyZenWithdrawal {withdrawal_id,destination_chain,asset,destination,amount_atomic} => {
            if request_id!=format!("usdc-bus-settle:{withdrawal_id}") || asset!="ZEN"
                || usdc_bus_reservation_action(&withdrawal_id,claims.financial_wallet_address.as_deref(),&claims.wallet_address,
                    &destination_chain,&asset,&destination,&amount_atomic).is_err() {
                return (StatusCode::FORBIDDEN,"ZEN_WITHDRAWAL_SETTLEMENT_BINDING_DENIED").into_response();
            }
            match prepare_standard_zen_withdrawal(&state,&claims,&body.identity_commitment,&withdrawal_id,
                destination_chain,asset,destination,amount_atomic).await {
                Ok(action)=>action,
                Err((status,code))=>return (status,code).into_response(),
            }
        }
        CustomerAction::LinkFinancialWallet {grant,signature} => {
            let Some(authority)=&state.usdc_link_authority else {return (StatusCode::SERVICE_UNAVAILABLE,"USDC_LINK_AUTHORITY_NOT_ENABLED").into_response();};
            if external_effect_pending {return (StatusCode::SERVICE_UNAVAILABLE,"EXTERNAL_EFFECT_FINALITY_PENDING").into_response();}
            match authority.verify(&grant,&signature,&claims,&request_id,now_unix()) {
                Ok(action)=>action,
                Err(_)=>return (StatusCode::FORBIDDEN,"USDC_WALLET_LINK_DENIED").into_response(),
            }
        }
        CustomerAction::BeginUsdcBusWithdrawal { destination_chain,asset,destination, amount_atomic } => {
            if external_effect_pending {
                return (StatusCode::SERVICE_UNAVAILABLE, "EXTERNAL_EFFECT_FINALITY_PENDING").into_response();
            }
            if asset=="ZEN"&&state.zen_custody.is_none() {return (StatusCode::SERVICE_UNAVAILABLE,"ZEN_CUSTODY_ADAPTER_NOT_ENABLED").into_response();}
            if asset!="ZEN"&&state.usdc_custody.is_none() {return (StatusCode::SERVICE_UNAVAILABLE,"USDC_CUSTODY_ADAPTER_NOT_ENABLED").into_response();}
            match usdc_bus_reservation_action(&request_id,claims.financial_wallet_address.as_deref(),&claims.wallet_address,&destination_chain,&asset,&destination,&amount_atomic) {
                Ok(action) => action,
                Err((status, code)) => return (status, code).into_response(),
            }
        }
        CustomerAction::CreditArbitrumUsdcBusDeposit {operation_id,amount_atomic,proof} if !external_effect_pending => {
            let Some(wallet)=claims.financial_wallet_address.as_deref() else {return (StatusCode::FORBIDDEN,"DIRECT_FINANCIAL_WALLET_REQUIRED").into_response();};
            if request_id!=format!("usdc-bus-deposit-credit:{operation_id}") {
                return (StatusCode::BAD_REQUEST,"DEPOSIT_IDEMPOTENCY_KEY_MISMATCH").into_response();
            }
            let Some(custody)=&state.usdc_bus_custody else {return (StatusCode::SERVICE_UNAVAILABLE,"USDC_BUS_CUSTODY_NOT_ENABLED").into_response();};
            match custody.conditional_deposit(wallet,&amount_atomic,&proof).await {
                Ok(Some(custody_reference))=>DirectAction::CreditArbitrumUsdcBusDeposit {operation_id,amount_atomic,custody_reference},
                Ok(None)=>return (StatusCode::SERVICE_UNAVAILABLE,"BUS_BOARDING_FINALITY_PENDING").into_response(),
                Err(_)=>return (StatusCode::CONFLICT,"BUS_BOARDING_PROOF_CONFLICT").into_response(),
            }
        }
        CustomerAction::FinalizeArbitrumUsdcBusDeposit {operation_id,amount_atomic,proof} if !external_effect_pending => {
            let Some(wallet)=claims.financial_wallet_address.as_deref() else {return (StatusCode::FORBIDDEN,"DIRECT_FINANCIAL_WALLET_REQUIRED").into_response();};
            if request_id!=format!("usdc-bus-deposit-finalize:{operation_id}") {
                return (StatusCode::BAD_REQUEST,"DEPOSIT_IDEMPOTENCY_KEY_MISMATCH").into_response();
            }
            let Some(custody)=&state.usdc_bus_custody else {return (StatusCode::SERVICE_UNAVAILABLE,"USDC_BUS_CUSTODY_NOT_ENABLED").into_response();};
            match custody.deposit_finalization(wallet,&amount_atomic,&proof).await {
                Ok(Some((boarding_reference,custody_reference)))=>DirectAction::FinalizeArbitrumUsdcBusDeposit {operation_id,amount_atomic,boarding_reference,custody_reference},
                Ok(None)=>return (StatusCode::SERVICE_UNAVAILABLE,"BUS_SETTLEMENT_FINALITY_PENDING").into_response(),
                Err(_)=>return (StatusCode::CONFLICT,"BUS_SETTLEMENT_PROOF_CONFLICT").into_response(),
            }
        }
        CustomerAction::CreditArbitrumUsdcBusDeposit {..}|CustomerAction::FinalizeArbitrumUsdcBusDeposit {..}=>return (StatusCode::SERVICE_UNAVAILABLE,"EXTERNAL_EFFECT_FINALITY_PENDING").into_response(),
        CustomerAction::CreditHorizenUsdcDeposit {transaction_hash,amount_atomic} if !external_effect_pending => {
            let Some(source)=claims.financial_wallet_address.as_deref() else {return (StatusCode::FORBIDDEN,"DIRECT_FINANCIAL_WALLET_REQUIRED").into_response();};
            let hash=transaction_hash.to_ascii_lowercase();let reference=format!("horizen-usdc-deposit:{hash}");
            if request_id!=reference {return (StatusCode::BAD_REQUEST,"DEPOSIT_IDEMPOTENCY_KEY_MISMATCH").into_response();}
            let Some(custody)=&state.usdc_custody else {return (StatusCode::SERVICE_UNAVAILABLE,"USDC_CUSTODY_ADAPTER_NOT_ENABLED").into_response();};
            match custody.deposit_finality(source,&hash,&amount_atomic).await {
                Ok(DepositFinality::Finalized)=>DirectAction::CreditHorizenUsdcDeposit {amount_atomic,custody_reference:reference},
                Ok(DepositFinality::Pending)=>return (StatusCode::SERVICE_UNAVAILABLE,"DEPOSIT_FINALITY_PENDING").into_response(),
                Ok(DepositFinality::Reverted|DepositFinality::Conflict)=>return (StatusCode::CONFLICT,"DEPOSIT_TRANSACTION_BINDING_CONFLICT").into_response(),
                Err(_)=>return (StatusCode::SERVICE_UNAVAILABLE,"DEPOSIT_FINALITY_UNAVAILABLE").into_response(),
            }
        }
        CustomerAction::CreditHorizenUsdcDeposit {..}=>return (StatusCode::SERVICE_UNAVAILABLE,"EXTERNAL_EFFECT_FINALITY_PENDING").into_response(),
        CustomerAction::CreditZenDeposit { transaction_hash, amount_atomic } if !external_effect_pending => {
            let Some(source) = claims.financial_wallet_address.as_deref() else {return (StatusCode::FORBIDDEN,"DIRECT_FINANCIAL_WALLET_REQUIRED").into_response();};
            let hash = transaction_hash.to_ascii_lowercase();
            let reference = format!("horizen-zen-deposit:{hash}");
            if request_id != reference {return (StatusCode::BAD_REQUEST,"DEPOSIT_IDEMPOTENCY_KEY_MISMATCH").into_response();}
            let Some(custody) = &state.zen_custody else {return (StatusCode::SERVICE_UNAVAILABLE,"ZEN_CUSTODY_ADAPTER_NOT_ENABLED").into_response();};
            match custody.deposit_finality(source,&hash,&amount_atomic).await {
                Ok(DepositFinality::Finalized) => DirectAction::CreditZenDeposit {amount_atomic,custody_reference:reference},
                Ok(DepositFinality::Pending) => return (StatusCode::SERVICE_UNAVAILABLE,"DEPOSIT_FINALITY_PENDING").into_response(),
                Ok(DepositFinality::Reverted | DepositFinality::Conflict) => return (StatusCode::CONFLICT,"DEPOSIT_TRANSACTION_BINDING_CONFLICT").into_response(),
                Err(_) => return (StatusCode::SERVICE_UNAVAILABLE,"DEPOSIT_FINALITY_UNAVAILABLE").into_response(),
            }
        }
        CustomerAction::CreditZenDeposit {..} => return (StatusCode::SERVICE_UNAVAILABLE,"EXTERNAL_EFFECT_FINALITY_PENDING").into_response(),
        CustomerAction::ReserveZenWithdrawal {destination_chain,destination,amount_atomic} => {
            if !matches!(destination_chain.as_str(),"base"|"horizen") {return (StatusCode::BAD_REQUEST,"ZEN_ROUTE_UNSUPPORTED").into_response();}
            if !claims.financial_wallet_address.as_deref().is_some_and(|signed| signed_base_withdrawal_destination_matches(&destination,signed)) {return (StatusCode::FORBIDDEN,"SIGNED_WITHDRAWAL_DESTINATION_MISMATCH").into_response();}
            match prepare_zen_withdrawal(&state,&claims,&body.identity_commitment,&request_id,destination_chain,destination,amount_atomic).await {
                Ok(action)=>action,Err((status,code))=>return (status,code).into_response(),
            }
        }
        CustomerAction::CreditDeposit {
            transaction_hash,
            amount_atomic,
        } if !external_effect_pending => {
            let Some(financial_wallet_address) = claims.financial_wallet_address.as_deref() else {
                return (StatusCode::FORBIDDEN, "DIRECT_FINANCIAL_WALLET_REQUIRED").into_response();
            };
            let canonical_hash = transaction_hash.to_ascii_lowercase();
            let required_request_id = format!("base-deposit:{canonical_hash}");
            if request_id != required_request_id {
                return (StatusCode::BAD_REQUEST, "DEPOSIT_IDEMPOTENCY_KEY_MISMATCH")
                    .into_response();
            }
            let Some(custody) = &state.custody else {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CUSTODY_ADAPTER_NOT_ENABLED",
                )
                    .into_response();
            };
            match custody
                .deposit_finality(financial_wallet_address, &canonical_hash, &amount_atomic)
                .await
            {
                Ok(DepositFinality::Finalized) => DirectAction::CreditDeposit {
                    amount_atomic,
                    custody_reference: required_request_id,
                },
                Ok(DepositFinality::Pending) => {
                    return (StatusCode::SERVICE_UNAVAILABLE, "DEPOSIT_FINALITY_PENDING")
                        .into_response()
                }
                Ok(DepositFinality::Reverted) => {
                    return (
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "DEPOSIT_TRANSACTION_REVERTED",
                    )
                        .into_response()
                }
                Ok(DepositFinality::Conflict) => {
                    return (StatusCode::CONFLICT, "DEPOSIT_TRANSACTION_BINDING_CONFLICT")
                        .into_response()
                }
                Err(_) => {
                    return (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "DEPOSIT_FINALITY_UNAVAILABLE",
                    )
                        .into_response()
                }
            }
        }
        CustomerAction::CreditDeposit { .. } => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "EXTERNAL_EFFECT_FINALITY_PENDING",
            )
                .into_response()
        }
        CustomerAction::PlaceOrder {
            order_id,
            market_id,
            outcome,
            action,
            price_micros,
            quantity_micros,
            time_in_force,
            expires_at_millis,
            now_millis,
        } if !external_effect_pending => DirectAction::PlaceOrder {
            order_id,
            market_id,
            outcome,
            action,
            price_micros,
            quantity_micros,
            time_in_force,
            expires_at_millis,
            now_millis,
        },
        CustomerAction::CancelOrder { order_id } if !external_effect_pending => {
            DirectAction::CancelOrder { order_id }
        }
        CustomerAction::RedeemCompleteSet { market_id, quantity_micros } if !external_effect_pending => {
            DirectAction::RedeemCompleteSet { market_id, quantity_micros }
        }
        CustomerAction::PlaceOrder { .. } | CustomerAction::CancelOrder { .. }
        | CustomerAction::RedeemCompleteSet { .. } => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "EXTERNAL_EFFECT_FINALITY_PENDING",
            )
                .into_response()
        }
        CustomerAction::ReserveWithdrawal {
            destination,
            amount_atomic,
            relay_route,
        } => {
            if let Some(relay) = relay_route.as_ref() {
                if !destination.eq_ignore_ascii_case(&relay.deposit_address)
                    || relay.verify(&amount_atomic).is_err()
                {
                    return (StatusCode::CONFLICT, "INVALID_RELAY_WITHDRAWAL_BINDING")
                        .into_response();
                }
            } else {
                // A direct Base withdrawal may target any syntactically valid
                // customer-provided address. The BFF signs that exact value
                // into the session and the action/intent bind it again. Privy
                // neither selects nor restricts the destination.
                let Some(signed_destination) = claims.financial_wallet_address.as_deref() else {
                    return (
                        StatusCode::FORBIDDEN,
                        "SIGNED_WITHDRAWAL_DESTINATION_REQUIRED",
                    )
                        .into_response();
                };
                if !signed_base_withdrawal_destination_matches(&destination, signed_destination) {
                    return (
                        StatusCode::FORBIDDEN,
                        "SIGNED_WITHDRAWAL_DESTINATION_MISMATCH",
                    )
                        .into_response();
                }
            }
            match prepare_external_withdrawal(
                &state,
                &claims,
                &body.identity_commitment,
                &request_id,
                destination,
                amount_atomic,
                relay_route,
            )
            .await
            {
                Ok(action) => action,
                Err((status, code)) => return (status, code).into_response(),
            }
        }
    };
    eprintln!("FINANCIAL_AWAIT_END stage=command_prepare");
    let mut request = DirectRequest {
        account_id: claims.subject_hash.clone(),
        identity_commitment: body.identity_commitment,
        request_id,
        request_hash: String::new(),
        financial_wallet_address: claims.financial_wallet_address.clone(),
        action,
    };
    request.request_hash = request_hash(&request);
    let task = tokio::spawn(commit_and_project(
        state.clone(),
        request,
        _financial_guard,
        ProjectionContext::Session(claims.clone()),
    ));
    match await_commit_task(task).await {
        Ok(result) => encrypted(&claims, &result),
        Err(CommitTaskError::Rejected(code)) => {
            (StatusCode::UNPROCESSABLE_ENTITY, code).into_response()
        }
        Err(CommitTaskError::SessionReplay) => {
            (StatusCode::CONFLICT, "SESSION_REPLAY_REJECTED").into_response()
        }
        Err(CommitTaskError::Projection) => {
            (StatusCode::SERVICE_UNAVAILABLE, "PROJECTION_UNAVAILABLE").into_response()
        }
        Err(CommitTaskError::Enclave(error))
            if error.to_string().contains("ARCHIVE_SEQUENCE_CONFLICT") =>
        {
            (StatusCode::CONFLICT, "ARCHIVE_COMMIT_CONFLICT").into_response()
        }
        Err(CommitTaskError::Enclave(error)) if error.to_string() == "ARCHIVE_TIMEOUT" => {
            (StatusCode::SERVICE_UNAVAILABLE, "ARCHIVE_TIMEOUT").into_response()
        }
        Err(CommitTaskError::Enclave(error)) if error.kind() == io::ErrorKind::TimedOut => {
            (StatusCode::SERVICE_UNAVAILABLE, "ENCLOSURE_TIMEOUT").into_response()
        }
        Err(CommitTaskError::Enclave(_) | CommitTaskError::Join) => {
            (StatusCode::BAD_GATEWAY, "ENCLOSURE_UNAVAILABLE").into_response()
        }
    }
}

async fn admit_identity(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let claims = match authenticated(&headers, &state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    if !direct_admission_route_enabled(
        state.isolated_test,
        env::var("LAYRS_DIRECT_EXECUTION_MODE").ok().as_deref(),
    ) {
        return (StatusCode::SERVICE_UNAVAILABLE, "ADMISSION_DISABLED").into_response();
    }
    if claims.identity_commitment
        != identity_commitment_for(&claims.subject_hash, &claims.wallet_address)
    {
        return (StatusCode::FORBIDDEN, "DIRECT_IDENTITY_BINDING_DENIED").into_response();
    }
    let request_id = match headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty() && value.len() <= 200)
    {
        Some(value) => value.to_string(),
        None => return (StatusCode::BAD_REQUEST, "IDEMPOTENCY_KEY_REQUIRED").into_response(),
    };
    let _guard = state.financial_gate.lock("write_request").await;
    let mut request = DirectRequest {
        // Admission is also a private-state mutation; its zero balance does
        // not make advancing an outstanding payout's root safe.
        account_id: claims.subject_hash.clone(),
        identity_commitment: claims.identity_commitment.clone(),
        request_id,
        request_hash: String::new(),
        financial_wallet_address: None,
        action: DirectAction::AdmitIdentity {
            wallet_address: claims.wallet_address.clone(),
        },
    };
    request.request_hash = request_hash(&request);
    let task = tokio::spawn(commit_and_project(
        state.clone(),
        request,
        _guard,
        ProjectionContext::Admission {
            claims: claims.clone(),
            wallet_address: claims.wallet_address.clone(),
        },
    ));
    match await_commit_task(task).await {
        Ok(result) => encrypted(&claims, &result),
        Err(CommitTaskError::Rejected(code)) => {
            (StatusCode::UNPROCESSABLE_ENTITY, code).into_response()
        }
        Err(CommitTaskError::SessionReplay) => {
            (StatusCode::CONFLICT, "SESSION_REPLAY_REJECTED").into_response()
        }
        Err(CommitTaskError::Projection) => {
            (StatusCode::SERVICE_UNAVAILABLE, "PROJECTION_UNAVAILABLE").into_response()
        }
        Err(CommitTaskError::Enclave(error))
            if error.to_string().contains("ARCHIVE_SEQUENCE_CONFLICT") =>
        {
            (StatusCode::CONFLICT, "ARCHIVE_COMMIT_CONFLICT").into_response()
        }
        Err(CommitTaskError::Enclave(error)) if error.to_string() == "ARCHIVE_TIMEOUT" => {
            (StatusCode::SERVICE_UNAVAILABLE, "ARCHIVE_TIMEOUT").into_response()
        }
        Err(CommitTaskError::Enclave(error)) if error.kind() == io::ErrorKind::TimedOut => {
            (StatusCode::SERVICE_UNAVAILABLE, "ENCLOSURE_TIMEOUT").into_response()
        }
        Err(CommitTaskError::Enclave(_) | CommitTaskError::Join) => {
            (StatusCode::BAD_GATEWAY, "ENCLOSURE_UNAVAILABLE").into_response()
        }
    }
}

async fn register_market(
    State(state): State<AppState>,
    Json(body): Json<MarketRegistrationCommand>,
) -> impl IntoResponse {
    if !direct_admission_route_enabled(
        state.isolated_test,
        env::var("LAYRS_DIRECT_EXECUTION_MODE").ok().as_deref(),
    ) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "MARKET_REGISTRATION_DISABLED",
        )
            .into_response();
    }
    let now = now_unix();
    if !state.isolated_test && !body.registration.verify(now) {
        return (
            StatusCode::FORBIDDEN,
            "MARKET_REGISTRATION_SIGNATURE_INVALID",
        )
            .into_response();
    }
    let mut request = DirectRequest {
        account_id: "governance".into(),
        identity_commitment: "governance".into(),
        request_id: body.registration.registration_id.clone(),
        request_hash: String::new(),
        financial_wallet_address: None,
        action: DirectAction::RegisterMarket {
            registration: body.registration,
            now_unix: now,
        },
    };
    request.request_hash = request_hash(&request);
    let _guard = state.financial_gate.lock("write_request").await;
    if !state.unresolved_external_effects.lock().await.is_empty() { return (StatusCode::SERVICE_UNAVAILABLE,"EXTERNAL_EFFECT_FINALITY_PENDING").into_response(); }
    operator_commit(state, request, _guard).await

}

async fn market_status(
    State(state): State<AppState>,
    Path(market_id): Path<String>,
) -> impl IntoResponse {
    match exchange(&state, RuntimeRequest::MarketStatus { market_id }).await {
        Ok(RuntimeResponse::MarketStatus { market }) => Json(serde_json::json!({
            "market": market
        }))
        .into_response(),
        Ok(RuntimeResponse::Error { code }) => {
            (StatusCode::SERVICE_UNAVAILABLE, code).into_response()
        }
        _ => (StatusCode::BAD_GATEWAY, "ENCLOSURE_UNAVAILABLE").into_response(),
    }
}

async fn resolve_market(
    State(state): State<AppState>,
    Json(body): Json<MarketResolutionCommand>,
) -> impl IntoResponse {
    if !direct_writer_route_enabled(
        state.isolated_test,
        env::var("LAYRS_DIRECT_EXECUTION_MODE").ok().as_deref(),
    ) {
        return (StatusCode::SERVICE_UNAVAILABLE, "WRITER_DISABLED").into_response();
    }
    let now = now_unix();
    if !state.isolated_test && !body.resolution.verify(now) {
        return (StatusCode::FORBIDDEN, "MARKET_RESOLUTION_SIGNATURE_INVALID").into_response();
    }
    let mut request = DirectRequest {
        account_id: "governance".into(),
        identity_commitment: "governance".into(),
        request_id: body.resolution.resolution_id.clone(),
        request_hash: String::new(),
        financial_wallet_address: None,
        action: DirectAction::ResolveMarket {
            resolution: body.resolution,
            now_unix: now,
        },
    };
    request.request_hash = request_hash(&request);
    let _guard = state.financial_gate.lock("write_request").await;
    if !state.unresolved_external_effects.lock().await.is_empty() { return (StatusCode::SERVICE_UNAVAILABLE,"EXTERNAL_EFFECT_FINALITY_PENDING").into_response(); }
    operator_commit(state, request, _guard).await

}

async fn apply_balance_recovery(
    State(state): State<AppState>,
    Json(recovery): Json<GovernedBalanceRecovery>,
) -> impl IntoResponse {
    if env::var("LAYRS_DIRECT_EXECUTION_MODE").as_deref() != Ok("production-enabled") {
        return (StatusCode::SERVICE_UNAVAILABLE, "WRITER_DISABLED").into_response();
    }
    let now = now_unix();
    if !recovery.verify(now) {
        return (StatusCode::FORBIDDEN, "BALANCE_RECOVERY_SIGNATURE_INVALID").into_response();
    }
    let mut request = DirectRequest {
        account_id: recovery.account_id.clone(),
        identity_commitment: recovery.identity_commitment.clone(),
        request_id: recovery.recovery_id.clone(),
        request_hash: String::new(),
        financial_wallet_address: None,
        action: DirectAction::GovernedBalanceRecovery {
            recovery,
            now_unix: now,
        },
    };
    request.request_hash = request_hash(&request);
    let _guard = state.financial_gate.lock("write_request").await;
    if !state.unresolved_external_effects.lock().await.is_empty() { return (StatusCode::SERVICE_UNAVAILABLE,"EXTERNAL_EFFECT_FINALITY_PENDING").into_response(); }
    operator_commit(state, request, _guard).await

}

async fn prepare_standard_zen_withdrawal(
    state:&AppState,claims:&SessionClaims,identity:&str,withdrawal_id:&str,
    destination_chain:String,asset:String,destination:String,amount_atomic:String,
) -> Result<DirectAction,(StatusCode,&'static str)> {
    if asset!="ZEN"||!matches!(destination_chain.as_str(),"base"|"horizen")
        ||canonical_evm_address(&destination).ok().as_deref()!=Some(destination.as_str())
        ||!amount_atomic.parse::<u128>().is_ok_and(|value|value>0)
        ||destination_chain=="base"&&!amount_atomic.parse::<u128>().is_ok_and(|value|value%1_000_000_000_000==0) {
        return Err((StatusCode::BAD_REQUEST,"ZEN_WITHDRAWAL_BINDING_INVALID"));
    }
    let custody=state.zen_custody.as_ref().ok_or((StatusCode::SERVICE_UNAVAILABLE,"ZEN_CUSTODY_ADAPTER_NOT_ENABLED"))?;
    let store=state.artifact_store.as_ref().ok_or((StatusCode::SERVICE_UNAVAILABLE,"DIRECT_ARTIFACT_STORE_NOT_CONFIGURED"))?;
    let intent_request_id=format!("zen-egress:{withdrawal_id}");
    let intents=store.load_intents().await.map_err(|_|(StatusCode::SERVICE_UNAVAILABLE,"ZEN_WITHDRAWAL_RECOVERY_FAILED"))?;
    let related=intents.iter().filter(|intent|intent.account_id==claims.subject_hash&&intent.request_id==intent_request_id).collect::<Vec<_>>();
    if related.len()>1||related.iter().any(|intent|intent.identity_commitment!=identity||intent.asset!="ZEN"||intent.chain!="horizen"
        ||intent.zen_destination_chain.as_ref()!=Some(&destination_chain)||intent.destination!=destination||intent.amount_atomic!=amount_atomic
        ||intent.provider_wallet_id!=custody.wallet_id||intent.custody_target!=custody.pool_address) {
        return Err((StatusCode::CONFLICT,"ZEN_WITHDRAWAL_REPLAY_CONFLICT"));
    }
    let intent=if let Some(intent)=related.first(){(*intent).clone()}else{
        let root=state.committed_state_root.lock().await.clone().ok_or((StatusCode::SERVICE_UNAVAILABLE,"DIRECT_STATE_ROOT_UNAVAILABLE"))?;
        let (nonce,gas,fee,priority)=custody.transaction_parameters().await.map_err(|_|(StatusCode::SERVICE_UNAVAILABLE,"CUSTODY_TRANSACTION_PARAMETERS_UNAVAILABLE"))?;
        let binding_hash=sha256(&serde_json::to_vec(&("layrs-standard-zen-egress-v1",withdrawal_id,&claims.subject_hash,identity,
            &destination_chain,&destination,&amount_atomic)).map_err(|_|(StatusCode::BAD_REQUEST,"ZEN_WITHDRAWAL_BINDING_INVALID"))?);
        let candidate=ExternalEffectIntent::create_zen_withdrawal(root,intent_request_id,binding_hash,claims.subject_hash.clone(),identity.into(),
            destination_chain.clone(),destination.clone(),amount_atomic.clone(),custody.wallet_id.clone(),custody.pool_address.clone(),
            nonce.to_string(),gas.to_string(),fee.to_string(),priority.to_string(),now_unix())
            .map_err(|_|(StatusCode::BAD_REQUEST,"ZEN_WITHDRAWAL_BINDING_INVALID"))?;
        store.persist_intent_readback(&candidate).await.map_err(|_|(StatusCode::SERVICE_UNAVAILABLE,"ZEN_WITHDRAWAL_INTENT_PERSISTENCE_FAILED"))?
    };
    match custody.settle(&intent,now_unix()).await.map_err(|_|(StatusCode::SERVICE_UNAVAILABLE,"ZEN_WITHDRAWAL_FINALITY_UNAVAILABLE"))? {
        ExternalEffectRecovery::BindFinalized{transaction_hash,..}=>Ok(DirectAction::SettleUsdcBusWithdrawal {withdrawal_id:withdrawal_id.into(),
            destination_chain:destination_chain.clone(),asset,destination,amount_atomic,
            custody_reference:format!("horizen-zen-{}:{transaction_hash}",if destination_chain=="base"{"oft"}else{"local"})}),
        ExternalEffectRecovery::BindReverted{transaction_hash,..}=>Ok(DirectAction::RevertUsdcBusWithdrawal {withdrawal_id:withdrawal_id.into(),
            destination_chain,asset,destination,amount_atomic,custody_reference:format!("horizen-zen-reverted:{transaction_hash}")}),
        _=>Err((StatusCode::SERVICE_UNAVAILABLE,"ZEN_WITHDRAWAL_FINALITY_PENDING")),
    }
}

async fn prepare_zen_withdrawal(
    state: &AppState, claims: &SessionClaims, identity: &str, request_id: &str,
    destination_chain: String, destination: String, amount_atomic: String,
) -> Result<DirectAction,(StatusCode,&'static str)> {
    let amount = amount_atomic.parse::<u128>().ok().filter(|value|*value>0)
        .ok_or((StatusCode::BAD_REQUEST,"ZEN_AMOUNT_INVALID"))?;
    if destination_chain == "base" && amount % 1_000_000_000_000 != 0 {return Err((StatusCode::BAD_REQUEST,"ZEN_BRIDGE_PRECISION_EXCEEDED"));}
    let custody=state.zen_custody.as_ref().ok_or((StatusCode::SERVICE_UNAVAILABLE,"ZEN_CUSTODY_ADAPTER_NOT_ENABLED"))?;
    let store=state.artifact_store.as_ref().ok_or((StatusCode::SERVICE_UNAVAILABLE,"DIRECT_ARTIFACT_STORE_NOT_CONFIGURED"))?;
    let intents=store.load_intents().await.map_err(|_|(StatusCode::SERVICE_UNAVAILABLE,"EXTERNAL_EFFECT_INTENT_RECOVERY_FAILED"))?;
    let receipts=store.committed_receipts(state).await.map_err(|_|(StatusCode::SERVICE_UNAVAILABLE,"DIRECT_STATE_RECOVERY_FAILED"))?;
    let related=intents.iter().filter(|intent|intent.account_id==claims.subject_hash && intent.request_id==request_id).collect::<Vec<_>>();
    if related.iter().any(|intent|intent.identity_commitment!=identity || intent.asset!="ZEN" || intent.chain!="horizen"
        || intent.zen_destination_chain.as_ref()!=Some(&destination_chain) || !intent.destination.eq_ignore_ascii_case(&destination)
        || intent.amount_atomic!=amount_atomic || intent.provider_wallet_id!=custody.wallet_id || intent.custody_target!=custody.pool_address) {
        return Err((StatusCode::CONFLICT,"EXTERNAL_EFFECT_REPLAY_CONFLICT"));
    }
    for intent in &related {
        if let Some(receipt)=receipts.iter().map(|(_, receipt)| receipt).find(|receipt|receipt.account_id==claims.subject_hash && receipt.request_id==request_id
            && receipt.request_hash==intent.request_hash && receipt.custody_reference.as_deref().is_some_and(|reference|reference.starts_with(&format!("{}:",intent.external_effect_reference)))) {
            let reference=receipt.custody_reference.clone().ok_or((StatusCode::CONFLICT,"EXTERNAL_EFFECT_RESULT_CONFLICT"))?;
            return match receipt.effect.as_str() {
                "WITHDRAWAL_SETTLED"=>Ok(DirectAction::ReserveZenWithdrawal {destination_chain,destination,amount_atomic,custody_reference:reference}),
                "WITHDRAWAL_REVERTED"=>Ok(DirectAction::RecordZenWithdrawalReverted {destination_chain,destination,amount_atomic,custody_reference:reference}),
                _=>Err((StatusCode::CONFLICT,"EXTERNAL_EFFECT_RESULT_CONFLICT")),
            };
        }
    }
    let root=state.committed_state_root.lock().await.clone().ok_or((StatusCode::SERVICE_UNAVAILABLE,"DIRECT_STATE_ROOT_UNAVAILABLE"))?;
    let intent=if let Some(intent)=related.first() {
        if related.len()!=1 || intent.prior_state_hash!=root {return Err((StatusCode::CONFLICT,"EXTERNAL_EFFECT_LINEAGE_CONFLICT"));}
        (*intent).clone()
    } else {
        if !state.unresolved_external_effects.lock().await.is_empty() {return Err((StatusCode::SERVICE_UNAVAILABLE,"EXTERNAL_EFFECT_FINALITY_PENDING"));}
        // Balance comes from the recovered private enclave, not Aurora or UI.
        let balance=exchange(state,RuntimeRequest::Balance {account_id:claims.subject_hash.clone(),identity_commitment:identity.into(),asset:"ZEN".into(),bucket:"USER_AVAILABLE".into()})
            .await.map_err(|_|(StatusCode::SERVICE_UNAVAILABLE,"ZEN_BALANCE_UNAVAILABLE"))?;
        if !matches!(balance,RuntimeResponse::Balance {amount_atomic:available} if available.parse::<u128>().is_ok_and(|value|value>=amount)) {
            return Err((StatusCode::UNPROCESSABLE_ENTITY,"INSUFFICIENT_AVAILABLE"));
        }
        let (nonce,gas,fee,priority)=custody.transaction_parameters().await.map_err(|_|(StatusCode::SERVICE_UNAVAILABLE,"CUSTODY_TRANSACTION_PARAMETERS_UNAVAILABLE"))?;
        let reference=reference_for(&root,request_id,&claims.subject_hash,identity,&format!("horizen-zen-{destination_chain}"),"ZEN",&destination,&amount_atomic,&custody.wallet_id);
        let mut request=DirectRequest {account_id:claims.subject_hash.clone(),identity_commitment:identity.into(),request_id:request_id.into(),request_hash:String::new(),
            financial_wallet_address:claims.financial_wallet_address.clone(),action:DirectAction::ReserveZenWithdrawal {destination_chain:destination_chain.clone(),destination:destination.clone(),amount_atomic:amount_atomic.clone(),custody_reference:reference}};
        request.request_hash=request_hash(&request);
        let intent=ExternalEffectIntent::create_zen_withdrawal(root,request_id.into(),request.request_hash,claims.subject_hash.clone(),identity.into(),destination_chain,destination,amount_atomic,
            custody.wallet_id.clone(),custody.pool_address.clone(),nonce.to_string(),gas.to_string(),fee.to_string(),priority.to_string(),now_unix())
            .map_err(|_|(StatusCode::BAD_REQUEST,"INVALID_WITHDRAWAL_INTENT"))?;
        store.persist_intent_readback(&intent).await.map_err(|_|(StatusCode::SERVICE_UNAVAILABLE,"EXTERNAL_EFFECT_INTENT_PERSISTENCE_FAILED"))?
    };
    // Keep the gate on every ambiguous error and until authoritative adoption.
    state.unresolved_external_effects.lock().await.insert(intent.intent_hash.clone(),intent.clone());
    match custody.settle(&intent,now_unix()).await.map_err(|_|(StatusCode::SERVICE_UNAVAILABLE,"CUSTODY_FINALITY_UNAVAILABLE"))? {
        terminal @ (ExternalEffectRecovery::BindFinalized {..}|ExternalEffectRecovery::BindReverted {..}) => direct_action_for_external_effect(&intent,terminal).map_err(|_|(StatusCode::CONFLICT,"EXTERNAL_EFFECT_RESULT_CONFLICT")),
        _=>Err((StatusCode::SERVICE_UNAVAILABLE,"CUSTODY_FINALITY_PENDING_FAIL_CLOSED")),
    }
}

async fn prepare_external_withdrawal(
    state: &AppState,
    claims: &SessionClaims,
    identity_commitment: &str,
    request_id: &str,
    destination: String,
    amount_atomic: String,
    relay_route: Option<RelayWithdrawalBinding>,
) -> Result<DirectAction, (StatusCode, &'static str)> {
    let Some(custody) = &state.custody else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "CUSTODY_ADAPTER_NOT_ENABLED",
        ));
    };
    let Some(store) = state.artifact_store.as_ref() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "DIRECT_ARTIFACT_STORE_NOT_CONFIGURED",
        ));
    };
    // Resolve an already-terminal request from the immutable private-state
    // lineage before doing any custody work. The external-effect reference is
    // part of the signed request hash, so recreating an intent from the newer
    // state root on replay would produce a different reference even though the
    // customer request is already terminal.
    let retained_intents = store.load_intents().await.map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "EXTERNAL_EFFECT_INTENT_RECOVERY_FAILED",
        )
    })?;
    let committed_receipts = store.committed_receipts(state).await.map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "DIRECT_STATE_RECOVERY_FAILED",
        )
    })?;
    if let Some(action) = committed_external_effect_action(
        &retained_intents,
        &committed_receipts,
        &claims.subject_hash,
        identity_commitment,
        request_id,
        &destination,
        &amount_atomic,
        relay_route.as_ref(),
    )
    .map_err(|_| (StatusCode::CONFLICT, "EXTERNAL_EFFECT_REPLAY_CONFLICT"))?
    {
        return Ok(action);
    }
    let prior_state_hash = state.committed_state_root.lock().await.clone().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "DIRECT_STATE_ROOT_UNAVAILABLE",
    ))?;
    if let Some(existing) = state
        .unresolved_external_effects
        .lock()
        .await
        .values()
        .find(|intent| {
            intent.account_id == claims.subject_hash
                && intent.request_id == request_id
                && intent.identity_commitment == identity_commitment
                && intent.destination.eq_ignore_ascii_case(&destination)
                && intent.amount_atomic == amount_atomic
                && intent.relay == relay_route
        })
        .cloned()
    {
        let outcome = if existing.relay.is_some() {
            custody.observe_terminal_only(&existing).await
        } else { custody.settle(&existing, now_unix()).await };
        match outcome.map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "CUSTODY_FINALITY_UNAVAILABLE",
            )
        })? {
            terminal @ (ExternalEffectRecovery::BindFinalized { .. }
            | ExternalEffectRecovery::BindReverted { .. }
            | ExternalEffectRecovery::BindRelayFinalized { .. }
            | ExternalEffectRecovery::BindRelayReverted { .. }) => {
                return direct_action_for_external_effect(&existing, terminal)
                    .map_err(|_| (StatusCode::CONFLICT, "EXTERNAL_EFFECT_RESULT_CONFLICT"));
            }
            ExternalEffectRecovery::AwaitExternalFinality
            | ExternalEffectRecovery::SubmitWithStableReference
            | ExternalEffectRecovery::FailClosed => {
                return Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CUSTODY_FINALITY_PENDING_FAIL_CLOSED",
                ));
            }
        }
    }
    validate_new_withdrawal_route(relay_route.as_ref())?;
    if !state.unresolved_external_effects.lock().await.is_empty() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "EXTERNAL_EFFECT_FINALITY_PENDING",
        ));
    }
    if state.usdc_custody.is_some() {
        // Fail before a legacy custody payout, not after money has moved.
        // The new per-account Bus hold cannot be bypassed through Base/Relay.
        let hold=exchange(state,RuntimeRequest::Balance {account_id:claims.subject_hash.clone(),identity_commitment:identity_commitment.into(),
            asset:"USDC".into(),bucket:"USER_WITHDRAWAL_HOLD".into()}).await
            .map_err(|_|(StatusCode::SERVICE_UNAVAILABLE,"USDC_WITHDRAWAL_PREFLIGHT_UNAVAILABLE"))?;
        let available=exchange(state,RuntimeRequest::Balance {account_id:claims.subject_hash.clone(),identity_commitment:identity_commitment.into(),
            asset:"USDC".into(),bucket:"USER_AVAILABLE".into()}).await
            .map_err(|_|(StatusCode::SERVICE_UNAVAILABLE,"USDC_WITHDRAWAL_PREFLIGHT_UNAVAILABLE"))?;
        usdc_withdrawal_preflight(&hold,&available,&amount_atomic)?;
    }
    // The financial mutex is held by command(): authorize principal against
    // the current private state BEFORE an intent, quote or payout can exist.
    // UI/Aurora checks cannot substitute for this serialized enclave check.
    let balance = exchange(state, RuntimeRequest::Balance {
        account_id: claims.subject_hash.clone(), identity_commitment: identity_commitment.into(),
        asset: "USDC".into(), bucket: "USER_AVAILABLE".into(),
    }).await.map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "USDC_BALANCE_UNAVAILABLE"))?;
    validate_usdc_pre_payout_balance(&balance, &amount_atomic)?;
    let (nonce, gas_limit, max_fee_per_gas, max_priority_fee_per_gas) =
        custody.transaction_parameters().await.map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "CUSTODY_TRANSACTION_PARAMETERS_UNAVAILABLE",
            )
        })?;
    let reference = match relay_route.as_ref() {
        Some(relay) => relay_reference_for(
            &prior_state_hash,
            request_id,
            &claims.subject_hash,
            identity_commitment,
            &amount_atomic,
            &custody.wallet_id,
            relay,
        ),
        None => reference_for(
            &prior_state_hash,
            request_id,
            &claims.subject_hash,
            identity_commitment,
            "base",
            "USDC",
            &destination,
            &amount_atomic,
            &custody.wallet_id,
        ),
    };
    let provisional_action = match relay_route.as_ref() {
        Some(relay) => DirectAction::SettleRelayWithdrawal {
            relay: relay.clone(),
            amount_atomic: amount_atomic.clone(),
            custody_reference: reference.clone(),
        },
        None => DirectAction::ReserveWithdrawal {
            destination: destination.clone(),
            amount_atomic: amount_atomic.clone(),
            custody_reference: reference.clone(),
        },
    };
    let provisional = DirectRequest {
        account_id: claims.subject_hash.clone(),
        identity_commitment: identity_commitment.into(),
        request_id: request_id.into(),
        request_hash: String::new(),
        financial_wallet_address: claims.financial_wallet_address.clone(),
        action: provisional_action,
    };
    let mut provisional = provisional;
    provisional.request_hash = request_hash(&provisional);
    let intent = match relay_route {
        Some(relay) => ExternalEffectIntent::create_relay_withdrawal(
            prior_state_hash,
            request_id.into(),
            provisional.request_hash.clone(),
            claims.subject_hash.clone(),
            identity_commitment.into(),
            amount_atomic.clone(),
            custody.wallet_id.clone(),
            custody.pool_address.clone(),
            nonce.to_string(),
            gas_limit.to_string(),
            max_fee_per_gas.to_string(),
            max_priority_fee_per_gas.to_string(),
            now_unix(),
            relay,
        ),
        None => ExternalEffectIntent::create(
            prior_state_hash,
            request_id.into(),
            provisional.request_hash.clone(),
            claims.subject_hash.clone(),
            identity_commitment.into(),
            "base".into(),
            "USDC".into(),
            destination.clone(),
            amount_atomic.clone(),
            custody.wallet_id.clone(),
            custody.pool_address.clone(),
            nonce.to_string(),
            gas_limit.to_string(),
            max_fee_per_gas.to_string(),
            max_priority_fee_per_gas.to_string(),
            now_unix(),
        ),
    }
    .map_err(|_| (StatusCode::BAD_REQUEST, "INVALID_WITHDRAWAL_INTENT"))?;
    let intent = store.persist_intent_readback(&intent).await.map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "EXTERNAL_EFFECT_INTENT_PERSISTENCE_FAILED",
        )
    })?;
    // Establish the gate BEFORE custody may submit or return an ambiguous
    // error, not only after a provider pending response.
    state.unresolved_external_effects.lock().await.insert(intent.intent_hash.clone(), intent.clone());
    match custody.settle(&intent, now_unix()).await.map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "CUSTODY_FINALITY_UNAVAILABLE",
        )
    })? {
        terminal @ (ExternalEffectRecovery::BindFinalized { .. }
        | ExternalEffectRecovery::BindReverted { .. }
        | ExternalEffectRecovery::BindRelayFinalized { .. }
        | ExternalEffectRecovery::BindRelayReverted { .. }) => {
            direct_action_for_external_effect(&intent, terminal)
                .map_err(|_| (StatusCode::CONFLICT, "EXTERNAL_EFFECT_RESULT_CONFLICT"))
        }
        ExternalEffectRecovery::AwaitExternalFinality
        | ExternalEffectRecovery::SubmitWithStableReference
        | ExternalEffectRecovery::FailClosed => {
            state
                .unresolved_external_effects
                .lock()
                .await
                .insert(intent.intent_hash.clone(), intent);
            Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "CUSTODY_FINALITY_PENDING_FAIL_CLOSED",
            ))
        }
    }
}

fn valid_base_withdrawal_destination(value: &str) -> bool {
    value.len() == 42
        && value.starts_with("0x")
        && value[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
        && value[2..].bytes().any(|byte| byte != b'0')
}

fn signed_base_withdrawal_destination_matches(
    action_destination: &str,
    signed_destination: &str,
) -> bool {
    valid_base_withdrawal_destination(action_destination)
        && valid_base_withdrawal_destination(signed_destination)
        && action_destination.eq_ignore_ascii_case(signed_destination)
}

/// Reserve entitlement in the trusted ledger before any worker moves money.
/// The route is exclusively Horizen -> Arbitrum; other phases use separate
/// certified actions, not caller-supplied chain IDs or generic calldata.
fn usdc_bus_reservation_action(
    request_id: &str,
    signed_identity:Option<&str>,expected_identity:&str,
    destination_chain:&str,
    asset:&str,
    destination: &str,
    amount_atomic: &str,
) -> Result<DirectAction, (StatusCode, &'static str)> {
    if !uuid::Uuid::parse_str(request_id).is_ok_and(|id| id.to_string() == request_id && !id.is_nil()) {
        return Err((StatusCode::BAD_REQUEST, "WITHDRAWAL_ID_INVALID"));
    }
    if !signed_identity.is_some_and(|signed|signed.eq_ignore_ascii_case(expected_identity)) {
        return Err((StatusCode::FORBIDDEN, "SIGNED_WITHDRAWAL_DESTINATION_MISMATCH"));
    }
    if !valid_layrs_withdrawal_destination(destination_chain,asset,destination) {
        return Err((StatusCode::BAD_REQUEST,"WITHDRAWAL_ROUTE_INVALID"));
    }
    if !amount_atomic.parse::<u128>().is_ok_and(|amount| amount > 0 && amount.to_string() == amount_atomic) {
        return Err((StatusCode::BAD_REQUEST, "WITHDRAWAL_AMOUNT_INVALID"));
    }
    Ok(DirectAction::BeginUsdcBusWithdrawal {
        withdrawal_id: request_id.into(),destination_chain:destination_chain.into(),asset:asset.into(),
        destination:if destination_chain=="solana" {destination.into()}else{destination.to_ascii_lowercase()}, amount_atomic: amount_atomic.into(),
    })
}
async fn balance(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(identity): Path<String>,
    Query(query): Query<BalanceQuery>,
) -> impl IntoResponse {
    let claims = match authenticated(&headers, &state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    match exchange(
        &state,
        RuntimeRequest::Balance {
            account_id: claims.subject_hash.clone(),
            identity_commitment: identity,
            asset: "USDC".into(),
            bucket: query.bucket.unwrap_or_else(|| "USER_AVAILABLE".into()),
        },
    )
    .await
    {
        Ok(RuntimeResponse::Balance { amount_atomic }) => encrypted(
            &claims,
            &serde_json::json!({"asset":"USDC", "amountAtomic": amount_atomic}),
        ),
        Ok(RuntimeResponse::Error { code }) => (StatusCode::FORBIDDEN, code).into_response(),
        _ => (StatusCode::BAD_GATEWAY, "ENCLOSURE_UNAVAILABLE").into_response(),
    }
}
async fn portfolio(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(identity): Path<String>,
) -> impl IntoResponse {
    let claims = match authenticated(&headers, &state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    match exchange(
        &state,
        RuntimeRequest::Portfolio {
            account_id: claims.subject_hash.clone(),
            identity_commitment: identity,
        },
    )
    .await
    {
        Ok(RuntimeResponse::Portfolio { portfolio }) => encrypted(&claims, &portfolio),
        Ok(RuntimeResponse::Error { code }) => (StatusCode::FORBIDDEN, code).into_response(),
        _ => (StatusCode::BAD_GATEWAY, "ENCLOSURE_UNAVAILABLE").into_response(),
    }
}
fn authenticated(
    headers: &HeaderMap,
    state: &AppState,
) -> Result<SessionClaims, axum::response::Response> {
    if state.session_key.len() < 32 {
        return Err((StatusCode::SERVICE_UNAVAILABLE, "AUTH_NOT_CONFIGURED").into_response());
    }
    let encoded = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "AUTH_REQUIRED").into_response())?;
    let claims: SessionClaims = URL_SAFE_NO_PAD
        .decode(encoded)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "INVALID_SESSION").into_response())?;
    let mut unsigned = claims.clone();
    unsigned.signature.clear();
    let bytes = serde_json::to_vec(&unsigned)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "INVALID_SESSION").into_response())?;
    if claims.audience != SESSION_AUDIENCE
        || claims.epoch_id != EPOCH_ID
        || claims.epoch_state_sha256 != layrs_direct_execution_v1::EPOCH_STATE_SHA256
        || !claims.wallet_address.starts_with("0x")
        || claims.wallet_address.len() != 42
        || !claims.wallet_address[2..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || claims
            .financial_wallet_address
            .as_ref()
            .is_some_and(|address| !valid_base_withdrawal_destination(address))
        || claims.identity_commitment.len() != 64
        || !claims
            .identity_commitment
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || claims.session_id.len() < 16
        || claims.subject_hash.len() != 64
        || claims.privy_user_id_hash.len() != 64
        || claims.expires_at_unix <= now_unix()
        || !constant_time_eq(&sign(&state.session_key, &bytes), &claims.signature)
        || URL_SAFE_NO_PAD
            .decode(&claims.response_key)
            .map_or(true, |key| key.len() != 32)
    {
        return Err((StatusCode::UNAUTHORIZED, "INVALID_SESSION").into_response());
    }
    Ok(claims)
}

#[derive(Debug)]
enum ProjectionError {
    Database,
    SessionReplay,
    OpeningMismatch,
}

#[derive(Clone)]
enum ProjectionContext {
    RecordOnly,
    Session(SessionClaims),
    Admission {
        claims: SessionClaims,
        wallet_address: String,
    },
}

#[derive(Debug)]
enum CommitTaskError {
    Enclave(io::Error),
    Rejected(String),
    Projection,
    SessionReplay,
    Join,
}

async fn record_result_with_retry(
    projection: &Projection,
    state: &AppState,
    result: &DirectResult,
) -> Result<(), ProjectionError> {
    let mut delay = Duration::from_millis(250);
    for attempt in 0..4 {
        eprintln!("FINANCIAL_AWAIT_BEGIN stage=projection_record attempt={}", attempt + 1);
        let recorded = projection.record_result(state, result).await;
        eprintln!("FINANCIAL_AWAIT_END stage=projection_record attempt={}", attempt + 1);
        if recorded.is_ok() {
            return Ok(());
        }
        if attempt < 3 {
            tokio::time::sleep(delay).await;
            delay = delay.saturating_mul(2);
        }
    }
    Err(ProjectionError::Database)
}

async fn commit_and_project(
    state: AppState,
    request: DirectRequest,
    guard: OwnedMutexGuard<()>,
    context: ProjectionContext,
) -> Result<DirectResult, CommitTaskError> {
    // The guard is deliberately owned by this detached task. If the HTTP
    // client disconnects, adoption and projection of the exact receipt still
    // finish before another financial command can enter.
    let guard = guard;
    let response = exchange_direct(&state, request, &guard)
        .await
        .map_err(CommitTaskError::Enclave)?;
    let RuntimeResponse::Execute { result } = response else {
        return match response {
            RuntimeResponse::Error { code } => Err(CommitTaskError::Rejected(code)),
            _ => Err(CommitTaskError::Enclave(invalid("ENCLOSURE_UNAVAILABLE"))),
        };
    };

    if let Some(projection) = &state.projection {
        match &context {
            ProjectionContext::Session(claims)
            | ProjectionContext::Admission { claims, .. } => {
                eprintln!("FINANCIAL_AWAIT_BEGIN stage=projection_session");
                let consumed = projection
                    .consume_session(claims, &result.receipt.request_hash)
                    .await;
                eprintln!("FINANCIAL_AWAIT_END stage=projection_session");
                if let Err(error) = consumed {
                    return Err(match error {
                        ProjectionError::SessionReplay => CommitTaskError::SessionReplay,
                        _ => CommitTaskError::Projection,
                    });
                }
            }
            ProjectionContext::RecordOnly => {}
        }
        record_result_with_retry(projection, &state, &result)
            .await
            .map_err(|_| CommitTaskError::Projection)?;
        if let ProjectionContext::Admission {
            claims,
            wallet_address,
        } = &context
        {
            eprintln!("FINANCIAL_AWAIT_BEGIN stage=projection_admission");
            let admitted = projection
                .record_identity_admission(
                    &claims.subject_hash,
                    &claims.identity_commitment,
                    wallet_address,
                    &result.receipt.receipt_id,
                )
                .await;
            eprintln!("FINANCIAL_AWAIT_END stage=projection_admission");
            admitted.map_err(|_| CommitTaskError::Projection)?;
        }
    } else if state.isolated_test {
        if let ProjectionContext::Session(claims)
        | ProjectionContext::Admission { claims, .. } = &context
        {
            let mut used = state.local_used_sessions.lock().await;
            if used.iter().any(|(session_id, request_hash)| {
                session_id == &claims.session_id && request_hash != &result.receipt.request_hash
            }) {
                return Err(CommitTaskError::SessionReplay);
            }
            used.insert((
                claims.session_id.clone(),
                result.receipt.request_hash.clone(),
            ));
        }
    } else {
        return Err(CommitTaskError::Projection);
    }

    if matches!(
        result.receipt.effect.as_str(),
        "WITHDRAWAL_SETTLED" | "WITHDRAWAL_REVERTED"
    ) {
        state.unresolved_external_effects.lock().await.retain(|_, intent| {
            !(intent.account_id == result.receipt.account_id
                && intent.identity_commitment == result.receipt.identity_commitment
                && intent.request_id == result.receipt.request_id
                && result.receipt.amount_atomic.as_deref() == Some(intent.amount_atomic.as_str())
                && result
                    .receipt
                    .custody_reference
                    .as_deref()
                    .is_some_and(|reference| {
                        reference.starts_with(&format!(
                            "{}:",
                            intent.external_effect_reference
                        ))
                    }))
        });
    }
    Ok(result)
}

async fn await_commit_task(
    task: tokio::task::JoinHandle<Result<DirectResult, CommitTaskError>>,
) -> Result<DirectResult, CommitTaskError> {
    task.await.map_err(|_| CommitTaskError::Join)?
}

fn commit_error_response(error: CommitTaskError) -> axum::response::Response {
    match error {
        CommitTaskError::Rejected(code) => {
            (StatusCode::UNPROCESSABLE_ENTITY, code).into_response()
        }
        CommitTaskError::SessionReplay => {
            (StatusCode::CONFLICT, "SESSION_REPLAY_REJECTED").into_response()
        }
        CommitTaskError::Projection => {
            (StatusCode::SERVICE_UNAVAILABLE, "PROJECTION_UNAVAILABLE").into_response()
        }
        CommitTaskError::Enclave(error)
            if error.to_string().contains("ARCHIVE_SEQUENCE_CONFLICT") =>
        {
            (StatusCode::CONFLICT, "ARCHIVE_COMMIT_CONFLICT").into_response()
        }
        CommitTaskError::Enclave(error) if error.to_string() == "ARCHIVE_TIMEOUT" => {
            (StatusCode::SERVICE_UNAVAILABLE, "ARCHIVE_TIMEOUT").into_response()
        }
        CommitTaskError::Enclave(error) if error.kind() == io::ErrorKind::TimedOut => {
            (StatusCode::SERVICE_UNAVAILABLE, "ENCLOSURE_TIMEOUT").into_response()
        }
        CommitTaskError::Enclave(_) | CommitTaskError::Join => {
            (StatusCode::BAD_GATEWAY, "ENCLOSURE_UNAVAILABLE").into_response()
        }
    }
}

async fn operator_commit(
    state: AppState,
    request: DirectRequest,
    guard: OwnedMutexGuard<()>,
) -> axum::response::Response {
    let task = tokio::spawn(commit_and_project(
        state,
        request,
        guard,
        ProjectionContext::RecordOnly,
    ));
    match await_commit_task(task).await {
        Ok(result) => Json(result).into_response(),
        Err(error) => commit_error_response(error),
    }
}

fn verified_receipt_sequence(records: &[DirectStateArtifact], receipt: &DirectReceipt) -> Result<i64, ProjectionError> {
    let mut matching = records.iter().filter(|record| record.receipt.receipt_id == receipt.receipt_id);
    let record = matching.next().ok_or(ProjectionError::Database)?;
    if matching.next().is_some() || record.receipt != *receipt || record.epoch_id != EPOCH_ID || record.sequence == 0 {
        return Err(ProjectionError::Database);
    }
    i64::try_from(record.sequence).map_err(|_| ProjectionError::Database)
}
fn verify_projected_receipt_lineage(records: &[DirectStateArtifact], receipts: &[DirectReceipt]) -> Result<(), ProjectionError> {
    let mut verified = HashMap::with_capacity(records.len());
    for record in records {
        if record.epoch_id != EPOCH_ID || record.sequence == 0
            || verified.insert(record.receipt.receipt_id.as_str(), &record.receipt).is_some() {
            return Err(ProjectionError::Database);
        }
    }
    // An independently persisted original receipt proves a lower bound on
    // committed history even when it made no balance change. PostgreSQL can
    // fence incomplete recovery, but cannot supply/decrypt/adopt private state.
    for receipt in receipts {
        if verified.get(receipt.receipt_id.as_str()).copied() != Some(receipt) {
            return Err(ProjectionError::Database);
        }
    }
    Ok(())
}

fn verify_committed_receipt_lineage(
    records: &[(u64, DirectReceipt)],
    receipts: &[DirectReceipt],
) -> Result<(), ProjectionError> {
    let mut verified = HashMap::with_capacity(records.len());
    if records.iter().enumerate().any(|(offset, (sequence, receipt))| {
        *sequence != offset as u64 + 1
            || verified
                .insert(receipt.receipt_id.as_str(), receipt)
                .is_some()
    }) || receipts
        .iter()
        .any(|receipt| verified.get(receipt.receipt_id.as_str()).copied() != Some(receipt))
    {
        return Err(ProjectionError::Database);
    }
    Ok(())
}

impl Projection {
    async fn record_extra_payout(&self, evidence: &ExtraPayoutEvidence) -> Result<(), ProjectionError> {
        let json = serde_json::to_string(evidence).map_err(|_| ProjectionError::Database)?;
        let digest = sha256(&serde_json::to_vec(evidence).map_err(|_| ProjectionError::Database)?);
        let mut client = self.client.lock().await;
        let tx = client.transaction().await.map_err(|_| ProjectionError::Database)?;
        tx.execute("INSERT INTO direct_execution_extra_payouts(epoch_id,intent_hash,original_receipt_id,transaction_hash,amount_atomic,evidence_sha256,evidence_json,disposition) VALUES($1,$2,$3,$4,$5::text::numeric,$6,$7::text::jsonb,'PROTOCOL_OVERPAYMENT_UNRECOVERED') ON CONFLICT DO NOTHING", &[&evidence.epoch_id,&evidence.intent_hash,&evidence.original_receipt_id,&evidence.transaction_hash,&evidence.amount_atomic,&digest,&json]).await.map_err(|_| ProjectionError::Database)?;
        let row = tx.query_opt("SELECT evidence_json::text,evidence_sha256,customer_debit_atomic::text FROM direct_execution_extra_payouts WHERE epoch_id=$1 AND intent_hash=$2", &[&evidence.epoch_id,&evidence.intent_hash]).await.map_err(|_| ProjectionError::Database)?.ok_or(ProjectionError::Database)?;
        let stored: ExtraPayoutEvidence = serde_json::from_str(&row.get::<_,String>(0)).map_err(|_|ProjectionError::Database)?;
        if stored != *evidence || row.get::<_, String>(1) != digest || row.get::<_, String>(2) != "0" { return Err(ProjectionError::Database); }
        tx.commit().await.map_err(|_| ProjectionError::Database)
    }

    async fn connect(
        url: &str,
        epoch: &SealedEpoch,
        isolated_test: bool,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let client = if isolated_test {
            let (client, connection) = tokio_postgres::connect(url, NoTls).await?;
            tokio::spawn(async move {
                let _ = connection.await;
            });
            client
        } else {
            let ca_pem = env::var("LAYRS_DIRECT_PROJECTION_DATABASE_CA_PEM")
                .map_err(|_| "production projection CA is required")?;
            // Secrets Manager JSON commonly stores PEM newlines as the two
            // characters `\\n`. Normalize that representation in memory;
            // never write or log the certificate or database credentials.
            let ca_pem = ca_pem.replace("\\n", "\n");
            let certificate = native_tls::Certificate::from_pem(ca_pem.as_bytes())?;
            let connector = native_tls::TlsConnector::builder()
                .add_root_certificate(certificate)
                .build()?;
            let connector = MakeTlsConnector::new(connector);
            let (client, connection) = tokio_postgres::connect(url, connector).await?;
            tokio::spawn(async move {
                let _ = connection.await;
            });
            client
        };
        let projection = Self {
            client: Arc::new(Mutex::new(client)),
        };
        if isolated_test {
            projection.client.lock().await
                .batch_execute(POSTGRES_PROJECTION_DDL)
                .await?;
            projection.client.lock().await.batch_execute(include_str!("../../sql/002_financial_wallet_aliases.sql")).await?;
            projection.client.lock().await.batch_execute(include_str!("../../sql/005_projection_frontier.sql")).await?;
            projection.client.lock().await.batch_execute(include_str!("../../sql/006_external_effect_reconciliation.sql")).await?;
        } else {
            // Production schema changes are applied once through the existing
            // migration principal. The long-running runtime receives only the
            // established projection-writer duty and fails closed if that
            // migration or its least-privilege grants are absent.
            if let Err(error) = projection.verify_schema_and_privileges().await {
                return Err(format!("projection schema verification failed: {error:?}").into());
            }
        }
        projection.client.lock().await
            .batch_execute("SET search_path TO layrs_direct_v1, pg_catalog")
            .await?;
        if let Err(error) = projection.import_opening(epoch).await {
            return Err(format!("opening projection import failed: {error:?}").into());
        }
        Ok(projection)
    }

    async fn verify_schema_and_privileges(&self) -> Result<(), ProjectionError> {
        let frontier = self.client.lock().await.query_one(
            "SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='layrs_direct_v1' AND table_name='direct_execution_epoch_balances' AND column_name='projection_sequence' AND data_type='bigint' AND is_nullable='NO')", &[]
        ).await.map_err(|_| ProjectionError::Database)?;
        if !frontier.get::<_, bool>(0) { return Err(ProjectionError::OpeningMismatch); }
        let tables = [
            ("direct_execution_receipts", "SELECT,INSERT"),
            ("direct_execution_epoch_balances", "SELECT,INSERT,UPDATE"),
            ("direct_execution_identities", "SELECT,INSERT"),
            ("direct_execution_privy_wallets", "SELECT,INSERT"),
            ("direct_execution_financial_wallet_aliases", "SELECT,INSERT"),
            ("direct_execution_identity_admissions", "SELECT,INSERT"),
            ("direct_execution_sessions", "SELECT,INSERT"),
            ("direct_execution_custody_events", "SELECT,INSERT"),
            ("direct_execution_accounting_events", "SELECT,INSERT"),
            ("direct_execution_order_events", "SELECT,INSERT"),
            ("direct_execution_trade_events", "SELECT,INSERT"),
            ("direct_execution_market_resolutions", "SELECT,INSERT"),
            ("direct_execution_writer_fence", "SELECT"),
            ("direct_execution_writer_grants", "SELECT"),
            ("direct_execution_extra_payouts", "SELECT,INSERT"),
        ];
        for (table, privileges) in tables {
            let qualified = format!("layrs_direct_v1.{table}");
            let row = self.client.lock().await
                .query_one(
                    "SELECT to_regclass($1)::text, has_table_privilege(current_user,$1,$2)",
                    &[&qualified, &privileges],
                )
                .await
                .map_err(|_| ProjectionError::Database)?;
            let relation: Option<String> = row.get(0);
            let allowed: bool = row.get(1);
            if relation.is_none() || !allowed {
                return Err(ProjectionError::OpeningMismatch);
            }
        }
        Ok(())
    }

    async fn import_opening(&self, epoch: &SealedEpoch) -> Result<(), ProjectionError> {
        let balances = epoch.projection_rows();
        let identities = epoch.projection_identity_rows();
        let wallets = epoch.projection_wallet_rows();
        for row in &identities {
            self.client.lock().await.execute(
                "INSERT INTO direct_execution_identities (epoch_id, auth_subject_hash, identity_commitment, admitted_post_genesis) VALUES ($1,$2,$3,false) ON CONFLICT (epoch_id, identity_commitment) DO NOTHING",
                &[&EPOCH_ID, &row.auth_subject_hash, &row.identity_commitment],
            ).await.map_err(|_| ProjectionError::Database)?;
        }
        for row in &balances {
            self.client.lock().await.execute(
                "INSERT INTO direct_execution_epoch_balances (epoch_id, auth_subject_hash, identity_commitment, asset, bucket, amount_atomic) VALUES ($1,$2,$3,$4,$5,$6::text::numeric) ON CONFLICT (epoch_id, identity_commitment, asset, bucket) DO NOTHING",
                &[&EPOCH_ID, &row.auth_subject_hash, &row.identity_commitment, &row.asset, &row.bucket, &row.amount_atomic],
            ).await.map_err(|_| ProjectionError::Database)?;
        }
        for row in &wallets {
            self.client.lock().await.execute(
                "INSERT INTO direct_execution_privy_wallets (epoch_id, auth_subject_hash, wallet_address) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING",
                &[&EPOCH_ID, &row.auth_subject_hash, &row.wallet_address],
            ).await.map_err(|_| ProjectionError::Database)?;
        }
        self.verify_opening(&identities, &balances, &wallets).await
    }

    async fn verify_opening(
        &self,
        identities: &[ProjectionIdentityRow],
        balances: &[ProjectionBalanceRow],
        wallets: &[ProjectionWalletRow],
    ) -> Result<(), ProjectionError> {
        for row in identities {
            let actual = self.client.lock().await.query_opt(
                "SELECT auth_subject_hash, admitted_post_genesis FROM direct_execution_identities WHERE epoch_id=$1 AND identity_commitment=$2",
                &[&EPOCH_ID, &row.identity_commitment],
            ).await.map_err(|_| ProjectionError::Database)?.ok_or(ProjectionError::OpeningMismatch)?;
            let subject: String = actual.get(0);
            let admitted: bool = actual.get(1);
            if subject != row.auth_subject_hash || admitted {
                return Err(ProjectionError::OpeningMismatch);
            }
        }
        for row in balances {
            let actual = self.client.lock().await.query_opt(
                "SELECT amount_atomic::text, auth_subject_hash FROM direct_execution_epoch_balances WHERE epoch_id=$1 AND identity_commitment=$2 AND asset=$3 AND bucket=$4",
                &[&EPOCH_ID, &row.identity_commitment, &row.asset, &row.bucket],
            ).await.map_err(|_| ProjectionError::Database)?.ok_or(ProjectionError::OpeningMismatch)?;
            let _amount: String = actual.get(0);
            let subject: String = actual.get(1);
            // A committed direct request legitimately advances this disposable
            // projection beyond genesis. Startup reconciles every current row
            // against the recovered enclave before serving; this opening pass
            // therefore verifies ownership and row presence without treating
            // the genesis amount as permanently authoritative.
            if subject != row.auth_subject_hash {
                return Err(ProjectionError::OpeningMismatch);
            }
        }
        for row in wallets {
            let found = self.client.lock().await.query_opt(
                "SELECT 1 FROM direct_execution_privy_wallets WHERE epoch_id=$1 AND auth_subject_hash=$2 AND wallet_address=$3",
                &[&EPOCH_ID, &row.auth_subject_hash, &row.wallet_address],
            ).await.map_err(|_| ProjectionError::Database)?.is_some();
            if !found {
                return Err(ProjectionError::OpeningMismatch);
            }
        }
        Ok(())
    }

    async fn consume_session(
        &self,
        claims: &SessionClaims,
        request_hash: &str,
    ) -> Result<(), ProjectionError> {
        let inserted = self.client.lock().await.execute(
            "INSERT INTO direct_execution_sessions (epoch_id, session_id, auth_subject_hash, request_hash, expires_at_unix) VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING",
            &[&EPOCH_ID, &claims.session_id, &claims.subject_hash, &request_hash, &(claims.expires_at_unix as i64)],
        ).await.map_err(|_| ProjectionError::Database)?;
        if inserted == 1 {
            return Ok(());
        }
        let existing = self.client.lock().await.query_opt(
            "SELECT auth_subject_hash, request_hash FROM direct_execution_sessions WHERE epoch_id=$1 AND session_id=$2",
            &[&EPOCH_ID, &claims.session_id],
        ).await.map_err(|_| ProjectionError::Database)?.ok_or(ProjectionError::Database)?;
        let subject: String = existing.get(0);
        let previous: String = existing.get(1);
        if subject == claims.subject_hash && previous == request_hash {
            Ok(())
        } else {
            Err(ProjectionError::SessionReplay)
        }
    }

    async fn record_result(&self, state: &AppState, result: &DirectResult) -> Result<(), ProjectionError> {
        let receipt = &result.receipt;
        // Ordering is bound to the fully verified immutable artifact, never a
        // user-supplied sequence or PostgreSQL's disposable receipt ordering.
        let sequence = state.artifact_store.as_ref().ok_or(ProjectionError::Database)?.receipt_sequence(state, receipt).await?;
        let mut client = self.client.lock().await;
        let transaction = client.transaction().await.map_err(|_| ProjectionError::Database)?;
        transaction.execute(
            "INSERT INTO direct_execution_receipts (receipt_id, epoch_id, auth_subject_hash, identity_commitment, request_id, request_hash, terminal_status, effect, custody_reference, receipt_json) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::text::jsonb) ON CONFLICT (receipt_id) DO NOTHING",
            &[&receipt.receipt_id, &EPOCH_ID, &receipt.account_id, &receipt.identity_commitment, &receipt.request_id, &receipt.request_hash, &format!("{:?}", receipt.status).to_uppercase(), &receipt.effect, &receipt.custody_reference, &serde_json::to_string(receipt).map_err(|_| ProjectionError::Database)?],
        ).await.map_err(|_| ProjectionError::Database)?;
        if let Some(wallet) = receipt_wallet_alias(receipt)? {
            transaction.execute(
                "INSERT INTO direct_execution_financial_wallet_aliases (epoch_id,auth_subject_hash,identity_commitment,wallet_address,receipt_id) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (epoch_id,wallet_address) DO NOTHING",
                &[&EPOCH_ID,&receipt.account_id,&receipt.identity_commitment,&wallet,&receipt.receipt_id],
            ).await.map_err(|_| ProjectionError::Database)?;
            let row = transaction.query_one(
                "SELECT auth_subject_hash,identity_commitment FROM direct_execution_financial_wallet_aliases WHERE epoch_id=$1 AND wallet_address=$2",
                &[&EPOCH_ID,&wallet],
            ).await.map_err(|_| ProjectionError::Database)?;
            if row.get::<_,String>(0) != receipt.account_id || row.get::<_,String>(1) != receipt.identity_commitment {
                return Err(ProjectionError::OpeningMismatch);
            }
        }
        for update in &receipt.projection_balance_updates {
            transaction.execute(
                "INSERT INTO direct_execution_epoch_balances (epoch_id, auth_subject_hash, identity_commitment, asset, bucket, amount_atomic, projection_sequence) VALUES ($1,$2,$3,$4,$5,$6::text::numeric,$7) ON CONFLICT (epoch_id, identity_commitment, asset, bucket) DO UPDATE SET auth_subject_hash=EXCLUDED.auth_subject_hash, amount_atomic=EXCLUDED.amount_atomic, projection_sequence=EXCLUDED.projection_sequence, updated_at=now() WHERE direct_execution_epoch_balances.projection_sequence<=EXCLUDED.projection_sequence",
                &[&EPOCH_ID, &update.auth_subject_hash, &update.identity_commitment, &update.asset, &update.bucket, &update.amount_atomic, &sequence],
            ).await.map_err(|_| ProjectionError::Database)?;
        }
        let accounting_amount = receipt.amount_atomic.clone();
        let (direction, amount) = receipt_custody(receipt);
        if let (Some(reference), Some(direction), Some(amount)) =
            (&receipt.custody_reference, direction, amount)
        {
            let (custody_chain_id, custody_transaction_hash) =
                custody_projection_binding(reference);
            transaction.execute(
                "INSERT INTO direct_execution_custody_events (epoch_id, custody_reference, direction, state, chain_id, tx_hash, auth_subject_hash, identity_commitment, amount_atomic) VALUES ($1,$2,$3,'FINAL',$4,$5,$6,$7,$8::text::numeric) ON CONFLICT DO NOTHING",
                &[&EPOCH_ID, reference, &direction, &custody_chain_id, &custody_transaction_hash, &receipt.account_id, &receipt.identity_commitment, &amount],
            ).await.map_err(|_| ProjectionError::Database)?;
        }
        transaction.execute(
            "INSERT INTO direct_execution_accounting_events (receipt_id, epoch_id, auth_subject_hash, identity_commitment, effect, amount_atomic) VALUES ($1,$2,$3,$4,$5,$6::text::numeric) ON CONFLICT DO NOTHING",
            &[&receipt.receipt_id, &EPOCH_ID, &receipt.account_id, &receipt.identity_commitment, &receipt.effect, &accounting_amount],
        ).await.map_err(|_| ProjectionError::Database)?;
        if let Some(execution) = &receipt.execution {
            let status = enum_name(&execution.status)?;
            let outcome = enum_name(&execution.outcome)?;
            let action = enum_name(&execution.action)?;
            transaction.execute(
                "INSERT INTO direct_execution_order_events (receipt_id, epoch_id, order_id, auth_subject_hash, identity_commitment, market_id, outcome, action, status, limit_price_micros, quantity_micros, executed_quantity_micros, remaining_quantity_micros, fee_atomic, resulting_position_micros, resulting_available_atomic) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::text::numeric,$12::text::numeric,$13::text::numeric,$14::text::numeric,$15::text::numeric,$16::text::numeric) ON CONFLICT DO NOTHING",
                &[&receipt.receipt_id, &EPOCH_ID, &execution.order_id, &receipt.account_id, &receipt.identity_commitment, &execution.market_id, &outcome, &action, &status, &(execution.limit_price_micros as i64), &execution.quantity_micros, &execution.executed_quantity_micros, &execution.remaining_quantity_micros, &execution.total_fee_atomic, &execution.resulting_position_micros, &execution.resulting_available_atomic],
            ).await.map_err(|_| ProjectionError::Database)?;
            for trade in &execution.trades {
                let trade_outcome = enum_name(&trade.outcome)?;
                let match_type = enum_name(&trade.match_type)?;
                transaction.execute(
                    "INSERT INTO direct_execution_trade_events (trade_id, receipt_id, epoch_id, market_id, maker_order_id, taker_order_id, outcome, match_type, executed_quantity_micros, execution_price_micros, fee_atomic) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::text::numeric,$10,$11::text::numeric) ON CONFLICT DO NOTHING",
                    &[&trade.trade_id, &receipt.receipt_id, &EPOCH_ID, &trade.market_id, &trade.maker_order_id, &trade.taker_order_id, &trade_outcome, &match_type, &trade.executed_quantity_micros, &(trade.execution_price_micros as i64), &trade.fee_atomic],
                ).await.map_err(|_| ProjectionError::Database)?;
            }
        }
        if let Some(resolution) = &receipt.resolution {
            let outcome = enum_name(&resolution.outcome)?;
            let cancelled_order_count = i64::try_from(resolution.cancelled_order_count)
                .map_err(|_| ProjectionError::Database)?;
            let settled_position_count = i64::try_from(resolution.settled_position_count)
                .map_err(|_| ProjectionError::Database)?;
            transaction.execute(
                "INSERT INTO direct_execution_market_resolutions (receipt_id, epoch_id, resolution_id, market_id, outcome, evidence_sha256, cancelled_order_count, settled_position_count, gross_payout_atomic, rounding_reserve_atomic) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::text::numeric,$10::text::numeric) ON CONFLICT DO NOTHING",
                &[&receipt.receipt_id, &EPOCH_ID, &resolution.resolution_id, &resolution.market_id, &outcome, &resolution.evidence_sha256, &cancelled_order_count, &settled_position_count, &resolution.gross_payout_atomic, &resolution.rounding_reserve_atomic],
            ).await.map_err(|_| ProjectionError::Database)?;
        }
        transaction.commit().await.map_err(|_| ProjectionError::Database)?;
        Ok(())
    }

    async fn record_identity_admission(
        &self,
        auth_subject_hash: &str,
        identity_commitment: &str,
        wallet_address: &str,
        receipt_id: &str,
    ) -> Result<(), ProjectionError> {
        self.client.lock().await.execute(
            "INSERT INTO direct_execution_identities (epoch_id, auth_subject_hash, identity_commitment, admitted_post_genesis) VALUES ($1,$2,$3,true) ON CONFLICT (epoch_id, identity_commitment) DO NOTHING",
            &[&EPOCH_ID, &auth_subject_hash, &identity_commitment],
        ).await.map_err(|_| ProjectionError::Database)?;
        self.client.lock().await.execute(
            "INSERT INTO direct_execution_epoch_balances (epoch_id, auth_subject_hash, identity_commitment, asset, bucket, amount_atomic) VALUES ($1,$2,$3,'USDC','USER_AVAILABLE',0) ON CONFLICT (epoch_id, identity_commitment, asset, bucket) DO NOTHING",
            &[&EPOCH_ID, &auth_subject_hash, &identity_commitment],
        ).await.map_err(|_| ProjectionError::Database)?;
        self.client.lock().await.execute(
            "INSERT INTO direct_execution_privy_wallets (epoch_id, auth_subject_hash, wallet_address) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING",
            &[&EPOCH_ID, &auth_subject_hash, &wallet_address],
        ).await.map_err(|_| ProjectionError::Database)?;
        self.client.lock().await.execute(
            "INSERT INTO direct_execution_identity_admissions (receipt_id, epoch_id, auth_subject_hash, identity_commitment, wallet_address) VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING",
            &[&receipt_id, &EPOCH_ID, &auth_subject_hash, &identity_commitment, &wallet_address],
        ).await.map_err(|_| ProjectionError::Database)?;
        let row = self.client.lock().await.query_opt(
            "SELECT identity.auth_subject_hash, wallet.wallet_address, admission.receipt_id FROM direct_execution_identities identity JOIN direct_execution_epoch_balances balance ON balance.epoch_id=identity.epoch_id AND balance.identity_commitment=identity.identity_commitment JOIN direct_execution_privy_wallets wallet ON wallet.epoch_id=identity.epoch_id AND wallet.auth_subject_hash=identity.auth_subject_hash JOIN direct_execution_identity_admissions admission ON admission.epoch_id=identity.epoch_id AND admission.identity_commitment=identity.identity_commitment WHERE identity.epoch_id=$1 AND identity.identity_commitment=$2 AND identity.admitted_post_genesis=true AND balance.asset='USDC' AND balance.bucket='USER_AVAILABLE' AND balance.amount_atomic=0",
            &[&EPOCH_ID, &identity_commitment],
        ).await.map_err(|_| ProjectionError::Database)?.ok_or(ProjectionError::OpeningMismatch)?;
        let actual_subject: String = row.get(0);
        let actual_wallet: String = row.get(1);
        let actual_receipt: String = row.get(2);
        if actual_subject == auth_subject_hash
            && actual_wallet.eq_ignore_ascii_case(wallet_address)
            && actual_receipt == receipt_id
        {
            Ok(())
        } else {
            Err(ProjectionError::OpeningMismatch)
        }
    }

    async fn verify_governed_runtime_mode(
        &self,
        grant: &WriterGrant,
        financial_writer_enabled: bool,
    ) -> Result<(), ProjectionError> {
        let row = self.client.lock().await.query_opt(
            "SELECT old_writer_fence_evidence_sha256, old_writer_authorized, target_writer_enabled, activation_id FROM direct_execution_writer_fence WHERE epoch_id=$1",
            &[&EPOCH_ID],
        ).await.map_err(|_| ProjectionError::Database)?.ok_or(ProjectionError::OpeningMismatch)?;
        let fence_hash: String = row.get(0);
        let old_authorized: bool = row.get(1);
        let target_enabled: bool = row.get(2);
        let activation: Option<String> = row.get(3);
        if old_authorized
            || target_enabled != financial_writer_enabled
            || fence_hash != grant.old_writer_fence_evidence_sha256
            || activation.as_deref() != Some(&grant.activation_id)
        {
            return Err(ProjectionError::OpeningMismatch);
        }
        let grant_row = self.client.lock().await.query_opt(
            "SELECT 1 FROM direct_execution_writer_grants WHERE activation_id=$1 AND epoch_id=$2 AND old_writer_fence_evidence_sha256=$3 AND expires_at_unix=$4",
            &[&grant.activation_id, &EPOCH_ID, &grant.old_writer_fence_evidence_sha256, &(grant.expires_at_unix as i64)],
        ).await.map_err(|_| ProjectionError::Database)?.is_some();
        if grant_row {
            Ok(())
        } else {
            Err(ProjectionError::OpeningMismatch)
        }
    }
}

fn usdc_withdrawal_preflight(hold:&RuntimeResponse,available:&RuntimeResponse,amount:&str)->Result<(),(StatusCode,&'static str)>{
    let RuntimeResponse::Balance {amount_atomic:held}=hold else {return Err((StatusCode::SERVICE_UNAVAILABLE,"USDC_WITHDRAWAL_PREFLIGHT_UNAVAILABLE"));};
    let held=held.parse::<u128>().map_err(|_|(StatusCode::SERVICE_UNAVAILABLE,"USDC_WITHDRAWAL_PREFLIGHT_UNAVAILABLE"))?;
    if held>0 {return Err((StatusCode::CONFLICT,"WITHDRAWAL_PENDING"));}
    let RuntimeResponse::Balance {amount_atomic:available}=available else {return Err((StatusCode::SERVICE_UNAVAILABLE,"USDC_WITHDRAWAL_PREFLIGHT_UNAVAILABLE"));};
    let available=available.parse::<u128>().map_err(|_|(StatusCode::SERVICE_UNAVAILABLE,"USDC_WITHDRAWAL_PREFLIGHT_UNAVAILABLE"))?;
    let amount=amount.parse::<u128>().ok().filter(|value|*value>0&&value.to_string()==amount)
        .ok_or((StatusCode::BAD_REQUEST,"WITHDRAWAL_AMOUNT_INVALID"))?;
    if available<amount {return Err((StatusCode::UNPROCESSABLE_ENTITY,"INSUFFICIENT_AVAILABLE"));}Ok(())
}

fn receipt_wallet_alias(receipt: &DirectReceipt) -> Result<Option<String>, ProjectionError> {
    if receipt.effect != "FINANCIAL_WALLET_LINKED" { return Ok(None); }
    if receipt.status != layrs_direct_execution_v1::TerminalStatus::Applied {
        return Err(ProjectionError::OpeningMismatch);
    }
    let wallet = receipt.custody_reference.as_deref().and_then(|value| value.strip_prefix("wallet-link:"))
        .filter(|value| value.len() == 42 && value.starts_with("0x")
            && value[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
            && *value != "0x0000000000000000000000000000000000000000")
        .ok_or(ProjectionError::OpeningMismatch)?;
    Ok(Some(wallet.to_ascii_lowercase()))
}

fn custody_projection_binding(reference: &str) -> (i64, String) {
    let parts = reference.split(':').collect::<Vec<_>>();
    if parts.first()==Some(&"arbitrum-usdc-bus-deposit") {
        if let Some(hash)=parts.get(1).filter(|hash|hash.len()==66&&hash.starts_with("0x")&&hash[2..].bytes().all(|byte|byte.is_ascii_hexdigit())) {
            return (42161,hash.to_ascii_lowercase());
        }
    }
    // The trusted receipt identifies the pool-side custody event. A Bus
    // settlement also carries the message GUID and destination hash; neither
    // replaces the Horizen pool transaction in the custody projection.
    if matches!(parts.first(), Some(&"horizen-usdc-deposit") | Some(&"horizen-usdc-bus")) {
        if let Some(hash) = parts.get(1).filter(|hash| {
            hash.len() == 66 && hash.starts_with("0x")
                && hash[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
        }) {
            return (26514, hash.to_ascii_lowercase());
        }
    }
    if parts.get(1) == Some(&"relay") {
        if let (Some(chain), Some(hash)) = (
            parts.get(3).and_then(|value| value.parse::<i64>().ok()),
            parts.get(5),
        ) {
            return (chain, (*hash).into());
        }
    }
    (8453, reference.into())
}

fn enum_name<T: Serialize>(value: &T) -> Result<String, ProjectionError> {
    serde_json::to_string(value)
        .map(|value| value.trim_matches('"').to_string())
        .map_err(|_| ProjectionError::Database)
}

fn receipt_custody(receipt: &DirectReceipt) -> (Option<&'static str>, Option<String>) {
    match receipt.effect.as_str() {
        "WITHDRAWAL_SETTLED" => (Some("WITHDRAWAL"), receipt.amount_atomic.clone()),
        "DEPOSIT_CREDITED"|"DEPOSIT_CONDITIONALLY_CREDITED" => (Some("DEPOSIT"), receipt.amount_atomic.clone()),
        _ => (None, None),
    }
}
fn encrypted_quest_witness<T:Serialize>(claims:&SessionClaims,body:&T)->axum::response::Response {
    let key=match URL_SAFE_NO_PAD.decode(&claims.response_key) {
        Ok(key) if key.len()==32=>zeroize::Zeroizing::new(key),
        _=>return (StatusCode::INTERNAL_SERVER_ERROR,"SESSION_ENCRYPTION_KEY_INVALID").into_response(),
    };
    let plaintext=match serde_json::to_vec(body) {
        Ok(bytes) if bytes.len()<=65536=>zeroize::Zeroizing::new(bytes),
        _=>return (StatusCode::INTERNAL_SERVER_ERROR,"RESPONSE_ENCODING_FAILED").into_response(),
    };
    let mut nonce=[0;12];
    if openssl::rand::rand_bytes(&mut nonce).is_err() {return (StatusCode::INTERNAL_SERVER_ERROR,"RESPONSE_ENCRYPTION_FAILED").into_response();}
    let cipher=ChaCha20Poly1305::new(Key::from_slice(&key));
    match cipher.encrypt(Nonce::from_slice(&nonce),plaintext.as_slice()) {
        Ok(ciphertext)=>Json(EncryptedResponse{algorithm:"CHACHA20_POLY1305",nonce:URL_SAFE_NO_PAD.encode(nonce),ciphertext:URL_SAFE_NO_PAD.encode(ciphertext)}).into_response(),
        Err(_)=>(StatusCode::INTERNAL_SERVER_ERROR,"RESPONSE_ENCRYPTION_FAILED").into_response(),
    }
}
fn encrypted<T: Serialize>(claims: &SessionClaims, body: &T) -> axum::response::Response {
    let key = match URL_SAFE_NO_PAD.decode(&claims.response_key) {
        Ok(value) if value.len() == 32 => value,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "SESSION_ENCRYPTION_KEY_INVALID",
            )
                .into_response()
        }
    };
    let bytes = match serde_json::to_vec(body) {
        Ok(value) => value,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "RESPONSE_ENCODING_FAILED",
            )
                .into_response()
        }
    };
    let digest = sha256(format!("{}:{}", claims.subject_hash, bytes.len()).as_bytes());
    let nonce_bytes = match hex::decode(&digest[..24]) {
        Ok(value) => value,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "RESPONSE_ENCRYPTION_FAILED",
            )
                .into_response()
        }
    };
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    match cipher.encrypt(Nonce::from_slice(&nonce_bytes), bytes.as_ref()) {
        Ok(ciphertext) => Json(EncryptedResponse {
            algorithm: "CHACHA20_POLY1305",
            nonce: URL_SAFE_NO_PAD.encode(nonce_bytes),
            ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
        })
        .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "RESPONSE_ENCRYPTION_FAILED",
        )
            .into_response(),
    }
}
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or(0)
}
fn now_unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|value| u64::try_from(value.as_millis()).ok())
        .unwrap_or(0)
}
fn constant_time_eq(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.as_bytes()
            .iter()
            .zip(b.as_bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}
async fn exchange(state: &AppState, request: RuntimeRequest) -> io::Result<RuntimeResponse> {
    exchange_with_timeout(state, request, ENCLOSURE_EXCHANGE_TIMEOUT).await
}
async fn exchange_with_timeout(
    state: &AppState,
    request: RuntimeRequest,
    duration: Duration,
) -> io::Result<RuntimeResponse> {
    let response = bounded_enclave_stage(duration, async {
        let mut stream =
            VsockStream::connect(VsockAddr::new(state.enclave_cid, ENCLOSURE_PORT)).await?;
        write_frame(&mut stream, &serde_cbor::to_vec(&request).map_err(invalid)?).await?;
        serde_cbor::from_slice(&read_frame(&mut stream).await?).map_err(invalid)
    })
    .await;
    if let Err(error) = &response {
        eprintln!("ENCLOSURE_TRANSPORT_FAILED kind={:?}", error.kind());
    }
    response
}

fn journal_checkpoint_verification_matches(
    checkpoint: &DirectV71Checkpoint,
    response: &RuntimeResponse,
) -> bool {
    matches!(
        response,
        RuntimeResponse::JournalCheckpointVerified {
            writer_epoch,
            sequence,
            record_hash,
            transition_root,
            request_index_root,
            financial_state_root,
        } if writer_epoch == &checkpoint.writer_epoch
            && sequence == &checkpoint.sequence
            && record_hash == &checkpoint.record_hash
            && transition_root == &checkpoint.transition_root
            && request_index_root == &checkpoint.request_index_root
            && financial_state_root == &checkpoint.financial_state_root
    )
}

async fn verify_journal_checkpoint_non_writer(
    state: &AppState,
    checkpoint: &DirectV71Checkpoint,
) -> Result<(), String> {
    let response = exchange_with_timeout(
        state,
        RuntimeRequest::VerifyJournalCheckpoint {
            checkpoint: checkpoint.clone(),
        },
        CHECKPOINT_EXCHANGE_TIMEOUT,
    )
    .await
    .map_err(|_| "journal checkpoint verification transport failed")?;
    if !journal_checkpoint_verification_matches(checkpoint, &response) {
        return Err("journal checkpoint verification mismatch".into());
    }
    eprintln!(
        "VERIFIED_JOURNAL_CHECKPOINT_NON_WRITER_RESTORE {}",
        checkpoint.sequence
    );
    Ok(())
}

async fn recover_enclave(state: &AppState) -> io::Result<()> {
    let store = state.artifact_store.as_ref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "DIRECT_ARTIFACT_STORE_NOT_CONFIGURED",
        )
    })?;
    if state.persistence_format == PersistenceFormat::V70RollbackBaseline {
        let ArchiveStore::S3(s3) = store else {
            return Err(invalid(
                "DIRECT_STATE_RECOVERY_FAILED:v70 rollback baseline requires the S3 archive",
            ));
        };
        let frontier = sparse_rollback_frontier(state)
            .map_err(|error| invalid(format!("DIRECT_STATE_RECOVERY_FAILED:{error}")))?;
        return s3
            .restore_sparse_rollback_with(state, frontier, |request| exchange(state, request))
            .await
            .map_err(|error| invalid(format!("DIRECT_STATE_RECOVERY_FAILED:{error}")));
    }
    if let ArchiveStore::S3(s3)=store {
        if state.effective_persistence_format() == PersistenceFormat::V71
            && s3.prepared_journal_restore.lock().await.is_some()
        {
            return s3.restore_journal_streamed(state).await
                .map_err(|error| invalid(format!("DIRECT_JOURNAL_RECOVERY_FAILED:{error}")));
        }
        return s3.restore_streamed(state).await.map_err(|error|invalid(format!("DIRECT_STATE_RECOVERY_FAILED:{error}")));
    }
    let artifacts = store.load_committed().await.map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("DIRECT_STATE_RECOVERY_FAILED:{error}"),
        )
    })?;
    let expected = artifacts.last().map(|artifact| {
        (
            artifact.sequence,
            artifact.state_hash.clone(),
            artifact.epoch_id.clone(),
        )
    });
    match exchange(state, RuntimeRequest::RecoverCommitted { artifacts }).await? {
        RuntimeResponse::RecoveryComplete {
            recovered_sequence,
            recovered_state_hash,
        } => match expected {
            Some((sequence, state_hash, epoch_id))
                if epoch_id == EPOCH_ID
                    && sequence == recovered_sequence
                    && state_hash == recovered_state_hash =>
            {
                *state.committed_state_root.lock().await = Some(recovered_state_hash);
                Ok(())
            }
            None if recovered_sequence == 0 => {
                *state.committed_state_root.lock().await = Some(recovered_state_hash);
                Ok(())
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DIRECT_STATE_RECOVERY_MISMATCH",
            )),
        },
        RuntimeResponse::Error { code } => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("DIRECT_STATE_RECOVERY_FAILED:{code}"),
        )),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DIRECT_STATE_RECOVERY_UNEXPECTED_RESPONSE",
        )),
    }
}

async fn activate_v71_from_restored_v70(state: &AppState) -> io::Result<()> {
    if !state.unresolved_external_effects.lock().await.is_empty() {
        return Err(invalid("V71_CUTOVER_EXTERNAL_EFFECT_PENDING"));
    }
    let store = match state.artifact_store.as_ref() {
        Some(ArchiveStore::S3(store)) => store,
        _ => return Err(invalid("V71_S3_ARCHIVE_REQUIRED")),
    };
    let bundle = match exchange(state, RuntimeRequest::SealV70Migration).await? {
        RuntimeResponse::V70MigrationSealed { bundle } => bundle,
        RuntimeResponse::Error { code } => {
            return Err(invalid(format!("V70_MIGRATION_SEAL_FAILED:{code}")))
        }
        _ => return Err(invalid("V70_MIGRATION_SEAL_UNEXPECTED_RESPONSE")),
    };
    let restored_root = state
        .committed_state_root
        .lock()
        .await
        .clone()
        .ok_or_else(|| invalid("DIRECT_STATE_ROOT_UNAVAILABLE"))?;
    if bundle.manifest.source_state_hash != restored_root {
        return Err(invalid("V70_MIGRATION_SOURCE_HEAD_MISMATCH"));
    }
    let records = store
        .verified_receipt_records
        .lock()
        .await
        .clone()
        .ok_or_else(|| invalid("V70_MIGRATION_RECEIPTS_UNAVAILABLE"))?;
    let (index, receipts, index_snapshot, receipt_snapshot) =
        migration_parent_state(&bundle, &records).map_err(invalid)?;

    store
        .persist_v70_migration_bundle(&bundle)
        .await
        .map_err(|error| invalid(format!("V70_MIGRATION_PERSISTENCE_FAILED:{error}")))?;
    let activated = exchange(
        state,
        RuntimeRequest::ActivateV71Migration {
            bundle: bundle.clone(),
        },
    )
    .await?;
    let (
        writer_epoch,
        sequence,
        record_hash,
        transition_root,
        request_index_root,
        financial_state_root,
    ) = match activated {
        RuntimeResponse::V71MigrationActivated {
            writer_epoch,
            sequence,
            record_hash,
            transition_root,
            request_index_root,
            financial_state_root,
        } if sequence == bundle.manifest.source_sequence
            && request_index_root == bundle.manifest.request_index_root =>
        {
            (
                writer_epoch,
                sequence,
                record_hash,
                transition_root,
                request_index_root,
                financial_state_root,
            )
        }
        RuntimeResponse::Error { code } => {
            return Err(invalid(format!("V71_MIGRATION_ACTIVATION_FAILED:{code}")))
        }
        _ => return Err(invalid("V71_MIGRATION_ACTIVATION_MISMATCH")),
    };
    let checkpoint = match exchange(state, RuntimeRequest::SealJournalCheckpoint).await? {
        RuntimeResponse::JournalCheckpointSealed { checkpoint }
            if checkpoint.writer_epoch == writer_epoch
                && checkpoint.sequence == sequence
                && checkpoint.record_hash == record_hash
                && checkpoint.transition_root == transition_root
                && checkpoint.request_index_root == request_index_root
                && checkpoint.financial_state_root == financial_state_root => checkpoint,
        RuntimeResponse::Error { code } => {
            return Err(invalid(format!("V71_CHECKPOINT_SEAL_FAILED:{code}")))
        }
        _ => return Err(invalid("V71_CHECKPOINT_SEAL_MISMATCH")),
    };
    verify_journal_checkpoint_non_writer(state, &checkpoint)
        .await
        .map_err(|error| invalid(format!("V71_CHECKPOINT_VERIFICATION_FAILED:{error}")))?;
    store
        .publish_journal_checkpoint(&checkpoint, &index_snapshot, &receipt_snapshot)
        .await
        .map_err(|error| invalid(format!("V71_CHECKPOINT_PUBLICATION_FAILED:{error}")))?;
    store
        .establish_journal_head(JournalHead {
            writer_epoch,
            sequence,
            record_hash,
            transition_root: transition_root.clone(),
            request_index_root,
            financial_state_root,
        })
        .await
        .map_err(|error| invalid(format!("V71_WRITER_HEAD_FAILED:{error}")))?;
    *state.journal_request_index.lock().await = Some(index);
    *state.journal_receipts.lock().await = Some(receipts);
    *state.journal_migration.lock().await = Some(bundle);
    *state.journal_transition_roots.lock().await = Some(BTreeMap::from([(
        sequence,
        transition_root.clone(),
    )]));
    state
        .journal_checkpoint_sequence
        .store(sequence, Ordering::Release);
    *state.committed_state_root.lock().await = Some(transition_root);
    // A successful cutover must make accidental v70 artifact reads fail
    // closed. The journal receipt cache above is now the only authoritative
    // committed lineage for retries, payout deduplication and projection.
    *store.verified_receipt_records.lock().await = None;
    eprintln!("V71_MIGRATION_CUTOVER_READY sequence={sequence}");
    Ok(())
}

#[derive(Clone)]
struct StagedV71Head {
    writer_epoch: String,
    sequence: u64,
    record_hash: String,
    transition_root: String,
    request_index_root: String,
    financial_state_root: String,
}

#[allow(clippy::too_many_arguments)]
async fn append_shadow_export(
    store: &S3ImmutableArtifactStore,
    index: &mut DirectRequestIndexState,
    receipts: &mut JournalReceiptCache,
    transition_roots: &mut BTreeMap<u64, String>,
    head: &mut StagedV71Head,
    records: Vec<DirectJournalRecord>,
    terminal_leaves: Vec<TerminalRequestLeaf>,
    results: Vec<DirectResult>,
    exported: &StagedV71Head,
) -> Result<(), String> {
    if records.len() != terminal_leaves.len() || records.len() != results.len() {
        return Err("V71_SHADOW_EXPORT_CARDINALITY_MISMATCH".into());
    }
    for ((record, leaf), result) in records
        .into_iter()
        .zip(terminal_leaves)
        .zip(results)
    {
        if record.writer_epoch != head.writer_epoch
            || record.sequence != head.sequence.saturating_add(1)
            || record.previous_record_hash != head.record_hash
            || record.previous_transition_root != head.transition_root
            || record.previous_request_index_root != head.request_index_root
            || !terminal_leaf_matches_record(&leaf, &record)
            || !verify_terminal_matches_record(&result, &record)
        {
            return Err("V71_SHADOW_EXPORT_LINEAGE_MISMATCH".into());
        }
        store.append_journal_record(&record).await?;
        index
            .insert(
                leaf,
                &record.previous_request_index_root,
                &record.request_index_root,
            )
            .map_err(|_| "V71_SHADOW_INDEX_ADVANCE_FAILED")?;
        if receipts
            .insert(
                (result.receipt.account_id.clone(), result.receipt.request_id.clone()),
                (record.sequence, result.receipt),
            )
            .is_some()
        {
            return Err("V71_SHADOW_RECEIPT_DUPLICATE".into());
        }
        head.sequence = record.sequence;
        head.record_hash = record
            .record_hash()
            .map_err(|_| "V71_SHADOW_RECORD_HASH_INVALID")?;
        head.transition_root = record.transition_root.clone();
        head.request_index_root = record.request_index_root.clone();
        head.financial_state_root = record.financial_state_root;
        if transition_roots
            .insert(head.sequence, head.transition_root.clone())
            .is_some()
        {
            return Err("V71_SHADOW_TRANSITION_DUPLICATE".into());
        }
    }
    if head.sequence != exported.sequence
        || head.writer_epoch != exported.writer_epoch
        || head.record_hash != exported.record_hash
        || head.transition_root != exported.transition_root
        || head.request_index_root != exported.request_index_root
        || head.financial_state_root != exported.financial_state_root
    {
        return Err("V71_SHADOW_EXPORT_HEAD_MISMATCH".into());
    }
    Ok(())
}

async fn export_shadow_after(
    state: &AppState,
    run_id: &str,
    after_sequence: u64,
    include_migration: bool,
) -> Result<
    (
        StagedV71Head,
        Option<V70MigrationBundle>,
        Option<DirectV71Checkpoint>,
        Vec<DirectJournalRecord>,
        Vec<TerminalRequestLeaf>,
        Vec<DirectResult>,
        u64,
    ),
    String,
> {
    match exchange_with_timeout(
        state,
        RuntimeRequest::ExportV71Shadow {
            run_id: run_id.into(),
            after_sequence,
            include_migration,
        },
        CHECKPOINT_EXCHANGE_TIMEOUT,
    )
    .await
    .map_err(|_| "V71_SHADOW_EXPORT_TRANSPORT_FAILED")?
    {
        RuntimeResponse::V71ShadowExport {
            run_id: returned_run_id,
            source_sequence,
            writer_epoch,
            sequence,
            record_hash,
            transition_root,
            request_index_root,
            financial_state_root,
            migration,
            base_checkpoint,
            records,
            terminal_leaves,
            results,
        } if returned_run_id == run_id => Ok((
            StagedV71Head {
                writer_epoch,
                sequence,
                record_hash,
                transition_root,
                request_index_root,
                financial_state_root,
            },
            migration,
            base_checkpoint,
            records,
            terminal_leaves,
            results,
            source_sequence,
        )),
        RuntimeResponse::Error { code } => Err(format!("V71_SHADOW_EXPORT_FAILED:{code}")),
        _ => Err("V71_SHADOW_EXPORT_UNEXPECTED_RESPONSE".into()),
    }
}

/// Stages only committed v71 state while v70 keeps serving traffic, then takes
/// the existing in-memory financial gate for one final bounded delta and an
/// atomic enclave promotion. No command is ever stored or queued by this path.
async fn stage_and_promote_v71_shadow(state: AppState, run_id: String) -> Result<(), String> {
    let store = match state.artifact_store.as_ref() {
        Some(ArchiveStore::S3(store)) => store,
        _ => return Err("V71_S3_ARCHIVE_REQUIRED".into()),
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10 * 60);
    let shadow_source_sequence = loop {
        if tokio::time::Instant::now() >= deadline {
            return Err("V71_SHADOW_PROMOTION_ABORT_10_MINUTES".into());
        }
        match exchange(&state, RuntimeRequest::V71ShadowStatus).await {
            Ok(RuntimeResponse::V71ShadowStatus {
                phase,
                source_sequence,
                consecutive_matches,
                ..
            }) if phase == "ACTIVE" && consecutive_matches >= 1 => break source_sequence,
            Ok(RuntimeResponse::V71ShadowStatus { phase, .. })
                if phase.starts_with("LATCHED:") =>
            {
                return Err(format!("V71_SHADOW_PROMOTION_ABORT:{phase}"));
            }
            Ok(_) => tokio::time::sleep(Duration::from_millis(250)).await,
            Err(_) => return Err("V71_SHADOW_STATUS_TRANSPORT_FAILED".into()),
        }
    };

    let (exported, migration, base_checkpoint, records, leaves, results, source_sequence) =
        export_shadow_after(
            &state,
            &run_id,
            shadow_source_sequence,
            true,
        )
        .await?;
    let migration = migration.ok_or("V71_SHADOW_MIGRATION_MISSING")?;
    let base_checkpoint = base_checkpoint.ok_or("V71_SHADOW_BASE_CHECKPOINT_MISSING")?;
    if migration.manifest.source_sequence != source_sequence
        || base_checkpoint.sequence != source_sequence
        || base_checkpoint.writer_epoch != exported.writer_epoch
    {
        return Err("V71_SHADOW_BASE_MISMATCH".into());
    }
    let source_len = usize::try_from(source_sequence)
        .map_err(|_| "V71_SHADOW_SOURCE_SEQUENCE_INVALID")?;
    let v70_records = store
        .verified_receipt_records
        .lock()
        .await
        .clone()
        .ok_or("V71_SHADOW_V70_RECEIPTS_UNAVAILABLE")?;
    let source_records = v70_records
        .get(..source_len)
        .ok_or("V71_SHADOW_V70_RECEIPTS_INCOMPLETE")?;
    let (mut index, mut receipts, index_snapshot, receipt_snapshot) =
        migration_parent_state(&migration, source_records)?;

    store.persist_v70_migration_bundle(&migration).await?;
    verify_journal_checkpoint_non_writer(&state, &base_checkpoint).await?;
    store
        .publish_journal_checkpoint(&base_checkpoint, &index_snapshot, &receipt_snapshot)
        .await?;
    let mut head = StagedV71Head {
        writer_epoch: base_checkpoint.writer_epoch.clone(),
        sequence: base_checkpoint.sequence,
        record_hash: base_checkpoint.record_hash.clone(),
        transition_root: base_checkpoint.transition_root.clone(),
        request_index_root: base_checkpoint.request_index_root.clone(),
        financial_state_root: base_checkpoint.financial_state_root.clone(),
    };
    store
        .establish_journal_head(JournalHead {
            writer_epoch: head.writer_epoch.clone(),
            sequence: head.sequence,
            record_hash: head.record_hash.clone(),
            transition_root: head.transition_root.clone(),
            request_index_root: head.request_index_root.clone(),
            financial_state_root: head.financial_state_root.clone(),
        })
        .await?;
    let mut transition_roots = BTreeMap::from([(
        head.sequence,
        head.transition_root.clone(),
    )]);
    append_shadow_export(
        store,
        &mut index,
        &mut receipts,
        &mut transition_roots,
        &mut head,
        records,
        leaves,
        results,
        &exported,
    )
    .await?;

    // Catch up without blocking traffic. Once a read is current, take the
    // ordinary in-memory writer gate and persist only the final small delta.
    let (next, _, _, records, leaves, results, _) =
            export_shadow_after(&state, &run_id, head.sequence, false).await?;
        append_shadow_export(
            store,
            &mut index,
            &mut receipts,
            &mut transition_roots,
            &mut head,
            records,
            leaves,
            results,
            &next,
        )
        .await?;
        let guard = state.financial_gate.lock("v71_hot_promotion").await;
        let (final_head, _, _, records, leaves, results, _) =
            export_shadow_after(&state, &run_id, head.sequence, false).await?;
        append_shadow_export(
            store,
            &mut index,
            &mut receipts,
            &mut transition_roots,
            &mut head,
            records,
            leaves,
            results,
            &final_head,
        )
        .await?;
        if !state.unresolved_external_effects.lock().await.is_empty() {
            drop(guard);
            return Err("V71_CUTOVER_EXTERNAL_EFFECT_PENDING".into());
        }
        // This immutable marker is the restart decision point. It describes
        // only the exact committed journal head staged above; it contains no
        // command or pending-work payload. If the following transport is
        // ambiguous, restart deterministically restores this v71 frontier.
        store.persist_v71_cutover_marker(&head).await?;
        let promoted = exchange(
            &state,
            RuntimeRequest::PromoteV71Shadow {
                run_id: run_id.clone(),
                expected_sequence: head.sequence,
                expected_record_hash: head.record_hash.clone(),
                expected_transition_root: head.transition_root.clone(),
                expected_request_index_root: head.request_index_root.clone(),
                expected_financial_state_root: head.financial_state_root.clone(),
            },
        )
        .await
        .map_err(|_| "V71_SHADOW_PROMOTION_TRANSPORT_FAILED")?;
        if !matches!(promoted, RuntimeResponse::V71ShadowPromoted {
            ref writer_epoch,
            sequence,
            ref record_hash,
            ref transition_root,
            ref request_index_root,
            ref financial_state_root,
        } if writer_epoch == &head.writer_epoch
            && sequence == head.sequence
            && record_hash == &head.record_hash
            && transition_root == &head.transition_root
            && request_index_root == &head.request_index_root
            && financial_state_root == &head.financial_state_root)
        {
            drop(guard);
            return Err("V71_SHADOW_PROMOTION_MISMATCH".into());
        }
        *state.journal_request_index.lock().await = Some(index);
        *state.journal_receipts.lock().await = Some(receipts);
        *state.journal_migration.lock().await = Some(migration);
        *state.journal_transition_roots.lock().await = Some(transition_roots);
        state
            .journal_checkpoint_sequence
            .store(source_sequence, Ordering::Release);
        *state.committed_state_root.lock().await = Some(head.transition_root.clone());
        *store.verified_receipt_records.lock().await = None;
        state.hot_v71_enabled.store(true, Ordering::Release);
        drop(guard);
        eprintln!(
            "V71_HOT_PROMOTION_COMPLETE run_id={} sequence={}",
            run_id, head.sequence
        );
    Ok(())
}

/// Materializes the exact v70 rollback package for the restored v71 head
/// under the explicitly supplied fresh prefix while retaining the financial
/// gate. The caller must keep the returned guard alive until the v70 writer
/// handoff is complete: no later command can then be acknowledged outside the
/// package. The authoritative archive is only read. `seal` performs the
/// enclave exchange; production passes
/// `|request| exchange_with_timeout(state, request, CHECKPOINT_EXCHANGE_TIMEOUT)`.
#[cfg_attr(not(test), allow(dead_code))]
async fn prepare_v70_rollback_handoff<F, Fut>(
    state: &AppState,
    fresh_prefix: &str,
    seal: F,
) -> Result<(V70RollbackPackage, OwnedMutexGuard<()>), String>
where
    F: FnOnce(RuntimeRequest) -> Fut,
    Fut: Future<Output = io::Result<RuntimeResponse>>,
{
    if state.effective_persistence_format() != PersistenceFormat::V71 {
        return Err("v70 rollback requires a restored v71 lineage".into());
    }
    let store = match state.artifact_store.as_ref() {
        Some(ArchiveStore::S3(store)) if store.journal_role == JournalRole::Writer => store,
        _ => return Err("v70 rollback requires the authoritative S3 archive".into()),
    };
    validate_v70_rollback_prefix(&store.prefix, fresh_prefix)?;
    // This is an explicit rollback handoff, not a background checkpoint. Keep
    // the gate through archive collection, enclave sealing, validation, and
    // durable publication. Returning the guard lets the operator path keep
    // dispatch fenced until the retained-v70 ASG has taken over.
    let guard = state.financial_gate.lock("v70_rollback_handoff").await;
    if !state.unresolved_external_effects.lock().await.is_empty() {
        return Err("v70 rollback external effect pending".into());
    }
    let head = match &*store.journal.lock().await {
        JournalWriterState::Eligible(head) => head.clone(),
        JournalWriterState::Unrestored | JournalWriterState::Latched(_) => {
            return Err("v70 rollback requires an eligible v71 head".into())
        }
    };
    let restored = state
        .journal_migration
        .lock()
        .await
        .clone()
        .ok_or("v70 rollback migration lineage unavailable")?;
    let target = store.v70_rollback_target(fresh_prefix);
    target
        .list_journal_keys(
            &format!("{fresh_prefix}/"),
            None,
            0,
            ARCHIVE_OPERATION_TIMEOUT,
        )
        .await
        .map_err(|_| "v70 rollback prefix not fresh")?;
    let (migration, journal_records) = store.load_v70_rollback_inputs(&head, &restored).await?;
    if !matches!(&*store.journal.lock().await, JournalWriterState::Eligible(current) if *current == head)
    {
        return Err("v70 rollback head advanced".into());
    }
    let receipts = ordered_journal_receipts(
        state
            .journal_receipts
            .lock()
            .await
            .as_ref()
            .ok_or("v70 rollback receipts unavailable")?,
    )?;
    let response = seal(RuntimeRequest::SealV70RollbackCheckpoint {
        migration,
        journal_records,
    })
    .await
    .map_err(|error| {
        if frame_oversized(&error) {
            "v70 rollback frame oversized"
        } else {
            "v70 rollback seal transport failed"
        }
    })?;
    let checkpoint = match response {
        RuntimeResponse::CheckpointSealed { checkpoint } => checkpoint,
        RuntimeResponse::Error { code } if code == CHECKPOINT_FRAME_OVERSIZED => {
            return Err("v70 rollback frame oversized".into())
        }
        RuntimeResponse::Error { .. } => return Err("v70 rollback seal rejected".into()),
        _ => return Err("v70 rollback seal unexpected response".into()),
    };
    let (key, pointer, frontier) =
        validate_v70_rollback_checkpoint(&checkpoint, head.sequence, &receipts, fresh_prefix)?;
    let checkpoint_key = target
        .write_v70_rollback_package(&checkpoint, &key, &pointer)
        .await?;
    let package = V70RollbackPackage {
        prefix: fresh_prefix.into(),
        sequence: frontier.sequence,
        state_hash: frontier.state_hash,
        artifact_hash: frontier.artifact_hash,
        checkpoint_key,
    };
    eprintln!(
        "V70_ROLLBACK_PACKAGE_MATERIALIZED sequence={} state_hash={} artifact_hash={}",
        package.sequence, package.state_hash, package.artifact_hash
    );
    Ok((package, guard))
}

/// Test/helper wrapper that intentionally releases the handoff fence after a
/// package is complete. Production uses `start_v70_rollback_handoff` below and
/// retains it until process replacement.
#[cfg_attr(not(test), allow(dead_code))]
async fn materialize_v70_rollback<F, Fut>(
    state: &AppState,
    fresh_prefix: &str,
    seal: F,
) -> Result<V70RollbackPackage, String>
where
    F: FnOnce(RuntimeRequest) -> Fut,
    Fut: Future<Output = io::Result<RuntimeResponse>>,
{
    let (package, guard) = prepare_v70_rollback_handoff(state, fresh_prefix, seal).await?;
    drop(guard);
    Ok(package)
}

/// Explicit local operator hook for the retained-v70 handoff. Merely setting
/// the prefix has no effect on live traffic. SIGUSR2 begins the one-shot
/// capture, and a successful capture intentionally keeps the financial gate
/// until this process is replaced by the rehearsed v70 ASG change. It never
/// stores or replays a pending command.
fn start_v70_rollback_handoff(state: AppState) {
    let Ok(prefix) = env::var("LAYRS_DIRECT_V70_ROLLBACK_PREFIX") else {
        return;
    };
    tokio::spawn(async move {
        let Ok(mut signal) = tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::user_defined2(),
        ) else {
            eprintln!("V70_ROLLBACK_HANDOFF_UNAVAILABLE reason=SIGNAL_REGISTRATION_FAILED");
            return;
        };
        eprintln!("V70_ROLLBACK_HANDOFF_ARMED signal=SIGUSR2");
        if signal.recv().await.is_none() {
            eprintln!("V70_ROLLBACK_HANDOFF_ABORTED reason=SIGNAL_STREAM_CLOSED");
            return;
        }
        if state.effective_persistence_format() != PersistenceFormat::V71 {
            eprintln!("V70_ROLLBACK_HANDOFF_ABORTED reason=V71_NOT_AUTHORITATIVE");
            return;
        }
        eprintln!("V70_ROLLBACK_HANDOFF_STARTED");
        let seal_state = state.clone();
        match prepare_v70_rollback_handoff(&state, &prefix, move |request| {
            let seal_state = seal_state.clone();
            async move {
                exchange_with_timeout(&seal_state, request, CHECKPOINT_EXCHANGE_TIMEOUT).await
            }
        })
        .await
        {
            Ok((package, guard)) => {
                eprintln!(
                    "V70_ROLLBACK_HANDOFF_READY prefix={} sequence={} state_hash={} artifact_hash={} checkpoint_key={}",
                    package.prefix,
                    package.sequence,
                    package.state_hash,
                    package.artifact_hash,
                    package.checkpoint_key
                );
                std::future::pending::<()>().await;
                drop(guard);
            }
            Err(reason) => eprintln!("V70_ROLLBACK_HANDOFF_ABORTED reason={reason}"),
        }
    });
}

fn intent_is_committed(intent: &ExternalEffectIntent, receipts: &[(u64, DirectReceipt)]) -> bool {
    let prefix = format!("{}:", intent.external_effect_reference);
    receipts.iter().any(|(_, receipt)| {
        receipt
            .custody_reference
            .as_deref()
            .is_some_and(|value| value.starts_with(&prefix))
    })
}

fn standard_zen_egress_intent(intent: &ExternalEffectIntent) -> bool {
    intent.request_id.starts_with("zen-egress:")
        && intent.chain == "horizen"
        && intent.asset == "ZEN"
        && intent.zen_destination_chain.is_some()
        && intent.relay.is_none()
}

fn same_external_effect_request(a: &ExternalEffectIntent, b: &ExternalEffectIntent) -> bool {
    a.account_id == b.account_id
        && a.request_id == b.request_id
        && a.identity_commitment == b.identity_commitment
        && a.chain == b.chain
        && a.asset == b.asset
        && a.destination.eq_ignore_ascii_case(&b.destination)
        && a.amount_atomic == b.amount_atomic
        && a.provider_wallet_id == b.provider_wallet_id
        && a.custody_target.eq_ignore_ascii_case(&b.custody_target)
        && a.relay == b.relay
        && a.zen_destination_chain == b.zen_destination_chain
}

/// This is external cash evidence, never a fabricated enclave receipt or a
/// second debit of the already-completed customer request. Stable fields make
/// write-once persistence and restart replay byte-identical.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct ExtraPayoutEvidence {
    protocol_version: String,
    epoch_id: String,
    intent_hash: String,
    original_intent_hash: String,
    original_receipt_id: String,
    original_transaction_hash: String,
    provider_transaction_id: String,
    transaction_hash: String,
    account_id: String,
    request_id: String,
    destination: String,
    chain: String,
    asset: String,
    amount_atomic: String,
    customer_debit_atomic: String,
    disposition: String,
}

fn extra_payout_evidence(intent: &ExternalEffectIntent, original: &ExternalEffectIntent, receipts: &[(u64, DirectReceipt)], outcome: ExternalEffectRecovery) -> io::Result<Option<ExtraPayoutEvidence>> {
    intent.verify().map_err(invalid)?;
    original.verify().map_err(invalid)?;
    if !same_external_effect_request(intent, original) || intent.intent_hash == original.intent_hash || intent.chain != "base" || intent.asset != "USDC" || intent.relay.is_some() || intent.zen_destination_chain.is_some() { return Err(invalid("extra payout binding conflict")); }
    let prefix = format!("{}:", original.external_effect_reference);
    let committed = receipts.iter().map(|(_, receipt)| receipt).find(|receipt| receipt.account_id == original.account_id && receipt.request_id == original.request_id && receipt.request_hash == original.request_hash && receipt.effect == "WITHDRAWAL_SETTLED" && receipt.amount_atomic.as_deref() == Some(original.amount_atomic.as_str()) && receipt.custody_reference.as_deref().is_some_and(|r|r.starts_with(&prefix))).ok_or_else(|| invalid("original payout is not committed"))?;
    let original_hash = committed.custody_reference.as_deref().and_then(|r|r.strip_prefix(&prefix)).filter(|r|valid_transaction_hash(r)).ok_or_else(||invalid("original payout hash invalid"))?;
    let ExternalEffectRecovery::BindFinalized {provider_transaction_id,transaction_hash} = outcome else {return Err(invalid("extra payout is not canonically finalized"));};
    if !valid_transaction_hash(&transaction_hash) { return Err(invalid("extra payout hash invalid")); }
    if original_hash.eq_ignore_ascii_case(&transaction_hash) { return Ok(None); } // Two references to one tx are not two payments.
    Ok(Some(ExtraPayoutEvidence {protocol_version:"layrs.external-extra-payout.v1".into(),epoch_id:EPOCH_ID.into(),intent_hash:intent.intent_hash.clone(),original_intent_hash:original.intent_hash.clone(),original_receipt_id:committed.receipt_id.clone(),original_transaction_hash:original_hash.to_ascii_lowercase(),provider_transaction_id,transaction_hash:transaction_hash.to_ascii_lowercase(),account_id:intent.account_id.clone(),request_id:intent.request_id.clone(),destination:intent.destination.to_ascii_lowercase(),chain:intent.chain.clone(),asset:intent.asset.clone(),amount_atomic:intent.amount_atomic.clone(),customer_debit_atomic:"0".into(),disposition:"PROTOCOL_OVERPAYMENT_UNRECOVERED".into()}))
}

/// Rebase ONLY a confirmed direct Base USDC outcome across an independently
/// verified successor chain with no intervening change to that user's USDC.
/// Unknown roots, gaps, request collisions and balance changes fail closed.
fn historical_intent_lineage_safe(intent: &ExternalEffectIntent, artifacts: &[DirectStateArtifact], current_root: &str) -> bool {
    if intent.chain != "base" || intent.asset != "USDC" || intent.relay.is_some() || intent.zen_destination_chain.is_some() || artifacts.is_empty() || artifacts.last().is_none_or(|a|a.state_hash != current_root) { return false; }
    if artifacts.iter().enumerate().any(|(i,a)|a.epoch_id != EPOCH_ID || a.sequence != i as u64+1 || (i>0 && a.prior_state_hash != artifacts[i-1].state_hash)) { return false; }
    let starts = artifacts.iter().enumerate().filter(|(_,a)|a.prior_state_hash == intent.prior_state_hash).map(|(i,_)|i).collect::<Vec<_>>();
    if starts.len()!=1 { return false; }
    artifacts[starts[0]..].iter().all(|a| {
        !(a.receipt.account_id == intent.account_id && a.receipt.request_id == intent.request_id)
        && !a.receipt.projection_balance_updates.iter().any(|b|b.identity_commitment == intent.identity_commitment && b.asset == intent.asset)
    })
}

fn historical_journal_intent_lineage_safe(
    intent: &ExternalEffectIntent,
    receipts: &[(u64, DirectReceipt)],
    transition_roots: &BTreeMap<u64, String>,
    current_root: &str,
) -> bool {
    if intent.chain != "base"
        || intent.asset != "USDC"
        || intent.relay.is_some()
        || intent.zen_destination_chain.is_some()
    {
        return false;
    }
    let Some((&current_sequence, restored_root)) = transition_roots.last_key_value() else {
        return false;
    };
    if restored_root != current_root
        || receipts.last().map(|(sequence, _)| *sequence) != Some(current_sequence)
        || transition_roots
            .keys()
            .zip(transition_roots.keys().skip(1))
            .any(|(left, right)| left.checked_add(1) != Some(*right))
    {
        return false;
    }
    let starts = transition_roots
        .iter()
        .filter_map(|(sequence, root)| (root == &intent.prior_state_hash).then_some(*sequence))
        .collect::<Vec<_>>();
    if starts.len() != 1 {
        return false;
    }
    receipts
        .iter()
        .filter(|(sequence, _)| *sequence > starts[0])
        .all(|(_, receipt)| {
            !(receipt.account_id == intent.account_id && receipt.request_id == intent.request_id)
                && !receipt.projection_balance_updates.iter().any(|balance| {
                    balance.identity_commitment == intent.identity_commitment
                        && balance.asset == intent.asset
                })
        })
}

fn committed_external_effect_action(
    intents: &[ExternalEffectIntent],
    receipts: &[(u64, DirectReceipt)],
    account_id: &str,
    identity_commitment: &str,
    request_id: &str,
    destination: &str,
    amount_atomic: &str,
    relay_route: Option<&RelayWithdrawalBinding>,
) -> Result<Option<DirectAction>, io::Error> {
    let related = intents
        .iter()
        .filter(|intent| intent.account_id == account_id && intent.request_id == request_id)
        .collect::<Vec<_>>();
    if related.is_empty() {
        return Ok(None);
    }
    if related.iter().any(|intent| {
        intent.identity_commitment != identity_commitment
            || intent.chain != "base"
            || intent.asset != "USDC"
            || !intent.destination.eq_ignore_ascii_case(destination)
            || intent.amount_atomic != amount_atomic
            || intent.relay.as_ref() != relay_route
    }) {
        return Err(invalid("external-effect replay binding conflict"));
    }
    for intent in related {
        let prefix = format!("{}:", intent.external_effect_reference);
        let Some(receipt) = receipts.iter().map(|(_, receipt)| receipt).find(|receipt| {
            receipt.account_id == account_id
                && receipt.identity_commitment == identity_commitment
                && receipt.request_id == request_id
                && receipt.amount_atomic.as_deref() == Some(amount_atomic)
                && receipt
                    .custody_reference
                    .as_deref()
                    .is_some_and(|value| value.starts_with(&prefix))
        }) else {
            continue;
        };
        let custody_reference = receipt
            .custody_reference
            .clone()
            .ok_or_else(|| invalid("committed withdrawal is missing custody binding"))?;
        let action = match (intent.relay.as_ref(), receipt.effect.as_str()) {
            (Some(relay), "WITHDRAWAL_SETTLED") => DirectAction::SettleRelayWithdrawal {
                relay: relay.clone(),
                amount_atomic: amount_atomic.into(),
                custody_reference,
            },
            (Some(relay), "WITHDRAWAL_REVERTED") => DirectAction::RecordRelayWithdrawalReverted {
                relay: relay.clone(),
                amount_atomic: amount_atomic.into(),
                custody_reference,
            },
            (None, "WITHDRAWAL_SETTLED") => DirectAction::ReserveWithdrawal {
                destination: destination.into(),
                amount_atomic: amount_atomic.into(),
                custody_reference,
            },
            (None, "WITHDRAWAL_REVERTED") => DirectAction::RecordWithdrawalReverted {
                destination: destination.into(),
                amount_atomic: amount_atomic.into(),
                custody_reference,
            },
            _ => return Err(invalid("committed external effect has unexpected effect")),
        };
        let mut request = DirectRequest {
            account_id: account_id.into(),
            identity_commitment: identity_commitment.into(),
            request_id: request_id.into(),
            request_hash: String::new(),
            financial_wallet_address: intent
                .relay
                .is_none()
                .then(|| destination.to_ascii_lowercase()),
            action: action.clone(),
        };
        request.request_hash = request_hash(&request);
        if request.request_hash != intent.request_hash
            || request.request_hash != receipt.request_hash
        {
            return Err(invalid("committed external-effect replay hash mismatch"));
        }
        return Ok(Some(action));
    }
    Ok(None)
}

fn direct_action_for_external_effect(
    intent: &ExternalEffectIntent,
    outcome: ExternalEffectRecovery,
) -> Result<DirectAction, io::Error> {
    if let Some(chain)=&intent.zen_destination_chain {
        return match outcome {
            ExternalEffectRecovery::BindFinalized {transaction_hash,..}=>Ok(DirectAction::ReserveZenWithdrawal {destination_chain:chain.clone(),destination:intent.destination.clone(),amount_atomic:intent.amount_atomic.clone(),custody_reference:format!("{}:{transaction_hash}",intent.external_effect_reference)}),
            ExternalEffectRecovery::BindReverted {transaction_hash,..}=>Ok(DirectAction::RecordZenWithdrawalReverted {destination_chain:chain.clone(),destination:intent.destination.clone(),amount_atomic:intent.amount_atomic.clone(),custody_reference:format!("{}:{transaction_hash}",intent.external_effect_reference)}),
            _=>Err(invalid("ZEN external result is not terminal")),
        };
    }
    match (intent.relay.as_ref(), outcome) {
        (
            Some(relay),
            ExternalEffectRecovery::BindRelayFinalized {
                intake_transaction_hash,
                relay_request_id,
                destination_transaction_hash,
                destination_amount_atomic,
                result_hash,
                ..
            },
        ) if relay_request_id.eq_ignore_ascii_case(&relay.request_id)
            && result_hash
                == relay_result_hash(
                    intent,
                    &intake_transaction_hash,
                    &destination_transaction_hash,
                    &destination_amount_atomic,
                )
                .ok_or_else(|| invalid("Relay result binding missing"))? =>
        {
            Ok(DirectAction::SettleRelayWithdrawal {
                relay: relay.clone(),
                amount_atomic: intent.amount_atomic.clone(),
                custody_reference: format!(
                    "{}:relay:{}:{}:{}:{}:{}:{}:{}",
                    intent.external_effect_reference,
                    relay.request_id,
                    relay.destination_chain_id,
                    intake_transaction_hash,
                    destination_transaction_hash,
                    destination_amount_atomic,
                    result_hash,
                    relay.binding_hash(),
                ),
            })
        }
        (
            Some(relay),
            ExternalEffectRecovery::BindRelayReverted {
                intake_transaction_hash,
                relay_request_id,
                terminal_status,
                result_hash,
                ..
            },
        ) if relay_request_id.eq_ignore_ascii_case(&relay.request_id)
            && result_hash
                == relay_reverted_result_hash(
                    relay,
                    &intent.external_effect_reference,
                    &intake_transaction_hash,
                    &terminal_status,
                ) =>
        {
            Ok(DirectAction::RecordRelayWithdrawalReverted {
                relay: relay.clone(),
                amount_atomic: intent.amount_atomic.clone(),
                custody_reference: format!(
                    "{}:relay-reverted:{}:{}:{}:{}:{}:{}",
                    intent.external_effect_reference,
                    relay.request_id,
                    relay.destination_chain_id,
                    intake_transaction_hash,
                    terminal_status,
                    result_hash,
                    relay.binding_hash(),
                ),
            })
        }
        (
            Some(relay),
            ExternalEffectRecovery::BindReverted {
                transaction_hash, ..
            },
        ) => {
            let terminal_status = "failure";
            let result_hash = relay_reverted_result_hash(
                relay,
                &intent.external_effect_reference,
                &transaction_hash,
                terminal_status,
            );
            Ok(DirectAction::RecordRelayWithdrawalReverted {
                relay: relay.clone(),
                amount_atomic: intent.amount_atomic.clone(),
                custody_reference: format!(
                    "{}:relay-reverted:{}:{}:{}:{}:{}:{}",
                    intent.external_effect_reference,
                    relay.request_id,
                    relay.destination_chain_id,
                    transaction_hash,
                    terminal_status,
                    result_hash,
                    relay.binding_hash(),
                ),
            })
        }
        (Some(_), _) => Err(invalid("Relay external-effect result mismatch")),
        (
            None,
            ExternalEffectRecovery::BindFinalized {
                transaction_hash, ..
            },
        ) => Ok(DirectAction::ReserveWithdrawal {
            destination: intent.destination.clone(),
            amount_atomic: intent.amount_atomic.clone(),
            custody_reference: format!("{}:{}", intent.external_effect_reference, transaction_hash),
        }),
        (
            None,
            ExternalEffectRecovery::BindReverted {
                transaction_hash, ..
            },
        ) => Ok(DirectAction::RecordWithdrawalReverted {
            destination: intent.destination.clone(),
            amount_atomic: intent.amount_atomic.clone(),
            custody_reference: format!("{}:{}", intent.external_effect_reference, transaction_hash),
        }),
        (None, _) => Err(invalid("external effect is not terminal")),
    }
}

fn request_for_external_effect(
    intent: &ExternalEffectIntent,
    outcome: ExternalEffectRecovery,
) -> Result<DirectRequest, io::Error> {
    let action = direct_action_for_external_effect(intent, outcome)?;
    let mut request = DirectRequest {
        account_id: intent.account_id.clone(),
        identity_commitment: intent.identity_commitment.clone(),
        request_id: intent.request_id.clone(),
        request_hash: String::new(),
        financial_wallet_address: intent
            .relay
            .is_none()
            .then(|| intent.destination.to_ascii_lowercase()),
        action,
    };
    request.request_hash = request_hash(&request);
    if request.request_hash != intent.request_hash {
        return Err(invalid("external-effect request binding mismatch"));
    }
    Ok(request)
}

fn validate_usdc_pre_payout_balance(balance: &RuntimeResponse, requested: &str) -> Result<(), (StatusCode, &'static str)> {
    let requested = requested.parse::<u128>().ok().filter(|v| *v > 0)
        .ok_or((StatusCode::BAD_REQUEST, "WITHDRAWAL_AMOUNT_INVALID"))?;
    let RuntimeResponse::Balance { amount_atomic } = balance else {
        return Err((StatusCode::SERVICE_UNAVAILABLE, "USDC_BALANCE_UNAVAILABLE"));
    };
    let available = amount_atomic.parse::<u128>()
        .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "USDC_BALANCE_UNAVAILABLE"))?;
    if available < requested { return Err((StatusCode::UNPROCESSABLE_ENTITY, "INSUFFICIENT_AVAILABLE")); }
    Ok(())
}

fn start_base_withdrawal_observer(state: AppState) {
    if state.isolated_test || state.custody.is_none() { return; }
    tokio::spawn(async move {
        let mut timer = tokio::time::interval(std::time::Duration::from_secs(5));
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            timer.tick().await;
            if state.unresolved_external_effects.lock().await.is_empty() { continue; }
            let guard = state.financial_gate.lock("withdrawal_observer").await;
            let pending: Vec<_> = state.unresolved_external_effects.lock().await.values()
                .filter(|i| base_withdrawal_observation_supported(i))
                .cloned().collect();
            for intent in pending {
                eprintln!("FINANCIAL_AWAIT_BEGIN stage=withdrawal_observation");
                if reconcile_observed_base_withdrawal(&state, &intent, &guard).await.is_err() {
                    // Stable trace/code only; never raw provider bodies or keys.
                    eprintln!("WITHDRAWAL_OBSERVATION_PENDING request_id={} intent_hash={}", intent.request_id, intent.intent_hash);
                }
                eprintln!("FINANCIAL_AWAIT_END stage=withdrawal_observation");
            }
        }
    });
}

fn base_withdrawal_observation_supported(intent: &ExternalEffectIntent) -> bool {
    // Relay intake is a Base pool effect too. Excluding it left the global
    // fence stuck after a delayed destination result, until owner retry/boot.
    intent.chain == "base" && intent.asset == "USDC"
}

fn validate_new_withdrawal_route(relay: Option<&RelayWithdrawalBinding>) -> Result<(), (StatusCode, &'static str)> {
    // Loading the existing provider credential for historical observation must
    // not reopen the retired route. Original intent recovery/replay precedes
    // this guard; no fresh Relay quote, intent, nonce or payout is permitted.
    if relay.is_some() { return Err((StatusCode::GONE, "RELAY_ROUTE_RETIRED")); }
    Ok(())
}

fn observed_terminal_recovery(outcome: ExternalEffectRecovery) -> Result<ExternalEffectRecovery, String> {
    match outcome {
        terminal @ (ExternalEffectRecovery::BindFinalized { .. } | ExternalEffectRecovery::BindReverted { .. }
            | ExternalEffectRecovery::BindRelayFinalized { .. }) => Ok(terminal),
        // A provider refund/failure label does not prove that paid principal
        // was returned or exclude late delivery. Retired Relay recovery must
        // remain fenced until independently certified refund evidence exists.
        _ => Err("historical custody effect is not authoritatively terminal".into()),
    }
}

async fn reconcile_observed_base_withdrawal(state: &AppState, intent: &ExternalEffectIntent, guard: &OwnedMutexGuard<()>) -> io::Result<()> {
    let custody = state.custody.as_ref().ok_or_else(|| invalid("Base custody unavailable"))?;
    // Unlike settle(), this cannot call submit_once even if the index is absent.
    let outcome = custody.observe_terminal_only(intent).await.map_err(invalid)?;
    let request = request_for_external_effect(intent, outcome)?;
    let RuntimeResponse::Execute { result } = exchange_direct(state, request, guard).await? else {
        return Err(invalid("withdrawal observation execution unavailable"));
    };
    if result.receipt.account_id != intent.account_id || result.receipt.identity_commitment != intent.identity_commitment
        || result.receipt.request_id != intent.request_id || result.receipt.amount_atomic.as_deref() != Some(intent.amount_atomic.as_str())
        || !matches!(result.receipt.effect.as_str(), "WITHDRAWAL_SETTLED" | "WITHDRAWAL_REVERTED")
        || result.receipt.status != layrs_direct_execution_v1::TerminalStatus::Applied {
        return Err(invalid("withdrawal observation receipt conflict"));
    }
    let projection = state.projection.as_ref().ok_or_else(|| invalid("withdrawal observation projection unavailable"))?;
    record_result_with_retry(projection, state, &result)
        .await
        .map_err(|_| invalid("withdrawal observation projection failed"))?;
    // Remove the gate only AFTER the genuine receipt and atomic projection.
    state.unresolved_external_effects.lock().await.remove(&intent.intent_hash);
    eprintln!("WITHDRAWAL_OBSERVATION_SETTLED request_id={} intent_hash={} receipt_id={}", intent.request_id, intent.intent_hash, result.receipt.receipt_id);
    Ok(())
}

async fn recover_external_effect_intents(state: &AppState) -> io::Result<()> {
    let Some(store) = state.artifact_store.as_ref() else {
        return Ok(());
    };
    let intents = store
        .load_intents()
        .await
        .map_err(|error| invalid(format!("external-effect intent recovery failed:{error}")))?;
    if intents.is_empty() {
        return Ok(());
    }
    let receipts = store
        .committed_receipts(state)
        .await
        .map_err(|error| invalid(format!("direct receipt recovery failed:{error}")))?;
    let transition_roots = state.journal_transition_roots.lock().await.clone();
    let artifacts = if transition_roots.is_none() {
        Some(
            store
                .load_committed()
                .await
                .map_err(|error| invalid(format!("direct artifact recovery failed:{error}")))?,
        )
    } else {
        None
    };
    // Recovery may publish terminal journal records and checkpoint capture
    // reads these same caches. Hold one gate for the complete pass so neither
    // a torn cache view nor a checkpoint past an unresolved intent is visible.
    // Startup has not begun serving requests yet, so this introduces no live
    // request contention.
    let guard = state.financial_gate.lock("external_effect_recovery").await;
    for intent in intents.iter().cloned() {
        // Standard ZEN egress is recovered by the withdrawal worker against
        // the original held withdrawal operation. Its immutable provider
        // intent uses a separate request id and must never be replayed as the
        // retired legacy withdrawal command or enter that global fence.
        if standard_zen_egress_intent(&intent) {
            continue;
        }
        if intent_is_committed(&intent, &receipts) {
            continue;
        }
        if let Some(committed_sibling) = intents.iter().find(|candidate| {
            candidate.account_id == intent.account_id
                && candidate.request_id == intent.request_id
                && intent_is_committed(candidate, &receipts)
        }) {
            if same_external_effect_request(&intent, committed_sibling) {
                // A second intent is NOT proof that it remained unsubmitted.
                // Observe canonical finality without any submission capability.
                let custody = state.custody.as_ref().ok_or_else(|| invalid("duplicate custody effect cannot be verified"))?;
                custody.validate_intent(&intent).map_err(invalid)?;
                let observation = custody.observe(&intent).await.map_err(invalid)?;
                match observation {
                    layrs_direct_execution_v1::ExternalEffectObservation::NotFound => return Err(invalid("duplicate custody reference is missing; no-effect cannot be assumed")),
                    finalized @ layrs_direct_execution_v1::ExternalEffectObservation::Finalized { .. } => {
                        let terminal = intent.recovery_action(now_unix(), finalized);
                        if let Some(evidence) = extra_payout_evidence(&intent, committed_sibling, &receipts, terminal)? {
                            store.persist_extra_payout(&evidence).await.map_err(invalid)?;
                            state.projection.as_ref().ok_or_else(|| invalid("extra payout projection unavailable"))?.record_extra_payout(&evidence).await.map_err(|_|invalid("extra payout projection reconciliation failed"))?;
                            eprintln!("VERIFIED_EXTRA_PAYOUT_RECONCILED {} customer_debit=0", evidence.intent_hash);
                        }
                    }
                    layrs_direct_execution_v1::ExternalEffectObservation::Reverted { .. } => {}, // Canonical revert: no principal payout.
                    _ => return Err(invalid("duplicate custody effect remains ambiguous")),
                }
                continue;
            }
            return Err(invalid(
                "conflicting external-effect intent follows a committed request",
            ));
        }
        let root = state.committed_state_root.lock().await.clone();
        let historical = root.as_deref() != Some(intent.prior_state_hash.as_str());
        let historical_lineage_safe = root.as_deref().is_some_and(|root| {
            match (&transition_roots, &artifacts) {
                (Some(roots), _) => {
                    historical_journal_intent_lineage_safe(&intent, &receipts, roots, root)
                }
                (None, Some(artifacts)) => {
                    historical_intent_lineage_safe(&intent, artifacts, root)
                }
                (None, None) => false,
            }
        });
        if historical && !historical_lineage_safe {
            return Err(invalid(
                "unresolved external-effect intent does not match committed lineage",
            ));
        }
        let settled = if historical || intent.relay.is_some() {
            // Retired Relay observation, including an intent at the current
            // tip, cannot rebroadcast, even inside an old provider
            // idempotency window. Only an existing canonical result can bind.
            match &state.custody {Some(custody)=>Some(custody.observe_terminal_only(&intent).await),None=>None}
        } else if intent.asset == "ZEN" {
            match &state.zen_custody {Some(custody)=>Some(custody.settle(&intent,now_unix()).await),None=>None}
        } else {match &state.custody {Some(custody)=>Some(custody.settle(&intent,now_unix()).await),None=>None}};
        let Some(settled) = settled else {
            state
                .unresolved_external_effects
                .lock()
                .await
                .insert(intent.intent_hash.clone(), intent);
            continue;
        };
        match settled.map_err(invalid)? {
            terminal @ (ExternalEffectRecovery::BindFinalized { .. }
            | ExternalEffectRecovery::BindReverted { .. }
            | ExternalEffectRecovery::BindRelayFinalized { .. }
            | ExternalEffectRecovery::BindRelayReverted { .. }) => {
                let request = request_for_external_effect(&intent, terminal)?;
                let response = exchange_direct(state, request, &guard).await?;
                let RuntimeResponse::Execute { result } = response else {
                    return Err(invalid("external-effect recovery execution failed"));
                };
                if let Some(projection) = &state.projection {
                    record_result_with_retry(projection, state, &result).await.map_err(|_| {
                        invalid("projection unavailable during external-effect recovery")
                    })?;
                }
                if historical { eprintln!("VERIFIED_HISTORICAL_WITHDRAWAL_RECONCILED {}", intent.intent_hash); }
            }
            ExternalEffectRecovery::AwaitExternalFinality
            | ExternalEffectRecovery::SubmitWithStableReference
            | ExternalEffectRecovery::FailClosed => {
                state
                    .unresolved_external_effects
                    .lock()
                    .await
                    .insert(intent.intent_hash.clone(), intent);
            }
        }
    }
    Ok(())
}

fn missing_projected_receipts(
    records: &[DirectStateArtifact],
    existing: &[DirectReceipt],
) -> Result<Vec<DirectReceipt>, ProjectionError> {
    verify_projected_receipt_lineage(records, existing)?;
    let present: HashSet<&str> = existing
        .iter()
        .map(|receipt| receipt.receipt_id.as_str())
        .collect();
    Ok(records
        .iter()
        .filter(|record| !present.contains(record.receipt.receipt_id.as_str()))
        .map(|record| record.receipt.clone())
        .collect())
}

fn missing_projected_journal_receipts(
    records: &JournalReceiptCache,
    existing: &[DirectReceipt],
) -> Result<Vec<DirectReceipt>, ProjectionError> {
    let ordered = ordered_journal_receipts(records).map_err(|_| ProjectionError::Database)?;
    let by_id = ordered
        .iter()
        .map(|(_, receipt)| (receipt.receipt_id.as_str(), receipt))
        .collect::<HashMap<_, _>>();
    if by_id.len() != ordered.len()
        || existing
            .iter()
            .any(|receipt| by_id.get(receipt.receipt_id.as_str()).copied() != Some(receipt))
    {
        return Err(ProjectionError::Database);
    }
    let present = existing
        .iter()
        .map(|receipt| receipt.receipt_id.as_str())
        .collect::<HashSet<_>>();
    Ok(ordered
        .into_iter()
        .filter(|(_, receipt)| !present.contains(receipt.receipt_id.as_str()))
        .map(|(_, receipt)| receipt)
        .collect())
}

/// Rebuild only missing disposable receipt projections from the verified,
/// immutable archive. Existing rows must first be proven to be an exact
/// subset of that lineage; conflicting or extra PostgreSQL history still
/// fails closed.
async fn reconcile_projection_from_archive(state: &AppState) -> io::Result<usize> {
    let Some(projection) = &state.projection else {
        return Ok(0);
    };
    let rows = projection
        .client
        .lock()
        .await
        .query(
            "SELECT receipt_json::text FROM direct_execution_receipts WHERE epoch_id=$1",
            &[&EPOCH_ID],
        )
        .await
        .map_err(|_| invalid("projection receipt reconciliation query failed"))?;
    let existing: Vec<DirectReceipt> = rows
        .into_iter()
        .map(|row| {
            let encoded: String = row.get(0);
            serde_json::from_str(&encoded)
                .map_err(|_| invalid("projection receipt is malformed"))
        })
        .collect::<io::Result<_>>()?;
    let missing = if state.effective_persistence_format() == PersistenceFormat::V71
        && state.journal_receipts.lock().await.is_some()
    {
        let records = state.journal_receipts.lock().await;
        missing_projected_journal_receipts(
            records.as_ref().ok_or_else(|| invalid("projection journal unavailable"))?,
            &existing,
        )
    } else {
        let records = state
            .artifact_store
            .as_ref()
            .ok_or_else(|| invalid("projection archive unavailable"))?
            .load_committed()
            .await
            .map_err(invalid)?;
        missing_projected_receipts(&records, &existing)
    }
    .map_err(|_| {
        invalid("projection receipt exceeds or conflicts with recovered immutable history")
    })?;
    for receipt in &missing {
        let result = DirectResult {
            status: receipt.status.clone(),
            effect: receipt.effect.clone(),
            genesis_ordinal: receipt.genesis_ordinal,
            receipt: receipt.clone(),
        };
        record_result_with_retry(projection, state, &result)
            .await
            .map_err(|_| invalid("projection archive replay failed"))?;
    }
    eprintln!("PROJECTION_RECONCILED n={}", missing.len());
    Ok(missing.len())
}

/// Compare the disposable PostgreSQL projection with the private state only
/// after the enclave has recovered the authoritative encrypted lineage.
async fn verify_recovered_projection(state: &AppState) -> io::Result<()> {
    let Some(projection) = &state.projection else {
        return Ok(());
    };
    let rows = projection
        .client
        .lock().await
        .query(
            "SELECT auth_subject_hash, identity_commitment, asset, bucket, amount_atomic::text FROM direct_execution_epoch_balances WHERE epoch_id=$1 ORDER BY identity_commitment,asset,bucket",
            &[&EPOCH_ID],
        )
        .await
        .map_err(|_| invalid("projection reconciliation query failed"))?;
    let mut projected_keys = HashSet::new();
    for row in rows {
        let account_id: String = row.get(0);
        let identity_commitment: String = row.get(1);
        let asset: String = row.get(2);
        let bucket: String = row.get(3);
        let expected: String = row.get(4);
        projected_keys.insert(format!("{identity_commitment}\0{asset}\0{bucket}"));
        match exchange(
            state,
            RuntimeRequest::Balance {
                account_id,
                identity_commitment,
                asset,
                bucket,
            },
        )
        .await?
        {
            RuntimeResponse::Balance { amount_atomic } if amount_atomic == expected => {}
            _ => return Err(invalid("projection does not match recovered private state")),
        }
    }
    let receipts = projection
        .client
        .lock().await
        .query(
            "SELECT receipt_json::text FROM direct_execution_receipts WHERE epoch_id=$1",
            &[&EPOCH_ID],
        )
        .await
        .map_err(|_| invalid("projection receipt reconciliation query failed"))?;
    let records = state.artifact_store.as_ref().ok_or_else(|| invalid("projection archive unavailable"))?.committed_receipts(state).await.map_err(invalid)?;
    let receipts: Vec<DirectReceipt> = receipts.into_iter().map(|row| {
        let encoded: String = row.get(0);
        serde_json::from_str(&encoded).map_err(|_| invalid("projection receipt is malformed"))
    }).collect::<io::Result<_>>()?;
    if let Err(_) = verify_committed_receipt_lineage(&records, &receipts) {
        // Name the first offending receipt so an operator can tell "another
        // writer kept committing after this restore listed the archive" from
        // a genuinely corrupt projection without querying the database.
        let known: HashSet<&str> = records.iter().map(|(_, receipt)| receipt.receipt_id.as_str()).collect();
        if let Some(extra) = receipts.iter().find(|receipt| !known.contains(receipt.receipt_id.as_str())) {
            eprintln!(
                "PROJECTION_LINEAGE_CONFLICT receipt_id={} request_id={} effect={}",
                extra.receipt_id, extra.request_id, extra.effect
            );
        } else {
            eprintln!("PROJECTION_LINEAGE_CONFLICT reason=receipt_content_differs");
        }
        return Err(invalid("projection receipt exceeds or conflicts with recovered immutable history"));
    }
    for receipt in receipts {
        for update in receipt.projection_balance_updates {
            let key = format!(
                "{}\0{}\0{}",
                update.identity_commitment, update.asset, update.bucket
            );
            if !projected_keys.contains(&key) {
                return Err(invalid("projection is missing a committed balance row"));
            }
        }
    }
    // Legacy rows have no ordering metadata. Stamp only after every amount
    // was independently compared with the recovered private state above.
    // This changes no financial amount and prevents an old first-time retry
    // from overwriting a newer, already-reconciled projection.
    let sequence = records.last().map_or(0, |(sequence, _)| *sequence);
    let sequence = i64::try_from(sequence).map_err(|_| invalid("projection sequence overflow"))?;
    let invalid_frontier = projection.client.lock().await.query_one(
        "SELECT EXISTS (SELECT 1 FROM direct_execution_epoch_balances WHERE epoch_id=$1 AND (projection_sequence<0 OR projection_sequence>$2))", &[&EPOCH_ID, &sequence]
    ).await.map_err(|_| invalid("projection ordering verification failed"))?;
    if invalid_frontier.get::<_, bool>(0) { return Err(invalid("projection ordering exceeds recovered private state")); }
    projection.client.lock().await.execute(
        "UPDATE direct_execution_epoch_balances SET projection_sequence=$2 WHERE epoch_id=$1 AND projection_sequence<$2", &[&EPOCH_ID, &sequence]
    ).await.map_err(|_| invalid("projection ordering initialization failed"))?;
    Ok(())
}

async fn bootstrap_isolated_enclave(state: &AppState) -> io::Result<()> {
    if !state.isolated_test {
        return Ok(());
    }
    let receipt_key = env::var("LAYRS_DIRECT_RECEIPT_KEY_HEX")
        .ok()
        .and_then(|value| hex::decode(value).ok())
        .filter(|value| value.len() == 32)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "DIRECT_RECEIPT_KEY_NOT_CONFIGURED",
            )
        })?;
    let state_key = env::var("LAYRS_DIRECT_STATE_KEY_HEX")
        .ok()
        .and_then(|value| hex::decode(value).ok())
        .filter(|value| value.len() == 32)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "DIRECT_STATE_KEY_NOT_CONFIGURED",
            )
        })?;
    if state.commit_ack_key.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "DIRECT_COMMIT_ACK_KEY_NOT_CONFIGURED",
        ));
    }
    match exchange(
        state,
        RuntimeRequest::BootstrapIsolated {
            receipt_key,
            state_key,
            commit_ack_key: state.commit_ack_key.clone(),
        },
    )
    .await?
    {
        RuntimeResponse::BootstrapComplete => Ok(()),
        RuntimeResponse::Error { code } => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("ISOLATED_BOOTSTRAP_FAILED:{code}"),
        )),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ISOLATED_BOOTSTRAP_UNEXPECTED_RESPONSE",
        )),
    }
}

async fn bootstrap_governed_enclave(state: &AppState) -> io::Result<()> {
    let Some(config) = &state.governed_bootstrap else {
        return Ok(());
    };
    if state.commit_ack_key.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "DIRECT_COMMIT_ACK_KEY_NOT_CONFIGURED",
        ));
    }
    let expected_commitment = config.grant.commitment();
    let begin = exchange(
        state,
        RuntimeRequest::BeginGovernedBootstrap {
            grant: config.grant.clone(),
            binding: config.binding.clone(),
            kms_key_id: config.kms_key_id.clone(),
            requested_mode: config.requested_mode.clone(),
        },
    )
    .await?;
    if matches!(begin, RuntimeResponse::Error { ref code } if code == "WRITER_GRANT_REPLAY") {
        return match exchange(state, RuntimeRequest::Status).await? {
            RuntimeResponse::Status { status }
                if governed_bootstrap_status_matches(
                    &status,
                    &expected_commitment,
                    &config.requested_mode,
                ) =>
            {
                Ok(())
            }
            _ => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "GOVERNED_BOOTSTRAP_REPLAY_MISMATCH",
            )),
        };
    }
    let RuntimeResponse::GovernedKeyRecipient {
        attestation_document,
        writer_grant_commitment,
        kms_key_id,
        encryption_context,
    } = begin
    else {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "GOVERNED_BOOTSTRAP_BEGIN_FAILED",
        ));
    };
    if writer_grant_commitment != expected_commitment
        || kms_key_id != config.kms_key_id
        || attestation_document.is_empty()
        || encryption_context
            .get("layrs-writer-grant")
            .map(String::as_str)
            != Some(expected_commitment.as_str())
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "GOVERNED_BOOTSTRAP_RECIPIENT_MISMATCH",
        ));
    }
    let store = state.artifact_store.as_ref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "DIRECT_ARTIFACT_STORE_NOT_CONFIGURED",
        )
    })?;
    let aws = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let kms = KmsClient::new(&aws);
    let recipient = RecipientInfo::builder()
        .key_encryption_algorithm(KeyEncryptionMechanism::RsaesOaepSha256)
        .attestation_document(KmsBlob::new(attestation_document))
        .build();
    let encryption_context_map: std::collections::HashMap<String, String> =
        encryption_context.clone().into_iter().collect();
    let (artifact, ciphertext_for_recipient) = match store
        .load_key_release(&config.grant.activation_id)
        .await
        .map_err(invalid)?
    {
        Some(artifact) => {
            if !artifact.verify_for(&config.grant, &config.binding, &config.kms_key_id) {
                return Err(invalid("KEY_RELEASE_ARTIFACT_INVALID"));
            }
            let output = kms
                .decrypt()
                .key_id(&config.kms_key_id)
                .ciphertext_blob(KmsBlob::new(artifact.ciphertext_blob.clone()))
                .set_encryption_context(Some(encryption_context_map.clone()))
                .recipient(recipient)
                .send()
                .await
                .map_err(|_| invalid("KMS_ATTESTED_KEY_RELEASE_FAILED"))?;
            if output.plaintext().is_some() {
                return Err(invalid("KMS_RETURNED_PARENT_PLAINTEXT"));
            }
            let ciphertext = output
                .ciphertext_for_recipient()
                .ok_or_else(|| invalid("KMS_RECIPIENT_CIPHERTEXT_MISSING"))?
                .as_ref()
                .to_vec();
            (artifact, ciphertext)
        }
        None => {
            let (ciphertext_blob, ciphertext_for_recipient) = if let Some(predecessor) =
                &config.grant.key_release_predecessor
            {
                let predecessor_artifact = store
                    .load_key_release(&predecessor.activation_id)
                    .await
                    .map_err(invalid)?
                    .ok_or_else(|| invalid("KEY_RELEASE_PREDECESSOR_MISSING"))?;
                if !predecessor_artifact.verify_as_predecessor(predecessor, &config.kms_key_id) {
                    return Err(invalid("KEY_RELEASE_PREDECESSOR_INVALID"));
                }
                let source_context: std::collections::HashMap<String, String> =
                    predecessor_artifact
                        .encryption_context
                        .clone()
                        .into_iter()
                        .collect();
                // KMS changes only the authenticated encryption context of
                // the same enclave root key. The parent receives no
                // plaintext and the signed grant binds the exact immutable
                // predecessor artifact and commitment.
                let reencrypted = kms
                    .re_encrypt()
                    .ciphertext_blob(KmsBlob::new(predecessor_artifact.ciphertext_blob.clone()))
                    .source_key_id(&config.kms_key_id)
                    .destination_key_id(&config.kms_key_id)
                    .set_source_encryption_context(Some(source_context))
                    .set_destination_encryption_context(Some(encryption_context_map.clone()))
                    .send()
                    .await
                    .map_err(|_| invalid("KMS_KEY_CONTINUITY_REENCRYPT_FAILED"))?;
                let ciphertext_blob = reencrypted
                    .ciphertext_blob()
                    .ok_or_else(|| invalid("KMS_REENCRYPTED_BLOB_MISSING"))?
                    .as_ref()
                    .to_vec();
                let released = kms
                    .decrypt()
                    .key_id(&config.kms_key_id)
                    .ciphertext_blob(KmsBlob::new(ciphertext_blob.clone()))
                    .set_encryption_context(Some(encryption_context_map.clone()))
                    .recipient(recipient)
                    .send()
                    .await
                    .map_err(|_| invalid("KMS_ATTESTED_KEY_RELEASE_FAILED"))?;
                if released.plaintext().is_some() {
                    return Err(invalid("KMS_RETURNED_PARENT_PLAINTEXT"));
                }
                let ciphertext_for_recipient = released
                    .ciphertext_for_recipient()
                    .ok_or_else(|| invalid("KMS_RECIPIENT_CIPHERTEXT_MISSING"))?
                    .as_ref()
                    .to_vec();
                (ciphertext_blob, ciphertext_for_recipient)
            } else {
                let output = kms
                    .generate_data_key()
                    .key_id(&config.kms_key_id)
                    .key_spec(DataKeySpec::Aes256)
                    .set_encryption_context(Some(encryption_context_map.clone()))
                    .recipient(recipient)
                    .send()
                    .await
                    .map_err(|_| invalid("KMS_ATTESTED_DATA_KEY_FAILED"))?;
                if output.plaintext().is_some() {
                    return Err(invalid("KMS_RETURNED_PARENT_PLAINTEXT"));
                }
                let ciphertext_blob = output
                    .ciphertext_blob()
                    .ok_or_else(|| invalid("KMS_CIPHERTEXT_BLOB_MISSING"))?
                    .as_ref()
                    .to_vec();
                let ciphertext_for_recipient = output
                    .ciphertext_for_recipient()
                    .ok_or_else(|| invalid("KMS_RECIPIENT_CIPHERTEXT_MISSING"))?
                    .as_ref()
                    .to_vec();
                (ciphertext_blob, ciphertext_for_recipient)
            };
            let artifact = GovernedKeyReleaseArtifact {
                protocol: "layrs.direct-execution.key-release.v1".into(),
                activation_id: config.grant.activation_id.clone(),
                writer_grant_commitment: expected_commitment.clone(),
                runtime_measurement: config.binding.clone(),
                kms_key_id: config.kms_key_id.clone(),
                encryption_context: encryption_context.clone(),
                ciphertext_blob,
            };
            if !artifact.verify_for(&config.grant, &config.binding, &config.kms_key_id) {
                return Err(invalid("KEY_RELEASE_ARTIFACT_INVALID"));
            }
            let artifact = store
                .persist_key_release(&artifact)
                .await
                .map_err(invalid)?;
            (artifact, ciphertext_for_recipient)
        }
    };
    let artifact_hash = artifact.artifact_hash();
    match exchange(
        state,
        RuntimeRequest::CompleteGovernedBootstrap {
            writer_grant_commitment: expected_commitment.clone(),
            key_release_artifact_hash: artifact_hash,
            ciphertext_for_recipient,
            commit_ack_key: state.commit_ack_key.clone(),
        },
    )
    .await?
    {
        RuntimeResponse::GovernedBootstrapComplete {
            writer_grant_commitment,
        } if writer_grant_commitment == expected_commitment => Ok(()),
        RuntimeResponse::Error { code } => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("GOVERNED_BOOTSTRAP_FAILED:{code}"),
        )),
        _ => Err(invalid("GOVERNED_BOOTSTRAP_UNEXPECTED_RESPONSE")),
    }
}

fn governed_bootstrap_status_matches(
    status: &layrs_direct_execution_v1::RuntimeBinding,
    expected_commitment: &str,
    requested_mode: &str,
) -> bool {
    status.writer_grant_commitment.as_deref() == Some(expected_commitment)
        && ((requested_mode == "production-enabled" && status.writer_enabled)
            || (requested_mode == "admission-enabled"
                && status.admission_enabled
                && !status.writer_enabled))
}

/// One bounded direct request.  The first response is deliberately not a
/// customer result: it is an opaque encrypted successor that must be stored
/// immutably and read back before this parent can issue an acknowledgement.
async fn exchange_direct(
    state: &AppState,
    request: DirectRequest,
    guard: &OwnedMutexGuard<()>,
) -> io::Result<RuntimeResponse> {
    match state.effective_persistence_format() {
        PersistenceFormat::V70 | PersistenceFormat::V70RollbackBaseline => {
            exchange_direct_v70(state, request, guard).await
        }
        PersistenceFormat::V71 => exchange_direct_v71(state, request, guard).await,
        PersistenceFormat::V71Hot => unreachable!("effective persistence format is concrete"),
    }
}

async fn exchange_direct_v70(
    state: &AppState,
    request: DirectRequest,
    _guard: &OwnedMutexGuard<()>,
) -> io::Result<RuntimeResponse> {
    let store = state.artifact_store.as_ref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "DIRECT_ARTIFACT_STORE_NOT_CONFIGURED",
        )
    })?;
    if state.commit_ack_key.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "DIRECT_COMMIT_ACK_KEY_NOT_CONFIGURED",
        ));
    }
    eprintln!("FINANCIAL_AWAIT_BEGIN stage=enclave_candidate");
    let (mut stream, first) = bounded_enclave_stage(ENCLOSURE_EXCHANGE_TIMEOUT, async {
        let mut stream =
            VsockStream::connect(VsockAddr::new(state.enclave_cid, ENCLOSURE_PORT)).await?;
        write_frame(
            &mut stream,
            &serde_cbor::to_vec(&RuntimeRequest::Execute { request }).map_err(invalid)?,
        )
        .await?;
        let first: RuntimeResponse =
            serde_cbor::from_slice(&read_frame(&mut stream).await?).map_err(invalid)?;
        Ok::<_, io::Error>((stream, first))
    })
    .await?;
    eprintln!("FINANCIAL_AWAIT_END stage=enclave_candidate");
    let response = match first {
        RuntimeResponse::CommitCandidate { artifact } => {
        // `persist_readback` uses create_new, fsyncs the write, rereads the
        // opaque bytes, decodes them, and compares the complete artifact plus
        // its CBOR hash before this acknowledgement exists.
        eprintln!("FINANCIAL_AWAIT_BEGIN stage=archive_persist_readback");
        let restored = store.persist_readback(&artifact).await.map_err(|error| {
            let code = if error == "ARCHIVE_TIMEOUT" {
                "ARCHIVE_TIMEOUT".to_string()
            } else {
                format!("IMMUTABLE_PERSISTENCE_FAILED:{error}")
            };
            io::Error::new(
                io::ErrorKind::Other,
                code,
            )
        })?;
        eprintln!("FINANCIAL_AWAIT_END stage=archive_persist_readback");
        if restored != artifact {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ARTIFACT_READBACK_MISMATCH",
            ));
        }
        let ack = DurabilityAck::issue(&restored, &state.commit_ack_key);
        eprintln!("FINANCIAL_AWAIT_BEGIN stage=enclave_durability_ack");
        let terminal = bounded_enclave_stage(ENCLOSURE_EXCHANGE_TIMEOUT, async {
            write_frame(
                &mut stream,
                &serde_cbor::to_vec(&RuntimeRequest::DurabilityAck { ack }).map_err(invalid)?,
            )
            .await?;
            serde_cbor::from_slice(&read_frame(&mut stream).await?).map_err(invalid)
        })
        .await?;
        eprintln!("FINANCIAL_AWAIT_END stage=enclave_durability_ack");
        if matches!(terminal, RuntimeResponse::Execute { .. }) {
            *state.committed_state_root.lock().await = Some(restored.state_hash.clone());
            state.last_commit_at.store(now_unix(), Ordering::Release);
        }
        terminal
        }
        other => other,
    };
    if matches!(response, RuntimeResponse::Execute { .. }) {
        if let ArchiveStore::S3(store) = store {
            // This effect already committed: a checkpoint failure must not
            // turn success into permission for another financial submission.
            // Coalesce concurrent refreshes, and never hold the committed
            // financial response hostage to optional checkpoint storage.
            if store.checkpoint_refresh_gate.lock().await.request() {
                let store = store.clone(); let state = state.clone();
                tokio::spawn(async move {
                    let (store, state) = (&store, &state);
                    refresh_checkpoints(&store.checkpoint_refresh_gate, move || store.seal_current_checkpoint_serialized(state)).await;
                });
            }
        }
    }
    Ok(response)
}

fn terminal_leaf_matches_record(
    leaf: &TerminalRequestLeaf,
    record: &DirectJournalRecord,
) -> bool {
    leaf.account_id == record.account_id
        && leaf.request_id == record.request_id
        && leaf.request_hash == record.request_hash
        && leaf.result_hash == record.result_hash
        && leaf.receipt_hash == record.receipt_hash
        && leaf.locator
            == (TerminalResultLocator::Journal {
                writer_epoch: record.writer_epoch.clone(),
                sequence: record.sequence,
            })
}

fn terminal_leaf_matches_migrated_record(
    leaf: &TerminalRequestLeaf,
    record: &MigratedTerminalRecord,
) -> bool {
    leaf.account_id == record.account_id
        && leaf.request_id == record.request_id
        && leaf.request_hash == record.request_hash
        && leaf.result_hash == record.result_hash
        && leaf.receipt_hash == record.receipt_hash
        && leaf.locator
            == (TerminalResultLocator::Migration {
                migration_id: record.migration_id.clone(),
                ordinal: record.ordinal,
            })
}

fn terminal_result_matches_leaf(result: &DirectResult, leaf: &TerminalRequestLeaf) -> bool {
    canonical_result_hash(result).is_ok_and(|hash| hash == leaf.result_hash)
        && canonical_receipt_hash(result).is_ok_and(|hash| hash == leaf.receipt_hash)
        && result.receipt.account_id == leaf.account_id
        && result.receipt.request_id == leaf.request_id
        && result.receipt.request_hash == leaf.request_hash
}

async fn archived_terminal_for_leaf(
    state: &AppState,
    store: &S3ImmutableArtifactStore,
    leaf: &TerminalRequestLeaf,
) -> Result<ArchivedTerminalRecord, String> {
    match &leaf.locator {
        TerminalResultLocator::Migration {
            migration_id,
            ordinal,
        } => {
            let migration = state.journal_migration.lock().await;
            let bundle = migration
                .as_ref()
                .ok_or("journal migration bundle unrestored")?;
            if bundle.manifest.migration_id != *migration_id {
                return Err("journal migration locator mismatch".into());
            }
            let index = ordinal
                .checked_sub(1)
                .and_then(|value| usize::try_from(value).ok())
                .ok_or("journal migration ordinal invalid")?;
            let record = bundle
                .records
                .get(index)
                .filter(|record| terminal_leaf_matches_migrated_record(leaf, record))
                .ok_or("journal migration record mismatch")?
                .clone();
            Ok(ArchivedTerminalRecord::Migration { record })
        }
        TerminalResultLocator::Journal {
            writer_epoch,
            sequence,
        } => {
            let record = store.load_journal_record(*sequence).await?;
            if record.writer_epoch != *writer_epoch || !terminal_leaf_matches_record(leaf, &record)
            {
                return Err("journal replay record locator mismatch".into());
            }
            Ok(ArchivedTerminalRecord::Journal { record })
        }
    }
}

type JournalReceiptCache = BTreeMap<(String, String), (u64, DirectReceipt)>;

fn ordered_journal_receipts(
    records: &JournalReceiptCache,
) -> Result<Vec<(u64, DirectReceipt)>, String> {
    let mut ordered = records.values().cloned().collect::<Vec<_>>();
    ordered.sort_by_key(|(sequence, _)| *sequence);
    let mut receipt_ids = HashSet::with_capacity(ordered.len());
    if ordered.iter().enumerate().any(|(offset, (sequence, receipt))| {
        *sequence != offset as u64 + 1
            || records.get(&(receipt.account_id.clone(), receipt.request_id.clone()))
                .is_none_or(|(cached_sequence, cached_receipt)| {
                    cached_sequence != sequence || cached_receipt != receipt
                })
            || !receipt_ids.insert(receipt.receipt_id.clone())
    }) {
        return Err("journal receipt cache invalid".into());
    }
    Ok(ordered)
}

fn migration_parent_state(
    bundle: &V70MigrationBundle,
    records: &[DirectStateArtifact],
) -> Result<
    (
        DirectRequestIndexState,
        JournalReceiptCache,
        DirectRequestIndexSnapshot,
        DirectReceiptSnapshot,
    ),
    String,
> {
    if records.len() as u64 != bundle.manifest.source_sequence
        || bundle.records.len() as u64 != bundle.manifest.record_count
        || bundle.leaves.len() != bundle.records.len()
        || bundle.leaves.len() as u64 != bundle.manifest.source_sequence
    {
        return Err("journal migration receipt lineage incomplete".into());
    }
    let index_snapshot = DirectRequestIndexSnapshot::from_leaves(
        bundle.manifest.source_sequence,
        &bundle.manifest.request_index_root,
        bundle.leaves.clone(),
    )
    .map_err(|_| "journal migration request index invalid")?;
    let receipt_snapshot = DirectReceiptSnapshot::from_receipts(
        &index_snapshot,
        records
            .iter()
            .map(|record| (record.sequence, record.receipt.clone())),
    )
    .map_err(|_| "journal migration receipts do not match request index")?;
    let mut receipts = BTreeMap::new();
    for (offset, record) in records.iter().enumerate() {
        if record.sequence != offset as u64 + 1
            || receipts
                .insert(
                    (
                        record.receipt.account_id.clone(),
                        record.receipt.request_id.clone(),
                    ),
                    (record.sequence, record.receipt.clone()),
                )
                .is_some()
        {
            return Err("journal migration receipt lineage invalid".into());
        }
    }
    let index = DirectRequestIndexState::from_snapshot(
        index_snapshot.clone(),
        bundle.manifest.source_sequence,
        &bundle.manifest.request_index_root,
    )
    .map_err(|_| "journal migration request index invalid")?;
    Ok((index, receipts, index_snapshot, receipt_snapshot))
}

fn migration_matches_restored_index(
    bundle: &V70MigrationBundle,
    index: &DirectRequestIndexSnapshot,
) -> bool {
    if bundle.manifest.source_sequence == 0
        || bundle.manifest.source_sequence > index.sequence
        || bundle.manifest.record_count != bundle.records.len() as u64
        || bundle.leaves.len() != bundle.records.len()
        || DirectRequestIndexSnapshot::from_leaves(
            bundle.manifest.source_sequence,
            &bundle.manifest.request_index_root,
            bundle.leaves.clone(),
        )
        .is_err()
    {
        return false;
    }
    let migrated = index
        .leaves
        .iter()
        .filter(|leaf| matches!(leaf.locator, TerminalResultLocator::Migration { .. }))
        .collect::<Vec<_>>();
    migrated.len() == bundle.leaves.len()
        && migrated
            .iter()
            .zip(&bundle.leaves)
            .all(|(indexed, bundled)| {
                *indexed == bundled
                    && matches!(
                        &indexed.locator,
                        TerminalResultLocator::Migration { migration_id, .. }
                            if migration_id == &bundle.manifest.migration_id
                    )
            })
}

/// v71 preserves the same two-phase enclave adoption rule as v70 while the
/// durable object is only the bounded encrypted successor record. The caller
/// holds the financial gate, so the proof cache and durable head advance in
/// one serial order. Any ambiguity after persistence latches the writer until
/// a fresh authenticated restore rebuilds all parent acceleration state.
async fn exchange_direct_v71(
    state: &AppState,
    request: DirectRequest,
    _guard: &OwnedMutexGuard<()>,
) -> io::Result<RuntimeResponse> {
    let store = match state.artifact_store.as_ref() {
        Some(ArchiveStore::S3(store)) => store,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "V71_S3_ARCHIVE_REQUIRED",
            ))
        }
    };
    if state.commit_ack_key.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "DIRECT_COMMIT_ACK_KEY_NOT_CONFIGURED",
        ));
    }
    let previous_request_index_root;
    let request_proof = {
        let index = state.journal_request_index.lock().await;
        let index = index
            .as_ref()
            .ok_or_else(|| invalid("JOURNAL_REQUEST_INDEX_UNRESTORED"))?;
        previous_request_index_root = index
            .root()
            .map_err(|_| invalid("JOURNAL_REQUEST_INDEX_INVALID"))?;
        index
            .proof(&request.account_id, &request.request_id)
            .map_err(|_| invalid("JOURNAL_REQUEST_PROOF_FAILED"))?
    };
    let replay_leaf = request_proof.leaf.clone();
    let archived = match replay_leaf.as_ref() {
        Some(leaf) => Some(
            archived_terminal_for_leaf(state, store, leaf)
                .await
                .map_err(invalid)?,
        ),
        None => None,
    };
    if state.journal_receipts.lock().await.is_none() {
        return Err(invalid("JOURNAL_RECEIPTS_UNRESTORED"));
    }

    eprintln!("FINANCIAL_AWAIT_BEGIN stage=enclave_journal_candidate");
    let (mut stream, first) = bounded_enclave_stage(ENCLOSURE_EXCHANGE_TIMEOUT, async {
        let mut stream =
            VsockStream::connect(VsockAddr::new(state.enclave_cid, ENCLOSURE_PORT)).await?;
        write_frame(
            &mut stream,
            &serde_cbor::to_vec(&RuntimeRequest::ExecuteJournal {
                request,
                request_proof,
                archived,
            })
            .map_err(invalid)?,
        )
        .await?;
        let first: RuntimeResponse =
            serde_cbor::from_slice(&read_frame(&mut stream).await?).map_err(invalid)?;
        Ok::<_, io::Error>((stream, first))
    })
    .await?;
    eprintln!("FINANCIAL_AWAIT_END stage=enclave_journal_candidate");
    if let Some(leaf) = replay_leaf {
        return match first {
            RuntimeResponse::Execute { result } if terminal_result_matches_leaf(&result, &leaf) => {
                Ok(RuntimeResponse::Execute { result })
            }
            RuntimeResponse::Error { code } => Ok(RuntimeResponse::Error { code }),
            _ => Err(invalid("JOURNAL_REPLAY_TERMINAL_INVALID")),
        };
    }
    let (record, terminal_leaf) = match first {
        RuntimeResponse::JournalCandidate {
            record,
            terminal_leaf,
        } if record.previous_request_index_root == previous_request_index_root
            && terminal_leaf_matches_record(&terminal_leaf, &record) =>
        {
            (record, terminal_leaf)
        }
        RuntimeResponse::Error { code } => {
            return Ok(RuntimeResponse::Error { code });
        }
        _ => {
            store.latch_journal("JOURNAL_CANDIDATE_INVALID").await;
            return Err(invalid("JOURNAL_CANDIDATE_INVALID"));
        }
    };

    eprintln!("FINANCIAL_AWAIT_BEGIN stage=journal_persist_readback");
    if let Err(error) = store.append_journal_record(&record).await {
        eprintln!("FINANCIAL_AWAIT_END stage=journal_persist_readback");
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("IMMUTABLE_JOURNAL_PERSISTENCE_FAILED:{error}"),
        ));
    }
    eprintln!("FINANCIAL_AWAIT_END stage=journal_persist_readback");
    let ack = JournalDurabilityAck::issue(&record, &state.commit_ack_key)
        .map_err(|_| invalid("JOURNAL_DURABILITY_ACK_FAILED"))?;
    eprintln!("FINANCIAL_AWAIT_BEGIN stage=enclave_journal_durability_ack");
    let terminal = bounded_enclave_stage(ENCLOSURE_EXCHANGE_TIMEOUT, async {
        write_frame(
            &mut stream,
            &serde_cbor::to_vec(&RuntimeRequest::JournalDurabilityAck { ack })
                .map_err(invalid)?,
        )
        .await?;
        serde_cbor::from_slice(&read_frame(&mut stream).await?).map_err(invalid)
    })
    .await;
    eprintln!("FINANCIAL_AWAIT_END stage=enclave_journal_durability_ack");
    let terminal = match terminal {
        Ok(RuntimeResponse::Execute { result })
            if verify_terminal_matches_record(&result, &record) => result,
        _ => {
            store.latch_journal("JOURNAL_TERMINAL_UNVERIFIED").await;
            return Err(invalid("JOURNAL_TERMINAL_UNVERIFIED"));
        }
    };

    let cache_advance = {
        let mut index = state.journal_request_index.lock().await;
        index
            .as_mut()
            .ok_or(())
            .and_then(|index| {
                index
                    .insert(
                        terminal_leaf,
                        &previous_request_index_root,
                        &record.request_index_root,
                    )
                    .map_err(|_| ())
            })
    };
    if cache_advance.is_err() {
        store.latch_journal("JOURNAL_REQUEST_INDEX_ADVANCE_FAILED").await;
        return Err(invalid("JOURNAL_REQUEST_INDEX_ADVANCE_FAILED"));
    }
    let receipt_key = (
        terminal.receipt.account_id.clone(),
        terminal.receipt.request_id.clone(),
    );
    let receipt_advance = state
        .journal_receipts
        .lock()
        .await
        .as_mut()
        .map(|receipts| {
            receipts.insert(receipt_key, (record.sequence, terminal.receipt.clone()))
        });
    if !matches!(receipt_advance, Some(None)) {
        store.latch_journal("JOURNAL_RECEIPT_ADVANCE_FAILED").await;
        return Err(invalid("JOURNAL_RECEIPT_ADVANCE_FAILED"));
    }
    let transition_advance = state
        .journal_transition_roots
        .lock()
        .await
        .as_mut()
        .map(|roots| {
            let previous = roots.last_key_value();
            if !matches!(previous, Some((sequence, root))
                if sequence.checked_add(1) == Some(record.sequence)
                    && root == &record.previous_transition_root)
            {
                return false;
            }
            roots
                .insert(record.sequence, record.transition_root.clone())
                .is_none()
        });
    if transition_advance != Some(true) {
        store.latch_journal("JOURNAL_TRANSITION_ROOT_ADVANCE_FAILED").await;
        return Err(invalid("JOURNAL_TRANSITION_ROOT_ADVANCE_FAILED"));
    }
    *state.committed_state_root.lock().await = Some(record.transition_root);
    state.last_commit_at.store(now_unix(), Ordering::Release);
    store.schedule_journal_checkpoint(state).await;
    Ok(RuntimeResponse::Execute { result: terminal })
}
fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}
#[derive(Debug)]
struct FrameOversized;
impl std::fmt::Display for FrameOversized {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("frame exceeds direct-execution limit")
    }
}
impl std::error::Error for FrameOversized {}
fn frame_oversized(error: &io::Error) -> bool {
    error.get_ref().is_some_and(|inner| inner.is::<FrameOversized>())
}
async fn read_frame<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> io::Result<Vec<u8>> {
    let length = stream.read_u32().await? as usize;
    if length > MAX_FRAME_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidData, FrameOversized));
    }
    if length == 0 {
        return Err(invalid("invalid frame"));
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}
async fn write_frame<S: tokio::io::AsyncWrite + Unpin>(stream: &mut S, bytes: &[u8]) -> io::Result<()> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidData, FrameOversized));
    }
    if bytes.is_empty() {
        return Err(invalid("invalid frame"));
    }
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(bytes).await?;
    stream.flush().await
}
#[cfg(test)]
mod tests {
    #[test]
    fn persistence_format_defaults_to_v70_and_rejects_unknown_values() {
        assert_eq!(
            super::PersistenceFormat::parse(None),
            Ok(super::PersistenceFormat::V70)
        );
        assert_eq!(
            super::PersistenceFormat::parse(Some("v70")),
            Ok(super::PersistenceFormat::V70)
        );
        assert_eq!(
            super::PersistenceFormat::parse(Some("v71")),
            Ok(super::PersistenceFormat::V71)
        );
        assert_eq!(
            super::PersistenceFormat::parse(Some("v71-hot")),
            Ok(super::PersistenceFormat::V71Hot)
        );
        for invalid in ["", "V71", "shadow", "v72", " v71"] {
            assert!(super::PersistenceFormat::parse(Some(invalid)).is_err());
        }
    }

    #[test]
    fn v71_hot_cutover_marker_is_canonical_committed_state_metadata() {
        let head = super::StagedV71Head {
            writer_epoch: "shadow-rollout-1".into(),
            sequence: 35_001,
            record_hash: "1".repeat(64),
            transition_root: "2".repeat(64),
            request_index_root: "3".repeat(64),
            financial_state_root: "4".repeat(64),
        };
        let marker = super::V71CutoverMarker::from_head(&head);
        assert!(marker.valid());
        assert_eq!(
            super::journal_cutover_marker_key("epoch"),
            "epoch/journal-v71/cutover.cbor"
        );
        let encoded = serde_cbor::to_vec(&marker).unwrap();
        assert_eq!(
            serde_cbor::from_slice::<super::V71CutoverMarker>(&encoded).unwrap(),
            marker
        );
        let mut invalid = marker;
        invalid.record_hash = "not-a-digest".into();
        assert!(!invalid.valid());
    }

    #[test]
    fn checkpoint_refresh_coalesces_bursts_and_retries_without_new_commits() {
        assert_eq!(super::CHECKPOINT_REFRESH_INTERVAL, std::time::Duration::from_secs(300));
        let mut refresh = super::CheckpointRefresh::default();
        let now = tokio::time::Instant::now();
        assert!(refresh.request());
        for _ in 0..100 { assert!(!refresh.request()); }
        assert_eq!(refresh.delay(now), std::time::Duration::ZERO);
        refresh.begin(now);
        assert!(!refresh.request()); // a commit while sealing schedules one successor
        assert!(refresh.finish(super::CheckpointRefreshOutcome::Persisted));
        assert_eq!(refresh.delay(now), super::CHECKPOINT_REFRESH_INTERVAL);
        refresh.begin(now + super::CHECKPOINT_REFRESH_INTERVAL);
        assert!(refresh.finish(super::CheckpointRefreshOutcome::Failed)); // failed refresh is not dropped in a quiet market
        assert_eq!(refresh.delay(now + super::CHECKPOINT_REFRESH_INTERVAL), super::CHECKPOINT_REFRESH_INTERVAL);
        refresh.begin(now + super::CHECKPOINT_REFRESH_INTERVAL * 2);
        assert!(!refresh.finish(super::CheckpointRefreshOutcome::Persisted));
        assert!(refresh.request());
        assert_eq!(refresh.delay(now + super::CHECKPOINT_REFRESH_INTERVAL * 2), super::CHECKPOINT_REFRESH_INTERVAL);
    }

    #[test]
    fn v71_checkpoint_cadence_leaves_three_retry_intervals_inside_restore_bound() {
        assert_eq!(V71_CHECKPOINT_INTERVAL_RECORDS, 250);
        assert_eq!(MAX_V71_RESTORE_TAIL_RECORDS, 1000);
        assert_eq!(MAX_V71_RESTORE_TAIL_BYTES, 256 * 1024 * 1024);
        assert!(!journal_checkpoint_due(249, 0));
        assert!(journal_checkpoint_due(250, 0));
        assert!(!journal_checkpoint_due(10_249, 10_000));
        assert!(journal_checkpoint_due(10_250, 10_000));
        assert!(!journal_checkpoint_due(9_999, 10_000));
        assert!(V71_CHECKPOINT_INTERVAL_RECORDS * 4 <= MAX_V71_RESTORE_TAIL_RECORDS as u64);
        assert_eq!(advance_journal_tail_bytes(MAX_V71_RESTORE_TAIL_BYTES - 1, 1), Ok(MAX_V71_RESTORE_TAIL_BYTES));
        assert_eq!(advance_journal_tail_bytes(MAX_V71_RESTORE_TAIL_BYTES, 1), Err("journal tail exceeds byte bound"));
        assert_eq!(advance_journal_tail_bytes(usize::MAX, 1), Err("journal tail exceeds byte bound"));
    }

    #[test]
    fn v71_ordered_receipt_cache_requires_complete_unique_sequence_and_identity() {
        let first = projection_sequence_fixture().receipt;
        let mut second = first.clone();
        second.receipt_id = "receipt-2".into();
        second.account_id = "account-2".into();
        second.request_id = "request-2".into();
        let cache = BTreeMap::from([
            ((second.account_id.clone(), second.request_id.clone()), (2, second.clone())),
            ((first.account_id.clone(), first.request_id.clone()), (1, first.clone())),
        ]);
        assert_eq!(
            ordered_journal_receipts(&cache).unwrap(),
            vec![(1, first.clone()), (2, second.clone())]
        );
        assert!(verify_committed_receipt_lineage(
            &[(1, first.clone()), (2, second.clone())],
            &[first.clone()]
        )
        .is_ok());

        let mut gap = cache.clone();
        gap.get_mut(&(second.account_id.clone(), second.request_id.clone()))
            .unwrap()
            .0 = 3;
        assert!(ordered_journal_receipts(&gap).is_err());
        let mut duplicate_receipt = cache;
        duplicate_receipt
            .get_mut(&(second.account_id.clone(), second.request_id.clone()))
            .unwrap()
            .1
            .receipt_id = first.receipt_id;
        assert!(ordered_journal_receipts(&duplicate_receipt).is_err());
    }

    #[tokio::test]
    async fn checkpoint_persistence_does_not_hold_the_financial_gate() {
        use std::sync::Arc;
        use tokio::sync::Notify;

        let gate = Arc::new(super::FinancialGate::new());
        let snapshot_started = Arc::new(Notify::new());
        let persistence_started = Arc::new(Notify::new());
        let checkpoint = {
            let gate = Arc::clone(&gate);
            let snapshot_started = Arc::clone(&snapshot_started);
            let persistence_started = Arc::clone(&persistence_started);
            tokio::spawn(async move {
                let (result, _, hold) = super::checkpoint_snapshot_under_gate(&gate, || async {
                    snapshot_started.notify_one();
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    Ok::<_, String>(())
                }).await;
                result.unwrap();
                assert!(hold >= std::time::Duration::from_millis(45));
                persistence_started.notify_one();
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            })
        };
        snapshot_started.notified().await;
        persistence_started.notified().await;
        let order_started = std::time::Instant::now();
        let order_guard = gate.lock("checkpoint_concurrency_test_order").await;
        let order_wait = order_started.elapsed();
        drop(order_guard);
        assert!(order_wait < std::time::Duration::from_millis(50), "order waited {order_wait:?} for ungated persistence");
        assert!(!checkpoint.is_finished(), "checkpoint persistence must still be running");
        checkpoint.await.unwrap();
    }

    /// Production-sized synthetic checkpoint/order benchmark. It uses the
    /// sealed opening fixture and local temporary storage only: no production
    /// artifact, grant, secret, network service or account is accessed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "isolated rehearsal benchmark; set LAYRS_GATE_BENCH_RECORDS"]
    async fn v70_checkpoint_gate_and_order_latency_benchmark() {
        use layrs_direct_execution_v1::{
            DirectRuntime, DirectStateStore, InMemoryDirectStateStore, RuntimeMode, SealedEpoch,
        };
        use uuid::Uuid;

        fn epoch_path() -> PathBuf {
            std::env::var("LAYRS_BRIDGE_BENCH_EPOCH_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../../.codex-review-bundles/unified-direct-execution-20260905/new-epoch-20260911/OPENING_EPOCH_STATE_20260911.json"))
        }
        fn request_for(subject: &str, identity: &str, id: &str, wallet: &str) -> DirectRequest {
            let action = DirectAction::BeginUsdcBusWithdrawal {
                withdrawal_id: id.into(),
                destination_chain: "arbitrum".into(),
                asset: "USDC".into(),
                destination: wallet.into(),
                amount_atomic: "999999999999999".into(),
            };
            let mut request = DirectRequest {
                account_id: subject.into(),
                identity_commitment: identity.into(),
                request_id: id.into(),
                request_hash: String::new(),
                financial_wallet_address: Some(wallet.into()),
                action,
            };
            request.request_hash = request_hash(&request);
            request
        }

        let target: u64 = std::env::var("LAYRS_GATE_BENCH_RECORDS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(70_000);
        assert!((3..=MAX_V70_LINEAGE_RECORDS as u64).contains(&target));

        let mut live = DirectRuntime::new(
            SealedEpoch::load(epoch_path()).unwrap(),
            RuntimeMode::IsolatedTest,
            vec![7; 32],
        ).unwrap();
        let mut store = InMemoryDirectStateStore::default();
        let subject = "a".repeat(64);
        let wallet = "0x1111111111111111111111111111111111111111".to_string();
        let identity = identity_commitment_for(&subject, &wallet);
        let mut admission = DirectRequest {
            account_id: subject.clone(),
            identity_commitment: identity.clone(),
            request_id: "gate-benchmark-admission".into(),
            request_hash: String::new(),
            financial_wallet_address: None,
            action: DirectAction::AdmitIdentity { wallet_address: wallet.clone() },
        };
        admission.request_hash = request_hash(&admission);
        live.execute_committed(admission, &[8; 32], &mut store).unwrap();
        let mut deposit = DirectRequest {
            account_id: subject.clone(),
            identity_commitment: identity.clone(),
            request_id: "gate-benchmark-deposit".into(),
            request_hash: String::new(),
            financial_wallet_address: Some(wallet.clone()),
            action: DirectAction::CreditHorizenUsdcDeposit {
                amount_atomic: "10000000".into(),
                custody_reference: format!("horizen-usdc-deposit:0x{}", "ab".repeat(32)),
            },
        };
        deposit.request_hash = request_hash(&deposit);
        live.execute_committed(deposit, &[8; 32], &mut store).unwrap();
        let mut records = store.artifacts().unwrap();
        records.sort_by_key(|artifact| artifact.sequence);
        for artifact in &mut records { artifact.ciphertext.clear(); }
        let mut synthetic_root = records.last().unwrap().state_hash.clone();
        let mut last_request = None;
        while live.committed_sequence() < target {
            let sequence = live.committed_sequence() + 1;
            let id = Uuid::from_u128(0x73737373222243338444000000000000 + sequence as u128).to_string();
            let request = request_for(&subject, &identity, &id, &wallet);
            let result = live.execute(request.clone()).unwrap();
            assert_eq!(result.effect, "WITHDRAWAL_REJECTED");
            let next_root = sha256(format!("v70-gate-benchmark:{sequence}").as_bytes());
            records.push(DirectStateArtifact {
                epoch_id: EPOCH_ID.into(),
                sequence,
                prior_state_hash: synthetic_root,
                state_hash: next_root.clone(),
                request_hash: request.request_hash.clone(),
                nonce: Vec::new(),
                ciphertext: Vec::new(),
                ciphertext_hash: String::new(),
                receipt: result.receipt,
            });
            synthetic_root = next_root;
            last_request = Some(request);
        }
        let artifact = live.prepare_candidate(last_request.unwrap(), &[8; 32]).unwrap().artifact;
        let predecessor = records.len() - 2;
        records[predecessor].state_hash = artifact.prior_state_hash.clone();
        let mut compact_head = artifact.clone();
        compact_head.ciphertext.clear();
        *records.last_mut().unwrap() = compact_head;
        let mut artifact_hashes = vec!["a".repeat(64); records.len()];
        *artifact_hashes.last_mut().unwrap() = artifact_hash(&artifact);
        let head_path = std::env::temp_dir().join(format!("layrs-v70-gate-benchmark-head-{}.cbor", std::process::id()));
        let artifact_bytes = {
            let bytes = serde_cbor::to_vec(&artifact).unwrap();
            let mut file = std::fs::File::create(&head_path).unwrap();
            std::io::Write::write_all(&mut file, &bytes).unwrap();
            file.sync_all().unwrap();
            bytes.len()
        };
        drop(artifact);

        let order_id = Uuid::from_u128(0x74747474222243338444000000000000 + target as u128).to_string();
        let order_request = request_for(&subject, &identity, &order_id, &wallet);
        let live = Arc::new(live);
        let gate = Arc::new(FinancialGate::new());

        let baseline_started = Instant::now();
        let baseline_guard = gate.lock("gate_benchmark_baseline_order").await;
        let baseline_runtime = Arc::clone(&live);
        let baseline_request = order_request.clone();
        tokio::task::spawn_blocking(move || baseline_runtime.prepare_candidate(baseline_request, &[8; 32]))
            .await.unwrap().unwrap();
        drop(baseline_guard);
        let baseline_order = baseline_started.elapsed();

        let snapshot_started = Arc::new(tokio::sync::Notify::new());
        let checkpoint_task = {
            let gate = Arc::clone(&gate);
            let live = Arc::clone(&live);
            let snapshot_started = Arc::clone(&snapshot_started);
            tokio::spawn(async move {
                let (checkpoint, wait, hold) = checkpoint_snapshot_under_gate(&gate, || async move {
                    snapshot_started.notify_one();
                    tokio::task::spawn_blocking(move || {
                        let bytes = std::fs::read(&head_path).unwrap();
                        std::fs::remove_file(&head_path).unwrap();
                        let exact_head: DirectStateArtifact = serde_cbor::from_slice(&bytes).unwrap();
                        live.seal_checkpoint(exact_head, records, artifact_hashes, &[8; 32])
                    })
                        .await.map_err(|_| "checkpoint benchmark task failed".to_string())?
                        .map_err(|_| "checkpoint benchmark seal failed".to_string())
                }).await;
                let checkpoint = checkpoint.unwrap();
                let persist_started = Instant::now();
                let path = std::env::temp_dir().join(format!("layrs-v70-gate-benchmark-{}.cbor", std::process::id()));
                let (checkpoint_bytes, path) = tokio::task::spawn_blocking(move || {
                    let bytes = serde_cbor::to_vec(&checkpoint).unwrap();
                    let mut file = std::fs::File::create(&path).unwrap();
                    std::io::Write::write_all(&mut file, &bytes).unwrap();
                    file.sync_all().unwrap();
                    (bytes.len(), path)
                }).await.unwrap();
                let persist = persist_started.elapsed();
                std::fs::remove_file(path).unwrap();
                (wait, hold, persist, checkpoint_bytes)
            })
        };
        snapshot_started.notified().await;
        let concurrent_started = Instant::now();
        let concurrent_guard = gate.lock("gate_benchmark_concurrent_order").await;
        let concurrent_gate_wait = concurrent_started.elapsed();
        let concurrent_service_started = Instant::now();
        let concurrent_runtime = Arc::clone(&live);
        tokio::task::spawn_blocking(move || concurrent_runtime.prepare_candidate(order_request, &[8; 32]))
            .await.unwrap().unwrap();
        drop(concurrent_guard);
        let concurrent_service = concurrent_service_started.elapsed();
        let concurrent_order = concurrent_started.elapsed();
        let (checkpoint_wait, checkpoint_hold, checkpoint_persist, checkpoint_bytes) = checkpoint_task.await.unwrap();

        eprintln!(
            "BRIDGE_GATE_BENCH records={target} artifact_bytes={artifact_bytes} checkpoint_bytes={checkpoint_bytes} checkpoint_wait_ms={} checkpoint_hold_ms={} checkpoint_persist_ms={} baseline_order_ms={} concurrent_order_ms={} concurrent_gate_wait_ms={} concurrent_service_ms={} concurrent_delta_ms={}",
            checkpoint_wait.as_millis(),
            checkpoint_hold.as_millis(),
            checkpoint_persist.as_millis(),
            baseline_order.as_millis(),
            concurrent_order.as_millis(),
            concurrent_gate_wait.as_millis(),
            concurrent_service.as_millis(),
            concurrent_order.saturating_sub(baseline_order).as_millis(),
        );
        assert!(checkpoint_hold < Duration::from_secs(15));
        assert!(checkpoint_persist > Duration::ZERO);
    }

    use super::*;
    #[test]
    fn oversized_checkpoint_refresh_returns_to_idle_even_with_a_coalesced_commit() {
        let mut refresh = CheckpointRefresh::default();
        let now = tokio::time::Instant::now();
        assert!(refresh.request());
        refresh.begin(now);
        assert!(!refresh.request()); // commit coalesced into the running refresh
        assert!(!refresh.finish(CheckpointRefreshOutcome::Skipped));
        assert!(!refresh.running && !refresh.requested);
        assert!(refresh.disabled);
        // State can only grow after a proven frame overflow. Do not consume
        // CPU retrying on every later commit; restart or upgrade resets it.
        assert!(!refresh.request());
    }
    #[tokio::test]
    async fn background_refresh_seals_an_oversized_checkpoint_once_then_exits() {
        let gate = Mutex::new(CheckpointRefresh::default());
        assert!(gate.lock().await.request());
        let mut attempts = 0;
        let shared = &gate;
        let refresh = refresh_checkpoints(&gate, || {
            attempts += 1;
            // A commit lands while the oversized seal is in flight.
            async move { assert!(!shared.lock().await.request()); Err(CHECKPOINT_OVERSIZED.to_string()) }
        });
        tokio::time::timeout(Duration::from_secs(5), refresh).await.expect("oversized refresh must not retry");
        assert_eq!(attempts, 1);
        let state = gate.lock().await;
        assert!(!state.running && !state.requested && state.disabled);
    }
    #[tokio::test]
    async fn background_refresh_retries_other_failures_only_after_the_interval() {
        let gate = Mutex::new(CheckpointRefresh::default());
        assert!(gate.lock().await.request());
        let mut attempts = 0;
        let refresh = refresh_checkpoints(&gate, || {
            attempts += 1;
            async { Err("checkpoint seal transport failed".to_string()) }
        });
        assert!(tokio::time::timeout(Duration::from_millis(200), refresh).await.is_err());
        assert_eq!(attempts, 1);
        assert!(gate.lock().await.running);
    }
    #[test]
    fn checkpoint_seal_reasons_are_finite_labels() {
        assert_eq!(checkpoint_seal_reason(CHECKPOINT_OVERSIZED), "oversized");
        assert_eq!(checkpoint_seal_reason("checkpoint seal transport failed"), "transport");
        assert_eq!(checkpoint_seal_reason("checkpoint seal rejected"), "head_validation");
        assert_eq!(checkpoint_seal_reason("checkpoint head mismatch"), "archive_head");
        assert_eq!(checkpoint_seal_reason("s3://bucket/secret-key AccessDenied"), "archive_read_or_write");
    }
    #[tokio::test]
    async fn parent_frame_limit_matches_enclave_and_marks_oversized_frames() {
        assert_eq!(MAX_FRAME_BYTES, 768 * 1024 * 1024);
        let (mut writer, mut reader) = tokio::io::duplex(64);
        write_frame(&mut writer, b"bounded").await.unwrap();
        assert_eq!(read_frame(&mut reader).await.unwrap(), b"bounded");
        // Zeroed and never read: rejected before any byte reaches the stream.
        let oversized = vec![0u8; MAX_FRAME_BYTES + 1];
        let error = write_frame(&mut writer, &oversized).await.unwrap_err();
        assert!(frame_oversized(&error));
        writer.write_u32((MAX_FRAME_BYTES + 1) as u32).await.unwrap();
        assert!(frame_oversized(&read_frame(&mut reader).await.unwrap_err()));
        writer.write_u32(0).await.unwrap();
        let empty = read_frame(&mut reader).await.unwrap_err();
        assert_eq!(empty.kind(), io::ErrorKind::InvalidData);
        assert!(!frame_oversized(&empty));
    }
    #[tokio::test]
    async fn restore_completes_when_the_post_restore_checkpoint_seal_fails() {
        // Serves a head artifact that disagrees with the verified receipt
        // cache, so the post-restore seal fails before contacting the enclave.
        let head = projection_sequence_fixture();
        let hash = "e".repeat(64);
        let mut divergent = head.clone(); divergent.state_hash = "f".repeat(64);
        let body = serde_cbor::to_vec(&divergent).unwrap();
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let address=listener.local_addr().unwrap();
        let expected_path = format!("/unit-test/epoch/artifacts/{:020}-{hash}.cbor", head.sequence);
        let server=tokio::spawn(async move {
            for _ in 0..2 {
                let (mut socket,_)=listener.accept().await.unwrap();let mut buffer=vec![0;8192];let size=socket.read(&mut buffer).await.unwrap();
                assert!(String::from_utf8_lossy(&buffer[..size]).contains(&expected_path));
                socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).as_bytes()).await.unwrap();
                socket.write_all(&body).await.unwrap();
            }
        });
        let configuration=aws_sdk_s3::config::Builder::new().behavior_version_latest().region(aws_sdk_s3::config::Region::new("us-east-1")).credentials_provider(aws_sdk_s3::config::Credentials::new("unit-test","unit-test",None,None,"local-only")).endpoint_url(format!("http://{address}")).force_path_style(true).build();
        let store=S3ImmutableArtifactStore {client:S3Client::from_conf(configuration),bucket:"unit-test".into(),prefix:"epoch".into(),kms_key_id:"not-used".into(),retention_seconds:86400,verified_receipt_records:Arc::new(Mutex::new(Some(vec![head.clone()]))),verified_artifact_hashes:Arc::new(Mutex::new(vec![hash.clone()])),prepared_restore:Arc::new(Mutex::new(None)),prepared_journal_restore:Arc::new(Mutex::new(None)),checkpoint_refresh_gate:Arc::new(Mutex::new(CheckpointRefresh::default())),journal:Arc::new(Mutex::new(JournalWriterState::Unrestored)),journal_role:JournalRole::Writer};
        let state = AppState {
            enclave_cid: 16,
            session_key: vec![7; 32],
            isolated_test: true,
            projection: None,
            local_used_sessions: Arc::new(Mutex::new(HashSet::new())),
            artifact_store: None,
            commit_ack_key: Vec::new(),
            custody: None,
            zen_custody: None,
            usdc_custody: None,
            usdc_link_authority: None,
            usdc_bus_custody: None,
            financial_gate: Arc::new(FinancialGate::new()),
            last_commit_at: Arc::new(AtomicU64::new(0)),
            health: Arc::new(ParentHealth::default()),
            committed_state_root: Arc::new(Mutex::new(Some(head.state_hash.clone()))),
            unresolved_external_effects: Arc::new(Mutex::new(BTreeMap::new())),
            governed_bootstrap: None,
            persistence_format: PersistenceFormat::V70,
            hot_v71_enabled: Arc::new(AtomicBool::new(false)),
            journal_request_index: Arc::new(Mutex::new(None)),
            journal_receipts: Arc::new(Mutex::new(None)),
            journal_migration: Arc::new(Mutex::new(None)),
            journal_checkpoint_sequence: Arc::new(AtomicU64::new(0)),
            journal_transition_roots: Arc::new(Mutex::new(None)),
        };
        assert_eq!(store.seal_current_checkpoint(&state).await.unwrap_err(), "checkpoint head mismatch");
        // restore_streamed's final step: the same failure is only diagnosed.
        store.schedule_restored_checkpoint(&state).await;
        server.await.unwrap();
        // The verified restore adoption is untouched by the failed seal.
        assert_eq!(store.verified_receipt_records.lock().await.as_deref(), Some(&[head.clone()][..]));
        assert_eq!(*store.verified_artifact_hashes.lock().await, vec![hash]);
        assert_eq!(*state.committed_state_root.lock().await, Some(head.state_hash));
    }
    #[test]
    fn usdc_preflight_rejects_a_cross_rail_hold_or_insufficient_balance_before_payout() {
        let balance=|amount:&str|RuntimeResponse::Balance {amount_atomic:amount.into()};
        assert_eq!(usdc_withdrawal_preflight(&balance("4840000"),&balance("5160000"),"5000000"),Err((StatusCode::CONFLICT,"WITHDRAWAL_PENDING")));
        assert_eq!(usdc_withdrawal_preflight(&balance("0"),&balance("4840000"),"5000000"),Err((StatusCode::UNPROCESSABLE_ENTITY,"INSUFFICIENT_AVAILABLE")));
        assert!(usdc_withdrawal_preflight(&balance("0"),&balance("4840000"),"4840000").is_ok());
        for invalid in ["0","-1","4.84","04840000"] {assert!(usdc_withdrawal_preflight(&balance("0"),&balance("4840000"),invalid).is_err());}
        assert!(usdc_withdrawal_preflight(&RuntimeResponse::Error {code:"unavailable".into()},&balance("5000000"),"5000000").is_err());
    }
    #[test]
    fn usdc_custody_projection_binds_horizen_pool_transaction_not_bus_guid() {
        let pool_hash = format!("0x{}", "ab".repeat(32));
        let guid = format!("0x{}", "cd".repeat(32));
        let destination_hash = format!("0x{}", "ef".repeat(32));
        assert_eq!(custody_projection_binding(&format!("horizen-usdc-deposit:{pool_hash}")), (26514, pool_hash.clone()));
        assert_eq!(custody_projection_binding(&format!("horizen-usdc-bus:{pool_hash}:{guid}:{destination_hash}")), (26514, pool_hash));
        assert_eq!(custody_projection_binding("legacy-base-reference"), (8453, "legacy-base-reference".into()));
        assert_eq!(custody_projection_binding("withdrawal:relay:id:42161:destination:0x123"), (42161, "0x123".into()));
        assert_eq!(custody_projection_binding("horizen-usdc-deposit:invalid"), (8453, "horizen-usdc-deposit:invalid".into()));
    }
    #[test]
    fn usdc_bus_reservation_requires_original_id_signed_recipient_and_positive_canonical_amount() {
        let id = "11111111-1111-4111-8111-111111111111";
        let destination = "0x193a0f49be79d12957f8a362fff0f43ebfd7527f";
        let action = usdc_bus_reservation_action(id,Some(destination),destination,"arbitrum","USDC",destination,"4840000").unwrap();
        assert!(matches!(action, DirectAction::BeginUsdcBusWithdrawal {withdrawal_id,destination_chain,asset,destination:to,amount_atomic}
            if withdrawal_id==id&&destination_chain=="arbitrum"&&asset=="USDC"&&to==destination.to_ascii_lowercase()&&amount_atomic=="4840000"));
        for chain in ["base","horizen"] {
            assert!(matches!(usdc_bus_reservation_action(id,Some(destination),destination,chain,"ZEN",destination,"1000000000000000000").unwrap(),
                DirectAction::BeginUsdcBusWithdrawal {destination_chain,asset,..} if destination_chain==chain&&asset=="ZEN"));
        }
        assert!(usdc_bus_reservation_action(id,Some(destination),destination,"arbitrum","ZEN",destination,"1000000000000000000").is_err());
        for invalid_id in ["new", "00000000-0000-0000-0000-000000000000", "11111111-1111-4111-8111-11111111111A"] {
            assert!(usdc_bus_reservation_action(invalid_id,Some(destination),destination,"arbitrum","USDC",destination,"5000000").is_err());
        }
        for amount in ["0", "-1", "5.1", "5e6", "05000000", "0x4c4b40", "340282366920938463463374607431768211456"] {
            assert!(usdc_bus_reservation_action(id,Some(destination),destination,"arbitrum","USDC",destination,amount).is_err());
        }
        assert!(usdc_bus_reservation_action(id,None,destination,"arbitrum","USDC",destination,"5000000").is_err());
        assert!(usdc_bus_reservation_action(id,Some("0x2222222222222222222222222222222222222222"),destination,"arbitrum","USDC",destination,"5000000").is_err());
        for chain in ["base","ethereum","polygon","tempo"] {
            assert!(usdc_bus_reservation_action(id,Some(destination),destination,chain,"USDC",destination,"5000000").is_ok());
        }
        assert!(usdc_bus_reservation_action(id,Some(destination),destination,"horizen","USDC.e",destination,"5000000").is_ok());
        assert!(usdc_bus_reservation_action(id,Some(destination),destination,"robinhood","USDG",destination,"5000000").is_ok());
        assert!(usdc_bus_reservation_action(id,Some(destination),destination,"solana","USDC","11111111111111111111111111111111","5000000").is_ok());
        for (chain,asset) in [("arbitrum","USDG"),("horizen","USDC"),("robinhood","USDC")] {
            assert!(usdc_bus_reservation_action(id,Some(destination),destination,chain,asset,destination,"5000000").is_err());
        }
    }
    #[test]
    fn usdc_bus_public_action_cannot_supply_a_terminal_worker_assertion() {
        let action = serde_json::json!({"type":"BEGIN_USDC_BUS_WITHDRAWAL","destinationChain":"arbitrum","asset":"USDC","destination":"0x1111111111111111111111111111111111111111","amountAtomic":"5000000"});
        assert!(serde_json::from_value::<CustomerAction>(action).is_ok());
        for kind in ["SETTLE_USDC_BUS_WITHDRAWAL", "REVERT_USDC_BUS_WITHDRAWAL"] {
            assert!(serde_json::from_value::<CustomerAction>(serde_json::json!({"type":kind,"withdrawalId":"11111111-1111-4111-8111-111111111111", "destination":"0x1111111111111111111111111111111111111111", "amountAtomic":"5000000", "custodyReference":"fake"})).is_err());
        }
    }
    #[test]
    fn usdc_pre_payout_requires_current_private_principal() {
        for (available, requested, expected) in [("5000000","5000000",true),("0","5000000",false),("4999999","5000000",false),("5000000","5000001",false)] {
            assert_eq!(validate_usdc_pre_payout_balance(&RuntimeResponse::Balance {amount_atomic:available.into()}, requested).is_ok(), expected);
        }
        assert_eq!(validate_usdc_pre_payout_balance(&RuntimeResponse::Balance {amount_atomic:"0".into()}, "5000000").unwrap_err().1, "INSUFFICIENT_AVAILABLE");
        for amount in ["0","-1","5.0","","340282366920938463463374607431768211456"] {
            assert_eq!(validate_usdc_pre_payout_balance(&RuntimeResponse::Balance {amount_atomic:"5000000".into()}, amount).unwrap_err().1,"WITHDRAWAL_AMOUNT_INVALID");
        }
        assert_eq!(validate_usdc_pre_payout_balance(&RuntimeResponse::Balance {amount_atomic:"corrupt".into()}, "5").unwrap_err().1,"USDC_BALANCE_UNAVAILABLE");
        assert_eq!(validate_usdc_pre_payout_balance(&RuntimeResponse::Error {code:"unavailable".into()}, "5").unwrap_err().1,"USDC_BALANCE_UNAVAILABLE");
    }
    #[test]
    fn bounded_prefetch_covers_every_archive_record_exactly_once_in_order() {
        for total in [0,1,3,4,5,1001,4724,4725] {
            let ranges=restore_prefetch_ranges(total);
            assert!(ranges.iter().all(|r|r.len()>0 && r.len()<=RESTORE_PREFETCH_WIDTH));
            assert_eq!(ranges.into_iter().flatten().collect::<Vec<_>>(),(0..total).collect::<Vec<_>>());
        }
    }
    fn reconciled_intent(root: &str) -> ExternalEffectIntent {
        ExternalEffectIntent::create(root.into(),"reconciliation-request".into(),"f".repeat(64),"c".repeat(64),"identity".into(),"base".into(),"USDC".into(),"0x2222222222222222222222222222222222222222".into(),"5000000".into(),"existing-wallet".into(),"0x1111111111111111111111111111111111111111".into(),"1".into(),"180000".into(),"11000000".into(),"1000000".into(),now_unix()).unwrap()
    }
    #[test]
    fn standard_zen_egress_intent_is_owned_by_the_restart_safe_withdrawal_worker() {
        let standard=ExternalEffectIntent::create_zen_withdrawal(
            "a".repeat(64),"zen-egress:11111111-1111-4111-8111-111111111111".into(),"b".repeat(64),"c".repeat(64),
            "identity".into(),"base".into(),"0x2222222222222222222222222222222222222222".into(),"1000000000000000000".into(),
            "existing-wallet".into(),"0x1111111111111111111111111111111111111111".into(),"1".into(),"180000".into(),
            "11000000".into(),"1000000".into(),now_unix()).unwrap();
        assert!(standard_zen_egress_intent(&standard));
        let legacy=ExternalEffectIntent::create_zen_withdrawal(
            "a".repeat(64),"legacy-zen-request".into(),"b".repeat(64),"c".repeat(64),"identity".into(),"base".into(),
            "0x2222222222222222222222222222222222222222".into(),"1000000000000000000".into(),"existing-wallet".into(),
            "0x1111111111111111111111111111111111111111".into(),"1".into(),"180000".into(),"11000000".into(),
            "1000000".into(),now_unix()).unwrap();
        assert!(!standard_zen_egress_intent(&legacy));
    }
    fn nonfinancial_chain() -> Vec<DirectStateArtifact> {
        (0..3).map(|i| { let mut a=projection_sequence_fixture(); a.sequence=i+1; a.prior_state_hash=((b'a'+i as u8) as char).to_string().repeat(64);a.state_hash=((b'b'+i as u8) as char).to_string().repeat(64);a.receipt.account_id="governance".into();a.receipt.request_id=format!("register-{i}");a.receipt.effect="MARKET_REGISTERED".into();a }).collect()
    }
    #[test]
    fn historical_withdrawal_requires_exact_unchanged_verified_ancestry() {
        let intent=reconciled_intent(&"b".repeat(64));let records=nonfinancial_chain();
        assert!(historical_intent_lineage_safe(&intent,&records,&"d".repeat(64)));
        assert!(!historical_intent_lineage_safe(&intent,&records,&"e".repeat(64)));
        assert!(!historical_intent_lineage_safe(&reconciled_intent(&"e".repeat(64)),&records,&"d".repeat(64)));
        let mut gap=records.clone();gap[1].sequence=7;assert!(!historical_intent_lineage_safe(&intent,&gap,&"d".repeat(64)));
        let mut fork=records.clone();fork[1].prior_state_hash="e".repeat(64);assert!(!historical_intent_lineage_safe(&intent,&fork,&"d".repeat(64)));
        let mut collision=records.clone();collision[2].receipt.account_id=intent.account_id.clone();collision[2].receipt.request_id=intent.request_id.clone();assert!(!historical_intent_lineage_safe(&intent,&collision,&"d".repeat(64)));
        let mut changed=records.clone();changed[2].receipt.projection_balance_updates.push(layrs_direct_execution_v1::ProjectionBalanceUpdate {auth_subject_hash:intent.account_id.clone(),identity_commitment:intent.identity_commitment.clone(),asset:"USDC".into(),bucket:"USER_AVAILABLE".into(),amount_atomic:"1".into()});assert!(!historical_intent_lineage_safe(&intent,&changed,&"d".repeat(64)));

        let receipts=records.iter().map(|record|(record.sequence,record.receipt.clone())).collect::<Vec<_>>();
        let roots=BTreeMap::from([(1,"b".repeat(64)),(2,"c".repeat(64)),(3,"d".repeat(64))]);
        assert!(historical_journal_intent_lineage_safe(&intent,&receipts,&roots,&"d".repeat(64)));
        assert!(!historical_journal_intent_lineage_safe(&intent,&receipts,&roots,&"e".repeat(64)));
        let missing_root=BTreeMap::from([(2,"c".repeat(64)),(3,"d".repeat(64))]);
        assert!(!historical_journal_intent_lineage_safe(&intent,&receipts,&missing_root,&"d".repeat(64)));
        let gap=BTreeMap::from([(1,"b".repeat(64)),(3,"d".repeat(64))]);
        assert!(!historical_journal_intent_lineage_safe(&intent,&receipts,&gap,&"d".repeat(64)));
        let mut changed_receipts=receipts.clone();
        changed_receipts[2].1.projection_balance_updates.push(layrs_direct_execution_v1::ProjectionBalanceUpdate {auth_subject_hash:intent.account_id.clone(),identity_commitment:intent.identity_commitment.clone(),asset:"USDC".into(),bucket:"USER_AVAILABLE".into(),amount_atomic:"1".into()});
        assert!(!historical_journal_intent_lineage_safe(&intent,&changed_receipts,&roots,&"d".repeat(64)));
    }
    #[test]
    fn confirmed_extra_payout_never_becomes_a_second_customer_debit() {
        let original=reconciled_intent(&"a".repeat(64));let extra=reconciled_intent(&"b".repeat(64));let mut committed=projection_sequence_fixture();
        committed.receipt.account_id=original.account_id.clone();committed.receipt.identity_commitment=original.identity_commitment.clone();committed.receipt.request_id=original.request_id.clone();committed.receipt.request_hash=original.request_hash.clone();committed.receipt.effect="WITHDRAWAL_SETTLED".into();committed.receipt.amount_atomic=Some(original.amount_atomic.clone());committed.receipt.custody_reference=Some(format!("{}:0x{}",original.external_effect_reference,"11".repeat(32)));
        let receipts=vec![(committed.sequence,committed.receipt.clone())];
        let outcome=ExternalEffectRecovery::BindFinalized {provider_transaction_id:"provider-2".into(),transaction_hash:format!("0x{}","22".repeat(32))};
        let evidence=extra_payout_evidence(&extra,&original,&receipts,outcome.clone()).unwrap().unwrap();assert_eq!(evidence.amount_atomic,"5000000");assert_eq!(evidence.customer_debit_atomic,"0");assert_eq!(evidence.disposition,"PROTOCOL_OVERPAYMENT_UNRECOVERED");
        assert_eq!(evidence,extra_payout_evidence(&extra,&original,&receipts,outcome).unwrap().unwrap());
        assert!(extra_payout_evidence(&extra,&original,&receipts,ExternalEffectRecovery::BindFinalized {provider_transaction_id:"alias".into(),transaction_hash:format!("0x{}","11".repeat(32))}).unwrap().is_none());
        assert!(extra_payout_evidence(&extra,&original,&receipts,ExternalEffectRecovery::SubmitWithStableReference).is_err());
        assert!(extra_payout_evidence(&extra,&original,&receipts,ExternalEffectRecovery::BindReverted {provider_transaction_id:"reverted".into(),transaction_hash:format!("0x{}","22".repeat(32))}).is_err());
    }
    fn projection_sequence_fixture() -> DirectStateArtifact {
        DirectStateArtifact {
            epoch_id: EPOCH_ID.into(), sequence: 7, prior_state_hash: "a".repeat(64), state_hash: "b".repeat(64), request_hash: "c".repeat(64),
            nonce: vec![1;12], ciphertext: vec![], ciphertext_hash: "d".repeat(64),
            receipt: DirectReceipt { receipt_id: "receipt".into(), account_id: "account".into(), identity_commitment: "identity".into(), request_id: "request".into(), request_hash: "c".repeat(64), status: layrs_direct_execution_v1::TerminalStatus::Applied, effect: "BALANCE_READ".into(), amount_atomic: None, custody_reference: None, execution: None, resolution: None, projection_balance_updates: vec![], genesis_ordinal: 0, signature: "signature".into() }
        }
    }
    #[test]
    fn archive_recovery_selects_only_head_backed_candidates_without_hiding_missing_history() {
        let key = |kind: &str, seq: u64, hash: &str| {
            format!("epoch/{kind}/{seq:020}-{}.cbor", hash.repeat(64))
        };
        let canonical = vec![
            key("artifacts", 1, "a"),
            key("artifacts", 2, "b"),
            key("artifacts", 3, "c"),
        ];
        let heads = (1..=3)
            .zip(["a", "b", "c"])
            .map(|(sequence, hash)| ResolvedArchiveHead {
                key: key("heads", sequence, hash),
                sequence,
                artifact_hash: hash.repeat(64),
            })
            .collect::<Vec<_>>();
        let mut candidates = canonical.clone();
        candidates.extend([key("artifacts", 1, "d"), key("artifacts", 2, "e")]);
        candidates.sort();
        for _ in 0..3 {
            assert_eq!(
                committed_archive_keys(&candidates, &heads, "epoch").unwrap(),
                canonical
            );
        }
        assert_eq!(
            committed_archive_keys(&canonical, &heads, "epoch").unwrap(),
            canonical
        );
        let mut missing = candidates.clone();
        missing.retain(|k| k != &canonical[1]);
        assert!(committed_archive_keys(&missing, &heads, "epoch").is_err());
        let mut tail = candidates.clone();
        tail.push(key("artifacts", 4, "f"));
        assert!(committed_archive_keys(&tail, &heads, "epoch").is_err());
        assert!(committed_archive_keys(&candidates, &heads[..2], "epoch").is_err());
        let mut duplicate = heads.clone();
        duplicate[1].sequence = heads[0].sequence;
        assert!(committed_archive_keys(&candidates, &duplicate, "epoch").is_err());
        let mut wrong = heads.clone();
        wrong[1].artifact_hash = "f".repeat(64);
        assert!(committed_archive_keys(&candidates, &wrong, "epoch").is_err());
        let mut malformed = candidates.clone();
        malformed.push("other/artifacts/not-a-record.cbor".into());
        assert!(committed_archive_keys(&malformed, &heads, "epoch").is_err());
        assert!(committed_archive_keys(&candidates, &[], "epoch").is_err());
        assert!(committed_archive_keys(&[], &[], "epoch")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn successor_lineage_resolves_legacy_twins_and_rejects_ambiguous_history() {
        let mut first = projection_sequence_fixture();
        first.sequence = 1;
        first.prior_state_hash = "0".repeat(64);
        first.state_hash = "1".repeat(64);
        let mut canonical_twin = first.clone();
        canonical_twin.sequence = 2;
        canonical_twin.prior_state_hash = first.state_hash.clone();
        canonical_twin.state_hash = "2".repeat(64);
        let mut orphan_twin = canonical_twin.clone();
        orphan_twin.state_hash = "f".repeat(64);
        let mut successor = canonical_twin.clone();
        successor.sequence = 3;
        successor.prior_state_hash = canonical_twin.state_hash.clone();
        successor.state_hash = "3".repeat(64);
        let entry = |artifact: DirectStateArtifact| {
            let hash = artifact_hash(&artifact);
            resolved_head_from_artifact(
                format!("epoch/heads/{:020}-{hash}.cbor", artifact.sequence),
                artifact,
                "epoch",
            )
            .unwrap()
        };
        let canonical_hash = artifact_hash(&canonical_twin);
        let orphan_hash = artifact_hash(&orphan_twin);
        let (resolved, orphans) = resolve_archive_heads(vec![
            entry(first),
            entry(orphan_twin),
            entry(canonical_twin),
            entry(successor),
        ])
        .unwrap();
        assert_eq!(
            resolved
                .iter()
                .map(|head| head.sequence)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        assert_eq!(resolved[1].artifact_hash, canonical_hash);
        assert_eq!(orphans.len(), 1);
        assert_eq!(orphans[0].artifact_hash, orphan_hash);

        let mut terminal = resolved.clone();
        terminal.push(ResolvedArchiveHead {
            key: "epoch/heads/00000000000000000003-f.cbor".into(),
            sequence: 3,
            artifact_hash: "f".repeat(64),
        });
        assert!(
            resolve_archive_heads(terminal.into_iter().map(|head| (head, None)).collect()).is_err()
        );
        assert!(resolve_archive_heads(vec![
            (resolved[0].clone(), None),
            (resolved[2].clone(), None)
        ])
        .is_err());
    }

    #[test]
    fn new_archive_head_is_sequence_unique_and_conflicts_are_stable() {
        assert_eq!(
            archive_head_key("epoch", 19085),
            "epoch/heads/00000000000000019085.cbor"
        );
        let response = commit_error_response(CommitTaskError::Enclave(io::Error::new(
            io::ErrorKind::Other,
            "IMMUTABLE_PERSISTENCE_FAILED:ARCHIVE_SEQUENCE_CONFLICT",
        )));
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn failed_restore_preflight_does_not_consume_bootstrap_and_retry_can_succeed() {
        let bootstraps = Arc::new(AtomicU64::new(0));
        let count = bootstraps.clone();
        let first = preflight_then_bootstrap(
            async {
                Err(invalid(
                    "archive duplicate head is not uniquely resolved by successor",
                ))
            },
            async move {
                count.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )
        .await;
        assert!(first.is_err());
        assert_eq!(bootstraps.load(Ordering::SeqCst), 0);

        let count = bootstraps.clone();
        preflight_then_bootstrap(async { Ok(()) }, async move {
            count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
        .await
        .unwrap();
        assert_eq!(bootstraps.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn checkpoint_archive_requires_exact_prefix_and_retains_unrestored_suffix() {
        let mut artifacts = nonfinancial_chain();
        for artifact in &mut artifacts {
            artifact.ciphertext = vec![1, 2, 3];
        }
        let hashes: Vec<_> = artifacts.iter().map(artifact_hash).collect();
        let keys: Vec<_> = artifacts
            .iter()
            .zip(&hashes)
            .map(|(record, hash)| format!("epoch/artifacts/{:020}-{hash}.cbor", record.sequence))
            .collect();
        let heads: Vec<_> = artifacts
            .iter()
            .zip(&hashes)
            .map(|(record, hash)| ResolvedArchiveHead {
                key: format!("epoch/heads/{:020}-{hash}.cbor", record.sequence),
                sequence: record.sequence,
                artifact_hash: hash.clone(),
            })
            .collect();
        let checkpoint = layrs_direct_execution_v1::DirectCheckpoint {
            protocol: "layrs.direct-execution.checkpoint.v1".into(),
            opening_state_hash: "a".repeat(64),
            artifact: artifacts[1].clone(),
            receipt_records: artifacts[..2].iter().map(receipt_only_record).collect(),
            artifact_hashes: hashes[..2].to_vec(),
            bootstrap_certificate: None,
            signature: "synthetic".into(),
        };
        assert_eq!(
            validate_checkpoint_archive(&checkpoint, &keys, &heads, "epoch").unwrap(),
            2
        );
        assert_eq!(
            keys.len() - validate_checkpoint_archive(&checkpoint, &keys, &heads, "epoch").unwrap(),
            1
        );
        assert!(
            validate_checkpoint_archive(&checkpoint, &keys[..1], &heads[..1], "epoch").is_err()
        );
        let mut missing = keys.clone();
        missing.remove(0);
        let mut missing_heads = heads.clone();
        missing_heads.remove(0);
        assert!(
            validate_checkpoint_archive(&checkpoint, &missing, &missing_heads, "epoch").is_err()
        );
        let mut changed = heads.clone();
        changed[0].artifact_hash = "f".repeat(64);
        assert!(validate_checkpoint_archive(&checkpoint, &keys, &changed, "epoch").is_err());
        let mut changed = checkpoint.clone();
        changed.artifact_hashes.pop();
        assert!(validate_checkpoint_archive(&changed, &keys, &heads, "epoch").is_err());
        let mut changed = checkpoint;
        changed.artifact.sequence = 0;
        assert!(validate_checkpoint_archive(&changed, &keys, &heads, "epoch").is_err());
    }
    #[test]
    fn checkpoint_recovery_cannot_hide_an_independently_persisted_balance_free_successor() {
        let mut records = nonfinancial_chain();
        for (index, record) in records.iter_mut().enumerate() { record.receipt.receipt_id = format!("receipt-{index}"); }
        let receipts: Vec<_> = records.iter().map(|record| record.receipt.clone()).collect();
        assert!(verify_projected_receipt_lineage(&records,&receipts).is_ok());
        assert!(verify_projected_receipt_lineage(&records[..2],&receipts).is_err());
        let mut changed = receipts.clone(); changed[0].request_hash = "b".repeat(64);
        assert!(verify_projected_receipt_lineage(&records,&changed).is_err());
        let mut duplicate = records.clone(); duplicate.push(records[0].clone());
        assert!(verify_projected_receipt_lineage(&duplicate,&receipts).is_err());
        assert!(verify_projected_receipt_lineage(&records,&receipts[..2]).is_ok()); // a lost projection reply is not new state authority
    }
    #[test]
    fn startup_reconciliation_selects_exactly_three_missing_verified_receipts_in_order() {
        let base = projection_sequence_fixture();
        let records: Vec<_> = (1..=4)
            .map(|sequence| {
                let mut record = base.clone();
                record.sequence = sequence;
                record.receipt.receipt_id = format!("receipt-{sequence}");
                record
            })
            .collect();
        let missing = missing_projected_receipts(&records, &[records[0].receipt.clone()]).unwrap();
        assert_eq!(
            missing
                .iter()
                .map(|receipt| receipt.receipt_id.as_str())
                .collect::<Vec<_>>(),
            vec!["receipt-2", "receipt-3", "receipt-4"]
        );
        let mut conflicting = records[0].receipt.clone();
        conflicting.request_hash = "f".repeat(64);
        assert!(missing_projected_receipts(&records, &[conflicting]).is_err());
    }
    #[test]
    fn health_distinguishes_restore_busy_idle_stall_and_expired_authorization() {
        let health = ParentHealth::default();
        assert_eq!(health.check(100, 100, false, false), Err("DIRECT_STATE_RECOVERY_REQUIRED"));
        health.restored.store(true, Ordering::Release);
        health.observe(100);
        assert_eq!(health.check(110, 0, false, false), Ok(())); // idle, recent status
        assert_eq!(health.check(150, 148, true, false), Ok(())); // busy but commits progress
        assert_eq!(health.check(150, 0, false, false), Err("ENCLOSURE_UNAVAILABLE"));
        health.observe(160);
        assert_eq!(health.check(160, 99, true, false), Err("WRITE_PATH_STALLED"));
        assert_eq!(health.check(160, 160, false, true), Err("WRITER_AUTHORIZATION_EXPIRED"));
        assert_eq!(health.check(159, 0, false, false), Err("ENCLOSURE_UNAVAILABLE")); // clock regression
    }

    #[tokio::test]
    async fn cancelled_gate_wait_does_not_leave_a_false_stall() {
        let gate = Arc::new(FinancialGate::new());
        let owner = gate.lock("owner").await;
        let other = Arc::clone(&gate);
        let waiter = tokio::spawn(async move { other.lock("cancelled").await });
        for _ in 0..50 { if gate.snapshot(now_unix()).0 > 0 { break; } tokio::task::yield_now().await; }
        assert_eq!(gate.snapshot(now_unix()).0, 1);
        waiter.abort();
        let _ = waiter.await;
        assert_eq!(gate.snapshot(now_unix()).0, 0);
        assert!(!gate.stalled(now_unix() + 120));
        drop(owner);
    }

    #[tokio::test]
    async fn write_path_health_detects_a_waiter_without_blocking_on_the_gate() {
        let gate = Arc::new(FinancialGate::new());
        let owner = gate.lock("test-owner").await;
        let waiting_gate = Arc::clone(&gate);
        let waiter = tokio::spawn(async move { waiting_gate.lock("test-waiter").await });
        for _ in 0..50 {
            if gate.snapshot(now_unix()).0 == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
        let now = now_unix();
        let (_, age) = gate.snapshot(now);
        assert_eq!(age, Some(0));
        assert!(gate.stalled(now + WRITE_PATH_STALL_THRESHOLD.as_secs()));
        drop(owner);
        drop(waiter.await.unwrap());
        assert_eq!(gate.snapshot(now_unix()).0, 0);
    }
    #[tokio::test]
    async fn hung_enclave_and_archive_stages_return_stable_timeout_codes() {
        let gate = Arc::new(FinancialGate::new());
        let guard = gate.lock("timeout-owner").await;
        let enclave = bounded_enclave_stage(
            Duration::from_millis(5),
            std::future::pending::<io::Result<()>>(),
        )
        .await
        .unwrap_err();
        assert_eq!(enclave.kind(), io::ErrorKind::TimedOut);
        assert_eq!(enclave.to_string(), "ENCLOSURE_TIMEOUT");
        let archive = bounded_archive_operation(
            Duration::from_millis(5),
            std::future::pending::<Result<(), ()>>(),
        )
        .await
        .unwrap_err();
        assert_eq!(archive, "ARCHIVE_TIMEOUT");
        drop(guard);
        let next = timeout(Duration::from_secs(1), gate.lock("after-timeout"))
            .await
            .expect("timeout path retained the financial gate");
        drop(next);
    }
    #[tokio::test]
    async fn detached_commit_owner_survives_the_waiting_client_future() {
        let gate = Arc::new(FinancialGate::new());
        let guard = gate.lock("detached-commit-test").await;
        let recorded_receipt = Arc::new(Mutex::new(None));
        let task_receipt = Arc::clone(&recorded_receipt);
        let (completed_tx, completed_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _guard = guard;
            tokio::task::yield_now().await;
            *task_receipt.lock().await = Some("receipt-after-client-drop".to_string());
            let _ = completed_tx.send(());
        });
        drop(task); // equivalent to an HTTP handler dropping its JoinHandle
        timeout(Duration::from_secs(1), completed_rx)
            .await
            .expect("detached commit task timed out")
            .expect("detached commit task was cancelled");
        assert_eq!(
            recorded_receipt.lock().await.as_deref(),
            Some("receipt-after-client-drop")
        );
        let next = timeout(Duration::from_secs(1), gate.lock("next-request"))
            .await
            .expect("financial gate was not released");
        drop(next);
    }
    #[tokio::test]
    async fn failed_projection_releases_gate_and_verified_receipt_replays_on_restart() {
        let gate = Arc::new(FinancialGate::new());
        let guard = gate.lock("projection-outage").await;
        let artifact = projection_sequence_fixture();
        let committed_receipt = artifact.receipt.clone();

        // Model an unreachable disposable projection after the immutable
        // receipt committed. The task fails, drops its owned guard, and the
        // next request can enter; the verified archive still selects the exact
        // absent receipt for startup replay.
        let task = tokio::spawn(async move {
            let _guard = guard;
            Err::<(), _>(ProjectionError::Database)
        });
        assert!(task.await.unwrap().is_err());
        let next = timeout(Duration::from_secs(1), gate.lock("after-projection-outage"))
            .await
            .expect("projection outage retained the financial gate");
        drop(next);
        let replay = missing_projected_receipts(&[artifact], &[]).unwrap();
        assert_eq!(replay, vec![committed_receipt]);
    }
    #[test]
    fn same_host_parent_restart_accepts_only_the_exact_live_governed_enclave() {
        let mut status = layrs_direct_execution_v1::RuntimeBinding {
            runtime: "runtime".into(),
            transaction_model: "model".into(),
            epoch_state_sha256: "a".repeat(64),
            evidence_manifest_sha256: "b".repeat(64),
            genesis_ordinal: 0,
            writer_enabled: true,
            admission_enabled: true,
            identity_count: 0,
            projection_schema_version: 1,
            writer_grant_commitment: Some("commitment".into()),
            writer_grant_expires_at_unix: Some(now_unix() + 60),
            key_release_artifact_hash: Some("c".repeat(64)),
        };
        assert!(governed_bootstrap_status_matches(
            &status,
            "commitment",
            "production-enabled"
        ));
        assert!(!governed_bootstrap_status_matches(
            &status,
            "different",
            "production-enabled"
        ));
        status.writer_enabled = false;
        assert!(governed_bootstrap_status_matches(
            &status,
            "commitment",
            "admission-enabled"
        ));
    }
    #[test]
    fn projection_sequence_requires_exact_verified_receipt() {
        let artifact = projection_sequence_fixture();
        assert_eq!(verified_receipt_sequence(&[artifact.clone()], &artifact.receipt).unwrap(), 7);
        let mut altered = artifact.receipt.clone(); altered.effect = "OTHER".into();
        assert!(verified_receipt_sequence(&[artifact.clone()], &altered).is_err());
        assert!(verified_receipt_sequence(&[], &artifact.receipt).is_err());
        assert!(verified_receipt_sequence(&[artifact.clone(), artifact.clone()], &artifact.receipt).is_err());
    }
    #[test]
    fn projection_sequence_rejects_foreign_zero_and_overflow_artifacts() {
        let original = projection_sequence_fixture();
        for sequence in [0, i64::MAX as u64 + 1] {
            let mut artifact = original.clone(); artifact.sequence = sequence;
            assert!(verified_receipt_sequence(&[artifact], &original.receipt).is_err());
        }
        let mut foreign = original.clone(); foreign.epoch_id = "foreign".into();
        assert!(verified_receipt_sequence(&[foreign], &original.receipt).is_err());
    }
    #[test]
    fn receipt_cache_releases_entire_snapshot_allocation() {
        let artifact=DirectStateArtifact {epoch_id:EPOCH_ID.into(),sequence:1,prior_state_hash:"a".repeat(64),state_hash:"b".repeat(64),request_hash:"c".repeat(64),nonce:vec![1;12],ciphertext:vec![7;2_000_000],ciphertext_hash:"d".repeat(64),
            receipt:DirectReceipt {receipt_id:"receipt".into(),account_id:"account".into(),identity_commitment:"identity".into(),request_id:"request".into(),request_hash:"c".repeat(64),status:layrs_direct_execution_v1::TerminalStatus::Applied,effect:"BALANCE_READ".into(),amount_atomic:None,custody_reference:None,execution:None,resolution:None,projection_balance_updates:vec![],genesis_ordinal:0,signature:"signature".into()}};
        let record=receipt_only_record(&artifact);
        assert_eq!(record.ciphertext.capacity(),0);
        assert!(record.ciphertext.is_empty());
        assert_eq!(record.receipt,artifact.receipt);
        assert_eq!(record.state_hash,artifact.state_hash);
        assert_eq!(artifact.ciphertext.len(),2_000_000);
    }
    #[tokio::test]
    async fn s3_archive_read_discards_truncated_body_and_retries_same_immutable_key() {
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let address=listener.local_addr().unwrap();
        let server=tokio::spawn(async move {
            for attempt in 0..2 {
                let (mut socket,_)=listener.accept().await.unwrap();let mut buffer=vec![0;8192];let size=socket.read(&mut buffer).await.unwrap();
                assert!(String::from_utf8_lossy(&buffer[..size]).contains("/unit-test/epoch/immutable.cbor"));
                let body=if attempt==0 {"bad"}else{"complete-opaque-ciphertext"};
                let length=if attempt==0 {64}else{body.len()};
                socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n{body}").as_bytes()).await.unwrap();
            }
        });
        let configuration=aws_sdk_s3::config::Builder::new().behavior_version_latest().region(aws_sdk_s3::config::Region::new("us-east-1")).credentials_provider(aws_sdk_s3::config::Credentials::new("unit-test","unit-test",None,None,"local-only")).endpoint_url(format!("http://{address}")).force_path_style(true).build();
        let store=S3ImmutableArtifactStore {client:S3Client::from_conf(configuration),bucket:"unit-test".into(),prefix:"epoch".into(),kms_key_id:"not-used".into(),retention_seconds:86400,verified_receipt_records:Arc::new(Mutex::new(None)),verified_artifact_hashes:Arc::new(Mutex::new(Vec::new())),prepared_restore:Arc::new(Mutex::new(None)),prepared_journal_restore:Arc::new(Mutex::new(None)),checkpoint_refresh_gate:Arc::new(Mutex::new(CheckpointRefresh::default())),journal:Arc::new(Mutex::new(JournalWriterState::Unrestored)),journal_role:JournalRole::Writer};
        assert_eq!(store.read("epoch/immutable.cbor").await.unwrap().as_ref(),b"complete-opaque-ciphertext");server.await.unwrap();
    }
    #[tokio::test]
    async fn s3_archive_read_fails_closed_after_five_truncated_bodies() {
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let address=listener.local_addr().unwrap();
        let server=tokio::spawn(async move {
            for _ in 0..5 {
                let (mut socket,_)=listener.accept().await.unwrap();let mut buffer=vec![0;8192];socket.read(&mut buffer).await.unwrap();
                socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 64\r\nConnection: close\r\n\r\nbad").await.unwrap();
            }
        });
        let configuration=aws_sdk_s3::config::Builder::new().behavior_version_latest().region(aws_sdk_s3::config::Region::new("us-east-1")).credentials_provider(aws_sdk_s3::config::Credentials::new("unit-test","unit-test",None,None,"local-only")).endpoint_url(format!("http://{address}")).force_path_style(true).build();
        let store=S3ImmutableArtifactStore {client:S3Client::from_conf(configuration),bucket:"unit-test".into(),prefix:"epoch".into(),kms_key_id:"not-used".into(),retention_seconds:86400,verified_receipt_records:Arc::new(Mutex::new(None)),verified_artifact_hashes:Arc::new(Mutex::new(Vec::new())),prepared_restore:Arc::new(Mutex::new(None)),prepared_journal_restore:Arc::new(Mutex::new(None)),checkpoint_refresh_gate:Arc::new(Mutex::new(CheckpointRefresh::default())),journal:Arc::new(Mutex::new(JournalWriterState::Unrestored)),journal_role:JournalRole::Writer};
        assert_eq!(store.read("epoch/immutable.cbor").await.unwrap_err(),"archive complete read retries exhausted");server.await.unwrap();
    }
    #[tokio::test]
    async fn s3_restore_listing_reads_beyond_the_first_thousand_without_skipping_keys() {
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let address=listener.local_addr().unwrap();
        let server=tokio::spawn(async move {
            for page in 0..2 {
                let (mut socket,_)=listener.accept().await.unwrap();let mut buffer=vec![0;8192];let size=socket.read(&mut buffer).await.unwrap();let request=String::from_utf8_lossy(&buffer[..size]);
                if page==1 {assert!(request.contains("continuation-token=page-two"));}
                let start=page*1000;let end=if page==0 {1000}else{1250};
                let objects=(start..end).map(|i|format!("<Contents><Key>epoch/artifacts/{:020}.cbor</Key><Size>1</Size></Contents>",i+1)).collect::<String>();
                let next=if page==0 {"<NextContinuationToken>page-two</NextContinuationToken>"}else{""};
                let body=format!("<?xml version=\"1.0\"?><ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><IsTruncated>{}</IsTruncated>{next}{objects}</ListBucketResult>",page==0);
                socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
            }
        });
        let configuration=aws_sdk_s3::config::Builder::new().behavior_version_latest().region(aws_sdk_s3::config::Region::new("us-east-1")).credentials_provider(aws_sdk_s3::config::Credentials::new("unit-test","unit-test",None,None,"local-only")).endpoint_url(format!("http://{address}")).force_path_style(true).build();
        let store=S3ImmutableArtifactStore {client:S3Client::from_conf(configuration),bucket:"unit-test".into(),prefix:"epoch".into(),kms_key_id:"not-used".into(),retention_seconds:86400,verified_receipt_records:Arc::new(Mutex::new(None)),verified_artifact_hashes:Arc::new(Mutex::new(Vec::new())),prepared_restore:Arc::new(Mutex::new(None)),prepared_journal_restore:Arc::new(Mutex::new(None)),checkpoint_refresh_gate:Arc::new(Mutex::new(CheckpointRefresh::default())),journal:Arc::new(Mutex::new(JournalWriterState::Unrestored)),journal_role:JournalRole::Writer};
        let keys=store.list_restore_keys("artifacts").await.unwrap();assert_eq!(keys.len(),1250);assert!(keys.first().unwrap().contains("00000000000000000001"));assert!(keys.last().unwrap().contains("00000000000000001250"));server.await.unwrap();
    }

    fn relay_binding() -> RelayWithdrawalBinding {
        RelayWithdrawalBinding {
            route_id: "11111111-2222-4333-8444-555555555555".into(),
            request_id: format!("0x{}", "aa".repeat(32)),
            deposit_address: "0x2222222222222222222222222222222222222222".into(),
            destination_chain_id: 42_161,
            destination_currency: "0xaf88d065e77c8cc2239327c5edb3a432268e5831".into(),
            recipient: "0x3333333333333333333333333333333333333333".into(),
            quoted_destination_amount_atomic: "4990000".into(),
            minimum_destination_amount_atomic: "4980000".into(),
            quote_payload_sha256: "44".repeat(32),
            expires_at_unix: 10_000,
        }
    }

    fn relay_intent() -> ExternalEffectIntent {
        let relay = relay_binding();
        let reference = relay_reference_for(
            &"a".repeat(64),
            "relay-withdrawal:11111111-2222-4333-8444-555555555555",
            &"b".repeat(64),
            "identity",
            "5000000",
            "existing-wallet",
            &relay,
        );
        let mut request = DirectRequest {
            account_id: "b".repeat(64),
            identity_commitment: "identity".into(),
            request_id: "relay-withdrawal:11111111-2222-4333-8444-555555555555".into(),
            request_hash: String::new(),
            financial_wallet_address: None,
            action: DirectAction::SettleRelayWithdrawal {
                relay: relay.clone(),
                amount_atomic: "5000000".into(),
                custody_reference: reference,
            },
        };
        request.request_hash = request_hash(&request);
        ExternalEffectIntent::create_relay_withdrawal(
            "a".repeat(64),
            request.request_id,
            request.request_hash,
            request.account_id,
            request.identity_commitment,
            "5000000".into(),
            "existing-wallet".into(),
            "0x1111111111111111111111111111111111111111".into(),
            "7".into(),
            "180000".into(),
            "2000000000".into(),
            "1000000000".into(),
            100,
            relay,
        )
        .unwrap()
    }

    fn relay_success_evidence(intent: &ExternalEffectIntent) -> (Value, Value, String, String) {
        let relay = intent.relay.as_ref().unwrap();
        let intake = format!("0x{}", "55".repeat(32));
        let destination = format!("0x{}", "66".repeat(32));
        let status = json!({
            "status": "success",
            "requestId": relay.request_id,
            "inTxHashes": [intake],
            "txHashes": [destination],
            "originChainId": 8453,
            "destinationChainId": relay.destination_chain_id,
        });
        let details = json!({"requests": [{
            "id": relay.request_id,
            "status": "success",
            "recipient": relay.recipient,
            "depositAddress": {"address": relay.deposit_address, "type": "strict"},
            "data": {
                "inTxs": [{"txHash": intake, "chainId": 8453, "status": "success"}],
                "outTxs": [{"txHash": destination, "chainId": relay.destination_chain_id, "status": "success"}],
                "route": {
                    "quoted": {
                        "origin": {"inputCurrency": {"currency": {"chainId": 8453, "address": BASE_USDC_ADDRESS}, "amount": intent.amount_atomic}},
                        "destination": {"outputCurrency": {"currency": {"chainId": relay.destination_chain_id, "address": relay.destination_currency}, "amount": relay.quoted_destination_amount_atomic}}
                    },
                    "actual": {
                        "destination": {"outputCurrency": {"currency": {"chainId": relay.destination_chain_id, "address": relay.destination_currency}, "amount": "4985000"}}
                    }
                }
            }
        }]});
        (status, details, intake, destination)
    }

    fn relay_forwarding_fixture() -> (ExternalEffectIntent, Value, Value, String, String, Value, Value, Value) {
        let intent = relay_intent();
        let (mut status, mut details, deposit_hash, _) = relay_success_evidence(&intent);
        let hash = format!("0x{}", "77".repeat(32));
        status["inTxHashes"] = json!([hash]);
        details["requests"][0]["depositAddress"]["depositor"] = json!("0x1111111111111111111111111111111111111111");
        details["requests"][0]["depositAddress"]["depositTxHash"] = json!(deposit_hash);
        details["requests"][0]["data"]["inTxs"][0]["txHash"] = json!(hash);
        let block_hash = format!("0x{}", "88".repeat(32));
        let block = json!({"hash":block_hash,"number":"0x66"});
        let deposit_block_hash = format!("0x{}", "aa".repeat(32));
        let deposit = json!({"status":"0x1","transactionHash":deposit_hash,"blockHash":deposit_block_hash,"blockNumber":"0x64","logs":[{
            "address":BASE_USDC_ADDRESS,"transactionHash":deposit_hash,"blockHash":deposit_block_hash,"removed":false,
            "topics":[ERC20_TRANSFER_TOPIC,address_topic("0x1111111111111111111111111111111111111111"),address_topic(&intent.relay.as_ref().unwrap().deposit_address)],
            "data":quantity(5_000_000)
        }]});
        let receipt = json!({"status":"0x1","transactionHash":hash,"blockHash":block_hash,"blockNumber":"0x66","logs":[{
            "address":BASE_USDC_ADDRESS,"transactionHash":hash,"blockHash":block_hash,"removed":false,
            "topics":[ERC20_TRANSFER_TOPIC,address_topic(&intent.relay.as_ref().unwrap().deposit_address),address_topic("0x9999999999999999999999999999999999999999")],
            "data":quantity(5_000_000)
        }]});
        (intent,status,details,deposit_hash,hash,deposit,receipt,block)
    }

    fn forwarding_fixture_is_canonical(intent: &ExternalEffectIntent, hash: &str, deposit: &Value, receipt: &Value, block: &Value, head: u128) -> bool {
        let deposit_block = json!({"hash":format!("0x{}", "aa".repeat(32)),"number":"0x64"});
        let original = format!("0x{}", "55".repeat(32));
        relay_forwarding_is_canonical(intent,"0x1111111111111111111111111111111111111111",&original,hash,deposit,&deposit_block,receipt,block,head,20)
    }

    #[test]
    fn relay_forwarded_deposit_binds_original_payout_and_terminal_result() {
        let (intent,status,details,deposit_hash,hash,deposit,receipt,block) = relay_forwarding_fixture();
        let pool = "0x1111111111111111111111111111111111111111";
        assert_eq!(relay_forwarding_candidate(&intent,pool,&deposit_hash,&status,&details),Some(hash.clone()));
        assert!(forwarding_fixture_is_canonical(&intent,&hash,&deposit,&receipt,&block,121));
        // Provider metadata alone must never enable the alternate intake hash.
        assert_eq!(classify_relay_destination_finality(&intent,"provider".into(),deposit_hash.clone(),&status,&details).unwrap(),layrs_direct_execution_v1::ExternalEffectObservation::Conflict);
        let proof = VerifiedRelayForwarding {deposit_hash:deposit_hash.clone(),forwarding_hash:hash};
        let observation = classify_relay_destination_finality_with_forwarding(&intent,"provider".into(),deposit_hash.clone(),&status,&details,Some(&proof)).unwrap();
        let terminal = intent.recovery_action(200,observation);
        let first = request_for_external_effect(&intent,terminal.clone()).unwrap();
        assert_eq!(first,request_for_external_effect(&intent,terminal).unwrap());
        assert_eq!(first.request_hash,intent.request_hash);
        assert!(matches!(first.action,DirectAction::SettleRelayWithdrawal {custody_reference,..} if custody_reference.contains(&deposit_hash) && !custody_reference.contains(&proof.forwarding_hash)));
    }

    #[test]
    fn relay_forwarding_metadata_substitution_and_ambiguous_hashes_fail_closed() {
        let (intent,status,details,deposit_hash,_,_,_,_) = relay_forwarding_fixture();
        let pool = "0x1111111111111111111111111111111111111111";
        for key in ["address","depositor","depositTxHash","type"] {
            let mut changed = details.clone();
            changed["requests"][0]["depositAddress"][key] = json!("substitution");
            assert!(relay_forwarding_candidate(&intent,pool,&deposit_hash,&status,&changed).is_none(),"{key}");
        }
        let mut changed = status.clone();changed["inTxHashes"] = json!([format!("0x{}","77".repeat(32)),format!("0x{}","99".repeat(32))]);
        assert!(relay_forwarding_candidate(&intent,pool,&deposit_hash,&changed,&details).is_none());
        let mut changed = details.clone();changed["requests"][0]["data"]["inTxs"][0]["chainId"] = json!(42161);
        assert!(relay_forwarding_candidate(&intent,pool,&deposit_hash,&status,&changed).is_none());
    }

    #[test]
    fn relay_forwarding_reorg_wrong_token_sender_amount_and_unfinalized_fail_closed() {
        let (intent,_,_,_,hash,deposit,receipt,block) = relay_forwarding_fixture();
        for field in ["status","transactionHash","blockHash","blockNumber"] {
            let mut changed = receipt.clone();changed[field] = json!("0x0");
            assert!(!forwarding_fixture_is_canonical(&intent,&hash,&deposit,&changed,&block,121),"{field}");
        }
        for field in ["address","transactionHash","blockHash","data"] {
            let mut changed = receipt.clone();changed["logs"][0][field] = json!("0x0");
            assert!(!forwarding_fixture_is_canonical(&intent,&hash,&deposit,&changed,&block,121),"log {field}");
        }
        let mut changed = receipt.clone();changed["logs"][0]["removed"] = json!(true);
        assert!(!forwarding_fixture_is_canonical(&intent,&hash,&deposit,&changed,&block,121));
        let mut changed = receipt.clone();changed["logs"][0]["topics"][1] = json!(address_topic("0x9999999999999999999999999999999999999999"));
        assert!(!forwarding_fixture_is_canonical(&intent,&hash,&deposit,&changed,&block,121));
        let mut changed = receipt.clone();changed["logs"].as_array_mut().unwrap().push(receipt["logs"][0].clone());
        assert!(!forwarding_fixture_is_canonical(&intent,&hash,&deposit,&changed,&block,121));
        assert!(!forwarding_fixture_is_canonical(&intent,&hash,&deposit,&receipt,&block,120));
        let mut changed = deposit.clone();changed["blockNumber"] = json!("0x67");
        assert!(!forwarding_fixture_is_canonical(&intent,&hash,&changed,&receipt,&block,121));
        for field in ["status","transactionHash","blockHash","blockNumber"] {
            let mut changed = deposit.clone();changed[field] = json!("0x0");
            assert!(!forwarding_fixture_is_canonical(&intent,&hash,&changed,&receipt,&block,121),"deposit {field}");
        }
        for field in ["address","transactionHash","blockHash","data"] {
            let mut changed = deposit.clone();changed["logs"][0][field] = json!("0x0");
            assert!(!forwarding_fixture_is_canonical(&intent,&hash,&changed,&receipt,&block,121),"deposit log {field}");
        }
    }

    #[test]
    fn relay_pending_intents_remain_in_background_observation_without_broadcast() {
        let mut intent = relay_intent();
        assert!(base_withdrawal_observation_supported(&intent));
        intent.relay = None;
        assert!(base_withdrawal_observation_supported(&intent));
        intent.chain = "horizen".into();
        assert!(!base_withdrawal_observation_supported(&intent));
        intent.chain = "base".into();intent.asset = "ZEN".into();
        assert!(!base_withdrawal_observation_supported(&intent));
    }

    #[tokio::test]
    async fn forwarded_relay_transport_only_reads_original_bound_chain_and_provider_evidence() {
        let (intent,status,details,deposit_hash,hash,deposit,receipt,block) = relay_forwarding_fixture();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let observed = Arc::new(Mutex::new(Vec::<String>::new()));
        let calls = observed.clone();
        let original = deposit_hash.clone();
        let forward = hash.clone();
        let reference = intent.external_effect_reference.clone();
        let provider_record = json!({"data":[{"id":"provider","wallet_id":intent.provider_wallet_id,"caip2":"eip155:8453","reference_id":reference,"status":"confirmed","transaction_hash":deposit_hash,"sponsored":false}]});
        let calldata = pool_withdraw_calldata(&intent.destination,&intent.amount_atomic).unwrap();
        let app = Router::new()
            .route("/v1/transactions",get(move |Query(query):Query<BTreeMap<String,String>>| {let v=provider_record.clone();let reference=reference.clone();async move {assert_eq!(query.get("reference_id"),Some(&reference));Json(v)}}))
            .route("/intents/status/v3",get(move || { let v=status.clone();async move {Json(v)} }))
            .route("/requests/v3",get(move || {let v=details.clone();async move {Json(v)} }))
            .route("/rpc",post(move |Json(body):Json<Value>| {
                let calls=calls.clone();let original=original.clone();let forward=forward.clone();
                let deposit=deposit.clone();let receipt=receipt.clone();let block=block.clone();
                let calldata=calldata.clone();
                async move {
                    let method=body["method"].as_str().unwrap().to_string();
                    calls.lock().await.push(method.clone());
                    let value=match method.as_str() {
                        "eth_getTransactionByHash" if body["params"][0] == original => json!({"from":"0x4444444444444444444444444444444444444444","to":"0x1111111111111111111111111111111111111111","input":calldata}),
                        "eth_getTransactionReceipt" if body["params"][0] == original => deposit,
                        "eth_getTransactionReceipt" if body["params"][0] == forward => receipt,
                        "eth_getBlockByNumber" if body["params"][0] == "0x64" => json!({"hash":format!("0x{}","aa".repeat(32)),"number":"0x64"}),
                        "eth_getBlockByNumber" if body["params"][0] == "0x66" => block,
                        "eth_blockNumber" => json!(quantity(121)),
                        _ => panic!("unexpected financial submission or substituted chain reference"),
                    };
                    Json(json!({"jsonrpc":"2.0","id":body["id"],"result":value}))
                }
            }));
        let server=tokio::spawn(async move {axum::serve(listener,app).await.unwrap()});
        let custody=PrivyBaseCustodyAdapter {
            client:reqwest::Client::builder().timeout(Duration::from_secs(2)).build().unwrap(),
            app_id:"synthetic".into(),app_secret:"synthetic".into(),wallet_id:intent.provider_wallet_id.clone(),
            wallet_address:"0x4444444444444444444444444444444444444444".into(),authorization_key_pem:"unused".into(),
            rpc_url:format!("http://{address}/rpc"),pool_address:intent.custody_target.clone(),
            confirmations:20,api_base_url:format!("http://{address}"),relay_api_key:Some("synthetic".into()),relay_api_base_url:format!("http://{address}"),
        };
        for _ in 0..2 {
            let terminal=custody.observe_terminal_only(&intent).await.unwrap();
            assert!(matches!(terminal,ExternalEffectRecovery::BindRelayFinalized {..}));
            let request=request_for_external_effect(&intent,terminal).unwrap();
            assert_eq!(request.request_hash,intent.request_hash);
            assert!(matches!(request.action,DirectAction::SettleRelayWithdrawal {custody_reference,..} if custody_reference.contains(&deposit_hash) && !custody_reference.contains(&hash)));
        }
        assert_eq!(*observed.lock().await,vec!["eth_getTransactionByHash","eth_getTransactionReceipt","eth_blockNumber","eth_getTransactionReceipt","eth_getBlockByNumber","eth_getTransactionReceipt","eth_getBlockByNumber","eth_blockNumber"].repeat(2));
        server.abort();
    }

    #[test]
    fn historical_observation_does_not_reopen_new_relay_withdrawals() {
        assert!(validate_new_withdrawal_route(None).is_ok());
        assert_eq!(validate_new_withdrawal_route(Some(&relay_binding())),Err((StatusCode::GONE,"RELAY_ROUTE_RETIRED")));
    }

    #[test]
    fn retired_relay_unknown_or_unproven_refund_never_releases_the_fence() {
        for outcome in [ExternalEffectRecovery::SubmitWithStableReference,ExternalEffectRecovery::AwaitExternalFinality,ExternalEffectRecovery::FailClosed,
            ExternalEffectRecovery::BindRelayReverted {provider_transaction_id:"provider".into(),intake_transaction_hash:format!("0x{}","55".repeat(32)),relay_request_id:relay_binding().request_id,terminal_status:"refund".into(),result_hash:"aa".repeat(32)}] {
            assert!(observed_terminal_recovery(outcome).is_err());
        }
        assert!(observed_terminal_recovery(ExternalEffectRecovery::BindReverted {provider_transaction_id:"provider".into(),transaction_hash:format!("0x{}","55".repeat(32))}).is_ok());
    }

    #[test]
    fn relay_intake_never_finalizes_private_withdrawal_while_destination_is_pending() {
        let intent = relay_intent();
        let relay = intent.relay.as_ref().unwrap();
        let intake = format!("0x{}", "55".repeat(32));
        let observation = classify_relay_destination_finality(
            &intent,
            "privy-transaction".into(),
            intake.clone(),
            &json!({
                "status": "pending", "requestId": relay.request_id,
                "inTxHashes": [intake], "originChainId": 8453,
                "destinationChainId": relay.destination_chain_id,
            }),
            &Value::Null,
        )
        .unwrap();
        assert!(matches!(
            intent.recovery_action(200, observation),
            ExternalEffectRecovery::AwaitExternalFinality
        ));
    }

    #[test]
    fn relay_success_binds_exact_route_destination_result_and_replays_identically() {
        let intent = relay_intent();
        let (status, details, intake, destination) = relay_success_evidence(&intent);
        let observation = classify_relay_destination_finality(
            &intent,
            "privy-transaction".into(),
            intake,
            &status,
            &details,
        )
        .unwrap();
        let terminal = intent.recovery_action(200, observation);
        assert!(matches!(
            terminal,
            ExternalEffectRecovery::BindRelayFinalized { .. }
        ));
        let first = request_for_external_effect(&intent, terminal.clone()).unwrap();
        let replay = request_for_external_effect(&intent, terminal).unwrap();
        assert_eq!(first, replay);
        assert_eq!(first.request_hash, intent.request_hash);
        assert!(
            matches!(first.action, DirectAction::SettleRelayWithdrawal { custody_reference, .. }
            if custody_reference.contains(&destination))
        );
    }

    #[test]
    fn relay_conflicting_recipient_amount_or_transaction_fails_closed() {
        let intent = relay_intent();
        let (status, mut details, intake, _) = relay_success_evidence(&intent);
        details["requests"][0]["recipient"] = json!("0x9999999999999999999999999999999999999999");
        assert_eq!(
            classify_relay_destination_finality(
                &intent,
                "privy-transaction".into(),
                intake.clone(),
                &status,
                &details,
            )
            .unwrap(),
            layrs_direct_execution_v1::ExternalEffectObservation::Conflict,
        );
        let (status, mut details, _, _) = relay_success_evidence(&intent);
        details["requests"][0]["data"]["route"]["actual"]["destination"]["outputCurrency"]
            ["amount"] = json!("1");
        assert_eq!(
            classify_relay_destination_finality(
                &intent,
                "privy-transaction".into(),
                intake,
                &status,
                &details,
            )
            .unwrap(),
            layrs_direct_execution_v1::ExternalEffectObservation::Conflict,
        );
    }
    #[test]
    fn privy_session_derivation_is_epoch_bound_and_deterministic() {
        let secret = b"p".repeat(32);
        let first = derive_direct_session_key(&secret);
        let second = derive_direct_session_key(&secret);
        assert_eq!(first, second);
        assert_eq!(
            hex::encode(&first),
            "4fe34632da8b4234bc67e743148300263046ab646abc3cd1e49a3c8c6ad6abd9"
        );
        assert_eq!(first.len(), 32);
        assert_ne!(first, secret);
    }
    #[test]
    fn privy_request_expiry_uses_milliseconds() {
        let before = now_unix_millis();
        let expiry = now_unix_millis().checked_add(60_000).unwrap();
        let after = now_unix_millis();
        assert!(expiry >= before + 60_000);
        assert!(expiry <= after + 60_000);
        assert!(expiry >= 1_000_000_000_000);
    }
    #[test]
    fn bff_listener_is_loopback_until_governed_production_mode() {
        assert_eq!(
            runtime_bind_address(None, Some("dormant"), false).unwrap(),
            std::net::Ipv4Addr::LOCALHOST,
        );
        assert!(runtime_bind_address(Some("0.0.0.0"), Some("dormant"), false).is_err());
        assert_eq!(
            runtime_bind_address(Some("0.0.0.0"), Some("dormant"), true).unwrap(),
            "0.0.0.0".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            runtime_bind_address(Some("0.0.0.0"), Some("production-enabled"), false).unwrap(),
            std::net::Ipv4Addr::UNSPECIFIED,
        );
    }
    #[test]
    fn packaged_isolated_routes_are_test_only_and_production_routes_remain_grant_scoped() {
        assert!(direct_writer_route_enabled(true, Some("dormant")));
        assert!(direct_admission_route_enabled(true, Some("dormant")));
        assert!(!direct_writer_route_enabled(false, Some("dormant")));
        assert!(!direct_admission_route_enabled(false, Some("dormant")));
        assert!(!direct_writer_route_enabled(
            false,
            Some("admission-enabled")
        ));
        assert!(direct_admission_route_enabled(
            false,
            Some("admission-enabled")
        ));
        assert!(direct_writer_route_enabled(
            false,
            Some("production-enabled")
        ));
        assert!(direct_admission_route_enabled(
            false,
            Some("production-enabled")
        ));
    }
    #[test]
    fn signed_session_rejects_tampering() {
        let key = vec![9; 32];
        let mut claims = SessionClaims {
            session_id: "isolated-parent-session-0001".into(),
            subject_hash: "a".repeat(64),
            privy_user_id_hash: "b".repeat(64),
            audience: SESSION_AUDIENCE.into(),
            epoch_id: EPOCH_ID.into(),
            epoch_state_sha256: layrs_direct_execution_v1::EPOCH_STATE_SHA256.into(),
            wallet_address: "0x1111111111111111111111111111111111111111".into(),
            financial_wallet_address: None,
            identity_commitment: "c".repeat(64),
            expires_at_unix: now_unix() + 60,
            response_key: URL_SAFE_NO_PAD.encode([3u8; 32]),
            signature: String::new(),
        };
        claims.signature = sign(&key, &serde_json::to_vec(&claims).unwrap());
        let frame=quest_receipt_frame(&claims,QuestReceiptQuery{receipt_account_id:"d".repeat(64),request_id:"taker-fill-01".into(),nonce:hex::encode([42;32])}).unwrap();
        assert_eq!(frame,RuntimeRequest::PublicQuestReceipt{participant_account:claims.subject_hash.clone(),receipt_account:"d".repeat(64),request_id:"taker-fill-01".into(),nonce:vec![42;32]});
        for (owner,request) in [("D".repeat(64),"valid".into()),("d".repeat(64),"x".repeat(129)),("d".repeat(64),"bad/request".into())] {
            assert!(quest_receipt_frame(&claims,QuestReceiptQuery{receipt_account_id:owner,request_id:request,nonce:hex::encode([42;32])}).is_err());
        }
        assert!(serde_json::from_value::<QuestReceiptQuery>(json!({"receiptAccountId":"d".repeat(64),"requestId":"fill","participantAccount":"e".repeat(64)})).is_err());
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            format!(
                "Bearer {}",
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
            )
            .parse()
            .unwrap(),
        );
        let state = AppState {
            enclave_cid: 16,
            session_key: key,
            isolated_test: true,
            projection: None,
            local_used_sessions: Arc::new(Mutex::new(HashSet::new())),
            artifact_store: None,
            commit_ack_key: Vec::new(),
            custody: None,
            zen_custody: None,
            usdc_custody: None,
            usdc_link_authority: None,
            usdc_bus_custody: None,
        financial_gate: Arc::new(FinancialGate::new()),
        last_commit_at: Arc::new(AtomicU64::new(0)),
        health: Arc::new(ParentHealth::default()),
            committed_state_root: Arc::new(Mutex::new(None)),
            unresolved_external_effects: Arc::new(Mutex::new(BTreeMap::new())),
            governed_bootstrap: None,
            persistence_format: PersistenceFormat::V70,
            hot_v71_enabled: Arc::new(AtomicBool::new(false)),
            journal_request_index: Arc::new(Mutex::new(None)),
            journal_receipts: Arc::new(Mutex::new(None)),
            journal_migration: Arc::new(Mutex::new(None)),
            journal_checkpoint_sequence: Arc::new(AtomicU64::new(0)),
            journal_transition_roots: Arc::new(Mutex::new(None)),
        };
        assert!(authenticated(&headers, &state).is_ok());

        claims.financial_wallet_address = Some(claims.wallet_address.clone());
        claims.signature.clear();
        claims.signature = sign(&state.session_key, &serde_json::to_vec(&claims).unwrap());
        headers.insert(
            "authorization",
            format!(
                "Bearer {}",
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
            )
            .parse()
            .unwrap(),
        );
        // Equality with the Privy auth wallet is not an authorization error:
        // this optional field does not select or restrict a withdrawal
        // destination. The signed action supplies that destination.
        assert!(authenticated(&headers, &state).is_ok());

        claims.financial_wallet_address = Some("0x2222222222222222222222222222222222222222".into());
        claims.signature.clear();
        claims.signature = sign(&state.session_key, &serde_json::to_vec(&claims).unwrap());
        headers.insert(
            "authorization",
            format!(
                "Bearer {}",
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
            )
            .parse()
            .unwrap(),
        );
        assert!(authenticated(&headers, &state).is_ok());

        claims.financial_wallet_address = Some("not-an-address".into());
        claims.signature.clear();
        claims.signature = sign(&state.session_key, &serde_json::to_vec(&claims).unwrap());
        headers.insert(
            "authorization",
            format!(
                "Bearer {}",
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
            )
            .parse()
            .unwrap(),
        );
        assert!(authenticated(&headers, &state).is_err());

        headers.insert("authorization", "Bearer bad".parse().unwrap());
        assert!(authenticated(&headers, &state).is_err());
    }
    #[tokio::test]
    async fn private_quest_witness_encryption_uses_fresh_nonce_even_for_repeated_equal_length_queries() {
        let claims=SessionClaims{session_id:"unit-test-only-session".into(),subject_hash:"a".repeat(64),privy_user_id_hash:"b".repeat(64),
            audience:SESSION_AUDIENCE.into(),epoch_id:EPOCH_ID.into(),epoch_state_sha256:layrs_direct_execution_v1::EPOCH_STATE_SHA256.into(),
            wallet_address:"0x1111111111111111111111111111111111111111".into(),financial_wallet_address:None,identity_commitment:"c".repeat(64),
            expires_at_unix:now_unix()+60,response_key:URL_SAFE_NO_PAD.encode([3;32]),signature:String::new()};
        let mut nonces=HashSet::new();
        for query in ["query-A","query-B","query-A"] {
            let body=json!({"syntheticPrivateLookup":query});
            let response=encrypted_quest_witness(&claims,&body);
            assert_eq!(response.status(),StatusCode::OK);
            let bytes=axum::body::to_bytes(response.into_body(),65536).await.unwrap();
            let envelope:Value=serde_json::from_slice(&bytes).unwrap();
            let nonce=URL_SAFE_NO_PAD.decode(envelope["nonce"].as_str().unwrap()).unwrap();
            assert_eq!(nonce.len(),12);assert!(nonces.insert(nonce.clone()));
            let ciphertext=URL_SAFE_NO_PAD.decode(envelope["ciphertext"].as_str().unwrap()).unwrap();
            let cipher=ChaCha20Poly1305::new(Key::from_slice(&[3;32]));
            assert_eq!(serde_json::from_slice::<Value>(&cipher.decrypt(Nonce::from_slice(&nonce),ciphertext.as_slice()).unwrap()).unwrap(),body);
        }
    }

    #[test]
    fn customer_command_accepts_documented_camel_case_fields() {
        let command: CustomerCommand = serde_json::from_value(serde_json::json!({
            "identityCommitment": "identity",
            "action": {
                "type": "RESERVE_WITHDRAWAL",
                "destination": "0xCCB96357dEB4cbF0808208d55916774f0B51a908",
                "amountAtomic": "1000000"
            }
        }))
        .unwrap();
        assert!(matches!(
            command.action,
            CustomerAction::ReserveWithdrawal { amount_atomic, .. } if amount_atomic == "1000000"
        ));
    }

    #[test]
    fn customer_deposit_requires_transaction_hash_and_exact_amount() {
        let command: CustomerCommand = serde_json::from_value(serde_json::json!({
            "identityCommitment": "identity",
            "action": {
                "type": "CREDIT_DEPOSIT",
                "transactionHash": format!("0x{}", "11".repeat(32)),
                "amountAtomic": "5000000"
            }
        }))
        .unwrap();
        assert!(matches!(
            command.action,
            CustomerAction::CreditDeposit { amount_atomic, .. } if amount_atomic == "5000000"
        ));
    }

    #[test]
    fn finalized_deposit_is_bound_to_wallet_pool_token_amount_and_confirmations() {
        let source = "0xd5d8f363b2122c1fcedaff313990b049fbd11e61";
        let pool = "0xb07627b0d646f5c82c8e30975a37650dc272a35f";
        let hash = format!("0x{}", "11".repeat(32));
        let block_hash = format!("0x{}", "22".repeat(32));
        let amount = 5_000_000u128;
        let transaction = json!({
            "from": source,
            "to": BASE_USDC_ADDRESS,
            "input": erc20_transfer_calldata(pool, amount).unwrap(),
            "value": "0x0",
            "blockHash": block_hash,
        });
        let receipt = json!({
            "transactionHash": hash,
            "blockHash": block_hash,
            "blockNumber": "0x64",
            "status": "0x1",
            "logs": [{
                "address": BASE_USDC_ADDRESS,
                "topics": [ERC20_TRANSFER_TOPIC, address_topic(source), address_topic(pool)],
                "data": quantity(amount),
            }],
        });
        assert_eq!(
            classify_base_deposit(source, pool, &hash, amount, 20, &transaction, &receipt, 118)
                .unwrap(),
            DepositFinality::Pending
        );
        assert_eq!(
            classify_base_deposit(source, pool, &hash, amount, 20, &transaction, &receipt, 119)
                .unwrap(),
            DepositFinality::Finalized
        );
        let mut wrong_amount = receipt.clone();
        wrong_amount["logs"][0]["data"] = json!(quantity(amount - 1));
        assert_eq!(
            classify_base_deposit(
                source,
                pool,
                &hash,
                amount,
                20,
                &transaction,
                &wrong_amount,
                119
            )
            .unwrap(),
            DepositFinality::Conflict
        );
        let mut reverted = receipt;
        reverted["status"] = json!("0x0");
        assert_eq!(
            classify_base_deposit(
                source,
                pool,
                &hash,
                amount,
                20,
                &transaction,
                &reverted,
                119
            )
            .unwrap(),
            DepositFinality::Reverted
        );
    }

    #[test]
    fn sponsored_withdrawal_binds_user_operation_and_exact_financial_logs() {
        let wallet = "0x2aeba31935ea5f8993cac56af2ac4dee74cfe13d";
        let pool = "0xb07627b0d646f5c82c8e30975a37650dc272a35f";
        let destination = "0xb69ac21b8a96234a09ba6c7644f1c2b106fd4a01";
        let user_operation_hash = format!("0x{}", "11".repeat(32));
        let amount = 5_000_000u128;
        let intent = ExternalEffectIntent::create(
            "a".repeat(64),
            "sponsored-withdrawal".into(),
            "b".repeat(64),
            "c".repeat(64),
            "identity".into(),
            "base".into(),
            "USDC".into(),
            destination.into(),
            amount.to_string(),
            "existing-wallet".into(),
            pool.into(),
            "1".into(),
            "180000".into(),
            "11000000".into(),
            "1000000".into(),
            now_unix(),
        )
        .unwrap();
        let receipt = json!({
            "logs": [
                {
                    "address": "0x0000000071727de22e5e9d8baf0edac6f37da032",
                    "topics": [USER_OPERATION_EVENT_TOPIC, user_operation_hash, address_topic(wallet)],
                    "data": format!("0x{:064x}{:064x}{:064x}{:064x}", 7, 1, 0, 129_564),
                },
                {
                    "address": BASE_USDC_ADDRESS,
                    "topics": [ERC20_TRANSFER_TOPIC, address_topic(pool), address_topic(destination)],
                    "data": quantity(amount),
                },
                {
                    "address": pool,
                    "topics": [POOL_WITHDRAW_TOPIC, address_topic(destination), address_topic(wallet)],
                    "data": quantity(amount),
                }
            ]
        });
        assert!(sponsored_withdrawal_receipt_matches(
            &intent,
            wallet,
            pool,
            Some(&user_operation_hash),
            &receipt,
        ));
        assert!(!sponsored_withdrawal_receipt_matches(
            &intent,
            wallet,
            pool,
            Some(&format!("0x{}", "22".repeat(32))),
            &receipt,
        ));
        let mut wrong_amount = receipt;
        wrong_amount["logs"][1]["data"] = json!(quantity(amount - 1));
        assert!(!sponsored_withdrawal_receipt_matches(
            &intent,
            wallet,
            pool,
            Some(&user_operation_hash),
            &wrong_amount,
        ));
    }

    #[test]
    fn immutable_intent_rebuilds_the_same_terminal_direct_request() {
        let reference = reference_for(
            &"a".repeat(64),
            "request-1",
            &"b".repeat(64),
            "identity",
            "base",
            "USDC",
            "0x2222222222222222222222222222222222222222",
            "1000000",
            "existing-wallet",
        );
        let mut provisional = DirectRequest {
            account_id: "b".repeat(64),
            identity_commitment: "identity".into(),
            request_id: "request-1".into(),
            request_hash: String::new(),
            financial_wallet_address: Some("0x2222222222222222222222222222222222222222".into()),
            action: DirectAction::ReserveWithdrawal {
                destination: "0x2222222222222222222222222222222222222222".into(),
                amount_atomic: "1000000".into(),
                custody_reference: reference,
            },
        };
        provisional.request_hash = request_hash(&provisional);
        let intent = ExternalEffectIntent::create(
            "a".repeat(64),
            "request-1".into(),
            provisional.request_hash.clone(),
            "b".repeat(64),
            "identity".into(),
            "base".into(),
            "USDC".into(),
            "0x2222222222222222222222222222222222222222".into(),
            "1000000".into(),
            "existing-wallet".into(),
            "0x1111111111111111111111111111111111111111".into(),
            "7".into(),
            "180000".into(),
            "2000000000".into(),
            "1000000000".into(),
            100,
        )
        .unwrap();
        let rebuilt = request_for_external_effect(
            &intent,
            ExternalEffectRecovery::BindFinalized {
                provider_transaction_id: "provider-1".into(),
                transaction_hash: format!("0x{}", "11".repeat(32)),
            },
        )
        .unwrap();
        assert_eq!(rebuilt.request_hash, intent.request_hash);
        assert!(
            matches!(rebuilt.action, DirectAction::ReserveWithdrawal { custody_reference, .. } if custody_reference.starts_with(&format!("{}:", intent.external_effect_reference)))
        );
    }

    #[test]
    fn committed_withdrawal_replay_precedes_a_duplicate_unsubmitted_intent() {
        let account = "b".repeat(64);
        let destination = "0xCCB96357dEB4cbF0808208d55916774f0B51a908";
        let reference = reference_for(
            &"a".repeat(64),
            "request-1",
            &account,
            "identity",
            "base",
            "USDC",
            destination,
            "1000000",
            "existing-wallet",
        );
        let custody_reference = format!("{}:0x{}", reference, "11".repeat(32));
        let mut request = DirectRequest {
            account_id: account.clone(),
            identity_commitment: "identity".into(),
            request_id: "request-1".into(),
            request_hash: String::new(),
            financial_wallet_address: Some(destination.to_ascii_lowercase()),
            action: DirectAction::ReserveWithdrawal {
                destination: destination.into(),
                amount_atomic: "1000000".into(),
                custody_reference: custody_reference.clone(),
            },
        };
        request.request_hash = request_hash(&request);
        let committed = ExternalEffectIntent::create(
            "a".repeat(64),
            "request-1".into(),
            request.request_hash.clone(),
            account.clone(),
            "identity".into(),
            "base".into(),
            "USDC".into(),
            destination.into(),
            "1000000".into(),
            "existing-wallet".into(),
            "0x1111111111111111111111111111111111111111".into(),
            "7".into(),
            "180000".into(),
            "2000000000".into(),
            "1000000000".into(),
            100,
        )
        .unwrap();
        let duplicate = ExternalEffectIntent::create(
            "d".repeat(64),
            "request-1".into(),
            "e".repeat(64),
            account.clone(),
            "identity".into(),
            "base".into(),
            "USDC".into(),
            destination.into(),
            "1000000".into(),
            "existing-wallet".into(),
            "0x1111111111111111111111111111111111111111".into(),
            "8".into(),
            "180000".into(),
            "2000000000".into(),
            "1000000000".into(),
            101,
        )
        .unwrap();
        assert!(same_external_effect_request(&committed, &duplicate));
        let artifact = DirectStateArtifact {
            epoch_id: EPOCH_ID.into(),
            sequence: 2,
            prior_state_hash: "a".repeat(64),
            state_hash: "d".repeat(64),
            request_hash: request.request_hash.clone(),
            nonce: vec![1; 12],
            ciphertext: vec![2; 16],
            ciphertext_hash: "f".repeat(64),
            receipt: DirectReceipt {
                receipt_id: "receipt".into(),
                account_id: account.clone(),
                identity_commitment: "identity".into(),
                request_id: "request-1".into(),
                request_hash: request.request_hash,
                status: layrs_direct_execution_v1::TerminalStatus::Applied,
                effect: "WITHDRAWAL_SETTLED".into(),
                amount_atomic: Some("1000000".into()),
                custody_reference: Some(custody_reference.clone()),
                execution: None,
                resolution: None,
                projection_balance_updates: vec![],
                genesis_ordinal: 0,
                signature: "signature".into(),
            },
        };
        let replay = committed_external_effect_action(
            &[committed, duplicate],
            &[(artifact.sequence,artifact.receipt)],
            &account,
            "identity",
            "request-1",
            destination,
            "1000000",
            None,
        )
        .unwrap();
        assert!(matches!(
            replay,
            Some(DirectAction::ReserveWithdrawal {
                custody_reference: value,
                ..
            }) if value == custody_reference
        ));
    }

    #[test]
    fn pool_calldata_is_bound_to_exact_destination_and_amount() {
        let data = pool_withdraw_calldata("0xCCB96357dEB4cbF0808208d55916774f0B51a908", "1000000")
            .unwrap();
        assert_eq!(data.len(), 2 + 8 + 64 + 64);
        assert!(data.ends_with(&format!("{:0>64}", "f4240")));
        assert!(data.contains("000000000000000000000000ccb96357deb4cbf0808208d55916774f0b51a908"));
        assert!(pool_withdraw_calldata("bad", "1000000").is_err());
        assert!(pool_withdraw_calldata("0xCCB96357dEB4cbF0808208d55916774f0B51a908", "0").is_err());
    }

    #[test]
    fn base_withdrawal_requires_signed_action_equality_without_an_allowlist() {
        let destination = "0xCCB96357dEB4cbF0808208d55916774f0B51a908";
        assert!(signed_base_withdrawal_destination_matches(
            destination,
            "0xccb96357deb4cbf0808208d55916774f0b51a908"
        ));

        // Both are valid Base addresses, but a session signed for one may not
        // authorize the other.
        assert!(!signed_base_withdrawal_destination_matches(
            destination,
            "0x1cBE2DDB7C7AC4C67BC692CB463f759D0D7b4dED"
        ));
        assert!(!signed_base_withdrawal_destination_matches(
            "not-an-address",
            "not-an-address"
        ));
        assert!(!signed_base_withdrawal_destination_matches(
            "0x0000000000000000000000000000000000000000",
            "0x0000000000000000000000000000000000000000"
        ));
    }


    fn v71_head() -> JournalHead {
        JournalHead {
            writer_epoch: "writer-epoch-1".into(),
            sequence: 41,
            record_hash: "a".repeat(64),
            transition_root: "b".repeat(64),
            request_index_root:
                layrs_direct_execution_v1::request_index::empty_request_index_root(),
            financial_state_root: "f".repeat(64),
        }
    }

    fn v71_candidate() -> (DirectResult, DirectJournalRecord) {
        let mut index = layrs_direct_execution_v1::request_index::SparseRequestTree::default();
        v71_candidate_after(&v71_head(), &mut index, "request-42")
    }

    /// Seals the record after `head`, inserting its request into `index`, so
    /// consecutive calls chain both request-index roots.
    fn v71_candidate_after(
        head: &JournalHead,
        index: &mut layrs_direct_execution_v1::request_index::SparseRequestTree,
        request_id: &str,
    ) -> (DirectResult, DirectJournalRecord) {
        let mut request = DirectRequest {
            account_id: "account".into(),
            identity_commitment: "identity".into(),
            request_id: request_id.into(),
            request_hash: String::new(),
            financial_wallet_address: None,
            action: DirectAction::AdmitIdentity {
                wallet_address: "0x1111111111111111111111111111111111111111".into(),
            },
        };
        request.request_hash = request_hash(&request);
        let mut receipt = DirectReceipt {
            receipt_id: "c".repeat(64),
            account_id: request.account_id.clone(),
            identity_commitment: request.identity_commitment.clone(),
            request_id: request.request_id.clone(),
            request_hash: request.request_hash.clone(),
            status: layrs_direct_execution_v1::TerminalStatus::Applied,
            effect: "IDENTITY_ADMITTED".into(),
            amount_atomic: None,
            custody_reference: None,
            execution: None,
            resolution: None,
            projection_balance_updates: vec![],
            genesis_ordinal: 0,
            signature: String::new(),
        };
        receipt.signature = layrs_direct_execution_v1::receipt_signature(&[9; 32], &receipt);
        let result = DirectResult {
            status: receipt.status.clone(),
            effect: receipt.effect.clone(),
            genesis_ordinal: receipt.genesis_ordinal,
            receipt,
        };
        let proof = index
            .proof(&request.account_id, &request.request_id)
            .unwrap();
        let previous_index = index.root().unwrap();
        let leaf = layrs_direct_execution_v1::request_index::TerminalRequestLeaf {
            account_id: request.account_id.clone(),
            request_id: request.request_id.clone(),
            request_hash: request.request_hash.clone(),
            result_hash: canonical_result_hash(&result).unwrap(),
            receipt_hash: canonical_receipt_hash(&result).unwrap(),
            locator: layrs_direct_execution_v1::request_index::TerminalResultLocator::Journal {
                writer_epoch: head.writer_epoch.clone(),
                sequence: head.sequence + 1,
            },
        };
        let next_index = index.insert(leaf).unwrap();
        let record = DirectJournalRecord::seal(
            &head.writer_epoch,
            head.sequence + 1,
            &head.record_hash,
            &head.transition_root,
            &previous_index,
            &next_index,
            &"f".repeat(64),
            proof,
            request,
            result.clone(),
            &[7; 32],
            &[8; 32],
            &[9; 32],
        )
        .unwrap();
        (result, record)
    }

    #[test]
    fn v71_record_key_shares_v70_head_slot_and_parser_rejects_legacy_and_foreign_keys() {
        let prefix = "archive/epoch";
        for sequence in [1, 42, u64::MAX] {
            let key = journal_record_key(prefix, sequence);
            assert_eq!(key, archive_head_key(prefix, sequence));
            assert_eq!(journal_record_key_sequence(&key, prefix), Ok(sequence));
        }
        assert_eq!(
            journal_record_key(prefix, 42),
            "archive/epoch/heads/00000000000000000042.cbor"
        );

        let legacy = format!(
            "{prefix}/heads/00000000000000000042-{}.cbor",
            "d".repeat(64)
        );
        // The v70 parser admits the legacy name; the journal parser never does.
        assert_eq!(
            archive_key_sequence(&legacy, &format!("{prefix}/heads/"), false),
            Ok(42)
        );
        for key in [
            legacy,
            format!("{prefix}/heads/00000000000000000042-.cbor"),
            format!("{prefix}/heads/42.cbor"),
            format!("{prefix}/heads/0000000000000000042.cbor"),
            format!("{prefix}/heads/000000000000000000042.cbor"),
            format!("{prefix}/heads/+0000000000000000042.cbor"),
            format!("{prefix}/heads/0000000000000000004a.cbor"),
            format!("{prefix}/heads/00000000000000000000.cbor"),
            format!("{prefix}/heads/18446744073709551616.cbor"),
            format!("{prefix}/heads/99999999999999999999.cbor"),
            format!("{prefix}/heads/00000000000000000042.CBOR"),
            format!("{prefix}/heads/00000000000000000042.cbor.tmp"),
            format!("{prefix}/heads/nested/00000000000000000042.cbor"),
            format!("{prefix}/artifacts/00000000000000000042.cbor"),
            format!("{prefix}/journal-v71/checkpoints/00000000000000000042.cbor"),
            format!("other/heads/00000000000000000042.cbor"),
            format!("{prefix}-other/heads/00000000000000000042.cbor"),
            format!("/{prefix}/heads/00000000000000000042.cbor"),
            String::new(),
        ] {
            assert!(journal_record_key_sequence(&key, prefix).is_err(), "{key}");
        }

        let checkpoint = journal_checkpoint_key(prefix, 42, b"checkpoint");
        assert_eq!(
            checkpoint,
            format!(
                "{prefix}/journal-v71/checkpoints/00000000000000000042-{}.cbor",
                sha256(b"checkpoint")
            )
        );
        assert_ne!(
            checkpoint,
            journal_checkpoint_key(prefix, 42, b"checkpoint2")
        );
        assert!(journal_record_key_sequence(&checkpoint, prefix).is_err());
    }

    #[test]
    fn v71_precheck_rejects_wrong_epoch_sequence_predecessor_root_protocol_and_size() {
        let head = v71_head();
        let (_, record) = v71_candidate();
        assert_eq!(
            precheck_journal_candidate(&head, &record),
            Ok(serde_cbor::to_vec(&record).unwrap())
        );

        let reject = |mutate: &dyn Fn(&mut DirectJournalRecord), expected: &str| {
            let mut candidate = record.clone();
            mutate(&mut candidate);
            assert_eq!(precheck_journal_candidate(&head, &candidate), Err(expected));
        };
        reject(
            &|r| r.protocol = "layrs.direct-execution.journal.v70".into(),
            "journal candidate protocol invalid",
        );
        reject(
            &|r| r.epoch_id = "other-epoch".into(),
            "journal candidate epoch invalid",
        );
        reject(
            &|r| r.writer_epoch = "writer-epoch-2".into(),
            "journal candidate writer epoch mismatch",
        );
        reject(&|r| r.sequence = 41, "journal candidate sequence mismatch");
        reject(&|r| r.sequence = 43, "journal candidate sequence mismatch");
        reject(&|r| r.sequence = 0, "journal candidate sequence mismatch");
        reject(
            &|r| r.previous_record_hash = "d".repeat(64),
            "journal candidate previous record mismatch",
        );
        reject(
            &|r| r.previous_transition_root = "d".repeat(64),
            "journal candidate previous transition root mismatch",
        );
        reject(
            &|r| r.previous_request_index_root = "d".repeat(64),
            "journal candidate previous request index root mismatch",
        );
        reject(
            &|r| r.ciphertext = vec![0; MAX_JOURNAL_RECORD_BYTES],
            "journal candidate oversized",
        );

        let mut exhausted = head.clone();
        exhausted.sequence = u64::MAX;
        let mut candidate = record.clone();
        candidate.sequence = u64::MAX;
        assert_eq!(
            precheck_journal_candidate(&exhausted, &candidate),
            Err("journal candidate sequence overflow")
        );
    }

    #[test]
    fn v71_tail_keys_reject_gap_duplicate_legacy_overflow_and_bound() {
        let prefix = "archive/epoch";
        let keys = |sequences: &[u64]| -> Vec<String> {
            sequences
                .iter()
                .map(|s| journal_record_key(prefix, *s))
                .collect()
        };
        assert_eq!(validate_journal_tail_keys(&[], prefix, 7, 0), Ok(vec![]));
        assert_eq!(
            validate_journal_tail_keys(&keys(&[8, 9, 10]), prefix, 7, 3),
            Ok(vec![
                (8, journal_record_key(prefix, 8)),
                (9, journal_record_key(prefix, 9)),
                (10, journal_record_key(prefix, 10)),
            ])
        );
        assert_eq!(
            validate_journal_tail_keys(&keys(&[8, 9, 10]), prefix, 7, 2),
            Err("journal tail exceeds bound".into())
        );
        assert_eq!(
            validate_journal_tail_keys(&keys(&[9]), prefix, 7, 3),
            Err("journal tail sequence gap".into())
        );
        assert_eq!(
            validate_journal_tail_keys(&keys(&[7, 8]), prefix, 7, 3),
            Err("journal tail duplicate key".into())
        );
        assert_eq!(
            validate_journal_tail_keys(&keys(&[8, 8]), prefix, 7, 3),
            Err("journal tail duplicate key".into())
        );
        assert_eq!(
            validate_journal_tail_keys(&keys(&[8, 10, 9]), prefix, 7, 3),
            Err("journal tail sequence gap".into())
        );
        assert_eq!(
            validate_journal_tail_keys(&keys(&[u64::MAX]), prefix, u64::MAX, 1),
            Err("journal tail sequence overflow".into())
        );
        let mut legacy = keys(&[8]);
        legacy.push(format!(
            "{prefix}/heads/00000000000000000009-{}.cbor",
            "d".repeat(64)
        ));
        assert_eq!(
            validate_journal_tail_keys(&legacy, prefix, 7, 3),
            Err("journal record key legacy suffix".into())
        );
        let mut foreign = keys(&[8]);
        foreign.push(format!("other/heads/{:020}.cbor", 9));
        assert!(validate_journal_tail_keys(&foreign, prefix, 7, 3).is_err());
        let mut overflow = keys(&[8]);
        overflow.push(format!("{prefix}/heads/99999999999999999999.cbor"));
        assert_eq!(
            validate_journal_tail_keys(&overflow, prefix, 7, 3),
            Err("archive sequence overflow".into())
        );
    }

    #[test]
    fn v71_terminal_must_match_record_result_receipt_and_request_hashes() {
        let (result, record) = v71_candidate();
        assert!(verify_terminal_matches_record(&result, &record));
        let leaf = TerminalRequestLeaf {
            account_id: record.account_id.clone(),
            request_id: record.request_id.clone(),
            request_hash: record.request_hash.clone(),
            result_hash: record.result_hash.clone(),
            receipt_hash: record.receipt_hash.clone(),
            locator: TerminalResultLocator::Journal {
                writer_epoch: record.writer_epoch.clone(),
                sequence: record.sequence,
            },
        };
        assert!(terminal_leaf_matches_record(&leaf, &record));
        let mut other_leaf = leaf;
        other_leaf.locator = TerminalResultLocator::Journal {
            writer_epoch: record.writer_epoch.clone(),
            sequence: record.sequence + 1,
        };
        assert!(!terminal_leaf_matches_record(&other_leaf, &record));

        let mut other = result.clone();
        other.effect = "IDENTITY_REJECTED".into();
        assert!(!verify_terminal_matches_record(&other, &record));

        let mut other = result.clone();
        other.receipt.receipt_id = "d".repeat(64);
        assert!(!verify_terminal_matches_record(&other, &record));

        let mut other = result.clone();
        other.receipt.request_hash = "d".repeat(64);
        assert!(!verify_terminal_matches_record(&other, &record));

        let mut other = record.clone();
        other.request_hash = "d".repeat(64);
        assert!(!verify_terminal_matches_record(&result, &other));

        let mut other = record.clone();
        other.receipt_hash = "d".repeat(64);
        assert!(!verify_terminal_matches_record(&result, &other));
    }

    #[test]
    fn v71_migration_parent_state_requires_complete_receipt_index_equivalence() {
        let (result, _) = v71_candidate();
        let migration_id = sha256(b"migration-fixture");
        let leaf = TerminalRequestLeaf {
            account_id: result.receipt.account_id.clone(),
            request_id: result.receipt.request_id.clone(),
            request_hash: result.receipt.request_hash.clone(),
            result_hash: canonical_result_hash(&result).unwrap(),
            receipt_hash: canonical_receipt_hash(&result).unwrap(),
            locator: TerminalResultLocator::Migration {
                migration_id: migration_id.clone(),
                ordinal: 1,
            },
        };
        let root = layrs_direct_execution_v1::request_index::request_index_root(&[leaf.clone()])
            .unwrap();
        let bundle = V70MigrationBundle {
            manifest: layrs_direct_execution_v1::migration::V70MigrationManifest {
                protocol: V70_MIGRATION_MANIFEST_PROTOCOL.into(),
                epoch_id: EPOCH_ID.into(),
                migration_id: migration_id.clone(),
                source_sequence: 1,
                source_state_hash: "a".repeat(64),
                record_count: 1,
                records_root: "b".repeat(64),
                request_index_root: root,
                signature: "c".repeat(128),
            },
            records: vec![layrs_direct_execution_v1::migration::MigratedTerminalRecord {
                protocol: "layrs.direct-execution.migrated-result.v71".into(),
                epoch_id: EPOCH_ID.into(),
                migration_id,
                source_sequence: 1,
                source_state_hash: "a".repeat(64),
                ordinal: 1,
                account_id: leaf.account_id.clone(),
                request_id: leaf.request_id.clone(),
                request_hash: leaf.request_hash.clone(),
                result_hash: leaf.result_hash.clone(),
                receipt_hash: leaf.receipt_hash.clone(),
                nonce: vec![0; 12],
                ciphertext: vec![1],
                ciphertext_hash: sha256(&[1]),
                signature: "d".repeat(128),
            }],
            leaves: vec![leaf],
        };
        let artifact = DirectStateArtifact {
            epoch_id: EPOCH_ID.into(),
            sequence: 1,
            prior_state_hash: "e".repeat(64),
            state_hash: "f".repeat(64),
            request_hash: result.receipt.request_hash.clone(),
            nonce: vec![0; 12],
            ciphertext: vec![1],
            ciphertext_hash: sha256(&[1]),
            receipt: result.receipt.clone(),
        };
        let (index, receipts, index_snapshot, receipt_snapshot) =
            migration_parent_state(&bundle, &[artifact.clone()]).unwrap();
        assert_eq!(index.len(), 1);
        assert_eq!(receipts.len(), 1);
        assert!(receipt_snapshot.verify(&index_snapshot).is_ok());
        assert!(migration_matches_restored_index(&bundle, &index_snapshot));

        let record = &bundle.records[0];
        assert!(terminal_leaf_matches_migrated_record(
            &bundle.leaves[0],
            record
        ));
        let mut changed_leaf = bundle.leaves[0].clone();
        changed_leaf.result_hash = "e".repeat(64);
        assert!(!terminal_leaf_matches_migrated_record(
            &changed_leaf,
            record
        ));

        let mut changed = artifact;
        changed.receipt.effect = "TAMPERED".into();
        assert!(migration_parent_state(&bundle, &[changed]).is_err());
        assert!(migration_parent_state(&bundle, &[]).is_err());
    }

    fn v71_http(status: u16, body: &[u8]) -> Vec<u8> {
        let mut response = format!(
            "HTTP/1.1 {status} Mock\r\nContent-Type: application/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(body);
        response
    }

    fn v71_s3_error(status: u16, code: &str) -> Vec<u8> {
        v71_http(
            status,
            format!(
                "<?xml version=\"1.0\"?><Error><Code>{code}</Code><Message>mock</Message></Error>"
            )
            .as_bytes(),
        )
    }

    fn v71_listing(keys: &[String]) -> Vec<u8> {
        let objects = keys
            .iter()
            .map(|key| format!("<Contents><Key>{key}</Key><Size>1</Size></Contents>"))
            .collect::<String>();
        v71_http(
            200,
            format!(
                "<?xml version=\"1.0\"?><ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><IsTruncated>false</IsTruncated><KeyCount>{}</KeyCount>{objects}</ListBucketResult>",
                keys.len()
            )
            .as_bytes(),
        )
    }

    type V71RequestLog = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

    /// Loopback S3 answering each request with the next scripted response (500
    /// once exhausted) and logging `(lowercased request head, body)` in order.
    async fn v71_mock_s3(
        responses: Vec<Vec<u8>>,
    ) -> (String, V71RequestLog, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let log = V71RequestLog::default();
        let recorded = log.clone();
        let server = tokio::spawn(async move {
            let mut responses = responses.into_iter();
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut buffer = [0u8; 8192];
                let entry = loop {
                    let size = socket.read(&mut buffer).await.unwrap();
                    assert!(size > 0, "request truncated");
                    request.extend_from_slice(&buffer[..size]);
                    let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") else {
                        continue;
                    };
                    let head = String::from_utf8_lossy(&request[..end]).to_ascii_lowercase();
                    let length = head
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length:"))
                        .map_or(0, |value| value.trim().parse::<usize>().unwrap());
                    if request.len() >= end + 4 + length {
                        break (head, request[end + 4..end + 4 + length].to_vec());
                    }
                };
                recorded.lock().await.push(entry);
                let response = responses
                    .next()
                    .unwrap_or_else(|| v71_s3_error(500, "InternalError"));
                socket.write_all(&response).await.unwrap();
            }
        });
        (endpoint, log, server)
    }

    fn v71_store(
        endpoint: &str,
        state: JournalWriterState,
        role: JournalRole,
    ) -> S3ImmutableArtifactStore {
        let configuration = aws_sdk_s3::config::Builder::new()
            .behavior_version_latest()
            .region(aws_sdk_s3::config::Region::new("us-east-1"))
            .credentials_provider(aws_sdk_s3::config::Credentials::new(
                "unit-test",
                "unit-test",
                None,
                None,
                "local-only",
            ))
            .endpoint_url(endpoint)
            .force_path_style(true)
            .build();
        S3ImmutableArtifactStore {
            client: S3Client::from_conf(configuration),
            bucket: "unit-test".into(),
            prefix: "epoch".into(),
            kms_key_id: "unit-kms-key".into(),
            retention_seconds: 86400,
            verified_receipt_records: Arc::new(Mutex::new(None)),
            verified_artifact_hashes: Arc::new(Mutex::new(Vec::new())),
            prepared_restore: Arc::new(Mutex::new(None)),
            prepared_journal_restore: Arc::new(Mutex::new(None)),
            checkpoint_refresh_gate: Arc::new(Mutex::new(CheckpointRefresh::default())),
            journal: Arc::new(Mutex::new(state)),
            journal_role: role,
        }
    }

    fn v71_next_head(record: &DirectJournalRecord) -> JournalHead {
        JournalHead {
            writer_epoch: v71_head().writer_epoch,
            sequence: 42,
            record_hash: record.record_hash().unwrap(),
            transition_root: record.transition_root.clone(),
            request_index_root: record.request_index_root.clone(),
            financial_state_root: record.financial_state_root.clone(),
        }
    }

    #[tokio::test]
    async fn v71_append_puts_create_only_then_reads_back_then_lists_fences() {
        let (_, record) = v71_candidate();
        let bytes = serde_cbor::to_vec(&record).unwrap();
        let (endpoint, log, server) = v71_mock_s3(vec![
            v71_http(200, b""),
            v71_http(200, &bytes),
            v71_listing(&[]),
        ])
        .await;
        let store = v71_store(
            &endpoint,
            JournalWriterState::Eligible(v71_head()),
            JournalRole::Writer,
        );
        let next = store.append_journal_record(&record).await.unwrap();
        assert_eq!(next, v71_next_head(&record));
        assert_eq!(
            *store.journal.lock().await,
            JournalWriterState::Eligible(next)
        );
        server.abort();
        let log = log.lock().await;
        assert_eq!(log.len(), 3);
        let (put, body) = &log[0];
        assert!(
            put.starts_with("put /unit-test/epoch/heads/00000000000000000042.cbor"),
            "{put}"
        );
        for header in [
            "\r\nif-none-match: *\r\n",
            "\r\nx-amz-server-side-encryption: aws:kms\r\n",
            "\r\nx-amz-server-side-encryption-aws-kms-key-id: unit-kms-key\r\n",
            "\r\nx-amz-object-lock-mode: compliance\r\n",
            "\r\nx-amz-object-lock-retain-until-date: ",
        ] {
            assert!(put.contains(header), "{header:?} missing from {put}");
        }
        assert!(body.windows(bytes.len()).any(|window| window == bytes));
        assert!(
            log[1]
                .0
                .starts_with("get /unit-test/epoch/heads/00000000000000000042.cbor"),
            "{}",
            log[1].0
        );
        let list = &log[2].0;
        let fence_prefix = journal_fence_prefix("epoch", "writer-epoch-1");
        assert!(list.starts_with("get /unit-test/?"), "{list}");
        for query in [
            "list-type=2".to_string(),
            "max-keys=1".to_string(),
            format!("prefix={}", fence_prefix.replace('/', "%2f")),
        ] {
            assert!(list.contains(&query), "{query} missing from {list}");
        }
    }

    #[tokio::test]
    async fn v71_append_412_with_identical_readback_is_idempotent_success() {
        let (_, record) = v71_candidate();
        let bytes = serde_cbor::to_vec(&record).unwrap();
        let (endpoint, log, server) = v71_mock_s3(vec![
            v71_s3_error(412, "PreconditionFailed"),
            v71_http(200, &bytes),
            v71_listing(&[]),
        ])
        .await;
        let store = v71_store(
            &endpoint,
            JournalWriterState::Eligible(v71_head()),
            JournalRole::Writer,
        );
        assert_eq!(
            store.append_journal_record(&record).await,
            Ok(v71_next_head(&record))
        );
        server.abort();
        let methods: Vec<_> = log
            .lock()
            .await
            .iter()
            .map(|(head, _)| head[..4].to_string())
            .collect();
        assert_eq!(methods, ["put ", "get ", "get "]);
    }

    #[tokio::test]
    async fn v71_append_412_with_different_readback_latches_sequence_conflict() {
        let (_, record) = v71_candidate();
        let (endpoint, log, server) = v71_mock_s3(vec![
            v71_s3_error(412, "PreconditionFailed"),
            v71_http(200, b"another-writer-record"),
        ])
        .await;
        let store = v71_store(
            &endpoint,
            JournalWriterState::Eligible(v71_head()),
            JournalRole::Writer,
        );
        assert_eq!(
            store.append_journal_record(&record).await,
            Err("ARCHIVE_SEQUENCE_CONFLICT".into())
        );
        assert_eq!(
            *store.journal.lock().await,
            JournalWriterState::Latched("ARCHIVE_SEQUENCE_CONFLICT")
        );
        // No fence listing after a conflict, and no further PUT once latched.
        assert_eq!(
            store.append_journal_record(&record).await,
            Err("JOURNAL_LATCHED".into())
        );
        server.abort();
        assert_eq!(log.lock().await.len(), 2);
    }

    #[tokio::test]
    async fn v71_durable_append_latches_on_existing_fence_or_fence_listing_failure() {
        let (_, record) = v71_candidate();
        let bytes = serde_cbor::to_vec(&record).unwrap();
        let fence = format!(
            "{}00000000000000000041.cbor",
            journal_fence_prefix("epoch", "writer-epoch-1")
        );
        let foreign = format!(
            "{}00000000000000000041.cbor",
            journal_fence_prefix("epoch", "writer-epoch-2")
        );
        for (listing, code) in [
            (v71_listing(&[fence]), "JOURNAL_WRITER_FENCED"),
            (
                v71_s3_error(403, "AccessDenied"),
                "JOURNAL_FENCE_UNAVAILABLE",
            ),
            (v71_listing(&[foreign]), "JOURNAL_FENCE_UNAVAILABLE"),
        ] {
            let (endpoint, log, server) =
                v71_mock_s3(vec![v71_http(200, b""), v71_http(200, &bytes), listing]).await;
            let store = v71_store(
                &endpoint,
                JournalWriterState::Eligible(v71_head()),
                JournalRole::Writer,
            );
            assert_eq!(store.append_journal_record(&record).await, Err(code.into()));
            assert_eq!(
                *store.journal.lock().await,
                JournalWriterState::Latched(code)
            );
            server.abort();
            assert_eq!(log.lock().await.len(), 3, "{code}");
        }
    }

    #[tokio::test]
    async fn v71_append_without_eligible_head_or_valid_candidate_never_touches_storage() {
        let (_, record) = v71_candidate();
        let (endpoint, log, server) = v71_mock_s3(Vec::new()).await;

        let store = v71_store(
            &endpoint,
            JournalWriterState::Unrestored,
            JournalRole::Writer,
        );
        assert_eq!(
            store.append_journal_record(&record).await,
            Err("JOURNAL_UNRESTORED".into())
        );
        assert_eq!(*store.journal.lock().await, JournalWriterState::Unrestored);

        let store = v71_store(
            &endpoint,
            JournalWriterState::Eligible(v71_head()),
            JournalRole::Writer,
        );
        store.latch_journal("ARCHIVE_TIMEOUT").await;
        assert_eq!(
            store.append_journal_record(&record).await,
            Err("JOURNAL_LATCHED".into())
        );
        assert_eq!(
            *store.journal.lock().await,
            JournalWriterState::Latched("ARCHIVE_TIMEOUT")
        );

        let mut stale = v71_head();
        stale.sequence = 40;
        let store = v71_store(
            &endpoint,
            JournalWriterState::Eligible(stale),
            JournalRole::Writer,
        );
        assert_eq!(
            store.append_journal_record(&record).await,
            Err("JOURNAL_CANDIDATE_OUT_OF_ORDER".into())
        );
        assert_eq!(
            *store.journal.lock().await,
            JournalWriterState::Latched("JOURNAL_CANDIDATE_OUT_OF_ORDER")
        );

        let store = v71_store(
            &endpoint,
            JournalWriterState::Eligible(v71_head()),
            JournalRole::Shadow,
        );
        assert_eq!(
            store.append_journal_record(&record).await,
            Err("JOURNAL_SHADOW_APPEND_UNSUPPORTED".into())
        );
        assert_eq!(
            *store.journal.lock().await,
            JournalWriterState::Eligible(v71_head())
        );

        server.abort();
        assert!(log.lock().await.is_empty());
    }


    fn v71_listing_page(keys: &[String], next_token: Option<&str>) -> Vec<u8> {
        let objects = keys
            .iter()
            .map(|key| format!("<Contents><Key>{key}</Key><Size>1</Size></Contents>"))
            .collect::<String>();
        let truncation = match next_token {
            Some(token) => format!(
                "<IsTruncated>true</IsTruncated><NextContinuationToken>{token}</NextContinuationToken>"
            ),
            None => "<IsTruncated>false</IsTruncated>".into(),
        };
        v71_http(
            200,
            format!(
                "<?xml version=\"1.0\"?><ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">{truncation}<KeyCount>{}</KeyCount>{objects}</ListBucketResult>",
                keys.len()
            )
            .as_bytes(),
        )
    }

    fn v71_http_with_etag(etag: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 200 Mock\r\nETag: \"{etag}\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .into_bytes()
    }

    /// Loopback S3 that accepts connections and never answers.
    async fn v71_silent_s3() -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let mut held = Vec::new();
            loop {
                held.push(listener.accept().await.unwrap().0);
            }
        });
        (endpoint, server)
    }

    fn v71_checkpoint(sequence: u64) -> DirectV71Checkpoint {
        DirectV71Checkpoint {
            protocol: DIRECT_V71_CHECKPOINT_PROTOCOL.into(),
            epoch_id: EPOCH_ID.into(),
            writer_epoch: "writer-epoch-1".into(),
            sequence,
            record_hash: v71_head().record_hash,
            transition_root: v71_head().transition_root,
            request_index_root: layrs_direct_execution_v1::request_index::empty_request_index_root(),
            financial_state_root: "d".repeat(64),
            nonce: vec![1; 12],
            ciphertext: b"sealed-state".to_vec(),
            ciphertext_hash: "e".repeat(64),
            signature: "f".repeat(128),
        }
    }

    #[test]
    fn v71_non_writer_checkpoint_verification_requires_every_authenticated_head_field() {
        let checkpoint = v71_checkpoint(41);
        let verified = RuntimeResponse::JournalCheckpointVerified {
            writer_epoch: checkpoint.writer_epoch.clone(),
            sequence: checkpoint.sequence,
            record_hash: checkpoint.record_hash.clone(),
            transition_root: checkpoint.transition_root.clone(),
            request_index_root: checkpoint.request_index_root.clone(),
            financial_state_root: checkpoint.financial_state_root.clone(),
        };
        assert!(journal_checkpoint_verification_matches(
            &checkpoint,
            &verified
        ));

        for mutated in [
            DirectV71Checkpoint {
                writer_epoch: "other-writer".into(),
                ..checkpoint.clone()
            },
            DirectV71Checkpoint {
                sequence: checkpoint.sequence + 1,
                ..checkpoint.clone()
            },
            DirectV71Checkpoint {
                record_hash: "0".repeat(64),
                ..checkpoint.clone()
            },
            DirectV71Checkpoint {
                transition_root: "0".repeat(64),
                ..checkpoint.clone()
            },
            DirectV71Checkpoint {
                request_index_root: "0".repeat(64),
                ..checkpoint.clone()
            },
            DirectV71Checkpoint {
                financial_state_root: "0".repeat(64),
                ..checkpoint.clone()
            },
        ] {
            assert!(!journal_checkpoint_verification_matches(
                &mutated, &verified
            ));
        }
        assert!(!journal_checkpoint_verification_matches(
            &checkpoint,
            &RuntimeResponse::Error {
                code: "CHECKPOINT_REJECTED".into()
            }
        ));
    }

    fn v71_checkpoint_publication_fixture() -> (
        DirectV71Checkpoint,
        DirectRequestIndexSnapshot,
        DirectReceiptSnapshot,
    ) {
        let (result, record) = v71_candidate();
        let leaf = TerminalRequestLeaf {
            account_id: record.account_id,
            request_id: record.request_id,
            request_hash: record.request_hash,
            result_hash: record.result_hash,
            receipt_hash: record.receipt_hash,
            locator: TerminalResultLocator::Journal {
                writer_epoch: "writer-epoch-1".into(),
                sequence: 1,
            },
        };
        let root = layrs_direct_execution_v1::request_index::request_index_root(&[leaf.clone()])
            .unwrap();
        let index = DirectRequestIndexSnapshot::from_leaves(1, &root, [leaf]).unwrap();
        let receipts =
            DirectReceiptSnapshot::from_receipts(&index, [(1, result.receipt)]).unwrap();
        let mut checkpoint = v71_checkpoint(1);
        checkpoint.request_index_root = root;
        (checkpoint, index, receipts)
    }

    fn v71_migration_bundle(migration_id: String) -> V70MigrationBundle {
        V70MigrationBundle {
            manifest: layrs_direct_execution_v1::migration::V70MigrationManifest {
                protocol: V70_MIGRATION_MANIFEST_PROTOCOL.into(),
                epoch_id: EPOCH_ID.into(),
                migration_id,
                source_sequence: 41,
                source_state_hash: "a".repeat(64),
                record_count: 0,
                records_root: "b".repeat(64),
                request_index_root: "c".repeat(64),
                signature: "d".repeat(128),
            },
            records: Vec::new(),
            leaves: Vec::new(),
        }
    }

    fn v71_assert_create_only_put(head: &str, key: &str) {
        assert!(head.starts_with(&format!("put /unit-test/{key}")), "{head}");
        for header in [
            "\r\nif-none-match: *\r\n",
            "\r\nx-amz-server-side-encryption: aws:kms\r\n",
            "\r\nx-amz-server-side-encryption-aws-kms-key-id: unit-kms-key\r\n",
            "\r\nx-amz-object-lock-mode: compliance\r\n",
            "\r\nx-amz-object-lock-retain-until-date: ",
        ] {
            assert!(head.contains(header), "{header:?} missing from {head}");
        }
    }

    #[test]
    fn v71_migration_and_checkpoint_content_keys_are_strict() {
        let prefix = "epoch";
        let hash = sha256(b"bundle");
        let key = journal_migration_key(prefix, 41, b"bundle");
        assert_eq!(
            key,
            format!("epoch/journal-v71/migrations/00000000000000000041-{hash}.cbor")
        );
        let migrations = "epoch/journal-v71/migrations/";
        assert_eq!(
            journal_content_key_parts(&key, migrations),
            Ok((41, hash.clone()))
        );
        for bad in [
            format!("{migrations}41-{hash}.cbor"),
            format!("{migrations}00000000000000000041-{}.cbor", hash.to_uppercase()),
            format!("{migrations}00000000000000000041-{}.cbor", &hash[1..]),
            format!("{migrations}00000000000000000041.cbor"),
            format!("{migrations}00000000000000000041-{hash}-x.cbor"),
            format!("{migrations}00000000000000000041-{hash}.cbor.cbor"),
            format!("{migrations}0000000000000000004a-{hash}.cbor"),
            format!("{migrations}99999999999999999999-{hash}.cbor"),
            format!("epoch/journal-v71/checkpoints/00000000000000000041-{hash}.cbor"),
            format!("{migrations}00000000000000000041-{hash}.json"),
        ] {
            assert!(journal_content_key_parts(&bad, migrations).is_err(), "{bad}");
        }

        let seven = journal_checkpoint_key(prefix, 7, b"seven");
        let forty_one = journal_checkpoint_key(prefix, 41, b"forty-one");
        let candidates =
            validate_journal_checkpoint_keys(&[forty_one.clone(), seven.clone()], prefix).unwrap();
        assert_eq!(
            candidates.iter().map(|c| c.sequence).collect::<Vec<_>>(),
            [7, 41]
        );
        assert_eq!(candidates[1].key, forty_one);
        assert_eq!(candidates[1].content_hash, sha256(b"forty-one"));
        assert_eq!(
            validate_journal_checkpoint_keys(
                &[forty_one.clone(), journal_checkpoint_key(prefix, 41, b"twin")],
                prefix
            ),
            Err("journal checkpoint duplicate sequence".into())
        );
        assert!(validate_journal_checkpoint_keys(
            &[seven, "epoch/journal-v71/checkpoints/00000000000000000041.cbor".into()],
            prefix
        )
        .is_err());
        assert!(validate_journal_checkpoint_keys(&[journal_record_key(prefix, 41)], prefix).is_err());
    }

    #[tokio::test]
    async fn v71_migration_bundle_persists_create_only_under_content_address_with_exact_readback() {
        let bundle = v71_migration_bundle("migration-1".into());
        let bytes = serde_cbor::to_vec(&bundle).unwrap();
        let key = journal_migration_key("epoch", 41, &bytes);

        let (endpoint, log, server) =
            v71_mock_s3(vec![v71_http(200, b""), v71_http(200, &bytes)]).await;
        let store = v71_store(&endpoint, JournalWriterState::Unrestored, JournalRole::Writer);
        assert_eq!(store.persist_v70_migration_bundle(&bundle).await, Ok(key.clone()));
        server.abort();
        let log = log.lock().await;
        assert_eq!(log.len(), 2);
        v71_assert_create_only_put(&log[0].0, &key);
        assert!(log[0].1.windows(bytes.len()).any(|window| window == bytes));
        assert!(log[1].0.starts_with(&format!("get /unit-test/{key}")), "{}", log[1].0);
        drop(log);

        // An existing identical object is idempotent success.
        let (endpoint, _, server) = v71_mock_s3(vec![
            v71_s3_error(412, "PreconditionFailed"),
            v71_http(200, &bytes),
        ])
        .await;
        let store = v71_store(&endpoint, JournalWriterState::Unrestored, JournalRole::Writer);
        assert_eq!(store.persist_v70_migration_bundle(&bundle).await, Ok(key.clone()));
        server.abort();

        for (responses, error) in [
            (
                vec![v71_s3_error(412, "PreconditionFailed"), v71_http(200, b"other")],
                "archive immutable write failed",
            ),
            (
                vec![v71_http(200, b""), v71_http(200, b"torn")],
                "archive readback mismatch",
            ),
        ] {
            let (endpoint, _, server) = v71_mock_s3(responses).await;
            let store = v71_store(&endpoint, JournalWriterState::Unrestored, JournalRole::Writer);
            assert_eq!(store.persist_v70_migration_bundle(&bundle).await, Err(error.into()));
            server.abort();
        }

        // A shadow store or a foreign bundle header never reaches storage.
        let (endpoint, log, server) = v71_mock_s3(Vec::new()).await;
        let store = v71_store(&endpoint, JournalWriterState::Unrestored, JournalRole::Shadow);
        assert_eq!(
            store.persist_v70_migration_bundle(&bundle).await,
            Err("JOURNAL_SHADOW_WRITE_UNSUPPORTED".into())
        );
        let store = v71_store(&endpoint, JournalWriterState::Unrestored, JournalRole::Writer);
        let mut foreign = bundle.clone();
        foreign.manifest.epoch_id = "other-epoch".into();
        assert_eq!(
            store.persist_v70_migration_bundle(&foreign).await,
            Err("journal migration bundle header invalid".into())
        );
        let mut foreign = bundle;
        foreign.manifest.protocol = "other-protocol".into();
        assert!(store.persist_v70_migration_bundle(&foreign).await.is_err());
        server.abort();
        assert!(log.lock().await.is_empty());
    }

    #[tokio::test]
    async fn v71_migration_bundle_load_requires_one_canonical_content_address() {
        let bundle = v71_migration_bundle("migration-1".into());
        let bytes = serde_cbor::to_vec(&bundle).unwrap();
        let key = journal_migration_key("epoch", 41, &bytes);
        let (endpoint, log, server) = v71_mock_s3(vec![
            v71_listing_page(&[key.clone()], None),
            v71_http(200, &bytes),
        ])
        .await;
        let store = v71_store(&endpoint, JournalWriterState::Unrestored, JournalRole::Shadow);
        assert_eq!(store.load_v70_migration_bundle().await, Ok(Some(bundle.clone())));
        server.abort();
        assert_eq!(log.lock().await.len(), 2);

        let twin = journal_migration_key("epoch", 42, b"twin");
        let (endpoint, log, server) = v71_mock_s3(vec![v71_listing_page(
            &[key.clone(), twin],
            None,
        )])
        .await;
        let store = v71_store(&endpoint, JournalWriterState::Unrestored, JournalRole::Shadow);
        assert_eq!(
            store.load_v70_migration_bundle().await,
            Err("journal migration bundle ambiguous".into())
        );
        server.abort();
        assert_eq!(log.lock().await.len(), 1);

        let (endpoint, _, server) = v71_mock_s3(vec![
            v71_listing_page(&[key], None),
            v71_http(200, b"corrupt"),
        ])
        .await;
        let store = v71_store(&endpoint, JournalWriterState::Unrestored, JournalRole::Shadow);
        assert_eq!(
            store.load_v70_migration_bundle().await,
            Err("journal migration bundle content address mismatch".into())
        );
        server.abort();
    }

    #[tokio::test]
    async fn v71_replay_record_load_is_exact_and_canonical() {
        let (_, record) = v71_candidate();
        let bytes = serde_cbor::to_vec(&record).unwrap();
        let key = journal_record_key("epoch", record.sequence);
        let (endpoint, log, server) = v71_mock_s3(vec![v71_http(200, &bytes)]).await;
        let store = v71_store(&endpoint, JournalWriterState::Unrestored, JournalRole::Shadow);
        assert_eq!(store.load_journal_record(record.sequence).await, Ok(record.clone()));
        server.abort();
        assert!(log.lock().await[0].0.starts_with(&format!("get /unit-test/{key}")));

        let (endpoint, _, server) = v71_mock_s3(vec![v71_http(200, &bytes)]).await;
        let store = v71_store(&endpoint, JournalWriterState::Unrestored, JournalRole::Shadow);
        assert_eq!(
            store.load_journal_record(record.sequence + 1).await,
            Err("journal replay record invalid".into())
        );
        server.abort();
    }

    #[tokio::test]
    async fn v71_production_sized_migration_bundle_uses_multipart_create_only_with_exact_readback() {
        let bundle = v71_migration_bundle("m".repeat(17 * 1024 * 1024));
        let bytes = serde_cbor::to_vec(&bundle).unwrap();
        assert!(bytes.len() > 16 * 1024 * 1024);
        let key = journal_migration_key("epoch", 41, &bytes);
        let (endpoint, log, server) = v71_mock_s3(vec![
            v71_http(
                200,
                format!(
                    "<?xml version=\"1.0\"?><InitiateMultipartUploadResult><Bucket>unit-test</Bucket><Key>{key}</Key><UploadId>upload-1</UploadId></InitiateMultipartUploadResult>"
                )
                .as_bytes(),
            ),
            v71_http_with_etag("part-a"),
            v71_http_with_etag("part-b"),
            v71_http(
                200,
                format!(
                    "<?xml version=\"1.0\"?><CompleteMultipartUploadResult><Bucket>unit-test</Bucket><Key>{key}</Key><ETag>\"whole\"</ETag></CompleteMultipartUploadResult>"
                )
                .as_bytes(),
            ),
            v71_http(200, &bytes),
        ])
        .await;
        let store = v71_store(&endpoint, JournalWriterState::Unrestored, JournalRole::Writer);
        assert_eq!(store.persist_v70_migration_bundle(&bundle).await, Ok(key.clone()));
        server.abort();
        let log = log.lock().await;
        assert_eq!(log.len(), 5);
        let create = &log[0].0;
        assert!(create.starts_with(&format!("post /unit-test/{key}?uploads")), "{create}");
        for header in [
            "\r\nx-amz-server-side-encryption: aws:kms\r\n",
            "\r\nx-amz-object-lock-mode: compliance\r\n",
        ] {
            assert!(create.contains(header), "{header:?} missing from {create}");
        }
        for (part, _) in &log[1..3] {
            assert!(part.starts_with(&format!("put /unit-test/{key}?")), "{part}");
            assert!(part.contains("uploadid=upload-1"), "{part}");
        }
        let complete = &log[3].0;
        assert!(complete.starts_with(&format!("post /unit-test/{key}?")), "{complete}");
        assert!(complete.contains("\r\nif-none-match: *\r\n"), "{complete}");
        assert!(log[4].0.starts_with(&format!("get /unit-test/{key}")), "{}", log[4].0);
    }

    #[tokio::test]
    async fn v71_checkpoint_persists_create_only_under_journal_checkpoint_key() {
        let checkpoint = v71_checkpoint(41);
        let bytes = serde_cbor::to_vec(&checkpoint).unwrap();
        let key = journal_checkpoint_key("epoch", 41, &bytes);

        let (endpoint, log, server) =
            v71_mock_s3(vec![v71_http(200, b""), v71_http(200, &bytes)]).await;
        let store = v71_store(&endpoint, JournalWriterState::Unrestored, JournalRole::Writer);
        assert_eq!(store.persist_journal_checkpoint(&checkpoint).await, Ok(key.clone()));
        server.abort();
        let log = log.lock().await;
        assert_eq!(log.len(), 2);
        v71_assert_create_only_put(&log[0].0, &key);
        assert!(log[1].0.starts_with(&format!("get /unit-test/{key}")), "{}", log[1].0);
        drop(log);

        let (endpoint, _, server) = v71_mock_s3(vec![
            v71_s3_error(412, "PreconditionFailed"),
            v71_http(200, b"other"),
        ])
        .await;
        let store = v71_store(&endpoint, JournalWriterState::Unrestored, JournalRole::Writer);
        assert_eq!(
            store.persist_journal_checkpoint(&checkpoint).await,
            Err("archive immutable write failed".into())
        );
        server.abort();

        let (endpoint, log, server) = v71_mock_s3(Vec::new()).await;
        let store = v71_store(&endpoint, JournalWriterState::Unrestored, JournalRole::Shadow);
        assert_eq!(
            store.persist_journal_checkpoint(&checkpoint).await,
            Err("JOURNAL_SHADOW_WRITE_UNSUPPORTED".into())
        );
        let store = v71_store(&endpoint, JournalWriterState::Unrestored, JournalRole::Writer);
        for mutate in [
            (|c: &mut DirectV71Checkpoint| c.protocol = "other".into()) as fn(&mut DirectV71Checkpoint),
            |c| c.epoch_id = "other-epoch".into(),
        ] {
            let mut foreign = checkpoint.clone();
            mutate(&mut foreign);
            assert_eq!(
                store.persist_journal_checkpoint(&foreign).await,
                Err("journal checkpoint header invalid".into())
            );
        }
        server.abort();
        assert!(log.lock().await.is_empty());
    }

    #[tokio::test]
    async fn v71_checkpoint_publication_writes_parent_snapshots_before_discovery_marker() {
        let (checkpoint, index, receipts) = v71_checkpoint_publication_fixture();
        let index_bytes = serde_cbor::to_vec(&index).unwrap();
        let receipt_bytes = serde_cbor::to_vec(&receipts).unwrap();
        let checkpoint_bytes = serde_cbor::to_vec(&checkpoint).unwrap();
        let checkpoint_key = journal_checkpoint_key("epoch", 1, &checkpoint_bytes);
        let (endpoint, log, server) = v71_mock_s3(vec![
            v71_http(200, b""),
            v71_http(200, &index_bytes),
            v71_http(200, b""),
            v71_http(200, &receipt_bytes),
            v71_http(200, b""),
            v71_http(200, &checkpoint_bytes),
        ])
        .await;
        let store = v71_store(&endpoint, JournalWriterState::Unrestored, JournalRole::Writer);
        assert_eq!(
            store
                .publish_journal_checkpoint(&checkpoint, &index, &receipts)
                .await,
            Ok(checkpoint_key.clone())
        );
        server.abort();
        let log = log.lock().await;
        assert_eq!(log.len(), 6);
        assert!(log[0].0.contains("journal-v71/request-index/"));
        assert!(log[2].0.contains("journal-v71/receipts/"));
        assert!(log[4]
            .0
            .starts_with(&format!("put /unit-test/{checkpoint_key}")));
    }

    #[tokio::test]
    async fn v71_checkpoint_listing_paginates_and_loads_only_the_newest_verified_checkpoint() {
        let older = serde_cbor::to_vec(&v71_checkpoint(7)).unwrap();
        let newest = serde_cbor::to_vec(&v71_checkpoint(41)).unwrap();
        let older_key = journal_checkpoint_key("epoch", 7, &older);
        let newest_key = journal_checkpoint_key("epoch", 41, &newest);
        let (endpoint, log, server) = v71_mock_s3(vec![
            v71_listing_page(&[older_key], Some("page-2")),
            v71_listing_page(&[newest_key.clone()], None),
            v71_http(200, &newest),
        ])
        .await;
        let store = v71_store(&endpoint, JournalWriterState::Unrestored, JournalRole::Shadow);
        let (candidate, checkpoint) = store.load_newest_journal_checkpoint().await.unwrap().unwrap();
        assert_eq!(
            candidate,
            JournalCheckpointCandidate {
                sequence: 41,
                content_hash: sha256(&newest),
                key: newest_key.clone(),
            }
        );
        assert_eq!(checkpoint, v71_checkpoint(41));
        server.abort();
        let log = log.lock().await;
        assert_eq!(log.len(), 3);
        assert!(log[0].0.contains("prefix=epoch%2fjournal-v71%2fcheckpoints%2f"), "{}", log[0].0);
        assert!(!log[0].0.contains("continuation-token="), "{}", log[0].0);
        assert!(log[1].0.contains("continuation-token=page-2"), "{}", log[1].0);
        assert!(log[2].0.starts_with(&format!("get /unit-test/{newest_key}")), "{}", log[2].0);
        drop(log);

        let (endpoint, _, server) = v71_mock_s3(vec![v71_listing_page(&[], None)]).await;
        let store = v71_store(&endpoint, JournalWriterState::Unrestored, JournalRole::Writer);
        assert_eq!(store.load_newest_journal_checkpoint().await, Ok(None));
        server.abort();
    }

    #[tokio::test]
    async fn v71_checkpoint_listing_fails_closed_on_malformed_duplicate_or_ambiguous_pages() {
        let seven = journal_checkpoint_key("epoch", 7, b"seven");
        let forty_one = journal_checkpoint_key("epoch", 41, b"forty-one");
        let miscounted = v71_http(
            200,
            format!(
                "<?xml version=\"1.0\"?><ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><IsTruncated>false</IsTruncated><KeyCount>2</KeyCount><Contents><Key>{seven}</Key><Size>1</Size></Contents></ListBucketResult>"
            )
            .as_bytes(),
        );
        let cases = vec![
            (
                vec![v71_listing_page(
                    &["epoch/journal-v71/checkpoints/00000000000000000041.cbor".into()],
                    None,
                )],
                "journal content key format invalid",
            ),
            (
                vec![v71_listing_page(
                    &[forty_one.clone(), journal_checkpoint_key("epoch", 41, b"twin")],
                    None,
                )],
                "journal checkpoint duplicate sequence",
            ),
            (
                vec![
                    v71_listing_page(&[seven.clone()], Some("t1")),
                    v71_listing_page(&[forty_one.clone()], Some("t1")),
                ],
                "journal pagination token repeated",
            ),
            (
                vec![v71_listing_page(&[seven.clone()], Some(""))],
                "journal pagination token missing",
            ),
            (
                vec![
                    v71_listing_page(&[seven.clone()], Some("t1")),
                    v71_listing_page(&[seven.clone()], None),
                ],
                "journal listing duplicate key",
            ),
            (
                vec![v71_listing_page(&[], Some("t1"))],
                "journal listing ambiguous",
            ),
            (vec![miscounted], "journal listing ambiguous"),
            (
                vec![v71_listing_page(&["epoch/checkpoints/x.cbor".into()], None)],
                "journal listing key foreign",
            ),
            (vec![v71_s3_error(403, "AccessDenied")], "journal listing failed"),
        ];
        for (responses, error) in cases {
            let pages = responses.len();
            let (endpoint, log, server) = v71_mock_s3(responses).await;
            let store = v71_store(&endpoint, JournalWriterState::Unrestored, JournalRole::Writer);
            assert_eq!(
                store.load_newest_journal_checkpoint().await,
                Err(error.into()),
                "{error}"
            );
            server.abort();
            // Never a read of any checkpoint once the listing is rejected.
            assert_eq!(log.lock().await.len(), pages, "{error}");
        }
    }

    #[tokio::test]
    async fn v71_newest_checkpoint_corruption_fails_closed_without_older_fallback() {
        let older = serde_cbor::to_vec(&v71_checkpoint(7)).unwrap();
        let older_key = journal_checkpoint_key("epoch", 7, &older);
        let mut wrong_protocol = v71_checkpoint(41);
        wrong_protocol.protocol = "other".into();
        let wrong_protocol = serde_cbor::to_vec(&wrong_protocol).unwrap();
        let wrong_sequence = serde_cbor::to_vec(&v71_checkpoint(40)).unwrap();
        let newest = serde_cbor::to_vec(&v71_checkpoint(41)).unwrap();
        let cases: Vec<(String, Vec<u8>, &str)> = vec![
            (
                journal_checkpoint_key("epoch", 41, &newest),
                older.clone(),
                "journal checkpoint content address mismatch; older fallback forbidden",
            ),
            (
                journal_checkpoint_key("epoch", 41, b"not-cbor"),
                b"not-cbor".to_vec(),
                "journal checkpoint decode failed; older fallback forbidden",
            ),
            (
                journal_checkpoint_key("epoch", 41, &wrong_sequence),
                wrong_sequence,
                "journal checkpoint invalid; older fallback forbidden",
            ),
            (
                journal_checkpoint_key("epoch", 41, &wrong_protocol),
                wrong_protocol,
                "journal checkpoint invalid; older fallback forbidden",
            ),
        ];
        for (newest_key, body, error) in cases {
            let (endpoint, log, server) = v71_mock_s3(vec![
                v71_listing_page(&[older_key.clone(), newest_key.clone()], None),
                v71_http(200, &body),
            ])
            .await;
            let store = v71_store(&endpoint, JournalWriterState::Unrestored, JournalRole::Writer);
            assert_eq!(store.load_newest_journal_checkpoint().await, Err(error.into()));
            server.abort();
            let log = log.lock().await;
            assert_eq!(log.len(), 2, "{error}");
            assert!(log[1].0.starts_with(&format!("get /unit-test/{newest_key}")), "{error}");
        }
    }

    #[tokio::test]
    async fn v71_tail_listing_starts_after_checkpoint_and_enforces_restore_bound() {
        assert_eq!(MAX_V71_RESTORE_TAIL_RECORDS, 1000);
        let keys = |range: std::ops::RangeInclusive<u64>| -> Vec<String> {
            range.map(|sequence| journal_record_key("epoch", sequence)).collect()
        };
        let (endpoint, log, server) = v71_mock_s3(vec![v71_listing_page(&keys(42..=43), None)]).await;
        let store = v71_store(&endpoint, JournalWriterState::Unrestored, JournalRole::Writer);
        assert_eq!(
            store.list_journal_tail(41).await,
            Ok(keys(42..=43).into_iter().zip(42..).map(|(k, s)| (s, k)).collect())
        );
        server.abort();
        let list = log.lock().await[0].0.clone();
        for query in [
            "list-type=2",
            "prefix=epoch%2fheads%2f",
            "start-after=epoch%2fheads%2f00000000000000000041.cbor",
        ] {
            assert!(list.contains(query), "{query} missing from {list}");
        }

        // Exactly the bound across pages is accepted.
        let (endpoint, _, server) = v71_mock_s3(vec![
            v71_listing_page(&keys(42..=641), Some("t1")),
            v71_listing_page(&keys(642..=1041), None),
        ])
        .await;
        let store = v71_store(&endpoint, JournalWriterState::Unrestored, JournalRole::Writer);
        assert_eq!(store.list_journal_tail(41).await.unwrap().len(), 1000);
        server.abort();

        // One record over the bound fails closed.
        let (endpoint, _, server) = v71_mock_s3(vec![
            v71_listing_page(&keys(42..=1041), Some("t1")),
            v71_listing_page(&keys(1042..=1042), None),
        ])
        .await;
        let store = v71_store(&endpoint, JournalWriterState::Unrestored, JournalRole::Writer);
        assert_eq!(
            store.list_journal_tail(41).await,
            Err("journal listing exceeds bound".into())
        );
        server.abort();

        let (endpoint, _, server) = v71_mock_s3(vec![v71_listing_page(&[], None)]).await;
        let store = v71_store(&endpoint, JournalWriterState::Unrestored, JournalRole::Writer);
        assert_eq!(store.list_journal_tail(41).await, Ok(Vec::new()));
        server.abort();
    }

    #[tokio::test]
    async fn v71_tail_listing_fails_closed_on_gap_duplicate_legacy_foreign_range_and_timeout() {
        let record = |sequence| journal_record_key("epoch", sequence);
        let legacy = format!("epoch/heads/00000000000000000043-{}.cbor", "a".repeat(64));
        let cases = vec![
            (vec![v71_listing_page(&[record(42), record(44)], None)], "journal tail sequence gap"),
            (vec![v71_listing_page(&[record(43)], None)], "journal tail sequence gap"),
            (
                vec![v71_listing_page(&[record(42), legacy], None)],
                "journal record key legacy suffix",
            ),
            (
                vec![v71_listing_page(&[record(41)], None)],
                "journal listing key out of range",
            ),
            (
                vec![
                    v71_listing_page(&[record(42)], Some("t1")),
                    v71_listing_page(&[record(42)], None),
                ],
                "journal listing duplicate key",
            ),
            (
                vec![v71_listing_page(&["epoch/artifacts/x.cbor".into()], None)],
                "journal listing key foreign",
            ),
            (
                vec![v71_listing_page(&["epoch/heads/zzz.cbor".into()], None)],
                "archive key format invalid",
            ),
        ];
        for (responses, error) in cases {
            let (endpoint, _, server) = v71_mock_s3(responses).await;
            let store = v71_store(&endpoint, JournalWriterState::Unrestored, JournalRole::Writer);
            assert_eq!(store.list_journal_tail(41).await, Err(error.into()), "{error}");
            server.abort();
        }

        let (endpoint, server) = v71_silent_s3().await;
        let store = v71_store(&endpoint, JournalWriterState::Unrestored, JournalRole::Writer);
        assert_eq!(
            store
                .list_journal_tail_with_timeout(41, Duration::from_millis(200))
                .await,
            Err("ARCHIVE_TIMEOUT".into())
        );
        server.abort();
    }

    #[tokio::test]
    async fn v71_tail_loading_chains_records_from_checkpoint_and_rejects_tampering() {
        let mut index = layrs_direct_execution_v1::request_index::SparseRequestTree::default();
        let (_, first) = v71_candidate_after(&v71_head(), &mut index, "request-42");
        let (_, second) = v71_candidate_after(&v71_next_head(&first), &mut index, "request-43");
        assert_eq!(second.previous_request_index_root, first.request_index_root);
        let first_bytes = serde_cbor::to_vec(&first).unwrap();
        let second_bytes = serde_cbor::to_vec(&second).unwrap();
        let listing = || {
            v71_listing_page(
                &[journal_record_key("epoch", 42), journal_record_key("epoch", 43)],
                None,
            )
        };
        let checkpoint = v71_checkpoint(41);

        let (endpoint, log, server) = v71_mock_s3(vec![
            listing(),
            v71_http(200, &first_bytes),
            v71_http(200, &second_bytes),
        ])
        .await;
        let store = v71_store(&endpoint, JournalWriterState::Unrestored, JournalRole::Writer);
        assert_eq!(
            store.load_journal_tail(&checkpoint).await,
            Ok(vec![first.clone(), second.clone()])
        );
        server.abort();
        let log = log.lock().await;
        assert!(log[1].0.starts_with("get /unit-test/epoch/heads/00000000000000000042.cbor"));
        assert!(log[2].0.starts_with("get /unit-test/epoch/heads/00000000000000000043.cbor"));
        drop(log);

        // The checkpoint anchor must match the first record on every chained
        // field, including the request-index root.
        for (mutate, field) in [
            (
                (|c: &mut DirectV71Checkpoint| c.record_hash = "9".repeat(64))
                    as fn(&mut DirectV71Checkpoint),
                "record hash",
            ),
            (|c| c.transition_root = "9".repeat(64), "transition root"),
            (|c| c.request_index_root = "9".repeat(64), "request-index root"),
        ] {
            let mut anchor = checkpoint.clone();
            mutate(&mut anchor);
            let (endpoint, _, server) = v71_mock_s3(vec![
                listing(),
                v71_http(200, &first_bytes),
                v71_http(200, &second_bytes),
            ])
            .await;
            let store = v71_store(&endpoint, JournalWriterState::Unrestored, JournalRole::Writer);
            assert_eq!(
                store.load_journal_tail(&anchor).await,
                Err("journal tail record predecessor mismatch".into()),
                "{field}"
            );
            server.abort();
        }

        // A second record whose request-index predecessor is not the first
        // record's request-index root breaks the chain even if every other
        // link holds. Its bytes are served verbatim, as tampered storage would.
        let mut forked = second.clone();
        forked.previous_request_index_root =
            layrs_direct_execution_v1::request_index::empty_request_index_root();
        assert_ne!(forked.previous_request_index_root, first.request_index_root);
        let mut forked_hash_link = second.clone();
        forked_hash_link.previous_record_hash = "9".repeat(64);
        let v70_head_body = "a".repeat(64).into_bytes();
        let cases: Vec<(Vec<u8>, Vec<u8>, &str)> = vec![
            (
                first_bytes.clone(),
                serde_cbor::to_vec(&forked).unwrap(),
                "journal tail record predecessor mismatch",
            ),
            (
                first_bytes.clone(),
                serde_cbor::to_vec(&forked_hash_link).unwrap(),
                "journal tail record predecessor mismatch",
            ),
            (
                second_bytes.clone(),
                first_bytes.clone(),
                "journal tail record sequence mismatch",
            ),
            (
                v70_head_body,
                second_bytes.clone(),
                "journal tail record decode failed",
            ),
        ];
        for (at_42, at_43, error) in cases {
            let (endpoint, _, server) =
                v71_mock_s3(vec![listing(), v71_http(200, &at_42), v71_http(200, &at_43)]).await;
            let store = v71_store(&endpoint, JournalWriterState::Unrestored, JournalRole::Writer);
            assert_eq!(store.load_journal_tail(&checkpoint).await, Err(error.into()), "{error}");
            server.abort();
        }
    }

    // v70 rollback materialization (FULL_STATE_JOURNAL_V71_CONTRACT.md,
    // "Rollback"). Loopback S3 and in-process library sealing only.

    type V70RollbackObjects = Arc<Mutex<BTreeMap<String, Vec<u8>>>>;

    fn v70_rollback_percent_decode(value: &str) -> String {
        let bytes = value.as_bytes();
        let mut decoded = Vec::with_capacity(bytes.len());
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] == b'%' && index + 2 < bytes.len() {
                decoded.push(u8::from_str_radix(&value[index + 1..index + 3], 16).unwrap());
                index += 3;
            } else {
                decoded.push(bytes[index]);
                index += 1;
            }
        }
        String::from_utf8(decoded).unwrap()
    }

    /// Stateful loopback S3: create-only PUT (412 on an existing key), GET,
    /// and one-page ListObjectsV2 honoring `prefix` and `start-after`. Each
    /// connection is served concurrently and logged as `(lowercased head, body)`.
    async fn v70_rollback_s3(
        objects: BTreeMap<String, Vec<u8>>,
    ) -> (
        String,
        V70RollbackObjects,
        V71RequestLog,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let objects = Arc::new(Mutex::new(objects));
        let log = V71RequestLog::default();
        let (stored, recorded) = (objects.clone(), log.clone());
        let server = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let (stored, recorded) = (stored.clone(), recorded.clone());
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut buffer = [0u8; 8192];
                    let (head, body) = loop {
                        let size = socket.read(&mut buffer).await.unwrap();
                        if size == 0 {
                            return;
                        }
                        request.extend_from_slice(&buffer[..size]);
                        let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") else {
                            continue;
                        };
                        let head = String::from_utf8_lossy(&request[..end]).to_ascii_lowercase();
                        let length = head
                            .lines()
                            .find_map(|line| line.strip_prefix("content-length:"))
                            .map_or(0, |value| value.trim().parse::<usize>().unwrap());
                        if request.len() >= end + 4 + length {
                            break (head, request[end + 4..end + 4 + length].to_vec());
                        }
                    };
                    recorded.lock().await.push((head.clone(), body.clone()));
                    let target = head.split_whitespace().nth(1).unwrap().to_string();
                    let (path, query) = target.split_once('?').unwrap_or((target.as_str(), ""));
                    let params = query
                        .split('&')
                        .filter_map(|pair| pair.split_once('='))
                        .map(|(name, value)| (name.to_string(), v70_rollback_percent_decode(value)))
                        .collect::<BTreeMap<_, _>>();
                    let key = v70_rollback_percent_decode(
                        path.trim_start_matches("/unit-test")
                            .trim_start_matches('/'),
                    );
                    let response = if head.starts_with("put ") {
                        let mut stored = stored.lock().await;
                        if head.contains("\r\nif-none-match: *") && stored.contains_key(&key) {
                            v71_s3_error(412, "PreconditionFailed")
                        } else {
                            stored.insert(key, body);
                            v71_http_with_etag("mock")
                        }
                    } else if params.get("list-type").map(String::as_str) == Some("2") {
                        let prefix = params.get("prefix").cloned().unwrap_or_default();
                        let after = params.get("start-after").cloned().unwrap_or_default();
                        let keys = stored
                            .lock()
                            .await
                            .keys()
                            .filter(|key| key.starts_with(&prefix) && key.as_str() > after.as_str())
                            .cloned()
                            .collect::<Vec<_>>();
                        v71_listing(&keys)
                    } else if let Some(bytes) = stored.lock().await.get(&key) {
                        v71_http(200, bytes)
                    } else {
                        v71_s3_error(404, "NoSuchKey")
                    };
                    socket.write_all(&response).await.unwrap();
                });
            }
        });
        (endpoint, objects, log, server)
    }

    struct V70RollbackFixture {
        epoch: SealedEpoch,
        v71: layrs_direct_execution_v1::v71::DirectV71Runtime,
        bundle: V70MigrationBundle,
        records: Vec<DirectJournalRecord>,
        commands: Vec<(DirectRequest, DirectResult)>,
        receipts: JournalReceiptCache,
        head: JournalHead,
    }

    fn v70_rollback_admission(seed: char, wallet_digit: char) -> DirectRequest {
        let subject = seed.to_string().repeat(64);
        let wallet = format!("0x{}", wallet_digit.to_string().repeat(40));
        let mut request = DirectRequest {
            account_id: subject.clone(),
            identity_commitment: identity_commitment_for(&subject, &wallet),
            request_id: format!("rollback-admission-{seed}"),
            request_hash: String::new(),
            financial_wallet_address: None,
            action: DirectAction::AdmitIdentity {
                wallet_address: wallet,
            },
        };
        request.request_hash = request_hash(&request);
        request
    }

    fn v70_rollback_journal_key() -> [u8; 32] {
        layrs_direct_execution_v1::journal::journal_verifying_key(&[8; 32]).unwrap()
    }

    /// Two v70 commits migrated at source sequence 2, then two v71 journal
    /// commits: head 4. Keys: state [7; 32], journal [8; 32], receipt [9; 32].
    fn v70_rollback_fixture() -> V70RollbackFixture {
        let epoch = SealedEpoch::load(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
            "../../../../.codex-review-bundles/unified-direct-execution-20260905/new-epoch-20260911/OPENING_EPOCH_STATE_20260911.json",
        ))
        .unwrap();
        let mut v70 = layrs_direct_execution_v1::DirectRuntime::new(
            epoch.clone(),
            layrs_direct_execution_v1::RuntimeMode::IsolatedTest,
            vec![9; 32],
        )
        .unwrap();
        let mut commands = Vec::new();
        let mut receipts = JournalReceiptCache::new();
        for (seed, wallet) in [('a', '1'), ('b', '2')] {
            let request = v70_rollback_admission(seed, wallet);
            let result = v70.execute(request.clone()).unwrap();
            receipts.insert(
                (request.account_id.clone(), request.request_id.clone()),
                (v70.committed_sequence(), result.receipt.clone()),
            );
            commands.push((request, result));
        }
        let bundle = V70MigrationBundle::seal(&v70, &[7; 32], &[8; 32]).unwrap();
        let mut v71 = layrs_direct_execution_v1::v71::DirectV71Runtime::from_v70_migration(
            v70,
            &bundle,
            "writer-epoch-2".into(),
            &[7; 32],
            &v70_rollback_journal_key(),
        )
        .unwrap();
        let mut tree = layrs_direct_execution_v1::request_index::SparseRequestTree::from_leaves(
            &bundle.leaves,
        )
        .unwrap();
        let mut records = Vec::new();
        for (seed, wallet) in [('c', '3'), ('d', '4')] {
            let request = v70_rollback_admission(seed, wallet);
            let proof = tree
                .proof(&request.account_id, &request.request_id)
                .unwrap();
            let candidate = v71
                .prepare_candidate(request.clone(), &proof, &[7; 32], &[8; 32])
                .unwrap();
            tree.insert(candidate.terminal_leaf().clone()).unwrap();
            records.push(candidate.record().clone());
            let result = v71.adopt_candidate(candidate).unwrap();
            receipts.insert(
                (request.account_id.clone(), request.request_id.clone()),
                (v71.sequence(), result.receipt.clone()),
            );
            commands.push((request, result));
        }
        let head = JournalHead {
            writer_epoch: v71.writer_epoch().into(),
            sequence: v71.sequence(),
            record_hash: v71.record_hash().into(),
            transition_root: v71.transition_root().into(),
            request_index_root: v71.request_index_root().into(),
            financial_state_root: v71.financial_state_root().unwrap(),
        };
        assert_eq!(head.sequence, 4);
        V70RollbackFixture {
            epoch,
            v71,
            bundle,
            records,
            commands,
            receipts,
            head,
        }
    }

    fn append_v71_rollback_successor(
        fixture: &mut V70RollbackFixture,
        seed: char,
        wallet: char,
    ) {
        let mut tree = layrs_direct_execution_v1::request_index::SparseRequestTree::from_leaves(
            &fixture.bundle.leaves,
        )
        .unwrap();
        for record in &fixture.records {
            tree.insert(TerminalRequestLeaf {
                account_id: record.account_id.clone(),
                request_id: record.request_id.clone(),
                request_hash: record.request_hash.clone(),
                result_hash: record.result_hash.clone(),
                receipt_hash: record.receipt_hash.clone(),
                locator: TerminalResultLocator::Journal {
                    writer_epoch: record.writer_epoch.clone(),
                    sequence: record.sequence,
                },
            })
            .unwrap();
        }
        let request = v70_rollback_admission(seed, wallet);
        let proof = tree
            .proof(&request.account_id, &request.request_id)
            .unwrap();
        let candidate = fixture
            .v71
            .prepare_candidate(request.clone(), &proof, &[7; 32], &[8; 32])
            .unwrap();
        fixture.records.push(candidate.record().clone());
        let result = fixture.v71.adopt_candidate(candidate).unwrap();
        fixture.receipts.insert(
            (request.account_id.clone(), request.request_id.clone()),
            (fixture.v71.sequence(), result.receipt.clone()),
        );
        fixture.commands.push((request, result));
        fixture.head = JournalHead {
            writer_epoch: fixture.v71.writer_epoch().into(),
            sequence: fixture.v71.sequence(),
            record_hash: fixture.v71.record_hash().into(),
            transition_root: fixture.v71.transition_root().into(),
            request_index_root: fixture.v71.request_index_root().into(),
            financial_state_root: fixture.v71.financial_state_root().unwrap(),
        };
    }

    /// The authoritative prefix `epoch`: the migration bundle, v70 head
    /// pointers (plus a legacy twin) through the source, then v71 records.
    fn v70_rollback_archive(fixture: &V70RollbackFixture) -> BTreeMap<String, Vec<u8>> {
        let source = fixture.bundle.manifest.source_sequence;
        let bundle = serde_cbor::to_vec(&fixture.bundle).unwrap();
        let mut objects =
            BTreeMap::from([(journal_migration_key("epoch", source, &bundle), bundle)]);
        for sequence in 1..=source {
            objects.insert(
                archive_head_key("epoch", sequence),
                sha256(format!("v70-{sequence}").as_bytes()).into_bytes(),
            );
        }
        objects.insert(
            format!("epoch/heads/{source:020}-{}.cbor", "e".repeat(64)),
            b"legacy".to_vec(),
        );
        for record in &fixture.records {
            objects.insert(
                journal_record_key("epoch", record.sequence),
                serde_cbor::to_vec(record).unwrap(),
            );
        }
        objects
    }

    fn v70_rollback_state(
        store: Option<S3ImmutableArtifactStore>,
        fixture: &V70RollbackFixture,
    ) -> AppState {
        AppState {
            enclave_cid: 16,
            session_key: vec![7; 32],
            isolated_test: true,
            projection: None,
            local_used_sessions: Arc::new(Mutex::new(HashSet::new())),
            artifact_store: store.map(ArchiveStore::S3),
            commit_ack_key: Vec::new(),
            custody: None,
            zen_custody: None,
            usdc_custody: None,
            usdc_link_authority: None,
            usdc_bus_custody: None,
            financial_gate: Arc::new(FinancialGate::new()),
            last_commit_at: Arc::new(AtomicU64::new(0)),
            health: Arc::new(ParentHealth::default()),
            committed_state_root: Arc::new(Mutex::new(Some(fixture.head.transition_root.clone()))),
            unresolved_external_effects: Arc::new(Mutex::new(BTreeMap::new())),
            governed_bootstrap: None,
            persistence_format: PersistenceFormat::V71,
            hot_v71_enabled: Arc::new(AtomicBool::new(false)),
            journal_request_index: Arc::new(Mutex::new(None)),
            journal_receipts: Arc::new(Mutex::new(Some(fixture.receipts.clone()))),
            journal_migration: Arc::new(Mutex::new(Some(fixture.bundle.clone()))),
            journal_checkpoint_sequence: Arc::new(AtomicU64::new(0)),
            journal_transition_roots: Arc::new(Mutex::new(None)),
        }
    }

    /// Stands in for the enclave exchange with the library's own
    /// `seal_v70_rollback_checkpoint`, recording that it was reached.
    fn v70_rollback_seal(
        v71: layrs_direct_execution_v1::v71::DirectV71Runtime,
        called: Arc<AtomicU64>,
    ) -> impl FnOnce(RuntimeRequest) -> std::future::Ready<io::Result<RuntimeResponse>> {
        move |request| {
            called.fetch_add(1, Ordering::SeqCst);
            let RuntimeRequest::SealV70RollbackCheckpoint {
                migration,
                journal_records,
            } = request
            else {
                panic!("unexpected enclave request");
            };
            std::future::ready(Ok(
                match v71.seal_v70_rollback_checkpoint(
                    &migration,
                    &journal_records,
                    &[7; 32],
                    &v70_rollback_journal_key(),
                ) {
                    Ok(checkpoint) => RuntimeResponse::CheckpointSealed { checkpoint },
                    Err(_) => RuntimeResponse::Error {
                        code: "V70_ROLLBACK_ARCHIVE_INVALID".into(),
                    },
                },
            ))
        }
    }

    fn v70_rollback_puts(log: &[(String, Vec<u8>)]) -> Vec<String> {
        log.iter()
            .filter(|(head, _)| head.starts_with("put "))
            .map(|(head, _)| head.clone())
            .collect()
    }

    #[test]
    fn v70_rollback_prefix_must_be_canonical_and_disjoint_from_the_authoritative_archive() {
        assert_eq!(
            validate_v70_rollback_prefix("epoch", "rollback/v70-2026.09_28"),
            Ok(())
        );
        assert_eq!(
            validate_v70_rollback_prefix("epoch", "epoch-rollback"),
            Ok(())
        );
        for fresh in ["epoch", "epoch/rollback", "epoch/shadow-v71/run"] {
            assert_eq!(
                validate_v70_rollback_prefix("epoch", fresh),
                Err("v70 rollback prefix overlaps authoritative archive"),
                "{fresh}"
            );
        }
        assert_eq!(
            validate_v70_rollback_prefix("layrs/epoch", "layrs"),
            Err("v70 rollback prefix overlaps authoritative archive")
        );
        for fresh in [
            "",
            "/rollback",
            "rollback/",
            "roll//back",
            "rollback/../epoch",
            "./rollback",
            "roll back",
            "rollback?x=1",
            &"r".repeat(513),
        ] {
            assert_eq!(
                validate_v70_rollback_prefix("epoch", fresh),
                Err("v70 rollback prefix invalid"),
                "{fresh}"
            );
        }
    }

    #[test]
    fn v70_rollback_request_frame_bound_is_exact() {
        let limit = MAX_FRAME_BYTES - V70_ROLLBACK_FRAME_ENVELOPE_BYTES;
        assert_eq!(advance_v70_rollback_frame_bytes(limit - 1, 1), Ok(limit));
        assert_eq!(
            advance_v70_rollback_frame_bytes(limit, 1),
            Err("v70 rollback request exceeds frame bound")
        );
        assert!(advance_v70_rollback_frame_bytes(usize::MAX, 1).is_err());
        assert!(advance_v70_rollback_frame_bytes(MAX_FRAME_BYTES, 0).is_err());
    }

    #[test]
    fn v70_rollback_checkpoint_must_match_head_receipt_order_and_content_addresses() {
        let fixture = v70_rollback_fixture();
        let checkpoint = v70_rollback_checkpoint(&fixture);
        let receipts = ordered_journal_receipts(&fixture.receipts).unwrap();
        let (key, head, frontier) =
            validate_v70_rollback_checkpoint(&checkpoint, 4, &receipts, "rollback").unwrap();
        let hash = artifact_hash(&checkpoint.artifact);
        assert_eq!(key, format!("rollback/artifacts/{:020}-{hash}.cbor", 4));
        assert_eq!(head.key, archive_head_key("rollback", 4));
        assert_eq!(head.sequence, 4);
        assert_eq!(head.artifact_hash, hash);
        assert_eq!(frontier.sequence, 4);
        assert_eq!(frontier.state_hash, checkpoint.artifact.state_hash);
        assert_eq!(frontier.artifact_hash, hash);
        assert!(frontier.accepts_checkpoint(&checkpoint));

        let header = "v70 rollback checkpoint header invalid";
        let lineage = "v70 rollback checkpoint lineage mismatch";
        assert_eq!(
            validate_v70_rollback_checkpoint(&checkpoint, 3, &receipts, "rollback"),
            Err(header.into())
        );
        assert_eq!(
            validate_v70_rollback_checkpoint(&checkpoint, 4, &receipts[..3], "rollback"),
            Err(header.into())
        );
        let mut reordered = receipts.clone();
        reordered.swap(2, 3);
        assert_eq!(
            validate_v70_rollback_checkpoint(&checkpoint, 4, &reordered, "rollback"),
            Err(lineage.into())
        );
        let mut foreign_receipt = receipts.clone();
        foreign_receipt[0].1.signature = "0".repeat(64);
        assert_eq!(
            validate_v70_rollback_checkpoint(&checkpoint, 4, &foreign_receipt, "rollback"),
            Err(lineage.into())
        );
        let mutations: Vec<(
            Box<dyn Fn(&mut layrs_direct_execution_v1::DirectCheckpoint)>,
            &str,
        )> =
            vec![
                (Box::new(|c| c.protocol = "other".into()), header),
                (Box::new(|c| c.signature.clear()), header),
                (
                    Box::new(|c| {
                        c.bootstrap_certificate = Some(
                        layrs_direct_execution_v1::CheckpointBootstrapCertificate::for_checkpoint(c)
                            .unwrap(),
                    )
                    }),
                    header,
                ),
                (Box::new(|c| c.artifact.ciphertext[0] ^= 1), header),
                (Box::new(|c| c.artifact.epoch_id = "other".into()), header),
                (Box::new(|c| c.artifact_hashes[0] = "0".repeat(64)), lineage),
                (Box::new(|c| c.artifact_hashes[3] = "0".repeat(64)), lineage),
                (
                    Box::new(|c| c.receipt_records[1].state_hash = "0".repeat(64)),
                    lineage,
                ),
                (
                    Box::new(|c| c.receipt_records[0].prior_state_hash = "0".repeat(64)),
                    lineage,
                ),
                (
                    Box::new(|c| c.receipt_records[2].ciphertext = vec![1]),
                    lineage,
                ),
                (Box::new(|c| c.receipt_records.swap(0, 1)), lineage),
                (Box::new(|c| c.opening_state_hash = "0".repeat(64)), lineage),
                (
                    Box::new(|c| c.receipt_records[3].request_hash = "0".repeat(64)),
                    lineage,
                ),
            ];
        for (index, (mutate, error)) in mutations.iter().enumerate() {
            let mut tampered = checkpoint.clone();
            mutate(&mut tampered);
            assert_eq!(
                validate_v70_rollback_checkpoint(&tampered, 4, &receipts, "rollback"),
                Err((*error).into()),
                "mutation {index}"
            );
        }
        // The terminal compact record must equal the full head artifact.
        let mut tampered = checkpoint;
        tampered.receipt_records[3].nonce = vec![0; 12];
        assert!(validate_v70_rollback_checkpoint(&tampered, 4, &receipts, "rollback").is_err());
    }

    fn v70_rollback_checkpoint(
        fixture: &V70RollbackFixture,
    ) -> layrs_direct_execution_v1::DirectCheckpoint {
        fixture
            .v71
            .seal_v70_rollback_checkpoint(
                &fixture.bundle,
                &fixture.records,
                &[7; 32],
                &v70_rollback_journal_key(),
            )
            .unwrap()
    }

    type V70RollbackEnclave = Arc<StdMutex<Option<layrs_direct_execution_v1::DirectRuntime>>>;

    /// The retained v70 enclave's unchanged BeginCheckpointRestore,
    /// AppendCommittedRestore, and FinishCommittedRestore rules under a
    /// governed frontier, served by the library runtime that implements them.
    /// The adopted runtime is left in the returned cell.
    fn v70_rollback_enclave(
        epoch: SealedEpoch,
        frontier: layrs_direct_execution_v1::CommittedRestoreFrontier,
    ) -> (
        V70RollbackEnclave,
        impl FnMut(RuntimeRequest) -> std::future::Ready<io::Result<RuntimeResponse>>,
    ) {
        let adopted = V70RollbackEnclave::default();
        let cell = adopted.clone();
        let mut candidate: Option<layrs_direct_execution_v1::DirectRuntime> = None;
        let error = |code: &str| RuntimeResponse::Error { code: code.into() };
        let exchange = move |request| {
            let response = match request {
                RuntimeRequest::BeginCheckpointRestore { checkpoint } => {
                    if candidate.is_some() || !frontier.accepts_checkpoint(&checkpoint) {
                        error("CHECKPOINT_BELOW_GOVERNED_FRONTIER")
                    } else {
                        match layrs_direct_execution_v1::DirectRuntime::new(
                            epoch.clone(),
                            layrs_direct_execution_v1::RuntimeMode::IsolatedTest,
                            vec![9; 32],
                        )
                        .and_then(|runtime| runtime.restore_checkpoint(&checkpoint, &[7; 32]))
                        {
                            Ok(runtime) => {
                                let response = RuntimeResponse::RestoreProgress {
                                    recovered_sequence: runtime.committed_sequence(),
                                    recovered_state_hash: runtime.committed_state_hash(),
                                };
                                candidate = Some(runtime);
                                response
                            }
                            Err(_) => error("CHECKPOINT_AUTHENTICATION_FAILED"),
                        }
                    }
                }
                RuntimeRequest::AppendCommittedRestore { artifact } => match candidate
                    .take()
                    .map(|runtime| runtime.restore_next_committed(&artifact, &[7; 32]))
                {
                    Some(Ok(runtime)) => {
                        let response = RuntimeResponse::RestoreProgress {
                            recovered_sequence: runtime.committed_sequence(),
                            recovered_state_hash: runtime.committed_state_hash(),
                        };
                        candidate = Some(runtime);
                        response
                    }
                    _ => error("RESTORE_SUCCESSOR_REJECTED"),
                },
                RuntimeRequest::FinishCommittedRestore {
                    expected_sequence,
                    expected_state_hash,
                } => match candidate.take() {
                    Some(runtime)
                        if runtime.committed_sequence() == expected_sequence
                            && runtime.committed_state_hash() == expected_state_hash
                            && expected_sequence >= frontier.sequence =>
                    {
                        *cell.lock().unwrap() = Some(runtime);
                        RuntimeResponse::RecoveryComplete {
                            recovered_sequence: expected_sequence,
                            recovered_state_hash: expected_state_hash,
                        }
                    }
                    _ => error("RESTORE_FINAL_HEAD_MISMATCH"),
                },
                _ => panic!("unexpected enclave request"),
            };
            std::future::ready(Ok(response))
        };
        (adopted, exchange)
    }

    fn v70_rollback_frontier(
        package: &V70RollbackPackage,
    ) -> layrs_direct_execution_v1::CommittedRestoreFrontier {
        layrs_direct_execution_v1::CommittedRestoreFrontier {
            sequence: package.sequence,
            state_hash: package.state_hash.clone(),
            artifact_hash: package.artifact_hash.clone(),
        }
    }

    /// Materializes the fixture's package under `rollback` and returns it
    /// with exactly the three objects written there.
    async fn v70_rollback_package(
        fixture: &V70RollbackFixture,
    ) -> (V70RollbackPackage, BTreeMap<String, Vec<u8>>) {
        let (endpoint, objects, _, server) = v70_rollback_s3(v70_rollback_archive(fixture)).await;
        let store = v71_store(
            &endpoint,
            JournalWriterState::Eligible(fixture.head.clone()),
            JournalRole::Writer,
        );
        let state = v70_rollback_state(Some(store), fixture);
        let package = materialize_v70_rollback(
            &state,
            "rollback",
            v70_rollback_seal(fixture.v71.clone(), Arc::new(AtomicU64::new(0))),
        )
        .await
        .unwrap();
        server.abort();
        let objects = objects
            .lock()
            .await
            .iter()
            .filter(|(key, _)| key.starts_with("rollback/"))
            .map(|(key, bytes)| (key.clone(), bytes.clone()))
            .collect::<BTreeMap<_, _>>();
        (package, objects)
    }

    fn v70_rollback_store_at(endpoint: &str, prefix: &str) -> S3ImmutableArtifactStore {
        let mut store = v71_store(
            endpoint,
            JournalWriterState::Unrestored,
            JournalRole::Writer,
        );
        store.prefix = prefix.into();
        store
    }

    fn v70_rollback_baseline_state(fixture: &V70RollbackFixture) -> AppState {
        let mut state = v70_rollback_state(None, fixture);
        state.persistence_format = PersistenceFormat::V70RollbackBaseline;
        state.journal_receipts = Arc::new(Mutex::new(None));
        state.journal_migration = Arc::new(Mutex::new(None));
        state.committed_state_root = Arc::new(Mutex::new(None));
        state
    }

    #[tokio::test]
    async fn v70_rollback_materializes_exactly_three_objects_restorable_in_baseline_mode() {
        let fixture = v70_rollback_fixture();
        let authoritative = v70_rollback_archive(&fixture);
        let (endpoint, objects, log, server) = v70_rollback_s3(authoritative.clone()).await;
        let store = v71_store(
            &endpoint,
            JournalWriterState::Eligible(fixture.head.clone()),
            JournalRole::Writer,
        );
        // The operator hook runs after a same-process v71-hot promotion, so
        // exercise that effective mode rather than only a cold v71 restart.
        let mut state = v70_rollback_state(Some(store), &fixture);
        state.persistence_format = PersistenceFormat::V71Hot;
        state.hot_v71_enabled.store(true, Ordering::Release);
        let called = Arc::new(AtomicU64::new(0));
        let package = materialize_v70_rollback(
            &state,
            "rollback/v70",
            v70_rollback_seal(fixture.v71.clone(), called.clone()),
        )
        .await
        .unwrap();
        assert_eq!(called.load(Ordering::SeqCst), 1);
        assert_eq!(package.prefix, "rollback/v70");
        assert_eq!(package.sequence, 4);
        let artifact_key = format!(
            "rollback/v70/artifacts/{:020}-{}.cbor",
            4, package.artifact_hash
        );
        let head_key = archive_head_key("rollback/v70", 4);

        // Exactly three create-only KMS/Object Lock PUTs under the fresh
        // prefix: the head artifact, its pointer, then the checkpoint.
        let stored = objects.lock().await.clone();
        assert_eq!(
            stored
                .iter()
                .filter(|(key, _)| key.starts_with("epoch/"))
                .map(|(key, bytes)| (key.clone(), bytes.clone()))
                .collect::<BTreeMap<_, _>>(),
            authoritative
        );
        let written = stored
            .keys()
            .filter(|key| key.starts_with("rollback/v70/"))
            .cloned()
            .collect::<Vec<_>>();
        let mut expected = vec![
            artifact_key.clone(),
            head_key.clone(),
            package.checkpoint_key.clone(),
        ];
        expected.sort();
        assert_eq!(written, expected);
        assert_eq!(stored.len(), authoritative.len() + 3);
        let puts = v70_rollback_puts(&log.lock().await);
        assert_eq!(puts.len(), 3);
        for (head, key) in puts
            .iter()
            .zip([&artifact_key, &head_key, &package.checkpoint_key])
        {
            v71_assert_create_only_put(head, key);
        }
        assert_eq!(stored[&head_key], package.artifact_hash.as_bytes());
        let checkpoint: layrs_direct_execution_v1::DirectCheckpoint =
            serde_cbor::from_slice(&stored[&package.checkpoint_key]).unwrap();
        let artifact: DirectStateArtifact = serde_cbor::from_slice(&stored[&artifact_key]).unwrap();
        assert_eq!(artifact, checkpoint.artifact);
        assert_eq!(artifact_hash(&artifact), package.artifact_hash);

        // The explicit baseline branch restores it through the retained
        // enclave's unchanged checkpoint rules and exact committed frontier.
        let fresh = v70_rollback_store_at(&endpoint, "rollback/v70");
        let frontier = v70_rollback_frontier(&package);
        let prepared = fresh
            .prepare_sparse_rollback_restore(&frontier)
            .await
            .unwrap();
        assert_eq!(prepared.keys, vec![artifact_key.clone()]);
        assert_eq!(
            prepared.checkpoint_keys,
            vec![package.checkpoint_key.clone()]
        );
        let baseline_state = v70_rollback_baseline_state(&fixture);
        let (adopted, enclave) = v70_rollback_enclave(fixture.epoch.clone(), frontier.clone());
        fresh
            .restore_sparse_rollback_with(&baseline_state, &frontier, enclave)
            .await
            .unwrap();
        let mut restored = adopted.lock().unwrap().take().unwrap();
        assert_eq!(restored.committed_sequence(), 4);
        assert_eq!(restored.committed_state_hash(), package.state_hash);
        assert_eq!(
            *baseline_state.committed_state_root.lock().await,
            Some(package.state_hash.clone())
        );
        assert_eq!(
            fresh
                .verified_receipt_records
                .lock()
                .await
                .as_ref()
                .unwrap(),
            &checkpoint.receipt_records
        );
        assert_eq!(
            *fresh.verified_artifact_hashes.lock().await,
            checkpoint.artifact_hashes
        );
        for (request, result) in &fixture.commands {
            assert_eq!(restored.execute(request.clone()).unwrap(), *result);
        }
        let mut conflicting = fixture.commands[3].0.clone();
        conflicting.action = DirectAction::AdmitIdentity {
            wallet_address: "0x5555555555555555555555555555555555555555".into(),
        };
        conflicting.request_hash = request_hash(&conflicting);
        assert!(restored.execute(conflicting).is_err());
        assert_eq!(restored.committed_sequence(), 4);
        let identity = &fixture.commands[3].0.identity_commitment;
        assert_eq!(
            restored.portfolio(identity).unwrap(),
            fixture.v71.portfolio(identity).unwrap()
        );

        // A used prefix is never reused, and nothing reaches the enclave.
        let before = log.lock().await.len();
        assert_eq!(
            materialize_v70_rollback(
                &state,
                "rollback/v70",
                v70_rollback_seal(fixture.v71.clone(), called.clone()),
            )
            .await,
            Err("v70 rollback prefix not fresh".into())
        );
        assert_eq!(called.load(Ordering::SeqCst), 1);
        assert!(v70_rollback_puts(&log.lock().await[before..]).is_empty());
        server.abort();
    }

    #[tokio::test]
    async fn v70_rollback_handoff_fences_post_capture_commit_until_v70_restore() {
        let mut fixture = v70_rollback_fixture();
        let (stale, _) = v70_rollback_package(&fixture).await;
        append_v71_rollback_successor(&mut fixture, 'e', '5');
        assert_eq!(stale.sequence + 1, fixture.head.sequence);

        let (endpoint, _, _, server) = v70_rollback_s3(v70_rollback_archive(&fixture)).await;
        let store = v71_store(
            &endpoint,
            JournalWriterState::Eligible(fixture.head.clone()),
            JournalRole::Writer,
        );
        let state = v70_rollback_state(Some(store), &fixture);
        let (package, handoff_guard) = prepare_v70_rollback_handoff(
            &state,
            "rollback",
            v70_rollback_seal(fixture.v71.clone(), Arc::new(AtomicU64::new(0))),
        )
        .await
        .unwrap();

        // Model a v71 command arriving after package publication. It cannot
        // enter the serialized commit path while the rollback handoff owns the
        // gate, so it cannot become an acknowledged successor omitted from the
        // retained-v70 frontier.
        let gate = Arc::clone(&state.financial_gate);
        let mut post_capture_commit = tokio::spawn(async move {
            let _guard = gate.lock("post_capture_v71_commit").await;
        });
        assert!(tokio::time::timeout(
            Duration::from_millis(50),
            &mut post_capture_commit,
        )
        .await
        .is_err());

        let frontier = v70_rollback_frontier(&package);
        let rollback = v70_rollback_store_at(&endpoint, "rollback");
        rollback
            .prepare_sparse_rollback_restore(&frontier)
            .await
            .unwrap();
        let (adopted, enclave) = v70_rollback_enclave(fixture.epoch.clone(), frontier);
        rollback
            .restore_sparse_rollback_with(
                &v70_rollback_baseline_state(&fixture),
                &v70_rollback_frontier(&package),
                enclave,
            )
            .await
            .unwrap();
        let mut restored = adopted.lock().unwrap().take().unwrap();
        assert_eq!(restored.committed_sequence(), fixture.v71.sequence());
        assert_eq!(restored.committed_state_hash(), package.state_hash);
        for (request, result) in &fixture.commands {
            assert_eq!(
                restored.portfolio(&request.identity_commitment).unwrap(),
                fixture
                    .v71
                    .portfolio(&request.identity_commitment)
                    .unwrap()
            );
            assert_eq!(restored.execute(request.clone()).unwrap(), *result);
        }

        // Only an explicit failed/abandoned handoff releases dispatch. The
        // production SIGUSR2 path intentionally never drops this guard.
        drop(handoff_guard);
        tokio::time::timeout(Duration::from_secs(1), post_capture_commit)
            .await
            .unwrap()
            .unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn v70_rollback_baseline_restores_contiguous_v70_successors() {
        let fixture = v70_rollback_fixture();
        let (package, mut objects) = v70_rollback_package(&fixture).await;
        let frontier = v70_rollback_frontier(&package);
        let checkpoint: layrs_direct_execution_v1::DirectCheckpoint =
            serde_cbor::from_slice(&objects[&package.checkpoint_key]).unwrap();
        // The rolled-back v70 writer commits sequence 5 as usual.
        let baseline = layrs_direct_execution_v1::DirectRuntime::new(
            fixture.epoch.clone(),
            layrs_direct_execution_v1::RuntimeMode::IsolatedTest,
            vec![9; 32],
        )
        .unwrap()
        .restore_checkpoint(&checkpoint, &[7; 32])
        .unwrap();
        let request = v70_rollback_admission('e', '5');
        let candidate = baseline
            .prepare_candidate(request.clone(), &[7; 32])
            .unwrap();
        let successor = candidate.artifact.clone();
        let successor_hash = artifact_hash(&successor);
        objects.insert(
            format!("rollback/artifacts/{:020}-{successor_hash}.cbor", 5),
            serde_cbor::to_vec(&successor).unwrap(),
        );
        objects.insert(
            archive_head_key("rollback", 5),
            successor_hash.clone().into_bytes(),
        );
        let (endpoint, _, _, server) = v70_rollback_s3(objects.clone()).await;
        let fresh = v70_rollback_store_at(&endpoint, "rollback");
        let prepared = fresh
            .prepare_sparse_rollback_restore(&frontier)
            .await
            .unwrap();
        assert_eq!(prepared.keys.len(), 2);
        let state = v70_rollback_baseline_state(&fixture);
        let (adopted, enclave) = v70_rollback_enclave(fixture.epoch.clone(), frontier.clone());
        fresh
            .restore_sparse_rollback_with(&state, &frontier, enclave)
            .await
            .unwrap();
        let mut restored = adopted.lock().unwrap().take().unwrap();
        assert_eq!(restored.committed_sequence(), 5);
        assert_eq!(restored.committed_state_hash(), successor.state_hash);
        assert_eq!(restored.execute(request).unwrap(), candidate.result);
        let records = fresh.verified_receipt_records.lock().await.clone().unwrap();
        assert_eq!(records.len(), 5);
        assert_eq!(records[4], receipt_only_record(&successor));
        assert_eq!(
            fresh.verified_artifact_hashes.lock().await[4],
            successor_hash
        );
        // The normal v70 restore still rejects the baseline-rooted archive.
        let mut v70_state = v70_rollback_state(None, &fixture);
        v70_state.persistence_format = PersistenceFormat::V70;
        assert_eq!(
            v70_rollback_store_at(&endpoint, "rollback")
                .prepare_restore(&v70_state)
                .await
                .err(),
            Some("archive head sequence gap".into())
        );
        server.abort();

        // A successor whose head points at another artifact, or a tampered
        // successor body, fails closed.
        let mut forked = objects.clone();
        forked.insert(archive_head_key("rollback", 5), "0".repeat(64).into_bytes());
        let (endpoint, _, _, server) = v70_rollback_s3(forked).await;
        assert_eq!(
            v70_rollback_store_at(&endpoint, "rollback")
                .prepare_sparse_rollback_restore(&frontier)
                .await
                .err(),
            Some("archive committed artifact missing".into())
        );
        server.abort();
        let mut tampered = objects;
        let mut body = successor.clone();
        body.prior_state_hash = "0".repeat(64);
        tampered.insert(
            format!("rollback/artifacts/{:020}-{successor_hash}.cbor", 5),
            serde_cbor::to_vec(&body).unwrap(),
        );
        let (endpoint, _, _, server) = v70_rollback_s3(tampered).await;
        let fresh = v70_rollback_store_at(&endpoint, "rollback");
        fresh
            .prepare_sparse_rollback_restore(&frontier)
            .await
            .unwrap();
        let (adopted, enclave) = v70_rollback_enclave(fixture.epoch.clone(), frontier.clone());
        assert_eq!(
            fresh
                .restore_sparse_rollback_with(
                    &v70_rollback_baseline_state(&fixture),
                    &frontier,
                    enclave
                )
                .await,
            Err("archive encrypted successor/head mismatch".into())
        );
        assert!(adopted.lock().unwrap().is_none());
        server.abort();
    }

    /// Runs the explicit baseline prepare and, if it passes, the restore.
    async fn v70_rollback_try_restore(
        fixture: &V70RollbackFixture,
        objects: BTreeMap<String, Vec<u8>>,
        frontier: &layrs_direct_execution_v1::CommittedRestoreFrontier,
    ) -> Result<u64, String> {
        let (endpoint, _, _, server) = v70_rollback_s3(objects).await;
        let fresh = v70_rollback_store_at(&endpoint, "rollback");
        let result = async {
            fresh.prepare_sparse_rollback_restore(frontier).await?;
            let (adopted, enclave) = v70_rollback_enclave(fixture.epoch.clone(), frontier.clone());
            fresh
                .restore_sparse_rollback_with(
                    &v70_rollback_baseline_state(fixture),
                    frontier,
                    enclave,
                )
                .await?;
            let sequence = adopted
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .committed_sequence();
            Ok(sequence)
        }
        .await;
        server.abort();
        result
    }

    #[tokio::test]
    async fn v70_rollback_baseline_rejects_mutated_missing_or_extra_objects() {
        let fixture = v70_rollback_fixture();
        let (package, objects) = v70_rollback_package(&fixture).await;
        let frontier = v70_rollback_frontier(&package);
        assert_eq!(objects.len(), 3);
        assert_eq!(
            v70_rollback_try_restore(&fixture, objects.clone(), &frontier).await,
            Ok(4)
        );
        let artifact_key = format!(
            "rollback/artifacts/{:020}-{}.cbor",
            4, package.artifact_hash
        );
        let head_key = archive_head_key("rollback", 4);
        let checkpoint_key = package.checkpoint_key.clone();
        let artifact: DirectStateArtifact =
            serde_cbor::from_slice(&objects[&artifact_key]).unwrap();
        let checkpoint: layrs_direct_execution_v1::DirectCheckpoint =
            serde_cbor::from_slice(&objects[&checkpoint_key]).unwrap();
        let mut mutated_artifact = artifact.clone();
        mutated_artifact.ciphertext[0] ^= 1;
        let mut mutated_checkpoint = checkpoint.clone();
        mutated_checkpoint.signature = "0".repeat(mutated_checkpoint.signature.len());
        let other_hash = sha256(b"other");
        let below_checkpoint = format!(
            "rollback/checkpoints/{:020}-{}-{}.cbor",
            3,
            package.state_hash,
            sha256(b"below")
        );
        let twin_checkpoint = format!(
            "rollback/checkpoints/{:020}-{}-{}.cbor",
            4,
            package.state_hash,
            sha256(b"twin")
        );

        type Edit = Box<dyn Fn(&mut BTreeMap<String, Vec<u8>>)>;
        let cases: Vec<(&str, Edit, &str)> = vec![
            // Mutation.
            (
                "head points elsewhere",
                Box::new({
                    let key = head_key.clone();
                    let hash = other_hash.clone();
                    move |objects| {
                        objects.insert(key.clone(), hash.clone().into_bytes());
                    }
                }),
                "sparse rollback baseline differs from governed frontier",
            ),
            (
                "head body malformed",
                Box::new({
                    let key = head_key.clone();
                    move |objects| {
                        objects.insert(key.clone(), b"not-a-hash".to_vec());
                    }
                }),
                "archive sequence head hash invalid",
            ),
            (
                "artifact body mutated",
                Box::new({
                    let key = artifact_key.clone();
                    let bytes = serde_cbor::to_vec(&mutated_artifact).unwrap();
                    move |objects| {
                        objects.insert(key.clone(), bytes.clone());
                    }
                }),
                "sparse rollback baseline artifact mismatch",
            ),
            (
                "checkpoint body mutated",
                Box::new({
                    let key = checkpoint_key.clone();
                    let bytes = serde_cbor::to_vec(&mutated_checkpoint).unwrap();
                    move |objects| {
                        objects.insert(key.clone(), bytes.clone());
                    }
                }),
                "checkpoint content address mismatch",
            ),
            (
                "checkpoint body corrupt",
                Box::new({
                    let key = checkpoint_key.clone();
                    move |objects| {
                        objects.insert(key.clone(), b"corrupt".to_vec());
                    }
                }),
                "checkpoint decode failed; genesis fallback forbidden",
            ),
            // Missing object.
            (
                "artifact missing",
                Box::new({
                    let key = artifact_key.clone();
                    move |objects| {
                        objects.remove(&key);
                    }
                }),
                "archive committed artifact missing",
            ),
            (
                "head missing",
                Box::new({
                    let key = head_key.clone();
                    move |objects| {
                        objects.remove(&key);
                    }
                }),
                "sparse rollback baseline head missing",
            ),
            (
                "checkpoint missing",
                Box::new({
                    let key = checkpoint_key.clone();
                    move |objects| {
                        objects.remove(&key);
                    }
                }),
                "sparse rollback baseline checkpoint missing or ambiguous",
            ),
            // Extra object.
            (
                "head below baseline",
                Box::new(|objects| {
                    objects.insert(archive_head_key("rollback", 3), "a".repeat(64).into_bytes());
                }),
                "sparse rollback head outside baseline lineage",
            ),
            (
                "legacy head twin",
                Box::new({
                    let hash = package.artifact_hash.clone();
                    move |objects| {
                        objects.insert(
                            format!("rollback/heads/{:020}-{hash}.cbor", 4),
                            b"legacy".to_vec(),
                        );
                    }
                }),
                "sparse rollback head outside baseline lineage",
            ),
            (
                "head above baseline without artifact",
                Box::new(|objects| {
                    objects.insert(archive_head_key("rollback", 5), "a".repeat(64).into_bytes());
                }),
                "archive committed artifact missing",
            ),
            (
                "artifact below baseline",
                Box::new(|objects| {
                    objects.insert(
                        format!("rollback/artifacts/{:020}-{}.cbor", 3, "a".repeat(64)),
                        b"below".to_vec(),
                    );
                }),
                "sparse rollback artifact outside baseline lineage",
            ),
            (
                "second baseline artifact",
                Box::new({
                    let hash = other_hash.clone();
                    move |objects| {
                        objects.insert(
                            format!("rollback/artifacts/{:020}-{hash}.cbor", 4),
                            b"twin".to_vec(),
                        );
                    }
                }),
                "sparse rollback artifact outside baseline lineage",
            ),
            (
                "unheaded artifact above baseline",
                Box::new(|objects| {
                    objects.insert(
                        format!("rollback/artifacts/{:020}-{}.cbor", 5, "a".repeat(64)),
                        b"unheaded".to_vec(),
                    );
                }),
                "sparse rollback artifact outside baseline lineage",
            ),
            (
                "foreign artifact key",
                Box::new(|objects| {
                    objects.insert("rollback/artifacts/foreign.cbor".into(), b"x".to_vec());
                }),
                "archive key format invalid",
            ),
            (
                "checkpoint below baseline",
                Box::new({
                    let key = below_checkpoint.clone();
                    move |objects| {
                        objects.insert(key.clone(), b"below".to_vec());
                    }
                }),
                "sparse rollback checkpoint outside baseline lineage",
            ),
            (
                "second baseline checkpoint",
                Box::new({
                    let key = twin_checkpoint.clone();
                    move |objects| {
                        objects.insert(key.clone(), b"twin".to_vec());
                    }
                }),
                "sparse rollback baseline checkpoint missing or ambiguous",
            ),
            (
                "malformed checkpoint key",
                Box::new(|objects| {
                    objects.insert("rollback/checkpoints/foreign.cbor".into(), b"x".to_vec());
                }),
                "sparse rollback checkpoint key invalid",
            ),
        ];
        for (name, edit, error) in cases {
            let mut edited = objects.clone();
            edit(&mut edited);
            assert_eq!(
                v70_rollback_try_restore(&fixture, edited, &frontier).await,
                Err(error.into()),
                "{name}"
            );
        }
    }

    #[tokio::test]
    async fn v70_rollback_baseline_requires_the_exact_governed_frontier() {
        let fixture = v70_rollback_fixture();
        let (package, objects) = v70_rollback_package(&fixture).await;
        let frontier = v70_rollback_frontier(&package);
        let with = |edit: &dyn Fn(&mut layrs_direct_execution_v1::CommittedRestoreFrontier)| {
            let mut frontier = frontier.clone();
            edit(&mut frontier);
            frontier
        };
        let cases = [
            (
                with(&|f| f.sequence = 3),
                "sparse rollback head outside baseline lineage",
            ),
            (
                with(&|f| f.sequence = 5),
                "sparse rollback head outside baseline lineage",
            ),
            (
                with(&|f| f.artifact_hash = sha256(b"other")),
                "sparse rollback baseline differs from governed frontier",
            ),
            (
                with(&|f| f.state_hash = sha256(b"other")),
                "sparse rollback baseline artifact mismatch",
            ),
            (
                with(&|f| f.sequence = 0),
                "governed checkpoint frontier invalid",
            ),
            (
                with(&|f| f.state_hash = "not-hex".into()),
                "governed checkpoint frontier invalid",
            ),
        ];
        for (wrong, error) in cases {
            assert_eq!(
                v70_rollback_try_restore(&fixture, objects.clone(), &wrong).await,
                Err(error.into()),
                "{wrong:?}"
            );
        }

        // Restore re-checks the checkpoint against the frontier it is given.
        let (endpoint, _, _, server) = v70_rollback_s3(objects.clone()).await;
        let fresh = v70_rollback_store_at(&endpoint, "rollback");
        fresh
            .prepare_sparse_rollback_restore(&frontier)
            .await
            .unwrap();
        let wrong = with(&|f| f.state_hash = sha256(b"other"));
        let (adopted, enclave) = v70_rollback_enclave(fixture.epoch.clone(), frontier.clone());
        assert_eq!(
            fresh
                .restore_sparse_rollback_with(
                    &v70_rollback_baseline_state(&fixture),
                    &wrong,
                    enclave
                )
                .await,
            Err("sparse checkpoint outside governed baseline".into())
        );
        assert!(adopted.lock().unwrap().is_none());
        // Restore never runs without a prepared baseline listing.
        let (_, enclave) = v70_rollback_enclave(fixture.epoch.clone(), frontier.clone());
        assert_eq!(
            fresh
                .restore_sparse_rollback_with(
                    &v70_rollback_baseline_state(&fixture),
                    &frontier,
                    enclave
                )
                .await,
            Err("archive restore was not validated before governed bootstrap".into())
        );
        server.abort();

        // The mode is explicit and requires the governed grant's frontier:
        // without it, neither preparation nor recovery reaches storage or
        // the enclave.
        assert_eq!(
            PersistenceFormat::parse(Some("v70-rollback-baseline")),
            Ok(PersistenceFormat::V70RollbackBaseline)
        );
        assert_eq!(PersistenceFormat::parse(None), Ok(PersistenceFormat::V70));
        let (endpoint, _, log, server) = v70_rollback_s3(objects).await;
        let mut state = v70_rollback_baseline_state(&fixture);
        state.artifact_store = Some(ArchiveStore::S3(v70_rollback_store_at(
            &endpoint, "rollback",
        )));
        assert_eq!(
            sparse_rollback_frontier(&state),
            Err("v70 rollback baseline requires the governed committed frontier".into())
        );
        assert_eq!(
            state
                .artifact_store
                .as_ref()
                .unwrap()
                .prepare_restore_before_grant(&state)
                .await,
            Err("v70 rollback baseline requires the governed committed frontier".into())
        );
        assert!(recover_enclave(&state)
            .await
            .unwrap_err()
            .to_string()
            .contains("requires the governed committed frontier"));
        assert!(log.lock().await.is_empty());
        server.abort();
        let directory = std::env::temp_dir().join(format!(
            "layrs-v70-rollback-baseline-{}",
            std::process::id()
        ));
        state.artifact_store = Some(ArchiveStore::Filesystem(
            FilesystemImmutableArtifactStore::new(directory),
        ));
        assert_eq!(
            state
                .artifact_store
                .as_ref()
                .unwrap()
                .prepare_restore_before_grant(&state)
                .await,
            Err("v70 rollback baseline requires the S3 archive".into())
        );
    }

    #[tokio::test]
    async fn v70_rollback_normal_v70_restore_rejects_the_sparse_archive() {
        let fixture = v70_rollback_fixture();
        let (_, objects) = v70_rollback_package(&fixture).await;
        let (endpoint, _, _, server) = v70_rollback_s3(objects).await;
        let fresh = v70_rollback_store_at(&endpoint, "rollback");
        for isolated_test in [true, false] {
            let mut state = v70_rollback_state(None, &fixture);
            state.persistence_format = PersistenceFormat::V70;
            state.isolated_test = isolated_test;
            assert_eq!(
                fresh.prepare_restore(&state).await.err(),
                Some("archive head sequence gap".into())
            );
            state.artifact_store = Some(ArchiveStore::S3(fresh.clone()));
            assert_eq!(
                state
                    .artifact_store
                    .as_ref()
                    .unwrap()
                    .prepare_restore_before_grant(&state)
                    .await,
                Err("archive head sequence gap".into())
            );
        }
        assert!(fresh.prepared_restore.lock().await.is_none());
        server.abort();
    }

    #[tokio::test]
    async fn v70_rollback_inputs_fail_closed_before_the_enclave_or_any_write() {
        let fixture = v70_rollback_fixture();
        let archive = v70_rollback_archive(&fixture);
        let record = |sequence| journal_record_key("epoch", sequence);
        let mut noncanonical = serde_cbor::to_vec(&fixture.records[0]).unwrap();
        noncanonical.push(0);
        let mut forked = fixture.records[1].clone();
        forked.previous_record_hash = "0".repeat(64);
        let mut other_bundle = fixture.bundle.clone();
        other_bundle.manifest.migration_id = "other-migration".into();
        let other_bundle_bytes = serde_cbor::to_vec(&other_bundle).unwrap();
        let mut stale_head = fixture.head.clone();
        stale_head.record_hash = "0".repeat(64);
        let mut unbounded_head = fixture.head.clone();
        unbounded_head.sequence = MAX_V70_LINEAGE_RECORDS as u64 + 1;

        type Edit = Box<dyn Fn(&mut BTreeMap<String, Vec<u8>>)>;
        let cases: Vec<(Edit, Option<V70MigrationBundle>, JournalHead, &str)> = vec![
            (
                Box::new(move |objects| {
                    objects.remove(&record(4));
                }),
                None,
                fixture.head.clone(),
                "v70 rollback journal incomplete",
            ),
            (
                Box::new(move |objects| {
                    objects.remove(&record(3));
                }),
                None,
                fixture.head.clone(),
                "journal tail sequence gap",
            ),
            (
                {
                    let bytes = serde_cbor::to_vec(&fixture.records[1]).unwrap();
                    Box::new(move |objects| {
                        objects.insert(record(5), bytes.clone());
                    })
                },
                None,
                fixture.head.clone(),
                "journal listing exceeds bound",
            ),
            (
                Box::new(move |objects| {
                    objects.insert(record(3), noncanonical.clone());
                }),
                None,
                fixture.head.clone(),
                "journal replay record decode failed",
            ),
            (
                {
                    let bytes = serde_cbor::to_vec(&forked).unwrap();
                    Box::new(move |objects| {
                        objects.insert(record(4), bytes.clone());
                    })
                },
                None,
                fixture.head.clone(),
                "v70 rollback record predecessor mismatch",
            ),
            (
                Box::new(move |objects| {
                    objects.insert(
                        journal_migration_key("epoch", 2, &other_bundle_bytes),
                        other_bundle_bytes.clone(),
                    );
                }),
                None,
                fixture.head.clone(),
                "journal migration bundle ambiguous",
            ),
            (
                Box::new(|_| {}),
                Some(other_bundle),
                fixture.head.clone(),
                "v70 rollback migration bundle differs from restored lineage",
            ),
            (
                Box::new(|_| {}),
                None,
                stale_head,
                "v70 rollback journal head mismatch",
            ),
            (
                Box::new(|_| {}),
                None,
                unbounded_head,
                "v70 rollback lineage outside bound",
            ),
        ];
        for (edit, restored, head, error) in cases {
            let mut objects = archive.clone();
            edit(&mut objects);
            let (endpoint, stored, log, server) = v70_rollback_s3(objects.clone()).await;
            let store = v71_store(
                &endpoint,
                JournalWriterState::Eligible(head),
                JournalRole::Writer,
            );
            let state = v70_rollback_state(Some(store), &fixture);
            if let Some(restored) = restored {
                *state.journal_migration.lock().await = Some(restored);
            }
            let called = Arc::new(AtomicU64::new(0));
            assert_eq!(
                materialize_v70_rollback(
                    &state,
                    "rollback",
                    v70_rollback_seal(fixture.v71.clone(), called.clone()),
                )
                .await,
                Err(error.into()),
                "{error}"
            );
            assert_eq!(called.load(Ordering::SeqCst), 0, "{error}");
            assert!(v70_rollback_puts(&log.lock().await).is_empty(), "{error}");
            assert_eq!(*stored.lock().await, objects, "{error}");
            server.abort();
        }
    }

    #[tokio::test]
    async fn v70_rollback_refuses_ineligible_overlapping_pending_or_rejected_state_without_writes()
    {
        let fixture = v70_rollback_fixture();
        let archive = v70_rollback_archive(&fixture);

        // Refused before any storage access.
        let (endpoint, _, log, server) = v70_rollback_s3(archive.clone()).await;
        let eligible = JournalWriterState::Eligible(fixture.head.clone());
        let cases = [
            (
                v70_rollback_state(
                    Some(v71_store(
                        &endpoint,
                        JournalWriterState::Unrestored,
                        JournalRole::Writer,
                    )),
                    &fixture,
                ),
                "rollback",
                "v70 rollback requires an eligible v71 head",
            ),
            (
                v70_rollback_state(
                    Some(v71_store(
                        &endpoint,
                        JournalWriterState::Latched("JOURNAL_WRITER_FENCED"),
                        JournalRole::Writer,
                    )),
                    &fixture,
                ),
                "rollback",
                "v70 rollback requires an eligible v71 head",
            ),
            (
                v70_rollback_state(
                    Some(v71_store(&endpoint, eligible.clone(), JournalRole::Shadow)),
                    &fixture,
                ),
                "rollback",
                "v70 rollback requires the authoritative S3 archive",
            ),
            (
                v70_rollback_state(None, &fixture),
                "rollback",
                "v70 rollback requires the authoritative S3 archive",
            ),
            (
                v70_rollback_state(
                    Some(v71_store(&endpoint, eligible.clone(), JournalRole::Writer)),
                    &fixture,
                ),
                "epoch",
                "v70 rollback prefix overlaps authoritative archive",
            ),
            (
                v70_rollback_state(
                    Some(v71_store(&endpoint, eligible.clone(), JournalRole::Writer)),
                    &fixture,
                ),
                "epoch/v70-rollback",
                "v70 rollback prefix overlaps authoritative archive",
            ),
            (
                v70_rollback_state(
                    Some(v71_store(&endpoint, eligible.clone(), JournalRole::Writer)),
                    &fixture,
                ),
                "../rollback",
                "v70 rollback prefix invalid",
            ),
        ];
        for (state, prefix, error) in cases {
            let called = Arc::new(AtomicU64::new(0));
            assert_eq!(
                materialize_v70_rollback(
                    &state,
                    prefix,
                    v70_rollback_seal(fixture.v71.clone(), called.clone()),
                )
                .await,
                Err(error.into()),
                "{error}"
            );
            assert_eq!(called.load(Ordering::SeqCst), 0);
        }
        for format in [
            PersistenceFormat::V70,
            PersistenceFormat::V70RollbackBaseline,
        ] {
            let mut state = v70_rollback_state(
                Some(v71_store(&endpoint, eligible.clone(), JournalRole::Writer)),
                &fixture,
            );
            state.persistence_format = format;
            assert_eq!(
                materialize_v70_rollback(
                    &state,
                    "rollback",
                    v70_rollback_seal(fixture.v71.clone(), Arc::new(AtomicU64::new(0))),
                )
                .await,
                Err("v70 rollback requires a restored v71 lineage".into())
            );
        }
        assert!(log.lock().await.is_empty());
        server.abort();

        // An unresolved external effect blocks the seal: it could not be
        // recovered from the fresh prefix.
        let (endpoint, _, log, server) = v70_rollback_s3(archive.clone()).await;
        let state = v70_rollback_state(
            Some(v71_store(&endpoint, eligible.clone(), JournalRole::Writer)),
            &fixture,
        );
        let intent = reconciled_intent(&fixture.head.transition_root);
        state
            .unresolved_external_effects
            .lock()
            .await
            .insert(intent.intent_hash.clone(), intent);
        let called = Arc::new(AtomicU64::new(0));
        assert_eq!(
            materialize_v70_rollback(
                &state,
                "rollback",
                v70_rollback_seal(fixture.v71.clone(), called.clone()),
            )
            .await,
            Err("v70 rollback external effect pending".into())
        );
        assert_eq!(called.load(Ordering::SeqCst), 0);
        assert!(v70_rollback_puts(&log.lock().await).is_empty());
        server.abort();

        // Enclave refusal, oversize, transport failure, or a foreign response
        // never writes the package.
        let responses: Vec<(io::Result<RuntimeResponse>, &str)> = vec![
            (
                Ok(RuntimeResponse::Error {
                    code: "V70_ROLLBACK_ARCHIVE_INVALID".into(),
                }),
                "v70 rollback seal rejected",
            ),
            (
                Ok(RuntimeResponse::Error {
                    code: CHECKPOINT_FRAME_OVERSIZED.into(),
                }),
                "v70 rollback frame oversized",
            ),
            (
                Err(io::Error::new(io::ErrorKind::InvalidData, FrameOversized)),
                "v70 rollback frame oversized",
            ),
            (
                Err(io::Error::new(io::ErrorKind::TimedOut, "ENCLAVE_TIMEOUT")),
                "v70 rollback seal transport failed",
            ),
            (
                Ok(RuntimeResponse::BootstrapComplete),
                "v70 rollback seal unexpected response",
            ),
        ];
        for (response, error) in responses {
            let (endpoint, _, log, server) = v70_rollback_s3(archive.clone()).await;
            let state = v70_rollback_state(
                Some(v71_store(&endpoint, eligible.clone(), JournalRole::Writer)),
                &fixture,
            );
            assert_eq!(
                materialize_v70_rollback(&state, "rollback", move |_| std::future::ready(response))
                    .await,
                Err(error.into()),
                "{error}"
            );
            assert!(v70_rollback_puts(&log.lock().await).is_empty(), "{error}");
            server.abort();
        }

        // A checkpoint for another head is rejected before any write.
        let (endpoint, _, log, server) = v70_rollback_s3(archive).await;
        let state = v70_rollback_state(
            Some(v71_store(&endpoint, eligible, JournalRole::Writer)),
            &fixture,
        );
        let mut foreign = v70_rollback_checkpoint(&fixture);
        foreign.receipt_records.pop();
        foreign.artifact_hashes.pop();
        assert_eq!(
            materialize_v70_rollback(&state, "rollback", move |_| std::future::ready(Ok(
                RuntimeResponse::CheckpointSealed {
                    checkpoint: foreign
                }
            )))
            .await,
            Err("v70 rollback checkpoint header invalid".into())
        );
        assert!(v70_rollback_puts(&log.lock().await).is_empty());
        server.abort();
    }

    #[tokio::test]
    async fn v70_rollback_interrupted_package_never_publishes_its_checkpoint() {
        let fixture = v70_rollback_fixture();
        let checkpoint = v70_rollback_checkpoint(&fixture);
        let receipts = ordered_journal_receipts(&fixture.receipts).unwrap();
        let (key, head, frontier) =
            validate_v70_rollback_checkpoint(&checkpoint, 4, &receipts, "rollback").unwrap();
        // A concurrent writer already holds the head slot with other bytes.
        let (endpoint, objects, log, server) = v70_rollback_s3(BTreeMap::from([(
            archive_head_key("rollback", 4),
            "0".repeat(64).into_bytes(),
        )]))
        .await;
        let target = v71_store(
            &endpoint,
            JournalWriterState::Unrestored,
            JournalRole::Writer,
        )
        .v70_rollback_target("rollback");
        assert_eq!(
            target
                .write_v70_rollback_package(&checkpoint, &key, &head)
                .await,
            Err("ARCHIVE_SEQUENCE_CONFLICT".into())
        );
        assert_eq!(v70_rollback_puts(&log.lock().await).len(), 2);
        assert!(!objects
            .lock()
            .await
            .keys()
            .any(|key| key.starts_with("rollback/checkpoints/")));
        // Neither restore branch accepts the partial package.
        assert!(v70_rollback_store_at(&endpoint, "rollback")
            .prepare_sparse_rollback_restore(&frontier)
            .await
            .is_err());
        let mut v70_state = v70_rollback_state(None, &fixture);
        v70_state.persistence_format = PersistenceFormat::V70;
        assert!(v70_rollback_store_at(&endpoint, "rollback")
            .prepare_restore(&v70_state)
            .await
            .is_err());
        // The rollback target can never accept a v71 journal append.
        assert_eq!(
            target.append_journal_record(&fixture.records[0]).await,
            Err("JOURNAL_LATCHED".into())
        );
        server.abort();

        // An extra object appearing under the prefix fails the exact listing.
        let (endpoint, objects, _, server) = v70_rollback_s3(BTreeMap::new()).await;
        objects
            .lock()
            .await
            .insert("rollback/stray.cbor".into(), b"stray".to_vec());
        let target = v71_store(
            &endpoint,
            JournalWriterState::Unrestored,
            JournalRole::Writer,
        )
        .v70_rollback_target("rollback");
        assert!(target
            .write_v70_rollback_package(&checkpoint, &key, &head)
            .await
            .is_err());
        server.abort();
    }
}
