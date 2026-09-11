//! The clean, single-request Layrs execution core.
//!
//! A command either returns one terminal, signed receipt or it has no effect.
//! The public database is deliberately a projection/receipt store: it is never
//! an input from which this private state is reconstructed.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const EPOCH_ID: &str = "layrs-opening-epoch-20260911-941107537728c98b";
pub const EPOCH_STATE_SHA256: &str =
    "84835da82210671d87321a21246317d898afd35381c57be8522df1a516dc3590";
pub const EVIDENCE_MANIFEST_SHA256: &str =
    "70e579f630c759258728d91cb957fa84e200674aeebd3eae5997430a62203957";
pub const TRANSACTION_MODEL: &str = "layrs.direct-execution.v1";
pub const PROJECTION_SCHEMA_VERSION: u32 = 1;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RuntimeError {
    #[error("opening epoch cannot be read")]
    Read,
    #[error("opening epoch hash mismatch")]
    EpochHash,
    #[error("opening epoch schema or safety controls mismatch")]
    EpochSchema,
    #[error("financial effects are disabled")]
    WriterDisabled,
    #[error("request id was reused with different content")]
    RequestReuse,
    #[error("invalid direct request")]
    InvalidRequest,
    #[error("caller is not bound to the requested identity")]
    IdentityDenied,
    #[error("withdrawal destination is not the caller's verified embedded wallet")]
    DestinationDenied,
    #[error("insufficient available balance")]
    InsufficientAvailable,
    #[error("unknown order")]
    UnknownOrder,
    #[error("authoritative state artifact is invalid")]
    StateArtifact,
    #[error("authoritative state persistence failed")]
    StatePersistence,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawEpoch {
    epoch_id: String,
    lineage: Lineage,
    architecture: serde_json::Value,
    identities: Vec<Identity>,
    privy_wallet_mappings: Vec<PrivyMapping>,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Lineage {
    #[serde(rename = "type")]
    lineage_type: String,
    genesis_ordinal: u64,
    predecessor_lineage_claim: Option<String>,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Identity {
    identity_commitment: String,
    auth_subject_hash: String,
    balances: Vec<Balance>,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Balance {
    asset: String,
    bucket: String,
    amount_atomic: String,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PrivyMapping {
    auth_subject_hash: String,
    identity_commitments: Vec<String>,
    embedded_evm: Vec<EmbeddedWallet>,
}
#[derive(Debug, Clone, Deserialize)]
struct EmbeddedWallet {
    address: String,
    #[serde(rename = "connectorType")]
    connector_type: String,
    #[serde(rename = "walletClientType")]
    wallet_client_type: String,
}

#[derive(Debug, Clone)]
pub struct SealedEpoch {
    identities: BTreeMap<String, BTreeMap<(String, String), u128>>,
    identity_subjects: BTreeMap<String, String>,
    subject_identities: BTreeMap<String, BTreeSet<String>>,
    subject_wallets: BTreeMap<String, BTreeSet<String>>,
}
impl SealedEpoch {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, RuntimeError> {
        let bytes = fs::read(path).map_err(|_| RuntimeError::Read)?;
        if sha256(&bytes) != EPOCH_STATE_SHA256 {
            return Err(RuntimeError::EpochHash);
        }
        let raw: RawEpoch =
            serde_json::from_slice(&bytes).map_err(|_| RuntimeError::EpochSchema)?;
        let valid = raw.epoch_id == EPOCH_ID
            && raw.lineage.lineage_type == "GOVERNED_FRESH_OPENING_STATE"
            && raw.lineage.genesis_ordinal == 0
            && raw.lineage.predecessor_lineage_claim.is_none()
            && raw
                .architecture
                .get("transactionModel")
                .and_then(serde_json::Value::as_str)
                == Some(TRANSACTION_MODEL);
        if !valid {
            return Err(RuntimeError::EpochSchema);
        }
        let mut subject_identities: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut identity_subjects = BTreeMap::new();
        let identities = raw
            .identities
            .into_iter()
            .map(|identity| {
                subject_identities
                    .entry(identity.auth_subject_hash.clone())
                    .or_default()
                    .insert(identity.identity_commitment.clone());
                identity_subjects.insert(
                    identity.identity_commitment.clone(),
                    identity.auth_subject_hash.clone(),
                );
                let balances = identity
                    .balances
                    .into_iter()
                    .map(|balance| {
                        let amount = balance
                            .amount_atomic
                            .parse()
                            .map_err(|_| RuntimeError::EpochSchema)?;
                        Ok(((balance.asset, balance.bucket), amount))
                    })
                    .collect::<Result<BTreeMap<_, _>, RuntimeError>>()?;
                Ok((identity.identity_commitment, balances))
            })
            .collect::<Result<BTreeMap<_, _>, RuntimeError>>()?;
        let mut subject_wallets = BTreeMap::new();
        for mapping in raw.privy_wallet_mappings {
            subject_identities
                .entry(mapping.auth_subject_hash.clone())
                .or_default()
                .extend(mapping.identity_commitments);
            let wallets = mapping
                .embedded_evm
                .into_iter()
                .filter(|wallet| {
                    wallet.connector_type == "embedded" && wallet.wallet_client_type == "privy"
                })
                .map(|wallet| wallet.address.to_ascii_lowercase())
                .collect::<BTreeSet<_>>();
            if !wallets.is_empty() {
                subject_wallets.insert(mapping.auth_subject_hash, wallets);
            }
        }
        Ok(Self {
            identities,
            identity_subjects,
            subject_identities,
            subject_wallets,
        })
    }
    pub fn load_with_evidence(
        epoch_path: impl AsRef<Path>,
        evidence_manifest_path: impl AsRef<Path>,
    ) -> Result<Self, RuntimeError> {
        let evidence = fs::read(evidence_manifest_path).map_err(|_| RuntimeError::Read)?;
        if sha256(&evidence) != EVIDENCE_MANIFEST_SHA256 {
            return Err(RuntimeError::EpochHash);
        }
        Self::load(epoch_path)
    }
    pub fn identity_count(&self) -> usize {
        self.identities.len()
    }
    /// Read-only opening data for the external accounting projection. It is
    /// never accepted as a source of enclave state.
    pub fn projection_rows(&self) -> Vec<ProjectionBalanceRow> {
        self.identities
            .iter()
            .flat_map(|(identity, balances)| {
                let subject = self
                    .identity_subjects
                    .get(identity)
                    .cloned()
                    .unwrap_or_default();
                balances
                    .iter()
                    .map(move |((asset, bucket), amount)| ProjectionBalanceRow {
                        auth_subject_hash: subject.clone(),
                        identity_commitment: identity.clone(),
                        asset: asset.clone(),
                        bucket: bucket.clone(),
                        amount_atomic: amount.to_string(),
                    })
            })
            .collect()
    }
    pub fn projection_wallet_rows(&self) -> Vec<ProjectionWalletRow> {
        self.subject_wallets
            .iter()
            .flat_map(|(subject, wallets)| {
                wallets.iter().map(move |wallet| ProjectionWalletRow {
                    auth_subject_hash: subject.clone(),
                    wallet_address: wallet.clone(),
                })
            })
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProjectionBalanceRow {
    pub auth_subject_hash: String,
    pub identity_commitment: String,
    pub asset: String,
    pub bucket: String,
    pub amount_atomic: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProjectionWalletRow {
    pub auth_subject_hash: String,
    pub wallet_address: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeMode {
    Dormant,
    IsolatedTest,
    ProductionEnabled,
}

/// A Step-6-only authorization.  This is a process-start gate, not a
/// financial transaction protocol: every customer command remains one direct,
/// terminal execution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeMeasurementBinding {
    pub ami_id: String,
    pub eif_sha256: String,
    pub pcr0: String,
    pub pcr1: String,
    pub pcr2: String,
    pub source_commit: String,
    pub enclave_sha256: String,
    pub parent_sha256: String,
}

impl RuntimeMeasurementBinding {
    pub fn valid(&self) -> bool {
        self.ami_id.starts_with("ami-")
            && self.source_commit.len() >= 7
            && [&self.eif_sha256, &self.enclave_sha256, &self.parent_sha256]
                .iter()
                .all(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
            && [&self.pcr0, &self.pcr1, &self.pcr2]
                .iter()
                .all(|value| value.len() == 96 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WriterGrant {
    pub activation_id: String,
    pub epoch_id: String,
    /// Binds a grant to direct execution rather than any legacy command
    /// runtime.
    pub runtime: String,
    /// Binds activation to the sealed opening epoch, not merely its label.
    pub opening_epoch_sha256: String,
    pub opening_evidence_manifest_sha256: String,
    pub runtime_measurement: RuntimeMeasurementBinding,
    pub old_writer_fence_evidence_sha256: String,
    pub expires_at_unix: u64,
    pub signature: String,
}

impl WriterGrant {
    pub fn verify(&self, governance_key: &[u8], now_unix: u64, binding: &RuntimeMeasurementBinding) -> bool {
        if self.activation_id.is_empty()
            || self.epoch_id != EPOCH_ID
            || self.runtime != TRANSACTION_MODEL
            || self.opening_epoch_sha256 != EPOCH_STATE_SHA256
            || self.opening_evidence_manifest_sha256 != EVIDENCE_MANIFEST_SHA256
            || !binding.valid()
            || &self.runtime_measurement != binding
            || self.old_writer_fence_evidence_sha256.len() != 64
            || self.expires_at_unix <= now_unix
        {
            return false;
        }
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        let Ok(bytes) = serde_json::to_vec(&unsigned) else {
            return false;
        };
        constant_time_eq(&sign(governance_key, &bytes), &self.signature)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DirectRequest {
    pub account_id: String,
    pub identity_commitment: String,
    pub request_id: String,
    pub request_hash: String,
    pub action: DirectAction,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DirectAction {
    CreditDeposit {
        amount_atomic: String,
        custody_reference: String,
    },
    PlaceOrder {
        order_id: String,
        market_id: String,
        reserve_atomic: String,
    },
    CancelOrder {
        order_id: String,
    },
    ReserveWithdrawal {
        destination: String,
        amount_atomic: String,
        custody_reference: String,
    },
    Transfer {
        recipient_identity_commitment: String,
        amount_atomic: String,
    },
}

/// Custody evidence is deliberately terminal-only at the direct execution
/// boundary. Observed and confirmed events may be projected for operations,
/// but cannot credit a customer or settle a withdrawal.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CustodyFinality {
    Observed,
    Confirmed,
    Final,
    Failed,
}

impl CustodyFinality {
    pub fn permits_settlement(self) -> bool {
        matches!(self, Self::Final)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TerminalStatus {
    Applied,
    RejectedEffectNone,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DirectReceipt {
    pub receipt_id: String,
    pub account_id: String,
    pub identity_commitment: String,
    pub request_id: String,
    pub request_hash: String,
    pub status: TerminalStatus,
    pub effect: String,
    pub amount_atomic: Option<String>,
    pub custody_reference: Option<String>,
    pub genesis_ordinal: u64,
    pub signature: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DirectResult {
    pub status: TerminalStatus,
    pub effect: String,
    pub genesis_ordinal: u64,
    pub receipt: DirectReceipt,
}

#[derive(Clone)]
pub struct DirectRuntime {
    balances: BTreeMap<String, BTreeMap<(String, String), u128>>,
    subject_identities: BTreeMap<String, BTreeSet<String>>,
    subject_wallets: BTreeMap<String, BTreeSet<String>>,
    orders: BTreeMap<String, (String, u128)>,
    requests: BTreeMap<(String, String), (String, DirectResult)>,
    receipt_key: Vec<u8>,
    mode: RuntimeMode,
}

/// The encrypted, write-once successor of the opening epoch.  It is the
/// authoritative recovery input; PostgreSQL is not included or consulted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DirectStateArtifact {
    pub epoch_id: String,
    pub sequence: u64,
    pub prior_state_hash: String,
    pub state_hash: String,
    pub request_hash: String,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub ciphertext_hash: String,
    pub receipt: DirectReceipt,
}

/// A parent may acknowledge a candidate only after the immutable artifact has
/// been read back byte-for-byte.  The acknowledgement is HMAC-bound to every
/// field that identifies the successor; it cannot be replayed for another
/// candidate, root, request, or epoch.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DurabilityAck {
    pub epoch_id: String,
    pub sequence: u64,
    pub prior_state_hash: String,
    pub state_hash: String,
    pub request_hash: String,
    pub artifact_hash: String,
    pub signature: String,
}
impl DurabilityAck {
    pub fn issue(artifact: &DirectStateArtifact, key: &[u8]) -> Self {
        let mut ack = Self {
            epoch_id: artifact.epoch_id.clone(),
            sequence: artifact.sequence,
            prior_state_hash: artifact.prior_state_hash.clone(),
            state_hash: artifact.state_hash.clone(),
            request_hash: artifact.request_hash.clone(),
            artifact_hash: artifact_hash(artifact),
            signature: String::new(),
        };
        ack.signature = sign(
            key,
            &serde_cbor::to_vec(&ack.unsigned()).expect("ack serializes"),
        );
        ack
    }
    pub fn verify_for(&self, artifact: &DirectStateArtifact, key: &[u8]) -> bool {
        key.len() >= 32
            && self.epoch_id == artifact.epoch_id
            && self.sequence == artifact.sequence
            && self.prior_state_hash == artifact.prior_state_hash
            && self.state_hash == artifact.state_hash
            && self.request_hash == artifact.request_hash
            && self.artifact_hash == artifact_hash(artifact)
            && constant_time_eq(
                &self.signature,
                &sign(
                    key,
                    &serde_cbor::to_vec(&self.unsigned()).expect("ack serializes"),
                ),
            )
    }
    fn unsigned(&self) -> Self {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        unsigned
    }
}

pub fn artifact_hash(artifact: &DirectStateArtifact) -> String {
    sha256(&serde_cbor::to_vec(artifact).expect("artifact serializes"))
}
pub struct DirectCandidate {
    runtime: DirectRuntime,
    pub artifact: DirectStateArtifact,
    pub result: DirectResult,
}

#[derive(Clone, Serialize, Deserialize)]
struct DirectState {
    balances: BTreeMap<String, BTreeMap<(String, String), u128>>,
    orders: BTreeMap<String, (String, u128)>,
    requests: BTreeMap<(String, String), (String, DirectResult)>,
}

/// Minimal immutable artifact boundary.  Production implements this with the
/// existing immutable-object archive; tests use this exact write-once contract.
pub trait DirectStateStore {
    fn put_if_absent(&mut self, artifact: &DirectStateArtifact) -> Result<(), RuntimeError>;
    fn artifacts(&self) -> Result<Vec<DirectStateArtifact>, RuntimeError>;
}

#[derive(Default)]
pub struct InMemoryDirectStateStore {
    artifacts: BTreeMap<String, DirectStateArtifact>,
}
impl InMemoryDirectStateStore {
    pub fn from_artifacts(artifacts: Vec<DirectStateArtifact>) -> Result<Self, RuntimeError> {
        let mut store = Self::default();
        for artifact in artifacts {
            store.put_if_absent(&artifact)?;
        }
        Ok(store)
    }
}
impl DirectStateStore for InMemoryDirectStateStore {
    fn put_if_absent(&mut self, artifact: &DirectStateArtifact) -> Result<(), RuntimeError> {
        match self.artifacts.get(&artifact.request_hash) {
            Some(existing) if existing == artifact => Ok(()),
            Some(_) => Err(RuntimeError::StatePersistence),
            None => {
                self.artifacts
                    .insert(artifact.request_hash.clone(), artifact.clone());
                Ok(())
            }
        }
    }
    fn artifacts(&self) -> Result<Vec<DirectStateArtifact>, RuntimeError> {
        Ok(self.artifacts.values().cloned().collect())
    }
}

/// The isolated implementation of the existing write-once encrypted artifact
/// boundary.  It deliberately stores opaque CBOR ciphertext and never derives
/// ledger state.  A production archive adapter must provide the same
/// create-if-absent plus readback contract.
#[derive(Debug, Clone)]
pub struct FilesystemImmutableArtifactStore {
    root: PathBuf,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct ArtifactRecoveryHead {
    epoch_id: String,
    sequence: u64,
    state_hash: String,
    artifact_hash: String,
}
impl FilesystemImmutableArtifactStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }
    fn path_for(&self, artifact: &DirectStateArtifact) -> PathBuf {
        self.root
            .join(format!("{}.artifact.cbor", artifact.request_hash))
    }
    fn head_path(&self) -> PathBuf {
        self.root.join("committed-head.cbor")
    }
    fn read_head(&self) -> Result<Option<ArtifactRecoveryHead>, RuntimeError> {
        let path = self.head_path();
        match fs::read(path) {
            Ok(bytes) => serde_cbor::from_slice(&bytes)
                .map(Some)
                .map_err(|_| RuntimeError::StatePersistence),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(RuntimeError::StatePersistence),
        }
    }
    fn persist_head(&self, head: &ArtifactRecoveryHead) -> Result<(), RuntimeError> {
        let tmp = self
            .root
            .join(format!(".committed-head-{}.tmp", std::process::id()));
        let bytes = serde_cbor::to_vec(head).map_err(|_| RuntimeError::StatePersistence)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(|_| RuntimeError::StatePersistence)?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| RuntimeError::StatePersistence)?;
        fs::rename(&tmp, self.head_path()).map_err(|_| RuntimeError::StatePersistence)?;
        fs::File::open(&self.root)
            .and_then(|dir| dir.sync_all())
            .map_err(|_| RuntimeError::StatePersistence)
    }
    fn advance_head(&self, artifact: &DirectStateArtifact) -> Result<(), RuntimeError> {
        let artifact_hash = artifact_hash(artifact);
        match self.read_head()? {
            Some(head)
                if head.epoch_id == artifact.epoch_id
                    && head.sequence == artifact.sequence
                    && head.state_hash == artifact.state_hash
                    && head.artifact_hash == artifact_hash =>
            {
                return Ok(())
            }
            Some(head)
                if artifact.sequence == head.sequence + 1
                    && artifact.prior_state_hash == head.state_hash => {}
            Some(_) => return Err(RuntimeError::StatePersistence),
            None if artifact.sequence == 1 => {}
            None => return Err(RuntimeError::StatePersistence),
        }
        self.persist_head(&ArtifactRecoveryHead {
            epoch_id: artifact.epoch_id.clone(),
            sequence: artifact.sequence,
            state_hash: artifact.state_hash.clone(),
            artifact_hash,
        })
    }
    pub fn persist_readback(
        &self,
        artifact: &DirectStateArtifact,
    ) -> Result<DirectStateArtifact, RuntimeError> {
        fs::create_dir_all(&self.root).map_err(|_| RuntimeError::StatePersistence)?;
        let path = self.path_for(artifact);
        let expected = serde_cbor::to_vec(artifact).map_err(|_| RuntimeError::StatePersistence)?;
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => {
                file.write_all(&expected)
                    .map_err(|_| RuntimeError::StatePersistence)?;
                file.sync_all()
                    .map_err(|_| RuntimeError::StatePersistence)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(RuntimeError::StatePersistence),
        }
        let actual = fs::read(&path).map_err(|_| RuntimeError::StatePersistence)?;
        if actual != expected {
            return Err(RuntimeError::StatePersistence);
        }
        let restored: DirectStateArtifact =
            serde_cbor::from_slice(&actual).map_err(|_| RuntimeError::StatePersistence)?;
        if &restored != artifact || artifact_hash(&restored) != artifact_hash(artifact) {
            return Err(RuntimeError::StatePersistence);
        }
        // The head is not state authority; it is a durable recovery floor.  It
        // prevents a deleted latest object from being mistaken for genesis.
        self.advance_head(&restored)?;
        Ok(restored)
    }
    /// Return the only recovery set acceptable to the enclave.  A corrupt,
    /// missing, forked, or untracked object is an error; callers must not fall
    /// back to opening state after this error.
    pub fn load_committed(&self) -> Result<Vec<DirectStateArtifact>, RuntimeError> {
        let head = self.read_head()?;
        let entries = match fs::read_dir(&self.root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && head.is_none() => {
                return Ok(Vec::new())
            }
            Err(_) => return Err(RuntimeError::StatePersistence),
        };
        let mut artifacts: Vec<DirectStateArtifact> = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|_| RuntimeError::StatePersistence)?;
            let name = entry.file_name();
            if !name.to_string_lossy().ends_with(".artifact.cbor") {
                continue;
            }
            let bytes = fs::read(entry.path()).map_err(|_| RuntimeError::StatePersistence)?;
            artifacts
                .push(serde_cbor::from_slice(&bytes).map_err(|_| RuntimeError::StatePersistence)?);
        }
        artifacts.sort_by_key(|artifact| artifact.sequence);
        match (head, artifacts.last()) {
            (None, None) => Ok(artifacts),
            (None, Some(_)) => Err(RuntimeError::StatePersistence),
            (Some(_), None) => Err(RuntimeError::StatePersistence),
            (Some(head), Some(last))
                if head.epoch_id == last.epoch_id
                    && head.sequence == last.sequence
                    && head.state_hash == last.state_hash
                    && head.artifact_hash == artifact_hash(last) =>
            {
                Ok(artifacts)
            }
            _ => Err(RuntimeError::StatePersistence),
        }
    }
    pub fn root(&self) -> &Path {
        &self.root
    }
}
impl DirectStateStore for FilesystemImmutableArtifactStore {
    fn put_if_absent(&mut self, artifact: &DirectStateArtifact) -> Result<(), RuntimeError> {
        self.persist_readback(artifact).map(|_| ())
    }
    fn artifacts(&self) -> Result<Vec<DirectStateArtifact>, RuntimeError> {
        self.load_committed()
    }
}
impl DirectRuntime {
    pub fn new(
        epoch: SealedEpoch,
        mode: RuntimeMode,
        receipt_key: Vec<u8>,
    ) -> Result<Self, RuntimeError> {
        if receipt_key.len() < 32 {
            return Err(RuntimeError::InvalidRequest);
        }
        Ok(Self {
            balances: epoch.identities,
            subject_identities: epoch.subject_identities,
            subject_wallets: epoch.subject_wallets,
            orders: BTreeMap::new(),
            requests: BTreeMap::new(),
            receipt_key,
            mode,
        })
    }
    pub fn execute(&mut self, request: DirectRequest) -> Result<DirectResult, RuntimeError> {
        if request.account_id.is_empty()
            || request.identity_commitment.is_empty()
            || request.request_id.is_empty()
            || request.request_hash != request_hash(&request)
        {
            return Err(RuntimeError::InvalidRequest);
        }
        let key = (request.account_id.clone(), request.request_id.clone());
        if let Some((prior_hash, result)) = self.requests.get(&key) {
            return if prior_hash == &request.request_hash {
                Ok(result.clone())
            } else {
                Err(RuntimeError::RequestReuse)
            };
        }
        if self.mode == RuntimeMode::Dormant {
            return Err(RuntimeError::WriterDisabled);
        }
        if !self.owns(&request.account_id, &request.identity_commitment) {
            return Err(RuntimeError::IdentityDenied);
        }
        let (effect, amount_atomic, custody_reference): (String, Option<String>, Option<String>) =
            match &request.action {
                DirectAction::CreditDeposit {
                    amount_atomic,
                    custody_reference,
                } => {
                    let value = amount(amount_atomic)?;
                    if custody_reference.is_empty() {
                        return Err(RuntimeError::InvalidRequest);
                    }
                    self.add(&request.identity_commitment, "USER_AVAILABLE", value)?;
                    (
                        "DEPOSIT_CREDITED".into(),
                        Some(amount_atomic.clone()),
                        Some(custody_reference.clone()),
                    )
                }
                DirectAction::PlaceOrder {
                    order_id,
                    market_id,
                    reserve_atomic,
                } => {
                    let value = amount(reserve_atomic)?;
                    if order_id.is_empty()
                        || market_id.is_empty()
                        || self.orders.contains_key(order_id)
                    {
                        return Err(RuntimeError::InvalidRequest);
                    }
                    self.move_bucket(
                        &request.identity_commitment,
                        "USER_AVAILABLE",
                        "USER_ORDER_HOLD",
                        value,
                    )?;
                    self.orders.insert(
                        order_id.clone(),
                        (request.identity_commitment.clone(), value),
                    );
                    ("ORDER_PLACED".into(), Some(reserve_atomic.clone()), None)
                }
                DirectAction::CancelOrder { order_id } => {
                    let (owner, value) = self
                        .orders
                        .remove(order_id)
                        .ok_or(RuntimeError::UnknownOrder)?;
                    if owner != request.identity_commitment {
                        self.orders.insert(order_id.clone(), (owner, value));
                        return Err(RuntimeError::IdentityDenied);
                    }
                    self.move_bucket(
                        &request.identity_commitment,
                        "USER_ORDER_HOLD",
                        "USER_AVAILABLE",
                        value,
                    )?;
                    ("ORDER_CANCELLED".into(), Some(value.to_string()), None)
                }
                DirectAction::ReserveWithdrawal {
                    destination,
                    amount_atomic,
                    custody_reference,
                } => {
                    let value = amount(amount_atomic)?;
                    let destination = destination.to_ascii_lowercase();
                    if custody_reference.is_empty()
                        || !self
                            .subject_wallets
                            .get(&request.account_id)
                            .is_some_and(|wallets| wallets.contains(&destination))
                    {
                        return Err(RuntimeError::DestinationDenied);
                    }
                    self.move_bucket(
                        &request.identity_commitment,
                        "USER_AVAILABLE",
                        "USER_WITHDRAWAL_HOLD",
                        value,
                    )?;
                    self.move_bucket(
                        &request.identity_commitment,
                        "USER_WITHDRAWAL_HOLD",
                        "USER_SETTLED",
                        value,
                    )?;
                    (
                        "WITHDRAWAL_SETTLED".into(),
                        Some(amount_atomic.clone()),
                        Some(custody_reference.clone()),
                    )
                }
                DirectAction::Transfer {
                    recipient_identity_commitment,
                    amount_atomic,
                } => {
                    let value = amount(amount_atomic)?;
                    if recipient_identity_commitment == &request.identity_commitment
                        || !self.balances.contains_key(recipient_identity_commitment)
                    {
                        return Err(RuntimeError::InvalidRequest);
                    }
                    self.move_bucket(
                        &request.identity_commitment,
                        "USER_AVAILABLE",
                        "USER_TRANSFER_HOLD",
                        value,
                    )?;
                    self.move_bucket(
                        &request.identity_commitment,
                        "USER_TRANSFER_HOLD",
                        "USER_SETTLED",
                        value,
                    )?;
                    self.add(recipient_identity_commitment, "USER_AVAILABLE", value)?;
                    ("TRANSFER_SETTLED".into(), Some(amount_atomic.clone()), None)
                }
            };
        let mut receipt = DirectReceipt {
            receipt_id: sha256(
                format!("{}:{}:{}", EPOCH_ID, request.account_id, request.request_id).as_bytes(),
            ),
            account_id: request.account_id.clone(),
            identity_commitment: request.identity_commitment.clone(),
            request_id: request.request_id.clone(),
            request_hash: request.request_hash.clone(),
            status: TerminalStatus::Applied,
            effect: effect.clone(),
            amount_atomic,
            custody_reference,
            genesis_ordinal: 0,
            signature: String::new(),
        };
        receipt.signature = receipt_signature(&self.receipt_key, &receipt);
        let result = DirectResult {
            status: TerminalStatus::Applied,
            effect,
            genesis_ordinal: 0,
            receipt,
        };
        self.requests
            .insert(key, (request.request_hash, result.clone()));
        Ok(result)
    }
    /// Returns an already-terminal result without creating a successor.  The
    /// VSOCK handler uses this before candidate creation so exact replay never
    /// creates another artifact.
    pub fn existing_result(
        &self,
        request: &DirectRequest,
    ) -> Result<Option<DirectResult>, RuntimeError> {
        let key = (request.account_id.clone(), request.request_id.clone());
        match self.requests.get(&key) {
            Some((prior_hash, result)) if prior_hash == &request.request_hash => {
                Ok(Some(result.clone()))
            }
            Some(_) => Err(RuntimeError::RequestReuse),
            None => Ok(None),
        }
    }
    /// Execute against a clone, durably publish its encrypted successor, then
    /// adopt it.  A failed write leaves `self` unchanged and returns no result.
    pub fn execute_committed<S: DirectStateStore>(
        &mut self,
        request: DirectRequest,
        state_key: &[u8],
        store: &mut S,
    ) -> Result<DirectResult, RuntimeError> {
        let key = (request.account_id.clone(), request.request_id.clone());
        if let Some((hash, result)) = self.requests.get(&key) {
            return if hash == &request.request_hash {
                Ok(result.clone())
            } else {
                Err(RuntimeError::RequestReuse)
            };
        }
        let candidate = self.prepare_candidate(request, state_key)?;
        store.put_if_absent(&candidate.artifact)?;
        if !candidate
            .runtime
            .verify_artifact(&candidate.artifact, state_key)?
        {
            return Err(RuntimeError::StateArtifact);
        }
        let result = candidate.result.clone();
        self.adopt_candidate(candidate, state_key)?;
        Ok(result)
    }
    pub fn prepare_candidate(
        &self,
        request: DirectRequest,
        state_key: &[u8],
    ) -> Result<DirectCandidate, RuntimeError> {
        let key = (request.account_id.clone(), request.request_id.clone());
        if let Some((hash, result)) = self.requests.get(&key) {
            return if hash == &request.request_hash {
                Ok(DirectCandidate {
                    runtime: self.clone(),
                    artifact: self.seal_artifact(
                        &self.state_hash(),
                        &request.request_hash,
                        state_key,
                        result.receipt.clone(),
                    )?,
                    result: result.clone(),
                })
            } else {
                Err(RuntimeError::RequestReuse)
            };
        }
        let prior = self.state_hash();
        let mut runtime = self.clone();
        let result = runtime.execute(request.clone())?;
        let artifact = runtime.seal_artifact(
            &prior,
            &request.request_hash,
            state_key,
            result.receipt.clone(),
        )?;
        if !runtime.verify_artifact(&artifact, state_key)? {
            return Err(RuntimeError::StateArtifact);
        }
        Ok(DirectCandidate {
            runtime,
            artifact,
            result,
        })
    }
    pub fn adopt_candidate(
        &mut self,
        candidate: DirectCandidate,
        state_key: &[u8],
    ) -> Result<(), RuntimeError> {
        if !candidate
            .runtime
            .verify_artifact(&candidate.artifact, state_key)?
        {
            return Err(RuntimeError::StateArtifact);
        }
        *self = candidate.runtime;
        Ok(())
    }
    pub fn restore_committed<S: DirectStateStore>(
        epoch: SealedEpoch,
        mode: RuntimeMode,
        receipt_key: Vec<u8>,
        state_key: &[u8],
        store: &S,
    ) -> Result<Self, RuntimeError> {
        let mut runtime = Self::new(epoch, mode, receipt_key)?;
        let mut prior = runtime.state_hash();
        let mut artifacts = store.artifacts()?;
        artifacts.sort_by_key(|a| a.sequence);
        let mut expected_sequence = 1u64;
        for artifact in artifacts {
            if artifact.sequence != expected_sequence
                || artifact.prior_state_hash != prior
                || !runtime.verify_artifact(&artifact, state_key)?
            {
                return Err(RuntimeError::StateArtifact);
            }
            runtime.apply_artifact(&artifact, state_key)?;
            if runtime.state_hash() != artifact.state_hash {
                return Err(RuntimeError::StateArtifact);
            }
            prior = runtime.state_hash();
            expected_sequence += 1;
        }
        Ok(runtime)
    }
    fn snapshot(&self) -> DirectState {
        DirectState {
            balances: self.balances.clone(),
            orders: self.orders.clone(),
            requests: self.requests.clone(),
        }
    }
    fn state_hash(&self) -> String {
        sha256(&serde_cbor::to_vec(&self.snapshot()).expect("state serializes"))
    }
    fn seal_artifact(
        &self,
        prior: &str,
        request_hash: &str,
        key: &[u8],
        receipt: DirectReceipt,
    ) -> Result<DirectStateArtifact, RuntimeError> {
        if key.len() != 32 {
            return Err(RuntimeError::StateArtifact);
        }
        let sequence = self.requests.len() as u64;
        let state_hash = self.state_hash();
        let seed = sha256(format!("{sequence}:{request_hash}:{state_hash}").as_bytes());
        let nonce = hex::decode(&seed[..24]).map_err(|_| RuntimeError::StateArtifact)?;
        let ciphertext = ChaCha20Poly1305::new(Key::from_slice(key))
            .encrypt(
                Nonce::from_slice(&nonce),
                serde_cbor::to_vec(&self.snapshot())
                    .map_err(|_| RuntimeError::StateArtifact)?
                    .as_ref(),
            )
            .map_err(|_| RuntimeError::StateArtifact)?;
        Ok(DirectStateArtifact {
            epoch_id: EPOCH_ID.into(),
            sequence,
            prior_state_hash: prior.into(),
            state_hash,
            request_hash: request_hash.into(),
            nonce,
            ciphertext_hash: sha256(&ciphertext),
            ciphertext,
            receipt,
        })
    }
    fn verify_artifact(&self, a: &DirectStateArtifact, key: &[u8]) -> Result<bool, RuntimeError> {
        if a.epoch_id != EPOCH_ID
            || a.nonce.len() != 12
            || a.ciphertext_hash != sha256(&a.ciphertext)
            || key.len() != 32
        {
            return Ok(false);
        }
        let plain = ChaCha20Poly1305::new(Key::from_slice(key))
            .decrypt(Nonce::from_slice(&a.nonce), a.ciphertext.as_ref())
            .map_err(|_| RuntimeError::StateArtifact)?;
        Ok(sha256(&plain) == a.state_hash && verify_receipt(&self.receipt_key, &a.receipt))
    }
    fn apply_artifact(&mut self, a: &DirectStateArtifact, key: &[u8]) -> Result<(), RuntimeError> {
        let plain = ChaCha20Poly1305::new(Key::from_slice(key))
            .decrypt(Nonce::from_slice(&a.nonce), a.ciphertext.as_ref())
            .map_err(|_| RuntimeError::StateArtifact)?;
        let state: DirectState =
            serde_cbor::from_slice(&plain).map_err(|_| RuntimeError::StateArtifact)?;
        self.balances = state.balances;
        self.orders = state.orders;
        self.requests = state.requests;
        Ok(())
    }
    fn add(&mut self, identity: &str, bucket: &str, value: u128) -> Result<(), RuntimeError> {
        let account = self
            .balances
            .get_mut(identity)
            .ok_or(RuntimeError::IdentityDenied)?;
        *account.entry(("USDC".into(), bucket.into())).or_default() += value;
        Ok(())
    }
    fn move_bucket(
        &mut self,
        identity: &str,
        from: &str,
        to: &str,
        value: u128,
    ) -> Result<(), RuntimeError> {
        let account = self
            .balances
            .get_mut(identity)
            .ok_or(RuntimeError::IdentityDenied)?;
        let available = account.entry(("USDC".into(), from.into())).or_default();
        if *available < value {
            return Err(RuntimeError::InsufficientAvailable);
        }
        *available -= value;
        *account.entry(("USDC".into(), to.into())).or_default() += value;
        Ok(())
    }
    pub fn balance(&self, identity: &str, asset: &str, bucket: &str) -> u128 {
        self.balances
            .get(identity)
            .and_then(|row| row.get(&(asset.into(), bucket.into())))
            .copied()
            .unwrap_or(0)
    }
    pub fn owns(&self, subject: &str, identity: &str) -> bool {
        self.subject_identities
            .get(subject)
            .is_some_and(|ids| ids.contains(identity))
    }
    pub fn writer_enabled(&self) -> bool {
        self.mode != RuntimeMode::Dormant
    }
    pub fn committed_state_hash(&self) -> String {
        self.state_hash()
    }
    pub fn committed_sequence(&self) -> u64 {
        self.requests.len() as u64
    }
}
fn amount(input: &str) -> Result<u128, RuntimeError> {
    let value = input
        .parse::<u128>()
        .map_err(|_| RuntimeError::InvalidRequest)?;
    if value == 0 {
        Err(RuntimeError::InvalidRequest)
    } else {
        Ok(value)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuntimeRequest {
    Attestation {
        nonce: Vec<u8>,
    },
    Status,
    /// Startup-only protected-key handoff for an explicitly isolated test
    /// runtime.  Nitro does not propagate the parent's systemd environment
    /// into an EIF, so test keys must cross the already-authenticated VSOCK
    /// boundary before recovery.  This is deliberately unavailable to a
    /// production-enabled runtime; production key release remains attestation
    /// governed and is not represented by this message.
    BootstrapIsolated {
        receipt_key: Vec<u8>,
        state_key: Vec<u8>,
        commit_ack_key: Vec<u8>,
    },
    Execute {
        request: DirectRequest,
    },
    /// The second, bounded frame of one direct request.  It is never stored as
    /// a workflow record: it merely proves that the parent read back the exact
    /// immutable candidate sent in the preceding frame.
    DurabilityAck {
        ack: DurabilityAck,
    },
    /// Startup-only handoff of immutable encrypted artifacts from the parent.
    /// The enclave reconstructs and verifies private state itself; PostgreSQL
    /// is never part of this input.
    RecoverCommitted {
        artifacts: Vec<DirectStateArtifact>,
    },
    Balance {
        account_id: String,
        identity_commitment: String,
        bucket: String,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuntimeResponse {
    Attestation {
        document: Vec<u8>,
        binding: RuntimeBinding,
    },
    Status {
        status: RuntimeStatus,
    },
    BootstrapComplete,
    Execute {
        result: DirectResult,
    },
    CommitCandidate {
        artifact: DirectStateArtifact,
    },
    RecoveryComplete {
        recovered_sequence: u64,
        recovered_state_hash: String,
    },
    Balance {
        amount_atomic: String,
    },
    Error {
        code: String,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeBinding {
    pub runtime: String,
    pub transaction_model: String,
    pub epoch_state_sha256: String,
    pub evidence_manifest_sha256: String,
    pub genesis_ordinal: u64,
    pub writer_enabled: bool,
    pub identity_count: usize,
    pub projection_schema_version: u32,
}
pub type RuntimeStatus = RuntimeBinding;
pub fn runtime_binding(identity_count: usize, writer_enabled: bool) -> RuntimeBinding {
    RuntimeBinding {
        runtime: "layrs.direct-execution.nitro.v1".into(),
        transaction_model: TRANSACTION_MODEL.into(),
        epoch_state_sha256: EPOCH_STATE_SHA256.into(),
        evidence_manifest_sha256: EVIDENCE_MANIFEST_SHA256.into(),
        genesis_ordinal: 0,
        writer_enabled,
        identity_count,
        projection_schema_version: PROJECTION_SCHEMA_VERSION,
    }
}
pub fn request_hash(request: &DirectRequest) -> String {
    sha256(
        &serde_json::to_vec(&(
            request.account_id.as_str(),
            request.identity_commitment.as_str(),
            request.request_id.as_str(),
            &request.action,
        ))
        .expect("serializable direct request"),
    )
}
pub fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
pub fn receipt_signature(key: &[u8], receipt: &DirectReceipt) -> String {
    let mut unsigned = receipt.clone();
    unsigned.signature.clear();
    sign(
        key,
        &serde_json::to_vec(&unsigned).expect("serializable receipt"),
    )
}
pub fn verify_receipt(key: &[u8], receipt: &DirectReceipt) -> bool {
    constant_time_eq(&receipt_signature(key, receipt), &receipt.signature)
}
pub fn sign(key: &[u8], bytes: &[u8]) -> String {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(key).expect("hmac accepts arbitrary key length");
    mac.update(bytes);
    hex::encode(mac.finalize().into_bytes())
}
fn constant_time_eq(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.as_bytes()
            .iter()
            .zip(b.as_bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

/// PostgreSQL is an auditable projection only.  It has no private balances and
/// cannot be used to restore the enclave state.
pub const POSTGRES_PROJECTION_DDL: &str =
    include_str!("../sql/001_direct_execution_projection.sql");

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    fn epoch_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../../.codex-review-bundles/unified-direct-execution-20260905/new-epoch-20260911/OPENING_EPOCH_STATE_20260911.json")
    }
    fn request(id: &str, action: DirectAction) -> DirectRequest {
        let mut r = DirectRequest {
            account_id: "88fff7d9668cf8b00cd7faa0680d05c6415221e6ab28c5be7fa71e047054d8fc".into(),
            identity_commitment: "0bafc03d08d4951d769d58284db85c7ac2ee3c79de87ec680f58edc03017c418"
                .into(),
            request_id: id.into(),
            request_hash: String::new(),
            action,
        };
        r.request_hash = request_hash(&r);
        r
    }
    fn runtime(mode: RuntimeMode) -> DirectRuntime {
        DirectRuntime::new(SealedEpoch::load(epoch_path()).unwrap(), mode, vec![7; 32]).unwrap()
    }
    #[test]
    fn loads_exact_sealed_epoch() {
        let epoch = SealedEpoch::load(epoch_path()).unwrap();
        assert_eq!(epoch.identity_count(), 438);
        assert_eq!(epoch.projection_rows().len(), 322);
        assert_eq!(epoch.projection_wallet_rows().len(), 414);
    }
    #[test]
    fn immediate_withdrawal_is_idempotent_and_bound_to_embedded_wallet() {
        let mut r = runtime(RuntimeMode::IsolatedTest);
        let q = request(
            "withdrawal-1",
            DirectAction::ReserveWithdrawal {
                destination: "0xCCB96357dEB4cbF0808208d55916774f0B51a908".into(),
                amount_atomic: "1000000".into(),
                custody_reference: "mock-base-tx-1".into(),
            },
        );
        let a = r.execute(q.clone()).unwrap();
        assert!(verify_receipt(&[7; 32], &a.receipt));
        assert_eq!(r.execute(q).unwrap(), a);
        assert_eq!(
            r.balance(
                "0bafc03d08d4951d769d58284db85c7ac2ee3c79de87ec680f58edc03017c418",
                "USDC",
                "USER_AVAILABLE"
            ),
            4000000
        );
        assert_eq!(
            r.balance(
                "0bafc03d08d4951d769d58284db85c7ac2ee3c79de87ec680f58edc03017c418",
                "USDC",
                "USER_SETTLED"
            ),
            1000000
        );
    }
    #[test]
    fn rejects_cross_account_and_wrong_destination_without_effect() {
        let mut r = runtime(RuntimeMode::IsolatedTest);
        let mut q = request(
            "denied",
            DirectAction::ReserveWithdrawal {
                destination: "0x0000000000000000000000000000000000000000".into(),
                amount_atomic: "1".into(),
                custody_reference: "mock".into(),
            },
        );
        assert_eq!(
            r.execute(q.clone()).unwrap_err(),
            RuntimeError::DestinationDenied
        );
        q.account_id = "bae54f222a79c2ea394fa5b087d6a843e4b82562d0f3dfa33b8149b4beea21b3".into();
        q.request_hash = request_hash(&q);
        assert_eq!(r.execute(q).unwrap_err(), RuntimeError::IdentityDenied);
    }
    #[test]
    fn dormant_has_no_effect() {
        let mut r = runtime(RuntimeMode::Dormant);
        assert_eq!(
            r.execute(request(
                "off",
                DirectAction::CreditDeposit {
                    amount_atomic: "1".into(),
                    custody_reference: "mock".into()
                }
            ))
            .unwrap_err(),
            RuntimeError::WriterDisabled
        );
    }
    #[test]
    fn p02_funded_legacy_identity_is_authorized() {
        let e = SealedEpoch::load(epoch_path()).unwrap();
        let r = DirectRuntime::new(e, RuntimeMode::IsolatedTest, vec![7; 32]).unwrap();
        assert!(r.owns(
            "bae54f222a79c2ea394fa5b087d6a843e4b82562d0f3dfa33b8149b4beea21b3",
            "9bf6b307e41f94a5f5ec4211d2ac9eb5e4f2743b25224573391d7e8903276481"
        ));
        assert_eq!(
            r.balance(
                "9bf6b307e41f94a5f5ec4211d2ac9eb5e4f2743b25224573391d7e8903276481",
                "USDC",
                "USER_AVAILABLE"
            ),
            5100000
        );
    }

    #[test]
    fn isolated_direct_path_covers_deposit_order_cancel_withdraw_and_restart() {
        let mut live_runtime = runtime(RuntimeMode::IsolatedTest);
        let identity = "0bafc03d08d4951d769d58284db85c7ac2ee3c79de87ec680f58edc03017c418";
        let start = live_runtime.balance(identity, "USDC", "USER_AVAILABLE");
        live_runtime
            .execute(request(
                "deposit-e2e",
                DirectAction::CreditDeposit {
                    amount_atomic: "9".into(),
                    custody_reference: "mock-deposit-finality-1".into(),
                },
            ))
            .unwrap();
        live_runtime
            .execute(request(
                "order-e2e",
                DirectAction::PlaceOrder {
                    order_id: "order-e2e-1".into(),
                    market_id: "isolated-market".into(),
                    reserve_atomic: "4".into(),
                },
            ))
            .unwrap();
        live_runtime
            .execute(request(
                "cancel-e2e",
                DirectAction::CancelOrder {
                    order_id: "order-e2e-1".into(),
                },
            ))
            .unwrap();
        live_runtime
            .execute(request(
                "withdraw-e2e",
                DirectAction::ReserveWithdrawal {
                    destination: "0xccb96357deb4cbf0808208d55916774f0b51a908".into(),
                    amount_atomic: "9".into(),
                    custody_reference: "mock-withdrawal-finality-1".into(),
                },
            ))
            .unwrap();
        assert_eq!(
            live_runtime.balance(identity, "USDC", "USER_AVAILABLE"),
            start
        );
        assert_eq!(live_runtime.balance(identity, "USDC", "USER_ORDER_HOLD"), 0);
        assert_eq!(live_runtime.balance(identity, "USDC", "USER_SETTLED"), 9);

        // A clean restart is always rooted in the immutable opening epoch; it
        // does not source private balances from a public projection.
        let restarted = runtime(RuntimeMode::Dormant);
        assert_eq!(restarted.balance(identity, "USDC", "USER_AVAILABLE"), start);
        assert_eq!(restarted.balance(identity, "USDC", "USER_SETTLED"), 0);
    }

    #[test]
    fn writer_grant_requires_matching_epoch_fence_signature_and_expiry() {
        let key = vec![1; 32];
        let binding = RuntimeMeasurementBinding {
            ami_id: "ami-0123456789abcdef0".into(),
            eif_sha256: "b".repeat(64),
            pcr0: "c".repeat(96), pcr1: "d".repeat(96), pcr2: "e".repeat(96),
            source_commit: "92e9918".into(), enclave_sha256: "f".repeat(64), parent_sha256: "a".repeat(64),
        };
        let mut grant = WriterGrant {
            activation_id: "step6-review-id".into(),
            epoch_id: EPOCH_ID.into(),
            runtime: TRANSACTION_MODEL.into(),
            opening_epoch_sha256: EPOCH_STATE_SHA256.into(),
            opening_evidence_manifest_sha256: EVIDENCE_MANIFEST_SHA256.into(),
            runtime_measurement: binding.clone(),
            old_writer_fence_evidence_sha256: "a".repeat(64),
            expires_at_unix: 200,
            signature: String::new(),
        };
        grant.signature = sign(&key, &serde_json::to_vec(&grant).unwrap());
        assert!(grant.verify(&key, 100, &binding));
        let mut forged = grant.clone();
        forged.signature = "0".repeat(64);
        assert!(!forged.verify(&key, 100, &binding));
        assert!(!grant.verify(&key, 200, &binding));
        grant.old_writer_fence_evidence_sha256 = "b".repeat(64);
        assert!(!grant.verify(&key, 100, &binding));
        grant.old_writer_fence_evidence_sha256 = "a".repeat(64);
        grant.runtime = "legacy.durable-command.v1".into();
        assert!(!grant.verify(&key, 100, &binding));
        grant.runtime = TRANSACTION_MODEL.into();
        grant.opening_epoch_sha256 = "b".repeat(64);
        assert!(!grant.verify(&key, 100, &binding));
        grant.opening_epoch_sha256 = EPOCH_STATE_SHA256.into();
        grant.epoch_id = "wrong-lineage".into();
        assert!(!grant.verify(&key, 100, &binding));
        grant.epoch_id = EPOCH_ID.into();
        grant.runtime_measurement.pcr0 = "0".repeat(96);
        assert!(!grant.verify(&key, 100, &binding));
    }

    #[test]
    fn only_final_custody_evidence_permits_settlement() {
        assert!(!CustodyFinality::Observed.permits_settlement());
        assert!(!CustodyFinality::Confirmed.permits_settlement());
        assert!(!CustodyFinality::Failed.permits_settlement());
        assert!(CustodyFinality::Final.permits_settlement());
    }
    #[test]
    fn committed_direct_execution_survives_restart_and_replays_once() {
        let identity = "0bafc03d08d4951d769d58284db85c7ac2ee3c79de87ec680f58edc03017c418";
        let state_key = vec![9; 32];
        let mut store = InMemoryDirectStateStore::default();
        let mut live = runtime(RuntimeMode::IsolatedTest);
        let command = request(
            "restart-safe-withdrawal",
            DirectAction::ReserveWithdrawal {
                destination: "0xccb96357deb4cbf0808208d55916774f0b51a908".into(),
                amount_atomic: "1000000".into(),
                custody_reference: "mock-finality-commit".into(),
            },
        );
        let receipt = live
            .execute_committed(command.clone(), &state_key, &mut store)
            .unwrap()
            .receipt;
        assert_eq!(live.balance(identity, "USDC", "USER_AVAILABLE"), 4000000);
        let mut restarted = DirectRuntime::restore_committed(
            SealedEpoch::load(epoch_path()).unwrap(),
            RuntimeMode::IsolatedTest,
            vec![7; 32],
            &state_key,
            &store,
        )
        .unwrap();
        assert_eq!(
            restarted.balance(identity, "USDC", "USER_AVAILABLE"),
            4000000
        );
        assert_eq!(
            restarted
                .execute_committed(command, &state_key, &mut store)
                .unwrap()
                .receipt,
            receipt
        );
        assert_eq!(store.artifacts().unwrap().len(), 1);
    }
}
