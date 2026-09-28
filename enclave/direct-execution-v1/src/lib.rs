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

use base64::{engine::general_purpose::STANDARD, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
pub use clob_service::private_core::{
    BookOrder, FeeProfileId, MarketConfig, MarketExecution, MatchType, OrderAction, OrderStatus,
    Outcome, PriceTimeBook, TimeInForce, PRICE_SCALE,
};
use hmac::{Hmac, Mac};
use p256::{
    ecdsa::{signature::Verifier, Signature, VerifyingKey},
    pkcs8::DecodePublicKey,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

pub mod direct_frame;
mod external_effect;
pub mod journal;
pub mod migration;
mod quest_receipts;
pub mod request_index;
pub mod request_index_snapshot;
pub mod receipt_snapshot;
pub mod v71;
pub mod v71_checkpoint;
pub use quest_receipts::{PublicQuestReceipt,QuestReceiptPayload,QuestReceiptKind,QuestReceiptWitness,QuestReceiptLookupPayload,quest_public_receipt_hash,QUEST_RECEIPT_PROTOCOL,
    quest_receipt_public_key,canonical_quest_receipt_payload,quest_receipt_attestation_commitment,verify_public_quest_receipt};
pub use external_effect::{
    reference_for, relay_reference_for, relay_result_hash, relay_reverted_result_hash,
    relay_terminal_result_hash, ExternalEffectIntent, ExternalEffectObservation,
    ExternalEffectRecovery, FilesystemImmutableIntentStore, ImmutableExternalEffectIntentStore,
    RelayWithdrawalBinding, EXTERNAL_EFFECT_INTENT_PROTOCOL_VERSION,
    MAX_PROVIDER_IDEMPOTENCY_WINDOW_SECONDS,
};

pub const EPOCH_ID: &str = "layrs-opening-epoch-20260911-941107537728c98b";
pub const EPOCH_STATE_SHA256: &str =
    "84835da82210671d87321a21246317d898afd35381c57be8522df1a516dc3590";
pub const EVIDENCE_MANIFEST_SHA256: &str =
    "70e579f630c759258728d91cb957fa84e200674aeebd3eae5997430a62203957";
pub const TRANSACTION_MODEL: &str = "layrs.direct-execution.v1";
pub const PROJECTION_SCHEMA_VERSION: u32 = 1;
/// v70 bridge bound for archived successors and compact checkpoint receipts.
/// The transport byte ceiling remains the tighter production bound; this
/// count guard prevents adversarial tiny-record expansion during decoding.
pub const MAX_V70_LINEAGE_RECORDS: usize = 250_000;
/// Domain separator for the browser-verifiable commitment carried in Nitro
/// attestation `user_data`.  The commitment is fixed-width so it remains well
/// below Nitro's 512-byte user-data limit even when governed runtime metadata
/// grows.
pub const DIRECT_RUNTIME_BINDING_DOMAIN: &[u8] = b"layrs.direct-runtime-binding.v1\0";
pub const IDENTITY_ADMISSION_DOMAIN: &str = "layrs.direct-identity-admission.v1\0";
pub const MARKET_REGISTRATION_DOMAIN: &str = "layrs.direct-market-registration.v1\0";
pub const MARKET_RESOLUTION_DOMAIN: &str = "layrs.direct-market-resolution.v1\0";
pub const BALANCE_RECOVERY_DOMAIN: &str = "layrs.direct-balance-recovery.v1\0";
/// Existing production recovery-evidence KMS signer.  This public key is
/// deliberately compiled into the measured enclave so the untrusted parent
/// cannot substitute governance verification material at activation time.
pub const GOVERNANCE_KEY_ID: &str = "alias/layrs/production/recovery-evidence-signing";
pub const GOVERNANCE_SIGNING_ALGORITHM: &str = "ECDSA_SHA_256";
const GOVERNANCE_PUBLIC_KEY_DER_BASE64: &str =
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEj+YWePc+NPoCGDc7OF6yw4rVY2VYN0Ty3K2Y/tndvv9YSEp3scEn24l8KwAlexmygo+jlBofIkiSr12Wk99iuQ==";

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
    #[error("identity or wallet is already admitted")]
    IdentityAlreadyAdmitted,
    #[error("external financial address is invalid or does not match the bound action")]
    DestinationDenied,
    #[error("custody reference has already been committed")]
    CustodyReferenceReuse,
    #[error("insufficient available balance")]
    InsufficientAvailable,
    #[error("an existing withdrawal is awaiting destination confirmation")]
    WithdrawalPending,
    #[error("unknown order")]
    UnknownOrder,
    #[error("unknown or invalid market")]
    InvalidMarket,
    #[error("invalid order or settlement")]
    InvalidOrder,
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
    pub fn projection_identity_rows(&self) -> Vec<ProjectionIdentityRow> {
        self.identity_subjects
            .iter()
            .map(
                |(identity_commitment, auth_subject_hash)| ProjectionIdentityRow {
                    auth_subject_hash: auth_subject_hash.clone(),
                    identity_commitment: identity_commitment.clone(),
                },
            )
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProjectionIdentityRow {
    pub auth_subject_hash: String,
    pub identity_commitment: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeMode {
    Dormant,
    /// Governed production mode that may append identity bindings but cannot
    /// execute a financial action.
    AdmissionOnly,
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
                .all(|value| {
                    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
            && [&self.pcr0, &self.pcr1, &self.pcr2].iter().all(|value| {
                value.len() == 96 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct KeyReleasePredecessor {
    pub activation_id: String,
    pub artifact_sha256: String,
    pub writer_grant_commitment: String,
}

impl KeyReleasePredecessor {
    fn valid(&self, current_activation_id: &str) -> bool {
        !self.activation_id.is_empty()
            && self.activation_id != current_activation_id
            && [&self.artifact_sha256, &self.writer_grant_commitment]
                .iter()
                .all(|value| {
                    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WriterGrant {
    pub activation_id: String,
    /// Signed deployment scope. A production grant cannot be replayed into an
    /// isolated or non-production runtime.
    pub environment: String,
    /// Exact capability released at startup. It is intentionally not a set of
    /// command permissions or a renewable lease.
    pub authorization_scope: String,
    pub epoch_id: String,
    /// Binds a grant to direct execution rather than any legacy command
    /// runtime.
    pub runtime: String,
    /// Binds activation to the sealed opening epoch, not merely its label.
    pub opening_epoch_sha256: String,
    pub opening_evidence_manifest_sha256: String,
    pub runtime_measurement: RuntimeMeasurementBinding,
    pub old_writer_fence_evidence_sha256: String,
    /// Existing KMS CMK that may release the enclave-only runtime root key.
    /// This is a reference, never key material.
    pub key_release_kms_key_id: String,
    /// A signed, exact pointer to the immutable prior key-release artifact.
    /// When present, KMS re-encrypts that same root key under this grant's
    /// context without exposing plaintext to the parent. This is runtime-key
    /// continuity, not a financial command or ledger state transition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_release_predecessor: Option<KeyReleasePredecessor>,
    /// Minimum immutable lineage pinned by the governed checkpoint cutover.
    /// Optional serialization preserves every predecessor grant's bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub committed_restore_frontier: Option<CommittedRestoreFrontier>,
    pub expires_at_unix: u64,
    /// KMS key alias and algorithm are signed fields, not deployment inputs.
    pub governance_key_id: String,
    pub signing_algorithm: String,
    /// Standard-base64 DER ECDSA P-256 signature returned by AWS KMS.
    pub signature: String,
}

impl WriterGrant {
    pub fn verify(&self, now_unix: u64, binding: &RuntimeMeasurementBinding) -> bool {
        let Some(bytes) = self.unsigned_bytes(now_unix, binding) else {
            return false;
        };
        let Ok(public_key_der) = STANDARD.decode(GOVERNANCE_PUBLIC_KEY_DER_BASE64) else {
            return false;
        };
        let Ok(verifying_key) = VerifyingKey::from_public_key_der(&public_key_der) else {
            return false;
        };
        self.verify_with_key(&verifying_key, &bytes)
    }

    fn unsigned_bytes(
        &self,
        now_unix: u64,
        binding: &RuntimeMeasurementBinding,
    ) -> Option<Vec<u8>> {
        if self.activation_id.is_empty()
            || self.environment != "production"
            || !matches!(
                self.authorization_scope.as_str(),
                "admission-enabled" | "production-enabled"
            )
            || self.epoch_id != EPOCH_ID
            || self.runtime != TRANSACTION_MODEL
            || self.opening_epoch_sha256 != EPOCH_STATE_SHA256
            || self.opening_evidence_manifest_sha256 != EVIDENCE_MANIFEST_SHA256
            || !binding.valid()
            || &self.runtime_measurement != binding
            || self.old_writer_fence_evidence_sha256.len() != 64
            || self.key_release_kms_key_id.is_empty()
            || self.key_release_kms_key_id.len() > 2_048
            || self
                .key_release_predecessor
                .as_ref()
                .is_some_and(|predecessor| !predecessor.valid(&self.activation_id))
            || self.committed_restore_frontier.as_ref().is_some_and(|frontier| !frontier.valid())
            || self.expires_at_unix <= now_unix
            || self.governance_key_id != GOVERNANCE_KEY_ID
            || self.signing_algorithm != GOVERNANCE_SIGNING_ALGORITHM
        {
            return None;
        }
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        serde_json::to_vec(&unsigned).ok()
    }

    /// Stable commitment used by the enclave bootstrap, KMS encryption
    /// context, and immutable key-release record. It includes the signature,
    /// so a different authorization can never reuse a prior release.
    pub fn commitment(&self) -> String {
        sha256(&serde_json::to_vec(self).unwrap_or_default())
    }

    fn verify_with_key(&self, verifying_key: &VerifyingKey, bytes: &[u8]) -> bool {
        let Ok(signature_der) = STANDARD.decode(&self.signature) else {
            return false;
        };
        let Ok(signature) = Signature::from_der(&signature_der) else {
            return false;
        };
        verifying_key.verify(&bytes, &signature).is_ok()
    }

    #[cfg(test)]
    fn verify_with_test_key(
        &self,
        now_unix: u64,
        binding: &RuntimeMeasurementBinding,
        verifying_key: &VerifyingKey,
    ) -> bool {
        self.unsigned_bytes(now_unix, binding)
            .is_some_and(|bytes| self.verify_with_key(verifying_key, &bytes))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CommittedRestoreFrontier {
    pub sequence: u64,
    pub state_hash: String,
    pub artifact_hash: String,
}
impl CommittedRestoreFrontier {
    pub fn valid(&self) -> bool {
        self.sequence > 0 && self.sequence <= MAX_V70_LINEAGE_RECORDS as u64
            && [&self.state_hash, &self.artifact_hash].iter().all(|hash| hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
    }
    pub fn accepts_checkpoint(&self, checkpoint: &DirectCheckpoint) -> bool {
        if !self.valid() || checkpoint.artifact.sequence < self.sequence { return false; }
        let index = self.sequence as usize - 1;
        checkpoint.receipt_records.get(index).is_some_and(|record| record.sequence == self.sequence && record.state_hash == self.state_hash)
            && checkpoint.artifact_hashes.get(index) == Some(&self.artifact_hash)
    }
}

/// Public, immutable metadata for the KMS-wrapped direct-runtime root key.
/// The plaintext key is returned only as KMS CiphertextForRecipient to the
/// attested enclave and is never present in this record or the parent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GovernedKeyReleaseArtifact {
    pub protocol: String,
    pub activation_id: String,
    pub writer_grant_commitment: String,
    pub runtime_measurement: RuntimeMeasurementBinding,
    pub kms_key_id: String,
    pub encryption_context: BTreeMap<String, String>,
    pub ciphertext_blob: Vec<u8>,
}

impl GovernedKeyReleaseArtifact {
    pub fn verify_for(
        &self,
        grant: &WriterGrant,
        binding: &RuntimeMeasurementBinding,
        kms_key_id: &str,
    ) -> bool {
        self.protocol == "layrs.direct-execution.key-release.v1"
            && self.activation_id == grant.activation_id
            && self.writer_grant_commitment == grant.commitment()
            && &self.runtime_measurement == binding
            && self.kms_key_id == kms_key_id
            && !self.ciphertext_blob.is_empty()
            && self.ciphertext_blob.len() <= 65_536
            && self
                .encryption_context
                .get("layrs-runtime")
                .map(String::as_str)
                == Some(TRANSACTION_MODEL)
            && self
                .encryption_context
                .get("layrs-epoch")
                .map(String::as_str)
                == Some(EPOCH_ID)
            && self
                .encryption_context
                .get("layrs-writer-grant")
                .map(String::as_str)
                == Some(self.writer_grant_commitment.as_str())
    }

    pub fn artifact_hash(&self) -> String {
        sha256(&serde_cbor::to_vec(self).unwrap_or_default())
    }

    pub fn verify_as_predecessor(
        &self,
        predecessor: &KeyReleasePredecessor,
        kms_key_id: &str,
    ) -> bool {
        predecessor.valid("")
            && self.protocol == "layrs.direct-execution.key-release.v1"
            && self.activation_id == predecessor.activation_id
            && self.writer_grant_commitment == predecessor.writer_grant_commitment
            && self.artifact_hash() == predecessor.artifact_sha256
            && self.runtime_measurement.valid()
            && self.kms_key_id == kms_key_id
            && !self.ciphertext_blob.is_empty()
            && self.ciphertext_blob.len() <= 65_536
            && self
                .encryption_context
                .get("layrs-runtime")
                .map(String::as_str)
                == Some(TRANSACTION_MODEL)
            && self
                .encryption_context
                .get("layrs-epoch")
                .map(String::as_str)
                == Some(EPOCH_ID)
            && self
                .encryption_context
                .get("layrs-writer-grant")
                .map(String::as_str)
                == Some(predecessor.writer_grant_commitment.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DirectRequest {
    pub account_id: String,
    pub identity_commitment: String,
    pub request_id: String,
    pub request_hash: String,
    /// For a direct Base withdrawal, this is the customer-provided destination
    /// copied from the independently signed session. It must equal the action
    /// destination already bound into `request_hash`; the authenticated Privy
    /// wallet never selects it. Other external-effect lanes retain their
    /// existing interpretation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub financial_wallet_address: Option<String>,
    pub action: DirectAction,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GovernedMarketRegistration {
    pub registration_id: String,
    pub epoch_id: String,
    pub runtime: String,
    pub market: MarketConfig,
    pub expires_at_unix: u64,
    pub governance_key_id: String,
    pub signing_algorithm: String,
    pub signature: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DirectResolutionOutcome {
    Up,
    Down,
    Push,
}

/// A terminal, governance-signed market outcome.  It is executed as one
/// synchronous direct request and persisted through the same immutable state
/// artifact as orders; it is not a queued or resumable lifecycle record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GovernedMarketResolution {
    pub resolution_id: String,
    pub epoch_id: String,
    pub runtime: String,
    pub market_id: String,
    pub outcome: DirectResolutionOutcome,
    pub evidence_sha256: String,
    pub resolved_at_millis: i64,
    pub expires_at_unix: u64,
    pub governance_key_id: String,
    pub signing_algorithm: String,
    pub signature: String,
}

impl GovernedMarketResolution {
    pub fn verify(&self, now_unix: u64) -> bool {
        if self.resolution_id.is_empty()
            || self.epoch_id != EPOCH_ID
            || self.runtime != TRANSACTION_MODEL
            || self.market_id.is_empty()
            || self.evidence_sha256.len() != 64
            || !self
                .evidence_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || self.resolved_at_millis <= 0
            || self.resolved_at_millis > now_unix.saturating_mul(1_000) as i64
            || self.expires_at_unix <= now_unix
            || self.governance_key_id != GOVERNANCE_KEY_ID
            || self.signing_algorithm != GOVERNANCE_SIGNING_ALGORITHM
        {
            return false;
        }
        let Ok(public_key_der) = STANDARD.decode(GOVERNANCE_PUBLIC_KEY_DER_BASE64) else {
            return false;
        };
        let Ok(verifying_key) = VerifyingKey::from_public_key_der(&public_key_der) else {
            return false;
        };
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        let Ok(payload) = serde_json::to_vec(&(MARKET_RESOLUTION_DOMAIN, unsigned)) else {
            return false;
        };
        let Ok(signature_der) = STANDARD.decode(&self.signature) else {
            return false;
        };
        let Ok(signature) = Signature::from_der(&signature_der) else {
            return false;
        };
        verifying_key.verify(&payload, &signature).is_ok()
    }
}

impl GovernedMarketRegistration {
    pub fn verify(&self, now_unix: u64) -> bool {
        if self.registration_id.is_empty()
            || self.epoch_id != EPOCH_ID
            || self.runtime != TRANSACTION_MODEL
            || self.expires_at_unix <= now_unix
            || self.governance_key_id != GOVERNANCE_KEY_ID
            || self.signing_algorithm != GOVERNANCE_SIGNING_ALGORITHM
            || validate_direct_market(&self.market, now_unix.saturating_mul(1_000) as i64).is_err()
        {
            return false;
        }
        let Ok(public_key_der) = STANDARD.decode(GOVERNANCE_PUBLIC_KEY_DER_BASE64) else {
            return false;
        };
        let Ok(verifying_key) = VerifyingKey::from_public_key_der(&public_key_der) else {
            return false;
        };
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        let Ok(payload) = serde_json::to_vec(&(MARKET_REGISTRATION_DOMAIN, unsigned)) else {
            return false;
        };
        let Ok(signature_der) = STANDARD.decode(&self.signature) else {
            return false;
        };
        let Ok(signature) = Signature::from_der(&signature_der) else {
            return false;
        };
        verifying_key.verify(&payload, &signature).is_ok()
    }
}

/// Exact, one-use governance authorization for correcting a proven customer
/// liability discrepancy. It is executed synchronously as one direct request;
/// it is neither an external-effect instruction nor a resumable command.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GovernedBalanceRecovery {
    pub recovery_id: String,
    pub epoch_id: String,
    pub runtime: String,
    pub account_id: String,
    pub identity_commitment: String,
    pub asset: String,
    pub bucket: String,
    pub amount_atomic: String,
    pub expected_balance_before_atomic: String,
    pub evidence_sha256: String,
    pub reason_code: String,
    pub expires_at_unix: u64,
    pub governance_key_id: String,
    pub signing_algorithm: String,
    pub signature: String,
}

impl GovernedBalanceRecovery {
    pub fn verify(&self, now_unix: u64) -> bool {
        if self.recovery_id.is_empty()
            || self.epoch_id != EPOCH_ID
            || self.runtime != TRANSACTION_MODEL
            || self.account_id.len() != 64
            || !self.account_id.bytes().all(|byte| byte.is_ascii_hexdigit())
            || self.identity_commitment.len() != 64
            || !self
                .identity_commitment
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || self.asset != "USDC"
            || self.bucket != "USER_AVAILABLE"
            || amount(&self.amount_atomic).is_err()
            || self.expected_balance_before_atomic.parse::<u128>().is_err()
            || self.evidence_sha256.len() != 64
            || !self
                .evidence_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || self.reason_code != "RESTORE_RETURNED_CANARY_PRINCIPAL"
            || self.expires_at_unix <= now_unix
            || self.governance_key_id != GOVERNANCE_KEY_ID
            || self.signing_algorithm != GOVERNANCE_SIGNING_ALGORITHM
        {
            return false;
        }
        let Ok(public_key_der) = STANDARD.decode(GOVERNANCE_PUBLIC_KEY_DER_BASE64) else {
            return false;
        };
        let Ok(verifying_key) = VerifyingKey::from_public_key_der(&public_key_der) else {
            return false;
        };
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        let Ok(payload) = serde_json::to_vec(&(BALANCE_RECOVERY_DOMAIN, unsigned)) else {
            return false;
        };
        let Ok(signature_der) = STANDARD.decode(&self.signature) else {
            return false;
        };
        let Ok(signature) = Signature::from_der(&signature_der) else {
            return false;
        };
        verifying_key.verify(&payload, &signature).is_ok()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DirectAction {
    /// A post-genesis identity binding. The zero-balance transition is part of
    /// the same encrypted lineage as every later financial request; the
    /// historical opening epoch remains byte-for-byte immutable.
    AdmitIdentity {
        wallet_address: String,
    },
    RegisterMarket {
        registration: GovernedMarketRegistration,
        now_unix: u64,
    },
    ResolveMarket {
        resolution: GovernedMarketResolution,
        now_unix: u64,
    },
    GovernedBalanceRecovery {
        recovery: GovernedBalanceRecovery,
        now_unix: u64,
    },
    CreditDeposit {
        amount_atomic: String,
        custody_reference: String,
    },
    CreditZenDeposit { amount_atomic: String, custody_reference: String },
    /// Parent constructs this only after independently observing the user's
    /// individual Horizen USDC.e pool deposit at canonical finality.
    CreditHorizenUsdcDeposit { amount_atomic: String, custody_reference: String },
    /// Parent verifies the participant's canonical normal Bus boarding first.
    CreditArbitrumUsdcBusDeposit { operation_id:String, amount_atomic:String, custody_reference:String },
    /// Parent proves that same Bus ticket arrived and the participant deposited
    /// its principal into the settlement pool. This never adds balance again.
    FinalizeArbitrumUsdcBusDeposit { operation_id:String, amount_atomic:String, boarding_reference:String, custody_reference:String },
    /// Add a newly verified participant wallet to the same canonical identity.
    /// Historical wallet references and every financial bucket remain intact.
    LinkFinancialWallet { wallet_address: String },
    /// Commit a per-user hold before custody movement. A Bus wait must not
    /// become the legacy global unresolved-external-effect writer fence.
    BeginUsdcBusWithdrawal { withdrawal_id: String, destination_chain:String, asset:String, destination: String, amount_atomic: String },
    /// Internal, parent-verified terminal proof; never a public customer action.
    SettleUsdcBusWithdrawal { withdrawal_id: String, destination_chain:String, asset:String, destination: String, amount_atomic: String, custody_reference: String },
    /// Release only on an independently verified reverted pool transaction.
    RevertUsdcBusWithdrawal { withdrawal_id: String, destination_chain:String, asset:String, destination: String, amount_atomic: String, custody_reference: String },
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
    /// Releases existing complete-set collateral to its owner. This is a
    /// balanced claim redemption, without a trade, fee or external inflow.
    RedeemCompleteSet {
        market_id: String,
        quantity_micros: String,
    },
    ReserveWithdrawal {
        destination: String,
        amount_atomic: String,
        custody_reference: String,
    },
    ReserveZenWithdrawal { destination_chain: String, destination: String, amount_atomic: String, custody_reference: String },
    RecordZenWithdrawalReverted { destination_chain: String, destination: String, amount_atomic: String, custody_reference: String },
    /// Cross-chain withdrawal whose Base transfer is only Relay intake.  This
    /// action is constructed exclusively after Relay reports a destination
    /// success bound to the immutable route and exact result hashes.
    SettleRelayWithdrawal {
        relay: RelayWithdrawalBinding,
        amount_atomic: String,
        custody_reference: String,
    },
    /// A terminal external revert is recorded once in the same immutable
    /// lineage, with no balance movement.  It is not a retriable custody job.
    RecordWithdrawalReverted {
        destination: String,
        amount_atomic: String,
        custody_reference: String,
    },
    RecordRelayWithdrawalReverted {
        relay: RelayWithdrawalBinding,
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
    pub execution: Option<OrderExecution>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution: Option<DirectResolutionExecution>,
    /// Exact post-request balance rows for every identity touched by the
    /// request. These signed rows feed PostgreSQL's disposable read model;
    /// recovery continues to use only the encrypted state artifact.
    pub projection_balance_updates: Vec<ProjectionBalanceUpdate>,
    pub genesis_ordinal: u64,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProjectionBalanceUpdate {
    pub auth_subject_hash: String,
    pub identity_commitment: String,
    pub asset: String,
    pub bucket: String,
    pub amount_atomic: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DirectResult {
    pub status: TerminalStatus,
    pub effect: String,
    pub genesis_ordinal: u64,
    pub receipt: DirectReceipt,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TradeExecution {
    pub trade_id: String,
    pub maker_order_id: String,
    pub taker_order_id: String,
    pub market_id: String,
    pub outcome: Outcome,
    pub match_type: MatchType,
    pub executed_quantity_micros: String,
    pub execution_price_micros: u64,
    pub fee_atomic: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OrderExecution {
    pub order_id: String,
    pub market_id: String,
    pub outcome: Outcome,
    pub action: OrderAction,
    pub limit_price_micros: u64,
    pub quantity_micros: String,
    pub status: OrderStatus,
    pub executed_quantity_micros: String,
    pub remaining_quantity_micros: String,
    pub total_fee_atomic: String,
    pub resulting_position_micros: String,
    pub resulting_available_atomic: String,
    pub trades: Vec<TradeExecution>,
}

/// Authenticated private trading state returned directly by the enclave.  It
/// is a read-only view of the recovered authoritative state; PostgreSQL is not
/// consulted and producing it creates no request, receipt, or artifact.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DirectPortfolio {
    pub identity_commitment: String,
    pub balances: Vec<DirectPortfolioBalance>,
    pub positions: Vec<DirectPortfolioPosition>,
    pub open_orders: Vec<DirectPortfolioOrder>,
    pub registered_market_ids: Vec<String>,
    pub genesis_ordinal: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DirectPortfolioBalance {
    pub asset: String,
    pub bucket: String,
    pub amount_atomic: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DirectPortfolioPosition {
    pub market_id: String,
    pub outcome: Outcome,
    pub available_quantity_micros: String,
    pub total_quantity_micros: String,
    pub cost_basis_atomic: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DirectPortfolioOrder {
    pub order_id: String,
    pub market_id: String,
    pub outcome: Outcome,
    pub action: OrderAction,
    pub price_micros: u64,
    pub quantity_micros: String,
    pub filled_quantity_micros: String,
    pub remaining_quantity_micros: String,
    pub time_in_force: TimeInForce,
    pub expires_at_millis: Option<i64>,
    pub status: OrderStatus,
    pub hold_atomic: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DirectResolutionExecution {
    pub resolution_id: String,
    pub market_id: String,
    pub outcome: DirectResolutionOutcome,
    pub evidence_sha256: String,
    pub cancelled_order_count: usize,
    pub settled_position_count: usize,
    pub gross_payout_atomic: String,
    pub rounding_reserve_atomic: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct DirectMarketResolutionRecord {
    outcome: DirectResolutionOutcome,
    evidence_sha256: String,
    resolved_at_millis: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DirectMarketStatus {
    pub market: MarketConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution_outcome: Option<DirectResolutionOutcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution_evidence_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_at_millis: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct OrderReservation {
    order: BookOrder,
    hold_atomic: u128,
}

#[derive(Clone)]
pub struct DirectRuntime {
    opening_state_hash: String,
    balances: BTreeMap<String, BTreeMap<(String, String), u128>>,
    subject_identities: BTreeMap<String, BTreeSet<String>>,
    subject_wallets: BTreeMap<String, BTreeSet<String>>,
    markets: BTreeMap<String, MarketConfig>,
    books: BTreeMap<String, PriceTimeBook>,
    orders: BTreeMap<String, OrderReservation>,
    positions: BTreeMap<(String, String, Outcome), u128>,
    position_holds: BTreeMap<String, u128>,
    position_cost_basis: BTreeMap<(String, String, Outcome), u128>,
    market_collateral: BTreeMap<String, u128>,
    resolved_markets: BTreeMap<String, DirectMarketResolutionRecord>,
    fee_revenue_atomic: u128,
    zen_fee_revenue_atomic: u128,
    zen_rounding_reserve_atomic: u128,
    rounding_reserve_atomic: u128,
    /// Finalized external inflows are consumed exactly once across every
    /// account and request id. The reference is derived from the Base
    /// transaction hash after the parent has independently verified the
    /// transfer and finality.
    credited_custody_references: BTreeSet<String>,
    usdc_bus_withdrawals: BTreeMap<String, UsdcBusHold>,
    conditional_usdc_deposits: BTreeMap<String, ConditionalUsdcDeposit>,
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

/// Recovery acceleration only: the original immutable artifacts remain the
/// financial authority. Issued only from an already-adopted, verified head.
/// The MAC binds the encrypted snapshot AND the complete compact receipt
/// lineage, including metadata used by historical payout reconciliation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectCheckpoint {
    pub protocol: String,
    pub opening_state_hash: String,
    pub artifact: DirectStateArtifact,
    pub receipt_records: Vec<DirectStateArtifact>,
    pub artifact_hashes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap_certificate: Option<CheckpointBootstrapCertificate>,
    pub signature: String,
}

/// One-time bridge from the already-verified predecessor enclave, which has
/// no checkpoint endpoint. Uses the EXISTING measured governance public key;
/// neither a parent-supplied key nor a database snapshot can authorize it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CheckpointBootstrapCertificate {
    pub protocol: String,
    pub epoch_id: String,
    pub opening_state_hash: String,
    pub sequence: u64,
    pub state_hash: String,
    pub artifact_hash: String,
    pub receipt_records_hash: String,
    pub artifact_hashes_hash: String,
    pub governance_key_id: String,
    pub signing_algorithm: String,
    pub signature: String,
}

impl CheckpointBootstrapCertificate {
    pub fn for_checkpoint(checkpoint: &DirectCheckpoint) -> Result<Self, RuntimeError> {
        Ok(Self {
            protocol: "layrs.direct-execution.checkpoint-bootstrap.v1".into(),
            epoch_id: EPOCH_ID.into(), opening_state_hash: checkpoint.opening_state_hash.clone(),
            sequence: checkpoint.artifact.sequence, state_hash: checkpoint.artifact.state_hash.clone(),
            artifact_hash: artifact_hash(&checkpoint.artifact),
            receipt_records_hash: sha256(&serde_cbor::to_vec(&checkpoint.receipt_records).map_err(|_| RuntimeError::StateArtifact)?),
            artifact_hashes_hash: sha256(&serde_cbor::to_vec(&checkpoint.artifact_hashes).map_err(|_| RuntimeError::StateArtifact)?),
            governance_key_id: GOVERNANCE_KEY_ID.into(), signing_algorithm: GOVERNANCE_SIGNING_ALGORITHM.into(),
            signature: String::new(),
        })
    }
    pub fn unsigned_bytes(&self) -> Result<Vec<u8>, RuntimeError> {
        let mut unsigned = self.clone(); unsigned.signature.clear();
        serde_json::to_vec(&unsigned).map_err(|_| RuntimeError::StateArtifact)
    }
    fn verify_with_key(&self, checkpoint: &DirectCheckpoint, key: &VerifyingKey) -> bool {
        let Ok(expected) = Self::for_checkpoint(checkpoint) else { return false; };
        let mut unsigned = self.clone(); unsigned.signature.clear();
        if unsigned != expected { return false; }
        let Ok(der) = STANDARD.decode(&self.signature) else { return false; };
        let Ok(signature) = Signature::from_der(&der) else { return false; };
        self.unsigned_bytes().is_ok_and(|bytes| key.verify(&bytes, &signature).is_ok())
    }
    pub fn verify(&self, checkpoint: &DirectCheckpoint) -> bool {
        let Ok(der) = STANDARD.decode(GOVERNANCE_PUBLIC_KEY_DER_BASE64) else { return false; };
        let Ok(key) = VerifyingKey::from_public_key_der(&der) else { return false; };
        self.verify_with_key(checkpoint, &key)
    }
}

impl DirectCheckpoint {
    fn signature_bytes(&self) -> Result<Vec<u8>, RuntimeError> {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        serde_cbor::to_vec(&unsigned).map_err(|_| RuntimeError::StateArtifact)
    }
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
struct UsdcBusHold {
    account_id: String,
    identity_commitment: String,
    destination: String,
    destination_chain:String,
    asset:String,
    amount_atomic: String,
}
#[derive(Clone, Serialize, Deserialize)]
struct ConditionalUsdcDeposit {
    account_id:String,
    identity_commitment:String,
    wallet_address:String,
    amount_atomic:String,
    boarding_reference:String,
}

#[derive(Clone, Serialize, Deserialize)]
struct DirectState {
    balances: BTreeMap<String, BTreeMap<(String, String), u128>>,
    subject_identities: BTreeMap<String, BTreeSet<String>>,
    subject_wallets: BTreeMap<String, BTreeSet<String>>,
    markets: BTreeMap<String, MarketConfig>,
    books: BTreeMap<String, PriceTimeBook>,
    orders: BTreeMap<String, OrderReservation>,
    positions: BTreeMap<(String, String, Outcome), u128>,
    position_holds: BTreeMap<String, u128>,
    position_cost_basis: BTreeMap<(String, String, Outcome), u128>,
    market_collateral: BTreeMap<String, u128>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    resolved_markets: BTreeMap<String, DirectMarketResolutionRecord>,
    fee_revenue_atomic: u128,
    #[serde(default, skip_serializing_if = "is_zero_u128")]
    zen_fee_revenue_atomic: u128,
    #[serde(default, skip_serializing_if = "is_zero_u128")]
    zen_rounding_reserve_atomic: u128,
    // This field was added after the opening lineage already had committed
    // artifacts.  Omitting its zero value preserves the exact pre-upgrade
    // CBOR and therefore the predecessor/state hashes for that lineage.
    #[serde(default, skip_serializing_if = "is_zero_u128")]
    rounding_reserve_atomic: u128,
    #[serde(default)]
    credited_custody_references: BTreeSet<String>,
    // An empty map preserves every historical state hash. A nonempty map is
    // part of the encrypted state hash, so old code cannot restore it while
    // silently dropping the withdrawal restriction.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    conditional_usdc_deposits: BTreeMap<String, ConditionalUsdcDeposit>,
    requests: BTreeMap<(String, String), (String, DirectResult)>,
}

fn is_zero_u128(value: &u128) -> bool {
    *value == 0
}

fn validate_conditional_deposits(state: &DirectState, key: &[u8]) -> Result<(), RuntimeError> {
    let invalid = || RuntimeError::StateArtifact;
    let mut expected = BTreeSet::new();
    for ((account, id), (hash, result)) in &state.requests {
        let Some(operation) = id.strip_prefix("usdc-bus-deposit-credit:") else { continue; };
        let receipt = &result.receipt;
        if !valid_bus_withdrawal_id(operation) || result.effect != "DEPOSIT_CONDITIONALLY_CREDITED"
            || result.status != TerminalStatus::Applied || receipt.status != result.status
            || receipt.effect != result.effect || receipt.account_id != *account || receipt.request_id != *id
            || receipt.request_hash != *hash || !verify_receipt(key, receipt)
            || !state.subject_identities.get(account).is_some_and(|set| set.contains(&receipt.identity_commitment))
            || !receipt.amount_atomic.as_deref().is_some_and(|value| amount(value).is_ok_and(|value| value >= 5_000_000))
            || !receipt.custody_reference.as_deref().is_some_and(|reference| valid_bus_deposit_reference(reference)
                && state.credited_custody_references.contains(reference))
            || !state.credited_custody_references.contains(&format!("arbitrum-usdc-bus-operation:{operation}")) {
            return Err(invalid());
        }
        if let Some((final_hash, final_result)) = state.requests.get(&(account.clone(), format!("usdc-bus-deposit-finalize:{operation}"))) {
            let final_receipt = &final_result.receipt;
            if final_result.status != TerminalStatus::Applied || final_result.effect != "DEPOSIT_FINALIZED"
                || final_receipt.status != final_result.status || final_receipt.effect != final_result.effect
                || final_receipt.account_id != *account || final_receipt.identity_commitment != receipt.identity_commitment
                || final_receipt.request_hash != *final_hash || final_receipt.request_id != format!("usdc-bus-deposit-finalize:{operation}")
                || final_receipt.amount_atomic != receipt.amount_atomic || !verify_receipt(key, final_receipt)
                || !final_receipt.custody_reference.as_deref().is_some_and(|reference|
                    reference.strip_prefix("horizen-usdc-deposit:").is_some_and(valid_transaction_hash_value)
                    && state.credited_custody_references.contains(reference))
                || state.conditional_usdc_deposits.contains_key(operation) { return Err(invalid()); }
        } else {
            let pending = state.conditional_usdc_deposits.get(operation).ok_or_else(invalid)?;
            if pending.account_id != *account || pending.identity_commitment != receipt.identity_commitment
                || Some(&pending.amount_atomic) != receipt.amount_atomic.as_ref()
                || Some(&pending.boarding_reference) != receipt.custody_reference.as_ref()
                || !state.subject_wallets.get(account).is_some_and(|wallets| wallets.contains(&pending.wallet_address))
                || !expected.insert(operation.to_string()) { return Err(invalid()); }
        }
    }
    if expected.len() != state.conditional_usdc_deposits.len() { return Err(invalid()); }
    Ok(())
}

fn reconstruct_bus_holds(state: &DirectState, receipt_key: &[u8]) -> Result<BTreeMap<String, UsdcBusHold>, RuntimeError> {
    let invalid = || RuntimeError::StateArtifact;
    let mut holds = BTreeMap::new();
    let mut totals = BTreeMap::<(String,String), u128>::new();
    for ((account, id), (hash, result)) in &state.requests {
        let receipt = &result.receipt;
        let terminal = id.starts_with("usdc-bus-settle:") || id.starts_with("usdc-bus-revert:");
        if result.effect != "WITHDRAWAL_RESERVED" && !terminal { continue; }
        if receipt.account_id != *account || receipt.request_id != *id || receipt.request_hash != *hash
            || result.status != TerminalStatus::Applied || receipt.status != result.status || receipt.effect != result.effect
            || !verify_receipt(receipt_key, receipt)
            || !state.subject_identities.get(account).is_some_and(|set| set.contains(&receipt.identity_commitment)) {
            return Err(invalid());
        }
        if terminal {
            let (prefix, effect, reverted) = if id.starts_with("usdc-bus-revert:") {
                ("usdc-bus-revert:", "WITHDRAWAL_REVERTED", true)
            } else { ("usdc-bus-settle:", "WITHDRAWAL_SETTLED", false) };
            let original_id = id.strip_prefix(prefix).ok_or_else(invalid)?;
            let original = &state.requests.get(&(account.clone(), original_id.into())).ok_or_else(invalid)?.1.receipt;
            if result.effect != effect || original.effect != "WITHDRAWAL_RESERVED"
                || original.identity_commitment != receipt.identity_commitment || original.amount_atomic != receipt.amount_atomic
                || !receipt.custody_reference.as_deref().is_some_and(|reference| valid_bus_terminal_reference(reference, reverted)) {
                return Err(invalid());
            }
            continue;
        }
        let reference = receipt.custody_reference.as_deref().ok_or_else(invalid)?;
        let binding = reference.strip_prefix(&format!("usdc-bus-reservation:{id}:")).ok_or_else(invalid)?;
        // Pre-route-expansion artifacts contained only the destination and are
        // therefore the original Arbitrum USDC route. New artifacts bind the
        // exact route and asset into the immutable receipt.
        let (destination_chain,asset,destination)=if let Some((chain,rest))=binding.split_once(':') {
            let (asset,destination)=rest.split_once(':').ok_or_else(invalid)?;(chain,asset,destination)
        }else {("arbitrum","USDC",binding)};
        let atomic = receipt.amount_atomic.as_deref().ok_or_else(invalid)?;
        let value = amount(atomic).map_err(|_| invalid())?;
        if !valid_bus_withdrawal_id(id)||!valid_layrs_withdrawal_destination(destination_chain,asset,destination)
            || value.to_string() != atomic { return Err(invalid()); }
        let settled = state.requests.contains_key(&(account.clone(), format!("usdc-bus-settle:{id}")));
        let reverted = state.requests.contains_key(&(account.clone(), format!("usdc-bus-revert:{id}")));
        if settled && reverted { return Err(invalid()); }
        if settled || reverted { continue; }
        if holds.values().any(|hold: &UsdcBusHold| hold.identity_commitment == receipt.identity_commitment)
            || holds.insert(id.clone(), UsdcBusHold { account_id: account.clone(), identity_commitment: receipt.identity_commitment.clone(),
                destination:destination.into(),destination_chain:destination_chain.into(),asset:asset.into(),amount_atomic:atomic.into() }).is_some() { return Err(invalid()); }
        let total = totals.entry((receipt.identity_commitment.clone(),asset.into())).or_default();
        *total = total.checked_add(value).ok_or_else(invalid)?;
    }
    // Legacy withdrawals move atomically and leave no persistent hold. A
    // missing receipt must never unlock either supported ledger asset.
    for (identity, balances) in &state.balances {
        for asset in ["USDC","ZEN"] {
            let actual = balances.get(&(asset.into(), "USER_WITHDRAWAL_HOLD".into())).copied().unwrap_or_default();
            if actual != totals.remove(&(identity.clone(),asset.into())).unwrap_or_default() { return Err(invalid()); }
        }
    }
    if !totals.is_empty() { return Err(invalid()); }
    Ok(holds)
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
        let mut runtime = Self {
            opening_state_hash: String::new(),
            balances: epoch.identities,
            subject_identities: epoch.subject_identities,
            subject_wallets: epoch.subject_wallets,
            markets: BTreeMap::new(),
            books: BTreeMap::new(),
            orders: BTreeMap::new(),
            positions: BTreeMap::new(),
            position_holds: BTreeMap::new(),
            position_cost_basis: BTreeMap::new(),
            market_collateral: BTreeMap::new(),
            resolved_markets: BTreeMap::new(),
            fee_revenue_atomic: 0,
            zen_fee_revenue_atomic: 0,
            zen_rounding_reserve_atomic: 0,
            rounding_reserve_atomic: 0,
            credited_custody_references: BTreeSet::new(),
            usdc_bus_withdrawals: BTreeMap::new(),
            conditional_usdc_deposits: BTreeMap::new(),
            requests: BTreeMap::new(),
            receipt_key,
            mode,
        };
        runtime.opening_state_hash = runtime.state_hash();
        Ok(runtime)
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
        let admission = matches!(&request.action, DirectAction::AdmitIdentity { .. });
        let governed_market_registration =
            matches!(&request.action, DirectAction::RegisterMarket { .. });
        let governed_market_resolution =
            matches!(&request.action, DirectAction::ResolveMarket { .. });
        if self.mode == RuntimeMode::AdmissionOnly && !(admission || governed_market_registration) {
            return Err(RuntimeError::WriterDisabled);
        }
        if !(admission
            || governed_market_registration
            || governed_market_resolution
            || self.owns(&request.account_id, &request.identity_commitment))
        {
            return Err(RuntimeError::IdentityDenied);
        }
        if matches!(&request.action,DirectAction::ReserveWithdrawal {..}|DirectAction::SettleRelayWithdrawal {..})
            &&self.usdc_bus_withdrawals.values().any(|hold|hold.identity_commitment==request.identity_commitment) {
            return Err(RuntimeError::WithdrawalPending);
        }
        let financial_wallet = request
            .financial_wallet_address
            .as_deref()
            .map(str::to_ascii_lowercase);
        match &request.action {
            // Preserve the existing deposit lane unchanged. Base deposit
            DirectAction::CreditZenDeposit { .. } | DirectAction::CreditHorizenUsdcDeposit { .. }
            | DirectAction::CreditArbitrumUsdcBusDeposit { .. } | DirectAction::FinalizeArbitrumUsdcBusDeposit { .. } => {
                let Some(wallet) = financial_wallet.as_deref() else { return Err(RuntimeError::DestinationDenied); };
                if !valid_evm_wallet(wallet) || !self.subject_wallets.get(&request.account_id)
                    .is_some_and(|wallets| wallets.contains(wallet)) { return Err(RuntimeError::DestinationDenied); }
            }
            // attribution is handled separately and is outside this patch.
            DirectAction::CreditDeposit { .. } => {
                let Some(wallet) = financial_wallet.as_deref() else {
                    return Err(RuntimeError::DestinationDenied);
                };
                if !valid_evm_wallet(wallet)
                    || self
                        .subject_wallets
                        .values()
                        .any(|wallets| wallets.contains(wallet))
                {
                    return Err(RuntimeError::DestinationDenied);
                }
            }
            DirectAction::ReserveWithdrawal { destination, .. }
            | DirectAction::RecordWithdrawalReverted { destination, .. }
            | DirectAction::ReserveZenWithdrawal { destination, .. }
            | DirectAction::RecordZenWithdrawalReverted { destination, .. } => {
                let Some(wallet) = financial_wallet.as_deref() else {
                    return Err(RuntimeError::DestinationDenied);
                };
                // The user-selected destination, including an address that
                // also happens to be a Privy wallet, is permitted. Equality
                // here binds the normalized transport field to the signed
                // action; it is not an identity or ownership allowlist.
                if !valid_evm_wallet(wallet) || !wallet.eq_ignore_ascii_case(destination) {
                    return Err(RuntimeError::DestinationDenied);
                }
            }
            DirectAction::BeginUsdcBusWithdrawal {destination_chain,asset,destination,..}
            | DirectAction::SettleUsdcBusWithdrawal {destination_chain,asset,destination,..}
            | DirectAction::RevertUsdcBusWithdrawal {destination_chain,asset,destination,..} => {
                let Some(wallet)=financial_wallet.as_deref() else {return Err(RuntimeError::DestinationDenied);};
                if !valid_evm_wallet(wallet)||!self.subject_wallets.get(&request.account_id).is_some_and(|wallets|wallets.contains(wallet))
                    ||!valid_layrs_withdrawal_destination(destination_chain,asset,destination){return Err(RuntimeError::DestinationDenied);}
            }
            DirectAction::SettleRelayWithdrawal { .. }
            | DirectAction::RecordRelayWithdrawalReverted { .. } => {
                if financial_wallet.is_some() {
                    return Err(RuntimeError::InvalidRequest);
                }
            }
            _ if financial_wallet.is_some() => return Err(RuntimeError::InvalidRequest),
            _ => {}
        }
        let mut execution = None;
        let mut resolution_execution = None;
        let mut touched_identities = BTreeSet::from([request.identity_commitment.clone()]);
        let (effect, amount_atomic, custody_reference): (String, Option<String>, Option<String>) =
            match &request.action {
                DirectAction::AdmitIdentity { wallet_address } => {
                    let wallet = wallet_address.to_ascii_lowercase();
                    if !valid_evm_wallet(&wallet)
                        || request.account_id.len() != 64
                        || !request
                            .account_id
                            .bytes()
                            .all(|byte| byte.is_ascii_hexdigit())
                        || request.identity_commitment
                            != identity_commitment_for(&request.account_id, &wallet)
                        || self.subject_identities.contains_key(&request.account_id)
                        || self.balances.contains_key(&request.identity_commitment)
                        || self
                            .subject_wallets
                            .values()
                            .any(|wallets| wallets.contains(&wallet))
                    {
                        return Err(RuntimeError::IdentityAlreadyAdmitted);
                    }
                    self.balances.insert(
                        request.identity_commitment.clone(),
                        BTreeMap::from([(("USDC".into(), "USER_AVAILABLE".into()), 0)]),
                    );
                    self.subject_identities.insert(
                        request.account_id.clone(),
                        BTreeSet::from([request.identity_commitment.clone()]),
                    );
                    self.subject_wallets
                        .insert(request.account_id.clone(), BTreeSet::from([wallet]));
                    ("IDENTITY_ADMITTED".into(), None, None)
                }
                DirectAction::RegisterMarket {
                    registration,
                    now_unix,
                } => {
                    if request.account_id != "governance"
                        || request.identity_commitment != "governance"
                        || self.markets.contains_key(&registration.market.market_id)
                        || !((self.mode == RuntimeMode::IsolatedTest
                            && registration.signature == "isolated-market-release"
                            && validate_direct_market(
                                &registration.market,
                                now_unix.saturating_mul(1_000) as i64,
                            )
                            .is_ok())
                            || registration.verify(*now_unix))
                    {
                        return Err(RuntimeError::InvalidMarket);
                    }
                    self.markets.insert(
                        registration.market.market_id.clone(),
                        registration.market.clone(),
                    );
                    self.books.insert(
                        registration.market.market_id.clone(),
                        PriceTimeBook::default(),
                    );
                    ("MARKET_REGISTERED".into(), None, None)
                }
                DirectAction::ResolveMarket {
                    resolution,
                    now_unix,
                } => {
                    let valid_authorization = resolution.verify(*now_unix)
                        || (self.mode == RuntimeMode::IsolatedTest
                            && resolution.signature == "isolated-market-resolution"
                            && resolution.expires_at_unix > *now_unix);
                    if request.account_id != "governance"
                        || request.identity_commitment != "governance"
                        || request.request_id != resolution.resolution_id
                        || !valid_authorization
                    {
                        return Err(RuntimeError::InvalidMarket);
                    }
                    let (details, identities) = self.resolve_market(resolution)?;
                    touched_identities.extend(identities);
                    resolution_execution = Some(details);
                    ("MARKET_RESOLVED".into(), None, None)
                }
                DirectAction::GovernedBalanceRecovery { recovery, now_unix } => {
                    let expected = recovery
                        .expected_balance_before_atomic
                        .parse::<u128>()
                        .map_err(|_| RuntimeError::InvalidRequest)?;
                    let valid_authorization = recovery.verify(*now_unix)
                        || (self.mode == RuntimeMode::IsolatedTest
                            && recovery.signature == "isolated-governed-balance-recovery"
                            && recovery.expires_at_unix > *now_unix);
                    if !valid_authorization
                        || request.request_id != recovery.recovery_id
                        || request.account_id != recovery.account_id
                        || request.identity_commitment != recovery.identity_commitment
                        || self.balance(
                            &request.identity_commitment,
                            &recovery.asset,
                            &recovery.bucket,
                        ) != expected
                    {
                        return Err(RuntimeError::InvalidRequest);
                    }
                    let value = amount(&recovery.amount_atomic)?;
                    self.add(&request.identity_commitment, &recovery.bucket, value)?;
                    (
                        "GOVERNED_BALANCE_RECOVERY_APPLIED".into(),
                        Some(recovery.amount_atomic.clone()),
                        Some(format!("recovery-evidence:{}", recovery.evidence_sha256)),
                    )
                }
                DirectAction::CreditDeposit {
                    amount_atomic,
                    custody_reference,
                } => {
                    let value = amount(amount_atomic)?;
                    if custody_reference.is_empty()
                        || (self.mode == RuntimeMode::ProductionEnabled
                            && !valid_deposit_custody_reference(custody_reference))
                    {
                        return Err(RuntimeError::InvalidRequest);
                    }
                    if !self
                        .credited_custody_references
                        .insert(custody_reference.to_ascii_lowercase())
                    {
                        return Err(RuntimeError::CustodyReferenceReuse);
                    }
                    self.add(&request.identity_commitment, "USER_AVAILABLE", value)?;
                    (
                        "DEPOSIT_CREDITED".into(),
                        Some(amount_atomic.clone()),
                        Some(custody_reference.clone()),
                    )
                }
                DirectAction::CreditZenDeposit { amount_atomic, custody_reference } => {
                    let value = amount(amount_atomic)?;
                    let hash = custody_reference.strip_prefix("horizen-zen-deposit:").filter(|value| valid_transaction_hash_value(value)).ok_or(RuntimeError::InvalidRequest)?;
                    if !self.credited_custody_references.insert(format!("horizen-zen-deposit:{}", hash.to_ascii_lowercase())) { return Err(RuntimeError::CustodyReferenceReuse); }
                    self.add_asset(&request.identity_commitment, "ZEN", "USER_AVAILABLE", value)?;
                    ("DEPOSIT_CREDITED".into(), Some(amount_atomic.clone()), Some(custody_reference.clone()))
                }
                DirectAction::CreditHorizenUsdcDeposit { amount_atomic, custody_reference } => {
                    if self.conditional_usdc_deposits.values().any(|pending|pending.account_id==request.account_id
                        &&Some(pending.wallet_address.as_str())==financial_wallet.as_deref()) {
                        return Err(RuntimeError::InvalidRequest);
                    }
                    let value=amount(amount_atomic)?;
                    let hash=custody_reference.strip_prefix("horizen-usdc-deposit:")
                        .filter(|value|valid_transaction_hash_value(value)).ok_or(RuntimeError::InvalidRequest)?;
                    if value<5_000_000 {return Err(RuntimeError::InvalidRequest);}
                    let reference=format!("horizen-usdc-deposit:{}",hash.to_ascii_lowercase());
                    if self.credited_custody_references.contains(&reference) {
                        return Err(RuntimeError::CustodyReferenceReuse);
                    }
                    self.add(&request.identity_commitment,"USER_AVAILABLE",value)?;
                    self.credited_custody_references.insert(reference);
                    ("DEPOSIT_CREDITED".into(),Some(amount_atomic.clone()),Some(custody_reference.clone()))
                }
                DirectAction::CreditArbitrumUsdcBusDeposit {operation_id,amount_atomic,custody_reference} => {
                    let value=amount(amount_atomic)?;
                    if value<5_000_000 || !valid_bus_withdrawal_id(operation_id)
                        ||request.request_id!=format!("usdc-bus-deposit-credit:{operation_id}")
                        ||!valid_bus_deposit_reference(custody_reference)
                        ||self.conditional_usdc_deposits.contains_key(operation_id) {
                        return Err(RuntimeError::InvalidRequest);
                    }
                    let operation_reference=format!("arbitrum-usdc-bus-operation:{operation_id}");
                    if self.credited_custody_references.contains(custody_reference)
                        ||self.credited_custody_references.contains(&operation_reference) {return Err(RuntimeError::CustodyReferenceReuse);}
                    let wallet=financial_wallet.clone().ok_or(RuntimeError::DestinationDenied)?;
                    if self.conditional_usdc_deposits.values().any(|pending|pending.wallet_address==wallet) {
                        return Err(RuntimeError::InvalidRequest);
                    }
                    self.add(&request.identity_commitment,"USER_AVAILABLE",value)?;
                    self.credited_custody_references.insert(custody_reference.clone());
                    self.credited_custody_references.insert(operation_reference);
                    self.conditional_usdc_deposits.insert(operation_id.clone(),ConditionalUsdcDeposit {
                        account_id:request.account_id.clone(),identity_commitment:request.identity_commitment.clone(),
                        wallet_address:wallet,amount_atomic:amount_atomic.clone(),boarding_reference:custody_reference.clone()});
                    ("DEPOSIT_CONDITIONALLY_CREDITED".into(),Some(amount_atomic.clone()),Some(custody_reference.clone()))
                }
                DirectAction::FinalizeArbitrumUsdcBusDeposit {operation_id,amount_atomic,boarding_reference,custody_reference} => {
                    let pending=self.conditional_usdc_deposits.get(operation_id).ok_or(RuntimeError::InvalidRequest)?;
                    if request.request_id!=format!("usdc-bus-deposit-finalize:{operation_id}")
                        ||pending.account_id!=request.account_id||pending.identity_commitment!=request.identity_commitment
                        ||Some(pending.wallet_address.as_str())!=financial_wallet.as_deref()
                        ||pending.amount_atomic!=*amount_atomic||pending.boarding_reference!=*boarding_reference
                        ||*custody_reference!=custody_reference.to_ascii_lowercase()
                        ||!custody_reference.strip_prefix("horizen-usdc-deposit:").is_some_and(valid_transaction_hash_value) {
                        return Err(RuntimeError::InvalidRequest);
                    }
                    if self.credited_custody_references.contains(custody_reference) {return Err(RuntimeError::CustodyReferenceReuse);}
                    self.credited_custody_references.insert(custody_reference.clone());
                    self.conditional_usdc_deposits.remove(operation_id);
                    ("DEPOSIT_FINALIZED".into(),Some(amount_atomic.clone()),Some(custody_reference.clone()))
                }
                DirectAction::LinkFinancialWallet {wallet_address} => {
                    let wallet=wallet_address.to_ascii_lowercase();
                    if !valid_evm_wallet(&wallet) {return Err(RuntimeError::DestinationDenied);}
                    if self.usdc_bus_withdrawals.values().any(|hold|hold.identity_commitment==request.identity_commitment) {
                        return Err(RuntimeError::WithdrawalPending);
                    }
                    if self.subject_wallets.iter().any(|(subject,wallets)|subject!=&request.account_id&&wallets.contains(&wallet)) {
                        return Err(RuntimeError::IdentityAlreadyAdmitted);
                    }
                    self.subject_wallets.entry(request.account_id.clone()).or_default().insert(wallet.clone());
                    ("FINANCIAL_WALLET_LINKED".into(),None,Some(format!("wallet-link:{wallet}")))
                }
                DirectAction::BeginUsdcBusWithdrawal {withdrawal_id,destination_chain,asset,destination,amount_atomic} => {
                    let value=amount(amount_atomic)?;
                    if !valid_bus_withdrawal_id(withdrawal_id)||withdrawal_id!=&request.request_id||value.to_string()!=*amount_atomic {return Err(RuntimeError::InvalidRequest);}
                    if self.usdc_bus_withdrawals.contains_key(withdrawal_id) {return Err(RuntimeError::RequestReuse);}
                    if self.usdc_bus_withdrawals.values().any(|hold|hold.identity_commitment==request.identity_commitment) {
                        return Err(RuntimeError::WithdrawalPending);
                    }
                    let ledger_asset=if asset=="ZEN" {"ZEN"} else {"USDC"};
                    if self.balance(&request.identity_commitment,ledger_asset,"USER_AVAILABLE")<value {
                        // Commit a money-free rejection under the original ID.
                        // A future deposit must never turn this refused request
                        // into a delayed payout after the UI cleared it.
                        ("WITHDRAWAL_REJECTED".into(),Some(amount_atomic.clone()),Some(format!("usdc-bus-rejection:{withdrawal_id}:INSUFFICIENT_AVAILABLE")))
                    } else {
                        if ledger_asset=="USDC" {self.verify_settled_usdc_withdrawal(&request.identity_commitment,value)?;}
                        self.move_asset_bucket(&request.identity_commitment,ledger_asset,"USER_AVAILABLE","USER_WITHDRAWAL_HOLD",value)?;
                        self.usdc_bus_withdrawals.insert(withdrawal_id.clone(),UsdcBusHold {account_id:request.account_id.clone(),
                            identity_commitment:request.identity_commitment.clone(),destination:if destination_chain=="solana" {destination.clone()}else{destination.to_ascii_lowercase()},
                            destination_chain:destination_chain.clone(),asset:asset.clone(),amount_atomic:amount_atomic.clone()});
                        ("WITHDRAWAL_RESERVED".into(),Some(amount_atomic.clone()),Some(format!("usdc-bus-reservation:{withdrawal_id}:{destination_chain}:{asset}:{}",if destination_chain=="solana" {destination.clone()}else{destination.to_ascii_lowercase()})))
                    }
                }
                DirectAction::SettleUsdcBusWithdrawal {withdrawal_id,destination_chain,asset,destination,amount_atomic,custody_reference}
                | DirectAction::RevertUsdcBusWithdrawal {withdrawal_id,destination_chain,asset,destination,amount_atomic,custody_reference} => {
                    let value=amount(amount_atomic)?;
                    let reverted=matches!(&request.action,DirectAction::RevertUsdcBusWithdrawal {..});
                    let expected_request=format!("usdc-bus-{}:{withdrawal_id}",if reverted {"revert"} else {"settle"});
                    let hold=self.usdc_bus_withdrawals.get(withdrawal_id).ok_or(RuntimeError::InvalidRequest)?;
                    if request.request_id!=expected_request || hold.account_id!=request.account_id
                        ||hold.identity_commitment!=request.identity_commitment||hold.destination!=if destination_chain=="solana" {destination.clone()}else{destination.to_ascii_lowercase()}
                        ||hold.destination_chain!=*destination_chain||hold.asset!=*asset
                        ||hold.amount_atomic!=*amount_atomic||!valid_bus_terminal_reference(custody_reference,reverted) {
                        return Err(RuntimeError::DestinationDenied);
                    }
                    // Existing state field, domain-separated references. No new
                    // always-present schema field breaks a drained fallback.
                    let parts=custody_reference.split(':').collect::<Vec<_>>();
                    let local=!reverted&&parts.first()==Some(&"horizen-usdc-local");
                    let zen=asset=="ZEN";
                    let pool_reference=if local||zen {custody_reference.clone()}else{format!("horizen-usdc-bus-pool:{}",parts[1])};
                    let delivery_reference=if reverted||local||zen {None} else {Some(format!("horizen-usdc-bus-delivery:{}:{}",parts[3],parts[5]))};
                    let seat_reference=if reverted||local||zen {None} else {Some(format!("horizen-usdc-bus-seat:{}:{}",parts[2],parts[4]))};
                    if self.credited_custody_references.contains(custody_reference)
                        ||self.credited_custody_references.contains(&pool_reference)
                        ||delivery_reference.as_ref().is_some_and(|reference|self.credited_custody_references.contains(reference))
                        ||seat_reference.as_ref().is_some_and(|reference|self.credited_custody_references.contains(reference)) {
                        return Err(RuntimeError::CustodyReferenceReuse);
                    }
                    let ledger_asset=if hold.asset=="ZEN" {"ZEN"} else {"USDC"};
                    self.move_asset_bucket(&request.identity_commitment,ledger_asset,"USER_WITHDRAWAL_HOLD",
                        if reverted {"USER_AVAILABLE"} else {"USER_SETTLED"},value)?;
                    self.credited_custody_references.insert(custody_reference.clone());
                    self.credited_custody_references.insert(pool_reference);
                    if let Some(reference)=delivery_reference {self.credited_custody_references.insert(reference);}
                    if let Some(reference)=seat_reference {self.credited_custody_references.insert(reference);}
                    self.usdc_bus_withdrawals.remove(withdrawal_id);
                    ((if reverted {"WITHDRAWAL_REVERTED"} else {"WITHDRAWAL_SETTLED"}).into(),Some(amount_atomic.clone()),Some(custody_reference.clone()))
                }
                DirectAction::PlaceOrder {
                    order_id,
                    market_id,
                    outcome,
                    action,
                    price_micros,
                    quantity_micros,
                    time_in_force,
                    expires_at_millis,
                    now_millis,
                } => {
                    let details = self.place_order(
                        &request.identity_commitment,
                        order_id,
                        market_id,
                        *outcome,
                        *action,
                        *price_micros,
                        quantity_micros,
                        *time_in_force,
                        *expires_at_millis,
                        *now_millis,
                    )?;
                    for trade in &details.trades {
                        for order_id in [&trade.maker_order_id, &trade.taker_order_id] {
                            if let Some(reservation) = self.orders.get(order_id) {
                                touched_identities
                                    .insert(reservation.order.private_user_id.clone());
                            }
                        }
                    }
                    let reserved = self
                        .orders
                        .get(order_id)
                        .map(|record| record.hold_atomic)
                        .unwrap_or_default();
                    let effect = if details.trades.is_empty() {
                        "ORDER_PLACED"
                    } else {
                        "ORDER_EXECUTED"
                    };
                    execution = Some(details);
                    (effect.into(), Some(reserved.to_string()), None)
                }
                DirectAction::CancelOrder { order_id } => {
                    let value = self.cancel_order(&request.identity_commitment, order_id)?;
                    ("ORDER_CANCELLED".into(), Some(value.to_string()), None)
                }
                DirectAction::RedeemCompleteSet { market_id, quantity_micros } => {
                    let quantity = amount(quantity_micros)?;
                    if quantity.to_string() != *quantity_micros || self.resolved_markets.contains_key(market_id) {
                        return Err(RuntimeError::InvalidRequest);
                    }
                    let market = self.markets.get(market_id).cloned().ok_or(RuntimeError::InvalidMarket)?;
                    let value = settlement_atomic(&market, quantity)?;
                    if value == 0 { return Err(RuntimeError::InvalidRequest); }
                    let keys = [Outcome::Up, Outcome::Down].map(|outcome| (request.identity_commitment.clone(), market_id.clone(), outcome));
                    if keys.iter().any(|key| self.positions.get(key).copied().unwrap_or_default() < quantity)
                        || self.market_collateral.get(market_id).copied().unwrap_or_default() < value {
                        return Err(RuntimeError::InsufficientAvailable);
                    }
                    // Available claims exclude positions reserved in orders.
                    // Each leg reduces its basis against its own prior total.
                    for key in &keys {
                        *self.positions.get_mut(key).ok_or(RuntimeError::InsufficientAvailable)? -= quantity;
                        self.reduce_position_basis(key, quantity)?;
                    }
                    *self.market_collateral.get_mut(market_id).ok_or(RuntimeError::InsufficientAvailable)? -= value;
                    self.add_asset(&request.identity_commitment, &market.settlement_asset, "USER_AVAILABLE", value)?;
                    ("COMPLETE_SET_REDEEMED".into(), Some(value.to_string()), None)
                }
                DirectAction::ReserveWithdrawal {
                    destination,
                    amount_atomic,
                    custody_reference,
                } => {
                    let value = amount(amount_atomic)?;
                    self.verify_settled_usdc_withdrawal(&request.identity_commitment,value)?;
                    let destination = destination.to_ascii_lowercase();
                    if !valid_withdrawal_custody_reference(custody_reference, self.mode)
                        || financial_wallet.as_deref() != Some(destination.as_str())
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
                DirectAction::ReserveZenWithdrawal { destination_chain, destination, amount_atomic, custody_reference }
                | DirectAction::RecordZenWithdrawalReverted { destination_chain, destination, amount_atomic, custody_reference } => {
                    let value = amount(amount_atomic)?;
                    if !matches!(destination_chain.as_str(), "base" | "horizen") || (destination_chain == "base" && value % 1_000_000_000_000 != 0)
                        || !valid_withdrawal_custody_reference(custody_reference, self.mode)
                        || financial_wallet.as_deref() != Some(destination.to_ascii_lowercase().as_str()) { return Err(RuntimeError::DestinationDenied); }
                    if matches!(&request.action, DirectAction::RecordZenWithdrawalReverted { .. }) {
                        ("WITHDRAWAL_REVERTED".into(), Some(amount_atomic.clone()), Some(custody_reference.clone()))
                    } else {
                        self.move_asset_bucket(&request.identity_commitment, "ZEN", "USER_AVAILABLE", "USER_SETTLED", value)?;
                        ("WITHDRAWAL_SETTLED".into(), Some(amount_atomic.clone()), Some(custody_reference.clone()))
                    }
                }
                DirectAction::SettleRelayWithdrawal {
                    relay,
                    amount_atomic,
                    custody_reference,
                } => {
                    let value = amount(amount_atomic)?;
                    self.verify_settled_usdc_withdrawal(&request.identity_commitment,value)?;
                    relay.verify(amount_atomic)?;
                    if !valid_relay_withdrawal_custody_reference(custody_reference, relay, false) {
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
                DirectAction::RecordWithdrawalReverted {
                    destination,
                    amount_atomic,
                    custody_reference,
                } => {
                    let _ = amount(amount_atomic)?;
                    let destination = destination.to_ascii_lowercase();
                    if !valid_withdrawal_custody_reference(custody_reference, self.mode)
                        || financial_wallet.as_deref() != Some(destination.as_str())
                    {
                        return Err(RuntimeError::DestinationDenied);
                    }
                    (
                        "WITHDRAWAL_REVERTED".into(),
                        Some(amount_atomic.clone()),
                        Some(custody_reference.clone()),
                    )
                }
                DirectAction::RecordRelayWithdrawalReverted {
                    relay,
                    amount_atomic,
                    custody_reference,
                } => {
                    let _ = amount(amount_atomic)?;
                    relay.verify(amount_atomic)?;
                    if !valid_relay_withdrawal_custody_reference(custody_reference, relay, true) {
                        return Err(RuntimeError::DestinationDenied);
                    }
                    (
                        "WITHDRAWAL_REVERTED".into(),
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
                    touched_identities.insert(recipient_identity_commitment.clone());
                    ("TRANSFER_SETTLED".into(), Some(amount_atomic.clone()), None)
                }
            };
        let terminal_status = if effect == "WITHDRAWAL_REVERTED" {
            TerminalStatus::RejectedEffectNone
        } else {
            TerminalStatus::Applied
        };
        let projection_balance_updates =
            touched_identities
                .iter()
                .filter_map(|identity| {
                    let auth_subject_hash =
                        self.subject_identities
                            .iter()
                            .find_map(|(subject, identities)| {
                                identities.contains(identity).then(|| subject.clone())
                            })?;
                    Some(self.balances.get(identity)?.iter().map(
                        move |((asset, bucket), amount)| ProjectionBalanceUpdate {
                            auth_subject_hash: auth_subject_hash.clone(),
                            identity_commitment: identity.clone(),
                            asset: asset.clone(),
                            bucket: bucket.clone(),
                            amount_atomic: amount.to_string(),
                        },
                    ))
                })
                .flatten()
                .collect();
        let mut receipt = DirectReceipt {
            receipt_id: sha256(
                format!("{}:{}:{}", EPOCH_ID, request.account_id, request.request_id).as_bytes(),
            ),
            account_id: request.account_id.clone(),
            identity_commitment: request.identity_commitment.clone(),
            request_id: request.request_id.clone(),
            request_hash: request.request_hash.clone(),
            status: terminal_status.clone(),
            effect: effect.clone(),
            amount_atomic,
            custody_reference,
            execution,
            resolution: resolution_execution,
            projection_balance_updates,
            genesis_ordinal: 0,
            signature: String::new(),
        };
        receipt.signature = receipt_signature(&self.receipt_key, &receipt);
        let result = DirectResult {
            status: terminal_status,
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
    /// Restore one encrypted successor without collecting the entire archive
    /// in one VSOCK frame. Call only on a startup candidate, never adopted state.
    pub fn restore_next_committed(mut self, artifact: &DirectStateArtifact, key: &[u8]) -> Result<Self, RuntimeError> {
        if artifact.sequence != self.committed_sequence()+1
            || artifact.prior_state_hash != self.state_hash()
            || !self.verify_artifact(artifact,key)? {
            return Err(RuntimeError::StateArtifact);
        }
        self.apply_artifact(artifact,key)?;
        if self.state_hash()!=artifact.state_hash || self.committed_sequence()!=artifact.sequence {
            return Err(RuntimeError::StateArtifact);
        }
        Ok(self)
    }
    pub fn seal_checkpoint(&self, artifact: DirectStateArtifact, receipt_records: Vec<DirectStateArtifact>, artifact_hashes: Vec<String>, key: &[u8]) -> Result<DirectCheckpoint, RuntimeError> {
        if self.receipt_key.len() != 32 || artifact.sequence == 0
            || artifact.sequence != self.committed_sequence()
            || artifact.state_hash != self.state_hash()
            || !self.verify_artifact(&artifact, key)? {
            return Err(RuntimeError::StateArtifact);
        }
        let mut checkpoint = DirectCheckpoint {
            protocol: "layrs.direct-execution.checkpoint.v1".into(),
            opening_state_hash: self.opening_state_hash.clone(), artifact, receipt_records, artifact_hashes, bootstrap_certificate: None,
            signature: String::new(),
        };
        self.validate_checkpoint_records(&checkpoint)?;
        checkpoint.signature = sign(&self.receipt_key, &checkpoint.signature_bytes()?);
        Ok(checkpoint)
    }
    /// Starts a private restore candidate at the authenticated checkpoint,
    /// not at genesis. The caller must prove its exact archived head and then
    /// append every immutable successor before FinishCommittedRestore.
    pub fn restore_checkpoint(mut self, checkpoint: &DirectCheckpoint, key: &[u8]) -> Result<Self, RuntimeError> {
        if self.committed_sequence() != 0 || self.receipt_key.len() != 32
            || checkpoint.protocol != "layrs.direct-execution.checkpoint.v1"
            || checkpoint.opening_state_hash != self.state_hash()
            || !(constant_time_eq(&sign(&self.receipt_key, &checkpoint.signature_bytes()?), &checkpoint.signature)
                || (checkpoint.signature.is_empty() && checkpoint.bootstrap_certificate.as_ref().is_some_and(|certificate| certificate.verify(checkpoint))))
            || !self.verify_artifact(&checkpoint.artifact, key)? {
            return Err(RuntimeError::StateArtifact);
        }
        self.apply_artifact(&checkpoint.artifact, key)?;
        if self.committed_sequence() != checkpoint.artifact.sequence
            || self.state_hash() != checkpoint.artifact.state_hash {
            return Err(RuntimeError::StateArtifact);
        }
        self.validate_checkpoint_records(checkpoint)?;
        Ok(self)
    }
    fn validate_checkpoint_records(&self, checkpoint: &DirectCheckpoint) -> Result<(), RuntimeError> {
        if checkpoint.artifact.sequence == 0 || checkpoint.receipt_records.len() > MAX_V70_LINEAGE_RECORDS
            || checkpoint.receipt_records.len() as u64 != checkpoint.artifact.sequence
            || checkpoint.artifact_hashes.len() != checkpoint.receipt_records.len()
            || checkpoint.artifact_hashes.iter().any(|hash| hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
            || checkpoint.artifact_hashes.last() != Some(&artifact_hash(&checkpoint.artifact)) {
            return Err(RuntimeError::StateArtifact);
        }
        let mut root = checkpoint.opening_state_hash.clone();
        let mut seen = BTreeSet::new();
        for (index, record) in checkpoint.receipt_records.iter().enumerate() {
            let receipt = &record.receipt;
            let request_key = (receipt.account_id.clone(), receipt.request_id.clone());
            let Some((hash, result)) = self.requests.get(&request_key) else { return Err(RuntimeError::StateArtifact); };
            if record.epoch_id != EPOCH_ID || record.sequence != index as u64 + 1
                || record.prior_state_hash != root || !record.ciphertext.is_empty()
                || record.request_hash != *hash || receipt.request_hash != *hash
                || result.receipt != *receipt || !verify_receipt(&self.receipt_key, receipt)
                || !seen.insert(request_key) {
                return Err(RuntimeError::StateArtifact);
            }
            root = record.state_hash.clone();
        }
        let mut head = checkpoint.artifact.clone(); head.ciphertext.clear();
        if root != checkpoint.artifact.state_hash || checkpoint.receipt_records.last() != Some(&head) {
            return Err(RuntimeError::StateArtifact);
        }
        Ok(())
    }
    fn verify_settled_usdc_withdrawal(&self,identity:&str,value:u128)->Result<(),RuntimeError> {
        let pending=self.conditional_usdc_deposits.values().filter(|entry|entry.identity_commitment==identity)
            .try_fold(0u128,|sum,entry|sum.checked_add(amount(&entry.amount_atomic)?).ok_or(RuntimeError::InvalidRequest))?;
        let available=self.balances.get(identity).and_then(|b|b.get(&("USDC".into(),"USER_AVAILABLE".into()))).copied().unwrap_or(0);
        if value>available.saturating_sub(pending) {return Err(RuntimeError::InsufficientAvailable);}
        Ok(())
    }
    fn snapshot(&self) -> DirectState {
        DirectState {
            balances: self.balances.clone(),
            subject_identities: self.subject_identities.clone(),
            subject_wallets: self.subject_wallets.clone(),
            markets: self.markets.clone(),
            books: self.books.clone(),
            orders: self.orders.clone(),
            positions: self.positions.clone(),
            position_holds: self.position_holds.clone(),
            position_cost_basis: self.position_cost_basis.clone(),
            market_collateral: self.market_collateral.clone(),
            resolved_markets: self.resolved_markets.clone(),
            fee_revenue_atomic: self.fee_revenue_atomic,
            zen_fee_revenue_atomic: self.zen_fee_revenue_atomic,
            zen_rounding_reserve_atomic: self.zen_rounding_reserve_atomic,
            rounding_reserve_atomic: self.rounding_reserve_atomic,
            credited_custody_references: self.credited_custody_references.clone(),
            conditional_usdc_deposits: self.conditional_usdc_deposits.clone(),
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
        // Keep every historical CBOR state compatible with the predecessor.
        // The signed original reservation binds the recipient; reconstruct
        // only its still-active entitlement, never from a disposable index.
        let bus_holds = reconstruct_bus_holds(&state, &self.receipt_key)?;
        validate_conditional_deposits(&state, &self.receipt_key)?;
        self.balances = state.balances;
        self.zen_fee_revenue_atomic = state.zen_fee_revenue_atomic;
        self.zen_rounding_reserve_atomic = state.zen_rounding_reserve_atomic;
        self.subject_identities = state.subject_identities;
        self.subject_wallets = state.subject_wallets;
        self.markets = state.markets;
        self.books = state.books;
        self.orders = state.orders;
        self.positions = state.positions;
        self.position_holds = state.position_holds;
        self.position_cost_basis = state.position_cost_basis;
        self.market_collateral = state.market_collateral;
        self.resolved_markets = state.resolved_markets;
        self.fee_revenue_atomic = state.fee_revenue_atomic;
        self.rounding_reserve_atomic = state.rounding_reserve_atomic;
        self.credited_custody_references = state.credited_custody_references;
        self.usdc_bus_withdrawals = bus_holds;
        self.conditional_usdc_deposits = state.conditional_usdc_deposits;
        self.requests = state.requests;
        Ok(())
    }
    fn resolve_market(
        &mut self,
        resolution: &GovernedMarketResolution,
    ) -> Result<(DirectResolutionExecution, BTreeSet<String>), RuntimeError> {
        let market = self
            .markets
            .get(&resolution.market_id)
            .cloned()
            .ok_or(RuntimeError::InvalidMarket)?;
        if self.resolved_markets.contains_key(&resolution.market_id)
            || resolution.resolved_at_millis < market.closes_at_millis
        {
            return Err(RuntimeError::InvalidMarket);
        }

        let position_keys = self
            .positions
            .keys()
            .filter(|key| key.1 == resolution.market_id && self.total_position(key) > 0)
            .cloned()
            .collect::<Vec<_>>();
        let gross_payout = position_keys.iter().try_fold(0u128, |total, key| {
            let quantity = settlement_atomic(&market, self.total_position(key))?;
            let payout = match resolution.outcome {
                DirectResolutionOutcome::Up if key.2 == Outcome::Up => quantity,
                DirectResolutionOutcome::Down if key.2 == Outcome::Down => quantity,
                DirectResolutionOutcome::Push => quantity / 2,
                _ => 0,
            };
            total.checked_add(payout).ok_or(RuntimeError::InvalidOrder)
        })?;
        let collateral = self
            .market_collateral
            .get(&resolution.market_id)
            .copied()
            .unwrap_or_default();
        if gross_payout > collateral {
            return Err(RuntimeError::InvalidOrder);
        }
        let rounding_reserve = collateral - gross_payout;

        // Apply to another clone even though the outer direct request already
        // executes against a clone.  This keeps direct library callers from
        // observing a partially applied resolution if an invariant fails.
        let mut next = self.clone();
        let order_ids = next
            .orders
            .iter()
            .filter(|(_, record)| {
                record.order.market_id == resolution.market_id
                    && matches!(
                        record.order.status,
                        OrderStatus::Open | OrderStatus::PartiallyFilled
                    )
            })
            .map(|(order_id, record)| (order_id.clone(), record.order.private_user_id.clone()))
            .collect::<Vec<_>>();
        let mut touched = BTreeSet::new();
        for (order_id, owner) in &order_ids {
            next.cancel_order(owner, order_id)?;
            touched.insert(owner.clone());
        }
        for key in &position_keys {
            let quantity = settlement_atomic(&market, next.positions.get(key).copied().unwrap_or_default())?;
            let payout = match resolution.outcome {
                DirectResolutionOutcome::Up if key.2 == Outcome::Up => quantity,
                DirectResolutionOutcome::Down if key.2 == Outcome::Down => quantity,
                DirectResolutionOutcome::Push => quantity / 2,
                _ => 0,
            };
            if payout > 0 {
                next.add_asset(&key.0, &market.settlement_asset, "USER_AVAILABLE", payout)?;
            }
            next.positions.remove(key);
            next.position_cost_basis.remove(key);
            touched.insert(key.0.clone());
        }
        next.position_cost_basis
            .retain(|(_, market_id, _), _| market_id != &resolution.market_id);
        next.market_collateral.remove(&resolution.market_id);
        let reserve = if market.settlement_asset == "ZEN" { &mut next.zen_rounding_reserve_atomic } else { &mut next.rounding_reserve_atomic };
        *reserve = reserve.checked_add(rounding_reserve).ok_or(RuntimeError::InvalidOrder)?;
        next.resolved_markets.insert(
            resolution.market_id.clone(),
            DirectMarketResolutionRecord {
                outcome: resolution.outcome,
                evidence_sha256: resolution.evidence_sha256.clone(),
                resolved_at_millis: resolution.resolved_at_millis,
            },
        );
        *self = next;
        Ok((
            DirectResolutionExecution {
                resolution_id: resolution.resolution_id.clone(),
                market_id: resolution.market_id.clone(),
                outcome: resolution.outcome,
                evidence_sha256: resolution.evidence_sha256.clone(),
                cancelled_order_count: order_ids.len(),
                settled_position_count: position_keys.len(),
                gross_payout_atomic: gross_payout.to_string(),
                rounding_reserve_atomic: rounding_reserve.to_string(),
            },
            touched,
        ))
    }
    #[allow(clippy::too_many_arguments)]
    fn place_order(
        &mut self,
        identity: &str,
        order_id: &str,
        market_id: &str,
        outcome: Outcome,
        action: OrderAction,
        price_micros: u64,
        quantity_micros: &str,
        time_in_force: TimeInForce,
        expires_at_millis: Option<i64>,
        now_millis: i64,
    ) -> Result<OrderExecution, RuntimeError> {
        let quantity = amount(quantity_micros)?;
        let order_uuid = Uuid::parse_str(order_id).map_err(|_| RuntimeError::InvalidOrder)?;
        let market = self
            .markets
            .get(market_id)
            .cloned()
            .ok_or(RuntimeError::InvalidMarket)?;
        if self.resolved_markets.contains_key(market_id) {
            return Err(RuntimeError::InvalidMarket);
        }
        validate_direct_market(&market, now_millis)?;
        if self.orders.contains_key(order_id)
            || now_millis < market.opens_at_millis
            || now_millis >= market.closes_at_millis
            || quantity < market.minimum_quantity_micros
            || quantity > market.maximum_quantity_micros
            || price_micros == 0
            || price_micros >= PRICE_SCALE as u64
            || !price_micros.is_multiple_of(market.tick_size_micros)
        {
            return Err(RuntimeError::InvalidOrder);
        }
        let position_key = (identity.to_string(), market_id.to_string(), outcome);
        let existing_position = self.total_position(&position_key);
        let order_notional = direct_notional(price_micros, quantity)?;
        let is_exact_full_position_close = action == OrderAction::Sell
            && quantity > 0
            && quantity == existing_position;
        if (order_notional < market.minimum_order_notional_micros
            && !is_exact_full_position_close)
            || order_notional > market.maximum_order_notional_micros
        {
            return Err(RuntimeError::InvalidOrder);
        }
        if action == OrderAction::Buy
            && existing_position
                .checked_add(quantity)
                .ok_or(RuntimeError::InvalidOrder)?
                > market.maximum_user_position_micros
        {
            return Err(RuntimeError::InvalidOrder);
        }
        let initial_hold = match action {
            OrderAction::Buy => settlement_atomic(&market, order_notional)?
                .checked_add(settlement_atomic(&market, maximum_direct_taker_fee(&market, quantity, price_micros)?)?)
                .ok_or(RuntimeError::InvalidOrder)?,
            OrderAction::Sell => {
                let available = self.positions.entry(position_key.clone()).or_default();
                if *available < quantity {
                    return Err(RuntimeError::InsufficientAvailable);
                }
                *available -= quantity;
                quantity
            }
        };
        if action == OrderAction::Buy {
            self.move_asset_bucket(identity, &market.settlement_asset, "USER_AVAILABLE", "USER_ORDER_HOLD", initial_hold)?;
        }
        let incoming = BookOrder::with_id(
            order_uuid,
            identity,
            market_id,
            outcome,
            action,
            price_micros,
            quantity,
            time_in_force,
            expires_at_millis,
        );
        self.orders.insert(
            order_id.into(),
            OrderReservation {
                order: incoming.clone(),
                hold_atomic: initial_hold,
            },
        );
        let prior_book = self
            .books
            .get(market_id)
            .cloned()
            .ok_or(RuntimeError::InvalidMarket)?;
        let mut next_book = prior_book.clone();
        let matched = next_book
            .submit(incoming, now_millis)
            .map_err(|_| RuntimeError::InvalidOrder)?;
        let accepted = matched
            .accepted_order
            .clone()
            .ok_or(RuntimeError::InvalidOrder)?;
        let mut trades = Vec::with_capacity(matched.fills.len());
        let mut total_fee = 0u128;
        for fill in &matched.fills {
            let maker = prior_book
                .order(fill.maker_order_id)
                .cloned()
                .ok_or(RuntimeError::InvalidOrder)?;
            let taker_fee = settlement_atomic(&market,
                direct_taker_fee(&market, fill.quantity_micros, fill.taker_price_micros())?)?;
            total_fee = total_fee
                .checked_add(taker_fee)
                .ok_or(RuntimeError::InvalidOrder)?;
            match fill.match_type {
                MatchType::Normal => self.settle_normal_fill(
                    &maker,
                    &accepted,
                    fill.quantity_micros,
                    fill.price_micros,
                    taker_fee,
                )?,
                MatchType::Mint => self.settle_mint_fill(
                    &maker,
                    &accepted,
                    fill.quantity_micros,
                    fill.price_micros,
                    taker_fee,
                )?,
                MatchType::Merge => self.settle_merge_fill(
                    &maker,
                    &accepted,
                    fill.quantity_micros,
                    fill.price_micros,
                    taker_fee,
                )?,
            }
            trades.push(TradeExecution {
                trade_id: fill.fill_id.to_string(),
                maker_order_id: fill.maker_order_id.to_string(),
                taker_order_id: fill.taker_order_id.to_string(),
                market_id: market_id.into(),
                outcome,
                match_type: fill.match_type,
                executed_quantity_micros: fill.quantity_micros.to_string(),
                execution_price_micros: fill.taker_price_micros(),
                fee_atomic: taker_fee.to_string(),
            });
        }
        self.books.insert(market_id.into(), next_book.clone());
        for fill in &matched.fills {
            if let Some(order) = next_book.order(fill.maker_order_id).cloned() {
                if let Some(reservation) = self.orders.get_mut(&order.order_id.to_string()) {
                    reservation.order = order;
                }
            }
        }
        if let Some(reservation) = self.orders.get_mut(order_id) {
            reservation.order = accepted.clone();
        }
        self.release_excess_order_hold(order_id)?;
        for fill in &matched.fills {
            self.release_excess_order_hold(&fill.maker_order_id.to_string())?;
        }
        Ok(OrderExecution {
            order_id: order_id.into(),
            market_id: market_id.into(),
            outcome,
            action,
            limit_price_micros: price_micros,
            quantity_micros: quantity.to_string(),
            status: accepted.status,
            executed_quantity_micros: accepted.filled_micros.to_string(),
            remaining_quantity_micros: accepted.remaining_micros.to_string(),
            total_fee_atomic: total_fee.to_string(),
            resulting_position_micros: self.total_position(&position_key).to_string(),
            resulting_available_atomic: self
                .balance(identity, &market.settlement_asset, "USER_AVAILABLE")
                .to_string(),
            trades,
        })
    }

    fn settle_normal_fill(
        &mut self,
        maker: &BookOrder,
        taker: &BookOrder,
        quantity: u128,
        price_micros: u64,
        taker_fee: u128,
    ) -> Result<(), RuntimeError> {
        let market = self.markets.get(&maker.market_id).cloned().ok_or(RuntimeError::InvalidMarket)?;
        let notional = settlement_atomic(&market, if maker.action == OrderAction::Buy {
            resting_buy_fill_notional(maker, quantity)?
        } else {
            direct_notional(price_micros, quantity)?
        })?;
        let (buyer, seller) = if taker.action == OrderAction::Buy {
            (taker, maker)
        } else {
            (maker, taker)
        };
        let buyer_debit = if buyer.order_id == taker.order_id {
            notional
                .checked_add(taker_fee)
                .ok_or(RuntimeError::InvalidOrder)?
        } else {
            notional
        };
        self.debit_order_hold(&buyer.order_id.to_string(), buyer_debit, true)?;
        self.debit_order_hold(&seller.order_id.to_string(), quantity, false)?;
        let seller_proceeds = if seller.order_id == taker.order_id {
            notional
                .checked_sub(taker_fee)
                .ok_or(RuntimeError::InvalidOrder)?
        } else {
            notional
        };
        self.add_asset(&seller.private_user_id, &market.settlement_asset, "USER_AVAILABLE", seller_proceeds)?;
        self.add_market_fee(&market, taker_fee)?;
        let seller_key = (
            seller.private_user_id.clone(),
            seller.market_id.clone(),
            seller.outcome,
        );
        self.reduce_position_basis(&seller_key, quantity)?;
        let buyer_key = (
            buyer.private_user_id.clone(),
            buyer.market_id.clone(),
            buyer.outcome,
        );
        *self.positions.entry(buyer_key.clone()).or_default() = self
            .positions
            .get(&buyer_key)
            .copied()
            .unwrap_or_default()
            .checked_add(quantity)
            .ok_or(RuntimeError::InvalidOrder)?;
        *self.position_cost_basis.entry(buyer_key).or_default() = self
            .position_cost_basis
            .get(&(
                buyer.private_user_id.clone(),
                buyer.market_id.clone(),
                buyer.outcome,
            ))
            .copied()
            .unwrap_or_default()
            .checked_add(notional)
            .ok_or(RuntimeError::InvalidOrder)?;
        Ok(())
    }

    fn settle_mint_fill(
        &mut self,
        maker: &BookOrder,
        taker: &BookOrder,
        quantity: u128,
        maker_price_micros: u64,
        taker_fee: u128,
    ) -> Result<(), RuntimeError> {
        if maker.action != OrderAction::Buy
            || taker.action != OrderAction::Buy
            || maker.outcome == taker.outcome
        {
            return Err(RuntimeError::InvalidOrder);
        }
        let market = self.markets.get(&maker.market_id).cloned().ok_or(RuntimeError::InvalidMarket)?;
        let collateral_atomic = settlement_atomic(&market, quantity)?;
        if maker_price_micros != maker.price_micros {
            return Err(RuntimeError::InvalidOrder);
        }
        let maker_amount = settlement_atomic(&market, resting_buy_fill_notional(maker, quantity)?)?;
        let taker_amount = collateral_atomic
            .checked_sub(maker_amount)
            .ok_or(RuntimeError::InvalidOrder)?;
        self.debit_order_hold(&maker.order_id.to_string(), maker_amount, true)?;
        self.debit_order_hold(
            &taker.order_id.to_string(),
            taker_amount
                .checked_add(taker_fee)
                .ok_or(RuntimeError::InvalidOrder)?,
            true,
        )?;
        *self
            .market_collateral
            .entry(maker.market_id.clone())
            .or_default() = self
            .market_collateral
            .get(&maker.market_id)
            .copied()
            .unwrap_or_default()
            .checked_add(collateral_atomic)
            .ok_or(RuntimeError::InvalidOrder)?;
        self.add_market_fee(&market, taker_fee)?;
        for (order, basis) in [(maker, maker_amount), (taker, taker_amount)] {
            let key = (
                order.private_user_id.clone(),
                order.market_id.clone(),
                order.outcome,
            );
            *self.positions.entry(key.clone()).or_default() = self
                .positions
                .get(&key)
                .copied()
                .unwrap_or_default()
                .checked_add(quantity)
                .ok_or(RuntimeError::InvalidOrder)?;
            *self.position_cost_basis.entry(key.clone()).or_default() = self
                .position_cost_basis
                .get(&key)
                .copied()
                .unwrap_or_default()
                .checked_add(basis)
                .ok_or(RuntimeError::InvalidOrder)?;
        }
        Ok(())
    }

    fn settle_merge_fill(
        &mut self,
        maker: &BookOrder,
        taker: &BookOrder,
        quantity: u128,
        maker_price_micros: u64,
        taker_fee: u128,
    ) -> Result<(), RuntimeError> {
        if maker.action != OrderAction::Sell
            || taker.action != OrderAction::Sell
            || maker.outcome == taker.outcome
        {
            return Err(RuntimeError::InvalidOrder);
        }
        self.debit_order_hold(&maker.order_id.to_string(), quantity, false)?;
        self.debit_order_hold(&taker.order_id.to_string(), quantity, false)?;
        let collateral = self
            .market_collateral
            .entry(maker.market_id.clone())
            .or_default();
        let market = self.markets.get(&maker.market_id).cloned().ok_or(RuntimeError::InvalidMarket)?;
        let collateral_atomic = settlement_atomic(&market, quantity)?;
        if *collateral < collateral_atomic {
            return Err(RuntimeError::InsufficientAvailable);
        }
        *collateral -= collateral_atomic;
        let maker_amount = settlement_atomic(&market, direct_notional(maker_price_micros, quantity)?)?;
        let taker_amount = collateral_atomic
            .checked_sub(maker_amount)
            .ok_or(RuntimeError::InvalidOrder)?;
        self.add_asset(&maker.private_user_id, &market.settlement_asset, "USER_AVAILABLE", maker_amount)?;
        self.add_asset(
            &taker.private_user_id,
            &market.settlement_asset,
            "USER_AVAILABLE",
            taker_amount
                .checked_sub(taker_fee)
                .ok_or(RuntimeError::InvalidOrder)?,
        )?;
        self.add_market_fee(&market, taker_fee)?;
        self.reduce_position_basis(
            &(
                maker.private_user_id.clone(),
                maker.market_id.clone(),
                maker.outcome,
            ),
            quantity,
        )?;
        self.reduce_position_basis(
            &(
                taker.private_user_id.clone(),
                taker.market_id.clone(),
                taker.outcome,
            ),
            quantity,
        )?;
        Ok(())
    }

    fn debit_order_hold(
        &mut self,
        order_id: &str,
        amount: u128,
        cash: bool,
    ) -> Result<(), RuntimeError> {
        let (owner, market_id) = {
            let reservation = self
                .orders
                .get_mut(order_id)
                .ok_or(RuntimeError::UnknownOrder)?;
            if reservation.hold_atomic < amount
                || (cash && reservation.order.action != OrderAction::Buy)
                || (!cash && reservation.order.action != OrderAction::Sell)
            {
                return Err(RuntimeError::InsufficientAvailable);
            }
            reservation.hold_atomic -= amount;
            (reservation.order.private_user_id.clone(), reservation.order.market_id.clone())
        };
        if cash {
            let asset = self.markets.get(&market_id).ok_or(RuntimeError::InvalidMarket)?.settlement_asset.clone();
            self.subtract_asset(&owner, &asset, "USER_ORDER_HOLD", amount)?;
        }
        Ok(())
    }

    fn release_excess_order_hold(&mut self, order_id: &str) -> Result<(), RuntimeError> {
        let (owner, action, desired, release, position_key) = {
            let reservation = self
                .orders
                .get(order_id)
                .ok_or(RuntimeError::UnknownOrder)?;
            // Remaining quantity describes the unfilled intent, not an active
            // entitlement. Terminal orders must never retain cash or positions.
            let desired = if !matches!(reservation.order.status, OrderStatus::Open | OrderStatus::PartiallyFilled) {
                0
            } else { match reservation.order.action {
                OrderAction::Buy => settlement_atomic(self.markets.get(&reservation.order.market_id).ok_or(RuntimeError::InvalidMarket)?, direct_notional(
                    reservation.order.price_micros,
                    reservation.order.remaining_micros,
                )?)?,
                OrderAction::Sell => reservation.order.remaining_micros,
            }};
            if reservation.hold_atomic < desired {
                return Err(RuntimeError::InvalidOrder);
            }
            (
                reservation.order.private_user_id.clone(),
                reservation.order.action,
                desired,
                reservation.hold_atomic - desired,
                (
                    reservation.order.private_user_id.clone(),
                    reservation.order.market_id.clone(),
                    reservation.order.outcome,
                ),
            )
        };
        if release > 0 {
            match action {
                OrderAction::Buy => {
                    let asset = self.markets.get(&position_key.1).ok_or(RuntimeError::InvalidMarket)?.settlement_asset.clone();
                    self.move_asset_bucket(&owner, &asset, "USER_ORDER_HOLD", "USER_AVAILABLE", release)?
                }
                OrderAction::Sell => {
                    *self.positions.entry(position_key.clone()).or_default() = self
                        .positions
                        .get(&position_key)
                        .copied()
                        .unwrap_or_default()
                        .checked_add(release)
                        .ok_or(RuntimeError::InvalidOrder)?;
                }
            }
        }
        self.orders
            .get_mut(order_id)
            .ok_or(RuntimeError::UnknownOrder)?
            .hold_atomic = desired;
        Ok(())
    }

    fn cancel_order(&mut self, identity: &str, order_id: &str) -> Result<u128, RuntimeError> {
        let reservation = self
            .orders
            .get(order_id)
            .cloned()
            .ok_or(RuntimeError::UnknownOrder)?;
        if reservation.order.private_user_id != identity {
            return Err(RuntimeError::IdentityDenied);
        }
        // Governed recovery for predecessor FOK rejections: these orders were
        // rejected before book insertion, but retained their original hold.
        // Preserve REJECTED, release only the recorded reservation, and make
        // subsequent owner requests harmless. Never bypass an active book order.
        if reservation.order.status == OrderStatus::Rejected
            && reservation.order.time_in_force == TimeInForce::Fok
            && reservation.order.filled_micros == 0
        {
            let book = self.books.get(&reservation.order.market_id)
                .ok_or(RuntimeError::InvalidMarket)?;
            if book.order(reservation.order.order_id).is_some() {
                return Err(RuntimeError::InvalidOrder);
            }
            self.release_excess_order_hold(order_id)?;
            return Ok(reservation.hold_atomic);
        }
        let mut book = self
            .books
            .get(&reservation.order.market_id)
            .cloned()
            .ok_or(RuntimeError::InvalidMarket)?;
        let cancelled = book
            .cancel(
                reservation.order.order_id,
                identity,
                reservation.order.updated_at_millis.saturating_add(1),
            )
            .map_err(|_| RuntimeError::InvalidOrder)?;
        self.books.insert(reservation.order.market_id.clone(), book);
        let release = reservation.hold_atomic;
        match reservation.order.action {
            OrderAction::Buy => {
                let asset = self.markets.get(&reservation.order.market_id).ok_or(RuntimeError::InvalidMarket)?.settlement_asset.clone();
                self.move_asset_bucket(identity, &asset, "USER_ORDER_HOLD", "USER_AVAILABLE", release)?
            }
            OrderAction::Sell => {
                let key = (
                    identity.to_string(),
                    reservation.order.market_id.clone(),
                    reservation.order.outcome,
                );
                *self.positions.entry(key.clone()).or_default() = self
                    .positions
                    .get(&key)
                    .copied()
                    .unwrap_or_default()
                    .checked_add(release)
                    .ok_or(RuntimeError::InvalidOrder)?;
            }
        }
        let record = self
            .orders
            .get_mut(order_id)
            .ok_or(RuntimeError::UnknownOrder)?;
        record.order = cancelled;
        record.hold_atomic = 0;
        Ok(release)
    }

    fn total_position(&self, key: &(String, String, Outcome)) -> u128 {
        let available = self.positions.get(key).copied().unwrap_or_default();
        self.orders
            .values()
            .filter(|record| {
                record.order.action == OrderAction::Sell
                    && record.order.private_user_id == key.0
                    && record.order.market_id == key.1
                    && record.order.outcome == key.2
            })
            .fold(available, |total, record| {
                total.saturating_add(record.hold_atomic)
            })
    }

    fn reduce_position_basis(
        &mut self,
        key: &(String, String, Outcome),
        quantity: u128,
    ) -> Result<(), RuntimeError> {
        let total_before = self
            .total_position(key)
            .checked_add(quantity)
            .ok_or(RuntimeError::InvalidOrder)?;
        let basis = self
            .position_cost_basis
            .get(key)
            .copied()
            .unwrap_or_default();
        let removed = if quantity == total_before {
            basis
        } else {
            basis
                .checked_mul(quantity)
                .ok_or(RuntimeError::InvalidOrder)?
                / total_before
        };
        self.position_cost_basis.insert(
            key.clone(),
            basis
                .checked_sub(removed)
                .ok_or(RuntimeError::InvalidOrder)?,
        );
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
    fn add_asset(&mut self, identity: &str, asset: &str, bucket: &str, value: u128) -> Result<(), RuntimeError> {
        let account = self.balances.get_mut(identity).ok_or(RuntimeError::IdentityDenied)?;
        let balance = account.entry((asset.into(), bucket.into())).or_default();
        *balance = balance.checked_add(value).ok_or(RuntimeError::InvalidRequest)?;
        Ok(())
    }
    fn subtract_asset(&mut self, identity: &str, asset: &str, bucket: &str, value: u128) -> Result<(), RuntimeError> {
        let account = self.balances.get_mut(identity).ok_or(RuntimeError::IdentityDenied)?;
        let balance = account.entry((asset.into(), bucket.into())).or_default();
        *balance = balance.checked_sub(value).ok_or(RuntimeError::InsufficientAvailable)?;
        Ok(())
    }
    fn add_market_fee(&mut self, market: &MarketConfig, value: u128) -> Result<(), RuntimeError> {
        let balance = if market.settlement_asset == "ZEN" { &mut self.zen_fee_revenue_atomic } else { &mut self.fee_revenue_atomic };
        *balance = balance.checked_add(value).ok_or(RuntimeError::InvalidOrder)?;
        Ok(())
    }
    fn move_asset_bucket(&mut self, identity: &str, asset: &str, from: &str, to: &str, value: u128) -> Result<(), RuntimeError> {
        let account = self.balances.get_mut(identity).ok_or(RuntimeError::IdentityDenied)?;
        let available = *account.get(&(asset.into(), from.into())).unwrap_or(&0);
        if available < value { return Err(RuntimeError::InsufficientAvailable); }
        let destination = account.get(&(asset.into(), to.into())).unwrap_or(&0).checked_add(value).ok_or(RuntimeError::InvalidRequest)?;
        account.insert((asset.into(), from.into()), available - value);
        account.insert((asset.into(), to.into()), destination);
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
    /// A full old-core fallback cannot discard active per-user holds. BFF/UI
    /// fallback may stop new admissions while the new runtime drains them.
    pub fn has_pending_usdc_bus_withdrawals(&self)->bool { !self.usdc_bus_withdrawals.is_empty() }
    pub fn pending_usdc_bus_withdrawal(&self,account:&str,id:&str)->Option<(String,String)> {
        self.usdc_bus_withdrawals.get(id).filter(|hold|hold.account_id==account)
            .map(|hold|(hold.destination.clone(),hold.amount_atomic.clone()))
    }
    pub fn portfolio(&self, identity: &str) -> Result<DirectPortfolio, RuntimeError> {
        let balances = self
            .balances
            .get(identity)
            .ok_or(RuntimeError::IdentityDenied)?
            .iter()
            .map(|((asset, bucket), amount)| DirectPortfolioBalance {
                asset: asset.clone(),
                bucket: bucket.clone(),
                amount_atomic: amount.to_string(),
            })
            .collect();
        let mut position_keys = self
            .positions
            .keys()
            .filter(|(owner, _, _)| owner == identity)
            .cloned()
            .collect::<BTreeSet<_>>();
        position_keys.extend(
            self.orders
                .values()
                .filter(|record| {
                    record.order.private_user_id == identity
                        && record.order.action == OrderAction::Sell
                        && record.hold_atomic > 0
                })
                .map(|record| {
                    (
                        identity.to_string(),
                        record.order.market_id.clone(),
                        record.order.outcome,
                    )
                }),
        );
        let positions = position_keys
            .into_iter()
            .filter_map(|key| {
                let available = self.positions.get(&key).copied().unwrap_or_default();
                let total = self.total_position(&key);
                (total > 0).then(|| DirectPortfolioPosition {
                    market_id: key.1.clone(),
                    outcome: key.2,
                    available_quantity_micros: available.to_string(),
                    total_quantity_micros: total.to_string(),
                    cost_basis_atomic: self
                        .position_cost_basis
                        .get(&key)
                        .copied()
                        .unwrap_or_default()
                        .to_string(),
                })
            })
            .collect();
        let open_orders = self
            .orders
            .values()
            .filter(|record| {
                record.order.private_user_id == identity
                    && matches!(
                        record.order.status,
                        OrderStatus::Open | OrderStatus::PartiallyFilled
                    )
            })
            .map(|record| DirectPortfolioOrder {
                order_id: record.order.order_id.to_string(),
                market_id: record.order.market_id.clone(),
                outcome: record.order.outcome,
                action: record.order.action,
                price_micros: record.order.price_micros,
                quantity_micros: record.order.quantity_micros.to_string(),
                filled_quantity_micros: record.order.filled_micros.to_string(),
                remaining_quantity_micros: record.order.remaining_micros.to_string(),
                time_in_force: record.order.time_in_force,
                expires_at_millis: record.order.expires_at_millis,
                status: record.order.status,
                hold_atomic: record.hold_atomic.to_string(),
            })
            .collect();
        Ok(DirectPortfolio {
            identity_commitment: identity.to_string(),
            balances,
            positions,
            open_orders,
            registered_market_ids: self
                .markets
                .keys()
                .filter(|market_id| !self.resolved_markets.contains_key(*market_id))
                .cloned()
                .collect(),
            genesis_ordinal: self.committed_sequence(),
        })
    }
    pub fn market_status(&self, market_id: &str) -> Option<DirectMarketStatus> {
        let market = self.markets.get(market_id)?.clone();
        let resolution = self.resolved_markets.get(market_id);
        Some(DirectMarketStatus {
            market,
            resolution_outcome: resolution.map(|value| value.outcome),
            resolution_evidence_sha256: resolution.map(|value| value.evidence_sha256.clone()),
            resolved_at_millis: resolution.map(|value| value.resolved_at_millis),
        })
    }
    pub fn owns(&self, subject: &str, identity: &str) -> bool {
        self.subject_identities
            .get(subject)
            .is_some_and(|ids| ids.contains(identity))
    }
    pub fn writer_enabled(&self) -> bool {
        matches!(
            self.mode,
            RuntimeMode::IsolatedTest | RuntimeMode::ProductionEnabled
        )
    }
    pub fn admission_enabled(&self) -> bool {
        self.mode != RuntimeMode::Dormant
    }
    pub fn identity_count(&self) -> usize {
        self.balances.len()
    }
    pub fn committed_state_hash(&self) -> String {
        self.state_hash()
    }
    pub fn committed_sequence(&self) -> u64 {
        self.requests.len() as u64
    }
}
pub fn identity_commitment_for(auth_subject_hash: &str, wallet_address: &str) -> String {
    sha256(
        format!(
            "{IDENTITY_ADMISSION_DOMAIN}{EPOCH_ID}\0{}\0{}",
            auth_subject_hash.to_ascii_lowercase(),
            wallet_address.to_ascii_lowercase(),
        )
        .as_bytes(),
    )
}

fn valid_evm_wallet(value: &str) -> bool {
    value.len() == 42
        && value.starts_with("0x")
        && value[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
        && value[2..].bytes().any(|byte| byte != b'0')
}
fn validate_direct_market(market: &MarketConfig, now_millis: i64) -> Result<(), RuntimeError> {
    let namespace =
        market.market_id.starts_with("layrs:v4:") || market.market_id.starts_with("layrs:v5:");
    if !namespace
        || !matches!((market.settlement_asset.as_str(), market.settlement_decimals), ("USDC", 6) | ("ZEN", 18))
        || (market.settlement_asset == "ZEN" && (!market.market_id.starts_with("layrs:v4:ZEN:") && !market.market_id.starts_with("layrs:v5:ZEN:ZEN:")))
        || (market.settlement_asset == "ZEN" && market.public_settlement_chain.as_deref() != Some("horizen"))
        || !matches!(
            market.public_settlement_chain.as_deref(),
            None | Some("base" | "horizen")
        )
        || !matches!(&market.execution, MarketExecution::NativeClob)
        || market.opens_at_millis >= market.closes_at_millis
        || market.closes_at_millis <= now_millis
        || market.minimum_quantity_micros == 0
        || market.minimum_quantity_micros > market.maximum_quantity_micros
        || market.maximum_quantity_micros > 1_000_000_000_000_000_000
        || market.minimum_order_notional_micros == 0
        || market.minimum_order_notional_micros > market.maximum_order_notional_micros
        || market.maximum_user_position_micros < market.maximum_quantity_micros
        || market.tick_size_micros == 0
        || market.tick_size_micros >= PRICE_SCALE as u64
        || !market.tick_size_micros.is_multiple_of(100)
        || market.oracle_feed_id == 0
    {
        Err(RuntimeError::InvalidMarket)
    } else {
        Ok(())
    }
}

/// Books and risk limits stay in token micros; custody balances use token atomics.
fn settlement_atomic(market: &MarketConfig, micros: u128) -> Result<u128, RuntimeError> {
    let scale = match (market.settlement_asset.as_str(), market.settlement_decimals) {
        ("USDC", 6) => 1,
        ("ZEN", 18) => 1_000_000_000_000,
        _ => return Err(RuntimeError::InvalidMarket),
    };
    micros.checked_mul(scale).ok_or(RuntimeError::InvalidOrder)
}

fn direct_notional(price_micros: u64, quantity_micros: u128) -> Result<u128, RuntimeError> {
    u128::from(price_micros)
        .checked_mul(quantity_micros)
        .and_then(|value| value.checked_add(PRICE_SCALE - 1))
        .map(|value| value / PRICE_SCALE)
        .ok_or(RuntimeError::InvalidOrder)
}

// Spend the difference between the rounded reservations before and after a
// resting buy fills. Rounding each fill independently can spend one micro that
// is still required by the remaining order. This telescopes across partial fills
// and preserves the existing fully backed remaining-hold check.
fn resting_buy_fill_notional(order: &BookOrder, quantity: u128) -> Result<u128, RuntimeError> {
    if order.action != OrderAction::Buy || quantity == 0 {
        return Err(RuntimeError::InvalidOrder);
    }
    let remaining = order.remaining_micros.checked_sub(quantity)
        .ok_or(RuntimeError::InvalidOrder)?;
    direct_notional(order.price_micros, order.remaining_micros)?
        .checked_sub(direct_notional(order.price_micros, remaining)?)
        .ok_or(RuntimeError::InvalidOrder)
}

fn direct_taker_fee(
    market: &MarketConfig,
    quantity_micros: u128,
    price_micros: u64,
) -> Result<u128, RuntimeError> {
    let price = u128::from(price_micros);
    if price == 0 || price >= PRICE_SCALE {
        return Err(RuntimeError::InvalidOrder);
    }
    let profile =
        serde_json::to_string(&market.fee_profile_id).map_err(|_| RuntimeError::InvalidMarket)?;
    let rate_bps = if profile.contains("CRYPTO_V2") {
        Some(700u128)
    } else if profile.contains("SPORTS_V2")
        || profile.contains("ESPORTS_V2")
        || profile.contains("MACRO_V2")
        || profile.contains("WEATHER_V2")
        || profile.contains("SCIENCE_V2")
        || profile.contains("CULTURE_V2")
        || profile.contains("GENERAL_V2")
    {
        Some(500)
    } else if profile.contains("FINANCE_V2")
        || profile.contains("POLITICS_V2")
        || profile.contains("TECHNOLOGY_V2")
        || profile.contains("MENTIONS_V2")
        || profile.contains("BUSINESS_V2")
    {
        Some(400)
    } else if profile.contains("GEOPOLITICS_V2") {
        Some(0)
    } else {
        None
    };
    let Some(rate_bps) = rate_bps else {
        let notional = direct_notional(price_micros, quantity_micros)?;
        return notional
            .checked_mul(20)
            .and_then(|value| value.checked_add(9_999))
            .map(|value| value / 10_000)
            .ok_or(RuntimeError::InvalidOrder);
    };
    if rate_bps == 0 || quantity_micros == 0 {
        return Ok(0);
    }
    let denominator = PRICE_SCALE
        .checked_mul(PRICE_SCALE)
        .and_then(|value| value.checked_mul(10_000))
        .ok_or(RuntimeError::InvalidOrder)?;
    let numerator = quantity_micros
        .checked_mul(price)
        .and_then(|value| value.checked_mul(PRICE_SCALE - price))
        .and_then(|value| value.checked_mul(rate_bps))
        .ok_or(RuntimeError::InvalidOrder)?;
    const FEE_QUANTUM: u128 = 10;
    numerator
        .checked_add(
            denominator
                .checked_mul(FEE_QUANTUM / 2)
                .ok_or(RuntimeError::InvalidOrder)?,
        )
        .map(|value| value / (denominator * FEE_QUANTUM) * FEE_QUANTUM)
        .ok_or(RuntimeError::InvalidOrder)
}

fn maximum_direct_taker_fee(
    market: &MarketConfig,
    quantity_micros: u128,
    limit_price_micros: u64,
) -> Result<u128, RuntimeError> {
    let profile =
        serde_json::to_string(&market.fee_profile_id).map_err(|_| RuntimeError::InvalidMarket)?;
    let reserve_price = if profile.contains("_V2") && limit_price_micros >= 500_000 {
        500_000
    } else {
        limit_price_micros
    };
    direct_taker_fee(market, quantity_micros, reserve_price)
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
    /// Independent receipt-key attestation. Existing runtime attestation and
    /// financial HMAC receipts retain their original protocol and bytes.
    QuestReceiptAttestation { nonce: Vec<u8> },
    PublicQuestReceipt { participant_account: String, receipt_account: String, request_id: String, nonce: Vec<u8> },
    PublicQuestReceiptJournal {
        participant_account: String,
        receipt_account: String,
        request_id: String,
        nonce: Vec<u8>,
        request_proof: request_index::SparseRequestProof,
        archived: v71::ArchivedTerminalRecord,
    },
    Status,
    /// First half of the production startup authorization. The enclave
    /// verifies the governed grant before creating an NSM-attested ephemeral
    /// recipient key. No writer state or key material is installed yet.
    BeginGovernedBootstrap {
        grant: WriterGrant,
        binding: RuntimeMeasurementBinding,
        kms_key_id: String,
        requested_mode: String,
    },
    /// Completes the same bounded startup exchange with KMS
    /// CiphertextForRecipient. Only the enclave can unwrap it. This is an
    /// authorization bootstrap, not a financial command lifecycle.
    CompleteGovernedBootstrap {
        writer_grant_commitment: String,
        key_release_artifact_hash: String,
        ciphertext_for_recipient: Vec<u8>,
        /// Existing parent durability-ACK credential. It is not a custody or
        /// ledger decryption key and is delivered only after grant validation.
        commit_ack_key: Vec<u8>,
    },
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
    ExecuteJournal {
        request: DirectRequest,
        request_proof: request_index::SparseRequestProof,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        archived: Option<v71::ArchivedTerminalRecord>,
    },
    /// The second, bounded frame of one direct request.  It is never stored as
    /// a workflow record: it merely proves that the parent read back the exact
    /// immutable candidate sent in the preceding frame.
    DurabilityAck {
        ack: DurabilityAck,
    },
    JournalDurabilityAck {
        ack: journal::JournalDurabilityAck,
    },
    BeginJournalRestore {
        checkpoint: v71_checkpoint::DirectV71Checkpoint,
    },
    AppendJournalRestore {
        record: journal::DirectJournalRecord,
    },
    FinishJournalRestore {
        expected_sequence: u64,
        expected_record_hash: String,
        expected_transition_root: String,
        expected_request_index_root: String,
        expected_financial_state_root: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        writer_fence_evidence_sha256: Option<String>,
    },
    SealJournalCheckpoint,
    /// Restores an authenticated checkpoint into a disposable runtime that is
    /// never installed as the writer. Parents use this before publishing each
    /// checkpoint; exact immutable readback then proves the published bytes
    /// are the bytes this non-writer restore accepted.
    VerifyJournalCheckpoint {
        checkpoint: v71_checkpoint::DirectV71Checkpoint,
    },
    /// Starts a non-authoritative v71 mirror from an instantaneous clone of
    /// the recovered v70 head. Migration sealing and bounded catch-up happen
    /// in the background while v70 remains the only writer.
    BeginV71Shadow {
        run_id: String,
    },
    V71ShadowStatus,
    /// Exports only already-committed shadow transitions. This is migration
    /// state, never a pending-command queue. The parent may durably stage it
    /// while v70 remains authoritative, then request a bounded final delta.
    ExportV71Shadow {
        run_id: String,
        after_sequence: u64,
        include_migration: bool,
    },
    /// Atomically promotes an exact, fully persisted shadow head inside the
    /// existing writer. No process restart or command buffering is involved.
    PromoteV71Shadow {
        run_id: String,
        expected_sequence: u64,
        expected_record_hash: String,
        expected_transition_root: String,
        expected_request_index_root: String,
        expected_financial_state_root: String,
    },
    SealV70Migration,
    SealV70RollbackCheckpoint {
        migration: migration::V70MigrationBundle,
        journal_records: Vec<journal::DirectJournalRecord>,
    },
    ActivateV71Migration {
        bundle: migration::V70MigrationBundle,
    },
    /// Startup-only handoff of immutable encrypted artifacts from the parent.
    /// The enclave reconstructs and verifies private state itself; PostgreSQL
    /// is never part of this input.
    RecoverCommitted {
        artifacts: Vec<DirectStateArtifact>,
    },
    BeginCommittedRestore,
    BeginCheckpointRestore { checkpoint: DirectCheckpoint },
    SealCheckpoint { artifact: DirectStateArtifact, receipt_records: Vec<DirectStateArtifact>, artifact_hashes: Vec<String> },
    AppendCommittedRestore { artifact: DirectStateArtifact },
    FinishCommittedRestore { expected_sequence: u64, expected_state_hash: String },
    Balance {
        account_id: String,
        identity_commitment: String,
        asset: String,
        bucket: String,
    },
    Portfolio {
        account_id: String,
        identity_commitment: String,
    },
    MarketStatus {
        market_id: String,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuntimeResponse {
    Attestation {
        document: Vec<u8>,
        binding: RuntimeBinding,
        binding_commitment: [u8; 32],
    },
    QuestReceiptAttestation {
        document: Vec<u8>, binding: RuntimeBinding,
        binding_commitment: [u8;32], public_key: Vec<u8>,
    },
    PublicQuestReceipt { witness: QuestReceiptWitness },
    Status {
        status: RuntimeStatus,
    },
    GovernedKeyRecipient {
        attestation_document: Vec<u8>,
        writer_grant_commitment: String,
        kms_key_id: String,
        encryption_context: BTreeMap<String, String>,
    },
    GovernedBootstrapComplete {
        writer_grant_commitment: String,
    },
    BootstrapComplete,
    Execute {
        result: DirectResult,
    },
    CommitCandidate {
        artifact: DirectStateArtifact,
    },
    JournalCandidate {
        record: journal::DirectJournalRecord,
        terminal_leaf: request_index::TerminalRequestLeaf,
    },
    JournalRestoreProgress {
        sequence: u64,
        record_hash: String,
        transition_root: String,
        request_index_root: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        receipt: Option<DirectReceipt>,
    },
    JournalRestoreComplete {
        writer_epoch: String,
        sequence: u64,
        record_hash: String,
        transition_root: String,
        request_index_root: String,
        financial_state_root: String,
    },
    JournalCheckpointSealed {
        checkpoint: v71_checkpoint::DirectV71Checkpoint,
    },
    JournalCheckpointVerified {
        writer_epoch: String,
        sequence: u64,
        record_hash: String,
        transition_root: String,
        request_index_root: String,
        financial_state_root: String,
    },
    V71ShadowStatus {
        run_id: String,
        phase: String,
        source_sequence: u64,
        sequence: u64,
        consecutive_matches: u64,
        observed_effects: Vec<String>,
    },
    V71ShadowExport {
        run_id: String,
        source_sequence: u64,
        writer_epoch: String,
        sequence: u64,
        record_hash: String,
        transition_root: String,
        request_index_root: String,
        financial_state_root: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        migration: Option<migration::V70MigrationBundle>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        base_checkpoint: Option<v71_checkpoint::DirectV71Checkpoint>,
        records: Vec<journal::DirectJournalRecord>,
        terminal_leaves: Vec<request_index::TerminalRequestLeaf>,
        results: Vec<DirectResult>,
    },
    V71ShadowPromoted {
        writer_epoch: String,
        sequence: u64,
        record_hash: String,
        transition_root: String,
        request_index_root: String,
        financial_state_root: String,
    },
    V70MigrationSealed {
        bundle: migration::V70MigrationBundle,
    },
    V71MigrationActivated {
        writer_epoch: String,
        sequence: u64,
        record_hash: String,
        transition_root: String,
        request_index_root: String,
        financial_state_root: String,
    },
    RecoveryComplete {
        recovered_sequence: u64,
        recovered_state_hash: String,
    },
    RestoreProgress { recovered_sequence: u64, recovered_state_hash: String },
    CheckpointSealed { checkpoint: DirectCheckpoint },
    Balance {
        amount_atomic: String,
    },
    Portfolio {
        portfolio: DirectPortfolio,
    },
    MarketStatus {
        market: Option<DirectMarketStatus>,
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
    pub admission_enabled: bool,
    pub identity_count: usize,
    pub projection_schema_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub writer_grant_commitment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub writer_grant_expires_at_unix: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_release_artifact_hash: Option<String>,
}
pub type RuntimeStatus = RuntimeBinding;

/// Return the deterministic JSON representation committed by direct-runtime
/// Nitro evidence. Object keys are lexicographically ordered and optional
/// fields are absent (never encoded as null). The schema is flat and contains
/// only JSON strings, booleans and non-negative integers, so this definition
/// has an exact, dependency-free browser implementation.
pub fn canonical_runtime_binding(binding: &RuntimeBinding) -> Vec<u8> {
    let mut fields = BTreeMap::<&str, serde_json::Value>::new();
    fields.insert("admissionEnabled", binding.admission_enabled.into());
    fields.insert(
        "epochStateSha256",
        binding.epoch_state_sha256.clone().into(),
    );
    fields.insert(
        "evidenceManifestSha256",
        binding.evidence_manifest_sha256.clone().into(),
    );
    fields.insert("genesisOrdinal", binding.genesis_ordinal.into());
    fields.insert("identityCount", binding.identity_count.into());
    if let Some(value) = &binding.key_release_artifact_hash {
        fields.insert("keyReleaseArtifactHash", value.clone().into());
    }
    fields.insert(
        "projectionSchemaVersion",
        binding.projection_schema_version.into(),
    );
    fields.insert("runtime", binding.runtime.clone().into());
    fields.insert("transactionModel", binding.transaction_model.clone().into());
    fields.insert("writerEnabled", binding.writer_enabled.into());
    if let Some(value) = &binding.writer_grant_commitment {
        fields.insert("writerGrantCommitment", value.clone().into());
    }
    if let Some(value) = binding.writer_grant_expires_at_unix {
        fields.insert("writerGrantExpiresAtUnix", value.into());
    }
    // BTreeMap ordering and these JSON scalar types make serialization
    // infallible. Avoid accepting a caller-supplied serialization of the
    // binding: the measured enclave owns this exact encoding.
    serde_json::to_vec(&fields).expect("runtime binding contains JSON scalar values only")
}

/// SHA-256(domain || canonical RuntimeBinding JSON). The raw 32-byte result is
/// placed in NSM user_data and also returned by the parent as lowercase hex.
pub fn runtime_binding_commitment(binding: &RuntimeBinding) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(DIRECT_RUNTIME_BINDING_DOMAIN);
    digest.update(canonical_runtime_binding(binding));
    digest.finalize().into()
}
pub fn runtime_binding(
    identity_count: usize,
    writer_enabled: bool,
    admission_enabled: bool,
    writer_grant_commitment: Option<String>,
    writer_grant_expires_at_unix: Option<u64>,
    key_release_artifact_hash: Option<String>,
) -> RuntimeBinding {
    RuntimeBinding {
        runtime: "layrs.direct-execution.nitro.v1".into(),
        transaction_model: TRANSACTION_MODEL.into(),
        epoch_state_sha256: EPOCH_STATE_SHA256.into(),
        evidence_manifest_sha256: EVIDENCE_MANIFEST_SHA256.into(),
        genesis_ordinal: 0,
        writer_enabled,
        admission_enabled,
        identity_count,
        projection_schema_version: PROJECTION_SCHEMA_VERSION,
        writer_grant_commitment,
        writer_grant_expires_at_unix,
        key_release_artifact_hash,
    }
}
pub fn request_hash(request: &DirectRequest) -> String {
    // A final transaction hash is an externally observed result, not customer
    // intent.  For an immutable external-effect intent the request binds the
    // stable provider reference, while the receipt/artifact still records the
    // exact resulting hash.  This makes startup recovery able to rebuild the
        // same direct request without mutating or extending the intent artifact.
    match &request.action {
        DirectAction::ReserveZenWithdrawal { destination_chain, destination, amount_atomic, custody_reference }
        | DirectAction::RecordZenWithdrawalReverted { destination_chain, destination, amount_atomic, custody_reference } => {
            let reference = custody_reference.split_once(':').map(|(reference, _)| reference).unwrap_or(custody_reference);
            sha256(&serde_json::to_vec(&(request.account_id.as_str(), request.identity_commitment.as_str(), request.request_id.as_str(),
                "RESERVE_ZEN_WITHDRAWAL", destination_chain, destination.to_ascii_lowercase(), amount_atomic, reference)).expect("ZEN withdrawal binding serializes"))
        }
        // `now_unix` is the enclave's observation used only to validate the
        // signed governance expiry. It is not part of the governed intent.
        // Excluding it keeps an exact HTTP retry stable across a parent or
        // enclave restart while the signed object itself remains hash-bound.
        DirectAction::RegisterMarket {
            registration,
            now_unix: _,
        } => sha256(
            &serde_json::to_vec(&(
                request.account_id.as_str(),
                request.identity_commitment.as_str(),
                request.request_id.as_str(),
                "REGISTER_MARKET",
                registration,
            ))
            .expect("serializable governed market registration"),
        ),
        DirectAction::ResolveMarket {
            resolution,
            now_unix: _,
        } => sha256(
            &serde_json::to_vec(&(
                request.account_id.as_str(),
                request.identity_commitment.as_str(),
                request.request_id.as_str(),
                "RESOLVE_MARKET",
                resolution,
            ))
            .expect("serializable governed market resolution"),
        ),
        DirectAction::GovernedBalanceRecovery {
            recovery,
            now_unix: _,
        } => sha256(
            &serde_json::to_vec(&(
                request.account_id.as_str(),
                request.identity_commitment.as_str(),
                request.request_id.as_str(),
                "GOVERNED_BALANCE_RECOVERY",
                recovery,
            ))
            .expect("serializable governed balance recovery"),
        ),
        DirectAction::ReserveWithdrawal {
            destination,
            amount_atomic,
            custody_reference,
        } if custody_reference.starts_with("lei-") => {
            let reference = custody_reference
                .split_once(':')
                .map(|(reference, _)| reference)
                .unwrap_or(custody_reference);
            sha256(
                &serde_json::to_vec(&(
                    request.account_id.as_str(),
                    request.identity_commitment.as_str(),
                    request.request_id.as_str(),
                    "RESERVE_WITHDRAWAL",
                    destination.to_ascii_lowercase(),
                    amount_atomic,
                    reference,
                ))
                .expect("serializable direct withdrawal request"),
            )
        }
        DirectAction::RecordWithdrawalReverted {
            destination,
            amount_atomic,
            custody_reference,
        } if custody_reference.starts_with("lei-") => {
            let reference = custody_reference
                .split_once(':')
                .map(|(reference, _)| reference)
                .unwrap_or(custody_reference);
            sha256(
                &serde_json::to_vec(&(
                    request.account_id.as_str(),
                    request.identity_commitment.as_str(),
                    request.request_id.as_str(),
                    "RESERVE_WITHDRAWAL",
                    destination.to_ascii_lowercase(),
                    amount_atomic,
                    reference,
                ))
                .expect("serializable reverted direct withdrawal request"),
            )
        }
        DirectAction::SettleRelayWithdrawal {
            relay,
            amount_atomic,
            custody_reference,
        }
        | DirectAction::RecordRelayWithdrawalReverted {
            relay,
            amount_atomic,
            custody_reference,
        } if custody_reference.starts_with("lei-") => {
            let reference = custody_reference
                .split_once(':')
                .map(|(reference, _)| reference)
                .unwrap_or(custody_reference);
            sha256(
                &serde_json::to_vec(&(
                    request.account_id.as_str(),
                    request.identity_commitment.as_str(),
                    request.request_id.as_str(),
                    "SETTLE_RELAY_WITHDRAWAL",
                    relay,
                    amount_atomic,
                    reference,
                ))
                .expect("serializable Relay withdrawal request"),
            )
        }
        _ => sha256(
            &serde_json::to_vec(&(
                request.account_id.as_str(),
                request.identity_commitment.as_str(),
                request.request_id.as_str(),
                &request.action,
            ))
            .expect("serializable direct request"),
        ),
    }
}

fn valid_withdrawal_custody_reference(reference: &str, mode: RuntimeMode) -> bool {
    if mode == RuntimeMode::IsolatedTest
        && (reference.starts_with("mock-") || reference.starts_with("isolated-"))
    {
        return true;
    }
    let Some((intent, transaction_hash)) = reference.split_once(':') else {
        return false;
    };
    intent.len() == 64
        && intent.starts_with("lei-")
        && intent[4..].bytes().all(|byte| byte.is_ascii_hexdigit())
        && transaction_hash.len() == 66
        && transaction_hash.starts_with("0x")
        && transaction_hash[2..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
}

fn valid_relay_withdrawal_custody_reference(
    reference: &str,
    relay: &RelayWithdrawalBinding,
    reverted: bool,
) -> bool {
    let parts = reference.split(':').collect::<Vec<_>>();
    if reverted {
        return parts.len() == 8
            && valid_external_effect_reference(parts[0])
            && parts[1] == "relay-reverted"
            && parts[2].eq_ignore_ascii_case(&relay.request_id)
            && parts[3] == relay.destination_chain_id.to_string()
            && valid_transaction_hash_value(parts[4])
            && matches!(parts[5], "failure" | "refund" | "refunded")
            && valid_sha256(parts[6])
            && parts[6] == relay_reverted_result_hash(relay, parts[0], parts[4], parts[5])
            && parts[7] == relay.binding_hash();
    }
    if parts.len() != 9
        || !valid_external_effect_reference(parts[0])
        || parts[1] != "relay"
        || !parts[2].eq_ignore_ascii_case(&relay.request_id)
        || parts[3] != relay.destination_chain_id.to_string()
        || !valid_transaction_hash_value(parts[4])
        || !valid_destination_transaction_hash(parts[5], relay.destination_chain_id)
        || positive_atomic_value(parts[6]).is_none()
        || !valid_sha256(parts[7])
        || parts[8] != relay.binding_hash()
    {
        return false;
    }
    let amount = positive_atomic_value(parts[6]).unwrap_or_default();
    let minimum =
        positive_atomic_value(&relay.minimum_destination_amount_atomic).unwrap_or(u128::MAX);
    amount >= minimum
        && parts[7] == relay_terminal_result_hash(relay, parts[0], parts[4], parts[5], parts[6])
}

fn valid_external_effect_reference(value: &str) -> bool {
    value.len() == 64
        && value.starts_with("lei-")
        && value[4..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_transaction_hash_value(value: &str) -> bool {
    value.len() == 66
        && value.starts_with("0x")
        && value[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_destination_transaction_hash(value: &str, chain_id: u64) -> bool {
    if chain_id == 792_703_809 {
        (64..=96).contains(&value.len()) && value.bytes().all(is_base58_value)
    } else {
        value.len() == 66
            && value.starts_with("0x")
            && value[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
    }
}

fn is_base58_value(byte: u8) -> bool {
    matches!(byte,
        b'1'..=b'9' | b'A'..=b'H' | b'J'..=b'N' | b'P'..=b'Z'
        | b'a'..=b'k' | b'm'..=b'z')
}

fn positive_atomic_value(value: &str) -> Option<u128> {
    value.parse::<u128>().ok().filter(|amount| *amount > 0)
}

fn valid_deposit_custody_reference(reference: &str) -> bool {
    let Some(transaction_hash) = reference.strip_prefix("base-deposit:") else {
        return false;
    };
    transaction_hash.len() == 66
        && transaction_hash.starts_with("0x")
        && transaction_hash[2..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
}
fn valid_bus_withdrawal_id(value:&str)->bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id|id.to_string()==value&&!id.is_nil())
}
fn valid_solana_wallet(value:&str)->bool {
    if !(32..=44).contains(&value.len()) {return false;}
    let alphabet=b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut bytes=Vec::<u8>::new();
    for character in value.bytes(){let Some(digit)=alphabet.iter().position(|byte|*byte==character) else{return false;};
        let mut carry=digit as u32;for byte in bytes.iter_mut().rev(){let next=u32::from(*byte)*58+carry;*byte=(next&255) as u8;carry=next>>8;}
        while carry>0 {bytes.insert(0,(carry&255) as u8);carry>>=8;}}
    value.bytes().take_while(|byte|*byte==b'1').count()+bytes.len()==32
}
pub fn valid_layrs_withdrawal_destination(chain:&str,asset:&str,destination:&str)->bool {
    match (chain,asset){
        ("arbitrum"|"base"|"ethereum"|"polygon"|"tempo","USDC")|("horizen","USDC.e")|("robinhood","USDG")=>valid_evm_wallet(destination)&&destination==destination.to_ascii_lowercase(),
        ("base"|"horizen","ZEN")=>valid_evm_wallet(destination)&&destination==destination.to_ascii_lowercase(),
        ("solana","USDC")=>valid_solana_wallet(destination),_=>false,
    }
}
fn valid_bus_deposit_reference(value:&str)->bool {
    let parts=value.split(':').collect::<Vec<_>>();
    parts.len()==3&&parts[0]=="arbitrum-usdc-bus-deposit"&&valid_transaction_hash_value(parts[1])
        &&parts[1]==parts[1].to_ascii_lowercase()
        &&parts[2].parse::<u128>().ok().is_some_and(|ticket|ticket<(1u128<<72)&&ticket.to_string()==parts[2])
}
fn valid_bus_terminal_reference(value:&str,reverted:bool)->bool {
    if !reverted {
        if let Some(hash)=value.strip_prefix("horizen-usdc-local:") {return valid_transaction_hash_value(hash)&&hash==hash.to_ascii_lowercase();}
        if let Some(hash)=value.strip_prefix("horizen-zen-local:").or_else(||value.strip_prefix("horizen-zen-oft:")) {
            return valid_transaction_hash_value(hash)&&hash==hash.to_ascii_lowercase();
        }
        if let Some(rest)=value.strip_prefix("horizen-usdc-relay:") {
            let parts=rest.split(':').collect::<Vec<_>>();
            return parts.len()==5&&parts[..4].iter().all(|hash|valid_transaction_hash_value(hash)&&*hash==hash.to_ascii_lowercase())
                &&(valid_transaction_hash_value(parts[4])&&parts[4]==parts[4].to_ascii_lowercase()
                    ||(64..=96).contains(&parts[4].len())&&parts[4].bytes().all(|byte|matches!(byte,
                        b'1'..=b'9'|b'A'..=b'H'|b'J'..=b'N'|b'P'..=b'Z'|b'a'..=b'k'|b'm'..=b'z')));
        }
    }
    if reverted {
        if let Some(hash)=value.strip_prefix("horizen-zen-reverted:") {return valid_transaction_hash_value(hash)&&hash==hash.to_ascii_lowercase();}
    }
    let prefix=if reverted {"horizen-usdc-bus-reverted:"} else {"horizen-usdc-bus:"};
    let Some(rest)=value.strip_prefix(prefix) else {return false;};
    let parts=rest.split(':').collect::<Vec<_>>();
    if parts.len()!=if reverted {1} else {5} {return false;}
    let hash_count=if reverted {1} else {3};
    if !parts[..hash_count].iter().all(|hash|valid_transaction_hash_value(hash)&&*hash==hash.to_ascii_lowercase()) {return false;}
    reverted || (parts[3].parse::<u8>().is_ok_and(|seat|seat<255&&seat.to_string()==parts[3])
        &&parts[4].parse::<u64>().is_ok_and(|index|index.to_string()==parts[4]))
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

/// PostgreSQL is an auditable projection only. Its balance rows are signed
/// receipt-derived read models and cannot be used to restore enclave state.
pub const POSTGRES_PROJECTION_DDL: &str =
    include_str!("../sql/001_direct_execution_projection.sql");

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn attestation_binding_vector() -> RuntimeBinding {
        RuntimeBinding {
            runtime: "layrs.direct-execution.nitro.v1".into(),
            transaction_model: "layrs.direct-execution.v1".into(),
            epoch_state_sha256: "11".repeat(32),
            evidence_manifest_sha256: "22".repeat(32),
            genesis_ordinal: 0,
            writer_enabled: true,
            admission_enabled: false,
            identity_count: 30,
            projection_schema_version: 1,
            writer_grant_commitment: Some("33".repeat(32)),
            writer_grant_expires_at_unix: Some(1_789_430_400),
            key_release_artifact_hash: Some("44".repeat(32)),
        }
    }

    #[test]
    fn direct_runtime_attestation_binding_is_canonical_and_tamper_evident() {
        let binding = attestation_binding_vector();
        let canonical = canonical_runtime_binding(&binding);
        assert_eq!(
            String::from_utf8(canonical).unwrap(),
            concat!(
                "{\"admissionEnabled\":false,",
                "\"epochStateSha256\":\"1111111111111111111111111111111111111111111111111111111111111111\",",
                "\"evidenceManifestSha256\":\"2222222222222222222222222222222222222222222222222222222222222222\",",
                "\"genesisOrdinal\":0,\"identityCount\":30,",
                "\"keyReleaseArtifactHash\":\"4444444444444444444444444444444444444444444444444444444444444444\",",
                "\"projectionSchemaVersion\":1,",
                "\"runtime\":\"layrs.direct-execution.nitro.v1\",",
                "\"transactionModel\":\"layrs.direct-execution.v1\",",
                "\"writerEnabled\":true,",
                "\"writerGrantCommitment\":\"3333333333333333333333333333333333333333333333333333333333333333\",",
                "\"writerGrantExpiresAtUnix\":1789430400}"
            )
        );
        let commitment = runtime_binding_commitment(&binding);
        assert_eq!(
            hex::encode(commitment),
            "979c32717f176b43e5f06004d30cceac55bf4f54c79e1de85d0cad88cad0a20e"
        );

        let mut tampered = binding.clone();
        tampered.writer_enabled = false;
        assert_ne!(runtime_binding_commitment(&tampered), commitment);
        let mut tampered = binding.clone();
        tampered.epoch_state_sha256 = "55".repeat(32);
        assert_ne!(runtime_binding_commitment(&tampered), commitment);
        let mut tampered = binding;
        tampered.writer_grant_commitment = None;
        assert_ne!(runtime_binding_commitment(&tampered), commitment);
    }
    fn epoch_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../../.codex-review-bundles/unified-direct-execution-20260905/new-epoch-20260911/OPENING_EPOCH_STATE_20260911.json")
    }
    fn request(id: &str, action: DirectAction) -> DirectRequest {
        request_for(
            "88fff7d9668cf8b00cd7faa0680d05c6415221e6ab28c5be7fa71e047054d8fc",
            "0bafc03d08d4951d769d58284db85c7ac2ee3c79de87ec680f58edc03017c418",
            id,
            action,
        )
    }
    fn request_for(subject: &str, identity: &str, id: &str, action: DirectAction) -> DirectRequest {
        let financial_wallet_address = match &action {
            DirectAction::CreditDeposit { .. } => {
                Some("0xfefefefefefefefefefefefefefefefefefefefe".into())
            }
            DirectAction::ReserveWithdrawal { destination, .. }
            | DirectAction::RecordWithdrawalReverted { destination, .. }
            | DirectAction::BeginUsdcBusWithdrawal { destination, .. }
            | DirectAction::SettleUsdcBusWithdrawal { destination, .. }
            | DirectAction::RevertUsdcBusWithdrawal { destination, .. } => {
                Some(destination.to_ascii_lowercase())
            }
            _ => None,
        };
        let mut r = DirectRequest {
            account_id: subject.into(),
            identity_commitment: identity.into(),
            request_id: id.into(),
            request_hash: String::new(),
            financial_wallet_address,
            action,
        };
        r.request_hash = request_hash(&r);
        r
    }
    fn market_registration_request(market_id: &str, request_id: &str) -> DirectRequest {
        let registration = GovernedMarketRegistration {
            registration_id: request_id.into(),
            epoch_id: EPOCH_ID.into(),
            runtime: TRANSACTION_MODEL.into(),
            market: isolated_market(market_id),
            expires_at_unix: 9_000,
            governance_key_id: GOVERNANCE_KEY_ID.into(),
            signing_algorithm: GOVERNANCE_SIGNING_ALGORITHM.into(),
            signature: "isolated-market-release".into(),
        };
        let mut request = DirectRequest {
            account_id: "governance".into(),
            identity_commitment: "governance".into(),
            request_id: request_id.into(),
            request_hash: String::new(),
            financial_wallet_address: None,
            action: DirectAction::RegisterMarket {
                registration,
                now_unix: 1,
            },
        };
        request.request_hash = request_hash(&request);
        request
    }
    fn market_resolution_request(
        market_id: &str,
        request_id: &str,
        outcome: DirectResolutionOutcome,
    ) -> DirectRequest {
        let resolution = GovernedMarketResolution {
            resolution_id: request_id.into(),
            epoch_id: EPOCH_ID.into(),
            runtime: TRANSACTION_MODEL.into(),
            market_id: market_id.into(),
            outcome,
            evidence_sha256: "a".repeat(64),
            resolved_at_millis: 10_000_000,
            expires_at_unix: 20_000,
            governance_key_id: GOVERNANCE_KEY_ID.into(),
            signing_algorithm: GOVERNANCE_SIGNING_ALGORITHM.into(),
            signature: "isolated-market-resolution".into(),
        };
        let mut request = DirectRequest {
            account_id: "governance".into(),
            identity_commitment: "governance".into(),
            request_id: request_id.into(),
            request_hash: String::new(),
            financial_wallet_address: None,
            action: DirectAction::ResolveMarket {
                resolution,
                now_unix: 10_000,
            },
        };
        request.request_hash = request_hash(&request);
        request
    }
    fn runtime(mode: RuntimeMode) -> DirectRuntime {
        DirectRuntime::new(SealedEpoch::load(epoch_path()).unwrap(), mode, vec![7; 32]).unwrap()
    }

    fn runtime_with_one_usdc_minimum_market(
        market_id: &str,
        identity: &str,
        position_quantity: u128,
    ) -> DirectRuntime {
        let mut live = runtime(RuntimeMode::IsolatedTest);
        let mut registration = market_registration_request(market_id, "full-close-market");
        let DirectAction::RegisterMarket { registration: release, .. } = &mut registration.action else {
            unreachable!()
        };
        release.market.minimum_order_notional_micros = 1_000_000;
        registration.request_hash = request_hash(&registration);
        live.execute(registration).unwrap();
        live.positions.insert(
            (identity.to_string(), market_id.to_string(), Outcome::Up),
            position_quantity,
        );
        live
    }

    #[test]
    fn fractional_partial_buy_fill_preserves_remaining_hold_and_cash_on_mint_and_normal() {
        const MARKET: &str = "layrs:v5:BTC:USDC:1h:rounding-canary";
        const MAKER: &str = "0bafc03d08d4951d769d58284db85c7ac2ee3c79de87ec680f58edc03017c418";
        const TAKER: &str = "9bf6b307e41f94a5f5ec4211d2ac9eb5e4f2743b25224573391d7e8903276481";
        fn cash(live: &DirectRuntime) -> u128 {
            live.balances.values().flat_map(|a| a.iter())
                .filter(|((asset, _), _)| asset == "USDC").map(|(_, v)| *v).sum::<u128>()
                + live.market_collateral.values().sum::<u128>() + live.fee_revenue_atomic
        }
        for normal in [false, true] {
            let mut live = runtime_with_one_usdc_minimum_market(MARKET, TAKER, 0);
            live.add_asset(MAKER, "USDC", "USER_AVAILABLE", 5_000_000).unwrap();
            live.add_asset(TAKER, "USDC", "USER_AVAILABLE", 6_000_000).unwrap();
            if normal {
                live.positions.insert((TAKER.into(), MARKET.into(), Outcome::Down), 1_137_656);
            }
            let before = cash(&live);
            let maker_id = Uuid::from_u128(401).to_string();
            live.place_order(MAKER, &maker_id, MARKET, Outcome::Down, OrderAction::Buy,
                154_000, "10000000", TimeInForce::Gtc, None, 1_000).unwrap();
            assert_eq!(live.orders[&maker_id].hold_atomic, 1_540_000);
            let (outcome, action, price) = if normal {
                (Outcome::Down, OrderAction::Sell, 154_000)
            } else {
                (Outcome::Up, OrderAction::Buy, 879_000)
            };
            let result = live.place_order(TAKER, &Uuid::from_u128(402).to_string(), MARKET,
                outcome, action, price, "1137656", TimeInForce::Fak, None, 1_000).unwrap();
            assert_eq!(result.trades.len(), 1);
            assert_eq!(result.executed_quantity_micros, "1137656");
            let maker = &live.orders[&maker_id];
            assert_eq!(maker.order.remaining_micros, 8_862_344);
            assert_eq!(maker.hold_atomic, 1_364_801);
            assert_eq!(maker.hold_atomic, direct_notional(154_000, maker.order.remaining_micros).unwrap());
            assert_eq!(cash(&live), before);
            assert_eq!(live.cancel_order(MAKER, &maker_id).unwrap(), 1_364_801);
            assert_eq!(live.orders[&maker_id].hold_atomic, 0);
            assert_eq!(cash(&live), before);
        }
    }

    #[test]
    fn fractional_partial_buy_reservations_telescope_and_reject_overfills() {
        for price in [100, 154_000, 333_300, 500_000, 846_000, 999_900] {
            let mut order = BookOrder::with_id(Uuid::from_u128(501), "maker", "market",
                Outcome::Down, OrderAction::Buy, price, 10_000_000, TimeInForce::Gtc, None);
            let mut paid = 0;
            for quantity in [1_137_656, 1, 1_153_847, 2_600_013, 5_108_483] {
                let debit = resting_buy_fill_notional(&order, quantity).unwrap();
                assert!(debit <= quantity);
                paid += debit;
                order.remaining_micros -= quantity;
                assert_eq!(paid + direct_notional(price, order.remaining_micros).unwrap(),
                    direct_notional(price, 10_000_000).unwrap());
            }
            assert_eq!(order.remaining_micros, 0);
            assert_eq!(resting_buy_fill_notional(&order, 1), Err(RuntimeError::InvalidOrder));
            assert_eq!(resting_buy_fill_notional(&order, 0), Err(RuntimeError::InvalidOrder));
        }
    }

    #[test]
    fn fractional_partial_mint_replays_once_after_restart_with_backed_remaining_order() {
        const MARKET: &str = "layrs:v5:BTC:USDC:1h:rounding-replay";
        const TAKER_SUBJECT: &str = "bae54f222a79c2ea394fa5b087d6a843e4b82562d0f3dfa33b8149b4beea21b3";
        const TAKER: &str = "9bf6b307e41f94a5f5ec4211d2ac9eb5e4f2743b25224573391d7e8903276481";
        let epoch = SealedEpoch::load(epoch_path()).unwrap();
        let mut live = DirectRuntime::new(epoch.clone(), RuntimeMode::IsolatedTest, vec![7;32]).unwrap();
        let mut store = InMemoryDirectStateStore::default();
        live.execute_committed(market_registration_request(MARKET, "rounding-market"), &[8;32], &mut store).unwrap();
        let maker_id = Uuid::from_u128(601).to_string();
        live.execute_committed(request("rounding-maker", DirectAction::PlaceOrder {
            order_id: maker_id.clone(), market_id: MARKET.into(), outcome: Outcome::Down,
            action: OrderAction::Buy, price_micros: 154_000, quantity_micros: "10000000".into(),
            time_in_force: TimeInForce::Gtc, expires_at_millis: None, now_millis: 1_000,
        }), &[8;32], &mut store).unwrap();
        let taker = request_for(TAKER_SUBJECT, TAKER, "rounding-taker", DirectAction::PlaceOrder {
            order_id: Uuid::from_u128(602).to_string(), market_id: MARKET.into(), outcome: Outcome::Up,
            action: OrderAction::Buy, price_micros: 879_000, quantity_micros: "1137656".into(),
            time_in_force: TimeInForce::Fak, expires_at_millis: None, now_millis: 2_000,
        });
        let result = live.execute_committed(taker.clone(), &[8;32], &mut store).unwrap();
        assert_eq!(live.orders[&maker_id].hold_atomic, 1_364_801);
        let hash = live.state_hash();
        let count = store.artifacts().unwrap().len();
        let mut restored = DirectRuntime::restore_committed(epoch, RuntimeMode::IsolatedTest,
            vec![7;32], &[8;32], &store).unwrap();
        for _ in 0..3 {
            assert_eq!(restored.execute_committed(taker.clone(), &[8;32], &mut store).unwrap(), result);
            assert_eq!(restored.state_hash(), hash);
            assert_eq!(store.artifacts().unwrap().len(), count);
            assert_eq!(restored.orders[&maker_id].hold_atomic, 1_364_801);
        }
    }

    #[test]
    fn direct_runtime_allows_only_exact_full_position_sell_below_minimum_notional() {
        const MARKET: &str = "layrs:v5:BTC:USDC:1h:full-close";
        const IDENTITY: &str = "full-close-identity";
        const POSITION: u128 = 1_919_385;

        let mut exact = runtime_with_one_usdc_minimum_market(MARKET, IDENTITY, POSITION);
        assert!(exact
            .place_order(
                IDENTITY,
                &Uuid::from_u128(1).to_string(),
                MARKET,
                Outcome::Up,
                OrderAction::Sell,
                490_000,
                &POSITION.to_string(),
                TimeInForce::Gtc,
                None,
                1_000,
            )
            .is_ok());

        let mut partial = runtime_with_one_usdc_minimum_market(MARKET, IDENTITY, POSITION);
        assert_eq!(
            partial.place_order(
                IDENTITY,
                &Uuid::from_u128(2).to_string(),
                MARKET,
                Outcome::Up,
                OrderAction::Sell,
                490_000,
                &(POSITION - 1).to_string(),
                TimeInForce::Gtc,
                None,
                1_000,
            ),
            Err(RuntimeError::InvalidOrder)
        );

        let mut buy = runtime_with_one_usdc_minimum_market(MARKET, IDENTITY, POSITION);
        assert_eq!(
            buy.place_order(
                IDENTITY,
                &Uuid::from_u128(3).to_string(),
                MARKET,
                Outcome::Up,
                OrderAction::Buy,
                490_000,
                &POSITION.to_string(),
                TimeInForce::Gtc,
                None,
                1_000,
            ),
            Err(RuntimeError::InvalidOrder)
        );
    }

    #[test]
    fn opening_state_hash_matches_existing_production_lineage() {
        let runtime = runtime(RuntimeMode::IsolatedTest);
        assert_eq!(runtime.committed_sequence(), 0);
        assert_eq!(
            runtime.state_hash(),
            "9fc0fd8e9699d23dcbb6fd85753035896dce219f6551a0540ea352c7089abe98"
        );
    }
    #[test]
    fn all_six_zen_windows_conserve_token_custody_through_fills_cancel_resolution_withdraw_and_restart() {
        const ONE: u128 = 1_000_000_000_000_000_000;
        for window in ["15m", "1h", "4h", "1d", "1w", "1mo"] {
            let epoch = SealedEpoch::load(epoch_path()).unwrap();
            let mut live = DirectRuntime::new(epoch.clone(), RuntimeMode::IsolatedTest, vec![7;32]).unwrap();
            let mut store = InMemoryDirectStateStore::default();
            let market_id = format!("layrs:v4:ZEN:{window}:1789344000");
            let mut registration = market_registration_request(&market_id,"zen-register");
            let DirectAction::RegisterMarket { registration: release, .. } = &mut registration.action else { unreachable!() };
            release.market.settlement_asset = "ZEN".into();
            release.market.settlement_decimals = 18;
            release.market.oracle_feed_id = 9001;
            registration.request_hash = request_hash(&registration);
            live.execute_committed(registration, &[8;32], &mut store).unwrap();
            let maker = "a".repeat(64);
            let taker = "b".repeat(64);
            let maker_wallet = "0x1111111111111111111111111111111111111111";
            let taker_wallet = "0x2222222222222222222222222222222222222222";
            let maker_id = identity_commitment_for(&maker,maker_wallet);
            let taker_id = identity_commitment_for(&taker,taker_wallet);
            for (subject,identity,wallet,hash) in [(&maker,&maker_id,maker_wallet,"1"),(&taker,&taker_id,taker_wallet,"2")] {
                live.execute_committed(request_for(subject,identity,"zen-admit",DirectAction::AdmitIdentity { wallet_address:wallet.into() }),&[8;32],&mut store).unwrap();
                let mut deposit = request_for(subject,identity,"zen-deposit",DirectAction::CreditZenDeposit {amount_atomic:(3*ONE).to_string(),custody_reference:format!("horizen-zen-deposit:0x{}",hash.repeat(64))});
                deposit.financial_wallet_address = Some(wallet.into());deposit.request_hash = request_hash(&deposit);
                let result=live.execute_committed(deposit.clone(),&[8;32],&mut store).unwrap();
                assert_eq!(result.effect,"DEPOSIT_CREDITED");
                assert_eq!(live.execute_committed(deposit,&[8;32],&mut store).unwrap(),result);
                assert_eq!(live.balance(identity,"ZEN","USER_AVAILABLE"),3*ONE);
                assert_eq!(live.balance(identity,"USDC","USER_AVAILABLE"),0);
            }
            let mut sequence=0u128;
            let order = |sequence:&mut u128, subject:&str,identity:&str,outcome,action,price,quantity| {
                *sequence+=1;
                let id=Uuid::from_u128(0x11111111222243338444000000000000+*sequence).to_string();
                (id.clone(),request_for(subject,identity,&format!("zen-order-{sequence}"),DirectAction::PlaceOrder {order_id:id,market_id:market_id.clone(),outcome,action,price_micros:price,quantity_micros:quantity,time_in_force:TimeInForce::Gtc,expires_at_millis:None,now_millis:1000}))
            };
            let (_,buy_up)=order(&mut sequence,&maker,&maker_id,Outcome::Up,OrderAction::Buy,400_000,"1000000".into());
            live.execute_committed(buy_up,&[8;32],&mut store).unwrap();
            let (_,buy_down)=order(&mut sequence,&taker,&taker_id,Outcome::Down,OrderAction::Buy,600_000,"1000000".into());
            let fill=live.execute_committed(buy_down.clone(),&[8;32],&mut store).unwrap();
            assert_eq!(fill.receipt.execution.as_ref().unwrap().trades[0].match_type,MatchType::Mint);
            assert_eq!(fill.receipt.execution.as_ref().unwrap().total_fee_atomic,"16800000000000000");
            assert_eq!(live.market_collateral.get(&market_id),Some(&ONE));
            assert_eq!(live.fee_revenue_atomic,0);
            let (sell_id,sell_up)=order(&mut sequence,&maker,&maker_id,Outcome::Up,OrderAction::Sell,450_000,"1000000".into());
            live.execute_committed(sell_up,&[8;32],&mut store).unwrap();
            let (_,normal_buy)=order(&mut sequence,&taker,&taker_id,Outcome::Up,OrderAction::Buy,450_000,"500000".into());
            let normal=live.execute_committed(normal_buy,&[8;32],&mut store).unwrap();
            assert_eq!(normal.receipt.execution.as_ref().unwrap().trades[0].match_type,MatchType::Normal);
            live.execute_committed(request_for(&maker,&maker_id,"zen-cancel",DirectAction::CancelOrder {order_id:sell_id}),&[8;32],&mut store).unwrap();
            assert_eq!(live.total_position(&(maker_id.clone(),market_id.clone(),Outcome::Up)),500_000);
            let (_,merge_up)=order(&mut sequence,&maker,&maker_id,Outcome::Up,OrderAction::Sell,400_000,"500000".into());
            live.execute_committed(merge_up,&[8;32],&mut store).unwrap();
            let (_,merge_down)=order(&mut sequence,&taker,&taker_id,Outcome::Down,OrderAction::Sell,600_000,"500000".into());
            let merge=live.execute_committed(merge_down,&[8;32],&mut store).unwrap();
            assert_eq!(merge.receipt.execution.as_ref().unwrap().trades[0].match_type,MatchType::Merge);
            let resolution=market_resolution_request(&market_id,"zen-resolution",DirectResolutionOutcome::Up);
            let settled=live.execute_committed(resolution.clone(),&[8;32],&mut store).unwrap();
            assert_eq!(settled.receipt.resolution.as_ref().unwrap().gross_payout_atomic,(ONE/2).to_string());
            assert_eq!(live.balance(&maker_id,"ZEN","USER_ORDER_HOLD"),0);
            assert_eq!(live.balance(&taker_id,"ZEN","USER_ORDER_HOLD"),0);
            assert_eq!(live.balance(&maker_id,"ZEN","USER_AVAILABLE")+live.balance(&taker_id,"ZEN","USER_AVAILABLE")+live.zen_fee_revenue_atomic+live.zen_rounding_reserve_atomic,6*ONE);
            for chain in ["base","horizen"] {
                let mut withdrawal=request_for(&maker,&maker_id,&format!("zen-withdraw-{chain}"),DirectAction::ReserveZenWithdrawal {destination_chain:chain.into(),destination:maker_wallet.into(),amount_atomic:(ONE/10).to_string(),custody_reference:format!("isolated-{chain}")});
                withdrawal.financial_wallet_address=Some(maker_wallet.into());withdrawal.request_hash=request_hash(&withdrawal);
                live.execute_committed(withdrawal,&[8;32],&mut store).unwrap();
            }
            let state_hash=live.state_hash();
            let mut restored=DirectRuntime::restore_committed(epoch,RuntimeMode::IsolatedTest,vec![7;32],&[8;32],&store).unwrap();
            assert_eq!(restored.state_hash(),state_hash);
            assert_eq!(restored.execute_committed(buy_down,&[8;32],&mut store).unwrap(),fill);
            assert_eq!(restored.execute_committed(resolution,&[8;32],&mut store).unwrap(),settled);
            assert_eq!(restored.state_hash(),state_hash);
            assert_eq!(restored.balance(&maker_id,"USDC","USER_AVAILABLE"),0);
            assert_eq!(restored.balance(&maker_id,"ZEN","USER_SETTLED"),ONE/5);
        }
    }

    #[test]
    fn zen_market_registration_rejects_wrong_token_precision_chain_and_family() {
        let mut market=isolated_market("layrs:v4:ZEN:15m:1789344000");
        market.settlement_asset="ZEN".into();market.settlement_decimals=18;
        assert!(validate_direct_market(&market,1).is_ok());
        market.settlement_decimals=6;assert!(validate_direct_market(&market,1).is_err());
        market.settlement_decimals=18;market.public_settlement_chain=Some("base".into());assert!(validate_direct_market(&market,1).is_err());
        market.public_settlement_chain=Some("horizen".into());market.market_id="layrs:v5:BTC:ZEN:15m:1789344000".into();assert!(validate_direct_market(&market,1).is_err());
    }
    fn isolated_market(market_id: &str) -> MarketConfig {
        MarketConfig {
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
        }
    }
    fn register_isolated_market(runtime: &mut DirectRuntime, market_id: &str, request_id: &str) {
        runtime
            .execute(market_registration_request(market_id, request_id))
            .unwrap();
    }
    #[test]
    fn governed_request_hash_excludes_only_parent_observed_validation_time() {
        let mut registration = market_registration_request(
            "layrs:v5:BTC:USDC:15m:governed-replay-hash",
            "governed-registration-replay-hash",
        );
        let original_registration_hash = registration.request_hash.clone();
        let DirectAction::RegisterMarket { now_unix, .. } = &mut registration.action else {
            unreachable!()
        };
        *now_unix = 2;
        assert_eq!(request_hash(&registration), original_registration_hash);

        let mut resolution_request = market_resolution_request(
            "layrs:v5:BTC:USDC:15m:governed-replay-hash",
            "governed-resolution-replay-hash",
            DirectResolutionOutcome::Up,
        );
        let original_resolution_hash = resolution_request.request_hash.clone();
        let DirectAction::ResolveMarket { now_unix, .. } = &mut resolution_request.action else {
            unreachable!()
        };
        *now_unix = 10_001;
        assert_eq!(request_hash(&resolution_request), original_resolution_hash);

        let DirectAction::ResolveMarket { resolution, .. } = &mut resolution_request.action else {
            unreachable!()
        };
        resolution.evidence_sha256 = "b".repeat(64);
        assert_ne!(request_hash(&resolution_request), original_resolution_hash);
    }
    #[test]
    fn loads_exact_sealed_epoch() {
        let epoch = SealedEpoch::load(epoch_path()).unwrap();
        assert_eq!(epoch.identity_count(), 438);
        assert_eq!(epoch.projection_rows().len(), 322);
        assert_eq!(epoch.projection_wallet_rows().len(), 414);
    }
    #[test]
    fn immediate_withdrawal_accepts_any_explicit_valid_destination_and_is_idempotent() {
        let mut r = runtime(RuntimeMode::IsolatedTest);
        // This address is also present in the opening auth-wallet mapping.
        // It is accepted only because the customer supplied it explicitly as
        // the action destination; the runtime never selected it from Privy.
        let q = request(
            "withdrawal-customer-selected-destination",
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
    fn relay_withdrawal_adopts_only_bound_destination_finality_and_replays_after_restart() {
        let identity = "0bafc03d08d4951d769d58284db85c7ac2ee3c79de87ec680f58edc03017c418";
        let relay = RelayWithdrawalBinding {
            route_id: "11111111-2222-4333-8444-555555555555".into(),
            request_id: format!("0x{}", "aa".repeat(32)),
            deposit_address: "0x2222222222222222222222222222222222222222".into(),
            destination_chain_id: 42_161,
            destination_currency: "0xaf88d065e77c8cc2239327c5edb3a432268e5831".into(),
            recipient: "0x3333333333333333333333333333333333333333".into(),
            quoted_destination_amount_atomic: "999000".into(),
            minimum_destination_amount_atomic: "998000".into(),
            quote_payload_sha256: "44".repeat(32),
            expires_at_unix: 10_000,
        };
        let reference = format!("lei-{}", "77".repeat(30));
        let intake = format!("0x{}", "55".repeat(32));
        let destination = format!("0x{}", "66".repeat(32));
        let delivered = "998500";
        let result =
            relay_terminal_result_hash(&relay, &reference, &intake, &destination, delivered);
        let custody_reference = format!(
            "{reference}:relay:{}:{}:{intake}:{destination}:{delivered}:{result}:{}",
            relay.request_id,
            relay.destination_chain_id,
            relay.binding_hash(),
        );
        let action = DirectAction::SettleRelayWithdrawal {
            relay: relay.clone(),
            amount_atomic: "1000000".into(),
            custody_reference: custody_reference.clone(),
        };
        let state_key = [9u8; 32];
        let mut store = InMemoryDirectStateStore::default();
        let mut live = runtime(RuntimeMode::IsolatedTest);

        let mut intake_only = request(
            "relay-intake-only",
            DirectAction::SettleRelayWithdrawal {
                relay: relay.clone(),
                amount_atomic: "1000000".into(),
                custody_reference: format!("{reference}:{intake}"),
            },
        );
        intake_only.financial_wallet_address = None;
        intake_only.request_hash = request_hash(&intake_only);
        assert_eq!(
            live.execute(intake_only),
            Err(RuntimeError::DestinationDenied)
        );
        assert_eq!(live.balance(identity, "USDC", "USER_AVAILABLE"), 5_000_000);

        let command = request("relay-terminal", action);
        live.execute_committed(command.clone(), &state_key, &mut store)
            .unwrap();
        assert_eq!(live.balance(identity, "USDC", "USER_AVAILABLE"), 4_000_000);
        let mut restored = DirectRuntime::restore_committed(
            SealedEpoch::load(epoch_path()).unwrap(),
            RuntimeMode::IsolatedTest,
            vec![7; 32],
            &state_key,
            &store,
        )
        .unwrap();
        assert_eq!(
            restored.balance(identity, "USDC", "USER_AVAILABLE"),
            4_000_000
        );
        let replay = restored
            .execute_committed(command, &state_key, &mut store)
            .unwrap();
        assert_eq!(replay.receipt.effect, "WITHDRAWAL_SETTLED");
        assert_eq!(
            restored.balance(identity, "USDC", "USER_AVAILABLE"),
            4_000_000
        );
        assert_eq!(store.artifacts().unwrap().len(), 1);
    }
    fn bus_fixture()->(DirectRuntime,String,String,String,InMemoryDirectStateStore) {
        bus_fixture_funded("10000000")
    }
    fn bus_fixture_funded(funded:&str)->(DirectRuntime,String,String,String,InMemoryDirectStateStore) {
        let mut live=runtime(RuntimeMode::IsolatedTest);
        let mut store=InMemoryDirectStateStore::default();
        let subject="a".repeat(64);
        let wallet="0x1111111111111111111111111111111111111111".to_string();
        let identity=identity_commitment_for(&subject,&wallet);
        live.execute_committed(request_for(&subject,&identity,"bus-admission",DirectAction::AdmitIdentity {wallet_address:wallet.clone()}),&[8;32],&mut store).unwrap();
        let mut deposit=request_for(&subject,&identity,"bus-deposit",DirectAction::CreditHorizenUsdcDeposit {
            amount_atomic:funded.into(),custody_reference:format!("horizen-usdc-deposit:0x{}","ab".repeat(32))});
        deposit.financial_wallet_address=Some(wallet.clone());deposit.request_hash=request_hash(&deposit);
        live.execute_committed(deposit,&[8;32],&mut store).unwrap();
        (live,subject,identity,wallet,store)
    }
    const BUS_ID:&str="11111111-2222-4333-8444-555555555555";
    fn conditional_fixture()->(DirectRuntime,String,String,String,InMemoryDirectStateStore,DirectRequest) {
        let mut live=runtime(RuntimeMode::IsolatedTest);let mut store=InMemoryDirectStateStore::default();
        let subject="a".repeat(64);let wallet="0x1111111111111111111111111111111111111111".to_string();
        let identity=identity_commitment_for(&subject,&wallet);
        live.execute_committed(request_for(&subject,&identity,"conditional-admission",DirectAction::AdmitIdentity {wallet_address:wallet.clone()}),&[8;32],&mut store).unwrap();
        let mut credit=request_for(&subject,&identity,&format!("usdc-bus-deposit-credit:{BUS_ID}"),DirectAction::CreditArbitrumUsdcBusDeposit {
            operation_id:BUS_ID.into(),amount_atomic:"5000000".into(),custody_reference:format!("arbitrum-usdc-bus-deposit:0x{}:7","ab".repeat(32))});
        credit.financial_wallet_address=Some(wallet.clone());credit.request_hash=request_hash(&credit);
        (live,subject,identity,wallet,store,credit)
    }
    #[test]
    fn conditional_bus_credit_trades_before_pool_finality_and_settles_without_second_balance_credit() {
        let (mut live,subject,identity,wallet,mut store,credit)=conditional_fixture();
        let result=live.execute_committed(credit.clone(),&[8;32],&mut store).unwrap();
        assert_eq!(result.effect,"DEPOSIT_CONDITIONALLY_CREDITED");assert_eq!(live.balance(&identity,"USDC","USER_AVAILABLE"),5_000_000);
        live.execute_committed(market_registration_request("layrs:v5:BTC:USDC:15m:conditional","conditional-market-registration"),&[8;32],&mut store).unwrap();
        let order=request_for(&subject,&identity,"conditional-order",DirectAction::PlaceOrder {
            order_id:"33333333-2222-4333-8444-555555555555".into(),market_id:"layrs:v5:BTC:USDC:15m:conditional".into(),outcome:Outcome::Up,action:OrderAction::Buy,
            price_micros:500_000,quantity_micros:"2000000".into(),time_in_force:TimeInForce::Gtc,expires_at_millis:None,now_millis:1000});
        live.execute_committed(order,&[8;32],&mut store).unwrap();
        assert!(live.balance(&identity,"USDC","USER_ORDER_HOLD")>=1_000_000);
        let mut withdrawal=bus_begin(&subject,&identity,&wallet,"22222222-2222-4333-8444-555555555555");
        if let DirectAction::BeginUsdcBusWithdrawal {amount_atomic,..}=&mut withdrawal.action {*amount_atomic="1000000".into();}
        withdrawal.request_hash=request_hash(&withdrawal);let root=live.committed_state_hash();
        assert_eq!(live.execute_committed(withdrawal.clone(),&[8;32],&mut store),Err(RuntimeError::InsufficientAvailable));
        assert_eq!(live.committed_state_hash(),root);
        let mut finalized=request_for(&subject,&identity,&format!("usdc-bus-deposit-finalize:{BUS_ID}"),DirectAction::FinalizeArbitrumUsdcBusDeposit {
            operation_id:BUS_ID.into(),amount_atomic:"5000000".into(),boarding_reference:result.receipt.custody_reference.clone().unwrap(),
            custody_reference:format!("horizen-usdc-deposit:0x{}","cd".repeat(32))});
        finalized.financial_wallet_address=Some(wallet);finalized.request_hash=request_hash(&finalized);
        let available=live.balance(&identity,"USDC","USER_AVAILABLE");
        assert_eq!(live.execute_committed(finalized.clone(),&[8;32],&mut store).unwrap().effect,"DEPOSIT_FINALIZED");
        assert_eq!(live.balance(&identity,"USDC","USER_AVAILABLE"),available);
        live.execute_committed(finalized,&[8;32],&mut store).unwrap();
        assert_eq!(live.balance(&identity,"USDC","USER_AVAILABLE"),available);
        assert!(live.execute_committed(withdrawal,&[8;32],&mut store).is_ok());
    }
    #[test]
    fn conditional_bus_credit_replays_after_restart_and_cannot_use_legacy_pool_credit_twice() {
        let (mut live,subject,identity,wallet,mut store,credit)=conditional_fixture();
        let credited=live.execute_committed(credit.clone(),&[8;32],&mut store).unwrap();
        let mut restored=DirectRuntime::restore_committed(SealedEpoch::load(epoch_path()).unwrap(),RuntimeMode::IsolatedTest,vec![7;32],&[8;32],&store).unwrap();
        let count=store.artifacts().unwrap().len();assert_eq!(restored.execute_committed(credit,&[8;32],&mut store).unwrap(),credited);
        assert_eq!(store.artifacts().unwrap().len(),count);assert_eq!(restored.balance(&identity,"USDC","USER_AVAILABLE"),5_000_000);
        let mut legacy=request_for(&subject,&identity,"legacy-pool-credit",DirectAction::CreditHorizenUsdcDeposit {
            amount_atomic:"5000000".into(),custody_reference:format!("horizen-usdc-deposit:0x{}","cd".repeat(32))});
        legacy.financial_wallet_address=Some(wallet);legacy.request_hash=request_hash(&legacy);
        assert_eq!(restored.execute_committed(legacy,&[8;32],&mut store),Err(RuntimeError::InvalidRequest));
    }
    #[test]
    fn conditional_bus_credit_rejects_subminimum_changed_identity_amount_ticket_and_operation() {
        for change in ["minimum","reference","wallet","operation","request"] {
            let (mut live,_,_,_,mut store,mut credit)=conditional_fixture();let root=live.committed_state_hash();
            if let DirectAction::CreditArbitrumUsdcBusDeposit {operation_id,amount_atomic,custody_reference}=&mut credit.action {
                match change {"minimum"=>*amount_atomic="4999999".into(),"reference"=>*custody_reference="arbitrum-usdc-bus-deposit:invalid:7".into(),
                    "operation"=>*operation_id="22222222-2222-4333-8444-555555555555".into(),_=>{}}
            }
            if change=="wallet" {credit.financial_wallet_address=Some("0x2222222222222222222222222222222222222222".into());}
            if change=="request" {credit.request_id="another-request".into();}credit.request_hash=request_hash(&credit);
            assert!(live.execute_committed(credit,&[8;32],&mut store).is_err());assert_eq!(live.committed_state_hash(),root);
        }
    }
    #[test]
    fn conditional_bus_credit_restore_rejects_missing_or_changed_pending_restrictions() {
        let (mut live,_,_,_,mut store,credit)=conditional_fixture();
        live.execute_committed(credit,&[8;32],&mut store).unwrap();
        validate_conditional_deposits(&live.snapshot(),&live.receipt_key).unwrap();
        for variant in ["missing","wallet","identity","amount","reference","operation"] {
            let mut state=live.snapshot();
            if variant=="missing" {state.conditional_usdc_deposits.clear();}
            else if variant=="operation" {state.credited_custody_references.remove(&format!("arbitrum-usdc-bus-operation:{BUS_ID}"));}
            else {let pending=state.conditional_usdc_deposits.get_mut(BUS_ID).unwrap();match variant {
                "wallet"=>pending.wallet_address="0x2222222222222222222222222222222222222222".into(),
                "identity"=>pending.identity_commitment="f".repeat(64),"amount"=>pending.amount_atomic="4999999".into(),
                _=>pending.boarding_reference=format!("arbitrum-usdc-bus-deposit:0x{}:8","ab".repeat(32))
            }}
            assert_eq!(validate_conditional_deposits(&state,&live.receipt_key),Err(RuntimeError::StateArtifact),"{variant}");
        }
    }
    fn checkpoint_fixture(live: &DirectRuntime, store: &InMemoryDirectStateStore) -> DirectCheckpoint {
        let mut artifacts = store.artifacts().unwrap();artifacts.sort_by_key(|artifact|artifact.sequence);
        let records = artifacts.iter().cloned().map(|mut record| { record.ciphertext.clear(); record }).collect();
        let hashes = artifacts.iter().map(artifact_hash).collect();
        live.seal_checkpoint(artifacts.last().unwrap().clone(), records, hashes, &[8;32]).unwrap()
    }
    #[test]
    fn checkpoint_4827_resumes_with_4828_without_reexecuting_prior_requests() {
        // Synthetic compact-prefix fixture: signed requests and the final
        // encrypted snapshot are real runtime outputs; intermediate roots,
        // ciphertext/object hashes are placeholders. Archive authentication
        // is tested separately, not certified by this counter-size fixture.
        let (mut live, subject, identity, wallet, store) = bus_fixture();
        let artifacts = store.artifacts().unwrap();
        let mut records: Vec<_> = artifacts.iter().cloned().map(|mut record| { record.ciphertext = Vec::new(); record }).collect();
        let mut hashes: Vec<_> = artifacts.iter().map(artifact_hash).collect();
        let mut last_request = None;
        while live.committed_sequence() < 4827 {
            let prior = records.last().unwrap().state_hash.clone();
            let id = Uuid::from_u128(0x11111111222243338444000000000000 + live.committed_sequence() as u128).to_string();
            let request = request_for(&subject,&identity,&id,
                DirectAction::BeginUsdcBusWithdrawal { withdrawal_id:id.clone(),destination_chain:"arbitrum".into(),asset:"USDC".into(),destination:wallet.clone(),amount_atomic:"999999999999999".into() });
            let result = live.execute(request.clone()).unwrap();
            let record = DirectStateArtifact { epoch_id: EPOCH_ID.into(), sequence: live.committed_sequence(), prior_state_hash: prior,
                state_hash: sha256(&live.committed_sequence().to_be_bytes()), request_hash: request.request_hash.clone(), nonce: vec![0;12], ciphertext: Vec::new(), ciphertext_hash: sha256(&[]), receipt: result.receipt };
            hashes.push(artifact_hash(&record)); records.push(record); last_request = Some(request);
        }
        let last = records.last().unwrap();
        let head = live.seal_artifact(&last.prior_state_hash,&last.request_hash,&[8;32],last.receipt.clone()).unwrap();
        *hashes.last_mut().unwrap() = artifact_hash(&head);
        let mut compact = head.clone(); compact.ciphertext = Vec::new(); *records.last_mut().unwrap() = compact;
        let checkpoint = live.seal_checkpoint(head,records,hashes,&[8;32]).unwrap();
        assert!(serde_cbor::to_vec(&RuntimeRequest::BeginCheckpointRestore { checkpoint: checkpoint.clone() }).unwrap().len() < 64*1024*1024);
        let mut recovered = runtime(RuntimeMode::IsolatedTest).restore_checkpoint(&checkpoint,&[8;32]).unwrap();
        assert_eq!(recovered.committed_sequence(),4827);
        assert_eq!(recovered.portfolio(&identity).unwrap(),live.portfolio(&identity).unwrap());
        let before = recovered.committed_state_hash();
        assert!(recovered.existing_result(&last_request.unwrap()).unwrap().is_some());
        assert_eq!(recovered.committed_state_hash(),before);
        let candidate = live.prepare_candidate(bus_begin(&subject,&identity,&wallet,BUS_ID),&[8;32]).unwrap();
        recovered = recovered.restore_next_committed(&candidate.artifact,&[8;32]).unwrap();
        assert_eq!(recovered.committed_sequence(),4828);
        assert_eq!(recovered.committed_state_hash(),candidate.runtime.committed_state_hash());
    }
    #[test]
    fn checkpoint_preserves_money_identity_deduplication_and_pending_bus_holds() {
        let (mut live, subject, identity, wallet, mut store) = bus_fixture();
        let reserve = bus_begin(&subject, &identity, &wallet, BUS_ID);
        let result = live.execute_committed(reserve.clone(), &[8;32], &mut store).unwrap();
        let checkpoint = checkpoint_fixture(&live, &store);
        let mut restarted = runtime(RuntimeMode::IsolatedTest).restore_checkpoint(&checkpoint, &[8;32]).unwrap();
        assert_eq!(restarted.committed_sequence(), 3);
        assert_eq!(restarted.committed_state_hash(), live.committed_state_hash());
        assert_eq!(restarted.portfolio(&identity).unwrap(), live.portfolio(&identity).unwrap());
        assert_eq!(restarted.pending_usdc_bus_withdrawal(&subject, BUS_ID), live.pending_usdc_bus_withdrawal(&subject, BUS_ID));
        assert_eq!(restarted.execute_committed(reserve, &[8;32], &mut store).unwrap(), result);
        assert_eq!(store.artifacts().unwrap().len(), 3);
        assert!(restarted.execute(bus_begin(&subject,&identity,&wallet,"22222222-2222-4333-8444-555555555555")).is_err());
    }
    #[test]
    fn checkpoint_rejects_tampering_missing_receipts_wrong_keys_and_epoch() {
        let (live, _, _, _, store) = bus_fixture();
        let checkpoint = checkpoint_fixture(&live, &store);
        let mut corruptions = Vec::new();
        let mut changed = checkpoint.clone(); changed.artifact.sequence += 1; corruptions.push(changed);
        let mut changed = checkpoint.clone(); changed.artifact.ciphertext[0] ^= 1; corruptions.push(changed);
        let mut changed = checkpoint.clone(); changed.receipt_records.pop(); corruptions.push(changed);
        let mut changed = checkpoint.clone(); changed.receipt_records[0].receipt.account_id = "b".repeat(64); corruptions.push(changed);
        let mut changed = checkpoint.clone(); changed.artifact_hashes[0] = "b".repeat(64); corruptions.push(changed);
        let mut changed = checkpoint.clone(); changed.opening_state_hash = "b".repeat(64); corruptions.push(changed);
        let mut changed = checkpoint.clone(); changed.artifact.epoch_id = "another-epoch".into(); corruptions.push(changed);
        let mut changed = checkpoint.clone(); changed.signature.clear(); corruptions.push(changed);
        for changed in corruptions { assert!(runtime(RuntimeMode::IsolatedTest).restore_checkpoint(&changed, &[8;32]).is_err()); }
        assert!(runtime(RuntimeMode::IsolatedTest).restore_checkpoint(&checkpoint, &[9;32]).is_err());
        let other_receipt_key = DirectRuntime::new(SealedEpoch::load(epoch_path()).unwrap(), RuntimeMode::IsolatedTest, vec![9;32]).unwrap();
        assert!(other_receipt_key.restore_checkpoint(&checkpoint, &[8;32]).is_err());
        assert!(live.restore_checkpoint(&checkpoint, &[8;32]).is_err());
    }
    #[test]
    fn checkpoint_verifies_only_the_committed_suffix_and_rejects_gaps() {
        let (mut live, subject, identity, wallet, mut store) = bus_fixture();
        let checkpoint = checkpoint_fixture(&live, &store);
        live.execute_committed(bus_begin(&subject,&identity,&wallet,BUS_ID), &[8;32], &mut store).unwrap();
        let artifact = store.artifacts().unwrap().into_iter().max_by_key(|artifact|artifact.sequence).unwrap();
        let candidate = runtime(RuntimeMode::IsolatedTest).restore_checkpoint(&checkpoint, &[8;32]).unwrap();
        let mut gap = artifact.clone(); gap.sequence += 1;
        assert!(candidate.clone().restore_next_committed(&gap, &[8;32]).is_err());
        let restored = candidate.restore_next_committed(&artifact, &[8;32]).unwrap();
        assert_eq!(restored.committed_state_hash(), live.committed_state_hash());
        assert_eq!(restored.committed_sequence(), 3);
    }
    #[test]
    fn checkpoint_frontier_rejects_older_snapshot_or_same_sequence_fork() {
        let (live, _, _, _, store) = bus_fixture(); let checkpoint = checkpoint_fixture(&live,&store);
        let frontier = CommittedRestoreFrontier { sequence: checkpoint.artifact.sequence, state_hash: checkpoint.artifact.state_hash.clone(), artifact_hash: artifact_hash(&checkpoint.artifact) };
        assert!(frontier.accepts_checkpoint(&checkpoint));
        let mut changed = frontier.clone(); changed.sequence += 1; assert!(!changed.accepts_checkpoint(&checkpoint));
        let mut changed = frontier.clone(); changed.state_hash = "a".repeat(64); assert!(!changed.accepts_checkpoint(&checkpoint));
        let mut changed = frontier.clone(); changed.artifact_hash = "a".repeat(64); assert!(!changed.accepts_checkpoint(&checkpoint));
        let mut changed = frontier; changed.sequence = 0; assert!(!changed.valid()); assert!(!changed.accepts_checkpoint(&checkpoint));
        let mut boundary = changed;
        boundary.sequence = MAX_V70_LINEAGE_RECORDS as u64;
        assert!(boundary.valid());
        boundary.sequence += 1;
        assert!(!boundary.valid());
    }
    #[test]
    fn checkpoint_bootstrap_certificate_binds_exact_snapshot_history_and_existing_governance_key() {
        use p256::ecdsa::{SigningKey, signature::Signer};
        let (live, _, _, _, store) = bus_fixture();
        let mut checkpoint = checkpoint_fixture(&live, &store); checkpoint.signature.clear();
        let signing_key = SigningKey::from_bytes((&[3u8;32]).into()).unwrap();
        let mut certificate = CheckpointBootstrapCertificate::for_checkpoint(&checkpoint).unwrap();
        let signature: Signature = signing_key.sign(&certificate.unsigned_bytes().unwrap());
        certificate.signature = STANDARD.encode(signature.to_der().as_bytes());
        assert!(certificate.verify_with_key(&checkpoint, signing_key.verifying_key()));
        assert!(!certificate.verify(&checkpoint)); // test keys NEVER authorize production recovery
        let mut changed = checkpoint.clone(); changed.receipt_records[0].prior_state_hash = "b".repeat(64);
        assert!(!certificate.verify_with_key(&changed, signing_key.verifying_key()));
        let mut changed = checkpoint.clone(); changed.artifact_hashes[0] = "b".repeat(64);
        assert!(!certificate.verify_with_key(&changed, signing_key.verifying_key()));
        let mut wrong_domain = certificate.clone(); wrong_domain.protocol = "layrs.direct-execution.writer-grant.v1".into();
        assert!(!wrong_domain.verify_with_key(&checkpoint, signing_key.verifying_key()));
        checkpoint.bootstrap_certificate = Some(certificate);
        assert!(runtime(RuntimeMode::IsolatedTest).restore_checkpoint(&checkpoint, &[8;32]).is_err());
    }
    #[test]
    fn public_quest_witness_is_owned_read_only_and_stable_after_recovery() {
        let (live,subject,identity,_,store)=bus_fixture();
        let before=(live.committed_sequence(),live.committed_state_hash(),live.portfolio(&identity).unwrap(),store.artifacts().unwrap());
        let key=quest_receipt_public_key(&[7;32]).unwrap();
        let witness=live.quest_receipt_witness(&subject,&subject,"bus-deposit",&[42;32]).unwrap();
        assert_eq!(witness.lookup.public_receipt_hash,quest_public_receipt_hash(&witness.receipt).unwrap());
        assert_eq!(witness.lookup.participant_account,subject);
        assert_eq!(witness.lookup.request_id,"bus-deposit");
        let public=openssl::pkey::PKey::public_key_from_raw_bytes(&key,openssl::pkey::Id::ED25519).unwrap();
        let payload=serde_json::to_vec(&serde_json::to_value(&witness.lookup).unwrap()).unwrap();
        let signature=hex::decode(&witness.lookup_signature).unwrap();
        assert!(openssl::sign::Verifier::new_without_digest(&public).unwrap().verify_oneshot(&signature,&[b"layrs.direct-receipt-lookup-signature.v1\0".as_slice(),&payload].concat()).unwrap());
        let mut changed=witness.lookup.clone();changed.request_id="another-deposit".into();
        let payload=serde_json::to_vec(&serde_json::to_value(changed).unwrap()).unwrap();
        assert!(!openssl::sign::Verifier::new_without_digest(&public).unwrap().verify_oneshot(&signature,&[b"layrs.direct-receipt-lookup-signature.v1\0".as_slice(),&payload].concat()).unwrap());
        assert!(live.quest_receipt_witness(&subject,&subject,"bus-deposit",&[42;31]).is_err());
        for (request,kind) in [("bus-admission",QuestReceiptKind::IdentityAdmission),("bus-deposit",QuestReceiptKind::Deposit)] {
            let witness=live.public_quest_receipt(&subject,&subject,request).unwrap();
            assert_eq!(witness.payload.kind,kind);
            assert!(verify_public_quest_receipt(&witness,&key));
            assert_eq!(witness.payload.enclave_sequence,"2");
            assert_eq!(witness.payload.state_root,before.1);
            let public=serde_json::to_string(&witness).unwrap();
            for private in [&subject,&identity,&request.to_string(),&"10000000".to_string()] {assert!(!public.contains(private));}
            let restored=DirectRuntime::restore_committed(SealedEpoch::load(epoch_path()).unwrap(),RuntimeMode::IsolatedTest,vec![7;32],&[8;32],&store).unwrap();
            assert_eq!(restored.public_quest_receipt(&subject,&subject,request).unwrap(),witness);
        }
        assert_eq!(before,(live.committed_sequence(),live.committed_state_hash(),live.portfolio(&identity).unwrap(),store.artifacts().unwrap()));
        assert_eq!(live.public_quest_receipt(&"b".repeat(64),&subject,"bus-deposit").unwrap_err(),RuntimeError::IdentityDenied);
        assert_eq!(live.public_quest_receipt(&subject,&"b".repeat(64),"bus-deposit").unwrap_err(),RuntimeError::InvalidRequest);
        assert_eq!(live.public_quest_receipt(&subject,&subject,"not-committed").unwrap_err(),RuntimeError::InvalidRequest);
        let dormant=runtime(RuntimeMode::Dormant);
        assert_eq!(dormant.public_quest_receipt(&subject,&subject,"bus-deposit").unwrap_err(),RuntimeError::WriterDisabled);
    }
    #[test]
    fn public_quest_witness_rejects_modified_payload_keys_and_private_receipts() {
        let (mut live,subject,_,_,_)=bus_fixture();
        let witness=live.public_quest_receipt(&subject,&subject,"bus-deposit").unwrap();
        let key=quest_receipt_public_key(&[7;32]).unwrap();
        assert!(!verify_public_quest_receipt(&witness,&quest_receipt_public_key(&[6;32]).unwrap()));
        assert!(!verify_public_quest_receipt(&witness,&[]));
        let value=serde_json::to_value(&witness).unwrap();
        for (field,replacement) in [
            ("protocol",serde_json::json!("other")),("epochId",serde_json::json!("other")),
            ("receiptId",serde_json::json!(format!("receipt_{}","a".repeat(64)))),
            ("participantCommitment",serde_json::json!("b".repeat(64))),
            ("kind",serde_json::json!("PRIVATE_FILL")),("enclaveSequence",serde_json::json!("3")),
            ("enclaveSequence",serde_json::json!("02")),("enclaveSequence",serde_json::json!("0")),
            ("enclaveSequence",serde_json::json!("18446744073709551616")),
            ("stateRoot",serde_json::json!("c".repeat(64))),
            ("commandCommitment",serde_json::json!("d".repeat(64))),
        ] {
            let mut changed=value.clone();changed["payload"][field]=replacement;
            assert!(!verify_public_quest_receipt(&serde_json::from_value(changed).unwrap(),&key),"{field}");
        }
        let mut changed=witness.clone();changed.signature.replace_range(..2,"00");
        assert!(!verify_public_quest_receipt(&changed,&key));
        changed=witness.clone();changed.public_key="00".repeat(32);
        assert!(!verify_public_quest_receipt(&changed,&key));
        let mut extra=value;extra["payload"]["amount"]=serde_json::json!("5000000");
        assert!(serde_json::from_value::<PublicQuestReceipt>(extra).is_err());
        live.requests.get_mut(&(subject.clone(),"bus-deposit".into())).unwrap().1.receipt.signature="00".repeat(32);
        assert_eq!(live.public_quest_receipt(&subject,&subject,"bus-deposit").unwrap_err(),RuntimeError::StateArtifact);
    }
    #[test]
    fn public_quest_withdrawal_witness_requires_committed_terminal_settlement() {
        let (mut live,subject,identity,wallet,mut store)=bus_fixture();
        live.execute_committed(bus_begin(&subject,&identity,&wallet,BUS_ID),&[8;32],&mut store).unwrap();
        assert_eq!(live.public_quest_receipt(&subject,&subject,BUS_ID).unwrap_err(),RuntimeError::InvalidRequest);
        let terminal=bus_terminal(&subject,&identity,&wallet,false);
        let request_id=terminal.request_id.clone();
        live.execute_committed(terminal,&[8;32],&mut store).unwrap();
        let witness=live.public_quest_receipt(&subject,&subject,&request_id).unwrap();
        assert_eq!(witness.payload.kind,QuestReceiptKind::Withdrawal);
        assert!(verify_public_quest_receipt(&witness,&quest_receipt_public_key(&[7;32]).unwrap()));
    }
    fn bus_begin(subject:&str,identity:&str,wallet:&str,id:&str)->DirectRequest {
        request_for(subject,identity,id,DirectAction::BeginUsdcBusWithdrawal {withdrawal_id:id.into(),destination_chain:"arbitrum".into(),asset:"USDC".into(),destination:wallet.into(),amount_atomic:"4840000".into()})
    }
    fn bus_terminal(subject:&str,identity:&str,wallet:&str,reverted:bool)->DirectRequest {
        let custody=if reverted {format!("horizen-usdc-bus-reverted:0x{}","ef".repeat(32))}
            else {format!("horizen-usdc-bus:0x{}:0x{}:0x{}:0:1","11".repeat(32),"22".repeat(32),"33".repeat(32))};
        let action=if reverted {DirectAction::RevertUsdcBusWithdrawal {withdrawal_id:BUS_ID.into(),destination_chain:"arbitrum".into(),asset:"USDC".into(),destination:wallet.into(),amount_atomic:"4840000".into(),custody_reference:custody}}
            else {DirectAction::SettleUsdcBusWithdrawal {withdrawal_id:BUS_ID.into(),destination_chain:"arbitrum".into(),asset:"USDC".into(),destination:wallet.into(),amount_atomic:"4840000".into(),custody_reference:custody}};
        request_for(subject,identity,&format!("usdc-bus-{}:{BUS_ID}",if reverted {"revert"} else {"settle"}),action)
    }
    #[test]
    fn usdc_bus_reservation_is_committed_once_and_survives_restart() {
        let (mut live,subject,identity,wallet,mut store)=bus_fixture();
        let begin=bus_begin(&subject,&identity,&wallet,BUS_ID);
        let first=live.execute_committed(begin.clone(),&[8;32],&mut store).unwrap();
        assert_eq!(first.effect,"WITHDRAWAL_RESERVED");
        assert_eq!(live.balance(&identity,"USDC","USER_AVAILABLE"),5_160_000);
        assert_eq!(live.balance(&identity,"USDC","USER_WITHDRAWAL_HOLD"),4_840_000);
        assert!(live.has_pending_usdc_bus_withdrawals());
        assert_eq!(live.execute_committed(begin.clone(),&[8;32],&mut store).unwrap(),first);
        let mut restarted=DirectRuntime::restore_committed(SealedEpoch::load(epoch_path()).unwrap(),RuntimeMode::IsolatedTest,vec![7;32],&[8;32],&store).unwrap();
        assert!(restarted.has_pending_usdc_bus_withdrawals());assert_eq!(restarted.pending_usdc_bus_withdrawal(&subject,BUS_ID),Some((wallet.clone(),"4840000".into())));
        assert_eq!(restarted.pending_usdc_bus_withdrawal(&"b".repeat(64),BUS_ID),None);
        assert_eq!(restarted.execute_committed(begin,&[8;32],&mut store).unwrap(),first);
    }
    #[test]
    fn zen_egress_uses_the_same_restart_safe_hold_and_exactly_once_terminal_path() {
        let (mut live,subject,identity,wallet,mut store)=bus_fixture_funded("5000000");
        let mut deposit=request_for(&subject,&identity,"zen-egress-funding",DirectAction::CreditZenDeposit {
            amount_atomic:"1000000000000000000".into(),custody_reference:format!("horizen-zen-deposit:0x{}","aa".repeat(32))});
        deposit.financial_wallet_address=Some(wallet.clone());deposit.request_hash=request_hash(&deposit);
        live.execute_committed(deposit,&[8;32],&mut store).unwrap();
        let begin=request_for(&subject,&identity,BUS_ID,DirectAction::BeginUsdcBusWithdrawal {withdrawal_id:BUS_ID.into(),
            destination_chain:"base".into(),asset:"ZEN".into(),destination:wallet.clone(),amount_atomic:"1000000000000000000".into()});
        let reserved=live.execute_committed(begin.clone(),&[8;32],&mut store).unwrap();
        assert_eq!(reserved.effect,"WITHDRAWAL_RESERVED");
        assert_eq!(live.balance(&identity,"ZEN","USER_AVAILABLE"),0);
        assert_eq!(live.balance(&identity,"ZEN","USER_WITHDRAWAL_HOLD"),1_000_000_000_000_000_000);
        let mut restarted=DirectRuntime::restore_committed(SealedEpoch::load(epoch_path()).unwrap(),RuntimeMode::IsolatedTest,vec![7;32],&[8;32],&store).unwrap();
        assert_eq!(restarted.execute_committed(begin,&[8;32],&mut store).unwrap(),reserved);
        let terminal=request_for(&subject,&identity,&format!("usdc-bus-settle:{BUS_ID}"),DirectAction::SettleUsdcBusWithdrawal {
            withdrawal_id:BUS_ID.into(),destination_chain:"base".into(),asset:"ZEN".into(),destination:wallet,
            amount_atomic:"1000000000000000000".into(),custody_reference:format!("horizen-zen-oft:0x{}","bb".repeat(32))});
        let settled=restarted.execute_committed(terminal.clone(),&[8;32],&mut store).unwrap();
        assert_eq!(settled.effect,"WITHDRAWAL_SETTLED");
        assert_eq!(restarted.balance(&identity,"ZEN","USER_WITHDRAWAL_HOLD"),0);
        assert_eq!(restarted.balance(&identity,"ZEN","USER_SETTLED"),1_000_000_000_000_000_000);
        assert_eq!(restarted.execute_committed(terminal,&[8;32],&mut store).unwrap(),settled);
    }
    #[test]
    fn refused_usdc_bus_request_cannot_become_a_payout_after_funding_or_restart() {
        let (mut live,subject,identity,wallet,mut store)=bus_fixture_funded("5000000");
        let refused=request_for(&subject,&identity,BUS_ID,DirectAction::BeginUsdcBusWithdrawal {
            withdrawal_id:BUS_ID.into(),destination_chain:"arbitrum".into(),asset:"USDC".into(),destination:wallet.clone(),amount_atomic:"5100000".into()});
        let first=live.execute_committed(refused.clone(),&[8;32],&mut store).unwrap();
        assert_eq!(first.effect,"WITHDRAWAL_REJECTED");
        assert_eq!(first.receipt.custody_reference,Some(format!("usdc-bus-rejection:{BUS_ID}:INSUFFICIENT_AVAILABLE")));
        assert_eq!(live.balance(&identity,"USDC","USER_AVAILABLE"),5_000_000);
        assert_eq!(live.balance(&identity,"USDC","USER_WITHDRAWAL_HOLD"),0);
        assert!(!live.has_pending_usdc_bus_withdrawals());
        let mut deposit=request_for(&subject,&identity,"later-deposit",DirectAction::CreditHorizenUsdcDeposit {
            amount_atomic:"5000000".into(),custody_reference:format!("horizen-usdc-deposit:0x{}","cd".repeat(32))});
        deposit.financial_wallet_address=Some(wallet.clone());deposit.request_hash=request_hash(&deposit);
        live.execute_committed(deposit,&[8;32],&mut store).unwrap();
        assert_eq!(live.execute_committed(refused.clone(),&[8;32],&mut store).unwrap(),first);
        let mut restarted=DirectRuntime::restore_committed(SealedEpoch::load(epoch_path()).unwrap(),RuntimeMode::IsolatedTest,vec![7;32],&[8;32],&store).unwrap();
        assert_eq!(restarted.execute_committed(refused,&[8;32],&mut store).unwrap(),first);
        assert_eq!(restarted.balance(&identity,"USDC","USER_AVAILABLE"),10_000_000);
        let next="21111111-2222-4333-8444-555555555555";
        assert_eq!(restarted.execute_committed(bus_begin(&subject,&identity,&wallet,next),&[8;32],&mut store).unwrap().effect,"WITHDRAWAL_RESERVED");
    }
    #[test]
    fn pending_bus_hold_blocks_another_user_withdrawal_not_other_user_deposits() {
        let (mut live,subject,identity,wallet,_)=bus_fixture();live.execute(bus_begin(&subject,&identity,&wallet,BUS_ID)).unwrap();
        let root=live.state_hash();
        assert_eq!(live.execute(bus_begin(&subject,&identity,&wallet,"21111111-2222-4333-8444-555555555555")).unwrap_err(),RuntimeError::WithdrawalPending);
        assert_eq!(live.state_hash(),root);
        let other_subject="b".repeat(64);let other_wallet="0x2222222222222222222222222222222222222222";
        let other_identity=identity_commitment_for(&other_subject,other_wallet);
        live.execute(request_for(&other_subject,&other_identity,"other-admit",DirectAction::AdmitIdentity {wallet_address:other_wallet.into()})).unwrap();
        let mut deposit=request_for(&other_subject,&other_identity,"other-deposit",DirectAction::CreditHorizenUsdcDeposit {
            amount_atomic:"5000000".into(),custody_reference:format!("horizen-usdc-deposit:0x{}","cd".repeat(32))});
        deposit.financial_wallet_address=Some(other_wallet.into());deposit.request_hash=request_hash(&deposit);
        assert_eq!(live.execute(deposit).unwrap().effect,"DEPOSIT_CREDITED");
        assert_eq!(live.balance(&other_identity,"USDC","USER_AVAILABLE"),5_000_000);
        assert_eq!(live.balance(&identity,"USDC","USER_WITHDRAWAL_HOLD"),4_840_000);
    }
    #[test]
    fn pending_bus_hold_cannot_be_bypassed_by_an_immediate_base_withdrawal() {
        let (mut live,subject,identity,wallet,_)=bus_fixture();
        live.execute(bus_begin(&subject,&identity,&wallet,BUS_ID)).unwrap();let root=live.state_hash();
        let withdrawal=request_for(&subject,&identity,"different-base-withdrawal",DirectAction::ReserveWithdrawal {
            destination:wallet,amount_atomic:"5000000".into(),custody_reference:"base-new-custody-proof".into()});
        assert_eq!(live.execute(withdrawal).unwrap_err(),RuntimeError::WithdrawalPending);
        assert_eq!(live.state_hash(),root);assert_eq!(live.balance(&identity,"USDC","USER_AVAILABLE"),5_160_000);
    }
    #[test]
    fn thirty_concurrent_requests_cannot_reserve_a_five_usdc_balance_twice() {
        use std::sync::{Arc,Mutex};
        let (live,subject,identity,wallet,store)=bus_fixture_funded("5000000");
        let shared=Arc::new(Mutex::new((live,store)));
        let begin=|id:&str|request_for(&subject,&identity,id,DirectAction::BeginUsdcBusWithdrawal {
            withdrawal_id:id.into(),destination_chain:"arbitrum".into(),asset:"USDC".into(),destination:wallet.clone(),amount_atomic:"5000000".into()});
        let original=begin(BUS_ID);
        {let mut locked=shared.lock().unwrap();let (live,store)=&mut *locked;live.execute_committed(original.clone(),&[8;32],store).unwrap();}
        let mut threads=Vec::new();
        for index in 0..30 {
            let shared=shared.clone();let repeated=index%2==0;
            let request=if repeated {original.clone()} else {begin(&format!("{:08x}-2222-4333-8444-555555555555",index+2))};
            threads.push(std::thread::spawn(move ||{
                let mut locked=shared.lock().unwrap();let (live,store)=&mut *locked;
                let result=live.execute_committed(request,&[8;32],store);
                if repeated {assert_eq!(result.unwrap().effect,"WITHDRAWAL_RESERVED");}else {assert_eq!(result.unwrap_err(),RuntimeError::WithdrawalPending);}
            }));
        }
        for thread in threads {thread.join().unwrap();}
        let locked=shared.lock().unwrap();let (live,store)=&*locked;
        assert_eq!(live.balance(&identity,"USDC","USER_AVAILABLE"),0);
        assert_eq!(live.balance(&identity,"USDC","USER_WITHDRAWAL_HOLD"),5_000_000);
        let restarted=DirectRuntime::restore_committed(SealedEpoch::load(epoch_path()).unwrap(),RuntimeMode::IsolatedTest,vec![7;32],&[8;32],store).unwrap();
        assert_eq!(restarted.balance(&identity,"USDC","USER_AVAILABLE"),0);
        assert_eq!(restarted.balance(&identity,"USDC","USER_WITHDRAWAL_HOLD"),5_000_000);
    }
    #[test]
    fn destination_settlement_consumes_only_the_original_hold_once() {
        let (mut live,subject,identity,wallet,_)=bus_fixture();live.execute(bus_begin(&subject,&identity,&wallet,BUS_ID)).unwrap();
        let terminal=bus_terminal(&subject,&identity,&wallet,false);
        let first=live.execute(terminal.clone()).unwrap();assert_eq!(first.effect,"WITHDRAWAL_SETTLED");
        assert_eq!(live.balance(&identity,"USDC","USER_AVAILABLE"),5_160_000);
        assert_eq!(live.balance(&identity,"USDC","USER_WITHDRAWAL_HOLD"),0);
        assert_eq!(live.balance(&identity,"USDC","USER_SETTLED"),4_840_000);
        assert!(!live.has_pending_usdc_bus_withdrawals());assert_eq!(live.execute(terminal).unwrap(),first);
    }
    #[test]
    fn verified_pool_revert_releases_hold_once_without_a_payout() {
        let (mut live,subject,identity,wallet,_)=bus_fixture();live.execute(bus_begin(&subject,&identity,&wallet,BUS_ID)).unwrap();
        let terminal=bus_terminal(&subject,&identity,&wallet,true);let first=live.execute(terminal.clone()).unwrap();
        assert_eq!(first.effect,"WITHDRAWAL_REVERTED");assert_eq!(live.balance(&identity,"USDC","USER_AVAILABLE"),10_000_000);
        assert_eq!(live.balance(&identity,"USDC","USER_WITHDRAWAL_HOLD"),0);assert_eq!(live.balance(&identity,"USDC","USER_SETTLED"),0);
        assert_eq!(live.execute(terminal).unwrap(),first);
    }
    #[test]
    fn terminal_bus_proof_cannot_change_destination_amount_or_request_identity() {
        for changed in ["destination","chain","asset","amount","request","proof"] {
            let (mut live,subject,identity,wallet,_)=bus_fixture();live.execute(bus_begin(&subject,&identity,&wallet,BUS_ID)).unwrap();
            let root=live.state_hash();let mut terminal=bus_terminal(&subject,&identity,&wallet,false);
            let DirectAction::SettleUsdcBusWithdrawal {destination_chain,asset,destination,amount_atomic,custody_reference,..}=&mut terminal.action else {unreachable!()};
            match changed {"destination"=>*destination="0x3333333333333333333333333333333333333333".into(),
                "chain"=>*destination_chain="base".into(),"asset"=>*asset="USDG".into(),
                "amount"=>*amount_atomic="5000000".into(),"request"=>terminal.request_id="other-request".into(),_=>*custody_reference="submitted-but-not-delivered".into()};
            terminal.request_hash=request_hash(&terminal);assert!(live.execute(terminal).is_err());assert_eq!(live.state_hash(),root);
        }
    }
    #[test]
    fn bus_delivery_reference_cannot_settle_a_second_hold() {
        let (mut live,subject,identity,wallet,_)=bus_fixture();live.execute(bus_begin(&subject,&identity,&wallet,BUS_ID)).unwrap();
        live.execute(bus_terminal(&subject,&identity,&wallet,false)).unwrap();
        let second="21111111-2222-4333-8444-555555555555";live.execute(bus_begin(&subject,&identity,&wallet,second)).unwrap();
        let root=live.state_hash();let mut terminal=bus_terminal(&subject,&identity,&wallet,false);
        let DirectAction::SettleUsdcBusWithdrawal {withdrawal_id,..}=&mut terminal.action else {unreachable!()};*withdrawal_id=second.into();
        terminal.request_id=format!("usdc-bus-settle:{second}");terminal.request_hash=request_hash(&terminal);
        assert_eq!(live.execute(terminal).unwrap_err(),RuntimeError::CustodyReferenceReuse);assert_eq!(live.state_hash(),root);
    }
    #[test]
    fn changing_only_one_bus_proof_hash_cannot_reuse_a_pool_release_or_delivery() {
        for changed in ["pool","guid","destination_transaction"] {
            let (mut live,subject,identity,wallet,mut store)=bus_fixture();
            live.execute_committed(bus_begin(&subject,&identity,&wallet,BUS_ID),&[8;32],&mut store).unwrap();
            live.execute_committed(bus_terminal(&subject,&identity,&wallet,false),&[8;32],&mut store).unwrap();
            let second="21111111-2222-4333-8444-555555555555";
            live.execute_committed(bus_begin(&subject,&identity,&wallet,second),&[8;32],&mut store).unwrap();
            let mut restarted=DirectRuntime::restore_committed(SealedEpoch::load(epoch_path()).unwrap(),RuntimeMode::IsolatedTest,vec![7;32],&[8;32],&store).unwrap();
            let root=restarted.state_hash();let mut terminal=bus_terminal(&subject,&identity,&wallet,false);
            let DirectAction::SettleUsdcBusWithdrawal {withdrawal_id,custody_reference,..}=&mut terminal.action else {unreachable!()};
            *withdrawal_id=second.into();
            let mut parts=custody_reference.split(':').map(str::to_string).collect::<Vec<_>>();
            parts[match changed {"pool"=>1,"guid"=>2,_=>3}]=format!("0x{}","44".repeat(32));
            *custody_reference=parts.join(":");terminal.request_id=format!("usdc-bus-settle:{second}");terminal.request_hash=request_hash(&terminal);
            assert_eq!(restarted.execute_committed(terminal,&[8;32],&mut store).unwrap_err(),RuntimeError::CustodyReferenceReuse);
            assert_eq!(restarted.state_hash(),root);assert_eq!(restarted.balance(&identity,"USDC","USER_WITHDRAWAL_HOLD"),4_840_000);
        }
    }
    #[test]
    fn distinct_seats_can_settle_identical_recipient_amounts_but_not_reuse_an_event_or_seat() {
        for variant in ["legitimate","same_event","same_seat"] {
            let (mut live,subject,identity,wallet,_)=bus_fixture();
            live.execute(bus_begin(&subject,&identity,&wallet,BUS_ID)).unwrap();
            live.execute(bus_terminal(&subject,&identity,&wallet,false)).unwrap();
            let second="21111111-2222-4333-8444-555555555555";
            live.execute(bus_begin(&subject,&identity,&wallet,second)).unwrap();
            let root=live.state_hash();let mut terminal=bus_terminal(&subject,&identity,&wallet,false);
            let DirectAction::SettleUsdcBusWithdrawal {withdrawal_id,custody_reference,..}=&mut terminal.action else {unreachable!()};
            *withdrawal_id=second.into();
            let mut parts=custody_reference.split(':').map(str::to_string).collect::<Vec<_>>();
            parts[1]=format!("0x{}","44".repeat(32));
            parts[4]=if variant=="same_seat" {"0"} else {"1"}.into();
            parts[5]=if variant=="same_event" {"1"} else {"3"}.into();
            *custody_reference=parts.join(":");terminal.request_id=format!("usdc-bus-settle:{second}");terminal.request_hash=request_hash(&terminal);
            if variant=="legitimate" {
                assert_eq!(live.execute(terminal).unwrap().effect,"WITHDRAWAL_SETTLED");
                assert_eq!(live.balance(&identity,"USDC","USER_SETTLED"),9_680_000);
            }else{
                assert_eq!(live.execute(terminal).unwrap_err(),RuntimeError::CustodyReferenceReuse);assert_eq!(live.state_hash(),root);
            }
        }
    }
    #[test]
    fn bus_terminal_references_require_canonical_seat_and_actual_event_index() {
        let valid=format!("horizen-usdc-bus:0x{}:0x{}:0x{}","11".repeat(32),"22".repeat(32),"33".repeat(32));
        for suffix in ["",":255:1",":-1:1",":01:1",":0:01",":0:-1",":0:1:extra"] {
            assert!(!valid_bus_terminal_reference(&format!("{valid}{suffix}"),false));
        }
        assert!(valid_bus_terminal_reference(&format!("{valid}:254:0"),false));
        let relay=format!("horizen-usdc-relay:0x{}:0x{}:0x{}:0x{}:{}","11".repeat(32),"22".repeat(32),"33".repeat(32),"44".repeat(32),"5".repeat(64));
        assert!(valid_bus_terminal_reference(&relay,false));
        assert!(!valid_bus_terminal_reference(&format!("{relay}:extra"),false));
    }
    #[test]
    fn every_bus_state_uses_the_predecessor_schema_and_reconstructs_signed_holds() {
        let (mut live,subject,identity,wallet,_)=bus_fixture();
        let has_hold_field=|runtime:&DirectRuntime| {
            let bytes=serde_cbor::to_vec(&runtime.snapshot()).unwrap();
            let serde_cbor::Value::Map(map)=serde_cbor::from_slice::<serde_cbor::Value>(&bytes).unwrap() else {unreachable!()};
            map.contains_key(&serde_cbor::Value::Text("usdc_bus_withdrawals".into()))
        };
        assert!(!has_hold_field(&live));
        live.execute(bus_begin(&subject,&identity,&wallet,BUS_ID)).unwrap();
        assert!(!has_hold_field(&live));
        let holds=reconstruct_bus_holds(&live.snapshot(),&live.receipt_key).unwrap();
        assert_eq!(holds.get(BUS_ID).unwrap().destination,wallet);
        assert_eq!(holds.get(BUS_ID).unwrap().amount_atomic,"4840000");
        live.execute(bus_terminal(&subject,&identity,&wallet,false)).unwrap();
        assert!(!has_hold_field(&live));
        assert!(reconstruct_bus_holds(&live.snapshot(),&live.receipt_key).unwrap().is_empty());
    }
    #[test]
    fn bus_hold_restore_rejects_missing_or_forged_binding_and_unbacked_balance() {
        let (mut live,subject,identity,wallet,_)=bus_fixture();
        live.execute(bus_begin(&subject,&identity,&wallet,BUS_ID)).unwrap();
        for variant in ["missing","signature","destination","amount","balance","terminal"] {
            let mut state=live.snapshot();
            if variant=="missing" { state.requests.remove(&(subject.clone(),BUS_ID.into())); }
            else if variant=="balance" { *state.balances.get_mut(&identity).unwrap().get_mut(&("USDC".into(),"USER_WITHDRAWAL_HOLD".into())).unwrap()+=1; }
            else if variant=="terminal" {
                let mut record=state.requests.get(&(subject.clone(),BUS_ID.into())).unwrap().clone();
                record.1.receipt.request_id=format!("usdc-bus-settle:{BUS_ID}");
                record.1.receipt.signature=receipt_signature(&live.receipt_key,&record.1.receipt);
                state.requests.insert((subject.clone(),record.1.receipt.request_id.clone()),record);
            } else {
                let receipt=&mut state.requests.get_mut(&(subject.clone(),BUS_ID.into())).unwrap().1.receipt;
                if variant=="signature" {receipt.signature="0".repeat(64);}
                if variant=="destination" {receipt.custody_reference=Some(format!("usdc-bus-reservation:{BUS_ID}:not-an-address"));receipt.signature=receipt_signature(&live.receipt_key,receipt);}
                if variant=="amount" {receipt.amount_atomic=Some("04840000".into());receipt.signature=receipt_signature(&live.receipt_key,receipt);}
            }
            assert!(matches!(reconstruct_bus_holds(&state,&live.receipt_key),Err(RuntimeError::StateArtifact)),"{variant}");
        }
    }
    #[test]
    fn horizen_usdc_credit_requires_the_own_admitted_wallet_minimum_and_unique_proof() {
        let (mut live,subject,identity,wallet,_)=bus_fixture();
        for (amount,source,reference) in [("4999999",wallet.as_str(),format!("horizen-usdc-deposit:0x{}","aa".repeat(32))),
            ("5000000","0x3333333333333333333333333333333333333333",format!("horizen-usdc-deposit:0x{}","aa".repeat(32))),
            ("5000000",wallet.as_str(),format!("base-deposit:0x{}","aa".repeat(32))),
            ("5000000",wallet.as_str(),format!("horizen-usdc-deposit:0x{}","ab".repeat(32)))] {
            let root=live.state_hash();let mut credit=request_for(&subject,&identity,"invalid-credit",DirectAction::CreditHorizenUsdcDeposit {
                amount_atomic:amount.into(),custody_reference:reference});credit.financial_wallet_address=Some(source.into());credit.request_hash=request_hash(&credit);
            assert!(live.execute(credit).is_err());assert_eq!(live.state_hash(),root);
        }
    }
    #[test]
    fn replacement_wallet_links_to_existing_identity_without_resetting_balance_or_history() {
        let (mut live,subject,identity,wallet,mut store)=bus_fixture();
        let replacement="0x2222222222222222222222222222222222222222";
        let before_balance=live.balance(&identity,"USDC","USER_AVAILABLE");let before_count=live.identity_count();
        let link=request_for(&subject,&identity,"wallet-link-new",DirectAction::LinkFinancialWallet {wallet_address:replacement.into()});
        let first=live.execute_committed(link.clone(),&[8;32],&mut store).unwrap();
        assert_eq!(first.effect,"FINANCIAL_WALLET_LINKED");assert_eq!(live.balance(&identity,"USDC","USER_AVAILABLE"),before_balance);
        assert_eq!(first.receipt.custody_reference,Some(format!("wallet-link:{replacement}")));
        assert_eq!(live.identity_count(),before_count);assert!(live.subject_wallets[&subject].contains(&wallet));
        let mut restarted=DirectRuntime::restore_committed(SealedEpoch::load(epoch_path()).unwrap(),RuntimeMode::IsolatedTest,vec![7;32],&[8;32],&store).unwrap();
        assert!(restarted.subject_wallets[&subject].contains(replacement));assert_eq!(restarted.execute_committed(link,&[8;32],&mut store).unwrap(),first);
        let mut credit=request_for(&subject,&identity,"replacement-deposit",DirectAction::CreditHorizenUsdcDeposit {
            amount_atomic:"5000000".into(),custody_reference:format!("horizen-usdc-deposit:0x{}","ee".repeat(32))});
        credit.financial_wallet_address=Some(replacement.into());credit.request_hash=request_hash(&credit);
        assert_eq!(restarted.execute_committed(credit,&[8;32],&mut store).unwrap().effect,"DEPOSIT_CREDITED");
        assert_eq!(restarted.balance(&identity,"USDC","USER_AVAILABLE"),before_balance+5_000_000);
    }
    #[test]
    fn wallet_link_cannot_take_over_another_account_or_change_during_a_pending_withdrawal() {
        let (mut live,subject,identity,wallet,_)=bus_fixture();
        let other="b".repeat(64);let other_wallet="0x2222222222222222222222222222222222222222";
        let other_identity=identity_commitment_for(&other,other_wallet);
        live.execute(request_for(&other,&other_identity,"other-admit",DirectAction::AdmitIdentity {wallet_address:other_wallet.into()})).unwrap();
        let before=live.state_hash();assert_eq!(live.execute(request_for(&subject,&identity,"takeover",DirectAction::LinkFinancialWallet {wallet_address:other_wallet.into()})).unwrap_err(),RuntimeError::IdentityAlreadyAdmitted);
        assert_eq!(live.state_hash(),before);live.execute(bus_begin(&subject,&identity,&wallet,BUS_ID)).unwrap();let before=live.state_hash();
        assert_eq!(live.execute(request_for(&subject,&identity,"pending-link",DirectAction::LinkFinancialWallet {wallet_address:"0x3333333333333333333333333333333333333333".into()})).unwrap_err(),RuntimeError::WithdrawalPending);
        assert_eq!(live.state_hash(),before);
    }
    #[test]
    fn finalized_deposit_reference_is_global_exactly_once_and_survives_restart() {
        let identity = "0bafc03d08d4951d769d58284db85c7ac2ee3c79de87ec680f58edc03017c418";
        let reference = format!("base-deposit:0x{}", "11".repeat(32));
        let state_key = [9u8; 32];
        let mut store = InMemoryDirectStateStore::default();
        let mut live = runtime(RuntimeMode::IsolatedTest);
        let first = request(
            "base-deposit:first",
            DirectAction::CreditDeposit {
                amount_atomic: "5000000".into(),
                custody_reference: reference.clone(),
            },
        );
        live.execute_committed(first.clone(), &state_key, &mut store)
            .unwrap();
        let after = live.balance(identity, "USDC", "USER_AVAILABLE");
        assert_eq!(after, 10_000_000);
        assert_eq!(
            live.execute_committed(
                request(
                    "base-deposit:different-request",
                    DirectAction::CreditDeposit {
                        amount_atomic: "5000000".into(),
                        custody_reference: reference,
                    },
                ),
                &state_key,
                &mut store,
            )
            .unwrap_err(),
            RuntimeError::CustodyReferenceReuse
        );
        assert_eq!(live.balance(identity, "USDC", "USER_AVAILABLE"), after);
        let mut restored = DirectRuntime::restore_committed(
            SealedEpoch::load(epoch_path()).unwrap(),
            RuntimeMode::IsolatedTest,
            vec![7; 32],
            &state_key,
            &store,
        )
        .unwrap();
        assert_eq!(restored.balance(identity, "USDC", "USER_AVAILABLE"), after);
        assert_eq!(
            restored
                .execute_committed(first, &state_key, &mut store)
                .unwrap()
                .receipt
                .effect,
            "DEPOSIT_CREDITED"
        );
        assert_eq!(store.artifacts().unwrap().len(), 1);
    }
    #[test]
    fn rejects_cross_account_and_wrong_destination_without_effect() {
        let mut r = runtime(RuntimeMode::IsolatedTest);
        let mut q = request(
            "denied",
            DirectAction::ReserveWithdrawal {
                destination: "0x2222222222222222222222222222222222222222".into(),
                amount_atomic: "1".into(),
                custody_reference: "mock".into(),
            },
        );
        q.financial_wallet_address = Some("0xfefefefefefefefefefefefefefefefefefefefe".into());
        q.request_hash = request_hash(&q);
        assert_eq!(
            r.execute(q.clone()).unwrap_err(),
            RuntimeError::DestinationDenied
        );
        let mut invalid_destination = request(
            "invalid-destination",
            DirectAction::ReserveWithdrawal {
                destination: "0x0000000000000000000000000000000000000000".into(),
                amount_atomic: "1".into(),
                custody_reference: "mock-invalid-destination".into(),
            },
        );
        invalid_destination.request_hash = request_hash(&invalid_destination);
        assert_eq!(
            r.execute(invalid_destination).unwrap_err(),
            RuntimeError::DestinationDenied
        );
        q.account_id = "bae54f222a79c2ea394fa5b087d6a843e4b82562d0f3dfa33b8149b4beea21b3".into();
        q.request_hash = request_hash(&q);
        assert_eq!(r.execute(q).unwrap_err(), RuntimeError::IdentityDenied);

        let mut privy_deposit = request(
            "privy-deposit-denied",
            DirectAction::CreditDeposit {
                amount_atomic: "1".into(),
                custody_reference: "mock-deposit".into(),
            },
        );
        privy_deposit.financial_wallet_address =
            Some("0xccb96357deb4cbf0808208d55916774f0b51a908".into());
        privy_deposit.request_hash = request_hash(&privy_deposit);
        assert_eq!(
            r.execute(privy_deposit).unwrap_err(),
            RuntimeError::DestinationDenied
        );
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
    fn governed_canary_liability_recovery_is_exact_once_restart_safe_and_has_no_custody_effect() {
        let subject = "7619baaa0831003f3ca58bfcf5b2c773c8bc302a015124b1c432d220ddaa704b";
        let identity = "88dff4a4d5ab480024423e999bd92463a6474bb00e56f46c264b944aaba39871";
        let state_key = [9u8; 32];
        let epoch = SealedEpoch::load(epoch_path()).unwrap();
        let mut runtime =
            DirectRuntime::new(epoch.clone(), RuntimeMode::IsolatedTest, vec![7; 32]).unwrap();
        let mut store = InMemoryDirectStateStore::default();
        runtime
            .execute_committed(
                request_for(
                    subject,
                    identity,
                    "simulate-returned-canary-principal",
                    DirectAction::ReserveWithdrawal {
                        destination: "0xfefefefefefefefefefefefefefefefefefefefe".into(),
                        amount_atomic: "5000000".into(),
                        custody_reference: "isolated-returned-canary-principal".into(),
                    },
                ),
                &state_key,
                &mut store,
            )
            .unwrap();
        assert_eq!(
            runtime.balance(identity, "USDC", "USER_AVAILABLE"),
            4_404_611
        );

        let recovery = GovernedBalanceRecovery {
            recovery_id: "recover-mm02-returned-canary-principal-20260913".into(),
            epoch_id: EPOCH_ID.into(),
            runtime: TRANSACTION_MODEL.into(),
            account_id: subject.into(),
            identity_commitment: identity.into(),
            asset: "USDC".into(),
            bucket: "USER_AVAILABLE".into(),
            amount_atomic: "5000000".into(),
            expected_balance_before_atomic: "4404611".into(),
            evidence_sha256: "a".repeat(64),
            reason_code: "RESTORE_RETURNED_CANARY_PRINCIPAL".into(),
            expires_at_unix: 2_000,
            governance_key_id: GOVERNANCE_KEY_ID.into(),
            signing_algorithm: GOVERNANCE_SIGNING_ALGORITHM.into(),
            signature: "isolated-governed-balance-recovery".into(),
        };
        let command = request_for(
            subject,
            identity,
            &recovery.recovery_id.clone(),
            DirectAction::GovernedBalanceRecovery {
                recovery,
                now_unix: 1_000,
            },
        );
        let applied = runtime
            .execute_committed(command.clone(), &state_key, &mut store)
            .unwrap();
        assert_eq!(applied.effect, "GOVERNED_BALANCE_RECOVERY_APPLIED");
        assert_eq!(
            runtime.balance(identity, "USDC", "USER_AVAILABLE"),
            9_404_611
        );
        assert_eq!(store.artifacts().unwrap().len(), 2);

        let mut restarted = DirectRuntime::restore_committed(
            epoch,
            RuntimeMode::IsolatedTest,
            vec![7; 32],
            &state_key,
            &store,
        )
        .unwrap();
        assert_eq!(
            restarted.balance(identity, "USDC", "USER_AVAILABLE"),
            9_404_611
        );
        assert_eq!(
            restarted
                .execute_committed(command, &state_key, &mut store)
                .unwrap(),
            applied
        );
        assert_eq!(store.artifacts().unwrap().len(), 2);
    }

    #[test]
    fn post_genesis_identity_admission_is_zero_balance_restart_and_replay_safe() {
        let subject = "d".repeat(64);
        let wallet = "0x2222222222222222222222222222222222222222";
        let identity = identity_commitment_for(&subject, wallet);
        let mut admission = DirectRequest {
            account_id: subject.clone(),
            identity_commitment: identity.clone(),
            request_id: "identity-admission-fixture-01".into(),
            request_hash: String::new(),
            financial_wallet_address: None,
            action: DirectAction::AdmitIdentity {
                wallet_address: wallet.into(),
            },
        };
        admission.request_hash = request_hash(&admission);
        let epoch = SealedEpoch::load(epoch_path()).unwrap();
        let mut runtime =
            DirectRuntime::new(epoch.clone(), RuntimeMode::AdmissionOnly, vec![7; 32]).unwrap();
        let mut store = InMemoryDirectStateStore::default();
        let result = runtime
            .execute_committed(admission.clone(), &[8; 32], &mut store)
            .unwrap();
        assert_eq!(result.effect, "IDENTITY_ADMITTED");
        assert!(runtime.owns(&subject, &identity));
        assert_eq!(runtime.identity_count(), 439);
        assert_eq!(runtime.balance(&identity, "USDC", "USER_AVAILABLE"), 0);
        assert_eq!(store.artifacts().unwrap().len(), 1);

        let mut restored = DirectRuntime::restore_committed(
            epoch,
            RuntimeMode::AdmissionOnly,
            vec![7; 32],
            &[8; 32],
            &store,
        )
        .unwrap();
        assert!(restored.owns(&subject, &identity));
        assert_eq!(restored.identity_count(), 439);
        assert_eq!(
            restored
                .execute_committed(admission, &[8; 32], &mut store)
                .unwrap(),
            result
        );
        assert_eq!(store.artifacts().unwrap().len(), 1);

        let other_wallet = "0x3333333333333333333333333333333333333333";
        let mut rebind = DirectRequest {
            account_id: subject.clone(),
            identity_commitment: identity_commitment_for(&subject, other_wallet),
            request_id: "identity-admission-fixture-02".into(),
            request_hash: String::new(),
            financial_wallet_address: None,
            action: DirectAction::AdmitIdentity {
                wallet_address: other_wallet.into(),
            },
        };
        rebind.request_hash = request_hash(&rebind);
        assert_eq!(
            restored.execute(rebind).unwrap_err(),
            RuntimeError::IdentityAlreadyAdmitted
        );
        assert_eq!(restored.identity_count(), 439);
    }

    #[test]
    fn admission_only_mode_cannot_execute_financial_actions() {
        let mut runtime = runtime(RuntimeMode::AdmissionOnly);
        assert_eq!(
            runtime
                .execute(request(
                    "admission-financial-denied",
                    DirectAction::CreditDeposit {
                        amount_atomic: "1".into(),
                        custody_reference: "isolated-finality".into(),
                    }
                ))
                .unwrap_err(),
            RuntimeError::WriterDisabled,
        );
        runtime.markets.insert(
            "layrs:v5:BTC:USDC:15m:admission-resolution-denied".into(),
            isolated_market("layrs:v5:BTC:USDC:15m:admission-resolution-denied"),
        );
        assert_eq!(
            runtime
                .execute(market_resolution_request(
                    "layrs:v5:BTC:USDC:15m:admission-resolution-denied",
                    "admission-market-resolution",
                    DirectResolutionOutcome::Push,
                ))
                .unwrap_err(),
            RuntimeError::WriterDisabled,
        );
    }

    fn complete_set_redemption_fixture() -> (SealedEpoch, DirectRuntime, InMemoryDirectStateStore, String) {
        let market = "layrs:v5:BTC:USDC:15m:paired-redemption-fixture".to_string();
        let epoch = SealedEpoch::load(epoch_path()).unwrap();
        let mut runtime = DirectRuntime::new(epoch.clone(), RuntimeMode::IsolatedTest, vec![7;32]).unwrap();
        let mut store = InMemoryDirectStateStore::default();
        runtime.execute_committed(market_registration_request(&market,"paired-market"), &[8;32], &mut store).unwrap();
        for (i, outcome) in [Outcome::Up,Outcome::Down,Outcome::Down,Outcome::Up].into_iter().enumerate() {
            let action=DirectAction::PlaceOrder {order_id:Uuid::from_u128(100+i as u128).to_string(),market_id:market.clone(),outcome,action:OrderAction::Buy,price_micros:500_000,quantity_micros:"2000000".into(),time_in_force:TimeInForce::Gtc,expires_at_millis:None,now_millis:1000+i as i64};
            let command=if i%2==0 {request(&format!("paired-order-{i}"),action)} else {request_for("bae54f222a79c2ea394fa5b087d6a843e4b82562d0f3dfa33b8149b4beea21b3","9bf6b307e41f94a5f5ec4211d2ac9eb5e4f2743b25224573391d7e8903276481",&format!("paired-order-{i}"),action)};
            runtime.execute_committed(command,&[8;32],&mut store).unwrap();
        }
        (epoch,runtime,store,market)
    }
    #[test]
    fn complete_set_redemption_conserves_backing_and_replays_after_restore() {
        let (epoch,mut runtime,mut store,market)=complete_set_redemption_fixture();
        let owner="0bafc03d08d4951d769d58284db85c7ac2ee3c79de87ec680f58edc03017c418";
        let other="9bf6b307e41f94a5f5ec4211d2ac9eb5e4f2743b25224573391d7e8903276481";
        let before=runtime.balance(owner,"USDC","USER_AVAILABLE");
        let other_before=runtime.portfolio(other).unwrap();let fees=runtime.fee_revenue_atomic;
        assert_eq!(runtime.market_collateral.get(&market),Some(&4_000_000));
        let command=request("paired-redeem",DirectAction::RedeemCompleteSet {market_id:market.clone(),quantity_micros:"2000000".into()});
        let result=runtime.execute_committed(command.clone(),&[8;32],&mut store).unwrap();
        assert_eq!(result.effect,"COMPLETE_SET_REDEEMED");assert_eq!(result.receipt.amount_atomic.as_deref(),Some("2000000"));
        assert_eq!(runtime.balance(owner,"USDC","USER_AVAILABLE"),before+2_000_000);
        assert_eq!(runtime.market_collateral.get(&market),Some(&2_000_000));assert_eq!(runtime.fee_revenue_atomic,fees);
        let other_after=runtime.portfolio(other).unwrap();assert_eq!(other_after.balances,other_before.balances);assert_eq!(other_after.positions,other_before.positions);assert_eq!(other_after.open_orders,other_before.open_orders);
        for outcome in [Outcome::Up,Outcome::Down] {let key=(owner.into(),market.clone(),outcome);assert_eq!(runtime.total_position(&key),0);assert_eq!(runtime.position_cost_basis.get(&key),Some(&0));}
        let count=store.artifacts().unwrap().len();assert_eq!(runtime.execute_committed(command.clone(),&[8;32],&mut store).unwrap(),result);assert_eq!(store.artifacts().unwrap().len(),count);
        let mut restored=DirectRuntime::restore_committed(epoch,RuntimeMode::IsolatedTest,vec![7;32],&[8;32],&store).unwrap();assert_eq!(restored.state_hash(),runtime.state_hash());assert_eq!(restored.execute_committed(command,&[8;32],&mut store).unwrap(),result);assert_eq!(store.artifacts().unwrap().len(),count);
    }
    #[test]
    fn complete_set_redemption_rejects_missing_claims_and_invalid_amount_without_effect() {
        let (_,mut runtime,mut store,market)=complete_set_redemption_fixture();
        for quantity in ["0","02000000","2000001","-1"] {
            let hash=runtime.state_hash();let count=store.artifacts().unwrap().len();
            assert!(runtime.execute_committed(request(&format!("invalid-pair-{quantity}"),DirectAction::RedeemCompleteSet {market_id:market.clone(),quantity_micros:quantity.into()}),&[8;32],&mut store).is_err());
            assert_eq!(runtime.state_hash(),hash);assert_eq!(store.artifacts().unwrap().len(),count);
        }
        runtime.market_collateral.insert(market.clone(),1_999_999);let hash=runtime.state_hash();
        assert!(runtime.execute_committed(request("underbacked-pair",DirectAction::RedeemCompleteSet {market_id:market,quantity_micros:"2000000".into()}),&[8;32],&mut store).is_err());assert_eq!(runtime.state_hash(),hash);
    }
    #[test]
    fn complete_set_redemption_does_not_consume_claims_held_in_orders() {
        let (_,mut runtime,mut store,market)=complete_set_redemption_fixture();
        runtime.execute_committed(request("pair-held-sell",DirectAction::PlaceOrder {order_id:Uuid::from_u128(200).to_string(),market_id:market.clone(),outcome:Outcome::Up,action:OrderAction::Sell,price_micros:900_000,quantity_micros:"2000000".into(),time_in_force:TimeInForce::Gtc,expires_at_millis:None,now_millis:2000}),&[8;32],&mut store).unwrap();
        let before=runtime.state_hash();let count=store.artifacts().unwrap().len();assert_eq!(runtime.execute_committed(request("held-pair-redeem",DirectAction::RedeemCompleteSet {market_id:market,quantity_micros:"2000000".into()}),&[8;32],&mut store).unwrap_err(),RuntimeError::InsufficientAvailable);assert_eq!(runtime.state_hash(),before);assert_eq!(store.artifacts().unwrap().len(),count);
    }
    #[test]
    fn native_clob_mint_fill_settles_fees_positions_and_replays_exactly_once_after_restart() {
        const MARKET: &str = "layrs:v5:BTC:USDC:15m:direct-fill-fixture";
        const MAKER_IDENTITY: &str =
            "0bafc03d08d4951d769d58284db85c7ac2ee3c79de87ec680f58edc03017c418";
        const TAKER_SUBJECT: &str =
            "bae54f222a79c2ea394fa5b087d6a843e4b82562d0f3dfa33b8149b4beea21b3";
        const TAKER_IDENTITY: &str =
            "9bf6b307e41f94a5f5ec4211d2ac9eb5e4f2743b25224573391d7e8903276481";
        let epoch = SealedEpoch::load(epoch_path()).unwrap();
        let mut runtime =
            DirectRuntime::new(epoch.clone(), RuntimeMode::IsolatedTest, vec![7; 32]).unwrap();
        let mut store = InMemoryDirectStateStore::default();
        runtime
            .execute_committed(
                market_registration_request(MARKET, "market-release-01"),
                &[8; 32],
                &mut store,
            )
            .unwrap();
        let maker = request(
            "maker-order-01",
            DirectAction::PlaceOrder {
                order_id: "11111111-2222-4333-8444-555555555555".into(),
                market_id: MARKET.into(),
                outcome: Outcome::Up,
                action: OrderAction::Buy,
                price_micros: 400_000,
                quantity_micros: "1000000".into(),
                time_in_force: TimeInForce::Gtc,
                expires_at_millis: None,
                now_millis: 1_000,
            },
        );
        runtime
            .execute_committed(maker, &[8; 32], &mut store)
            .unwrap();
        let maker_subject="88fff7d9668cf8b00cd7faa0680d05c6415221e6ab28c5be7fa71e047054d8fc";
        assert_eq!(runtime.public_quest_receipt(maker_subject,maker_subject,"maker-order-01").unwrap_err(),RuntimeError::InvalidRequest);
        let taker = request_for(
            TAKER_SUBJECT,
            TAKER_IDENTITY,
            "taker-order-01",
            DirectAction::PlaceOrder {
                order_id: "22222222-3333-4444-8555-666666666666".into(),
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
        let executed = runtime
            .execute_committed(taker.clone(), &[8; 32], &mut store)
            .unwrap();
        let detail = executed.receipt.execution.as_ref().unwrap();
        assert_eq!(executed.effect, "ORDER_EXECUTED");
        assert_eq!(detail.trades.len(), 1);
        assert_eq!(detail.trades[0].match_type, MatchType::Mint);
        assert_eq!(detail.trades[0].executed_quantity_micros, "1000000");
        assert_eq!(detail.trades[0].execution_price_micros, 600_000);
        assert_eq!(detail.trades[0].fee_atomic, "16800");
        let before_witness=(runtime.committed_state_hash(),runtime.committed_sequence());
        for participant in [maker_subject,TAKER_SUBJECT] {
            let witness=runtime.public_quest_receipt(participant,TAKER_SUBJECT,"taker-order-01").unwrap();
            assert_eq!(witness.payload.kind,QuestReceiptKind::PrivateFill);
            assert!(verify_public_quest_receipt(&witness,&quest_receipt_public_key(&[7;32]).unwrap()));
        }
        assert_eq!(before_witness,(runtime.committed_state_hash(),runtime.committed_sequence()));
        let mut wrong_asset=runtime.clone();wrong_asset.markets.get_mut(MARKET).unwrap().settlement_asset="ZEN".into();
        assert_eq!(wrong_asset.public_quest_receipt(TAKER_SUBJECT,TAKER_SUBJECT,"taker-order-01").unwrap_err(),RuntimeError::InvalidRequest);
        assert_eq!(
            runtime.total_position(&(MAKER_IDENTITY.into(), MARKET.into(), Outcome::Up)),
            1_000_000
        );
        assert_eq!(
            runtime.total_position(&(TAKER_IDENTITY.into(), MARKET.into(), Outcome::Down)),
            1_000_000
        );
        assert_eq!(runtime.market_collateral.get(MARKET), Some(&1_000_000));
        assert_eq!(runtime.fee_revenue_atomic, 16_800);
        assert_eq!(store.artifacts().unwrap().len(), 3);
        let portfolio = runtime.portfolio(TAKER_IDENTITY).unwrap();
        assert_eq!(portfolio.identity_commitment, TAKER_IDENTITY);
        assert_eq!(portfolio.registered_market_ids, vec![MARKET]);
        assert_eq!(portfolio.open_orders.len(), 0);
        assert_eq!(portfolio.positions.len(), 1);
        assert_eq!(portfolio.positions[0].market_id, MARKET);
        assert_eq!(portfolio.positions[0].outcome, Outcome::Down);
        assert_eq!(portfolio.positions[0].total_quantity_micros, "1000000");
        assert_eq!(portfolio.genesis_ordinal, 3);

        let mut restored = DirectRuntime::restore_committed(
            epoch,
            RuntimeMode::IsolatedTest,
            vec![7; 32],
            &[8; 32],
            &store,
        )
        .unwrap();
        assert_eq!(
            restored.total_position(&(TAKER_IDENTITY.into(), MARKET.into(), Outcome::Down)),
            1_000_000
        );
        assert_eq!(
            restored
                .execute_committed(taker, &[8; 32], &mut store)
                .unwrap(),
            executed
        );
        assert_eq!(
            restored.total_position(&(TAKER_IDENTITY.into(), MARKET.into(), Outcome::Down)),
            1_000_000
        );
        assert_eq!(restored.fee_revenue_atomic, 16_800);
        assert_eq!(store.artifacts().unwrap().len(), 3);
        assert_eq!(restored.portfolio(TAKER_IDENTITY).unwrap(), portfolio);
        assert_eq!(
            restored.portfolio(&"f".repeat(64)).unwrap_err(),
            RuntimeError::IdentityDenied
        );
    }

    #[test]
    fn governed_market_resolution_pays_once_closes_market_and_survives_restart() {
        const MARKET: &str = "layrs:v5:BTC:USDC:15m:direct-resolution-fixture";
        const MAKER_IDENTITY: &str =
            "0bafc03d08d4951d769d58284db85c7ac2ee3c79de87ec680f58edc03017c418";
        const TAKER_SUBJECT: &str =
            "bae54f222a79c2ea394fa5b087d6a843e4b82562d0f3dfa33b8149b4beea21b3";
        const TAKER_IDENTITY: &str =
            "9bf6b307e41f94a5f5ec4211d2ac9eb5e4f2743b25224573391d7e8903276481";
        let epoch = SealedEpoch::load(epoch_path()).unwrap();
        let mut runtime =
            DirectRuntime::new(epoch.clone(), RuntimeMode::IsolatedTest, vec![7; 32]).unwrap();
        let mut store = InMemoryDirectStateStore::default();
        runtime
            .execute_committed(
                market_registration_request(MARKET, "resolution-market"),
                &[8; 32],
                &mut store,
            )
            .unwrap();
        runtime
            .execute_committed(
                request(
                    "resolution-maker",
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
                &[8; 32],
                &mut store,
            )
            .unwrap();
        runtime
            .execute_committed(
                request_for(
                    TAKER_SUBJECT,
                    TAKER_IDENTITY,
                    "resolution-taker",
                    DirectAction::PlaceOrder {
                        order_id: "66666666-7777-4888-8999-000000000000".into(),
                        market_id: MARKET.into(),
                        outcome: Outcome::Down,
                        action: OrderAction::Buy,
                        price_micros: 600_000,
                        quantity_micros: "1000000".into(),
                        time_in_force: TimeInForce::Gtc,
                        expires_at_millis: None,
                        now_millis: 2_000,
                    },
                ),
                &[8; 32],
                &mut store,
            )
            .unwrap();
        runtime
            .execute_committed(
                request(
                    "resolution-resting-order",
                    DirectAction::PlaceOrder {
                        order_id: "88888888-9999-4000-8111-222222222222".into(),
                        market_id: MARKET.into(),
                        outcome: Outcome::Up,
                        action: OrderAction::Buy,
                        price_micros: 300_000,
                        quantity_micros: "1000000".into(),
                        time_in_force: TimeInForce::Gtc,
                        expires_at_millis: None,
                        now_millis: 3_000,
                    },
                ),
                &[8; 32],
                &mut store,
            )
            .unwrap();
        let maker_before = runtime.balance(MAKER_IDENTITY, "USDC", "USER_AVAILABLE")
            + runtime.balance(MAKER_IDENTITY, "USDC", "USER_ORDER_HOLD");
        let taker_before = runtime.balance(TAKER_IDENTITY, "USDC", "USER_AVAILABLE");
        let resolution = market_resolution_request(
            MARKET,
            "resolution-up-terminal",
            DirectResolutionOutcome::Up,
        );
        let resolved = runtime
            .execute_committed(resolution.clone(), &[8; 32], &mut store)
            .unwrap();
        assert_eq!(resolved.effect, "MARKET_RESOLVED");
        let details = resolved.receipt.resolution.as_ref().unwrap();
        assert_eq!(details.outcome, DirectResolutionOutcome::Up);
        assert_eq!(details.gross_payout_atomic, "1000000");
        assert_eq!(details.rounding_reserve_atomic, "0");
        assert_eq!(details.cancelled_order_count, 1);
        assert_eq!(details.settled_position_count, 2);
        assert_eq!(
            runtime.balance(MAKER_IDENTITY, "USDC", "USER_AVAILABLE"),
            maker_before + 1_000_000
        );
        assert_eq!(
            runtime.balance(MAKER_IDENTITY, "USDC", "USER_ORDER_HOLD"),
            0
        );
        assert_eq!(
            runtime.balance(TAKER_IDENTITY, "USDC", "USER_AVAILABLE"),
            taker_before
        );
        assert!(runtime
            .portfolio(MAKER_IDENTITY)
            .unwrap()
            .positions
            .is_empty());
        assert!(runtime
            .portfolio(TAKER_IDENTITY)
            .unwrap()
            .positions
            .is_empty());
        assert!(!runtime
            .portfolio(MAKER_IDENTITY)
            .unwrap()
            .registered_market_ids
            .contains(&MARKET.to_string()));
        let status = runtime.market_status(MARKET).unwrap();
        assert_eq!(status.market.market_id, MARKET);
        assert_eq!(status.resolution_outcome, Some(DirectResolutionOutcome::Up));
        assert_eq!(status.resolution_evidence_sha256, Some("a".repeat(64)));
        assert_eq!(store.artifacts().unwrap().len(), 5);

        let mut restarted = DirectRuntime::restore_committed(
            epoch,
            RuntimeMode::IsolatedTest,
            vec![7; 32],
            &[8; 32],
            &store,
        )
        .unwrap();
        assert_eq!(
            restarted
                .execute_committed(resolution, &[8; 32], &mut store)
                .unwrap(),
            resolved
        );
        assert_eq!(store.artifacts().unwrap().len(), 5);
        assert_eq!(
            restarted
                .execute(request(
                    "post-resolution-order",
                    DirectAction::PlaceOrder {
                        order_id: "77777777-8888-4999-8000-111111111111".into(),
                        market_id: MARKET.into(),
                        outcome: Outcome::Up,
                        action: OrderAction::Buy,
                        price_micros: 500_000,
                        quantity_micros: "1000000".into(),
                        time_in_force: TimeInForce::Gtc,
                        expires_at_millis: None,
                        now_millis: 10_000_001,
                    },
                ))
                .unwrap_err(),
            RuntimeError::InvalidMarket
        );
    }

    #[test]
    fn push_resolution_moves_indivisible_dust_to_rounding_reserve() {
        const MARKET: &str = "layrs:v5:BTC:USDC:15m:direct-push-rounding-fixture";
        const TAKER_SUBJECT: &str =
            "bae54f222a79c2ea394fa5b087d6a843e4b82562d0f3dfa33b8149b4beea21b3";
        const TAKER_IDENTITY: &str =
            "9bf6b307e41f94a5f5ec4211d2ac9eb5e4f2743b25224573391d7e8903276481";
        let epoch = SealedEpoch::load(epoch_path()).unwrap();
        let mut runtime =
            DirectRuntime::new(epoch.clone(), RuntimeMode::IsolatedTest, vec![7; 32]).unwrap();
        let mut store = InMemoryDirectStateStore::default();
        runtime
            .execute_committed(
                market_registration_request(MARKET, "push-market"),
                &[8; 32],
                &mut store,
            )
            .unwrap();
        runtime
            .execute_committed(
                request(
                    "push-maker",
                    DirectAction::PlaceOrder {
                        order_id: "12345678-1111-4111-8111-111111111111".into(),
                        market_id: MARKET.into(),
                        outcome: Outcome::Up,
                        action: OrderAction::Buy,
                        price_micros: 400_000,
                        quantity_micros: "3".into(),
                        time_in_force: TimeInForce::Gtc,
                        expires_at_millis: None,
                        now_millis: 1_000,
                    },
                ),
                &[8; 32],
                &mut store,
            )
            .unwrap();
        runtime
            .execute_committed(
                request_for(
                    TAKER_SUBJECT,
                    TAKER_IDENTITY,
                    "push-taker",
                    DirectAction::PlaceOrder {
                        order_id: "12345678-2222-4222-8222-222222222222".into(),
                        market_id: MARKET.into(),
                        outcome: Outcome::Down,
                        action: OrderAction::Buy,
                        price_micros: 600_000,
                        quantity_micros: "3".into(),
                        time_in_force: TimeInForce::Gtc,
                        expires_at_millis: None,
                        now_millis: 2_000,
                    },
                ),
                &[8; 32],
                &mut store,
            )
            .unwrap();
        let resolved = runtime
            .execute_committed(
                market_resolution_request(MARKET, "push-terminal", DirectResolutionOutcome::Push),
                &[8; 32],
                &mut store,
            )
            .unwrap();
        let details = resolved.receipt.resolution.as_ref().unwrap();
        assert_eq!(details.gross_payout_atomic, "2");
        assert_eq!(details.rounding_reserve_atomic, "1");
        assert_eq!(runtime.rounding_reserve_atomic, 1);
        assert!(!runtime.market_collateral.contains_key(MARKET));

        let restored = DirectRuntime::restore_committed(
            epoch,
            RuntimeMode::IsolatedTest,
            vec![7; 32],
            &[8; 32],
            &store,
        )
        .unwrap();
        assert_eq!(restored.rounding_reserve_atomic, 1);
        assert_eq!(
            restored.market_status(MARKET).unwrap().resolution_outcome,
            Some(DirectResolutionOutcome::Push)
        );
    }

    #[test]
    fn synthetic_new_user_lifecycle_is_conserved_archived_restart_and_replay_safe() {
        const MARKET: &str = "layrs:v5:BTC:USDC:15m:mm20-lifecycle-fixture";
        let subject = "d".repeat(64);
        let wallet = "0x2020202020202020202020202020202020202020";
        let identity = identity_commitment_for(&subject, wallet);
        let epoch = SealedEpoch::load(epoch_path()).unwrap();
        let mut runtime =
            DirectRuntime::new(epoch.clone(), RuntimeMode::IsolatedTest, vec![7; 32]).unwrap();
        let original_total: u128 = runtime
            .balances
            .values()
            .flat_map(|row| row.iter())
            .filter(|((asset, _), _)| asset == "USDC")
            .map(|(_, amount)| *amount)
            .sum();
        let mut store = InMemoryDirectStateStore::default();
        let mut admission = DirectRequest {
            account_id: subject.clone(),
            identity_commitment: identity.clone(),
            request_id: "mm20-admission".into(),
            request_hash: String::new(),
            financial_wallet_address: None,
            action: DirectAction::AdmitIdentity {
                wallet_address: wallet.into(),
            },
        };
        admission.request_hash = request_hash(&admission);
        runtime
            .execute_committed(admission, &[8; 32], &mut store)
            .unwrap();
        let deposit = request_for(
            &subject,
            &identity,
            "mm20-deposit",
            DirectAction::CreditDeposit {
                amount_atomic: "5000000".into(),
                custody_reference: "isolated-final-deposit".into(),
            },
        );
        runtime
            .execute_committed(deposit, &[8; 32], &mut store)
            .unwrap();
        runtime
            .execute_committed(
                market_registration_request(MARKET, "mm20-market"),
                &[8; 32],
                &mut store,
            )
            .unwrap();
        runtime
            .execute_committed(
                request(
                    "mm20-maker",
                    DirectAction::PlaceOrder {
                        order_id: "33333333-4444-4555-8666-777777777777".into(),
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
                &[8; 32],
                &mut store,
            )
            .unwrap();
        let trade = request_for(
            &subject,
            &identity,
            "mm20-trade",
            DirectAction::PlaceOrder {
                order_id: "44444444-5555-4666-8777-888888888888".into(),
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
        let traded = runtime
            .execute_committed(trade.clone(), &[8; 32], &mut store)
            .unwrap();
        assert_eq!(traded.receipt.execution.as_ref().unwrap().trades.len(), 1);
        let projected_identities = traded
            .receipt
            .projection_balance_updates
            .iter()
            .map(|row| row.identity_commitment.as_str())
            .collect::<BTreeSet<_>>();
        assert!(projected_identities.contains(identity.as_str()));
        assert!(projected_identities
            .contains("0bafc03d08d4951d769d58284db85c7ac2ee3c79de87ec680f58edc03017c418"));
        assert_eq!(
            runtime.balance(&identity, "USDC", "USER_AVAILABLE"),
            4_383_200
        );
        assert_eq!(
            runtime.total_position(&(identity.clone(), MARKET.into(), Outcome::Down)),
            1_000_000
        );
        let withdrawal = request_for(
            &subject,
            &identity,
            "mm20-withdrawal",
            DirectAction::ReserveWithdrawal {
                destination: "0x2222222222222222222222222222222222222222".into(),
                amount_atomic: "4383200".into(),
                custody_reference: "isolated-final-withdrawal".into(),
            },
        );
        let withdrawn = runtime
            .execute_committed(withdrawal.clone(), &[8; 32], &mut store)
            .unwrap();
        assert_eq!(runtime.balance(&identity, "USDC", "USER_AVAILABLE"), 0);
        assert_eq!(
            runtime.balance(&identity, "USDC", "USER_SETTLED"),
            4_383_200
        );
        let post_total: u128 = runtime
            .balances
            .values()
            .flat_map(|row| row.iter())
            .filter(|((asset, _), _)| asset == "USDC")
            .map(|(_, amount)| *amount)
            .sum::<u128>()
            + runtime.market_collateral.values().sum::<u128>()
            + runtime.fee_revenue_atomic;
        // Deposit representation is the sole external inflow; matching itself
        // conserves every atomic unit across users, collateral, and fees.
        assert_eq!(post_total, original_total + 5_000_000);
        assert_eq!(store.artifacts().unwrap().len(), 6);
        let mut restored = DirectRuntime::restore_committed(
            epoch,
            RuntimeMode::IsolatedTest,
            vec![7; 32],
            &[8; 32],
            &store,
        )
        .unwrap();
        assert_eq!(restored.balance(&identity, "USDC", "USER_AVAILABLE"), 0);
        assert_eq!(
            restored.balance(&identity, "USDC", "USER_SETTLED"),
            4_383_200
        );
        assert_eq!(
            restored
                .execute_committed(withdrawal, &[8; 32], &mut store)
                .unwrap(),
            withdrawn
        );
        assert_eq!(
            restored
                .execute_committed(trade, &[8; 32], &mut store)
                .unwrap(),
            traded
        );
        assert_eq!(store.artifacts().unwrap().len(), 6);
    }

    #[test]
    fn isolated_direct_path_covers_deposit_order_cancel_withdraw_and_restart() {
        let mut live_runtime = runtime(RuntimeMode::IsolatedTest);
        register_isolated_market(
            &mut live_runtime,
            "layrs:v5:BTC:USDC:15m:fixture",
            "register-market-e2e",
        );
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
                    order_id: "11111111-2222-4333-8444-555555555555".into(),
                    market_id: "layrs:v5:BTC:USDC:15m:fixture".into(),
                    outcome: Outcome::Up,
                    action: OrderAction::Buy,
                    price_micros: 400_000,
                    quantity_micros: "10".into(),
                    time_in_force: TimeInForce::Gtc,
                    expires_at_millis: None,
                    now_millis: 1_000,
                },
            ))
            .unwrap();
        live_runtime
            .execute(request(
                "cancel-e2e",
                DirectAction::CancelOrder {
                    order_id: "11111111-2222-4333-8444-555555555555".into(),
                },
            ))
            .unwrap();
        live_runtime
            .execute(request(
                "withdraw-e2e",
                DirectAction::ReserveWithdrawal {
                    destination: "0x2222222222222222222222222222222222222222".into(),
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
    fn rejected_fok_releases_cash_and_positions_without_fill_or_fee() {
        for action in [OrderAction::Buy, OrderAction::Sell] {
            let (mut live, subject, identity, _, mut store) = bus_fixture();
            let market = "layrs:v5:BTC:USDC:15m:fok-rejection";
            live.execute_committed(market_registration_request(market, "fok-market"), &[8;32], &mut store).unwrap();
            let key = (identity.clone(), market.to_string(), Outcome::Up);
            if action == OrderAction::Sell { live.positions.insert(key.clone(), 2_000_000); }
            let start = live.balance(&identity, "USDC", "USER_AVAILABLE");
            let command = request_for(&subject, &identity, "rejected-fok", DirectAction::PlaceOrder {
                order_id: BUS_ID.into(), market_id: market.into(), outcome: Outcome::Up, action,
                price_micros: 500_000, quantity_micros: "2000000".into(), time_in_force: TimeInForce::Fok,
                expires_at_millis: None, now_millis: 1_000,
            });
            let result = live.execute_committed(command.clone(), &[8;32], &mut store).unwrap();
            let execution = result.receipt.execution.as_ref().unwrap();
            assert_eq!(execution.status, OrderStatus::Rejected);
            assert_eq!(execution.executed_quantity_micros, "0");
            assert!(execution.trades.is_empty());
            assert_eq!(execution.total_fee_atomic, "0");
            assert_eq!(live.orders[BUS_ID].hold_atomic, 0);
            assert_eq!(live.balance(&identity, "USDC", "USER_ORDER_HOLD"), 0);
            assert_eq!(live.balance(&identity, "USDC", "USER_AVAILABLE"), start);
            if action == OrderAction::Sell { assert_eq!(live.positions[&key], 2_000_000); }
            // SELL inventory above is a synthetic in-memory fixture; BUY uses
            // the genuine committed deposit and exercises the full restore.
            if action == OrderAction::Sell { continue; }
            let mut restored = runtime(RuntimeMode::IsolatedTest);
            let mut artifacts = store.artifacts().unwrap();
            artifacts.sort_by_key(|artifact| artifact.sequence);
            for artifact in artifacts {
                let sequence = artifact.sequence;
                restored = restored.restore_next_committed(&artifact, &[8;32]).unwrap_or_else(|error| panic!("{action:?} successor {sequence}: {error:?}"));
            }
            assert_eq!(restored.orders[BUS_ID].hold_atomic, 0);
            assert_eq!(restored.execute_committed(command, &[8;32], &mut store).unwrap(), result);
        }
    }

    #[test]
    fn predecessor_rejected_fok_hold_recovers_by_owned_command_once() {
        let (mut live, subject, identity, _, mut store) = bus_fixture();
        let market = "layrs:v5:BTC:USDC:15m:fok-recovery";
        live.execute_committed(market_registration_request(market, "fok-recovery-market"), &[8;32], &mut store).unwrap();
        live.execute_committed(request_for(&subject, &identity, "old-fok", DirectAction::PlaceOrder {
            order_id: BUS_ID.into(), market_id: market.into(), outcome: Outcome::Up, action: OrderAction::Buy,
            price_micros: 500_000, quantity_micros: "2000000".into(), time_in_force: TimeInForce::Fok,
            expires_at_millis: None, now_millis: 1_000,
        }), &[8;32], &mut store).unwrap();
        // Synthetic predecessor snapshot reproduces the known retained hold.
        live.move_asset_bucket(&identity, "USDC", "USER_AVAILABLE", "USER_ORDER_HOLD", 1_000_000).unwrap();
        live.orders.get_mut(BUS_ID).unwrap().hold_atomic = 1_000_000;
        let mut artifacts = store.artifacts().unwrap();
        artifacts.sort_by_key(|artifact| artifact.sequence);
        let old = artifacts.pop().unwrap();
        let predecessor = live.seal_artifact(&old.prior_state_hash, &old.request_hash, &[8;32], old.receipt).unwrap();
        artifacts.push(predecessor);
        store = InMemoryDirectStateStore::from_artifacts(artifacts).unwrap();
        let start = live.balance(&identity, "USDC", "USER_AVAILABLE");
        assert!(matches!(live.cancel_order("wrong-owner", BUS_ID), Err(RuntimeError::IdentityDenied)));
        assert_eq!(live.orders[BUS_ID].hold_atomic, 1_000_000);
        let command = request_for(&subject, &identity, "owned-rejected-fok-recovery", DirectAction::CancelOrder { order_id: BUS_ID.into() });
        let result = live.execute_committed(command.clone(), &[8;32], &mut store).unwrap();
        assert_eq!(result.receipt.status, TerminalStatus::Applied);
        assert_eq!(live.orders[BUS_ID].order.status, OrderStatus::Rejected);
        assert_eq!(live.balance(&identity, "USDC", "USER_AVAILABLE"), start + 1_000_000);
        assert_eq!(live.balance(&identity, "USDC", "USER_ORDER_HOLD"), 0);
        let mut artifacts = store.artifacts().unwrap();
        artifacts.sort_by_key(|artifact| artifact.sequence);
        let head = artifacts.last().unwrap().clone();
        let hashes = artifacts.iter().map(artifact_hash).collect();
        let records = artifacts.into_iter().map(|mut artifact| { artifact.ciphertext.clear(); artifact }).collect();
        let checkpoint = live.seal_checkpoint(head, records, hashes, &[8;32]).unwrap();
        let mut restored = runtime(RuntimeMode::IsolatedTest).restore_checkpoint(&checkpoint, &[8;32]).unwrap();
        assert_eq!(restored.execute_committed(command, &[8;32], &mut store).unwrap(), result);
        assert_eq!(restored.cancel_order(&identity, BUS_ID).unwrap(), 0);
        assert_eq!(restored.balance(&identity, "USDC", "USER_AVAILABLE"), start + 1_000_000);
    }

    #[test]
    fn writer_grant_requires_matching_epoch_fence_signature_and_expiry() {
        use p256::ecdsa::{signature::Signer, SigningKey};
        let signing_key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let verifying_key = VerifyingKey::from(&signing_key);
        let binding = RuntimeMeasurementBinding {
            ami_id: "ami-0123456789abcdef0".into(),
            eif_sha256: "b".repeat(64),
            pcr0: "c".repeat(96),
            pcr1: "d".repeat(96),
            pcr2: "e".repeat(96),
            source_commit: "92e9918".into(),
            enclave_sha256: "f".repeat(64),
            parent_sha256: "a".repeat(64),
        };
        let mut grant = WriterGrant {
            activation_id: "step6-review-id".into(),
            environment: "production".into(),
            authorization_scope: "production-enabled".into(),
            epoch_id: EPOCH_ID.into(),
            runtime: TRANSACTION_MODEL.into(),
            opening_epoch_sha256: EPOCH_STATE_SHA256.into(),
            opening_evidence_manifest_sha256: EVIDENCE_MANIFEST_SHA256.into(),
            runtime_measurement: binding.clone(),
            old_writer_fence_evidence_sha256: "a".repeat(64),
            key_release_kms_key_id: "arn:aws:kms:us-east-1:111122223333:key/example".into(),
            key_release_predecessor: None,
            committed_restore_frontier: None,
            expires_at_unix: 200,
            governance_key_id: GOVERNANCE_KEY_ID.into(),
            signing_algorithm: GOVERNANCE_SIGNING_ALGORITHM.into(),
            signature: String::new(),
        };
        let signature: Signature = signing_key.sign(&serde_json::to_vec(&grant).unwrap());
        grant.signature = STANDARD.encode(signature.to_der().as_bytes());
        assert!(grant.verify_with_test_key(100, &binding, &verifying_key));
        let mut forged = grant.clone();
        forged.signature = STANDARD.encode([0u8; 8]);
        assert!(!forged.verify_with_test_key(100, &binding, &verifying_key));
        assert!(!grant.verify_with_test_key(200, &binding, &verifying_key));
        grant.old_writer_fence_evidence_sha256 = "b".repeat(64);
        assert!(!grant.verify_with_test_key(100, &binding, &verifying_key));
        grant.old_writer_fence_evidence_sha256 = "a".repeat(64);
        grant.runtime = "legacy.durable-command.v1".into();
        assert!(!grant.verify_with_test_key(100, &binding, &verifying_key));
        grant.runtime = TRANSACTION_MODEL.into();
        grant.environment = "isolated".into();
        assert!(!grant.verify_with_test_key(100, &binding, &verifying_key));
        grant.environment = "production".into();
        grant.opening_epoch_sha256 = "b".repeat(64);
        assert!(!grant.verify_with_test_key(100, &binding, &verifying_key));
        grant.opening_epoch_sha256 = EPOCH_STATE_SHA256.into();
        grant.epoch_id = "wrong-lineage".into();
        assert!(!grant.verify_with_test_key(100, &binding, &verifying_key));
        grant.epoch_id = EPOCH_ID.into();
        grant.runtime_measurement.pcr0 = "0".repeat(96);
        assert!(!grant.verify_with_test_key(100, &binding, &verifying_key));
    }

    #[test]
    fn governed_key_release_artifact_is_exactly_grant_and_measurement_bound() {
        use p256::ecdsa::{signature::Signer, SigningKey};
        let signing_key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let binding = RuntimeMeasurementBinding {
            ami_id: "ami-0123456789abcdef0".into(),
            eif_sha256: "b".repeat(64),
            pcr0: "c".repeat(96),
            pcr1: "d".repeat(96),
            pcr2: "e".repeat(96),
            source_commit: "key-release-test".into(),
            enclave_sha256: "f".repeat(64),
            parent_sha256: "a".repeat(64),
        };
        let mut grant = WriterGrant {
            activation_id: "key-release-test".into(),
            environment: "production".into(),
            authorization_scope: "production-enabled".into(),
            epoch_id: EPOCH_ID.into(),
            runtime: TRANSACTION_MODEL.into(),
            opening_epoch_sha256: EPOCH_STATE_SHA256.into(),
            opening_evidence_manifest_sha256: EVIDENCE_MANIFEST_SHA256.into(),
            runtime_measurement: binding.clone(),
            old_writer_fence_evidence_sha256: "1".repeat(64),
            key_release_kms_key_id: "arn:aws:kms:us-east-1:1:key/test".into(),
            key_release_predecessor: None,
            committed_restore_frontier: None,
            expires_at_unix: 200,
            governance_key_id: GOVERNANCE_KEY_ID.into(),
            signing_algorithm: GOVERNANCE_SIGNING_ALGORITHM.into(),
            signature: String::new(),
        };
        let signature: Signature = signing_key.sign(&serde_json::to_vec(&grant).unwrap());
        grant.signature = STANDARD.encode(signature.to_der().as_bytes());
        let artifact = GovernedKeyReleaseArtifact {
            protocol: "layrs.direct-execution.key-release.v1".into(),
            activation_id: grant.activation_id.clone(),
            writer_grant_commitment: grant.commitment(),
            runtime_measurement: binding.clone(),
            kms_key_id: grant.key_release_kms_key_id.clone(),
            encryption_context: BTreeMap::from([
                ("layrs-runtime".into(), TRANSACTION_MODEL.into()),
                ("layrs-epoch".into(), EPOCH_ID.into()),
                ("layrs-writer-grant".into(), grant.commitment()),
            ]),
            ciphertext_blob: vec![7; 64],
        };
        assert!(artifact.verify_for(&grant, &binding, &grant.key_release_kms_key_id));
        let predecessor = KeyReleasePredecessor {
            activation_id: artifact.activation_id.clone(),
            artifact_sha256: artifact.artifact_hash(),
            writer_grant_commitment: artifact.writer_grant_commitment.clone(),
        };
        assert!(artifact.verify_as_predecessor(&predecessor, &grant.key_release_kms_key_id));
        let mut wrong_predecessor = predecessor;
        wrong_predecessor.artifact_sha256 = "0".repeat(64);
        assert!(!artifact.verify_as_predecessor(&wrong_predecessor, &grant.key_release_kms_key_id));
        let mut conflict = artifact.clone();
        conflict.runtime_measurement.pcr0 = "9".repeat(96);
        assert!(!conflict.verify_for(&grant, &binding, &grant.key_release_kms_key_id));
        let mut conflict = artifact;
        conflict
            .encryption_context
            .insert("layrs-writer-grant".into(), "0".repeat(64));
        assert!(!conflict.verify_for(&grant, &binding, &grant.key_release_kms_key_id));
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
                destination: "0x2222222222222222222222222222222222222222".into(),
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

    // v70 persistence baseline (FULL_STATE_JOURNAL_V71_CONTRACT.md). These
    // tests characterize existing behavior only; they must keep passing
    // unchanged against v70 artifacts before compaction or journal work.
    const V70_MARKET: &str = "layrs:v5:BTC:USDC:1h:v70-baseline";
    const V70_MAKER_IDENTITY: &str =
        "0bafc03d08d4951d769d58284db85c7ac2ee3c79de87ec680f58edc03017c418";

    struct V70Lineage {
        live: DirectRuntime,
        store: InMemoryDirectStateStore,
        committed: Vec<(DirectRequest, DirectResult)>,
        subject: String,
        identity: String,
        wallet: String,
        maker_order: String,
    }

    /// Governance registration, admission, deposit, resting order, and a
    /// pending bus withdrawal: every persisted family touched by restore.
    fn v70_lineage() -> V70Lineage {
        let mut live = runtime(RuntimeMode::IsolatedTest);
        let mut store = InMemoryDirectStateStore::default();
        let subject = "a".repeat(64);
        let wallet = "0x1111111111111111111111111111111111111111".to_string();
        let identity = identity_commitment_for(&subject, &wallet);
        let maker_order = Uuid::from_u128(701).to_string();
        let mut deposit = request_for(
            &subject,
            &identity,
            "v70-deposit",
            DirectAction::CreditHorizenUsdcDeposit {
                amount_atomic: "10000000".into(),
                custody_reference: format!("horizen-usdc-deposit:0x{}", "ab".repeat(32)),
            },
        );
        deposit.financial_wallet_address = Some(wallet.clone());
        deposit.request_hash = request_hash(&deposit);
        let commands = vec![
            market_registration_request(V70_MARKET, "v70-market"),
            request_for(
                &subject,
                &identity,
                "v70-admission",
                DirectAction::AdmitIdentity { wallet_address: wallet.clone() },
            ),
            deposit,
            request(
                "v70-maker",
                DirectAction::PlaceOrder {
                    order_id: maker_order.clone(),
                    market_id: V70_MARKET.into(),
                    outcome: Outcome::Down,
                    action: OrderAction::Buy,
                    price_micros: 154_000,
                    quantity_micros: "10000000".into(),
                    time_in_force: TimeInForce::Gtc,
                    expires_at_millis: None,
                    now_millis: 1_000,
                },
            ),
            bus_begin(&subject, &identity, &wallet, BUS_ID),
        ];
        let mut committed = Vec::new();
        for command in commands {
            let result = live
                .execute_committed(command.clone(), &[8; 32], &mut store)
                .unwrap();
            committed.push((command, result));
        }
        assert_eq!(live.orders[&maker_order].hold_atomic, 1_540_000);
        assert!(live.pending_usdc_bus_withdrawal(&subject, BUS_ID).is_some());
        V70Lineage { live, store, committed, subject, identity, wallet, maker_order }
    }

    fn v70_sorted_artifacts(store: &InMemoryDirectStateStore) -> Vec<DirectStateArtifact> {
        let mut artifacts = store.artifacts().unwrap();
        artifacts.sort_by_key(|artifact| artifact.sequence);
        artifacts
    }

    /// Same account and request id, different intent. Only variants used by
    /// `v70_lineage` are supported.
    fn v70_conflicting(command: &DirectRequest) -> DirectRequest {
        let mut conflict = command.clone();
        match &mut conflict.action {
            DirectAction::RegisterMarket { registration, .. } => registration.expires_at_unix += 1,
            DirectAction::AdmitIdentity { wallet_address } => {
                *wallet_address = "0x3333333333333333333333333333333333333333".into()
            }
            DirectAction::CreditHorizenUsdcDeposit { amount_atomic, .. } => {
                *amount_atomic = "10000001".into()
            }
            DirectAction::PlaceOrder { price_micros, .. } => *price_micros += 100,
            DirectAction::BeginUsdcBusWithdrawal { amount_atomic, .. } => {
                *amount_atomic = "4840001".into()
            }
            _ => unreachable!("not part of the v70 baseline lineage"),
        }
        conflict.request_hash = request_hash(&conflict);
        assert_ne!(conflict.request_hash, command.request_hash);
        conflict
    }

    #[test]
    fn v70_exact_replay_returns_original_terminal_result_without_successor() {
        let V70Lineage { mut live, mut store, committed, subject, identity, wallet, .. } =
            v70_lineage();
        let archived = v70_sorted_artifacts(&store);
        let head_sequence = live.committed_sequence();
        let head_hash = live.committed_state_hash();
        for (command, result) in &committed {
            assert_eq!(live.existing_result(command).unwrap().as_ref(), Some(result));
            assert_eq!(live.execute_committed(command.clone(), &[8; 32], &mut store).unwrap(), *result);
            assert_eq!(live.execute(command.clone()).unwrap(), *result);
            // A replay candidate re-seals the current head; it is not a successor.
            let candidate = live.prepare_candidate(command.clone(), &[8; 32]).unwrap();
            assert_eq!(candidate.result, *result);
            assert_eq!(candidate.artifact.sequence, head_sequence);
            assert_eq!(candidate.artifact.prior_state_hash, head_hash);
            assert_eq!(candidate.artifact.state_hash, head_hash);
            assert!(live.clone().restore_next_committed(&candidate.artifact, &[8; 32]).is_err());
            assert_eq!(live.committed_sequence(), head_sequence);
            assert_eq!(live.committed_state_hash(), head_hash);
            assert_eq!(v70_sorted_artifacts(&store), archived);
        }

        // Replay is answered before writer authority is consulted.
        let mut dormant = DirectRuntime::restore_committed(
            SealedEpoch::load(epoch_path()).unwrap(),
            RuntimeMode::Dormant,
            vec![7; 32],
            &[8; 32],
            &store,
        )
        .unwrap();
        for (command, result) in &committed {
            assert_eq!(dormant.execute_committed(command.clone(), &[8; 32], &mut store).unwrap(), *result);
        }
        let fresh = bus_begin(&subject, &identity, &wallet, "22222222-2222-4333-8444-555555555555");
        assert_eq!(
            dormant.execute_committed(fresh, &[8; 32], &mut store),
            Err(RuntimeError::WriterDisabled)
        );
        assert_eq!(dormant.committed_state_hash(), head_hash);
        assert_eq!(v70_sorted_artifacts(&store), archived);
    }

    #[test]
    fn v70_conflicting_request_id_reuse_fails_closed() {
        let V70Lineage { live, mut store, committed, .. } = v70_lineage();
        let archived = v70_sorted_artifacts(&store);
        let checkpoint = checkpoint_fixture(&live, &store);
        let restarted = DirectRuntime::restore_committed(
            SealedEpoch::load(epoch_path()).unwrap(),
            RuntimeMode::IsolatedTest,
            vec![7; 32],
            &[8; 32],
            &store,
        )
        .unwrap();
        let checkpointed = runtime(RuntimeMode::IsolatedTest)
            .restore_checkpoint(&checkpoint, &[8; 32])
            .unwrap();
        for mut recovered in [live, restarted, checkpointed] {
            let head_hash = recovered.committed_state_hash();
            let head_sequence = recovered.committed_sequence();
            for (command, result) in &committed {
                let conflict = v70_conflicting(command);
                assert_eq!(recovered.existing_result(&conflict), Err(RuntimeError::RequestReuse));
                assert!(matches!(
                    recovered.prepare_candidate(conflict.clone(), &[8; 32]),
                    Err(RuntimeError::RequestReuse)
                ));
                assert_eq!(recovered.execute(conflict.clone()), Err(RuntimeError::RequestReuse));
                assert_eq!(
                    recovered.execute_committed(conflict, &[8; 32], &mut store),
                    Err(RuntimeError::RequestReuse)
                );
                // The original terminal result remains the only answer.
                assert_eq!(recovered.existing_result(command).unwrap().as_ref(), Some(result));
                assert_eq!(recovered.committed_state_hash(), head_hash);
                assert_eq!(recovered.committed_sequence(), head_sequence);
                assert_eq!(v70_sorted_artifacts(&store), archived);
            }
        }
    }

    #[test]
    fn v70_committed_sequence_is_derived_from_request_map_cardinality() {
        let V70Lineage { mut live, mut store, committed, subject, identity, wallet, .. } =
            v70_lineage();
        let artifacts = v70_sorted_artifacts(&store);
        assert_eq!(artifacts.len(), committed.len());
        assert_eq!(live.committed_sequence(), live.requests.len() as u64);
        assert_eq!(live.committed_sequence(), committed.len() as u64);

        let mut replay = runtime(RuntimeMode::IsolatedTest);
        assert_eq!(replay.committed_sequence(), 0);
        assert!(replay.requests.is_empty());
        for (artifact, (command, result)) in artifacts.iter().zip(&committed) {
            replay = replay.restore_next_committed(artifact, &[8; 32]).unwrap();
            assert_eq!(replay.committed_sequence(), artifact.sequence);
            assert_eq!(replay.requests.len() as u64, artifact.sequence);
            assert_eq!(artifact.request_hash, command.request_hash);
            assert_eq!(artifact.receipt, result.receipt);
        }

        // A command that errors records nothing and consumes no sequence.
        let head = artifacts.last().unwrap();
        let refused = bus_begin(&subject, &identity, &wallet, "22222222-2222-4333-8444-555555555555");
        assert_eq!(
            live.execute_committed(refused, &[8; 32], &mut store),
            Err(RuntimeError::WithdrawalPending)
        );
        assert_eq!(live.committed_sequence(), head.sequence);
        assert_eq!(live.requests.len() as u64, head.sequence);
        assert_eq!(v70_sorted_artifacts(&store), artifacts);

        // v70 has no explicit sequence: removing one historical request entry
        // (a naive compaction) rewinds the sealed sequence and forgets the
        // deduplication entry. v71 must not inherit this coupling.
        let (first, _) = &committed[0];
        let mut compacted = live.clone();
        compacted
            .requests
            .remove(&(first.account_id.clone(), first.request_id.clone()))
            .unwrap();
        assert_eq!(compacted.committed_sequence(), head.sequence - 1);
        assert_eq!(compacted.existing_result(first).unwrap(), None);
        let resealed = compacted
            .seal_artifact(&head.state_hash, &head.request_hash, &[8; 32], head.receipt.clone())
            .unwrap();
        assert_eq!(resealed.sequence, head.sequence - 1);
    }

    #[test]
    fn v70_artifact_restore_preserves_terminal_results_and_financial_state_hash() {
        let V70Lineage { live, store, committed, subject, identity, maker_order, .. } =
            v70_lineage();
        let artifacts = v70_sorted_artifacts(&store);
        let head = artifacts.last().unwrap();
        assert_eq!(head.state_hash, live.committed_state_hash());
        for (artifact, (_, result)) in artifacts.iter().zip(&committed) {
            assert_eq!(artifact.receipt, result.receipt);
        }

        let restored = DirectRuntime::restore_committed(
            SealedEpoch::load(epoch_path()).unwrap(),
            RuntimeMode::IsolatedTest,
            vec![7; 32],
            &[8; 32],
            &store,
        )
        .unwrap();
        let mut stepwise = runtime(RuntimeMode::IsolatedTest);
        for artifact in &artifacts {
            stepwise = stepwise.restore_next_committed(artifact, &[8; 32]).unwrap();
        }
        let checkpointed = runtime(RuntimeMode::IsolatedTest)
            .restore_checkpoint(&checkpoint_fixture(&live, &store), &[8; 32])
            .unwrap();

        for (path, recovered) in [("full", &restored), ("stepwise", &stepwise), ("checkpoint", &checkpointed)] {
            assert_eq!(recovered.committed_state_hash(), head.state_hash, "{path}");
            assert_eq!(recovered.committed_sequence(), head.sequence, "{path}");
            assert_eq!(recovered.balances, live.balances, "{path}");
            assert_eq!(recovered.positions, live.positions, "{path}");
            assert_eq!(recovered.market_collateral, live.market_collateral, "{path}");
            assert_eq!(recovered.credited_custody_references, live.credited_custody_references, "{path}");
            assert_eq!(recovered.orders[&maker_order].hold_atomic, live.orders[&maker_order].hold_atomic, "{path}");
            assert_eq!(recovered.portfolio(&identity).unwrap(), live.portfolio(&identity).unwrap(), "{path}");
            assert_eq!(
                recovered.portfolio(V70_MAKER_IDENTITY).unwrap(),
                live.portfolio(V70_MAKER_IDENTITY).unwrap(),
                "{path}"
            );
            assert_eq!(
                recovered.pending_usdc_bus_withdrawal(&subject, BUS_ID),
                live.pending_usdc_bus_withdrawal(&subject, BUS_ID),
                "{path}"
            );
            for (command, result) in &committed {
                let recovered_result = recovered.existing_result(command).unwrap().unwrap();
                assert_eq!(&recovered_result, result, "{path}");
                assert!(verify_receipt(&[7; 32], &recovered_result.receipt), "{path}");
            }
        }
    }

    #[test]
    fn v70_checkpoint_validation_detects_missing_duplicated_reordered_and_modified_records() {
        let V70Lineage { live, store, .. } = v70_lineage();
        let checkpoint = checkpoint_fixture(&live, &store);
        let records = &checkpoint.receipt_records;
        assert_eq!(records.len(), 5);
        assert_eq!(live.validate_checkpoint_records(&checkpoint), Ok(()));
        assert!(runtime(RuntimeMode::IsolatedTest).restore_checkpoint(&checkpoint, &[8; 32]).is_ok());

        let mut variants: Vec<(&str, DirectCheckpoint)> = Vec::new();
        let mut changed = checkpoint.clone();
        changed.receipt_records.remove(1);
        variants.push(("missing", changed));
        let mut changed = checkpoint.clone();
        changed.receipt_records.remove(1);
        changed.artifact_hashes.remove(1);
        variants.push(("missing-with-hash", changed));
        let mut changed = checkpoint.clone();
        changed.receipt_records.insert(2, records[1].clone());
        changed.artifact_hashes.insert(2, checkpoint.artifact_hashes[1].clone());
        variants.push(("duplicated", changed));
        let mut changed = checkpoint.clone();
        changed.receipt_records[2] = DirectStateArtifact {
            sequence: records[2].sequence,
            prior_state_hash: records[2].prior_state_hash.clone(),
            state_hash: records[2].state_hash.clone(),
            ..records[1].clone()
        };
        variants.push(("duplicated-rechained", changed));
        let mut changed = checkpoint.clone();
        changed.receipt_records.swap(1, 2);
        variants.push(("reordered", changed));
        let mut changed = checkpoint.clone();
        changed.receipt_records[1].receipt.effect = "TAMPERED".into();
        variants.push(("modified-effect", changed));
        let mut changed = checkpoint.clone();
        changed.receipt_records[1].receipt.signature = "0".repeat(64);
        variants.push(("modified-signature", changed));
        let mut changed = checkpoint.clone();
        changed.receipt_records[1].request_hash = "b".repeat(64);
        variants.push(("modified-request-hash", changed));
        let mut changed = checkpoint.clone();
        changed.receipt_records[1].state_hash = "b".repeat(64);
        variants.push(("modified-root", changed));
        let mut changed = checkpoint.clone();
        changed.receipt_records[1].ciphertext = vec![1];
        variants.push(("modified-ciphertext", changed));
        let mut changed = checkpoint.clone();
        changed.receipt_records[4].receipt.amount_atomic = Some("1".into());
        variants.push(("modified-head", changed));

        for (name, changed) in &variants {
            assert_eq!(live.validate_checkpoint_records(changed), Err(RuntimeError::StateArtifact), "{name}");
            assert!(
                live.seal_checkpoint(
                    checkpoint.artifact.clone(),
                    changed.receipt_records.clone(),
                    changed.artifact_hashes.clone(),
                    &[8; 32],
                )
                .is_err(),
                "{name}"
            );
            assert!(runtime(RuntimeMode::IsolatedTest).restore_checkpoint(changed, &[8; 32]).is_err(), "{name}");
            // Structural validation fails closed even under a valid MAC.
            let mut resigned = changed.clone();
            resigned.signature = sign(&[7; 32], &resigned.signature_bytes().unwrap());
            assert!(runtime(RuntimeMode::IsolatedTest).restore_checkpoint(&resigned, &[8; 32]).is_err(), "{name}");
        }

        // Characterization gap: structural validation binds each receipt to
        // the request map and a contiguous root chain, not to its original
        // position. A swap re-chained to the original sequences and roots is
        // rejected only by the checkpoint MAC.
        let mut rechained = checkpoint.clone();
        rechained.receipt_records[1] = DirectStateArtifact {
            sequence: records[1].sequence,
            prior_state_hash: records[1].prior_state_hash.clone(),
            state_hash: records[1].state_hash.clone(),
            ..records[2].clone()
        };
        rechained.receipt_records[2] = DirectStateArtifact {
            sequence: records[2].sequence,
            prior_state_hash: records[2].prior_state_hash.clone(),
            state_hash: records[2].state_hash.clone(),
            ..records[1].clone()
        };
        assert_eq!(live.validate_checkpoint_records(&rechained), Ok(()));
        assert!(runtime(RuntimeMode::IsolatedTest).restore_checkpoint(&rechained, &[8; 32]).is_err());
    }

    #[derive(Debug)]
    struct V70StateBytes {
        total: usize,
        request_history: usize,
        sealed_artifact: usize,
    }

    /// Serialized sizes of the exact v70 encrypted snapshot. The artifact is
    /// sealed only in memory and is never persisted.
    fn v70_state_bytes(live: &DirectRuntime) -> V70StateBytes {
        let state = live.snapshot();
        let (_, (hash, result)) = live.requests.iter().next_back().unwrap();
        let artifact = live
            .seal_artifact(&live.state_hash(), hash, &[8; 32], result.receipt.clone())
            .unwrap();
        V70StateBytes {
            total: serde_cbor::to_vec(&state).unwrap().len(),
            request_history: serde_cbor::to_vec(&state.requests).unwrap().len(),
            sealed_artifact: serde_cbor::to_vec(&artifact).unwrap().len(),
        }
    }

    /// Money-free terminal rejections grow only the request history.
    fn v70_append_money_free_rejections(
        live: &mut DirectRuntime,
        subject: &str,
        identity: &str,
        wallet: &str,
        count: u64,
    ) {
        for _ in 0..count {
            let id = Uuid::from_u128(0x70707070222243338444000000000000 + live.committed_sequence() as u128)
                .to_string();
            let result = live
                .execute(request_for(
                    subject,
                    identity,
                    &id,
                    DirectAction::BeginUsdcBusWithdrawal {
                        withdrawal_id: id.clone(),
                        destination_chain: "arbitrum".into(),
                        asset: "USDC".into(),
                        destination: wallet.into(),
                        amount_atomic: "999999999999999".into(),
                    },
                ))
                .unwrap();
            assert_eq!(result.effect, "WITHDRAWAL_REJECTED");
        }
    }

    #[test]
    fn v70_request_history_accounts_for_all_synthetic_state_growth() {
        let (mut live, subject, identity, wallet, _) = bus_fixture();
        let before = v70_state_bytes(&live);
        let sequence = live.committed_sequence();
        let balances = live.balances.clone();
        v70_append_money_free_rejections(&mut live, &subject, &identity, &wallet, 64);
        let after = v70_state_bytes(&live);
        assert_eq!(live.committed_sequence(), sequence + 64);
        assert_eq!(live.requests.len() as u64, sequence + 64);
        assert_eq!(live.balances, balances);
        assert_eq!(after.total - after.request_history, before.total - before.request_history);
        assert!(after.request_history > before.request_history);
        assert!(after.sealed_artifact > after.total);
    }

    #[test]
    #[ignore = "local measurement; run with --ignored --nocapture"]
    fn v70_measure_serialized_state_bytes_by_request_history() {
        let (mut live, subject, identity, wallet, _) = bus_fixture();
        let base_sequence = live.committed_sequence();
        let base = v70_state_bytes(&live);
        println!(
            "requests,total_state_bytes,request_history_bytes,non_request_bytes,sealed_artifact_cbor_bytes,incremental_request_bytes,incremental_bytes_per_request"
        );
        for target in [base_sequence, 1_000, 10_000, 50_000] {
            let missing = target - live.committed_sequence();
            v70_append_money_free_rejections(&mut live, &subject, &identity, &wallet, missing);
            let bytes = v70_state_bytes(&live);
            let added = live.committed_sequence() - base_sequence;
            let incremental = bytes.request_history - base.request_history;
            assert_eq!(bytes.total - bytes.request_history, base.total - base.request_history);
            println!(
                "{},{},{},{},{},{},{}",
                live.committed_sequence(),
                bytes.total,
                bytes.request_history,
                bytes.total - bytes.request_history,
                bytes.sealed_artifact,
                incremental,
                if added == 0 { 0 } else { incremental as u64 / added },
            );
        }
    }

    fn process_high_water_kib() -> u64 {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|status| {
                status.lines().find_map(|line| {
                    line.strip_prefix("VmHWM:")?
                        .split_whitespace()
                        .next()?
                        .parse()
                        .ok()
                })
            })
            .unwrap_or_default()
    }

    /// Conservative local RSS benchmark for the v70 frame bridge. It holds
    /// the source runtime while measuring candidate commit, checkpoint seal,
    /// checkpoint encoding, and restore, matching the enclave's worst overlap
    /// more closely than measuring serialized bytes alone.
    #[test]
    #[ignore = "local memory benchmark; set LAYRS_BRIDGE_BENCH_RECORDS"]
    fn v70_bridge_commit_checkpoint_and_restore_memory_benchmark() {
        let target: u64 = std::env::var("LAYRS_BRIDGE_BENCH_RECORDS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(10_000);
        assert!(target >= 3 && target <= MAX_V70_LINEAGE_RECORDS as u64);

        let started = std::time::Instant::now();
        let (mut live, subject, identity, wallet, store) = bus_fixture();
        let mut records = v70_sorted_artifacts(&store)
            .into_iter()
            .map(|mut artifact| {
                artifact.ciphertext.clear();
                artifact
            })
            .collect::<Vec<_>>();
        let mut root = records.last().unwrap().state_hash.clone();
        while live.committed_sequence() < target {
            let sequence = live.committed_sequence() + 1;
            let id = Uuid::from_u128(0x71717171222243338444000000000000 + sequence as u128)
                .to_string();
            let request = request_for(
                &subject,
                &identity,
                &id,
                DirectAction::BeginUsdcBusWithdrawal {
                    withdrawal_id: id.clone(),
                    destination_chain: "arbitrum".into(),
                    asset: "USDC".into(),
                    destination: wallet.clone(),
                    amount_atomic: "999999999999999".into(),
                },
            );
            let result = live.execute(request.clone()).unwrap();
            assert_eq!(result.effect, "WITHDRAWAL_REJECTED");
            let next_root = sha256(format!("v70-bridge-benchmark:{sequence}").as_bytes());
            records.push(DirectStateArtifact {
                epoch_id: EPOCH_ID.into(),
                sequence,
                prior_state_hash: root,
                state_hash: next_root.clone(),
                request_hash: request.request_hash,
                nonce: Vec::new(),
                ciphertext: Vec::new(),
                ciphertext_hash: String::new(),
                receipt: result.receipt,
            });
            root = next_root;
        }
        eprintln!(
            "BRIDGE_MEMORY stage=fixture records={target} elapsed_ms={} vmhwm_kib={}",
            started.elapsed().as_millis(),
            process_high_water_kib()
        );

        let next_sequence = live.committed_sequence() + 1;
        let next_id = Uuid::from_u128(
            0x72727272222243338444000000000000 + next_sequence as u128,
        )
        .to_string();
        let next = request_for(
            &subject,
            &identity,
            &next_id,
            DirectAction::BeginUsdcBusWithdrawal {
                withdrawal_id: next_id.clone(),
                destination_chain: "arbitrum".into(),
                asset: "USDC".into(),
                destination: wallet.clone(),
                amount_atomic: "999999999999999".into(),
            },
        );
        let commit_started = std::time::Instant::now();
        let candidate = live.prepare_candidate(next, &[8; 32]).unwrap();
        assert_eq!(candidate.artifact.sequence, next_sequence);
        eprintln!(
            "BRIDGE_MEMORY stage=commit elapsed_ms={} artifact_bytes={} vmhwm_kib={}",
            commit_started.elapsed().as_millis(),
            serde_cbor::to_vec(&candidate.artifact).unwrap().len(),
            process_high_water_kib()
        );
        drop(candidate);

        let last = records.pop().unwrap();
        let artifact = live
            .seal_artifact(
                &last.prior_state_hash,
                &last.request_hash,
                &[8; 32],
                last.receipt,
            )
            .unwrap();
        let mut compact_head = artifact.clone();
        compact_head.ciphertext.clear();
        records.push(compact_head);
        let mut artifact_hashes = vec!["a".repeat(64); records.len()];
        *artifact_hashes.last_mut().unwrap() = artifact_hash(&artifact);

        let checkpoint_started = std::time::Instant::now();
        let checkpoint = live
            .seal_checkpoint(artifact, records, artifact_hashes, &[8; 32])
            .unwrap();
        let checkpoint_bytes = serde_cbor::to_vec(&checkpoint).unwrap().len();
        assert!(checkpoint_bytes < crate::direct_frame::MAX_FRAME_BYTES);
        eprintln!(
            "BRIDGE_MEMORY stage=checkpoint elapsed_ms={} checkpoint_bytes={} vmhwm_kib={}",
            checkpoint_started.elapsed().as_millis(),
            checkpoint_bytes,
            process_high_water_kib()
        );

        let restore_started = std::time::Instant::now();
        let restored = runtime(RuntimeMode::IsolatedTest)
            .restore_checkpoint(&checkpoint, &[8; 32])
            .unwrap();
        assert_eq!(restored.committed_sequence(), target);
        assert_eq!(restored.committed_state_hash(), live.committed_state_hash());
        eprintln!(
            "BRIDGE_MEMORY stage=restore elapsed_ms={} vmhwm_kib={}",
            restore_started.elapsed().as_millis(),
            process_high_water_kib()
        );
    }
}
