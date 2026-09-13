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

mod external_effect;
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
    ReserveWithdrawal {
        destination: String,
        amount_atomic: String,
        custody_reference: String,
    },
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
    rounding_reserve_atomic: u128,
    /// Finalized external inflows are consumed exactly once across every
    /// account and request id. The reference is derived from the Base
    /// transaction hash after the parent has independently verified the
    /// transfer and finality.
    credited_custody_references: BTreeSet<String>,
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
    // This field was added after the opening lineage already had committed
    // artifacts.  Omitting its zero value preserves the exact pre-upgrade
    // CBOR and therefore the predecessor/state hashes for that lineage.
    #[serde(default, skip_serializing_if = "is_zero_u128")]
    rounding_reserve_atomic: u128,
    #[serde(default)]
    credited_custody_references: BTreeSet<String>,
    requests: BTreeMap<(String, String), (String, DirectResult)>,
}

fn is_zero_u128(value: &u128) -> bool {
    *value == 0
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
            markets: BTreeMap::new(),
            books: BTreeMap::new(),
            orders: BTreeMap::new(),
            positions: BTreeMap::new(),
            position_holds: BTreeMap::new(),
            position_cost_basis: BTreeMap::new(),
            market_collateral: BTreeMap::new(),
            resolved_markets: BTreeMap::new(),
            fee_revenue_atomic: 0,
            rounding_reserve_atomic: 0,
            credited_custody_references: BTreeSet::new(),
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
        let financial_wallet = request
            .financial_wallet_address
            .as_deref()
            .map(str::to_ascii_lowercase);
        match &request.action {
            // Preserve the existing deposit lane unchanged. Base deposit
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
            | DirectAction::RecordWithdrawalReverted { destination, .. } => {
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
                DirectAction::ReserveWithdrawal {
                    destination,
                    amount_atomic,
                    custody_reference,
                } => {
                    let value = amount(amount_atomic)?;
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
                DirectAction::SettleRelayWithdrawal {
                    relay,
                    amount_atomic,
                    custody_reference,
                } => {
                    let value = amount(amount_atomic)?;
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
            rounding_reserve_atomic: self.rounding_reserve_atomic,
            credited_custody_references: self.credited_custody_references.clone(),
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
            let quantity = self.total_position(key);
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
            let quantity = next.positions.get(key).copied().unwrap_or_default();
            let payout = match resolution.outcome {
                DirectResolutionOutcome::Up if key.2 == Outcome::Up => quantity,
                DirectResolutionOutcome::Down if key.2 == Outcome::Down => quantity,
                DirectResolutionOutcome::Push => quantity / 2,
                _ => 0,
            };
            if payout > 0 {
                next.add(&key.0, "USER_AVAILABLE", payout)?;
            }
            next.positions.remove(key);
            next.position_cost_basis.remove(key);
            touched.insert(key.0.clone());
        }
        next.position_cost_basis
            .retain(|(_, market_id, _), _| market_id != &resolution.market_id);
        next.market_collateral.remove(&resolution.market_id);
        next.rounding_reserve_atomic = next
            .rounding_reserve_atomic
            .checked_add(rounding_reserve)
            .ok_or(RuntimeError::InvalidOrder)?;
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
        let order_notional = direct_notional(price_micros, quantity)?;
        if order_notional < market.minimum_order_notional_micros
            || order_notional > market.maximum_order_notional_micros
        {
            return Err(RuntimeError::InvalidOrder);
        }
        let position_key = (identity.to_string(), market_id.to_string(), outcome);
        let existing_position = self.total_position(&position_key);
        if action == OrderAction::Buy
            && existing_position
                .checked_add(quantity)
                .ok_or(RuntimeError::InvalidOrder)?
                > market.maximum_user_position_micros
        {
            return Err(RuntimeError::InvalidOrder);
        }
        let initial_hold = match action {
            OrderAction::Buy => order_notional
                .checked_add(maximum_direct_taker_fee(&market, quantity, price_micros)?)
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
            self.move_bucket(identity, "USER_AVAILABLE", "USER_ORDER_HOLD", initial_hold)?;
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
            let taker_fee =
                direct_taker_fee(&market, fill.quantity_micros, fill.taker_price_micros())?;
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
                .balance(identity, "USDC", "USER_AVAILABLE")
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
        let notional = direct_notional(price_micros, quantity)?;
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
        self.add(&seller.private_user_id, "USER_AVAILABLE", seller_proceeds)?;
        self.fee_revenue_atomic = self
            .fee_revenue_atomic
            .checked_add(taker_fee)
            .ok_or(RuntimeError::InvalidOrder)?;
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
        let maker_amount = direct_notional(maker_price_micros, quantity)?;
        let taker_amount = quantity
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
            .checked_add(quantity)
            .ok_or(RuntimeError::InvalidOrder)?;
        self.fee_revenue_atomic = self
            .fee_revenue_atomic
            .checked_add(taker_fee)
            .ok_or(RuntimeError::InvalidOrder)?;
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
        if *collateral < quantity {
            return Err(RuntimeError::InsufficientAvailable);
        }
        *collateral -= quantity;
        let maker_amount = direct_notional(maker_price_micros, quantity)?;
        let taker_amount = quantity
            .checked_sub(maker_amount)
            .ok_or(RuntimeError::InvalidOrder)?;
        self.add(&maker.private_user_id, "USER_AVAILABLE", maker_amount)?;
        self.add(
            &taker.private_user_id,
            "USER_AVAILABLE",
            taker_amount
                .checked_sub(taker_fee)
                .ok_or(RuntimeError::InvalidOrder)?,
        )?;
        self.fee_revenue_atomic = self
            .fee_revenue_atomic
            .checked_add(taker_fee)
            .ok_or(RuntimeError::InvalidOrder)?;
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
        let owner = {
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
            reservation.order.private_user_id.clone()
        };
        if cash {
            self.subtract_bucket(&owner, "USER_ORDER_HOLD", amount)?;
        }
        Ok(())
    }

    fn release_excess_order_hold(&mut self, order_id: &str) -> Result<(), RuntimeError> {
        let (owner, action, desired, release, position_key) = {
            let reservation = self
                .orders
                .get(order_id)
                .ok_or(RuntimeError::UnknownOrder)?;
            let desired = match reservation.order.action {
                OrderAction::Buy => direct_notional(
                    reservation.order.price_micros,
                    reservation.order.remaining_micros,
                )?,
                OrderAction::Sell => reservation.order.remaining_micros,
            };
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
                    self.move_bucket(&owner, "USER_ORDER_HOLD", "USER_AVAILABLE", release)?
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
                self.move_bucket(identity, "USER_ORDER_HOLD", "USER_AVAILABLE", release)?
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

    fn subtract_bucket(
        &mut self,
        identity: &str,
        bucket: &str,
        value: u128,
    ) -> Result<(), RuntimeError> {
        let account = self
            .balances
            .get_mut(identity)
            .ok_or(RuntimeError::IdentityDenied)?;
        let balance = account.entry(("USDC".into(), bucket.into())).or_default();
        if *balance < value {
            return Err(RuntimeError::InsufficientAvailable);
        }
        *balance -= value;
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
        || market.settlement_asset != "USDC"
        || market.settlement_decimals != 6
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

fn direct_notional(price_micros: u64, quantity_micros: u128) -> Result<u128, RuntimeError> {
    u128::from(price_micros)
        .checked_mul(quantity_micros)
        .and_then(|value| value.checked_add(PRICE_SCALE - 1))
        .map(|value| value / PRICE_SCALE)
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
    },
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
    RecoveryComplete {
        recovered_sequence: u64,
        recovered_state_hash: String,
    },
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
            | DirectAction::RecordWithdrawalReverted { destination, .. } => {
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

    #[test]
    fn opening_state_hash_matches_existing_production_lineage() {
        let runtime = runtime(RuntimeMode::IsolatedTest);
        assert_eq!(runtime.committed_sequence(), 0);
        assert_eq!(
            runtime.state_hash(),
            "9fc0fd8e9699d23dcbb6fd85753035896dce219f6551a0540ea352c7089abe98"
        );
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
}
