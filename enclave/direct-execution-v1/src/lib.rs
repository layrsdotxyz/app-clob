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
    reference_for, ExternalEffectIntent, ExternalEffectObservation, ExternalEffectRecovery,
    FilesystemImmutableIntentStore, ImmutableExternalEffectIntentStore,
    EXTERNAL_EFFECT_INTENT_PROTOCOL_VERSION, MAX_PROVIDER_IDEMPOTENCY_WINDOW_SECONDS,
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
    #[error("withdrawal destination is not the caller's verified embedded wallet")]
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
    /// A terminal external revert is recorded once in the same immutable
    /// lineage, with no balance movement.  It is not a retriable custody job.
    RecordWithdrawalReverted {
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
    pub execution: Option<OrderExecution>,
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
    fee_revenue_atomic: u128,
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
    fee_revenue_atomic: u128,
    #[serde(default)]
    credited_custody_references: BTreeSet<String>,
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
            markets: BTreeMap::new(),
            books: BTreeMap::new(),
            orders: BTreeMap::new(),
            positions: BTreeMap::new(),
            position_holds: BTreeMap::new(),
            position_cost_basis: BTreeMap::new(),
            market_collateral: BTreeMap::new(),
            fee_revenue_atomic: 0,
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
        let governed_market = matches!(&request.action, DirectAction::RegisterMarket { .. });
        if self.mode == RuntimeMode::AdmissionOnly && !(admission || governed_market) {
            return Err(RuntimeError::WriterDisabled);
        }
        if !(admission || governed_market)
            && !self.owns(&request.account_id, &request.identity_commitment)
        {
            return Err(RuntimeError::IdentityDenied);
        }
        let mut execution = None;
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
                DirectAction::RecordWithdrawalReverted {
                    destination,
                    amount_atomic,
                    custody_reference,
                } => {
                    let _ = amount(amount_atomic)?;
                    let destination = destination.to_ascii_lowercase();
                    if !valid_withdrawal_custody_reference(custody_reference, self.mode)
                        || !self
                            .subject_wallets
                            .get(&request.account_id)
                            .is_some_and(|wallets| wallets.contains(&destination))
                    {
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
            fee_revenue_atomic: self.fee_revenue_atomic,
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
        self.fee_revenue_atomic = state.fee_revenue_atomic;
        self.credited_custody_references = state.credited_custody_references;
        self.requests = state.requests;
        Ok(())
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
        let mut r = DirectRequest {
            account_id: subject.into(),
            identity_commitment: identity.into(),
            request_id: id.into(),
            request_hash: String::new(),
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
            action: DirectAction::RegisterMarket {
                registration,
                now_unix: 1,
            },
        };
        request.request_hash = request_hash(&request);
        request
    }
    fn runtime(mode: RuntimeMode) -> DirectRuntime {
        DirectRuntime::new(SealedEpoch::load(epoch_path()).unwrap(), mode, vec![7; 32]).unwrap()
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
    fn post_genesis_identity_admission_is_zero_balance_restart_and_replay_safe() {
        let subject = "d".repeat(64);
        let wallet = "0x2222222222222222222222222222222222222222";
        let identity = identity_commitment_for(&subject, wallet);
        let mut admission = DirectRequest {
            account_id: subject.clone(),
            identity_commitment: identity.clone(),
            request_id: "identity-admission-fixture-01".into(),
            request_hash: String::new(),
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
                destination: wallet.into(),
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
