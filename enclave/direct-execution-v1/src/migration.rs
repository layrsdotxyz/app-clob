//! Authenticated exact-result records for the one-time v70 to v71 migration.
//!
//! v70 keeps only `(request_hash, DirectResult)` in its live request map; it
//! does not retain the original `DirectRequest`.  These immutable records let
//! v71 remove that map while preserving exact retry results and conflicting-id
//! rejection.  They are deliberately separate from successor journal records:
//! migration records describe already-committed history and never mutate state.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;

use crate::{
    journal::{canonical_receipt_hash, canonical_result_hash},
    request_index::{request_index_root, TerminalRequestLeaf, TerminalResultLocator},
    sha256, verify_receipt, DirectResult, DirectRuntime, EPOCH_ID,
};

pub const V70_MIGRATION_RECORD_PROTOCOL: &str = "layrs.direct-execution.v70-migration-result.v1";
const MIGRATION_ID_DOMAIN: &[u8] = b"layrs.direct-execution.v70-migration-id.v1\0";
const MIGRATION_NONCE_DOMAIN: &[u8] = b"layrs.direct-execution.v70-migration-nonce.v1\0";
const MIGRATION_RECORDS_ROOT_DOMAIN: &[u8] =
    b"layrs.direct-execution.v70-migration-records-root.v1\0";
pub const V70_MIGRATION_MANIFEST_PROTOCOL: &str =
    "layrs.direct-execution.v70-migration-manifest.v1";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MigrationError {
    #[error("migration input is invalid")]
    Invalid,
    #[error("migration record authentication failed")]
    Authentication,
    #[error("migration record could not be decrypted")]
    Decryption,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MigratedTerminalRecord {
    pub protocol: String,
    pub epoch_id: String,
    pub migration_id: String,
    pub source_sequence: u64,
    pub source_state_hash: String,
    pub ordinal: u64,
    pub account_id: String,
    pub request_id: String,
    pub request_hash: String,
    pub result_hash: String,
    pub receipt_hash: String,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub ciphertext_hash: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V70MigrationManifest {
    pub protocol: String,
    pub epoch_id: String,
    pub migration_id: String,
    pub source_sequence: u64,
    pub source_state_hash: String,
    pub record_count: u64,
    pub records_root: String,
    pub request_index_root: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V70MigrationBundle {
    pub manifest: V70MigrationManifest,
    pub records: Vec<MigratedTerminalRecord>,
    pub leaves: Vec<TerminalRequestLeaf>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MigrationAssociatedData<'a> {
    protocol: &'a str,
    epoch_id: &'a str,
    migration_id: &'a str,
    source_sequence: u64,
    source_state_hash: &'a str,
    ordinal: u64,
    account_id: &'a str,
    request_id: &'a str,
    request_hash: &'a str,
    result_hash: &'a str,
    receipt_hash: &'a str,
}

impl MigratedTerminalRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn seal(
        source_sequence: u64,
        source_state_hash: &str,
        ordinal: u64,
        account_id: &str,
        request_id: &str,
        request_hash: &str,
        result: DirectResult,
        state_key: &[u8],
        signing_key_seed: &[u8],
        receipt_key: &[u8],
    ) -> Result<Self, MigrationError> {
        let migration_id = v70_migration_id(source_sequence, source_state_hash)?;
        let result_hash = canonical_result_hash(&result).map_err(|_| MigrationError::Invalid)?;
        let receipt_hash = canonical_receipt_hash(&result).map_err(|_| MigrationError::Invalid)?;
        if ordinal == 0
            || ordinal > source_sequence
            || account_id.is_empty()
            || request_id.is_empty()
            || !digest(request_hash)
            || state_key.len() != 32
            || signing_key_seed.len() != 32
            || receipt_key.len() != 32
            || !result_matches(account_id, request_id, request_hash, &result)
            || !verify_receipt(receipt_key, &result.receipt)
        {
            return Err(MigrationError::Invalid);
        }
        let associated_data = associated_data(
            &migration_id,
            source_sequence,
            source_state_hash,
            ordinal,
            account_id,
            request_id,
            request_hash,
            &result_hash,
            &receipt_hash,
        )?;
        let plaintext = serde_cbor::to_vec(&result).map_err(|_| MigrationError::Invalid)?;
        let nonce = migration_nonce(state_key, &associated_data, &plaintext)?;
        let ciphertext = ChaCha20Poly1305::new(Key::from_slice(state_key))
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &associated_data,
                },
            )
            .map_err(|_| MigrationError::Invalid)?;
        let mut record = Self {
            protocol: V70_MIGRATION_RECORD_PROTOCOL.into(),
            epoch_id: EPOCH_ID.into(),
            migration_id,
            source_sequence,
            source_state_hash: source_state_hash.into(),
            ordinal,
            account_id: account_id.into(),
            request_id: request_id.into(),
            request_hash: request_hash.into(),
            result_hash,
            receipt_hash,
            nonce,
            ciphertext_hash: sha256(&ciphertext),
            ciphertext,
            signature: String::new(),
        };
        record.signature = sign(signing_key_seed, &record.signature_bytes()?)?;
        Ok(record)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn open_replay(
        &self,
        expected_migration_id: &str,
        expected_ordinal: u64,
        expected_account_id: &str,
        expected_request_id: &str,
        expected_request_hash: &str,
        expected_result_hash: &str,
        expected_receipt_hash: &str,
        state_key: &[u8],
        verification_key: &[u8],
        receipt_key: &[u8],
    ) -> Result<DirectResult, MigrationError> {
        if self.protocol != V70_MIGRATION_RECORD_PROTOCOL
            || self.epoch_id != EPOCH_ID
            || self.migration_id != expected_migration_id
            || self.ordinal != expected_ordinal
            || self.account_id != expected_account_id
            || self.request_id != expected_request_id
            || self.request_hash != expected_request_hash
            || self.result_hash != expected_result_hash
            || self.receipt_hash != expected_receipt_hash
            || self.source_sequence == 0
            || self.ordinal == 0
            || self.ordinal > self.source_sequence
            || self.account_id.is_empty()
            || self.request_id.is_empty()
            || self.nonce.len() != 12
            || state_key.len() != 32
            || verification_key.len() != 32
            || receipt_key.len() != 32
            || ![
                self.migration_id.as_str(),
                self.source_state_hash.as_str(),
                self.request_hash.as_str(),
                self.result_hash.as_str(),
                self.receipt_hash.as_str(),
                self.ciphertext_hash.as_str(),
            ]
            .into_iter()
            .all(digest)
            || self.migration_id != v70_migration_id(self.source_sequence, &self.source_state_hash)?
            || self.ciphertext_hash != sha256(&self.ciphertext)
        {
            return Err(MigrationError::Invalid);
        }
        verify_signature(verification_key, &self.signature_bytes()?, &self.signature)?;
        let associated_data = associated_data(
            &self.migration_id,
            self.source_sequence,
            &self.source_state_hash,
            self.ordinal,
            &self.account_id,
            &self.request_id,
            &self.request_hash,
            &self.result_hash,
            &self.receipt_hash,
        )?;
        let plaintext = ChaCha20Poly1305::new(Key::from_slice(state_key))
            .decrypt(
                Nonce::from_slice(&self.nonce),
                Payload {
                    msg: &self.ciphertext,
                    aad: &associated_data,
                },
            )
            .map_err(|_| MigrationError::Decryption)?;
        if self.nonce != migration_nonce(state_key, &associated_data, &plaintext)? {
            return Err(MigrationError::Authentication);
        }
        let result: DirectResult =
            serde_cbor::from_slice(&plaintext).map_err(|_| MigrationError::Invalid)?;
        if canonical_result_hash(&result).map_err(|_| MigrationError::Invalid)? != self.result_hash
            || canonical_receipt_hash(&result).map_err(|_| MigrationError::Invalid)?
                != self.receipt_hash
            || !result_matches(
                &self.account_id,
                &self.request_id,
                &self.request_hash,
                &result,
            )
            || !verify_receipt(receipt_key, &result.receipt)
        {
            return Err(MigrationError::Authentication);
        }
        Ok(result)
    }

    pub fn record_hash(&self) -> Result<String, MigrationError> {
        serde_cbor::to_vec(self)
            .map(|bytes| sha256(&bytes))
            .map_err(|_| MigrationError::Invalid)
    }

    fn signature_bytes(&self) -> Result<Vec<u8>, MigrationError> {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        serde_cbor::to_vec(&unsigned).map_err(|_| MigrationError::Invalid)
    }
}

impl V70MigrationManifest {
    pub fn manifest_hash(&self) -> Result<String, MigrationError> {
        serde_cbor::to_vec(self)
            .map(|bytes| sha256(&bytes))
            .map_err(|_| MigrationError::Invalid)
    }

    fn signature_bytes(&self) -> Result<Vec<u8>, MigrationError> {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        serde_cbor::to_vec(&unsigned).map_err(|_| MigrationError::Invalid)
    }

    pub fn verify_signature(&self, verification_key: &[u8]) -> Result<(), MigrationError> {
        if self.protocol != V70_MIGRATION_MANIFEST_PROTOCOL
            || self.epoch_id != EPOCH_ID
            || self.source_sequence == 0
            || self.record_count != self.source_sequence
            || ![
                self.migration_id.as_str(),
                self.source_state_hash.as_str(),
                self.records_root.as_str(),
                self.request_index_root.as_str(),
            ]
            .into_iter()
            .all(digest)
            || self.migration_id != v70_migration_id(self.source_sequence, &self.source_state_hash)?
        {
            return Err(MigrationError::Invalid);
        }
        verify_signature(verification_key, &self.signature_bytes()?, &self.signature)
    }
}

impl V70MigrationBundle {
    /// Creates an authenticated export from the exact in-enclave v70 head.
    /// BTreeMap iteration fixes ordinals by `(account_id, request_id)` and the
    /// manifest commits both every record and the complete request-index root.
    pub fn seal(
        runtime: &DirectRuntime,
        state_key: &[u8],
        signing_key_seed: &[u8],
    ) -> Result<Self, MigrationError> {
        let source_sequence = runtime.requests.len() as u64;
        if source_sequence == 0
            || source_sequence != runtime.committed_sequence()
            || state_key.len() != 32
            || signing_key_seed.len() != 32
        {
            return Err(MigrationError::Invalid);
        }
        let source_state_hash = runtime.committed_state_hash();
        let migration_id = v70_migration_id(source_sequence, &source_state_hash)?;
        let mut records = Vec::with_capacity(runtime.requests.len());
        let mut leaves = Vec::with_capacity(runtime.requests.len());
        for (index, ((account_id, request_id), (request_hash, result))) in
            runtime.requests.iter().enumerate()
        {
            let ordinal = index as u64 + 1;
            let record = MigratedTerminalRecord::seal(
                source_sequence,
                &source_state_hash,
                ordinal,
                account_id,
                request_id,
                request_hash,
                result.clone(),
                state_key,
                signing_key_seed,
                &runtime.receipt_key,
            )?;
            leaves.push(TerminalRequestLeaf {
                account_id: account_id.clone(),
                request_id: request_id.clone(),
                request_hash: request_hash.clone(),
                result_hash: record.result_hash.clone(),
                receipt_hash: record.receipt_hash.clone(),
                locator: TerminalResultLocator::Migration {
                    migration_id: migration_id.clone(),
                    ordinal,
                },
            });
            records.push(record);
        }
        let records_root = migration_records_root(&migration_id, &records)?;
        let request_index_root =
            request_index_root(&leaves).map_err(|_| MigrationError::Invalid)?;
        let mut manifest = V70MigrationManifest {
            protocol: V70_MIGRATION_MANIFEST_PROTOCOL.into(),
            epoch_id: EPOCH_ID.into(),
            migration_id,
            source_sequence,
            source_state_hash,
            record_count: records.len() as u64,
            records_root,
            request_index_root,
            signature: String::new(),
        };
        manifest.signature = sign(signing_key_seed, &manifest.signature_bytes()?)?;
        Ok(Self {
            manifest,
            records,
            leaves,
        })
    }

    pub fn verify_complete(
        &self,
        state_key: &[u8],
        verification_key: &[u8],
        receipt_key: &[u8],
    ) -> Result<(), MigrationError> {
        self.manifest.verify_signature(verification_key)?;
        if self.records.len() != self.manifest.record_count as usize
            || self.leaves.len() != self.records.len()
            || migration_records_root(&self.manifest.migration_id, &self.records)?
                != self.manifest.records_root
            || request_index_root(&self.leaves).map_err(|_| MigrationError::Invalid)?
                != self.manifest.request_index_root
        {
            return Err(MigrationError::Authentication);
        }
        for (index, (record, leaf)) in self.records.iter().zip(&self.leaves).enumerate() {
            let ordinal = index as u64 + 1;
            if record.migration_id != self.manifest.migration_id
                || record.source_sequence != self.manifest.source_sequence
                || record.source_state_hash != self.manifest.source_state_hash
                || record.ordinal != ordinal
                || leaf.account_id != record.account_id
                || leaf.request_id != record.request_id
                || leaf.request_hash != record.request_hash
                || leaf.result_hash != record.result_hash
                || leaf.receipt_hash != record.receipt_hash
                || leaf.locator
                    != (TerminalResultLocator::Migration {
                        migration_id: self.manifest.migration_id.clone(),
                        ordinal,
                    })
            {
                return Err(MigrationError::Authentication);
            }
            record.open_replay(
                &self.manifest.migration_id,
                ordinal,
                &leaf.account_id,
                &leaf.request_id,
                &leaf.request_hash,
                &leaf.result_hash,
                &leaf.receipt_hash,
                state_key,
                verification_key,
                receipt_key,
            )?;
        }
        Ok(())
    }
}

fn migration_records_root(
    migration_id: &str,
    records: &[MigratedTerminalRecord],
) -> Result<String, MigrationError> {
    if !digest(migration_id) || records.is_empty() {
        return Err(MigrationError::Invalid);
    }
    let mut opening = Vec::with_capacity(MIGRATION_RECORDS_ROOT_DOMAIN.len() + migration_id.len());
    opening.extend_from_slice(MIGRATION_RECORDS_ROOT_DOMAIN);
    opening.extend_from_slice(migration_id.as_bytes());
    let mut root = sha256(&opening);
    for (index, record) in records.iter().enumerate() {
        if record.ordinal != index as u64 + 1 || record.migration_id != migration_id {
            return Err(MigrationError::Invalid);
        }
        let mut bytes =
            Vec::with_capacity(MIGRATION_RECORDS_ROOT_DOMAIN.len() + root.len() + 8 + 64);
        bytes.extend_from_slice(MIGRATION_RECORDS_ROOT_DOMAIN);
        bytes.extend_from_slice(root.as_bytes());
        bytes.extend_from_slice(&record.ordinal.to_be_bytes());
        bytes.extend_from_slice(record.record_hash()?.as_bytes());
        root = sha256(&bytes);
    }
    Ok(root)
}

pub fn v70_migration_id(
    source_sequence: u64,
    source_state_hash: &str,
) -> Result<String, MigrationError> {
    if source_sequence == 0 || !digest(source_state_hash) {
        return Err(MigrationError::Invalid);
    }
    let mut bytes = Vec::with_capacity(
        MIGRATION_ID_DOMAIN.len() + EPOCH_ID.len() + source_state_hash.len() + 8,
    );
    bytes.extend_from_slice(MIGRATION_ID_DOMAIN);
    bytes.extend_from_slice(EPOCH_ID.as_bytes());
    bytes.extend_from_slice(&source_sequence.to_be_bytes());
    bytes.extend_from_slice(source_state_hash.as_bytes());
    Ok(sha256(&bytes))
}

#[allow(clippy::too_many_arguments)]
fn associated_data(
    migration_id: &str,
    source_sequence: u64,
    source_state_hash: &str,
    ordinal: u64,
    account_id: &str,
    request_id: &str,
    request_hash: &str,
    result_hash: &str,
    receipt_hash: &str,
) -> Result<Vec<u8>, MigrationError> {
    serde_cbor::to_vec(&MigrationAssociatedData {
        protocol: V70_MIGRATION_RECORD_PROTOCOL,
        epoch_id: EPOCH_ID,
        migration_id,
        source_sequence,
        source_state_hash,
        ordinal,
        account_id,
        request_id,
        request_hash,
        result_hash,
        receipt_hash,
    })
    .map_err(|_| MigrationError::Invalid)
}

fn migration_nonce(
    state_key: &[u8],
    associated_data: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, MigrationError> {
    if state_key.len() != 32 || associated_data.is_empty() || plaintext.is_empty() {
        return Err(MigrationError::Invalid);
    }
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(state_key).map_err(|_| MigrationError::Invalid)?;
    mac.update(MIGRATION_NONCE_DOMAIN);
    mac.update(&(associated_data.len() as u64).to_be_bytes());
    mac.update(associated_data);
    mac.update(&(plaintext.len() as u64).to_be_bytes());
    mac.update(plaintext);
    Ok(mac.finalize().into_bytes()[..12].to_vec())
}

fn result_matches(
    account_id: &str,
    request_id: &str,
    request_hash: &str,
    result: &DirectResult,
) -> bool {
    result.status == result.receipt.status
        && result.effect == result.receipt.effect
        && result.genesis_ordinal == result.receipt.genesis_ordinal
        && result.receipt.account_id == account_id
        && result.receipt.request_id == request_id
        && result.receipt.request_hash == request_hash
}

fn sign(seed: &[u8], bytes: &[u8]) -> Result<String, MigrationError> {
    let seed: [u8; 32] = seed.try_into().map_err(|_| MigrationError::Invalid)?;
    Ok(hex::encode(
        SigningKey::from_bytes(&seed).sign(bytes).to_bytes(),
    ))
}

fn verify_signature(key: &[u8], bytes: &[u8], signature: &str) -> Result<(), MigrationError> {
    let key: [u8; 32] = key.try_into().map_err(|_| MigrationError::Authentication)?;
    let signature: [u8; 64] = hex::decode(signature)
        .map_err(|_| MigrationError::Authentication)?
        .try_into()
        .map_err(|_| MigrationError::Authentication)?;
    VerifyingKey::from_bytes(&key)
        .map_err(|_| MigrationError::Authentication)?
        .verify(bytes, &Signature::from_bytes(&signature))
        .map_err(|_| MigrationError::Authentication)
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;
    use crate::{
        identity_commitment_for, journal::journal_verifying_key, receipt_signature, request_hash,
        DirectAction, DirectReceipt, DirectRequest, RuntimeMode, SealedEpoch, TerminalStatus,
    };

    fn result() -> DirectResult {
        let mut receipt = DirectReceipt {
            receipt_id: "a".repeat(64),
            account_id: "account".into(),
            identity_commitment: "identity".into(),
            request_id: "request-1".into(),
            request_hash: "b".repeat(64),
            status: TerminalStatus::Applied,
            effect: "IDENTITY_ADMITTED".into(),
            amount_atomic: None,
            custody_reference: None,
            command_commitment: None,
            execution: None,
            resolution: None,
            projection_balance_updates: vec![],
            genesis_ordinal: 0,
            signature: String::new(),
        };
        receipt.signature = receipt_signature(&[9; 32], &receipt);
        DirectResult {
            status: receipt.status.clone(),
            effect: receipt.effect.clone(),
            genesis_ordinal: receipt.genesis_ordinal,
            receipt,
        }
    }

    fn record() -> MigratedTerminalRecord {
        MigratedTerminalRecord::seal(
            35_000,
            &"c".repeat(64),
            7,
            "account",
            "request-1",
            &"b".repeat(64),
            result(),
            &[7; 32],
            &[8; 32],
            &[9; 32],
        )
        .unwrap()
    }

    #[test]
    fn migrated_result_round_trip_preserves_exact_terminal_result() {
        let record = record();
        let replayed = record
            .open_replay(
                &record.migration_id,
                7,
                "account",
                "request-1",
                &"b".repeat(64),
                &record.result_hash,
                &record.receipt_hash,
                &[7; 32],
                &journal_verifying_key(&[8; 32]).unwrap(),
                &[9; 32],
            )
            .unwrap();
        assert_eq!(replayed, result());
        assert!(serde_cbor::to_vec(&record).unwrap().len() < 16 * 1024);
    }

    #[test]
    fn migrated_result_rejects_wrong_locator_and_tampering() {
        let record = record();
        assert_eq!(
            record.open_replay(
                &record.migration_id,
                8,
                "account",
                "request-1",
                &"b".repeat(64),
                &record.result_hash,
                &record.receipt_hash,
                &[7; 32],
                &journal_verifying_key(&[8; 32]).unwrap(),
                &[9; 32],
            ),
            Err(MigrationError::Invalid)
        );
        let mut tampered = record;
        tampered.ciphertext[0] ^= 1;
        assert!(tampered
            .open_replay(
                &tampered.migration_id,
                7,
                "account",
                "request-1",
                &"b".repeat(64),
                &tampered.result_hash,
                &tampered.receipt_hash,
                &[7; 32],
                &journal_verifying_key(&[8; 32]).unwrap(),
                &[9; 32],
            )
            .is_err());
    }

    #[test]
    fn complete_bundle_binds_every_v70_result_and_sparse_root() {
        let epoch = SealedEpoch {
            identities: BTreeMap::new(),
            identity_subjects: BTreeMap::new(),
            subject_identities: BTreeMap::new(),
            subject_wallets: BTreeMap::<String, BTreeSet<String>>::new(),
        };
        let mut runtime =
            DirectRuntime::new(epoch, RuntimeMode::IsolatedTest, vec![9; 32]).unwrap();
        for index in 1..=2 {
            let account = if index == 1 {
                "a".repeat(64)
            } else {
                "b".repeat(64)
            };
            let wallet = format!("0x{index:040x}");
            let mut request = DirectRequest {
                account_id: account.clone(),
                identity_commitment: identity_commitment_for(&account, &wallet),
                request_id: format!("request-{index}"),
                request_hash: String::new(),
                financial_wallet_address: None,
                action: DirectAction::AdmitIdentity {
                    wallet_address: wallet,
                },
            };
            request.request_hash = request_hash(&request);
            runtime.execute(request).unwrap();
        }
        let bundle = V70MigrationBundle::seal(&runtime, &[7; 32], &[8; 32]).unwrap();
        assert_eq!(bundle.manifest.source_sequence, 2);
        assert_eq!(bundle.manifest.record_count, 2);
        assert_eq!(
            bundle.manifest.source_state_hash,
            runtime.committed_state_hash()
        );
        bundle
            .verify_complete(
                &[7; 32],
                &journal_verifying_key(&[8; 32]).unwrap(),
                &[9; 32],
            )
            .unwrap();

        let mut omitted = bundle.clone();
        omitted.records.pop();
        assert!(omitted
            .verify_complete(
                &[7; 32],
                &journal_verifying_key(&[8; 32]).unwrap(),
                &[9; 32],
            )
            .is_err());
        let mut reordered = bundle;
        reordered.records.swap(0, 1);
        assert!(reordered
            .verify_complete(
                &[7; 32],
                &journal_verifying_key(&[8; 32]).unwrap(),
                &[9; 32],
            )
            .is_err());
    }
}
