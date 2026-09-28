//! Canonical, encrypted successor records for the v71 persistence path.
//!
//! This module is deliberately independent of the active v70 commit path. It
//! defines and verifies the bounded record that will replace a full encrypted
//! state snapshot after every command; wiring it into writer authority is a
//! separate, explicitly tested migration step.

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
    constant_time_eq, request_hash,
    request_index::{SparseRequestProof, TerminalRequestLeaf, TerminalResultLocator},
    sha256, sign as hmac_sign, verify_receipt, DirectRequest, DirectResult, EPOCH_ID,
};

pub const DIRECT_JOURNAL_PROTOCOL: &str = "layrs.direct-execution.journal.v71";
const JOURNAL_NONCE_DOMAIN: &[u8] = b"layrs.direct-execution.journal-nonce.v1\0";
const JOURNAL_TRANSITION_DOMAIN: &[u8] = b"layrs.direct-execution.transition-root.v1\0";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum JournalError {
    #[error("journal input is invalid")]
    Invalid,
    #[error("journal authentication failed")]
    Authentication,
    #[error("journal payload could not be decrypted")]
    Decryption,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectJournalPayload {
    pub request: DirectRequest,
    pub result: DirectResult,
    pub request_proof: SparseRequestProof,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectJournalRecord {
    pub protocol: String,
    pub epoch_id: String,
    pub writer_epoch: String,
    pub sequence: u64,
    pub previous_record_hash: String,
    pub previous_transition_root: String,
    pub transition_root: String,
    pub previous_request_index_root: String,
    pub request_index_root: String,
    pub account_id: String,
    pub request_id: String,
    pub request_hash: String,
    pub receipt_hash: String,
    pub result_hash: String,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub ciphertext_hash: String,
    pub signature: String,
}

/// Parent acknowledgement issued only after the exact journal record has been
/// durably created and read back. The HMAC prevents an untrusted process from
/// adopting an unpersisted or different candidate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JournalDurabilityAck {
    pub epoch_id: String,
    pub writer_epoch: String,
    pub sequence: u64,
    pub previous_record_hash: String,
    pub record_hash: String,
    pub transition_root: String,
    pub request_index_root: String,
    pub request_hash: String,
    pub result_hash: String,
    pub signature: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JournalAssociatedData<'a> {
    protocol: &'a str,
    epoch_id: &'a str,
    writer_epoch: &'a str,
    sequence: u64,
    previous_record_hash: &'a str,
    previous_transition_root: &'a str,
    transition_root: &'a str,
    previous_request_index_root: &'a str,
    request_index_root: &'a str,
    account_id: &'a str,
    request_id: &'a str,
    request_hash: &'a str,
    receipt_hash: &'a str,
    result_hash: &'a str,
}

impl DirectJournalRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn seal(
        writer_epoch: &str,
        sequence: u64,
        previous_record_hash: &str,
        previous_transition_root: &str,
        previous_request_index_root: &str,
        request_index_root: &str,
        request_proof: SparseRequestProof,
        request: DirectRequest,
        result: DirectResult,
        state_key: &[u8],
        signing_key_seed: &[u8],
        receipt_key: &[u8],
    ) -> Result<Self, JournalError> {
        if writer_epoch.is_empty()
            || writer_epoch.len() > 128
            || sequence == 0
            || !digest(previous_record_hash)
            || !digest(previous_transition_root)
            || !digest(previous_request_index_root)
            || !digest(request_index_root)
            || previous_request_index_root == request_index_root
            || state_key.len() != 32
            || signing_key_seed.len() != 32
            || receipt_key.len() != 32
            || request.account_id.is_empty()
            || request.request_id.is_empty()
            || request.request_hash != request_hash(&request)
            || !result_matches_request(&result, &request)
            || !verify_receipt(receipt_key, &result.receipt)
        {
            return Err(JournalError::Invalid);
        }

        let account_id = request.account_id.clone();
        let request_id = request.request_id.clone();
        let committed_request_hash = request.request_hash.clone();
        let receipt_hash = canonical_hash(&result.receipt)?;
        let result_hash = canonical_hash(&result)?;
        let terminal_leaf = TerminalRequestLeaf {
            account_id: account_id.clone(),
            request_id: request_id.clone(),
            request_hash: committed_request_hash.clone(),
            result_hash: result_hash.clone(),
            receipt_hash: receipt_hash.clone(),
            locator: TerminalResultLocator::Journal {
                writer_epoch: writer_epoch.into(),
                sequence,
            },
        };
        if request_proof.leaf.is_some()
            || request_proof
                .insert(previous_request_index_root, &terminal_leaf)
                .ok()
                .as_deref()
                != Some(request_index_root)
        {
            return Err(JournalError::Invalid);
        }
        let transition_root = transition_root(
            previous_transition_root,
            sequence,
            &committed_request_hash,
            &result_hash,
            request_index_root,
        );
        let associated_data = associated_data(
            writer_epoch,
            sequence,
            previous_record_hash,
            previous_transition_root,
            &transition_root,
            previous_request_index_root,
            request_index_root,
            &account_id,
            &request_id,
            &committed_request_hash,
            &receipt_hash,
            &result_hash,
        )?;
        let plaintext = serde_cbor::to_vec(&DirectJournalPayload {
            request,
            result,
            request_proof,
        })
        .map_err(|_| JournalError::Invalid)?;
        // A writer crash can cause the same sequence to be prepared again
        // against a different predecessor or result.  Bind the nonce to all
        // authenticated metadata and plaintext so those competing candidates
        // cannot reuse a ChaCha20-Poly1305 nonce under the same state key.
        let nonce = journal_nonce(state_key, &associated_data, &plaintext)?;
        let ciphertext = ChaCha20Poly1305::new(Key::from_slice(state_key))
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &associated_data,
                },
            )
            .map_err(|_| JournalError::Invalid)?;
        let mut record = Self {
            protocol: DIRECT_JOURNAL_PROTOCOL.into(),
            epoch_id: EPOCH_ID.into(),
            writer_epoch: writer_epoch.into(),
            sequence,
            previous_record_hash: previous_record_hash.into(),
            previous_transition_root: previous_transition_root.into(),
            transition_root,
            previous_request_index_root: previous_request_index_root.into(),
            request_index_root: request_index_root.into(),
            account_id,
            request_id,
            request_hash: committed_request_hash,
            receipt_hash,
            result_hash,
            nonce,
            ciphertext_hash: sha256(&ciphertext),
            ciphertext,
            signature: String::new(),
        };
        record.signature = sign(signing_key_seed, &record.signature_bytes()?)?;
        Ok(record)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn open_successor(
        &self,
        expected_writer_epoch: &str,
        expected_sequence: u64,
        expected_previous_record_hash: &str,
        expected_previous_transition_root: &str,
        expected_previous_request_index_root: &str,
        state_key: &[u8],
        verification_key: &[u8],
        receipt_key: &[u8],
    ) -> Result<DirectJournalPayload, JournalError> {
        if self.writer_epoch != expected_writer_epoch
            || self.sequence != expected_sequence
            || self.previous_record_hash != expected_previous_record_hash
            || self.previous_transition_root != expected_previous_transition_root
            || self.previous_request_index_root != expected_previous_request_index_root
        {
            return Err(JournalError::Invalid);
        }
        self.open_authenticated(state_key, verification_key, receipt_key)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn open_replay(
        &self,
        expected_writer_epoch: &str,
        expected_sequence: u64,
        expected_account_id: &str,
        expected_request_id: &str,
        expected_request_hash: &str,
        expected_result_hash: &str,
        expected_receipt_hash: &str,
        state_key: &[u8],
        verification_key: &[u8],
        receipt_key: &[u8],
    ) -> Result<DirectJournalPayload, JournalError> {
        if self.writer_epoch != expected_writer_epoch
            || self.sequence != expected_sequence
            || self.account_id != expected_account_id
            || self.request_id != expected_request_id
            || self.request_hash != expected_request_hash
            || self.result_hash != expected_result_hash
            || self.receipt_hash != expected_receipt_hash
        {
            return Err(JournalError::Invalid);
        }
        self.open_authenticated(state_key, verification_key, receipt_key)
    }

    fn open_authenticated(
        &self,
        state_key: &[u8],
        verification_key: &[u8],
        receipt_key: &[u8],
    ) -> Result<DirectJournalPayload, JournalError> {
        if self.protocol != DIRECT_JOURNAL_PROTOCOL
            || self.epoch_id != EPOCH_ID
            || self.writer_epoch.is_empty()
            || self.writer_epoch.len() > 128
            || self.sequence == 0
            || self.account_id.is_empty()
            || self.request_id.is_empty()
            || self.nonce.len() != 12
            || state_key.len() != 32
            || verification_key.len() != 32
            || receipt_key.len() != 32
            || self.previous_request_index_root == self.request_index_root
            || ![
                self.previous_record_hash.as_str(),
                self.previous_transition_root.as_str(),
                self.transition_root.as_str(),
                self.previous_request_index_root.as_str(),
                self.request_index_root.as_str(),
                self.request_hash.as_str(),
                self.receipt_hash.as_str(),
                self.result_hash.as_str(),
                self.ciphertext_hash.as_str(),
            ]
            .into_iter()
            .all(digest)
            || self.ciphertext_hash != sha256(&self.ciphertext)
            || self.transition_root
                != transition_root(
                    &self.previous_transition_root,
                    self.sequence,
                    &self.request_hash,
                    &self.result_hash,
                    &self.request_index_root,
                )
        {
            return Err(JournalError::Invalid);
        }
        verify_signature(verification_key, &self.signature_bytes()?, &self.signature)?;
        let associated_data = associated_data(
            &self.writer_epoch,
            self.sequence,
            &self.previous_record_hash,
            &self.previous_transition_root,
            &self.transition_root,
            &self.previous_request_index_root,
            &self.request_index_root,
            &self.account_id,
            &self.request_id,
            &self.request_hash,
            &self.receipt_hash,
            &self.result_hash,
        )?;
        let plaintext = ChaCha20Poly1305::new(Key::from_slice(state_key))
            .decrypt(
                Nonce::from_slice(&self.nonce),
                Payload {
                    msg: &self.ciphertext,
                    aad: &associated_data,
                },
            )
            .map_err(|_| JournalError::Decryption)?;
        let payload: DirectJournalPayload =
            serde_cbor::from_slice(&plaintext).map_err(|_| JournalError::Invalid)?;
        let terminal_leaf = TerminalRequestLeaf {
            account_id: self.account_id.clone(),
            request_id: self.request_id.clone(),
            request_hash: self.request_hash.clone(),
            result_hash: self.result_hash.clone(),
            receipt_hash: self.receipt_hash.clone(),
            locator: TerminalResultLocator::Journal {
                writer_epoch: self.writer_epoch.clone(),
                sequence: self.sequence,
            },
        };
        if self.nonce != journal_nonce(state_key, &associated_data, &plaintext)?
            || payload.request.account_id != self.account_id
            || payload.request.request_id != self.request_id
            || payload.request.request_hash != self.request_hash
            || request_hash(&payload.request) != self.request_hash
            || canonical_hash(&payload.result.receipt)? != self.receipt_hash
            || canonical_hash(&payload.result)? != self.result_hash
            || !result_matches_request(&payload.result, &payload.request)
            || !verify_receipt(receipt_key, &payload.result.receipt)
            || payload.request_proof.leaf.is_some()
            || payload
                .request_proof
                .insert(&self.previous_request_index_root, &terminal_leaf)
                .ok()
                .as_deref()
                != Some(self.request_index_root.as_str())
        {
            return Err(JournalError::Authentication);
        }
        Ok(payload)
    }

    pub fn record_hash(&self) -> Result<String, JournalError> {
        canonical_hash(self)
    }

    fn signature_bytes(&self) -> Result<Vec<u8>, JournalError> {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        serde_cbor::to_vec(&unsigned).map_err(|_| JournalError::Invalid)
    }
}

impl JournalDurabilityAck {
    pub fn issue(record: &DirectJournalRecord, key: &[u8]) -> Result<Self, JournalError> {
        if key.len() < 32 {
            return Err(JournalError::Invalid);
        }
        let mut ack = Self {
            epoch_id: record.epoch_id.clone(),
            writer_epoch: record.writer_epoch.clone(),
            sequence: record.sequence,
            previous_record_hash: record.previous_record_hash.clone(),
            record_hash: record.record_hash()?,
            transition_root: record.transition_root.clone(),
            request_index_root: record.request_index_root.clone(),
            request_hash: record.request_hash.clone(),
            result_hash: record.result_hash.clone(),
            signature: String::new(),
        };
        ack.signature = hmac_sign(key, &ack.unsigned_bytes()?);
        Ok(ack)
    }

    pub fn verify_for(&self, record: &DirectJournalRecord, key: &[u8]) -> bool {
        key.len() >= 32
            && record
                .record_hash()
                .is_ok_and(|hash| hash == self.record_hash)
            && self.epoch_id == record.epoch_id
            && self.writer_epoch == record.writer_epoch
            && self.sequence == record.sequence
            && self.previous_record_hash == record.previous_record_hash
            && self.transition_root == record.transition_root
            && self.request_index_root == record.request_index_root
            && self.request_hash == record.request_hash
            && self.result_hash == record.result_hash
            && self
                .unsigned_bytes()
                .is_ok_and(|bytes| constant_time_eq(&self.signature, &hmac_sign(key, &bytes)))
    }

    fn unsigned_bytes(&self) -> Result<Vec<u8>, JournalError> {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        serde_cbor::to_vec(&unsigned).map_err(|_| JournalError::Invalid)
    }
}

pub fn transition_root(
    previous_transition_root: &str,
    sequence: u64,
    request_hash: &str,
    result_hash: &str,
    request_index_root: &str,
) -> String {
    let mut bytes = Vec::with_capacity(
        JOURNAL_TRANSITION_DOMAIN.len()
            + previous_transition_root.len()
            + request_hash.len()
            + result_hash.len()
            + request_index_root.len()
            + 8,
    );
    bytes.extend_from_slice(JOURNAL_TRANSITION_DOMAIN);
    bytes.extend_from_slice(previous_transition_root.as_bytes());
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes.extend_from_slice(request_hash.as_bytes());
    bytes.extend_from_slice(result_hash.as_bytes());
    bytes.extend_from_slice(request_index_root.as_bytes());
    sha256(&bytes)
}

fn associated_data(
    writer_epoch: &str,
    sequence: u64,
    previous_record_hash: &str,
    previous_transition_root: &str,
    transition_root: &str,
    previous_request_index_root: &str,
    request_index_root: &str,
    account_id: &str,
    request_id: &str,
    request_hash: &str,
    receipt_hash: &str,
    result_hash: &str,
) -> Result<Vec<u8>, JournalError> {
    serde_cbor::to_vec(&JournalAssociatedData {
        protocol: DIRECT_JOURNAL_PROTOCOL,
        epoch_id: EPOCH_ID,
        writer_epoch,
        sequence,
        previous_record_hash,
        previous_transition_root,
        transition_root,
        previous_request_index_root,
        request_index_root,
        account_id,
        request_id,
        request_hash,
        receipt_hash,
        result_hash,
    })
    .map_err(|_| JournalError::Invalid)
}

fn journal_nonce(
    state_key: &[u8],
    associated_data: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, JournalError> {
    if state_key.len() != 32 || associated_data.is_empty() || plaintext.is_empty() {
        return Err(JournalError::Invalid);
    }
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(state_key).map_err(|_| JournalError::Invalid)?;
    mac.update(JOURNAL_NONCE_DOMAIN);
    mac.update(&(associated_data.len() as u64).to_be_bytes());
    mac.update(associated_data);
    mac.update(&(plaintext.len() as u64).to_be_bytes());
    mac.update(plaintext);
    Ok(mac.finalize().into_bytes()[..12].to_vec())
}

fn canonical_hash<T: Serialize>(value: &T) -> Result<String, JournalError> {
    serde_cbor::to_vec(value)
        .map(|bytes| sha256(&bytes))
        .map_err(|_| JournalError::Invalid)
}

pub fn canonical_result_hash(result: &DirectResult) -> Result<String, JournalError> {
    canonical_hash(result)
}

pub fn canonical_receipt_hash(result: &DirectResult) -> Result<String, JournalError> {
    canonical_hash(&result.receipt)
}

fn result_matches_request(result: &DirectResult, request: &DirectRequest) -> bool {
    result.status == result.receipt.status
        && result.effect == result.receipt.effect
        && result.genesis_ordinal == result.receipt.genesis_ordinal
        && result.receipt.account_id == request.account_id
        && result.receipt.identity_commitment == request.identity_commitment
        && result.receipt.request_id == request.request_id
        && result.receipt.request_hash == request.request_hash
}

pub fn journal_verifying_key(signing_key_seed: &[u8]) -> Result<[u8; 32], JournalError> {
    let seed: [u8; 32] = signing_key_seed
        .try_into()
        .map_err(|_| JournalError::Invalid)?;
    Ok(SigningKey::from_bytes(&seed).verifying_key().to_bytes())
}

pub fn derive_journal_signing_key(state_key: &[u8]) -> Result<[u8; 32], JournalError> {
    if state_key.len() != 32 {
        return Err(JournalError::Invalid);
    }
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(state_key).map_err(|_| JournalError::Invalid)?;
    mac.update(b"layrs.direct-execution.journal-signing-key.v1\0");
    mac.update(EPOCH_ID.as_bytes());
    Ok(mac.finalize().into_bytes().into())
}

fn sign(signing_key_seed: &[u8], bytes: &[u8]) -> Result<String, JournalError> {
    let seed: [u8; 32] = signing_key_seed
        .try_into()
        .map_err(|_| JournalError::Invalid)?;
    Ok(hex::encode(
        SigningKey::from_bytes(&seed).sign(bytes).to_bytes(),
    ))
}

fn verify_signature(key: &[u8], bytes: &[u8], signature: &str) -> Result<(), JournalError> {
    let key: [u8; 32] = key.try_into().map_err(|_| JournalError::Authentication)?;
    let signature: [u8; 64] = hex::decode(signature)
        .map_err(|_| JournalError::Authentication)?
        .try_into()
        .map_err(|_| JournalError::Authentication)?;
    VerifyingKey::from_bytes(&key)
        .map_err(|_| JournalError::Authentication)?
        .verify(bytes, &Signature::from_bytes(&signature))
        .map_err(|_| JournalError::Authentication)
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{receipt_signature, DirectAction, DirectReceipt, TerminalStatus};

    fn payload() -> (DirectRequest, DirectResult) {
        let mut request = DirectRequest {
            account_id: "account".into(),
            identity_commitment: "identity".into(),
            request_id: "request-1".into(),
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
            status: TerminalStatus::Applied,
            effect: "IDENTITY_ADMITTED".into(),
            amount_atomic: None,
            custody_reference: None,
            execution: None,
            resolution: None,
            projection_balance_updates: vec![],
            genesis_ordinal: 0,
            signature: String::new(),
        };
        receipt.signature = receipt_signature(&[9; 32], &receipt);
        let result = DirectResult {
            status: receipt.status.clone(),
            effect: receipt.effect.clone(),
            genesis_ordinal: receipt.genesis_ordinal,
            receipt,
        };
        (request, result)
    }

    fn terminal_leaf(
        writer_epoch: &str,
        sequence: u64,
        request: &DirectRequest,
        result: &DirectResult,
    ) -> TerminalRequestLeaf {
        TerminalRequestLeaf {
            account_id: request.account_id.clone(),
            request_id: request.request_id.clone(),
            request_hash: request.request_hash.clone(),
            result_hash: canonical_result_hash(result).unwrap(),
            receipt_hash: canonical_receipt_hash(result).unwrap(),
            locator: TerminalResultLocator::Journal {
                writer_epoch: writer_epoch.into(),
                sequence,
            },
        }
    }

    fn record() -> DirectJournalRecord {
        let (request, result) = payload();
        let proof = SparseRequestProof::empty_tree();
        let previous_index = crate::request_index::empty_request_index_root();
        let next_index = proof
            .insert(
                &previous_index,
                &terminal_leaf("writer-epoch-1", 1, &request, &result),
            )
            .unwrap();
        DirectJournalRecord::seal(
            "writer-epoch-1",
            1,
            &"a".repeat(64),
            &"b".repeat(64),
            &previous_index,
            &next_index,
            proof,
            request,
            result,
            &[7; 32],
            &[8; 32],
            &[9; 32],
        )
        .unwrap()
    }

    fn journal_public_key() -> [u8; 32] {
        journal_verifying_key(&[8; 32]).unwrap()
    }

    #[test]
    fn journal_round_trip_is_bounded_and_authenticated() {
        let record = record();
        assert!(serde_cbor::to_vec(&record).unwrap().len() < 64 * 1024);
        let payload = record
            .open_successor(
                "writer-epoch-1",
                1,
                &"a".repeat(64),
                &"b".repeat(64),
                &record.previous_request_index_root,
                &[7; 32],
                &journal_public_key(),
                &[9; 32],
            )
            .unwrap();
        assert_eq!(payload.request.request_id, "request-1");
        assert_eq!(payload.result.effect, "IDENTITY_ADMITTED");
    }

    #[test]
    fn nonce_is_stable_for_an_identical_record_but_changes_with_the_candidate() {
        let (request, result) = payload();
        let proof = SparseRequestProof::empty_tree();
        let previous_index = crate::request_index::empty_request_index_root();
        let next_index = proof
            .insert(
                &previous_index,
                &terminal_leaf("writer-epoch-1", 1, &request, &result),
            )
            .unwrap();
        let first = DirectJournalRecord::seal(
            "writer-epoch-1",
            1,
            &"a".repeat(64),
            &"b".repeat(64),
            &previous_index,
            &next_index,
            proof.clone(),
            request.clone(),
            result.clone(),
            &[7; 32],
            &[8; 32],
            &[9; 32],
        )
        .unwrap();
        let identical = DirectJournalRecord::seal(
            "writer-epoch-1",
            1,
            &"a".repeat(64),
            &"b".repeat(64),
            &previous_index,
            &next_index,
            proof.clone(),
            request.clone(),
            result.clone(),
            &[7; 32],
            &[8; 32],
            &[9; 32],
        )
        .unwrap();
        let competing = DirectJournalRecord::seal(
            "writer-epoch-1",
            1,
            &"c".repeat(64),
            &"d".repeat(64),
            &previous_index,
            &next_index,
            proof,
            request,
            result,
            &[7; 32],
            &[8; 32],
            &[9; 32],
        )
        .unwrap();

        assert_eq!(first, identical);
        assert_ne!(first.nonce, competing.nonce);
        assert_ne!(first.ciphertext, competing.ciphertext);
    }

    #[test]
    fn journal_rejects_wrong_sequence_and_predecessor() {
        let record = record();
        assert_eq!(
            record.open_successor(
                "writer-epoch-1",
                2,
                &"a".repeat(64),
                &"b".repeat(64),
                &record.previous_request_index_root,
                &[7; 32],
                &journal_public_key(),
                &[9; 32],
            ),
            Err(JournalError::Invalid)
        );
        assert_eq!(
            record.open_successor(
                "writer-epoch-1",
                1,
                &"d".repeat(64),
                &"b".repeat(64),
                &record.previous_request_index_root,
                &[7; 32],
                &journal_public_key(),
                &[9; 32],
            ),
            Err(JournalError::Invalid)
        );
    }

    #[test]
    fn journal_rejects_modified_ciphertext_and_signature() {
        let mut tampered_ciphertext = record();
        tampered_ciphertext.ciphertext[0] ^= 1;
        assert!(tampered_ciphertext
            .open_successor(
                "writer-epoch-1",
                1,
                &"a".repeat(64),
                &"b".repeat(64),
                &tampered_ciphertext.previous_request_index_root,
                &[7; 32],
                &journal_public_key(),
                &[9; 32],
            )
            .is_err());

        let mut tampered_signature = record();
        tampered_signature.signature.replace_range(..2, "00");
        assert_eq!(
            tampered_signature.open_successor(
                "writer-epoch-1",
                1,
                &"a".repeat(64),
                &"b".repeat(64),
                &tampered_signature.previous_request_index_root,
                &[7; 32],
                &journal_public_key(),
                &[9; 32],
            ),
            Err(JournalError::Authentication)
        );
    }

    #[test]
    fn journal_chain_uses_the_complete_previous_record() {
        let first = record();
        let (mut request, result) = payload();
        request.request_id = "request-2".into();
        request.request_hash = request_hash(&request);
        let mut result = result;
        result.receipt.request_id = request.request_id.clone();
        result.receipt.request_hash = request.request_hash.clone();
        result.receipt.receipt_id = "d".repeat(64);
        result.receipt.signature = receipt_signature(&[9; 32], &result.receipt);
        let first_leaf = TerminalRequestLeaf {
            account_id: first.account_id.clone(),
            request_id: first.request_id.clone(),
            request_hash: first.request_hash.clone(),
            result_hash: first.result_hash.clone(),
            receipt_hash: first.receipt_hash.clone(),
            locator: TerminalResultLocator::Journal {
                writer_epoch: first.writer_epoch.clone(),
                sequence: first.sequence,
            },
        };
        let tree = crate::request_index::SparseRequestTree::from_leaves(&[first_leaf]).unwrap();
        let proof = tree
            .proof(&request.account_id, &request.request_id)
            .unwrap();
        let next_index = proof
            .insert(
                &first.request_index_root,
                &terminal_leaf("writer-epoch-1", 2, &request, &result),
            )
            .unwrap();
        let second = DirectJournalRecord::seal(
            "writer-epoch-1",
            2,
            &first.record_hash().unwrap(),
            &first.transition_root,
            &first.request_index_root,
            &next_index,
            proof,
            request,
            result,
            &[7; 32],
            &[8; 32],
            &[9; 32],
        )
        .unwrap();
        assert!(second
            .open_successor(
                "writer-epoch-1",
                2,
                &first.record_hash().unwrap(),
                &first.transition_root,
                &first.request_index_root,
                &[7; 32],
                &journal_public_key(),
                &[9; 32],
            )
            .is_ok());
    }

    #[test]
    fn durability_ack_is_bound_to_the_exact_journal_candidate() {
        let record = record();
        let ack = JournalDurabilityAck::issue(&record, &[6; 32]).unwrap();
        assert!(ack.verify_for(&record, &[6; 32]));
        assert!(!ack.verify_for(&record, &[5; 32]));

        let mut changed = record;
        changed.request_index_root = "d".repeat(64);
        assert!(!ack.verify_for(&changed, &[6; 32]));
        let mut changed_ack = ack;
        changed_ack.sequence += 1;
        assert!(!changed_ack.verify_for(&changed, &[6; 32]));
    }

    #[test]
    fn journal_signing_key_is_domain_derived_from_the_state_key() {
        let first = derive_journal_signing_key(&[7; 32]).unwrap();
        assert_eq!(first, derive_journal_signing_key(&[7; 32]).unwrap());
        assert_ne!(first, derive_journal_signing_key(&[8; 32]).unwrap());
        assert!(derive_journal_signing_key(&[7; 31]).is_err());
        assert!(journal_verifying_key(&first).is_ok());
    }
}
