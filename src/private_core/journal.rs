use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use ed25519_dalek::{Signer, SigningKey};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{CoreError, CoreResult};

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct JournalKey([u8; 32]);

impl JournalKey {
    pub fn generate() -> Self {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        Self(key)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedJournalRecord {
    pub sequence: u64,
    pub nonce: [u8; 12],
    pub prior_record_hash: [u8; 32],
    pub state_root: [u8; 32],
    pub ciphertext: Vec<u8>,
    pub record_hash: [u8; 32],
}

pub struct EncryptedJournal {
    cipher: Aes256Gcm,
    records: Vec<EncryptedJournalRecord>,
}

impl EncryptedJournal {
    pub fn new(key: JournalKey) -> Self {
        Self {
            cipher: Aes256Gcm::new_from_slice(&key.0).expect("AES-256 key length is fixed"),
            records: Vec::new(),
        }
    }

    pub fn append<T: Serialize>(
        &mut self,
        state_root: [u8; 32],
        value: &T,
    ) -> CoreResult<EncryptedJournalRecord> {
        let sequence = self.records.len() as u64 + 1;
        let prior_record_hash = self
            .records
            .last()
            .map(|record| record.record_hash)
            .unwrap_or([0u8; 32]);
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&sequence.to_be_bytes());
        OsRng.fill_bytes(&mut nonce[8..]);
        let aad = associated_data(sequence, &prior_record_hash, &state_root);
        let plaintext = serde_json::to_vec(value).map_err(|_| CoreError::JournalCrypto)?;
        let ciphertext = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| CoreError::JournalCrypto)?;
        let record_hash = hash_record(
            sequence,
            &nonce,
            &prior_record_hash,
            &state_root,
            &ciphertext,
        );
        let record = EncryptedJournalRecord {
            sequence,
            nonce,
            prior_record_hash,
            state_root,
            ciphertext,
            record_hash,
        };
        self.records.push(record.clone());
        Ok(record)
    }

    pub fn decrypt<T: for<'de> Deserialize<'de>>(
        &self,
        record: &EncryptedJournalRecord,
    ) -> CoreResult<T> {
        let expected_prior = if record.sequence == 1 {
            [0u8; 32]
        } else {
            self.records
                .get(record.sequence as usize - 2)
                .map(|value| value.record_hash)
                .ok_or(CoreError::JournalChainMismatch)?
        };
        if record.prior_record_hash != expected_prior
            || record.record_hash
                != hash_record(
                    record.sequence,
                    &record.nonce,
                    &record.prior_record_hash,
                    &record.state_root,
                    &record.ciphertext,
                )
        {
            return Err(CoreError::JournalChainMismatch);
        }
        let aad = associated_data(
            record.sequence,
            &record.prior_record_hash,
            &record.state_root,
        );
        let plaintext = self
            .cipher
            .decrypt(
                Nonce::from_slice(&record.nonce),
                Payload {
                    msg: &record.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| CoreError::JournalCrypto)?;
        serde_json::from_slice(&plaintext).map_err(|_| CoreError::JournalCrypto)
    }

    pub fn records(&self) -> &[EncryptedJournalRecord] {
        &self.records
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnclaveReceipt {
    pub protocol_version: String,
    pub receipt_id: String,
    pub command_id: String,
    pub idempotency_key: String,
    pub enclave_sequence: u64,
    pub prior_state_root: [u8; 32],
    pub state_root: [u8; 32],
    pub journal_hash: [u8; 32],
    pub enclave_measurement: [u8; 32],
    pub occurred_at_millis: i64,
    pub signature: Vec<u8>,
}

pub struct ReceiptSigner {
    signing_key: SigningKey,
    enclave_measurement: [u8; 32],
}

impl ReceiptSigner {
    pub fn generate(enclave_measurement: [u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
            enclave_measurement,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        &self,
        command_id: String,
        idempotency_key: String,
        enclave_sequence: u64,
        prior_state_root: [u8; 32],
        state_root: [u8; 32],
        journal_hash: [u8; 32],
        occurred_at_millis: i64,
    ) -> EnclaveReceipt {
        let mut receipt = EnclaveReceipt {
            protocol_version: "layrs.v1".into(),
            receipt_id: uuid::Uuid::new_v4().to_string(),
            command_id,
            idempotency_key,
            enclave_sequence,
            prior_state_root,
            state_root,
            journal_hash,
            enclave_measurement: self.enclave_measurement,
            occurred_at_millis,
            signature: Vec::new(),
        };
        let payload = serde_json::to_vec(&receipt).expect("receipt serialization cannot fail");
        receipt.signature = self.signing_key.sign(&payload).to_bytes().to_vec();
        receipt
    }

    pub fn verifying_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }
}

fn associated_data(sequence: u64, prior: &[u8; 32], root: &[u8; 32]) -> Vec<u8> {
    let mut output = Vec::with_capacity(72);
    output.extend_from_slice(&sequence.to_be_bytes());
    output.extend_from_slice(prior);
    output.extend_from_slice(root);
    output
}

fn hash_record(
    sequence: u64,
    nonce: &[u8; 12],
    prior: &[u8; 32],
    root: &[u8; 32],
    ciphertext: &[u8],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"layrs.encrypted-journal.v1");
    hash.update(sequence.to_be_bytes());
    hash.update(nonce);
    hash.update(prior);
    hash.update(root);
    hash.update(ciphertext);
    hash.finalize().into()
}
