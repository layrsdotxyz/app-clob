use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use ed25519_dalek::{Signer, SigningKey};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Cursor, Read};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{CoreError, CoreResult};

const SNAPSHOT_ZSTD_MAGIC: &[u8] = b"layrs.snapshot.zstd.v1\0";
const MAX_SNAPSHOT_PLAINTEXT_BYTES: u64 = 512 * 1024 * 1024;
const SNAPSHOT_ZSTD_LEVEL: i32 = 1;

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

    pub fn derive(&self, domain: &[u8]) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"layrs.enclave-key-derivation.v1\0");
        hash.update(self.0);
        hash.update((domain.len() as u32).to_be_bytes());
        hash.update(domain);
        hash.finalize().into()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedJournalRecord {
    pub sequence: u64,
    pub nonce: [u8; 12],
    pub prior_record_hash: [u8; 32],
    pub state_root: [u8; 32],
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
    pub record_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedSnapshot {
    pub sequence: u64,
    pub journal_head: [u8; 32],
    pub state_root: [u8; 32],
    pub nonce: [u8; 12],
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
    pub ciphertext_hash: [u8; 32],
}

#[cfg(test)]
mod wire_tests {
    use super::EncryptedSnapshot;

    #[test]
    fn snapshot_ciphertext_is_compact_on_the_internal_cbor_wire() {
        let ciphertext = vec![0xabu8; 7 * 1024 * 1024];
        let snapshot = EncryptedSnapshot {
            sequence: 99_960,
            journal_head: [1; 32],
            state_root: [2; 32],
            nonce: [3; 12],
            ciphertext,
            ciphertext_hash: [4; 32],
        };
        let encoded = serde_cbor::to_vec(&snapshot).unwrap();
        assert!(encoded.len() < 7 * 1024 * 1024 + 512);
        let decoded: EncryptedSnapshot = serde_cbor::from_slice(&encoded).unwrap();
        assert_eq!(decoded, snapshot);
        assert!(serde_json::to_value(&snapshot).unwrap()["ciphertext"].is_array());
    }
}

#[derive(Clone)]
pub struct EncryptedJournal {
    cipher: Aes256Gcm,
    records: Vec<EncryptedJournalRecord>,
    sequence: u64,
    head: [u8; 32],
}

impl EncryptedJournal {
    pub fn new(key: JournalKey) -> Self {
        Self {
            cipher: Aes256Gcm::new_from_slice(&key.0).expect("AES-256 key length is fixed"),
            records: Vec::new(),
            sequence: 0,
            head: [0u8; 32],
        }
    }

    pub fn append<T: Serialize>(
        &mut self,
        state_root: [u8; 32],
        value: &T,
    ) -> CoreResult<EncryptedJournalRecord> {
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or(CoreError::JournalChainMismatch)?;
        let prior_record_hash = self.head;
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
        self.sequence = sequence;
        self.head = record_hash;
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

    pub fn chain_head(&self) -> (u64, [u8; 32]) {
        (self.sequence, self.head)
    }

    pub fn restore_chain_head(&mut self, sequence: u64, head: [u8; 32]) -> CoreResult<()> {
        if (sequence == 0) != (head == [0u8; 32]) {
            return Err(CoreError::JournalChainMismatch);
        }
        self.sequence = sequence;
        self.head = head;
        self.records.clear();
        Ok(())
    }

    pub fn seal_snapshot<T: Serialize>(
        &self,
        state_root: [u8; 32],
        value: &T,
    ) -> CoreResult<EncryptedSnapshot> {
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let aad = snapshot_associated_data(self.sequence, &self.head, &state_root);
        let mut plaintext = serde_json::to_vec(value).map_err(|_| CoreError::JournalCrypto)?;
        let mut compressed = zstd::stream::encode_all(Cursor::new(&plaintext), SNAPSHOT_ZSTD_LEVEL)
            .map_err(|_| CoreError::JournalCrypto)?;
        let mut sealed_plaintext = Vec::with_capacity(SNAPSHOT_ZSTD_MAGIC.len() + compressed.len());
        sealed_plaintext.extend_from_slice(SNAPSHOT_ZSTD_MAGIC);
        sealed_plaintext.append(&mut compressed);
        plaintext.zeroize();
        let result = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &sealed_plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| CoreError::JournalCrypto);
        sealed_plaintext.zeroize();
        let ciphertext = result?;
        let ciphertext_hash = Sha256::digest(&ciphertext).into();
        Ok(EncryptedSnapshot {
            sequence: self.sequence,
            journal_head: self.head,
            state_root,
            nonce,
            ciphertext,
            ciphertext_hash,
        })
    }

    pub fn open_snapshot<T: for<'de> Deserialize<'de>>(
        &self,
        snapshot: &EncryptedSnapshot,
    ) -> CoreResult<T> {
        let expected_hash: [u8; 32] = Sha256::digest(&snapshot.ciphertext).into();
        if snapshot.ciphertext_hash != expected_hash {
            return Err(CoreError::JournalChainMismatch);
        }
        let aad = snapshot_associated_data(
            snapshot.sequence,
            &snapshot.journal_head,
            &snapshot.state_root,
        );
        let mut plaintext = self
            .cipher
            .decrypt(
                Nonce::from_slice(&snapshot.nonce),
                Payload {
                    msg: &snapshot.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| CoreError::JournalCrypto)?;
        let value = if let Some(compressed) = plaintext.strip_prefix(SNAPSHOT_ZSTD_MAGIC) {
            let mut decoded = decode_snapshot_payload(compressed, MAX_SNAPSHOT_PLAINTEXT_BYTES)?;
            let result = serde_json::from_slice(&decoded).map_err(|_| CoreError::JournalCrypto);
            decoded.zeroize();
            result
        } else {
            // Backward compatibility is required for the immutable pre-compression
            // checkpoints already archived in production. Their authenticated
            // plaintext begins directly with the legacy JSON document.
            serde_json::from_slice(&plaintext).map_err(|_| CoreError::JournalCrypto)
        };
        plaintext.zeroize();
        value
    }
}

fn decode_snapshot_payload(compressed: &[u8], maximum: u64) -> CoreResult<Vec<u8>> {
    let decoder = zstd::stream::read::Decoder::new(Cursor::new(compressed))
        .map_err(|_| CoreError::JournalCrypto)?;
    let mut decoded = Vec::new();
    decoder
        .take(maximum + 1)
        .read_to_end(&mut decoded)
        .map_err(|_| CoreError::JournalCrypto)?;
    if decoded.len() as u64 > maximum {
        decoded.zeroize();
        return Err(CoreError::JournalCrypto);
    }
    Ok(decoded)
}

#[cfg(test)]
mod snapshot_tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct RepetitiveSnapshot {
        markets: Vec<String>,
    }

    #[test]
    fn compressed_snapshot_round_trips_and_materially_reduces_ciphertext() {
        let journal = EncryptedJournal::new(JournalKey::from_bytes([7; 32]));
        let value = RepetitiveSnapshot {
            markets: (0..20_000)
                .map(|index| format!("layrs:v5:ZEN:15m:fixed-prefix-{:05}", index % 100))
                .collect(),
        };
        let json_bytes = serde_json::to_vec(&value).unwrap();
        let snapshot = journal.seal_snapshot([9; 32], &value).unwrap();
        assert!(snapshot.ciphertext.len() < json_bytes.len() / 5);
        let restored: RepetitiveSnapshot = journal.open_snapshot(&snapshot).unwrap();
        assert_eq!(restored, value);
    }

    #[test]
    fn legacy_uncompressed_snapshot_remains_restorable() {
        let journal = EncryptedJournal::new(JournalKey::from_bytes([8; 32]));
        let value = RepetitiveSnapshot {
            markets: vec!["legacy".into()],
        };
        let plaintext = serde_json::to_vec(&value).unwrap();
        let nonce = [3; 12];
        let state_root = [4; 32];
        let aad = snapshot_associated_data(0, &[0; 32], &state_root);
        let ciphertext = journal
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .unwrap();
        let snapshot = EncryptedSnapshot {
            sequence: 0,
            journal_head: [0; 32],
            state_root,
            nonce,
            ciphertext_hash: Sha256::digest(&ciphertext).into(),
            ciphertext,
        };
        let restored: RepetitiveSnapshot = journal.open_snapshot(&snapshot).unwrap();
        assert_eq!(restored, value);
    }

    #[test]
    fn decompression_limit_rejects_oversized_plaintext() {
        let input = vec![0x41; 4096];
        let compressed = zstd::stream::encode_all(Cursor::new(&input), 1).unwrap();
        assert!(decode_snapshot_payload(&compressed, 1024).is_err());
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnclaveReceipt {
    pub protocol_version: String,
    pub receipt_id: String,
    pub command_id: String,
    pub idempotency_key: String,
    /// SHA-256 commitment to the exact authenticated user command accepted by
    /// the enclave. Historical v1 system receipts omit it; user-command v2
    /// receipts always include it so a user can verify the action privately
    /// without publishing the order or cancellation payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_commitment_sha256: Option<[u8; 32]>,
    /// Whether this receipt represents a state-changing private command and is
    /// therefore eligible for privacy-safe public root batching. Read-only
    /// portfolio/status receipts remain user-verifiable but are never anchored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publication_eligible: Option<bool>,
    pub enclave_sequence: u64,
    pub prior_state_root: [u8; 32],
    pub state_root: [u8; 32],
    pub journal_hash: [u8; 32],
    pub enclave_measurement_sha384: Vec<u8>,
    pub occurred_at_millis: i64,
    pub signature: Vec<u8>,
}

#[derive(Clone)]
pub struct ReceiptSigner {
    signing_key: SigningKey,
    enclave_measurement_sha384: [u8; 48],
}

impl ReceiptSigner {
    pub fn generate(enclave_measurement_sha384: [u8; 48]) -> Self {
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
            enclave_measurement_sha384,
        }
    }

    /// Restores the enclave receipt identity from KMS-protected key material.
    /// The seed is derived inside the enclave from the private-core journal key,
    /// so receipts remain verifiable across enclave restarts without ever
    /// persisting an unsealed signing key outside the enclave boundary.
    pub fn from_seed(seed: [u8; 32], enclave_measurement_sha384: [u8; 48]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&seed),
            enclave_measurement_sha384,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        &self,
        command_id: String,
        idempotency_key: String,
        command_commitment_sha256: Option<[u8; 32]>,
        publication_eligible: Option<bool>,
        enclave_sequence: u64,
        prior_state_root: [u8; 32],
        state_root: [u8; 32],
        journal_hash: [u8; 32],
        occurred_at_millis: i64,
    ) -> EnclaveReceipt {
        assert_eq!(
            command_commitment_sha256.is_some(),
            publication_eligible.is_some(),
            "receipt command commitment and publication policy must be versioned together"
        );
        let mut receipt = EnclaveReceipt {
            protocol_version: if command_commitment_sha256.is_some() {
                "layrs.v2".into()
            } else {
                "layrs.v1".into()
            },
            receipt_id: deterministic_receipt_id(
                &command_id,
                &idempotency_key,
                enclave_sequence,
                &state_root,
            ),
            command_id,
            idempotency_key,
            command_commitment_sha256,
            publication_eligible,
            enclave_sequence,
            prior_state_root,
            state_root,
            journal_hash,
            enclave_measurement_sha384: self.enclave_measurement_sha384.to_vec(),
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

    pub fn sign_domain_payload<T: Serialize>(&self, domain: &[u8], value: &T) -> Vec<u8> {
        let encoded = serde_json::to_vec(value).expect("authorization serialization cannot fail");
        let mut payload = Vec::with_capacity(domain.len() + 4 + encoded.len());
        payload.extend_from_slice(domain);
        payload.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
        payload.extend_from_slice(&encoded);
        self.signing_key.sign(&payload).to_bytes().to_vec()
    }
}

fn deterministic_receipt_id(
    command_id: &str,
    idempotency_key: &str,
    sequence: u64,
    state_root: &[u8; 32],
) -> String {
    let mut hash = Sha256::new();
    hash.update(b"layrs.receipt.v1\0");
    hash.update(command_id.as_bytes());
    hash.update([0]);
    hash.update(idempotency_key.as_bytes());
    hash.update(sequence.to_be_bytes());
    hash.update(state_root);
    format!("receipt_{}", hex::encode(hash.finalize()))
}

fn associated_data(sequence: u64, prior: &[u8; 32], root: &[u8; 32]) -> Vec<u8> {
    let mut output = Vec::with_capacity(72);
    output.extend_from_slice(&sequence.to_be_bytes());
    output.extend_from_slice(prior);
    output.extend_from_slice(root);
    output
}

fn snapshot_associated_data(sequence: u64, head: &[u8; 32], root: &[u8; 32]) -> Vec<u8> {
    let mut value = b"layrs.private-snapshot.v1\0".to_vec();
    value.extend_from_slice(&sequence.to_be_bytes());
    value.extend_from_slice(head);
    value.extend_from_slice(root);
    value
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
