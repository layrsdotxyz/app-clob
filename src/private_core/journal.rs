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
    pub ciphertext: Vec<u8>,
    pub record_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedSnapshot {
    pub sequence: u64,
    pub journal_head: [u8; 32],
    pub state_root: [u8; 32],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub ciphertext_hash: [u8; 32],
}

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
        let result = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| CoreError::JournalCrypto);
        plaintext.zeroize();
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
        let value = serde_json::from_slice(&plaintext).map_err(|_| CoreError::JournalCrypto);
        plaintext.zeroize();
        value
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnclaveReceipt {
    pub protocol_version: String,
    pub receipt_id: String,
    pub command_id: String,
    pub idempotency_key: String,
    /// Present on authenticated user-command receipts. These commitments bind
    /// the signed state transition to the exact encrypted request and private
    /// result without revealing either value to the host or public chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_hash: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_hash: Option<[u8; 32]>,
    pub enclave_sequence: u64,
    pub prior_state_root: [u8; 32],
    pub state_root: [u8; 32],
    pub journal_hash: [u8; 32],
    pub enclave_measurement_sha384: Vec<u8>,
    pub occurred_at_millis: i64,
    pub signature: Vec<u8>,
}

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
        enclave_sequence: u64,
        prior_state_root: [u8; 32],
        state_root: [u8; 32],
        journal_hash: [u8; 32],
        occurred_at_millis: i64,
    ) -> EnclaveReceipt {
        self.sign_internal(
            "layrs.v1",
            command_id,
            idempotency_key,
            None,
            None,
            enclave_sequence,
            prior_state_root,
            state_root,
            journal_hash,
            occurred_at_millis,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn sign_user(
        &self,
        command_id: String,
        idempotency_key: String,
        request_hash: [u8; 32],
        result_hash: [u8; 32],
        enclave_sequence: u64,
        prior_state_root: [u8; 32],
        state_root: [u8; 32],
        journal_hash: [u8; 32],
        occurred_at_millis: i64,
    ) -> EnclaveReceipt {
        self.sign_internal(
            "layrs.v2",
            command_id,
            idempotency_key,
            Some(request_hash),
            Some(result_hash),
            enclave_sequence,
            prior_state_root,
            state_root,
            journal_hash,
            occurred_at_millis,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn sign_internal(
        &self,
        protocol_version: &str,
        command_id: String,
        idempotency_key: String,
        request_hash: Option<[u8; 32]>,
        result_hash: Option<[u8; 32]>,
        enclave_sequence: u64,
        prior_state_root: [u8; 32],
        state_root: [u8; 32],
        journal_hash: [u8; 32],
        occurred_at_millis: i64,
    ) -> EnclaveReceipt {
        let mut receipt = EnclaveReceipt {
            protocol_version: protocol_version.into(),
            receipt_id: deterministic_receipt_id(
                &command_id,
                &idempotency_key,
                enclave_sequence,
                &state_root,
            ),
            command_id,
            idempotency_key,
            request_hash,
            result_hash,
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

#[cfg(test)]
mod receipt_tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    fn signed_payload(receipt: &EnclaveReceipt) -> Vec<u8> {
        let mut unsigned = receipt.clone();
        unsigned.signature.clear();
        serde_json::to_vec(&unsigned).expect("receipt serialization")
    }

    fn verify(receipt: &EnclaveReceipt, key: [u8; 32]) -> bool {
        let Ok(key) = VerifyingKey::from_bytes(&key) else {
            return false;
        };
        let Ok(signature) = Signature::try_from(receipt.signature.as_slice()) else {
            return false;
        };
        key.verify(&signed_payload(receipt), &signature).is_ok()
    }

    #[test]
    fn user_receipt_binds_request_result_and_measurement() {
        let signer = ReceiptSigner::from_seed([7u8; 32], [9u8; 48]);
        let receipt = signer.sign_user(
            "command-1".into(),
            "idempotency-1".into(),
            [11u8; 32],
            [12u8; 32],
            42,
            [13u8; 32],
            [14u8; 32],
            [15u8; 32],
            1_785_000_000_000,
        );

        assert_eq!(receipt.protocol_version, "layrs.v2");
        assert_eq!(receipt.request_hash, Some([11u8; 32]));
        assert_eq!(receipt.result_hash, Some([12u8; 32]));
        assert_eq!(receipt.enclave_measurement_sha384, vec![9u8; 48]);
        assert!(verify(&receipt, signer.verifying_key()));
    }

    #[test]
    fn user_receipt_rejects_request_result_and_state_tampering() {
        let signer = ReceiptSigner::from_seed([17u8; 32], [19u8; 48]);
        let receipt = signer.sign_user(
            "command-2".into(),
            "idempotency-2".into(),
            [21u8; 32],
            [22u8; 32],
            77,
            [23u8; 32],
            [24u8; 32],
            [25u8; 32],
            1_785_000_000_001,
        );

        for mutate in [
            |value: &mut EnclaveReceipt| value.request_hash = Some([31u8; 32]),
            |value: &mut EnclaveReceipt| value.result_hash = Some([32u8; 32]),
            |value: &mut EnclaveReceipt| value.state_root = [33u8; 32],
            |value: &mut EnclaveReceipt| value.enclave_sequence += 1,
        ] {
            let mut tampered = receipt.clone();
            mutate(&mut tampered);
            assert!(!verify(&tampered, signer.verifying_key()));
        }
    }

    #[test]
    fn user_receipt_is_deterministic_for_identical_inputs() {
        let left = ReceiptSigner::from_seed([41u8; 32], [42u8; 48]);
        let right = ReceiptSigner::from_seed([41u8; 32], [42u8; 48]);
        let sign = |signer: &ReceiptSigner| {
            signer.sign_user(
                "command-3".into(),
                "idempotency-3".into(),
                [43u8; 32],
                [44u8; 32],
                101,
                [45u8; 32],
                [46u8; 32],
                [47u8; 32],
                1_785_000_000_002,
            )
        };

        assert_eq!(sign(&left), sign(&right));
    }

    #[test]
    fn legacy_receipt_remains_v1_without_private_commitments() {
        let signer = ReceiptSigner::from_seed([51u8; 32], [52u8; 48]);
        let receipt = signer.sign(
            "system-command".into(),
            "system-idempotency".into(),
            2,
            [53u8; 32],
            [54u8; 32],
            [55u8; 32],
            1_785_000_000_003,
        );

        assert_eq!(receipt.protocol_version, "layrs.v1");
        assert!(receipt.request_hash.is_none());
        assert!(receipt.result_hash.is_none());
        assert!(verify(&receipt, signer.verifying_key()));
    }
}
