//! Public witnesses of committed direct-core activity. Existing private HMAC
//! receipts, encrypted state and financial authorization are not modified.
use super::*;
use openssl::{
    pkey::{Id, PKey, Private},
    sign::{Signer, Verifier as PublicVerifier},
};
use zeroize::Zeroizing;

pub const QUEST_RECEIPT_PROTOCOL: &str = "layrs.direct-public-receipt.v1";
const KEY_DOMAIN: &[u8] = b"layrs.direct-public-receipt-key.v1\0";
const SIGN_DOMAIN: &[u8] = b"layrs.direct-public-receipt-signature.v1\0";
pub const QUEST_RECEIPT_ATTESTATION_DOMAIN: &[u8] = b"layrs.direct-public-receipt-attestation.v1\0";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum QuestReceiptKind {
    IdentityAdmission,
    WalletLink,
    Deposit,
    PrivateFill,
    Withdrawal,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QuestReceiptPayload {
    pub protocol: String,
    pub epoch_id: String,
    pub receipt_id: String,
    pub participant_commitment: String,
    pub kind: QuestReceiptKind,
    pub enclave_sequence: String,
    pub state_root: String,
    pub command_commitment: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicQuestReceipt {
    pub payload: QuestReceiptPayload,
    pub signature: String,
    pub public_key: String,
}
/// Private transport binding; never included in public receipt batches or CSV.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QuestReceiptLookupPayload {
    pub protocol: String,
    pub participant_account: String,
    pub receipt_account: String,
    pub request_id: String,
    pub nonce: String,
    pub public_receipt_hash: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QuestReceiptWitness {
    pub receipt: PublicQuestReceipt,
    pub lookup: QuestReceiptLookupPayload,
    pub lookup_signature: String,
}
pub fn quest_public_receipt_hash(receipt: &PublicQuestReceipt) -> Result<String, RuntimeError> {
    let mut hash = Sha256::new();
    hash.update(b"layrs.public-receipt-reference.v1\0");
    hash.update(canonical_quest_receipt_payload(&receipt.payload)?);
    hash.update(hex::decode(&receipt.signature).map_err(|_| RuntimeError::StateArtifact)?);
    hash.update(hex::decode(&receipt.public_key).map_err(|_| RuntimeError::StateArtifact)?);
    Ok(hex::encode(hash.finalize()))
}
fn signing_key(receipt_key: &[u8]) -> Result<PKey<Private>, RuntimeError> {
    if receipt_key.len() < 32 {
        return Err(RuntimeError::StateArtifact);
    }
    let seed = Zeroizing::new(
        hex::decode(sign(receipt_key, KEY_DOMAIN)).map_err(|_| RuntimeError::StateArtifact)?,
    );
    PKey::private_key_from_raw_bytes(&seed, Id::ED25519).map_err(|_| RuntimeError::StateArtifact)
}
fn valid_hex32(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
pub fn quest_receipt_public_key(receipt_key: &[u8]) -> Result<Vec<u8>, RuntimeError> {
    signing_key(receipt_key)?
        .raw_public_key()
        .map_err(|_| RuntimeError::StateArtifact)
}
pub fn canonical_quest_receipt_payload(
    payload: &QuestReceiptPayload,
) -> Result<Vec<u8>, RuntimeError> {
    // serde_json::Value's default map representation sorts object keys. There
    // are only strings in this flat schema, avoiding JSON integer rounding.
    serde_json::to_vec(&serde_json::to_value(payload).map_err(|_| RuntimeError::StateArtifact)?)
        .map_err(|_| RuntimeError::StateArtifact)
}
pub fn quest_receipt_attestation_commitment(
    binding: &RuntimeBinding,
    public_key: &[u8],
) -> Result<[u8; 32], RuntimeError> {
    if public_key.len() != 32 {
        return Err(RuntimeError::StateArtifact);
    }
    let mut hash = Sha256::new();
    hash.update(QUEST_RECEIPT_ATTESTATION_DOMAIN);
    hash.update(runtime_binding_commitment(binding));
    hash.update(public_key);
    Ok(hash.finalize().into())
}
pub fn verify_public_quest_receipt(
    receipt: &PublicQuestReceipt,
    attested_public_key: &[u8],
) -> bool {
    let p = &receipt.payload;
    if p.protocol != QUEST_RECEIPT_PROTOCOL
        || p.epoch_id != EPOCH_ID
        || attested_public_key.len() != 32
        || receipt.public_key != hex::encode(attested_public_key)
        || !p
            .receipt_id
            .strip_prefix("receipt_")
            .is_some_and(valid_hex32)
        || ![
            &p.participant_commitment,
            &p.state_root,
            &p.command_commitment,
        ]
        .iter()
        .all(|value| valid_hex32(value))
        || !p
            .enclave_sequence
            .parse::<u64>()
            .is_ok_and(|sequence| sequence > 0 && sequence.to_string() == p.enclave_sequence)
    {
        return false;
    }
    let Ok(signature) = hex::decode(&receipt.signature) else {
        return false;
    };
    if signature.len() != 64 || hex::encode(&signature) != receipt.signature {
        return false;
    }
    let Ok(key) = PKey::public_key_from_raw_bytes(attested_public_key, Id::ED25519) else {
        return false;
    };
    let Ok(mut verifier) = PublicVerifier::new_without_digest(&key) else {
        return false;
    };
    let Ok(payload) = canonical_quest_receipt_payload(p) else {
        return false;
    };
    verifier
        .verify_oneshot(&signature, &[SIGN_DOMAIN, &payload].concat())
        .unwrap_or(false)
}
impl DirectRuntime {
    pub fn quest_receipt_witness(
        &self,
        participant: &str,
        owner: &str,
        request: &str,
        nonce: &[u8],
    ) -> Result<QuestReceiptWitness, RuntimeError> {
        if nonce.len() != 32 {
            return Err(RuntimeError::InvalidRequest);
        }
        let receipt = self.public_quest_receipt(participant, owner, request)?;
        let lookup = QuestReceiptLookupPayload {
            protocol: "layrs.direct-receipt-lookup.v1".into(),
            participant_account: participant.into(),
            receipt_account: owner.into(),
            request_id: request.into(),
            nonce: hex::encode(nonce),
            public_receipt_hash: quest_public_receipt_hash(&receipt)?,
        };
        let payload = serde_json::to_vec(
            &serde_json::to_value(&lookup).map_err(|_| RuntimeError::StateArtifact)?,
        )
        .map_err(|_| RuntimeError::StateArtifact)?;
        let key = signing_key(&self.receipt_key)?;
        let signature = Signer::new_without_digest(&key)
            .map_err(|_| RuntimeError::StateArtifact)?
            .sign_oneshot_to_vec(
                &[
                    b"layrs.direct-receipt-lookup-signature.v1\0".as_slice(),
                    &payload,
                ]
                .concat(),
            )
            .map_err(|_| RuntimeError::StateArtifact)?;
        Ok(QuestReceiptWitness {
            receipt,
            lookup,
            lookup_signature: hex::encode(signature),
        })
    }
    /// Read-only membership witness. Callers cannot supply a kind, signature,
    /// fill count, financial fields, state root or receipt body to certify.
    pub fn public_quest_receipt(
        &self,
        participant_account: &str,
        receipt_account: &str,
        request_id: &str,
    ) -> Result<PublicQuestReceipt, RuntimeError> {
        if !self.writer_enabled() {
            return Err(RuntimeError::WriterDisabled);
        }
        let identities = self
            .subject_identities
            .get(participant_account)
            .ok_or(RuntimeError::IdentityDenied)?;
        let (request_hash, result) = self
            .requests
            .get(&(receipt_account.into(), request_id.into()))
            .ok_or(RuntimeError::InvalidRequest)?;
        let receipt = &result.receipt;
        if result.status != TerminalStatus::Applied
            || receipt.status != result.status
            || receipt.effect != result.effect
            || receipt.account_id != receipt_account
            || receipt.request_id != request_id
            || receipt.request_hash != *request_hash
            || !verify_receipt(&self.receipt_key, receipt)
        {
            return Err(RuntimeError::StateArtifact);
        }
        let own = participant_account == receipt_account
            && identities.contains(&receipt.identity_commitment);
        let filled = result.effect == "ORDER_EXECUTED"
            && receipt.execution.as_ref().is_some_and(|execution| {
                self.markets
                    .get(&execution.market_id)
                    .is_some_and(|market| {
                        market.settlement_asset == "USDC" && market.settlement_decimals == 6
                    })
                    && !execution.trades.is_empty()
                    && execution.trades.iter().all(|trade| {
                        trade.market_id == execution.market_id
                            && positive_atomic_value(&trade.executed_quantity_micros).is_some()
                    })
            });
        let kind = match result.effect.as_str() {
            "IDENTITY_ADMITTED" if own => QuestReceiptKind::IdentityAdmission,
            "FINANCIAL_WALLET_LINKED" if own => QuestReceiptKind::WalletLink,
            "DEPOSIT_CREDITED" if own => QuestReceiptKind::Deposit,
            "WITHDRAWAL_SETTLED" if own => QuestReceiptKind::Withdrawal,
            "ORDER_EXECUTED"
                if filled
                    && (own
                        || receipt.projection_balance_updates.iter().any(|update| {
                            update.auth_subject_hash == participant_account
                                && identities.contains(&update.identity_commitment)
                        })) =>
            {
                QuestReceiptKind::PrivateFill
            }
            _ => return Err(RuntimeError::InvalidRequest),
        };
        let participant_commitment = sign(
            &self.receipt_key,
            &[
                b"layrs.quest-participant.v1\0".as_slice(),
                participant_account.as_bytes(),
            ]
            .concat(),
        );
        let command_commitment = sign(
            &self.receipt_key,
            &[
                b"layrs.quest-command.v1\0".as_slice(),
                request_hash.as_bytes(),
            ]
            .concat(),
        );
        let receipt_id = format!(
            "receipt_{}",
            sha256(
                format!(
                    "layrs.quest-receipt.v1\0{}\0{participant_commitment}",
                    receipt.receipt_id
                )
                .as_bytes()
            )
        );
        let payload = QuestReceiptPayload {
            protocol: QUEST_RECEIPT_PROTOCOL.into(),
            epoch_id: EPOCH_ID.into(),
            receipt_id,
            participant_commitment,
            kind,
            enclave_sequence: self.committed_sequence().to_string(),
            state_root: self.committed_state_hash(),
            command_commitment,
        };
        let key = signing_key(&self.receipt_key)?;
        let signature = Signer::new_without_digest(&key)
            .map_err(|_| RuntimeError::StateArtifact)?
            .sign_oneshot_to_vec(
                &[SIGN_DOMAIN, &canonical_quest_receipt_payload(&payload)?].concat(),
            )
            .map_err(|_| RuntimeError::StateArtifact)?;
        Ok(PublicQuestReceipt {
            payload,
            signature: hex::encode(signature),
            public_key: hex::encode(
                key.raw_public_key()
                    .map_err(|_| RuntimeError::StateArtifact)?,
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ed25519_receipt_matches_independent_node_crypto_u64_golden_vector() {
        let payload = QuestReceiptPayload {
            protocol: QUEST_RECEIPT_PROTOCOL.into(),
            epoch_id: EPOCH_ID.into(),
            receipt_id: format!("receipt_{}", "a".repeat(64)),
            participant_commitment: "b".repeat(64),
            kind: QuestReceiptKind::PrivateFill,
            enclave_sequence: u64::MAX.to_string(),
            state_root: "c".repeat(64),
            command_commitment: "d".repeat(64),
        };
        let key = signing_key(&[7; 32]).unwrap();
        let signature = Signer::new_without_digest(&key)
            .unwrap()
            .sign_oneshot_to_vec(
                &[
                    SIGN_DOMAIN,
                    &canonical_quest_receipt_payload(&payload).unwrap(),
                ]
                .concat(),
            )
            .unwrap();
        let receipt = PublicQuestReceipt {
            payload,
            signature: hex::encode(signature),
            public_key: hex::encode(key.raw_public_key().unwrap()),
        };
        assert_eq!(
            receipt.public_key,
            "9fbab0b36744b7676ec2a3135a654fd8468a2dd324ac24872a525447249d5337"
        );
        assert_eq!(receipt.signature,"19e8551bd6d182e77c2499ddba61f9308eb73f1b56322e785736b79812db41b2f439dd5215cc015d66d8d9dad1ea5ddfbb24fce44d9a19ff752cbf2f022fa70f");
        assert!(verify_public_quest_receipt(
            &receipt,
            &hex::decode(&receipt.public_key).unwrap()
        ));
        assert!(quest_receipt_public_key(&[7; 31]).is_err());
    }
}
