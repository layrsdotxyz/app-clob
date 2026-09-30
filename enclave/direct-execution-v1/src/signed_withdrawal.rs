//! Canonical user authorization for unified withdrawals.
//!
//! The same EIP-712 digest is checked by the enclave before reserving balance
//! and by `LayrsPool` before releasing custody. A nonce-stable request id makes
//! a second payload with the same user nonce collide in v71's authenticated
//! sparse request index, even after the active hold has reached a terminal
//! state and left compact financial state.

use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::Keccak256;

pub const WITHDRAWAL_SOURCE_CHAIN_ID: u64 = 26_514;
pub const WITHDRAWAL_EIP712_NAME: &str = "LayrsPool";
pub const WITHDRAWAL_EIP712_VERSION: &str = "2";
const COMMAND_COMMITMENT_DOMAIN: &[u8] = b"layrs.unified-withdrawal-reserve.v1\0";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedWithdrawalIntent {
    pub account: String,
    pub pool: String,
    pub token: String,
    /// Permanent backend-controlled wallet assigned to this user. LayrsPool
    /// pays only this address; Relay then moves that operation's funds onward.
    pub route_wallet: String,
    pub amount_atomic: String,
    pub recipient: String,
    pub destination_chain: String,
    pub nonce: String,
    pub expiry_unix: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignedWithdrawalError {
    InvalidIntent,
    InvalidSignature,
}

impl SignedWithdrawalIntent {
    pub fn validate(&self) -> Result<(), SignedWithdrawalError> {
        parse_address(&self.account)?;
        parse_address(&self.pool)?;
        parse_address(&self.token)?;
        parse_address(&self.route_wallet)?;
        let amount = parse_u128(&self.amount_atomic)?;
        let _nonce = parse_u128(&self.nonce)?;
        if amount == 0
            || self.expiry_unix == 0
            || !valid_destination(&self.destination_chain, &self.recipient)
        {
            return Err(SignedWithdrawalError::InvalidIntent);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<[u8; 32], SignedWithdrawalError> {
        self.validate()?;
        let domain_type_hash = keccak(
            b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
        );
        let intent_type_hash = keccak(
            b"WithdrawalIntent(address account,uint256 amount,address token,address routeWallet,string recipient,string destinationChain,uint256 nonce,uint256 expiry)",
        );
        let mut domain = Vec::with_capacity(32 * 5);
        domain.extend_from_slice(&domain_type_hash);
        domain.extend_from_slice(&keccak(WITHDRAWAL_EIP712_NAME.as_bytes()));
        domain.extend_from_slice(&keccak(WITHDRAWAL_EIP712_VERSION.as_bytes()));
        domain.extend_from_slice(&word_u128(WITHDRAWAL_SOURCE_CHAIN_ID as u128));
        domain.extend_from_slice(&word_address(&parse_address(&self.pool)?));

        let mut body = Vec::with_capacity(32 * 9);
        body.extend_from_slice(&intent_type_hash);
        body.extend_from_slice(&word_address(&parse_address(&self.account)?));
        body.extend_from_slice(&word_u128(parse_u128(&self.amount_atomic)?));
        body.extend_from_slice(&word_address(&parse_address(&self.token)?));
        body.extend_from_slice(&word_address(&parse_address(&self.route_wallet)?));
        body.extend_from_slice(&keccak(self.recipient.as_bytes()));
        body.extend_from_slice(&keccak(self.destination_chain.as_bytes()));
        body.extend_from_slice(&word_u128(parse_u128(&self.nonce)?));
        body.extend_from_slice(&word_u128(self.expiry_unix as u128));

        let mut payload = Vec::with_capacity(66);
        payload.extend_from_slice(b"\x19\x01");
        payload.extend_from_slice(&keccak(&domain));
        payload.extend_from_slice(&keccak(&body));
        Ok(keccak(&payload))
    }

    pub fn intent_hash_hex(&self) -> Result<String, SignedWithdrawalError> {
        Ok(format!("0x{}", hex::encode(self.digest()?)))
    }

    pub fn command_commitment(&self) -> Result<String, SignedWithdrawalError> {
        let mut payload = Vec::with_capacity(COMMAND_COMMITMENT_DOMAIN.len() + 32);
        payload.extend_from_slice(COMMAND_COMMITMENT_DOMAIN);
        payload.extend_from_slice(&self.digest()?);
        Ok(hex::encode(Sha256::digest(payload)))
    }

    pub fn nonce_request_id(&self) -> Result<String, SignedWithdrawalError> {
        self.validate()?;
        Ok(format!(
            "signed-withdrawal:{}:{}",
            self.account.to_ascii_lowercase(),
            parse_u128(&self.nonce)?
        ))
    }

    pub fn verify_signature(&self, signature_hex: &str) -> Result<(), SignedWithdrawalError> {
        let bytes = decode_signature(signature_hex)?;
        let signature = Signature::try_from(&bytes[..64])
            .map_err(|_| SignedWithdrawalError::InvalidSignature)?;
        // Match OpenZeppelin ECDSA's canonical low-s requirement so the
        // enclave and LayrsPool accept precisely the same signature set.
        if signature.normalize_s().is_some() {
            return Err(SignedWithdrawalError::InvalidSignature);
        }
        let recovery_id = RecoveryId::try_from(normalize_recovery_id(bytes[64])?)
            .map_err(|_| SignedWithdrawalError::InvalidSignature)?;
        let key = VerifyingKey::recover_from_prehash(&self.digest()?, &signature, recovery_id)
            .map_err(|_| SignedWithdrawalError::InvalidSignature)?;
        let encoded = key.to_encoded_point(false);
        let recovered = &keccak(&encoded.as_bytes()[1..])[12..];
        if recovered != parse_address(&self.account)? {
            return Err(SignedWithdrawalError::InvalidSignature);
        }
        Ok(())
    }
}

fn decode_signature(value: &str) -> Result<[u8; 65], SignedWithdrawalError> {
    let raw = value.strip_prefix("0x").unwrap_or(value);
    if raw.len() != 130 || !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(SignedWithdrawalError::InvalidSignature);
    }
    let decoded = hex::decode(raw).map_err(|_| SignedWithdrawalError::InvalidSignature)?;
    decoded
        .try_into()
        .map_err(|_| SignedWithdrawalError::InvalidSignature)
}

fn normalize_recovery_id(value: u8) -> Result<u8, SignedWithdrawalError> {
    match value {
        0 | 1 => Ok(value),
        27 | 28 => Ok(value - 27),
        _ => Err(SignedWithdrawalError::InvalidSignature),
    }
}

fn parse_address(value: &str) -> Result<[u8; 20], SignedWithdrawalError> {
    let raw = value
        .strip_prefix("0x")
        .ok_or(SignedWithdrawalError::InvalidIntent)?;
    if raw.len() != 40 || !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(SignedWithdrawalError::InvalidIntent);
    }
    hex::decode(raw)
        .map_err(|_| SignedWithdrawalError::InvalidIntent)?
        .try_into()
        .map_err(|_| SignedWithdrawalError::InvalidIntent)
}

fn parse_u128(value: &str) -> Result<u128, SignedWithdrawalError> {
    let parsed = value
        .parse::<u128>()
        .map_err(|_| SignedWithdrawalError::InvalidIntent)?;
    if parsed.to_string() != value {
        return Err(SignedWithdrawalError::InvalidIntent);
    }
    Ok(parsed)
}

fn valid_destination(chain: &str, recipient: &str) -> bool {
    if !matches!(
        chain,
        "ethereum" | "base" | "arbitrum" | "polygon" | "solana" | "tempo" | "robinhood" | "horizen"
    ) {
        return false;
    }
    if chain == "solana" {
        return (32..=44).contains(&recipient.len())
            && recipient.bytes().all(|byte| {
                matches!(byte,
                b'1'..=b'9' | b'A'..=b'H' | b'J'..=b'N' | b'P'..=b'Z'
                    | b'a'..=b'k' | b'm'..=b'z')
            });
    }
    parse_address(recipient).is_ok()
}

fn word_address(address: &[u8; 20]) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(address);
    word
}

fn word_u128(value: u128) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[16..].copy_from_slice(&value.to_be_bytes());
    word
}

fn keccak(bytes: &[u8]) -> [u8; 32] {
    Keccak256::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;

    fn fixture(key: &SigningKey) -> SignedWithdrawalIntent {
        let public = key.verifying_key().to_encoded_point(false);
        let address = &keccak(&public.as_bytes()[1..])[12..];
        SignedWithdrawalIntent {
            account: format!("0x{}", hex::encode(address)),
            pool: "0xb412f63299ccff4fe57714ee580895cca74dd284".into(),
            token: "0xdf7108f8b10f9b9ec1aba01cca057268cbf86b6c".into(),
            route_wallet: "0x2222222222222222222222222222222222222222".into(),
            amount_atomic: "20000000".into(),
            recipient: "0x0d2bf0c9d6d96eea797c9d1b96895d8f70e3322e".into(),
            destination_chain: "base".into(),
            nonce: "42".into(),
            expiry_unix: 1_800_000_000,
        }
    }

    fn sign(intent: &SignedWithdrawalIntent, key: &SigningKey) -> String {
        let (signature, recovery_id) = key
            .sign_prehash_recoverable(&intent.digest().unwrap())
            .unwrap();
        let mut bytes = signature.to_bytes().to_vec();
        bytes.push(recovery_id.to_byte() + 27);
        format!("0x{}", hex::encode(bytes))
    }

    #[test]
    fn signature_nonce_key_and_commitment_are_stable() {
        let key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let intent = fixture(&key);
        let signature = sign(&intent, &key);
        assert_eq!(
            intent.intent_hash_hex().unwrap(),
            "0x9f2c75358eee694a9314d5f2306cf02b8b8c0e629e5018cac727e5b217986fa5"
        );
        assert_eq!(
            intent.command_commitment().unwrap(),
            "34b95928d767dda04814fc0ae2c48bdb8da6e5f97983f6557eac8625a427a7f2"
        );
        assert_eq!(
            signature,
            "0x64f5058ed8dfb51be05e905b43ae7f5ff2de9b4c304c52a5418e44a194f9f5d9602b4c29cd47360685da243e6b27d83f31175f40a0579db7bca51dde4cbac2ff1b"
        );
        intent.verify_signature(&signature).unwrap();
        assert_eq!(
            intent.nonce_request_id().unwrap(),
            format!("signed-withdrawal:{}:42", intent.account)
        );
        assert_eq!(intent.command_commitment().unwrap().len(), 64);
        assert_eq!(intent.intent_hash_hex().unwrap().len(), 66);
    }

    #[test]
    fn payload_or_signer_change_is_rejected() {
        let key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let other = SigningKey::from_bytes((&[8u8; 32]).into()).unwrap();
        let intent = fixture(&key);
        let signature = sign(&intent, &key);
        let mut changed = intent.clone();
        changed.amount_atomic = "20000001".into();
        assert_eq!(
            changed.verify_signature(&signature),
            Err(SignedWithdrawalError::InvalidSignature)
        );
        assert_eq!(
            intent.verify_signature(&sign(&intent, &other)),
            Err(SignedWithdrawalError::InvalidSignature)
        );
    }

    #[test]
    fn nonce_request_id_collides_across_different_payloads() {
        let key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let intent = fixture(&key);
        let mut changed = intent.clone();
        changed.recipient = "0x1111111111111111111111111111111111111111".into();
        assert_eq!(
            intent.nonce_request_id().unwrap(),
            changed.nonce_request_id().unwrap()
        );
        assert_ne!(
            intent.command_commitment().unwrap(),
            changed.command_commitment().unwrap()
        );
    }

    #[test]
    fn rejects_noncanonical_values_and_bad_destination() {
        let key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let mut intent = fixture(&key);
        intent.amount_atomic = "020000000".into();
        assert_eq!(intent.validate(), Err(SignedWithdrawalError::InvalidIntent));
        intent = fixture(&key);
        intent.destination_chain = "unsupported".into();
        assert_eq!(intent.validate(), Err(SignedWithdrawalError::InvalidIntent));
    }
}
