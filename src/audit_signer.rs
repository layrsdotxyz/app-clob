use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
};

use ed25519_dalek::{Signature as Ed25519Signature, Verifier, VerifyingKey};
use ethers_core::{
    abi::{encode, Token},
    types::{
        transaction::eip2718::TypedTransaction, Address, Bytes, Eip1559TransactionRequest,
        NameOrAddress, H256, U256,
    },
    utils::keccak256,
};
use ethers_signers::{LocalWallet, Signer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::private_core::SignedAuditFillArtifact;

const DOMAIN_NAME: &str = "PredifiMatchSettlement";
const DOMAIN_VERSION: &str = "1";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditSignerBundle {
    pub domains: Vec<AuditSignerDomainSecret>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditSignerDomainSecret {
    pub chain: String,
    pub chain_id: u64,
    pub settlement_address: String,
    pub eoa_private_key_hex: String,
}

#[derive(Debug, Clone)]
struct AuditSignerDomain {
    chain_id: u64,
    settlement: Address,
    wallet: LocalWallet,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditBatchRequest {
    pub chain: String,
    pub artifacts: Vec<SignedAuditFillArtifact>,
    pub deadline: u64,
    pub now_seconds: u64,
    pub transaction_nonce: u64,
    pub gas_limit: u64,
    pub max_fee_per_gas_wei: String,
    pub max_priority_fee_per_gas_wei: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedAuditSettlementTransaction {
    pub chain: String,
    pub chain_id: u64,
    pub signer: String,
    pub settlement_address: String,
    pub batch_id: String,
    pub deadline: u64,
    pub receipt_merkle_root: String,
    pub fill_count: usize,
    pub transaction_nonce: u64,
    pub transaction_hash: String,
    pub raw_transaction_hex: String,
}

#[derive(Debug, Clone)]
struct ValidatedFill {
    market_id: [u8; 32],
    buyer: Address,
    seller: Address,
    quantity: U256,
    price: U256,
    fee: U256,
    nonce: U256,
    leaf_hash: [u8; 32],
}

pub struct EnclaveAuditSigner {
    domains: BTreeMap<String, AuditSignerDomain>,
}

impl EnclaveAuditSigner {
    pub fn new(mut bundle: AuditSignerBundle) -> Result<Self, String> {
        if bundle.domains.len() != 2 {
            bundle
                .domains
                .iter_mut()
                .for_each(|domain| domain.eoa_private_key_hex.zeroize());
            return Err("AUDIT_SIGNER_REQUIRES_TWO_DOMAINS".into());
        }
        let mut domains = BTreeMap::new();
        for mut secret in bundle.domains {
            let expected_chain_id = match secret.chain.as_str() {
                "base" => 8_453,
                "horizen" => 26_514,
                _ => {
                    secret.eoa_private_key_hex.zeroize();
                    return Err("INVALID_AUDIT_SIGNER_DOMAIN".into());
                }
            };
            if secret.chain_id != expected_chain_id || domains.contains_key(&secret.chain) {
                secret.eoa_private_key_hex.zeroize();
                return Err("INVALID_AUDIT_SIGNER_DOMAIN".into());
            }
            let settlement = Address::from_str(&secret.settlement_address)
                .map_err(|_| "INVALID_AUDIT_SETTLEMENT_ADDRESS".to_string())?;
            if settlement == Address::zero() {
                secret.eoa_private_key_hex.zeroize();
                return Err("INVALID_AUDIT_SETTLEMENT_ADDRESS".into());
            }
            let parsed = secret.eoa_private_key_hex.parse::<LocalWallet>();
            secret.eoa_private_key_hex.zeroize();
            let wallet = parsed
                .map_err(|_| "INVALID_AUDIT_SIGNER_KEY".to_string())?
                .with_chain_id(secret.chain_id);
            domains.insert(
                secret.chain.clone(),
                AuditSignerDomain {
                    chain_id: secret.chain_id,
                    settlement,
                    wallet,
                },
            );
        }
        Ok(Self { domains })
    }

    pub async fn sign_batch_transaction(
        &self,
        request: AuditBatchRequest,
        trusted_receipt_public_key: [u8; 32],
    ) -> Result<SignedAuditSettlementTransaction, String> {
        let domain = self
            .domains
            .get(&request.chain)
            .ok_or_else(|| "AUDIT_SIGNER_DOMAIN_NOT_FOUND".to_string())?;
        if request.artifacts.is_empty() || request.artifacts.len() > 100 {
            return Err("INVALID_AUDIT_BATCH_SIZE".into());
        }
        if request.deadline <= request.now_seconds
            || request.deadline > request.now_seconds.saturating_add(3_600)
        {
            return Err("INVALID_AUDIT_BATCH_DEADLINE".into());
        }
        if !(250_000..=12_000_000).contains(&request.gas_limit) {
            return Err("INVALID_AUDIT_GAS_LIMIT".into());
        }
        let max_fee = U256::from_dec_str(&request.max_fee_per_gas_wei)
            .map_err(|_| "INVALID_MAX_FEE".to_string())?;
        let priority_fee = U256::from_dec_str(&request.max_priority_fee_per_gas_wei)
            .map_err(|_| "INVALID_PRIORITY_FEE".to_string())?;
        if max_fee.is_zero() || priority_fee > max_fee {
            return Err("INVALID_AUDIT_TRANSACTION_FEE".into());
        }

        let verifying_key = VerifyingKey::from_bytes(&trusted_receipt_public_key)
            .map_err(|_| "INVALID_RECEIPT_PUBLIC_KEY".to_string())?;
        let mut keys = BTreeSet::new();
        let mut fills = Vec::with_capacity(request.artifacts.len());
        for artifact in &request.artifacts {
            if artifact.statement.chain != request.chain
                || artifact.receipt_public_key != trusted_receipt_public_key
            {
                return Err("UNTRUSTED_AUDIT_ARTIFACT".into());
            }
            verify_artifact(artifact, &verifying_key)?;
            let fill = validate_fill(artifact)?;
            if !keys.insert((
                artifact.statement.market_id_bytes32.clone(),
                artifact.statement.nonce.clone(),
            )) {
                return Err("DUPLICATE_AUDIT_FILL".into());
            }
            fills.push(fill);
        }

        let merkle_root = merkle_root(fills.iter().map(|fill| fill.leaf_hash).collect());
        let batch_id = batch_id(merkle_root, request.deadline);
        let digest = eip712_digest(domain, batch_id, request.deadline, &fills);
        let signature = domain
            .wallet
            .sign_hash(H256::from(digest))
            .map_err(|_| "AUDIT_BATCH_SIGNING_FAILED".to_string())?;
        let signature_bytes = signature.to_vec();
        let calldata = batch_calldata(batch_id, request.deadline, &fills, &signature_bytes);
        let transaction = TypedTransaction::Eip1559(Eip1559TransactionRequest {
            from: Some(domain.wallet.address()),
            to: Some(NameOrAddress::Address(domain.settlement)),
            gas: Some(request.gas_limit.into()),
            value: Some(U256::zero()),
            data: Some(Bytes::from(calldata)),
            nonce: Some(request.transaction_nonce.into()),
            access_list: Default::default(),
            max_priority_fee_per_gas: Some(priority_fee),
            max_fee_per_gas: Some(max_fee),
            chain_id: Some(domain.chain_id.into()),
        });
        let transaction_signature = domain
            .wallet
            .sign_transaction(&transaction)
            .await
            .map_err(|_| "AUDIT_TRANSACTION_SIGNING_FAILED".to_string())?;
        let raw = transaction.rlp_signed(&transaction_signature);
        Ok(SignedAuditSettlementTransaction {
            chain: request.chain,
            chain_id: domain.chain_id,
            signer: format!("{:#x}", domain.wallet.address()),
            settlement_address: format!("{:#x}", domain.settlement),
            batch_id: batch_id.to_string(),
            deadline: request.deadline,
            receipt_merkle_root: format!("0x{}", hex::encode(merkle_root)),
            fill_count: fills.len(),
            transaction_nonce: request.transaction_nonce,
            transaction_hash: format!("0x{}", hex::encode(keccak256(&raw))),
            raw_transaction_hex: format!("0x{}", hex::encode(raw)),
        })
    }
}

fn verify_artifact(artifact: &SignedAuditFillArtifact, key: &VerifyingKey) -> Result<(), String> {
    let signature: [u8; 64] = artifact
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| "INVALID_AUDIT_ARTIFACT_SIGNATURE".to_string())?;
    let mut unsigned = artifact.clone();
    unsigned.signature.clear();
    let encoded =
        serde_json::to_vec(&unsigned).map_err(|_| "INVALID_AUDIT_ARTIFACT".to_string())?;
    let mut payload = b"layrs.audit-fill-artifact.v1\0".to_vec();
    payload.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
    payload.extend_from_slice(&encoded);
    key.verify(&payload, &Ed25519Signature::from_bytes(&signature))
        .map_err(|_| "INVALID_AUDIT_ARTIFACT_SIGNATURE".to_string())
}

fn validate_fill(artifact: &SignedAuditFillArtifact) -> Result<ValidatedFill, String> {
    let statement = &artifact.statement;
    if statement.protocol_version != "layrs.audit-fill.v1" {
        return Err("INVALID_AUDIT_PROTOCOL".into());
    }
    if !matches!(
        statement.outcome.as_deref(),
        None | Some("UP") | Some("DOWN")
    ) || !matches!(
        statement.match_type.as_deref(),
        None | Some("NORMAL") | Some("MINT") | Some("MERGE")
    ) || statement.outcome.is_some() != statement.match_type.is_some()
    {
        return Err("INVALID_AUDIT_QUOTE_METADATA".into());
    }
    let market = fixed_bytes::<32>(&statement.market_id_bytes32, "INVALID_MARKET_ID")?;
    if market != keccak256(statement.market_id.as_bytes()) {
        return Err("MARKET_ID_HASH_MISMATCH".into());
    }
    let buyer = Address::from_str(&statement.buyer_one_time_pseudonym)
        .map_err(|_| "INVALID_BUYER_ALIAS".to_string())?;
    let seller = Address::from_str(&statement.seller_one_time_pseudonym)
        .map_err(|_| "INVALID_SELLER_ALIAS".to_string())?;
    if buyer == Address::zero() || seller == Address::zero() || buyer == seller {
        return Err("INVALID_AUDIT_COUNTERPARTY".into());
    }
    let quantity = U256::from_dec_str(&statement.quantity_atomic)
        .map_err(|_| "INVALID_AUDIT_QUANTITY".to_string())?;
    let fee =
        U256::from_dec_str(&statement.fee_atomic).map_err(|_| "INVALID_AUDIT_FEE".to_string())?;
    let nonce =
        U256::from_dec_str(&statement.nonce).map_err(|_| "INVALID_AUDIT_NONCE".to_string())?;
    if quantity.is_zero()
        || statement.price_micros == 0
        || statement.price_micros >= 1_000_000
        || !statement.price_micros.is_multiple_of(100)
    {
        return Err("INVALID_AUDIT_ECONOMICS".into());
    }
    let state_root: [u8; 32] = artifact.state_root;
    let mut leaf = Sha256::new();
    leaf.update(b"layrs.audit-receipt.v1\0");
    leaf.update(artifact.receipt_id.as_bytes());
    leaf.update(state_root);
    leaf.update(market);
    leaf.update(nonce.to_string().as_bytes());
    Ok(ValidatedFill {
        market_id: market,
        buyer,
        seller,
        quantity,
        price: U256::from(statement.price_micros / 100),
        fee,
        nonce,
        leaf_hash: leaf.finalize().into(),
    })
}

fn fill_hash(fill: &ValidatedFill) -> [u8; 32] {
    keccak256(encode(&[
        Token::FixedBytes(keccak256(b"Fill(bytes32 marketId,address buyer,address seller,uint256 quantity,uint256 price,uint256 fee,uint256 nonce)").to_vec()),
        Token::FixedBytes(fill.market_id.to_vec()), Token::Address(fill.buyer), Token::Address(fill.seller),
        Token::Uint(fill.quantity), Token::Uint(fill.price), Token::Uint(fill.fee), Token::Uint(fill.nonce),
    ]))
}

fn eip712_digest(
    domain: &AuditSignerDomain,
    batch_id: U256,
    deadline: u64,
    fills: &[ValidatedFill],
) -> [u8; 32] {
    let packed_fill_hashes: Vec<u8> = fills.iter().flat_map(fill_hash).collect();
    let struct_hash = keccak256(encode(&[
        Token::FixedBytes(keccak256(b"BatchSettlement(uint256 batchId,Fill[] fills,uint256 deadline)Fill(bytes32 marketId,address buyer,address seller,uint256 quantity,uint256 price,uint256 fee,uint256 nonce)").to_vec()),
        Token::Uint(batch_id), Token::FixedBytes(keccak256(packed_fill_hashes).to_vec()), Token::Uint(deadline.into()),
    ]));
    let domain_separator = keccak256(encode(&[
        Token::FixedBytes(keccak256(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)").to_vec()),
        Token::FixedBytes(keccak256(DOMAIN_NAME.as_bytes()).to_vec()),
        Token::FixedBytes(keccak256(DOMAIN_VERSION.as_bytes()).to_vec()),
        Token::Uint(domain.chain_id.into()), Token::Address(domain.settlement),
    ]));
    keccak256([b"\x19\x01".as_slice(), &domain_separator, &struct_hash].concat())
}

fn batch_calldata(
    batch_id: U256,
    deadline: u64,
    fills: &[ValidatedFill],
    signature: &[u8],
) -> Vec<u8> {
    let fill_tokens = fills
        .iter()
        .map(|fill| {
            Token::Tuple(vec![
                Token::FixedBytes(fill.market_id.to_vec()),
                Token::Address(fill.buyer),
                Token::Address(fill.seller),
                Token::Uint(fill.quantity),
                Token::Uint(fill.price),
                Token::Uint(fill.fee),
                Token::Uint(fill.nonce),
            ])
        })
        .collect();
    let mut calldata = keccak256(b"batchSettle((uint256,(bytes32,address,address,uint256,uint256,uint256,uint256)[],uint256),bytes)")[..4].to_vec();
    calldata.extend_from_slice(&encode(&[
        Token::Tuple(vec![
            Token::Uint(batch_id),
            Token::Array(fill_tokens),
            Token::Uint(deadline.into()),
        ]),
        Token::Bytes(signature.to_vec()),
    ]));
    calldata
}

fn merkle_root(mut layer: Vec<[u8; 32]>) -> [u8; 32] {
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        for pair in layer.chunks(2) {
            let right = pair.get(1).unwrap_or(&pair[0]);
            next.push(Sha256::digest([pair[0].as_slice(), right.as_slice()].concat()).into());
        }
        layer = next;
    }
    layer[0]
}

fn batch_id(root: [u8; 32], deadline: u64) -> U256 {
    let digest = Sha256::digest(
        [
            b"layrs.audit-batch.v1\0".as_slice(),
            root.as_slice(),
            deadline.to_string().as_bytes(),
        ]
        .concat(),
    );
    U256::from_big_endian(&digest)
}

fn fixed_bytes<const N: usize>(value: &str, code: &str) -> Result<[u8; N], String> {
    let decoded = hex::decode(value.strip_prefix("0x").ok_or_else(|| code.to_string())?)
        .map_err(|_| code.to_string())?;
    decoded.try_into().map_err(|_| code.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::private_core::{AuditFillStatement, ReceiptSigner};

    #[tokio::test]
    async fn signs_only_receipt_key_bound_audited_batches() {
        let receipt = ReceiptSigner::generate([9u8; 48]);
        let market_id = "layrs:v1:ZEN:15m:1800000000";
        let mut artifact = SignedAuditFillArtifact {
            statement: AuditFillStatement {
                protocol_version: "layrs.audit-fill.v1".into(),
                chain: "horizen".into(),
                market_id: market_id.into(),
                market_id_bytes32: format!("0x{}", hex::encode(keccak256(market_id.as_bytes()))),
                buyer_one_time_pseudonym: "0x1111111111111111111111111111111111111111".into(),
                seller_one_time_pseudonym: "0x2222222222222222222222222222222222222222".into(),
                quantity_atomic: "1000000".into(),
                price_micros: 510000,
                outcome: Some("UP".into()),
                match_type: Some("NORMAL".into()),
                fee_atomic: "102".into(),
                nonce: "7".into(),
            },
            receipt_id: format!("receipt_{}", "11".repeat(32)),
            state_root: [3u8; 32],
            receipt_public_key: receipt.verifying_key(),
            signature: Vec::new(),
        };
        artifact.signature =
            receipt.sign_domain_payload(b"layrs.audit-fill-artifact.v1\0", &artifact);
        let signer = EnclaveAuditSigner::new(AuditSignerBundle {
            domains: vec![
                AuditSignerDomainSecret {
                    chain: "base".into(),
                    chain_id: 8453,
                    settlement_address: "0x1111111111111111111111111111111111111111".into(),
                    eoa_private_key_hex:
                        "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d".into(),
                },
                AuditSignerDomainSecret {
                    chain: "horizen".into(),
                    chain_id: 26514,
                    settlement_address: "0x2222222222222222222222222222222222222222".into(),
                    eoa_private_key_hex:
                        "0x8b3a350cf5c34c9194ca3a545d9c34e9e00f4d10b423f7594c35c3bb2d95b42f".into(),
                },
            ],
        })
        .unwrap();
        let signed = signer
            .sign_batch_transaction(
                AuditBatchRequest {
                    chain: "horizen".into(),
                    artifacts: vec![artifact.clone()],
                    deadline: 1_300,
                    now_seconds: 1_000,
                    transaction_nonce: 4,
                    gas_limit: 500_000,
                    max_fee_per_gas_wei: "200000000".into(),
                    max_priority_fee_per_gas_wei: "100000000".into(),
                },
                receipt.verifying_key(),
            )
            .await
            .unwrap();
        assert_eq!(signed.chain_id, 26_514);
        assert!(signed.raw_transaction_hex.starts_with("0x02"));
        artifact.signature[0] ^= 1;
        let error = signer
            .sign_batch_transaction(
                AuditBatchRequest {
                    chain: "horizen".into(),
                    artifacts: vec![artifact],
                    deadline: 1_300,
                    now_seconds: 1_000,
                    transaction_nonce: 4,
                    gas_limit: 500_000,
                    max_fee_per_gas_wei: "200000000".into(),
                    max_priority_fee_per_gas_wei: "100000000".into(),
                },
                receipt.verifying_key(),
            )
            .await
            .unwrap_err();
        assert_eq!(error, "INVALID_AUDIT_ARTIFACT_SIGNATURE");
    }
}
