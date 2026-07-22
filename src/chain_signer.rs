use ed25519_dalek::{Signer as Ed25519Signer, SigningKey};
use ethers_core::{
    abi::{encode, Token},
    types::{
        transaction::eip2718::TypedTransaction, Address, Bytes, Eip1559TransactionRequest,
        NameOrAddress, U256,
    },
    utils::keccak256,
};
use ethers_signers::{LocalWallet, Signer};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, str::FromStr};
use zeroize::Zeroize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainSignerBundle {
    pub domains: Vec<ChainSignerDomainSecret>,
    pub resolution_private_key_hex: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainSignerDomainSecret {
    pub chain: String,
    pub chain_id: u64,
    pub asset: String,
    pub pool_address: String,
    pub eoa_private_key_hex: String,
    pub admin_oracle_address: String,
    pub oracle_private_key_hex: String,
}

#[derive(Debug, Clone)]
struct ChainSignerDomain {
    chain_id: u64,
    asset: String,
    pool: Address,
    ledger_wallet: LocalWallet,
    admin_oracle: Address,
    oracle_wallet: LocalWallet,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolWithdrawalTransaction {
    pub chain: String,
    pub chain_id: u64,
    pub asset: String,
    pub signer: String,
    pub pool_address: String,
    pub nonce: u64,
    pub transaction_hash: String,
    pub raw_transaction_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarketResolutionTransaction {
    pub chain: String,
    pub chain_id: u64,
    pub signer: String,
    pub admin_oracle_address: String,
    pub market_id_bytes32: String,
    pub outcome: String,
    pub nonce: u64,
    pub transaction_hash: String,
    pub raw_transaction_hex: String,
}

pub struct EnclaveChainSigner {
    domains: BTreeMap<String, ChainSignerDomain>,
    resolution_signer: SigningKey,
}

impl EnclaveChainSigner {
    pub fn new(mut bundle: ChainSignerBundle) -> Result<Self, String> {
        if bundle.domains.len() != 2 {
            bundle
                .domains
                .iter_mut()
                .for_each(|domain| domain.eoa_private_key_hex.zeroize());
            bundle.resolution_private_key_hex.zeroize();
            return Err("CHAIN_SIGNER_REQUIRES_TWO_DOMAINS".into());
        }
        let resolution_bytes =
            hex::decode(bundle.resolution_private_key_hex.trim_start_matches("0x"));
        bundle.resolution_private_key_hex.zeroize();
        let mut resolution_seed: [u8; 32] = match resolution_bytes
            .ok()
            .and_then(|value| value.try_into().ok())
        {
            Some(seed) => seed,
            None => {
                bundle.domains.iter_mut().for_each(|domain| {
                    domain.eoa_private_key_hex.zeroize();
                    domain.oracle_private_key_hex.zeroize();
                });
                return Err("INVALID_RESOLUTION_SIGNING_KEY".into());
            }
        };
        let resolution_signer = SigningKey::from_bytes(&resolution_seed);
        resolution_seed.zeroize();
        let mut domains = BTreeMap::new();
        for mut secret in bundle.domains {
            let expected = match secret.chain.as_str() {
                "base" => (8_453, "USDC"),
                "horizen" => (26_514, "ZEN"),
                _ => {
                    secret.eoa_private_key_hex.zeroize();
                    secret.oracle_private_key_hex.zeroize();
                    return Err("INVALID_CHAIN_SIGNER_DOMAIN".into());
                }
            };
            if secret.chain_id != expected.0
                || secret.asset != expected.1
                || domains.contains_key(&secret.chain)
            {
                secret.eoa_private_key_hex.zeroize();
                secret.oracle_private_key_hex.zeroize();
                return Err("INVALID_CHAIN_SIGNER_DOMAIN".into());
            }
            let pool = match Address::from_str(&secret.pool_address) {
                Ok(value) => value,
                Err(_) => {
                    secret.eoa_private_key_hex.zeroize();
                    secret.oracle_private_key_hex.zeroize();
                    return Err("INVALID_CHAIN_SIGNER_POOL".into());
                }
            };
            let admin_oracle = match Address::from_str(&secret.admin_oracle_address) {
                Ok(value) => value,
                Err(_) => {
                    secret.eoa_private_key_hex.zeroize();
                    secret.oracle_private_key_hex.zeroize();
                    return Err("INVALID_CHAIN_SIGNER_ORACLE".into());
                }
            };
            if pool == Address::zero() || admin_oracle == Address::zero() {
                secret.eoa_private_key_hex.zeroize();
                secret.oracle_private_key_hex.zeroize();
                return Err("INVALID_CHAIN_SIGNER_CONTRACT".into());
            }
            let parsed_ledger = secret.eoa_private_key_hex.parse::<LocalWallet>();
            let parsed_oracle = secret.oracle_private_key_hex.parse::<LocalWallet>();
            secret.eoa_private_key_hex.zeroize();
            secret.oracle_private_key_hex.zeroize();
            let ledger_wallet = parsed_ledger
                .map_err(|_| "INVALID_CHAIN_SIGNER_KEY".to_string())?
                .with_chain_id(secret.chain_id);
            let oracle_wallet = parsed_oracle
                .map_err(|_| "INVALID_CHAIN_ORACLE_KEY".to_string())?
                .with_chain_id(secret.chain_id);
            if ledger_wallet.address() == oracle_wallet.address() {
                return Err("CHAIN_SIGNER_KEYS_MUST_BE_SEPARATED".into());
            }
            domains.insert(
                secret.chain.clone(),
                ChainSignerDomain {
                    chain_id: secret.chain_id,
                    asset: secret.asset,
                    pool,
                    ledger_wallet,
                    admin_oracle,
                    oracle_wallet,
                },
            );
        }
        Ok(Self {
            domains,
            resolution_signer,
        })
    }

    pub fn resolution_verifying_key(&self) -> [u8; 32] {
        self.resolution_signer.verifying_key().to_bytes()
    }

    pub fn sign_resolution_payload(&self, payload: &[u8]) -> Vec<u8> {
        self.resolution_signer.sign(payload).to_bytes().to_vec()
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn sign_pool_withdrawal(
        &self,
        chain: &str,
        asset: &str,
        destination: &str,
        amount_atomic: &str,
        nonce: u64,
        gas_limit: u64,
        max_fee_per_gas_wei: &str,
        max_priority_fee_per_gas_wei: &str,
    ) -> Result<PoolWithdrawalTransaction, String> {
        let domain = self
            .domains
            .get(chain)
            .ok_or_else(|| "CHAIN_SIGNER_DOMAIN_NOT_FOUND".to_string())?;
        if asset != domain.asset {
            return Err("CHAIN_SIGNER_ASSET_MISMATCH".into());
        }
        if !(45_000..=250_000).contains(&gas_limit) {
            return Err("INVALID_WITHDRAWAL_GAS_LIMIT".into());
        }
        let destination = Address::from_str(destination)
            .map_err(|_| "INVALID_WITHDRAWAL_DESTINATION".to_string())?;
        if destination == Address::zero() {
            return Err("INVALID_WITHDRAWAL_DESTINATION".into());
        }
        let amount = U256::from_dec_str(amount_atomic)
            .map_err(|_| "INVALID_WITHDRAWAL_AMOUNT".to_string())?;
        if amount.is_zero() {
            return Err("INVALID_WITHDRAWAL_AMOUNT".into());
        }
        let max_fee =
            U256::from_dec_str(max_fee_per_gas_wei).map_err(|_| "INVALID_MAX_FEE".to_string())?;
        let priority_fee = U256::from_dec_str(max_priority_fee_per_gas_wei)
            .map_err(|_| "INVALID_PRIORITY_FEE".to_string())?;
        if max_fee.is_zero() || priority_fee > max_fee {
            return Err("INVALID_WITHDRAWAL_FEE".into());
        }

        let mut calldata = Vec::with_capacity(68);
        calldata.extend_from_slice(&keccak256(b"withdraw(address,uint256)")[..4]);
        calldata.extend_from_slice(&[0u8; 12]);
        calldata.extend_from_slice(destination.as_bytes());
        let mut encoded_amount = [0u8; 32];
        amount.to_big_endian(&mut encoded_amount);
        calldata.extend_from_slice(&encoded_amount);
        let request = Eip1559TransactionRequest {
            from: Some(domain.ledger_wallet.address()),
            to: Some(NameOrAddress::Address(domain.pool)),
            gas: Some(gas_limit.into()),
            value: Some(U256::zero()),
            data: Some(Bytes::from(calldata)),
            nonce: Some(nonce.into()),
            access_list: Default::default(),
            max_priority_fee_per_gas: Some(priority_fee),
            max_fee_per_gas: Some(max_fee),
            chain_id: Some(domain.chain_id.into()),
        };
        let transaction = TypedTransaction::Eip1559(request);
        let signature = domain
            .ledger_wallet
            .sign_transaction(&transaction)
            .await
            .map_err(|_| "WITHDRAWAL_SIGNING_FAILED".to_string())?;
        let raw = transaction.rlp_signed(&signature);
        Ok(PoolWithdrawalTransaction {
            chain: chain.into(),
            chain_id: domain.chain_id,
            asset: asset.into(),
            signer: format!("{:#x}", domain.ledger_wallet.address()),
            pool_address: format!("{:#x}", domain.pool),
            nonce,
            transaction_hash: format!("0x{}", hex::encode(keccak256(&raw))),
            raw_transaction_hex: format!("0x{}", hex::encode(raw)),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn sign_market_resolution(
        &self,
        chain: &str,
        canonical_market_id: &str,
        outcome: &str,
        reason_uri: &str,
        nonce: u64,
        gas_limit: u64,
        max_fee_per_gas_wei: &str,
        max_priority_fee_per_gas_wei: &str,
    ) -> Result<MarketResolutionTransaction, String> {
        let domain = self
            .domains
            .get(chain)
            .ok_or_else(|| "CHAIN_SIGNER_DOMAIN_NOT_FOUND".to_string())?;
        if !valid_market_id(canonical_market_id)
            || !(75_000..=350_000).contains(&gas_limit)
            || reason_uri.len() > 512
            || !reason_uri.starts_with("https://api.layrs.xyz/v1/resolutions/")
        {
            return Err("INVALID_MARKET_RESOLUTION_REQUEST".into());
        }
        let outcome_value = match outcome {
            "UP" => 1u8,
            "DOWN" => 2u8,
            "PUSH" => 3u8,
            _ => return Err("INVALID_MARKET_RESOLUTION_OUTCOME".into()),
        };
        let max_fee =
            U256::from_dec_str(max_fee_per_gas_wei).map_err(|_| "INVALID_MAX_FEE".to_string())?;
        let priority_fee = U256::from_dec_str(max_priority_fee_per_gas_wei)
            .map_err(|_| "INVALID_PRIORITY_FEE".to_string())?;
        if max_fee.is_zero() || priority_fee > max_fee {
            return Err("INVALID_RESOLUTION_FEE".into());
        }
        let market_id = keccak256(canonical_market_id.as_bytes());
        let mut calldata = keccak256(b"resolve(bytes32,uint8,string)")[..4].to_vec();
        calldata.extend_from_slice(&encode(&[
            Token::FixedBytes(market_id.to_vec()),
            Token::Uint(U256::from(outcome_value)),
            Token::String(reason_uri.into()),
        ]));
        let request = Eip1559TransactionRequest {
            from: Some(domain.oracle_wallet.address()),
            to: Some(NameOrAddress::Address(domain.admin_oracle)),
            gas: Some(gas_limit.into()),
            value: Some(U256::zero()),
            data: Some(Bytes::from(calldata)),
            nonce: Some(nonce.into()),
            access_list: Default::default(),
            max_priority_fee_per_gas: Some(priority_fee),
            max_fee_per_gas: Some(max_fee),
            chain_id: Some(domain.chain_id.into()),
        };
        let transaction = TypedTransaction::Eip1559(request);
        let signature = domain
            .oracle_wallet
            .sign_transaction(&transaction)
            .await
            .map_err(|_| "RESOLUTION_SIGNING_FAILED".to_string())?;
        let raw = transaction.rlp_signed(&signature);
        Ok(MarketResolutionTransaction {
            chain: chain.into(),
            chain_id: domain.chain_id,
            signer: format!("{:#x}", domain.oracle_wallet.address()),
            admin_oracle_address: format!("{:#x}", domain.admin_oracle),
            market_id_bytes32: format!("0x{}", hex::encode(market_id)),
            outcome: outcome.into(),
            nonce,
            transaction_hash: format!("0x{}", hex::encode(keccak256(&raw))),
            raw_transaction_hex: format!("0x{}", hex::encode(raw)),
        })
    }
}

fn valid_market_id(value: &str) -> bool {
    let parts: Vec<&str> = value.split(':').collect();
    parts.len() == 5
        && parts[0] == "layrs"
        && parts[1] == "v1"
        && matches!(parts[2], "BTC" | "ETH" | "SOL" | "ZEN")
        && matches!(parts[3], "15m" | "1h" | "4h" | "1d" | "1w" | "1mo")
        && parts[4].len() == 10
        && parts[4].bytes().all(|byte| byte.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethers_core::utils::rlp::Rlp;

    #[tokio::test]
    async fn signs_only_the_audited_pool_withdraw_selector() {
        let signer = EnclaveChainSigner::new(ChainSignerBundle {
            resolution_private_key_hex:
                "0x4f3edf983ac63ad7c7f9a2f8b7f3fb6d84ff79d59bf393ae7d4bc0f6f1a5c06d".into(),
            domains: vec![
                ChainSignerDomainSecret {
                    chain: "base".into(),
                    chain_id: 8453,
                    asset: "USDC".into(),
                    pool_address: "0x1111111111111111111111111111111111111111".into(),
                    eoa_private_key_hex:
                        "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d".into(),
                    admin_oracle_address: "0x4444444444444444444444444444444444444444".into(),
                    oracle_private_key_hex:
                        "0x0dbbe8e4e7a7e1bfa5fd84f122539111716f10a741f14e20511e097c620c4681".into(),
                },
                ChainSignerDomainSecret {
                    chain: "horizen".into(),
                    chain_id: 26514,
                    asset: "ZEN".into(),
                    pool_address: "0x2222222222222222222222222222222222222222".into(),
                    eoa_private_key_hex:
                        "0x8b3a350cf5c34c9194ca3a545d9c34e9e00f4d10b423f7594c35c3bb2d95b42f".into(),
                    admin_oracle_address: "0x5555555555555555555555555555555555555555".into(),
                    oracle_private_key_hex:
                        "0x47e179ec197488593b187f80a00eb0da91f1b9d9e85bc7b52cda8535144f2381".into(),
                },
            ],
        })
        .unwrap();
        let signed = signer
            .sign_pool_withdrawal(
                "base",
                "USDC",
                "0x3333333333333333333333333333333333333333",
                "1000000",
                7,
                80_000,
                "200000000",
                "100000000",
            )
            .await
            .unwrap();
        assert_eq!(signed.chain_id, 8453);
        assert!(signed.raw_transaction_hex.starts_with("0x02"));
        assert!(!Rlp::new(&hex::decode(&signed.raw_transaction_hex[4..]).unwrap()).is_empty());
        assert_eq!(signed.transaction_hash.len(), 66);
    }

    #[tokio::test]
    async fn signs_only_the_pinned_admin_oracle_resolution_call() {
        let signer = EnclaveChainSigner::new(ChainSignerBundle {
            resolution_private_key_hex:
                "0x4f3edf983ac63ad7c7f9a2f8b7f3fb6d84ff79d59bf393ae7d4bc0f6f1a5c06d".into(),
            domains: vec![
                ChainSignerDomainSecret {
                    chain: "base".into(),
                    chain_id: 8453,
                    asset: "USDC".into(),
                    pool_address: "0x1111111111111111111111111111111111111111".into(),
                    eoa_private_key_hex:
                        "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d".into(),
                    admin_oracle_address: "0x4444444444444444444444444444444444444444".into(),
                    oracle_private_key_hex:
                        "0x0dbbe8e4e7a7e1bfa5fd84f122539111716f10a741f14e20511e097c620c4681".into(),
                },
                ChainSignerDomainSecret {
                    chain: "horizen".into(),
                    chain_id: 26514,
                    asset: "ZEN".into(),
                    pool_address: "0x2222222222222222222222222222222222222222".into(),
                    eoa_private_key_hex:
                        "0x8b3a350cf5c34c9194ca3a545d9c34e9e00f4d10b423f7594c35c3bb2d95b42f".into(),
                    admin_oracle_address: "0x5555555555555555555555555555555555555555".into(),
                    oracle_private_key_hex:
                        "0x47e179ec197488593b187f80a00eb0da91f1b9d9e85bc7b52cda8535144f2381".into(),
                },
            ],
        })
        .unwrap();
        let signed = signer
            .sign_market_resolution(
                "horizen",
                "layrs:v1:ZEN:15m:1800000000",
                "PUSH",
                "https://api.layrs.xyz/v1/resolutions/layrs%3Av1%3AZEN%3A15m%3A1800000000",
                9,
                180_000,
                "200000000",
                "100000000",
            )
            .await
            .unwrap();
        assert_eq!(signed.chain_id, 26514);
        assert_eq!(signed.outcome, "PUSH");
        assert_eq!(
            signed.admin_oracle_address,
            "0x5555555555555555555555555555555555555555"
        );
        assert!(signed.raw_transaction_hex.starts_with("0x02"));
    }
}
