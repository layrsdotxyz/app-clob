use ed25519_dalek::{Signer as Ed25519Signer, SigningKey};
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeApprovalRequest {
    pub chain: String,
    pub verifying_contract: String,
    pub independent_approver: String,
    pub tee_approver: String,
    pub amount_atomic: String,
    pub destination_eid: u32,
    pub recipient: String,
    pub minimum_destination_amount_atomic: String,
    pub native_fee_wei: String,
    pub nonce: String,
    pub deadline_seconds: u64,
    pub route_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeApprovalSignature {
    pub chain: String,
    pub chain_id: u64,
    pub verifying_contract: String,
    pub signer: String,
    pub signature_hex: String,
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

    /// Returns only public addresses so role wiring can be verified without
    /// exporting any enclave-held key material.
    pub fn bridge_approval_signers(&self) -> BTreeMap<String, String> {
        self.domains
            .iter()
            .map(|(chain, domain)| {
                (
                    chain.clone(),
                    format!("{:#x}", domain.ledger_wallet.address()),
                )
            })
            .collect()
    }

    pub fn sign_bridge_approval(
        &self,
        request: &BridgeApprovalRequest,
        now_millis: i64,
    ) -> Result<BridgeApprovalSignature, String> {
        let domain = self
            .domains
            .get(&request.chain)
            .ok_or_else(|| "CHAIN_SIGNER_DOMAIN_NOT_FOUND".to_string())?;
        let expected_destination_eid = match request.chain.as_str() {
            "base" => 30_399,
            "horizen" => 30_184,
            _ => return Err("INVALID_BRIDGE_APPROVAL_CHAIN".into()),
        };
        if request.destination_eid != expected_destination_eid
            || now_millis < 0
            || request.deadline_seconds <= (now_millis as u64 / 1_000)
            || request.deadline_seconds > (now_millis as u64 / 1_000).saturating_add(86_400)
        {
            return Err("INVALID_BRIDGE_APPROVAL_WINDOW".into());
        }

        let verifying_contract = parse_nonzero_address(&request.verifying_contract)?;
        let independent_approver = parse_nonzero_address(&request.independent_approver)?;
        let tee_approver = parse_nonzero_address(&request.tee_approver)?;
        let recipient = parse_nonzero_address(&request.recipient)?;
        if independent_approver == tee_approver || tee_approver != domain.ledger_wallet.address() {
            return Err("INVALID_BRIDGE_APPROVAL_SIGNER".into());
        }

        let amount = parse_positive_u256(&request.amount_atomic, "INVALID_BRIDGE_APPROVAL_AMOUNT")?;
        let minimum_destination_amount = parse_positive_u256(
            &request.minimum_destination_amount_atomic,
            "INVALID_BRIDGE_APPROVAL_MINIMUM",
        )?;
        if minimum_destination_amount > amount {
            return Err("INVALID_BRIDGE_APPROVAL_MINIMUM".into());
        }
        let native_fee = U256::from_dec_str(&request.native_fee_wei)
            .map_err(|_| "INVALID_BRIDGE_APPROVAL_FEE".to_string())?;
        let nonce = U256::from_dec_str(&request.nonce)
            .map_err(|_| "INVALID_BRIDGE_APPROVAL_NONCE".to_string())?;
        let route_hash = parse_nonzero_h256(&request.route_hash, "INVALID_BRIDGE_APPROVAL_ROUTE")?;

        let domain_name = if request.chain == "base" {
            b"LayrsBaseZenStrategyManager".as_slice()
        } else {
            b"LayrsHorizenZenStrategyReceiver".as_slice()
        };
        let domain_separator = keccak256(encode(&[
            Token::FixedBytes(keccak256(
                b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
            ).to_vec()),
            Token::FixedBytes(keccak256(domain_name).to_vec()),
            Token::FixedBytes(keccak256(b"1").to_vec()),
            Token::Uint(domain.chain_id.into()),
            Token::Address(verifying_contract),
        ]));
        let struct_hash = keccak256(encode(&[
            Token::FixedBytes(keccak256(
                b"BridgeApproval(address independentApprover,address teeApprover,uint256 amount,uint32 destinationEid,address recipient,uint256 minAmountLD,uint256 nativeFee,uint256 nonce,uint256 deadline,bytes32 routeHash)",
            ).to_vec()),
            Token::Address(independent_approver),
            Token::Address(tee_approver),
            Token::Uint(amount),
            Token::Uint(request.destination_eid.into()),
            Token::Address(recipient),
            Token::Uint(minimum_destination_amount),
            Token::Uint(native_fee),
            Token::Uint(nonce),
            Token::Uint(request.deadline_seconds.into()),
            Token::FixedBytes(route_hash.as_bytes().to_vec()),
        ]));
        let mut encoded = Vec::with_capacity(66);
        encoded.extend_from_slice(b"\x19\x01");
        encoded.extend_from_slice(&domain_separator);
        encoded.extend_from_slice(&struct_hash);
        let signature = domain
            .ledger_wallet
            .sign_hash(H256::from(keccak256(encoded)))
            .map_err(|_| "BRIDGE_APPROVAL_SIGNING_FAILED".to_string())?;

        Ok(BridgeApprovalSignature {
            chain: request.chain.clone(),
            chain_id: domain.chain_id,
            verifying_contract: format!("{verifying_contract:#x}"),
            signer: format!("{:#x}", domain.ledger_wallet.address()),
            signature_hex: format!("0x{}", hex::encode(signature.to_vec())),
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

fn parse_nonzero_address(value: &str) -> Result<Address, String> {
    Address::from_str(value)
        .ok()
        .filter(|address| *address != Address::zero())
        .ok_or_else(|| "INVALID_BRIDGE_APPROVAL_ADDRESS".to_string())
}

fn parse_positive_u256(value: &str, error: &str) -> Result<U256, String> {
    U256::from_dec_str(value)
        .ok()
        .filter(|amount| !amount.is_zero())
        .ok_or_else(|| error.to_string())
}

fn parse_nonzero_h256(value: &str, error: &str) -> Result<H256, String> {
    H256::from_str(value)
        .ok()
        .filter(|hash| *hash != H256::zero())
        .ok_or_else(|| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethers_core::utils::rlp::Rlp;

    fn test_signer() -> EnclaveChainSigner {
        EnclaveChainSigner::new(ChainSignerBundle {
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
        .unwrap()
    }

    #[test]
    fn bridge_approval_signs_only_for_the_enclave_domain_key() {
        let signer = test_signer();
        let addresses = signer.bridge_approval_signers();
        let tee_approver = addresses["base"].clone();
        assert_ne!(tee_approver, addresses["horizen"]);
        let request = BridgeApprovalRequest {
            chain: "base".into(),
            verifying_contract: "0x7777777777777777777777777777777777777777".into(),
            independent_approver: "0x8888888888888888888888888888888888888888".into(),
            tee_approver: tee_approver.clone(),
            amount_atomic: "1000000000000000000".into(),
            destination_eid: 30399,
            recipient: "0x9999999999999999999999999999999999999999".into(),
            minimum_destination_amount_atomic: "999000000000000000".into(),
            native_fee_wei: "12345".into(),
            nonce: "42".into(),
            deadline_seconds: 1_800_000_000,
            route_hash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        };
        let signed = signer
            .sign_bridge_approval(&request, 1_799_999_000_000)
            .unwrap();
        assert_eq!(signed.signer, tee_approver);
        assert_eq!(signed.chain_id, 8453);
        assert_eq!(signed.signature_hex.len(), 132);
    }

    #[test]
    fn bridge_approval_rejects_wrong_route_or_signer() {
        let signer = test_signer();
        let mut request = BridgeApprovalRequest {
            chain: "base".into(),
            verifying_contract: "0x7777777777777777777777777777777777777777".into(),
            independent_approver: "0x8888888888888888888888888888888888888888".into(),
            tee_approver: signer.bridge_approval_signers()["base"].clone(),
            amount_atomic: "1".into(),
            destination_eid: 30184,
            recipient: "0x9999999999999999999999999999999999999999".into(),
            minimum_destination_amount_atomic: "1".into(),
            native_fee_wei: "1".into(),
            nonce: "1".into(),
            deadline_seconds: 2_000,
            route_hash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        };
        assert_eq!(
            signer
                .sign_bridge_approval(&request, 1_000_000)
                .unwrap_err(),
            "INVALID_BRIDGE_APPROVAL_WINDOW"
        );
        request.destination_eid = 30399;
        request.tee_approver = request.independent_approver.clone();
        assert_eq!(
            signer
                .sign_bridge_approval(&request, 1_000_000)
                .unwrap_err(),
            "INVALID_BRIDGE_APPROVAL_SIGNER"
        );
    }

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
