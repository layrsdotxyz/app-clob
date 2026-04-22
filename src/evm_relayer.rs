/// EVM Relayer — signs and submits transactions to Horizen EVM contracts.
///
/// Replaces `starknet_root_publisher.rs`. Uses `ethers` with a `LocalWallet`
/// backed by a hex private key. All writes go through a single `SignerMiddleware`
/// so nonce management is automatic.
use std::sync::Arc;

use ethers::{
    abi::{encode, Token},
    contract::Contract,
    middleware::SignerMiddleware,
    prelude::*,
    providers::{Http, Provider, Middleware},
    signers::{LocalWallet, Signer},
    types::{Address, Bytes, TransactionRequest, U256, H256},
};
use tracing::{error, info, warn};

use crate::{
    error::{ClobError, ClobResult},
    proof_generation::{parse_honk_proof_from_output, HonkProof},
};

pub type EvmClient = SignerMiddleware<Provider<Http>, LocalWallet>;

/// Config loaded from environment variables.
#[derive(Debug, Clone)]
pub struct EvmRelayerConfig {
    /// JSON-RPC endpoint for Horizen EON / testnet.
    pub rpc_url: String,
    /// Chain ID (e.g. 1663 for Horizen Gobi testnet).
    pub chain_id: u64,
    /// Operator/relayer private key (hex, with or without 0x prefix).
    pub private_key: String,
    /// Deployed `PredictionMarket.sol` address.
    pub prediction_market_address: Option<String>,
    /// Deployed `PredictionMarketVault.sol` (WETH) address.
    pub vault_address: Option<String>,
    /// Deployed ZEN `PrivacyVault` address.
    pub zen_vault_address: Option<String>,
}

impl EvmRelayerConfig {
    pub fn from_env() -> Option<Self> {
        let rpc_url = std::env::var("HORIZEN_RPC_URL")
            .or_else(|_| std::env::var("EVM_RPC_URL"))
            .ok()?;
        let private_key = std::env::var("EVM_OPERATOR_PRIVATE_KEY")
            .or_else(|_| std::env::var("OPERATOR_PRIVATE_KEY"))
            .ok()?;
        let chain_id = std::env::var("EVM_CHAIN_ID")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1663); // Horizen Gobi testnet

        Some(Self {
            rpc_url,
            chain_id,
            private_key,
            prediction_market_address: std::env::var("PREDICTION_MARKET_ADDRESS").ok(),
            vault_address: std::env::var("PREDICTION_MARKET_VAULT_ADDRESS")
                .or_else(|_| std::env::var("PM_VAULT_ADDRESS"))
                .ok(),
            zen_vault_address: std::env::var("ZEN_VAULT_ADDRESS").ok(),
        })
    }
}

/// Shared EVM transaction sender.
pub struct EvmRelayer {
    pub client: Arc<EvmClient>,
    pub config: EvmRelayerConfig,
}

impl EvmRelayer {
    /// Build from environment variables. Returns `None` if required vars are missing.
    pub fn from_env() -> Option<Self> {
        let config = EvmRelayerConfig::from_env()?;
        let provider = Provider::<Http>::try_from(config.rpc_url.as_str())
            .map_err(|e| error!("EVM relayer: bad RPC URL: {e}"))
            .ok()?;

        let key = config.private_key.trim_start_matches("0x");
        let wallet: LocalWallet = key.parse()
            .map_err(|e| error!("EVM relayer: bad private key: {e}"))
            .ok()?;
        let wallet = wallet.with_chain_id(config.chain_id);

        let client = Arc::new(SignerMiddleware::new(provider, wallet));
        info!(
            rpc = %config.rpc_url,
            chain_id = config.chain_id,
            "EVM relayer initialized"
        );
        Some(Self { client, config })
    }

    /// Low-level: call a contract function by ABI-encoding `data` and sending it as a tx.
    /// Returns the transaction hash as a hex string.
    pub async fn send_tx(&self, to: Address, data: Bytes) -> ClobResult<String> {
        let tx = TransactionRequest::new().to(to).data(data);
        let pending = self
            .client
            .send_transaction(tx, None)
            .await
            .map_err(|e| ClobError::Internal(format!("send_tx failed: {e}")))?;

        let receipt = pending
            .await
            .map_err(|e| ClobError::Internal(format!("tx receipt error: {e}")))?;

        match receipt {
            Some(r) if r.status == Some(1u64.into()) => {
                let hash = format!("{:?}", r.transaction_hash);
                info!(tx_hash = %hash, "EVM tx confirmed");
                Ok(hash)
            }
            Some(r) => {
                let hash = format!("{:?}", r.transaction_hash);
                error!(tx_hash = %hash, "EVM tx reverted");
                Err(ClobError::Internal(format!("tx reverted: {hash}")))
            }
            None => Err(ClobError::Internal("tx dropped (no receipt)".to_string())),
        }
    }

    pub fn vault_address(&self) -> Option<Address> {
        self.config.vault_address.as_deref()?.parse().ok()
    }

    pub fn pm_address(&self) -> Option<Address> {
        self.config.prediction_market_address.as_deref()?.parse().ok()
    }

    /// Resolve the PrivacyVault contract address by token symbol.
    /// Falls back to PREDICTION_MARKET_VAULT_ADDRESS for unknown symbols.
    pub fn vault_address_for_token(&self, token: &str) -> Option<String> {
        match token.to_uppercase().as_str() {
            "WETH" | "ETH" => self.config.vault_address.clone(),
            "ZEN" => self.config.zen_vault_address.clone(),
            _ => self.config.vault_address.clone(),
        }
    }

    /// Submit a `withdrawWithProof` transaction to the PrivacyVault contract.
    ///
    /// `vault_address_hex` — the deployed PrivacyVault/PredictionMarketVault address.
    /// `proof_output_json` — prover worker output with `proof_format: "ultra_honk"`,
    ///   `proof_hex`, and `public_inputs` (10 entries for vault_spend circuit).
    ///
    /// Public inputs layout (vault_spend circuit, UltraHonk):
    ///   [0] root, [1] nullifierHash, [2] sharesPublic, [3] sharePrice,
    ///   [4] amount, [5] vaultId, [6] recipient, [7] relayer, [8] fee, [9] extDataHash
    pub async fn submit_withdraw_with_proof(
        &self,
        vault_address_hex: &str,
        proof_output_json: &str,
    ) -> ClobResult<String> {
        let honk = parse_honk_proof_from_output(proof_output_json)?;

        if honk.public_inputs.len() != 10 {
            return Err(ClobError::Internal(format!(
                "expected 10 public inputs for vault_spend, got {}",
                honk.public_inputs.len()
            )));
        }

        let vault_addr: Address = vault_address_hex
            .parse()
            .map_err(|e| ClobError::Internal(format!("invalid vault address: {e}")))?;

        // selector: keccak256("withdrawWithProof(bytes,bytes32[10])")
        let selector = &ethers::utils::keccak256(b"withdrawWithProof(bytes,bytes32[10])")[..4];

        let proof_bytes = hex::decode(
            honk.proof_hex
                .strip_prefix("0x")
                .or_else(|| honk.proof_hex.strip_prefix("0X"))
                .ok_or_else(|| ClobError::Internal("proof_hex not 0x-prefixed".into()))?,
        )
        .map_err(|e| ClobError::Internal(format!("decode proof_hex: {e}")))?;

        let input_tokens: ClobResult<Vec<Token>> = honk
            .public_inputs
            .iter()
            .enumerate()
            .map(|(i, s): (usize, &String)| {
                let hex_body = s
                    .strip_prefix("0x")
                    .or_else(|| s.strip_prefix("0X"))
                    .ok_or_else(|| {
                        ClobError::Internal(format!("public_inputs[{i}] not 0x-prefixed"))
                    })?;
                let bytes = hex::decode(hex_body)
                    .map_err(|e| ClobError::Internal(format!("decode input[{i}]: {e}")))?;
                if bytes.len() != 32 {
                    return Err(ClobError::Internal(format!(
                        "public_inputs[{i}] must be 32 bytes, got {}",
                        bytes.len()
                    )));
                }
                Ok(Token::FixedBytes(bytes))
            })
            .collect();

        let tokens = vec![
            Token::Bytes(proof_bytes),
            Token::FixedArray(input_tokens?),
        ];

        use ethers::abi::encode;
        let calldata: Bytes = [selector, encode(&tokens).as_slice()].concat().into();

        let tx = TransactionRequest::new()
            .to(vault_addr)
            .data(calldata);

        let pending = self
            .client
            .send_transaction(tx, None)
            .await
            .map_err(|e| ClobError::Internal(format!("withdrawWithProof tx failed: {e}")))?;

        let tx_hash = format!("{:#x}", pending.tx_hash());
        info!(tx_hash = %tx_hash, vault = %vault_address_hex, "withdrawWithProof submitted on Horizen");
        Ok(tx_hash)
    }
}

