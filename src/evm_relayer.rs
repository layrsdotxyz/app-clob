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

use crate::error::{ClobError, ClobResult};

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
    /// Deployed `PredictionMarketVault.sol` address.
    pub vault_address: Option<String>,
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
}
