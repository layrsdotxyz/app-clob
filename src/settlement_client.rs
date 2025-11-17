use crate::eip712::{Eip712Order, Eip712Signer};
use anyhow::Result;
use ethers::{
    abi::{encode, Token},
    contract::Contract,
    prelude::*,
    providers::{Http, Provider},
    types::{Address, TransactionReceipt, U256, H256},
};
use std::sync::Arc;

/// Onchain fill structure matching smart contract
#[derive(Debug, Clone)]
pub struct OnchainFill {
    pub order_id: U256,
    pub market_id: U256,
    pub maker: Address,
    pub taker: Address,
    pub maker_side: u8,  // 0 = BUY, 1 = SELL
    pub price: U256,      // Basis points (0-10000)
    pub size: U256,       // Token amount (18 decimals)
    pub timestamp: U256,  // Unix timestamp
}

impl OnchainFill {
    /// Convert to tuple format for contract call
    pub fn to_tuple(
        &self,
    ) -> (U256, U256, Address, Address, u8, U256, U256, U256) {
        (
            self.order_id,
            self.market_id,
            self.maker,
            self.taker,
            self.maker_side,
            self.price,
            self.size,
            self.timestamp,
        )
    }
}

/// Settlement client for submitting trades to smart contract
pub struct SettlementClient {
    contract: Contract<SignerMiddleware<Provider<Http>, LocalWallet>>,
    contract_address: Address,
    chain_id: u64,
    signer: Eip712Signer,
}

impl SettlementClient {
    /// Create new settlement client
    pub async fn new(
        rpc_url: &str,
        contract_address: Address,
        private_key: &str,
        chain_id: u64,
    ) -> Result<Self> {
        // Create provider
        let provider = Provider::<Http>::try_from(rpc_url)?;

        // Create wallet
        let wallet: LocalWallet = private_key.parse()?;
        let wallet = wallet.with_chain_id(chain_id);

        // Create client with middleware
        let client = Arc::new(SignerMiddleware::new(provider, wallet));

        // Create contract instance with minimal ABI
        let abi_json = r#"[
            {
                "name": "settleTrade",
                "type": "function",
                "inputs": [{
                    "name": "fill",
                    "type": "tuple",
                    "components": [
                        {"name": "orderId", "type": "uint256"},
                        {"name": "marketId", "type": "uint256"},
                        {"name": "maker", "type": "address"},
                        {"name": "taker", "type": "address"},
                        {"name": "makerSide", "type": "uint8"},
                        {"name": "price", "type": "uint256"},
                        {"name": "size", "type": "uint256"},
                        {"name": "timestamp", "type": "uint256"}
                    ]
                }],
                "outputs": []
            },
            {
                "name": "settleMultipleTrades",
                "type": "function",
                "inputs": [{
                    "name": "fills",
                    "type": "tuple[]",
                    "components": [
                        {"name": "orderId", "type": "uint256"},
                        {"name": "marketId", "type": "uint256"},
                        {"name": "maker", "type": "address"},
                        {"name": "taker", "type": "address"},
                        {"name": "makerSide", "type": "uint8"},
                        {"name": "price", "type": "uint256"},
                        {"name": "size", "type": "uint256"},
                        {"name": "timestamp", "type": "uint256"}
                    ]
                }],
                "outputs": []
            }
        ]"#;
        
        let abi: ethers::abi::Abi = serde_json::from_str(abi_json)?;
        let contract = Contract::new(contract_address, abi, client);

        // Create EIP-712 signer (for verification only, not signing)
        let signer = Eip712Signer::new(chain_id, contract_address, None)?;

        Ok(Self {
            contract,
            contract_address,
            chain_id,
            signer,
        })
    }

    /// Settle a single trade onchain
    pub async fn settle_trade(&self, fill: OnchainFill) -> Result<TransactionReceipt> {
        tracing::info!(
            order_id = %fill.order_id,
            market_id = %fill.market_id,
            maker = ?fill.maker,
            taker = ?fill.taker,
            size = %fill.size,
            "Submitting trade to settlement contract"
        );

        let call = self
            .contract
            .method::<_, H256>("settleTrade", (fill.to_tuple(),))?;
        
        let pending_tx = call.send().await?;

        let receipt = pending_tx
            .await?
            .ok_or_else(|| anyhow::anyhow!("Transaction dropped from mempool"))?;

        tracing::info!(
            tx_hash = ?receipt.transaction_hash,
            gas_used = ?receipt.gas_used,
            status = ?receipt.status,
            "Trade settled onchain"
        );

        Ok(receipt)
    }

    /// Settle multiple trades in a single transaction (gas optimization)
    pub async fn settle_batch(&self, fills: Vec<OnchainFill>) -> Result<TransactionReceipt> {
        if fills.is_empty() {
            return Err(anyhow::anyhow!("Cannot settle empty batch"));
        }

        tracing::info!(
            count = fills.len(),
            "Submitting batch settlement"
        );

        let tuples: Vec<_> = fills.iter().map(|f| f.to_tuple()).collect();

        let call = self
            .contract
            .method::<_, H256>("settleMultipleTrades", (tuples,))?;
        
        let pending_tx = call.send().await?;

        let receipt = pending_tx
            .await?
            .ok_or_else(|| anyhow::anyhow!("Transaction dropped from mempool"))?;

        tracing::info!(
            tx_hash = ?receipt.transaction_hash,
            gas_used = ?receipt.gas_used,
            fills = fills.len(),
            "Batch settled onchain"
        );

        Ok(receipt)
    }

    /// Get contract address
    pub fn contract_address(&self) -> Address {
        self.contract_address
    }

    /// Get chain ID
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Verify order signature before settlement
    pub fn verify_order_signature(
        &self,
        order: &Eip712Order,
        signature: &ethers::types::Signature,
    ) -> Result<bool> {
        self.signer.verify_order(order, signature)
    }
}

/// Settlement manager - handles retry logic and batching
pub struct SettlementManager {
    client: Arc<SettlementClient>,
    batch_size: usize,
    retry_attempts: u32,
}

impl SettlementManager {
    pub fn new(client: SettlementClient, batch_size: usize, retry_attempts: u32) -> Self {
        Self {
            client: Arc::new(client),
            batch_size,
            retry_attempts,
        }
    }

    /// Submit fills with automatic batching and retry
    pub async fn submit_fills(&self, fills: Vec<OnchainFill>) -> Result<Vec<TransactionReceipt>> {
        if fills.is_empty() {
            return Ok(Vec::new());
        }

        let mut receipts = Vec::new();

        // Process in batches
        for batch in fills.chunks(self.batch_size) {
            let mut attempts = 0;
            let mut last_error = None;

            while attempts < self.retry_attempts {
                match self.submit_batch_with_retry(batch.to_vec()).await {
                    Ok(receipt) => {
                        receipts.push(receipt);
                        break;
                    }
                    Err(e) => {
                        attempts += 1;
                        last_error = Some(e);

                        if attempts < self.retry_attempts {
                            tracing::warn!(
                                attempt = attempts,
                                batch_size = batch.len(),
                                error = %last_error.as_ref().unwrap(),
                                "Retrying batch settlement"
                            );

                            // Exponential backoff
                            tokio::time::sleep(tokio::time::Duration::from_millis(
                                100 * 2u64.pow(attempts),
                            ))
                            .await;
                        }
                    }
                }
            }

            if attempts >= self.retry_attempts {
                return Err(last_error.unwrap());
            }
        }

        Ok(receipts)
    }

    async fn submit_batch_with_retry(&self, fills: Vec<OnchainFill>) -> Result<TransactionReceipt> {
        if fills.len() == 1 {
            self.client.settle_trade(fills[0].clone()).await
        } else {
            self.client.settle_batch(fills).await
        }
    }

    /// Get client reference
    pub fn client(&self) -> Arc<SettlementClient> {
        self.client.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_onchain_fill_tuple() {
        let fill = OnchainFill {
            order_id: U256::from(1),
            market_id: U256::from(1000000),
            maker: "0x1234567890123456789012345678901234567890"
                .parse()
                .unwrap(),
            taker: "0x0987654321098765432109876543210987654321"
                .parse()
                .unwrap(),
            maker_side: 0,
            price: U256::from(5000),
            size: U256::from(100),
            timestamp: U256::from(1700000000),
        };

        let tuple = fill.to_tuple();
        assert_eq!(tuple.0, U256::from(1));
        assert_eq!(tuple.4, 0);
    }
}
