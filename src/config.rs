use anyhow::Result;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default = "default_host")]
    pub host: String,
    
    #[serde(default = "default_port")]
    pub port: u16,
    
    pub redis_url: String,
    
    #[serde(default = "default_max_orders_per_user")]
    pub max_orders_per_user: usize,
    
    #[serde(default = "default_max_order_size")]
    pub max_order_size: rust_decimal::Decimal,
    
    #[serde(default = "default_maker_fee")]
    pub maker_fee_bps: u16,
    
    #[serde(default = "default_taker_fee")]
    pub taker_fee_bps: u16,
    
    #[serde(default = "default_min_order_size")]
    pub min_order_size: rust_decimal::Decimal,
    
    // Smart contract integration
    #[serde(default)]
    pub enable_settlement: bool,
    pub rpc_url: Option<String>,
    pub settlement_contract: Option<String>,
    pub settlement_private_key: Option<String>,
    pub chain_id: Option<u64>,
    #[serde(default)]
    pub settlement_batch_size: usize,
    #[serde(default)]
    pub settlement_retry_attempts: u32,
}

fn default_host() -> String {
    "0.0.0.0".to_string()
}

fn default_port() -> u16 {
    8080
}

fn default_max_orders_per_user() -> usize {
    100
}

fn default_max_order_size() -> rust_decimal::Decimal {
    rust_decimal::Decimal::from(1_000_000)
}

fn default_maker_fee() -> u16 {
    0 // 0% - No fees by default
}

fn default_taker_fee() -> u16 {
    0 // 0% - No fees by default
}

fn default_min_order_size() -> rust_decimal::Decimal {
    rust_decimal::Decimal::from(1)
}

impl Config {
    pub fn from_env() -> Result<Self> {
        dotenvy::dotenv().ok();
        
        let config = Self {
            host: std::env::var("HOST").unwrap_or_else(|_| default_host()),
            port: std::env::var("PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or_else(default_port),
            redis_url: std::env::var("REDIS_URL")
                .expect("REDIS_URL must be set"),
            max_orders_per_user: std::env::var("MAX_ORDERS_PER_USER")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or_else(default_max_orders_per_user),
            max_order_size: std::env::var("MAX_ORDER_SIZE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or_else(default_max_order_size),
            maker_fee_bps: std::env::var("MAKER_FEE_BPS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or_else(default_maker_fee),
            taker_fee_bps: std::env::var("TAKER_FEE_BPS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or_else(default_taker_fee),
            min_order_size: std::env::var("MIN_ORDER_SIZE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or_else(default_min_order_size),
            enable_settlement: std::env::var("ENABLE_SETTLEMENT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(false),
            rpc_url: std::env::var("RPC_URL").ok(),
            settlement_contract: std::env::var("SETTLEMENT_CONTRACT").ok(),
            settlement_private_key: std::env::var("SETTLEMENT_PRIVATE_KEY").ok(),
            chain_id: std::env::var("CHAIN_ID")
                .ok()
                .and_then(|v| v.parse().ok()),
            settlement_batch_size: std::env::var("SETTLEMENT_BATCH_SIZE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10),
            settlement_retry_attempts: std::env::var("SETTLEMENT_RETRY_ATTEMPTS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3),
        };
        
        Ok(config)
    }
    
    pub fn settlement_contract_address(&self) -> Result<ethers::types::Address> {
        let addr_str = self.settlement_contract
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("SETTLEMENT_CONTRACT not configured"))?;
        addr_str
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid settlement contract address: {}", e))
    }
}
