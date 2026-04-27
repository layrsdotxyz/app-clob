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
    
    // Optional PostgreSQL database URL
    pub database_url: Option<String>,

    // Explicit treasury addresses for the current PM/privacy split
    pub pm_usdc_treasury_address: Option<String>,
    pub pm_zen_treasury_address: Option<String>,
    pub privacy_weth_vault_address: Option<String>,

    // Compatibility aliases for older config consumers
    pub prediction_market_treasury_address: Option<String>,
    pub zen_treasury_address: Option<String>,

    // Additional contract addresses used for runtime validation
    pub zen_token_address: Option<String>,
    pub market_factory_address: Option<String>,

    #[serde(default)]
    pub market_oracle_enabled: bool,

    #[serde(default)]
    pub market_lifecycle_enabled: bool,

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

fn first_env(names: &[&str]) -> Option<String> {
    names
        .iter()
        .find_map(|name| std::env::var(name).ok())
        .filter(|value| !value.trim().is_empty())
}

impl Config {
    pub fn from_env() -> Result<Self> {
        dotenvy::dotenv().ok();

        let pm_usdc_treasury_address = first_env(&[
            "PM_USDC_TREASURY_ADDRESS",
            "PREDICTION_MARKET_TREASURY_ADDRESS",
            "PM_TREASURY_ADDRESS",
            "PM_USDC_VAULT_ADDRESS",
            "PREDICTION_MARKET_VAULT_ADDRESS",
            "PM_VAULT_ADDRESS",
            "USDC_VAULT_ADDRESS",
        ]);
        let pm_zen_treasury_address = first_env(&[
            "PM_ZEN_TREASURY_ADDRESS",
            "ZEN_PM_TREASURY_ADDRESS",
            "ZEN_TREASURY_ADDRESS",
            "PM_ZEN_VAULT_ADDRESS",
            "ZEN_PM_VAULT_ADDRESS",
            "ZEN_VAULT_ADDRESS",
        ]);
        let privacy_weth_vault_address = first_env(&[
            "PRIVACY_WETH_TREASURY_ADDRESS",
            "LP_TREASURY_ADDRESS",
            "PRIVACY_WETH_VAULT_ADDRESS",
            "WETH_VAULT_ADDRESS",
            "ETH_VAULT_ADDRESS",
            "LP_VAULT_ADDRESS",
        ]);
        
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
            database_url: std::env::var("DATABASE_URL").ok(),
            pm_usdc_treasury_address: pm_usdc_treasury_address.clone(),
            pm_zen_treasury_address: pm_zen_treasury_address.clone(),
            privacy_weth_vault_address: privacy_weth_vault_address,
            prediction_market_treasury_address: pm_usdc_treasury_address,
            zen_treasury_address: pm_zen_treasury_address,
            zen_token_address: std::env::var("ZEN_TOKEN_ADDRESS").ok(),
            market_factory_address: std::env::var("MARKET_FACTORY_ADDRESS").ok(),
            market_oracle_enabled: std::env::var("MARKET_ORACLE_ENABLED")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(false),
            market_lifecycle_enabled: std::env::var("MARKET_LIFECYCLE_ENABLED")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(false),
            enable_settlement: std::env::var("ENABLE_SETTLEMENT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(false),
            rpc_url: std::env::var("RPC_URL")
                .or_else(|_| std::env::var("HORIZEN_RPC_URL"))
                .or_else(|_| std::env::var("EVM_RPC_URL"))
                .ok(),
            settlement_contract: std::env::var("SETTLEMENT_CONTRACT").ok(),
            settlement_private_key: std::env::var("SETTLEMENT_PRIVATE_KEY").ok(),
            chain_id: std::env::var("CHAIN_ID")
                .or_else(|_| std::env::var("EVM_CHAIN_ID"))
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

        config.validate()?;

        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        validate_optional_address(
            "PM_USDC_TREASURY_ADDRESS/PREDICTION_MARKET_TREASURY_ADDRESS/PM_TREASURY_ADDRESS/PM_USDC_VAULT_ADDRESS/PREDICTION_MARKET_VAULT_ADDRESS/PM_VAULT_ADDRESS",
            self.pm_usdc_treasury_address.as_deref(),
        )?;
        validate_optional_address(
            "PM_ZEN_TREASURY_ADDRESS/ZEN_PM_TREASURY_ADDRESS/ZEN_TREASURY_ADDRESS/PM_ZEN_VAULT_ADDRESS/ZEN_VAULT_ADDRESS",
            self.pm_zen_treasury_address.as_deref(),
        )?;
        validate_optional_address(
            "PRIVACY_WETH_VAULT_ADDRESS/WETH_VAULT_ADDRESS/LP_VAULT_ADDRESS",
            self.privacy_weth_vault_address.as_deref(),
        )?;
        validate_optional_address("ZEN_TOKEN_ADDRESS", self.zen_token_address.as_deref())?;
        validate_optional_address(
            "MARKET_FACTORY_ADDRESS",
            self.market_factory_address.as_deref(),
        )?;

        if let Some(chain_id) = self.chain_id {
            if chain_id != 2_651_420 {
                anyhow::bail!(
                    "Milestone 1 is pinned to Horizen testnet chain_id 2651420, got {}",
                    chain_id
                );
            }
        }

        if self.market_oracle_enabled && self.market_lifecycle_enabled {
            anyhow::bail!(
                "MARKET_ORACLE_ENABLED and MARKET_LIFECYCLE_ENABLED cannot both be true"
            );
        }

        if let (Some(pm_usdc_treasury), Some(pm_zen_treasury)) = (
            self.pm_usdc_treasury_address.as_ref(),
            self.pm_zen_treasury_address.as_ref(),
        ) {
            if pm_usdc_treasury.eq_ignore_ascii_case(pm_zen_treasury) {
                anyhow::bail!(
                    "PM_USDC_TREASURY_ADDRESS/PM_USDC_VAULT_ADDRESS and PM_ZEN_TREASURY_ADDRESS/PM_ZEN_VAULT_ADDRESS must refer to different treasuries"
                );
            }
        }

        if let (Some(pm_usdc_treasury), Some(privacy_weth_vault)) = (
            self.pm_usdc_treasury_address.as_ref(),
            self.privacy_weth_vault_address.as_ref(),
        ) {
            if pm_usdc_treasury.eq_ignore_ascii_case(privacy_weth_vault) {
                anyhow::bail!(
                    "PM_USDC_TREASURY_ADDRESS/PM_USDC_VAULT_ADDRESS and PRIVACY_WETH_VAULT_ADDRESS must refer to different contracts"
                );
            }
        }

        if let (Some(pm_zen_treasury), Some(privacy_weth_vault)) = (
            self.pm_zen_treasury_address.as_ref(),
            self.privacy_weth_vault_address.as_ref(),
        ) {
            if pm_zen_treasury.eq_ignore_ascii_case(privacy_weth_vault) {
                anyhow::bail!(
                    "PM_ZEN_TREASURY_ADDRESS/PM_ZEN_VAULT_ADDRESS and PRIVACY_WETH_VAULT_ADDRESS must refer to different contracts"
                );
            }
        }

        if self.market_oracle_enabled {
            if self.market_factory_address.is_none() {
                anyhow::bail!(
                    "MARKET_FACTORY_ADDRESS must be set when MARKET_ORACLE_ENABLED=true"
                );
            }

            if self
                .rpc_url
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .is_none()
            {
                anyhow::bail!(
                    "RPC_URL, HORIZEN_RPC_URL, or EVM_RPC_URL must be set when MARKET_ORACLE_ENABLED=true"
                );
            }

            if env_var_is_missing("EVM_OPERATOR_PRIVATE_KEY")
                && env_var_is_missing("OPERATOR_PRIVATE_KEY")
            {
                anyhow::bail!(
                    "EVM_OPERATOR_PRIVATE_KEY or OPERATOR_PRIVATE_KEY must be set when MARKET_ORACLE_ENABLED=true"
                );
            }
        }

        Ok(())
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

fn validate_optional_address(label: &str, value: Option<&str>) -> Result<()> {
    if let Some(raw) = value.map(str::trim).filter(|raw| !raw.is_empty()) {
        raw.parse::<ethers::types::Address>()
            .map_err(|e| anyhow::anyhow!("{} is not a valid EVM address: {}", label, e))?;
    }

    Ok(())
}

fn env_var_is_missing(key: &str) -> bool {
    std::env::var(key)
        .map(|value| value.trim().is_empty())
        .unwrap_or(true)
}
