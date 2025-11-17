use anyhow::Result;
use ethers::types::{Address, U256};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Market ID mapper - converts string market IDs to uint256 for smart contracts
pub struct MarketIdMapper {
    /// String -> U256 mapping
    string_to_uint: Arc<RwLock<HashMap<String, U256>>>,
    /// U256 -> String reverse mapping
    uint_to_string: Arc<RwLock<HashMap<U256, String>>>,
    /// Counter for sequential IDs
    next_id: Arc<RwLock<U256>>,
    /// Offset to avoid collisions
    offset: U256,
}

impl MarketIdMapper {
    pub fn new(offset: u64) -> Self {
        Self {
            string_to_uint: Arc::new(RwLock::new(HashMap::new())),
            uint_to_string: Arc::new(RwLock::new(HashMap::new())),
            next_id: Arc::new(RwLock::new(U256::from(offset))),
            offset: U256::from(offset),
        }
    }

    /// Get or create uint256 ID for a string market ID
    pub async fn get_or_create_uint(&self, market_id: &str) -> Result<U256> {
        // Check if already mapped
        {
            let map = self.string_to_uint.read().await;
            if let Some(id) = map.get(market_id) {
                return Ok(*id);
            }
        }

        // Create new mapping
        let mut string_map = self.string_to_uint.write().await;
        let mut uint_map = self.uint_to_string.write().await;
        let mut next_id = self.next_id.write().await;

        // Double-check after acquiring write lock
        if let Some(id) = string_map.get(market_id) {
            return Ok(*id);
        }

        let new_id = *next_id;
        string_map.insert(market_id.to_string(), new_id);
        uint_map.insert(new_id, market_id.to_string());
        *next_id = new_id + U256::one();

        tracing::info!(
            market_id = %market_id,
            uint_id = %new_id,
            "Created market ID mapping"
        );

        Ok(new_id)
    }

    /// Get string market ID from uint256
    pub async fn get_string(&self, uint_id: U256) -> Option<String> {
        let map = self.uint_to_string.read().await;
        map.get(&uint_id).cloned()
    }

    /// Get uint256 from string market ID (if exists)
    pub async fn get_uint(&self, market_id: &str) -> Option<U256> {
        let map = self.string_to_uint.read().await;
        map.get(market_id).copied()
    }

    /// Preload existing mappings (e.g., from Redis on startup)
    pub async fn load_mappings(&self, mappings: Vec<(String, U256)>) {
        let mut string_map = self.string_to_uint.write().await;
        let mut uint_map = self.uint_to_string.write().await;

        for (string_id, uint_id) in mappings {
            string_map.insert(string_id.clone(), uint_id);
            uint_map.insert(uint_id, string_id);
        }
    }

    /// Get all mappings (for persistence)
    pub async fn get_all_mappings(&self) -> Vec<(String, U256)> {
        let map = self.string_to_uint.read().await;
        map.iter().map(|(k, v)| (k.clone(), *v)).collect()
    }
}

/// Nonce tracker - prevents replay attacks per EIP-712
pub struct NonceTracker {
    /// User address -> nonce
    nonces: Arc<RwLock<HashMap<Address, u64>>>,
}

impl NonceTracker {
    pub fn new() -> Self {
        Self {
            nonces: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get current nonce for user
    pub async fn get_nonce(&self, user: Address) -> u64 {
        let map = self.nonces.read().await;
        map.get(&user).copied().unwrap_or(0)
    }

    /// Increment and return next nonce for user
    pub async fn increment_nonce(&self, user: Address) -> u64 {
        let mut map = self.nonces.write().await;
        let nonce = map.entry(user).or_insert(0);
        *nonce += 1;
        *nonce
    }

    /// Validate nonce (must be current nonce)
    pub async fn validate_nonce(&self, user: Address, nonce: u64) -> bool {
        let current = self.get_nonce(user).await;
        nonce == current
    }

    /// Set nonce explicitly (for syncing with onchain state)
    pub async fn set_nonce(&self, user: Address, nonce: u64) {
        let mut map = self.nonces.write().await;
        map.insert(user, nonce);
    }

    /// Load nonces from storage
    pub async fn load_nonces(&self, nonces: Vec<(Address, u64)>) {
        let mut map = self.nonces.write().await;
        for (addr, nonce) in nonces {
            map.insert(addr, nonce);
        }
    }
}

/// Type conversion utilities
pub mod conversions {
    use super::*;
    use ethers::utils::keccak256;
    use rust_decimal::Decimal;

    /// Convert Decimal price to basis points (0-10000 = 0-100%)
    pub fn price_to_basis_points(price: Decimal) -> Result<U256> {
        use rust_decimal::prelude::ToPrimitive;
        
        let bps = (price * Decimal::from(10000))
            .to_u64()
            .ok_or_else(|| anyhow::anyhow!("Price out of range"))?;

        if bps > 10000 {
            return Err(anyhow::anyhow!("Price exceeds 100%"));
        }

        Ok(U256::from(bps))
    }

    /// Convert basis points to Decimal price
    pub fn basis_points_to_price(bps: U256) -> Result<Decimal> {
        let bps_u64: u64 = bps
            .try_into()
            .map_err(|_| anyhow::anyhow!("Basis points too large"))?;

        Ok(Decimal::from(bps_u64) / Decimal::from(10000))
    }

    /// Convert Decimal amount to U256 (18 decimals)
    pub fn decimal_to_u256(amount: Decimal) -> Result<U256> {
        let scaled = amount * Decimal::from(10u64.pow(18));
        let scaled_str = scaled.trunc().to_string();

        U256::from_dec_str(&scaled_str)
            .map_err(|e| anyhow::anyhow!("Failed to convert decimal: {}", e))
    }

    /// Convert U256 to Decimal (18 decimals)
    pub fn u256_to_decimal(amount: U256) -> Result<Decimal> {
        let amount_str = amount.to_string();
        let decimal = Decimal::from_str_exact(&amount_str)
            .map_err(|e| anyhow::anyhow!("Failed to parse U256: {}", e))?;

        Ok(decimal / Decimal::from(10u64.pow(18)))
    }

    /// Parse Ethereum address from string
    pub fn parse_address(addr_str: &str) -> Result<Address> {
        addr_str
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid address: {}", e))
    }

    /// Hash market ID to uint256 (alternative to sequential mapping)
    pub fn hash_market_id(market_id: &str) -> U256 {
        let hash = keccak256(market_id.as_bytes());
        U256::from(&hash[..])
    }

    /// Format address to checksummed string
    pub fn format_address(addr: Address) -> String {
        format!("{:?}", addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal_macros::dec;

    #[tokio::test]
    async fn test_market_id_mapper() {
        let mapper = MarketIdMapper::new(1000000);

        let id1 = mapper.get_or_create_uint("ETH-USD-2025").await.unwrap();
        let id2 = mapper.get_or_create_uint("BTC-USD-2025").await.unwrap();
        let id1_again = mapper.get_or_create_uint("ETH-USD-2025").await.unwrap();

        assert_eq!(id1, id1_again);
        assert_ne!(id1, id2);
        assert_eq!(id1, U256::from(1000000));
        assert_eq!(id2, U256::from(1000001));

        let market_str = mapper.get_string(id1).await.unwrap();
        assert_eq!(market_str, "ETH-USD-2025");
    }

    #[tokio::test]
    async fn test_nonce_tracker() {
        let tracker = NonceTracker::new();
        let user: Address = "0x1234567890123456789012345678901234567890"
            .parse()
            .unwrap();

        let nonce1 = tracker.get_nonce(user).await;
        assert_eq!(nonce1, 0);

        let nonce2 = tracker.increment_nonce(user).await;
        assert_eq!(nonce2, 1);

        let nonce3 = tracker.increment_nonce(user).await;
        assert_eq!(nonce3, 2);

        assert!(tracker.validate_nonce(user, 2).await);
        assert!(!tracker.validate_nonce(user, 1).await);
    }

    #[test]
    fn test_price_conversion() {
        use conversions::*;

        // 50% = 5000 basis points
        let price = dec!(0.5);
        let bps = price_to_basis_points(price).unwrap();
        assert_eq!(bps, U256::from(5000));

        let price_back = basis_points_to_price(bps).unwrap();
        assert_eq!(price_back, price);
    }

    #[test]
    fn test_decimal_conversion() {
        use conversions::*;

        let amount = dec!(123.456);
        let u256_val = decimal_to_u256(amount).unwrap();
        let amount_back = u256_to_decimal(u256_val).unwrap();

        // Should be equal within precision
        assert!((amount - amount_back).abs() < dec!(0.000001));
    }
}
