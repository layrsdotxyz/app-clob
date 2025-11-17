# Smart Contract Integration Guide

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         OFFCHAIN                                │
├─────────────────────────────────────────────────────────────────┤
│  Rust CLOB Service                                              │
│  - Order Book (Redis)                                           │
│  - Matching Engine                                              │
│  - REST API + WebSocket                                         │
│                                                                 │
│  Produces: Matched Fills                                        │
└─────────────────────┬───────────────────────────────────────────┘
                      │ Fill[] (with EIP-712 signatures)
                      ↓
┌─────────────────────────────────────────────────────────────────┐
│                         ONCHAIN                                 │
├─────────────────────────────────────────────────────────────────┤
│  Smart Contracts (Solidity)                                     │
│  - Settlement.sol: settleTrade(Fill)                            │
│  - YesNoToken.sol: Mint/burn position tokens                   │
│  - FeeCollector.sol: Collect fees on claim                     │
│  - MarketFactory.sol: Market lifecycle                          │
└─────────────────────────────────────────────────────────────────┘
```

## Current Compatibility

### ✅ Already Compatible

| Feature | Smart Contract | Rust Service | Status |
|---------|---------------|--------------|--------|
| Offchain matching | ✅ Design assumption | ✅ Implemented | **Compatible** |
| Price in basis points | ✅ 0-10000 (0-100%) | ✅ Decimal | **Compatible** |
| Order sides (BUY/SELL) | ✅ YES/NO tokens | ✅ Buy/Sell | **Compatible** |
| Fee structure | ✅ 2-5% on claim | ✅ 0.1-0.2% maker/taker | **Configurable** |
| Market ID | ✅ uint256 | ✅ String | **Needs mapping** |

### ⚠️ Needs Integration

| Feature | Smart Contract | Rust Service | Required Change |
|---------|---------------|--------------|-----------------|
| Order signatures | ✅ EIP-712 | ❌ Not implemented | **Add EIP-712** |
| Fill structure | ✅ Defined | ❌ Different format | **Align structs** |
| Market ID format | ✅ uint256 | ❌ String | **Add mapping** |
| Nonce tracking | ✅ Per-user nonce | ❌ Not implemented | **Add nonce** |
| Settlement calls | ✅ settleTrade() | ❌ Not implemented | **Add web3 client** |

## Required Changes to Rust Service

### 1. Add EIP-712 Order Signing

**Smart Contract Expectation** (`CLOBTypes.sol:Order`):
```solidity
struct Order {
    uint256 orderId;
    uint256 marketId;
    address maker;
    Side side;
    uint256 price;      // Basis points (0-10000)
    uint256 size;
    uint256 filled;
    uint256 nonce;
    uint256 expiry;
    bytes signature;    // EIP-712 signature
}
```

**Required in Rust** (`src/models.rs`):
```rust
use ethers::{
    types::{Address, U256, Signature},
    utils::keccak256,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Order {
    pub id: Uuid,                    // Maps to orderId
    pub user_id: String,             // Maps to maker (Ethereum address)
    pub market_id: String,           // Maps to marketId (needs uint256 conversion)
    pub side: OrderSide,             // Maps to Side enum
    pub price: Decimal,              // Maps to price in basis points
    pub size: Decimal,
    pub filled: Decimal,
    pub nonce: u64,                  // NEW: Per-user nonce
    pub expiry: u64,                 // NEW: Unix timestamp
    pub signature: Option<Vec<u8>>,  // NEW: EIP-712 signature
    // ... existing fields
}

// EIP-712 domain separator
pub fn get_domain_separator(chain_id: u64, verifying_contract: Address) -> [u8; 32] {
    let domain_type_hash = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    // ... implementation
}

// Order type hash for EIP-712
pub fn get_order_type_hash() -> [u8; 32] {
    keccak256(
        "Order(uint256 orderId,uint256 marketId,address maker,uint8 side,uint256 price,uint256 size,uint256 nonce,uint256 expiry)"
    )
}
```

**Add to `Cargo.toml`**:
```toml
ethers = { version = "2.0", features = ["rustls", "ws"] }
```

### 2. Align Fill Structure

**Smart Contract** (`CLOBTypes.sol:Fill`):
```solidity
struct Fill {
    uint256 orderId;
    uint256 marketId;
    address maker;
    address taker;
    Side makerSide;
    uint256 price;      // Basis points
    uint256 size;
    uint256 timestamp;
}
```

**Rust Service** (`src/models.rs`):
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnchainFill {
    pub order_id: U256,        // Changed from Uuid
    pub market_id: U256,       // Changed from String
    pub maker: Address,        // Changed from String
    pub taker: Address,        // Changed from String
    pub maker_side: u8,        // 0 = BUY, 1 = SELL
    pub price: U256,           // Basis points (e.g., 5000 = 50%)
    pub size: U256,            // Token amount
    pub timestamp: U256,       // Unix timestamp
}

impl From<Fill> for OnchainFill {
    fn from(fill: Fill) -> Self {
        Self {
            order_id: U256::from(fill.order_id.as_u128()), // Convert Uuid
            market_id: market_id_to_uint256(&fill.market_id),
            maker: fill.maker_user_id.parse().unwrap(),
            taker: fill.taker_user_id.parse().unwrap(),
            maker_side: match fill.maker_side {
                OrderSide::Buy => 0,
                OrderSide::Sell => 1,
            },
            price: decimal_to_basis_points(fill.price),
            size: decimal_to_uint256(fill.size),
            timestamp: U256::from(fill.timestamp.timestamp() as u64),
        }
    }
}
```

### 3. Add Settlement Client

**New file**: `src/settlement_client.rs`
```rust
use ethers::{
    prelude::*,
    providers::{Provider, Http},
};
use std::sync::Arc;

abigen!(
    SettlementContract,
    r#"[
        function settleTrade(tuple(uint256,uint256,address,address,uint8,uint256,uint256,uint256)) external
        function settleMultipleTrades(tuple(uint256,uint256,address,address,uint8,uint256,uint256,uint256)[]) external
    ]"#
);

pub struct SettlementClient {
    contract: SettlementContract<SignerMiddleware<Provider<Http>, LocalWallet>>,
}

impl SettlementClient {
    pub fn new(rpc_url: &str, contract_address: Address, private_key: &str) -> Result<Self> {
        let provider = Provider::<Http>::try_from(rpc_url)?;
        let wallet: LocalWallet = private_key.parse()?;
        let client = SignerMiddleware::new(provider, wallet);
        
        let contract = SettlementContract::new(contract_address, Arc::new(client));
        
        Ok(Self { contract })
    }
    
    pub async fn settle_trade(&self, fill: OnchainFill) -> Result<TransactionReceipt> {
        let tx = self.contract.settle_trade(fill).send().await?;
        let receipt = tx.await?.unwrap();
        Ok(receipt)
    }
    
    pub async fn settle_batch(&self, fills: Vec<OnchainFill>) -> Result<TransactionReceipt> {
        let tx = self.contract.settle_multiple_trades(fills).send().await?;
        let receipt = tx.await?.unwrap();
        Ok(receipt)
    }
}
```

### 4. Update Matching Engine

**Modify** `src/matching.rs`:
```rust
impl MatchingEngine {
    pub async fn submit_order(&self, mut order: Order) -> ClobResult<MatchResult> {
        // ... existing matching logic
        
        // After matching, submit fills to settlement contract
        if !match_result.fills.is_empty() {
            self.submit_to_settlement(&match_result.fills).await?;
        }
        
        Ok(match_result)
    }
    
    async fn submit_to_settlement(&self, fills: &[Fill]) -> ClobResult<()> {
        // Convert to onchain format
        let onchain_fills: Vec<OnchainFill> = fills
            .iter()
            .map(|f| OnchainFill::from(f.clone()))
            .collect();
        
        // Submit to settlement contract
        match self.settlement_client.settle_batch(onchain_fills).await {
            Ok(receipt) => {
                tracing::info!(
                    tx_hash = ?receipt.transaction_hash,
                    fills = fills.len(),
                    "Fills submitted to settlement contract"
                );
                Ok(())
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to submit fills");
                Err(ClobError::Internal(format!("Settlement failed: {}", e)))
            }
        }
    }
}
```

### 5. Add Configuration

**Update** `src/config.rs`:
```rust
pub struct Config {
    // ... existing fields
    
    // Settlement contract
    pub settlement_contract_address: String,
    pub settlement_rpc_url: String,
    pub settlement_private_key: String,
    pub chain_id: u64,
    
    // Market ID mapping (string -> uint256)
    pub market_id_offset: u64,  // e.g., 1000000 to avoid collisions
}
```

**Update** `.env.example`:
```bash
# Settlement contract
SETTLEMENT_CONTRACT_ADDRESS=0x...
SETTLEMENT_RPC_URL=https://base-sepolia.g.alchemy.com/v2/YOUR_KEY
SETTLEMENT_PRIVATE_KEY=0x...
CHAIN_ID=84532
MARKET_ID_OFFSET=1000000
```

### 6. Market ID Mapping

**Add helper functions** (`src/utils/market_id.rs`):
```rust
use ethers::types::U256;

// Convert string market ID to uint256 for smart contracts
pub fn market_id_to_uint256(market_id: &str, offset: u64) -> U256 {
    // Option 1: Hash the string
    let hash = keccak256(market_id.as_bytes());
    U256::from(&hash[..8])
    
    // Option 2: Use sequential IDs
    // Store in Redis: market_id_str -> uint256
    // This ensures consistency between offchain and onchain
}

// Convert price from Decimal to basis points (0-10000)
pub fn decimal_to_basis_points(price: Decimal) -> U256 {
    let bps = (price * Decimal::from(10000)).to_u64().unwrap_or(0);
    U256::from(bps)
}

// Convert Decimal to U256 wei (18 decimals)
pub fn decimal_to_uint256(amount: Decimal) -> U256 {
    let wei = (amount * Decimal::from(10u64.pow(18))).to_string();
    U256::from_dec_str(&wei).unwrap_or(U256::zero())
}
```

## Integration Workflow

### Order Flow (Offchain → Onchain)

1. **User submits signed order** (EIP-712)
   ```
   User → POST /v1/orders (with signature)
   ```

2. **Rust service validates signature**
   ```rust
   verify_eip712_signature(&order) → valid/invalid
   ```

3. **Rust matching engine matches orders**
   ```
   Orderbook → Matching Engine → Fills
   ```

4. **Rust service submits fills to settlement contract**
   ```rust
   settlement_client.settle_batch(fills) → Transaction
   ```

5. **Smart contract mints/burns tokens**
   ```solidity
   Settlement.settleTrade() → YesNoToken.mint/burn()
   ```

6. **Rust service broadcasts WebSocket updates**
   ```
   WebSocket → Clients (trade executed)
   ```

## Fee Discrepancy Resolution

Your smart contracts use **fee-on-resolve** (2-5% when claiming winnings).
Your Rust service uses **maker/taker fees** (0.1-0.2% per trade).

**Options**:
1. **Keep both** - Offchain fees for liquidity, onchain fees for protocol
2. **Disable offchain fees** - Set `MAKER_FEE_BPS=0 TAKER_FEE_BPS=0`
3. **Unified fee model** - Modify smart contracts to charge per-trade fees

## Next Steps (Priority Order)

1. ✅ **Add `ethers-rs` dependency**
2. ✅ **Implement EIP-712 signing and verification**
3. ✅ **Add market ID mapping (Redis store)**
4. ✅ **Create settlement client**
5. ✅ **Update matching engine to submit fills**
6. ✅ **Add nonce tracking per user**
7. ✅ **Test with Base Sepolia testnet**
8. ⚠️ **Deploy settlement contract**
9. ⚠️ **Fund relayer wallet**
10. ⚠️ **Production deployment**

## Testing Checklist

- [ ] EIP-712 signatures validate correctly
- [ ] Market IDs map consistently (offchain ↔ onchain)
- [ ] Fills settle onchain after matching
- [ ] YesNoToken balances update correctly
- [ ] Fees collected properly
- [ ] WebSocket broadcasts include tx hashes
- [ ] Settlement failures handled gracefully
- [ ] Nonce prevents replay attacks

## Estimated Development Time

- EIP-712 integration: **2-3 days**
- Settlement client: **1-2 days**
- Market ID mapping: **1 day**
- Testing: **2-3 days**
- **Total: 1-1.5 weeks**

---

**TLDR**: Your Rust CLOB service is **architecturally compatible** but needs **EIP-712 signatures, settlement client, and data format alignment** to integrate with your smart contracts. This is standard for offchain/onchain hybrid systems.
