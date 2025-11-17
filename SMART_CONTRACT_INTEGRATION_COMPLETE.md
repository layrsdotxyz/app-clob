# CLOB Service - Smart Contract Integration

## Overview
This document explains the smart contract integration added to the Rust CLOB service.

## New Components

### 1. EIP-712 Order Signing (`src/eip712.rs`)
- **Eip712Domain**: Domain separator configuration (chain ID, verifying contract)
- **Eip712Order**: Typed order struct matching smart contract Order type
- **Eip712Signer**: Signs and verifies orders using EIP-712 standard

**Key Features:**
- Full EIP-712 compliance for order signing
- Signature verification with address recovery
- Compatible with smart contract `verifyOrderSignature()` function

### 2. Settlement Client (`src/settlement_client.rs`)
- **OnchainFill**: Converts internal fills to smart contract format
- **SettlementClient**: Web3 client for calling `Settlement.settleTrade()`
- **SettlementManager**: Batch settlement with retry logic

**Key Features:**
- Single trade settlement via `settleTrade()`
- Batch settlement via `settleMultipleTrades()` (gas optimization)
- Automatic retry with exponential backoff
- Transaction receipt tracking

### 3. Type Converters (`src/chain_types.rs`)
- **MarketIdMapper**: String market ID ↔ uint256 mapping
- **NonceTracker**: Per-user nonce tracking for replay protection
- **Conversion utilities**: Rust types → Solidity types

**Type Conversions:**
- `Decimal` → `U256` (basis points for prices, 18 decimals for amounts)
- `String` → `Address` (with validation)
- Market ID hashing for deterministic uint256

### 4. Enhanced Data Models (`src/models.rs`)
Added smart contract fields to existing types:

**Order:**
- `maker_address: Option<Address>` - Ethereum address of maker
- `signature: Option<Signature>` - EIP-712 signature
- `nonce: Option<u64>` - Nonce for replay protection
- `market_id_uint: Option<U256>` - uint256 market ID

**Trade:**
- `maker_address: Option<Address>`
- `taker_address: Option<Address>`
- `market_id_uint: Option<U256>`
- `settlement_tx: Option<H256>` - Settlement transaction hash

## Configuration

Add to `.env`:

```bash
# Smart Contract Settlement (optional)
ENABLE_SETTLEMENT=true
RPC_URL=https://sepolia.base.org
SETTLEMENT_CONTRACT=0xYourContractAddress
SETTLEMENT_PRIVATE_KEY=0xYourPrivateKey
CHAIN_ID=84532

# Settlement Options
SETTLEMENT_BATCH_SIZE=10
SETTLEMENT_RETRY_ATTEMPTS=3
```

## Usage Examples

### 1. Creating Signed Orders

```rust
use crate::eip712::{Eip712Order, Eip712Signer};
use ethers::types::U256;

// Initialize signer
let signer = Eip712Signer::new(
    84532, // Base Sepolia
    settlement_contract_address,
    Some(private_key)
)?;

// Create EIP-712 order
let order = Eip712Order {
    order_id: U256::from(1),
    market_id: U256::from(1000000),
    maker: maker_address,
    side: 0, // BUY
    price: U256::from(5000), // 50% in basis points
    size: U256::from(100),
    nonce: U256::from(1),
    expiry: U256::from(1700000000),
};

// Sign order
let signature = signer.sign_order(&order).await?;

// Verify signature
let is_valid = signer.verify_order(&order, &signature)?;
```

### 2. Settling Trades Onchain

```rust
use crate::settlement_client::{SettlementClient, OnchainFill};

// Initialize settlement client
let client = SettlementClient::new(
    &config.rpc_url.unwrap(),
    config.settlement_contract_address()?,
    &config.settlement_private_key.unwrap(),
    config.chain_id.unwrap()
).await?;

// Create onchain fill
let fill = OnchainFill {
    order_id: order.id_as_u256(),
    market_id: U256::from(1000000),
    maker: maker_address,
    taker: taker_address,
    maker_side: 0, // BUY
    price: U256::from(5000),
    size: U256::from(100),
    timestamp: U256::from(chrono::Utc::now().timestamp()),
};

// Settle single trade
let receipt = client.settle_trade(fill).await?;

// Or batch multiple trades
let receipts = client.settle_batch(fills).await?;
```

### 3. Market ID Mapping

```rust
use crate::chain_types::MarketIdMapper;

let mapper = MarketIdMapper::new(1_000_000); // Start at 1M

// Get or create uint256 ID
let uint_id = mapper.get_or_create_uint("ETH-USD-2025").await?;

// Retrieve string ID
let market_str = mapper.get_string(uint_id).await;
```

### 4. Type Conversions

```rust
use crate::chain_types::conversions;
use rust_decimal_macros::dec;

// Price to basis points (50% = 5000 bps)
let price = dec!(0.5);
let bps = conversions::price_to_basis_points(price)?;
assert_eq!(bps, U256::from(5000));

// Amount to U256 (18 decimals)
let amount = dec!(123.456);
let u256_amount = conversions::decimal_to_u256(amount)?;

// Parse address
let addr = conversions::parse_address("0x1234...5678")?;
```

## Integration Flow

1. **Order Submission** (offchain):
   - User creates order with EIP-712 signature
   - Matching engine validates signature
   - Order enters order book

2. **Order Matching** (offchain):
   - Matching engine finds crossing orders
   - Generates fills with maker/taker addresses
   - Tracks market IDs as uint256

3. **Settlement** (onchain - optional):
   - Settlement manager batches fills
   - Calls `Settlement.settleTrade()` or `settleMultipleTrades()`
   - Records transaction hash in fill records

4. **Nonce Management**:
   - Track nonces per user
   - Increment after successful order
   - Sync with onchain state periodically

## Data Format Alignment

| Rust Type | Solidity Type | Conversion |
|-----------|---------------|------------|
| `Decimal` (price) | `uint256` (0-10000) | `price_to_basis_points()` |
| `Decimal` (amount) | `uint256` (18 decimals) | `decimal_to_u256()` |
| `String` (market ID) | `uint256` | `MarketIdMapper` or `hash_market_id()` |
| `String` (user ID) | `address` | `parse_address()` |
| `OrderSide` | `uint8` | `side.to_u8()` (0=BUY, 1=SELL) |
| `Uuid` | `uint256` | `id_as_u256()` |

## Fee Handling

**Two Fee Models:**

1. **Rust Service** (offchain matching):
   - Maker: 0.10% (10 bps)
   - Taker: 0.20% (20 bps)
   - Calculated during matching

2. **Smart Contract** (onchain settlement):
   - Fee-on-resolve: 2-5% of winnings
   - Collected when market resolves
   - Independent of matching fees

**Recommendation**: Keep both models. Offchain fees for liquidity incentives, onchain fees for protocol sustainability.

## Security Considerations

1. **Signature Verification**: Always verify EIP-712 signatures match maker addresses
2. **Nonce Tracking**: Prevent replay attacks with per-user nonces
3. **Balance Checks**: Verify sufficient balance before settlement (can read from RPC)
4. **Private Key Security**: Store `SETTLEMENT_PRIVATE_KEY` in secrets manager
5. **Rate Limiting**: Limit settlement submission rate to avoid griefing

## Testing

```bash
# Unit tests
cargo test chain_types
cargo test eip712
cargo test settlement_client

# Integration test on OP Sepolia
ENABLE_SETTLEMENT=true \
RPC_URL=https://sepolia.optimism.io \
SETTLEMENT_CONTRACT=0x... \
SETTLEMENT_PRIVATE_KEY=0x... \
CHAIN_ID=11155420 \
cargo test --test integration_settlement

# Integration test on OP Mainnet
ENABLE_SETTLEMENT=true \
RPC_URL=https://mainnet.optimism.io \
SETTLEMENT_CONTRACT=0x... \
SETTLEMENT_PRIVATE_KEY=0x... \
CHAIN_ID=10 \
cargo test --test integration_settlement
```

## Performance Notes

- **Batch Settlement**: Use `settleMultipleTrades()` for >5 fills (30-50% gas savings)
- **Nonce Caching**: Keep nonces in Redis to avoid RPC calls
- **Async Settlement**: Settlement runs in background, doesn't block matching
- **Retry Logic**: Exponential backoff handles network issues gracefully

## Next Steps

1. **Local Testing**: Test with Anvil local node (fork OP Sepolia)
2. **OP Sepolia Deployment**: 
   - Deploy contracts to OP Sepolia
   - Get testnet ETH from faucet
   - Test settlement with testnet transactions
3. **OP Mainnet Deployment**:
   - Deploy contracts to OP Mainnet
   - Update chain ID to 10
   - Update RPC URL to mainnet.optimism.io
4. **Monitoring**: Add metrics for settlement success rate
5. **Balance Sync**: Implement periodic balance verification from RPC
6. **Gas Optimization**: Tune batch size based on OP Mainnet gas prices

## Troubleshooting

**Signature verification fails:**
- Check chain ID matches between signer and contract
- Verify domain separator is correct
- Ensure nonce is current

**Settlement transaction reverts:**
- Check maker/taker have sufficient balances onchain
- Verify market exists and is not resolved
- Check order hasn't expired

**Nonce mismatch:**
- Sync nonces from smart contract: `orderBook.getUserNonce(address)`
- Reset local nonce tracker to match onchain

## References

- Smart Contracts: `/contracts/contracts/clob/`
- EIP-712 Spec: https://eips.ethereum.org/EIPS/eip-712
- Ethers-rs Docs: https://docs.rs/ethers/latest/ethers/
- Contract Integration Guide: `SMART_CONTRACT_INTEGRATION.md`
