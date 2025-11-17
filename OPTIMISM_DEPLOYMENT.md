# Optimism Deployment Guide

## Network Information

### OP Sepolia Testnet
- **Chain ID**: `11155420`
- **RPC URL**: `https://sepolia.optimism.io`
- **Explorer**: https://sepolia-optimism.etherscan.io
- **Faucet**: https://app.optimism.io/faucet (or use Superchain Faucet)
- **Gas Token**: Sepolia ETH

### OP Mainnet
- **Chain ID**: `10`
- **RPC URL**: `https://mainnet.optimism.io`
- **Explorer**: https://optimistic.etherscan.io
- **Gas Token**: ETH

## Configuration

### OP Sepolia (.env for testing)
```bash
ENABLE_SETTLEMENT=true
RPC_URL=https://sepolia.optimism.io
SETTLEMENT_CONTRACT=0xYourSepoliaContractAddress
SETTLEMENT_PRIVATE_KEY=0xYourTestPrivateKey
CHAIN_ID=11155420
SETTLEMENT_BATCH_SIZE=10
SETTLEMENT_RETRY_ATTEMPTS=3
```

### OP Mainnet (.env for production)
```bash
ENABLE_SETTLEMENT=true
RPC_URL=https://mainnet.optimism.io
SETTLEMENT_CONTRACT=0xYourMainnetContractAddress
SETTLEMENT_PRIVATE_KEY=0xYourProductionPrivateKey
CHAIN_ID=10
SETTLEMENT_BATCH_SIZE=20  # Larger batches for mainnet
SETTLEMENT_RETRY_ATTEMPTS=5  # More retries for production
```

## Getting Started

### 1. Get OP Sepolia ETH

**Option A: Official Optimism Faucet**
```bash
# Visit https://app.optimism.io/faucet
# Connect your wallet
# Request testnet ETH
```

**Option B: Superchain Faucet**
```bash
# Visit https://console.optimism.io/faucet
# Requires GitHub account
# Can claim daily
```

**Option C: Bridge from Sepolia ETH**
```bash
# Visit https://app.optimism.io/bridge
# Bridge Sepolia ETH to OP Sepolia
```

### 2. Deploy Contracts to OP Sepolia

```bash
cd /home/zoopx/zoopx/predifi/contracts

# Set environment variables
export RPC_URL=https://sepolia.optimism.io
export PRIVATE_KEY=0xYourPrivateKey
export CHAIN_ID=11155420

# Deploy Settlement contract
forge script script/DeploySettlement.s.sol:DeploySettlement \
  --rpc-url $RPC_URL \
  --private-key $PRIVATE_KEY \
  --broadcast \
  --verify

# Note the deployed contract address
```

### 3. Configure CLOB Service

```bash
cd /home/zoopx/zoopx/predifi/clob-service

# Update .env
cat > .env << EOF
HOST=0.0.0.0
PORT=8080
REDIS_URL=redis://localhost:6379
MAX_ORDERS_PER_USER=100
MAX_ORDER_SIZE=1000000
MIN_ORDER_SIZE=1
MAKER_FEE_BPS=10
TAKER_FEE_BPS=20
RUST_LOG=clob_service=debug,tower_http=debug

# OP Sepolia Settlement
ENABLE_SETTLEMENT=true
RPC_URL=https://sepolia.optimism.io
SETTLEMENT_CONTRACT=0xYourDeployedContractAddress
SETTLEMENT_PRIVATE_KEY=0xYourPrivateKey
CHAIN_ID=11155420
SETTLEMENT_BATCH_SIZE=10
SETTLEMENT_RETRY_ATTEMPTS=3
EOF
```

### 4. Start Redis

```bash
docker run -d -p 6379:6379 redis:7-alpine
```

### 5. Run CLOB Service

```bash
cargo run --release
```

### 6. Test Settlement

```bash
# Submit a test order
curl -X POST http://localhost:8080/v1/orders \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "0xYourAddress",
    "market_id": "ETH-USD-2025",
    "side": "BUY",
    "order_type": "LIMIT",
    "time_in_force": "GTC",
    "price": "0.5",
    "size": "100"
  }'

# Check transaction on OP Sepolia Explorer
# https://sepolia-optimism.etherscan.io/address/0xYourContractAddress
```

## Production Deployment to OP Mainnet

### 1. Deploy Contracts to OP Mainnet

```bash
cd /home/zoopx/zoopx/predifi/contracts

# Set mainnet environment
export RPC_URL=https://mainnet.optimism.io
export PRIVATE_KEY=0xYourProductionPrivateKey
export CHAIN_ID=10

# Deploy Settlement contract
forge script script/DeploySettlement.s.sol:DeploySettlement \
  --rpc-url $RPC_URL \
  --private-key $PRIVATE_KEY \
  --broadcast \
  --verify \
  --etherscan-api-key YOUR_OPTIMISTIC_ETHERSCAN_API_KEY

# Save the deployed contract address
```

### 2. Configure Production Environment

```bash
# Update production .env
ENABLE_SETTLEMENT=true
RPC_URL=https://mainnet.optimism.io
SETTLEMENT_CONTRACT=0xYourMainnetContractAddress
SETTLEMENT_PRIVATE_KEY=0xYourProductionPrivateKey
CHAIN_ID=10
SETTLEMENT_BATCH_SIZE=20
SETTLEMENT_RETRY_ATTEMPTS=5
```

### 3. Deploy to Cloud Run (GCP)

```bash
cd /home/zoopx/zoopx/predifi/clob-service

# Store private key in Secret Manager
gcloud secrets create settlement-private-key \
  --data-file=- <<< "0xYourProductionPrivateKey"

# Update deploy script for OP Mainnet
./deploy-cloudrun.sh us-east1 predifi-clob-mainnet
```

### 4. Monitor Production

```bash
# Check service logs
gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=predifi-clob-mainnet" \
  --limit 100 \
  --format json

# Monitor settlement transactions
# Visit https://optimistic.etherscan.io/address/0xYourContractAddress

# Check Prometheus metrics
curl https://your-service-url.run.app/metrics
```

## Gas Optimization on Optimism

### Batch Size Tuning

Optimism has lower gas costs than Ethereum mainnet. Adjust batch sizes:

**OP Sepolia** (testing):
```bash
SETTLEMENT_BATCH_SIZE=10  # Conservative for testing
```

**OP Mainnet** (production):
```bash
SETTLEMENT_BATCH_SIZE=20  # Larger batches save more gas
```

### Gas Price Monitoring

```rust
// Check current gas price before settlement
let gas_price = client.get_gas_price().await?;
if gas_price > threshold {
    // Wait for lower gas prices
    tokio::time::sleep(Duration::from_secs(60)).await;
}
```

## RPC Providers

### Public RPCs (Free)
- **OP Sepolia**: `https://sepolia.optimism.io`
- **OP Mainnet**: `https://mainnet.optimism.io`

### Private RPCs (Recommended for Production)
- **Alchemy**: `https://opt-mainnet.g.alchemy.com/v2/YOUR_API_KEY`
- **Infura**: `https://optimism-mainnet.infura.io/v3/YOUR_API_KEY`
- **QuickNode**: `https://YOUR_ENDPOINT.optimism.quiknode.pro/`

Example with Alchemy:
```bash
RPC_URL=https://opt-mainnet.g.alchemy.com/v2/YOUR_API_KEY
```

## Troubleshooting

### Issue: "Insufficient funds for gas"
**Solution**: Ensure your settlement private key has enough ETH
```bash
# Check balance
cast balance 0xYourAddress --rpc-url https://sepolia.optimism.io
```

### Issue: "Nonce too low"
**Solution**: Sync nonces from chain
```rust
// Reset nonce tracker
let onchain_nonce = client.get_transaction_count(address).await?;
nonce_tracker.set_nonce(address, onchain_nonce).await;
```

### Issue: "Transaction underpriced"
**Solution**: Increase gas price
```rust
// Set higher gas price
call.gas_price(U256::from(1_500_000_000))  // 1.5 gwei
```

### Issue: "Contract execution reverted"
**Solution**: Check contract state
- Verify market exists
- Check order hasn't expired
- Verify signatures are valid

## Security Best Practices

1. **Private Key Management**
   - Never commit private keys to git
   - Use GCP Secret Manager in production
   - Rotate keys regularly

2. **RPC Endpoint Security**
   - Use authenticated RPC endpoints for production
   - Implement rate limiting
   - Monitor for anomalies

3. **Settlement Monitoring**
   - Set up alerts for failed settlements
   - Monitor gas usage
   - Track settlement latency

4. **Access Control**
   - Limit settlement private key to single address
   - Use separate keys for testnet and mainnet
   - Implement multi-sig for high-value operations

## Useful Links

- **OP Sepolia Faucet**: https://app.optimism.io/faucet
- **OP Sepolia Explorer**: https://sepolia-optimism.etherscan.io
- **OP Mainnet Explorer**: https://optimistic.etherscan.io
- **Optimism Docs**: https://docs.optimism.io
- **Bridge**: https://app.optimism.io/bridge
- **Gas Tracker**: https://optimism.blockscout.com/stats

## Support

For Optimism-specific issues:
- **Discord**: https://discord.optimism.io
- **Forum**: https://gov.optimism.io
- **GitHub**: https://github.com/ethereum-optimism/optimism
