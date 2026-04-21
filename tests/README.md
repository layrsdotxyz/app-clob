# Integration Tests for Layrs Services

Tests that verify the integration between Rust services and smart contracts using Anvil (local Ethereum node).

## Test Suites

### 1. Deposit Flow Integration
- Deploy contracts to Anvil
- Start deposit listener
- Simulate user deposit
- Verify balance credited in mock database
- Check event processing

### 2. Withdrawal Flow Integration
- Deploy contracts to Anvil
- Create withdrawal intent
- Sign with EIP-712
- Submit to withdrawal service
- Verify on-chain withdrawal (privacy-preserving)
- Check off-chain attribution

### 3. Multi-Chain Integration
- Spawn multiple Anvil instances
- Deploy to each chain
- Test cross-chain deposits
- Verify chain-specific balances

## Running Tests

```bash
cd /home/zoopx/zoopx/layrs/clob-service

# Run all integration tests
cargo test --test '*' --features integration-tests

# Run specific test
cargo test --test deposit_integration

# Run with output
cargo test --test deposit_integration -- --nocapture
```

## Prerequisites

- Anvil (from Foundry)
- PostgreSQL (for balance storage)
- Redis (for rate limiting)
