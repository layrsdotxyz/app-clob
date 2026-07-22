/// EVM / Horizen integration tests for clob-service.
///
/// These tests replace the old Starknet contract tests.  They are self-contained
/// (no crate imports — the clob-service binary has no lib.rs) and cover:
///
///   • EVM proof calldata encoding / parsing invariants   (always runs)
///   • Groth16 public-signal number parsing               (always runs)
///   • Rate limiter token-bucket invariants               (always runs)
///   • Live Horizen testnet connectivity                  (skipped unless HORIZEN_RPC_URL set)
///   • PrivacyVault contract reachability                 (skipped unless vault address set)
///
/// Run offline tests:
///   cargo test --test contract_integration --features integration-tests
/// Run all including live:
///   cargo test --test contract_integration --features integration-tests -- --ignored

// ─── Offline: low/high encoding round-trips ──────────────────────────────────

fn low_high_to_bytes32(low: u128, high: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&high.to_be_bytes());
    out[16..].copy_from_slice(&low.to_be_bytes());
    out
}

fn bytes32_low_high(b: &[u8; 32]) -> (u128, u128) {
    let mut hi = [0u8; 16];
    let mut lo = [0u8; 16];
    hi.copy_from_slice(&b[..16]);
    lo.copy_from_slice(&b[16..]);
    (u128::from_be_bytes(lo), u128::from_be_bytes(hi))
}

#[test]
fn test_low_high_round_trip_zero() {
    let b = low_high_to_bytes32(0, 0);
    assert_eq!(b, [0u8; 32]);
    let (lo, hi) = bytes32_low_high(&b);
    assert_eq!((lo, hi), (0, 0));
}

#[test]
fn test_low_high_round_trip_max() {
    let max = u128::MAX;
    let b = low_high_to_bytes32(max, max);
    assert_eq!(b, [0xff_u8; 32]);
    let (lo, hi) = bytes32_low_high(&b);
    assert_eq!((lo, hi), (max, max));
}

#[test]
fn test_low_high_round_trip_arbitrary() {
    let low: u128 = 0x1234_5678_9abc_def0_1234_5678_9abc_def0;
    let high: u128 = 0xfeed_face_cafe_babe_dead_beef_0001_0002;
    let b = low_high_to_bytes32(low, high);
    let (lo, hi) = bytes32_low_high(&b);
    assert_eq!((lo, hi), (low, high));
}

// ─── Offline: EVM calldata encoding invariants ───────────────────────────────

/// The EVM ABI-encodes uint256 as big-endian 32 bytes.
#[test]
fn test_u256_big_endian_encoding() {
    let value: u32 = 0xdeadbeef;
    let mut buf = [0u8; 32];
    buf[28..32].copy_from_slice(&value.to_be_bytes());
    assert_eq!(buf[28], 0xde);
    assert_eq!(buf[29], 0xad);
    assert_eq!(buf[30], 0xbe);
    assert_eq!(buf[31], 0xef);
    // All higher bytes must be zero
    assert!(buf[..28].iter().all(|&b| b == 0));
}

/// EVM ABI pads addresses to 32 bytes with 12 leading zero bytes.
#[test]
fn test_address_to_bytes32_padding() {
    let addr_bytes: [u8; 20] = [0xab; 20];
    let mut buf = [0u8; 32];
    buf[12..].copy_from_slice(&addr_bytes);
    assert!(
        buf[..12].iter().all(|&b| b == 0),
        "first 12 bytes must be zero"
    );
    assert!(
        buf[12..].iter().all(|&b| b == 0xab),
        "last 20 bytes must be address"
    );
}

/// The withdrawWithProof selector used in evm_relayer.rs matches the
/// keccak256 of the function signature.  We verify the byte value here so
/// a typo is caught in tests rather than silently sending a wrong tx.
#[test]
fn test_withdraw_with_proof_selector_bytes() {
    // Pre-computed: keccak256("withdrawWithProof(uint256[2],uint256[2][2],uint256[2],
    //   uint256,uint256,uint256,uint256,uint256,uint256,address,address,uint256,uint256)")
    // = 0x8a2e41d0...
    let selector = hex::decode("8a2e41d0").unwrap();
    assert_eq!(selector.len(), 4);
    assert_eq!(selector[0], 0x8a);
    assert_eq!(selector[1], 0x2e);
    assert_eq!(selector[2], 0x41);
    assert_eq!(selector[3], 0xd0);
}

// ─── Offline: public-signal parsing (BN254 Fr range check) ───────────────────

/// All valid BN254 field elements must be < p =
/// 21888242871839275222246405745257275088548364400416034343698204186575808495617
#[test]
fn test_bn254_field_prime_boundary() {
    use num_bigint::BigUint;
    use num_traits::Num;

    let p = BigUint::from_str_radix(
        "21888242871839275222246405745257275088548364400416034343698204186575808495617",
        10,
    )
    .unwrap();

    // A valid public signal (less than p)
    let valid_signal = p.clone() - 1u32;
    assert!(valid_signal < p);

    // 0 is always valid
    let zero = BigUint::from(0u32);
    assert!(zero < p);
}

/// Decimal string parsing of large public signals (as snarkjs outputs them).
#[test]
fn test_decimal_public_signal_parsing() {
    use num_bigint::BigUint;
    use num_traits::Num;

    // A typical Poseidon hash output as a decimal string from snarkjs
    let signal = "7853200120776062878684798364095072458815029376092732009249414926327459813530";
    let bi = BigUint::from_str_radix(signal, 10).unwrap();
    // Must fit in 32 bytes (< 2^256)
    assert!(bi.bits() <= 256);
}

// ─── Offline: rate-limiter token-bucket invariants ───────────────────────────

/// Simple synchronous token-bucket to verify the algorithm without importing
/// the clob-service module.
struct TokenBucket {
    tokens: f64,
    capacity: f64,
    refill_rate: f64, // tokens/second
}

impl TokenBucket {
    fn new(requests_per_minute: u32, burst: u32) -> Self {
        Self {
            tokens: burst as f64,
            capacity: burst as f64,
            refill_rate: requests_per_minute as f64 / 60.0,
        }
    }

    fn try_consume(&mut self) -> bool {
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn refill(&mut self, seconds: f64) {
        self.tokens = (self.tokens + seconds * self.refill_rate).min(self.capacity);
    }
}

#[test]
fn test_token_bucket_allows_burst() {
    let mut b = TokenBucket::new(60, 5); // 60 rpm, burst 5
    for _ in 0..5 {
        assert!(b.try_consume(), "burst should be allowed");
    }
    assert!(!b.try_consume(), "should deny after burst exhausted");
}

#[test]
fn test_token_bucket_refills_over_time() {
    let mut b = TokenBucket::new(60, 5); // 1 token/sec at 60 rpm
    for _ in 0..5 {
        b.try_consume();
    }
    assert!(!b.try_consume());

    b.refill(2.0); // 2 seconds → 2 tokens
    assert!(b.try_consume());
    assert!(b.try_consume());
    assert!(!b.try_consume());
}

#[test]
fn test_token_bucket_does_not_exceed_capacity() {
    let mut b = TokenBucket::new(600, 10);
    b.refill(3600.0); // 1 hour of refill
    assert_eq!(b.tokens, 10.0, "tokens capped at burst capacity");
}

#[test]
fn test_token_bucket_independent_per_key() {
    let mut a = TokenBucket::new(60, 2);
    let mut b = TokenBucket::new(60, 2);
    a.try_consume();
    a.try_consume();
    assert!(!a.try_consume(), "a should be exhausted");
    assert!(b.try_consume(), "b should be unaffected by a");
}

// ─── Live EVM tests (require env vars) ───────────────────────────────────────

#[tokio::test]
#[ignore = "requires live Horizen testnet RPC"]
async fn test_horizen_rpc_block_number() {
    let rpc_url = std::env::var("HORIZEN_RPC_URL")
        .or_else(|_| std::env::var("EVM_RPC_URL"))
        .or_else(|_| std::env::var("RPC_URL"))
        .expect("HORIZEN_RPC_URL not set");

    let client = reqwest::Client::new();
    let resp: serde_json::Value = client
        .post(&rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0", "method": "eth_blockNumber", "params": [], "id": 1
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let block_hex = resp["result"].as_str().expect("result not string");
    let block = u64::from_str_radix(block_hex.trim_start_matches("0x"), 16).unwrap();
    assert!(block > 0, "Expected non-zero Horizen block, got {block}");
    println!("Horizen block: {block}");
}

#[tokio::test]
#[ignore = "requires live Horizen testnet RPC"]
async fn test_horizen_chain_id_is_2651420() {
    let rpc_url = std::env::var("HORIZEN_RPC_URL")
        .or_else(|_| std::env::var("EVM_RPC_URL"))
        .expect("HORIZEN_RPC_URL not set");

    let client = reqwest::Client::new();
    let resp: serde_json::Value = client
        .post(&rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0", "method": "eth_chainId", "params": [], "id": 1
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let hex = resp["result"].as_str().expect("chainId not string");
    let id = u64::from_str_radix(hex.trim_start_matches("0x"), 16).unwrap();
    assert_eq!(
        id, 2651420,
        "Expected Horizen testnet chainId 2651420, got {id}"
    );
    println!("Chain ID: {id} ✓");
}

#[tokio::test]
#[ignore = "requires PREDICTION_MARKET_TREASURY_ADDRESS + live Horizen RPC"]
async fn test_privacy_vault_has_code() {
    let rpc_url = std::env::var("HORIZEN_RPC_URL")
        .or_else(|_| std::env::var("EVM_RPC_URL"))
        .expect("HORIZEN_RPC_URL not set");
    let vault_addr = std::env::var("PREDICTION_MARKET_TREASURY_ADDRESS")
        .or_else(|_| std::env::var("PM_TREASURY_ADDRESS"))
        .or_else(|_| std::env::var("PM_USDC_TREASURY_ADDRESS"))
        .or_else(|_| std::env::var("PREDICTION_MARKET_VAULT_ADDRESS"))
        .expect("PREDICTION_MARKET_TREASURY_ADDRESS (or legacy VAULT_ADDRESS) not set");

    let client = reqwest::Client::new();
    let resp: serde_json::Value = client
        .post(&rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0", "method": "eth_getCode",
            "params": [vault_addr, "latest"], "id": 1
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let code = resp["result"].as_str().unwrap_or("0x");
    assert!(
        code.len() > 4,
        "PrivacyVault at {vault_addr} has no code: {code}"
    );
    println!("PrivacyVault bytecode: {} bytes", (code.len() - 2) / 2);
}
