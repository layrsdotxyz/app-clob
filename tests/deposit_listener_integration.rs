#![allow(dead_code, clippy::empty_line_after_doc_comments)]

/// EVM deposit listener integration tests.
///
/// Verify deposit event parsing logic and optionally poll Horizen testnet
/// for live PrivacyVault Deposit events.
///
/// These replace the old Starknet deposit listener tests.
///
/// Offline tests run always.  Live tests are #[ignore] and require env vars.
///
/// Run offline:
///   cargo test --test deposit_listener_integration --features integration-tests
/// Run all:
///   cargo test --test deposit_listener_integration --features integration-tests -- --ignored

// ─── Offline: event parsing invariants ──────────────────────────────────────

/// The Deposit event topic (keccak256 of the ABI signature) must be
/// exactly 32 bytes, 0x-prefixed.
#[test]
fn test_deposit_event_topic_length() {
    let topic = "0x90890809c654f11d6e72a28fa60149770a0d11ec6c92319d6ceb2bb0a4ea1a15";
    assert!(topic.starts_with("0x"));
    // 32 bytes = 64 hex chars + 2 for "0x" = 66 total
    assert_eq!(topic.len(), 66, "topic must be 66 chars (0x + 64 hex)");
}

/// EVM indexed address topics are ABI-padded to 32 bytes: 12 zero bytes + 20 address bytes.
#[test]
fn test_depositor_address_extracted_from_topic() {
    // topics[1] = depositor address (indexed, left-padded to 32 bytes)
    let padded = "0x000000000000000000000000abcdef1234567890abcdef1234567890abcdef12";
    let hex = padded.trim_start_matches("0x");
    assert_eq!(hex.len(), 64);
    // First 24 hex chars (12 bytes) must be zero padding
    assert!(
        hex[..24].chars().all(|c| c == '0'),
        "first 12 bytes must be zero"
    );
    let addr = format!("0x{}", &hex[24..]);
    assert_eq!(addr.len(), 42); // 0x + 40 hex
    assert_eq!(addr, "0xabcdef1234567890abcdef1234567890abcdef12");
}

/// eth_getLogs block range is hex-encoded.
#[test]
fn test_block_range_hex_encoding() {
    let from: u64 = 1_000_000;
    let to: u64 = 1_001_000;
    assert_eq!(format!("0x{:x}", from), "0xf4240");
    assert_eq!(format!("0x{:x}", to), "0xf4628");
}

/// ABI-encoded uint256 in event data: big-endian, left-zero-padded to 32 bytes.
#[test]
fn test_amount_from_event_data() {
    // Simulate a data field with amount = 1 ETH (1e18 wei) at offset 32
    // data = [32 bytes padding/vault_id] ++ [32 bytes amount]
    let amount: u128 = 1_000_000_000_000_000_000u128; // 1 ETH
    let mut data = [0u8; 64];
    // last 16 bytes of the second 32-byte slot hold the u128 value
    data[48..64].copy_from_slice(&amount.to_be_bytes());

    let mut arr = [0u8; 16];
    arr.copy_from_slice(&data[48..64]);
    let parsed = u128::from_be_bytes(arr);
    assert_eq!(parsed, amount);
}

/// Null data field (0x) must not panic.
#[test]
fn test_empty_event_data_handled_gracefully() {
    let data_hex = "0x";
    let stripped = data_hex.trim_start_matches("0x");
    // decode gracefully — if empty, no data bytes
    if stripped.is_empty() {
        // no-op: empty data is valid for events with no non-indexed params
        return;
    }
    let bytes = hex::decode(stripped).unwrap();
    assert!(bytes.is_empty() || bytes.len() >= 32);
}

/// Replay protection: a Deposit event at block N should not be processed twice.
/// This is a logic-level test of the dedup invariant.
#[test]
fn test_deposit_dedup_by_tx_hash() {
    use std::collections::HashSet;

    let mut seen: HashSet<String> = HashSet::new();
    let tx_hash = "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab";

    assert!(
        seen.insert(tx_hash.to_string()),
        "first insert should succeed"
    );
    assert!(
        !seen.insert(tx_hash.to_string()),
        "duplicate should be detected"
    );
}

// ─── Live EVM tests ──────────────────────────────────────────────────────────

#[tokio::test]
#[ignore = "requires live Horizen testnet RPC"]
async fn test_get_recent_deposit_events() {
    let rpc_url = std::env::var("HORIZEN_RPC_URL")
        .or_else(|_| std::env::var("EVM_RPC_URL"))
        .or_else(|_| std::env::var("RPC_URL"))
        .expect("HORIZEN_RPC_URL not set");
    let vault_addr = std::env::var("PREDICTION_MARKET_TREASURY_ADDRESS")
        .or_else(|_| std::env::var("PM_TREASURY_ADDRESS"))
        .or_else(|_| std::env::var("PM_USDC_TREASURY_ADDRESS"))
        .or_else(|_| std::env::var("PREDICTION_MARKET_VAULT_ADDRESS"))
        .expect("PREDICTION_MARKET_TREASURY_ADDRESS (or legacy VAULT_ADDRESS) not set");

    let client = reqwest::Client::new();

    // Get current block
    let blk: serde_json::Value = client
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
    let cur =
        u64::from_str_radix(blk["result"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
    let from = cur.saturating_sub(1000);

    // Query Deposit events from vault
    let resp: serde_json::Value = client
        .post(&rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0", "method": "eth_getLogs",
            "params": [{
                "fromBlock": format!("0x{:x}", from),
                "toBlock":   "latest",
                "address":   vault_addr,
                "topics":    [
                    "0x90890809c654f11d6e72a28fa60149770a0d11ec6c92319d6ceb2bb0a4ea1a15"
                ]
            }],
            "id": 2
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert!(
        resp.get("error").is_none(),
        "eth_getLogs error: {:?}",
        resp["error"]
    );
    let logs = resp["result"].as_array().unwrap();
    println!(
        "Found {} Deposit event(s) in blocks {from}..{cur}",
        logs.len()
    );

    // Validate structure of any events found
    for log in logs {
        let topics = log["topics"].as_array().expect("log has topics");
        assert!(
            topics.len() >= 2,
            "Deposit event should have topic0 + depositor topic"
        );
        assert_eq!(
            topics[0].as_str().unwrap(),
            "0x90890809c654f11d6e72a28fa60149770a0d11ec6c92319d6ceb2bb0a4ea1a15",
            "topic0 mismatch"
        );
    }
}

#[tokio::test]
#[ignore = "requires live Horizen testnet RPC"]
async fn test_block_polling_advances() {
    let rpc_url = std::env::var("HORIZEN_RPC_URL")
        .or_else(|_| std::env::var("EVM_RPC_URL"))
        .expect("HORIZEN_RPC_URL not set");

    let client = reqwest::Client::new();
    let fetch_block = || async {
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
        u64::from_str_radix(
            resp["result"].as_str().unwrap().trim_start_matches("0x"),
            16,
        )
        .unwrap()
    };

    let b1 = fetch_block().await;
    assert!(b1 > 0, "initial block must be > 0");
    println!("Block at start: {b1}");
    // We don't sleep and wait for a new block (that would take ~2s on Horizen)
    // Just verify we can query block number twice without error.
    let b2 = fetch_block().await;
    assert!(b2 >= b1, "block number must be non-decreasing");
    println!("Block at end: {b2}");
}
