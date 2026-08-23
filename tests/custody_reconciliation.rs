use clob_service::private_core::{
    AccountBucket, AccountKey, CoreError, ExternalFlowDirection, JournalKey, Ledger,
    PrivateTradingCore, ReceiptSigner,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

fn account(owner: &str, bucket: AccountBucket, asset: &str) -> AccountKey {
    AccountKey::new(owner, bucket, asset)
}

#[test]
fn custody_snapshot_aggregates_only_external_boundary_buckets() {
    let mut ledger = Ledger::default();
    ledger
        .seed_balance(account("pool-a", AccountBucket::PoolCash, "USDC"), 4)
        .unwrap();
    ledger
        .seed_balance(account("pool-b", AccountBucket::PoolCash, "USDC"), 6)
        .unwrap();
    ledger
        .seed_balance(account("vault", AccountBucket::VaultCash, "USDC"), 3)
        .unwrap();
    ledger
        .seed_balance(
            account("strategy-a", AccountBucket::VaultStrategyReceivable, "ZEN"),
            7,
        )
        .unwrap();
    ledger
        .seed_balance(
            account("bridge-a", AccountBucket::BridgeInTransit, "ZEN"),
            2,
        )
        .unwrap();
    ledger
        .seed_balance(
            account("opaque-user", AccountBucket::UserAvailable, "USDC"),
            99,
        )
        .unwrap();
    ledger
        .seed_balance(
            account("opaque-order", AccountBucket::UserOrderHold, "USDC"),
            17,
        )
        .unwrap();

    let totals = ledger.custody_reconciliation_totals().unwrap();
    assert_eq!(totals.len(), 4);
    assert!(totals
        .iter()
        .any(|item| item.bucket == AccountBucket::PoolCash
            && item.asset == "USDC"
            && item.amount == 10));
    assert!(totals
        .iter()
        .any(|item| item.bucket == AccountBucket::VaultCash
            && item.asset == "USDC"
            && item.amount == 3));
    assert!(totals
        .iter()
        .any(|item| item.bucket == AccountBucket::VaultStrategyReceivable
            && item.asset == "ZEN"
            && item.amount == 7));
    assert!(totals
        .iter()
        .any(|item| item.bucket == AccountBucket::BridgeInTransit
            && item.asset == "ZEN"
            && item.amount == 2));

    let encoded = serde_json::to_string(&totals).unwrap();
    for forbidden in [
        "opaque-user",
        "opaque-order",
        "owner",
        "market",
        "outcome",
        "wallet",
    ] {
        assert!(!encoded.contains(forbidden));
    }
}

#[test]
fn custody_aggregation_overflow_fails_closed() {
    let mut ledger = Ledger::default();
    ledger
        .seed_balance(account("pool-a", AccountBucket::PoolCash, "ZEN"), u128::MAX)
        .unwrap();
    ledger
        .seed_balance(account("pool-b", AccountBucket::PoolCash, "ZEN"), 1)
        .unwrap();
    assert_eq!(
        ledger.custody_reconciliation_totals().unwrap_err(),
        CoreError::UnbalancedTransaction
    );
}

#[test]
fn snapshot_is_read_only_and_bound_to_enclave_sequence_and_root() {
    let mut core = PrivateTradingCore::new(
        JournalKey::from_bytes([0x71; 32]),
        ReceiptSigner::generate([0x72; 48]),
    );
    let pool = account("layrs", AccountBucket::PoolCash, "USDC");
    core.apply_external_flow(
        "sys:custody-snapshot-seed".into(),
        pool,
        12,
        ExternalFlowDirection::Inflow,
        [0x73; 32],
        1_800_000_000_000,
    )
    .unwrap();
    let root = core.state_root();

    let first = core
        .custody_reconciliation_snapshot([0x74; 32], vec![[0x75; 32], [0x76; 32]])
        .unwrap();
    let second = core
        .custody_reconciliation_snapshot([0x74; 32], vec![[0x75; 32], [0x76; 32]])
        .unwrap();
    assert_eq!(first, second);
    assert_eq!(first.enclave_sequence, 1);
    assert_eq!(first.state_root, root);
    assert_eq!(core.state_root(), root);
    let mut unsigned = first.clone();
    unsigned.signature.clear();
    let encoded = serde_json::to_vec(&unsigned).unwrap();
    let mut payload = b"layrs.custody-reconciliation-snapshot.v1\0".to_vec();
    payload.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
    payload.extend_from_slice(&encoded);
    VerifyingKey::from_bytes(&first.receipt_public_key)
        .unwrap()
        .verify(&payload, &Signature::from_slice(&first.signature).unwrap())
        .unwrap();
}

#[test]
fn snapshot_rejects_unbound_or_ambiguous_finality() {
    let core = PrivateTradingCore::new(
        JournalKey::from_bytes([0x77; 32]),
        ReceiptSigner::generate([0x78; 48]),
    );
    assert!(core
        .custody_reconciliation_snapshot([0; 32], vec![[1; 32], [2; 32]])
        .is_err());
    assert!(core
        .custody_reconciliation_snapshot([3; 32], vec![[1; 32]])
        .is_err());
    assert!(core
        .custody_reconciliation_snapshot([3; 32], vec![[1; 32], [1; 32]])
        .is_err());
}
