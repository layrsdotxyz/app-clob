use clob_service::private_core::{
    AccountBucket, AccountKey, CoreError, Ledger, LedgerTransaction, Transfer,
};
use proptest::prelude::*;
use serde_json::json;

fn available(owner: &str) -> AccountKey {
    AccountKey::new(owner, AccountBucket::UserAvailable, "USDC")
}

#[test]
fn genesis_rejects_zero_duplicate_and_invalid_accounts() {
    let mut ledger = Ledger::default();
    assert_eq!(
        ledger.seed_balance(available("zero"), 0),
        Err(CoreError::ZeroAmount)
    );
    ledger.seed_balance(available("alice"), 10).unwrap();
    assert_eq!(
        ledger.seed_balance(available("alice"), 10),
        Err(CoreError::DuplicateCommand)
    );
    assert_eq!(
        ledger.seed_balance(available("bad\nowner"), 1),
        Err(CoreError::UnbalancedTransaction)
    );
}

#[test]
fn snapshot_rejects_duplicate_zero_overflow_and_invalid_replay_state() {
    let account = json!({
        "owner": "opaque-user",
        "bucket": "USER_AVAILABLE",
        "asset": "USDC",
        "market_id": null,
        "outcome": null
    });
    let duplicate = json!({
        "balances": [[account.clone(), 1], [account.clone(), 2]],
        "applied_idempotency_keys": [],
        "sequence": 0
    });
    assert!(serde_json::from_value::<Ledger>(duplicate).is_err());

    let zero = json!({
        "balances": [[account.clone(), 0]],
        "applied_idempotency_keys": [],
        "sequence": 0
    });
    assert!(serde_json::from_value::<Ledger>(zero).is_err());

    let invalid_replay = json!({
        "balances": [],
        "applied_idempotency_keys": [""],
        "sequence": 1
    });
    assert!(serde_json::from_value::<Ledger>(invalid_replay).is_err());
}

#[test]
fn aggregate_overflow_is_explicit_and_never_wraps() {
    let mut ledger = Ledger::default();
    ledger.seed_balance(available("alice"), u128::MAX).unwrap();
    ledger.seed_balance(available("bob"), 1).unwrap();
    assert_eq!(ledger.total_for_asset("USDC"), u128::MAX);
    assert_eq!(
        ledger.checked_total_for_asset("USDC"),
        Err(CoreError::UnbalancedTransaction)
    );

    let mut owner_overflow = Ledger::default();
    owner_overflow
        .seed_balance(available("alice"), u128::MAX)
        .unwrap();
    owner_overflow
        .seed_balance(
            AccountKey::new("alice", AccountBucket::UserWithdrawalHold, "USDC"),
            1,
        )
        .unwrap();
    assert_eq!(
        owner_overflow.total_for_owner_asset("alice", "USDC"),
        u128::MAX
    );
    assert_eq!(
        owner_overflow.checked_total_for_owner_asset("alice", "USDC"),
        Err(CoreError::UnbalancedTransaction)
    );
}

#[test]
fn transfer_is_atomic_replay_safe_and_prunes_spent_accounts() {
    let alice = available("alice");
    let bob = available("bob");
    let mut ledger = Ledger::default();
    ledger.seed_balance(alice.clone(), 100).unwrap();
    let root = ledger.state_root();

    assert!(matches!(
        ledger.apply(LedgerTransaction {
            idempotency_key: "self".into(),
            business_reference: "self".into(),
            transfers: vec![Transfer {
                from: alice.clone(),
                to: alice.clone(),
                amount: 1
            }],
        }),
        Err(CoreError::UnbalancedTransaction)
    ));
    assert_eq!(ledger.state_root(), root);

    ledger
        .apply(LedgerTransaction {
            idempotency_key: "move-all".into(),
            business_reference: "move-all".into(),
            transfers: vec![Transfer {
                from: alice.clone(),
                to: bob.clone(),
                amount: 100,
            }],
        })
        .unwrap();
    assert_eq!(ledger.balance(&alice), 0);
    assert_eq!(ledger.balance(&bob), 100);
    let encoded = serde_json::to_string(&ledger).unwrap();
    assert!(
        !encoded.contains("alice"),
        "spent zero-balance account leaked into snapshot"
    );

    let root = ledger.state_root();
    assert!(matches!(
        ledger.apply(LedgerTransaction {
            idempotency_key: "move-all".into(),
            business_reference: "retry".into(),
            transfers: vec![Transfer {
                from: bob,
                to: alice,
                amount: 1
            }],
        }),
        Err(CoreError::DuplicateCommand)
    ));
    assert_eq!(ledger.state_root(), root);
}

#[test]
fn rounding_reserve_accepts_bounded_dust_and_rejects_material_imbalance() {
    let source = AccountKey::new("layrs", AccountBucket::MarketCollateral, "USDC");
    let reserve = AccountKey::new("layrs", AccountBucket::RoundingReserve, "USDC");
    let mut ledger = Ledger::default();
    ledger.seed_balance(source.clone(), 2_000).unwrap();
    ledger
        .apply(LedgerTransaction {
            idempotency_key: "bounded-dust".into(),
            business_reference: "bounded-dust".into(),
            transfers: vec![Transfer {
                from: source.clone(),
                to: reserve.clone(),
                amount: 1_000,
            }],
        })
        .unwrap();
    let root = ledger.state_root();
    assert!(matches!(
        ledger.apply(LedgerTransaction {
            idempotency_key: "material-residual".into(),
            business_reference: "material-residual".into(),
            transfers: vec![Transfer {
                from: source,
                to: reserve,
                amount: 1_001
            }],
        }),
        Err(CoreError::UnbalancedTransaction)
    ));
    assert_eq!(ledger.state_root(), root);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(5_000))]

    #[test]
    fn arbitrary_valid_transfers_never_create_value_or_persist_zero_dust(
        initial in 1u128..1_000_000_000_000u128,
        moves in prop::collection::vec((0usize..8, 0usize..8, 0u64..1_000_000u64), 1..128),
    ) {
        let accounts: Vec<_> = (0..8).map(|index| available(&format!("opaque-{index}"))).collect();
        let mut ledger = Ledger::default();
        ledger.seed_balance(accounts[0].clone(), initial).unwrap();
        let mut model = vec![0u128; accounts.len()];
        model[0] = initial;

        for (sequence, (from, to, requested)) in moves.into_iter().enumerate() {
            if from == to || model[from] == 0 { continue; }
            let amount = u128::from(requested).min(model[from]).max(1);
            let result = ledger.apply(LedgerTransaction {
                idempotency_key: format!("property-{sequence}"),
                business_reference: "property".into(),
                transfers: vec![Transfer {
                    from: accounts[from].clone(),
                    to: accounts[to].clone(),
                    amount,
                }],
            });
            prop_assert!(result.is_ok());
            model[from] -= amount;
            model[to] += amount;
            prop_assert_eq!(ledger.total_for_asset("USDC"), initial);
            for (index, account) in accounts.iter().enumerate() {
                prop_assert_eq!(ledger.balance(account), model[index]);
            }
            let snapshot = serde_json::to_value(&ledger).unwrap();
            let balances = snapshot["balances"].as_array().unwrap();
            prop_assert!(balances.iter().all(|row| row[1].as_u64().is_some_and(|value| value > 0)));
        }
    }
}
