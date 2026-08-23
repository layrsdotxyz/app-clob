use clob_service::private_core::{
    AccountBucket, AccountKey, CoreError, ExternalFlowDirection, ExternalFlowTransaction, Ledger,
    LedgerTransaction, PostingSide, Transfer,
};

const ASSET: &str = "USDC";

fn accounts() -> (AccountKey, AccountKey, AccountKey) {
    (
        AccountKey::new("usr_opaque_withdrawer", AccountBucket::UserAvailable, ASSET),
        AccountKey::new(
            "usr_opaque_withdrawer",
            AccountBucket::UserWithdrawalHold,
            ASSET,
        ),
        AccountKey::new("layrs", AccountBucket::PoolCash, ASSET),
    )
}

fn funded_ledger(amount: u128) -> Ledger {
    let (available, _, _) = accounts();
    let mut ledger = Ledger::default();
    ledger
        .apply_confirmed_deposit(ExternalFlowTransaction {
            idempotency_key: "deposit:initial".into(),
            evidence_hash: [0x11; 32],
            account: available,
            amount,
            direction: ExternalFlowDirection::Inflow,
        })
        .unwrap();
    ledger
}

fn reserve(ledger: &mut Ledger, amount: u128) {
    let (available, hold, _) = accounts();
    ledger
        .apply(LedgerTransaction {
            idempotency_key: format!("withdrawal-reserve:{amount}"),
            business_reference: "private-withdrawal-reservation".into(),
            transfers: vec![Transfer {
                from: available,
                to: hold,
                amount,
            }],
        })
        .unwrap();
}

fn confirmation(key: &str, evidence: u8, amount: u128) -> ExternalFlowTransaction {
    let (_, hold, _) = accounts();
    ExternalFlowTransaction {
        idempotency_key: key.into(),
        evidence_hash: [evidence; 32],
        account: hold,
        amount,
        direction: ExternalFlowDirection::Outflow,
    }
}

#[test]
fn confirmed_withdrawal_reduces_pool_asset_and_user_hold_with_balanced_postings() {
    let mut ledger = funded_ledger(9_000_000);
    reserve(&mut ledger, 4_000_000);
    let (available, hold, pool) = accounts();

    let applied = ledger
        .apply_confirmed_withdrawal(confirmation("operator:a", 0x22, 4_000_000))
        .unwrap();

    assert_eq!(ledger.balance(&available), 5_000_000);
    assert_eq!(ledger.balance(&hold), 0);
    assert_eq!(ledger.balance(&pool), 5_000_000);
    assert!(applied.transfers.is_empty());
    assert_eq!(applied.postings.len(), 2);
    assert_eq!(applied.postings[0].account, hold);
    assert_eq!(applied.postings[0].side, PostingSide::Debit);
    assert_eq!(applied.postings[0].amount, 4_000_000);
    assert_eq!(applied.postings[1].account, pool);
    assert_eq!(applied.postings[1].side, PostingSide::Credit);
    assert_eq!(applied.postings[1].amount, 4_000_000);
    assert_eq!(
        applied
            .postings
            .iter()
            .filter(|posting| posting.side == PostingSide::Debit)
            .map(|posting| posting.amount)
            .sum::<u128>(),
        applied
            .postings
            .iter()
            .filter(|posting| posting.side == PostingSide::Credit)
            .map(|posting| posting.amount)
            .sum::<u128>()
    );
}

#[test]
fn confirmation_is_replay_safe_across_operator_keys_and_snapshot_restore() {
    let mut ledger = funded_ledger(6_000_000);
    reserve(&mut ledger, 2_000_000);
    ledger
        .apply_confirmed_withdrawal(confirmation("operator:first", 0x23, 2_000_000))
        .unwrap();
    let encoded = serde_json::to_vec(&ledger).unwrap();
    let mut restored: Ledger = serde_json::from_slice(&encoded).unwrap();
    let root = restored.state_root();
    let sequence = restored.sequence();

    assert_eq!(
        restored
            .apply_confirmed_withdrawal(confirmation("operator:retry", 0x23, 2_000_000))
            .unwrap_err(),
        CoreError::DuplicateCommand
    );
    assert_eq!(restored.state_root(), root);
    assert_eq!(restored.sequence(), sequence);
}

#[test]
fn confirmation_failure_is_atomic_for_hold_pool_evidence_and_shape_errors() {
    let cases = [
        confirmation("operator:hold-short", 0x24, 4_000_001),
        ExternalFlowTransaction {
            evidence_hash: [0; 32],
            ..confirmation("operator:no-evidence", 0x24, 1)
        },
        ExternalFlowTransaction {
            direction: ExternalFlowDirection::Inflow,
            ..confirmation("operator:wrong-direction", 0x25, 1)
        },
        ExternalFlowTransaction {
            account: AccountKey::new("layrs", AccountBucket::PoolCash, ASSET),
            ..confirmation("operator:wrong-account", 0x26, 1)
        },
    ];
    for flow in cases {
        let mut ledger = funded_ledger(4_000_000);
        reserve(&mut ledger, 4_000_000);
        let root = ledger.state_root();
        let sequence = ledger.sequence();
        assert!(ledger.apply_confirmed_withdrawal(flow).is_err());
        assert_eq!(ledger.state_root(), root);
        assert_eq!(ledger.sequence(), sequence);
    }

    // An imported inconsistent state with a sufficient user hold but
    // insufficient pool asset must also fail without partially consuming the hold.
    let (_, hold, pool) = accounts();
    let mut ledger = Ledger::default();
    ledger.seed_balance(hold.clone(), 2).unwrap();
    ledger.seed_balance(pool.clone(), 1).unwrap();
    let root = ledger.state_root();
    assert_eq!(
        ledger
            .apply_confirmed_withdrawal(confirmation("operator:pool-short", 0x27, 2))
            .unwrap_err(),
        CoreError::InsufficientBalance
    );
    assert_eq!(ledger.balance(&hold), 2);
    assert_eq!(ledger.balance(&pool), 1);
    assert_eq!(ledger.state_root(), root);
}

#[test]
fn failure_release_is_balanced_dust_safe_and_evidence_replay_safe() {
    let mut ledger = funded_ledger(2);
    reserve(&mut ledger, 1);
    let (available, hold, pool) = accounts();
    let applied = ledger
        .release_withdrawal(
            "release:first".into(),
            [0x31; 32],
            hold.clone(),
            available.clone(),
            1,
        )
        .unwrap();
    assert_eq!(ledger.balance(&available), 2);
    assert_eq!(ledger.balance(&hold), 0);
    assert_eq!(ledger.balance(&pool), 2);
    assert_eq!(applied.postings.len(), 2);

    let encoded = serde_json::to_vec(&ledger).unwrap();
    let mut restored: Ledger = serde_json::from_slice(&encoded).unwrap();
    let root = restored.state_root();
    assert_eq!(
        restored
            .release_withdrawal(
                "release:other-operator-key".into(),
                [0x31; 32],
                hold,
                available,
                1,
            )
            .unwrap_err(),
        CoreError::DuplicateCommand
    );
    assert_eq!(restored.state_root(), root);
}

#[test]
fn confirm_and_release_are_mutually_exclusive_under_any_serialized_race_order() {
    let mut base = funded_ledger(5_000_000);
    reserve(&mut base, 3_000_000);
    let (available, hold, pool) = accounts();

    let mut confirm_wins = base.clone();
    confirm_wins
        .apply_confirmed_withdrawal(confirmation("confirm:wins", 0x41, 3_000_000))
        .unwrap();
    assert_eq!(
        confirm_wins
            .release_withdrawal(
                "release:loses".into(),
                [0x42; 32],
                hold.clone(),
                available.clone(),
                3_000_000,
            )
            .unwrap_err(),
        CoreError::InsufficientBalance
    );
    assert_eq!(confirm_wins.balance(&pool), 2_000_000);
    assert_eq!(confirm_wins.balance(&available), 2_000_000);

    let mut release_wins = base;
    release_wins
        .release_withdrawal(
            "release:wins".into(),
            [0x43; 32],
            hold,
            available.clone(),
            3_000_000,
        )
        .unwrap();
    assert_eq!(
        release_wins
            .apply_confirmed_withdrawal(confirmation("confirm:loses", 0x44, 3_000_000))
            .unwrap_err(),
        CoreError::InsufficientBalance
    );
    assert_eq!(release_wins.balance(&pool), 5_000_000);
    assert_eq!(release_wins.balance(&available), 5_000_000);
}

#[test]
fn varied_partial_withdrawals_conserve_pool_and_liability_per_asset() {
    for amount in [1, 2, 3, 10, 999_999, 1_000_000, 7_777_777, 25_000_000] {
        let total = amount + 17;
        let mut ledger = funded_ledger(total);
        reserve(&mut ledger, amount);
        let (available, hold, pool) = accounts();
        ledger
            .apply_confirmed_withdrawal(confirmation("operator:property", 0x51, amount))
            .unwrap();
        assert_eq!(ledger.balance(&available), 17);
        assert_eq!(ledger.balance(&hold), 0);
        assert_eq!(ledger.balance(&pool), 17);
    }
}
