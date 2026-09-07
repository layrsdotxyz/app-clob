use clob_service::private_core::{
    AccountBucket, AccountKey, CoreError, ExternalFlowDirection, ExternalFlowTransaction,
    JournalKey, Ledger, PostingSide, PrivateTradingCore, ReceiptSigner,
};
use sha2::{Digest, Sha256};

fn confirmed_deposit(key: &str, account: AccountKey, amount: u128) -> ExternalFlowTransaction {
    ExternalFlowTransaction {
        idempotency_key: key.into(),
        evidence_hash: [0x42; 32],
        account,
        amount,
        direction: ExternalFlowDirection::Inflow,
    }
}

#[test]
fn finalized_deposit_debits_pool_cash_and_credits_private_user_liability() {
    let mut ledger = Ledger::default();
    let user = AccountKey::new("usr_opaque_7d9", AccountBucket::UserAvailable, "USDC");
    let pool = AccountKey::new("layrs", AccountBucket::PoolCash, "USDC");

    let applied = ledger
        .apply_confirmed_deposit(confirmed_deposit(
            "deposit:transfer-1",
            user.clone(),
            9_000_000,
        ))
        .unwrap();

    assert_eq!(ledger.balance(&pool), 9_000_000);
    assert_eq!(ledger.balance(&user), 9_000_000);
    assert!(applied.transfers.is_empty());
    assert_eq!(applied.postings.len(), 2);
    assert_eq!(applied.postings[0].account, pool);
    assert_eq!(applied.postings[0].side, PostingSide::Debit);
    assert_eq!(applied.postings[0].amount, 9_000_000);
    assert_eq!(applied.postings[1].account, user);
    assert_eq!(applied.postings[1].side, PostingSide::Credit);
    assert_eq!(applied.postings[1].amount, 9_000_000);
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
fn duplicate_receipt_key_cannot_credit_pool_or_user_twice() {
    let mut ledger = Ledger::default();
    let user = AccountKey::new("usr_opaque_a1", AccountBucket::UserAvailable, "ZEN");
    let pool = AccountKey::new("layrs", AccountBucket::PoolCash, "ZEN");
    let flow = confirmed_deposit(
        "deposit:transfer-2",
        user.clone(),
        1_000_000_000_000_000_000,
    );

    ledger.apply_confirmed_deposit(flow.clone()).unwrap();
    assert!(matches!(
        ledger.apply_confirmed_deposit(flow),
        Err(CoreError::DuplicateCommand)
    ));
    assert_eq!(ledger.balance(&pool), 1_000_000_000_000_000_000);
    assert_eq!(ledger.balance(&user), 1_000_000_000_000_000_000);
    assert_eq!(ledger.sequence(), 1);
}

#[test]
fn split_session_transfers_credit_exact_total_and_remain_duplicate_safe() {
    let journal_key = [0x21; 32];
    let commitment = [0x22; 32];
    let owner = derived_private_user(journal_key, commitment);
    let user = AccountKey::new(owner, AccountBucket::UserAvailable, "USDC");
    let pool = AccountKey::new("layrs", AccountBucket::PoolCash, "USDC");
    let mut core = PrivateTradingCore::new(
        JournalKey::from_bytes(journal_key),
        ReceiptSigner::generate([0x23; 48]),
    );

    core.apply_user_external_flow(
        "deposit:split-session-main".into(),
        commitment,
        "USDC".into(),
        AccountBucket::UserAvailable,
        5_100_000,
        ExternalFlowDirection::Inflow,
        [0x24; 32],
        1_800_000_000_000,
    )
    .unwrap();
    core.apply_user_external_flow(
        "deposit:split-session-dust".into(),
        commitment,
        "USDC".into(),
        AccountBucket::UserAvailable,
        10_000,
        ExternalFlowDirection::Inflow,
        [0x25; 32],
        1_800_000_000_001,
    )
    .unwrap();

    assert_eq!(core.balance(&pool), 5_110_000);
    assert_eq!(core.balance(&user), 5_110_000);
    assert_eq!(core.sequence(), 2);
    let root_after_split = core.state_root();
    assert_eq!(
        core.apply_user_external_flow(
            "deposit:split-session-dust".into(),
            commitment,
            "USDC".into(),
            AccountBucket::UserAvailable,
            10_000,
            ExternalFlowDirection::Inflow,
            [0x25; 32],
            1_800_000_000_001,
        )
        .unwrap_err(),
        CoreError::DuplicateCommand
    );
    assert_eq!(core.balance(&pool), 5_110_000);
    assert_eq!(core.balance(&user), 5_110_000);
    assert_eq!(core.sequence(), 2);
    assert_eq!(core.state_root(), root_after_split);
}

#[test]
fn same_finality_evidence_under_a_different_operator_key_cannot_credit_twice() {
    let mut ledger = Ledger::default();
    let user = AccountKey::new("usr_opaque_evidence", AccountBucket::UserAvailable, "USDC");
    let pool = AccountKey::new("layrs", AccountBucket::PoolCash, "USDC");
    let first = confirmed_deposit("deposit:operator-key-a", user.clone(), 6_000_000);
    let second = ExternalFlowTransaction {
        idempotency_key: "deposit:operator-key-b".into(),
        ..first.clone()
    };

    ledger.apply_confirmed_deposit(first).unwrap();
    let root_after_first = ledger.state_root();
    assert_eq!(
        ledger.apply_confirmed_deposit(second).unwrap_err(),
        CoreError::DuplicateCommand
    );
    assert_eq!(ledger.balance(&pool), 6_000_000);
    assert_eq!(ledger.balance(&user), 6_000_000);
    assert_eq!(ledger.sequence(), 1);
    assert_eq!(ledger.state_root(), root_after_first);
}

#[test]
fn non_user_or_non_inflow_commands_fail_before_any_mutation() {
    let cases = [
        ExternalFlowTransaction {
            direction: ExternalFlowDirection::Outflow,
            ..confirmed_deposit(
                "deposit:bad-direction",
                AccountKey::new("usr_opaque_b2", AccountBucket::UserAvailable, "USDC"),
                1,
            )
        },
        confirmed_deposit(
            "deposit:pool-as-user",
            AccountKey::new("layrs", AccountBucket::PoolCash, "USDC"),
            1,
        ),
        ExternalFlowTransaction {
            evidence_hash: [0; 32],
            ..confirmed_deposit(
                "deposit:no-evidence",
                AccountKey::new("usr_opaque_c3", AccountBucket::UserAvailable, "USDC"),
                1,
            )
        },
    ];

    for flow in cases {
        let mut ledger = Ledger::default();
        assert!(ledger.apply_confirmed_deposit(flow).is_err());
        assert_eq!(ledger.sequence(), 0);
        assert_eq!(ledger.total_for_asset("USDC"), 0);
    }
}

#[test]
fn overflow_on_either_leg_leaves_both_balances_and_root_unchanged() {
    let mut ledger = Ledger::default();
    let user = AccountKey::new("usr_opaque_full", AccountBucket::UserAvailable, "USDC");
    let pool = AccountKey::new("layrs", AccountBucket::PoolCash, "USDC");
    ledger.seed_balance(user.clone(), u128::MAX).unwrap();
    ledger.seed_balance(pool.clone(), 7).unwrap();
    let before = ledger.state_root();

    assert_eq!(
        ledger
            .apply_confirmed_deposit(confirmed_deposit("deposit:overflow", user.clone(), 1))
            .unwrap_err(),
        CoreError::UnbalancedTransaction
    );
    assert_eq!(ledger.balance(&pool), 7);
    assert_eq!(ledger.balance(&user), u128::MAX);
    assert_eq!(ledger.sequence(), 0);
    assert_eq!(ledger.state_root(), before);
}

#[test]
fn credit_deposit_command_commits_both_balances_under_one_private_root() {
    let journal_key = [0x31; 32];
    let commitment = [0x32; 32];
    let owner = derived_private_user(journal_key, commitment);
    let user = AccountKey::new(owner, AccountBucket::UserAvailable, "USDC");
    let pool = AccountKey::new("layrs", AccountBucket::PoolCash, "USDC");
    let mut core = PrivateTradingCore::new(
        JournalKey::from_bytes(journal_key),
        ReceiptSigner::generate([0x33; 48]),
    );
    let before = core.state_root();

    let response = core
        .apply_user_external_flow(
            "sys:deposit:pool-receipt-3".into(),
            commitment,
            "USDC".into(),
            AccountBucket::UserAvailable,
            5_000_000,
            ExternalFlowDirection::Inflow,
            [0x34; 32],
            1_800_000_000_000,
        )
        .unwrap();

    assert_eq!(core.balance(&pool), 5_000_000);
    assert_eq!(core.balance(&user), 5_000_000);
    assert_ne!(core.state_root(), before);
    assert_eq!(response.receipt.command_id, "confirmed-deposit");
    assert_eq!(response.receipt.prior_state_root, before);
    assert_eq!(response.receipt.state_root, core.state_root());
}

#[test]
fn enclave_rejects_same_deposit_evidence_with_different_system_keys() {
    let journal_key = [0x41; 32];
    let commitment = [0x42; 32];
    let owner = derived_private_user(journal_key, commitment);
    let user = AccountKey::new(owner, AccountBucket::UserAvailable, "USDC");
    let pool = AccountKey::new("layrs", AccountBucket::PoolCash, "USDC");
    let mut core = PrivateTradingCore::new(
        JournalKey::from_bytes(journal_key),
        ReceiptSigner::generate([0x43; 48]),
    );
    let evidence = [0x44; 32];

    core.apply_user_external_flow(
        "sys:deposit:operator-a".into(),
        commitment,
        "USDC".into(),
        AccountBucket::UserAvailable,
        6_000_000,
        ExternalFlowDirection::Inflow,
        evidence,
        1_800_000_000_000,
    )
    .unwrap();
    let root_after_first = core.state_root();
    let second = core.apply_user_external_flow(
        "sys:deposit:operator-b".into(),
        commitment,
        "USDC".into(),
        AccountBucket::UserAvailable,
        6_000_000,
        ExternalFlowDirection::Inflow,
        evidence,
        1_800_000_000_001,
    );

    assert_eq!(second.unwrap_err(), CoreError::DuplicateCommand);
    assert_eq!(core.balance(&pool), 6_000_000);
    assert_eq!(core.balance(&user), 6_000_000);
    assert_eq!(core.state_root(), root_after_first);
}

#[test]
fn generic_external_flow_cannot_bypass_balanced_user_deposit_command() {
    let mut core = PrivateTradingCore::new(
        JournalKey::from_bytes([0x35; 32]),
        ReceiptSigner::generate([0x36; 48]),
    );
    let before = core.state_root();
    let user = AccountKey::new("usr_opaque_bypass", AccountBucket::UserAvailable, "USDC");

    let result = core.apply_external_flow(
        "sys:unsafe-user-credit".into(),
        user.clone(),
        1_000_000,
        ExternalFlowDirection::Inflow,
        [0x37; 32],
        1_800_000_000_000,
    );

    assert!(matches!(result, Err(CoreError::InvalidOrder(_))));
    assert_eq!(core.balance(&user), 0);
    assert_eq!(core.state_root(), before);
}

fn derived_private_user(journal_key: [u8; 32], commitment: [u8; 32]) -> String {
    let mut key_hash = Sha256::new();
    key_hash.update(b"layrs.enclave-key-derivation.v1\0");
    key_hash.update(journal_key);
    key_hash.update((15u32).to_be_bytes());
    key_hash.update(b"private-user-id");
    let identity_key = key_hash.finalize();
    let mut user_hash = Sha256::new();
    user_hash.update(b"layrs.private-user-id.v1\0");
    user_hash.update(identity_key);
    user_hash.update(commitment);
    format!("usr_{}", hex::encode(user_hash.finalize()))
}
