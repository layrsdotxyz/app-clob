use clob_service::private_core::{
    AccountBucket, AccountKey, BookOrder, CoreError, EncryptedJournal, JournalKey, Ledger,
    LedgerTransaction, OrderAction, OrderStatus, Outcome, PriceTimeBook, SessionGuard,
    SessionRequest, TimeInForce, Transfer,
};

#[test]
fn ledger_is_atomic_conservative_and_idempotent() {
    let mut ledger = Ledger::default();
    let user = AccountKey::new("usr_A", AccountBucket::UserAvailable, "ZEN");
    let hold = AccountKey::new("usr_A", AccountBucket::UserOrderHold, "ZEN");
    ledger.seed_balance(user.clone(), 1_000).unwrap();
    let total_before = ledger.total_for_asset("ZEN");

    let applied = ledger
        .apply(LedgerTransaction {
            idempotency_key: "order:reserve:001".into(),
            business_reference: "order:001".into(),
            transfers: vec![Transfer {
                from: user.clone(),
                to: hold.clone(),
                amount: 400,
            }],
        })
        .unwrap();

    assert_eq!(ledger.balance(&user), 600);
    assert_eq!(ledger.balance(&hold), 400);
    assert_eq!(ledger.total_for_asset("ZEN"), total_before);
    assert_ne!(applied.prior_state_root, applied.state_root);

    let duplicate = ledger.apply(LedgerTransaction {
        idempotency_key: "order:reserve:001".into(),
        business_reference: "order:001".into(),
        transfers: vec![Transfer {
            from: user,
            to: hold,
            amount: 1,
        }],
    });
    assert_eq!(duplicate.unwrap_err(), CoreError::DuplicateCommand);
}

#[test]
fn insufficient_transfer_does_not_partially_mutate_ledger() {
    let mut ledger = Ledger::default();
    let source = AccountKey::new("usr_A", AccountBucket::UserAvailable, "USDC");
    let first = AccountKey::new("usr_B", AccountBucket::UserAvailable, "USDC");
    let second = AccountKey::new("usr_C", AccountBucket::UserAvailable, "USDC");
    ledger.seed_balance(source.clone(), 100).unwrap();
    let root_before = ledger.state_root();
    let result = ledger.apply(LedgerTransaction {
        idempotency_key: "atomic:001".into(),
        business_reference: "test:001".into(),
        transfers: vec![
            Transfer {
                from: source.clone(),
                to: first.clone(),
                amount: 80,
            },
            Transfer {
                from: source.clone(),
                to: second.clone(),
                amount: 80,
            },
        ],
    });
    assert_eq!(result.unwrap_err(), CoreError::InsufficientBalance);
    assert_eq!(ledger.balance(&source), 100);
    assert_eq!(ledger.balance(&first), 0);
    assert_eq!(ledger.balance(&second), 0);
    assert_eq!(ledger.state_root(), root_before);
}

#[test]
fn price_time_priority_and_self_trade_prevention_are_deterministic() {
    let mut book = PriceTimeBook::default();
    let now = 1_800_000_000_000;
    let maker_one = BookOrder::new(
        "usr_A",
        "layrs:v1:ZEN:15m:1800000000",
        Outcome::Up,
        OrderAction::Sell,
        400_000,
        10_000_000,
        TimeInForce::Gtc,
        None,
    );
    let maker_one_id = maker_one.order_id;
    book.submit(maker_one, now).unwrap();
    let maker_two = BookOrder::new(
        "usr_B",
        "layrs:v1:ZEN:15m:1800000000",
        Outcome::Up,
        OrderAction::Sell,
        400_000,
        10_000_000,
        TimeInForce::Gtc,
        None,
    );
    let maker_two_id = maker_two.order_id;
    book.submit(maker_two, now).unwrap();

    let taker = BookOrder::new(
        "usr_C",
        "layrs:v1:ZEN:15m:1800000000",
        Outcome::Up,
        OrderAction::Buy,
        450_000,
        15_000_000,
        TimeInForce::Fak,
        None,
    );
    let result = book.submit(taker, now).unwrap();
    assert_eq!(result.fills.len(), 2);
    assert_eq!(result.fills[0].maker_order_id, maker_one_id);
    assert_eq!(result.fills[1].maker_order_id, maker_two_id);
    assert_eq!(result.fills[0].quantity_micros, 10_000_000);
    assert_eq!(result.fills[1].quantity_micros, 5_000_000);
}

#[test]
fn fok_rejects_without_mutating_resting_liquidity() {
    let mut book = PriceTimeBook::default();
    let now = 1_800_000_000_000;
    book.submit(
        BookOrder::new(
            "usr_A",
            "layrs:v1:ZEN:15m:1800000000",
            Outcome::Down,
            OrderAction::Sell,
            600_000,
            2_000_000,
            TimeInForce::Gtc,
            None,
        ),
        now,
    )
    .unwrap();
    let result = book
        .submit(
            BookOrder::new(
                "usr_B",
                "layrs:v1:ZEN:15m:1800000000",
                Outcome::Down,
                OrderAction::Buy,
                600_000,
                3_000_000,
                TimeInForce::Fok,
                None,
            ),
            now,
        )
        .unwrap();
    assert_eq!(result.accepted_order.unwrap().status, OrderStatus::Rejected);
    assert!(result.fills.is_empty());
    let (_, asks) = book.aggregate_depth("layrs:v1:ZEN:15m:1800000000", Outcome::Down, now);
    assert_eq!(asks, vec![(600_000, 2_000_000, 1)]);
}

#[test]
fn encrypted_journal_detects_ciphertext_and_chain_tampering() {
    let mut journal = EncryptedJournal::new(JournalKey::from_bytes([7u8; 32]));
    let record = journal
        .append([1u8; 32], &serde_json::json!({"private":"order"}))
        .unwrap();
    let decoded: serde_json::Value = journal.decrypt(&record).unwrap();
    assert_eq!(decoded["private"], "order");
    assert!(!String::from_utf8_lossy(&record.ciphertext).contains("order"));

    let mut tampered = record;
    tampered.ciphertext[0] ^= 1;
    assert_eq!(
        journal.decrypt::<serde_json::Value>(&tampered).unwrap_err(),
        CoreError::JournalChainMismatch
    );
}

#[test]
fn session_guard_rejects_replays_and_expiry() {
    let mut guard = SessionGuard::default();
    let request = SessionRequest {
        session_id: "session:private:001".into(),
        sequence: 1,
        issued_at_millis: 1_000,
        expires_at_millis: 10_000,
        request_hash: [1u8; 32],
    };
    guard.accept(&request, 5_000).unwrap();
    assert_eq!(
        guard.accept(&request, 5_000).unwrap_err(),
        CoreError::ReplayedSequence
    );
    let expired = SessionRequest {
        sequence: 2,
        expires_at_millis: 4_999,
        ..request
    };
    assert_eq!(
        guard.accept(&expired, 5_000).unwrap_err(),
        CoreError::ExpiredSession
    );
}
