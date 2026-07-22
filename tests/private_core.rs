use clob_service::private_core::{
    command_request_hash, resolution_signing_payload, signing_payload, AccountBucket, AccountKey,
    BookOrder, BoundaryEvidence, CommandResult, CompleteSetDirection, CoreError, EncryptedJournal,
    ExternalFlowDirection, JournalKey, Ledger, LedgerTransaction, MarketConfig, OrderAction,
    OrderStatus, Outcome, PriceTimeBook, PrivateTradingCore, ReceiptSigner, ResolutionStatement,
    SessionGuard, SessionRequest, SignedResolution, SignedSessionRequest, TimeInForce, Transfer,
    UserCommand, UserCommandAction,
};
use ed25519_dalek::{Signer, SigningKey};

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

#[test]
fn private_core_executes_collateralized_trade_and_profit_fee_resolution() {
    let oracle = SigningKey::from_bytes(&[11u8; 32]);
    let alice = SigningKey::from_bytes(&[12u8; 32]);
    let bob = SigningKey::from_bytes(&[13u8; 32]);
    let journal_key = JournalKey::from_bytes([14u8; 32]);
    let mut core = PrivateTradingCore::new_with_oracle(
        journal_key.clone(),
        ReceiptSigner::generate([15u8; 48]),
        oracle.verifying_key().to_bytes(),
    )
    .unwrap();
    let market_id = "layrs:v1:ZEN:15m:2000";
    core.register_market(
        "sys:market:1".into(),
        MarketConfig {
            market_id: market_id.into(),
            settlement_asset: "ZEN".into(),
            opens_at_millis: 900,
            closes_at_millis: 2_000,
            minimum_quantity_micros: 1,
            maximum_quantity_micros: 10_000_000,
            tick_size_micros: 1_000,
            oracle_feed_id: 245,
        },
        800,
    )
    .unwrap();
    for (index, owner, key) in [(1, "usr_alice", &alice), (2, "usr_bob", &bob)] {
        core.register_session(
            format!("sys:session:{index}"),
            format!("session:{index}"),
            owner.into(),
            key.verifying_key().to_bytes(),
            3_000,
            800,
        )
        .unwrap();
        core.apply_external_flow(
            format!("sys:deposit:{index}"),
            AccountKey::new(owner, AccountBucket::UserAvailable, "ZEN"),
            1_000_000,
            ExternalFlowDirection::Inflow,
            [index as u8; 32],
            850,
        )
        .unwrap();
    }

    execute_signed(
        &mut core,
        &bob,
        "session:2",
        1,
        "cmd:mint",
        UserCommandAction::CompleteSet {
            market_id: market_id.into(),
            quantity_micros: 1_000_000,
            direction: CompleteSetDirection::Mint,
        },
        1_000,
    );
    execute_signed(
        &mut core,
        &bob,
        "session:2",
        2,
        "cmd:sell",
        UserCommandAction::SubmitOrder {
            order: BookOrder::new(
                "usr_bob",
                market_id,
                Outcome::Up,
                OrderAction::Sell,
                400_000,
                1_000_000,
                TimeInForce::Gtc,
                None,
            ),
        },
        1_100,
    );
    let fill = execute_signed(
        &mut core,
        &alice,
        "session:1",
        1,
        "cmd:buy",
        UserCommandAction::SubmitOrder {
            order: BookOrder::new(
                "usr_alice",
                market_id,
                Outcome::Up,
                OrderAction::Buy,
                400_000,
                1_000_000,
                TimeInForce::Fak,
                None,
            ),
        },
        1_200,
    );
    assert!(matches!(fill, CommandResult::Order { .. }));

    let boundary = |end: i64, price: i64, marker: u8| BoundaryEvidence {
        window_start_micros: end * 1_000 - 5_000_000,
        window_end_micros: end * 1_000,
        median_price_e8: price,
        sample_count: 25,
        minimum_publisher_count: 3,
        signed_payload_commitment: [marker; 32],
    };
    let statement = ResolutionStatement {
        market_id: market_id.into(),
        oracle_feed_id: 245,
        opening: boundary(900, 1_000_000_000, 21),
        closing: boundary(2_000, 1_100_000_000, 22),
        issued_at_millis: 2_100,
    };
    let signature = oracle
        .sign(&resolution_signing_payload(&statement).unwrap())
        .to_bytes()
        .to_vec();
    core.resolve_market(
        "sys:resolve:1".into(),
        SignedResolution {
            statement,
            signature,
        },
        2_100,
    )
    .unwrap();

    assert_eq!(
        core.balance(&AccountKey::new(
            "usr_alice",
            AccountBucket::UserAvailable,
            "ZEN"
        )),
        1_569_200
    );
    assert_eq!(
        core.balance(&AccountKey::new("layrs", AccountBucket::FeeRevenue, "ZEN")),
        30_800
    );

    let snapshot = core.export_encrypted_snapshot().unwrap();
    let restored = PrivateTradingCore::restore_encrypted_snapshot(
        journal_key.clone(),
        ReceiptSigner::generate([16u8; 48]),
        &snapshot,
        snapshot.sequence,
    )
    .unwrap();
    assert_eq!(restored.state_root(), core.state_root());
    assert_eq!(
        restored.balance(&AccountKey::new(
            "usr_alice",
            AccountBucket::UserAvailable,
            "ZEN"
        )),
        1_569_200
    );
    assert!(matches!(
        PrivateTradingCore::restore_encrypted_snapshot(
            journal_key,
            ReceiptSigner::generate([17u8; 48]),
            &snapshot,
            snapshot.sequence + 1,
        ),
        Err(CoreError::RollbackDetected)
    ));
}

#[allow(clippy::too_many_arguments)]
fn execute_signed(
    core: &mut PrivateTradingCore,
    key: &SigningKey,
    session_id: &str,
    sequence: u64,
    command_id: &str,
    action: UserCommandAction,
    now_millis: i64,
) -> CommandResult {
    let idempotency_key = format!("idem:{command_id}");
    let request_hash = command_request_hash(command_id, &idempotency_key, &action).unwrap();
    let request = SessionRequest {
        session_id: session_id.into(),
        sequence,
        issued_at_millis: now_millis,
        expires_at_millis: 2_900,
        request_hash,
    };
    let signature = key.sign(&signing_payload(&request)).to_bytes().to_vec();
    core.execute(
        UserCommand {
            command_id: command_id.into(),
            idempotency_key,
            session: SignedSessionRequest { request, signature },
            action,
        },
        now_millis,
    )
    .unwrap()
    .result
}
