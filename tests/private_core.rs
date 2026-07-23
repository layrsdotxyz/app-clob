use clob_service::private_core::{
    command_request_hash, polymarket_resolution_signing_payload, resolution_signing_payload,
    signing_payload, AccountBucket, AccountKey, BookOrder, BoundaryEvidence, CommandResult,
    CompleteSetDirection, CoreError, EncryptedJournal, ExternalFlowDirection, JournalKey, Ledger,
    LedgerTransaction, MarketConfig, MarketExecution, OrderAction, OrderStatus, Outcome,
    PolymarketResolutionStatement, PriceTimeBook, PrivateTradingCore, ReceiptSigner,
    ResolutionOutcome, ResolutionStatement, SessionGuard, SessionRequest,
    SignedPolymarketResolution, SignedResolution, SignedSessionRequest, TimeInForce, Transfer,
    UserCommand, UserCommandAction,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

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
            settlement_decimals: 18,
            public_settlement_chain: "horizen".into(),
            opens_at_millis: 900,
            closes_at_millis: 2_000,
            minimum_quantity_micros: 1,
            maximum_quantity_micros: 10_000_000,
            minimum_order_notional_micros: 1,
            maximum_order_notional_micros: 10_000_000,
            maximum_user_position_micros: 10_000_000,
            maximum_pending_bootstrap_notional_micros: 100_000_000,
            tick_size_micros: 1_000,
            oracle_feed_id: 245,
            execution: clob_service::private_core::MarketExecution::NativeClob,
        },
        800,
    )
    .unwrap();
    let alice_owner = derived_private_user([14u8; 32], [1u8; 32]);
    for (index, key) in [(1, &alice), (2, &bob)] {
        let commitment = [index as u8; 32];
        core.register_session(
            format!("sys:session:{index}"),
            format!("session:{index}"),
            commitment,
            key.verifying_key().to_bytes(),
            3_000,
            800,
        )
        .unwrap();
        core.apply_user_external_flow(
            format!("sys:deposit:{index}"),
            commitment,
            "ZEN".into(),
            AccountBucket::UserAvailable,
            1_000_000_000_000_000_000,
            ExternalFlowDirection::Inflow,
            [index as u8; 32],
            850,
        )
        .unwrap();
    }

    core.set_trading_freeze("sys:freeze:1".into(), true, [91u8; 32], 900)
        .unwrap();
    assert!(core.trading_frozen());
    let frozen_action = UserCommandAction::CompleteSet {
        market_id: market_id.into(),
        quantity_micros: 1_000_000,
        direction: CompleteSetDirection::Mint,
    };
    assert_eq!(
        execute_signed_result(
            &mut core,
            &bob,
            "session:2",
            1,
            "cmd:frozen-mint",
            frozen_action,
            950,
        )
        .unwrap_err(),
        CoreError::TradingFrozen
    );
    core.set_trading_freeze("sys:unfreeze:1".into(), false, [92u8; 32], 975)
        .unwrap();
    assert!(!core.trading_frozen());

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
    let fill_response = execute_signed_response(
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
    assert!(matches!(fill_response.result, CommandResult::Order { .. }));
    assert_eq!(fill_response.audit_fills.len(), 1);
    let audit = &fill_response.audit_fills[0];
    assert_eq!(audit.statement.chain, "horizen");
    assert_eq!(audit.statement.market_id, market_id);
    assert_eq!(audit.statement.price_micros, 400_000);
    assert_eq!(audit.statement.quantity_atomic, "1000000");
    assert_ne!(
        audit.statement.buyer_one_time_pseudonym,
        audit.statement.seller_one_time_pseudonym
    );
    assert_eq!(audit.receipt_id, fill_response.receipt.receipt_id);
    let mut unsigned = audit.clone();
    let signature = std::mem::take(&mut unsigned.signature);
    let encoded = serde_json::to_vec(&unsigned).unwrap();
    let mut payload = b"layrs.audit-fill-artifact.v1\0".to_vec();
    payload.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
    payload.extend_from_slice(&encoded);
    VerifyingKey::from_bytes(&audit.receipt_public_key)
        .unwrap()
        .verify(&payload, &Signature::from_slice(&signature).unwrap())
        .unwrap();
    if let CommandResult::Order { result } = &fill_response.result {
        assert!(result
            .fills
            .iter()
            .all(|fill| fill.maker_private_user_id.is_empty()
                && fill.taker_private_user_id.is_empty()));
    }

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
            &alice_owner,
            AccountBucket::UserAvailable,
            "ZEN"
        )),
        1_569_200_000_000_000_000
    );
    assert_eq!(
        core.balance(&AccountKey::new("layrs", AccountBucket::FeeRevenue, "ZEN")),
        30_800_000_000_000_000
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
            &alice_owner,
            AccountBucket::UserAvailable,
            "ZEN"
        )),
        1_569_200_000_000_000_000
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

#[test]
fn polymarket_bootstrap_never_credits_an_unconfirmed_fill() {
    let oracle = SigningKey::from_bytes(&[40u8; 32]);
    let user = SigningKey::from_bytes(&[41u8; 32]);
    let journal_key = [42u8; 32];
    let commitment = [43u8; 32];
    let private_user = derived_private_user(journal_key, commitment);
    let mut core = PrivateTradingCore::new_with_oracle(
        JournalKey::from_bytes(journal_key),
        ReceiptSigner::generate([44u8; 48]),
        oracle.verifying_key().to_bytes(),
    )
    .unwrap();
    let market_id = "layrs:v1:BTC:15m:10000";
    core.register_market(
        "sys:market:bootstrap".into(),
        MarketConfig {
            market_id: market_id.into(),
            settlement_asset: "USDC".into(),
            settlement_decimals: 6,
            public_settlement_chain: "horizen".into(),
            opens_at_millis: 1_000,
            closes_at_millis: 10_000,
            minimum_quantity_micros: 1,
            maximum_quantity_micros: 10_000_000,
            minimum_order_notional_micros: 1,
            maximum_order_notional_micros: 10_000_000,
            maximum_user_position_micros: 10_000_000,
            maximum_pending_bootstrap_notional_micros: 100_000_000,
            tick_size_micros: 1_000,
            oracle_feed_id: 1,
            execution: MarketExecution::PolymarketBootstrap {
                condition_id: format!("0x{}", "11".repeat(32)),
                up_token_id: "123456789".into(),
                down_token_id: "987654321".into(),
                up_outcome_index: 0,
                down_outcome_index: 1,
                neg_risk: false,
            },
        },
        900,
    )
    .unwrap();
    core.register_session(
        "sys:session:bootstrap".into(),
        "session:bootstrap".into(),
        commitment,
        user.verifying_key().to_bytes(),
        9_000,
        900,
    )
    .unwrap();
    core.apply_user_external_flow(
        "sys:deposit:bootstrap".into(),
        commitment,
        "USDC".into(),
        AccountBucket::UserAvailable,
        1_000_000,
        ExternalFlowDirection::Inflow,
        [45u8; 32],
        950,
    )
    .unwrap();
    core.apply_external_flow(
        "sys:pool-capital".into(),
        AccountKey::new("layrs", AccountBucket::PoolCash, "USDC"),
        1_000_000,
        ExternalFlowDirection::Inflow,
        [46u8; 32],
        950,
    )
    .unwrap();

    let execution_id = uuid::Uuid::from_u128(47);
    let pending = execute_signed(
        &mut core,
        &user,
        "session:bootstrap",
        1,
        "cmd:bootstrap-buy",
        UserCommandAction::SubmitOrder {
            order: BookOrder::with_id(
                execution_id,
                "ignored-by-enclave",
                market_id,
                Outcome::Up,
                OrderAction::Buy,
                400_000,
                1_000_000,
                TimeInForce::Fok,
                None,
            ),
        },
        1_100,
    );
    assert!(matches!(pending, CommandResult::BootstrapPending { .. }));
    assert_eq!(
        core.balance(&AccountKey::new(
            &private_user,
            AccountBucket::UserAvailable,
            "USDC"
        )),
        599_200
    );
    assert_eq!(
        core.balance(&AccountKey::position(
            &private_user,
            format!("CLAIM:{market_id}:UP"),
            market_id,
            "UP"
        )),
        0
    );

    core.mark_bootstrap_submitted(
        "sys:venue-submitted:47".into(),
        execution_id,
        "pm-order-47".into(),
        1_150,
    )
    .unwrap();
    assert!(core
        .confirm_bootstrap_fill(
            "sys:bad-fill:47".into(),
            execution_id,
            401_000,
            [48u8; 32],
            1_160,
        )
        .is_err());
    assert_eq!(
        core.balance(&AccountKey::position(
            &private_user,
            format!("CLAIM:{market_id}:UP"),
            market_id,
            "UP"
        )),
        0
    );

    let fill_response = core
        .confirm_bootstrap_fill(
            "sys:fill:47".into(),
            execution_id,
            390_000,
            [49u8; 32],
            1_170,
        )
        .unwrap();
    assert_eq!(fill_response.audit_fills[0].statement.chain, "horizen");
    assert_eq!(
        core.balance(&AccountKey::position(
            &private_user,
            format!("CLAIM:{market_id}:UP"),
            market_id,
            "UP"
        )),
        1_000_000
    );
    assert_eq!(
        core.balance(&AccountKey::new(
            &private_user,
            AccountBucket::UserAvailable,
            "USDC"
        )),
        609_220
    );
    assert_eq!(
        core.balance(&AccountKey::new("layrs", AccountBucket::FeeRevenue, "USDC")),
        780
    );
    assert!(core
        .confirm_bootstrap_fill(
            "sys:duplicate-fill:47".into(),
            execution_id,
            390_000,
            [49u8; 32],
            1_180,
        )
        .is_err());

    let status = execute_signed(
        &mut core,
        &user,
        "session:bootstrap",
        2,
        "cmd:bootstrap-status",
        UserCommandAction::BootstrapStatus { execution_id },
        1_200,
    );
    assert!(matches!(
        status,
        CommandResult::BootstrapStatus { execution }
            if execution.state == clob_service::private_core::BootstrapExecutionState::VenueConfirmed
                && execution.confirmed_price_micros == Some(390_000)
    ));

    let resolution = PolymarketResolutionStatement {
        market_id: market_id.into(),
        condition_id: format!("0x{}", "11".repeat(32)),
        outcome: ResolutionOutcome::Up,
        redemption_amount_atomic: 1_000_000,
        redemption_transaction_hash: [51u8; 32],
        redemption_block_number: 50_000_000,
        evidence_hash: [50u8; 32],
        issued_at_millis: 10_100,
    };
    let signature = oracle
        .sign(&polymarket_resolution_signing_payload(&resolution).unwrap())
        .to_bytes()
        .to_vec();
    core.resolve_polymarket_market(
        "sys:resolve:bootstrap".into(),
        SignedPolymarketResolution {
            statement: resolution,
            signature,
        },
        10_100,
    )
    .unwrap();
    assert_eq!(
        core.balance(&AccountKey::new(
            &private_user,
            AccountBucket::UserAvailable,
            "USDC"
        )),
        1_578_720
    );
    assert_eq!(
        core.balance(&AccountKey::new("layrs", AccountBucket::FeeRevenue, "USDC")),
        31_280
    );
}

#[test]
fn portfolio_and_withdrawal_remain_signed_enclave_commands() {
    let user = SigningKey::from_bytes(&[31u8; 32]);
    let receipt_signer = ReceiptSigner::generate([32u8; 48]);
    let receipt_public_key = receipt_signer.verifying_key();
    let journal_key = [33u8; 32];
    let identity_commitment = [35u8; 32];
    let private_user = derived_private_user(journal_key, identity_commitment);
    let mut core = PrivateTradingCore::new(JournalKey::from_bytes(journal_key), receipt_signer);
    core.register_session(
        "sys:session:withdrawal".into(),
        "session:withdrawal".into(),
        identity_commitment,
        user.verifying_key().to_bytes(),
        10_000,
        1_000,
    )
    .unwrap();
    core.apply_user_external_flow(
        "sys:deposit:withdrawal".into(),
        identity_commitment,
        "USDC".into(),
        AccountBucket::UserAvailable,
        50_000_000,
        ExternalFlowDirection::Inflow,
        [34u8; 32],
        1_100,
    )
    .unwrap();

    let portfolio = execute_signed_response(
        &mut core,
        &user,
        "session:withdrawal",
        1,
        "cmd:portfolio",
        UserCommandAction::Portfolio,
        1_200,
    );
    match portfolio.result {
        CommandResult::Portfolio { snapshot } => {
            assert_eq!(snapshot.balances.len(), 1);
            assert_eq!(snapshot.balances[0].amount_atomic, "50000000");
        }
        _ => panic!("expected private portfolio"),
    }

    let response = execute_signed_response(
        &mut core,
        &user,
        "session:withdrawal",
        2,
        "cmd:withdrawal",
        UserCommandAction::RequestWithdrawal {
            withdrawal_id: uuid::Uuid::from_u128(35),
            chain: "base".into(),
            asset: "USDC".into(),
            amount_atomic: 10_000_000,
            destination: "0x1111111111111111111111111111111111111111".into(),
        },
        1_300,
    );
    let authorization = response.withdrawal_authorization.unwrap();
    assert_eq!(authorization.intent.receipt_id, response.receipt.receipt_id);
    assert_eq!(
        core.balance(&AccountKey::new(
            &private_user,
            AccountBucket::UserAvailable,
            "USDC"
        )),
        40_000_000
    );
    assert_eq!(
        core.balance(&AccountKey::new(
            &private_user,
            AccountBucket::UserWithdrawalHold,
            "USDC"
        )),
        10_000_000
    );
    let encoded = serde_json::to_vec(&authorization.intent).unwrap();
    let mut signed = b"layrs.withdrawal-authorization.v1\0".to_vec();
    signed.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
    signed.extend_from_slice(&encoded);
    VerifyingKey::from_bytes(&receipt_public_key)
        .unwrap()
        .verify(
            &signed,
            &Signature::from_slice(&authorization.signature).unwrap(),
        )
        .unwrap();
    core.validate_withdrawal_intent(&authorization.intent)
        .unwrap();
    let raw_transaction = format!("0x02{}", "11".repeat(80));
    core.record_prepared_withdrawal(
        "sys:withdrawal-prepare:35".into(),
        authorization.intent.withdrawal_id,
        [37u8; 32],
        raw_transaction.clone(),
        1_350,
    )
    .unwrap();
    assert_eq!(
        core.prepared_withdrawal(authorization.intent.withdrawal_id),
        Some(([37u8; 32], raw_transaction)),
    );
    let snapshot = core.export_encrypted_snapshot().unwrap();
    let restored = PrivateTradingCore::restore_encrypted_snapshot(
        JournalKey::from_bytes(journal_key),
        ReceiptSigner::generate([32u8; 48]),
        &snapshot,
        0,
    )
    .unwrap();
    restored
        .validate_withdrawal_intent(&authorization.intent)
        .unwrap();
    assert_eq!(
        restored
            .prepared_withdrawal(authorization.intent.withdrawal_id)
            .unwrap()
            .0,
        [37u8; 32]
    );
    core.release_user_withdrawal(
        "sys:withdrawal-release:35".into(),
        identity_commitment,
        "USDC".into(),
        10_000_000,
        [36u8; 32],
        1_400,
    )
    .unwrap();
    assert_eq!(
        core.balance(&AccountKey::new(
            &private_user,
            AccountBucket::UserAvailable,
            "USDC"
        )),
        50_000_000
    );
    assert_eq!(
        core.balance(&AccountKey::new(
            &private_user,
            AccountBucket::UserWithdrawalHold,
            "USDC"
        )),
        0
    );
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
    execute_signed_response(
        core, key, session_id, sequence, command_id, action, now_millis,
    )
    .result
}

#[allow(clippy::too_many_arguments)]
fn execute_signed_response(
    core: &mut PrivateTradingCore,
    key: &SigningKey,
    session_id: &str,
    sequence: u64,
    command_id: &str,
    action: UserCommandAction,
    now_millis: i64,
) -> clob_service::private_core::CoreResponse {
    execute_signed_result(
        core, key, session_id, sequence, command_id, action, now_millis,
    )
    .unwrap()
}

#[allow(clippy::too_many_arguments)]
fn execute_signed_result(
    core: &mut PrivateTradingCore,
    key: &SigningKey,
    session_id: &str,
    sequence: u64,
    command_id: &str,
    action: UserCommandAction,
    now_millis: i64,
) -> Result<clob_service::private_core::CoreResponse, CoreError> {
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
}
