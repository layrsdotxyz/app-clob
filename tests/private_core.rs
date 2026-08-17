use clob_service::private_core::{
    command_request_hash, polymarket_resolution_signing_payload, resolution_signing_payload,
    signing_payload, AccountBucket, AccountKey, BookOrder, BoundaryEvidence, CommandResult,
    CompleteSetDirection, CoreError, EncryptedJournal, ExternalFlowDirection, FeeProfileId,
    JournalKey, Ledger, LedgerTransaction, MarketConfig, MarketExecution, OrderAction, OrderStatus,
    Outcome, PolymarketResolutionStatement, PostingSide, PriceTimeBook, PrivateTradingCore,
    ReceiptSigner, ResolutionOutcome, ResolutionStatement, SessionGuard, SessionRequest,
    SignedPolymarketResolution, SignedResolution, SignedResolutionEvidence, SignedSessionRequest,
    TimeInForce, Transfer, UserCommand, UserCommandAction,
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
    assert_eq!(applied.postings.len(), 2);
    assert_eq!(applied.postings[0].account, user);
    assert_eq!(applied.postings[0].side, PostingSide::Debit);
    assert_eq!(applied.postings[0].amount, 400);
    assert_eq!(applied.postings[1].account, hold);
    assert_eq!(applied.postings[1].side, PostingSide::Credit);
    assert_eq!(applied.postings[1].amount, 400);

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
fn order_hold_postings_are_atomic_exact_and_race_safe() {
    let user = AccountKey::new("usr_hold", AccountBucket::UserAvailable, "USDC");
    let mut hold = AccountKey::new("usr_hold", AccountBucket::UserOrderHold, "USDC");
    hold.market_id = Some("layrs:v5:BTC:USDC:15m:1".into());
    hold.outcome = Some("UP".into());
    let mut collateral = AccountKey::new("layrs", AccountBucket::MarketCollateral, "USDC");
    collateral.market_id = hold.market_id.clone();

    let mut ledger = Ledger::default();
    ledger.seed_balance(user.clone(), 1_000).unwrap();
    let reserve = ledger
        .apply(LedgerTransaction {
            idempotency_key: "order-hold:reserve:1".into(),
            business_reference: "private-order:1".into(),
            transfers: vec![Transfer {
                from: user.clone(),
                to: hold.clone(),
                amount: 700,
            }],
        })
        .unwrap();
    assert_eq!(ledger.balance(&user), 300);
    assert_eq!(ledger.balance(&hold), 700);
    assert_balanced_postings(&reserve, 700);

    let partial_fill = ledger
        .apply(LedgerTransaction {
            idempotency_key: "order-hold:partial-fill:1".into(),
            business_reference: "private-fill:1".into(),
            transfers: vec![Transfer {
                from: hold.clone(),
                to: collateral.clone(),
                amount: 250,
            }],
        })
        .unwrap();
    assert_eq!(ledger.balance(&hold), 450);
    assert_balanced_postings(&partial_fill, 250);

    let release = ledger
        .apply(LedgerTransaction {
            idempotency_key: "order-hold:cancel:1".into(),
            business_reference: "private-order:1".into(),
            transfers: vec![Transfer {
                from: hold.clone(),
                to: user.clone(),
                amount: 450,
            }],
        })
        .unwrap();
    assert_eq!(ledger.balance(&hold), 0);
    assert_eq!(ledger.balance(&user), 750);
    assert_eq!(ledger.balance(&collateral), 250);
    assert_eq!(ledger.total_for_asset("USDC"), 1_000);
    assert_balanced_postings(&release, 450);

    // The command replay cannot reserve a second time, even after the order's
    // remaining hold has been released.
    let root = ledger.state_root();
    assert_eq!(
        ledger
            .apply(LedgerTransaction {
                idempotency_key: "order-hold:reserve:1".into(),
                business_reference: "private-order:1".into(),
                transfers: vec![Transfer {
                    from: user.clone(),
                    to: hold.clone(),
                    amount: 700
                }],
            })
            .unwrap_err(),
        CoreError::DuplicateCommand
    );
    assert_eq!(ledger.state_root(), root);

    // A one-atomic-unit remainder remains representable and releases exactly;
    // no settlement-precision dust is rounded into or out of the hold bucket.
    let dust_reserve = ledger
        .apply(LedgerTransaction {
            idempotency_key: "order-hold:dust-reserve".into(),
            business_reference: "private-order:dust".into(),
            transfers: vec![Transfer {
                from: user.clone(),
                to: hold.clone(),
                amount: 1,
            }],
        })
        .unwrap();
    assert_balanced_postings(&dust_reserve, 1);
    ledger
        .apply(LedgerTransaction {
            idempotency_key: "order-hold:dust-release".into(),
            business_reference: "private-order:dust".into(),
            transfers: vec![Transfer {
                from: hold.clone(),
                to: user.clone(),
                amount: 1,
            }],
        })
        .unwrap();
    assert_eq!(ledger.balance(&hold), 0);

    // Cancel and full-fill are mutually exclusive consumers of the same hold.
    // Whichever serializable transition wins leaves the loser unable to debit
    // the now-zero bucket, with no partial state mutation.
    let mut race_base = Ledger::default();
    race_base.seed_balance(user.clone(), 100).unwrap();
    race_base
        .apply(LedgerTransaction {
            idempotency_key: "race:reserve".into(),
            business_reference: "private-order:race".into(),
            transfers: vec![Transfer {
                from: user.clone(),
                to: hold.clone(),
                amount: 100,
            }],
        })
        .unwrap();

    let mut cancel_wins = race_base.clone();
    cancel_wins
        .apply(LedgerTransaction {
            idempotency_key: "race:cancel".into(),
            business_reference: "private-order:race".into(),
            transfers: vec![Transfer {
                from: hold.clone(),
                to: user.clone(),
                amount: 100,
            }],
        })
        .unwrap();
    let cancel_root = cancel_wins.state_root();
    assert_eq!(
        cancel_wins
            .apply(LedgerTransaction {
                idempotency_key: "race:fill".into(),
                business_reference: "private-fill:race".into(),
                transfers: vec![Transfer {
                    from: hold.clone(),
                    to: collateral.clone(),
                    amount: 100
                }],
            })
            .unwrap_err(),
        CoreError::InsufficientBalance
    );
    assert_eq!(cancel_wins.state_root(), cancel_root);

    let mut fill_wins = race_base;
    fill_wins
        .apply(LedgerTransaction {
            idempotency_key: "race:fill".into(),
            business_reference: "private-fill:race".into(),
            transfers: vec![Transfer {
                from: hold.clone(),
                to: collateral,
                amount: 100,
            }],
        })
        .unwrap();
    let fill_root = fill_wins.state_root();
    assert_eq!(
        fill_wins
            .apply(LedgerTransaction {
                idempotency_key: "race:cancel".into(),
                business_reference: "private-order:race".into(),
                transfers: vec![Transfer {
                    from: hold,
                    to: user,
                    amount: 100
                }],
            })
            .unwrap_err(),
        CoreError::InsufficientBalance
    );
    assert_eq!(fill_wins.state_root(), fill_root);
}

fn assert_balanced_postings(
    applied: &clob_service::private_core::AppliedLedgerTransaction,
    amount: u128,
) {
    let debits: u128 = applied
        .postings
        .iter()
        .filter(|posting| posting.side == PostingSide::Debit)
        .map(|posting| posting.amount)
        .sum();
    let credits: u128 = applied
        .postings
        .iter()
        .filter(|posting| posting.side == PostingSide::Credit)
        .map(|posting| posting.amount)
        .sum();
    assert_eq!(debits, amount);
    assert_eq!(credits, amount);
    assert_eq!(applied.postings.len(), applied.transfers.len() * 2);
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
fn duplicate_order_id_is_rejected_before_it_can_replace_resting_liquidity() {
    let mut book = PriceTimeBook::default();
    let now = 1_800_000_000_000;
    let order_id = uuid::Uuid::new_v4();
    let market_id = "layrs:v1:ZEN:15m:1800000000";

    book.submit(
        BookOrder::with_id(
            order_id,
            "usr_A",
            market_id,
            Outcome::Up,
            OrderAction::Buy,
            500_000,
            1_000_000,
            TimeInForce::Gtc,
            None,
        ),
        now,
    )
    .unwrap();

    let duplicate = book.submit(
        BookOrder::with_id(
            order_id,
            "usr_A",
            market_id,
            Outcome::Up,
            OrderAction::Buy,
            600_000,
            2_000_000,
            TimeInForce::Gtc,
            None,
        ),
        now,
    );

    assert!(matches!(
        duplicate.unwrap_err(),
        CoreError::InvalidOrder(message) if message == "duplicate order id"
    ));

    let (bids, asks) = book.aggregate_depth(market_id, Outcome::Up, now);
    assert_eq!(bids, vec![(500_000, 1_000_000, 1)]);
    assert!(asks.is_empty());
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
fn legacy_market_config_keeps_public_settlement_chain_out_of_snapshot_wire_shape() {
    let raw = serde_json::json!({
        "market_id": "layrs:v1:ZEN:15m:2000",
        "settlement_asset": "ZEN",
        "settlement_decimals": 18,
        "opens_at_millis": 900,
        "closes_at_millis": 2000,
        "minimum_quantity_micros": "1",
        "maximum_quantity_micros": "10000000",
        "minimum_order_notional_micros": "1",
        "maximum_order_notional_micros": "10000000",
        "maximum_user_position_micros": "10000000",
        "maximum_pending_bootstrap_notional_micros": "100000000",
        "tick_size_micros": 1000,
        "oracle_feed_id": 245,
        "execution": "NATIVE_CLOB"
    });
    let market: MarketConfig = serde_json::from_value(raw).unwrap();
    assert_eq!(market.public_settlement_chain, None);
    assert_eq!(market.fee_profile_id, FeeProfileId::LegacyProfitV1);
    let encoded = serde_json::to_value(&market).unwrap();
    assert!(encoded.get("public_settlement_chain").is_none());
    assert!(encoded.get("fee_profile_id").is_none());
}

#[test]
fn private_core_accepts_v2_rolling_market_ids() {
    let mut core = PrivateTradingCore::new(
        JournalKey::from_bytes([41u8; 32]),
        ReceiptSigner::generate([42u8; 48]),
    );

    core.register_market(
        "sys:market:v2:1".into(),
        MarketConfig {
            market_id: "layrs:v2:ZEN:15m:2000".into(),
            settlement_asset: "ZEN".into(),
            settlement_decimals: 18,
            public_settlement_chain: Some("horizen".into()),
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
            fee_profile_id: FeeProfileId::LegacyProfitV1,
            execution: MarketExecution::NativeClob,
        },
        800,
    )
    .unwrap();
}

#[test]
fn private_core_accepts_v3_rolling_market_ids() {
    let mut core = PrivateTradingCore::new(
        JournalKey::from_bytes([43u8; 32]),
        ReceiptSigner::generate([44u8; 48]),
    );

    core.register_market(
        "sys:market:v3:1".into(),
        MarketConfig {
            market_id: "layrs:v3:ZEN:15m:2000".into(),
            settlement_asset: "ZEN".into(),
            settlement_decimals: 18,
            public_settlement_chain: Some("horizen".into()),
            opens_at_millis: 900,
            closes_at_millis: 2_000,
            minimum_quantity_micros: 250_000,
            maximum_quantity_micros: 10_000_000,
            minimum_order_notional_micros: 250_000,
            maximum_order_notional_micros: 10_000_000,
            maximum_user_position_micros: 10_000_000,
            maximum_pending_bootstrap_notional_micros: 100_000_000,
            tick_size_micros: 1_000,
            oracle_feed_id: 245,
            fee_profile_id: FeeProfileId::LegacyProfitV1,
            execution: MarketExecution::NativeClob,
        },
        800,
    )
    .unwrap();
}

#[test]
fn private_core_accepts_signed_v4_event_market_ids_with_exact_polymarket_mapping() {
    let mut core = PrivateTradingCore::new(
        JournalKey::from_bytes([45u8; 32]),
        ReceiptSigner::generate([46u8; 48]),
    );

    core.register_market(
        "sys:market:v4:sports:1".into(),
        MarketConfig {
            market_id: "layrs:v4:SPORTS:arsenal-chelsea:abababababababab".into(),
            settlement_asset: "USDC".into(),
            settlement_decimals: 6,
            public_settlement_chain: Some("horizen".into()),
            opens_at_millis: 900,
            closes_at_millis: 2_000,
            minimum_quantity_micros: 1,
            maximum_quantity_micros: 10_000_000,
            minimum_order_notional_micros: 1_000_000,
            maximum_order_notional_micros: 10_000_000,
            maximum_user_position_micros: 10_000_000,
            maximum_pending_bootstrap_notional_micros: 100_000_000,
            tick_size_micros: 1_000,
            oracle_feed_id: 1,
            fee_profile_id: FeeProfileId::LegacyProfitV1,
            execution: MarketExecution::PolymarketBootstrap {
                condition_id: format!("0x{}", "ab".repeat(32)),
                up_token_id: "1".into(),
                down_token_id: "2".into(),
                up_outcome_index: 0,
                down_outcome_index: 1,
                neg_risk: false,
            },
        },
        800,
    )
    .unwrap();
}

#[test]
fn private_core_accepts_v5_native_event_markets_without_venue_execution() {
    let mut core = PrivateTradingCore::new(
        JournalKey::from_bytes([47u8; 32]),
        ReceiptSigner::generate([48u8; 48]),
    );

    core.register_market(
        "sys:market:v5:sports:1".into(),
        MarketConfig {
            market_id: "layrs:v5:SPORTS:arsenal-chelsea:abababababababab".into(),
            settlement_asset: "USDC".into(),
            settlement_decimals: 6,
            public_settlement_chain: Some("horizen".into()),
            opens_at_millis: 900,
            closes_at_millis: 2_000,
            minimum_quantity_micros: 1,
            maximum_quantity_micros: 10_000_000,
            minimum_order_notional_micros: 1_000_000,
            maximum_order_notional_micros: 10_000_000,
            maximum_user_position_micros: 10_000_000,
            maximum_pending_bootstrap_notional_micros: 100_000_000,
            tick_size_micros: 1_000,
            oracle_feed_id: 1,
            fee_profile_id: FeeProfileId::LegacyProfitV1,
            execution: MarketExecution::NativeExactCondition {
                condition_id: format!("0x{}", "ab".repeat(32)),
                up_outcome_index: 0,
                down_outcome_index: 1,
            },
        },
        800,
    )
    .unwrap();
}

#[test]
fn private_core_accepts_v5_native_macro_markets_without_venue_execution() {
    let mut core = PrivateTradingCore::new(
        JournalKey::from_bytes([49u8; 32]),
        ReceiptSigner::generate([50u8; 48]),
    );

    core.register_market(
        "sys:market:v5:macro:1".into(),
        MarketConfig {
            market_id: "layrs:v5:MACRO:cpiaucsl-20260812:abababababababab".into(),
            settlement_asset: "USDC".into(),
            settlement_decimals: 6,
            public_settlement_chain: Some("horizen".into()),
            opens_at_millis: 900,
            closes_at_millis: 2_000,
            minimum_quantity_micros: 1,
            maximum_quantity_micros: 10_000_000,
            minimum_order_notional_micros: 1_000_000,
            maximum_order_notional_micros: 10_000_000,
            maximum_user_position_micros: 10_000_000,
            maximum_pending_bootstrap_notional_micros: 100_000_000,
            tick_size_micros: 1_000,
            oracle_feed_id: 1,
            fee_profile_id: FeeProfileId::LegacyProfitV1,
            execution: MarketExecution::NativeExactCondition {
                condition_id: format!("0x{}", "ab".repeat(32)),
                up_outcome_index: 0,
                down_outcome_index: 1,
            },
        },
        800,
    )
    .unwrap();
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
            public_settlement_chain: Some("horizen".into()),
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
            fee_profile_id: FeeProfileId::LegacyProfitV1,
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
    let buy_action = UserCommandAction::SubmitOrder {
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
    };
    let fill_response = execute_signed_response(
        &mut core,
        &alice,
        "session:1",
        1,
        "cmd:buy",
        buy_action.clone(),
        1_200,
    );
    assert_eq!(fill_response.receipt.protocol_version, "layrs.v2");
    assert_eq!(fill_response.receipt.publication_eligible, Some(true));
    assert_eq!(
        fill_response.receipt.command_commitment_sha256,
        Some(command_request_hash("cmd:buy", "idem:cmd:buy", &buy_action).unwrap())
    );
    assert!(matches!(fill_response.result, CommandResult::Order { .. }));
    assert_eq!(fill_response.audit_fills.len(), 1);
    let audit = &fill_response.audit_fills[0];
    assert_eq!(audit.statement.chain, "horizen");
    assert_eq!(audit.statement.market_id, market_id);
    assert_eq!(audit.statement.price_micros, 400_000);
    assert_eq!(audit.statement.outcome.as_deref(), Some("UP"));
    assert_eq!(audit.statement.match_type.as_deref(), Some("NORMAL"));
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
    assert_eq!(fill_response.task_qualifications.len(), 1);
    let task = &fill_response.task_qualifications[0];
    assert_eq!(task.statement.event_type, "ORDER_ACCEPTED");
    assert_eq!(task.statement.settlement_asset, "ZEN");
    assert_eq!(task.statement.asset_notional_micros, 400_000);
    assert_eq!(task.statement.filled_quantity_micros, 1_000_000);
    assert_eq!(task.receipt_id, fill_response.receipt.receipt_id);
    let serialized_task = serde_json::to_string(task).unwrap();
    for private_value in ["usr_", market_id, "BUY", "UP"] {
        assert!(
            !serialized_task.contains(private_value),
            "task qualification leaked private order field: {private_value}"
        );
    }
    let mut unsigned_task = task.clone();
    let task_signature = std::mem::take(&mut unsigned_task.signature);
    let encoded_task = serde_json::to_vec(&unsigned_task).unwrap();
    let mut task_payload = b"layrs.task-qualification-artifact.v1\0".to_vec();
    task_payload.extend_from_slice(&(encoded_task.len() as u32).to_be_bytes());
    task_payload.extend_from_slice(&encoded_task);
    VerifyingKey::from_bytes(&task.receipt_public_key)
        .unwrap()
        .verify(
            &task_payload,
            &Signature::from_slice(&task_signature).unwrap(),
        )
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
fn native_clob_partial_fill_locks_remainder_and_cancel_releases_once() {
    let alice = SigningKey::from_bytes(&[61u8; 32]);
    let bob = SigningKey::from_bytes(&[62u8; 32]);
    let journal_key = [63u8; 32];
    let mut core = PrivateTradingCore::new(
        JournalKey::from_bytes(journal_key),
        ReceiptSigner::generate([64u8; 48]),
    );
    let market_id = "layrs:v3:ZEN:15m:3000";
    core.register_market(
        "sys:market:partial".into(),
        MarketConfig {
            market_id: market_id.into(),
            settlement_asset: "ZEN".into(),
            settlement_decimals: 18,
            public_settlement_chain: Some("horizen".into()),
            opens_at_millis: 900,
            closes_at_millis: 3_000,
            minimum_quantity_micros: 1,
            maximum_quantity_micros: 10_000_000,
            minimum_order_notional_micros: 1,
            maximum_order_notional_micros: 10_000_000,
            maximum_user_position_micros: 10_000_000,
            maximum_pending_bootstrap_notional_micros: 100_000_000,
            tick_size_micros: 1_000,
            oracle_feed_id: 245,
            fee_profile_id: FeeProfileId::LegacyProfitV1,
            execution: MarketExecution::NativeClob,
        },
        800,
    )
    .unwrap();

    let alice_commitment = [65u8; 32];
    let bob_commitment = [66u8; 32];
    let alice_owner = derived_private_user(journal_key, alice_commitment);
    let bob_owner = derived_private_user(journal_key, bob_commitment);
    for (label, key, commitment) in [
        ("alice", &alice, alice_commitment),
        ("bob", &bob, bob_commitment),
    ] {
        core.register_session(
            format!("sys:session:{label}"),
            format!("session:{label}"),
            commitment,
            key.verifying_key().to_bytes(),
            3_000,
            900,
        )
        .unwrap();
        core.apply_user_external_flow(
            format!("sys:deposit:{label}"),
            commitment,
            "ZEN".into(),
            AccountBucket::UserAvailable,
            1_000_000_000_000_000_000,
            ExternalFlowDirection::Inflow,
            [label.as_bytes()[0]; 32],
            950,
        )
        .unwrap();
    }

    execute_signed(
        &mut core,
        &bob,
        "session:bob",
        1,
        "cmd:bob-mint",
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
        "session:bob",
        2,
        "cmd:bob-ask",
        UserCommandAction::SubmitOrder {
            order: BookOrder::new(
                "ignored",
                market_id,
                Outcome::Up,
                OrderAction::Sell,
                500_000,
                400_000,
                TimeInForce::Gtc,
                None,
            ),
        },
        1_050,
    );

    let buy_response = execute_signed_response(
        &mut core,
        &alice,
        "session:alice",
        1,
        "cmd:alice-partial-buy",
        UserCommandAction::SubmitOrder {
            order: BookOrder::new(
                "ignored",
                market_id,
                Outcome::Up,
                OrderAction::Buy,
                500_000,
                1_000_000,
                TimeInForce::Gtc,
                None,
            ),
        },
        1_100,
    );
    let resting_buy = match buy_response.result {
        CommandResult::Order { result } => {
            assert_eq!(result.fills.len(), 1);
            let accepted = result.accepted_order.unwrap();
            assert_eq!(accepted.status, OrderStatus::PartiallyFilled);
            assert_eq!(accepted.filled_micros, 400_000);
            assert_eq!(accepted.remaining_micros, 600_000);
            accepted
        }
        _ => panic!("expected order response"),
    };

    let mut alice_cash_hold = AccountKey::new(&alice_owner, AccountBucket::UserOrderHold, "ZEN");
    alice_cash_hold.market_id = Some(market_id.into());
    alice_cash_hold.outcome = Some("UP".into());
    assert_eq!(
        core.balance(&AccountKey::new(
            &alice_owner,
            AccountBucket::UserAvailable,
            "ZEN"
        )),
        499_600_000_000_000_000
    );
    assert_eq!(core.balance(&alice_cash_hold), 300_000_000_000_000_000);
    assert_eq!(
        core.balance(&AccountKey::position(
            &alice_owner,
            format!("CLAIM:{market_id}:UP"),
            market_id,
            "UP"
        )),
        400_000
    );
    assert_eq!(
        core.balance(&AccountKey::new(
            &bob_owner,
            AccountBucket::UserAvailable,
            "ZEN"
        )),
        200_000_000_000_000_000
    );

    let overdraw = execute_signed_result(
        &mut core,
        &alice,
        "session:alice",
        2,
        "cmd:alice-overdraw-locked",
        UserCommandAction::RequestWithdrawal {
            withdrawal_id: uuid::Uuid::from_u128(66),
            chain: "horizen".into(),
            asset: "ZEN".into(),
            amount_atomic: 800_000_000_000_000_000,
            destination: "0x1111111111111111111111111111111111111111".into(),
        },
        1_150,
    );
    assert_eq!(overdraw.unwrap_err(), CoreError::InsufficientBalance);

    execute_signed(
        &mut core,
        &alice,
        "session:alice",
        3,
        "cmd:alice-cancel-resting",
        UserCommandAction::CancelOrder {
            market_id: market_id.into(),
            order_id: resting_buy.order_id,
        },
        1_200,
    );
    assert_eq!(core.balance(&alice_cash_hold), 0);
    assert_eq!(
        core.balance(&AccountKey::new(
            &alice_owner,
            AccountBucket::UserAvailable,
            "ZEN"
        )),
        799_600_000_000_000_000
    );

    let repeat_cancel = execute_signed_result(
        &mut core,
        &alice,
        "session:alice",
        4,
        "cmd:alice-repeat-cancel",
        UserCommandAction::CancelOrder {
            market_id: market_id.into(),
            order_id: resting_buy.order_id,
        },
        1_250,
    );
    assert!(matches!(
        repeat_cancel.unwrap_err(),
        CoreError::InvalidOrder(message) if message == "order is not cancellable"
    ));
    assert_eq!(core.balance(&alice_cash_hold), 0);
    assert_eq!(
        core.balance(&AccountKey::new(
            &alice_owner,
            AccountBucket::UserAvailable,
            "ZEN"
        )),
        799_600_000_000_000_000
    );

    // Fill the seller's remaining UP claim completely. The second order
    // proves that a prior partial fill plus a later full fill preserve the
    // collateral account and book the exact buyer position, seller proceeds
    // and taker fees.
    execute_signed(
        &mut core,
        &bob,
        "session:bob",
        3,
        "cmd:bob-final-ask",
        UserCommandAction::SubmitOrder {
            order: BookOrder::new(
                "ignored",
                market_id,
                Outcome::Up,
                OrderAction::Sell,
                500_000,
                600_000,
                TimeInForce::Gtc,
                None,
            ),
        },
        1_300,
    );
    let full_buy_action = UserCommandAction::SubmitOrder {
        order: BookOrder::new(
            "ignored",
            market_id,
            Outcome::Up,
            OrderAction::Buy,
            500_000,
            600_000,
            TimeInForce::Gtc,
            None,
        ),
    };
    let full_fill = execute_signed_response(
        &mut core,
        &alice,
        "session:alice",
        5,
        "cmd:alice-full-buy",
        full_buy_action.clone(),
        1_350,
    );
    assert!(matches!(
        full_fill.result,
        CommandResult::Order { ref result }
            if result.fills.len() == 1
                && result.accepted_order.as_ref().is_some_and(|order|
                    order.status == OrderStatus::Filled
                        && order.remaining_micros == 0
                        && order.filled_micros == 600_000)
    ));

    let mut collateral = AccountKey::new("layrs", AccountBucket::MarketCollateral, "ZEN");
    collateral.market_id = Some(market_id.into());
    assert_eq!(core.balance(&collateral), 1_000_000_000_000_000_000);
    assert_eq!(
        core.balance(&AccountKey::new(
            &alice_owner,
            AccountBucket::UserAvailable,
            "ZEN"
        )),
        499_000_000_000_000_000
    );
    assert_eq!(core.balance(&alice_cash_hold), 0);
    assert_eq!(
        core.balance(&AccountKey::new(
            &bob_owner,
            AccountBucket::UserAvailable,
            "ZEN"
        )),
        500_000_000_000_000_000
    );
    assert_eq!(
        core.balance(&AccountKey::new("layrs", AccountBucket::FeeRevenue, "ZEN")),
        1_000_000_000_000_000
    );
    assert_eq!(
        core.balance(&AccountKey::position(
            &alice_owner,
            format!("CLAIM:{market_id}:UP"),
            market_id,
            "UP"
        )),
        1_000_000
    );
    assert_eq!(
        core.balance(&AccountKey::position(
            &bob_owner,
            format!("CLAIM:{market_id}:UP"),
            market_id,
            "UP"
        )),
        0
    );

    // Exercise the opposite fee direction: the resting BUY maker funds the
    // gross notional from its hold, while the incoming SELL taker receives
    // net proceeds and the fee is split to protocol revenue atomically.
    execute_signed(
        &mut core,
        &bob,
        "session:bob",
        4,
        "cmd:bob-resting-bid",
        UserCommandAction::SubmitOrder {
            order: BookOrder::new(
                "ignored",
                market_id,
                Outcome::Up,
                OrderAction::Buy,
                500_000,
                200_000,
                TimeInForce::Gtc,
                None,
            ),
        },
        1_400,
    );
    let sell_taker_action = UserCommandAction::SubmitOrder {
        order: BookOrder::new(
            "ignored",
            market_id,
            Outcome::Up,
            OrderAction::Sell,
            500_000,
            200_000,
            TimeInForce::Gtc,
            None,
        ),
    };
    let sell_taker_fill = execute_signed_response(
        &mut core,
        &alice,
        "session:alice",
        6,
        "cmd:alice-sell-taker",
        sell_taker_action.clone(),
        1_450,
    );
    assert!(matches!(
        sell_taker_fill.result,
        CommandResult::Order { ref result }
            if result.fills.len() == 1
                && result.accepted_order.as_ref().is_some_and(|order|
                    order.status == OrderStatus::Filled
                        && order.remaining_micros == 0
                        && order.filled_micros == 200_000)
    ));
    assert_eq!(
        core.balance(&AccountKey::new(
            &alice_owner,
            AccountBucket::UserAvailable,
            "ZEN"
        )),
        598_800_000_000_000_000
    );
    assert_eq!(
        core.balance(&AccountKey::new(
            &bob_owner,
            AccountBucket::UserAvailable,
            "ZEN"
        )),
        400_000_000_000_000_000
    );
    assert_eq!(
        core.balance(&AccountKey::new("layrs", AccountBucket::FeeRevenue, "ZEN")),
        1_200_000_000_000_000
    );
    assert_eq!(
        core.balance(&AccountKey::position(
            &alice_owner,
            format!("CLAIM:{market_id}:UP"),
            market_id,
            "UP"
        )),
        800_000
    );
    assert_eq!(
        core.balance(&AccountKey::position(
            &bob_owner,
            format!("CLAIM:{market_id}:UP"),
            market_id,
            "UP"
        )),
        200_000
    );
    assert_eq!(core.balance(&collateral), 1_000_000_000_000_000_000);

    // A committed response may be lost between the enclave and API. Snapshot
    // recovery keeps only the processed request hash, so the same signed
    // command must be reported as previously processed without applying the
    // fill, fee or position transfer a second time.
    let snapshot = core.export_encrypted_snapshot().unwrap();
    let snapshot_sequence = snapshot.sequence;
    let mut restored = PrivateTradingCore::restore_encrypted_snapshot(
        JournalKey::from_bytes(journal_key),
        ReceiptSigner::generate([67u8; 48]),
        &snapshot,
        snapshot_sequence,
    )
    .unwrap();
    let restored_root = restored.state_root();
    let lost_response_retry = execute_signed_result(
        &mut restored,
        &alice,
        "session:alice",
        6,
        "cmd:alice-sell-taker",
        sell_taker_action,
        1_450,
    );
    assert_eq!(
        lost_response_retry.unwrap_err(),
        CoreError::PreviouslyProcessed
    );
    assert_eq!(restored.state_root(), restored_root);
    assert_eq!(restored.balance(&collateral), 1_000_000_000_000_000_000);
    assert_eq!(
        restored.balance(&AccountKey::new("layrs", AccountBucket::FeeRevenue, "ZEN")),
        1_200_000_000_000_000
    );
}

#[test]
fn rolling_zen_markets_handle_many_small_multi_user_trades_cancellation_and_locked_withdrawal() {
    let oracle = SigningKey::from_bytes(&[81u8; 32]);
    let seller = SigningKey::from_bytes(&[82u8; 32]);
    let buyer_one = SigningKey::from_bytes(&[83u8; 32]);
    let buyer_two = SigningKey::from_bytes(&[84u8; 32]);
    let journal_key = [85u8; 32];
    let mut core = PrivateTradingCore::new_with_oracle(
        JournalKey::from_bytes(journal_key),
        ReceiptSigner::generate([86u8; 48]),
        oracle.verifying_key().to_bytes(),
    )
    .unwrap();
    let markets = [
        ("layrs:v3:ZEN:15m:3000", 3_000_i64),
        ("layrs:v3:ZEN:15m:4000", 4_000_i64),
    ];
    for (index, (market_id, closes_at)) in markets.iter().enumerate() {
        core.register_market(
            format!("sys:market:stress:{index}"),
            MarketConfig {
                market_id: (*market_id).into(),
                settlement_asset: "ZEN".into(),
                settlement_decimals: 18,
                public_settlement_chain: Some("horizen".into()),
                opens_at_millis: 900,
                closes_at_millis: *closes_at,
                minimum_quantity_micros: 1,
                maximum_quantity_micros: 10_000_000,
                minimum_order_notional_micros: 1,
                maximum_order_notional_micros: 10_000_000,
                maximum_user_position_micros: 10_000_000,
                maximum_pending_bootstrap_notional_micros: 100_000_000,
                tick_size_micros: 1_000,
                oracle_feed_id: 245,
                fee_profile_id: FeeProfileId::LegacyProfitV1,
                execution: MarketExecution::NativeClob,
            },
            800,
        )
        .unwrap();
    }

    let users = [
        (
            "seller",
            &seller,
            [87u8; 32],
            5_000_000_000_000_000_000_u128,
        ),
        (
            "buyer-one",
            &buyer_one,
            [88u8; 32],
            2_000_000_000_000_000_000_u128,
        ),
        (
            "buyer-two",
            &buyer_two,
            [89u8; 32],
            2_000_000_000_000_000_000_u128,
        ),
    ];
    for (label, key, commitment, amount) in &users {
        core.register_session(
            format!("sys:session:stress:{label}"),
            format!("session:stress:{label}"),
            *commitment,
            key.verifying_key().to_bytes(),
            10_000,
            850,
        )
        .unwrap();
        core.apply_user_external_flow(
            format!("sys:deposit:stress:{label}"),
            *commitment,
            "ZEN".into(),
            AccountBucket::UserAvailable,
            *amount,
            ExternalFlowDirection::Inflow,
            *commitment,
            875,
        )
        .unwrap();
    }

    let mut buyer_one_sequence = 1_u64;
    let mut buyer_two_sequence = 1_u64;
    for (market_index, (market_id, _)) in markets.iter().enumerate() {
        execute_signed(
            &mut core,
            &seller,
            "session:stress:seller",
            (market_index * 2 + 1) as u64,
            &format!("cmd:stress:mint:{market_index}"),
            UserCommandAction::CompleteSet {
                market_id: (*market_id).into(),
                quantity_micros: 1_000_000,
                direction: CompleteSetDirection::Mint,
            },
            1_000 + market_index as i64 * 100,
        );
        execute_signed(
            &mut core,
            &seller,
            "session:stress:seller",
            (market_index * 2 + 2) as u64,
            &format!("cmd:stress:sell:{market_index}"),
            UserCommandAction::SubmitOrder {
                order: BookOrder::new(
                    "ignored",
                    *market_id,
                    Outcome::Up,
                    OrderAction::Sell,
                    500_000,
                    200_000,
                    TimeInForce::Gtc,
                    None,
                ),
            },
            1_025 + market_index as i64 * 100,
        );

        for trade_index in 0..20 {
            let (buyer, session_id, sequence) = if trade_index % 2 == 0 {
                let sequence = buyer_one_sequence;
                buyer_one_sequence += 1;
                (&buyer_one, "session:stress:buyer-one", sequence)
            } else {
                let sequence = buyer_two_sequence;
                buyer_two_sequence += 1;
                (&buyer_two, "session:stress:buyer-two", sequence)
            };
            let response = execute_signed_response(
                &mut core,
                buyer,
                session_id,
                sequence,
                &format!("cmd:stress:buy:{market_index}:{trade_index}"),
                UserCommandAction::SubmitOrder {
                    order: BookOrder::new(
                        "ignored",
                        *market_id,
                        Outcome::Up,
                        OrderAction::Buy,
                        500_000,
                        10_000,
                        TimeInForce::Fak,
                        None,
                    ),
                },
                1_200 + market_index as i64 * 300 + trade_index as i64,
            );
            match response.result {
                CommandResult::Order { result } => {
                    assert_eq!(result.fills.len(), 1);
                    let accepted = result.accepted_order.unwrap();
                    assert_eq!(accepted.status, OrderStatus::Filled);
                    assert_eq!(accepted.remaining_micros, 0);
                }
                _ => panic!("expected small ZEN fill"),
            }
            assert_eq!(response.audit_fills.len(), 1);
        }
    }

    let buyer_one_owner = derived_private_user(journal_key, [88u8; 32]);
    let available_before_resting = core.balance(&AccountKey::new(
        &buyer_one_owner,
        AccountBucket::UserAvailable,
        "ZEN",
    ));
    let resting = execute_signed_response(
        &mut core,
        &buyer_one,
        "session:stress:buyer-one",
        buyer_one_sequence,
        "cmd:stress:resting",
        UserCommandAction::SubmitOrder {
            order: BookOrder::new(
                "ignored",
                markets[1].0,
                Outcome::Down,
                OrderAction::Buy,
                400_000,
                100_000,
                TimeInForce::Gtc,
                None,
            ),
        },
        1_900,
    );
    buyer_one_sequence += 1;
    let resting_order_id = match resting.result {
        CommandResult::Order { result } => result.accepted_order.unwrap().order_id,
        _ => panic!("expected resting order"),
    };

    let locked_withdrawal = execute_signed_result(
        &mut core,
        &buyer_one,
        "session:stress:buyer-one",
        buyer_one_sequence,
        "cmd:stress:locked-withdrawal",
        UserCommandAction::RequestWithdrawal {
            withdrawal_id: uuid::Uuid::from_u128(90),
            chain: "horizen".into(),
            asset: "ZEN".into(),
            amount_atomic: available_before_resting,
            destination: "0x1111111111111111111111111111111111111111".into(),
        },
        1_925,
    );
    buyer_one_sequence += 1;
    assert_eq!(
        locked_withdrawal.unwrap_err(),
        CoreError::InsufficientBalance
    );

    execute_signed(
        &mut core,
        &buyer_one,
        "session:stress:buyer-one",
        buyer_one_sequence,
        "cmd:stress:cancel-resting",
        UserCommandAction::CancelOrder {
            market_id: markets[1].0.into(),
            order_id: resting_order_id,
        },
        1_950,
    );
    assert_eq!(
        core.balance(&AccountKey::new(
            &buyer_one_owner,
            AccountBucket::UserAvailable,
            "ZEN",
        )),
        available_before_resting
    );

    let boundary = |end: i64, price: i64, marker: u8| BoundaryEvidence {
        window_start_micros: end * 1_000 - 5_000_000,
        window_end_micros: end * 1_000,
        median_price_e8: price,
        sample_count: 25,
        minimum_publisher_count: 3,
        signed_payload_commitment: [marker; 32],
    };
    for (index, (market_id, closes_at)) in markets.iter().enumerate() {
        let statement = ResolutionStatement {
            market_id: (*market_id).into(),
            oracle_feed_id: 245,
            opening: boundary(900, 1_000_000_000, 100 + index as u8),
            closing: boundary(
                *closes_at,
                if index == 0 {
                    1_100_000_000
                } else {
                    900_000_000
                },
                102 + index as u8,
            ),
            issued_at_millis: closes_at + 100,
        };
        let signature = oracle
            .sign(&resolution_signing_payload(&statement).unwrap())
            .to_bytes()
            .to_vec();
        core.resolve_market(
            format!("sys:resolve:stress:{index}"),
            SignedResolution {
                statement,
                signature,
            },
            closes_at + 100,
        )
        .unwrap();
    }

    assert!(core.balance(&AccountKey::new("layrs", AccountBucket::FeeRevenue, "ZEN",)) > 0);
    for owner in [
        derived_private_user(journal_key, [87u8; 32]),
        buyer_one_owner,
        derived_private_user(journal_key, [89u8; 32]),
    ] {
        for market_id in markets.map(|market| market.0) {
            assert_eq!(
                core.balance(&AccountKey::position(
                    &owner,
                    format!("CLAIM:{market_id}:UP"),
                    market_id,
                    "UP",
                )),
                0
            );
            assert_eq!(
                core.balance(&AccountKey::position(
                    &owner,
                    format!("CLAIM:{market_id}:DOWN"),
                    market_id,
                    "DOWN",
                )),
                0
            );
        }
    }
}

#[test]
fn public_depth_hides_thin_levels_buckets_size_and_clears_at_market_close() {
    let journal_key = [211u8; 32];
    let mut core = PrivateTradingCore::new(
        JournalKey::from_bytes(journal_key),
        ReceiptSigner::generate([212u8; 48]),
    );
    let market_id = "layrs:v5:BTC:USDC:15m:3";
    core.register_market(
        "sys:market:privacy-depth".into(),
        MarketConfig {
            market_id: market_id.into(),
            settlement_asset: "USDC".into(),
            settlement_decimals: 6,
            public_settlement_chain: Some("base".into()),
            opens_at_millis: 1_000,
            closes_at_millis: 3_000,
            minimum_quantity_micros: 1,
            maximum_quantity_micros: 100_000_000,
            minimum_order_notional_micros: 1,
            maximum_order_notional_micros: 100_000_000,
            maximum_user_position_micros: 100_000_000,
            maximum_pending_bootstrap_notional_micros: 100_000_000,
            tick_size_micros: 10_000,
            oracle_feed_id: 9002,
            fee_profile_id: FeeProfileId::PolymarketCryptoV2,
            execution: MarketExecution::NativeClob,
        },
        900,
    )
    .unwrap();

    let users = [
        (SigningKey::from_bytes(&[213u8; 32]), [214u8; 32]),
        (SigningKey::from_bytes(&[215u8; 32]), [216u8; 32]),
        (SigningKey::from_bytes(&[217u8; 32]), [218u8; 32]),
    ];
    for (index, (key, commitment)) in users.iter().enumerate() {
        let session_id = format!("session:privacy-depth:{index}");
        core.register_session(
            format!("sys:session:privacy-depth:{index}"),
            session_id.clone(),
            *commitment,
            key.verifying_key().to_bytes(),
            10_000,
            925 + index as i64,
        )
        .unwrap();
        core.apply_user_external_flow(
            format!("sys:deposit:privacy-depth:{index}"),
            *commitment,
            "USDC".into(),
            AccountBucket::UserAvailable,
            10_000_000,
            ExternalFlowDirection::Inflow,
            *commitment,
            950 + index as i64,
        )
        .unwrap();
        execute_signed(
            &mut core,
            key,
            &session_id,
            1,
            &format!("cmd:privacy-depth:{index}"),
            UserCommandAction::SubmitOrder {
                order: BookOrder::new(
                    "ignored",
                    market_id,
                    Outcome::Up,
                    OrderAction::Buy,
                    150_000,
                    6_666_667,
                    TimeInForce::Gtc,
                    None,
                ),
            },
            1_100 + index as i64,
        );

        let (bids, _) = core.aggregate_depth(market_id, Outcome::Up, 1_500, 1_000_000);
        if index < 2 {
            assert!(bids.is_empty(), "one or two owners must remain private");
        } else {
            assert_eq!(bids, vec![(150_000, 20_000_000)]);
        }
    }

    let (closed_bids, closed_asks) = core.aggregate_depth(market_id, Outcome::Up, 3_000, 1_000_000);
    assert!(closed_bids.is_empty());
    assert!(closed_asks.is_empty());
}

#[test]
fn resolution_cannot_double_credit_and_dust_fees_stay_conservative() {
    let oracle = SigningKey::from_bytes(&[71u8; 32]);
    let user = SigningKey::from_bytes(&[72u8; 32]);
    let journal_key = [73u8; 32];
    let commitment = [74u8; 32];
    let owner = derived_private_user(journal_key, commitment);
    let mut core = PrivateTradingCore::new_with_oracle(
        JournalKey::from_bytes(journal_key),
        ReceiptSigner::generate([75u8; 48]),
        oracle.verifying_key().to_bytes(),
    )
    .unwrap();
    let market_id = "layrs:v3:USDC:15m:4000";
    core.register_market(
        "sys:market:dust".into(),
        MarketConfig {
            market_id: market_id.into(),
            settlement_asset: "USDC".into(),
            settlement_decimals: 6,
            public_settlement_chain: Some("horizen".into()),
            opens_at_millis: 900,
            closes_at_millis: 4_000,
            minimum_quantity_micros: 1,
            maximum_quantity_micros: 10_000_000,
            minimum_order_notional_micros: 1,
            maximum_order_notional_micros: 10_000_000,
            maximum_user_position_micros: 10_000_000,
            maximum_pending_bootstrap_notional_micros: 100_000_000,
            tick_size_micros: 100,
            oracle_feed_id: 1,
            fee_profile_id: FeeProfileId::LegacyProfitV1,
            execution: MarketExecution::NativeClob,
        },
        800,
    )
    .unwrap();
    core.register_session(
        "sys:session:dust".into(),
        "session:dust".into(),
        commitment,
        user.verifying_key().to_bytes(),
        4_500,
        900,
    )
    .unwrap();
    core.apply_user_external_flow(
        "sys:deposit:dust".into(),
        commitment,
        "USDC".into(),
        AccountBucket::UserAvailable,
        10,
        ExternalFlowDirection::Inflow,
        [76u8; 32],
        950,
    )
    .unwrap();
    execute_signed(
        &mut core,
        &user,
        "session:dust",
        1,
        "cmd:dust-mint",
        UserCommandAction::CompleteSet {
            market_id: market_id.into(),
            quantity_micros: 1,
            direction: CompleteSetDirection::Mint,
        },
        1_000,
    );

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
        oracle_feed_id: 1,
        opening: boundary(900, 100, 77),
        closing: boundary(4_000, 101, 78),
        issued_at_millis: 4_100,
    };
    let signature = oracle
        .sign(&resolution_signing_payload(&statement).unwrap())
        .to_bytes()
        .to_vec();
    let signed = SignedResolution {
        statement,
        signature,
    };
    core.resolve_market("sys:resolve:dust".into(), signed.clone(), 4_100)
        .unwrap();

    assert_eq!(
        core.balance(&AccountKey::new(
            &owner,
            AccountBucket::UserAvailable,
            "USDC"
        )),
        9
    );
    assert_eq!(
        core.balance(&AccountKey::new("layrs", AccountBucket::FeeRevenue, "USDC")),
        1
    );
    assert_eq!(
        core.balance(&AccountKey::position(
            &owner,
            format!("CLAIM:{market_id}:UP"),
            market_id,
            "UP"
        )),
        0
    );
    assert_eq!(
        core.balance(&AccountKey::position(
            &owner,
            format!("CLAIM:{market_id}:DOWN"),
            market_id,
            "DOWN"
        )),
        0
    );
    let root_after_first_resolution = core.state_root();
    core.validate_onchain_resolution_authorization(
        market_id,
        ResolutionOutcome::Up,
        &SignedResolutionEvidence::Pyth(signed.clone()),
        4_200,
    )
    .unwrap();

    let mut conflicting_statement = signed.statement.clone();
    conflicting_statement.closing.median_price_e8 = 102;
    let conflicting_signature = oracle
        .sign(&resolution_signing_payload(&conflicting_statement).unwrap())
        .to_bytes()
        .to_vec();
    let conflicting = SignedResolution {
        statement: conflicting_statement,
        signature: conflicting_signature,
    };
    let conflict = core.validate_onchain_resolution_authorization(
        market_id,
        ResolutionOutcome::Up,
        &SignedResolutionEvidence::Pyth(conflicting),
        4_200,
    );
    assert!(matches!(
        conflict.unwrap_err(),
        CoreError::InvalidResolution(message)
            if message == "resolution evidence conflicts with committed resolution"
    ));

    let second_resolution = core.resolve_market("sys:resolve:dust-again".into(), signed, 4_200);
    assert!(matches!(
        second_resolution.unwrap_err(),
        CoreError::InvalidResolution(message) if message == "market is already resolved"
    ));
    assert_eq!(core.state_root(), root_after_first_resolution);
    assert_eq!(
        core.balance(&AccountKey::new("layrs", AccountBucket::FeeRevenue, "USDC")),
        1
    );
}

#[test]
fn category_fee_profiles_settle_usdc_and_zen_through_the_full_ledger_path() {
    let cases = [
        (
            "USDC",
            6u8,
            FeeProfileId::MacroV1,
            1_500_000u128,
            198_500_000u128,
        ),
        (
            "ZEN",
            18u8,
            FeeProfileId::CryptoV1,
            2_000_000_000_000_000_000u128,
            198_000_000_000_000_000_000u128,
        ),
    ];
    for (index, (asset, decimals, profile, expected_fee, expected_available)) in
        cases.into_iter().enumerate()
    {
        let marker = 180u8 + index as u8 * 10;
        let oracle = SigningKey::from_bytes(&[marker; 32]);
        let user = SigningKey::from_bytes(&[marker + 1; 32]);
        let journal_key = [marker + 2; 32];
        let commitment = [marker + 3; 32];
        let owner = derived_private_user(journal_key, commitment);
        let mut core = PrivateTradingCore::new_with_oracle(
            JournalKey::from_bytes(journal_key),
            ReceiptSigner::generate([marker + 4; 48]),
            oracle.verifying_key().to_bytes(),
        )
        .unwrap();
        let market_id = format!("layrs:v3:{asset}:15m:category-fee-{index}");
        core.register_market(
            format!("sys:market:category-fee:{index}"),
            MarketConfig {
                market_id: market_id.clone(),
                settlement_asset: asset.into(),
                settlement_decimals: decimals,
                public_settlement_chain: Some("horizen".into()),
                opens_at_millis: 900,
                closes_at_millis: 4_000,
                minimum_quantity_micros: 1,
                maximum_quantity_micros: 1_000_000_000,
                minimum_order_notional_micros: 1,
                maximum_order_notional_micros: 1_000_000_000,
                maximum_user_position_micros: 1_000_000_000,
                maximum_pending_bootstrap_notional_micros: 1_000_000_000,
                tick_size_micros: 1_000,
                oracle_feed_id: 245,
                fee_profile_id: profile,
                execution: MarketExecution::NativeClob,
            },
            800,
        )
        .unwrap();
        core.register_session(
            format!("sys:session:category-fee:{index}"),
            format!("session:category-fee:{index}"),
            commitment,
            user.verifying_key().to_bytes(),
            5_000,
            850,
        )
        .unwrap();
        let scale = 10u128.pow(decimals as u32 - 6);
        core.apply_user_external_flow(
            format!("sys:deposit:category-fee:{index}"),
            commitment,
            asset.into(),
            AccountBucket::UserAvailable,
            200_000_000u128 * scale,
            ExternalFlowDirection::Inflow,
            [marker + 5; 32],
            875,
        )
        .unwrap();
        execute_signed(
            &mut core,
            &user,
            &format!("session:category-fee:{index}"),
            1,
            &format!("cmd:category-fee:mint:{index}"),
            UserCommandAction::CompleteSet {
                market_id: market_id.clone(),
                quantity_micros: 100_000_000,
                direction: CompleteSetDirection::Mint,
            },
            1_000,
        );

        let boundary = |end: i64, price: i64, evidence_marker: u8| BoundaryEvidence {
            window_start_micros: end * 1_000 - 5_000_000,
            window_end_micros: end * 1_000,
            median_price_e8: price,
            sample_count: 25,
            minimum_publisher_count: 3,
            signed_payload_commitment: [evidence_marker; 32],
        };
        let statement = ResolutionStatement {
            market_id: market_id.clone(),
            oracle_feed_id: 245,
            opening: boundary(900, 100, marker + 6),
            closing: boundary(4_000, 101, marker + 7),
            issued_at_millis: 4_100,
        };
        let signature = oracle
            .sign(&resolution_signing_payload(&statement).unwrap())
            .to_bytes()
            .to_vec();
        core.resolve_market(
            format!("sys:resolve:category-fee:{index}"),
            SignedResolution {
                statement,
                signature,
            },
            4_100,
        )
        .unwrap();

        assert_eq!(
            core.balance(&AccountKey::new(
                &owner,
                AccountBucket::UserAvailable,
                asset
            )),
            expected_available,
        );
        assert_eq!(
            core.balance(&AccountKey::new("layrs", AccountBucket::FeeRevenue, asset)),
            expected_fee,
        );
    }
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
            public_settlement_chain: Some("horizen".into()),
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
            fee_profile_id: FeeProfileId::LegacyProfitV1,
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

    let root_before_portfolio = core.state_root();
    let snapshot_before_portfolio = core.export_encrypted_snapshot().unwrap();

    let portfolio = execute_signed_response(
        &mut core,
        &user,
        "session:withdrawal",
        1,
        "cmd:portfolio",
        UserCommandAction::Portfolio,
        1_200,
    );
    assert_eq!(portfolio.receipt.protocol_version, "layrs.v2");
    assert_eq!(portfolio.receipt.publication_eligible, Some(false));
    assert!(portfolio.encrypted_record.is_none());
    assert_eq!(portfolio.receipt.prior_state_root, root_before_portfolio);
    assert_eq!(portfolio.receipt.state_root, root_before_portfolio);
    assert_eq!(core.state_root(), root_before_portfolio);
    assert_eq!(
        core.export_encrypted_snapshot().unwrap().sequence,
        snapshot_before_portfolio.sequence
    );
    assert_eq!(
        portfolio.receipt.command_commitment_sha256,
        Some(
            command_request_hash(
                "cmd:portfolio",
                "idem:cmd:portfolio",
                &UserCommandAction::Portfolio,
            )
            .unwrap()
        ),
    );
    let mut portfolio_signed_payload = portfolio.receipt.clone();
    let portfolio_signature = std::mem::take(&mut portfolio_signed_payload.signature);
    VerifyingKey::from_bytes(&receipt_public_key)
        .unwrap()
        .verify(
            &serde_json::to_vec(&portfolio_signed_payload).unwrap(),
            &Signature::from_slice(&portfolio_signature).unwrap(),
        )
        .unwrap();
    portfolio_signed_payload.command_commitment_sha256 = Some([0xff; 32]);
    assert!(VerifyingKey::from_bytes(&receipt_public_key)
        .unwrap()
        .verify(
            &serde_json::to_vec(&portfolio_signed_payload).unwrap(),
            &Signature::from_slice(&portfolio_signature).unwrap(),
        )
        .is_err());
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
    assert_eq!(response.receipt.protocol_version, "layrs.v2");
    assert_eq!(response.receipt.publication_eligible, Some(true));
    assert!(response.encrypted_record.is_some());
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

#[test]
fn registration_receipt_is_publication_eligible_private_and_identity_unique() {
    let receipt_signer = ReceiptSigner::generate([71u8; 48]);
    let receipt_public_key = receipt_signer.verifying_key();
    let mut core = PrivateTradingCore::new(JournalKey::from_bytes([72u8; 32]), receipt_signer);
    let identity = [73u8; 32];
    let first_key = SigningKey::from_bytes(&[74u8; 32]);
    let second_key = SigningKey::from_bytes(&[75u8; 32]);

    let first = core
        .register_session(
            "registration:first".into(),
            "session:registration:first".into(),
            identity,
            first_key.verifying_key().to_bytes(),
            20_000,
            1_000,
        )
        .unwrap();
    let second = core
        .register_session(
            "registration:second".into(),
            "session:registration:second".into(),
            identity,
            second_key.verifying_key().to_bytes(),
            20_000,
            1_100,
        )
        .unwrap();

    assert_eq!(first.receipt.protocol_version, "layrs.v2");
    assert_eq!(first.receipt.publication_eligible, Some(true));
    assert!(first.receipt.command_commitment_sha256.is_some());
    let first_evidence = first.registration_evidence.unwrap();
    let second_evidence = second.registration_evidence.unwrap();
    assert_ne!(first_evidence.commitment, second_evidence.commitment);
    assert_eq!(first_evidence.nullifier, second_evidence.nullifier);
    assert_eq!(first.evidence_commitment, Some(first_evidence.commitment));
    assert!(!serde_json::to_vec(&first_evidence)
        .unwrap()
        .windows(identity.len())
        .any(|window| window == identity));

    let mut signed_payload = first.receipt.clone();
    let signature = std::mem::take(&mut signed_payload.signature);
    VerifyingKey::from_bytes(&receipt_public_key)
        .unwrap()
        .verify(
            &serde_json::to_vec(&signed_payload).unwrap(),
            &Signature::from_slice(&signature).unwrap(),
        )
        .unwrap();
}

#[test]
fn private_user_transfer_is_registered_atomic_available_only_and_replay_safe() {
    let sender_key = SigningKey::from_bytes(&[81u8; 32]);
    let recipient_key = SigningKey::from_bytes(&[82u8; 32]);
    let journal_key = [83u8; 32];
    let sender_identity = [84u8; 32];
    let recipient_identity = [85u8; 32];
    let sender_private_user = derived_private_user(journal_key, sender_identity);
    let recipient_private_user = derived_private_user(journal_key, recipient_identity);
    let mut core = PrivateTradingCore::new(
        JournalKey::from_bytes(journal_key),
        ReceiptSigner::generate([86u8; 48]),
    );

    core.register_session(
        "sys:session:transfer:sender".into(),
        "session:transfer:sender".into(),
        sender_identity,
        sender_key.verifying_key().to_bytes(),
        20_000,
        1_000,
    )
    .unwrap();
    core.register_session(
        "sys:session:transfer:recipient".into(),
        "session:transfer:recipient".into(),
        recipient_identity,
        recipient_key.verifying_key().to_bytes(),
        20_000,
        1_010,
    )
    .unwrap();
    assert!(!core.transfer_account_status(sender_identity).registered);
    let sender_account = core
        .register_transfer_account("sys:transfer-account:sender".into(), sender_identity, 1_020)
        .unwrap()
        .transfer_account
        .unwrap();
    let recipient_account = core
        .register_transfer_account(
            "sys:transfer-account:recipient".into(),
            recipient_identity,
            1_030,
        )
        .unwrap()
        .transfer_account
        .unwrap();
    assert_eq!(
        core.transfer_account_status(sender_identity)
            .transfer_account,
        sender_account
    );
    assert!(core.transfer_account_status(sender_identity).registered);
    assert!(core.transfer_account_status(recipient_identity).registered);
    assert!(sender_account.starts_with("layrs_"));
    assert_ne!(sender_account, recipient_account);

    core.apply_user_external_flow(
        "sys:deposit:transfer:sender".into(),
        sender_identity,
        "USDC".into(),
        AccountBucket::UserAvailable,
        10_000_000,
        ExternalFlowDirection::Inflow,
        [87u8; 32],
        1_040,
    )
    .unwrap();
    // Reserve part of the balance. A private transfer must never consume it.
    execute_signed_response(
        &mut core,
        &sender_key,
        "session:transfer:sender",
        1,
        "cmd:transfer:reserve",
        UserCommandAction::RequestWithdrawal {
            withdrawal_id: uuid::Uuid::from_u128(88),
            chain: "base".into(),
            asset: "USDC".into(),
            amount_atomic: 2_000_000,
            destination: "0x1111111111111111111111111111111111111111".into(),
        },
        1_050,
    );

    let transfer_id = uuid::Uuid::from_u128(89);
    let action = UserCommandAction::TransferFunds {
        transfer_id,
        recipient_account: recipient_account.clone(),
        asset: "USDC".into(),
        amount_atomic: 6_000_000,
    };
    let command_id = "cmd:transfer:success";
    let idempotency_key = format!("idem:{command_id}");
    let request_hash = command_request_hash(command_id, &idempotency_key, &action).unwrap();
    let request = SessionRequest {
        session_id: "session:transfer:sender".into(),
        sequence: 2,
        issued_at_millis: 1_060,
        expires_at_millis: 2_900,
        request_hash,
    };
    let command = UserCommand {
        command_id: command_id.into(),
        idempotency_key,
        session: SignedSessionRequest {
            signature: sender_key
                .sign(&signing_payload(&request))
                .to_bytes()
                .to_vec(),
            request,
        },
        action,
    };
    let first = core.execute(command.clone(), 1_060).unwrap();
    let replay = core.execute(command, 1_061).unwrap();
    assert_eq!(first, replay);
    assert!(first.receipt.publication_eligible == Some(true));
    assert!(matches!(
        first.result,
        CommandResult::FundsTransferred {
            transfer_id: id,
            amount_atomic: 6_000_000,
            ..
        } if id == transfer_id
    ));
    assert_eq!(
        core.balance(&AccountKey::new(
            &sender_private_user,
            AccountBucket::UserAvailable,
            "USDC"
        )),
        2_000_000
    );
    assert_eq!(
        core.balance(&AccountKey::new(
            &sender_private_user,
            AccountBucket::UserWithdrawalHold,
            "USDC"
        )),
        2_000_000
    );
    assert_eq!(
        core.balance(&AccountKey::new(
            &recipient_private_user,
            AccountBucket::UserAvailable,
            "USDC"
        )),
        6_000_000
    );

    let root_before_failure = core.state_root();
    let insufficient = execute_signed_result(
        &mut core,
        &sender_key,
        "session:transfer:sender",
        3,
        "cmd:transfer:insufficient",
        UserCommandAction::TransferFunds {
            transfer_id: uuid::Uuid::from_u128(90),
            recipient_account: recipient_account.clone(),
            asset: "USDC".into(),
            amount_atomic: 2_000_001,
        },
        1_070,
    );
    assert_eq!(insufficient.unwrap_err(), CoreError::InsufficientBalance);
    assert_eq!(core.state_root(), root_before_failure);

    let self_transfer = execute_signed_result(
        &mut core,
        &sender_key,
        "session:transfer:sender",
        3,
        "cmd:transfer:self",
        UserCommandAction::TransferFunds {
            transfer_id: uuid::Uuid::from_u128(91),
            recipient_account: sender_account,
            asset: "USDC".into(),
            amount_atomic: 1,
        },
        1_080,
    );
    assert_eq!(
        self_transfer.unwrap_err(),
        CoreError::InvalidOrder("sender and recipient must be different".into())
    );

    let unknown = execute_signed_result(
        &mut core,
        &sender_key,
        "session:transfer:sender",
        3,
        "cmd:transfer:unknown",
        UserCommandAction::TransferFunds {
            transfer_id: uuid::Uuid::from_u128(92),
            recipient_account: format!("layrs_{}", "00".repeat(32)),
            asset: "USDC".into(),
            amount_atomic: 1,
        },
        1_090,
    );
    assert_eq!(
        unknown.unwrap_err(),
        CoreError::InvalidOrder("unknown transfer account".into())
    );

    for (id, suffix, recipient, asset, amount) in [
        (93, "zero", recipient_account.clone(), "USDC".to_string(), 0),
        (
            94,
            "asset",
            recipient_account.clone(),
            "WETH".to_string(),
            1,
        ),
        (
            95,
            "canonical",
            recipient_account.to_uppercase(),
            "USDC".to_string(),
            1,
        ),
    ] {
        let root = core.state_root();
        let invalid = execute_signed_result(
            &mut core,
            &sender_key,
            "session:transfer:sender",
            3,
            &format!("cmd:transfer:{suffix}"),
            UserCommandAction::TransferFunds {
                transfer_id: uuid::Uuid::from_u128(id),
                recipient_account: recipient,
                asset,
                amount_atomic: amount,
            },
            1_100,
        );
        assert_eq!(
            invalid.unwrap_err(),
            CoreError::InvalidOrder("invalid private transfer request".into())
        );
        assert_eq!(core.state_root(), root);
    }

    let snapshot = core.export_encrypted_snapshot().unwrap();
    let restored = PrivateTradingCore::restore_encrypted_snapshot(
        JournalKey::from_bytes(journal_key),
        ReceiptSigner::generate([93u8; 48]),
        &snapshot,
        snapshot.sequence,
    )
    .unwrap();
    assert!(restored.transfer_account_status(sender_identity).registered);
    assert!(
        restored
            .transfer_account_status(recipient_identity)
            .registered
    );
    assert_eq!(restored.state_root(), core.state_root());
    assert_eq!(
        restored.balance(&AccountKey::new(
            &recipient_private_user,
            AccountBucket::UserAvailable,
            "USDC"
        )),
        6_000_000
    );
}

#[test]
fn base_zen_bridge_back_withdrawal_is_reserved_and_authorized_by_the_enclave() {
    let user = SigningKey::from_bytes(&[42u8; 32]);
    let journal_key = [43u8; 32];
    let identity_commitment = [44u8; 32];
    let private_user = derived_private_user(journal_key, identity_commitment);
    let mut core = PrivateTradingCore::new(
        JournalKey::from_bytes(journal_key),
        ReceiptSigner::generate([45u8; 48]),
    );
    core.register_session(
        "sys:session:base-zen-withdrawal".into(),
        "session:base-zen-withdrawal".into(),
        identity_commitment,
        user.verifying_key().to_bytes(),
        10_000,
        1_000,
    )
    .unwrap();
    core.apply_user_external_flow(
        "sys:deposit:base-zen-withdrawal".into(),
        identity_commitment,
        "ZEN".into(),
        AccountBucket::UserAvailable,
        1_000_000_000_000_000_000,
        ExternalFlowDirection::Inflow,
        [46u8; 32],
        1_100,
    )
    .unwrap();

    let response = execute_signed_response(
        &mut core,
        &user,
        "session:base-zen-withdrawal",
        1,
        "cmd:base-zen-withdrawal",
        UserCommandAction::RequestWithdrawal {
            withdrawal_id: uuid::Uuid::from_u128(47),
            chain: "base".into(),
            asset: "ZEN".into(),
            amount_atomic: 1_000_000_000_000_000_000,
            destination: "0x1111111111111111111111111111111111111111".into(),
        },
        1_200,
    );
    let authorization = response.withdrawal_authorization.unwrap();

    assert_eq!(authorization.intent.chain, "base");
    assert_eq!(authorization.intent.asset, "ZEN");
    core.validate_withdrawal_intent(&authorization.intent)
        .unwrap();
    assert_eq!(
        core.balance(&AccountKey::new(
            &private_user,
            AccountBucket::UserAvailable,
            "ZEN"
        )),
        0
    );
    assert_eq!(
        core.balance(&AccountKey::new(
            &private_user,
            AccountBucket::UserWithdrawalHold,
            "ZEN"
        )),
        1_000_000_000_000_000_000
    );
}

#[test]
fn private_rewards_accrue_cumulatively_and_authorize_only_the_bound_account() {
    let user = SigningKey::from_bytes(&[41u8; 32]);
    let journal_key = [42u8; 32];
    let identity_commitment = [43u8; 32];
    let mut core = PrivateTradingCore::new(
        JournalKey::from_bytes(journal_key),
        ReceiptSigner::generate([44u8; 48]),
    );
    core.register_session(
        "sys:session:rewards".into(),
        "session:rewards".into(),
        identity_commitment,
        user.verifying_key().to_bytes(),
        10_000,
        1_000,
    )
    .unwrap();
    let reward_token = "0x0000000000000000000000000000000000000011";
    core.accrue_private_reward(
        "sys:reward:one".into(),
        identity_commitment,
        "base".into(),
        reward_token.into(),
        100,
        [45u8; 32],
        1_100,
    )
    .unwrap();
    core.accrue_private_reward(
        "sys:reward:two".into(),
        identity_commitment,
        "base".into(),
        reward_token.into(),
        25,
        [46u8; 32],
        1_200,
    )
    .unwrap();

    match execute_signed(
        &mut core,
        &user,
        "session:rewards",
        1,
        "cmd:rewards",
        UserCommandAction::Rewards,
        1_300,
    ) {
        CommandResult::Rewards { entitlements } => {
            assert_eq!(entitlements.len(), 1);
            assert_eq!(entitlements[0].cumulative_amount_atomic, "125");
            assert!(entitlements[0].claim_account.is_none());
        }
        _ => panic!("expected private rewards"),
    }

    let account = "0x0000000000000000000000000000000000000022";
    let recipient = "0x0000000000000000000000000000000000000033";
    let authorized = execute_signed_response(
        &mut core,
        &user,
        "session:rewards",
        2,
        "cmd:reward-claim",
        UserCommandAction::RequestRewardClaim {
            chain: "base".into(),
            account: account.into(),
            recipient: recipient.into(),
            reward_token: reward_token.into(),
            deadline_seconds: 900,
        },
        1_400,
    );
    match authorized.result {
        CommandResult::RewardClaimAuthorized { intent } => {
            assert_eq!(intent.account, account);
            assert_eq!(intent.recipient, recipient);
            assert_eq!(intent.cumulative_amount_atomic, "125");
            assert_ne!(intent.context_hash, [0u8; 32]);
        }
        _ => panic!("expected reward claim authorization"),
    }
    assert!(authorized.reward_claim_authorization.is_none());

    let changed_account = execute_signed_result(
        &mut core,
        &user,
        "session:rewards",
        3,
        "cmd:reward-claim-redirect",
        UserCommandAction::RequestRewardClaim {
            chain: "base".into(),
            account: "0x0000000000000000000000000000000000000044".into(),
            recipient: recipient.into(),
            reward_token: reward_token.into(),
            deadline_seconds: 901,
        },
        1_500,
    );
    assert!(matches!(changed_account, Err(CoreError::InvalidOrder(_))));

    let snapshot = core.export_encrypted_snapshot().unwrap();
    let mut restored = PrivateTradingCore::restore_encrypted_snapshot(
        JournalKey::from_bytes(journal_key),
        ReceiptSigner::generate([44u8; 48]),
        &snapshot,
        snapshot.sequence,
    )
    .unwrap();
    match execute_signed(
        &mut restored,
        &user,
        "session:rewards",
        3,
        "cmd:rewards-restored",
        UserCommandAction::Rewards,
        1_600,
    ) {
        CommandResult::Rewards { entitlements } => {
            assert_eq!(entitlements[0].claim_account.as_deref(), Some(account));
            assert_eq!(entitlements[0].cumulative_amount_atomic, "125");
        }
        _ => panic!("expected restored private rewards"),
    }
}

#[allow(clippy::too_many_arguments)]
#[test]
fn expired_market_rejects_position_close_but_allows_unfilled_hold_release() {
    let alice = SigningKey::from_bytes(&[121u8; 32]);
    let bob = SigningKey::from_bytes(&[122u8; 32]);
    let journal_key = [123u8; 32];
    let mut core = PrivateTradingCore::new(
        JournalKey::from_bytes(journal_key),
        ReceiptSigner::generate([124u8; 48]),
    );
    let market_id = "layrs:v3:ZEN:15m:2000";
    core.register_market(
        "sys:market:resolution-guard".into(),
        MarketConfig {
            market_id: market_id.into(),
            settlement_asset: "ZEN".into(),
            settlement_decimals: 18,
            public_settlement_chain: Some("horizen".into()),
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
            fee_profile_id: FeeProfileId::LegacyProfitV1,
            execution: MarketExecution::NativeClob,
        },
        800,
    )
    .unwrap();

    let alice_commitment = [125u8; 32];
    let bob_commitment = [126u8; 32];
    for (label, key, commitment) in [
        ("alice", &alice, alice_commitment),
        ("bob", &bob, bob_commitment),
    ] {
        core.register_session(
            format!("sys:session:resolution-guard:{label}"),
            format!("session:resolution-guard:{label}"),
            commitment,
            key.verifying_key().to_bytes(),
            3_000,
            850,
        )
        .unwrap();
        core.apply_user_external_flow(
            format!("sys:deposit:resolution-guard:{label}"),
            commitment,
            "ZEN".into(),
            AccountBucket::UserAvailable,
            1_000_000_000_000_000_000,
            ExternalFlowDirection::Inflow,
            [label.as_bytes()[0]; 32],
            875,
        )
        .unwrap();
    }

    execute_signed(
        &mut core,
        &bob,
        "session:resolution-guard:bob",
        1,
        "cmd:resolution-guard:mint",
        UserCommandAction::CompleteSet {
            market_id: market_id.into(),
            quantity_micros: 1_000_000,
            direction: CompleteSetDirection::Mint,
        },
        1_000,
    );
    let ask_response = execute_signed_response(
        &mut core,
        &bob,
        "session:resolution-guard:bob",
        2,
        "cmd:resolution-guard:ask",
        UserCommandAction::SubmitOrder {
            order: BookOrder::new(
                "ignored",
                market_id,
                Outcome::Up,
                OrderAction::Sell,
                500_000,
                1_000_000,
                TimeInForce::Gtc,
                None,
            ),
        },
        1_100,
    );
    let filled_ask_id = match ask_response.result {
        CommandResult::Order { result } => result.accepted_order.unwrap().order_id,
        _ => panic!("expected resting ask response"),
    };
    execute_signed(
        &mut core,
        &alice,
        "session:resolution-guard:alice",
        1,
        "cmd:resolution-guard:buy",
        UserCommandAction::SubmitOrder {
            order: BookOrder::new(
                "ignored",
                market_id,
                Outcome::Up,
                OrderAction::Buy,
                500_000,
                1_000_000,
                TimeInForce::Fak,
                None,
            ),
        },
        1_200,
    );
    let resting_response = execute_signed_response(
        &mut core,
        &alice,
        "session:resolution-guard:alice",
        2,
        "cmd:resolution-guard:resting",
        UserCommandAction::SubmitOrder {
            order: BookOrder::new(
                "ignored",
                market_id,
                Outcome::Down,
                OrderAction::Buy,
                100_000,
                1_000_000,
                TimeInForce::Gtc,
                None,
            ),
        },
        1_300,
    );
    let resting_order = match resting_response.result {
        CommandResult::Order { result } => result.accepted_order.unwrap(),
        _ => panic!("expected resting order response"),
    };
    assert_eq!(resting_order.status, OrderStatus::Open);

    let alice_owner = derived_private_user(journal_key, alice_commitment);
    let up_position = AccountKey::position(
        &alice_owner,
        format!("CLAIM:{market_id}:UP"),
        market_id,
        "UP",
    );
    assert_eq!(core.balance(&up_position), 1_000_000);

    let cancel_filled_trade = execute_signed_result(
        &mut core,
        &bob,
        "session:resolution-guard:bob",
        3,
        "cmd:resolution-guard:cancel-filled",
        UserCommandAction::CancelOrder {
            market_id: market_id.into(),
            order_id: filled_ask_id,
        },
        2_100,
    );
    assert!(matches!(
        cancel_filled_trade.unwrap_err(),
        CoreError::InvalidOrder(message) if message == "order is not cancellable"
    ));

    let close_after_expiry = execute_signed_result(
        &mut core,
        &alice,
        "session:resolution-guard:alice",
        3,
        "cmd:resolution-guard:late-close",
        UserCommandAction::SubmitOrder {
            order: BookOrder::new(
                "ignored",
                market_id,
                Outcome::Up,
                OrderAction::Sell,
                500_000,
                1_000_000,
                TimeInForce::Fak,
                None,
            ),
        },
        2_100,
    );
    assert_eq!(
        close_after_expiry.unwrap_err(),
        CoreError::InvalidOrder("market is not open".into())
    );
    assert_eq!(core.balance(&up_position), 1_000_000);

    let cancel_response = execute_signed_response(
        &mut core,
        &alice,
        "session:resolution-guard:alice",
        3,
        "cmd:resolution-guard:release-unfilled",
        UserCommandAction::CancelOrder {
            market_id: market_id.into(),
            order_id: resting_order.order_id,
        },
        2_100,
    );
    assert!(matches!(
        cancel_response.result,
        CommandResult::Cancelled { .. }
    ));
    assert_eq!(core.balance(&up_position), 1_000_000);
}

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
