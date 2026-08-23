use clob_service::private_core::{
    command_request_hash, polymarket_resolution_signing_payload, resolution_signing_payload,
    signing_payload, AccountBucket, AccountKey, BookOrder, BootstrapPreparedVenueOrder,
    BoundaryEvidence, CancelAllOrdersFilter, CommandReceiptState, CommandResult,
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
fn delegated_portfolio_snapshot_is_strictly_identity_scoped() {
    let mut core = PrivateTradingCore::new(
        JournalKey::from_bytes([211u8; 32]),
        ReceiptSigner::generate([212u8; 48]),
    );
    let alice = [1u8; 32];
    let bob = [2u8; 32];
    core.apply_user_external_flow(
        "delegated-read:alice".into(),
        alice,
        "USDC".into(),
        AccountBucket::UserAvailable,
        5_000_000,
        ExternalFlowDirection::Inflow,
        [3u8; 32],
        1_000,
    )
    .unwrap();
    core.apply_user_external_flow(
        "delegated-read:bob".into(),
        bob,
        "USDC".into(),
        AccountBucket::UserAvailable,
        9_000_000,
        ExternalFlowDirection::Inflow,
        [4u8; 32],
        1_001,
    )
    .unwrap();

    let alice_view = core.portfolio_snapshot_for_identity(alice, 2_000);
    let bob_view = core.portfolio_snapshot_for_identity(bob, 2_000);
    assert_eq!(alice_view.balances.len(), 1);
    assert_eq!(alice_view.balances[0].amount_atomic, "5000000");
    assert_eq!(bob_view.balances.len(), 1);
    assert_eq!(bob_view.balances[0].amount_atomic, "9000000");
    assert_ne!(alice_view.balances, bob_view.balances);
    assert!(alice_view.positions.is_empty() && alice_view.orders.is_empty());
    assert!(bob_view.positions.is_empty() && bob_view.orders.is_empty());
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
fn cancelled_then_replaced_order_receives_fresh_deterministic_priority() {
    let mut book = PriceTimeBook::default();
    let market_id = "layrs:v5:BTC:USDC:15m:replace-priority";
    let old_id = uuid::Uuid::from_u128(1);
    let peer_id = uuid::Uuid::from_u128(2);
    let replacement_id = uuid::Uuid::from_u128(3);
    for (order_id, owner, now) in [(old_id, "usr_a", 1_000), (peer_id, "usr_b", 1_100)] {
        book.submit(
            BookOrder::with_id(
                order_id,
                owner,
                market_id,
                Outcome::Up,
                OrderAction::Buy,
                400_000,
                1_000_000,
                TimeInForce::Gtc,
                None,
            ),
            now,
        )
        .unwrap();
    }
    book.cancel(old_id, "usr_a", 1_200).unwrap();
    book.submit(
        BookOrder::with_id(
            replacement_id,
            "usr_a",
            market_id,
            Outcome::Up,
            OrderAction::Buy,
            400_000,
            1_000_000,
            TimeInForce::Gtc,
            None,
        ),
        1_200,
    )
    .unwrap();

    let fill = book
        .submit(
            BookOrder::with_id(
                uuid::Uuid::from_u128(4),
                "usr_c",
                market_id,
                Outcome::Up,
                OrderAction::Sell,
                400_000,
                1_000_000,
                TimeInForce::Fak,
                None,
            ),
            1_300,
        )
        .unwrap();
    assert_eq!(fill.fills.len(), 1);
    assert_eq!(fill.fills[0].maker_order_id, peer_id);
    assert_eq!(book.order(old_id).unwrap().status, OrderStatus::Cancelled);
    assert_eq!(
        book.order(replacement_id).unwrap().status,
        OrderStatus::Open
    );
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
    assert_eq!(
        execute_signed_result(
            &mut core,
            &bob,
            "session:2",
            1,
            "cmd:frozen-withdrawal",
            UserCommandAction::RequestWithdrawal {
                withdrawal_id: uuid::Uuid::from_u128(9001),
                chain: "horizen".into(),
                asset: "ZEN".into(),
                amount_atomic: 1,
                destination: "0x1111111111111111111111111111111111111111".into(),
            },
            960,
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
    let resting_order = execute_signed_response(
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
    assert!(resting_order.audit_fills.is_empty());
    assert_eq!(resting_order.task_qualifications.len(), 1);
    assert_eq!(
        resting_order.task_qualifications[0]
            .statement
            .market_id
            .as_deref(),
        Some(market_id)
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
    assert_eq!(fill_response.receipt.protocol_version, "layrs.v3");
    assert!(fill_response.receipt.result_commitment_sha256.is_some());
    assert_eq!(fill_response.receipt.journal_committed, Some(true));
    assert_eq!(fill_response.receipt_state, CommandReceiptState::Filled);
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
    assert_eq!(task.statement.market_id.as_deref(), Some(market_id));
    assert_eq!(task.statement.settlement_asset, "ZEN");
    assert_eq!(task.statement.asset_notional_micros, 400_000);
    assert_eq!(task.statement.filled_quantity_micros, 1_000_000);
    assert_eq!(task.receipt_id, fill_response.receipt.receipt_id);
    let serialized_task = serde_json::to_string(task).unwrap();
    for private_value in ["usr_", "BUY", "UP"] {
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

    core.set_trading_freeze("sys:freeze:cancel-only".into(), true, [93u8; 32], 1_175)
        .unwrap();
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
    core.set_trading_freeze("sys:unfreeze:cancel-only".into(), false, [94u8; 32], 1_225)
        .unwrap();
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
        // The stale close above used 1_340 but failed. A successful command at
        // 1_335 proves failed execution did not burn the durable time fence.
        1_335,
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

    // A committed SubmitOrder response may be lost between the enclave and
    // API. Its bounded recovery capsule preserves the exact private semantic
    // result and receipt across restore without applying the fill, fee or
    // position transfer a second time.
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
    let recovered = lost_response_retry.expect("recover committed submit result");
    assert_eq!(recovered.result, sell_taker_fill.result);
    assert_eq!(recovered.receipt, sell_taker_fill.receipt);
    assert_eq!(recovered.audit_fills, sell_taker_fill.audit_fills);
    assert_eq!(
        recovered.task_qualifications,
        sell_taker_fill.task_qualifications
    );
    assert!(recovered.encrypted_record.is_none());
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
            1_000 + market_index as i64 * 300,
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
            1_025 + market_index as i64 * 300,
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

    assert!(core.bootstrap_prepared_venue_order(execution_id).is_err());
    let exact_body = "{".to_string() + &"x".repeat(80) + "}";
    core.mark_bootstrap_venue_intent_durable(
        "sys:venue-intent:47".into(),
        execution_id,
        BootstrapPreparedVenueOrder {
            deterministic_order_id: format!("0x{}", "ab".repeat(32)),
            request_body_sha256: Sha256::digest(exact_body.as_bytes()).into(),
            exact_request_body: exact_body.clone(),
            credential_generation_sha256: [50u8; 32],
        },
        1_140,
    )
    .unwrap();
    let root_before_unauthorized_submit = core.state_root();
    assert!(core
        .mark_bootstrap_submitted(
            "sys:venue-submitted-before-attempt:47".into(),
            execution_id,
            format!("0x{}", "ab".repeat(32)),
            1_142,
        )
        .is_err());
    assert_eq!(core.state_root(), root_before_unauthorized_submit);
    core.authorize_bootstrap_submission_attempt("sys:venue-attempt:47".into(), execution_id, 1_145)
        .unwrap();
    let prepared = core.bootstrap_prepared_venue_order(execution_id).unwrap();
    assert_eq!(prepared.exact_request_body, exact_body);
    assert_eq!(prepared.credential_generation_sha256, [50u8; 32]);
    core.mark_bootstrap_submitted(
        "sys:venue-submitted:47".into(),
        execution_id,
        format!("0x{}", "ab".repeat(32)),
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
    let public_receipt = serde_json::to_string(&response.receipt).unwrap();
    assert!(!public_receipt.contains("0x1111111111111111111111111111111111111111"));
    assert!(!public_receipt.contains(&hex::encode(identity_commitment)));
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

    let release_snapshot = core.export_encrypted_snapshot().unwrap();
    let mut release_restored = PrivateTradingCore::restore_encrypted_snapshot(
        JournalKey::from_bytes(journal_key),
        ReceiptSigner::generate([32u8; 48]),
        &release_snapshot,
        0,
    )
    .unwrap();
    assert_eq!(
        release_restored
            .release_user_withdrawal(
                "sys:withdrawal-release:35:retry".into(),
                identity_commitment,
                "USDC".into(),
                10_000_000,
                [36u8; 32],
                1_410,
            )
            .unwrap_err(),
        clob_service::private_core::CoreError::DuplicateCommand
    );

    execute_signed_response(
        &mut core,
        &user,
        "session:withdrawal",
        3,
        "cmd:withdrawal-confirmed",
        UserCommandAction::RequestWithdrawal {
            withdrawal_id: uuid::Uuid::from_u128(36),
            chain: "base".into(),
            asset: "USDC".into(),
            amount_atomic: 10_000_000,
            destination: "0x2222222222222222222222222222222222222222".into(),
        },
        1_500,
    );
    core.apply_user_external_flow(
        "withdrawal-final:36".into(),
        identity_commitment,
        "USDC".into(),
        AccountBucket::UserWithdrawalHold,
        10_000_000,
        ExternalFlowDirection::Outflow,
        [38u8; 32],
        1_600,
    )
    .unwrap();
    assert_eq!(
        core.balance(&AccountKey::new(
            &private_user,
            AccountBucket::UserWithdrawalHold,
            "USDC"
        )),
        0
    );
    assert_eq!(
        core.balance(&AccountKey::new("layrs", AccountBucket::PoolCash, "USDC")),
        40_000_000
    );
    let confirmed_snapshot = core.export_encrypted_snapshot().unwrap();
    let mut confirmed_restored = PrivateTradingCore::restore_encrypted_snapshot(
        JournalKey::from_bytes(journal_key),
        ReceiptSigner::generate([32u8; 48]),
        &confirmed_snapshot,
        0,
    )
    .unwrap();
    assert_eq!(
        confirmed_restored
            .apply_user_external_flow(
                "withdrawal-final:36:retry".into(),
                identity_commitment,
                "USDC".into(),
                AccountBucket::UserWithdrawalHold,
                10_000_000,
                ExternalFlowDirection::Outflow,
                [38u8; 32],
                1_610,
            )
            .unwrap_err(),
        clob_service::private_core::CoreError::DuplicateCommand
    );
}

#[test]
fn committed_withdrawal_authorization_recovers_exactly_after_restart_and_expiry() {
    let user = SigningKey::from_bytes(&[121u8; 32]);
    let receipt_signer = ReceiptSigner::generate([122u8; 48]);
    let journal_key = [123u8; 32];
    let identity_commitment = [124u8; 32];
    let private_user = derived_private_user(journal_key, identity_commitment);
    let session_id = "session:withdrawal-restart";
    let withdrawal_id = uuid::Uuid::from_u128(125);
    let mut core =
        PrivateTradingCore::new(JournalKey::from_bytes(journal_key), receipt_signer.clone());
    core.register_session(
        "sys:session:withdrawal-restart".into(),
        session_id.into(),
        identity_commitment,
        user.verifying_key().to_bytes(),
        4_000,
        1_000,
    )
    .unwrap();
    core.apply_user_external_flow(
        "sys:deposit:withdrawal-restart".into(),
        identity_commitment,
        "USDC".into(),
        AccountBucket::UserAvailable,
        25_000_000,
        ExternalFlowDirection::Inflow,
        [126u8; 32],
        1_100,
    )
    .unwrap();

    let mut committed = execute_signed_response(
        &mut core,
        &user,
        session_id,
        1,
        "cmd:withdrawal-restart",
        UserCommandAction::RequestWithdrawal {
            withdrawal_id,
            chain: "base".into(),
            asset: "USDC".into(),
            amount_atomic: 13_799_435,
            destination: "0x1111111111111111111111111111111111111111".into(),
        },
        1_200,
    );
    let sequence = core.sequence();
    let state_root = core.state_root();
    let terminal_record = committed.encrypted_record.clone().unwrap();
    let snapshot = core.export_encrypted_snapshot().unwrap();

    let restored = PrivateTradingCore::restore_encrypted_snapshot(
        JournalKey::from_bytes(journal_key),
        receipt_signer,
        &snapshot,
        sequence,
    )
    .unwrap();
    // Recovery is deliberately independent of the current clock/session and
    // authorization expiry because it returns only the already-signed result.
    let recovered = restored
        .recover_withdrawal_authorization(withdrawal_id, session_id)
        .unwrap()
        .unwrap();
    // Journal ciphertext is already durably archived outside the enclave and
    // is intentionally not duplicated in the bounded snapshot capsule.
    committed.encrypted_record = None;
    assert_eq!(recovered, committed);
    assert_eq!(restored.sequence(), sequence);
    assert_eq!(restored.state_root(), state_root);
    assert_eq!(
        restored.balance(&AccountKey::new(
            &private_user,
            AccountBucket::UserAvailable,
            "USDC"
        )),
        11_200_565
    );
    assert_eq!(
        restored.balance(&AccountKey::new(
            &private_user,
            AccountBucket::UserWithdrawalHold,
            "USDC"
        )),
        13_799_435
    );
    assert!(restored
        .recover_withdrawal_authorization(withdrawal_id, "session:wrong-owner")
        .unwrap()
        .is_none());
    assert!(restored
        .recover_withdrawal_authorization(uuid::Uuid::from_u128(999), session_id)
        .unwrap()
        .is_none());

    let journal_recovery = restored
        .recover_terminal_withdrawal_authorization(
            &terminal_record,
            withdrawal_id,
            session_id,
            1_000_000,
        )
        .unwrap();
    let journal_authorization = journal_recovery.withdrawal_authorization.unwrap();
    assert_eq!(
        journal_authorization.intent.protocol_version,
        "layrs.withdrawal-recovery.v1"
    );
    let proof = journal_authorization.intent.recovery_proof.unwrap();
    assert_eq!(
        proof.original_idempotency_key,
        "idem:cmd:withdrawal-restart"
    );
    assert_eq!(proof.terminal_enclave_sequence, sequence);
    assert_eq!(proof.terminal_state_root, state_root);
    assert_eq!(proof.terminal_journal_head, terminal_record.record_hash);
    assert_eq!(restored.sequence(), sequence);
    assert_eq!(restored.state_root(), state_root);

    let mut tampered_record = terminal_record.clone();
    tampered_record.ciphertext[0] ^= 1;
    assert_eq!(
        restored
            .recover_terminal_withdrawal_authorization(
                &tampered_record,
                withdrawal_id,
                session_id,
                1_000_000,
            )
            .unwrap_err(),
        CoreError::JournalChainMismatch
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
        [55u8; 32],
        "trader-reward-v1".into(),
        "TRADER_REWARD".into(),
        "layrs-fee-v2".into(),
        1,
        "LAYRS_FEE_V2".into(),
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
        [56u8; 32],
        "trader-reward-v1".into(),
        "TRADER_REWARD".into(),
        "layrs-fee-v2".into(),
        1,
        "LAYRS_FEE_V2".into(),
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
    let reward_claim_command = signed_user_command(
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
    let authorized = core.execute(reward_claim_command.clone(), 1_400).unwrap();
    let claim_intent = match &authorized.result {
        CommandResult::RewardClaimAuthorized { intent } => {
            assert_eq!(intent.account, account);
            assert_eq!(intent.recipient, recipient);
            assert_eq!(intent.cumulative_amount_atomic, "125");
            assert_ne!(intent.context_hash, [0u8; 32]);
            intent.clone()
        }
        _ => panic!("expected reward claim authorization"),
    };
    assert!(authorized.reward_claim_authorization.is_none());

    // The wrapper signs only after the financial core commits. The exact
    // signed response must be cached without another sequence/root mutation so
    // a dropped first response can be returned byte-for-byte on retry.
    let signed_authorization = clob_service::private_core::RewardClaimAuthorization {
        intent: claim_intent,
        chain_id: 8_453,
        distributor: "0x0000000000000000000000000000000000000055".into(),
        signer: "0x0000000000000000000000000000000000000066".into(),
        signature: vec![0x77; 65],
    };
    let root_before_authorization = core.state_root();
    core.attach_reward_claim_authorization(&reward_claim_command, signed_authorization.clone())
        .unwrap();
    assert_eq!(core.state_root(), root_before_authorization);
    let recovered = core
        .recover_exact_user_command(&reward_claim_command)
        .unwrap()
        .expect("exact reward claim retry");
    assert_eq!(
        recovered.reward_claim_authorization,
        Some(signed_authorization)
    );
    assert_eq!(
        recovered.receipt.enclave_sequence,
        authorized.receipt.enclave_sequence
    );

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
    // A scheduler may lose the first response after the enclave committed it.
    // Retrying under a new transport idempotency key must not double-accrue,
    // and an altered payload under the same evidence must fail closed.
    restored
        .accrue_private_reward(
            "sys:reward:lost-response-retry".into(),
            identity_commitment,
            "base".into(),
            reward_token.into(),
            100,
            [45u8; 32],
            [55u8; 32],
            "trader-reward-v1".into(),
            "TRADER_REWARD".into(),
            "layrs-fee-v2".into(),
            1,
            "LAYRS_FEE_V2".into(),
            1_550,
        )
        .unwrap();
    assert!(matches!(
        restored.accrue_private_reward(
            "sys:reward:conflicting-retry".into(),
            identity_commitment,
            "base".into(),
            reward_token.into(),
            101,
            [45u8; 32],
            [55u8; 32],
            "trader-reward-v1".into(),
            "TRADER_REWARD".into(),
            "layrs-fee-v2".into(),
            1,
            "LAYRS_FEE_V2".into(),
            1_560,
        ),
        Err(CoreError::InvalidOrder(message)) if message.contains("immutable accrual")
    ));
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

#[test]
fn api_order_creation_enforces_funded_hold_limits_tif_and_replay() {
    let user_key = SigningKey::from_bytes(&[101u8; 32]);
    let journal_key = [102u8; 32];
    let commitment = [103u8; 32];
    let owner = derived_private_user(journal_key, commitment);
    let market_id = "layrs:v5:BTC:USDC:15m:2000";
    let mut core = PrivateTradingCore::new(
        JournalKey::from_bytes(journal_key),
        ReceiptSigner::generate([104u8; 48]),
    );
    core.register_market(
        "sys:market:api-order".into(),
        MarketConfig {
            market_id: market_id.into(),
            settlement_asset: "USDC".into(),
            settlement_decimals: 6,
            public_settlement_chain: Some("horizen".into()),
            opens_at_millis: 900,
            closes_at_millis: 2_000,
            minimum_quantity_micros: 250_000,
            maximum_quantity_micros: 10_000_000,
            minimum_order_notional_micros: 250_000,
            maximum_order_notional_micros: 5_000_000,
            maximum_user_position_micros: 10_000_000,
            maximum_pending_bootstrap_notional_micros: 10_000_000,
            tick_size_micros: 10_000,
            oracle_feed_id: 9002,
            fee_profile_id: FeeProfileId::LegacyProfitV1,
            execution: MarketExecution::NativeClob,
        },
        800,
    )
    .unwrap();
    core.register_session(
        "sys:session:api-order".into(),
        "session:api-order".into(),
        commitment,
        user_key.verifying_key().to_bytes(),
        3_000,
        850,
    )
    .unwrap();
    core.apply_user_external_flow(
        "sys:deposit:api-order".into(),
        commitment,
        "USDC".into(),
        AccountBucket::UserAvailable,
        5_000_000,
        ExternalFlowDirection::Inflow,
        [105u8; 32],
        875,
    )
    .unwrap();

    let limit = UserCommandAction::SubmitOrder {
        order: BookOrder::new(
            "client-placeholder",
            market_id,
            Outcome::Up,
            OrderAction::Buy,
            400_000,
            2_500_000,
            TimeInForce::Gtc,
            None,
        ),
    };
    let first = execute_signed_response(
        &mut core,
        &user_key,
        "session:api-order",
        1,
        "cmd:api-limit",
        limit.clone(),
        1_000,
    );
    assert!(matches!(first.result, CommandResult::Order { .. }));
    let available = AccountKey::new(&owner, AccountBucket::UserAvailable, "USDC");
    let mut hold = AccountKey::new(&owner, AccountBucket::UserOrderHold, "USDC");
    hold.market_id = Some(market_id.into());
    hold.outcome = Some("UP".into());
    assert!(core.balance(&hold) >= 1_000_000);
    assert_eq!(core.balance(&available) + core.balance(&hold), 5_000_000);

    let committed_root = core.state_root();
    let replay = execute_signed_response(
        &mut core,
        &user_key,
        "session:api-order",
        1,
        "cmd:api-limit",
        limit,
        1_000,
    );
    assert_eq!(replay.receipt.state_root, first.receipt.state_root);
    assert_eq!(core.state_root(), committed_root);

    let protected = UserCommandAction::SubmitOrder {
        order: BookOrder::new(
            "client-placeholder",
            market_id,
            Outcome::Down,
            OrderAction::Buy,
            200_000,
            1_250_000,
            TimeInForce::Fak,
            None,
        ),
    };
    let before_protected = core.balance(&available);
    let result = execute_signed(
        &mut core,
        &user_key,
        "session:api-order",
        2,
        "cmd:api-protected",
        protected,
        1_100,
    );
    let CommandResult::Order { result } = result else {
        panic!("order result")
    };
    assert_eq!(result.cancelled_remainder_micros, 1_250_000);
    assert!(result.fills.is_empty());
    assert_eq!(core.balance(&available), before_protected);

    let invalid_root = core.state_root();
    let invalid = execute_signed_result(
        &mut core,
        &user_key,
        "session:api-order",
        3,
        "cmd:api-invalid-tif",
        UserCommandAction::SubmitOrder {
            order: BookOrder::new(
                "client-placeholder",
                market_id,
                Outcome::Up,
                OrderAction::Buy,
                400_000,
                1_000_000,
                TimeInForce::Gtd,
                None,
            ),
        },
        1_200,
    );
    assert!(matches!(invalid, Err(CoreError::InvalidOrder(_))));
    assert_eq!(core.state_root(), invalid_root);
}

#[test]
fn api_order_replacement_is_atomic_replay_safe_and_releases_exact_collateral() {
    let user_key = SigningKey::from_bytes(&[111u8; 32]);
    let journal_key = [112u8; 32];
    let commitment = [113u8; 32];
    let owner = derived_private_user(journal_key, commitment);
    let market_id = "layrs:v5:BTC:USDC:15m:3000";
    let mut core = PrivateTradingCore::new(
        JournalKey::from_bytes(journal_key),
        ReceiptSigner::generate([114u8; 48]),
    );
    core.register_market(
        "sys:market:replace-atomic".into(),
        MarketConfig {
            market_id: market_id.into(),
            settlement_asset: "USDC".into(),
            settlement_decimals: 6,
            public_settlement_chain: Some("horizen".into()),
            opens_at_millis: 900,
            closes_at_millis: 3_000,
            minimum_quantity_micros: 250_000,
            maximum_quantity_micros: 10_000_000,
            minimum_order_notional_micros: 250_000,
            maximum_order_notional_micros: 5_000_000,
            maximum_user_position_micros: 10_000_000,
            maximum_pending_bootstrap_notional_micros: 10_000_000,
            tick_size_micros: 10_000,
            oracle_feed_id: 9002,
            fee_profile_id: FeeProfileId::LegacyProfitV1,
            execution: MarketExecution::NativeClob,
        },
        800,
    )
    .unwrap();
    core.register_session(
        "sys:session:replace-atomic".into(),
        "session:replace-atomic".into(),
        commitment,
        user_key.verifying_key().to_bytes(),
        4_000,
        850,
    )
    .unwrap();
    core.apply_user_external_flow(
        "sys:deposit:replace-atomic".into(),
        commitment,
        "USDC".into(),
        AccountBucket::UserAvailable,
        5_000_000,
        ExternalFlowDirection::Inflow,
        [115u8; 32],
        875,
    )
    .unwrap();

    let original_response = execute_signed_response(
        &mut core,
        &user_key,
        "session:replace-atomic",
        1,
        "cmd:replace-original",
        UserCommandAction::SubmitOrder {
            order: BookOrder::new(
                "ignored",
                market_id,
                Outcome::Up,
                OrderAction::Buy,
                400_000,
                2_500_000,
                TimeInForce::Gtc,
                None,
            ),
        },
        1_000,
    );
    let original = match original_response.result {
        CommandResult::Order { result } => result.accepted_order.unwrap(),
        _ => panic!("expected original order"),
    };
    let available = AccountKey::new(&owner, AccountBucket::UserAvailable, "USDC");
    let mut hold = AccountKey::new(&owner, AccountBucket::UserOrderHold, "USDC");
    hold.market_id = Some(market_id.into());
    hold.outcome = Some("UP".into());
    let root_before_failure = core.state_root();
    let available_before_failure = core.balance(&available);
    let hold_before_failure = core.balance(&hold);

    let invalid = execute_signed_result(
        &mut core,
        &user_key,
        "session:replace-atomic",
        2,
        "cmd:replace-invalid",
        UserCommandAction::ReplaceOrder {
            market_id: market_id.into(),
            order_id: original.order_id,
            replacement: BookOrder::new(
                "ignored",
                market_id,
                Outcome::Up,
                OrderAction::Buy,
                400_000,
                20_000_000,
                TimeInForce::Gtc,
                None,
            ),
        },
        1_100,
    );
    assert!(matches!(invalid, Err(CoreError::InvalidOrder(_))));
    assert_eq!(core.state_root(), root_before_failure);
    assert_eq!(core.balance(&available), available_before_failure);
    assert_eq!(core.balance(&hold), hold_before_failure);

    let rejected_fok = execute_signed_result(
        &mut core,
        &user_key,
        "session:replace-atomic",
        2,
        "cmd:replace-rejected-fok",
        UserCommandAction::ReplaceOrder {
            market_id: market_id.into(),
            order_id: original.order_id,
            replacement: BookOrder::new(
                "ignored",
                market_id,
                Outcome::Up,
                OrderAction::Buy,
                500_000,
                1_000_000,
                TimeInForce::Fok,
                None,
            ),
        },
        1_150,
    );
    assert!(matches!(rejected_fok, Err(CoreError::InvalidOrder(_))));
    assert_eq!(core.state_root(), root_before_failure);
    assert_eq!(core.balance(&available), available_before_failure);
    assert_eq!(core.balance(&hold), hold_before_failure);

    let replacement = BookOrder::new(
        "ignored",
        market_id,
        Outcome::Up,
        OrderAction::Buy,
        500_000,
        1_000_000,
        TimeInForce::Gtc,
        None,
    );
    let action = UserCommandAction::ReplaceOrder {
        market_id: market_id.into(),
        order_id: original.order_id,
        replacement: replacement.clone(),
    };
    let replaced = execute_signed_response(
        &mut core,
        &user_key,
        "session:replace-atomic",
        2,
        "cmd:replace-success",
        action.clone(),
        1_200,
    );
    let (cancelled, accepted) = match &replaced.result {
        CommandResult::Replaced { cancelled, result } => {
            (cancelled, result.accepted_order.as_ref().unwrap())
        }
        _ => panic!("expected replacement result"),
    };
    assert_eq!(cancelled.order_id, original.order_id);
    assert_eq!(cancelled.status, OrderStatus::Cancelled);
    assert_eq!(accepted.order_id, replacement.order_id);
    assert_eq!(accepted.status, OrderStatus::Open);
    assert!(accepted.sequence > original.sequence);
    assert_eq!(core.balance(&available) + core.balance(&hold), 5_000_000);
    assert!(core.balance(&hold) < hold_before_failure);

    let committed_root = core.state_root();
    let available_after = core.balance(&available);
    let hold_after = core.balance(&hold);
    let replay = execute_signed_response(
        &mut core,
        &user_key,
        "session:replace-atomic",
        2,
        "cmd:replace-success",
        action,
        1_200,
    );
    assert_eq!(replay.receipt.state_root, replaced.receipt.state_root);
    assert_eq!(core.state_root(), committed_root);
    assert_eq!(core.balance(&available), available_after);
    assert_eq!(core.balance(&hold), hold_after);
}

#[test]
fn api_order_cancellation_bypasses_placement_freeze_and_releases_hold_once() {
    let user_key = SigningKey::from_bytes(&[121u8; 32]);
    let journal_key = [122u8; 32];
    let commitment = [123u8; 32];
    let owner = derived_private_user(journal_key, commitment);
    let market_id = "layrs:v5:BTC:USDC:15m:4000";
    let mut core = PrivateTradingCore::new(
        JournalKey::from_bytes(journal_key),
        ReceiptSigner::generate([124u8; 48]),
    );
    core.register_market(
        "sys:market:cancel-priority".into(),
        MarketConfig {
            market_id: market_id.into(),
            settlement_asset: "USDC".into(),
            settlement_decimals: 6,
            public_settlement_chain: Some("horizen".into()),
            opens_at_millis: 900,
            closes_at_millis: 4_000,
            minimum_quantity_micros: 250_000,
            maximum_quantity_micros: 10_000_000,
            minimum_order_notional_micros: 250_000,
            maximum_order_notional_micros: 5_000_000,
            maximum_user_position_micros: 10_000_000,
            maximum_pending_bootstrap_notional_micros: 10_000_000,
            tick_size_micros: 10_000,
            oracle_feed_id: 9002,
            fee_profile_id: FeeProfileId::LegacyProfitV1,
            execution: MarketExecution::NativeClob,
        },
        800,
    )
    .unwrap();
    core.register_session(
        "sys:session:cancel-priority".into(),
        "session:cancel-priority".into(),
        commitment,
        user_key.verifying_key().to_bytes(),
        5_000,
        850,
    )
    .unwrap();
    core.apply_user_external_flow(
        "sys:deposit:cancel-priority".into(),
        commitment,
        "USDC".into(),
        AccountBucket::UserAvailable,
        5_000_000,
        ExternalFlowDirection::Inflow,
        [125u8; 32],
        875,
    )
    .unwrap();

    let created = execute_signed_response(
        &mut core,
        &user_key,
        "session:cancel-priority",
        1,
        "cmd:cancel-priority-create",
        UserCommandAction::SubmitOrder {
            order: BookOrder::new(
                "ignored",
                market_id,
                Outcome::Up,
                OrderAction::Buy,
                400_000,
                2_500_000,
                TimeInForce::Gtc,
                None,
            ),
        },
        1_000,
    );
    let resting = match created.result {
        CommandResult::Order { result } => result.accepted_order.unwrap(),
        _ => panic!("expected resting order"),
    };
    let available = AccountKey::new(&owner, AccountBucket::UserAvailable, "USDC");
    let mut hold = AccountKey::new(&owner, AccountBucket::UserOrderHold, "USDC");
    hold.market_id = Some(market_id.into());
    hold.outcome = Some("UP".into());
    assert_eq!(core.balance(&available), 4_000_000);
    assert_eq!(core.balance(&hold), 1_000_000);

    core.set_trading_freeze(
        "sys:freeze:cancel-priority".into(),
        true,
        [126u8; 32],
        1_050,
    )
    .unwrap();
    let blocked = execute_signed_result(
        &mut core,
        &user_key,
        "session:cancel-priority",
        2,
        "cmd:cancel-priority-blocked-placement",
        UserCommandAction::SubmitOrder {
            order: BookOrder::new(
                "ignored",
                market_id,
                Outcome::Down,
                OrderAction::Buy,
                400_000,
                1_000_000,
                TimeInForce::Gtc,
                None,
            ),
        },
        1_100,
    );
    assert_eq!(blocked.unwrap_err(), CoreError::TradingFrozen);

    let cancel_action = UserCommandAction::CancelOrder {
        market_id: market_id.into(),
        order_id: resting.order_id,
    };
    let cancelled = execute_signed_response(
        &mut core,
        &user_key,
        "session:cancel-priority",
        2,
        "cmd:cancel-priority-release",
        cancel_action.clone(),
        1_150,
    );
    assert!(matches!(cancelled.result, CommandResult::Cancelled { .. }));
    assert_eq!(core.balance(&available), 5_000_000);
    assert_eq!(core.balance(&hold), 0);

    let committed_root = core.state_root();
    let replay = execute_signed_response(
        &mut core,
        &user_key,
        "session:cancel-priority",
        2,
        "cmd:cancel-priority-release",
        cancel_action,
        1_150,
    );
    assert_eq!(replay.receipt.state_root, cancelled.receipt.state_root);
    assert_eq!(core.state_root(), committed_root);
    assert_eq!(core.balance(&available), 5_000_000);
    assert_eq!(core.balance(&hold), 0);
}

#[test]
fn api_cancel_all_filters_owner_orders_releases_holds_and_replays_once() {
    let alice_key = SigningKey::from_bytes(&[127u8; 32]);
    let bob_key = SigningKey::from_bytes(&[128u8; 32]);
    let journal_key = [129u8; 32];
    let alice_commitment = [130u8; 32];
    let bob_commitment = [131u8; 32];
    let alice = derived_private_user(journal_key, alice_commitment);
    let bob = derived_private_user(journal_key, bob_commitment);
    let btc = "layrs:v5:BTC:USDC:15m:5000";
    let eth = "layrs:v5:ETH:USDC:15m:5000";
    let zen = "layrs:v5:ZEN:ZEN:15m:5000";
    let mut core = PrivateTradingCore::new(
        JournalKey::from_bytes(journal_key),
        ReceiptSigner::generate([132u8; 48]),
    );
    for (index, (market_id, asset, decimals)) in
        [(btc, "USDC", 6), (eth, "USDC", 6), (zen, "ZEN", 18)]
            .into_iter()
            .enumerate()
    {
        core.register_market(
            format!("sys:market:cancel-all:{index}"),
            MarketConfig {
                market_id: market_id.into(),
                settlement_asset: asset.into(),
                settlement_decimals: decimals,
                public_settlement_chain: Some("horizen".into()),
                opens_at_millis: 900,
                closes_at_millis: 5_000,
                minimum_quantity_micros: 250_000,
                maximum_quantity_micros: 10_000_000,
                minimum_order_notional_micros: 250_000,
                maximum_order_notional_micros: 5_000_000,
                maximum_user_position_micros: 10_000_000,
                maximum_pending_bootstrap_notional_micros: 10_000_000,
                tick_size_micros: 10_000,
                oracle_feed_id: [9_002, 9_003, 9_001][index],
                fee_profile_id: FeeProfileId::LegacyProfitV1,
                execution: MarketExecution::NativeClob,
            },
            800,
        )
        .unwrap();
    }
    for (index, (session, commitment, key)) in [
        ("session:cancel-all:alice", alice_commitment, &alice_key),
        ("session:cancel-all:bob", bob_commitment, &bob_key),
    ]
    .into_iter()
    .enumerate()
    {
        core.register_session(
            format!("sys:session:cancel-all:{index}"),
            session.into(),
            commitment,
            key.verifying_key().to_bytes(),
            6_000,
            825 + index as i64,
        )
        .unwrap();
    }
    for (index, (commitment, asset, amount)) in [
        (alice_commitment, "USDC", 5_000_000),
        (alice_commitment, "ZEN", 3_000_000_000_000_000_000),
        (bob_commitment, "USDC", 1_000_000),
    ]
    .into_iter()
    .enumerate()
    {
        core.apply_user_external_flow(
            format!("sys:deposit:cancel-all:{index}"),
            commitment,
            asset.into(),
            AccountBucket::UserAvailable,
            amount,
            ExternalFlowDirection::Inflow,
            [133 + index as u8; 32],
            850 + index as i64,
        )
        .unwrap();
    }

    let mut create_at_millis = 1_000_i64;
    let mut create = |core: &mut PrivateTradingCore,
                      key: &SigningKey,
                      session: &str,
                      sequence: u64,
                      command_id: &str,
                      market_id: &str,
                      price: u64,
                      quantity: u128| {
        let now_millis = create_at_millis;
        create_at_millis += 1;
        let response = execute_signed_response(
            core,
            key,
            session,
            sequence,
            command_id,
            UserCommandAction::SubmitOrder {
                order: BookOrder::new(
                    "ignored",
                    market_id,
                    Outcome::Up,
                    OrderAction::Buy,
                    price,
                    quantity,
                    TimeInForce::Gtc,
                    None,
                ),
            },
            now_millis,
        );
        match response.result {
            CommandResult::Order { result } => result.accepted_order.unwrap(),
            _ => panic!("expected resting order"),
        }
    };
    let alice_btc = create(
        &mut core,
        &alice_key,
        "session:cancel-all:alice",
        1,
        "cmd:cancel-all:alice-btc",
        btc,
        400_000,
        2_500_000,
    );
    let alice_btc_second = create(
        &mut core,
        &alice_key,
        "session:cancel-all:alice",
        2,
        "cmd:cancel-all:alice-btc-second",
        btc,
        250_000,
        1_000_000,
    );
    let alice_eth = create(
        &mut core,
        &alice_key,
        "session:cancel-all:alice",
        3,
        "cmd:cancel-all:alice-eth",
        eth,
        500_000,
        2_000_000,
    );
    let alice_zen = create(
        &mut core,
        &alice_key,
        "session:cancel-all:alice",
        4,
        "cmd:cancel-all:alice-zen",
        zen,
        500_000,
        2_000_000,
    );
    let bob_btc = create(
        &mut core,
        &bob_key,
        "session:cancel-all:bob",
        1,
        "cmd:cancel-all:bob-btc",
        btc,
        300_000,
        1_000_000,
    );

    let alice_usdc = AccountKey::new(&alice, AccountBucket::UserAvailable, "USDC");
    let alice_zen_available = AccountKey::new(&alice, AccountBucket::UserAvailable, "ZEN");
    let bob_usdc = AccountKey::new(&bob, AccountBucket::UserAvailable, "USDC");
    assert_eq!(core.balance(&alice_usdc), 2_750_000);
    assert_eq!(
        core.balance(&alice_zen_available),
        2_000_000_000_000_000_000
    );
    assert_eq!(core.balance(&bob_usdc), 700_000);

    core.set_trading_freeze("sys:freeze:cancel-all".into(), true, [136u8; 32], 1_100)
        .unwrap();
    let by_market = execute_signed_response(
        &mut core,
        &alice_key,
        "session:cancel-all:alice",
        5,
        "cmd:cancel-all:market",
        UserCommandAction::CancelAllOrders {
            filter: CancelAllOrdersFilter::Market {
                market_id: btc.into(),
            },
        },
        1_150,
    );
    assert_eq!(by_market.receipt.protocol_version, "layrs.v3");
    assert_eq!(by_market.receipt_state, CommandReceiptState::Cancelled);
    assert_eq!(by_market.receipt.publication_eligible, Some(true));
    match by_market.result {
        CommandResult::OrdersCancelled { filter, outcomes } => {
            assert_eq!(
                filter,
                Some(CancelAllOrdersFilter::Market {
                    market_id: btc.into()
                })
            );
            assert_eq!(outcomes.len(), 2);
            assert_eq!(outcomes[0].order_id, alice_btc.order_id);
            assert_eq!(outcomes[0].status, OrderStatus::Cancelled);
            assert_eq!(outcomes[1].order_id, alice_btc_second.order_id);
            assert_eq!(outcomes[1].status, OrderStatus::Cancelled);
        }
        _ => panic!("expected market cancellation outcomes"),
    }
    assert_eq!(core.balance(&alice_usdc), 4_000_000);
    assert_eq!(core.balance(&bob_usdc), 700_000);

    let asset_action = UserCommandAction::CancelAllOrders {
        filter: CancelAllOrdersFilter::Asset {
            asset: "USDC".into(),
        },
    };
    let by_asset = execute_signed_response(
        &mut core,
        &alice_key,
        "session:cancel-all:alice",
        6,
        "cmd:cancel-all:asset",
        asset_action.clone(),
        1_200,
    );
    match &by_asset.result {
        CommandResult::OrdersCancelled { outcomes, .. } => {
            assert_eq!(outcomes.len(), 1);
            assert_eq!(outcomes[0].order_id, alice_eth.order_id);
        }
        _ => panic!("expected asset cancellation outcomes"),
    }
    assert_eq!(core.balance(&alice_usdc), 5_000_000);
    let root = core.state_root();
    let replay = execute_signed_response(
        &mut core,
        &alice_key,
        "session:cancel-all:alice",
        6,
        "cmd:cancel-all:asset",
        asset_action,
        1_200,
    );
    assert_eq!(replay.result, by_asset.result);
    assert_eq!(replay.receipt.state_root, by_asset.receipt.state_root);
    assert_eq!(core.state_root(), root);
    assert_eq!(core.balance(&alice_usdc), 5_000_000);

    let all = execute_signed_response(
        &mut core,
        &alice_key,
        "session:cancel-all:alice",
        7,
        "cmd:cancel-all:all",
        UserCommandAction::CancelAllOrders {
            filter: CancelAllOrdersFilter::All,
        },
        1_250,
    );
    match all.result {
        CommandResult::OrdersCancelled { outcomes, .. } => {
            assert_eq!(outcomes.len(), 1);
            assert_eq!(outcomes[0].order_id, alice_zen.order_id);
        }
        _ => panic!("expected all-market cancellation outcomes"),
    }
    assert_eq!(
        core.balance(&alice_zen_available),
        3_000_000_000_000_000_000
    );

    let root_before_invalid_filter = core.state_root();
    let invalid = execute_signed_result(
        &mut core,
        &alice_key,
        "session:cancel-all:alice",
        8,
        "cmd:cancel-all:unknown-market",
        UserCommandAction::CancelAllOrders {
            filter: CancelAllOrdersFilter::Market {
                market_id: "layrs:v5:BTC:USDC:15m:unknown".into(),
            },
        },
        1_275,
    )
    .unwrap_err();
    assert_eq!(invalid, CoreError::InvalidOrder("unknown market".into()));
    assert_eq!(core.state_root(), root_before_invalid_filter);
    assert_eq!(core.balance(&alice_usdc), 5_000_000);
    assert_eq!(
        core.balance(&alice_zen_available),
        3_000_000_000_000_000_000
    );

    let bob_portfolio = execute_signed(
        &mut core,
        &bob_key,
        "session:cancel-all:bob",
        2,
        "cmd:cancel-all:bob-portfolio",
        UserCommandAction::Portfolio,
        1_300,
    );
    match bob_portfolio {
        CommandResult::Portfolio { snapshot } => {
            assert!(snapshot
                .orders
                .iter()
                .any(|order| order.order_id == bob_btc.order_id));
        }
        _ => panic!("expected Bob portfolio"),
    }
}

#[test]
fn legacy_command_results_restore_without_s08_private_binding_echoes() {
    let cancel_all: CommandResult = serde_json::from_value(serde_json::json!({
        "type": "ORDERS_CANCELLED",
        "outcomes": [{
            "order_id": "00000000-0000-4000-8000-000000000001",
            "market_id": "market-1",
            "status": "CANCELLED"
        }]
    }))
    .unwrap();
    let CommandResult::OrdersCancelled { filter, .. } = &cancel_all else {
        panic!("expected legacy cancel-all result");
    };
    assert_eq!(filter, &None);
    assert!(serde_json::to_value(cancel_all)
        .unwrap()
        .get("filter")
        .is_none());

    let preview: CommandResult = serde_json::from_value(serde_json::json!({
        "type": "POSITION_CLOSE_PREVIEW",
        "preview": {
            "position_id": "pos_legacy", "quantity_micros": "1", "minimum_price_micros": 1,
            "average_price_micros": 1, "gross_payout_atomic": "1", "fee_atomic": "0",
            "net_payout_atomic": "1", "book_commitment_sha256": vec![0; 32], "book_sequence": 0,
            "expires_at_millis": 1, "quote_commitment_sha256": vec![0; 32]
        }
    }))
    .unwrap();
    let CommandResult::PositionClosePreview {
        market_id,
        outcome,
        session_tag,
        ..
    } = preview
    else {
        panic!("expected legacy close preview");
    };
    assert_eq!((market_id, outcome, session_tag), (None, None, None));
}

#[test]
fn api_position_close_previews_and_executes_exact_protected_payout_atomically() {
    let alice = SigningKey::from_bytes(&[141u8; 32]);
    let bob = SigningKey::from_bytes(&[142u8; 32]);
    let oracle = SigningKey::from_bytes(&[143u8; 32]);
    let journal_key = [144u8; 32];
    let alice_commitment = [145u8; 32];
    let bob_commitment = [146u8; 32];
    let alice_owner = derived_private_user(journal_key, alice_commitment);
    let market_id = "layrs:v5:BTC:USDC:15m:2500";
    let mut core = PrivateTradingCore::new_with_oracle(
        JournalKey::from_bytes(journal_key),
        ReceiptSigner::generate([147u8; 48]),
        oracle.verifying_key().to_bytes(),
    )
    .unwrap();
    core.register_market(
        "sys:market:position-close".into(),
        MarketConfig {
            market_id: market_id.into(),
            settlement_asset: "USDC".into(),
            settlement_decimals: 6,
            public_settlement_chain: Some("horizen".into()),
            opens_at_millis: 900,
            closes_at_millis: 100_000,
            minimum_quantity_micros: 250_000,
            maximum_quantity_micros: 10_000_000,
            minimum_order_notional_micros: 1,
            maximum_order_notional_micros: 10_000_000,
            maximum_user_position_micros: 10_000_000,
            maximum_pending_bootstrap_notional_micros: 100_000_000,
            tick_size_micros: 1_000,
            oracle_feed_id: 9002,
            fee_profile_id: FeeProfileId::LegacyProfitV1,
            execution: MarketExecution::NativeClob,
        },
        800,
    )
    .unwrap();
    for (label, key, commitment) in [
        ("alice", &alice, alice_commitment),
        ("bob", &bob, bob_commitment),
    ] {
        core.register_session(
            format!("sys:session:position-close:{label}"),
            format!("session:position-close:{label}"),
            commitment,
            key.verifying_key().to_bytes(),
            120_000,
            850,
        )
        .unwrap();
        core.apply_user_external_flow(
            format!("sys:deposit:position-close:{label}"),
            commitment,
            "USDC".into(),
            AccountBucket::UserAvailable,
            2_000_000,
            ExternalFlowDirection::Inflow,
            [label.as_bytes()[0]; 32],
            875,
        )
        .unwrap();
    }

    execute_signed(
        &mut core,
        &alice,
        "session:position-close:alice",
        1,
        "cmd:position-close:mint",
        UserCommandAction::CompleteSet {
            market_id: market_id.into(),
            quantity_micros: 2_000_000,
            direction: CompleteSetDirection::Mint,
        },
        1_000,
    );
    let first_bid = execute_signed(
        &mut core,
        &bob,
        "session:position-close:bob",
        1,
        "cmd:position-close:bid",
        UserCommandAction::SubmitOrder {
            order: BookOrder::new(
                "ignored",
                market_id,
                Outcome::Up,
                OrderAction::Buy,
                400_000,
                2_000_000,
                TimeInForce::Gtc,
                None,
            ),
        },
        1_100,
    );
    let CommandResult::Order { result: first_bid } = first_bid else {
        panic!("expected first close-liquidity bid");
    };
    let first_bid_id = first_bid.accepted_order.expect("accepted bid").order_id;
    let portfolio = execute_signed(
        &mut core,
        &alice,
        "session:position-close:alice",
        2,
        "cmd:position-close:portfolio",
        UserCommandAction::Portfolio,
        1_200,
    );
    let CommandResult::Portfolio { snapshot } = portfolio else {
        panic!("expected portfolio");
    };
    let position_id = snapshot
        .positions
        .iter()
        .find(|position| position.market_id == market_id && position.outcome == "UP")
        .expect("UP position")
        .position_id
        .clone();
    assert!(position_id.starts_with("pos_"));
    assert_eq!(position_id.len(), 68);

    let preview = execute_signed_response(
        &mut core,
        &alice,
        "session:position-close:alice",
        2,
        "cmd:position-close:preview",
        UserCommandAction::PreviewPositionClose {
            position_id: position_id.clone(),
            market_id: market_id.into(),
            outcome: Outcome::Up,
            session_tag: "test-session-tag".into(),
            quantity_micros: 2_000_000,
            minimum_price_micros: 350_000,
        },
        1_300,
    );
    assert_ne!(preview.receipt.prior_state_root, preview.receipt.state_root);
    assert!(preview.encrypted_record.is_some());
    assert_eq!(preview.receipt.publication_eligible, Some(false));
    assert_eq!(preview.receipt.protocol_version, "layrs.v2");
    assert_eq!(preview.receipt.result_commitment_sha256, None);
    assert_eq!(preview.receipt_state, CommandReceiptState::Accepted);
    let CommandResult::PositionClosePreview { preview: quote, .. } = preview.result else {
        panic!("expected close preview");
    };
    assert_eq!(quote.position_id, position_id);
    assert_eq!(quote.quantity_micros, 2_000_000);
    assert_eq!(quote.minimum_price_micros, 350_000);
    assert_eq!(quote.average_price_micros, 400_000);
    assert_eq!(quote.gross_payout_atomic, 800_000);
    assert_eq!(quote.fee_atomic, 1_600);
    assert_eq!(quote.net_payout_atomic, 798_400);
    assert_ne!(quote.book_commitment_sha256, [0u8; 32]);
    assert_ne!(quote.quote_commitment_sha256, [0u8; 32]);
    assert_eq!(quote.expires_at_millis, 31_300);
    let alice_up = AccountKey::position(
        &alice_owner,
        format!("CLAIM:{market_id}:UP"),
        market_id,
        "UP",
    );
    assert_eq!(core.balance(&alice_up), 2_000_000);

    let close_action = UserCommandAction::ClosePosition {
        position_id: position_id.clone(),
        market_id: market_id.into(),
        outcome: Outcome::Up,
        session_tag: "test-session-tag".into(),
        quantity_micros: 2_000_000,
        minimum_price_micros: 350_000,
        quote: quote.clone(),
    };
    core.set_trading_freeze("sys:freeze:position-close".into(), true, [148u8; 32], 1_310)
        .unwrap();
    assert_eq!(
        execute_signed_result(
            &mut core,
            &alice,
            "session:position-close:alice",
            3,
            "cmd:position-close:frozen",
            close_action.clone(),
            1_315,
        )
        .unwrap_err(),
        CoreError::TradingFrozen
    );
    core.set_trading_freeze(
        "sys:unfreeze:position-close".into(),
        false,
        [149u8; 32],
        1_320,
    )
    .unwrap();

    let second_bid = execute_signed(
        &mut core,
        &bob,
        "session:position-close:bob",
        2,
        "cmd:position-close:second-bid",
        UserCommandAction::SubmitOrder {
            order: BookOrder::new(
                "ignored",
                market_id,
                Outcome::Up,
                OrderAction::Buy,
                410_000,
                1_000_000,
                TimeInForce::Gtc,
                None,
            ),
        },
        1_330,
    );
    let CommandResult::Order { result: second_bid } = second_bid else {
        panic!("expected second close-liquidity bid");
    };
    let second_bid_id = second_bid
        .accepted_order
        .expect("accepted second bid")
        .order_id;
    let root_before_stale = core.state_root();
    let stale = execute_signed_result(
        &mut core,
        &alice,
        "session:position-close:alice",
        3,
        "cmd:position-close:stale",
        close_action,
        1_340,
    );
    assert!(matches!(
        stale.unwrap_err(),
        CoreError::InvalidOrder(message) if message == "position close quote is stale"
    ));
    assert_eq!(core.state_root(), root_before_stale);

    let refreshed = execute_signed_response(
        &mut core,
        &alice,
        "session:position-close:alice",
        3,
        "cmd:position-close:preview-refreshed",
        UserCommandAction::PreviewPositionClose {
            position_id: position_id.clone(),
            market_id: market_id.into(),
            outcome: Outcome::Up,
            session_tag: "test-session-tag".into(),
            quantity_micros: 2_000_000,
            minimum_price_micros: 350_000,
        },
        1_350,
    );
    let CommandResult::PositionClosePreview {
        preview: refreshed_quote,
        ..
    } = refreshed.result
    else {
        panic!("expected refreshed preview");
    };
    execute_signed(
        &mut core,
        &bob,
        "session:position-close:bob",
        3,
        "cmd:position-close:cancel-first-bid",
        UserCommandAction::CancelOrder {
            market_id: market_id.into(),
            order_id: first_bid_id,
        },
        1_360,
    );
    let root_before_partial_fok = core.state_root();
    let partial_fok = execute_signed_result(
        &mut core,
        &alice,
        "session:position-close:alice",
        4,
        "cmd:position-close:partial-fok",
        UserCommandAction::ClosePosition {
            position_id: position_id.clone(),
            market_id: market_id.into(),
            outcome: Outcome::Up,
            session_tag: "test-session-tag".into(),
            quantity_micros: 2_000_000,
            minimum_price_micros: 350_000,
            quote: refreshed_quote,
        },
        1_370,
    );
    assert!(matches!(
        partial_fok.unwrap_err(),
        CoreError::InvalidOrder(message)
            if message == "insufficient protected liquidity for position close"
    ));
    assert_eq!(core.state_root(), root_before_partial_fok);

    execute_signed(
        &mut core,
        &bob,
        "session:position-close:bob",
        4,
        "cmd:position-close:cancel-second-bid",
        UserCommandAction::CancelOrder {
            market_id: market_id.into(),
            order_id: second_bid_id,
        },
        1_375,
    );

    execute_signed(
        &mut core,
        &bob,
        "session:position-close:bob",
        5,
        "cmd:position-close:replacement-bid",
        UserCommandAction::SubmitOrder {
            order: BookOrder::new(
                "ignored",
                market_id,
                Outcome::Up,
                OrderAction::Buy,
                400_000,
                2_000_000,
                TimeInForce::Gtc,
                None,
            ),
        },
        1_380,
    );

    let insufficient = execute_signed_result(
        &mut core,
        &alice,
        "session:position-close:alice",
        4,
        "cmd:position-close:protected",
        UserCommandAction::PreviewPositionClose {
            position_id: position_id.clone(),
            market_id: market_id.into(),
            outcome: Outcome::Up,
            session_tag: "test-session-tag".into(),
            quantity_micros: 2_000_000,
            minimum_price_micros: 450_000,
        },
        1_390,
    );
    assert!(matches!(
        insufficient.unwrap_err(),
        CoreError::InvalidOrder(message)
            if message == "insufficient protected liquidity for position close"
    ));

    let final_preview = execute_signed_response(
        &mut core,
        &alice,
        "session:position-close:alice",
        4,
        "cmd:position-close:preview-final",
        UserCommandAction::PreviewPositionClose {
            position_id: position_id.clone(),
            market_id: market_id.into(),
            outcome: Outcome::Up,
            session_tag: "test-session-tag".into(),
            quantity_micros: 2_000_000,
            minimum_price_micros: 350_000,
        },
        1_400,
    );
    let CommandResult::PositionClosePreview { preview: quote, .. } = final_preview.result else {
        panic!("expected final close preview");
    };

    // The quote TTL is half-open and evaluated against enclave-trusted time.
    // Both equality and any later instant reject without mutating state.
    let pre_close_snapshot = core.export_encrypted_snapshot().unwrap();
    for (label, now) in [
        ("at-expiry", quote.expires_at_millis),
        ("after-expiry", quote.expires_at_millis + 1),
    ] {
        let mut expiry_core = PrivateTradingCore::restore_encrypted_snapshot(
            JournalKey::from_bytes(journal_key),
            ReceiptSigner::generate([147u8; 48]),
            &pre_close_snapshot,
            pre_close_snapshot.sequence,
        )
        .unwrap();
        let root_before = expiry_core.state_root();
        let command = signed_user_command_with_expiry(
            &alice,
            "session:position-close:alice",
            5,
            &format!("cmd:position-close:{label}"),
            UserCommandAction::ClosePosition {
                position_id: position_id.clone(),
                market_id: market_id.into(),
                outcome: Outcome::Up,
                session_tag: "test-session-tag".into(),
                quantity_micros: 2_000_000,
                minimum_price_micros: 350_000,
                quote: quote.clone(),
            },
            now,
            90_000,
        );
        assert!(matches!(
            expiry_core.execute(command, now).unwrap_err(),
            CoreError::InvalidOrder(message) if message == "position close quote is stale"
        ));
        assert_eq!(expiry_core.state_root(), root_before);
    }

    // Every quoted field and the HMAC itself are authenticated. Forgery fails
    // without consuming session sequence, clock fence, collateral, or journal.
    for (label, forged_quote) in [
        ("forged-economics", {
            let mut forged = quote.clone();
            forged.net_payout_atomic += 1;
            forged
        }),
        ("forged-hmac", {
            let mut forged = quote.clone();
            forged.quote_commitment_sha256[0] ^= 1;
            forged
        }),
    ] {
        let root_before = core.state_root();
        let forged = execute_signed_result(
            &mut core,
            &alice,
            "session:position-close:alice",
            5,
            &format!("cmd:position-close:{label}"),
            UserCommandAction::ClosePosition {
                position_id: position_id.clone(),
                market_id: market_id.into(),
                outcome: Outcome::Up,
                session_tag: "test-session-tag".into(),
                quantity_micros: 2_000_000,
                minimum_price_micros: 350_000,
                quote: forged_quote,
            },
            1_405,
        );
        assert!(matches!(
            forged.unwrap_err(),
            CoreError::InvalidOrder(message) if message == "position close quote is stale"
        ));
        assert_eq!(core.state_root(), root_before);
    }

    // A worse, unconsumed dust order changes the whole book but not the exact
    // executable slice protected by the quote. It must not create a cheap quote
    // invalidation DoS.
    execute_signed(
        &mut core,
        &bob,
        "session:position-close:bob",
        6,
        "cmd:position-close:irrelevant-dust",
        UserCommandAction::SubmitOrder {
            order: BookOrder::new(
                "ignored",
                market_id,
                Outcome::Up,
                OrderAction::Buy,
                300_000,
                250_000,
                TimeInForce::Gtc,
                None,
            ),
        },
        1_407,
    );
    let close_action = UserCommandAction::ClosePosition {
        position_id: position_id.clone(),
        market_id: market_id.into(),
        outcome: Outcome::Up,
        session_tag: "test-session-tag".into(),
        quantity_micros: 2_000_000,
        minimum_price_micros: 350_000,
        quote: quote.clone(),
    };
    let close_command = signed_user_command(
        &alice,
        "session:position-close:alice",
        5,
        "cmd:position-close:execute",
        close_action.clone(),
        1_410,
    );
    let closed = core.execute(close_command.clone(), 1_410).unwrap();
    assert!(core
        .recover_exact_user_command(&close_command)
        .unwrap()
        .is_some());
    assert_eq!(closed.receipt.publication_eligible, Some(true));
    let CommandResult::PositionClosed {
        preview: actual,
        order_id,
        ..
    } = &closed.result
    else {
        panic!("expected closed position");
    };
    assert_ne!(*order_id, uuid::Uuid::nil());
    assert_eq!(actual, &quote);
    assert_eq!(closed.audit_fills.len(), 1);
    assert_eq!(
        closed.audit_fills[0].statement.match_type.as_deref(),
        Some("NORMAL")
    );
    assert_eq!(closed.audit_fills[0].statement.fee_atomic, "1600");
    assert_eq!(core.balance(&alice_up), 0);
    let alice_available = AccountKey::new(&alice_owner, AccountBucket::UserAvailable, "USDC");
    assert_eq!(core.balance(&alice_available), 798_400);
    assert_eq!(
        core.balance(&AccountKey::new("layrs", AccountBucket::FeeRevenue, "USDC",)),
        1_600
    );
    let bob_owner = derived_private_user(journal_key, bob_commitment);
    assert_eq!(
        core.balance(&AccountKey::position(
            &bob_owner,
            format!("CLAIM:{market_id}:UP"),
            market_id,
            "UP",
        )),
        2_000_000
    );
    let bob_portfolio = execute_signed(
        &mut core,
        &bob,
        "session:position-close:bob",
        7,
        "cmd:position-close:bob-portfolio",
        UserCommandAction::Portfolio,
        1_415,
    );
    let CommandResult::Portfolio { snapshot } = bob_portfolio else {
        panic!("expected Bob portfolio after position close");
    };
    let acquired = snapshot
        .positions
        .iter()
        .find(|position| position.market_id == market_id && position.outcome == "UP")
        .expect("Bob acquired UP position");
    assert_eq!(acquired.quantity_micros, "2000000");
    assert_eq!(acquired.cost_basis_micros, "800000");
    let replay = core.execute(close_command.clone(), 1_420).unwrap();
    assert_eq!(replay.result, closed.result);
    assert_eq!(replay.receipt.state_root, closed.receipt.state_root);
    assert_eq!(core.balance(&alice_available), 798_400);

    let mut mismatched_retry = close_command.clone();
    if let UserCommandAction::ClosePosition {
        quantity_micros, ..
    } = &mut mismatched_retry.action
    {
        *quantity_micros = 1_000_000;
    } else {
        panic!("expected close command");
    }
    mismatched_retry.session.request.request_hash = command_request_hash(
        &mismatched_retry.command_id,
        &mismatched_retry.idempotency_key,
        &mismatched_retry.action,
    )
    .unwrap();
    mismatched_retry.session.signature = alice
        .sign(&signing_payload(&mismatched_retry.session.request))
        .to_bytes()
        .to_vec();
    assert_eq!(
        core.recover_exact_user_command(&mismatched_retry)
            .unwrap_err(),
        CoreError::DuplicateCommand
    );
    assert_eq!(
        core.execute(mismatched_retry, 1_420).unwrap_err(),
        CoreError::DuplicateCommand
    );

    let snapshot = core.export_encrypted_snapshot().unwrap();
    let snapshot_sequence = snapshot.sequence;
    let mut restored = PrivateTradingCore::restore_encrypted_snapshot(
        JournalKey::from_bytes(journal_key),
        ReceiptSigner::generate([147u8; 48]),
        &snapshot,
        snapshot_sequence,
    )
    .unwrap();
    let restored_root = restored.state_root();
    assert_eq!(restored_root, core.state_root());
    assert_eq!(
        restored.execute(close_command, 1_420).unwrap_err(),
        CoreError::PreviouslyProcessed
    );
    assert_eq!(restored.state_root(), restored_root);
    assert_eq!(restored.balance(&alice_available), 798_400);

    let rewind_root = restored.state_root();
    assert_eq!(
        execute_signed_result(
            &mut restored,
            &alice,
            "session:position-close:alice",
            6,
            "cmd:position-close:rewound-clock",
            UserCommandAction::PreviewPositionClose {
                position_id: format!("pos_{}", "00".repeat(32)),
                market_id: market_id.into(),
                outcome: Outcome::Up,
                session_tag: "test-session-tag".into(),
                quantity_micros: 250_000,
                minimum_price_micros: 350_000,
            },
            1_409,
        )
        .unwrap_err(),
        CoreError::RollbackDetected
    );
    assert_eq!(restored.state_root(), rewind_root);

    let wrong_owner = execute_signed_result(
        &mut core,
        &alice,
        "session:position-close:alice",
        6,
        "cmd:position-close:wrong-owner",
        UserCommandAction::PreviewPositionClose {
            position_id: format!("pos_{}", "00".repeat(32)),
            market_id: market_id.into(),
            outcome: Outcome::Up,
            session_tag: "test-session-tag".into(),
            quantity_micros: 250_000,
            minimum_price_micros: 350_000,
        },
        1_500,
    );
    assert!(matches!(
        wrong_owner.unwrap_err(),
        CoreError::InvalidOrder(message) if message == "position owner mismatch"
    ));

    let closed_market = core.execute(
        signed_user_command_with_expiry(
            &alice,
            "session:position-close:alice",
            6,
            "cmd:position-close:closed-market",
            close_action.clone(),
            100_001,
            110_000,
        ),
        100_001,
    );
    assert!(matches!(
        closed_market.unwrap_err(),
        CoreError::InvalidOrder(message) if message == "market is closed"
    ));

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
        oracle_feed_id: 9002,
        opening: boundary(900, 1_000_000_000, 151),
        closing: boundary(100_000, 1_100_000_000, 152),
        issued_at_millis: 100_100,
    };
    let signature = oracle
        .sign(&resolution_signing_payload(&statement).unwrap())
        .to_bytes()
        .to_vec();
    core.resolve_market(
        "sys:resolve:position-close".into(),
        SignedResolution {
            statement,
            signature,
        },
        100_100,
    )
    .unwrap();
    let resolving = core.execute(
        signed_user_command_with_expiry(
            &alice,
            "session:position-close:alice",
            6,
            "cmd:position-close:resolving",
            close_action,
            100_200,
            110_000,
        ),
        100_200,
    );
    assert!(matches!(
        resolving.unwrap_err(),
        CoreError::InvalidOrder(message) if message == "market is resolving or resolved"
    ));
}

#[test]
fn api_position_close_mixes_normal_and_merge_zen_liquidity_with_exact_conservation() {
    const ZEN: u128 = 1_000_000_000_000_000_000;
    let alice = SigningKey::from_bytes(&[161u8; 32]);
    let bob = SigningKey::from_bytes(&[162u8; 32]);
    let journal_key = [163u8; 32];
    let alice_commitment = [164u8; 32];
    let bob_commitment = [165u8; 32];
    let alice_owner = derived_private_user(journal_key, alice_commitment);
    let bob_owner = derived_private_user(journal_key, bob_commitment);
    let market_id = "layrs:v5:ZEN:ZEN:15m:10000";
    let mut core = PrivateTradingCore::new(
        JournalKey::from_bytes(journal_key),
        ReceiptSigner::generate([166u8; 48]),
    );
    core.register_market(
        "sys:market:position-close-mixed".into(),
        MarketConfig {
            market_id: market_id.into(),
            settlement_asset: "ZEN".into(),
            settlement_decimals: 18,
            public_settlement_chain: Some("horizen".into()),
            opens_at_millis: 900,
            closes_at_millis: 10_000,
            minimum_quantity_micros: 250_000,
            maximum_quantity_micros: 10_000_000,
            minimum_order_notional_micros: 1,
            maximum_order_notional_micros: 10_000_000,
            maximum_user_position_micros: 10_000_000,
            maximum_pending_bootstrap_notional_micros: 100_000_000,
            tick_size_micros: 1_000,
            oracle_feed_id: 9001,
            fee_profile_id: FeeProfileId::LayrsCryptoV2,
            execution: MarketExecution::NativeClob,
        },
        800,
    )
    .unwrap();
    for (label, key, commitment) in [
        ("alice", &alice, alice_commitment),
        ("bob", &bob, bob_commitment),
    ] {
        core.register_session(
            format!("sys:session:position-close-mixed:{label}"),
            format!("session:position-close-mixed:{label}"),
            commitment,
            key.verifying_key().to_bytes(),
            20_000,
            850,
        )
        .unwrap();
        core.apply_user_external_flow(
            format!("sys:deposit:position-close-mixed:{label}"),
            commitment,
            "ZEN".into(),
            AccountBucket::UserAvailable,
            5 * ZEN,
            ExternalFlowDirection::Inflow,
            [label.as_bytes()[0]; 32],
            875,
        )
        .unwrap();
    }

    for (key, session, command) in [
        (
            &alice,
            "session:position-close-mixed:alice",
            "cmd:position-close-mixed:alice-mint",
        ),
        (
            &bob,
            "session:position-close-mixed:bob",
            "cmd:position-close-mixed:bob-mint",
        ),
    ] {
        execute_signed(
            &mut core,
            key,
            session,
            1,
            command,
            UserCommandAction::CompleteSet {
                market_id: market_id.into(),
                quantity_micros: 2_000_000,
                direction: CompleteSetDirection::Mint,
            },
            1_000,
        );
    }
    execute_signed(
        &mut core,
        &bob,
        "session:position-close-mixed:bob",
        2,
        "cmd:position-close-mixed:normal-bid",
        UserCommandAction::SubmitOrder {
            order: BookOrder::new(
                "ignored",
                market_id,
                Outcome::Up,
                OrderAction::Buy,
                410_000,
                1_000_000,
                TimeInForce::Gtc,
                None,
            ),
        },
        1_100,
    );
    execute_signed(
        &mut core,
        &bob,
        "session:position-close-mixed:bob",
        3,
        "cmd:position-close-mixed:merge-ask",
        UserCommandAction::SubmitOrder {
            order: BookOrder::new(
                "ignored",
                market_id,
                Outcome::Down,
                OrderAction::Sell,
                600_000,
                1_000_000,
                TimeInForce::Gtc,
                None,
            ),
        },
        1_200,
    );

    let portfolio = execute_signed(
        &mut core,
        &alice,
        "session:position-close-mixed:alice",
        2,
        "cmd:position-close-mixed:portfolio",
        UserCommandAction::Portfolio,
        1_250,
    );
    let CommandResult::Portfolio { snapshot } = portfolio else {
        panic!("expected Alice portfolio");
    };
    let position_id = snapshot
        .positions
        .iter()
        .find(|position| position.market_id == market_id && position.outcome == "UP")
        .expect("Alice UP position")
        .position_id
        .clone();
    let preview = execute_signed_response(
        &mut core,
        &alice,
        "session:position-close-mixed:alice",
        2,
        "cmd:position-close-mixed:preview",
        UserCommandAction::PreviewPositionClose {
            position_id: position_id.clone(),
            market_id: market_id.into(),
            outcome: Outcome::Up,
            session_tag: "test-session-tag".into(),
            quantity_micros: 2_000_000,
            minimum_price_micros: 390_000,
        },
        1_300,
    );
    let CommandResult::PositionClosePreview { preview: quote, .. } = preview.result else {
        panic!("expected mixed close preview");
    };
    assert_eq!(quote.average_price_micros, 405_000);
    assert_eq!(quote.gross_payout_atomic, 810_000_000_000_000_000);
    assert_eq!(quote.fee_atomic, 33_730_000_000_000_000);
    assert_eq!(quote.net_payout_atomic, 776_270_000_000_000_000);

    let closed = execute_signed_response(
        &mut core,
        &alice,
        "session:position-close-mixed:alice",
        3,
        "cmd:position-close-mixed:close",
        UserCommandAction::ClosePosition {
            position_id,
            market_id: market_id.into(),
            outcome: Outcome::Up,
            session_tag: "test-session-tag".into(),
            quantity_micros: 2_000_000,
            minimum_price_micros: 390_000,
            quote: quote.clone(),
        },
        1_350,
    );
    let CommandResult::PositionClosed {
        preview: executed, ..
    } = closed.result
    else {
        panic!("expected mixed position close");
    };
    assert_eq!(executed, quote);
    assert_eq!(closed.audit_fills.len(), 2);
    assert_eq!(
        closed
            .audit_fills
            .iter()
            .map(|fill| fill.statement.match_type.as_deref().unwrap())
            .collect::<Vec<_>>(),
        vec!["NORMAL", "MERGE"]
    );
    assert_eq!(
        closed
            .audit_fills
            .iter()
            .map(|fill| fill.statement.fee_atomic.as_str())
            .collect::<Vec<_>>(),
        vec!["16930000000000000", "16800000000000000"]
    );

    let available =
        |owner: &str| core.balance(&AccountKey::new(owner, AccountBucket::UserAvailable, "ZEN"));
    let position = |owner: &str, outcome: Outcome| {
        core.balance(&AccountKey::position(
            owner,
            format!(
                "CLAIM:{market_id}:{}",
                if outcome == Outcome::Up { "UP" } else { "DOWN" }
            ),
            market_id,
            if outcome == Outcome::Up { "UP" } else { "DOWN" },
        ))
    };
    let mut collateral = AccountKey::new("layrs", AccountBucket::MarketCollateral, "ZEN");
    collateral.market_id = Some(market_id.into());
    let fee_revenue = core.balance(&AccountKey::new("layrs", AccountBucket::FeeRevenue, "ZEN"));
    assert_eq!(available(&alice_owner), 3_776_270_000_000_000_000);
    assert_eq!(available(&bob_owner), 3_190_000_000_000_000_000);
    assert_eq!(position(&alice_owner, Outcome::Up), 0);
    assert_eq!(position(&alice_owner, Outcome::Down), 2_000_000);
    assert_eq!(position(&bob_owner, Outcome::Up), 3_000_000);
    assert_eq!(position(&bob_owner, Outcome::Down), 1_000_000);
    assert_eq!(core.balance(&collateral), 3 * ZEN);
    assert_eq!(fee_revenue, 33_730_000_000_000_000);
    assert_eq!(
        available(&alice_owner) + available(&bob_owner) + core.balance(&collateral) + fee_revenue,
        10 * ZEN
    );

    let bob_rewards = execute_signed(
        &mut core,
        &bob,
        "session:position-close-mixed:bob",
        4,
        "cmd:position-close-mixed:bob-rewards",
        UserCommandAction::Rewards,
        1_400,
    );
    let CommandResult::Rewards { entitlements } = bob_rewards else {
        panic!("expected Bob reward attribution");
    };
    assert_eq!(entitlements.len(), 1);
    assert_eq!(
        entitlements[0].cumulative_maker_rebate_atomic,
        "6746000000000000"
    );
    assert_eq!(entitlements[0].cumulative_maker_volume_micros, "2000000");
    let alice_rewards = execute_signed(
        &mut core,
        &alice,
        "session:position-close-mixed:alice",
        4,
        "cmd:position-close-mixed:alice-rewards",
        UserCommandAction::Rewards,
        1_400,
    );
    let CommandResult::Rewards { entitlements } = alice_rewards else {
        panic!("expected Alice fee attribution");
    };
    assert_eq!(entitlements.len(), 1);
    assert_eq!(
        entitlements[0].cumulative_taker_fees_atomic,
        "33730000000000000"
    );
    assert_eq!(entitlements[0].cumulative_taker_volume_micros, "2000000");
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
    core.execute(
        signed_user_command(key, session_id, sequence, command_id, action, now_millis),
        now_millis,
    )
}

fn signed_user_command(
    key: &SigningKey,
    session_id: &str,
    sequence: u64,
    command_id: &str,
    action: UserCommandAction,
    issued_at_millis: i64,
) -> UserCommand {
    signed_user_command_with_expiry(
        key,
        session_id,
        sequence,
        command_id,
        action,
        issued_at_millis,
        2_900,
    )
}

#[allow(clippy::too_many_arguments)]
fn signed_user_command_with_expiry(
    key: &SigningKey,
    session_id: &str,
    sequence: u64,
    command_id: &str,
    action: UserCommandAction,
    issued_at_millis: i64,
    expires_at_millis: i64,
) -> UserCommand {
    let idempotency_key = format!("idem:{command_id}");
    let request_hash = command_request_hash(command_id, &idempotency_key, &action).unwrap();
    let request = SessionRequest {
        session_id: session_id.into(),
        sequence,
        issued_at_millis,
        expires_at_millis,
        request_hash,
    };
    let signature = key.sign(&signing_payload(&request)).to_bytes().to_vec();
    UserCommand {
        command_id: command_id.into(),
        idempotency_key,
        session: SignedSessionRequest { request, signature },
        action,
    }
}
