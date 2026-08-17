use clob_service::private_core::{
    command_request_hash, signing_payload, AccountBucket, AccountKey, BookOrder,
    CompleteSetDirection, CoreResponse, ExternalFlowDirection, FeeProfileId, JournalKey,
    MarketConfig, MarketExecution, MatchType, OrderAction, OrderStatus, Outcome, PriceTimeBook,
    PrivateTradingCore, ReceiptSigner, SessionRequest, SignedSessionRequest, TimeInForce,
    UserCommand, UserCommandAction,
};
use ed25519_dalek::{Signer, SigningKey};
use proptest::prelude::*;
use sha2::{Digest, Sha256};
use uuid::Uuid;

const MARKET_ID: &str = "layrs:v3:ZEN:15m:normal-certification";
const ONE_ZEN: u128 = 1_000_000_000_000_000_000;

fn order(
    id: u128,
    owner: &str,
    outcome: Outcome,
    action: OrderAction,
    price_micros: u64,
    quantity_micros: u128,
    time_in_force: TimeInForce,
) -> BookOrder {
    BookOrder::with_id(
        Uuid::from_u128(id),
        owner,
        MARKET_ID,
        outcome,
        action,
        price_micros,
        quantity_micros,
        time_in_force,
        None,
    )
}

#[test]
fn normal_matching_is_best_price_fifo_partial_and_self_trade_safe() {
    let run = || {
        let now = 1_000;
        let mut book = PriceTimeBook::default();

        // Better-priced self liquidity must never execute.
        book.submit(
            order(
                1,
                "taker",
                Outcome::Up,
                OrderAction::Sell,
                250_000,
                1_000_000,
                TimeInForce::Gtc,
            ),
            now,
        )
        .unwrap();
        // Equal-priced makers must remain FIFO.
        for (id, owner) in [(2, "maker-early"), (3, "maker-late")] {
            book.submit(
                order(
                    id,
                    owner,
                    Outcome::Up,
                    OrderAction::Sell,
                    350_000,
                    2_000_000,
                    TimeInForce::Gtc,
                ),
                now,
            )
            .unwrap();
        }
        book.submit(
            order(
                4,
                "maker-worse",
                Outcome::Up,
                OrderAction::Sell,
                400_000,
                2_000_000,
                TimeInForce::Gtc,
            ),
            now,
        )
        .unwrap();

        // Neither a different outcome nor the same action is NORMAL liquidity.
        book.submit(
            order(
                5,
                "down-seller",
                Outcome::Down,
                OrderAction::Sell,
                900_000,
                5_000_000,
                TimeInForce::Gtc,
            ),
            now,
        )
        .unwrap();
        book.submit(
            order(
                6,
                "up-buyer",
                Outcome::Up,
                OrderAction::Buy,
                100_000,
                5_000_000,
                TimeInForce::Gtc,
            ),
            now,
        )
        .unwrap();

        let result = book
            .submit(
                order(
                    7,
                    "taker",
                    Outcome::Up,
                    OrderAction::Buy,
                    400_000,
                    7_000_000,
                    TimeInForce::Fak,
                ),
                now + 1,
            )
            .unwrap();
        (book, result)
    };

    let (book, result) = run();
    assert_eq!(result.fills.len(), 3);
    assert_eq!(
        result
            .fills
            .iter()
            .map(|fill| fill.maker_order_id)
            .collect::<Vec<_>>(),
        vec![Uuid::from_u128(2), Uuid::from_u128(3), Uuid::from_u128(4)]
    );
    assert_eq!(
        result
            .fills
            .iter()
            .map(|fill| fill.price_micros)
            .collect::<Vec<_>>(),
        vec![350_000, 350_000, 400_000]
    );
    assert!(result
        .fills
        .iter()
        .all(|fill| fill.match_type == MatchType::Normal
            && fill.outcome == Outcome::Up
            && fill.maker_outcome() == Outcome::Up
            && fill.quantity_micros == 2_000_000
            && fill.maker_private_user_id != fill.taker_private_user_id));
    assert_eq!(result.cancelled_remainder_micros, 1_000_000);
    let accepted = result.accepted_order.as_ref().unwrap();
    assert_eq!(accepted.status, OrderStatus::PartiallyFilled);
    assert_eq!(accepted.filled_micros, 6_000_000);
    assert_eq!(accepted.remaining_micros, 0);

    // STP and match classification leave all ineligible orders untouched.
    for id in [1, 5, 6] {
        let resting = book.order(Uuid::from_u128(id)).unwrap();
        assert_eq!(resting.filled_micros, 0);
        assert_eq!(resting.remaining_micros, resting.quantity_micros);
        assert_eq!(resting.status, OrderStatus::Open);
    }

    // Fixed IDs and deterministic sequence allocation make fills replay-identical.
    let (_, replayed) = run();
    assert_eq!(result, replayed);
}

#[test]
fn normal_fok_rejection_is_atomic_and_gtc_remainder_stays_resting() {
    let now = 1_000;
    let mut book = PriceTimeBook::default();
    let maker_id = Uuid::from_u128(20);
    book.submit(
        order(
            20,
            "maker",
            Outcome::Down,
            OrderAction::Buy,
            650_000,
            2_000_000,
            TimeInForce::Gtc,
        ),
        now,
    )
    .unwrap();

    let rejected = book
        .submit(
            order(
                21,
                "fok-seller",
                Outcome::Down,
                OrderAction::Sell,
                600_000,
                3_000_000,
                TimeInForce::Fok,
            ),
            now + 1,
        )
        .unwrap();
    assert!(rejected.fills.is_empty());
    assert_eq!(
        rejected.accepted_order.unwrap().status,
        OrderStatus::Rejected
    );
    assert_eq!(book.order(maker_id).unwrap().remaining_micros, 2_000_000);

    let partial = book
        .submit(
            order(
                22,
                "gtc-seller",
                Outcome::Down,
                OrderAction::Sell,
                600_000,
                3_000_000,
                TimeInForce::Gtc,
            ),
            now + 2,
        )
        .unwrap();
    assert_eq!(partial.fills.len(), 1);
    assert_eq!(partial.fills[0].match_type, MatchType::Normal);
    assert_eq!(partial.fills[0].price_micros, 650_000);
    let accepted = partial.accepted_order.unwrap();
    assert_eq!(accepted.status, OrderStatus::PartiallyFilled);
    assert_eq!(accepted.filled_micros, 2_000_000);
    assert_eq!(accepted.remaining_micros, 1_000_000);
    assert_eq!(book.order(maker_id).unwrap().status, OrderStatus::Filled);
}

proptest! {
    #[test]
    fn normal_crosses_conserve_quantity_and_replay_for_both_actions(
        maker_price in 1u64..999_999,
        improvement in 0u64..50_000,
        quantity in 1u128..10_000_000,
        incoming_is_buy in any::<bool>(),
    ) {
        let (maker_action, incoming_action, incoming_limit) = if incoming_is_buy {
            (
                OrderAction::Sell,
                OrderAction::Buy,
                maker_price.saturating_add(improvement).min(999_999),
            )
        } else {
            (
                OrderAction::Buy,
                OrderAction::Sell,
                maker_price.saturating_sub(improvement).max(1),
            )
        };
        let run = || {
            let mut book = PriceTimeBook::default();
            book.submit(
                order(
                    30,
                    "maker",
                    Outcome::Up,
                    maker_action,
                    maker_price,
                    quantity,
                    TimeInForce::Gtc,
                ),
                1_000,
            )
            .unwrap();
            let result = book
                .submit(
                    order(
                        31,
                        "taker",
                        Outcome::Up,
                        incoming_action,
                        incoming_limit,
                        quantity,
                        TimeInForce::Fok,
                    ),
                    1_001,
                )
                .unwrap();
            (book, result)
        };

        let (book, result) = run();
        prop_assert_eq!(result.fills.len(), 1);
        let fill = &result.fills[0];
        prop_assert_eq!(fill.match_type, MatchType::Normal);
        prop_assert_eq!(fill.outcome, Outcome::Up);
        prop_assert_eq!(fill.price_micros, maker_price);
        prop_assert_eq!(fill.taker_price_micros(), maker_price);
        prop_assert_eq!(fill.quantity_micros, quantity);
        prop_assert_eq!(book.order(Uuid::from_u128(30)).unwrap().filled_micros, quantity);
        prop_assert_eq!(book.order(Uuid::from_u128(30)).unwrap().remaining_micros, 0);
        let accepted = result.accepted_order.as_ref().unwrap();
        prop_assert_eq!(accepted.filled_micros, quantity);
        prop_assert_eq!(accepted.remaining_micros, 0);
        prop_assert_eq!(accepted.status, OrderStatus::Filled);

        let (_, replayed) = run();
        prop_assert_eq!(result, replayed);
    }
}

#[test]
fn normal_fill_fees_cash_claims_and_snapshot_restore_are_conservative() {
    let run = || {
        let journal_key_bytes = [201u8; 32];
        let maker_key = SigningKey::from_bytes(&[202u8; 32]);
        let taker_key = SigningKey::from_bytes(&[203u8; 32]);
        let maker_commitment = [204u8; 32];
        let taker_commitment = [205u8; 32];
        let maker_owner = derived_private_user(journal_key_bytes, maker_commitment);
        let taker_owner = derived_private_user(journal_key_bytes, taker_commitment);
        let journal_key = JournalKey::from_bytes(journal_key_bytes);
        let mut core =
            PrivateTradingCore::new(journal_key.clone(), ReceiptSigner::generate([206u8; 48]));
        core.register_market(
            "sys:market:normal-certification".into(),
            MarketConfig {
                market_id: MARKET_ID.into(),
                settlement_asset: "ZEN".into(),
                settlement_decimals: 18,
                public_settlement_chain: Some("horizen".into()),
                opens_at_millis: 900,
                closes_at_millis: 4_000,
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
        for (label, key, commitment, evidence) in [
            ("maker", &maker_key, maker_commitment, [207u8; 32]),
            ("taker", &taker_key, taker_commitment, [208u8; 32]),
        ] {
            core.register_session(
                format!("sys:session:{label}"),
                format!("session:{label}"),
                commitment,
                key.verifying_key().to_bytes(),
                5_000,
                825,
            )
            .unwrap();
            core.apply_user_external_flow(
                format!("sys:deposit:{label}"),
                commitment,
                "ZEN".into(),
                AccountBucket::UserAvailable,
                3 * ONE_ZEN,
                ExternalFlowDirection::Inflow,
                evidence,
                850,
            )
            .unwrap();
        }

        execute(
            &mut core,
            &maker_key,
            "session:maker",
            1,
            "cmd:maker:mint",
            UserCommandAction::CompleteSet {
                market_id: MARKET_ID.into(),
                quantity_micros: 2_000_000,
                direction: CompleteSetDirection::Mint,
            },
            1_000,
        );
        execute(
            &mut core,
            &maker_key,
            "session:maker",
            2,
            "cmd:maker:sell-up",
            UserCommandAction::SubmitOrder {
                order: order(
                    40,
                    "ignored",
                    Outcome::Up,
                    OrderAction::Sell,
                    350_000,
                    2_000_000,
                    TimeInForce::Gtc,
                ),
            },
            1_100,
        );
        let fill = execute(
            &mut core,
            &taker_key,
            "session:taker",
            1,
            "cmd:taker:buy-up",
            UserCommandAction::SubmitOrder {
                order: order(
                    41,
                    "ignored",
                    Outcome::Up,
                    OrderAction::Buy,
                    400_000,
                    2_000_000,
                    TimeInForce::Fok,
                ),
            },
            1_200,
        );

        let expected_fee = 1_400_000_000_000_000u128;
        assert_eq!(fill.audit_fills.len(), 1);
        let statement = &fill.audit_fills[0].statement;
        assert_eq!(statement.match_type.as_deref(), Some("NORMAL"));
        assert_eq!(statement.outcome.as_deref(), Some("UP"));
        assert_eq!(statement.price_micros, 350_000);
        assert_eq!(statement.quantity_atomic, "2000000");
        assert_eq!(statement.fee_atomic, expected_fee.to_string());
        assert_ne!(
            statement.buyer_one_time_pseudonym,
            statement.seller_one_time_pseudonym
        );

        let maker_available = core.balance(&available(&maker_owner));
        let taker_available = core.balance(&available(&taker_owner));
        let fee = core.balance(&AccountKey::new("layrs", AccountBucket::FeeRevenue, "ZEN"));
        let collateral = core.balance(&market_collateral());
        assert_eq!(maker_available, 1_700_000_000_000_000_000);
        assert_eq!(taker_available, 2_298_600_000_000_000_000);
        assert_eq!(fee, expected_fee);
        assert_eq!(collateral, 2 * ONE_ZEN);
        assert_eq!(
            maker_available + taker_available + fee + collateral,
            6 * ONE_ZEN
        );
        assert_eq!(core.balance(&claim(&maker_owner, Outcome::Up)), 0);
        assert_eq!(core.balance(&claim(&maker_owner, Outcome::Down)), 2_000_000);
        assert_eq!(core.balance(&claim(&taker_owner, Outcome::Up)), 2_000_000);
        assert_eq!(core.balance(&claim(&taker_owner, Outcome::Down)), 0);

        let snapshot = core.export_encrypted_snapshot().unwrap();
        let restored = PrivateTradingCore::restore_encrypted_snapshot(
            journal_key,
            ReceiptSigner::generate([209u8; 48]),
            &snapshot,
            snapshot.sequence,
        )
        .unwrap();
        assert_eq!(restored.state_root(), core.state_root());
        assert_eq!(restored.balance(&available(&maker_owner)), maker_available);
        assert_eq!(restored.balance(&available(&taker_owner)), taker_available);
        assert_eq!(restored.balance(&market_collateral()), collateral);
        assert_eq!(
            restored.balance(&claim(&taker_owner, Outcome::Up)),
            2_000_000
        );

        (
            core.state_root(),
            fill.result,
            fill.audit_fills[0].statement.clone(),
            maker_available,
            taker_available,
            fee,
            collateral,
        )
    };

    assert_eq!(run(), run());
}

fn execute(
    core: &mut PrivateTradingCore,
    key: &SigningKey,
    session_id: &str,
    sequence: u64,
    command_id: &str,
    action: UserCommandAction,
    now_millis: i64,
) -> CoreResponse {
    let idempotency_key = format!("idem:{command_id}");
    let request_hash = command_request_hash(command_id, &idempotency_key, &action).unwrap();
    let request = SessionRequest {
        session_id: session_id.into(),
        sequence,
        issued_at_millis: now_millis,
        expires_at_millis: 4_900,
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

fn available(owner: &str) -> AccountKey {
    AccountKey::new(owner, AccountBucket::UserAvailable, "ZEN")
}

fn market_collateral() -> AccountKey {
    let mut account = AccountKey::new("layrs", AccountBucket::MarketCollateral, "ZEN");
    account.market_id = Some(MARKET_ID.into());
    account
}

fn claim(owner: &str, outcome: Outcome) -> AccountKey {
    let outcome = match outcome {
        Outcome::Up => "UP",
        Outcome::Down => "DOWN",
    };
    AccountKey::position(
        owner,
        format!("CLAIM:{MARKET_ID}:{outcome}"),
        MARKET_ID,
        outcome,
    )
}
