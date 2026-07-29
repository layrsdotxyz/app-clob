use clob_service::private_core::{
    command_request_hash, signing_payload, AccountBucket, AccountKey, BookOrder, CommandResult,
    ExternalFlowDirection, Fill, JournalKey, MarketConfig, MarketExecution, MatchType, OrderAction,
    OrderStatus, Outcome, PriceTimeBook, PrivateTradingCore, ReceiptSigner, SessionRequest,
    SignedSessionRequest, TimeInForce, UserCommand, UserCommandAction,
};
use ed25519_dalek::{Signer, SigningKey};
use proptest::prelude::*;
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[test]
fn normal_fill_retains_the_legacy_serialized_shape() {
    let fill = Fill {
        fill_id: Uuid::from_u128(1),
        market_id: "layrs:v3:ZEN:15m:1785300300".to_owned(),
        outcome: Outcome::Up,
        match_type: MatchType::Normal,
        maker_order_id: Uuid::from_u128(2),
        taker_order_id: Uuid::from_u128(3),
        maker_private_user_id: "maker".to_owned(),
        taker_private_user_id: "taker".to_owned(),
        price_micros: 400_000,
        quantity_micros: 1_000_000,
        sequence: 4,
    };

    let value = serde_json::to_value(&fill).expect("serialize normal fill");
    assert!(
        value.get("match_type").is_none(),
        "NORMAL must preserve the pre-feature journal/state-root wire shape"
    );
    let restored: Fill = serde_json::from_value(value).expect("restore legacy-shaped fill");
    assert_eq!(restored, fill);
}

const MARKET_ID: &str = "layrs:v3:ZEN:15m:2000";
const ONE_ZEN: u128 = 1_000_000_000_000_000_000;

#[test]
fn complementary_buy_boundary_partial_and_fok_semantics_are_deterministic() {
    let now = 1_000;
    let mut book = PriceTimeBook::default();
    let maker_id = Uuid::from_u128(1);
    book.submit(
        BookOrder::with_id(
            maker_id,
            "maker",
            MARKET_ID,
            Outcome::Up,
            OrderAction::Buy,
            400_000,
            500_000,
            TimeInForce::Gtc,
            None,
        ),
        now,
    )
    .unwrap();

    let below = book
        .submit(
            BookOrder::with_id(
                Uuid::from_u128(2),
                "below",
                MARKET_ID,
                Outcome::Down,
                OrderAction::Buy,
                599_999,
                100_000,
                TimeInForce::Fak,
                None,
            ),
            now,
        )
        .unwrap();
    assert!(below.fills.is_empty());
    assert_eq!(below.cancelled_remainder_micros, 100_000);

    let fok = book
        .submit(
            BookOrder::with_id(
                Uuid::from_u128(3),
                "fok",
                MARKET_ID,
                Outcome::Down,
                OrderAction::Buy,
                600_000,
                600_000,
                TimeInForce::Fok,
                None,
            ),
            now,
        )
        .unwrap();
    assert_eq!(fok.accepted_order.unwrap().status, OrderStatus::Rejected);
    assert!(fok.fills.is_empty());

    let partial = book
        .submit(
            BookOrder::with_id(
                Uuid::from_u128(4),
                "partial",
                MARKET_ID,
                Outcome::Down,
                OrderAction::Buy,
                600_000,
                700_000,
                TimeInForce::Fak,
                None,
            ),
            now,
        )
        .unwrap();
    assert_eq!(partial.fills.len(), 1);
    assert_eq!(partial.fills[0].match_type, MatchType::Mint);
    assert_eq!(partial.fills[0].maker_order_id, maker_id);
    assert_eq!(partial.fills[0].quantity_micros, 500_000);
    assert_eq!(partial.fills[0].price_micros, 400_000);
    assert_eq!(partial.fills[0].taker_price_micros(), 600_000);
    assert_eq!(partial.cancelled_remainder_micros, 200_000);

    let mut replay = PriceTimeBook::default();
    replay
        .submit(
            BookOrder::with_id(
                maker_id,
                "maker",
                MARKET_ID,
                Outcome::Up,
                OrderAction::Buy,
                400_000,
                500_000,
                TimeInForce::Gtc,
                None,
            ),
            now,
        )
        .unwrap();
    replay
        .submit(
            BookOrder::with_id(
                Uuid::from_u128(2),
                "below",
                MARKET_ID,
                Outcome::Down,
                OrderAction::Buy,
                599_999,
                100_000,
                TimeInForce::Fak,
                None,
            ),
            now,
        )
        .unwrap();
    replay
        .submit(
            BookOrder::with_id(
                Uuid::from_u128(3),
                "fok",
                MARKET_ID,
                Outcome::Down,
                OrderAction::Buy,
                600_000,
                600_000,
                TimeInForce::Fok,
                None,
            ),
            now,
        )
        .unwrap();
    let replayed = replay
        .submit(
            BookOrder::with_id(
                Uuid::from_u128(4),
                "partial",
                MARKET_ID,
                Outcome::Down,
                OrderAction::Buy,
                600_000,
                700_000,
                TimeInForce::Fak,
                None,
            ),
            now,
        )
        .unwrap();
    assert_eq!(partial, replayed);
}

#[test]
fn complementary_self_trade_is_prevented_across_outcomes() {
    let mut book = PriceTimeBook::default();
    book.submit(
        BookOrder::with_id(
            Uuid::from_u128(10),
            "same-user",
            MARKET_ID,
            Outcome::Up,
            OrderAction::Buy,
            400_000,
            1_000_000,
            TimeInForce::Gtc,
            None,
        ),
        1_000,
    )
    .unwrap();
    let result = book
        .submit(
            BookOrder::with_id(
                Uuid::from_u128(11),
                "same-user",
                MARKET_ID,
                Outcome::Down,
                OrderAction::Buy,
                600_000,
                1_000_000,
                TimeInForce::Fak,
                None,
            ),
            1_000,
        )
        .unwrap();
    assert!(result.fills.is_empty());
    assert_eq!(result.cancelled_remainder_micros, 1_000_000);
}

#[test]
fn complementary_sell_boundary_crosses_but_price_sum_above_one_does_not() {
    let mut book = PriceTimeBook::default();
    book.submit(
        BookOrder::with_id(
            Uuid::from_u128(12),
            "up-seller",
            MARKET_ID,
            Outcome::Up,
            OrderAction::Sell,
            400_000,
            1_000_000,
            TimeInForce::Gtc,
            None,
        ),
        1_000,
    )
    .unwrap();
    let above = book
        .submit(
            BookOrder::with_id(
                Uuid::from_u128(13),
                "above",
                MARKET_ID,
                Outcome::Down,
                OrderAction::Sell,
                600_001,
                250_000,
                TimeInForce::Fak,
                None,
            ),
            1_000,
        )
        .unwrap();
    assert!(above.fills.is_empty());

    let boundary = book
        .submit(
            BookOrder::with_id(
                Uuid::from_u128(14),
                "boundary",
                MARKET_ID,
                Outcome::Down,
                OrderAction::Sell,
                600_000,
                1_000_000,
                TimeInForce::Fok,
                None,
            ),
            1_000,
        )
        .unwrap();
    assert_eq!(boundary.fills.len(), 1);
    assert_eq!(boundary.fills[0].match_type, MatchType::Merge);
    assert_eq!(boundary.fills[0].taker_price_micros(), 600_000);
}

#[test]
fn effective_price_priority_prefers_normal_then_complete_set_on_tie() {
    let mut book = PriceTimeBook::default();
    let complementary = Uuid::from_u128(20);
    let normal = Uuid::from_u128(21);
    book.submit(
        BookOrder::with_id(
            complementary,
            "mint-maker",
            MARKET_ID,
            Outcome::Down,
            OrderAction::Buy,
            600_000,
            1_000_000,
            TimeInForce::Gtc,
            None,
        ),
        1_000,
    )
    .unwrap();
    book.submit(
        BookOrder::with_id(
            normal,
            "normal-maker",
            MARKET_ID,
            Outcome::Up,
            OrderAction::Sell,
            400_000,
            1_000_000,
            TimeInForce::Gtc,
            None,
        ),
        1_000,
    )
    .unwrap();
    let result = book
        .submit(
            BookOrder::with_id(
                Uuid::from_u128(22),
                "taker",
                MARKET_ID,
                Outcome::Up,
                OrderAction::Buy,
                400_000,
                2_000_000,
                TimeInForce::Fok,
                None,
            ),
            1_000,
        )
        .unwrap();
    assert_eq!(result.fills.len(), 2);
    assert_eq!(result.fills[0].maker_order_id, normal);
    assert_eq!(result.fills[0].match_type, MatchType::Normal);
    assert_eq!(result.fills[1].maker_order_id, complementary);
    assert_eq!(result.fills[1].match_type, MatchType::Mint);
}

#[test]
fn mint_then_merge_conserves_collateral_and_charges_only_the_taker() {
    let (mut core, up_key, down_key, up_owner, down_owner) = configured_core();

    let up_order = BookOrder::with_id(
        Uuid::from_u128(100),
        "ignored",
        MARKET_ID,
        Outcome::Up,
        OrderAction::Buy,
        400_000,
        1_000_000,
        TimeInForce::Gtc,
        None,
    );
    execute(
        &mut core,
        &up_key,
        "session:up",
        1,
        "cmd:mint-maker",
        UserCommandAction::SubmitOrder { order: up_order },
        1_000,
    );
    let mint = execute(
        &mut core,
        &down_key,
        "session:down",
        1,
        "cmd:mint-taker",
        UserCommandAction::SubmitOrder {
            order: BookOrder::with_id(
                Uuid::from_u128(101),
                "ignored",
                MARKET_ID,
                Outcome::Down,
                OrderAction::Buy,
                600_000,
                1_000_000,
                TimeInForce::Fok,
                None,
            ),
        },
        1_050,
    );
    let mint_result = order_result(&mint.result);
    assert_eq!(mint_result.fills[0].match_type, MatchType::Mint);
    assert_eq!(mint_result.fills[0].taker_price_micros(), 600_000);
    assert_eq!(mint.audit_fills[0].statement.price_micros, 600_000);

    let collateral = market_collateral();
    let fee = AccountKey::new("layrs", AccountBucket::FeeRevenue, "ZEN");
    assert_eq!(core.balance(&collateral), ONE_ZEN);
    assert_eq!(core.balance(&claim(&up_owner, Outcome::Up)), 1_000_000);
    assert_eq!(core.balance(&claim(&down_owner, Outcome::Down)), 1_000_000);
    assert_eq!(core.balance(&claim(&up_owner, Outcome::Down)), 0);
    assert_eq!(core.balance(&claim(&down_owner, Outcome::Up)), 0);
    assert_eq!(core.balance(&fee), 1_200_000_000_000_000);

    execute(
        &mut core,
        &up_key,
        "session:up",
        2,
        "cmd:merge-maker",
        UserCommandAction::SubmitOrder {
            order: BookOrder::with_id(
                Uuid::from_u128(102),
                "ignored",
                MARKET_ID,
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
    let merge = execute(
        &mut core,
        &down_key,
        "session:down",
        2,
        "cmd:merge-taker",
        UserCommandAction::SubmitOrder {
            order: BookOrder::with_id(
                Uuid::from_u128(103),
                "ignored",
                MARKET_ID,
                Outcome::Down,
                OrderAction::Sell,
                600_000,
                1_000_000,
                TimeInForce::Fok,
                None,
            ),
        },
        1_150,
    );
    let merge_result = order_result(&merge.result);
    assert_eq!(merge_result.fills[0].match_type, MatchType::Merge);
    assert_eq!(merge_result.fills[0].taker_price_micros(), 600_000);
    assert_eq!(merge.audit_fills[0].statement.price_micros, 600_000);

    assert_eq!(core.balance(&collateral), 0);
    assert_eq!(core.balance(&claim(&up_owner, Outcome::Up)), 0);
    assert_eq!(core.balance(&claim(&down_owner, Outcome::Down)), 0);
    assert_eq!(core.balance(&fee), 2_400_000_000_000_000);
    assert_eq!(
        core.balance(&AccountKey::new(
            &up_owner,
            AccountBucket::UserAvailable,
            "ZEN"
        )),
        ONE_ZEN
    );
    assert_eq!(
        core.balance(&AccountKey::new(
            &down_owner,
            AccountBucket::UserAvailable,
            "ZEN"
        )),
        997_600_000_000_000_000
    );
    assert_eq!(
        core.balance(&AccountKey::new(
            &up_owner,
            AccountBucket::UserAvailable,
            "ZEN"
        )) + core.balance(&AccountKey::new(
            &down_owner,
            AccountBucket::UserAvailable,
            "ZEN"
        )) + core.balance(&fee)
            + core.balance(&collateral),
        2 * ONE_ZEN
    );
}

#[test]
fn complete_set_command_replay_produces_identical_fill_and_state_root() {
    let run = || {
        let (mut core, up_key, down_key, _, _) = configured_core();
        execute(
            &mut core,
            &up_key,
            "session:up",
            1,
            "cmd:deterministic-maker",
            UserCommandAction::SubmitOrder {
                order: BookOrder::with_id(
                    Uuid::from_u128(700),
                    "ignored",
                    MARKET_ID,
                    Outcome::Up,
                    OrderAction::Buy,
                    400_000,
                    1_000_000,
                    TimeInForce::Gtc,
                    None,
                ),
            },
            1_000,
        );
        execute(
            &mut core,
            &down_key,
            "session:down",
            1,
            "cmd:deterministic-taker",
            UserCommandAction::SubmitOrder {
                order: BookOrder::with_id(
                    Uuid::from_u128(701),
                    "ignored",
                    MARKET_ID,
                    Outcome::Down,
                    OrderAction::Buy,
                    600_000,
                    1_000_000,
                    TimeInForce::Fok,
                    None,
                ),
            },
            1_050,
        )
    };
    let first = run();
    let second = run();
    assert_eq!(first.result, second.result);
    assert_eq!(first.receipt.state_root, second.receipt.state_root);
    assert_eq!(
        first.audit_fills[0].statement,
        second.audit_fills[0].statement
    );
}

proptest! {
    #[test]
    fn complementary_crossing_is_deterministic_for_valid_prices_and_sizes(
        maker_price in 1u64..999_999,
        price_improvement in 0u64..10_000,
        quantity in 1u128..10_000_000,
    ) {
        let complementary = 1_000_000u64 - maker_price;
        let taker_limit = complementary.saturating_add(price_improvement).min(999_999);
        prop_assume!(taker_limit >= complementary);
        let maker = BookOrder::with_id(
            Uuid::from_u128(500),
            "maker",
            MARKET_ID,
            Outcome::Up,
            OrderAction::Buy,
            maker_price,
            quantity,
            TimeInForce::Gtc,
            None,
        );
        let taker = BookOrder::with_id(
            Uuid::from_u128(501),
            "taker",
            MARKET_ID,
            Outcome::Down,
            OrderAction::Buy,
            taker_limit,
            quantity,
            TimeInForce::Fok,
            None,
        );
        let run = || {
            let mut book = PriceTimeBook::default();
            book.submit(maker.clone(), 1_000).unwrap();
            book.submit(taker.clone(), 1_000).unwrap()
        };
        let first = run();
        let second = run();
        prop_assert_eq!(&first, &second);
        prop_assert_eq!(first.fills.len(), 1);
        prop_assert_eq!(first.fills[0].match_type, MatchType::Mint);
        prop_assert_eq!(
            first.fills[0].price_micros + first.fills[0].taker_price_micros(),
            1_000_000
        );
        prop_assert_eq!(first.fills[0].quantity_micros, quantity);
    }
}

fn configured_core() -> (PrivateTradingCore, SigningKey, SigningKey, String, String) {
    let journal_key = [31u8; 32];
    let up_key = SigningKey::from_bytes(&[32u8; 32]);
    let down_key = SigningKey::from_bytes(&[33u8; 32]);
    let up_commitment = [34u8; 32];
    let down_commitment = [35u8; 32];
    let up_owner = derived_private_user(journal_key, up_commitment);
    let down_owner = derived_private_user(journal_key, down_commitment);
    let mut core = PrivateTradingCore::new(
        JournalKey::from_bytes(journal_key),
        ReceiptSigner::generate([36u8; 48]),
    );
    core.register_market(
        "sys:market:complete-set".into(),
        MarketConfig {
            market_id: MARKET_ID.into(),
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
            tick_size_micros: 100,
            oracle_feed_id: 245,
            execution: MarketExecution::NativeClob,
        },
        800,
    )
    .unwrap();
    for (label, key, commitment, evidence) in [
        ("up", &up_key, up_commitment, [37u8; 32]),
        ("down", &down_key, down_commitment, [38u8; 32]),
    ] {
        core.register_session(
            format!("sys:session:{label}"),
            format!("session:{label}"),
            commitment,
            key.verifying_key().to_bytes(),
            3_000,
            850,
        )
        .unwrap();
        core.apply_user_external_flow(
            format!("sys:deposit:{label}"),
            commitment,
            "ZEN".into(),
            AccountBucket::UserAvailable,
            ONE_ZEN,
            ExternalFlowDirection::Inflow,
            evidence,
            875,
        )
        .unwrap();
    }
    (core, up_key, down_key, up_owner, down_owner)
}

#[allow(clippy::too_many_arguments)]
fn execute(
    core: &mut PrivateTradingCore,
    key: &SigningKey,
    session_id: &str,
    sequence: u64,
    command_id: &str,
    action: UserCommandAction,
    now_millis: i64,
) -> clob_service::private_core::CoreResponse {
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
}

fn order_result(result: &CommandResult) -> &clob_service::private_core::MatchResult {
    match result {
        CommandResult::Order { result } => result,
        _ => panic!("expected order result"),
    }
}

fn claim(owner: &str, outcome: Outcome) -> AccountKey {
    let name = match outcome {
        Outcome::Up => "UP",
        Outcome::Down => "DOWN",
    };
    AccountKey::position(owner, format!("CLAIM:{MARKET_ID}:{name}"), MARKET_ID, name)
}

fn market_collateral() -> AccountKey {
    let mut account = AccountKey::new("layrs", AccountBucket::MarketCollateral, "ZEN");
    account.market_id = Some(MARKET_ID.into());
    account
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
