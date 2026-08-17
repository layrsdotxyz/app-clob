use clob_service::private_core::{
    command_request_hash, exact_condition_resolution_signing_payload, resolution_signing_payload,
    signing_payload, AccountBucket, AccountKey, BookOrder, BoundaryEvidence, CommandResult,
    CompleteSetDirection, ExactConditionResolutionStatement, ExternalFlowDirection, FeeProfileId,
    JournalKey, MarketConfig, MarketExecution, MatchType, OrderAction, OrderStatus, Outcome,
    PriceTimeBook, PrivateTradingCore, ReceiptSigner, ResolutionOutcome, ResolutionStatement,
    SessionRequest, SignedExactConditionResolution, SignedResolution, SignedSessionRequest,
    TimeInForce, UserCommand, UserCommandAction,
};
use ed25519_dalek::{Signer, SigningKey};
use proptest::prelude::*;
use sha2::{Digest, Sha256};
use uuid::Uuid;

const MARKET_ID: &str = "layrs:v3:ZEN:15m:2000";
const ONE_ZEN: u128 = 1_000_000_000_000_000_000;
const ORACLE_KEY: [u8; 32] = [39u8; 32];

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
fn complementary_rounding_dust_does_not_poison_a_price_level() {
    let now = 1_000;
    let mut book = PriceTimeBook::default();
    let dust_maker_id = Uuid::from_u128(5);
    let clean_maker_id = Uuid::from_u128(6);

    book.submit(
        BookOrder::with_id(
            dust_maker_id,
            "up-maker-one",
            MARKET_ID,
            Outcome::Up,
            OrderAction::Buy,
            350_000,
            2_857_143,
            TimeInForce::Gtc,
            None,
        ),
        now,
    )
    .unwrap();
    let first = book
        .submit(
            BookOrder::with_id(
                Uuid::from_u128(7),
                "down-taker-one",
                MARKET_ID,
                Outcome::Down,
                OrderAction::Buy,
                650_000,
                2_857_142,
                TimeInForce::Fak,
                None,
            ),
            now + 1,
        )
        .unwrap();
    assert_eq!(first.fills.len(), 1);
    assert_eq!(first.fills[0].quantity_micros, 2_857_142);
    assert_eq!(book.order(dust_maker_id).unwrap().remaining_micros, 1);

    book.submit(
        BookOrder::with_id(
            clean_maker_id,
            "up-maker-two",
            MARKET_ID,
            Outcome::Up,
            OrderAction::Buy,
            350_000,
            2_500_000,
            TimeInForce::Gtc,
            None,
        ),
        now + 2,
    )
    .unwrap();
    let second_order = BookOrder::with_id(
        Uuid::from_u128(8),
        "down-taker-two",
        MARKET_ID,
        Outcome::Down,
        OrderAction::Buy,
        650_000,
        2_500_000,
        TimeInForce::Fok,
        None,
    );
    let before_second = book.clone();
    let second = book.submit(second_order.clone(), now + 3).unwrap();

    assert_eq!(second.fills.len(), 1);
    assert_eq!(second.fills[0].maker_order_id, clean_maker_id);
    assert_eq!(second.fills[0].quantity_micros, 2_500_000);
    assert_eq!(book.order(dust_maker_id).unwrap().remaining_micros, 1);

    let mut replay = before_second;
    assert_eq!(second, replay.submit(second_order, now + 3).unwrap());
}

#[test]
fn fok_ignores_complete_set_quantity_that_cannot_split_at_settlement_precision() {
    let now = 1_000;
    let mut book = PriceTimeBook::default();
    book.submit(
        BookOrder::with_id(
            Uuid::from_u128(9),
            "high-price-maker",
            MARKET_ID,
            Outcome::Up,
            OrderAction::Buy,
            650_000,
            2,
            TimeInForce::Gtc,
            None,
        ),
        now,
    )
    .unwrap();

    let result = book
        .submit(
            BookOrder::with_id(
                Uuid::from_u128(11),
                "complementary-taker",
                MARKET_ID,
                Outcome::Down,
                OrderAction::Buy,
                350_000,
                2,
                TimeInForce::Fok,
                None,
            ),
            now + 1,
        )
        .unwrap();
    assert!(result.fills.is_empty());
    assert_eq!(result.accepted_order.unwrap().status, OrderStatus::Rejected);
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
    assert_eq!(
        mint.audit_fills[0].statement.outcome.as_deref(),
        Some("DOWN")
    );
    assert_eq!(
        mint.audit_fills[0].statement.match_type.as_deref(),
        Some("MINT")
    );

    let collateral = market_collateral();
    let fee = AccountKey::new("layrs", AccountBucket::FeeRevenue, "ZEN");
    assert_eq!(core.balance(&collateral), ONE_ZEN);
    assert_eq!(core.balance(&claim(&up_owner, Outcome::Up)), 1_000_000);
    assert_eq!(core.balance(&claim(&down_owner, Outcome::Down)), 1_000_000);
    assert_eq!(core.balance(&claim(&up_owner, Outcome::Down)), 0);
    assert_eq!(core.balance(&claim(&down_owner, Outcome::Up)), 0);
    assert_eq!(core.balance(&fee), 1_200_000_000_000_000);
    let readiness = core.market_settlement_readiness(MARKET_ID, 1_075).unwrap();
    assert_eq!(readiness.collateral_atomic, ONE_ZEN);
    assert_eq!(readiness.up_liability_atomic, ONE_ZEN);
    assert_eq!(readiness.down_liability_atomic, ONE_ZEN);
    assert_eq!(readiness.push_liability_atomic, ONE_ZEN);
    assert_eq!(readiness.active_order_count, 0);
    assert!(
        readiness.cancellation_ready,
        "cancellation failed: {:?}",
        readiness.cancellation_error
    );
    assert!(readiness.up_solvent);
    assert!(readiness.down_solvent);
    assert!(readiness.push_solvent);

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
    assert_eq!(
        merge.audit_fills[0].statement.outcome.as_deref(),
        Some("DOWN")
    );
    assert_eq!(
        merge.audit_fills[0].statement.match_type.as_deref(),
        Some("MERGE")
    );

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
fn native_exact_condition_market_resolves_from_existing_collateral_without_venue_inflow() {
    let (mut core, up_key, down_key, up_owner, down_owner) = configured_exact_condition_core();
    execute(
        &mut core,
        &up_key,
        "session:up",
        1,
        "cmd:exact-up",
        UserCommandAction::SubmitOrder {
            order: BookOrder::with_id(
                Uuid::from_u128(210),
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
    let crossed = execute(
        &mut core,
        &down_key,
        "session:down",
        1,
        "cmd:exact-down",
        UserCommandAction::SubmitOrder {
            order: BookOrder::with_id(
                Uuid::from_u128(211),
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
    assert_eq!(
        order_result(&crossed.result).fills[0].match_type,
        MatchType::Mint
    );
    assert_eq!(core.balance(&market_collateral_usdc()), 1_000_000);

    let statement = ExactConditionResolutionStatement {
        market_id: MARKET_ID.into(),
        condition_id: format!("0x{}", "22".repeat(32)),
        outcome: ResolutionOutcome::Up,
        evidence_hash: [70u8; 32],
        issued_at_millis: 2_100,
    };
    let oracle = SigningKey::from_bytes(&ORACLE_KEY);
    let signature = oracle
        .sign(&exact_condition_resolution_signing_payload(&statement).unwrap())
        .to_bytes()
        .to_vec();
    core.resolve_exact_condition_market(
        "sys:resolve:exact".into(),
        SignedExactConditionResolution {
            statement,
            signature,
        },
        2_100,
    )
    .unwrap();

    assert_eq!(core.balance(&market_collateral_usdc()), 0);
    assert_eq!(core.balance(&claim(&up_owner, Outcome::Up)), 0);
    assert_eq!(core.balance(&claim(&down_owner, Outcome::Down)), 0);
    assert_eq!(
        core.balance(&AccountKey::new(
            &up_owner,
            AccountBucket::UserAvailable,
            "USDC"
        )),
        1_570_000
    );
    assert_eq!(
        core.balance(&AccountKey::new(
            &down_owner,
            AccountBucket::UserAvailable,
            "USDC"
        )),
        398_800
    );
    let fee = AccountKey::new("layrs", AccountBucket::FeeRevenue, "USDC");
    assert_eq!(core.balance(&fee), 31_200);
    assert_eq!(
        core.balance(&AccountKey::new(
            &up_owner,
            AccountBucket::UserAvailable,
            "USDC"
        )) + core.balance(&AccountKey::new(
            &down_owner,
            AccountBucket::UserAvailable,
            "USDC"
        )) + core.balance(&fee)
            + core.balance(&market_collateral_usdc()),
        2_000_000
    );
}

#[test]
fn native_exact_condition_rejects_wrong_condition_and_tampered_outcome_without_mutation() {
    let (mut wrong_condition_core, _, _, _, _) = configured_exact_condition_core();
    let oracle = SigningKey::from_bytes(&ORACLE_KEY);
    let wrong_condition = ExactConditionResolutionStatement {
        market_id: MARKET_ID.into(),
        condition_id: format!("0x{}", "23".repeat(32)),
        outcome: ResolutionOutcome::Up,
        evidence_hash: [71u8; 32],
        issued_at_millis: 2_100,
    };
    let signature = oracle
        .sign(&exact_condition_resolution_signing_payload(&wrong_condition).unwrap())
        .to_bytes()
        .to_vec();
    assert!(wrong_condition_core
        .resolve_exact_condition_market(
            "sys:resolve:wrong-condition".into(),
            SignedExactConditionResolution {
                statement: wrong_condition,
                signature,
            },
            2_100,
        )
        .is_err());
    assert!(wrong_condition_core.market_resolution(MARKET_ID).is_none());

    let (mut tampered_core, _, _, _, _) = configured_exact_condition_core();
    let signed_up = ExactConditionResolutionStatement {
        market_id: MARKET_ID.into(),
        condition_id: format!("0x{}", "22".repeat(32)),
        outcome: ResolutionOutcome::Up,
        evidence_hash: [72u8; 32],
        issued_at_millis: 2_100,
    };
    let signature = oracle
        .sign(&exact_condition_resolution_signing_payload(&signed_up).unwrap())
        .to_bytes()
        .to_vec();
    let tampered = ExactConditionResolutionStatement {
        outcome: ResolutionOutcome::Down,
        ..signed_up
    };
    assert!(tampered_core
        .resolve_exact_condition_market(
            "sys:resolve:tampered".into(),
            SignedExactConditionResolution {
                statement: tampered,
                signature,
            },
            2_100,
        )
        .is_err());
    assert!(tampered_core.market_resolution(MARKET_ID).is_none());
}

#[test]
fn two_internal_market_maker_identities_can_stress_native_usdc_without_privileged_credit() {
    let (mut core, up_key, down_key, up_owner, down_owner) =
        configured_exact_condition_core_with_balance(500_000_000);
    for index in 0u64..30 {
        execute(
            &mut core,
            &up_key,
            "session:up",
            index + 1,
            &format!("cmd:mm-up:{index}"),
            UserCommandAction::SubmitOrder {
                order: BookOrder::with_id(
                    Uuid::from_u128(1_000 + u128::from(index)),
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
            1_000 + index as i64,
        );
        let crossed = execute(
            &mut core,
            &down_key,
            "session:down",
            index + 1,
            &format!("cmd:mm-down:{index}"),
            UserCommandAction::SubmitOrder {
                order: BookOrder::with_id(
                    Uuid::from_u128(2_000 + u128::from(index)),
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
            1_050 + index as i64,
        );
        assert_eq!(order_result(&crossed.result).fills.len(), 1);
        assert_eq!(
            order_result(&crossed.result).fills[0].match_type,
            MatchType::Mint
        );
    }

    let collateral = market_collateral_usdc();
    let fee = AccountKey::new("layrs", AccountBucket::FeeRevenue, "USDC");
    let up_available = AccountKey::new(&up_owner, AccountBucket::UserAvailable, "USDC");
    let down_available = AccountKey::new(&down_owner, AccountBucket::UserAvailable, "USDC");
    assert_eq!(core.balance(&collateral), 30_000_000);
    assert_eq!(core.balance(&fee), 36_000);
    assert_eq!(core.balance(&claim(&up_owner, Outcome::Up)), 30_000_000);
    assert_eq!(core.balance(&claim(&down_owner, Outcome::Down)), 30_000_000);
    assert_eq!(
        core.balance(&up_available)
            + core.balance(&down_available)
            + core.balance(&collateral)
            + core.balance(&fee),
        1_000_000_000
    );
}

#[test]
fn complementary_mint_at_live_prices_remains_fully_collateralized_through_resolution() {
    let (mut core, up_key, down_key, up_owner, down_owner) = configured_core();
    let quantity_micros = 588_235;

    execute(
        &mut core,
        &up_key,
        "session:up",
        1,
        "cmd:live-mint-maker",
        UserCommandAction::SubmitOrder {
            order: BookOrder::with_id(
                Uuid::from_u128(104),
                "ignored",
                MARKET_ID,
                Outcome::Up,
                OrderAction::Buy,
                150_000,
                quantity_micros,
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
        "cmd:live-mint-taker",
        UserCommandAction::SubmitOrder {
            order: BookOrder::with_id(
                Uuid::from_u128(105),
                "ignored",
                MARKET_ID,
                Outcome::Down,
                OrderAction::Buy,
                850_000,
                quantity_micros,
                TimeInForce::Fok,
                None,
            ),
        },
        1_050,
    );

    assert_eq!(core.balance(&market_collateral()), 588_235_000_000_000_000);
    assert_eq!(
        core.balance(&claim(&up_owner, Outcome::Up)),
        quantity_micros
    );
    assert_eq!(
        core.balance(&claim(&down_owner, Outcome::Down)),
        quantity_micros
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
        market_id: MARKET_ID.into(),
        oracle_feed_id: 245,
        opening: boundary(900, 410_000_000, 40),
        closing: boundary(2_000, 400_000_000, 41),
        issued_at_millis: 2_100,
    };
    let oracle = SigningKey::from_bytes(&ORACLE_KEY);
    let signature = oracle
        .sign(&resolution_signing_payload(&statement).unwrap())
        .to_bytes()
        .to_vec();
    core.resolve_market(
        "sys:resolve:live-mint".into(),
        SignedResolution {
            statement,
            signature,
        },
        2_100,
    )
    .unwrap();

    assert_eq!(core.balance(&market_collateral()), 0);
    assert_eq!(core.balance(&claim(&up_owner, Outcome::Up)), 0);
    assert_eq!(core.balance(&claim(&down_owner, Outcome::Down)), 0);
    assert_eq!(
        core.balance(&AccountKey::new(
            &down_owner,
            AccountBucket::UserAvailable,
            "ZEN"
        )),
        1_082_824_200_000_000_000
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

#[test]
fn complementary_mint_self_trade_is_prevented_across_alias_sessions_and_replay() {
    let (mut core, primary_key, counterparty_key, primary_owner, _) = configured_core();
    let alias_key = SigningKey::from_bytes(&[40u8; 32]);
    core.register_session(
        "sys:session:up-alias".into(),
        "session:up-alias".into(),
        [34u8; 32],
        alias_key.verifying_key().to_bytes(),
        3_000,
        850,
    )
    .unwrap();

    let maker = execute(
        &mut core,
        &primary_key,
        "session:up",
        1,
        "cmd:alias-mint-maker",
        UserCommandAction::SubmitOrder {
            order: BookOrder::with_id(
                Uuid::from_u128(9_001),
                "caller-controlled-maker-alias",
                MARKET_ID,
                Outcome::Up,
                OrderAction::Buy,
                400_000,
                500_000,
                TimeInForce::Gtc,
                None,
            ),
        },
        1_000,
    );
    assert!(
        order_result(&maker.result)
            .accepted_order
            .as_ref()
            .unwrap()
            .private_user_id
            .is_empty(),
        "the private response must not echo either the canonical identity or caller alias"
    );

    let alias_action = UserCommandAction::SubmitOrder {
        order: BookOrder::with_id(
            Uuid::from_u128(9_002),
            "different-caller-controlled-alias",
            MARKET_ID,
            Outcome::Down,
            OrderAction::Buy,
            610_000,
            500_000,
            TimeInForce::Fak,
            None,
        ),
    };
    let blocked = execute(
        &mut core,
        &alias_key,
        "session:up-alias",
        1,
        "cmd:alias-mint-blocked",
        alias_action.clone(),
        1_010,
    );
    assert!(order_result(&blocked.result).fills.is_empty());
    assert_eq!(
        order_result(&blocked.result).cancelled_remainder_micros,
        500_000
    );
    assert_eq!(core.balance(&market_collateral()), 0);
    assert_eq!(core.balance(&claim(&primary_owner, Outcome::Up)), 0);
    assert_eq!(core.balance(&claim(&primary_owner, Outcome::Down)), 0);

    let root_after_block = core.state_root();
    let replay = execute(
        &mut core,
        &alias_key,
        "session:up-alias",
        1,
        "cmd:alias-mint-blocked",
        alias_action,
        1_011,
    );
    assert_eq!(replay, blocked);
    assert_eq!(core.state_root(), root_after_block);

    let control = execute(
        &mut core,
        &counterparty_key,
        "session:down",
        1,
        "cmd:alias-mint-control",
        UserCommandAction::SubmitOrder {
            order: BookOrder::with_id(
                Uuid::from_u128(9_003),
                "counterparty-alias",
                MARKET_ID,
                Outcome::Down,
                OrderAction::Buy,
                610_000,
                500_000,
                TimeInForce::Fok,
                None,
            ),
        },
        1_020,
    );
    assert_eq!(order_result(&control.result).fills.len(), 1);
    assert_eq!(
        order_result(&control.result).fills[0].match_type,
        MatchType::Mint
    );
}

#[test]
fn complementary_merge_self_trade_is_prevented_across_alias_sessions() {
    let (mut core, primary_key, counterparty_key, primary_owner, _) = configured_core();
    let alias_key = SigningKey::from_bytes(&[41u8; 32]);
    core.register_session(
        "sys:session:merge-alias".into(),
        "session:merge-alias".into(),
        [34u8; 32],
        alias_key.verifying_key().to_bytes(),
        3_000,
        850,
    )
    .unwrap();

    for (key, session, command) in [
        (&primary_key, "session:up", "cmd:primary-complete-set"),
        (
            &counterparty_key,
            "session:down",
            "cmd:counterparty-complete-set",
        ),
    ] {
        execute(
            &mut core,
            key,
            session,
            1,
            command,
            UserCommandAction::CompleteSet {
                market_id: MARKET_ID.into(),
                quantity_micros: 1_000_000,
                direction: CompleteSetDirection::Mint,
            },
            950,
        );
    }

    execute(
        &mut core,
        &primary_key,
        "session:up",
        2,
        "cmd:alias-merge-maker",
        UserCommandAction::SubmitOrder {
            order: BookOrder::with_id(
                Uuid::from_u128(9_011),
                "maker-alias",
                MARKET_ID,
                Outcome::Up,
                OrderAction::Sell,
                410_000,
                1_000_000,
                TimeInForce::Gtc,
                None,
            ),
        },
        1_000,
    );
    let blocked = execute(
        &mut core,
        &alias_key,
        "session:merge-alias",
        1,
        "cmd:alias-merge-blocked",
        UserCommandAction::SubmitOrder {
            order: BookOrder::with_id(
                Uuid::from_u128(9_012),
                "taker-alias",
                MARKET_ID,
                Outcome::Down,
                OrderAction::Sell,
                580_000,
                1_000_000,
                TimeInForce::Fak,
                None,
            ),
        },
        1_010,
    );
    assert!(order_result(&blocked.result).fills.is_empty());
    assert_eq!(
        order_result(&blocked.result).cancelled_remainder_micros,
        1_000_000
    );
    assert_eq!(core.balance(&market_collateral()), 2 * ONE_ZEN);
    assert_eq!(
        core.balance(&claim(&primary_owner, Outcome::Down)),
        1_000_000
    );

    let control = execute(
        &mut core,
        &counterparty_key,
        "session:down",
        2,
        "cmd:alias-merge-control",
        UserCommandAction::SubmitOrder {
            order: BookOrder::with_id(
                Uuid::from_u128(9_013),
                "counterparty-alias",
                MARKET_ID,
                Outcome::Down,
                OrderAction::Sell,
                580_000,
                1_000_000,
                TimeInForce::Fok,
                None,
            ),
        },
        1_020,
    );
    assert_eq!(order_result(&control.result).fills.len(), 1);
    assert_eq!(
        order_result(&control.result).fills[0].match_type,
        MatchType::Merge
    );
    assert_eq!(core.balance(&market_collateral()), ONE_ZEN);
}

#[test]
fn encrypted_snapshot_preserves_canonical_identity_across_alias_sessions() {
    let journal_key = JournalKey::from_bytes([31u8; 32]);
    let (mut core, primary_key, _, _, _) = configured_core();
    let alias_key = SigningKey::from_bytes(&[42u8; 32]);
    core.register_session(
        "sys:session:snapshot-alias".into(),
        "session:snapshot-alias".into(),
        [34u8; 32],
        alias_key.verifying_key().to_bytes(),
        3_000,
        850,
    )
    .unwrap();
    execute(
        &mut core,
        &primary_key,
        "session:up",
        1,
        "cmd:snapshot-stp-maker",
        UserCommandAction::SubmitOrder {
            order: BookOrder::with_id(
                Uuid::from_u128(9_021),
                "pre-snapshot-alias",
                MARKET_ID,
                Outcome::Up,
                OrderAction::Buy,
                350_000,
                500_000,
                TimeInForce::Gtc,
                None,
            ),
        },
        1_000,
    );

    let snapshot = core.export_encrypted_snapshot().unwrap();
    let mut restored = PrivateTradingCore::restore_encrypted_snapshot(
        journal_key,
        ReceiptSigner::generate([43u8; 48]),
        &snapshot,
        snapshot.sequence,
    )
    .unwrap();
    assert_eq!(restored.state_root(), core.state_root());

    let blocked = execute(
        &mut restored,
        &alias_key,
        "session:snapshot-alias",
        1,
        "cmd:snapshot-stp-blocked",
        UserCommandAction::SubmitOrder {
            order: BookOrder::with_id(
                Uuid::from_u128(9_022),
                "post-snapshot-alias",
                MARKET_ID,
                Outcome::Down,
                OrderAction::Buy,
                650_000,
                500_000,
                TimeInForce::Fak,
                None,
            ),
        },
        1_010,
    );
    assert!(order_result(&blocked.result).fills.is_empty());
    assert!(blocked.audit_fills.is_empty());
    assert_eq!(restored.balance(&market_collateral()), 0);
}

proptest! {
    #[test]
    fn cross_outcome_self_trade_filter_precedes_mint_merge_and_precision_checks(
        maker_price in 1u64..999_999,
        improvement in 0u64..10_000,
        quantity in prop_oneof![Just(1u128), 2u128..10_000_000],
        is_mint in any::<bool>(),
    ) {
        let taker_price = if is_mint {
            (1_000_000u64 - maker_price)
                .saturating_add(improvement)
                .min(999_999)
        } else {
            (1_000_000u64 - maker_price).saturating_sub(improvement).max(1)
        };
        let action = if is_mint { OrderAction::Buy } else { OrderAction::Sell };
        let mut book = PriceTimeBook::default();
        book.submit(
            BookOrder::with_id(
                Uuid::from_u128(9_101),
                "canonical-user",
                MARKET_ID,
                Outcome::Up,
                action,
                maker_price,
                quantity,
                TimeInForce::Gtc,
                None,
            ),
            1_000,
        ).unwrap();
        let blocked = book.submit(
            BookOrder::with_id(
                Uuid::from_u128(9_102),
                "canonical-user",
                MARKET_ID,
                Outcome::Down,
                action,
                taker_price,
                quantity,
                TimeInForce::Fak,
                None,
            ),
            1_001,
        ).unwrap();
        prop_assert!(blocked.fills.is_empty());
        prop_assert_eq!(blocked.cancelled_remainder_micros, quantity);
        let maker = book.order(Uuid::from_u128(9_101)).unwrap();
        prop_assert_eq!(maker.status, OrderStatus::Open);
        prop_assert_eq!(maker.remaining_micros, quantity);
    }
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

#[test]
fn live_shape_partial_mint_is_ready_for_resolution_after_cancelling_remainder() {
    let (mut core, up_key, down_key, up_owner, down_owner) = configured_core();
    execute(
        &mut core,
        &up_key,
        "session:up",
        1,
        "cmd:live-shape-maker",
        UserCommandAction::SubmitOrder {
            order: BookOrder::with_id(
                Uuid::from_u128(700),
                "ignored",
                MARKET_ID,
                Outcome::Up,
                OrderAction::Buy,
                150_000,
                1_000_000,
                TimeInForce::Gtc,
                None,
            ),
        },
        1_000,
    );
    let mint = execute(
        &mut core,
        &down_key,
        "session:down",
        1,
        "cmd:live-shape-taker",
        UserCommandAction::SubmitOrder {
            order: BookOrder::with_id(
                Uuid::from_u128(701),
                "ignored",
                MARKET_ID,
                Outcome::Down,
                OrderAction::Buy,
                850_000,
                588_235,
                TimeInForce::Fok,
                None,
            ),
        },
        1_050,
    );
    assert_eq!(
        order_result(&mint.result).fills[0].match_type,
        MatchType::Mint
    );

    let readiness = core.market_settlement_readiness(MARKET_ID, 2_001).unwrap();
    assert_eq!(readiness.active_order_count, 1);
    assert!(
        readiness.cancellation_ready,
        "cancellation failed: {:?}",
        readiness.cancellation_error
    );
    assert_eq!(readiness.up_claim_quantity_micros, 588_235);
    assert_eq!(readiness.down_claim_quantity_micros, 588_235);
    assert_eq!(readiness.collateral_atomic, 588_235_000_000_000_000);
    assert_eq!(readiness.down_liability_atomic, readiness.collateral_atomic);
    assert!(readiness.up_solvent);
    assert!(readiness.down_solvent);
    assert!(readiness.push_solvent);

    let oracle = SigningKey::from_bytes(&[39u8; 32]);
    let boundary = |end: i64, price: i64, marker: u8| BoundaryEvidence {
        window_start_micros: end * 1_000 - 5_000_000,
        window_end_micros: end * 1_000,
        median_price_e8: price,
        sample_count: 25,
        minimum_publisher_count: 3,
        signed_payload_commitment: [marker; 32],
    };
    let statement = ResolutionStatement {
        market_id: MARKET_ID.into(),
        oracle_feed_id: 245,
        opening: boundary(900, 1_000_000_000, 40),
        closing: boundary(2_000, 900_000_000, 41),
        issued_at_millis: 2_001,
    };
    let signature = oracle
        .sign(&resolution_signing_payload(&statement).unwrap())
        .to_bytes()
        .to_vec();
    core.resolve_market(
        "sys:resolve:live-shape".into(),
        SignedResolution {
            statement,
            signature,
        },
        2_001,
    )
    .unwrap();
    assert!(core.market_resolution(MARKET_ID).is_some());
    assert_eq!(core.balance(&claim(&up_owner, Outcome::Up)), 0);
    assert_eq!(core.balance(&claim(&down_owner, Outcome::Down)), 0);
}

#[test]
fn layrs_curve_fee_and_maker_rebate_are_private_and_conserved_on_mint() {
    let (mut core, up_key, down_key, _, _) =
        configured_core_with_profile(FeeProfileId::LayrsCryptoV2);
    execute(
        &mut core,
        &up_key,
        "session:up",
        1,
        "cmd:v2-rebate-maker",
        UserCommandAction::SubmitOrder {
            order: BookOrder::with_id(
                Uuid::from_u128(799),
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
    let taker_fill = execute(
        &mut core,
        &down_key,
        "session:down",
        1,
        "cmd:v2-rebate-taker",
        UserCommandAction::SubmitOrder {
            order: BookOrder::with_id(
                Uuid::from_u128(800),
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
    assert_eq!(
        order_result(&taker_fill.result).fills[0].match_type,
        MatchType::Mint
    );
    assert_eq!(
        taker_fill.audit_fills[0].statement.fee_atomic,
        "16800000000000000"
    );

    let maker_rewards = execute(
        &mut core,
        &up_key,
        "session:up",
        2,
        "cmd:v2-maker-rewards",
        UserCommandAction::Rewards,
        1_100,
    );
    let taker_rewards = execute(
        &mut core,
        &down_key,
        "session:down",
        2,
        "cmd:v2-taker-rewards",
        UserCommandAction::Rewards,
        1_100,
    );
    let CommandResult::Rewards { entitlements } = maker_rewards.result else {
        panic!("expected maker rewards");
    };
    assert_eq!(entitlements.len(), 1);
    assert_eq!(entitlements[0].cumulative_amount_atomic, "3360000000000000");
    assert_eq!(
        entitlements[0].cumulative_maker_rebate_atomic,
        "3360000000000000"
    );
    let CommandResult::Rewards { entitlements } = taker_rewards.result else {
        panic!("expected taker rewards");
    };
    assert_eq!(entitlements.len(), 1);
    assert_eq!(entitlements[0].cumulative_amount_atomic, "0");
    assert_eq!(
        entitlements[0].cumulative_taker_fees_atomic,
        "16800000000000000"
    );
}

fn configured_core() -> (PrivateTradingCore, SigningKey, SigningKey, String, String) {
    configured_core_with_profile(FeeProfileId::LegacyProfitV1)
}

fn configured_core_with_profile(
    fee_profile_id: FeeProfileId,
) -> (PrivateTradingCore, SigningKey, SigningKey, String, String) {
    let journal_key = [31u8; 32];
    let up_key = SigningKey::from_bytes(&[32u8; 32]);
    let down_key = SigningKey::from_bytes(&[33u8; 32]);
    let up_commitment = [34u8; 32];
    let down_commitment = [35u8; 32];
    let up_owner = derived_private_user(journal_key, up_commitment);
    let down_owner = derived_private_user(journal_key, down_commitment);
    let oracle = SigningKey::from_bytes(&[39u8; 32]);
    let mut core = PrivateTradingCore::new_with_oracle(
        JournalKey::from_bytes(journal_key),
        ReceiptSigner::generate([36u8; 48]),
        oracle.verifying_key().to_bytes(),
    )
    .unwrap();
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
            fee_profile_id,
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

fn configured_exact_condition_core() -> (PrivateTradingCore, SigningKey, SigningKey, String, String)
{
    configured_exact_condition_core_with_balance(1_000_000)
}

fn configured_exact_condition_core_with_balance(
    initial_balance_atomic: u128,
) -> (PrivateTradingCore, SigningKey, SigningKey, String, String) {
    let journal_key = [31u8; 32];
    let up_key = SigningKey::from_bytes(&[32u8; 32]);
    let down_key = SigningKey::from_bytes(&[33u8; 32]);
    let up_commitment = [34u8; 32];
    let down_commitment = [35u8; 32];
    let up_owner = derived_private_user(journal_key, up_commitment);
    let down_owner = derived_private_user(journal_key, down_commitment);
    let oracle = SigningKey::from_bytes(&ORACLE_KEY);
    let mut core = PrivateTradingCore::new_with_oracle(
        JournalKey::from_bytes(journal_key),
        ReceiptSigner::generate([36u8; 48]),
        oracle.verifying_key().to_bytes(),
    )
    .unwrap();
    core.register_market(
        "sys:market:exact-condition".into(),
        MarketConfig {
            market_id: MARKET_ID.into(),
            settlement_asset: "USDC".into(),
            settlement_decimals: 6,
            public_settlement_chain: Some("horizen".into()),
            opens_at_millis: 900,
            closes_at_millis: 2_000,
            minimum_quantity_micros: 1,
            maximum_quantity_micros: 100_000_000,
            minimum_order_notional_micros: 1,
            maximum_order_notional_micros: 10_000_000,
            maximum_user_position_micros: 100_000_000,
            maximum_pending_bootstrap_notional_micros: 100_000_000,
            tick_size_micros: 100,
            // The core market envelope retains a non-zero feed slot for schema
            // compatibility; exact-condition resolution ignores it and verifies
            // the signed condition/evidence tuple instead.
            oracle_feed_id: 245,
            fee_profile_id: FeeProfileId::LegacyProfitV1,
            execution: MarketExecution::NativeExactCondition {
                condition_id: format!("0x{}", "22".repeat(32)),
                up_outcome_index: 0,
                down_outcome_index: 1,
            },
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
            "USDC".into(),
            AccountBucket::UserAvailable,
            initial_balance_atomic,
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

fn market_collateral_usdc() -> AccountKey {
    let mut account = AccountKey::new("layrs", AccountBucket::MarketCollateral, "USDC");
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
