use clob_service::private_core::{
    command_request_hash, signing_payload, AccountBucket, AccountKey, BookOrder, CommandResult,
    CoreError, ExternalFlowDirection, FeeProfileId, JournalKey, MarketConfig, MarketExecution,
    MatchType, OrderAction, OrderStatus, Outcome, PriceTimeBook, PrivateTradingCore, ReceiptSigner,
    SessionRequest, SignedSessionRequest, TimeInForce, UserCommand, UserCommandAction,
};
use ed25519_dalek::{Signer, SigningKey};
use proptest::prelude::*;
use sha2::{Digest, Sha256};
use uuid::Uuid;

const MARKET_ID: &str = "layrs:v3:ZEN:15m:2000";
const ONE_ZEN: u128 = 1_000_000_000_000_000_000;
const INITIAL_BALANCE: u128 = 5 * ONE_ZEN;
const PRICE_SCALE: u128 = 1_000_000;

#[test]
fn better_price_merge_burns_complete_set_charges_fee_and_replays_exactly_once() {
    let (mut core, up_key, down_key, up_owner, down_owner) = configured_core();
    mint_claims(&mut core, &up_key, &down_key, 1_000_000, "better-price");

    let fee = fee_revenue();
    let up_available = available(&up_owner);
    let down_available = available(&down_owner);
    assert_eq!(core.balance(&market_collateral()), ONE_ZEN);
    assert_eq!(core.balance(&claim(&up_owner, Outcome::Up)), 1_000_000);
    assert_eq!(core.balance(&claim(&down_owner, Outcome::Down)), 1_000_000);
    assert_eq!(core.balance(&fee), 16_800_000_000_000_000);

    let maker_order = BookOrder::with_id(
        Uuid::from_u128(102),
        "ignored",
        MARKET_ID,
        Outcome::Up,
        OrderAction::Sell,
        400_000,
        1_000_000,
        TimeInForce::Gtc,
        None,
    );
    execute(
        &mut core,
        &up_key,
        "session:up",
        2,
        "cmd:better-price-merge-maker",
        UserCommandAction::SubmitOrder { order: maker_order },
        1_100,
    );
    assert_eq!(core.balance(&claim_hold(&up_owner, Outcome::Up)), 1_000_000);
    assert_eq!(core.balance(&claim(&up_owner, Outcome::Up)), 0);

    // The DOWN taker is willing to sell for 50c but receives the 60c
    // complement of the resting 40c UP seller. SELL orders reserve claims,
    // not cash; the better execution price is paid from the burned set.
    let action = UserCommandAction::SubmitOrder {
        order: BookOrder::with_id(
            Uuid::from_u128(103),
            "ignored",
            MARKET_ID,
            Outcome::Down,
            OrderAction::Sell,
            500_000,
            1_000_000,
            TimeInForce::Fok,
            None,
        ),
    };
    let command = signed_command(
        &down_key,
        "session:down",
        2,
        "cmd:better-price-merge-taker",
        action,
        1_150,
    );
    let first = core.execute(command.clone(), 1_150).unwrap();
    let result = order_result(&first.result);
    assert_eq!(result.fills.len(), 1);
    assert_eq!(result.fills[0].match_type, MatchType::Merge);
    assert_eq!(result.fills[0].price_micros, 400_000);
    assert_eq!(result.fills[0].taker_price_micros(), 600_000);
    assert_eq!(
        first.audit_fills[0].statement.match_type.as_deref(),
        Some("MERGE")
    );
    assert_eq!(
        first.audit_fills[0].statement.fee_atomic,
        "16800000000000000"
    );

    // The initial MINT and subsequent MERGE each charge the DOWN taker the
    // current Layrs 60c curve fee. The complete set is burned exactly once.
    assert_eq!(core.balance(&market_collateral()), 0);
    assert_eq!(core.balance(&claim(&up_owner, Outcome::Up)), 0);
    assert_eq!(core.balance(&claim(&down_owner, Outcome::Down)), 0);
    assert_eq!(core.balance(&claim_hold(&up_owner, Outcome::Up)), 0);
    assert_eq!(core.balance(&claim_hold(&down_owner, Outcome::Down)), 0);
    assert_eq!(core.balance(&up_available), 5_000_000_000_000_000_000);
    assert_eq!(core.balance(&down_available), 4_966_400_000_000_000_000);
    assert_eq!(core.balance(&fee), 33_600_000_000_000_000);
    assert_eq!(
        core.balance(&up_available)
            + core.balance(&down_available)
            + core.balance(&fee)
            + core.balance(&market_collateral()),
        2 * INITIAL_BALANCE
    );

    let maker_rewards = execute(
        &mut core,
        &up_key,
        "session:up",
        3,
        "cmd:better-price-merge-maker-rewards",
        UserCommandAction::Rewards,
        1_175,
    );
    let CommandResult::Rewards { entitlements } = maker_rewards.result else {
        panic!("expected maker rewards");
    };
    assert_eq!(entitlements.len(), 1);
    assert_eq!(entitlements[0].cumulative_amount_atomic, "6720000000000000");
    assert_eq!(
        entitlements[0].cumulative_maker_rebate_atomic,
        "6720000000000000"
    );

    let root_after_first = core.state_root();
    let replay = core.execute(command, 1_176).unwrap();
    assert_eq!(replay, first);
    assert_eq!(core.state_root(), root_after_first);
    assert_eq!(core.balance(&fee), 33_600_000_000_000_000);
}

#[test]
fn partial_merge_survives_encrypted_snapshot_and_cancel_releases_claims_once() {
    let (mut core, up_key, down_key, up_owner, down_owner) = configured_core();
    mint_claims(&mut core, &up_key, &down_key, 2_000_000, "partial-snapshot");

    let maker_order_id = Uuid::from_u128(202);
    execute(
        &mut core,
        &up_key,
        "session:up",
        2,
        "cmd:partial-merge-maker",
        UserCommandAction::SubmitOrder {
            order: BookOrder::with_id(
                maker_order_id,
                "ignored",
                MARKET_ID,
                Outcome::Up,
                OrderAction::Sell,
                400_000,
                2_000_000,
                TimeInForce::Gtc,
                None,
            ),
        },
        1_100,
    );
    let partial_action = UserCommandAction::SubmitOrder {
        order: BookOrder::with_id(
            Uuid::from_u128(203),
            "ignored",
            MARKET_ID,
            Outcome::Down,
            OrderAction::Sell,
            550_000,
            1_250_000,
            TimeInForce::Fok,
            None,
        ),
    };
    let partial_command = signed_command(
        &down_key,
        "session:down",
        2,
        "cmd:partial-merge-taker",
        partial_action,
        1_150,
    );
    let partial = core.execute(partial_command.clone(), 1_150).unwrap();
    let result = order_result(&partial.result);
    assert_eq!(result.fills.len(), 1);
    assert_eq!(result.fills[0].match_type, MatchType::Merge);
    assert_eq!(result.fills[0].quantity_micros, 1_250_000);
    assert_eq!(result.fills[0].taker_price_micros(), 600_000);

    let maker_hold = claim_hold(&up_owner, Outcome::Up);
    let up_available = available(&up_owner);
    let down_available = available(&down_owner);
    let fee = fee_revenue();
    assert_eq!(core.balance(&maker_hold), 750_000);
    assert_eq!(core.balance(&claim(&down_owner, Outcome::Down)), 750_000);
    assert_eq!(core.balance(&market_collateral()), 750_000_000_000_000_000);
    assert_eq!(core.balance(&fee), 54_600_000_000_000_000);
    assert_eq!(core.balance(&up_available), 4_700_000_000_000_000_000);
    assert_eq!(core.balance(&down_available), 4_495_400_000_000_000_000);
    assert_eq!(
        core.balance(&up_available)
            + core.balance(&down_available)
            + core.balance(&fee)
            + core.balance(&market_collateral()),
        2 * INITIAL_BALANCE
    );

    let snapshot = core.export_encrypted_snapshot().unwrap();
    let snapshot_root = core.state_root();
    let mut restored = PrivateTradingCore::restore_encrypted_snapshot(
        JournalKey::from_bytes([31u8; 32]),
        ReceiptSigner::generate([90u8; 48]),
        &snapshot,
        snapshot.sequence,
    )
    .unwrap();
    assert_eq!(restored.state_root(), snapshot_root);
    assert_eq!(restored.balance(&maker_hold), 750_000);
    assert_eq!(
        restored
            .market_settlement_readiness(MARKET_ID, 1_175)
            .unwrap()
            .active_order_count,
        1
    );

    // Snapshots keep processed request hashes. Without the external response
    // archive, a pre-snapshot financial command fails closed and cannot burn
    // the same complete-set collateral twice.
    let before_replay = restored.state_root();
    assert_eq!(
        restored.execute(partial_command, 1_176).unwrap_err(),
        CoreError::PreviouslyProcessed
    );
    assert_eq!(restored.state_root(), before_replay);

    execute(
        &mut restored,
        &up_key,
        "session:up",
        3,
        "cmd:partial-merge-cancel-maker",
        UserCommandAction::CancelOrder {
            market_id: MARKET_ID.into(),
            order_id: maker_order_id,
        },
        1_200,
    );
    assert_eq!(restored.balance(&maker_hold), 0);
    assert_eq!(restored.balance(&claim(&up_owner, Outcome::Up)), 750_000);
    assert_eq!(
        restored.balance(&claim(&down_owner, Outcome::Down)),
        750_000
    );
    assert_eq!(
        restored.balance(&up_available)
            + restored.balance(&down_available)
            + restored.balance(&fee)
            + restored.balance(&market_collateral()),
        2 * INITIAL_BALANCE
    );
}

#[test]
fn merge_self_trade_and_below_precision_liquidity_fail_closed() {
    let mut self_trade_book = PriceTimeBook::default();
    self_trade_book
        .submit(
            BookOrder::with_id(
                Uuid::from_u128(300),
                "same-user",
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
    let self_trade = self_trade_book
        .submit(
            BookOrder::with_id(
                Uuid::from_u128(301),
                "same-user",
                MARKET_ID,
                Outcome::Down,
                OrderAction::Sell,
                600_000,
                1_000_000,
                TimeInForce::Fak,
                None,
            ),
            1_001,
        )
        .unwrap();
    assert!(self_trade.fills.is_empty());
    assert_eq!(self_trade.cancelled_remainder_micros, 1_000_000);

    let mut precision_book = PriceTimeBook::default();
    precision_book
        .submit(
            BookOrder::with_id(
                Uuid::from_u128(302),
                "dust-maker",
                MARKET_ID,
                Outcome::Up,
                OrderAction::Sell,
                650_000,
                2,
                TimeInForce::Gtc,
                None,
            ),
            1_000,
        )
        .unwrap();
    let dust = precision_book
        .submit(
            BookOrder::with_id(
                Uuid::from_u128(303),
                "dust-taker",
                MARKET_ID,
                Outcome::Down,
                OrderAction::Sell,
                350_000,
                2,
                TimeInForce::Fok,
                None,
            ),
            1_001,
        )
        .unwrap();
    assert!(dust.fills.is_empty());
    assert_eq!(dust.accepted_order.unwrap().status, OrderStatus::Rejected);

    // Invalid dust at the same level cannot poison later executable MERGE
    // liquidity. The clean order is selected deterministically.
    let clean_maker_id = Uuid::from_u128(304);
    precision_book
        .submit(
            BookOrder::with_id(
                clean_maker_id,
                "clean-maker",
                MARKET_ID,
                Outcome::Up,
                OrderAction::Sell,
                650_000,
                2_000_000,
                TimeInForce::Gtc,
                None,
            ),
            1_002,
        )
        .unwrap();
    let clean_order = BookOrder::with_id(
        Uuid::from_u128(305),
        "clean-taker",
        MARKET_ID,
        Outcome::Down,
        OrderAction::Sell,
        300_000,
        2_000_000,
        TimeInForce::Fok,
        None,
    );
    let before = precision_book.clone();
    let clean = precision_book.submit(clean_order.clone(), 1_003).unwrap();
    assert_eq!(clean.fills.len(), 1);
    assert_eq!(clean.fills[0].maker_order_id, clean_maker_id);
    assert_eq!(clean.fills[0].match_type, MatchType::Merge);
    assert_eq!(clean.fills[0].taker_price_micros(), 350_000);
    let mut replay = before;
    assert_eq!(clean, replay.submit(clean_order, 1_003).unwrap());
}

proptest! {
    #[test]
    fn complementary_merge_crossing_is_deterministic_for_precision_safe_vectors(
        maker_price in 1u64..999_999,
        price_improvement in 0u64..10_000,
        quantity_multiple in 1u128..1_000,
    ) {
        let complement = 1_000_000u64 - maker_price;
        let taker_limit = complement.saturating_sub(price_improvement).max(1);
        prop_assume!(taker_limit <= complement);
        let minimum_quantity = PRICE_SCALE.div_ceil(PRICE_SCALE - u128::from(maker_price));
        let quantity = minimum_quantity * quantity_multiple;
        let maker = BookOrder::with_id(
            Uuid::from_u128(400),
            "maker",
            MARKET_ID,
            Outcome::Up,
            OrderAction::Sell,
            maker_price,
            quantity,
            TimeInForce::Gtc,
            None,
        );
        let taker = BookOrder::with_id(
            Uuid::from_u128(401),
            "taker",
            MARKET_ID,
            Outcome::Down,
            OrderAction::Sell,
            taker_limit,
            quantity,
            TimeInForce::Fok,
            None,
        );
        let run = || {
            let mut book = PriceTimeBook::default();
            book.submit(maker.clone(), 1_000).unwrap();
            book.submit(taker.clone(), 1_001).unwrap()
        };
        let first = run();
        let second = run();
        prop_assert_eq!(&first, &second);
        prop_assert_eq!(first.fills.len(), 1);
        prop_assert_eq!(first.fills[0].match_type, MatchType::Merge);
        prop_assert_eq!(
            first.fills[0].price_micros + first.fills[0].taker_price_micros(),
            1_000_000
        );
        prop_assert_eq!(first.fills[0].quantity_micros, quantity);
    }
}

fn mint_claims(
    core: &mut PrivateTradingCore,
    up_key: &SigningKey,
    down_key: &SigningKey,
    quantity_micros: u128,
    label: &str,
) {
    execute(
        core,
        up_key,
        "session:up",
        1,
        &format!("cmd:{label}:mint-maker"),
        UserCommandAction::SubmitOrder {
            order: BookOrder::with_id(
                Uuid::new_v5(&Uuid::NAMESPACE_OID, format!("{label}:up").as_bytes()),
                "ignored",
                MARKET_ID,
                Outcome::Up,
                OrderAction::Buy,
                400_000,
                quantity_micros,
                TimeInForce::Gtc,
                None,
            ),
        },
        1_000,
    );
    let minted = execute(
        core,
        down_key,
        "session:down",
        1,
        &format!("cmd:{label}:mint-taker"),
        UserCommandAction::SubmitOrder {
            order: BookOrder::with_id(
                Uuid::new_v5(&Uuid::NAMESPACE_OID, format!("{label}:down").as_bytes()),
                "ignored",
                MARKET_ID,
                Outcome::Down,
                OrderAction::Buy,
                600_000,
                quantity_micros,
                TimeInForce::Fok,
                None,
            ),
        },
        1_050,
    );
    assert_eq!(
        order_result(&minted.result).fills[0].match_type,
        MatchType::Mint
    );
}

fn configured_core() -> (PrivateTradingCore, SigningKey, SigningKey, String, String) {
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
        "sys:market:merge-certification".into(),
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
            tick_size_micros: 100,
            oracle_feed_id: 245,
            fee_profile_id: FeeProfileId::LayrsCryptoV2,
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
            5_000,
            850,
        )
        .unwrap();
        core.apply_user_external_flow(
            format!("sys:deposit:{label}"),
            commitment,
            "ZEN".into(),
            AccountBucket::UserAvailable,
            INITIAL_BALANCE,
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
    core.execute(
        signed_command(key, session_id, sequence, command_id, action, now_millis),
        now_millis,
    )
    .unwrap()
}

#[allow(clippy::too_many_arguments)]
fn signed_command(
    key: &SigningKey,
    session_id: &str,
    sequence: u64,
    command_id: &str,
    action: UserCommandAction,
    now_millis: i64,
) -> UserCommand {
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
    UserCommand {
        command_id: command_id.into(),
        idempotency_key,
        session: SignedSessionRequest { request, signature },
        action,
    }
}

fn order_result(result: &CommandResult) -> &clob_service::private_core::MatchResult {
    match result {
        CommandResult::Order { result } => result,
        _ => panic!("expected order result"),
    }
}

fn available(owner: &str) -> AccountKey {
    AccountKey::new(owner, AccountBucket::UserAvailable, "ZEN")
}

fn fee_revenue() -> AccountKey {
    AccountKey::new("layrs", AccountBucket::FeeRevenue, "ZEN")
}

fn claim(owner: &str, outcome: Outcome) -> AccountKey {
    let name = outcome_name(outcome);
    AccountKey::position(owner, format!("CLAIM:{MARKET_ID}:{name}"), MARKET_ID, name)
}

fn claim_hold(owner: &str, outcome: Outcome) -> AccountKey {
    let name = outcome_name(outcome);
    let mut account = AccountKey::new(
        owner,
        AccountBucket::UserOrderHold,
        format!("CLAIM:{MARKET_ID}:{name}"),
    );
    account.market_id = Some(MARKET_ID.into());
    account.outcome = Some(name.into());
    account
}

fn market_collateral() -> AccountKey {
    let mut account = AccountKey::new("layrs", AccountBucket::MarketCollateral, "ZEN");
    account.market_id = Some(MARKET_ID.into());
    account
}

fn outcome_name(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::Up => "UP",
        Outcome::Down => "DOWN",
    }
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
