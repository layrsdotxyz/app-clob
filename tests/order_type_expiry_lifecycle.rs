use clob_service::private_core::{
    command_request_hash, exact_condition_resolution_signing_payload, signing_payload,
    AccountBucket, AccountKey, BookOrder, CommandResult, CompleteSetDirection, CoreError,
    ExactConditionResolutionStatement, ExternalFlowDirection, FeeProfileId, JournalKey,
    MarketConfig, MarketExecution, OrderAction, OrderStatus, Outcome, PriceTimeBook,
    PrivateTradingCore, ReceiptSigner, ResolutionOutcome, SessionRequest,
    SignedExactConditionResolution, SignedSessionRequest, TimeInForce, UserCommand,
    UserCommandAction,
};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const OLD_MARKET: &str = "layrs:v5:SPORTS:lifecycle-old:abababababababab";
const NEW_MARKET: &str = "layrs:v5:SPORTS:lifecycle-new:cdcdcdcdcdcdcdcd";
const ONE_USDC: u128 = 1_000_000;
const JOURNAL_KEY: [u8; 32] = [11u8; 32];
const USER_COMMITMENT: [u8; 32] = [12u8; 32];
const USER_KEY: [u8; 32] = [13u8; 32];
const ORACLE_KEY: [u8; 32] = [14u8; 32];
const RECEIPT_KEY: [u8; 48] = [15u8; 48];

#[test]
fn gtc_gtd_fak_and_fok_have_deterministic_orderbook_semantics() {
    let mut partial_base = PriceTimeBook::default();
    partial_base
        .submit(
            order(
                1,
                "maker",
                OLD_MARKET,
                Outcome::Up,
                OrderAction::Sell,
                500_000,
                2_000_000,
                TimeInForce::Gtc,
                None,
            ),
            1_000,
        )
        .unwrap();
    let fak = order(
        2,
        "fak-taker",
        OLD_MARKET,
        Outcome::Up,
        OrderAction::Buy,
        500_000,
        3_000_000,
        TimeInForce::Fak,
        None,
    );
    let mut partial_first = partial_base.clone();
    let mut partial_second = partial_base;
    let first = partial_first.submit(fak.clone(), 1_010).unwrap();
    let second = partial_second.submit(fak, 1_010).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.fills.len(), 1);
    assert_eq!(first.fills[0].quantity_micros, 2_000_000);
    assert_eq!(first.cancelled_remainder_micros, 1_000_000);
    let accepted = first.accepted_order.unwrap();
    assert_eq!(accepted.status, OrderStatus::PartiallyFilled);
    assert_eq!(accepted.filled_micros, 2_000_000);
    assert_eq!(accepted.remaining_micros, 0);

    let mut insufficient = PriceTimeBook::default();
    insufficient
        .submit(
            order(
                3,
                "maker",
                OLD_MARKET,
                Outcome::Up,
                OrderAction::Sell,
                500_000,
                2_000_000,
                TimeInForce::Gtc,
                None,
            ),
            1_000,
        )
        .unwrap();
    let fok_id = Uuid::from_u128(4);
    let rejected = insufficient
        .submit(
            order(
                4,
                "fok-taker",
                OLD_MARKET,
                Outcome::Up,
                OrderAction::Buy,
                500_000,
                3_000_000,
                TimeInForce::Fok,
                None,
            ),
            1_010,
        )
        .unwrap();
    assert!(rejected.fills.is_empty());
    assert_eq!(rejected.cancelled_remainder_micros, 0);
    assert_eq!(
        rejected.accepted_order.unwrap().status,
        OrderStatus::Rejected
    );
    assert!(insufficient.order(fok_id).is_none());

    let mut sufficient = PriceTimeBook::default();
    sufficient
        .submit(
            order(
                5,
                "maker",
                OLD_MARKET,
                Outcome::Up,
                OrderAction::Sell,
                500_000,
                3_000_000,
                TimeInForce::Gtc,
                None,
            ),
            1_000,
        )
        .unwrap();
    let filled = sufficient
        .submit(
            order(
                6,
                "fok-taker",
                OLD_MARKET,
                Outcome::Up,
                OrderAction::Buy,
                500_000,
                3_000_000,
                TimeInForce::Fok,
                None,
            ),
            1_010,
        )
        .unwrap();
    assert_eq!(filled.fills.len(), 1);
    assert_eq!(filled.cancelled_remainder_micros, 0);
    assert_eq!(filled.accepted_order.unwrap().status, OrderStatus::Filled);

    let mut expiry_book = PriceTimeBook::default();
    let missing_expiry = expiry_book.submit(
        order(
            7,
            "gtd",
            OLD_MARKET,
            Outcome::Down,
            OrderAction::Buy,
            400_000,
            1_000_000,
            TimeInForce::Gtd,
            None,
        ),
        1_000,
    );
    assert_eq!(
        missing_expiry.unwrap_err(),
        CoreError::InvalidOrder("GTD requires an expiry".into())
    );
    for (id, tif) in [
        (70, TimeInForce::Gtc),
        (71, TimeInForce::Fak),
        (72, TimeInForce::Fok),
    ] {
        let invalid_expiry = expiry_book.submit(
            order(
                id,
                "non-gtd",
                OLD_MARKET,
                Outcome::Down,
                OrderAction::Buy,
                400_000,
                1_000_000,
                tif,
                Some(1_500),
            ),
            1_000,
        );
        assert_eq!(
            invalid_expiry.unwrap_err(),
            CoreError::InvalidOrder("only GTD accepts an expiry".into())
        );
    }
    let gtd_id = Uuid::from_u128(8);
    expiry_book
        .submit(
            order(
                8,
                "gtd",
                OLD_MARKET,
                Outcome::Down,
                OrderAction::Buy,
                400_000,
                1_000_000,
                TimeInForce::Gtd,
                Some(1_500),
            ),
            1_000,
        )
        .unwrap();
    expiry_book
        .submit(
            order(
                9,
                "gtc",
                OLD_MARKET,
                Outcome::Up,
                OrderAction::Buy,
                300_000,
                1_000_000,
                TimeInForce::Gtc,
                None,
            ),
            1_000,
        )
        .unwrap();
    assert!(expiry_book.cancel_expired(OLD_MARKET, 1_499).is_empty());
    assert_eq!(expiry_book.order(gtd_id).unwrap().status, OrderStatus::Open);
    assert_eq!(
        expiry_book.order(Uuid::from_u128(9)).unwrap().status,
        OrderStatus::Open
    );
    let expired = expiry_book.cancel_expired(OLD_MARKET, 1_500);
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0].order_id, gtd_id);
    assert_eq!(expired[0].status, OrderStatus::Expired);
    assert_eq!(expired[0].updated_at_millis, 1_500);
    assert_eq!(
        expiry_book.order(gtd_id).unwrap().status,
        OrderStatus::Expired
    );
    assert!(expiry_book.cancel_expired(OLD_MARKET, i64::MAX).is_empty());
    assert_eq!(
        expiry_book.order(Uuid::from_u128(9)).unwrap().status,
        OrderStatus::Open
    );
}

#[test]
fn expired_gtd_hold_is_released_before_replacement_and_replay_is_exact() {
    let (mut core, user_key, owner) = configured_core(&[(OLD_MARKET, 900, 2_000, 1_000_000)]);
    let gtd_id = Uuid::from_u128(100);
    execute(
        &mut core,
        &user_key,
        1,
        "cmd:gtd:rest",
        UserCommandAction::SubmitOrder {
            order: order(
                100,
                "ignored",
                OLD_MARKET,
                Outcome::Up,
                OrderAction::Buy,
                400_000,
                1_000_000,
                TimeInForce::Gtd,
                Some(1_500),
            ),
        },
        1_000,
    )
    .unwrap();
    let hold = cash_hold(&owner, OLD_MARKET, Outcome::Up);
    let available = available(&owner);
    assert_eq!(core.balance(&hold), 400_000);
    assert_eq!(core.balance(&available), 600_000);

    let replacement_id = Uuid::from_u128(101);
    let replacement = signed_command(
        &user_key,
        2,
        "cmd:gtd:replace",
        UserCommandAction::SubmitOrder {
            order: order(
                101,
                "ignored",
                OLD_MARKET,
                Outcome::Up,
                OrderAction::Buy,
                300_000,
                1_000_000,
                TimeInForce::Gtc,
                None,
            ),
        },
        1_600,
    );
    let first = core.execute(replacement.clone(), 1_600).unwrap();
    let root = core.state_root();
    let replay = core.execute(replacement, 1_601).unwrap();
    assert_eq!(replay, first);
    assert_eq!(core.state_root(), root);
    assert_eq!(core.balance(&hold), 300_000);
    assert_eq!(core.balance(&available), 700_000);

    let before_old_cancel = core.state_root();
    let old_cancel = execute(
        &mut core,
        &user_key,
        3,
        "cmd:gtd:cancel-expired",
        UserCommandAction::CancelOrder {
            market_id: OLD_MARKET.into(),
            order_id: gtd_id,
        },
        1_700,
    );
    assert_eq!(
        old_cancel.unwrap_err(),
        CoreError::InvalidOrder("order is not cancellable".into())
    );
    assert_eq!(core.state_root(), before_old_cancel);

    execute(
        &mut core,
        &user_key,
        3,
        "cmd:gtd:cancel-replacement",
        UserCommandAction::CancelOrder {
            market_id: OLD_MARKET.into(),
            order_id: replacement_id,
        },
        1_700,
    )
    .unwrap();
    assert_eq!(core.balance(&hold), 0);
    assert_eq!(core.balance(&available), ONE_USDC);
}

#[test]
fn api_tif_commands_preserve_fees_conservation_privacy_and_snapshot_replay() {
    const COUNTERPARTY_COMMITMENT: [u8; 32] = [18u8; 32];
    const COUNTERPARTY_KEY: [u8; 32] = [19u8; 32];
    const TOTAL_INFLOW: u128 = 10 * ONE_USDC;
    let (mut core, taker_key, taker_owner) =
        configured_core(&[(OLD_MARKET, 900, 3_000, 10_000_000)]);
    core.apply_user_external_flow(
        "sys:deposit:lifecycle:taker-extra".into(),
        USER_COMMITMENT,
        "USDC".into(),
        AccountBucket::UserAvailable,
        4 * ONE_USDC,
        ExternalFlowDirection::Inflow,
        [20u8; 32],
        880,
    )
    .unwrap();
    let maker_key = SigningKey::from_bytes(&COUNTERPARTY_KEY);
    let maker_owner = derived_private_user(JOURNAL_KEY, COUNTERPARTY_COMMITMENT);
    core.register_session(
        "sys:session:lifecycle:maker".into(),
        "session:lifecycle:maker".into(),
        COUNTERPARTY_COMMITMENT,
        maker_key.verifying_key().to_bytes(),
        10_000,
        850,
    )
    .unwrap();
    core.apply_user_external_flow(
        "sys:deposit:lifecycle:maker".into(),
        COUNTERPARTY_COMMITMENT,
        "USDC".into(),
        AccountBucket::UserAvailable,
        5 * ONE_USDC,
        ExternalFlowDirection::Inflow,
        [21u8; 32],
        875,
    )
    .unwrap();

    execute_for_session(
        &mut core,
        &maker_key,
        "session:lifecycle:maker",
        1,
        "cmd:tif:maker-mint",
        UserCommandAction::CompleteSet {
            market_id: OLD_MARKET.into(),
            quantity_micros: 3_000_000,
            direction: CompleteSetDirection::Mint,
        },
        1_000,
    )
    .unwrap();
    execute_for_session(
        &mut core,
        &maker_key,
        "session:lifecycle:maker",
        2,
        "cmd:tif:maker-ask-two",
        UserCommandAction::SubmitOrder {
            order: order(
                400,
                "ignored",
                OLD_MARKET,
                Outcome::Up,
                OrderAction::Sell,
                400_000,
                2_000_000,
                TimeInForce::Gtc,
                None,
            ),
        },
        1_050,
    )
    .unwrap();

    let fak_command = signed_command(
        &taker_key,
        1,
        "cmd:tif:fak-partial",
        UserCommandAction::SubmitOrder {
            order: order(
                401,
                "ignored",
                OLD_MARKET,
                Outcome::Up,
                OrderAction::Buy,
                400_000,
                3_000_000,
                TimeInForce::Fak,
                None,
            ),
        },
        1_100,
    );
    let fak = core.execute(fak_command.clone(), 1_100).unwrap();
    let CommandResult::Order { result } = &fak.result else {
        panic!("expected FAK result");
    };
    let accepted = result.accepted_order.as_ref().expect("accepted FAK");
    assert_eq!(accepted.status, OrderStatus::PartiallyFilled);
    assert_eq!(accepted.filled_micros, 2_000_000);
    assert_eq!(accepted.remaining_micros, 0);
    assert_eq!(accepted.private_user_id, "");
    assert_eq!(result.cancelled_remainder_micros, 1_000_000);
    assert_eq!(result.fills.len(), 1);
    assert_eq!(result.fills[0].quantity_micros, 2_000_000);
    assert_eq!(result.fills[0].maker_private_user_id, "");
    assert_eq!(result.fills[0].taker_private_user_id, "");
    assert_eq!(
        core.balance(&cash_hold(&taker_owner, OLD_MARKET, Outcome::Up)),
        0
    );
    let fak_root = core.state_root();
    let fak_snapshot = core.export_encrypted_snapshot().unwrap();
    let mut core = PrivateTradingCore::restore_encrypted_snapshot(
        JournalKey::from_bytes(JOURNAL_KEY),
        ReceiptSigner::generate(RECEIPT_KEY),
        &fak_snapshot,
        fak_snapshot.sequence,
    )
    .unwrap();
    let mut recovered_fak = fak.clone();
    // A recovered result is the exact private financial outcome, but it must
    // not replay the already-committed encrypted journal sidecar.
    recovered_fak.encrypted_record = None;
    assert_eq!(core.execute(fak_command, 1_111).unwrap(), recovered_fak);
    assert_eq!(core.state_root(), fak_root);

    let remaining_ask_id = Uuid::from_u128(402);
    execute_for_session(
        &mut core,
        &maker_key,
        "session:lifecycle:maker",
        3,
        "cmd:tif:maker-ask-one",
        UserCommandAction::SubmitOrder {
            order: order(
                402,
                "ignored",
                OLD_MARKET,
                Outcome::Up,
                OrderAction::Sell,
                400_000,
                1_000_000,
                TimeInForce::Gtc,
                None,
            ),
        },
        1_150,
    )
    .unwrap();

    let fok_action = UserCommandAction::SubmitOrder {
        order: order(
            403,
            "ignored",
            OLD_MARKET,
            Outcome::Up,
            OrderAction::Buy,
            400_000,
            2_000_000,
            TimeInForce::Fok,
            None,
        ),
    };
    let before_fok_balances = financial_balances(&core, &taker_owner, &maker_owner);
    let fok_command = signed_command(&taker_key, 2, "cmd:tif:fok-no-fill", fok_action, 1_200);
    let rejected = core.execute(fok_command.clone(), 1_200).unwrap();
    let CommandResult::Order { result } = &rejected.result else {
        panic!("expected FOK result");
    };
    assert!(result.fills.is_empty());
    assert_eq!(
        result.accepted_order.as_ref().expect("rejected FOK").status,
        OrderStatus::Rejected
    );
    assert_eq!(
        core.aggregate_depth(OLD_MARKET, Outcome::Up, 1_200, 1),
        (Vec::new(), Vec::new())
    );
    assert_eq!(
        core.balance(&claim_hold_for(&maker_owner, OLD_MARKET, Outcome::Up)),
        1_000_000
    );
    assert_eq!(
        financial_balances(&core, &taker_owner, &maker_owner),
        before_fok_balances
    );
    let rejected_root = core.state_root();
    assert_eq!(core.execute(fok_command.clone(), 1_250).unwrap(), rejected);
    assert_eq!(core.state_root(), rejected_root);

    let snapshot = core.export_encrypted_snapshot().unwrap();
    let mut restored = PrivateTradingCore::restore_encrypted_snapshot(
        JournalKey::from_bytes(JOURNAL_KEY),
        ReceiptSigner::generate(RECEIPT_KEY),
        &snapshot,
        snapshot.sequence,
    )
    .unwrap();
    assert_eq!(restored.state_root(), rejected_root);
    let mut recovered_rejection = rejected.clone();
    recovered_rejection.encrypted_record = None;
    assert_eq!(
        restored.execute(fok_command, 1_260).unwrap(),
        recovered_rejection
    );
    assert_eq!(restored.state_root(), rejected_root);

    let gtc = execute(
        &mut restored,
        &taker_key,
        3,
        "cmd:tif:gtc-partial-rest",
        UserCommandAction::SubmitOrder {
            order: order(
                404,
                "ignored",
                OLD_MARKET,
                Outcome::Up,
                OrderAction::Buy,
                400_000,
                2_000_000,
                TimeInForce::Gtc,
                None,
            ),
        },
        1_300,
    )
    .unwrap();
    let resting_buy_id = Uuid::from_u128(404);
    let CommandResult::Order { result } = gtc.result else {
        panic!("expected GTC result");
    };
    let accepted = result.accepted_order.expect("accepted GTC");
    assert_eq!(accepted.status, OrderStatus::PartiallyFilled);
    assert_eq!(accepted.filled_micros, 1_000_000);
    assert_eq!(accepted.remaining_micros, 1_000_000);
    assert_eq!(result.cancelled_remainder_micros, 0);
    assert_eq!(
        restored.balance(&cash_hold(&taker_owner, OLD_MARKET, Outcome::Up)),
        400_000
    );
    assert_eq!(
        restored.balance(&claim_hold_for(&maker_owner, OLD_MARKET, Outcome::Up)),
        0
    );
    assert!(restored.balance(&AccountKey::new("layrs", AccountBucket::FeeRevenue, "USDC")) > 0);

    execute(
        &mut restored,
        &taker_key,
        4,
        "cmd:tif:cancel-gtc-rest",
        UserCommandAction::CancelOrder {
            market_id: OLD_MARKET.into(),
            order_id: resting_buy_id,
        },
        1_350,
    )
    .unwrap();
    assert_eq!(
        restored.balance(&cash_hold(&taker_owner, OLD_MARKET, Outcome::Up)),
        0
    );
    let portfolio = execute(
        &mut restored,
        &taker_key,
        5,
        "cmd:tif:private-portfolio",
        UserCommandAction::Portfolio,
        1_400,
    )
    .unwrap();
    let CommandResult::Portfolio { snapshot } = portfolio.result else {
        panic!("expected portfolio");
    };
    assert!(snapshot
        .orders
        .iter()
        .all(|order| order.private_user_id.is_empty()));
    assert!(snapshot
        .orders
        .iter()
        .all(|order| order.order_id != remaining_ask_id));

    let fee = restored.balance(&AccountKey::new("layrs", AccountBucket::FeeRevenue, "USDC"));
    let mut collateral = AccountKey::new("layrs", AccountBucket::MarketCollateral, "USDC");
    collateral.market_id = Some(OLD_MARKET.into());
    assert_eq!(
        restored.balance(&available(&taker_owner))
            + restored.balance(&available(&maker_owner))
            + restored.balance(&collateral)
            + fee,
        TOTAL_INFLOW
    );
}

#[test]
fn close_and_rollover_keep_market_holds_isolated_and_replay_safe() {
    let (mut core, user_key, owner) = configured_core(&[
        (OLD_MARKET, 900, 2_000, 4_000_000),
        (NEW_MARKET, 2_000, 3_000, 4_000_000),
    ]);
    let old_id = Uuid::from_u128(200);
    execute(
        &mut core,
        &user_key,
        1,
        "cmd:rollover:old",
        UserCommandAction::SubmitOrder {
            order: order(
                200,
                "ignored",
                OLD_MARKET,
                Outcome::Up,
                OrderAction::Buy,
                200_000,
                1_000_000,
                TimeInForce::Gtc,
                None,
            ),
        },
        1_900,
    )
    .unwrap();
    let close_root = core.state_root();
    let closed_submit = execute(
        &mut core,
        &user_key,
        2,
        "cmd:rollover:closed-submit",
        UserCommandAction::SubmitOrder {
            order: order(
                201,
                "ignored",
                OLD_MARKET,
                Outcome::Down,
                OrderAction::Buy,
                300_000,
                1_000_000,
                TimeInForce::Fak,
                None,
            ),
        },
        2_000,
    );
    assert_eq!(
        closed_submit.unwrap_err(),
        CoreError::InvalidOrder("market is not open".into())
    );
    assert_eq!(core.state_root(), close_root);
    assert_eq!(
        core.aggregate_depth(OLD_MARKET, Outcome::Up, 2_000, 1),
        (Vec::new(), Vec::new())
    );

    let new_id = Uuid::from_u128(202);
    let new_response = execute(
        &mut core,
        &user_key,
        2,
        "cmd:rollover:new",
        UserCommandAction::SubmitOrder {
            order: order(
                202,
                "ignored",
                NEW_MARKET,
                Outcome::Up,
                OrderAction::Buy,
                300_000,
                1_000_000,
                TimeInForce::Gtc,
                None,
            ),
        },
        2_000,
    )
    .unwrap();
    let CommandResult::Order { result } = new_response.result else {
        panic!("expected rollover order");
    };
    assert_eq!(result.accepted_order.unwrap().status, OrderStatus::Open);
    assert!(result.fills.is_empty());
    let old_hold = cash_hold(&owner, OLD_MARKET, Outcome::Up);
    let new_hold = cash_hold(&owner, NEW_MARKET, Outcome::Up);
    assert_eq!(core.balance(&old_hold), 200_000);
    assert_eq!(core.balance(&new_hold), 300_000);

    let cancel = signed_command(
        &user_key,
        3,
        "cmd:rollover:cancel-old",
        UserCommandAction::CancelOrder {
            market_id: OLD_MARKET.into(),
            order_id: old_id,
        },
        2_100,
    );
    let first = core.execute(cancel.clone(), 2_100).unwrap();
    let root = core.state_root();
    assert_eq!(core.execute(cancel, 2_101).unwrap(), first);
    assert_eq!(core.state_root(), root);
    assert_eq!(core.balance(&old_hold), 0);
    assert_eq!(core.balance(&new_hold), 300_000);
    assert_eq!(core.balance(&available(&owner)), 700_000);

    execute(
        &mut core,
        &user_key,
        4,
        "cmd:rollover:cancel-new",
        UserCommandAction::CancelOrder {
            market_id: NEW_MARKET.into(),
            order_id: new_id,
        },
        2_500,
    )
    .unwrap();
    assert_eq!(core.balance(&new_hold), 0);
    assert_eq!(core.balance(&available(&owner)), ONE_USDC);
}

#[test]
fn resolution_cancels_all_order_holds_and_is_deterministic_after_snapshot() {
    let (mut core, user_key, owner) = configured_core(&[(OLD_MARKET, 900, 2_000, 4_000_000)]);
    for (sequence, id, outcome, price, tif, expiry) in [
        (1, 300, Outcome::Up, 200_000, TimeInForce::Gtc, None),
        (
            2,
            301,
            Outcome::Down,
            300_000,
            TimeInForce::Gtd,
            Some(1_900),
        ),
    ] {
        execute(
            &mut core,
            &user_key,
            sequence,
            &format!("cmd:resolution:order:{id}"),
            UserCommandAction::SubmitOrder {
                order: order(
                    id,
                    "ignored",
                    OLD_MARKET,
                    outcome,
                    OrderAction::Buy,
                    price,
                    1_000_000,
                    tif,
                    expiry,
                ),
            },
            1_000 + sequence as i64 * 100,
        )
        .unwrap();
    }
    let up_hold = cash_hold(&owner, OLD_MARKET, Outcome::Up);
    let down_hold = cash_hold(&owner, OLD_MARKET, Outcome::Down);
    assert_eq!(core.balance(&up_hold), 200_000);
    assert_eq!(core.balance(&down_hold), 300_000);

    let snapshot = core.export_encrypted_snapshot().unwrap();
    let mut first = PrivateTradingCore::restore_encrypted_snapshot(
        JournalKey::from_bytes(JOURNAL_KEY),
        ReceiptSigner::generate(RECEIPT_KEY),
        &snapshot,
        snapshot.sequence,
    )
    .unwrap();
    let mut second = PrivateTradingCore::restore_encrypted_snapshot(
        JournalKey::from_bytes(JOURNAL_KEY),
        ReceiptSigner::generate(RECEIPT_KEY),
        &snapshot,
        snapshot.sequence,
    )
    .unwrap();
    let signed = signed_resolution(OLD_MARKET, 2_100);
    let first_response = first
        .resolve_exact_condition_market("sys:resolution:lifecycle".into(), signed.clone(), 2_100)
        .unwrap();
    let second_response = second
        .resolve_exact_condition_market("sys:resolution:lifecycle".into(), signed, 2_100)
        .unwrap();
    // Restoring the same encrypted snapshot and applying the same signed
    // resolution produces the same semantic receipt and state. Journal
    // encryption intentionally uses a fresh nonce, so ciphertext/hash/signature
    // bytes are not required to match across independent runtime instances.
    assert_eq!(
        first_response.receipt.receipt_id,
        second_response.receipt.receipt_id
    );
    assert_eq!(
        first_response.receipt.prior_state_root,
        second_response.receipt.prior_state_root
    );
    assert_eq!(
        first_response.receipt.state_root,
        second_response.receipt.state_root
    );
    assert_eq!(first_response.audit_fills, second_response.audit_fills);
    assert_eq!(first.state_root(), second.state_root());
    assert_eq!(
        first.market_resolution(OLD_MARKET),
        second.market_resolution(OLD_MARKET)
    );
    assert_eq!(first.balance(&up_hold), 0);
    assert_eq!(first.balance(&down_hold), 0);
    assert_eq!(first.balance(&available(&owner)), ONE_USDC);
    assert_eq!(
        first
            .market_settlement_readiness(OLD_MARKET, 2_100)
            .unwrap()
            .active_order_count,
        0
    );

    let locked_root = first.state_root();
    let late_order = execute(
        &mut first,
        &user_key,
        3,
        "cmd:resolution:late-order",
        UserCommandAction::SubmitOrder {
            order: order(
                302,
                "ignored",
                OLD_MARKET,
                Outcome::Up,
                OrderAction::Sell,
                500_000,
                1_000_000,
                TimeInForce::Fak,
                None,
            ),
        },
        2_200,
    );
    assert_eq!(
        late_order.unwrap_err(),
        CoreError::InvalidOrder("market is not open".into())
    );
    let late_cancel = execute(
        &mut first,
        &user_key,
        3,
        "cmd:resolution:late-cancel",
        UserCommandAction::CancelOrder {
            market_id: OLD_MARKET.into(),
            order_id: Uuid::from_u128(300),
        },
        2_200,
    );
    assert_eq!(
        late_cancel.unwrap_err(),
        CoreError::InvalidOrder("order is not cancellable".into())
    );
    assert_eq!(first.state_root(), locked_root);
}

fn configured_core(markets: &[(&str, i64, i64, u128)]) -> (PrivateTradingCore, SigningKey, String) {
    let user_key = SigningKey::from_bytes(&USER_KEY);
    let oracle = SigningKey::from_bytes(&ORACLE_KEY);
    let owner = derived_private_user(JOURNAL_KEY, USER_COMMITMENT);
    let mut core = PrivateTradingCore::new_with_oracle(
        JournalKey::from_bytes(JOURNAL_KEY),
        ReceiptSigner::generate(RECEIPT_KEY),
        oracle.verifying_key().to_bytes(),
    )
    .unwrap();
    for (index, (market_id, opens_at, closes_at, max_position)) in markets.iter().enumerate() {
        core.register_market(
            format!("sys:market:lifecycle:{index}"),
            MarketConfig {
                market_id: (*market_id).into(),
                settlement_asset: "USDC".into(),
                settlement_decimals: 6,
                public_settlement_chain: Some("horizen".into()),
                opens_at_millis: *opens_at,
                closes_at_millis: *closes_at,
                minimum_quantity_micros: 1,
                maximum_quantity_micros: *max_position,
                minimum_order_notional_micros: 1,
                maximum_order_notional_micros: 4_000_000,
                maximum_user_position_micros: *max_position,
                maximum_pending_bootstrap_notional_micros: 4_000_000,
                tick_size_micros: 100,
                oracle_feed_id: 245,
                fee_profile_id: FeeProfileId::LayrsCryptoV2,
                execution: MarketExecution::NativeExactCondition {
                    condition_id: condition_id(market_id),
                    up_outcome_index: 0,
                    down_outcome_index: 1,
                },
            },
            800,
        )
        .unwrap();
    }
    core.register_session(
        "sys:session:lifecycle".into(),
        "session:lifecycle".into(),
        USER_COMMITMENT,
        user_key.verifying_key().to_bytes(),
        10_000,
        850,
    )
    .unwrap();
    core.apply_user_external_flow(
        "sys:deposit:lifecycle".into(),
        USER_COMMITMENT,
        "USDC".into(),
        AccountBucket::UserAvailable,
        ONE_USDC,
        ExternalFlowDirection::Inflow,
        [16u8; 32],
        875,
    )
    .unwrap();
    (core, user_key, owner)
}

fn signed_resolution(market_id: &str, now_millis: i64) -> SignedExactConditionResolution {
    let statement = ExactConditionResolutionStatement {
        market_id: market_id.into(),
        condition_id: condition_id(market_id),
        outcome: ResolutionOutcome::Up,
        evidence_hash: [17u8; 32],
        issued_at_millis: now_millis,
    };
    let oracle = SigningKey::from_bytes(&ORACLE_KEY);
    let signature = oracle
        .sign(&exact_condition_resolution_signing_payload(&statement).unwrap())
        .to_bytes()
        .to_vec();
    SignedExactConditionResolution {
        statement,
        signature,
    }
}

fn execute(
    core: &mut PrivateTradingCore,
    key: &SigningKey,
    sequence: u64,
    command_id: &str,
    action: UserCommandAction,
    now_millis: i64,
) -> Result<clob_service::private_core::CoreResponse, CoreError> {
    core.execute(
        signed_command(key, sequence, command_id, action, now_millis),
        now_millis,
    )
}

#[allow(clippy::too_many_arguments)]
fn execute_for_session(
    core: &mut PrivateTradingCore,
    key: &SigningKey,
    session_id: &str,
    sequence: u64,
    command_id: &str,
    action: UserCommandAction,
    now_millis: i64,
) -> Result<clob_service::private_core::CoreResponse, CoreError> {
    core.execute(
        signed_command_for_session(key, session_id, sequence, command_id, action, now_millis),
        now_millis,
    )
}

fn signed_command(
    key: &SigningKey,
    sequence: u64,
    command_id: &str,
    action: UserCommandAction,
    now_millis: i64,
) -> UserCommand {
    signed_command_for_session(
        key,
        "session:lifecycle",
        sequence,
        command_id,
        action,
        now_millis,
    )
}

fn signed_command_for_session(
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
        expires_at_millis: 9_900,
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

#[allow(clippy::too_many_arguments)]
fn order(
    id: u128,
    owner: &str,
    market_id: &str,
    outcome: Outcome,
    action: OrderAction,
    price_micros: u64,
    quantity_micros: u128,
    tif: TimeInForce,
    expiry: Option<i64>,
) -> BookOrder {
    BookOrder::with_id(
        Uuid::from_u128(id),
        owner,
        market_id,
        outcome,
        action,
        price_micros,
        quantity_micros,
        tif,
        expiry,
    )
}

fn available(owner: &str) -> AccountKey {
    AccountKey::new(owner, AccountBucket::UserAvailable, "USDC")
}

fn cash_hold(owner: &str, market_id: &str, outcome: Outcome) -> AccountKey {
    let mut account = AccountKey::new(owner, AccountBucket::UserOrderHold, "USDC");
    account.market_id = Some(market_id.into());
    account.outcome = Some(match outcome {
        Outcome::Up => "UP".into(),
        Outcome::Down => "DOWN".into(),
    });
    account
}

fn claim_hold_for(owner: &str, market_id: &str, outcome: Outcome) -> AccountKey {
    let outcome = match outcome {
        Outcome::Up => "UP",
        Outcome::Down => "DOWN",
    };
    let mut account = AccountKey::new(
        owner,
        AccountBucket::UserOrderHold,
        format!("CLAIM:{market_id}:{outcome}"),
    );
    account.market_id = Some(market_id.into());
    account.outcome = Some(outcome.into());
    account
}

fn financial_balances(
    core: &PrivateTradingCore,
    taker_owner: &str,
    maker_owner: &str,
) -> Vec<u128> {
    let position = |owner: &str, outcome: Outcome| {
        let outcome_name = if outcome == Outcome::Up { "UP" } else { "DOWN" };
        core.balance(&AccountKey::position(
            owner,
            format!("CLAIM:{OLD_MARKET}:{outcome_name}"),
            OLD_MARKET,
            outcome_name,
        ))
    };
    let mut collateral = AccountKey::new("layrs", AccountBucket::MarketCollateral, "USDC");
    collateral.market_id = Some(OLD_MARKET.into());
    vec![
        core.balance(&available(taker_owner)),
        core.balance(&cash_hold(taker_owner, OLD_MARKET, Outcome::Up)),
        position(taker_owner, Outcome::Up),
        position(taker_owner, Outcome::Down),
        core.balance(&available(maker_owner)),
        core.balance(&cash_hold(maker_owner, OLD_MARKET, Outcome::Up)),
        core.balance(&claim_hold_for(maker_owner, OLD_MARKET, Outcome::Up)),
        position(maker_owner, Outcome::Up),
        position(maker_owner, Outcome::Down),
        core.balance(&collateral),
        core.balance(&AccountKey::new("layrs", AccountBucket::FeeRevenue, "USDC")),
    ]
}

fn condition_id(market_id: &str) -> String {
    format!("0x{}", hex::encode(Sha256::digest(market_id.as_bytes())))
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
