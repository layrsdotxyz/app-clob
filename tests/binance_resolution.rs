use clob_service::private_core::{
    binance_resolution_signing_payload, BinanceBoundaryEvidence, BinanceResolutionStatement,
    CoreError, JournalKey, MarketConfig, MarketExecution, PrivateTradingCore, ReceiptSigner,
    ResolutionEvidence, ResolutionOutcome, SignedBinanceResolution,
};
use ed25519_dalek::{Signer, SigningKey};

const MARKET_ID: &str = "layrs:v4:ZEN:15m:200000";
const BINANCE_SOURCE: &str = "BINANCE_SPOT_ZENUSDT_1S_V1";
const OPENS_AT: i64 = 100_000;
const CLOSES_AT: i64 = 200_000;

fn market(oracle_feed_id: u64) -> MarketConfig {
    MarketConfig {
        market_id: MARKET_ID.into(),
        settlement_asset: "ZEN".into(),
        settlement_decimals: 18,
        public_settlement_chain: Some("horizen".into()),
        opens_at_millis: OPENS_AT,
        closes_at_millis: CLOSES_AT,
        minimum_quantity_micros: 250_000,
        maximum_quantity_micros: 10_000_000,
        minimum_order_notional_micros: 250_000,
        maximum_order_notional_micros: 10_000_000,
        maximum_user_position_micros: 10_000_000,
        maximum_pending_bootstrap_notional_micros: 100_000_000,
        tick_size_micros: 1_000,
        oracle_feed_id,
        execution: MarketExecution::NativeClob,
    }
}

fn core(oracle: &SigningKey, marker: u8, oracle_feed_id: u64) -> PrivateTradingCore {
    let mut core = PrivateTradingCore::new_with_oracle(
        JournalKey::from_bytes([marker; 32]),
        ReceiptSigner::generate([marker.wrapping_add(1); 48]),
        oracle.verifying_key().to_bytes(),
    )
    .unwrap();
    core.register_market(
        format!("register:{marker}"),
        market(oracle_feed_id),
        OPENS_AT - 1,
    )
    .unwrap();
    core
}

fn boundary(target_millis: i64, price_e8: i64, marker: u8) -> BinanceBoundaryEvidence {
    BinanceBoundaryEvidence {
        window_start_millis: target_millis - 5_000,
        window_end_millis: target_millis,
        median_price_e8: price_e8,
        sample_count: 5,
        evidence_path_count: 2,
        evidence_commitment: [marker; 32],
    }
}

fn primary_statement() -> BinanceResolutionStatement {
    BinanceResolutionStatement {
        market_id: MARKET_ID.into(),
        oracle_source: BINANCE_SOURCE.into(),
        opening: Some(boundary(OPENS_AT, 400_000_000, 11)),
        closing: Some(boundary(CLOSES_AT, 410_000_000, 12)),
        fallback: None,
        reason: None,
        outcome: None,
        opening_boundary_millis: None,
        closing_boundary_millis: None,
        deadline_millis: None,
        missing_boundaries: Vec::new(),
        issued_at_millis: CLOSES_AT + 1_000,
    }
}

fn timeout_statement() -> BinanceResolutionStatement {
    let deadline = CLOSES_AT + 120_000;
    BinanceResolutionStatement {
        market_id: MARKET_ID.into(),
        oracle_source: BINANCE_SOURCE.into(),
        opening: None,
        closing: None,
        fallback: Some("PUSH_REFUND".into()),
        reason: Some("BINANCE_EVIDENCE_TIMEOUT".into()),
        outcome: Some(ResolutionOutcome::Push),
        opening_boundary_millis: Some(OPENS_AT),
        closing_boundary_millis: Some(CLOSES_AT),
        deadline_millis: Some(deadline),
        missing_boundaries: vec!["OPENING".into(), "CLOSING".into()],
        issued_at_millis: deadline,
    }
}

fn sign(oracle: &SigningKey, statement: BinanceResolutionStatement) -> SignedBinanceResolution {
    let signature = oracle
        .sign(&binance_resolution_signing_payload(&statement).unwrap())
        .to_bytes()
        .to_vec();
    SignedBinanceResolution {
        statement,
        signature,
    }
}

#[test]
fn resolves_from_exact_five_second_dual_path_evidence() {
    let oracle = SigningKey::from_bytes(&[31; 32]);
    let mut core = core(&oracle, 32, 9001);
    core.resolve_binance_market(
        "resolve:primary".into(),
        sign(&oracle, primary_statement()),
        CLOSES_AT + 1_000,
    )
    .unwrap();

    let resolution = core.market_resolution(MARKET_ID).unwrap();
    assert_eq!(resolution.outcome, ResolutionOutcome::Up);
    assert!(matches!(
        resolution.evidence,
        ResolutionEvidence::BinanceSpotKlineMedian { .. }
    ));
}

#[test]
fn rejects_single_path_wrong_feed_and_signature_tampering() {
    let oracle = SigningKey::from_bytes(&[33; 32]);

    let mut single_path = primary_statement();
    single_path.opening.as_mut().unwrap().evidence_path_count = 1;
    let error = core(&oracle, 34, 9001)
        .resolve_binance_market(
            "resolve:single-path".into(),
            sign(&oracle, single_path),
            CLOSES_AT + 1_000,
        )
        .unwrap_err();
    assert!(matches!(error, CoreError::InvalidResolution(_)));

    let error = core(&oracle, 35, 245)
        .resolve_binance_market(
            "resolve:wrong-feed".into(),
            sign(&oracle, primary_statement()),
            CLOSES_AT + 1_000,
        )
        .unwrap_err();
    assert!(matches!(error, CoreError::InvalidResolution(_)));

    let mut signed = sign(&oracle, primary_statement());
    signed.statement.closing.as_mut().unwrap().median_price_e8 += 1;
    assert_eq!(
        core(&oracle, 36, 9001)
            .resolve_binance_market("resolve:tampered".into(), signed, CLOSES_AT + 1_000,)
            .unwrap_err(),
        CoreError::InvalidOracleSignature
    );
}

#[test]
fn timeout_refund_is_unavailable_early_and_exact_at_deadline() {
    let oracle = SigningKey::from_bytes(&[37; 32]);
    let deadline = CLOSES_AT + 120_000;
    let signed = sign(&oracle, timeout_statement());

    let error = core(&oracle, 38, 9001)
        .resolve_binance_market("resolve:early".into(), signed.clone(), deadline - 1)
        .unwrap_err();
    assert!(matches!(error, CoreError::InvalidResolution(_)));

    let mut timeout_core = core(&oracle, 39, 9001);
    timeout_core
        .resolve_binance_market("resolve:timeout".into(), signed, deadline)
        .unwrap();
    assert_eq!(
        timeout_core.market_resolution(MARKET_ID).unwrap().outcome,
        ResolutionOutcome::Push
    );

    let mut duplicate_missing = timeout_statement();
    duplicate_missing.missing_boundaries = vec!["OPENING".into(), "OPENING".into()];
    let error = core(&oracle, 40, 9001)
        .resolve_binance_market(
            "resolve:bad-timeout".into(),
            sign(&oracle, duplicate_missing),
            deadline,
        )
        .unwrap_err();
    assert!(matches!(error, CoreError::InvalidResolution(_)));
}

#[test]
fn identical_evidence_replays_to_identical_state() {
    let oracle = SigningKey::from_bytes(&[41; 32]);
    let signed = sign(&oracle, primary_statement());
    let mut first = core(&oracle, 42, 9001);
    let mut second = core(&oracle, 42, 9001);

    first
        .resolve_binance_market(
            "resolve:deterministic".into(),
            signed.clone(),
            CLOSES_AT + 1_000,
        )
        .unwrap();
    second
        .resolve_binance_market("resolve:deterministic".into(), signed, CLOSES_AT + 1_000)
        .unwrap();

    assert_eq!(first.state_root(), second.state_root());
    assert_eq!(
        first.market_resolution(MARKET_ID),
        second.market_resolution(MARKET_ID)
    );
}
