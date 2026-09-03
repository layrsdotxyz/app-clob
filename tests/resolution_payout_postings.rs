use clob_service::private_core::{
    AccountBucket, AccountKey, ClaimPayout, CoreError, Ledger, PostingSide, ResolutionPayoutKind,
};
use proptest::prelude::*;

const MARKET: &str = "layrs:v5:BTC:USDC:15m:1786963200";

fn claim(owner: &str, outcome: &str) -> AccountKey {
    AccountKey::position(owner, format!("CLAIM:{MARKET}:{outcome}"), MARKET, outcome)
}

fn available(owner: &str) -> AccountKey {
    AccountKey::new(owner, AccountBucket::UserAvailable, "USDC")
}

fn collateral() -> AccountKey {
    AccountKey {
        owner: "layrs".into(),
        bucket: AccountBucket::MarketCollateral,
        asset: "USDC".into(),
        market_id: Some(MARKET.into()),
        outcome: None,
    }
}

fn fee_revenue() -> AccountKey {
    AccountKey::new("layrs", AccountBucket::FeeRevenue, "USDC")
}

fn payout(owner: &str, outcome: &str, quantity: u128, gross: u128, fee: u128) -> ClaimPayout {
    ClaimPayout {
        claim_account: claim(owner, outcome),
        destination: available(owner),
        claim_quantity_micros: quantity,
        gross_payout_atomic: gross,
        winning_fee_atomic: fee,
    }
}

fn monetary_sides(applied: &clob_service::private_core::AppliedLedgerTransaction) -> (u128, u128) {
    let debits = applied
        .postings
        .iter()
        .filter(|posting| posting.account.asset == "USDC" && posting.side == PostingSide::Debit)
        .map(|posting| posting.amount)
        .sum();
    let credits = applied
        .postings
        .iter()
        .filter(|posting| posting.account.asset == "USDC" && posting.side == PostingSide::Credit)
        .map(|posting| posting.amount)
        .sum();
    (debits, credits)
}

#[test]
fn up_and_down_results_balance_winner_collateral_and_fee_postings() {
    for (marker, kind, winning_outcome) in [
        (1u8, ResolutionPayoutKind::Up, "UP"),
        (2u8, ResolutionPayoutKind::Down, "DOWN"),
    ] {
        let losing_outcome = if winning_outcome == "UP" {
            "DOWN"
        } else {
            "UP"
        };
        let mut ledger = Ledger::default();
        ledger.seed_balance(collateral(), 2_000_000).unwrap();
        ledger
            .seed_balance(claim("winner", winning_outcome), 2_000_000)
            .unwrap();
        ledger
            .seed_balance(claim("loser", losing_outcome), 2_000_000)
            .unwrap();

        let applied = ledger
            .apply_claim_payouts(
                format!("resolve-{winning_outcome}"),
                MARKET.into(),
                [marker; 32],
                kind,
                collateral(),
                fee_revenue(),
                vec![
                    payout("winner", winning_outcome, 2_000_000, 2_000_000, 15_000),
                    payout("loser", losing_outcome, 2_000_000, 0, 0),
                ],
            )
            .unwrap();

        assert_eq!(monetary_sides(&applied), (2_000_000, 2_000_000));
        assert_eq!(ledger.balance(&available("winner")), 1_985_000);
        assert_eq!(ledger.balance(&available("loser")), 0);
        assert_eq!(ledger.balance(&fee_revenue()), 15_000);
        assert_eq!(ledger.balance(&collateral()), 0);
        assert_eq!(ledger.balance(&claim("winner", winning_outcome)), 0);
        assert_eq!(ledger.balance(&claim("loser", losing_outcome)), 0);
    }
}

#[test]
fn push_and_invalid_refund_both_sides_symmetrically_without_fee() {
    for (marker, kind) in [
        (3u8, ResolutionPayoutKind::Push),
        (4u8, ResolutionPayoutKind::Invalid),
    ] {
        let mut ledger = Ledger::default();
        ledger.seed_balance(collateral(), 3_000_000).unwrap();
        ledger
            .seed_balance(claim("alice", "UP"), 4_000_000)
            .unwrap();
        ledger
            .seed_balance(claim("bob", "DOWN"), 2_000_000)
            .unwrap();

        let applied = ledger
            .apply_claim_payouts(
                format!("void-{marker}"),
                MARKET.into(),
                [marker; 32],
                kind,
                collateral(),
                fee_revenue(),
                vec![
                    payout("alice", "UP", 4_000_000, 2_000_000, 0),
                    payout("bob", "DOWN", 2_000_000, 1_000_000, 0),
                ],
            )
            .unwrap();

        assert_eq!(monetary_sides(&applied), (3_000_000, 3_000_000));
        assert_eq!(ledger.balance(&available("alice")), 2_000_000);
        assert_eq!(ledger.balance(&available("bob")), 1_000_000);
        assert_eq!(ledger.balance(&fee_revenue()), 0);
        assert_eq!(ledger.balance(&collateral()), 0);
    }
}

#[test]
fn evidence_replay_is_exact_once_across_operator_keys_and_snapshot_recovery() {
    let payouts = vec![
        payout("alice", "UP", 1_000_000, 1_000_000, 7_500),
        payout("bob", "DOWN", 1_000_000, 0, 0),
    ];
    let mut ledger = Ledger::default();
    ledger.seed_balance(collateral(), 1_000_000).unwrap();
    ledger
        .seed_balance(claim("alice", "UP"), 1_000_000)
        .unwrap();
    ledger
        .seed_balance(claim("bob", "DOWN"), 1_000_000)
        .unwrap();
    ledger
        .apply_claim_payouts(
            "operator-key-one".into(),
            MARKET.into(),
            [9u8; 32],
            ResolutionPayoutKind::Up,
            collateral(),
            fee_revenue(),
            payouts.clone(),
        )
        .unwrap();

    // Commit succeeded but the response was lost. Recovery loads the durable snapshot and a
    // redispatch uses a different operator key with the same signed evidence.
    let encoded = serde_json::to_vec(&ledger).unwrap();
    let mut recovered: Ledger = serde_json::from_slice(&encoded).unwrap();
    let root = recovered.state_root();
    let replay = recovered.apply_claim_payouts(
        "operator-key-two".into(),
        MARKET.into(),
        [9u8; 32],
        ResolutionPayoutKind::Up,
        collateral(),
        fee_revenue(),
        payouts,
    );
    assert_eq!(replay.unwrap_err(), CoreError::DuplicateCommand);
    assert_eq!(recovered.state_root(), root);
    assert_eq!(recovered.sequence(), 1);
}

#[test]
fn malformed_or_underfunded_resolution_is_atomic() {
    let cases = [
        (
            [0u8; 32],
            ResolutionPayoutKind::Up,
            vec![payout("alice", "UP", 1_000_000, 1_000_000, 0)],
        ),
        (
            [10u8; 32],
            ResolutionPayoutKind::Push,
            vec![payout("alice", "UP", 1_000_000, 500_000, 1)],
        ),
        (
            [11u8; 32],
            ResolutionPayoutKind::Up,
            vec![payout("bob", "DOWN", 1_000_000, 1, 0)],
        ),
        (
            [12u8; 32],
            ResolutionPayoutKind::Up,
            vec![payout("alice", "UP", 1_000_000, 0, 0)],
        ),
    ];
    for (index, (evidence, kind, payouts)) in cases.into_iter().enumerate() {
        let mut ledger = Ledger::default();
        ledger.seed_balance(collateral(), 500_000).unwrap();
        ledger
            .seed_balance(claim("alice", "UP"), 1_000_000)
            .unwrap();
        ledger
            .seed_balance(claim("bob", "DOWN"), 1_000_000)
            .unwrap();
        let root = ledger.state_root();
        let rejected = ledger.apply_claim_payouts(
            format!("malformed-{index}"),
            MARKET.into(),
            evidence,
            kind,
            collateral(),
            fee_revenue(),
            payouts,
        );
        assert!(rejected.is_err());
        assert_eq!(ledger.state_root(), root);
        assert_eq!(ledger.sequence(), 0);
    }

    let mut underfunded = Ledger::default();
    underfunded.seed_balance(collateral(), 999_999).unwrap();
    underfunded
        .seed_balance(claim("alice", "UP"), 1_000_000)
        .unwrap();
    let root = underfunded.state_root();
    let rejected = underfunded.apply_claim_payouts(
        "underfunded".into(),
        MARKET.into(),
        [14u8; 32],
        ResolutionPayoutKind::Up,
        collateral(),
        fee_revenue(),
        vec![payout("alice", "UP", 1_000_000, 1_000_000, 0)],
    );
    assert_eq!(rejected.unwrap_err(), CoreError::InsufficientBalance);
    assert_eq!(underfunded.state_root(), root);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]
    #[test]
    fn arbitrary_resolution_amounts_conserve_monetary_liability(
        quantity in 1u128..1_000_000_000u128,
        fee in 0u128..1_000_000u128,
        is_up in any::<bool>(),
    ) {
        prop_assume!(fee <= quantity);
        let (kind, winner_outcome, loser_outcome) = if is_up {
            (ResolutionPayoutKind::Up, "UP", "DOWN")
        } else {
            (ResolutionPayoutKind::Down, "DOWN", "UP")
        };
        let mut ledger = Ledger::default();
        ledger.seed_balance(collateral(), quantity).unwrap();
        ledger.seed_balance(claim("winner", winner_outcome), quantity).unwrap();
        ledger.seed_balance(claim("loser", loser_outcome), quantity).unwrap();
        let applied = ledger.apply_claim_payouts(
            "property".into(),
            MARKET.into(),
            [13u8; 32],
            kind,
            collateral(),
            fee_revenue(),
            vec![
                payout("winner", winner_outcome, quantity, quantity, fee),
                payout("loser", loser_outcome, quantity, 0, 0),
            ],
        ).unwrap();
        prop_assert_eq!(monetary_sides(&applied), (quantity, quantity));
        prop_assert_eq!(ledger.balance(&collateral()), 0);
        prop_assert_eq!(ledger.balance(&available("winner")), quantity - fee);
        prop_assert_eq!(ledger.balance(&fee_revenue()), fee);
    }
}
