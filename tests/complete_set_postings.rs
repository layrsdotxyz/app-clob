use clob_service::private_core::{
    AccountBucket, AccountKey, CompleteSetDirection, CompleteSetFillPosting, CoreError, Ledger,
    PostingSide,
};
use proptest::prelude::*;

const MARKET: &str = "layrs:v5:BTC:USDC:15m:1786963200";

fn cash_hold(owner: &str, outcome: &str) -> AccountKey {
    AccountKey {
        owner: owner.into(),
        bucket: AccountBucket::UserOrderHold,
        asset: "USDC".into(),
        market_id: Some(MARKET.into()),
        outcome: Some(outcome.into()),
    }
}

fn claim(owner: &str, outcome: &str, bucket: AccountBucket) -> AccountKey {
    AccountKey {
        owner: owner.into(),
        bucket,
        asset: format!("CLAIM:{MARKET}:{outcome}"),
        market_id: Some(MARKET.into()),
        outcome: Some(outcome.into()),
    }
}

fn available(owner: &str) -> AccountKey {
    AccountKey::new(owner, AccountBucket::UserAvailable, "USDC")
}

fn collateral() -> AccountKey {
    let mut account = AccountKey::new("layrs", AccountBucket::MarketCollateral, "USDC");
    account.market_id = Some(MARKET.into());
    account
}

fn fee_revenue() -> AccountKey {
    AccountKey::new("layrs", AccountBucket::FeeRevenue, "USDC")
}

fn mint(
    fill_id: &str,
    maker: &str,
    taker: &str,
    maker_atomic: u128,
    taker_atomic: u128,
    fee: u128,
    quantity: u128,
) -> CompleteSetFillPosting {
    CompleteSetFillPosting {
        fill_id: fill_id.into(),
        direction: CompleteSetDirection::Mint,
        maker_hold: cash_hold(maker, "UP"),
        taker_hold: cash_hold(taker, "DOWN"),
        maker_destination: claim(maker, "UP", AccountBucket::UserPosition),
        taker_destination: claim(taker, "DOWN", AccountBucket::UserPosition),
        market_collateral: collateral(),
        fee_revenue: fee_revenue(),
        quantity_micros: quantity,
        collateral_amount_atomic: maker_atomic + taker_atomic,
        maker_amount_atomic: maker_atomic,
        taker_amount_atomic: taker_atomic,
        taker_fee_atomic: fee,
    }
}

fn merge(
    fill_id: &str,
    maker: &str,
    taker: &str,
    maker_atomic: u128,
    taker_atomic: u128,
    fee: u128,
    quantity: u128,
) -> CompleteSetFillPosting {
    CompleteSetFillPosting {
        fill_id: fill_id.into(),
        direction: CompleteSetDirection::Burn,
        maker_hold: claim(maker, "UP", AccountBucket::UserOrderHold),
        taker_hold: claim(taker, "DOWN", AccountBucket::UserOrderHold),
        maker_destination: available(maker),
        taker_destination: available(taker),
        market_collateral: collateral(),
        fee_revenue: fee_revenue(),
        quantity_micros: quantity,
        collateral_amount_atomic: maker_atomic + taker_atomic,
        maker_amount_atomic: maker_atomic,
        taker_amount_atomic: taker_atomic,
        taker_fee_atomic: fee,
    }
}

fn seed_mint(ledger: &mut Ledger, fill: &CompleteSetFillPosting) {
    ledger
        .seed_balance(fill.maker_hold.clone(), fill.maker_amount_atomic)
        .unwrap();
    ledger
        .seed_balance(
            fill.taker_hold.clone(),
            fill.taker_amount_atomic + fill.taker_fee_atomic,
        )
        .unwrap();
}

fn cash_sides(applied: &clob_service::private_core::AppliedLedgerTransaction) -> (u128, u128) {
    let debits = applied
        .postings
        .iter()
        .filter(|p| p.account.asset == "USDC" && p.side == PostingSide::Debit)
        .map(|p| p.amount)
        .sum();
    let credits = applied
        .postings
        .iter()
        .filter(|p| p.account.asset == "USDC" && p.side == PostingSide::Credit)
        .map(|p| p.amount)
        .sum();
    (debits, credits)
}

#[test]
fn mint_posts_balanced_cash_and_equal_opposite_claims() {
    let fill = mint(
        "mint-balanced",
        "maker",
        "taker",
        350_000,
        650_000,
        1_300,
        1_000_000,
    );
    let mut ledger = Ledger::default();
    seed_mint(&mut ledger, &fill);

    let applied = ledger
        .apply_complete_set_fill("operator-one".into(), "mint".into(), fill.clone())
        .unwrap();

    assert_eq!(cash_sides(&applied), (1_001_300, 1_001_300));
    assert_eq!(ledger.balance(&fill.maker_hold), 0);
    assert_eq!(ledger.balance(&fill.taker_hold), 0);
    assert_eq!(ledger.balance(&fill.market_collateral), 1_000_000);
    assert_eq!(ledger.balance(&fill.fee_revenue), 1_300);
    assert_eq!(ledger.balance(&fill.maker_destination), 1_000_000);
    assert_eq!(ledger.balance(&fill.taker_destination), 1_000_000);
    assert_eq!(applied.sequence, 1);
}

#[test]
fn partial_mints_then_full_merge_conserve_collateral_claims_and_fees() {
    let first = mint(
        "mint-partial-one",
        "maker",
        "taker",
        100_000,
        150_000,
        300,
        250_000,
    );
    let second = mint(
        "mint-partial-two",
        "maker",
        "taker",
        300_000,
        450_000,
        900,
        750_000,
    );
    let mut ledger = Ledger::default();
    ledger
        .seed_balance(first.maker_hold.clone(), 400_000)
        .unwrap();
    ledger
        .seed_balance(first.taker_hold.clone(), 601_200)
        .unwrap();
    ledger
        .apply_complete_set_fill("mint-one".into(), "mint-one".into(), first.clone())
        .unwrap();
    ledger
        .apply_complete_set_fill("mint-two".into(), "mint-two".into(), second.clone())
        .unwrap();

    assert_eq!(ledger.balance(&collateral()), 1_000_000);
    assert_eq!(
        ledger.balance(&claim("maker", "UP", AccountBucket::UserPosition)),
        1_000_000
    );
    assert_eq!(
        ledger.balance(&claim("taker", "DOWN", AccountBucket::UserPosition)),
        1_000_000
    );

    // Moving positions into holds models two accepted complementary SELL orders.
    ledger
        .apply(clob_service::private_core::LedgerTransaction {
            idempotency_key: "hold-claims".into(),
            business_reference: "hold-claims".into(),
            transfers: vec![
                clob_service::private_core::Transfer {
                    from: claim("maker", "UP", AccountBucket::UserPosition),
                    to: claim("maker", "UP", AccountBucket::UserOrderHold),
                    amount: 1_000_000,
                },
                clob_service::private_core::Transfer {
                    from: claim("taker", "DOWN", AccountBucket::UserPosition),
                    to: claim("taker", "DOWN", AccountBucket::UserOrderHold),
                    amount: 1_000_000,
                },
            ],
        })
        .unwrap();
    let burn = merge(
        "merge-full",
        "maker",
        "taker",
        400_000,
        600_000,
        1_200,
        1_000_000,
    );
    let applied = ledger
        .apply_complete_set_fill("merge".into(), "merge".into(), burn.clone())
        .unwrap();

    assert_eq!(cash_sides(&applied), (1_000_000, 1_000_000));
    assert_eq!(ledger.balance(&collateral()), 0);
    assert_eq!(ledger.balance(&burn.maker_hold), 0);
    assert_eq!(ledger.balance(&burn.taker_hold), 0);
    assert_eq!(ledger.balance(&available("maker")), 400_000);
    assert_eq!(ledger.balance(&available("taker")), 598_800);
    assert_eq!(ledger.balance(&fee_revenue()), 2_400);
}

#[test]
fn fill_evidence_replay_survives_snapshot_and_lost_response() {
    let fill = mint(
        "mint-replay-evidence",
        "maker",
        "taker",
        400_000,
        600_000,
        1_200,
        1_000_000,
    );
    let mut ledger = Ledger::default();
    seed_mint(&mut ledger, &fill);
    ledger
        .apply_complete_set_fill("operator-key-one".into(), "mint".into(), fill.clone())
        .unwrap();

    let encoded = serde_json::to_vec(&ledger).unwrap();
    let mut restored: Ledger = serde_json::from_slice(&encoded).unwrap();
    let root = restored.state_root();
    let replay = restored.apply_complete_set_fill(
        "operator-key-two".into(),
        "lost-response-retry".into(),
        fill,
    );
    assert_eq!(replay.unwrap_err(), CoreError::DuplicateCommand);
    assert_eq!(restored.state_root(), root);
    assert_eq!(restored.sequence(), 1);
}

#[test]
fn dust_imbalance_and_malformed_accounts_fail_without_mutation() {
    let cases = [
        {
            let mut f = mint("zero", "maker", "taker", 1, 1, 0, 1);
            f.quantity_micros = 0;
            f
        },
        {
            let mut f = mint("imbalance", "maker", "taker", 10, 10, 0, 10);
            f.collateral_amount_atomic = 19;
            f
        },
        {
            let mut f = mint("same-outcome", "maker", "taker", 10, 10, 0, 10);
            f.taker_hold.outcome = Some("UP".into());
            f.taker_destination = claim("taker", "UP", AccountBucket::UserPosition);
            f
        },
        {
            let mut f = mint("operator-owner", "maker", "taker", 10, 10, 0, 10);
            f.maker_hold.owner = "layrs".into();
            f.maker_destination.owner = "layrs".into();
            f
        },
    ];
    for fill in cases {
        let mut ledger = Ledger::default();
        let root = ledger.state_root();
        assert!(ledger
            .apply_complete_set_fill("operator".into(), "invalid".into(), fill)
            .is_err());
        assert_eq!(ledger.state_root(), root);
        assert_eq!(ledger.sequence(), 0);
    }
}

proptest! {
    #[test]
    fn arbitrary_precision_safe_mint_merge_round_trips_value(
        maker_atomic in 1u128..1_000_000,
        taker_atomic in 1u128..1_000_000,
        quantity in 1u128..5_000_000,
        fee_bps in 0u128..=200,
    ) {
        let fee = taker_atomic * fee_bps / 10_000;
        let minted = mint("prop-mint", "maker", "taker", maker_atomic, taker_atomic, fee, quantity);
        let mut ledger = Ledger::default();
        seed_mint(&mut ledger, &minted);
        let mint_applied = ledger
            .apply_complete_set_fill("prop-mint-key".into(), "prop-mint".into(), minted.clone())
            .unwrap();
        prop_assert_eq!(cash_sides(&mint_applied).0, cash_sides(&mint_applied).1);
        prop_assert_eq!(ledger.balance(&collateral()), maker_atomic + taker_atomic);
        prop_assert_eq!(ledger.balance(&minted.maker_destination), quantity);
        prop_assert_eq!(ledger.balance(&minted.taker_destination), quantity);

        ledger.apply(clob_service::private_core::LedgerTransaction {
            idempotency_key: "prop-holds".into(),
            business_reference: "prop-holds".into(),
            transfers: vec![
                clob_service::private_core::Transfer {
                    from: minted.maker_destination.clone(),
                    to: claim("maker", "UP", AccountBucket::UserOrderHold),
                    amount: quantity,
                },
                clob_service::private_core::Transfer {
                    from: minted.taker_destination.clone(),
                    to: claim("taker", "DOWN", AccountBucket::UserOrderHold),
                    amount: quantity,
                },
            ],
        }).unwrap();
        let burned = merge("prop-merge", "maker", "taker", maker_atomic, taker_atomic, fee, quantity);
        let burn_applied = ledger
            .apply_complete_set_fill("prop-merge-key".into(), "prop-merge".into(), burned)
            .unwrap();
        prop_assert_eq!(cash_sides(&burn_applied).0, cash_sides(&burn_applied).1);
        prop_assert_eq!(ledger.balance(&collateral()), 0);
        prop_assert_eq!(ledger.balance(&available("maker")), maker_atomic);
        prop_assert_eq!(ledger.balance(&available("taker")), taker_atomic - fee);
        prop_assert_eq!(ledger.balance(&fee_revenue()), fee * 2);
    }
}
