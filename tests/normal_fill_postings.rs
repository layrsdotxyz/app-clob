use clob_service::private_core::{
    AccountBucket, AccountKey, CoreError, Ledger, LedgerTransaction, NormalFillPosting,
    PostingSide, Transfer,
};
use proptest::prelude::*;

const MARKET: &str = "layrs:v5:BTC:USDC:15m:1786963200";
const CLAIM: &str = "CLAIM:layrs:v5:BTC:USDC:15m:1786963200:UP";

fn cash_hold(owner: &str) -> AccountKey {
    AccountKey {
        owner: owner.into(),
        bucket: AccountBucket::UserOrderHold,
        asset: "USDC".into(),
        market_id: Some(MARKET.into()),
        outcome: Some("UP".into()),
    }
}

fn claim_hold(owner: &str) -> AccountKey {
    AccountKey {
        owner: owner.into(),
        bucket: AccountBucket::UserOrderHold,
        asset: CLAIM.into(),
        market_id: Some(MARKET.into()),
        outcome: Some("UP".into()),
    }
}

fn position(owner: &str) -> AccountKey {
    AccountKey::position(owner, CLAIM, MARKET, "UP")
}

fn available(owner: &str) -> AccountKey {
    AccountKey::new(owner, AccountBucket::UserAvailable, "USDC")
}

fn fee_revenue() -> AccountKey {
    AccountKey::new("layrs", AccountBucket::FeeRevenue, "USDC")
}

fn fill(
    fill_id: &str,
    buyer: &str,
    seller: &str,
    seller_proceeds_atomic: u128,
    fee_atomic: u128,
    quantity_micros: u128,
) -> NormalFillPosting {
    NormalFillPosting {
        fill_id: fill_id.into(),
        buyer_cash_hold: cash_hold(buyer),
        seller_available: available(seller),
        seller_claim_hold: claim_hold(seller),
        buyer_position: position(buyer),
        fee_revenue: fee_revenue(),
        seller_proceeds_atomic,
        fee_atomic,
        quantity_micros,
    }
}

fn fill_transfers(fill: &NormalFillPosting) -> Vec<Transfer> {
    let mut transfers = Vec::new();
    if fill.seller_proceeds_atomic > 0 {
        transfers.push(Transfer {
            from: fill.buyer_cash_hold.clone(),
            to: fill.seller_available.clone(),
            amount: fill.seller_proceeds_atomic,
        });
    }
    if fill.fee_atomic > 0 {
        transfers.push(Transfer {
            from: fill.buyer_cash_hold.clone(),
            to: fill.fee_revenue.clone(),
            amount: fill.fee_atomic,
        });
    }
    transfers.push(Transfer {
        from: fill.seller_claim_hold.clone(),
        to: fill.buyer_position.clone(),
        amount: fill.quantity_micros,
    });
    transfers
}

fn assert_balanced_by_asset(postings: &[clob_service::private_core::LedgerPosting]) {
    for asset in ["USDC", CLAIM] {
        let debits: u128 = postings
            .iter()
            .filter(|posting| posting.account.asset == asset && posting.side == PostingSide::Debit)
            .map(|posting| posting.amount)
            .sum();
        let credits: u128 = postings
            .iter()
            .filter(|posting| posting.account.asset == asset && posting.side == PostingSide::Credit)
            .map(|posting| posting.amount)
            .sum();
        assert_eq!(debits, credits, "unbalanced postings for {asset}");
    }
}

#[test]
fn partial_and_full_normal_fills_balance_cash_claims_and_fees() {
    let partial = fill(
        "fill-partial",
        "buyer",
        "seller-one",
        350_000,
        700,
        1_000_000,
    );
    let full = fill(
        "fill-full",
        "buyer",
        "seller-two",
        525_000,
        1_050,
        1_500_000,
    );
    let mut ledger = Ledger::default();
    ledger
        .seed_balance(
            cash_hold("buyer"),
            partial.seller_proceeds_atomic
                + partial.fee_atomic
                + full.seller_proceeds_atomic
                + full.fee_atomic,
        )
        .unwrap();
    ledger
        .seed_balance(claim_hold("seller-one"), partial.quantity_micros)
        .unwrap();
    ledger
        .seed_balance(claim_hold("seller-two"), full.quantity_micros)
        .unwrap();

    let mut transfers = fill_transfers(&partial);
    transfers.extend(fill_transfers(&full));
    let applied = ledger
        .apply_normal_fill_settlement(
            LedgerTransaction {
                idempotency_key: "order:normal:partial-full".into(),
                business_reference: "cmd:normal:partial-full".into(),
                transfers,
            },
            vec![partial.clone(), full.clone()],
        )
        .unwrap();

    assert_balanced_by_asset(&applied.postings);
    assert_eq!(ledger.balance(&cash_hold("buyer")), 0);
    assert_eq!(ledger.balance(&available("seller-one")), 350_000);
    assert_eq!(ledger.balance(&available("seller-two")), 525_000);
    assert_eq!(ledger.balance(&fee_revenue()), 1_750);
    assert_eq!(ledger.balance(&position("buyer")), 2_500_000);
    assert_eq!(ledger.balance(&claim_hold("seller-one")), 0);
    assert_eq!(ledger.balance(&claim_hold("seller-two")), 0);
}

#[test]
fn fill_evidence_replay_survives_snapshot_and_ignores_operator_key_changes() {
    let posting = fill("fill-replay", "buyer", "seller", 400_000, 800, 1_000_000);
    let mut ledger = Ledger::default();
    ledger.seed_balance(cash_hold("buyer"), 400_800).unwrap();
    ledger
        .seed_balance(claim_hold("seller"), 1_000_000)
        .unwrap();
    ledger
        .apply_normal_fill_settlement(
            LedgerTransaction {
                idempotency_key: "operator-key-one".into(),
                business_reference: "normal-fill".into(),
                transfers: fill_transfers(&posting),
            },
            vec![posting.clone()],
        )
        .unwrap();

    // Simulate commit success followed by a lost response and process restart.
    let serialized = serde_json::to_vec(&ledger).unwrap();
    let mut restored: Ledger = serde_json::from_slice(&serialized).unwrap();
    let root = restored.state_root();
    let replay = restored.apply_normal_fill_settlement(
        LedgerTransaction {
            idempotency_key: "operator-key-two".into(),
            business_reference: "normal-fill-retry".into(),
            transfers: fill_transfers(&posting),
        },
        vec![posting],
    );
    assert_eq!(replay.unwrap_err(), CoreError::DuplicateCommand);
    assert_eq!(restored.state_root(), root);
    assert_eq!(restored.sequence(), 1);
}

#[test]
fn malformed_normal_fill_is_rejected_without_partial_mutation() {
    let mut posting = fill("fill-malformed", "buyer", "seller", 400_000, 800, 1_000_000);
    let mut ledger = Ledger::default();
    ledger.seed_balance(cash_hold("buyer"), 400_800).unwrap();
    ledger
        .seed_balance(claim_hold("seller"), 1_000_000)
        .unwrap();
    let root = ledger.state_root();
    let transfers = fill_transfers(&posting);
    posting.buyer_position.owner = "different-buyer".into();
    let rejected = ledger.apply_normal_fill_settlement(
        LedgerTransaction {
            idempotency_key: "bad-normal-fill".into(),
            business_reference: "bad-normal-fill".into(),
            transfers,
        },
        vec![posting],
    );
    assert_eq!(rejected.unwrap_err(), CoreError::UnbalancedTransaction);
    assert_eq!(ledger.state_root(), root);
    assert_eq!(ledger.sequence(), 0);
}

#[test]
fn fee_mismatch_duplicate_fill_and_one_atomic_dust_are_safe() {
    let dust = fill("fill-dust", "buyer", "seller", 0, 1, 1);
    let mut ledger = Ledger::default();
    ledger.seed_balance(cash_hold("buyer"), 1).unwrap();
    ledger.seed_balance(claim_hold("seller"), 1).unwrap();
    let applied = ledger
        .apply_normal_fill_settlement(
            LedgerTransaction {
                idempotency_key: "normal-dust".into(),
                business_reference: "normal-dust".into(),
                transfers: fill_transfers(&dust),
            },
            vec![dust],
        )
        .unwrap();
    assert_balanced_by_asset(&applied.postings);
    assert_eq!(ledger.balance(&fee_revenue()), 1);
    assert_eq!(ledger.balance(&position("buyer")), 1);

    let posting = fill("fill-duplicate", "buyer", "seller", 10, 1, 2);
    let mut duplicate_ledger = Ledger::default();
    duplicate_ledger
        .seed_balance(cash_hold("buyer"), 22)
        .unwrap();
    duplicate_ledger
        .seed_balance(claim_hold("seller"), 4)
        .unwrap();
    let mut duplicate_transfers = fill_transfers(&posting);
    duplicate_transfers.extend(fill_transfers(&posting));
    let duplicate_root = duplicate_ledger.state_root();
    let duplicate = duplicate_ledger.apply_normal_fill_settlement(
        LedgerTransaction {
            idempotency_key: "duplicate-fill-batch".into(),
            business_reference: "duplicate-fill-batch".into(),
            transfers: duplicate_transfers,
        },
        vec![posting.clone(), posting.clone()],
    );
    assert_eq!(duplicate.unwrap_err(), CoreError::DuplicateCommand);
    assert_eq!(duplicate_ledger.state_root(), duplicate_root);

    let mut mismatch_ledger = Ledger::default();
    mismatch_ledger
        .seed_balance(cash_hold("buyer"), 11)
        .unwrap();
    mismatch_ledger
        .seed_balance(claim_hold("seller"), 2)
        .unwrap();
    let mismatch_root = mismatch_ledger.state_root();
    let mut wrong_transfers = fill_transfers(&posting);
    wrong_transfers
        .iter_mut()
        .find(|transfer| transfer.to == fee_revenue())
        .unwrap()
        .amount = 2;
    let mismatch = mismatch_ledger.apply_normal_fill_settlement(
        LedgerTransaction {
            idempotency_key: "fee-mismatch".into(),
            business_reference: "fee-mismatch".into(),
            transfers: wrong_transfers,
        },
        vec![posting],
    );
    assert_eq!(mismatch.unwrap_err(), CoreError::UnbalancedTransaction);
    assert_eq!(mismatch_ledger.state_root(), mismatch_root);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]
    #[test]
    fn arbitrary_normal_fill_amounts_conserve_each_asset(
        seller_proceeds in 0u128..1_000_000_000_000u128,
        fee in 0u128..10_000_000u128,
        quantity in 1u128..1_000_000_000u128,
    ) {
        prop_assume!(seller_proceeds + fee > 0);
        let posting = fill("fill-property", "buyer", "seller", seller_proceeds, fee, quantity);
        let cash = seller_proceeds + fee;
        let mut ledger = Ledger::default();
        ledger.seed_balance(cash_hold("buyer"), cash).unwrap();
        ledger.seed_balance(claim_hold("seller"), quantity).unwrap();
        let cash_total = ledger.total_for_asset("USDC");
        let claim_total = ledger.total_for_asset(CLAIM);

        let applied = ledger.apply_normal_fill_settlement(
            LedgerTransaction {
                idempotency_key: "normal-property".into(),
                business_reference: "normal-property".into(),
                transfers: fill_transfers(&posting),
            },
            vec![posting],
        ).unwrap();

        assert_balanced_by_asset(&applied.postings);
        prop_assert_eq!(ledger.total_for_asset("USDC"), cash_total);
        prop_assert_eq!(ledger.total_for_asset(CLAIM), claim_total);
        prop_assert_eq!(ledger.balance(&cash_hold("buyer")), 0);
        prop_assert_eq!(ledger.balance(&available("seller")), seller_proceeds);
        prop_assert_eq!(ledger.balance(&fee_revenue()), fee);
        prop_assert_eq!(ledger.balance(&position("buyer")), quantity);
    }
}
