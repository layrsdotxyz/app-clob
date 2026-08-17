use clob_service::private_core::{
    AccountBucket, AccountKey, CoreError, ExternalFlowDirection, ExternalFlowTransaction, Ledger,
    PostingSide, VaultStrategyTransaction, VaultStrategyTransition,
};
use proptest::prelude::*;

const ASSET: &str = "USDC";

fn transaction(
    key: &str,
    evidence: u8,
    operation: u8,
    amount: u128,
    transition: VaultStrategyTransition,
) -> VaultStrategyTransaction {
    VaultStrategyTransaction {
        idempotency_key: key.into(),
        evidence_hash: [evidence; 32],
        vault_commitment: [0x11; 32],
        strategy_commitment: [0x22; 32],
        operation_commitment: [operation; 32],
        asset: ASSET.into(),
        amount,
        transition,
    }
}

fn cash() -> AccountKey {
    AccountKey::new(
        format!("vault:{}", hex::encode([0x11; 32])),
        AccountBucket::VaultCash,
        ASSET,
    )
}

fn receivable() -> AccountKey {
    AccountKey::new(
        format!(
            "vault:{}:strategy:{}",
            hex::encode([0x11; 32]),
            hex::encode([0x22; 32])
        ),
        AccountBucket::VaultStrategyReceivable,
        ASSET,
    )
}

fn transit(operation: u8) -> AccountKey {
    AccountKey::new(
        format!(
            "vault:{}:operation:{}",
            hex::encode([0x11; 32]),
            hex::encode([operation; 32])
        ),
        AccountBucket::VaultStrategyInTransit,
        ASSET,
    )
}

fn funded(amount: u128) -> Ledger {
    let mut ledger = Ledger::default();
    ledger.seed_balance(cash(), amount).unwrap();
    ledger
}

#[test]
fn direct_deploy_replaces_cash_with_receivable_without_touching_pool_cash() {
    let mut ledger = funded(10_000_000);
    let pool = AccountKey::new("layrs", AccountBucket::PoolCash, ASSET);
    let applied = ledger
        .apply_vault_strategy_transition(transaction(
            "deploy:one",
            0x31,
            0x41,
            7_500_000,
            VaultStrategyTransition::CashToReceivable,
        ))
        .unwrap();

    assert_eq!(ledger.balance(&cash()), 2_500_000);
    assert_eq!(ledger.balance(&receivable()), 7_500_000);
    assert_eq!(ledger.balance(&pool), 0);
    assert_eq!(applied.postings.len(), 2);
    assert_eq!(applied.postings[0].side, PostingSide::Debit);
    assert_eq!(applied.postings[0].account.bucket, AccountBucket::VaultCash);
    assert_eq!(applied.postings[1].side, PostingSide::Credit);
    assert_eq!(
        applied.postings[1].account.bucket,
        AccountBucket::VaultStrategyReceivable
    );
}

#[test]
fn cross_chain_lifecycle_conserves_principal_at_every_boundary() {
    let mut ledger = funded(9_000_000);
    ledger
        .apply_vault_strategy_transition(transaction(
            "dispatch",
            0x32,
            0x42,
            6_000_000,
            VaultStrategyTransition::CashToTransit,
        ))
        .unwrap();
    assert_eq!(ledger.balance(&cash()), 3_000_000);
    assert_eq!(ledger.balance(&transit(0x42)), 6_000_000);
    assert_eq!(ledger.balance(&receivable()), 0);

    ledger
        .apply_vault_strategy_transition(transaction(
            "delivery",
            0x33,
            0x42,
            6_000_000,
            VaultStrategyTransition::TransitToReceivable,
        ))
        .unwrap();
    assert_eq!(ledger.balance(&transit(0x42)), 0);
    assert_eq!(ledger.balance(&receivable()), 6_000_000);

    ledger
        .apply_vault_strategy_transition(transaction(
            "recall",
            0x34,
            0x43,
            2_000_000,
            VaultStrategyTransition::ReceivableToTransit,
        ))
        .unwrap();
    ledger
        .apply_vault_strategy_transition(transaction(
            "returned",
            0x35,
            0x43,
            2_000_000,
            VaultStrategyTransition::TransitToCash,
        ))
        .unwrap();
    assert_eq!(ledger.balance(&cash()), 5_000_000);
    assert_eq!(ledger.balance(&receivable()), 4_000_000);
    assert_eq!(ledger.balance(&transit(0x43)), 0);
}

#[test]
fn finality_evidence_is_the_replay_boundary_even_when_operator_key_changes() {
    let mut ledger = funded(10);
    ledger
        .apply_vault_strategy_transition(transaction(
            "first-key",
            0x51,
            0x61,
            4,
            VaultStrategyTransition::CashToReceivable,
        ))
        .unwrap();
    let prior_root = ledger.state_root();
    let prior_sequence = ledger.sequence();
    let error = ledger
        .apply_vault_strategy_transition(transaction(
            "different-key",
            0x51,
            0x62,
            4,
            VaultStrategyTransition::CashToReceivable,
        ))
        .unwrap_err();
    assert_eq!(error, CoreError::DuplicateCommand);
    assert_eq!(ledger.state_root(), prior_root);
    assert_eq!(ledger.sequence(), prior_sequence);
    assert_eq!(ledger.balance(&cash()), 6);
    assert_eq!(ledger.balance(&receivable()), 4);
}

#[test]
fn evidence_replay_survives_snapshot_and_lost_response() {
    let mut ledger = funded(10);
    let posted = transaction(
        "request-before-lost-response",
        0x52,
        0x63,
        4,
        VaultStrategyTransition::CashToReceivable,
    );
    ledger
        .apply_vault_strategy_transition(posted.clone())
        .unwrap();

    // Simulate a committed encrypted snapshot followed by a lost HTTP
    // response and process restart. The transport key changes, but the
    // independent finality evidence remains the replay boundary.
    let snapshot = serde_json::to_vec(&ledger).unwrap();
    let mut restored: Ledger = serde_json::from_slice(&snapshot).unwrap();
    let root = restored.state_root();
    let replay = restored.apply_vault_strategy_transition(VaultStrategyTransaction {
        idempotency_key: "retry-after-lost-response".into(),
        ..posted
    });
    assert_eq!(replay.unwrap_err(), CoreError::DuplicateCommand);
    assert_eq!(restored.state_root(), root);
    assert_eq!(restored.sequence(), 1);
    assert_eq!(restored.balance(&cash()), 6);
    assert_eq!(restored.balance(&receivable()), 4);
}

#[test]
fn generic_external_flow_cannot_create_synthetic_vault_principal() {
    for bucket in [
        AccountBucket::VaultCash,
        AccountBucket::VaultStrategyInTransit,
        AccountBucket::VaultStrategyReceivable,
    ] {
        let mut ledger = Ledger::default();
        let account = AccountKey::new("opaque-vault", bucket, ASSET);
        let root = ledger.state_root();
        let result = ledger.apply_external_flow(ExternalFlowTransaction {
            idempotency_key: "unsafe-vault-credit".into(),
            evidence_hash: [0x53; 32],
            account: account.clone(),
            amount: 1,
            direction: ExternalFlowDirection::Inflow,
        });
        assert!(matches!(result, Err(CoreError::InvalidOrder(_))));
        assert_eq!(ledger.balance(&account), 0);
        assert_eq!(ledger.sequence(), 0);
        assert_eq!(ledger.state_root(), root);
    }
}

#[test]
fn rejected_zero_invalid_and_insufficient_transitions_are_atomic() {
    let mut ledger = funded(1);
    let original_root = ledger.state_root();
    for invalid in [
        transaction(
            "zero",
            0x71,
            0x72,
            0,
            VaultStrategyTransition::CashToReceivable,
        ),
        transaction(
            "insufficient",
            0x73,
            0x74,
            2,
            VaultStrategyTransition::CashToReceivable,
        ),
        VaultStrategyTransaction {
            evidence_hash: [0; 32],
            ..transaction(
                "no-evidence",
                0x75,
                0x76,
                1,
                VaultStrategyTransition::CashToReceivable,
            )
        },
    ] {
        assert!(ledger.apply_vault_strategy_transition(invalid).is_err());
        assert_eq!(ledger.state_root(), original_root);
        assert_eq!(ledger.sequence(), 0);
    }
}

#[test]
fn one_atomic_unit_moves_without_dust_or_synthetic_duplication() {
    let mut ledger = funded(1);
    ledger
        .apply_vault_strategy_transition(transaction(
            "one-unit",
            0x77,
            0x78,
            1,
            VaultStrategyTransition::CashToReceivable,
        ))
        .unwrap();
    assert_eq!(ledger.balance(&cash()), 0);
    assert_eq!(ledger.balance(&receivable()), 1);
}

proptest! {
    #[test]
    fn arbitrary_partial_deploy_and_recall_conserve_vault_principal(
        total in 1u128..1_000_000_000_000u128,
        deployed_bps in 0u16..=10_000u16,
        recalled_bps in 0u16..=10_000u16,
    ) {
        let deployed = total * u128::from(deployed_bps) / 10_000;
        let recalled = deployed * u128::from(recalled_bps) / 10_000;
        let mut ledger = funded(total);
        if deployed > 0 {
            ledger.apply_vault_strategy_transition(transaction(
                "property-deploy", 0x81, 0x82, deployed,
                VaultStrategyTransition::CashToReceivable,
            )).unwrap();
        }
        if recalled > 0 {
            ledger.apply_vault_strategy_transition(transaction(
                "property-recall", 0x83, 0x84, recalled,
                VaultStrategyTransition::ReceivableToTransit,
            )).unwrap();
            ledger.apply_vault_strategy_transition(transaction(
                "property-return", 0x85, 0x84, recalled,
                VaultStrategyTransition::TransitToCash,
            )).unwrap();
        }
        let recognized = ledger.balance(&cash())
            + ledger.balance(&receivable())
            + ledger.balance(&transit(0x84));
        prop_assert_eq!(recognized, total);
    }
}
