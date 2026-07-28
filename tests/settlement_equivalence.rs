use clob_service::private_core::{derive_resolution_outcome, ResolutionOutcome};
use layrs_settlement_proof_core::{
    prove_resolution, ResolutionOutcome as ProofOutcome, SettlementProofInput,
};
use proptest::prelude::*;

fn mapped(outcome: ProofOutcome) -> ResolutionOutcome {
    match outcome {
        ProofOutcome::Up => ResolutionOutcome::Up,
        ProofOutcome::Down => ResolutionOutcome::Down,
        ProofOutcome::Push => ResolutionOutcome::Push,
    }
}

#[test]
fn production_engine_matches_real_market_golden_vector() {
    let input: SettlementProofInput = serde_json::from_str(include_str!(
        "../proofs/settlement/fixtures/layrs-v3-zen-15m-1785196800.json"
    ))
    .expect("golden proof fixture must decode");
    let output = prove_resolution(input).expect("golden proof fixture must validate");
    let proof_outcome = mapped(output.outcome);
    assert_eq!(
        derive_resolution_outcome(output.opening_median_e8, output.closing_median_e8),
        proof_outcome
    );
    assert_eq!(output.opening_median_e8, 391_009_849);
    assert_eq!(output.closing_median_e8, 387_166_933);
    assert_eq!(proof_outcome, ResolutionOutcome::Down);
}

proptest! {
    #[test]
    fn production_and_proof_outcome_are_equivalent(
        opening in 1_i64..=i64::MAX,
        closing in 1_i64..=i64::MAX,
    ) {
        let proof = layrs_settlement_proof_core::derive_resolution_outcome(opening, closing);
        prop_assert_eq!(derive_resolution_outcome(opening, closing), mapped(proof));
    }
}
