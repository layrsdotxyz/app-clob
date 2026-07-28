use layrs_settlement_proof_core::{
    encode_public_journal, prove_resolution, SettlementProofInput,
};
use risc0_zkvm::guest::env;

fn main() {
    let input: SettlementProofInput = env::read();
    let output = prove_resolution(input).expect("invalid Layrs settlement proof input");
    env::commit_slice(&encode_public_journal(&output));
}
