mod order_match_prover;
mod evm_proof_calldata;
mod prover_pipeline;
pub mod groth16_verifier;

pub use order_match_prover::OrderMatchProver;
pub use evm_proof_calldata::{
    EvmGroth16Proof,
    parse_snarkjs_proof,
    parse_evm_proof_from_output,
    low_high_hex_to_bytes32,
    parse_u128_hex,
};
pub use prover_pipeline::{ProverJob, ProverJobStatus, ProverJobType, ProverPipeline};
pub use groth16_verifier::verify_snarkjs_proof;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderMatchProofData {
    pub proof_id: String,
    pub epoch_id: u64,
    pub market_id: String,
    pub order_batch_hash: String,
    pub matching_root: String,
    pub public_inputs_hash: String,
    pub total_volume: u64,
    pub unique_users: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitInput {
    pub order_batch_hash: String,
    pub matching_root: String,
    pub epoch_id: String,
    pub orders: Vec<Vec<String>>,
    pub fills: Vec<Vec<String>>,
    pub num_orders: String,
    pub num_fills: String,
}
