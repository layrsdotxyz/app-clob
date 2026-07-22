mod evm_proof_calldata;
mod order_match_prover;
mod prover_pipeline;
pub mod prover_worker;

pub use evm_proof_calldata::{
    low_high_hex_to_bytes32, parse_honk_proof_from_output, parse_u128_hex, HonkProof,
};
pub use order_match_prover::{OrderMatchProver, ORDER_MATCH_UNSUPPORTED_MESSAGE};
pub use prover_pipeline::{ProverJob, ProverJobStatus, ProverJobType, ProverPipeline};
pub use prover_worker::ProverWorker;

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
