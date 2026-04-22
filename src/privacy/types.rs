use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoteStatus {
    Unspent,
    Locked,
    Spent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionStatus {
    Pending,
    Attested,
    Finalized,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateNote {
    pub note_id: String,
    pub commitment: String,
    pub amount_commitment: String,
    pub asset: String,
    pub owner_key_hash: String,
    pub epoch_id: u64,
    pub status: NoteStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NullifierRecord {
    pub nullifier: String,
    pub note_commitment: String,
    pub tx_ref: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateStateTransition {
    pub transition_id: String,
    pub epoch_id: u64,
    pub old_root: String,
    pub new_root: String,
    pub nullifiers: Vec<String>,
    pub new_commitments: Vec<String>,
    pub proof_job_id: Option<String>,
    pub status: TransitionStatus,
    /// EVM transaction hash set after the withdrawal is submitted on-chain.
    #[serde(default)]
    pub evm_tx_hash: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
