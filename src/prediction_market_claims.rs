use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const PM_CLAIM_QUEUE: &str = "pm:claim:queue";
pub const PM_CLAIM_JOB_PREFIX: &str = "pm:claim:job:";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PredictionMarketClaimJob {
    pub job_id: String,
    pub recipient: String,
    pub market_id: String,
    pub outcome: u8,
    pub amount: String,
    pub status: String,
    pub prover_job_id: Option<String>,
    pub claim_tx_hash: Option<String>,
    pub last_error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// EVM treasury contract address to route the claimWinnings call to.
    /// Falls back to the configured PM treasury env vars when empty.
    #[serde(default)]
    pub vault_address: String,
}

impl PredictionMarketClaimJob {
    pub fn redis_key(&self) -> String {
        format!("{}{}", PM_CLAIM_JOB_PREFIX, self.job_id)
    }
}
