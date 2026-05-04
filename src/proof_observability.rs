use crate::{error::ClobResult, redis_store::RedisStore};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

const PROOF_ATTEMPT_PREFIX: &str = "proof_attempt:";
const PROOF_ATTEMPT_USER_PREFIX: &str = "proof_attempt:user:";
/// 7-day TTL — long enough for post-incident debugging, short enough not to bloat Redis.
const PROOF_ATTEMPT_TTL_SECS: u64 = 604_800;
/// Max proof IDs returned per user-list query.
const MAX_PROOF_LIST: usize = 100;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofAttempt {
    pub proof_id: String,
    pub proof_type: String,
    pub user_id: Option<String>,
    pub trade_id: Option<String>,
    pub market_id: Option<String>,
    /// Full circuit inputs passed to `bb execute` — the primary debugging field.
    pub circuit_inputs_json: Option<String>,
    pub status: String,
    pub prover_job_id: Option<String>,
    pub proof_hex: Option<String>,
    pub public_inputs: Option<Vec<String>>,
    pub error: Option<String>,
    pub duration_ms: Option<u64>,
    pub tx_hash: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

pub async fn create_attempt(
    store: &Arc<RedisStore>,
    proof_type: &str,
    user_id: Option<&str>,
    trade_id: Option<&str>,
    market_id: Option<&str>,
    circuit_inputs_json: Option<String>,
) -> ClobResult<String> {
    let proof_id = Uuid::new_v4().to_string();
    let now = Utc::now().timestamp_millis();

    let attempt = ProofAttempt {
        proof_id: proof_id.clone(),
        proof_type: proof_type.to_string(),
        user_id: user_id.map(str::to_string),
        trade_id: trade_id.map(str::to_string),
        market_id: market_id.map(str::to_string),
        circuit_inputs_json,
        status: "running".to_string(),
        prover_job_id: None,
        proof_hex: None,
        public_inputs: None,
        error: None,
        duration_ms: None,
        tx_hash: None,
        created_at: now,
        updated_at: now,
    };

    let key = format!("{}{}", PROOF_ATTEMPT_PREFIX, proof_id);
    store
        .set_with_expiry(&key, &serde_json::to_string(&attempt)?, PROOF_ATTEMPT_TTL_SECS)
        .await?;

    // Index by user so list-by-user queries are O(1).
    if let Some(uid) = user_id {
        let user_key = format!("{}{}", PROOF_ATTEMPT_USER_PREFIX, uid.to_lowercase());
        let _ = store.append_json_array_value(&user_key, &proof_id).await;
    }

    Ok(proof_id)
}

pub async fn update_attempt(
    store: &Arc<RedisStore>,
    proof_id: &str,
    status: &str,
    prover_job_id: Option<&str>,
    proof_hex: Option<String>,
    public_inputs: Option<Vec<String>>,
    error: Option<String>,
    duration_ms: Option<u64>,
    tx_hash: Option<String>,
) -> ClobResult<()> {
    let key = format!("{}{}", PROOF_ATTEMPT_PREFIX, proof_id);
    let Some(raw) = store.get_optional(&key).await? else {
        return Ok(()); // already expired or never created — ignore
    };
    let mut attempt: ProofAttempt = serde_json::from_str(&raw)
        .map_err(|e| crate::error::ClobError::Other(format!("corrupt proof_attempt: {e}")))?;

    attempt.status = status.to_string();
    attempt.updated_at = Utc::now().timestamp_millis();
    if let Some(v) = prover_job_id {
        attempt.prover_job_id = Some(v.to_string());
    }
    if proof_hex.is_some() {
        attempt.proof_hex = proof_hex;
    }
    if public_inputs.is_some() {
        attempt.public_inputs = public_inputs;
    }
    if error.is_some() {
        attempt.error = error;
    }
    if duration_ms.is_some() {
        attempt.duration_ms = duration_ms;
    }
    if tx_hash.is_some() {
        attempt.tx_hash = tx_hash;
    }

    store
        .set_with_expiry(&key, &serde_json::to_string(&attempt)?, PROOF_ATTEMPT_TTL_SECS)
        .await?;
    Ok(())
}

pub async fn get_attempt(store: &Arc<RedisStore>, proof_id: &str) -> ClobResult<Option<ProofAttempt>> {
    let key = format!("{}{}", PROOF_ATTEMPT_PREFIX, proof_id);
    let Some(raw) = store.get_optional(&key).await? else {
        return Ok(None);
    };
    let attempt: ProofAttempt = serde_json::from_str(&raw)
        .map_err(|e| crate::error::ClobError::Other(format!("corrupt proof_attempt: {e}")))?;
    Ok(Some(attempt))
}

pub async fn list_user_attempts(
    store: &Arc<RedisStore>,
    user_id: &str,
    filter_type: Option<&str>,
) -> ClobResult<Vec<ProofAttempt>> {
    let user_key = format!("{}{}", PROOF_ATTEMPT_USER_PREFIX, user_id.to_lowercase());
    let ids = store.get_json_array_values(&user_key, MAX_PROOF_LIST).await?;

    let mut out = Vec::new();
    // Iterate in reverse so newest attempts come first.
    for id in ids.iter().rev() {
        if let Ok(Some(attempt)) = get_attempt(store, id).await {
            if let Some(pt) = filter_type {
                if attempt.proof_type != pt {
                    continue;
                }
            }
            out.push(attempt);
        }
    }
    Ok(out)
}
