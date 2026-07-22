use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use ethers::types::Address;

use crate::{
    error::{ClobError, ClobResult},
    models::{NoteLockRecord, NoteLockStatus, Order, TimeInForce, Trade},
    pm_claim_worker::claim_input_key,
    prediction_market_claims::{PredictionMarketClaimJob, PM_CLAIM_QUEUE},
    proof_generation::{low_high_hex_to_bytes32, parse_u128_hex, HonkProof},
    AppState,
};

const PM_PRIVATE_CLAIMS_BY_RECIPIENT_PREFIX: &str = "pm:claim:recipient:";
const PM_PRIVATE_CLAIM_DEDUP_PREFIX: &str = "pm:claim:dedup:";

/// UltraHonk proof payload as submitted by the frontend/relayer.
/// `proof_hex` is a `0x`-prefixed hex string of the raw proof bytes.
/// `public_inputs` is an ordered array of `0x`-prefixed `bytes32` hex strings.
#[derive(Debug, Deserialize)]
pub struct ProofPayload {
    pub proof_hex: String,
    pub public_inputs: Vec<String>,
}

impl From<ProofPayload> for HonkProof {
    fn from(p: ProofPayload) -> Self {
        Self {
            proof_hex: p.proof_hex,
            public_inputs: p.public_inputs,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct LockCollateralRequest {
    pub order_commitment_low: String,
    pub order_commitment_high: String,
    pub required_amount_low: String,
    pub lock_expiry_ts: u64,
    pub proof: ProofPayload,
    /// The user placing this order (EVM address or internal user ID).
    pub user_id: String,
    pub market_id: String,
    #[serde(default = "default_side")]
    pub side: String,
    /// Unix timestamp after which the on-chain commitment expires (-1 = no expiry).
    #[serde(default = "default_commitment_expiry")]
    pub commitment_expiry_ts: i64,
    /// Optional: EVM treasury contract address. Routes to the correct treasury.
    /// Falls back to the configured PM treasury env vars if absent or empty.
    #[serde(default)]
    pub vault_address: String,
}

fn default_side() -> String {
    "unknown".to_string()
}
fn default_commitment_expiry() -> i64 {
    -1
}

#[derive(Debug, Deserialize)]
pub struct UnlockCollateralRequest {
    pub note_nullifier_low: String,
    pub note_nullifier_high: String,
    pub order_commitment_low: String,
    pub order_commitment_high: String,
    /// The user who owns this lock (required to update the index).
    pub user_id: String,
    /// Optional: EVM treasury contract address. Routes to the correct treasury.
    #[serde(default)]
    pub vault_address: String,
}

#[derive(Debug, Deserialize)]
pub struct SettleFillRequest {
    pub market_id: u64,
    pub position_side: bool,
    pub spent_note_nullifier_low: String,
    pub spent_note_nullifier_high: String,
    /// order_commitment_low identifies which note-lock to mark as settled.
    pub order_commitment_low: String,
    /// The user who owns this lock (required to update the index).
    pub user_id: String,
    pub pot_contribution_low: String,
    pub position_payout_units_low: String,
    pub trade_fee_amount_low: String,
    pub proof: ProofPayload,
    /// Optional: EVM treasury contract address (from the order's compatibility field).
    /// Routes settlement to the correct on-chain treasury.
    /// Falls back to the configured PM treasury env vars if absent or empty.
    #[serde(default)]
    pub vault_address: String,
}

#[derive(Debug, Deserialize)]
pub struct ClaimWinningsRequest {
    /// EVM address of the recipient (hex, with 0x prefix).
    pub recipient: String,
    pub proof: ProofPayload,
    /// Optional: EVM treasury contract address. Routes claim to the correct treasury.
    /// Falls back to the configured PM treasury env vars if absent or empty.
    #[serde(default)]
    pub vault_address: String,
}

#[derive(Debug, Deserialize)]
pub struct SubmitClaimRequest {
    pub recipient: String,
    pub market_id: String,
    pub outcome: u8,
    pub amount: String,
    pub proof_input: Value,
    /// Optional: EVM treasury contract address to route the on-chain claim to.
    /// Falls back to the configured PM treasury env vars if absent or empty.
    #[serde(default)]
    pub vault_address: String,
}

#[derive(Debug, Serialize)]
pub struct RelayTxResponse {
    pub tx_hash: String,
}

#[derive(Debug, Serialize)]
pub struct SubmitClaimResponse {
    pub claim_job: PredictionMarketClaimJob,
}

#[derive(Debug, Deserialize)]
pub struct PrivateIndexQuery {
    pub market_id: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct PrivateIndexNoteLockSnapshot {
    pub order_id: String,
    pub market_id: String,
    pub side: String,
    pub status: String,
    pub note_nullifier_low: String,
    pub note_nullifier_high: String,
    pub required_amount_low: String,
    pub required_amount_high: String,
    pub order_commitment_low: String,
    pub order_commitment_high: String,
    pub lock_expiry_ts: u64,
    pub commitment_expiry_ts: i64,
    pub updated_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct PrivateIndexResponse {
    pub user_id: String,
    pub market_id: Option<String>,
    pub reconciled_at: chrono::DateTime<Utc>,
    pub open_orders: Vec<Order>,
    pub note_locks: Vec<PrivateIndexNoteLockSnapshot>,
    pub fills: Vec<Trade>,
    pub claims: Vec<PredictionMarketClaimJob>,
}

pub async fn lock_collateral(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LockCollateralRequest>,
) -> ClobResult<impl IntoResponse> {
    if req.user_id.trim().is_empty() {
        return Err(ClobError::InvalidOrder("user_id is required".to_string()));
    }
    if req.market_id.trim().is_empty() {
        return Err(ClobError::InvalidOrder("market_id is required".to_string()));
    }

    let relayer = get_relayer(&state)?;
    let proof: HonkProof = req.proof.into();
    let treasury_override = treasury_override_opt(&req.vault_address);
    let tx_hash = relayer
        .lock_collateral(
            low_high_hex_to_bytes32(&req.order_commitment_low, "0x0")?,
            parse_u128_hex(&req.required_amount_low, "required_amount")?.into(),
            req.lock_expiry_ts,
            &proof,
            treasury_override,
        )
        .await?;

    // Persist the note-lock so the private index can serve it.
    let now = Utc::now();
    let record = NoteLockRecord {
        order_commitment_low: req.order_commitment_low.clone(),
        order_commitment_high: req.order_commitment_high.clone(),
        note_nullifier_low: None,
        note_nullifier_high: None,
        user_id: req.user_id.trim().to_string(),
        market_id: req.market_id.trim().to_string(),
        side: req.side.clone(),
        required_amount_low: req.required_amount_low.clone(),
        lock_expiry_ts: req.lock_expiry_ts,
        commitment_expiry_ts: req.commitment_expiry_ts,
        status: NoteLockStatus::Locked,
        lock_tx_hash: tx_hash.clone(),
        settle_tx_hash: None,
        created_at: now,
        updated_at: now,
    };
    state.redis_store.save_note_lock(&record).await?;

    Ok(Json(RelayTxResponse { tx_hash }))
}

pub async fn unlock_collateral(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UnlockCollateralRequest>,
) -> ClobResult<impl IntoResponse> {
    let relayer = get_relayer(&state)?;
    let treasury_override = treasury_override_opt(&req.vault_address);
    let tx_hash = relayer
        .unlock_collateral(
            low_high_hex_to_bytes32(&req.note_nullifier_low, &req.note_nullifier_high)?,
            low_high_hex_to_bytes32(&req.order_commitment_low, &req.order_commitment_high)?,
            treasury_override,
        )
        .await?;

    // Update note-lock status to Unlocked (update in-place to preserve history).
    let key = format!(
        "pm:note_lock:{}:{}",
        req.user_id.trim(),
        &req.order_commitment_low
    );
    if let Some(json) = state.redis_store.get_optional(&key).await? {
        if let Ok(mut record) = serde_json::from_str::<NoteLockRecord>(&json) {
            record.status = NoteLockStatus::Unlocked;
            record.note_nullifier_low = Some(req.note_nullifier_low.clone());
            record.note_nullifier_high = Some(req.note_nullifier_high.clone());
            record.updated_at = Utc::now();
            state.redis_store.save_note_lock(&record).await?;
        }
    }

    Ok(Json(RelayTxResponse { tx_hash }))
}

pub async fn settle_fill(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SettleFillRequest>,
) -> ClobResult<impl IntoResponse> {
    let relayer = get_relayer(&state)?;
    let proof: HonkProof = req.proof.into();
    let treasury_override = treasury_override_opt(&req.vault_address);
    let tx_hash = relayer
        .settle_fill(
            req.market_id,
            req.position_side,
            low_high_hex_to_bytes32(
                &req.spent_note_nullifier_low,
                &req.spent_note_nullifier_high,
            )?,
            parse_u128_hex(&req.pot_contribution_low, "pot_contribution")?,
            parse_u128_hex(&req.position_payout_units_low, "position_payout_units")?,
            parse_u128_hex(&req.trade_fee_amount_low, "trade_fee_amount")?,
            &proof,
            treasury_override,
        )
        .await?;

    // Update note-lock status to Settled.
    let key = format!(
        "pm:note_lock:{}:{}",
        req.user_id.trim(),
        &req.order_commitment_low
    );
    if let Some(json) = state.redis_store.get_optional(&key).await? {
        if let Ok(mut record) = serde_json::from_str::<NoteLockRecord>(&json) {
            record.status = NoteLockStatus::Settled;
            record.note_nullifier_low = Some(req.spent_note_nullifier_low.clone());
            record.note_nullifier_high = Some(req.spent_note_nullifier_high.clone());
            record.settle_tx_hash = Some(tx_hash.clone());
            record.updated_at = Utc::now();
            state.redis_store.save_note_lock(&record).await?;
        }
    }

    Ok(Json(RelayTxResponse { tx_hash }))
}

pub async fn claim_winnings(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ClaimWinningsRequest>,
) -> ClobResult<impl IntoResponse> {
    let relayer = get_relayer(&state)?;
    let recipient: Address = req
        .recipient
        .parse()
        .map_err(|e| ClobError::InvalidOrder(format!("invalid recipient address: {e}")))?;
    let proof: HonkProof = req.proof.into();
    let treasury_override = treasury_override_opt(&req.vault_address);
    let tx_hash = relayer
        .claim_winnings(recipient, &proof, treasury_override)
        .await?;
    Ok(Json(RelayTxResponse { tx_hash }))
}

pub async fn submit_claim(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SubmitClaimRequest>,
) -> ClobResult<impl IntoResponse> {
    if req.outcome > 1 {
        return Err(ClobError::InvalidOrder(
            "claim outcome must be 0 or 1".to_string(),
        ));
    }
    if req.market_id.trim().is_empty() || req.amount.trim().is_empty() {
        return Err(ClobError::InvalidOrder(
            "market_id and amount are required".to_string(),
        ));
    }

    // Parse and normalise the EVM recipient address (checksum-normalise for dedup).
    let recipient: Address = req
        .recipient
        .parse()
        .map_err(|e| ClobError::InvalidOrder(format!("invalid recipient address: {e}")))?;
    let recipient_str = format!("{recipient:?}");
    validate_claim_input(
        &req.proof_input,
        &recipient_str,
        &req.market_id,
        req.outcome,
        &req.amount,
    )?;

    let dedup_key = claim_dedup_key(&req.recipient, &req.market_id, req.outcome, &req.amount);
    if let Some(existing_job_id) = state.redis_store.get_optional(&dedup_key).await? {
        let Some(existing_job_payload) = state
            .redis_store
            .get_optional(&format!("pm:claim:job:{}", existing_job_id))
            .await?
        else {
            return Err(ClobError::InvalidOrder(
                "duplicate PM claim detected while previous job metadata is missing".to_string(),
            ));
        };
        let existing_job: PredictionMarketClaimJob = serde_json::from_str(&existing_job_payload)?;
        if !is_retryable_claim_status(&existing_job.status) {
            return Err(ClobError::InvalidOrder(format!(
                "duplicate PM claim already exists as job {} with status {}",
                existing_job.job_id, existing_job.status
            )));
        }
    }

    let now = Utc::now();
    let job = PredictionMarketClaimJob {
        job_id: Uuid::new_v4().to_string(),
        recipient: req.recipient,
        market_id: req.market_id,
        outcome: req.outcome,
        amount: req.amount,
        status: "pending_proof_generation".to_string(),
        prover_job_id: None,
        claim_tx_hash: None,
        last_error: None,
        created_at: now,
        updated_at: now,
        vault_address: req.vault_address,
    };

    state
        .redis_store
        .set(
            &claim_input_key(&job.job_id),
            &serde_json::to_string(&req.proof_input)?,
        )
        .await?;
    state
        .redis_store
        .set(&job.redis_key(), &serde_json::to_string(&job)?)
        .await?;
    state.redis_store.set(&dedup_key, &job.job_id).await?;
    state
        .redis_store
        .append_json_array_value(
            &format!("{}{}", PM_PRIVATE_CLAIMS_BY_RECIPIENT_PREFIX, job.recipient),
            &job.job_id,
        )
        .await?;
    state
        .redis_store
        .push_queue(PM_CLAIM_QUEUE, &job.job_id)
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(SubmitClaimResponse { claim_job: job }),
    ))
}

pub async fn get_private_index(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<String>,
    Query(query): Query<PrivateIndexQuery>,
) -> ClobResult<impl IntoResponse> {
    let limit = query.limit.unwrap_or(100).clamp(1, 500);
    let market_filter = query
        .market_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    let open_orders = state
        .redis_store
        .get_user_orders(&user_id)
        .await?
        .into_iter()
        .filter(|order| order.time_in_force == TimeInForce::Gtc && order.is_active())
        .filter(|order| {
            market_filter
                .map(|market_id| order.market_id == market_id)
                .unwrap_or(true)
        })
        .take(limit)
        .collect::<Vec<_>>();

    // Fetch real note-lock records from Redis and convert to snapshots.
    let note_locks: Vec<PrivateIndexNoteLockSnapshot> = state
        .redis_store
        .get_note_locks_for_user(&user_id)
        .await?
        .into_iter()
        .filter(|r| market_filter.map(|m| r.market_id == m).unwrap_or(true))
        .take(limit)
        .map(|r| PrivateIndexNoteLockSnapshot {
            order_id: r.order_commitment_low.clone(),
            market_id: r.market_id.clone(),
            side: r.side.clone(),
            status: format!("{:?}", r.status).to_lowercase(),
            note_nullifier_low: r.note_nullifier_low.unwrap_or_default(),
            note_nullifier_high: r.note_nullifier_high.unwrap_or_default(),
            required_amount_low: r.required_amount_low.clone(),
            required_amount_high: String::new(),
            order_commitment_low: r.order_commitment_low.clone(),
            order_commitment_high: r.order_commitment_high.clone(),
            lock_expiry_ts: r.lock_expiry_ts,
            commitment_expiry_ts: r.commitment_expiry_ts,
            updated_at: r.updated_at,
        })
        .collect();

    let fills = state
        .redis_store
        .get_user_trades(&user_id, limit)
        .await?
        .into_iter()
        .filter(|trade| {
            market_filter
                .map(|market_id| trade.market_id == market_id)
                .unwrap_or(true)
        })
        .collect::<Vec<_>>();

    let claims = get_claim_jobs_for_recipient(&state, &user_id, limit, market_filter).await?;

    Ok(Json(PrivateIndexResponse {
        user_id,
        market_id: market_filter.map(str::to_string),
        reconciled_at: Utc::now(),
        open_orders,
        note_locks,
        fills,
        claims,
    }))
}

pub async fn get_claim_status(
    State(state): State<Arc<AppState>>,
    Path(job_id): Path<String>,
) -> ClobResult<impl IntoResponse> {
    let payload = state
        .redis_store
        .get_optional(&format!("pm:claim:job:{}", job_id))
        .await?
        .ok_or_else(|| ClobError::OrderNotFound(format!("PM claim job {} not found", job_id)))?;
    let job: PredictionMarketClaimJob = serde_json::from_str(&payload)?;
    Ok(Json(job))
}

fn get_relayer(
    state: &AppState,
) -> ClobResult<Arc<crate::prediction_market_relayer::PredictionMarketRelayer>> {
    state.prediction_market_relayer.clone().ok_or_else(|| {
        ClobError::Internal("prediction market relayer is not configured".to_string())
    })
}

/// Returns `Some(addr)` when the compatibility address field is non-empty, else
/// `None` so the relayer falls back to the configured treasury default.
fn treasury_override_opt(vault_address: &str) -> Option<&str> {
    let trimmed = vault_address.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

async fn get_claim_jobs_for_recipient(
    state: &Arc<AppState>,
    recipient: &str,
    limit: usize,
    market_filter: Option<&str>,
) -> ClobResult<Vec<PredictionMarketClaimJob>> {
    let job_ids = state
        .redis_store
        .get_json_array_values(
            &format!("{}{}", PM_PRIVATE_CLAIMS_BY_RECIPIENT_PREFIX, recipient),
            limit,
        )
        .await?;

    let mut jobs = Vec::new();
    for job_id in job_ids {
        let Some(payload) = state
            .redis_store
            .get_optional(&format!("pm:claim:job:{}", job_id))
            .await?
        else {
            continue;
        };

        let Ok(job) = serde_json::from_str::<PredictionMarketClaimJob>(&payload) else {
            continue;
        };

        if market_filter
            .map(|market_id| job.market_id == market_id)
            .unwrap_or(true)
        {
            jobs.push(job);
        }
    }

    Ok(jobs)
}

#[derive(Debug, Deserialize)]
pub struct DepositNoteRequest {
    pub wallet_address: String,
    pub tx_hash: String,
    pub amount_raw: String,
}

#[derive(Debug, Serialize)]
pub struct DepositNoteResponse {
    pub acknowledged: bool,
    pub record_id: String,
}

pub async fn deposit_note(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DepositNoteRequest>,
) -> ClobResult<impl IntoResponse> {
    if req.wallet_address.trim().is_empty() || req.tx_hash.trim().is_empty() {
        return Err(ClobError::InvalidOrder(
            "wallet_address and tx_hash are required".to_string(),
        ));
    }

    let record_id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let wallet_key = req.wallet_address.trim().to_lowercase();

    let record = serde_json::json!({
        "record_id": record_id,
        "wallet_address": req.wallet_address.trim(),
        "tx_hash": req.tx_hash.trim(),
        "amount_raw": req.amount_raw.trim(),
        "registered_at": now,
        "status": "pending_operator_processing",
    });

    let entry_key = format!("pm:deposit_note:{}:{}", wallet_key, record_id);
    state
        .redis_store
        .set(&entry_key, &record.to_string())
        .await?;
    state
        .redis_store
        .append_json_array_value(&format!("pm:deposit_records:{}", wallet_key), &record_id)
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(DepositNoteResponse {
            acknowledged: true,
            record_id,
        }),
    ))
}

fn claim_dedup_key(recipient: &str, market_id: &str, outcome: u8, amount: &str) -> String {
    format!(
        "{}{}:{}:{}:{}",
        PM_PRIVATE_CLAIM_DEDUP_PREFIX,
        recipient.trim().to_lowercase(),
        market_id.trim(),
        outcome,
        amount.trim()
    )
}

fn is_retryable_claim_status(status: &str) -> bool {
    matches!(status, "proof_submission_failed" | "proof_failed")
}

fn validate_claim_input(
    proof_input: &Value,
    recipient: &str,
    market_id: &str,
    outcome: u8,
    amount: &str,
) -> ClobResult<()> {
    let destination = proof_input
        .get("destinationAddressField")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ClobError::InvalidOrder(
                "claim proof_input.destinationAddressField is required".to_string(),
            )
        })?;
    let proof_market_id = proof_input
        .get("market_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ClobError::InvalidOrder("claim proof_input.market_id is required".to_string())
        })?;
    let proof_amount = proof_input
        .get("amount")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ClobError::InvalidOrder("claim proof_input.amount is required".to_string())
        })?;

    let proof_outcome = proof_input
        .get("outcome")
        .and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_str().and_then(|s| s.parse::<u64>().ok()))
        })
        .ok_or_else(|| {
            ClobError::InvalidOrder("claim proof_input.outcome is required".to_string())
        })?;

    // EVM address comparison: normalise both to lowercase for case-insensitive match.
    if destination.to_lowercase() != recipient.to_lowercase() {
        return Err(ClobError::InvalidOrder(
            "claim recipient does not match proof_input.destinationAddressField".to_string(),
        ));
    }
    if proof_market_id != market_id {
        return Err(ClobError::InvalidOrder(
            "claim market_id does not match proof_input.market_id".to_string(),
        ));
    }
    if proof_amount != amount {
        return Err(ClobError::InvalidOrder(
            "claim amount does not match proof_input.amount".to_string(),
        ));
    }
    if proof_outcome != u64::from(outcome) {
        return Err(ClobError::InvalidOrder(
            "claim outcome does not match proof_input.outcome".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claim_dedup_key_is_stable() {
        let first = claim_dedup_key("0xABC", "42", 1, "10");
        let second = claim_dedup_key("0xabc", "42", 1, "10");
        assert_eq!(first, second);
    }

    #[test]
    fn only_failed_claim_statuses_are_retryable() {
        assert!(is_retryable_claim_status("proof_submission_failed"));
        assert!(is_retryable_claim_status("proof_failed"));
        assert!(!is_retryable_claim_status("pending_proof_generation"));
        assert!(!is_retryable_claim_status("claimed"));
    }
}
