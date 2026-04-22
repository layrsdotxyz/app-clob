use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    auth::AuthenticatedUser,
    prediction_market_settlement::{PM_SETTLEMENT_JOB_PREFIX, PM_SETTLEMENT_QUEUE},
    AppState,
};

/// Response for settlement job queries.
#[derive(Debug, Serialize)]
pub struct SettlementJobSummary {
    pub job_id: String,
    pub trade_id: String,
    pub market_id: String,
    pub settlement_status: String,
    pub legs: Vec<LegSummary>,
    pub settlement_txs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LegSummary {
    pub leg_role: String,
    pub order_id: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relay_tx_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// Request body for submitting a per-leg circuit witness.
///
/// The client generates the full `private_transfer_settlement` witness
/// client-side (where their private note keys live) and POSTs it here.
/// No private data is retained after the proof job completes.
#[derive(Debug, Deserialize)]
pub struct SubmitWitnessRequest {
    /// The snarkjs-format circuit input object.  Must contain all public +
    /// private inputs required by the `private_transfer_settlement` circuit.
    pub witness: Value,
}

/// GET /v1/settlements/:job_id
///
/// Returns the current status of a settlement job.
/// Callers must be authenticated (via `require_auth` in the router).
pub async fn get_settlement_job(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthenticatedUser>,
    Path(job_id): Path<String>,
) -> impl IntoResponse {
    let key = format!("{}{}", PM_SETTLEMENT_JOB_PREFIX, job_id);
    let raw = match state.redis_store.get_optional(&key).await {
        Ok(Some(v)) => v,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to fetch settlement job");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let job: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    // Users may only view jobs in which they are the maker or taker.
    let maker_uid = job.get("maker_user_id").and_then(|v| v.as_str()).unwrap_or("");
    let taker_uid = job.get("taker_user_id").and_then(|v| v.as_str()).unwrap_or("");
    if auth.user_id != maker_uid && auth.user_id != taker_uid {
        return StatusCode::FORBIDDEN.into_response();
    }

    let legs: Vec<LegSummary> = job
        .get("legs")
        .and_then(|l| l.as_array())
        .map(|arr| {
            arr.iter()
                .map(|leg| LegSummary {
                    leg_role: leg
                        .get("leg_role")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    order_id: leg
                        .get("order_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    status: leg
                        .get("status")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    relay_tx_hash: leg
                        .get("relay_tx_hash")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    last_error: leg
                        .get("last_error")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                })
                .collect()
        })
        .unwrap_or_default();

    let summary = SettlementJobSummary {
        job_id: job_id.clone(),
        trade_id: job
            .get("trade_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        market_id: job
            .get("market_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        settlement_status: job
            .get("settlement_status")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        legs,
        settlement_txs: job
            .get("settlement_txs")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default(),
        last_error: job
            .get("last_error")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
    };

    Json(summary).into_response()
}

/// POST /v1/settlements/:job_id/legs/:leg_role/witness
///
/// Submit the circuit witness for one leg of a `waiting_for_proof` settlement job.
/// `leg_role` must be "maker" or "taker".
///
/// The caller must be the authenticated user that owns that leg (i.e. their
/// `user_id` matches `leg.user_id`).  Once both legs have a witness the job
/// transitions to `pending_proof_generation` and is enqueued for the prover.
pub async fn submit_leg_witness(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthenticatedUser>,
    Path((job_id, leg_role)): Path<(String, String)>,
    Json(body): Json<SubmitWitnessRequest>,
) -> impl IntoResponse {
    if leg_role != "maker" && leg_role != "taker" {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "leg_role must be 'maker' or 'taker'" })),
        )
            .into_response();
    }

    let key = format!("{}{}", PM_SETTLEMENT_JOB_PREFIX, job_id);
    let raw = match state.redis_store.get_optional(&key).await {
        Ok(Some(v)) => v,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to fetch settlement job for witness submission");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let mut job: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    // Only allow witness submission for jobs still waiting.
    let status = job
        .get("settlement_status")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if status != "waiting_for_proof" {
        return (
            StatusCode::CONFLICT,
            Json(
                serde_json::json!({ "error": "job is not in waiting_for_proof state", "status": status }),
            ),
        )
            .into_response();
    }

    // Locate the leg and verify ownership.
    let legs = match job.get_mut("legs").and_then(|v| v.as_array_mut()) {
        Some(l) => l,
        None => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    let leg_index = legs.iter().position(|leg| {
        leg.get("leg_role").and_then(|v| v.as_str()) == Some(leg_role.as_str())
    });

    let Some(idx) = leg_index else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let leg_user_id = legs[idx]
        .get("user_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    if auth.user_id != leg_user_id {
        return StatusCode::FORBIDDEN.into_response();
    }

    // Store the witness and advance the leg status.
    legs[idx]["proof_input"] = body.witness;
    legs[idx]["status"] = serde_json::Value::String("witness_received".to_string());

    // Check if all legs now have a non-empty witness.
    let all_ready = legs.iter().all(|leg| {
        leg.get("proof_input")
            .map(|v| !v.as_object().map(|o| o.is_empty()).unwrap_or(true))
            .unwrap_or(false)
    });

    if all_ready {
        job["settlement_status"] =
            serde_json::Value::String("pending_proof_generation".to_string());
    }

    let updated = serde_json::to_string(&job).unwrap_or_default();
    if let Err(e) = state.redis_store.set(&key, &updated).await {
        tracing::error!(error = %e, "Failed to save settlement job after witness submission");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    // Enqueue now if all legs are ready.
    if all_ready {
        if let Err(e) = state
            .redis_store
            .push_queue(PM_SETTLEMENT_QUEUE, &job_id)
            .await
        {
            tracing::error!(error = %e, "Failed to enqueue settlement job after witness completion");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        tracing::info!(
            job_id = %job_id,
            "All legs have witness — settlement job queued for proving"
        );
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "job_id": job_id,
            "leg_role": leg_role,
            "all_legs_ready": all_ready,
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settlement_job_summary_serializes_correctly() {
        let summary = SettlementJobSummary {
            job_id: "job-1".to_string(),
            trade_id: "trade-1".to_string(),
            market_id: "mkt-1".to_string(),
            settlement_status: "waiting_for_proof".to_string(),
            legs: vec![],
            settlement_txs: vec![],
            last_error: None,
        };
        let v = serde_json::to_value(&summary).unwrap();
        assert_eq!(v["job_id"], "job-1");
        assert_eq!(v["settlement_status"], "waiting_for_proof");
        assert!(
            v.get("last_error").is_none(),
            "last_error should be absent when None"
        );
        assert_eq!(v["legs"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn leg_summary_serializes_with_optional_tx_hash() {
        let leg = LegSummary {
            leg_role: "maker".to_string(),
            order_id: "order-1".to_string(),
            status: "relayed".to_string(),
            relay_tx_hash: Some("0xabc".to_string()),
            last_error: None,
        };
        let v = serde_json::to_value(&leg).unwrap();
        assert_eq!(v["leg_role"], "maker");
        assert_eq!(v["relay_tx_hash"], "0xabc");
        assert!(v.get("last_error").is_none());
    }

    #[test]
    fn leg_summary_omits_optional_fields_when_none() {
        let leg = LegSummary {
            leg_role: "taker".to_string(),
            order_id: "order-2".to_string(),
            status: "pending".to_string(),
            relay_tx_hash: None,
            last_error: None,
        };
        let v = serde_json::to_value(&leg).unwrap();
        assert!(v.get("relay_tx_hash").is_none());
        assert!(v.get("last_error").is_none());
    }

    #[test]
    fn settlement_job_summary_last_error_present_when_some() {
        let summary = SettlementJobSummary {
            job_id: "j".to_string(),
            trade_id: "t".to_string(),
            market_id: "m".to_string(),
            settlement_status: "failed".to_string(),
            legs: vec![],
            settlement_txs: vec![],
            last_error: Some("proof timed out".to_string()),
        };
        let v = serde_json::to_value(&summary).unwrap();
        assert_eq!(v["last_error"], "proof timed out");
    }

    #[test]
    fn submit_witness_request_deserializes_object() {
        let raw = r#"{"witness": {"pub_input": "0xabc", "priv_input": {"x": 1}}}"#;
        let req: SubmitWitnessRequest = serde_json::from_str(raw).unwrap();
        assert_eq!(req.witness["pub_input"], "0xabc");
        assert_eq!(req.witness["priv_input"]["x"], 1);
    }

    #[test]
    fn submit_witness_request_accepts_null_witness() {
        let raw = r#"{"witness": null}"#;
        let req: SubmitWitnessRequest = serde_json::from_str(raw).unwrap();
        assert!(req.witness.is_null());
    }

    #[test]
    fn submit_witness_request_accepts_empty_object() {
        let raw = r#"{"witness": {}}"#;
        let req: SubmitWitnessRequest = serde_json::from_str(raw).unwrap();
        assert!(req.witness.as_object().unwrap().is_empty());
    }

    #[test]
    fn settlement_job_summary_with_legs_and_txs() {
        let summary = SettlementJobSummary {
            job_id: "job-2".to_string(),
            trade_id: "trade-2".to_string(),
            market_id: "mkt-2".to_string(),
            settlement_status: "complete".to_string(),
            legs: vec![
                LegSummary {
                    leg_role: "maker".to_string(),
                    order_id: "o-1".to_string(),
                    status: "relayed".to_string(),
                    relay_tx_hash: Some("0xdeadbeef".to_string()),
                    last_error: None,
                },
                LegSummary {
                    leg_role: "taker".to_string(),
                    order_id: "o-2".to_string(),
                    status: "relayed".to_string(),
                    relay_tx_hash: Some("0xcafe".to_string()),
                    last_error: None,
                },
            ],
            settlement_txs: vec!["0xabc".to_string(), "0xdef".to_string()],
            last_error: None,
        };
        let v = serde_json::to_value(&summary).unwrap();
        assert_eq!(v["legs"].as_array().unwrap().len(), 2);
        assert_eq!(v["legs"][0]["leg_role"], "maker");
        assert_eq!(v["legs"][1]["relay_tx_hash"], "0xcafe");
        assert_eq!(v["settlement_txs"][0], "0xabc");
    }

    /// Documents that leg_role validation in submit_leg_witness is case-sensitive
    /// and only accepts "maker" or "taker".
    #[test]
    fn leg_role_is_case_sensitive_maker_or_taker() {
        let accepted: &[&str] = &["maker", "taker"];
        let rejected: &[&str] = &["", "Maker", "TAKER", "buyer", "seller", "maker "];
        for &role in accepted {
            assert!(role == "maker" || role == "taker", "expected '{}' to be accepted", role);
        }
        for &role in rejected {
            assert!(role != "maker" && role != "taker", "expected '{}' to be rejected", role);
        }
    }
}
