use chrono::Utc;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

const DEFAULT_RESOLUTION_SLA_SECS: u64 = 120;
const DEFAULT_DISPUTE_AFTER_SECS: u64 = 300;
const DEFAULT_INVALIDATE_AFTER_SECS: u64 = 1_800;
const DEFAULT_MAX_SOURCE_DEVIATION_BPS: u64 = 150;
const DEFAULT_MAX_HOURLY_MOVE_BPS: u64 = 2_500;

const ORACLE_AUDIT_PREFIX: &str = "pm:oracle:audit:";
const ORACLE_AUDIT_HISTORY_PREFIX: &str = "pm:oracle:audit_history:";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OracleResolutionStatus {
    PendingResolution,
    ReadyToResolve,
    Disputed,
    Invalidated,
    ResolvePublished,
    Finalized,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleResolutionAuditRecord {
    pub market_id: String,
    pub expiry_ts: u64,
    pub status: OracleResolutionStatus,
    pub primary_source: String,
    pub fallback_source: Option<String>,
    pub primary_price: Option<String>,
    pub fallback_price: Option<String>,
    pub final_price: Option<String>,
    pub strike_price: Option<String>,
    pub source_deviation_bps: Option<u64>,
    pub dispute_deadline_ts: Option<u64>,
    pub invalidate_after_ts: u64,
    pub published_tx_hash: Option<String>,
    pub invalidation_tx_hash: Option<String>,
    pub reason: Option<String>,
    pub operator_action: Option<String>,
    pub attempts: u32,
    pub created_at: u64,
    pub updated_at: u64,
}

impl OracleResolutionAuditRecord {
    pub fn redis_key(&self) -> String {
        format!("{}{}", ORACLE_AUDIT_PREFIX, self.market_id)
    }

    pub fn history_key(&self) -> String {
        format!("{}{}", ORACLE_AUDIT_HISTORY_PREFIX, self.market_id)
    }
}

#[derive(Debug, Clone)]
pub struct OraclePolicy {
    pub resolution_sla_secs: u64,
    pub dispute_after_secs: u64,
    pub invalidate_after_secs: u64,
    pub max_source_deviation_bps: u64,
    pub max_hourly_move_bps: u64,
}

impl OraclePolicy {
    pub fn from_env() -> Self {
        Self {
            resolution_sla_secs: read_u64_env(
                "PM_ORACLE_RESOLUTION_SLA_SECS",
                DEFAULT_RESOLUTION_SLA_SECS,
            ),
            dispute_after_secs: read_u64_env(
                "PM_ORACLE_DISPUTE_AFTER_SECS",
                DEFAULT_DISPUTE_AFTER_SECS,
            ),
            invalidate_after_secs: read_u64_env(
                "PM_ORACLE_INVALIDATE_AFTER_SECS",
                DEFAULT_INVALIDATE_AFTER_SECS,
            ),
            max_source_deviation_bps: read_u64_env(
                "PM_ORACLE_MAX_SOURCE_DEVIATION_BPS",
                DEFAULT_MAX_SOURCE_DEVIATION_BPS,
            ),
            max_hourly_move_bps: read_u64_env(
                "PM_ORACLE_MAX_HOURLY_MOVE_BPS",
                DEFAULT_MAX_HOURLY_MOVE_BPS,
            ),
        }
    }
}

impl Default for OraclePolicy {
    fn default() -> Self {
        Self::from_env()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum OracleResolutionDecision {
    Resolve {
        price: Decimal,
        source: String,
        source_deviation_bps: Option<u64>,
        reason: Option<String>,
    },
    Pending {
        reason: String,
    },
    Disputed {
        reason: String,
    },
    Invalidate {
        reason: String,
    },
}

pub fn evaluate_resolution_candidates(
    age_secs: u64,
    strike_price: Option<Decimal>,
    primary_source: &str,
    primary_price: Option<Decimal>,
    fallback_source: Option<&str>,
    fallback_price: Option<Decimal>,
    policy: &OraclePolicy,
) -> OracleResolutionDecision {
    let primary = filter_sane_price(primary_price, strike_price, policy);
    let fallback = filter_sane_price(fallback_price, strike_price, policy);

    if let (Some(primary), Some(fallback)) = (primary, fallback) {
        let deviation = compute_deviation_bps(primary, fallback);
        if deviation > policy.max_source_deviation_bps {
            return if age_secs >= policy.invalidate_after_secs {
                OracleResolutionDecision::Invalidate {
                    reason: format!(
                        "{} and {} deviated by {} bps beyond {} bps threshold",
                        primary_source,
                        fallback_source.unwrap_or("fallback"),
                        deviation,
                        policy.max_source_deviation_bps
                    ),
                }
            } else {
                OracleResolutionDecision::Disputed {
                    reason: format!(
                        "{} and {} deviated by {} bps beyond {} bps threshold",
                        primary_source,
                        fallback_source.unwrap_or("fallback"),
                        deviation,
                        policy.max_source_deviation_bps
                    ),
                }
            };
        }

        return OracleResolutionDecision::Resolve {
            price: primary,
            source: primary_source.to_string(),
            source_deviation_bps: Some(deviation),
            reason: Some(format!(
                "{} confirmed by {} within {} bps",
                primary_source,
                fallback_source.unwrap_or("fallback"),
                deviation
            )),
        };
    }

    if let Some(primary) = primary {
        return OracleResolutionDecision::Resolve {
            price: primary,
            source: primary_source.to_string(),
            source_deviation_bps: None,
            reason: Some("primary source passed sanity validation".to_string()),
        };
    }

    if let Some(fallback) = fallback {
        return OracleResolutionDecision::Resolve {
            price: fallback,
            source: fallback_source.unwrap_or("fallback").to_string(),
            source_deviation_bps: None,
            reason: Some("fallback source used after primary failure".to_string()),
        };
    }

    if age_secs < policy.resolution_sla_secs {
        OracleResolutionDecision::Pending {
            reason: "awaiting trustworthy oracle confirmation within resolution SLA".to_string(),
        }
    } else if age_secs >= policy.invalidate_after_secs {
        OracleResolutionDecision::Invalidate {
            reason: "no trustworthy oracle source before invalidation timeout".to_string(),
        }
    } else if age_secs >= policy.dispute_after_secs {
        OracleResolutionDecision::Disputed {
            reason: "no trustworthy oracle source before dispute threshold".to_string(),
        }
    } else {
        OracleResolutionDecision::Pending {
            reason: "resolution delayed while waiting for fallback oracle confirmation".to_string(),
        }
    }
}

pub fn create_audit_record(
    market_id: impl Into<String>,
    expiry_ts: u64,
    strike_price: Option<Decimal>,
    primary_source: &str,
    primary_price: Option<Decimal>,
    fallback_source: Option<&str>,
    fallback_price: Option<Decimal>,
    attempts: u32,
    policy: &OraclePolicy,
    decision: &OracleResolutionDecision,
) -> OracleResolutionAuditRecord {
    let now = Utc::now().timestamp().max(0) as u64;
    let (status, final_price, deviation_bps, reason, operator_action) = match decision {
        OracleResolutionDecision::Resolve {
            price,
            source_deviation_bps,
            reason,
            ..
        } => (
            OracleResolutionStatus::ReadyToResolve,
            Some(price.to_string()),
            *source_deviation_bps,
            reason.clone(),
            None,
        ),
        OracleResolutionDecision::Pending { reason } => (
            OracleResolutionStatus::PendingResolution,
            None,
            None,
            Some(reason.clone()),
            Some("wait for additional oracle confirmations before publishing".to_string()),
        ),
        OracleResolutionDecision::Disputed { reason } => (
            OracleResolutionStatus::Disputed,
            None,
            None,
            Some(reason.clone()),
            Some("operator review required during dispute window".to_string()),
        ),
        OracleResolutionDecision::Invalidate { reason } => (
            OracleResolutionStatus::Invalidated,
            None,
            None,
            Some(reason.clone()),
            Some("operator should invalidate market or resolve manually".to_string()),
        ),
    };

    OracleResolutionAuditRecord {
        market_id: market_id.into(),
        expiry_ts,
        status,
        primary_source: primary_source.to_string(),
        fallback_source: fallback_source.map(str::to_string),
        primary_price: primary_price.map(|value| value.to_string()),
        fallback_price: fallback_price.map(|value| value.to_string()),
        final_price,
        strike_price: strike_price.map(|value| value.to_string()),
        source_deviation_bps: deviation_bps,
        dispute_deadline_ts: Some(expiry_ts + policy.dispute_after_secs),
        invalidate_after_ts: expiry_ts + policy.invalidate_after_secs,
        published_tx_hash: None,
        invalidation_tx_hash: None,
        reason,
        operator_action,
        attempts,
        created_at: now,
        updated_at: now,
    }
}

fn filter_sane_price(
    price: Option<Decimal>,
    strike_price: Option<Decimal>,
    policy: &OraclePolicy,
) -> Option<Decimal> {
    let price = price?;
    if price <= Decimal::ZERO {
        return None;
    }

    if let Some(strike) = strike_price {
        if strike > Decimal::ZERO {
            let move_bps = compute_deviation_bps(price, strike);
            if move_bps > policy.max_hourly_move_bps {
                return None;
            }
        }
    }

    Some(price)
}

fn compute_deviation_bps(lhs: Decimal, rhs: Decimal) -> u64 {
    if lhs <= Decimal::ZERO || rhs <= Decimal::ZERO {
        return u64::MAX;
    }
    let baseline = if lhs < rhs { lhs } else { rhs };
    let delta = (lhs - rhs).abs();
    ((delta / baseline) * Decimal::from(10_000u64))
        .round()
        .to_u64()
        .unwrap_or(u64::MAX)
}

fn read_u64_env(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(default)
}

trait DecimalToU64 {
    fn to_u64(&self) -> Option<u64>;
}

impl DecimalToU64 for Decimal {
    fn to_u64(&self) -> Option<u64> {
        rust_decimal::prelude::ToPrimitive::to_u64(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal_macros::dec;

    #[test]
    fn resolves_with_primary_when_sources_agree() {
        let policy = OraclePolicy::default();
        let decision = evaluate_resolution_candidates(
            90,
            Some(dec!(100000)),
            "coinbase",
            Some(dec!(101000)),
            Some("kraken"),
            Some(dec!(101050)),
            &policy,
        );

        match decision {
            OracleResolutionDecision::Resolve {
                source,
                source_deviation_bps,
                ..
            } => {
                assert_eq!(source, "coinbase");
                assert!(source_deviation_bps.unwrap() < policy.max_source_deviation_bps);
            }
            _ => panic!("expected resolve decision"),
        }
    }

    #[test]
    fn disputes_when_sources_diverge_before_timeout() {
        let policy = OraclePolicy::default();
        let decision = evaluate_resolution_candidates(
            600,
            Some(dec!(100000)),
            "coinbase",
            Some(dec!(101000)),
            Some("kraken"),
            Some(dec!(110000)),
            &policy,
        );

        match decision {
            OracleResolutionDecision::Disputed { reason } => {
                assert!(reason.contains("deviated"));
            }
            _ => panic!("expected disputed decision"),
        }
    }

    #[test]
    fn invalidates_when_no_trustworthy_source_past_timeout() {
        let policy = OraclePolicy::default();
        let decision = evaluate_resolution_candidates(
            policy.invalidate_after_secs + 1,
            Some(dec!(100000)),
            "coinbase",
            None,
            Some("kraken"),
            None,
            &policy,
        );

        match decision {
            OracleResolutionDecision::Invalidate { reason } => {
                assert!(reason.contains("no trustworthy oracle source"));
            }
            _ => panic!("expected invalidation decision"),
        }
    }

    #[test]
    fn rejects_extreme_hourly_move_as_untrustworthy() {
        let policy = OraclePolicy::default();
        let decision = evaluate_resolution_candidates(
            60,
            Some(dec!(100000)),
            "coinbase",
            Some(dec!(150000)),
            None,
            None,
            &policy,
        );

        match decision {
            OracleResolutionDecision::Pending { .. } => {}
            _ => panic!("expected pending decision after sanity rejection"),
        }
    }
}
