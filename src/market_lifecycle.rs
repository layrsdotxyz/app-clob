use crate::{
    balance_service::BalanceService,
    database::Database,
    error::{ClobError, ClobResult},
    market_resolution_policy::{
        create_audit_record, evaluate_resolution_candidates, OraclePolicy,
        OracleResolutionDecision, OracleResolutionStatus,
    },
    oracle::PythOracle,
    redis_store::RedisStore,
};
use rust_decimal::Decimal;
use serde::Deserialize;
use std::sync::Arc;
use tokio::time::{interval, Duration};
use tracing::{error, info, warn};

// ─── Market Series Config ────────────────────────────────────────────────────

/// Configuration for a single market series (e.g. BTC-USDC hourly markets).
#[derive(Clone, Debug, Deserialize)]
pub struct MarketSeriesConfig {
    /// Oracle asset ticker: "BTC", "ETH", "SOL", "ZEN"
    pub oracle_asset: String,
    /// Collateral currency: "USDC" | "ZEN"
    pub currency: String,
    /// EVM treasury contract address for this series.
    pub vault_address: String,
    /// Market question template. Placeholders: {asset}, {price}, {time}.
    pub question_template: String,
    /// Market creation interval in seconds (3600 = hourly).
    pub interval_secs: u64,
    /// Whether this series is enabled.
    pub enabled: bool,
}

impl MarketSeriesConfig {
    /// Build the market ID for a given expiry timestamp.
    /// Format: "{ASSET}-USD-{CURRENCY}-HOUR-{expiry_ts}"
    pub fn market_id(&self, expiry_ts: u64) -> String {
        format!(
            "{}-USD-{}-HOUR-{}",
            self.oracle_asset.to_uppercase(),
            self.currency.to_uppercase(),
            expiry_ts
        )
    }

    /// Build the human-readable question for a given threshold and expiry time.
    pub fn question(&self, threshold: &Decimal, expiry_ts: u64) -> String {
        let expiry_time = chrono::DateTime::from_timestamp(expiry_ts as i64, 0)
            .unwrap_or_else(chrono::Utc::now);
        let time_str = expiry_time.format("%H:%M UTC %b %d %Y").to_string();
        self.question_template
            .replace("{asset}", &self.oracle_asset.to_uppercase())
            .replace("{price}", &threshold.to_string())
            .replace("{time}", &time_str)
    }
}

/// Load all market series from environment.
///
/// Default series (all hourly):
///   BTC-USDC, ETH-USDC, SOL-USDC  →  USDC vault
///   BTC-ZEN,  ETH-ZEN,  SOL-ZEN   →  ZEN vault
///
/// Per-series overrides:
///   MARKET_SERIES_BTC_USDC_ENABLED=false   (disable individual series)
///   MARKET_SERIES_ETH_USDC_ENABLED=false
///   MARKET_SERIES_SOL_USDC_ENABLED=false
///   MARKET_SERIES_BTC_ZEN_ENABLED=false
///   MARKET_SERIES_ETH_ZEN_ENABLED=false
///   MARKET_SERIES_SOL_ZEN_ENABLED=false
pub fn load_market_series() -> Vec<MarketSeriesConfig> {
    let usdc_vault = std::env::var("PM_USDC_TREASURY_ADDRESS")
        .or_else(|_| std::env::var("PREDICTION_MARKET_TREASURY_ADDRESS"))
        .or_else(|_| std::env::var("PM_TREASURY_ADDRESS"))
        .or_else(|_| std::env::var("PM_USDC_VAULT_ADDRESS"))
        .or_else(|_| std::env::var("USDC_VAULT_ADDRESS"))
        .or_else(|_| std::env::var("PM_VAULT_ADDRESS"))
        .or_else(|_| std::env::var("PREDICTION_MARKET_VAULT_ADDRESS"))
        .unwrap_or_default();

    let zen_vault = std::env::var("PM_ZEN_TREASURY_ADDRESS")
        .or_else(|_| std::env::var("ZEN_PM_TREASURY_ADDRESS"))
        .or_else(|_| std::env::var("ZEN_TREASURY_ADDRESS"))
        .or_else(|_| std::env::var("PM_ZEN_VAULT_ADDRESS"))
        .or_else(|_| std::env::var("ZEN_PM_VAULT_ADDRESS"))
        .or_else(|_| std::env::var("ZEN_VAULT_ADDRESS"))
        .unwrap_or_default();

    fn is_enabled(key: &str) -> bool {
        std::env::var(key)
            .map(|v| v.to_lowercase() != "false")
            .unwrap_or(true)
    }

    let assets = [("BTC", "Bitcoin"), ("ETH", "Ethereum"), ("SOL", "Solana")];

    let mut series = Vec::with_capacity(assets.len() * 2);

    for (asset, _name) in &assets {
        let usdc_key = format!("MARKET_SERIES_{}_USDC_ENABLED", asset);
        let zen_key = format!("MARKET_SERIES_{}_ZEN_ENABLED", asset);

        series.push(MarketSeriesConfig {
            oracle_asset: asset.to_string(),
            currency: "USDC".to_string(),
            vault_address: usdc_vault.clone(),
            question_template: format!(
                "Will {{asset}} close above ${{price}} at {{time}}?"
            ),
            interval_secs: std::env::var("MARKET_INTERVAL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(900), // default: 15 minutes
            enabled: is_enabled(&usdc_key),
        });

        series.push(MarketSeriesConfig {
            oracle_asset: asset.to_string(),
            currency: "ZEN".to_string(),
            vault_address: zen_vault.clone(),
            question_template: format!(
                "Will {{asset}} close above ${{price}} at {{time}}?"
            ),
            interval_secs: std::env::var("MARKET_INTERVAL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(900), // default: 15 minutes
            enabled: is_enabled(&zen_key),
        });
    }

    series
}

// ─── Market Lifecycle Manager ─────────────────────────────────────────────────

/// Automated market lifecycle manager.
///
/// Every minute: checks if we're within minute 1-3 of a new hour.
/// If so, for each enabled series:
///   1. Resolve the market that expired at the previous hour boundary.
///   2. Create a new market expiring at the next hour boundary.
///
/// Strike price = Pyth price at the current hour boundary (previous candle close).
/// Resolution price = Pyth price at the previous hour boundary.
/// Both are sourced from Pyth Hermes — single source of truth for map + resolution.
pub struct MarketLifecycleManager {
    oracle: Arc<PythOracle>,
    store: Arc<RedisStore>,
    database: Option<Arc<Database>>,
    balance_service: Arc<BalanceService>,
    policy: OraclePolicy,
    check_interval: Duration,
    series: Vec<MarketSeriesConfig>,
}

impl MarketLifecycleManager {
    pub fn new(
        oracle: Arc<PythOracle>,
        store: Arc<RedisStore>,
        balance_service: Arc<BalanceService>,
        database: Option<Arc<Database>>,
    ) -> Self {
        Self {
            oracle,
            store,
            database,
            balance_service,
            policy: OraclePolicy::from_env(),
            check_interval: Duration::from_secs(60),
            series: load_market_series(),
        }
    }

    /// Start the automated market lifecycle — runs forever.
    pub async fn start(self: Arc<Self>) {
        let enabled: Vec<&MarketSeriesConfig> =
            self.series.iter().filter(|s| s.enabled).collect();

        info!(
            total = self.series.len(),
            enabled = enabled.len(),
            series = ?enabled.iter().map(|s| format!("{}-{}", s.oracle_asset, s.currency)).collect::<Vec<_>>(),
            "Market Lifecycle Manager started (Pyth oracle)"
        );

        let mut tick = interval(self.check_interval);
        loop {
            tick.tick().await;
            if let Err(e) = self.process_all_series().await {
                error!(error = %e, "Market lifecycle tick failed");
            }
        }
    }

    /// Process all enabled series.  Only acts during the first 3 minutes of each interval window.
    async fn process_all_series(&self) -> ClobResult<()> {
        let now = chrono::Utc::now().timestamp() as u64;
        let interval_secs = self.series.first().map(|s| s.interval_secs).unwrap_or(900);
        let secs_into_interval = now % interval_secs;
        let mins_into_interval = secs_into_interval / 60;

        // Guard: only act once per interval window (minutes 1-3 to allow Pyth data to settle).
        if mins_into_interval < 1 || mins_into_interval > 3 {
            return Ok(());
        }

        for cfg in &self.series {
            if !cfg.enabled {
                continue;
            }
            if let Err(e) = self.process_lifecycle(cfg, now).await {
                warn!(
                    series = format!("{}-{}", cfg.oracle_asset, cfg.currency),
                    error = %e,
                    "Series lifecycle error"
                );
            }
        }
        Ok(())
    }

    async fn process_lifecycle(&self, cfg: &MarketSeriesConfig, now: u64) -> ClobResult<()> {
        let interval = cfg.interval_secs;
        let current_boundary = (now / interval) * interval;
        let previous_boundary = current_boundary.saturating_sub(interval);
        let next_boundary = current_boundary + interval;

        info!(
            series = format!("{}-{}", cfg.oracle_asset, cfg.currency),
            current_boundary,
            next_boundary,
            "Processing market lifecycle"
        );

        // Resolve previous market.
        let prev_id = cfg.market_id(previous_boundary);
        if self.should_resolve(&prev_id).await? {
            match self.resolve_market(cfg, &prev_id, previous_boundary, now).await {
                Ok(_) => info!(market_id = %prev_id, "Resolved"),
                Err(e) => warn!(market_id = %prev_id, error = %e, "Resolution failed"),
            }
        }

        // Create next market.
        let new_id = cfg.market_id(next_boundary);
        if self.should_create(&new_id).await? {
            match self.create_market(cfg, &new_id, current_boundary, next_boundary).await {
                Ok(_) => info!(market_id = %new_id, "Created"),
                Err(e) => warn!(market_id = %new_id, error = %e, "Creation failed"),
            }
        }

        Ok(())
    }

    async fn should_resolve(&self, market_id: &str) -> ClobResult<bool> {
        let key = format!("market:{}:status", market_id);
        let status: Option<String> = self.store.get(&key).await.ok();
        Ok(status.as_deref() == Some("ACTIVE"))
    }

    async fn should_create(&self, market_id: &str) -> ClobResult<bool> {
        let key = format!("market:{}:status", market_id);
        Ok(self.store.get(&key).await.is_err())
    }

    /// Create a new hourly market for `cfg`.
    ///
    /// Strike price = Pyth price at `threshold_ts` (the current hour boundary,
    /// i.e. the close of the candle that just completed).
    async fn create_market(
        &self,
        cfg: &MarketSeriesConfig,
        market_id: &str,
        threshold_ts: u64,
        expiry_ts: u64,
    ) -> ClobResult<()> {
        // Fetch strike price from Pyth at the current hour boundary.
        let resolution = self
            .oracle
            .resolve_at_timestamp(&cfg.oracle_asset, threshold_ts)
            .await?;
        let threshold = resolution.close_price;
        let question = cfg.question(&threshold, expiry_ts);

        let market_data = serde_json::json!({
            "market_id":    market_id,
            "status":       "ACTIVE",
            "token":        cfg.oracle_asset,
            "currency":     cfg.currency,
            "vault_address": cfg.vault_address,
            "threshold":    threshold.to_string(),
            "threshold_ts": threshold_ts,
            "expiry_ts":    expiry_ts,
            "created_at":   chrono::Utc::now().timestamp(),
            "question":     question,
            "source":       "pyth",
            "granularity":  "hourly",
            "kind":         "binary",
            "pyth_feed_id": crate::oracle::pyth::feed_id(&cfg.oracle_asset),
            "pyth_publish_time": resolution.publish_time,
        });

        self.store
            .set(
                &format!("market:{}:metadata", market_id),
                &serde_json::to_string(&market_data)?,
            )
            .await?;
        self.store
            .set(&format!("market:{}:status", market_id), "ACTIVE")
            .await?;

        // Persist to PostgreSQL
        if let Some(db) = &self.database {
            if let Err(e) = db.upsert_market(
                market_id,
                &question,
                expiry_ts,
                "active",
                None,
                Some(threshold),
                Some(&cfg.currency),
                Some(&cfg.vault_address),
                Some("pyth"),
                None,
            ).await {
                warn!(market_id, error = %e, "Failed to persist new market to DB");
            }
        }

        info!(
            market_id,
            asset = %cfg.oracle_asset,
            currency = %cfg.currency,
            threshold = %threshold,
            expiry_ts,
            "Market created"
        );
        Ok(())
    }

    /// Resolve a market using the Pyth price at `resolution_ts`.
    async fn resolve_market(
        &self,
        cfg: &MarketSeriesConfig,
        market_id: &str,
        resolution_ts: u64,
        now: u64,
    ) -> ClobResult<()> {
        let metadata_key = format!("market:{}:metadata", market_id);
        let metadata_str = self.store.get(&metadata_key).await?;
        let metadata: serde_json::Value = serde_json::from_str(&metadata_str)?;

        let threshold = Decimal::from_str_exact(
            metadata["threshold"]
                .as_str()
                .ok_or_else(|| ClobError::InvalidOrder("Missing threshold".to_string()))?,
        )
        .map_err(|e| ClobError::InvalidPrice(e.to_string()))?;

        let expiry_ts = metadata["expiry_ts"]
            .as_u64()
            .ok_or_else(|| ClobError::InvalidOrder("Missing expiry_ts".to_string()))?;

        // Fetch settlement price from Pyth at resolution timestamp.
        let settlement_price = self
            .oracle
            .resolve_at_timestamp(&cfg.oracle_asset, resolution_ts)
            .await
            .ok()
            .map(|r| r.close_price);

        let decision = evaluate_resolution_candidates(
            now.saturating_sub(expiry_ts),
            Some(threshold),
            "pyth",
            settlement_price,
            None,
            None,
            &self.policy,
        );

        let mut audit = create_audit_record(
            market_id.to_string(),
            expiry_ts,
            Some(threshold),
            "pyth",
            settlement_price,
            None,
            None,
            1,
            &self.policy,
            &decision,
        );

        match decision {
            OracleResolutionDecision::Pending { reason } => {
                audit.status = OracleResolutionStatus::PendingResolution;
                audit.reason = Some(reason);
                self.persist_audit(&audit).await?;
                self.store
                    .set(&format!("market:{}:status", market_id), "PENDING_RESOLUTION")
                    .await?;
                return Ok(());
            }
            OracleResolutionDecision::Disputed { reason } => {
                audit.status = OracleResolutionStatus::Disputed;
                audit.reason = Some(reason);
                self.persist_audit(&audit).await?;
                self.store
                    .set(&format!("market:{}:status", market_id), "DISPUTED")
                    .await?;
                return Ok(());
            }
            OracleResolutionDecision::Invalidate { reason } => {
                audit.status = OracleResolutionStatus::Invalidated;
                audit.reason = Some(reason.clone());
                self.persist_audit(&audit).await?;
                self.store
                    .set(&format!("market:{}:status", market_id), "INVALIDATED")
                    .await?;
                self.store
                    .set(
                        &format!("market:{}:resolution", market_id),
                        &serde_json::json!({
                            "status": "INVALIDATED",
                            "reason": reason,
                            "resolved_at": now,
                        })
                        .to_string(),
                    )
                    .await?;
                return Ok(());
            }
            OracleResolutionDecision::Resolve { .. } => {}
        }

        let settlement_price = settlement_price.ok_or_else(|| {
            ClobError::InvalidPrice("Policy selected Resolve but no price available".to_string())
        })?;

        let outcome = settlement_price >= threshold;

        let resolution_data = serde_json::json!({
            "status":           "RESOLVED",
            "outcome":          if outcome { "YES" } else { "NO" },
            "settlement_price": settlement_price.to_string(),
            "threshold":        threshold.to_string(),
            "resolution_time":  resolution_ts,
            "resolved_at":      chrono::Utc::now().timestamp(),
            "claimable_at":     expiry_ts + self.policy.dispute_after_secs,
            "currency":         cfg.currency,
            "vault_address":    cfg.vault_address,
            "source":           "pyth",
        });

        self.store
            .set(
                &format!("market:{}:resolution", market_id),
                &serde_json::to_string(&resolution_data)?,
            )
            .await?;
        self.store
            .set(&format!("market:{}:status", market_id), "RESOLVED")
            .await?;

        audit.status = OracleResolutionStatus::Finalized;
        audit.final_price = Some(settlement_price.to_string());
        audit.reason = Some("finalized via Pyth oracle".to_string());
        self.persist_audit(&audit).await?;

        // Persist resolution to PostgreSQL
        if let Some(db) = &self.database {
            if let Err(e) = db.update_market_resolution(market_id, settlement_price, "resolved").await {
                warn!(market_id, error = %e, "Failed to persist market resolution to DB");
            }
        }

        self.distribute_payouts(market_id, outcome).await?;
        self.enqueue_resolution_proof(market_id, outcome, settlement_price, threshold)
            .await?;

        info!(
            market_id,
            asset = %cfg.oracle_asset,
            outcome = if outcome { "YES" } else { "NO" },
            settlement_price = %settlement_price,
            threshold = %threshold,
            "Market resolved"
        );
        Ok(())
    }

    async fn distribute_payouts(&self, market_id: &str, outcome: bool) -> ClobResult<()> {
        let positions_json = self
            .store
            .get(&format!("market:{}:positions", market_id))
            .await
            .unwrap_or_else(|_| "[]".to_string());
        let positions: Vec<serde_json::Value> =
            serde_json::from_str(&positions_json).unwrap_or_default();

        if positions.is_empty() {
            warn!(market_id, "No positions found for payout distribution");
            return Ok(());
        }

        let winning_side = if outcome { "YES" } else { "NO" };
        let mut winners = 0usize;
        let mut total_payout = Decimal::ZERO;

        for p in positions {
            let Some(user_id) = p.get("user_id").and_then(|v| v.as_str()) else {
                continue;
            };
            let side = p.get("side").and_then(|v| v.as_str()).unwrap_or_default();
            let size = p
                .get("size")
                .and_then(|v| v.as_str())
                .and_then(|v| Decimal::from_str_exact(v).ok())
                .unwrap_or(Decimal::ZERO);

            if size <= Decimal::ZERO || !side.eq_ignore_ascii_case(winning_side) {
                continue;
            }

            self.balance_service.credit(user_id, market_id, size);
            winners += 1;
            total_payout += size;
        }

        info!(market_id, winners, total_payout = %total_payout, "Payouts distributed");
        Ok(())
    }

    async fn enqueue_resolution_proof(
        &self,
        market_id: &str,
        outcome: bool,
        settlement_price: Decimal,
        threshold: Decimal,
    ) -> ClobResult<()> {
        let payload = serde_json::json!({
            "market_id":        market_id,
            "outcome":          if outcome { "YES" } else { "NO" },
            "settlement_price": settlement_price.to_string(),
            "threshold":        threshold.to_string(),
            "requested_at":     chrono::Utc::now().timestamp(),
        });
        let payload_str = payload.to_string();

        self.store
            .set(
                &format!("proof:resolution:request:{}", market_id),
                &payload_str,
            )
            .await?;
        self.store
            .push_queue("proof:resolution:queue", &payload_str)
            .await?;
        Ok(())
    }

    async fn persist_audit(
        &self,
        audit: &crate::market_resolution_policy::OracleResolutionAuditRecord,
    ) -> ClobResult<()> {
        let payload = serde_json::to_string(audit)?;
        self.store.set(&audit.redis_key(), &payload).await?;
        self.store
            .append_json_array_value(&audit.history_key(), &payload)
            .await?;
        Ok(())
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_market_series_defaults() {
        // 3 assets × 2 currencies = 6 series
        let series = load_market_series();
        assert_eq!(series.len(), 6);

        let assets: Vec<&str> = series.iter().map(|s| s.oracle_asset.as_str()).collect();
        assert!(assets.contains(&"BTC"));
        assert!(assets.contains(&"ETH"));
        assert!(assets.contains(&"SOL"));

        let currencies: Vec<&str> = series.iter().map(|s| s.currency.as_str()).collect();
        assert!(currencies.contains(&"USDC"));
        assert!(currencies.contains(&"ZEN"));
    }

    #[test]
    fn test_market_id_format() {
        let cfg = MarketSeriesConfig {
            oracle_asset: "ETH".to_string(),
            currency: "USDC".to_string(),
            vault_address: String::new(),
            question_template: "Will {asset} close above ${price} at {time}?".to_string(),
            interval_secs: 3600,
            enabled: true,
        };
        assert_eq!(cfg.market_id(1738368000), "ETH-USD-USDC-HOUR-1738368000");
    }

    #[test]
    fn test_market_id_sol_zen() {
        let cfg = MarketSeriesConfig {
            oracle_asset: "SOL".to_string(),
            currency: "ZEN".to_string(),
            vault_address: String::new(),
            question_template: "Will {asset} close above ${price} at {time}?".to_string(),
            interval_secs: 3600,
            enabled: true,
        };
        assert_eq!(cfg.market_id(1738368000), "SOL-USD-ZEN-HOUR-1738368000");
    }

    #[test]
    fn test_question_template() {
        use rust_decimal_macros::dec;
        let cfg = MarketSeriesConfig {
            oracle_asset: "ETH".to_string(),
            currency: "USDC".to_string(),
            vault_address: String::new(),
            question_template: "Will {asset} close above ${price} at {time}?".to_string(),
            interval_secs: 3600,
            enabled: true,
        };
        let q = cfg.question(&dec!(2500), 1738368000);
        assert!(q.contains("ETH"));
        assert!(q.contains("2500"));
    }

    #[test]
    fn test_hour_boundaries() {
        let now = 1738368000u64; // top of hour
        let interval = 3600u64;
        let current = (now / interval) * interval;
        let prev = current.saturating_sub(interval);
        let next = current + interval;
        assert_eq!(current, 1738368000);
        assert_eq!(prev, 1738364400);
        assert_eq!(next, 1738371600);
    }

    #[test]
    fn test_minute_guard() {
        // Minute 0 → skip
        let ts_min0 = 1738368000u64;
        assert_eq!((ts_min0 / 60) % 60, 0);

        // Minute 1 → act
        let ts_min1 = 1738368060u64;
        assert_eq!((ts_min1 / 60) % 60, 1);

        // Minute 4 → skip
        let ts_min4 = 1738368240u64;
        assert_eq!((ts_min4 / 60) % 60, 4);
    }
}
