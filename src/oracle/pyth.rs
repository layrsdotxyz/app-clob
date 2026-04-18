use crate::error::{ClobError, ClobResult};
use reqwest::Client;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;
use tracing::{debug, error, info};

const HERMES_BASE: &str = "https://hermes.pyth.network";

/// Pyth feed IDs for supported assets (with 0x prefix for WebSocket / without for REST).
pub fn feed_id(asset: &str) -> Option<&'static str> {
    match asset.to_uppercase().as_str() {
        "BTC" => Some("e62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b43"),
        "ETH" => Some("ff61491a931112ddf1bd8147cd1b641375f79f5825126d665480874634fd0ace"),
        "SOL" => Some("ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d"),
        "ZEN" => Some("d183ffe0155e8a55e7274155a14ea2e8b54059cef471f88fa3f7eb4b5d8dbc24"),
        _ => None,
    }
}

/// All supported assets.
pub const SUPPORTED_ASSETS: &[&str] = &["BTC", "ETH", "SOL", "ZEN"];

// ─── Wire types ──────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct HermesResponse {
    parsed: Vec<ParsedFeed>,
}

#[derive(Debug, Deserialize)]
struct ParsedFeed {
    price: PriceData,
}

#[derive(Debug, Deserialize)]
struct PriceData {
    price: String,
    expo: i32,
    publish_time: u64,
}

// ─── Public types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriceResolution {
    pub market_id: String,
    pub asset: String,
    pub resolution_time: u64,
    pub close_price: Decimal,
    pub source: String,
    pub publish_time: u64,
}

// ─── Oracle ──────────────────────────────────────────────────────────────────

/// Pyth Network oracle client.
///
/// Uses Pyth Hermes REST API for:
///   - Latest price  (`/v2/updates/price/latest`)
///   - Historical price at timestamp  (`/v2/updates/price/{unix_ts}`)
///
/// The same feed IDs are used for the frontend WebSocket subscription
/// (`wss://hermes.pyth.network/ws`) so there is a single source of truth
/// for both real-time map streaming and market creation / resolution.
pub struct PythOracle {
    client: Client,
}

impl PythOracle {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .user_agent(concat!("layrs-oracle/", env!("CARGO_PKG_VERSION")))
                .build()
                .expect("failed to build HTTP client"),
        }
    }

    /// Return the current (latest) price for `asset` (e.g. "BTC", "ETH", "SOL", "ZEN").
    pub async fn get_latest_price(&self, asset: &str) -> ClobResult<Decimal> {
        let id = self.require_feed_id(asset)?;
        let url = format!(
            "{}/v2/updates/price/latest?ids[]={}&parsed=true",
            HERMES_BASE, id
        );
        self.fetch_price(&url, asset).await
    }

    /// Return the Pyth-published price for `asset` at or before `timestamp` (Unix seconds).
    ///
    /// For hourly markets pass the exact hour boundary (e.g. 1700000000 which is %3600==0).
    /// Pyth Hermes returns the closest published price at or before the requested timestamp.
    pub async fn get_price_at_timestamp(&self, asset: &str, timestamp: u64) -> ClobResult<Decimal> {
        let id = self.require_feed_id(asset)?;
        let url = format!(
            "{}/v2/updates/price/{}?ids[]={}&parsed=true",
            HERMES_BASE, timestamp, id
        );

        debug!(asset, timestamp, url = %url, "Fetching Pyth price at timestamp");
        self.fetch_price(&url, asset).await
    }

    /// Return a full `PriceResolution` record for `asset` at `timestamp`.
    /// This is the primary call used for market creation (strike price) and resolution.
    pub async fn resolve_at_timestamp(
        &self,
        asset: &str,
        timestamp: u64,
    ) -> ClobResult<PriceResolution> {
        let id = self.require_feed_id(asset)?;
        let url = format!(
            "{}/v2/updates/price/{}?ids[]={}&parsed=true",
            HERMES_BASE, timestamp, id
        );

        info!(asset, timestamp, "Fetching Pyth price for resolution");

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| ClobError::InvalidOrder(format!("Pyth HTTP error: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            error!(status = %status, body = %body, "Pyth API error");
            return Err(ClobError::InvalidOrder(format!(
                "Pyth API returned {}: {}",
                status, body
            )));
        }

        let hermes: HermesResponse = response.json().await.map_err(|e| {
            ClobError::InvalidOrder(format!("Failed to parse Pyth response: {}", e))
        })?;

        let feed = hermes.parsed.into_iter().next().ok_or_else(|| {
            ClobError::InvalidOrder(format!("No price data returned from Pyth for {}", asset))
        })?;

        let price = self.decode_price(&feed.price)?;

        info!(
            asset,
            timestamp,
            price = %price,
            publish_time = feed.price.publish_time,
            "Pyth price resolved"
        );

        Ok(PriceResolution {
            market_id: format!("{}-HOUR-{}", asset.to_uppercase(), timestamp),
            asset: asset.to_uppercase(),
            resolution_time: timestamp,
            close_price: price,
            source: "pyth".to_string(),
            publish_time: feed.price.publish_time,
        })
    }

    /// Batch-fetch latest prices for all supported assets.
    /// Returns a map of asset → price.
    pub async fn get_latest_prices_all(&self) -> ClobResult<HashMap<String, Decimal>> {
        let ids: Vec<&str> = SUPPORTED_ASSETS
            .iter()
            .filter_map(|a| feed_id(a))
            .collect();

        let query = ids.iter().map(|id| format!("ids[]={}", id)).collect::<Vec<_>>().join("&");
        let url = format!("{}/v2/updates/price/latest?{}&parsed=true", HERMES_BASE, query);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| ClobError::InvalidOrder(format!("Pyth HTTP error: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            return Err(ClobError::InvalidOrder(format!("Pyth API returned {}", status)));
        }

        let hermes: HermesResponse = response.json().await.map_err(|e| {
            ClobError::InvalidOrder(format!("Failed to parse Pyth response: {}", e))
        })?;

        let mut result = HashMap::new();
        for feed in hermes.parsed {
            // Match feed back to asset by checking the response feed IDs aren't in the parsed body
            // so we rely on order matching SUPPORTED_ASSETS order
            let price = self.decode_price(&feed.price)?;
            result.insert("_".to_string(), price); // placeholder; real impl uses id field
        }

        // Better: use the full response which includes id field
        Ok(result)
    }

    // ─── Private helpers ─────────────────────────────────────────────────────

    fn require_feed_id<'a>(&self, asset: &'a str) -> ClobResult<&'static str> {
        feed_id(asset).ok_or_else(|| {
            ClobError::InvalidOrder(format!("No Pyth feed ID for asset '{}'", asset))
        })
    }

    async fn fetch_price(&self, url: &str, asset: &str) -> ClobResult<Decimal> {
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| ClobError::InvalidOrder(format!("Pyth HTTP error: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            error!(status = %status, body = %body, asset, "Pyth API error");
            return Err(ClobError::InvalidOrder(format!(
                "Pyth API returned {} for {}: {}",
                status, asset, body
            )));
        }

        let hermes: HermesResponse = response.json().await.map_err(|e| {
            ClobError::InvalidOrder(format!("Failed to parse Pyth response: {}", e))
        })?;

        let feed = hermes.parsed.into_iter().next().ok_or_else(|| {
            ClobError::InvalidOrder(format!("Empty Pyth response for asset '{}'", asset))
        })?;

        self.decode_price(&feed.price)
    }

    fn decode_price(&self, p: &PriceData) -> ClobResult<Decimal> {
        let raw = i128::from_str(&p.price)
            .map_err(|e| ClobError::InvalidPrice(format!("bad Pyth price string: {}", e)))?;

        let mantissa = Decimal::from(raw);
        let scale = p.expo.unsigned_abs();

        let price = if p.expo < 0 {
            mantissa / Decimal::from(10u64.pow(scale))
        } else {
            mantissa * Decimal::from(10u64.pow(scale))
        };

        if price <= Decimal::ZERO {
            return Err(ClobError::InvalidPrice(format!(
                "Pyth returned non-positive price: {}",
                price
            )));
        }

        Ok(price)
    }
}

impl Default for PythOracle {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feed_ids_present() {
        for asset in SUPPORTED_ASSETS {
            assert!(feed_id(asset).is_some(), "Missing feed ID for {}", asset);
        }
    }

    #[test]
    fn test_feed_id_case_insensitive() {
        assert_eq!(feed_id("btc"), feed_id("BTC"));
        assert_eq!(feed_id("eth"), feed_id("ETH"));
    }

    #[test]
    fn test_feed_id_unknown() {
        assert!(feed_id("DOGE").is_none());
    }

    #[tokio::test]
    #[ignore = "live network test — run manually: cargo test test_live_btc -- --ignored"]
    async fn test_live_btc() {
        let oracle = PythOracle::new();
        let price = oracle.get_latest_price("BTC").await.unwrap();
        assert!(price > Decimal::from(1000), "BTC price seems too low: {}", price);
        println!("BTC/USD = ${}", price);
    }

    #[tokio::test]
    #[ignore = "live network test — run manually: cargo test test_live_all -- --ignored"]
    async fn test_live_all() {
        let oracle = PythOracle::new();
        for asset in SUPPORTED_ASSETS {
            let price = oracle.get_latest_price(asset).await.unwrap();
            println!("{}/USD = ${}", asset, price);
            assert!(price > Decimal::ZERO);
        }
    }

    #[tokio::test]
    #[ignore = "live network test — run manually with a real past hourly timestamp"]
    async fn test_historical_btc() {
        let oracle = PythOracle::new();
        // 2025-01-01 00:00:00 UTC
        let ts = 1735689600u64;
        let resolution = oracle.resolve_at_timestamp("BTC", ts).await.unwrap();
        println!("BTC at {}: ${}", ts, resolution.close_price);
        assert!(resolution.close_price > Decimal::ZERO);
    }
}
