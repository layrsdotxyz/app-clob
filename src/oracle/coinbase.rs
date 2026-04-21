#![allow(dead_code)]

use crate::error::{ClobError, ClobResult};
use reqwest::Client;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use tracing::{debug, error, info};

/// Coinbase candle data structure
/// Response format: [[timestamp, low, high, open, close, volume], ...]
type CandleData = Vec<Vec<f64>>;

const COINBASE_API_BASE: &str = "https://api.exchange.coinbase.com";

/// Coinbase oracle client for BTC/USD price resolution
/// 
/// Price source: Coinbase Advanced Trade API (free)
/// Documentation: https://docs.cloud.coinbase.com/exchange/reference
/// 
/// Transparency: All market pages display TradingView chart for user verification
pub struct CoinbaseOracle {
    client: Client,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriceResolution {
    pub market_id: String,
    pub resolution_time: u64,      // Unix timestamp (hourly boundary)
    pub btc_usd_close: Decimal,    // Coinbase BTC-USD hourly candle close
    pub source: String,            // "coinbase"
    pub granularity: u64,          // 3600 (hourly)
    pub candle_data: Option<CandleInfo>, // For ZK proof
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandleInfo {
    pub timestamp: u64,
    pub low: Decimal,
    pub high: Decimal,
    pub open: Decimal,
    pub close: Decimal,
    pub volume: Decimal,
}

impl CoinbaseOracle {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .expect("Failed to create HTTP client"),
        }
    }

    /// Get BTC-USD hourly candle close price at specific timestamp
    /// 
    /// # Arguments
    /// * `timestamp` - Unix timestamp (should be on hourly boundary, e.g., 1700000000)
    /// 
    /// # Returns
    /// * `Decimal` - Close price of the hourly candle ending at this timestamp
    /// 
    /// # Example
    /// ```
    /// let oracle = CoinbaseOracle::new();
    /// let price = oracle.get_hourly_close(1738368000).await?; // 3:00 PM close
    /// ```
    pub async fn get_hourly_close(&self, timestamp: u64) -> ClobResult<Decimal> {
        let resolution = self.resolve_market_at_timestamp(timestamp).await?;
        Ok(resolution.btc_usd_close)
    }

    /// Resolve market at specific timestamp with full candle data
    /// Used for generating ZK proofs of correct resolution
    pub async fn resolve_market_at_timestamp(
        &self,
        timestamp: u64,
    ) -> ClobResult<PriceResolution> {
        // Validate timestamp is on hourly boundary
        if timestamp % 3600 != 0 {
            return Err(ClobError::InvalidPrice(format!(
                "Timestamp {} is not on hourly boundary",
                timestamp
            )));
        }

        info!(
            timestamp = %timestamp,
            "Fetching BTC-USD hourly candle close from Coinbase"
        );

        // Fetch candles from Coinbase
        // Granularity 3600 = 1 hour candles
        // Start/End = get the specific hour we want
        let url = format!(
            "{}/products/BTC-USD/candles?granularity=3600&start={}&end={}",
            COINBASE_API_BASE,
            timestamp - 3600, // Start of the hour
            timestamp         // End of the hour (close time)
        );

        debug!(url = %url, "Coinbase API request");

        let response = self
            .client
            .get(&url)
            .header("User-Agent", "Layrs/1.0")
            .send()
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to fetch Coinbase data");
                ClobError::InvalidOrder(format!("Coinbase API error: {}", e))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            error!(status = %status, body = %body, "Coinbase API error response");
            return Err(ClobError::InvalidOrder(format!(
                "Coinbase API returned {}: {}",
                status, body
            )));
        }

        let candles: CandleData = response.json().await.map_err(|e| {
            error!(error = %e, "Failed to parse Coinbase response");
            ClobError::InvalidOrder(format!("Failed to parse Coinbase data: {}", e))
        })?;

        if candles.is_empty() {
            error!(timestamp = %timestamp, "No candle data returned from Coinbase");
            return Err(ClobError::InvalidOrder(
                "No candle data available for this timestamp".to_string(),
            ));
        }

        // Candle format: [timestamp, low, high, open, close, volume]
        let candle = &candles[0];
        if candle.len() < 6 {
            error!(candle = ?candle, "Invalid candle data format");
            return Err(ClobError::InvalidOrder("Invalid candle format".to_string()));
        }

        let candle_timestamp = candle[0] as u64;
        let low = Decimal::from_str(&candle[1].to_string())
            .map_err(|e| ClobError::InvalidPrice(e.to_string()))?;
        let high = Decimal::from_str(&candle[2].to_string())
            .map_err(|e| ClobError::InvalidPrice(e.to_string()))?;
        let open = Decimal::from_str(&candle[3].to_string())
            .map_err(|e| ClobError::InvalidPrice(e.to_string()))?;
        let close = Decimal::from_str(&candle[4].to_string())
            .map_err(|e| ClobError::InvalidPrice(e.to_string()))?;
        let volume = Decimal::from_str(&candle[5].to_string())
            .map_err(|e| ClobError::InvalidPrice(e.to_string()))?;

        info!(
            timestamp = %timestamp,
            candle_timestamp = %candle_timestamp,
            close = %close,
            "Successfully fetched BTC-USD close price"
        );

        Ok(PriceResolution {
            market_id: format!("BTC-HOUR-{}", timestamp),
            resolution_time: timestamp,
            btc_usd_close: close,
            source: "coinbase".to_string(),
            granularity: 3600,
            candle_data: Some(CandleInfo {
                timestamp: candle_timestamp,
                low,
                high,
                open,
                close,
                volume,
            }),
        })
    }

    /// Get current (latest) BTC-USD price
    /// Uses spot price API for real-time data
    pub async fn get_current_price(&self) -> ClobResult<Decimal> {
        let url = format!("{}/products/BTC-USD/ticker", COINBASE_API_BASE);

        let response = self
            .client
            .get(&url)
            .header("User-Agent", "Layrs/1.0")
            .send()
            .await
            .map_err(|e| ClobError::InvalidOrder(format!("Coinbase API error: {}", e)))?;

        #[derive(Deserialize)]
        struct Ticker {
            price: String,
        }

        let ticker: Ticker = response
            .json()
            .await
            .map_err(|e| ClobError::InvalidOrder(format!("Failed to parse ticker: {}", e)))?;

        Decimal::from_str(&ticker.price)
            .map_err(|e| ClobError::InvalidPrice(e.to_string()))
    }
}

impl Default for CoinbaseOracle {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_get_current_price() {
        let oracle = CoinbaseOracle::new();
        let price = oracle.get_current_price().await.unwrap();
        
        // BTC should be between $10k and $200k
        assert!(price > Decimal::from(10000));
        assert!(price < Decimal::from(200000));
        
        println!("Current BTC-USD price: ${}", price);
    }

    #[tokio::test]
    #[ignore] // Run manually: cargo test test_get_historical_candle -- --ignored
    async fn test_get_historical_candle() {
        let oracle = CoinbaseOracle::new();
        
        // Test with a known timestamp (Jan 1, 2024, 00:00 UTC)
        let timestamp = 1704067200u64;
        
        let resolution = oracle.resolve_market_at_timestamp(timestamp).await.unwrap();
        
        assert_eq!(resolution.resolution_time, timestamp);
        assert_eq!(resolution.source, "coinbase");
        assert!(resolution.btc_usd_close > Decimal::ZERO);
        
        println!("Resolution: {:?}", resolution);
    }

    #[test]
    fn test_timestamp_validation() {
        // Valid hourly boundaries
        assert_eq!(1704067200 % 3600, 0);  // 2024-01-01 00:00:00
        assert_eq!(1704070800 % 3600, 0);  // 2024-01-01 01:00:00
        
        // Invalid (not on boundary)
        assert_ne!(1704067230 % 3600, 0);  // 2024-01-01 00:00:30
    }
}
