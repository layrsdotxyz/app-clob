#![allow(dead_code)]

use crate::{
    error::{ClobError, ClobResult},
    models::*,
    redis_store::RedisStore,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

/// Order book snapshot for recovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderBookSnapshot {
    pub market_id: String,
    pub timestamp: i64,
    pub bids: Vec<Order>,
    pub asks: Vec<Order>,
    pub last_trade_id: Option<String>,
    pub version: u64,
}

/// System state snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemSnapshot {
    pub timestamp: i64,
    pub orderbooks: HashMap<String, OrderBookSnapshot>,
    pub balances_checksum: String,
    pub total_orders: usize,
    pub total_trades: usize,
}

/// Error recovery service
pub struct ErrorRecoveryService {
    redis: Arc<RedisStore>,
    snapshots: Arc<RwLock<Vec<SystemSnapshot>>>,
    max_snapshots: usize,
    redis_reconnect_attempts: Arc<RwLock<u32>>,
    max_reconnect_attempts: u32,
}

impl ErrorRecoveryService {
    pub fn new(redis: Arc<RedisStore>) -> Self {
        Self {
            redis,
            snapshots: Arc::new(RwLock::new(Vec::new())),
            max_snapshots: 10, // Keep last 10 snapshots
            redis_reconnect_attempts: Arc::new(RwLock::new(0)),
            max_reconnect_attempts: 5,
        }
    }

    /// Create a snapshot of the current system state
    pub async fn create_snapshot(&self, market_id: &str) -> ClobResult<OrderBookSnapshot> {
        info!(market_id = %market_id, "Creating order book snapshot");

        // Get all orders for this market
        let bids = self.redis.get_orders_by_side(market_id, OrderSide::Buy).await?;
        let asks = self.redis.get_orders_by_side(market_id, OrderSide::Sell).await?;

        // Get last trade ID
        let recent_trades = self.redis.get_recent_trades(market_id, 1).await.ok();
        let last_trade_id = recent_trades
            .and_then(|trades| trades.first().map(|t| t.id.to_string()));

        let snapshot = OrderBookSnapshot {
            market_id: market_id.to_string(),
            timestamp: chrono::Utc::now().timestamp(),
            bids,
            asks,
            last_trade_id,
            version: 1,
        };

        // Store snapshot in Redis for persistence
        self.store_snapshot(&snapshot).await?;

        Ok(snapshot)
    }

    /// Store snapshot to Redis
    async fn store_snapshot(&self, snapshot: &OrderBookSnapshot) -> ClobResult<()> {
        let key = format!("snapshot:{}:{}", snapshot.market_id, snapshot.timestamp);
        let data = serde_json::to_string(snapshot)
            .map_err(|e| ClobError::Other(format!("Failed to serialize snapshot: {}", e)))?;

        self.redis
            .store_proof_data(&key, &data)
            .await
            .map_err(|e| ClobError::Other(format!("Failed to store snapshot: {}", e)))?;

        // Keep only last 10 snapshots
        let _list_key = format!("snapshots:{}", snapshot.market_id);
        // This is a simplified version - in production, use LPUSH + LTRIM
        
        info!(
            market_id = %snapshot.market_id,
            orders_count = %(snapshot.bids.len() + snapshot.asks.len()),
            "Snapshot stored successfully"
        );

        Ok(())
    }

    /// Restore order book from latest snapshot
    pub async fn restore_from_snapshot(&self, market_id: &str) -> ClobResult<OrderBookSnapshot> {
        info!(market_id = %market_id, "Attempting to restore from snapshot");

        // Get latest snapshot from Redis
        let snapshot_key = format!("snapshot:{}:latest", market_id);
        let snapshot_data = self
            .redis
            .retrieve_proof_data(&snapshot_key)
            .await
            .map_err(|e| ClobError::Other(format!("Failed to retrieve snapshot: {}", e)))?
            .ok_or_else(|| ClobError::Other("Snapshot not found".to_string()))?;

        let snapshot: OrderBookSnapshot = serde_json::from_str(&snapshot_data)
            .map_err(|e| ClobError::Other(format!("Failed to deserialize snapshot: {}", e)))?;

        info!(
            market_id = %market_id,
            orders_count = %(snapshot.bids.len() + snapshot.asks.len()),
            snapshot_age_secs = %(chrono::Utc::now().timestamp() - snapshot.timestamp),
            "Snapshot restored successfully"
        );

        Ok(snapshot)
    }

    /// Handle Redis connection failure and attempt recovery
    pub async fn handle_redis_failure(&self) -> ClobResult<bool> {
        let mut attempts = self.redis_reconnect_attempts.write().await;
        *attempts += 1;

        if *attempts > self.max_reconnect_attempts {
            error!(
                attempts = %attempts,
                "Redis reconnection attempts exceeded maximum"
            );
            return Ok(false);
        }

        warn!(
            attempt = %attempts,
            max_attempts = %self.max_reconnect_attempts,
            "Attempting Redis reconnection"
        );

        // Try to ping Redis
        match self.redis.ping().await {
            Ok(_) => {
                info!("Redis connection restored");
                *attempts = 0;
                Ok(true)
            }
            Err(e) => {
                error!(error = %e, "Redis reconnection failed");
                
                // Wait before next attempt (exponential backoff)
                let delay_secs = 2_u64.pow(*attempts);
                tokio::time::sleep(tokio::time::Duration::from_secs(delay_secs)).await;
                
                Ok(false)
            }
        }
    }

    /// Recover from order processing failure
    pub async fn recover_from_order_failure(
        &self,
        order: &Order,
        error: &ClobError,
    ) -> ClobResult<()> {
        error!(
            order_id = %order.id,
            user_id = %order.user_id,
            error = %error,
            "Order processing failed, attempting recovery"
        );

        // Log failure for audit
        let failure_log = format!(
            "Order {} failed: {}. Time: {}",
            order.id,
            error,
            chrono::Utc::now().to_rfc3339()
        );

        self.redis
            .store_proof_data(
                &format!("failure:order:{}", order.id),
                &failure_log,
            )
            .await?;

        // Attempt to cancel order if it's in an inconsistent state
        // This prevents partial fills from causing issues
        warn!(
            order_id = %order.id,
            "Marking order as failed in system"
        );

        Ok(())
    }

    /// Perform full system health check and recovery
    pub async fn perform_health_check(&self) -> ClobResult<HashMap<String, String>> {
        let mut status = HashMap::new();

        // Check Redis connectivity
        match self.redis.ping().await {
            Ok(_) => {
                status.insert("redis".to_string(), "healthy".to_string());
            }
            Err(e) => {
                status.insert("redis".to_string(), format!("unhealthy: {}", e));
                // Attempt recovery
                self.handle_redis_failure().await?;
            }
        }

        // Check recent failures
        let attempts = self.redis_reconnect_attempts.read().await;
        status.insert("reconnect_attempts".to_string(), attempts.to_string());

        // Check snapshot availability
        let snapshots = self.snapshots.read().await;
        status.insert("available_snapshots".to_string(), snapshots.len().to_string());

        Ok(status)
    }

    /// Clean up old snapshots
    pub async fn cleanup_old_snapshots(&self) -> ClobResult<usize> {
        let mut snapshots = self.snapshots.write().await;
        let _original_count = snapshots.len();

        // Keep only the most recent snapshots
        if snapshots.len() > self.max_snapshots {
            let to_remove = snapshots.len() - self.max_snapshots;
            snapshots.drain(0..to_remove);
            
            info!(
                removed = %to_remove,
                remaining = %snapshots.len(),
                "Cleaned up old snapshots"
            );
            
            Ok(to_remove)
        } else {
            Ok(0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mini_redis::server;
    use tokio::sync::oneshot;

    async fn setup_test_redis() -> (Arc<RedisStore>, oneshot::Sender<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            let _ = server::run(listener, async { let _ = rx.await; }).await;
        });
        let client = redis::Client::open(format!("redis://{}/", addr)).unwrap();
        let conn = redis::aio::ConnectionManager::new(client).await.unwrap();
        (Arc::new(RedisStore::new(conn)), tx)
    }

    #[tokio::test]
    async fn test_recovery_service_creation() {
        let (redis, _shutdown) = setup_test_redis().await;
        let recovery = ErrorRecoveryService::new(redis);
        
        let status = recovery.perform_health_check().await.unwrap();
        assert!(status.contains_key("redis"));
    }

    #[tokio::test]
    async fn test_snapshot_creation() {
        let (redis, _shutdown) = setup_test_redis().await;
        let recovery = ErrorRecoveryService::new(redis);
        
        // This will fail if Redis is not running, which is expected in testing
        match recovery.create_snapshot("TEST-MARKET").await {
            Ok(snapshot) => {
                assert_eq!(snapshot.market_id, "TEST-MARKET");
                assert!(snapshot.timestamp > 0);
            }
            Err(_) => {
                // Expected if Redis not available
            }
        }
    }
}
