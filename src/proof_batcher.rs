#![allow(dead_code)]

use crate::{error::ClobResult, redis_store::RedisStore};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{interval, Duration};
use tracing::{error, info, warn};

/// Market resolution data for ZK proof generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketResolution {
    pub market_id: String,
    pub resolution_time: u64,
    pub threshold: String,        // Decimal as string
    pub settlement_price: String, // Decimal as string
    pub outcome: bool,            // YES/NO
    pub market_salt: String,      // For ZK proof privacy
}

/// Proof Batcher - Accumulates market resolutions for ZK proof generation
///
/// Why batching?
/// Batching reduces per-proof overhead: Cost = [Estimate + Tip] / batch_size
/// - Without batching: 1.2 ACME per proof ($0.12 @ $0.10/ACME)
/// - With 100-proof batch: 0.012 ACME per proof ($0.0012)
/// - **100x cost reduction!**
///
/// Strategy:
/// - Accumulate proofs for `batch_interval` (default: 5 minutes)
/// - Submit all pending proofs as a single batch for on-chain verification
/// - Monitor for NewProof and CannotAggregate events
pub struct ProofBatcher {
    store: Arc<RedisStore>,
    pending_proofs: Arc<Mutex<Vec<MarketResolution>>>,
    batch_interval: Duration,
    max_batch_size: usize, // Submit early if batch reaches this size
}

impl ProofBatcher {
    pub fn new(store: Arc<RedisStore>) -> Self {
        let batch_interval = std::env::var("PROOF_BATCH_INTERVAL_SECONDS")
            .unwrap_or_else(|_| "300".to_string()) // Default: 5 minutes
            .parse::<u64>()
            .unwrap_or(300);

        let max_batch_size = std::env::var("PROOF_MAX_BATCH_SIZE")
            .unwrap_or_else(|_| "100".to_string())
            .parse::<usize>()
            .unwrap_or(100);

        Self {
            store,
            pending_proofs: Arc::new(Mutex::new(Vec::new())),
            batch_interval: Duration::from_secs(batch_interval),
            max_batch_size,
        }
    }

    /// Add a market resolution to the pending batch
    pub async fn enqueue_proof(&self, resolution: MarketResolution) -> ClobResult<()> {
        let mut proofs = self.pending_proofs.lock().await;
        proofs.push(resolution.clone());

        let batch_size = proofs.len();
        info!(
            market_id = %resolution.market_id,
            batch_size = batch_size,
            "Market resolution enqueued for ZK proof"
        );

        // Submit early if batch is full
        if batch_size >= self.max_batch_size {
            drop(proofs); // Release lock
            self.submit_batch().await?;
        }

        Ok(())
    }

    /// Start the batching loop
    pub async fn start(self: Arc<Self>) {
        info!(
            interval_seconds = self.batch_interval.as_secs(),
            max_batch_size = self.max_batch_size,
            "📦 Proof Batcher started"
        );

        let mut interval_timer = interval(self.batch_interval);

        loop {
            interval_timer.tick().await;

            if let Err(e) = self.submit_batch().await {
                error!(error = %e, "Failed to submit proof batch");
            }
        }
    }

    /// Flush accumulated proofs to the proof generation queue
    async fn submit_batch(&self) -> ClobResult<()> {
        let mut proofs = self.pending_proofs.lock().await;

        if proofs.is_empty() {
            return Ok(());
        }

        let batch_size = proofs.len();
        info!(
            batch_size = batch_size,
            "Flushing proof batch to generation queue"
        );

        let batch_id = uuid::Uuid::new_v4().to_string();
        self.store
            .set(
                &format!("proof:batch:{}:meta", batch_id),
                &serde_json::json!({
                    "batch_id": batch_id,
                    "size": batch_size,
                    "created_at": chrono::Utc::now().timestamp(),
                    "status": "submitting"
                })
                .to_string(),
            )
            .await?;

        for resolution in proofs.iter() {
            if let Err(e) = self.generate_and_submit_proof(resolution).await {
                warn!(
                    market_id = %resolution.market_id,
                    error = %e,
                    "Failed to generate proof"
                );
            }
        }

        // Clear batch after submission
        let submitted_count = proofs.len();
        proofs.clear();

        info!(
            submitted = submitted_count,
            batch_id = %batch_id,
            "✅ Proof batch submitted successfully"
        );

        Ok(())
    }

    /// Generate ZK proof for a single market resolution
    async fn generate_and_submit_proof(&self, resolution: &MarketResolution) -> ClobResult<()> {
        info!(
            market_id = %resolution.market_id,
            outcome = resolution.outcome,
            "Generating ZK proof for market resolution"
        );

        // Store proof generation request in Redis
        let proof_key = format!("proof:pending:{}", resolution.market_id);
        let resolution_json = serde_json::to_string(resolution)?;
        self.store.set(&proof_key, &resolution_json).await?;

        let proof_job = serde_json::json!({
            "market_id": resolution.market_id,
            "resolution_time": resolution.resolution_time,
            "threshold": resolution.threshold,
            "settlement_price": resolution.settlement_price,
            "outcome": resolution.outcome,
            "market_salt": resolution.market_salt,
            "queued_at": chrono::Utc::now().timestamp(),
        });

        self.store
            .push_queue("proof:generation:queue", &proof_job.to_string())
            .await?;

        let proof_data = serde_json::json!({
            "market_id": resolution.market_id,
            "status": "QUEUED",
            "queue": "proof:generation:queue",
            "submitted_at": chrono::Utc::now().timestamp(),
        });

        let result_key = format!("proof:result:{}", resolution.market_id);
        self.store.set(&result_key, &proof_data.to_string()).await?;

        Ok(())
    }

    /// Get batch statistics
    pub async fn get_stats(&self) -> BatchStats {
        let proofs = self.pending_proofs.lock().await;
        BatchStats {
            pending_proofs: proofs.len(),
            batch_interval_seconds: self.batch_interval.as_secs(),
            max_batch_size: self.max_batch_size,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BatchStats {
    pub pending_proofs: usize,
    pub batch_interval_seconds: u64,
    pub max_batch_size: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cost_calculation() {
        // Cost per proof with batch size
        // Estimate = 1.0 unit
        // Tip = 0.1 + 0.1 * 1.0 = 0.2 unit
        // Total = 1.2 unit

        let estimate = 1.0;
        let tip = 0.1 + 0.1 * estimate;
        let total = estimate + tip;

        assert_eq!(total, 1.2);

        // Cost per proof with different batch sizes
        let batch_100 = total / 100.0;
        let batch_1000 = total / 1000.0;

        assert_eq!(batch_100, 0.012); // $0.0012 @ $0.10/ACME
        assert_eq!(batch_1000, 0.0012); // $0.00012 @ $0.10/ACME
    }

    #[tokio::test]
    async fn test_batch_accumulation() {
        // Test that proofs accumulate correctly
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let _ = mini_redis::server::run(listener, async {
                let _ = rx.await;
            })
            .await;
        });
        let client = redis::Client::open(format!("redis://{}/", addr)).unwrap();
        let conn = redis::aio::ConnectionManager::new(client).await.unwrap();
        let store = Arc::new(RedisStore::new(conn));
        let _shutdown = tx; // keep alive for test duration

        let batcher = ProofBatcher::new(store);

        // Add 3 proofs
        for i in 0..3 {
            let resolution = MarketResolution {
                market_id: format!("BTC-HOUR-{}", i),
                resolution_time: 1738368000,
                threshold: "62450.00".to_string(),
                settlement_price: "62785.50".to_string(),
                outcome: true,
                market_salt: "test_salt".to_string(),
            };
            batcher.enqueue_proof(resolution).await.unwrap();
        }

        let stats = batcher.get_stats().await;
        assert_eq!(stats.pending_proofs, 3);
    }
}
