#![allow(dead_code)]

use crate::{
    error::ClobResult,
    orderbook::OrderBookManager,
    proof_generation::{OrderMatchProver, ProverJobType, ProverPipeline},
    redis_store::RedisStore,
    metrics::Metrics,
};
use std::sync::Arc;
use tokio::time::{interval, Duration};
use tracing::{error, info, warn};

/// Epoch service that triggers proof generation on epoch boundaries
pub struct EpochService {
    orderbook: Arc<OrderBookManager>,
    prover: Arc<OrderMatchProver>,
    redis_store: Arc<RedisStore>,
    metrics: Arc<Metrics>,
    epoch_duration: Duration,
    current_epoch: u64,
    /// Optional privacy prover pipeline — queues a PrivateYieldDistribution job per market each epoch.
    prover_pipeline: Option<Arc<ProverPipeline>>,
}

impl EpochService {
    pub fn new(
        orderbook: Arc<OrderBookManager>,
        prover: Arc<OrderMatchProver>,
        redis_store: Arc<RedisStore>,
        metrics: Arc<Metrics>,
        epoch_duration_secs: u64,
    ) -> Self {
        Self {
            orderbook,
            prover,
            redis_store,
            metrics,
            epoch_duration: Duration::from_secs(epoch_duration_secs),
            current_epoch: 0,
            prover_pipeline: None,
        }
    }

    /// Attach a privacy prover pipeline to trigger PrivateYieldDistribution jobs each epoch.
    pub fn with_prover_pipeline(mut self, pipeline: Arc<ProverPipeline>) -> Self {
        self.prover_pipeline = Some(pipeline);
        self
    }

    /// Start the epoch timer service
    pub async fn start(&mut self) -> ClobResult<()> {
        info!(
            epoch_duration_secs = self.epoch_duration.as_secs(),
            "Starting epoch service"
        );

        let mut interval = interval(self.epoch_duration);

        loop {
            interval.tick().await;
            self.current_epoch += 1;

            info!(
                epoch_id = self.current_epoch,
                "Epoch boundary reached, triggering proof generation"
            );

            match self.process_epoch().await {
                Ok(_) => {
                    info!(
                        epoch_id = self.current_epoch,
                        "Epoch processed successfully"
                    );
                }
                Err(e) => {
                    error!(
                        epoch_id = self.current_epoch,
                        error = %e,
                        "Failed to process epoch"
                    );
                    // Continue to next epoch even if this one fails
                }
            }
        }
    }

    /// Process epoch boundary: collect fills and generate ORDER_MATCH proof
    async fn process_epoch(&self) -> ClobResult<()> {
        // Get all markets
        let markets = self.orderbook.list_markets().await?;
        
        for market_id in markets {
            match self.process_market_epoch(&market_id).await {
                Ok(_) => {
                    info!(
                        epoch_id = self.current_epoch,
                        market_id = %market_id,
                        "Market epoch processed"
                    );
                }
                Err(e) => {
                    warn!(
                        epoch_id = self.current_epoch,
                        market_id = %market_id,
                        error = %e,
                        "Failed to process market epoch"
                    );
                }
            }
        }

        Ok(())
    }

    /// Process single market for current epoch
    async fn process_market_epoch(&self, market_id: &str) -> ClobResult<()> {
        // Get epoch trades
        let trades = self.orderbook.get_epoch_trades(market_id, self.current_epoch).await?;
        
        if trades.is_empty() {
            info!(
                epoch_id = self.current_epoch,
                market_id = %market_id,
                "No trades in epoch, skipping proof generation"
            );
            return Ok(());
        }

        info!(
            epoch_id = self.current_epoch,
            market_id = %market_id,
            num_trades = trades.len(),
            "Generating ORDER_MATCH proof"
        );

        // Generate proof
        let proof_data = self.prover.generate_order_match_proof(
            self.current_epoch,
            market_id,
            &trades,
        ).await?;

        info!(
            epoch_id = self.current_epoch,
            market_id = %market_id,
            proof_id = ?proof_data.proof_id,
            "ORDER_MATCH proof generated and submitted"
        );

        // Trigger PrivateYieldDistribution job if the privacy prover pipeline is wired
        if let Some(pp) = &self.prover_pipeline {
            let payload = serde_json::json!({
                "epoch_id": self.current_epoch,
                "market_id": market_id,
                "num_trades": trades.len(),
            });
            match pp.submit_job(
                ProverJobType::PrivateYieldDistribution,
                "private_yield_distribution",
                &payload,
            ).await {
                Ok(job) => info!(
                    epoch_id = self.current_epoch,
                    market_id = %market_id,
                    job_id = %job.job_id,
                    "PrivateYieldDistribution job submitted"
                ),
                Err(e) => warn!(
                    epoch_id = self.current_epoch,
                    market_id = %market_id,
                    error = %e,
                    "Failed to submit PrivateYieldDistribution job"
                ),
            }
        }

        Ok(())
    }

    pub fn get_current_epoch(&self) -> u64 {
        self.current_epoch
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orderbook::OrderBookManager;
    use crate::proof_generation::OrderMatchProver;
    use crate::redis_store::RedisStore;
    use crate::metrics::Metrics;
    use mini_redis::server;
    use std::sync::Arc;
    use tokio::sync::oneshot;

    async fn make_redis() -> (Arc<RedisStore>, oneshot::Sender<()>) {
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
    async fn test_epoch_service_creation() {
        let (redis, _shutdown) = make_redis().await;
        let metrics = Metrics::test_instance();
        let orderbook = Arc::new(OrderBookManager::new(redis.clone(), metrics.clone(), None));
        let prover = Arc::new(OrderMatchProver::new(redis.clone()));

        let service = EpochService::new(
            orderbook,
            prover,
            redis.clone(),
            metrics,
            300,
        );
        assert_eq!(service.current_epoch, 0);
        assert_eq!(service.epoch_duration.as_secs(), 300);
    }
}
