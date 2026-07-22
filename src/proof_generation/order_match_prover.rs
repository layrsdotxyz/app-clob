use crate::{
    error::{ClobError, ClobResult},
    models::Trade,
    proof_generation::OrderMatchProofData,
    redis_store::RedisStore,
};
use std::sync::Arc;
use tracing::warn;

pub const ORDER_MATCH_UNSUPPORTED_MESSAGE: &str = "Epoch ORDER_MATCH proof generation is unavailable in this build: the legacy Groth16 Circom artifacts and the Node/snarkjs toolchain are not shipped. Track a Noir ORDER_MATCH circuit as a separate feature workstream.";

pub struct OrderMatchProver {
    _redis: Arc<RedisStore>,
}

impl OrderMatchProver {
    pub fn new(redis: Arc<RedisStore>) -> Self {
        Self { _redis: redis }
    }

    pub async fn generate_order_match_proof(
        &self,
        epoch_id: u64,
        market_id: &str,
        trades: &[Trade],
    ) -> ClobResult<OrderMatchProofData> {
        warn!(
            epoch_id,
            market_id,
            num_trades = trades.len(),
            reason = ORDER_MATCH_UNSUPPORTED_MESSAGE,
            "Deprecated ORDER_MATCH proof requested"
        );

        Err(ClobError::ServiceUnavailable(
            ORDER_MATCH_UNSUPPORTED_MESSAGE.to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redis_store::RedisStore;
    use mini_redis::server;
    use std::sync::Arc;
    use tokio::sync::oneshot;

    async fn make_redis() -> (Arc<RedisStore>, oneshot::Sender<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            let _ = server::run(listener, async {
                let _ = rx.await;
            })
            .await;
        });
        let client = redis::Client::open(format!("redis://{}/", addr)).unwrap();
        let conn = redis::aio::ConnectionManager::new(client).await.unwrap();
        (Arc::new(RedisStore::new(conn)), tx)
    }

    #[tokio::test]
    async fn test_order_match_prover_returns_explicit_unsupported_error() {
        let (redis, _shutdown) = make_redis().await;
        let prover = OrderMatchProver::new(redis);
        let error = prover
            .generate_order_match_proof(1, "BTC-USD", &[])
            .await
            .unwrap_err();

        assert!(matches!(error, ClobError::ServiceUnavailable(_)));
        assert!(format!("{error}").contains("ORDER_MATCH proof generation is unavailable"));
    }
}
