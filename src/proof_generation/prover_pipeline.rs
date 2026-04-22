use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::{
    error::{ClobError, ClobResult},
    redis_store::RedisStore,
};

const PROVER_QUEUE_PENDING: &str = "prover:jobs:pending";
const PROVER_QUEUE_RETRY: &str = "prover:jobs:retry";
const PROVER_JOB_PREFIX: &str = "prover:job:";
const PROVER_INPUT_PREFIX: &str = "prover:input:";
const PROVER_OUTPUT_PREFIX: &str = "prover:output:";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProverJobType {
    PrivateDeposit,
    PrivateOrderCommitment,
    PrivateTransferSettlement,
    PrivateMarketClaim,
    PrivateWithdraw,
    PrivateYieldDistribution,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProverJobStatus {
    Pending,
    Running,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProverJob {
    pub job_id: String,
    pub job_type: ProverJobType,
    pub circuit_name: String,
    pub input_key: String,
    pub status: ProverJobStatus,
    pub attempts: u8,
    pub last_error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub struct ProverPipeline {
    redis: Arc<RedisStore>,
    max_attempts: u8,
}

impl ProverPipeline {
    pub fn new(redis: Arc<RedisStore>, max_attempts: u8) -> Self {
        Self {
            redis,
            max_attempts: if max_attempts == 0 { 3 } else { max_attempts },
        }
    }

    pub async fn submit_job<T: Serialize>(
        &self,
        job_type: ProverJobType,
        circuit_name: impl Into<String>,
        input_payload: &T,
    ) -> ClobResult<ProverJob> {
        let job_id = Uuid::new_v4().to_string();
        let input_key = format!("{}{}", PROVER_INPUT_PREFIX, job_id);

        self.redis
            .set(&input_key, &serde_json::to_string(input_payload)?)
            .await?;

        let now = Utc::now();
        let job = ProverJob {
            job_id: job_id.clone(),
            job_type,
            circuit_name: circuit_name.into(),
            input_key,
            status: ProverJobStatus::Pending,
            attempts: 0,
            last_error: None,
            created_at: now,
            updated_at: now,
        };

        self.save_job(&job).await?;
        self.redis.push_queue(PROVER_QUEUE_PENDING, &job_id).await?;

        Ok(job)
    }

    pub async fn claim_next_job(&self) -> ClobResult<Option<ProverJob>> {
        let next_id = self
            .redis
            .pop_queue(PROVER_QUEUE_RETRY)
            .await?
            .or(self.redis.pop_queue(PROVER_QUEUE_PENDING).await?);

        let Some(job_id) = next_id else {
            return Ok(None);
        };

        let mut job = self
            .get_job(&job_id)
            .await?
            .ok_or_else(|| ClobError::OrderNotFound(format!("Prover job {} not found", job_id)))?;

        job.status = ProverJobStatus::Running;
        job.attempts = job.attempts.saturating_add(1);
        job.updated_at = Utc::now();
        self.save_job(&job).await?;

        Ok(Some(job))
    }

    pub async fn mark_completed(&self, job_id: &str, proof_output: &str) -> ClobResult<()> {
        let mut job = self
            .get_job(job_id)
            .await?
            .ok_or_else(|| ClobError::OrderNotFound(format!("Prover job {} not found", job_id)))?;

        job.status = ProverJobStatus::Completed;
        job.last_error = None;
        job.updated_at = Utc::now();
        self.save_job(&job).await?;

        let output_key = format!("{}{}", PROVER_OUTPUT_PREFIX, job_id);
        self.redis.set(&output_key, proof_output).await
    }

    pub async fn mark_failed(&self, job_id: &str, error: &str) -> ClobResult<()> {
        let mut job = self
            .get_job(job_id)
            .await?
            .ok_or_else(|| ClobError::OrderNotFound(format!("Prover job {} not found", job_id)))?;

        job.last_error = Some(error.to_string());
        job.updated_at = Utc::now();

        if job.attempts >= self.max_attempts {
            job.status = ProverJobStatus::Failed;
            self.save_job(&job).await
        } else {
            job.status = ProverJobStatus::Pending;
            self.save_job(&job).await?;
            self.redis.push_queue(PROVER_QUEUE_RETRY, job_id).await
        }
    }

    pub async fn get_job(&self, job_id: &str) -> ClobResult<Option<ProverJob>> {
        let key = format!("{}{}", PROVER_JOB_PREFIX, job_id);
        let payload = self.redis.get_optional(&key).await?;
        payload
            .map(|s| serde_json::from_str::<ProverJob>(&s).map_err(ClobError::from))
            .transpose()
    }

    pub async fn get_output(&self, job_id: &str) -> ClobResult<Option<String>> {
        let key = format!("{}{}", PROVER_OUTPUT_PREFIX, job_id);
        self.redis.get_optional(&key).await
    }
    /// Return the number of jobs currently waiting in the pending queue.
    pub async fn queue_depth(&self) -> ClobResult<i64> {
        self.redis.queue_depth(PROVER_QUEUE_PENDING).await
    }
    pub async fn get_input(&self, job_id: &str) -> ClobResult<Option<String>> {
        let job = self.get_job(job_id).await?;
        let Some(job) = job else {
            return Ok(None);
        };

        self.redis.get_optional(&job.input_key).await
    }

    async fn save_job(&self, job: &ProverJob) -> ClobResult<()> {
        let key = format!("{}{}", PROVER_JOB_PREFIX, job.job_id);
        self.redis.set(&key, &serde_json::to_string(job)?).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redis_store::RedisStore;
    use mini_redis::server;
    use tokio::sync::oneshot;

    async fn setup_pipeline(max_attempts: u8) -> (ProverPipeline, oneshot::Sender<()>) {
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
        let store = Arc::new(RedisStore::new(conn));
        (ProverPipeline::new(store, max_attempts), tx)
    }

    #[tokio::test]
    #[ignore = "requires RPUSH/LPOP — mini-redis 0.4.1 only implements GET/SET/PING (no list commands)"]
    async fn test_job_lifecycle_success() {
        let (pipeline, shutdown) = setup_pipeline(3).await;

        let payload = serde_json::json!({"foo": "bar"});
        let submitted = pipeline
            .submit_job(ProverJobType::PrivateDeposit, "private_deposit", &payload)
            .await
            .unwrap();

        let claimed = pipeline.claim_next_job().await.unwrap().unwrap();
        assert_eq!(claimed.job_id, submitted.job_id);
        assert_eq!(claimed.status, ProverJobStatus::Running);
        assert_eq!(claimed.attempts, 1);

        let input = pipeline.get_input(&claimed.job_id).await.unwrap().unwrap();
        assert!(input.contains("foo"));

        pipeline
            .mark_completed(&claimed.job_id, r#"{"proof":"ok"}"#)
            .await
            .unwrap();

        let stored = pipeline.get_job(&claimed.job_id).await.unwrap().unwrap();
        assert_eq!(stored.status, ProverJobStatus::Completed);
        assert!(pipeline.get_output(&claimed.job_id).await.unwrap().is_some());

        let _ = shutdown.send(());
    }

    #[tokio::test]
    #[ignore = "requires RPUSH/LPOP — mini-redis 0.4.1 only implements GET/SET/PING (no list commands)"]
    async fn test_job_retries_and_terminal_failure() {
        let (pipeline, shutdown) = setup_pipeline(2).await;

        let payload = serde_json::json!({"x": 1});
        let submitted = pipeline
            .submit_job(ProverJobType::PrivateWithdraw, "private_withdraw", &payload)
            .await
            .unwrap();

        let first = pipeline.claim_next_job().await.unwrap().unwrap();
        assert_eq!(first.attempts, 1);
        pipeline.mark_failed(&first.job_id, "boom1").await.unwrap();

        let second = pipeline.claim_next_job().await.unwrap().unwrap();
        assert_eq!(second.job_id, submitted.job_id);
        assert_eq!(second.attempts, 2);
        pipeline.mark_failed(&second.job_id, "boom2").await.unwrap();

        let terminal = pipeline.get_job(&submitted.job_id).await.unwrap().unwrap();
        assert_eq!(terminal.status, ProverJobStatus::Failed);
        assert_eq!(terminal.last_error.as_deref(), Some("boom2"));

        let _ = shutdown.send(());
    }
}
