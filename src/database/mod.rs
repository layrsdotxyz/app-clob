use crate::error::{ClobError, ClobResult};
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use std::time::Duration;
use uuid::Uuid;

#[derive(Clone)]
pub struct Database {
    pool: PgPool,
}

impl Database {
    pub async fn connect(database_url: &str) -> ClobResult<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .acquire_timeout(Duration::from_secs(5))
            .connect(database_url)
            .await
            .map_err(|e| ClobError::Internal(format!("database connect error: {}", e)))?;

        Ok(Self { pool })
    }

    pub async fn migrate(&self) -> ClobResult<()> {
        let pool: &PgPool = &self.pool;
        sqlx::migrate!("./migrations")
            .run(pool)
            .await
            .map_err(|e| ClobError::Internal(format!("database migration error: {}", e)))
    }

    pub async fn health_check(&self) -> ClobResult<()> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map_err(|e| ClobError::Internal(format!("database health check failed: {}", e)))?;
        Ok(())
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn get_user_id_by_wallet(&self, wallet: &str) -> ClobResult<Option<String>> {
        let wallet_str = wallet.to_lowercase();
        let row = sqlx::query("SELECT user_id FROM users WHERE evm_address = $1")
            .bind(wallet_str)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| ClobError::Internal(format!("get user by wallet failed: {}", e)))?;

        Ok(row.map(|r| r.get::<Uuid, _>("user_id").to_string()))
    }

    pub async fn get_or_create_user_id_by_wallet(&self, wallet: &str) -> ClobResult<String> {
        if let Some(user_id) = self.get_user_id_by_wallet(wallet).await? {
            return Ok(user_id);
        }

        let wallet_str = wallet.to_lowercase();
        let user_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO users (user_id, evm_address, created_at) VALUES ($1, $2, NOW()) \
             ON CONFLICT (evm_address) DO NOTHING",
        )
        .bind(user_id)
        .bind(wallet_str)
        .execute(&self.pool)
        .await
        .map_err(|e| ClobError::Internal(format!("create user failed: {}", e)))?;

        if let Some(found) = self.get_user_id_by_wallet(wallet).await? {
            Ok(found)
        } else {
            Ok(user_id.to_string())
        }
    }

    pub async fn get_last_processed_block(&self, chain_id: i64) -> ClobResult<u64> {
        let row = sqlx::query("SELECT last_block FROM deposit_checkpoints WHERE chain_id = $1")
            .bind(chain_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| ClobError::Internal(format!("get checkpoint failed: {}", e)))?;

        Ok(row
            .map(|r| r.get::<i64, _>("last_block") as u64)
            .unwrap_or(0))
    }

    pub async fn save_last_processed_block(&self, chain_id: i64, block_number: i64) -> ClobResult<()> {
        sqlx::query(
            "INSERT INTO deposit_checkpoints (chain_id, last_block, updated_at)
             VALUES ($1, $2, NOW())
             ON CONFLICT (chain_id)
             DO UPDATE SET last_block = EXCLUDED.last_block, updated_at = NOW()",
        )
        .bind(chain_id)
        .bind(block_number)
        .execute(&self.pool)
        .await
        .map_err(|e| ClobError::Internal(format!("save checkpoint failed: {}", e)))?;

        Ok(())
    }

    pub async fn is_deposit_processed(&self, chain_id: i64, tx_hash: &str) -> ClobResult<bool> {
        let row = sqlx::query("SELECT 1 FROM processed_deposits WHERE chain_id = $1 AND tx_hash = $2 LIMIT 1")
            .bind(chain_id)
            .bind(tx_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| ClobError::Internal(format!("deposit processed lookup failed: {}", e)))?;

        Ok(row.is_some())
    }

    pub async fn mark_deposit_processed(
        &self,
        chain_id: i64,
        tx_hash: &str,
        user_wallet: &str,
        token: &str,
        amount: &str,
        block_number: i64,
    ) -> ClobResult<()> {
        sqlx::query(
            "INSERT INTO processed_deposits (chain_id, tx_hash, user_wallet, token, amount, block_number, processed_at)
             VALUES ($1, $2, $3, $4, $5, $6, NOW())
             ON CONFLICT (chain_id, tx_hash) DO NOTHING",
        )
        .bind(chain_id)
        .bind(tx_hash)
        .bind(user_wallet)
        .bind(token)
        .bind(amount)
        .bind(block_number)
        .execute(&self.pool)
        .await
        .map_err(|e| ClobError::Internal(format!("mark deposit processed failed: {}", e)))?;

        Ok(())
    }

    pub async fn get_wallet_nonce(&self, wallet: &str) -> ClobResult<u64> {
        let wallet_str = wallet.to_lowercase();
        let row = sqlx::query("SELECT nonce FROM user_nonces WHERE wallet = $1")
            .bind(wallet_str)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| ClobError::Internal(format!("get nonce failed: {}", e)))?;

        Ok(row.map(|r| r.get::<i64, _>("nonce") as u64).unwrap_or(0))
    }

    pub async fn increment_wallet_nonce(&self, wallet: &str) -> ClobResult<u64> {
        let wallet_str = wallet.to_lowercase();
        let row = sqlx::query(
            "INSERT INTO user_nonces (wallet, nonce, updated_at) VALUES ($1, 1, NOW())
             ON CONFLICT (wallet)
             DO UPDATE SET nonce = user_nonces.nonce + 1, updated_at = NOW()
             RETURNING nonce",
        )
        .bind(wallet_str)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| ClobError::Internal(format!("increment nonce failed: {}", e)))?;

        Ok(row.get::<i64, _>("nonce") as u64)
    }

    pub async fn create_withdrawal_request(
        &self,
        withdrawal_id: &str,
        user_id: &str,
        tx_hash: Option<&str>,
        token: &str,
        amount: &str,
        destination_address: &str,
        status: &str,
    ) -> ClobResult<()> {
        let user_uuid = Uuid::parse_str(user_id)
            .map_err(|e| ClobError::InvalidOrder(format!("invalid user_id uuid: {}", e)))?;

        sqlx::query(
            "INSERT INTO withdrawals (withdrawal_id, user_id, transaction_hash, token_address, amount, destination_address, status, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())",
        )
        .bind(withdrawal_id)
        .bind(user_uuid)
        .bind(tx_hash)
        .bind(token)
        .bind(amount)
        .bind(destination_address)
        .bind(status)
        .execute(&self.pool)
        .await
        .map_err(|e| ClobError::Internal(format!("create withdrawal request failed: {}", e)))?;

        Ok(())
    }

    pub async fn update_withdrawal_status(
        &self,
        withdrawal_id: &str,
        status: &str,
        tx_hash: Option<&str>,
    ) -> ClobResult<()> {
        sqlx::query(
            "UPDATE withdrawals SET status = $2, transaction_hash = COALESCE($3, transaction_hash), updated_at = NOW() WHERE withdrawal_id = $1",
        )
        .bind(withdrawal_id)
        .bind(status)
        .bind(tx_hash)
        .execute(&self.pool)
        .await
        .map_err(|e| ClobError::Internal(format!("update withdrawal status failed: {}", e)))?;

        Ok(())
    }
}
