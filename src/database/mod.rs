use crate::{
    error::{ClobError, ClobResult},
    models::{Fill, Order, OrderStatus, PublicMarketMetadata, Trade},
};
use rust_decimal::Decimal;
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use std::time::Duration;
use uuid::Uuid;

fn slugify_fragment(input: &str) -> String {
    let mut slug = String::with_capacity(input.len());
    let mut last_was_dash = false;

    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
            last_was_dash = false;
        } else if !last_was_dash && !slug.is_empty() {
            slug.push('-');
            last_was_dash = true;
        }
    }

    while slug.ends_with('-') {
        slug.pop();
    }

    if slug.is_empty() {
        "market".to_string()
    } else {
        slug
    }
}

fn market_asset_symbol(market_id: &str) -> Option<String> {
    market_id
        .split('-')
        .next()
        .filter(|segment| !segment.is_empty())
        .map(|segment| segment.to_ascii_uppercase())
}

fn market_metadata_from_row(row: &sqlx::postgres::PgRow) -> PublicMarketMetadata {
    let market_id = row.get::<String, _>("market_id");
    let description = row
        .try_get::<Option<String>, _>("description")
        .ok()
        .flatten()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| market_id.clone());
    let on_chain_market_id = row.try_get::<Option<i64>, _>("on_chain_market_id").ok().flatten();
    let slug = row
        .try_get::<Option<String>, _>("slug")
        .ok()
        .flatten()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| generate_market_slug(&description, &market_id, on_chain_market_id));
    let expiry_ts = row
        .try_get::<Option<chrono::NaiveDateTime>, _>("expiry")
        .ok()
        .flatten()
        .map(|value| value.and_utc().timestamp().max(0) as u64);
    let status = row
        .try_get::<Option<String>, _>("status")
        .ok()
        .flatten()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "open".to_string());
    let source = row.try_get::<Option<String>, _>("source").ok().flatten();

    PublicMarketMetadata {
        market_id: market_id.clone(),
        slug,
        question: description,
        expiry_ts,
        status,
        source,
        on_chain_market_id,
        asset_symbol: market_asset_symbol(&market_id),
    }
}

pub fn generate_market_slug(
    description: &str,
    market_id: &str,
    on_chain_market_id: Option<i64>,
) -> String {
    let base_input = if description.trim().is_empty() {
        market_id
    } else {
        description
    };
    let mut base = slugify_fragment(base_input);
    if base.len() > 96 {
        base.truncate(96);
        while base.ends_with('-') {
            base.pop();
        }
    }

    let suffix = on_chain_market_id
        .map(|value| value.to_string())
        .unwrap_or_else(|| slugify_fragment(market_id));

    if base == suffix {
        base
    } else {
        format!("{base}-{suffix}")
    }
}

#[cfg(test)]
mod tests {
    use super::generate_market_slug;

    #[test]
    fn market_slug_uses_human_readable_question_with_unique_suffix() {
        let slug = generate_market_slug(
            "Will BTC close above $95,000 at Unix 1714148100?",
            "BTC-160",
            Some(160),
        );

        assert_eq!(slug, "will-btc-close-above-95-000-at-unix-1714148100-160");
    }

    #[test]
    fn market_slug_falls_back_to_market_id_without_duplicate_suffix() {
        let slug = generate_market_slug("", "BTC-160", None);

        assert_eq!(slug, "btc-160");
    }
}

#[derive(Debug, Clone)]
pub struct PersistedOracleMarket {
    pub market_id: String,
    pub on_chain_market_id: u64,
    pub expiry_ts: u64,
}

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

    // ==================== Trade + Fill persistence ====================

    /// Persist a trade.  Idempotent — duplicate trade IDs are silently ignored.
    pub async fn save_trade(&self, trade: &Trade) -> ClobResult<()> {
        let side_str = format!("{:?}", trade.side).to_lowercase();
        let settlement_tx = trade.settlement_tx.map(|h| format!("{:?}", h));

        sqlx::query(
            "INSERT INTO trades
                (id, market_id, maker_order_id, taker_order_id, maker_user_id, taker_user_id,
                 side, price, size, settlement_tx, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(trade.id)
        .bind(&trade.market_id)
        .bind(trade.maker_order_id)
        .bind(trade.taker_order_id)
        .bind(&trade.maker_user_id)
        .bind(&trade.taker_user_id)
        .bind(side_str)
        .bind(trade.price)
        .bind(trade.size)
        .bind(settlement_tx)
        .bind(trade.timestamp.naive_utc())
        .execute(&self.pool)
        .await
        .map_err(|e| ClobError::Internal(format!("save_trade failed: {}", e)))?;

        Ok(())
    }

    /// Persist a fill.  Idempotent — duplicate fill IDs are silently ignored.
    pub async fn save_fill(&self, fill: &Fill) -> ClobResult<()> {
        sqlx::query(
            "INSERT INTO fills (id, order_id, trade_id, price, size, fee, is_maker, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(fill.id)
        .bind(fill.order_id)
        .bind(fill.trade_id)
        .bind(fill.price)
        .bind(fill.size)
        .bind(fill.fee)
        .bind(fill.is_maker)
        .bind(fill.timestamp.naive_utc())
        .execute(&self.pool)
        .await
        .map_err(|e| ClobError::Internal(format!("save_fill failed: {}", e)))?;

        Ok(())
    }

    // ==================== Order persistence ====================

    /// Insert or update an order row.
    pub async fn upsert_order(&self, order: &Order) -> ClobResult<()> {
        let status_str = format!("{:?}", order.status).to_lowercase();
        let side_str = format!("{:?}", order.side).to_lowercase();
        let type_str = format!("{:?}", order.order_type).to_lowercase();

        let user_uuid = Uuid::parse_str(&order.user_id).unwrap_or_else(|_| Uuid::new_v4());

        sqlx::query(
            "INSERT INTO orders
                (order_id, user_id, market_id, side, price, amount, status, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
             ON CONFLICT (order_id)
             DO UPDATE SET
                 status     = EXCLUDED.status,
                 amount     = EXCLUDED.amount,
                 updated_at = EXCLUDED.updated_at",
        )
        .bind(order.id.to_string())
        .bind(user_uuid)
        .bind(&order.market_id)
        .bind(format!("{}-{}", side_str, type_str))
        .bind(order.price)
        .bind(order.size)
        .bind(status_str)
        .bind(order.created_at.naive_utc())
        .bind(order.updated_at.naive_utc())
        .execute(&self.pool)
        .await
        .map_err(|e| ClobError::Internal(format!("upsert_order failed: {}", e)))?;

        Ok(())
    }

    /// Update status, filled, and remaining on an existing order row.
    pub async fn update_order_status(
        &self,
        order_id: Uuid,
        status: &OrderStatus,
        filled: Decimal,
        remaining: Decimal,
    ) -> ClobResult<()> {
        let status_str = format!("{:?}", status).to_lowercase();
        // remaining is stored in the `amount` column (current outstanding quantity)
        sqlx::query(
            "UPDATE orders
             SET status = $2, amount = $3, updated_at = NOW()
             WHERE order_id = $1",
        )
        .bind(order_id.to_string())
        .bind(status_str)
        .bind(remaining)
        .execute(&self.pool)
        .await
        .map_err(|e| ClobError::Internal(format!("update_order_status failed: {}", e)))?;

        let _ = filled; // tracked per-fills row; kept in signature for clarity
        Ok(())
    }

    // ==================== Market persistence ====================

    /// Insert or update a market row (called on market creation).
    #[allow(clippy::too_many_arguments)]
    pub async fn upsert_market(
        &self,
        market_id: &str,
        description: &str,
        expiry_ts: u64,
        status: &str,
        oracle_address: Option<&str>,
        strike_price: Option<Decimal>,
        currency: Option<&str>,
        vault_address: Option<&str>,
        source: Option<&str>,
        on_chain_market_id: Option<i64>,
    ) -> ClobResult<()> {
        let expiry_dt = chrono::DateTime::from_timestamp(expiry_ts as i64, 0)
            .unwrap_or_else(chrono::Utc::now)
            .naive_utc();
        let slug = generate_market_slug(description, market_id, on_chain_market_id);

        sqlx::query(
            "INSERT INTO markets
                (market_id, description, expiry, oracle_address, status,
                 strike_price, currency, vault_address, source, on_chain_market_id,
                 slug,
                 created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW(), NOW())
             ON CONFLICT (market_id)
             DO UPDATE SET
                 description        = EXCLUDED.description,
                 expiry             = EXCLUDED.expiry,
                 status             = EXCLUDED.status,
                 strike_price       = COALESCE(EXCLUDED.strike_price, markets.strike_price),
                 currency           = COALESCE(EXCLUDED.currency, markets.currency),
                 vault_address      = COALESCE(EXCLUDED.vault_address, markets.vault_address),
                 source             = COALESCE(EXCLUDED.source, markets.source),
                 on_chain_market_id = COALESCE(EXCLUDED.on_chain_market_id, markets.on_chain_market_id),
                 slug               = COALESCE(markets.slug, EXCLUDED.slug),
                 updated_at         = NOW()",
        )
        .bind(market_id)
        .bind(description)
        .bind(expiry_dt)
        .bind(oracle_address)
        .bind(status)
        .bind(strike_price)
        .bind(currency)
        .bind(vault_address)
        .bind(source)
        .bind(on_chain_market_id)
        .bind(slug)
        .execute(&self.pool)
        .await
        .map_err(|e| ClobError::Internal(format!("upsert_market failed: {}", e)))?;

        Ok(())
    }

    /// Update market status and resolution price after oracle resolution.
    pub async fn update_market_resolution(
        &self,
        market_id: &str,
        resolution_price: Decimal,
        status: &str,
    ) -> ClobResult<()> {
        sqlx::query(
            "UPDATE markets
             SET resolution_price = $2, status = $3, updated_at = NOW()
             WHERE market_id = $1",
        )
        .bind(market_id)
        .bind(resolution_price)
        .bind(status)
        .execute(&self.pool)
        .await
        .map_err(|e| ClobError::Internal(format!("update_market_resolution failed: {}", e)))?;

        Ok(())
    }

    pub async fn get_public_market_metadata(
        &self,
        market_id: &str,
    ) -> ClobResult<Option<PublicMarketMetadata>> {
        let row = sqlx::query(
            "SELECT market_id, slug, description, expiry, status, source, on_chain_market_id
             FROM markets
             WHERE market_id = $1",
        )
        .bind(market_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ClobError::Internal(format!("get_public_market_metadata failed: {}", e)))?;

        Ok(row.as_ref().map(market_metadata_from_row))
    }

    pub async fn get_public_market_metadata_by_slug(
        &self,
        slug: &str,
    ) -> ClobResult<Option<PublicMarketMetadata>> {
        let row = sqlx::query(
            "SELECT market_id, slug, description, expiry, status, source, on_chain_market_id
             FROM markets
             WHERE slug = $1",
        )
        .bind(slug)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ClobError::Internal(format!("get_public_market_metadata_by_slug failed: {}", e)))?;

        Ok(row.as_ref().map(market_metadata_from_row))
    }

    pub async fn get_expired_active_pyth_markets(
        &self,
        asset: &str,
        now_ts: u64,
    ) -> ClobResult<Vec<PersistedOracleMarket>> {
        let expiry_cutoff = chrono::DateTime::from_timestamp(now_ts as i64, 0)
            .unwrap_or_else(chrono::Utc::now)
            .naive_utc();
        let asset_prefix = format!("{asset}-%");

        let rows = sqlx::query(
            "SELECT market_id, on_chain_market_id, expiry
             FROM markets
             WHERE source = 'pyth'
               AND status = 'active'
               AND expiry IS NOT NULL
               AND expiry <= $1
               AND market_id LIKE $2
             ORDER BY expiry ASC, market_id ASC",
        )
        .bind(expiry_cutoff)
        .bind(asset_prefix)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ClobError::Internal(format!("get_expired_active_pyth_markets failed: {}", e)))?;

        let mut persisted = Vec::with_capacity(rows.len());
        for row in rows {
            let market_id = row.get::<String, _>("market_id");
            let on_chain_market_id = row
                .try_get::<Option<i64>, _>("on_chain_market_id")
                .ok()
                .flatten()
                .and_then(|value| u64::try_from(value).ok())
                .or_else(|| {
                    market_id
                        .rsplit('-')
                        .next()
                        .and_then(|value| value.parse::<u64>().ok())
                })
                .ok_or_else(|| {
                    ClobError::Internal(format!(
                        "active pyth market {} is missing a usable on_chain_market_id",
                        market_id
                    ))
                })?;
            let expiry_ts = row
                .try_get::<Option<chrono::NaiveDateTime>, _>("expiry")
                .ok()
                .flatten()
                .map(|value| value.and_utc().timestamp().max(0) as u64)
                .ok_or_else(|| {
                    ClobError::Internal(format!(
                        "active pyth market {} is missing expiry",
                        market_id
                    ))
                })?;

            persisted.push(PersistedOracleMarket {
                market_id,
                on_chain_market_id,
                expiry_ts,
            });
        }

        Ok(persisted)
    }

    // ==================== Balance persistence ====================

    /// Upsert a user's balance for a given token (market_id used as token_address key).
    /// `total` is the gross balance; `reserved` is the portion locked in open orders.
    pub async fn upsert_balance(
        &self,
        user_id: &str,
        token_address: &str,
        total: Decimal,
        reserved: Decimal,
    ) -> ClobResult<()> {
        // Convert Decimal → i64 scaled by 1e18 for the NUMERIC(78,0) column.
        // We store the raw string representation to avoid precision loss.
        let total_scaled = (total * Decimal::from(1_000_000_000_000_000_000u64))
            .round()
            .to_string();
        let reserved_scaled = (reserved * Decimal::from(1_000_000_000_000_000_000u64))
            .round()
            .to_string();

        // Resolve user_id to UUID if possible, otherwise look it up.
        let user_uuid = if let Ok(u) = Uuid::parse_str(user_id) {
            u
        } else {
            // wallet address — look up or create
            return self
                .upsert_balance_by_wallet(user_id, token_address, total, reserved)
                .await;
        };

        self.upsert_balance_sql(user_uuid, token_address, &total_scaled, &reserved_scaled)
            .await
    }

    /// Variant for wallet-addressed users (resolves wallet → user_id first).
    async fn upsert_balance_by_wallet(
        &self,
        wallet: &str,
        token_address: &str,
        total: Decimal,
        reserved: Decimal,
    ) -> ClobResult<()> {
        let user_id_str = self.get_or_create_user_id_by_wallet(wallet).await?;
        let user_uuid = Uuid::parse_str(&user_id_str)
            .map_err(|e| ClobError::Internal(format!("invalid uuid from db: {}", e)))?;
        let total_scaled = (total * Decimal::from(1_000_000_000_000_000_000u64))
            .round()
            .to_string();
        let reserved_scaled = (reserved * Decimal::from(1_000_000_000_000_000_000u64))
            .round()
            .to_string();
        self.upsert_balance_sql(user_uuid, token_address, &total_scaled, &reserved_scaled)
            .await
    }

    /// Execute the actual balance upsert SQL (takes pre-scaled string values and a resolved UUID).
    async fn upsert_balance_sql(
        &self,
        user_uuid: Uuid,
        token_address: &str,
        total_scaled: &str,
        reserved_scaled: &str,
    ) -> ClobResult<()> {
        sqlx::query(
            "INSERT INTO balances (user_id, token_address, balance, reserved, updated_at)
             VALUES ($1, $2, $3::NUMERIC, $4::NUMERIC, NOW())
             ON CONFLICT (user_id, token_address)
             DO UPDATE SET
                 balance    = EXCLUDED.balance,
                 reserved   = EXCLUDED.reserved,
                 updated_at = NOW()",
        )
        .bind(user_uuid)
        .bind(token_address)
        .bind(total_scaled)
        .bind(reserved_scaled)
        .execute(&self.pool)
        .await
        .map_err(|e| ClobError::Internal(format!("upsert_balance failed: {}", e)))?;

        Ok(())
    }

    /// Load all balances from DB into a Vec of (user_id_str, token_address, total, reserved).
    /// Used on startup to re-populate the in-memory BalanceService.
    pub async fn load_all_balances(
        &self,
    ) -> ClobResult<Vec<(String, String, Decimal, Decimal)>> {
        let rows = sqlx::query(
            "SELECT u.user_id::text, b.token_address,
                    b.balance::text, b.reserved::text
             FROM balances b
             JOIN users u ON u.user_id = b.user_id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ClobError::Internal(format!("load_all_balances failed: {}", e)))?;

        let mut result = Vec::with_capacity(rows.len());
        for row in rows {
            let user_id: String = row.get("user_id");
            let token: String = row.get("token_address");
            let balance_str: String = row.get("balance");
            let reserved_str: String = row.get("reserved");

            // Convert from 1e18-scaled integer string back to Decimal
            let scale = Decimal::from(1_000_000_000_000_000_000u64);
            let total = balance_str
                .parse::<Decimal>()
                .unwrap_or(Decimal::ZERO)
                / scale;
            let reserved = reserved_str
                .parse::<Decimal>()
                .unwrap_or(Decimal::ZERO)
                / scale;

            result.push((user_id, token, total, reserved));
        }

        Ok(result)
    }
}
