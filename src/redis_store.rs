use crate::{error::ClobResult, models::*};
use chrono::Utc;
use redis::{aio::ConnectionManager, AsyncCommands, Script};
use rust_decimal::Decimal;
use std::collections::HashMap;
use uuid::Uuid;

/// Redis key prefixes
const ORDER_PREFIX: &str = "order:";
const ORDERBOOK_BID_PREFIX: &str = "ob:bid:";
const ORDERBOOK_ASK_PREFIX: &str = "ob:ask:";
const USER_ORDERS_PREFIX: &str = "user:orders:";
const MARKET_TRADES_PREFIX: &str = "market:trades:";
const USER_TRADES_PREFIX: &str = "user:trades:";
const MARKET_STATS_PREFIX: &str = "market:stats:";

pub struct RedisStore {
    conn: ConnectionManager,
}

impl RedisStore {
    pub fn new(conn: ConnectionManager) -> Self {
        Self { conn }
    }

    // ==================== Generic KV Operations ====================

    pub async fn get(&self, key: &str) -> ClobResult<String> {
        let mut conn = self.conn.clone();
        let value: Option<String> = conn.get(key).await?;
        Ok(value.unwrap_or_default())
    }

    pub async fn set(&self, key: &str, value: &str) -> ClobResult<()> {
        let mut conn = self.conn.clone();
        conn.set::<_, _, ()>(key, value).await?;
        Ok(())
    }

    pub async fn get_optional(&self, key: &str) -> ClobResult<Option<String>> {
        let mut conn = self.conn.clone();
        let value: Option<String> = conn.get(key).await?;
        Ok(value)
    }

    pub async fn append_json_array_value(&self, key: &str, value: &str) -> ClobResult<()> {
        let mut conn = self.conn.clone();
        let existing: Option<String> = conn.get(key).await?;
        let mut values: Vec<String> = existing
            .as_deref()
            .and_then(|s| serde_json::from_str::<Vec<String>>(s).ok())
            .unwrap_or_default();

        if !values.iter().any(|v| v == value) {
            values.push(value.to_string());
        }

        let payload = serde_json::to_string(&values)?;
        conn.set::<_, _, ()>(key, payload).await?;
        Ok(())
    }

    pub async fn get_json_array_values(&self, key: &str, limit: usize) -> ClobResult<Vec<String>> {
        let mut conn = self.conn.clone();
        let existing: Option<String> = conn.get(key).await?;
        let values: Vec<String> = existing
            .as_deref()
            .and_then(|s| serde_json::from_str::<Vec<String>>(s).ok())
            .unwrap_or_default();

        if values.len() <= limit {
            return Ok(values);
        }

        Ok(values.into_iter().rev().take(limit).collect())
    }

    pub async fn push_queue(&self, queue_key: &str, value: &str) -> ClobResult<()> {
        let mut conn = self.conn.clone();
        conn.rpush::<_, _, ()>(queue_key, value).await?;
        Ok(())
    }

    pub async fn pop_queue(&self, queue_key: &str) -> ClobResult<Option<String>> {
        let mut conn = self.conn.clone();
        let value: Option<String> = conn.lpop(queue_key, None).await?;
        Ok(value)
    }

    pub async fn queue_depth(&self, queue_key: &str) -> ClobResult<i64> {
        let mut conn = self.conn.clone();
        let depth: i64 = conn.llen(queue_key).await?;
        Ok(depth)
    }

    pub async fn ping(&self) -> ClobResult<()> {
        let mut conn = self.conn.clone();
        let _: String = redis::cmd("PING").query_async(&mut conn).await?;
        Ok(())
    }

    /// Atomically set key only if it does not already exist. Returns true if key was set.
    ///
    /// When `REDIS_COMPAT_DISABLE_SET_NX=true` (for mini-redis test environments that
    /// don't implement SET NX), falls back to an unconditional SET and always returns true.
    pub async fn set_if_not_exists(&self, key: &str, value: &str) -> ClobResult<bool> {
        if std::env::var("REDIS_COMPAT_DISABLE_SET_NX").as_deref() == Ok("true") {
            self.set(key, value).await?;
            return Ok(true);
        }
        let mut conn = self.conn.clone();
        Ok(conn.set_nx(key, value).await?)
    }

    /// Set a key with a TTL in seconds.
    ///
    /// When `REDIS_COMPAT_DISABLE_SET_EX=true` (for mini-redis test environments that
    /// don't implement SET EX), falls back to an unconditional SET without TTL.
    /// Callers that encode an expiry timestamp inside the JSON value can still
    /// enforce expiry semantically on read.
    pub async fn set_with_expiry(&self, key: &str, value: &str, ttl_secs: u64) -> ClobResult<()> {
        if std::env::var("REDIS_COMPAT_DISABLE_SET_EX").as_deref() == Ok("true") {
            return self.set(key, value).await;
        }
        let mut conn = self.conn.clone();
        conn.set_ex::<_, _, ()>(key, value, ttl_secs).await?;
        Ok(())
    }

    /// Delete a key from Redis.
    pub async fn delete_key(&self, key: &str) -> ClobResult<()> {
        let mut conn = self.conn.clone();
        conn.del::<_, ()>(key).await?;
        Ok(())
    }

    /// Returns true if the key exists in Redis.
    ///
    /// When `REDIS_COMPAT_DISABLE_EXISTS=true` (mini-redis v0.4 does not implement EXISTS),
    /// falls back to a GET and checks for a non-None result.
    pub async fn exists_key(&self, key: &str) -> ClobResult<bool> {
        if std::env::var("REDIS_COMPAT_DISABLE_EXISTS").as_deref() == Ok("true") {
            return Ok(self.get_optional(key).await?.is_some());
        }
        let mut conn = self.conn.clone();
        let n: i64 = conn.exists(key).await?;
        Ok(n > 0)
    }

    pub async fn store_proof_data(&self, key: &str, value: &str) -> ClobResult<()> {
        self.set(key, value).await
    }

    pub async fn retrieve_proof_data(&self, key: &str) -> ClobResult<Option<String>> {
        self.get_optional(key).await
    }

    pub async fn get_orders_by_side(&self, market_id: &str, side: OrderSide) -> ClobResult<Vec<Order>> {
        let levels = self
            .get_orderbook_levels(market_id, side, 10_000)
            .await?;

        let mut orders = Vec::new();
        for level in levels {
            let at_price = self.get_orders_at_price(market_id, &side, level.price).await?;
            orders.extend(at_price);
        }

        Ok(orders)
    }

    // ==================== Order Operations ====================
    
    pub async fn save_order(&self, order: &Order) -> ClobResult<()> {
        let mut conn = self.conn.clone();
        let key = format!("{}{}", ORDER_PREFIX, order.id);
        let json = serde_json::to_string(order).unwrap();
        
        conn.set::<_, _, ()>(&key, json).await?;
        
        // Add to user's order set
        let user_key = format!("{}{}", USER_ORDERS_PREFIX, order.user_id);
        conn.sadd::<_, _, ()>(&user_key, order.id.to_string()).await?;
        
        Ok(())
    }

    pub async fn get_order(&self, order_id: Uuid) -> ClobResult<Option<Order>> {
        let mut conn = self.conn.clone();
        let key = format!("{}{}", ORDER_PREFIX, order_id);
        
        let json: Option<String> = conn.get(&key).await?;
        Ok(json.and_then(|s| serde_json::from_str(&s).ok()))
    }

    pub async fn delete_order(&self, order_id: Uuid, user_id: &str) -> ClobResult<()> {
        let mut conn = self.conn.clone();
        let key = format!("{}{}", ORDER_PREFIX, order_id);
        
        conn.del::<_, ()>(&key).await?;
        
        // Remove from user's order set
        let user_key = format!("{}{}", USER_ORDERS_PREFIX, user_id);
        conn.srem::<_, _, ()>(&user_key, order_id.to_string()).await?;
        
        Ok(())
    }

    pub async fn get_user_orders(&self, user_id: &str) -> ClobResult<Vec<Order>> {
        let mut conn = self.conn.clone();
        let user_key = format!("{}{}", USER_ORDERS_PREFIX, user_id);
        
        let order_ids: Vec<String> = conn.smembers(&user_key).await?;
        let mut orders = Vec::new();
        
        for order_id_str in order_ids {
            if let Ok(order_id) = Uuid::parse_str(&order_id_str) {
                if let Some(order) = self.get_order(order_id).await? {
                    orders.push(order);
                }
            }
        }
        
        Ok(orders)
    }

    // ==================== Order Book Operations ====================
    
    pub async fn add_to_orderbook(
        &self,
        market_id: &str,
        order: &Order,
    ) -> ClobResult<()> {
        let mut conn = self.conn.clone();
        
        let key = match order.side {
            OrderSide::Buy => format!("{}{}", ORDERBOOK_BID_PREFIX, market_id),
            OrderSide::Sell => format!("{}{}", ORDERBOOK_ASK_PREFIX, market_id),
        };
        
        // Use price as score, with negative for bids to sort descending
        let score = match order.side {
            OrderSide::Buy => -order.price.to_string().parse::<f64>().unwrap_or(0.0),
            OrderSide::Sell => order.price.to_string().parse::<f64>().unwrap_or(0.0),
        };
        
        // Store order_id:size:timestamp as member
        let member = format!("{}:{}:{}", order.id, order.remaining, order.created_at.timestamp_nanos_opt().unwrap_or(0));
        
        conn.zadd::<_, _, _, ()>(&key, &member, score).await?;
        
        Ok(())
    }

    pub async fn remove_from_orderbook(
        &self,
        market_id: &str,
        order_id: Uuid,
        side: OrderSide,
    ) -> ClobResult<()> {
        let mut conn = self.conn.clone();
        
        let key = match side {
            OrderSide::Buy => format!("{}{}", ORDERBOOK_BID_PREFIX, market_id),
            OrderSide::Sell => format!("{}{}", ORDERBOOK_ASK_PREFIX, market_id),
        };
        
        // Remove all members with this order_id prefix
        let members: Vec<String> = conn.zrange(&key, 0, -1).await?;
        
        for member in members {
            if member.starts_with(&format!("{}:", order_id)) {
                conn.zrem::<_, _, ()>(&key, &member).await?;
            }
        }
        
        Ok(())
    }

    pub async fn get_orders_at_price(
        &self,
        market_id: &str,
        side: &OrderSide,
        price: Decimal,
    ) -> ClobResult<Vec<Order>> {
        let mut conn = self.conn.clone();
        
        let key = match side {
            OrderSide::Buy => format!("{}{}", ORDERBOOK_BID_PREFIX, market_id),
            OrderSide::Sell => format!("{}{}", ORDERBOOK_ASK_PREFIX, market_id),
        };
        
        // Get all members at this price
        let score = match side {
            OrderSide::Buy => -(price.to_string().parse::<f64>().unwrap_or(0.0)),
            OrderSide::Sell => price.to_string().parse::<f64>().unwrap_or(0.0),
        };
        
        let members: Vec<String> = conn.zrangebyscore(&key, score, score).await?;
        
        // Extract order IDs and fetch full orders
        let mut orders = Vec::new();
        for member in members {
            let parts: Vec<&str> = member.split(':').collect();
            if let Some(order_id_str) = parts.first() {
                if let Ok(order_id) = Uuid::parse_str(order_id_str) {
                    if let Some(order) = self.get_order(order_id).await? {
                        orders.push(order);
                    }
                }
            }
        }
        
        Ok(orders)
    }
    
    pub async fn get_orderbook_levels(
        &self,
        market_id: &str,
        side: OrderSide,
        depth: usize,
    ) -> ClobResult<Vec<OrderBookLevel>> {
        let mut conn = self.conn.clone();
        
        let key = match side {
            OrderSide::Buy => format!("{}{}", ORDERBOOK_BID_PREFIX, market_id),
            OrderSide::Sell => format!("{}{}", ORDERBOOK_ASK_PREFIX, market_id),
        };

        // mini-redis v0.4 does not implement ZRANGE WITHSCORES — return empty
        // levels list when the compat shim is active (test environments).
        if std::env::var("REDIS_COMPAT_DISABLE_SORTED_SETS").as_deref() == Ok("true") {
            return Ok(vec![]);
        }

        let members: Vec<(String, f64)> = conn.zrange_withscores(&key, 0, depth as isize - 1).await?;
        
        let mut price_map: HashMap<String, (Decimal, Decimal, u32)> = HashMap::new();
        
        for (member, score) in members {
            let parts: Vec<&str> = member.split(':').collect();
            if parts.len() >= 2 {
                if let (Ok(size), price_float) = (parts[1].parse::<Decimal>(), score) {
                    let price = match side {
                        OrderSide::Buy => Decimal::from_f64_retain(-price_float).unwrap_or(Decimal::ZERO),
                        OrderSide::Sell => Decimal::from_f64_retain(price_float).unwrap_or(Decimal::ZERO),
                    };
                    
                    let price_key = price.to_string();
                    let entry = price_map.entry(price_key.clone()).or_insert((price, Decimal::ZERO, 0));
                    entry.1 += size;
                    entry.2 += 1;
                }
            }
        }
        
        let mut levels: Vec<OrderBookLevel> = price_map
            .into_iter()
            .map(|(_, (price, size, count))| OrderBookLevel {
                price,
                size,
                order_count: count,
            })
            .collect();
        
        levels.sort_by(|a, b| match side {
            OrderSide::Buy => b.price.cmp(&a.price),
            OrderSide::Sell => a.price.cmp(&b.price),
        });
        
        Ok(levels)
    }

    // ==================== Trade Operations ====================
    
    pub async fn save_trade(&self, trade: &Trade) -> ClobResult<()> {
        let mut conn = self.conn.clone();
        
        // Save trade object
        let key = format!("trade:{}", trade.id);
        let json = serde_json::to_string(trade).unwrap();
        conn.set::<_, _, ()>(&key, &json).await?;
        
        // Add to market trades sorted set (by timestamp)
        let market_key = format!("{}{}", MARKET_TRADES_PREFIX, trade.market_id);
        let score = trade.timestamp.timestamp() as f64;
        conn.zadd::<_, _, _, ()>(&market_key, trade.id.to_string(), score).await?;
        
        // Add to user trades
        let maker_key = format!("{}{}", USER_TRADES_PREFIX, trade.maker_user_id);
        let taker_key = format!("{}{}", USER_TRADES_PREFIX, trade.taker_user_id);
        conn.zadd::<_, _, _, ()>(&maker_key, trade.id.to_string(), score).await?;
        conn.zadd::<_, _, _, ()>(&taker_key, trade.id.to_string(), score).await?;
        
        Ok(())
    }

    pub async fn get_recent_trades(&self, market_id: &str, limit: usize) -> ClobResult<Vec<Trade>> {
        // mini-redis v0.4 does not implement ZREVRANGE — return empty list when shim is active.
        if std::env::var("REDIS_COMPAT_DISABLE_SORTED_SETS").as_deref() == Ok("true") {
            return Ok(Vec::new());
        }
        let mut conn = self.conn.clone();
        let key = format!("{}{}", MARKET_TRADES_PREFIX, market_id);
        
        let trade_ids: Vec<String> = conn.zrevrange(&key, 0, limit as isize - 1).await?;
        
        let mut trades = Vec::new();
        for trade_id_str in trade_ids {
            if let Ok(trade_id) = Uuid::parse_str(&trade_id_str) {
                let trade_key = format!("trade:{}", trade_id);
                if let Some(json) = conn.get::<_, Option<String>>(&trade_key).await? {
                    if let Ok(trade) = serde_json::from_str(&json) {
                        trades.push(trade);
                    }
                }
            }
        }
        
        Ok(trades)
    }

    /// Scan all keys matching a glob pattern.
    ///
    /// When `REDIS_COMPAT_DISABLE_KEYS=true` (mini-redis v0.4 does not implement KEYS),
    /// returns an empty vec. Callers that test the "not found" case will get the correct
    /// `Ok(None)` result from the fallback loop in `find_transition_by_proof_job_id`.
    pub async fn scan_keys(&self, pattern: &str) -> ClobResult<Vec<String>> {
        if std::env::var("REDIS_COMPAT_DISABLE_KEYS").as_deref() == Ok("true") {
            return Ok(Vec::new());
        }
        let mut conn = self.conn.clone();
        let keys: Vec<String> = redis::cmd("KEYS")
            .arg(pattern)
            .query_async(&mut conn)
            .await?;
        Ok(keys)
    }

    // ==================== Note-Lock Operations ====================

    /// Persist a note-lock record under `pm:note_lock:<user_id>:<order_commitment_low>`.
    pub async fn save_note_lock(&self, record: &crate::models::NoteLockRecord) -> ClobResult<()> {
        let key = format!("pm:note_lock:{}:{}", record.user_id, record.order_commitment_low);
        let json = serde_json::to_string(record)?;
        self.set(&key, &json).await
    }

    /// Delete a note-lock record (e.g. after it has been fully spent and confirmed).
    pub async fn delete_note_lock(&self, user_id: &str, order_commitment_low: &str) -> ClobResult<()> {
        let mut conn = self.conn.clone();
        let key = format!("pm:note_lock:{}:{}", user_id, order_commitment_low);
        conn.del::<_, ()>(&key).await?;
        Ok(())
    }

    /// Retrieve all note-lock records for a user (scans `pm:note_lock:<user_id>:*`).
    pub async fn get_note_locks_for_user(
        &self,
        user_id: &str,
    ) -> ClobResult<Vec<crate::models::NoteLockRecord>> {
        let pattern = format!("pm:note_lock:{}:*", user_id);
        let keys = self.scan_keys(&pattern).await?;
        let mut records = Vec::with_capacity(keys.len());
        for key in keys {
            if let Some(json) = self.get_optional(&key).await? {
                if let Ok(record) = serde_json::from_str::<crate::models::NoteLockRecord>(&json) {
                    records.push(record);
                }
            }
        }
        Ok(records)
    }

    pub async fn get_user_trades(&self, user_id: &str, limit: usize) -> ClobResult<Vec<Trade>> {
        let mut conn = self.conn.clone();
        let key = format!("{}{}", USER_TRADES_PREFIX, user_id);

        let trade_ids: Vec<String> = conn.zrevrange(&key, 0, limit as isize - 1).await?;

        let mut trades = Vec::new();
        for trade_id_str in trade_ids {
            if let Ok(trade_id) = Uuid::parse_str(&trade_id_str) {
                let trade_key = format!("trade:{}", trade_id);
                if let Some(json) = conn.get::<_, Option<String>>(&trade_key).await? {
                    if let Ok(trade) = serde_json::from_str(&json) {
                        trades.push(trade);
                    }
                }
            }
        }

        Ok(trades)
    }

    // ==================== Market Stats ====================
    
    pub async fn update_market_stats(&self, trade: &Trade) -> ClobResult<()> {
        let mut conn = self.conn.clone();
        let key = format!("{}{}", MARKET_STATS_PREFIX, trade.market_id);
        
        // Use Lua script for atomic stats update
        let script = Script::new(r"
            local key = KEYS[1]
            local price = tonumber(ARGV[1])
            local size = tonumber(ARGV[2])
            local timestamp = tonumber(ARGV[3])
            
            redis.call('HSET', key, 'last_price', price)
            redis.call('HINCRBYFLOAT', key, 'volume_24h', size)
            
            local high = redis.call('HGET', key, 'high_24h')
            if not high or tonumber(high) < price then
                redis.call('HSET', key, 'high_24h', price)
            end
            
            local low = redis.call('HGET', key, 'low_24h')
            if not low or tonumber(low) > price then
                redis.call('HSET', key, 'low_24h', price)
            end
            
            redis.call('HSET', key, 'updated_at', timestamp)
            return 1
        ");
        
        script.key(&key)
            .arg(trade.price.to_string().parse::<f64>().unwrap_or(0.0))
            .arg(trade.size.to_string().parse::<f64>().unwrap_or(0.0))
            .arg(Utc::now().timestamp())
            .invoke_async::<i32>(&mut conn)
            .await?;
        
        Ok(())
    }

    pub async fn get_market_stats(&self, market_id: &str) -> ClobResult<Option<MarketStats>> {
        let mut conn = self.conn.clone();
        let key = format!("{}{}", MARKET_STATS_PREFIX, market_id);
        
        let stats: HashMap<String, String> = conn.hgetall(&key).await?;
        
        if stats.is_empty() {
            return Ok(None);
        }
        
        let parse_decimal = |key: &str| -> Option<Decimal> {
            stats.get(key).and_then(|v| v.parse().ok())
        };
        
        Ok(Some(MarketStats {
            market_id: market_id.to_string(),
            last_price: parse_decimal("last_price"),
            volume_24h: parse_decimal("volume_24h").unwrap_or(Decimal::ZERO),
            high_24h: parse_decimal("high_24h"),
            low_24h: parse_decimal("low_24h"),
            best_bid: None,   // Computed separately
            best_ask: None,   // Computed separately
            spread: None,     // Computed separately
            open_interest: parse_decimal("open_interest").unwrap_or(Decimal::ZERO),
        }))
    }

    /// Increment open interest when an order is added to the book.
    pub async fn increment_open_interest(&self, market_id: &str, size: Decimal) -> ClobResult<()> {
        let mut conn = self.conn.clone();
        let key = format!("{}{}", MARKET_STATS_PREFIX, market_id);
        let delta = size.to_string().parse::<f64>().unwrap_or(0.0);
        conn.hincr::<_, _, _, ()>(&key, "open_interest", delta).await?;
        Ok(())
    }

    /// Decrement open interest when an order is removed or filled.
    pub async fn decrement_open_interest(&self, market_id: &str, size: Decimal) -> ClobResult<()> {
        let mut conn = self.conn.clone();
        let key = format!("{}{}", MARKET_STATS_PREFIX, market_id);
        let delta = -(size.to_string().parse::<f64>().unwrap_or(0.0));
        conn.hincr::<_, _, _, ()>(&key, "open_interest", delta).await?;
        Ok(())
    }
}
