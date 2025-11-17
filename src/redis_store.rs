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

    // ==================== Order Operations ====================
    
    pub async fn save_order(&self, order: &Order) -> ClobResult<()> {
        let mut conn = self.conn.clone();
        let key = format!("{}{}", ORDER_PREFIX, order.id);
        let json = serde_json::to_string(order).unwrap();
        
        conn.set(&key, json).await?;
        
        // Add to user's order set
        let user_key = format!("{}{}", USER_ORDERS_PREFIX, order.user_id);
        conn.sadd(&user_key, order.id.to_string()).await?;
        
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
        
        conn.del(&key).await?;
        
        // Remove from user's order set
        let user_key = format!("{}{}", USER_ORDERS_PREFIX, user_id);
        conn.srem(&user_key, order_id.to_string()).await?;
        
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
        
        conn.zadd(&key, &member, score).await?;
        
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
                conn.zrem(&key, &member).await?;
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
        conn.set(&key, &json).await?;
        
        // Add to market trades sorted set (by timestamp)
        let market_key = format!("{}{}", MARKET_TRADES_PREFIX, trade.market_id);
        let score = trade.timestamp.timestamp() as f64;
        conn.zadd(&market_key, trade.id.to_string(), score).await?;
        
        // Add to user trades
        let maker_key = format!("{}{}", USER_TRADES_PREFIX, trade.maker_user_id);
        let taker_key = format!("{}{}", USER_TRADES_PREFIX, trade.taker_user_id);
        conn.zadd(&maker_key, trade.id.to_string(), score).await?;
        conn.zadd(&taker_key, trade.id.to_string(), score).await?;
        
        Ok(())
    }

    pub async fn get_recent_trades(&self, market_id: &str, limit: usize) -> ClobResult<Vec<Trade>> {
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
            redis.call('HINCRBY', key, 'volume_24h', size)
            
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
            best_bid: None, // Computed separately
            best_ask: None, // Computed separately
            spread: None,   // Computed separately
            open_interest: Decimal::ZERO, // TODO: Track positions
        }))
    }
}
