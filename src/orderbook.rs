use crate::{
    database::Database,
    error::{ClobError, ClobResult},
    metrics::Metrics,
    models::*,
    redis_store::RedisStore,
};
use dashmap::DashMap;
use rust_decimal::Decimal;
use std::sync::Arc;
use uuid::Uuid;

pub struct OrderBookManager {
    pub store: Arc<RedisStore>,
    pub metrics: Arc<Metrics>,
    database: Option<Arc<Database>>,
    // In-memory cache for hot path lookups
    active_markets: DashMap<String, bool>,
}

impl OrderBookManager {
    pub fn new(
        store: Arc<RedisStore>,
        metrics: Arc<Metrics>,
        database: Option<Arc<Database>>,
    ) -> Self {
        Self {
            store,
            metrics,
            database,
            active_markets: DashMap::new(),
        }
    }

    /// Add order to the order book
    pub async fn add_order(&self, order: &Order) -> ClobResult<()> {
        // Save order to Redis
        self.store.save_order(order).await?;
        
        // Add to order book sorted set
        self.store.add_to_orderbook(&order.market_id, order).await?;

        // Track open interest
        self.store.increment_open_interest(&order.market_id, order.remaining).await?;
        
        // Mark market as active
        self.active_markets.insert(order.market_id.clone(), true);
        
        // Persist to PostgreSQL (write-behind; log failure, don't abort)
        if let Some(db) = &self.database {
            if let Err(e) = db.upsert_order(order).await {
                tracing::error!(order_id = %order.id, error = %e, "Failed to persist order to DB");
            }
        }

        // Update metrics
        self.metrics.record_order_added(&order.market_id, &order.side);
        
        tracing::debug!(
            order_id = %order.id,
            market_id = %order.market_id,
            side = ?order.side,
            price = %order.price,
            size = %order.size,
            "Order added to book"
        );
        
        Ok(())
    }

    /// Remove order from the order book
    pub async fn remove_order(&self, order_id: Uuid) -> ClobResult<Order> {
        let order = self.store
            .get_order(order_id)
            .await?
            .ok_or_else(|| ClobError::OrderNotFound(order_id.to_string()))?;
        
        // Remove from order book
        self.store
            .remove_from_orderbook(&order.market_id, order_id, order.side.clone())
            .await?;

        // Reduce open interest by the unfilled amount
        self.store.decrement_open_interest(&order.market_id, order.remaining).await?;
        
        // Delete order from Redis
        self.store.delete_order(order_id, &order.user_id).await?;

        // Persist cancellation to DB
        if let Some(db) = &self.database {
            if let Err(e) = db
                .update_order_status(order_id, &OrderStatus::Cancelled, order.filled, Decimal::ZERO)
                .await
            {
                tracing::error!(order_id = %order_id, error = %e, "Failed to persist order cancellation to DB");
            }
        }

        // Update metrics
        self.metrics.record_order_removed(&order.market_id, &order.side);
        
        tracing::debug!(
            order_id = %order_id,
            market_id = %order.market_id,
            "Order removed from book"
        );
        
        Ok(order)
    }

    /// Get order book snapshot
    pub async fn get_orderbook(&self, market_id: &str, depth: usize) -> ClobResult<OrderBook> {
        let bids = self.store
            .get_orderbook_levels(market_id, OrderSide::Buy, depth)
            .await?;
        
        let asks = self.store
            .get_orderbook_levels(market_id, OrderSide::Sell, depth)
            .await?;
        
        Ok(OrderBook {
            market_id: market_id.to_string(),
            bids,
            asks,
            timestamp: chrono::Utc::now(),
        })
    }

    /// Get best bid price
    pub async fn get_best_bid(&self, market_id: &str) -> ClobResult<Option<Decimal>> {
        let bids = self.store
            .get_orderbook_levels(market_id, OrderSide::Buy, 1)
            .await?;
        
        Ok(bids.first().map(|level| level.price))
    }

    /// Get best ask price
    pub async fn get_best_ask(&self, market_id: &str) -> ClobResult<Option<Decimal>> {
        let asks = self.store
            .get_orderbook_levels(market_id, OrderSide::Sell, 1)
            .await?;
        
        Ok(asks.first().map(|level| level.price))
    }

    /// Get mid price
    pub async fn get_mid_price(&self, market_id: &str) -> ClobResult<Option<Decimal>> {
        let best_bid = self.get_best_bid(market_id).await?;
        let best_ask = self.get_best_ask(market_id).await?;
        
        match (best_bid, best_ask) {
            (Some(bid), Some(ask)) => Ok(Some((bid + ask) / Decimal::from(2))),
            _ => Ok(None),
        }
    }

    /// Update order after partial fill
    pub async fn update_order_after_fill(
        &self,
        order_id: Uuid,
        filled_size: Decimal,
        fill: Fill,
    ) -> ClobResult<Order> {
        let mut order = self.store
            .get_order(order_id)
            .await?
            .ok_or_else(|| ClobError::OrderNotFound(order_id.to_string()))?;
        
        order.filled += filled_size;
        order.remaining -= filled_size;
        order.updated_at = chrono::Utc::now();
        order.fills.push(fill);

        // Reduce open interest by the filled amount
        self.store.decrement_open_interest(&order.market_id, filled_size).await?;
        
        if order.remaining <= Decimal::ZERO {
            order.status = OrderStatus::Filled;
            // Remove from order book
            self.store
                .remove_from_orderbook(&order.market_id, order_id, order.side.clone())
                .await?;
        } else {
            order.status = OrderStatus::Partial;
            // Update order book entry with new remaining size
            self.store
                .remove_from_orderbook(&order.market_id, order_id, order.side.clone())
                .await?;
            self.store
                .add_to_orderbook(&order.market_id, &order)
                .await?;
        }
        
        // Save updated order
        self.store.save_order(&order).await?;

        // Persist updated status to DB (write-behind)
        if let Some(db) = &self.database {
            if let Err(e) = db
                .update_order_status(order_id, &order.status, order.filled, order.remaining)
                .await
            {
                tracing::error!(order_id = %order_id, error = %e, "Failed to persist order status update to DB");
            }
        }
        
        tracing::debug!(
            order_id = %order_id,
            filled_size = %filled_size,
            remaining = %order.remaining,
            status = ?order.status,
            "Order updated after fill"
        );
        
        Ok(order)
    }

    /// Get user's orders
    pub async fn get_user_orders(&self, user_id: &str) -> ClobResult<Vec<Order>> {
        self.store.get_user_orders(user_id).await
    }

    /// Register a market as active. Used for startup seeding.
    pub fn seed_market(&self, market_id: &str) {
        self.active_markets.insert(market_id.to_string(), true);
        tracing::info!(market_id = %market_id, "Seeded active market on startup");
    }

    /// Get active markets
    pub fn get_active_markets(&self) -> Vec<String> {
        self.active_markets
            .iter()
            .map(|entry| entry.key().clone())
            .collect()
    }

    /// Compatibility helper used by epoch service.
    pub async fn list_markets(&self) -> ClobResult<Vec<String>> {
        Ok(self.get_active_markets())
    }

    /// Compatibility helper used by epoch service.
    /// Current implementation returns recent trades for the market.
    pub async fn get_epoch_trades(&self, market_id: &str, _epoch_id: u64) -> ClobResult<Vec<Trade>> {
        self.store.get_recent_trades(market_id, 10_000).await
    }
}
