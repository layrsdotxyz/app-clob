use crate::{
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
    // In-memory cache for hot path lookups
    active_markets: DashMap<String, bool>,
}

impl OrderBookManager {
    pub fn new(store: Arc<RedisStore>, metrics: Arc<Metrics>) -> Self {
        Self {
            store,
            metrics,
            active_markets: DashMap::new(),
        }
    }

    /// Add order to the order book
    pub async fn add_order(&self, order: &Order) -> ClobResult<()> {
        // Save order to Redis
        self.store.save_order(order).await?;
        
        // Add to order book sorted set
        self.store.add_to_orderbook(&order.market_id, order).await?;
        
        // Mark market as active
        self.active_markets.insert(order.market_id.clone(), true);
        
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
        
        // Delete order
        self.store.delete_order(order_id, &order.user_id).await?;
        
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

    /// Get active markets
    pub fn get_active_markets(&self) -> Vec<String> {
        self.active_markets
            .iter()
            .map(|entry| entry.key().clone())
            .collect()
    }
}
