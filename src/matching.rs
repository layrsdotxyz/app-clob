use crate::{
    error::{ClobError, ClobResult},
    metrics::Metrics,
    models::*,
    orderbook::OrderBookManager,
    settlement::SettlementEngine,
};
use chrono::Utc;
use rust_decimal::Decimal;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

pub struct MatchingEngine {
    orderbook: Arc<OrderBookManager>,
    settlement: Arc<SettlementEngine>,
    metrics: Arc<Metrics>,
    // Lock per market to prevent concurrent matching
    market_locks: Arc<dashmap::DashMap<String, Arc<RwLock<()>>>>,
}

impl MatchingEngine {
    pub fn new(
        orderbook: Arc<OrderBookManager>,
        settlement: Arc<SettlementEngine>,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self {
            orderbook,
            settlement,
            metrics,
            market_locks: Arc::new(dashmap::DashMap::new()),
        }
    }

    /// Submit an order to the matching engine
    pub async fn submit_order(&self, mut order: Order) -> ClobResult<MatchResult> {
        let start_time = std::time::Instant::now();
        
        // Validate order
        self.validate_order(&order).await?;
        
        // Check user balance
        self.settlement
            .check_balance(&order.user_id, &order.market_id, &order)
            .await?;
        
        // Get market lock
        let lock = self.get_market_lock(&order.market_id);
        let _guard = lock.write().await;
        
        // Try to match order
        let match_result = self.match_order(&mut order).await?;
        
        // Handle remaining order based on time in force
        if order.remaining > Decimal::ZERO && order.can_match() {
            match order.time_in_force {
                TimeInForce::Gtc | TimeInForce::Ioc => {
                    // Add to order book if GTC, or if IOC and fully filled
                    if order.time_in_force == TimeInForce::Gtc || order.filled == Decimal::ZERO {
                        if order.order_type == OrderType::PostOnly && !match_result.fills.is_empty() {
                            // PostOnly order would have taken liquidity - reject
                            order.status = OrderStatus::Rejected;
                            return Err(ClobError::InvalidOrder(
                                "PostOnly order would cross the book".to_string(),
                            ));
                        }
                        
                        self.orderbook.add_order(&order).await?;
                    } else {
                        // IOC with partial fill - cancel remaining
                        order.status = OrderStatus::Cancelled;
                    }
                }
                TimeInForce::Fok => {
                    // FOK must be completely filled
                    if order.filled < order.size {
                        order.status = OrderStatus::Rejected;
                        // Rollback all fills
                        for fill in &match_result.fills {
                            self.settlement.rollback_fill(fill).await?;
                        }
                        return Err(ClobError::InvalidOrder(
                            "FOK order cannot be completely filled".to_string(),
                        ));
                    }
                }
            }
        }
        
        // Record metrics
        let latency = start_time.elapsed();
        self.metrics.record_order_latency(latency);
        self.metrics.record_order_submitted(&order.market_id, &order.side);
        
        if !match_result.fills.is_empty() {
            self.metrics.record_match(&order.market_id, match_result.fills.len());
        }
        
        tracing::info!(
            order_id = %order.id,
            market_id = %order.market_id,
            fills = match_result.fills.len(),
            filled_size = %order.filled,
            remaining = %order.remaining,
            latency_us = latency.as_micros(),
            "Order processed"
        );
        
        Ok(match_result)
    }

    /// Cancel an order
    pub async fn cancel_order(&self, order_id: Uuid, user_id: &str) -> ClobResult<Order> {
        let mut order = self.orderbook.remove_order(order_id).await?;
        
        // Verify user owns the order
        if order.user_id != user_id {
            return Err(ClobError::Unauthorized("Order does not belong to user".to_string()));
        }
        
        // Update order status
        order.status = OrderStatus::Cancelled;
        order.updated_at = chrono::Utc::now();
        
        // Release reserved balance
        self.settlement.release_order_balance(&order).await?;
        
        self.metrics.record_order_cancelled(&order.market_id);
        
        tracing::info!(
            order_id = %order_id,
            market_id = %order.market_id,
            user_id = %user_id,
            "Order cancelled"
        );
        
        Ok(order)
    }

    // ==================== Private Methods ====================

    async fn validate_order(&self, order: &Order) -> ClobResult<()> {
        // Validate price
        if order.price <= Decimal::ZERO {
            return Err(ClobError::InvalidPrice("Price must be positive".to_string()));
        }
        
        // Validate size
        if order.size <= Decimal::ZERO {
            return Err(ClobError::InvalidOrder("Size must be positive".to_string()));
        }
        
        // Validate market exists (could check against registry)
        if order.market_id.is_empty() {
            return Err(ClobError::MarketNotFound("Market ID is empty".to_string()));
        }
        
        Ok(())
    }

    async fn match_order(&self, order: &mut Order) -> ClobResult<MatchResult> {
        let mut fills = Vec::new();
        let mut trades = Vec::new();
        
        while order.remaining > Decimal::ZERO {
            // Get best counter-side price
            let best_counter = match order.side {
                OrderSide::Buy => self.orderbook.get_best_ask(&order.market_id).await?,
                OrderSide::Sell => self.orderbook.get_best_bid(&order.market_id).await?,
            };
            
            tracing::debug!(
                order_id = %order.id,
                side = ?order.side,
                price = %order.price,
                best_counter = ?best_counter,
                "Checking match possibility"
            );
            
            // Check if order can be matched
            let can_match = match (order.side.clone(), best_counter) {
                (OrderSide::Buy, Some(ask)) => order.price >= ask,
                (OrderSide::Sell, Some(bid)) => order.price <= bid,
                _ => false,
            };
            
            tracing::debug!(
                order_id = %order.id,
                can_match = can_match,
                "Match check result"
            );
            
            if !can_match {
                break;
            }
            
            // Get counter orders at best price
            let counter_orders = self.get_counter_orders_at_price(
                &order.market_id,
                &order.side,
                best_counter.unwrap(),
            ).await?;
            
            tracing::debug!(
                order_id = %order.id,
                counter_orders_count = counter_orders.len(),
                "Retrieved counter orders"
            );
            
            if counter_orders.is_empty() {
                tracing::debug!(
                    order_id = %order.id,
                    "No counter orders found, breaking"
                );
                break;
            }
            
            // Match against counter orders (price-time priority)
            for mut counter_order in counter_orders {
                if order.remaining <= Decimal::ZERO {
                    break;
                }
                
                // Calculate fill size
                let fill_size = order.remaining.min(counter_order.remaining);
                let fill_price = counter_order.price; // Maker price
                
                // Create trade
                let trade = Trade {
                    id: Uuid::new_v4(),
                    market_id: order.market_id.clone(),
                    maker_order_id: counter_order.id,
                    taker_order_id: order.id,
                    maker_user_id: counter_order.user_id.clone(),
                    taker_user_id: order.user_id.clone(),
                    side: order.side,
                    price: fill_price,
                    size: fill_size,
                    timestamp: Utc::now(),
                    maker_address: counter_order.maker_address,
                    taker_address: order.maker_address,
                    market_id_uint: order.market_id_uint,
                    settlement_tx: None,
                };
                
                // Calculate fees (maker pays maker fee, taker pays taker fee)
                let maker_fee = self.settlement.calculate_fee(fill_size, fill_price, true);
                let taker_fee = self.settlement.calculate_fee(fill_size, fill_price, false);
                
                // Create fills
                let maker_fill = Fill {
                    id: Uuid::new_v4(),
                    order_id: counter_order.id,
                    trade_id: trade.id,
                    price: fill_price,
                    size: fill_size,
                    fee: maker_fee,
                    is_maker: true,
                    timestamp: trade.timestamp,
                };
                
                let taker_fill = Fill {
                    id: Uuid::new_v4(),
                    order_id: order.id,
                    trade_id: trade.id,
                    price: fill_price,
                    size: fill_size,
                    fee: taker_fee,
                    is_maker: false,
                    timestamp: trade.timestamp,
                };
                
                // Update orders
                order.filled += fill_size;
                order.remaining -= fill_size;
                order.fills.push(taker_fill.clone());
                
                counter_order.filled += fill_size;
                counter_order.remaining -= fill_size;
                counter_order.fills.push(maker_fill.clone());
                
                // Settle trade
                self.settlement.settle_trade(&trade, &maker_fill, &taker_fill).await?;
                
                // Update maker order in book
                self.orderbook
                    .update_order_after_fill(counter_order.id, fill_size, maker_fill.clone())
                    .await?;
                
                fills.push(taker_fill);
                trades.push(trade);
                
                tracing::debug!(
                    trade_id = %trades.last().unwrap().id,
                    maker_order = %counter_order.id,
                    taker_order = %order.id,
                    price = %fill_price,
                    size = %fill_size,
                    "Trade executed"
                );
            }
        }
        
        Ok(MatchResult {
            order: order.clone(),
            fills,
            trades,
        })
    }

    async fn get_counter_orders_at_price(
        &self,
        market_id: &str,
        side: &OrderSide,
        price: Decimal,
    ) -> ClobResult<Vec<Order>> {
        // Get counter-side (for a BUY order, we need SELL orders)
        let counter_side = match side {
            OrderSide::Buy => OrderSide::Sell,
            OrderSide::Sell => OrderSide::Buy,
        };
        
        // Get all orders at this price level from Redis
        let orders = self.orderbook.store
            .get_orders_at_price(market_id, &counter_side, price)
            .await?;
        
        Ok(orders)
    }

    fn get_market_lock(&self, market_id: &str) -> Arc<RwLock<()>> {
        self.market_locks
            .entry(market_id.to_string())
            .or_insert_with(|| Arc::new(RwLock::new(())))
            .clone()
    }
}

#[derive(Debug, Clone)]
pub struct MatchResult {
    pub order: Order,
    pub fills: Vec<Fill>,
    pub trades: Vec<Trade>,
}
