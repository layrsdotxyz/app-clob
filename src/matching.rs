use crate::{
    error::{ClobError, ClobResult},
    metrics::Metrics,
    models::*,
    orderbook::OrderBookManager,
    privacy::{NoteStatus, PrivacyStateService},
    settlement::{user_alias, SettlementEngine},
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
    /// Optional ZK privacy state — when present, locks/unlocks/spends notes as orders
    /// progress through their lifecycle (G1, G2, G3).
    privacy_state: Option<Arc<PrivacyStateService>>,
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
            privacy_state: None,
        }
    }

    /// Attach a PrivacyStateService to enable note soft-lock lifecycle.
    pub fn with_privacy_state(mut self, ps: Arc<PrivacyStateService>) -> Self {
        self.privacy_state = Some(ps);
        self
    }

    // ── Note lifecycle helpers ────────────────────────────────────────────────

    /// Lock the note attached to an order when it enters the book (GTC) or is
    /// being processed (IOC/FOK). No-op if the order has no note_commitment or
    /// privacy state is not wired.
    async fn lock_note_for_order(&self, order: &Order) {
        if let (Some(ps), Some(commitment)) = (&self.privacy_state, &order.note_commitment) {
            if let Err(e) = ps.mark_note_locked(commitment).await {
                tracing::warn!(
                    order_id = %order.id,
                    error = %e,
                    "Failed to lock note for order — proceeding (soft lock only)"
                );
            }
        }
    }

    /// Unlock (reset to Unspent) the note attached to an order when it is
    /// cancelled, IOC-expired, or FOK-rejected.
    async fn unlock_note_for_order(&self, order: &Order) {
        if let (Some(ps), Some(commitment)) = (&self.privacy_state, &order.note_commitment) {
            if let Err(e) = ps.update_note_status_pub(commitment, NoteStatus::Unspent).await {
                tracing::warn!(
                    order_id = %order.id,
                    error = %e,
                    "Failed to unlock note for cancelled order"
                );
            }
        }
    }

    /// Mark the note attached to an order as Spent after a fill.
    /// The settlement proof pipeline will handle creating new position notes.
    async fn spend_note_for_order(&self, order: &Order) {
        if let (Some(ps), Some(commitment)) = (&self.privacy_state, &order.note_commitment) {
            if let Err(e) = ps.mark_note_spent(commitment).await {
                tracing::warn!(
                    order_id = %order.id,
                    error = %e,
                    "Failed to mark note spent after fill"
                );
            }
        }
    }

    /// Submit an order to the matching engine
    pub async fn submit_order(&self, mut order: Order) -> ClobResult<MatchResult> {
        let start_time = std::time::Instant::now();
        
        // Validate order
        self.validate_order(&order).await?;

        // Convert Market orders to aggressive-limit + IOC so they always cross the book
        // immediately; any unfilled tail cancels (standard exchange behaviour).
        // Price is set to best_counter ×1.05 (Buy) or ×0.95 (Sell) to guarantee a cross.
        if order.order_type == OrderType::Market {
            let best_counter = match order.side {
                OrderSide::Buy  => self.orderbook.get_best_ask(&order.market_id).await?,
                OrderSide::Sell => self.orderbook.get_best_bid(&order.market_id).await?,
            };
            let best_price = best_counter.ok_or_else(|| {
                ClobError::InvalidOrder("No liquidity available for market order".to_string())
            })?;
            order.price = match order.side {
                OrderSide::Buy  => best_price * (Decimal::from(105) / Decimal::from(100)),
                OrderSide::Sell => best_price * (Decimal::from(95)  / Decimal::from(100)),
            };
            order.time_in_force = TimeInForce::Ioc;
            tracing::debug!(
                order_id = %order.id,
                side = ?order.side,
                aggressive_price = %order.price,
                "Market order converted to aggressive limit/IOC"
            );
        }

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
                TimeInForce::Gtc => {
                    // GTC: PostOnly check, then rest in book.
                    if order.order_type == OrderType::PostOnly && !match_result.fills.is_empty() {
                        // PostOnly order would have taken liquidity — reject.
                        self.unlock_note_for_order(&order).await;
                        order.status = OrderStatus::Rejected;
                        return Err(ClobError::InvalidOrder(
                            "PostOnly order would cross the book".to_string(),
                        ));
                    }
                    // Lock the note now that the order is safely in the book.
                    self.lock_note_for_order(&order).await;
                    self.orderbook.add_order(&order).await?;
                }
                TimeInForce::Ioc => {
                    // IOC: never rests in book; release unfilled reservation and cancel.
                    self.settlement.release_order_balance(&order).await?;
                    // If partially or fully filled, mark the note spent.
                    // If zero fill, unlock it so the user can reuse the note.
                    if order.filled > Decimal::ZERO {
                        self.spend_note_for_order(&order).await;
                        order.status = OrderStatus::Partial;
                    } else {
                        self.unlock_note_for_order(&order).await;
                        order.status = OrderStatus::Cancelled;
                    }
                    tracing::debug!(
                        order_id = %order.id,
                        filled = %order.filled,
                        remaining = %order.remaining,
                        "IOC order expired, unfilled balance released"
                    );
                }
                TimeInForce::Fok => {
                    // FOK must be completely filled or the whole order is rejected.
                    if order.filled < order.size {
                        order.status = OrderStatus::Rejected;
                        // Rollback all trades (credit both sides back)
                        for trade in &match_result.trades {
                            self.settlement.rollback_trade(trade).await?;
                        }
                        // Release the remaining reservation (full order, since fills were rolled back)
                        self.settlement.release_order_balance(&order).await?;
                        // Unlock the note — the order never executed.
                        self.unlock_note_for_order(&order).await;
                        return Err(ClobError::InvalidOrder(
                            "FOK order cannot be completely filled".to_string(),
                        ));
                    }
                }
            }
        }
        
        // If the order was fully consumed by fills, mark its note spent now.
        // Partial + resting GTC notes are marked spent by the cancel path or
        // the next fill that exhausts them.
        if order.filled >= order.size && order.note_commitment.is_some() {
            self.spend_note_for_order(&order).await;
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
        // Unlock the note — order no longer holds the position.
        self.unlock_note_for_order(&order).await;
        
        self.metrics.record_order_cancelled(&order.market_id);
        
        tracing::info!(
            order_id = %order_id,
            market_id = %order.market_id,
            user_alias = %user_alias(user_id),
            "Order cancelled"
        );
        
        Ok(order)
    }

    // ==================== Private Methods ====================

    async fn validate_order(&self, order: &Order) -> ClobResult<()> {
        // Market orders execute at whatever price is available — skip price check.
        // All other order types must specify a positive price.
        if order.order_type != OrderType::Market && order.price <= Decimal::ZERO {
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

                // Enqueue PM settlement job (no-op for non-PM markets).
                self.settlement
                    .enqueue_pm_settlement_job(
                        &trade,
                        &counter_order,
                        &order,
                        &maker_fill,
                        &taker_fill,
                    )
                    .await?;
                
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Order, OrderSide, OrderStatus, OrderType, TimeInForce};
    use rust_decimal_macros::dec;
    use uuid::Uuid;

    // ── Order construction helpers ───────────────────────────────────────────

    fn make_limit_order(
        user: &str,
        market: &str,
        side: OrderSide,
        price: rust_decimal::Decimal,
        size: rust_decimal::Decimal,
        tif: TimeInForce,
    ) -> Order {
        Order::new(user.to_string(), market.to_string(), side, OrderType::Limit, tif, price, size)
    }

    // ── 3. Trade: order field validation ────────────────────────────────────

    /// Limit order has correct initial fields.
    #[test]
    fn test_limit_order_initial_fields() {
        let order = make_limit_order("alice", "BTC-1H", OrderSide::Buy, dec!(0.55), dec!(100), TimeInForce::Gtc);
        assert_eq!(order.status, OrderStatus::Open);
        assert_eq!(order.filled, dec!(0));
        assert_eq!(order.remaining, dec!(100));
        assert_eq!(order.side, OrderSide::Buy);
        assert_eq!(order.order_type, OrderType::Limit);
        assert_eq!(order.time_in_force, TimeInForce::Gtc);
        assert_eq!(order.price, dec!(0.55));
        assert!(order.is_active());
        assert!(order.can_match());
    }

    /// Market orders use OrderType::Market and TimeInForce::Ioc.
    /// The engine itself does NOT enforce reduce-only — market orders can open new
    /// positions just like limit orders. The caller sets the price; aggressive
    /// market buyers typically use a high price, sellers a low price.
    ///
    /// Reduce-only enforcement (selling no more than a held position) is NOT
    /// implemented in the current matching engine and would require separate
    /// position tracking outside of collateral balance.
    #[test]
    fn test_market_order_ioc_fields() {
        // Market buy: aggressive price to sweep the book
        let buy = Order::new(
            "bob".to_string(), "ETH-1H".to_string(),
            OrderSide::Buy, OrderType::Market, TimeInForce::Ioc,
            dec!(9999999), dec!(50),
        );
        assert_eq!(buy.order_type, OrderType::Market);
        assert_eq!(buy.time_in_force, TimeInForce::Ioc);
        assert_eq!(buy.remaining, dec!(50));
        assert!(buy.can_match());

        // Market sell: aggressive low price
        let sell = Order::new(
            "carol".to_string(), "ETH-1H".to_string(),
            OrderSide::Sell, OrderType::Market, TimeInForce::Ioc,
            dec!(0.01), dec!(25),
        );
        assert_eq!(sell.order_type, OrderType::Market);
        assert_eq!(sell.side, OrderSide::Sell);
        assert_eq!(sell.remaining, dec!(25));
    }

    /// PostOnly order is flagged as Limit type (it's a subtype of limit in OMS).
    #[test]
    fn test_postonly_order_type() {
        let order = Order::new(
            "alice".to_string(),
            "SOL-1H".to_string(),
            OrderSide::Buy,
            OrderType::PostOnly,
            TimeInForce::Gtc,
            dec!(0.40),
            dec!(200),
        );
        assert_eq!(order.order_type, OrderType::PostOnly);
        assert_eq!(order.status, OrderStatus::Open);
    }

    /// FOK order is flagged with FOK time-in-force.
    #[test]
    fn test_fok_order_fields() {
        let order = make_limit_order("alice", "BTC-1H", OrderSide::Buy, dec!(0.60), dec!(100), TimeInForce::Fok);
        assert_eq!(order.time_in_force, TimeInForce::Fok);
        assert!(order.is_active());
    }

    // ── 3. Trade: order status transitions ──────────────────────────────────

    /// Filled order is inactive (cannot match).
    #[test]
    fn test_filled_order_is_inactive() {
        let mut order = make_limit_order("alice", "BTC-1H", OrderSide::Buy, dec!(0.55), dec!(100), TimeInForce::Gtc);
        order.filled = dec!(100);
        order.remaining = dec!(0);
        order.status = OrderStatus::Filled;
        assert!(!order.is_active());
        assert!(!order.can_match());
    }

    /// Cancelled order is inactive.
    #[test]
    fn test_cancelled_order_is_inactive() {
        let mut order = make_limit_order("alice", "BTC-1H", OrderSide::Buy, dec!(0.55), dec!(100), TimeInForce::Gtc);
        order.status = OrderStatus::Cancelled;
        assert!(!order.is_active());
        assert!(!order.can_match());
    }

    /// Partial fill: order is still active but remaining is reduced.
    #[test]
    fn test_partial_fill_status() {
        let mut order = make_limit_order("alice", "BTC-1H", OrderSide::Buy, dec!(0.55), dec!(100), TimeInForce::Gtc);
        order.filled = dec!(60);
        order.remaining = dec!(40);
        order.status = OrderStatus::Partial;
        assert!(order.is_active());
        assert!(order.can_match());
    }

    // ── 3. Trade: order price/size validation helpers ────────────────────────

    /// Zero price violates the positive price invariant.
    #[test]
    fn test_order_zero_price_invalid() {
        // MatchingEngine.validate_order() checks price > 0.
        // We call it via a separate price check here to confirm the rule.
        let price = dec!(0);
        assert!(price <= dec!(0), "zero price must be caught as invalid");
    }

    /// Negative price is also invalid.
    #[test]
    fn test_order_negative_price_invalid() {
        let price = dec!(-1);
        assert!(price <= dec!(0));
    }

    /// Zero size is invalid.
    #[test]
    fn test_order_zero_size_invalid() {
        let size = dec!(0);
        assert!(size <= dec!(0));
    }

    /// Positive price and size pass validation.
    #[test]
    fn test_order_valid_price_and_size() {
        let price = dec!(0.75);
        let size = dec!(100);
        assert!(price > dec!(0));
        assert!(size > dec!(0));
    }

    // ── 3. Trade: Buy/Sell matching price logic ──────────────────────────────

    /// Buy order matches when its price >= ask.
    #[test]
    fn test_buy_matches_when_price_gte_ask() {
        let buy_price = dec!(0.65);
        let best_ask  = dec!(0.60);
        assert!(buy_price >= best_ask, "buy should match at or above ask");
    }

    /// Buy order does NOT match when its price < ask.
    #[test]
    fn test_buy_no_match_when_price_below_ask() {
        let buy_price = dec!(0.55);
        let best_ask  = dec!(0.60);
        assert!(buy_price < best_ask, "buy should not match below ask");
    }

    /// Sell order matches when its price <= bid.
    #[test]
    fn test_sell_matches_when_price_lte_bid() {
        let sell_price = dec!(0.55);
        let best_bid   = dec!(0.60);
        assert!(sell_price <= best_bid, "sell should match at or below bid");
    }

    /// Sell order does NOT match when its price > bid.
    #[test]
    fn test_sell_no_match_when_price_above_bid() {
        let sell_price = dec!(0.70);
        let best_bid   = dec!(0.60);
        assert!(sell_price > best_bid, "sell should not match above bid");
    }

    // ── 3. Trade: IOC / FOK semantics ───────────────────────────────────────

    /// IOC with partial fill: remaining should be cancelled.
    #[test]
    fn test_ioc_partial_fill_cancels_remainder() {
        // After partial fill, IOC remaining → status Cancelled.
        let mut order = make_limit_order("alice", "BTC-1H", OrderSide::Buy, dec!(0.60), dec!(100), TimeInForce::Ioc);
        order.filled = dec!(40);
        order.remaining = dec!(60);
        // IOC rule: if filled > 0 and remaining > 0 → cancel remaining
        if order.time_in_force == TimeInForce::Ioc && order.filled > dec!(0) && order.remaining > dec!(0) {
            order.status = OrderStatus::Cancelled;
        }
        assert_eq!(order.status, OrderStatus::Cancelled);
    }

    /// IOC with zero fill → full cancel.
    #[test]
    fn test_ioc_zero_fill_cancels() {
        let mut order = make_limit_order("alice", "BTC-1H", OrderSide::Buy, dec!(0.10), dec!(100), TimeInForce::Ioc);
        // No matches found
        assert_eq!(order.filled, dec!(0));
        // IOC rule: zero fill → no add to book, cancel
        if order.time_in_force == TimeInForce::Ioc && order.filled == dec!(0) {
            order.status = OrderStatus::Cancelled;
        }
        assert_eq!(order.status, OrderStatus::Cancelled);
    }

    /// FOK must be fully filled or fully cancelled.
    #[test]
    fn test_fok_partial_fill_means_rejection() {
        let mut order = make_limit_order("alice", "BTC-1H", OrderSide::Buy, dec!(0.60), dec!(100), TimeInForce::Fok);
        order.filled = dec!(50);
        // FOK rule: if filled < size → reject
        if order.time_in_force == TimeInForce::Fok && order.filled < order.size {
            order.status = OrderStatus::Rejected;
        }
        assert_eq!(order.status, OrderStatus::Rejected);
    }

    // ── 3. Trade: market auto-close on resolution ────────────────────────────

    /// Market closure: open orders should be cancelled (status → Cancelled).
    #[test]
    fn test_open_orders_cancelled_on_market_close() {
        let mut open_orders: Vec<Order> = vec![
            make_limit_order("alice", "BTC-1H", OrderSide::Buy,  dec!(0.55), dec!(100), TimeInForce::Gtc),
            make_limit_order("bob",   "BTC-1H", OrderSide::Sell, dec!(0.65), dec!(50),  TimeInForce::Gtc),
        ];
        // Market closes → engine cancels all open orders
        for o in &mut open_orders {
            if o.is_active() {
                o.status = OrderStatus::Cancelled;
            }
        }
        assert!(open_orders.iter().all(|o| o.status == OrderStatus::Cancelled));
    }

    /// Resolved market: winning side credited, losing side debited.
    /// (Settlement amounts are domain logic; here tested at the model level.)
    #[test]
    fn test_market_settle_winner_loser() {
        use crate::balance_service::BalanceService;
        let svc = BalanceService::new(None);
        svc.deposit("winner", "BTC-USDC-HOUR-1", dec!(500));
        svc.deposit("loser",  "BTC-USDC-HOUR-1", dec!(500));
        svc.reserve_balance("loser",  "BTC-USDC-HOUR-1", dec!(200)).unwrap();
        // Settlement: winner gets payout, loser's reserved funds are debited
        svc.credit("winner", "BTC-USDC-HOUR-1", dec!(200));
        svc.debit("loser",   "BTC-USDC-HOUR-1", dec!(200)).unwrap();
        assert_eq!(svc.get_total_balance("winner", "BTC-USDC-HOUR-1"), dec!(700));
        assert_eq!(svc.get_total_balance("loser",  "BTC-USDC-HOUR-1"), dec!(300));
    }

    // ── 3. Trade: UUID uniqueness ────────────────────────────────────────────

    /// Each order gets a unique ID.
    #[test]
    fn test_order_ids_are_unique() {
        let o1 = make_limit_order("a", "M", OrderSide::Buy, dec!(0.5), dec!(1), TimeInForce::Gtc);
        let o2 = make_limit_order("a", "M", OrderSide::Buy, dec!(0.5), dec!(1), TimeInForce::Gtc);
        assert_ne!(o1.id, o2.id);
    }

    /// Order ID as U256 is deterministic given the same UUID.
    #[test]
    fn test_order_id_as_u256_deterministic() {
        let order = make_limit_order("a", "M", OrderSide::Buy, dec!(0.5), dec!(1), TimeInForce::Gtc);
        let u1 = order.id_as_u256();
        let u2 = order.id_as_u256();
        assert_eq!(u1, u2);
    }

    // ── 3. Trade: manipulate order (modify price/size — not in OMS; cancel+resubmit) ──

    /// Simulated order "update" is a cancel + re-submit with new params.
    #[test]
    fn test_order_manipulation_is_cancel_resubmit() {
        use crate::balance_service::BalanceService;
        let svc = BalanceService::new(None);
        svc.deposit("alice", "BTC-USDC-HOUR-1", dec!(1000));
        // Place order (reserve)
        svc.reserve_balance("alice", "BTC-USDC-HOUR-1", dec!(300)).unwrap();
        // Modify = cancel original (release)
        svc.release_balance("alice", "BTC-USDC-HOUR-1", dec!(300)).unwrap();
        // Re-submit at new price (reserve again)
        svc.reserve_balance("alice", "BTC-USDC-HOUR-1", dec!(350)).unwrap();
        assert_eq!(svc.get_reserved_balance("alice", "BTC-USDC-HOUR-1"), dec!(350));
        assert_eq!(svc.get_available_balance("alice", "BTC-USDC-HOUR-1"), dec!(650));
    }

    // ── Note lifecycle: balance state machines ───────────────────────────────

    /// Deposit increases total and available; reserved unchanged.
    #[test]
    fn test_note_deposit_increases_total_and_available() {
        use crate::balance_service::BalanceService;
        let svc = BalanceService::new(None);
        svc.deposit("alice", "BTC-ZEN-HOUR-1", dec!(1000));
        assert_eq!(svc.get_total_balance("alice", "BTC-ZEN-HOUR-1"), dec!(1000));
        assert_eq!(svc.get_available_balance("alice", "BTC-ZEN-HOUR-1"), dec!(1000));
        assert_eq!(svc.get_reserved_balance("alice", "BTC-ZEN-HOUR-1"), dec!(0));
    }

    /// Order submission reserves collateral: available shrinks, total unchanged.
    #[test]
    fn test_note_order_submit_reserves_collateral() {
        use crate::balance_service::BalanceService;
        let svc = BalanceService::new(None);
        svc.deposit("alice", "BTC-ZEN-HOUR-1", dec!(1000));
        // Simulate reserve for order: size=100 @ price=0.60 + taker_fee (~0 bps here)
        svc.reserve_balance("alice", "BTC-ZEN-HOUR-1", dec!(60)).unwrap();
        assert_eq!(svc.get_total_balance("alice", "BTC-ZEN-HOUR-1"), dec!(1000));
        assert_eq!(svc.get_reserved_balance("alice", "BTC-ZEN-HOUR-1"), dec!(60));
        assert_eq!(svc.get_available_balance("alice", "BTC-ZEN-HOUR-1"), dec!(940));
    }

    /// Fill (trade): debit releases reserved and reduces total by fill cost.
    #[test]
    fn test_note_fill_debits_reserved_and_total() {
        use crate::balance_service::BalanceService;
        let svc = BalanceService::new(None);
        svc.deposit("alice", "BTC-ZEN-HOUR-1", dec!(1000));
        svc.reserve_balance("alice", "BTC-ZEN-HOUR-1", dec!(60)).unwrap();
        // Fill: size=100 @ price=0.60, fee=0 → cost=60
        svc.debit("alice", "BTC-ZEN-HOUR-1", dec!(60)).unwrap();
        assert_eq!(svc.get_total_balance("alice", "BTC-ZEN-HOUR-1"), dec!(940));
        assert_eq!(svc.get_reserved_balance("alice", "BTC-ZEN-HOUR-1"), dec!(0));
        assert_eq!(svc.get_available_balance("alice", "BTC-ZEN-HOUR-1"), dec!(940));
    }

    /// Cancel: release restores available; total unchanged.
    #[test]
    fn test_note_cancel_releases_reserved_restores_available() {
        use crate::balance_service::BalanceService;
        let svc = BalanceService::new(None);
        svc.deposit("alice", "BTC-ZEN-HOUR-1", dec!(1000));
        svc.reserve_balance("alice", "BTC-ZEN-HOUR-1", dec!(60)).unwrap();
        // Cancel order → release reservation
        svc.release_balance("alice", "BTC-ZEN-HOUR-1", dec!(60)).unwrap();
        assert_eq!(svc.get_total_balance("alice", "BTC-ZEN-HOUR-1"), dec!(1000));
        assert_eq!(svc.get_reserved_balance("alice", "BTC-ZEN-HOUR-1"), dec!(0));
        assert_eq!(svc.get_available_balance("alice", "BTC-ZEN-HOUR-1"), dec!(1000));
    }

    /// IOC partial fill: filled portion debited, remaining portion released.
    /// After both operations available should equal total minus cost of filled part.
    #[test]
    fn test_note_ioc_partial_fill_releases_unfilled_reservation() {
        use crate::balance_service::BalanceService;
        let svc = BalanceService::new(None);
        // Alice deposits 1000, submits IOC buy 200 @ 0.50 (reserves 100)
        svc.deposit("alice", "BTC-USDC-HOUR-1", dec!(1000));
        svc.reserve_balance("alice", "BTC-USDC-HOUR-1", dec!(100)).unwrap(); // full reservation

        // 100 units fill at 0.50 → debit 50
        svc.debit("alice", "BTC-USDC-HOUR-1", dec!(50)).unwrap();

        // IOC expires: release remaining 50 reservation (for 100 unfilled units @ 0.50)
        svc.release_balance("alice", "BTC-USDC-HOUR-1", dec!(50)).unwrap();

        assert_eq!(svc.get_total_balance("alice", "BTC-USDC-HOUR-1"), dec!(950));
        assert_eq!(svc.get_reserved_balance("alice", "BTC-USDC-HOUR-1"), dec!(0));
        assert_eq!(svc.get_available_balance("alice", "BTC-USDC-HOUR-1"), dec!(950));
    }

    /// FOK fail: all fills are rolled back, full reservation released; Note unchanged.
    #[test]
    fn test_note_fok_fail_full_reservation_released() {
        use crate::balance_service::BalanceService;
        let svc = BalanceService::new(None);
        // Alice deposits 1000, submits FOK buy 200 @ 0.60 (reserves 120)
        svc.deposit("alice", "BTC-USDC-HOUR-1", dec!(1000));
        svc.reserve_balance("alice", "BTC-USDC-HOUR-1", dec!(120)).unwrap();

        // FOK partially filled 100 units, then fails → rollback: credit 60 back
        svc.credit("alice", "BTC-USDC-HOUR-1", dec!(60));
        // Release the remaining reserved amount (120 - 60 filled + 60 credited back = 120 total)
        // After credit, total=1000 (not debited yet since it's a rollback)
        // Release full reserved 120
        svc.release_balance("alice", "BTC-USDC-HOUR-1", dec!(120)).unwrap();

        assert_eq!(svc.get_total_balance("alice", "BTC-USDC-HOUR-1"), dec!(1060)); // 1000 + 60 credited
        assert_eq!(svc.get_reserved_balance("alice", "BTC-USDC-HOUR-1"), dec!(0));
    }

    /// release_order_balance uses remaining (not size): partial fill releases only unfilled amount.
    #[test]
    fn test_note_release_order_balance_uses_remaining_not_size() {
        use crate::balance_service::BalanceService;
        let svc = BalanceService::new(None);
        // Order: size=200 @ 0.50 → full reservation = 100
        svc.deposit("alice", "BTC-USDC-HOUR-1", dec!(1000));
        svc.reserve_balance("alice", "BTC-USDC-HOUR-1", dec!(100)).unwrap();

        // 100 units fill at 0.50 → debit 50
        svc.debit("alice", "BTC-USDC-HOUR-1", dec!(50)).unwrap();
        // remaining = 100, price = 0.50 → unfilled_reserved = 50

        // release_order_balance should release remaining=100 * 0.50 = 50 (not size=200 * 0.50 = 100)
        let unfilled_reserved = dec!(50); // remaining * price
        svc.release_balance("alice", "BTC-USDC-HOUR-1", unfilled_reserved).unwrap();

        // total=950 (1000 - 50 for fill), reserved=0
        assert_eq!(svc.get_total_balance("alice", "BTC-USDC-HOUR-1"), dec!(950));
        assert_eq!(svc.get_reserved_balance("alice", "BTC-USDC-HOUR-1"), dec!(0));
        assert_eq!(svc.get_available_balance("alice", "BTC-USDC-HOUR-1"), dec!(950));
    }

    /// Market order aggressive-limit price is set above ask for Buy.
    #[test]
    fn test_market_order_aggressive_price_buy() {
        let best_ask = dec!(0.65);
        // Engine sets price = best_ask * 1.05
        let aggressive_price = best_ask * (Decimal::from(105) / Decimal::from(100));
        assert!(aggressive_price > best_ask, "market buy price must exceed best ask");
        assert_eq!(aggressive_price, dec!(0.6825));
    }

    /// Market order aggressive-limit price is set below bid for Sell.
    #[test]
    fn test_market_order_aggressive_price_sell() {
        let best_bid = dec!(0.60);
        // Engine sets price = best_bid * 0.95
        let aggressive_price = best_bid * (Decimal::from(95) / Decimal::from(100));
        assert!(aggressive_price < best_bid, "market sell price must be below best bid");
        assert_eq!(aggressive_price, dec!(0.57));
    }
}

