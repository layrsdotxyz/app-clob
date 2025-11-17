use crate::{
    error::{ClobError, ClobResult},
    models::*,
    redis_store::RedisStore,
};
use rust_decimal::Decimal;
use std::sync::Arc;

pub struct SettlementEngine {
    store: Arc<RedisStore>,
    maker_fee_bps: u16,
    taker_fee_bps: u16,
}

impl SettlementEngine {
    pub fn new(store: Arc<RedisStore>, maker_fee_bps: u16, taker_fee_bps: u16) -> Self {
        Self { store, maker_fee_bps, taker_fee_bps }
    }

    /// Check if user has sufficient balance for order
    pub async fn check_balance(
        &self,
        user_id: &str,
        market_id: &str,
        order: &Order,
    ) -> ClobResult<()> {
        let required = self.calculate_required_balance(order);
        let available = self.get_user_balance(user_id, market_id).await?;
        
        if available < required {
            return Err(ClobError::InsufficientBalance {
                required,
                available,
            });
        }
        
        // Reserve balance for order
        self.reserve_balance(user_id, market_id, required).await?;
        
        Ok(())
    }

    /// Calculate required balance for order (size * price + estimated fees)
    fn calculate_required_balance(&self, order: &Order) -> Decimal {
        let notional = order.size * order.price;
        let fee = self.calculate_fee(order.size, order.price, false);
        notional + fee
    }

    /// Calculate fee for a fill
    pub fn calculate_fee(&self, size: Decimal, price: Decimal, is_maker: bool) -> Decimal {
        let notional = size * price;
        let fee_bps = if is_maker { self.maker_fee_bps } else { self.taker_fee_bps };
        notional * Decimal::from(fee_bps) / Decimal::from(10_000)
    }

    /// Settle a trade (update balances, record trade)
    pub async fn settle_trade(
        &self,
        trade: &Trade,
        maker_fill: &Fill,
        taker_fill: &Fill,
    ) -> ClobResult<()> {
        // Save trade to Redis
        self.store.save_trade(trade).await?;
        
        // Update market stats
        self.store.update_market_stats(trade).await?;
        
        // Update user balances
        self.update_balances_for_trade(trade, maker_fill, taker_fill).await?;
        
        tracing::info!(
            trade_id = %trade.id,
            maker = %trade.maker_user_id,
            taker = %trade.taker_user_id,
            price = %trade.price,
            size = %trade.size,
            "Trade settled"
        );
        
        Ok(())
    }

    /// Rollback a fill (used for FOK cancellation)
    pub async fn rollback_fill(&self, _fill: &Fill) -> ClobResult<()> {
        // TODO: Implement balance rollback
        tracing::warn!("Fill rollback not yet implemented");
        Ok(())
    }

    /// Release reserved balance when order is cancelled
    pub async fn release_order_balance(&self, order: &Order) -> ClobResult<()> {
        let reserved = self.calculate_required_balance(order);
        self.release_balance(&order.user_id, &order.market_id, reserved).await?;
        Ok(())
    }

    // ==================== Balance Management ====================

    async fn get_user_balance(&self, user_id: &str, market_id: &str) -> ClobResult<Decimal> {
        // TODO: Integrate with balance service or on-chain wallet
        // For now, return a large balance for testing
        let _ = (user_id, market_id);
        Ok(Decimal::from(1_000_000))
    }

    async fn reserve_balance(
        &self,
        user_id: &str,
        market_id: &str,
        amount: Decimal,
    ) -> ClobResult<()> {
        // TODO: Implement balance reservation
        tracing::debug!(
            user_id = %user_id,
            market_id = %market_id,
            amount = %amount,
            "Balance reserved"
        );
        Ok(())
    }

    async fn release_balance(
        &self,
        user_id: &str,
        market_id: &str,
        amount: Decimal,
    ) -> ClobResult<()> {
        // TODO: Implement balance release
        tracing::debug!(
            user_id = %user_id,
            market_id = %market_id,
            amount = %amount,
            "Balance released"
        );
        Ok(())
    }

    async fn update_balances_for_trade(
        &self,
        trade: &Trade,
        maker_fill: &Fill,
        taker_fill: &Fill,
    ) -> ClobResult<()> {
        // TODO: Implement actual balance transfers
        tracing::debug!(
            trade_id = %trade.id,
            maker_fee = %maker_fill.fee,
            taker_fee = %taker_fill.fee,
            "Balances updated for trade"
        );
        Ok(())
    }
}
