use crate::error::{ClobError, ClobResult};
use dashmap::DashMap;
use rust_decimal::Decimal;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Balance service - manages user balances for trading
/// 
/// Production modes:
/// 1. In-memory (default) - Fast for testing, no persistence
/// 2. On-chain (future) - Read from LiquidityVaultV1.sol via RPC
/// 3. Hybrid - Cache on-chain balances with periodic sync
pub struct BalanceService {
    /// In-memory balance storage: user_id -> market_id -> balance
    balances: Arc<DashMap<String, DashMap<String, Decimal>>>,
    /// Reserved (locked) balances: user_id -> market_id -> reserved_amount
    reserved: Arc<DashMap<String, DashMap<String, Decimal>>>,
}

impl BalanceService {
    pub fn new() -> Self {
        Self {
            balances: Arc::new(DashMap::new()),
            reserved: Arc::new(DashMap::new()),
        }
    }

    /// Get available (unreserved) balance for user in market
    pub fn get_available_balance(&self, user_id: &str, market_id: &str) -> Decimal {
        let total = self.get_total_balance(user_id, market_id);
        let reserved = self.get_reserved_balance(user_id, market_id);
        total - reserved
    }

    /// Get total balance (including reserved)
    pub fn get_total_balance(&self, user_id: &str, market_id: &str) -> Decimal {
        self.balances
            .get(user_id)
            .and_then(|user_balances| user_balances.get(market_id).map(|b| *b))
            .unwrap_or(Decimal::ZERO)
    }

    /// Get reserved (locked) balance
    pub fn get_reserved_balance(&self, user_id: &str, market_id: &str) -> Decimal {
        self.reserved
            .get(user_id)
            .and_then(|user_reserved| user_reserved.get(market_id).map(|r| *r))
            .unwrap_or(Decimal::ZERO)
    }

    /// Reserve balance for an order (lock funds)
    pub fn reserve_balance(
        &self,
        user_id: &str,
        market_id: &str,
        amount: Decimal,
    ) -> ClobResult<()> {
        let available = self.get_available_balance(user_id, market_id);
        
        if available < amount {
            return Err(ClobError::InsufficientBalance {
                required: amount,
                available,
            });
        }

        // Add to reserved
        let user_reserved = self.reserved.entry(user_id.to_string()).or_insert_with(DashMap::new);
        user_reserved
            .entry(market_id.to_string())
            .and_modify(|r| *r += amount)
            .or_insert(amount);

        debug!(
            user_id = %user_id,
            market_id = %market_id,
            amount = %amount,
            "Balance reserved"
        );

        Ok(())
    }

    /// Release reserved balance (unlock funds, e.g., on order cancellation)
    pub fn release_balance(
        &self,
        user_id: &str,
        market_id: &str,
        amount: Decimal,
    ) -> ClobResult<()> {
        let user_reserved = self.reserved.entry(user_id.to_string()).or_insert_with(DashMap::new);
        
        let current_reserved = user_reserved
            .get(market_id)
            .map(|r| *r)
            .unwrap_or(Decimal::ZERO);

        if current_reserved < amount {
            warn!(
                user_id = %user_id,
                market_id = %market_id,
                requested = %amount,
                reserved = %current_reserved,
                "Attempted to release more than reserved"
            );
            return Err(ClobError::InvalidOrder(
                "Cannot release more than reserved".to_string(),
            ));
        }

        user_reserved
            .entry(market_id.to_string())
            .and_modify(|r| *r -= amount);

        debug!(
            user_id = %user_id,
            market_id = %market_id,
            amount = %amount,
            "Balance released"
        );

        Ok(())
    }

    /// Debit balance (remove from total, used when order fills)
    pub fn debit(
        &self,
        user_id: &str,
        market_id: &str,
        amount: Decimal,
    ) -> ClobResult<()> {
        // First release from reserved (since order execution consumes reserved funds)
        self.release_balance(user_id, market_id, amount)?;

        // Then debit from total
        let user_balances = self.balances.entry(user_id.to_string()).or_insert_with(DashMap::new);
        
        let current_balance = user_balances
            .get(market_id)
            .map(|b| *b)
            .unwrap_or(Decimal::ZERO);

        if current_balance < amount {
            return Err(ClobError::InsufficientBalance {
                required: amount,
                available: current_balance,
            });
        }

        user_balances
            .entry(market_id.to_string())
            .and_modify(|b| *b -= amount);

        debug!(
            user_id = %user_id,
            market_id = %market_id,
            amount = %amount,
            "Balance debited"
        );

        Ok(())
    }

    /// Credit balance (add to total, used when receiving trade proceeds)
    pub fn credit(
        &self,
        user_id: &str,
        market_id: &str,
        amount: Decimal,
    ) {
        let user_balances = self.balances.entry(user_id.to_string()).or_insert_with(DashMap::new);
        
        user_balances
            .entry(market_id.to_string())
            .and_modify(|b| *b += amount)
            .or_insert(amount);

        debug!(
            user_id = %user_id,
            market_id = %market_id,
            amount = %amount,
            "Balance credited"
        );
    }

    /// Deposit funds (e.g., from on-chain deposit or initial test balance)
    pub fn deposit(
        &self,
        user_id: &str,
        market_id: &str,
        amount: Decimal,
    ) {
        self.credit(user_id, market_id, amount);
        
        info!(
            user_id = %user_id,
            market_id = %market_id,
            amount = %amount,
            "Deposit processed"
        );
    }

    /// Withdraw funds (e.g., to on-chain withdrawal)
    pub fn withdraw(
        &self,
        user_id: &str,
        market_id: &str,
        amount: Decimal,
    ) -> ClobResult<()> {
        let available = self.get_available_balance(user_id, market_id);
        
        if available < amount {
            return Err(ClobError::InsufficientBalance {
                required: amount,
                available,
            });
        }

        self.debit(user_id, market_id, amount)?;
        
        Ok(())
    }

    /// Release reserved and adjust total balance (for trade settlement)
    /// This is used when settling trades where the reserved amount differs from the consumed amount
    pub fn release_and_adjust(
        &self,
        user_id: &str,
        market_id: &str,
        release_amount: Decimal,
        balance_delta: Decimal,  // Can be negative
    ) -> ClobResult<()> {
        // Release from reserved
        self.release_balance(user_id, market_id, release_amount)?;
        
        // Adjust total balance
        let user_balances = self.balances.entry(user_id.to_string()).or_insert_with(DashMap::new);
        user_balances.entry(market_id.to_string())
            .and_modify(|b| *b += balance_delta)
            .or_insert(balance_delta);
        
        debug!(
            user_id = %user_id,
            market_id = %market_id,
            release = %release_amount,
            delta = %balance_delta,
            "Balance released and adjusted for trade"
        );
        
        Ok(())
    }
}

impl Default for BalanceService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal_macros::dec;

    #[test]
    fn test_deposit_and_balance() {
        let service = BalanceService::new();
        
        service.deposit("alice", "BTC-HOUR-1", dec!(1000));
        assert_eq!(service.get_total_balance("alice", "BTC-HOUR-1"), dec!(1000));
        assert_eq!(service.get_available_balance("alice", "BTC-HOUR-1"), dec!(1000));
    }

    #[test]
    fn test_reserve_and_release() {
        let service = BalanceService::new();
        service.deposit("alice", "BTC-HOUR-1", dec!(1000));

        // Reserve 300
        service.reserve_balance("alice", "BTC-HOUR-1", dec!(300)).unwrap();
        assert_eq!(service.get_total_balance("alice", "BTC-HOUR-1"), dec!(1000));
        assert_eq!(service.get_available_balance("alice", "BTC-HOUR-1"), dec!(700));
        assert_eq!(service.get_reserved_balance("alice", "BTC-HOUR-1"), dec!(300));

        // Release 100
        service.release_balance("alice", "BTC-HOUR-1", dec!(100)).unwrap();
        assert_eq!(service.get_available_balance("alice", "BTC-HOUR-1"), dec!(800));
        assert_eq!(service.get_reserved_balance("alice", "BTC-HOUR-1"), dec!(200));
    }

    #[test]
    fn test_debit_and_credit() {
        let service = BalanceService::new();
        service.deposit("alice", "BTC-HOUR-1", dec!(1000));
        service.reserve_balance("alice", "BTC-HOUR-1", dec!(300)).unwrap();

        // Debit 200 (releases from reserved and deducts from total)
        service.debit("alice", "BTC-HOUR-1", dec!(200)).unwrap();
        assert_eq!(service.get_total_balance("alice", "BTC-HOUR-1"), dec!(800));
        assert_eq!(service.get_reserved_balance("alice", "BTC-HOUR-1"), dec!(100));

        // Credit 50
        service.credit("alice", "BTC-HOUR-1", dec!(50));
        assert_eq!(service.get_total_balance("alice", "BTC-HOUR-1"), dec!(850));
    }

    #[test]
    fn test_insufficient_balance_error() {
        let service = BalanceService::new();
        service.deposit("alice", "BTC-HOUR-1", dec!(100));

        let result = service.reserve_balance("alice", "BTC-HOUR-1", dec!(200));
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ClobError::InsufficientBalance { .. }));
    }

    #[test]
    fn test_multiple_users_and_markets() {
        let service = BalanceService::new();
        
        service.deposit("alice", "BTC-HOUR-1", dec!(1000));
        service.deposit("alice", "ETH-HOUR-1", dec!(2000));
        service.deposit("bob", "BTC-HOUR-1", dec!(500));

        assert_eq!(service.get_total_balance("alice", "BTC-HOUR-1"), dec!(1000));
        assert_eq!(service.get_total_balance("alice", "ETH-HOUR-1"), dec!(2000));
        assert_eq!(service.get_total_balance("bob", "BTC-HOUR-1"), dec!(500));
        assert_eq!(service.get_total_balance("bob", "ETH-HOUR-1"), dec!(0));
    }
}
