#![allow(dead_code)]

use crate::error::ClobResult;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, warn};

/// User-specific rate limiting tiers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitTier {
    Free,       // 10 req/min
    Basic,      // 60 req/min
    Premium,    // 300 req/min
    Maker,      // 1000 req/min (market makers)
    Unlimited,  // No limits (internal/admin)
}

impl RateLimitTier {
    pub fn requests_per_minute(&self) -> u32 {
        match self {
            Self::Free => 10,
            Self::Basic => 60,
            Self::Premium => 300,
            Self::Maker => 1000,
            Self::Unlimited => u32::MAX,
        }
    }

    pub fn burst_size(&self) -> u32 {
        match self {
            Self::Free => 5,
            Self::Basic => 10,
            Self::Premium => 50,
            Self::Maker => 100,
            Self::Unlimited => u32::MAX,
        }
    }
}

/// Token bucket for user rate limiting
#[derive(Debug, Clone)]
struct UserTokenBucket {
    tokens: f64,
    capacity: f64,
    refill_rate: f64,  // tokens per second
    last_refill: i64,
    tier: RateLimitTier,
}

impl UserTokenBucket {
    fn new(tier: RateLimitTier) -> Self {
        let capacity = tier.burst_size() as f64;
        Self {
            tokens: capacity,
            capacity,
            refill_rate: tier.requests_per_minute() as f64 / 60.0,
            last_refill: chrono::Utc::now().timestamp(),
            tier,
        }
    }

    fn refill(&mut self) {
        let now = chrono::Utc::now().timestamp();
        let time_passed = (now - self.last_refill) as f64;
        
        self.tokens = (self.tokens + time_passed * self.refill_rate).min(self.capacity);
        self.last_refill = now;
    }

    fn try_consume(&mut self, tokens: f64) -> bool {
        self.refill();
        
        if self.tokens >= tokens {
            self.tokens -= tokens;
            true
        } else {
            false
        }
    }

    fn available_tokens(&self) -> u32 {
        self.tokens as u32
    }
}

/// Per-user rate limiter
pub struct UserRateLimiter {
    buckets: Arc<RwLock<HashMap<String, UserTokenBucket>>>,
    tiers: Arc<RwLock<HashMap<String, RateLimitTier>>>,
    default_tier: RateLimitTier,
}

impl UserRateLimiter {
    pub fn new(default_tier: RateLimitTier) -> Self {
        Self {
            buckets: Arc::new(RwLock::new(HashMap::new())),
            tiers: Arc::new(RwLock::new(HashMap::new())),
            default_tier,
        }
    }

    /// Check if user can make a request
    pub async fn check_rate_limit(&self, user_id: &str) -> ClobResult<bool> {
        self.check_rate_limit_with_cost(user_id, 1.0).await
    }

    /// Check rate limit with custom cost
    /// Heavy operations can cost more tokens
    pub async fn check_rate_limit_with_cost(&self, user_id: &str, cost: f64) -> ClobResult<bool> {
        let mut buckets = self.buckets.write().await;
        
        // Get or create bucket for user
        let bucket = buckets.entry(user_id.to_string()).or_insert_with(|| {
            let tier = self.get_user_tier_sync(user_id);
            UserTokenBucket::new(tier)
        });

        let allowed = bucket.try_consume(cost);
        
        if !allowed {
            warn!(
                user_id = %user_id,
                cost = %cost,
                available = %bucket.available_tokens(),
                tier = ?bucket.tier,
                "User rate limit exceeded"
            );
        } else {
            debug!(
                user_id = %user_id,
                cost = %cost,
                remaining = %bucket.available_tokens(),
                "Rate limit check passed"
            );
        }

        Ok(allowed)
    }

    /// Set user rate limit tier
    pub async fn set_user_tier(&self, user_id: &str, tier: RateLimitTier) {
        let mut tiers = self.tiers.write().await;
        tiers.insert(user_id.to_string(), tier);
        
        // Update existing bucket if present and refill to new capacity
        let mut buckets = self.buckets.write().await;
        if let Some(bucket) = buckets.get_mut(user_id) {
            bucket.tier = tier;
            bucket.capacity = tier.burst_size() as f64;
            bucket.refill_rate = tier.requests_per_minute() as f64 / 60.0;
            bucket.tokens = bucket.capacity; // Refill to new capacity on upgrade
            bucket.last_refill = chrono::Utc::now().timestamp();
        }
        
        debug!(
            user_id = %user_id,
            tier = ?tier,
            "User rate limit tier updated"
        );
    }

    /// Get user's current tier
    pub async fn get_user_tier(&self, user_id: &str) -> RateLimitTier {
        let tiers = self.tiers.read().await;
        tiers.get(user_id).copied().unwrap_or(self.default_tier)
    }

    fn get_user_tier_sync(&self, _user_id: &str) -> RateLimitTier {
        // For use during bucket creation - uses default tier
        // Actual tier updates are handled by set_user_tier
        self.default_tier
    }

    /// Get user's remaining quota
    pub async fn get_user_quota(&self, user_id: &str) -> (u32, u32) {
        let buckets = self.buckets.read().await;
        
        if let Some(bucket) = buckets.get(user_id) {
            let available = bucket.available_tokens();
            let total = bucket.tier.burst_size();
            (available, total)
        } else {
            let tier = self.get_user_tier(user_id).await;
            (tier.burst_size(), tier.burst_size())
        }
    }

    /// Get all users and their tiers (for admin)
    pub async fn get_all_tiers(&self) -> HashMap<String, RateLimitTier> {
        self.tiers.read().await.clone()
    }

    /// Clean up idle users (not used in last hour)
    pub async fn cleanup_idle_users(&self) -> usize {
        let cutoff = chrono::Utc::now().timestamp() - 3600;
        let mut buckets = self.buckets.write().await;
        
        let original_count = buckets.len();
        buckets.retain(|_, bucket| bucket.last_refill > cutoff);
        
        let removed = original_count - buckets.len();
        if removed > 0 {
            debug!(removed = %removed, "Cleaned up idle user rate limit buckets");
        }
        
        removed
    }

    /// Get rate limit stats
    pub async fn get_stats(&self) -> HashMap<String, u32> {
        let buckets = self.buckets.read().await;
        let tiers = self.tiers.read().await;
        
        let mut stats = HashMap::new();
        stats.insert("total_users".to_string(), buckets.len() as u32);
        stats.insert("total_tiers".to_string(), tiers.len() as u32);
        
        // Count users by tier
        let mut tier_counts: HashMap<String, u32> = HashMap::new();
        for bucket in buckets.values() {
            let tier_name = format!("{:?}", bucket.tier);
            *tier_counts.entry(tier_name).or_insert(0) += 1;
        }
        
        for (tier, count) in tier_counts {
            stats.insert(format!("tier_{}", tier.to_lowercase()), count);
        }
        
        stats
    }
}

impl Default for UserRateLimiter {
    fn default() -> Self {
        Self::new(RateLimitTier::Basic)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_user_rate_limit() {
        let limiter = UserRateLimiter::new(RateLimitTier::Free); // 10 req/min
        
        // First request should succeed
        assert!(limiter.check_rate_limit("user1").await.unwrap());
        
        // Burst should work up to limit
        for _ in 0..4 {
            assert!(limiter.check_rate_limit("user1").await.unwrap());
        }
        
        // Should hit limit
        assert!(!limiter.check_rate_limit("user1").await.unwrap());
    }

    #[tokio::test]
    async fn test_tier_upgrade() {
        let limiter = UserRateLimiter::new(RateLimitTier::Free);
        
        // Exhaust free tier
        for _ in 0..5 {
            limiter.check_rate_limit("user2").await.unwrap();
        }
        assert!(!limiter.check_rate_limit("user2").await.unwrap());
        
        // Upgrade to premium
        limiter.set_user_tier("user2", RateLimitTier::Premium).await;
        
        // Should now have more quota
        assert!(limiter.check_rate_limit("user2").await.unwrap());
    }

    #[tokio::test]
    async fn test_weighted_cost() {
        let limiter = UserRateLimiter::new(RateLimitTier::Basic);
        
        // Heavy operation costs 5 tokens
        assert!(limiter.check_rate_limit_with_cost("user3", 5.0).await.unwrap());
        
        // Should have fewer tokens left
        let (available, total) = limiter.get_user_quota("user3").await;
        assert!(available < total);
    }

    #[tokio::test]
    async fn test_quota_info() {
        let limiter = UserRateLimiter::new(RateLimitTier::Basic);
        
        let (available, total) = limiter.get_user_quota("user4").await;
        assert_eq!(total, 10); // Basic tier burst size
        assert_eq!(available, 10); // No requests yet
    }

    #[tokio::test]
    async fn test_stats() {
        let limiter = UserRateLimiter::new(RateLimitTier::Basic);
        
        limiter.check_rate_limit("user5").await.unwrap();
        limiter.check_rate_limit("user6").await.unwrap();
        limiter.set_user_tier("user5", RateLimitTier::Maker).await;
        
        let stats = limiter.get_stats().await;
        assert_eq!(stats.get("total_users").unwrap(), &2);
    }
}
