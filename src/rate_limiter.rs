use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;

/// Rate limiter using token bucket algorithm
#[derive(Clone)]
pub struct RateLimiter {
    buckets: Arc<RwLock<HashMap<String, TokenBucket>>>,
    requests_per_minute: u32,
    burst_size: u32,
}

struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

impl RateLimiter {
    pub fn new(requests_per_minute: u32, burst_size: u32) -> Self {
        Self {
            buckets: Arc::new(RwLock::new(HashMap::new())),
            requests_per_minute,
            burst_size,
        }
    }

    pub async fn check_rate_limit(&self, key: &str) -> bool {
        let mut buckets = self.buckets.write().await;
        let bucket = buckets.entry(key.to_string()).or_insert(TokenBucket {
            tokens: self.burst_size as f64,
            last_refill: Instant::now(),
        });

        // Refill tokens based on time elapsed
        let now = Instant::now();
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        let refill_rate = self.requests_per_minute as f64 / 60.0; // tokens per second
        bucket.tokens = (bucket.tokens + elapsed * refill_rate).min(self.burst_size as f64);
        bucket.last_refill = now;

        // Check if we have tokens available
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Cleanup old entries periodically
    pub async fn cleanup(&self) {
        let mut buckets = self.buckets.write().await;
        let now = Instant::now();
        buckets
            .retain(|_, bucket| now.duration_since(bucket.last_refill) < Duration::from_secs(300));
    }
}

/// Rate limiting middleware
pub async fn rate_limit_middleware(request: Request, next: Next) -> Response {
    // Extract rate limiter from extensions if available
    let limiter = request.extensions().get::<RateLimiter>().cloned();

    if let Some(limiter) = limiter {
        // Use IP address as key (in production, use user_id if authenticated)
        let key = request
            .headers()
            .get("x-forwarded-for")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("unknown")
            .to_string();

        if !limiter.check_rate_limit(&key).await {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                "Rate limit exceeded. Please try again later.",
            )
                .into_response();
        }
    }

    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_limiter() {
        let limiter = RateLimiter::new(60, 10); // 60 req/min, burst 10

        // Should allow burst
        for _ in 0..10 {
            assert!(limiter.check_rate_limit("test_user").await);
        }

        // Should deny after burst
        assert!(!limiter.check_rate_limit("test_user").await);
    }

    #[tokio::test]
    async fn test_token_refill() {
        let limiter = RateLimiter::new(60, 5);

        // Use all tokens
        for _ in 0..5 {
            assert!(limiter.check_rate_limit("test_user").await);
        }
        assert!(!limiter.check_rate_limit("test_user").await);

        // Wait for refill (1 second = 1 token at 60 req/min)
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(limiter.check_rate_limit("test_user").await);
    }
}
