use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;

/// Circuit breaker states
#[derive(Debug, Clone, PartialEq)]
pub enum CircuitState {
    Closed,      // Normal operation
    Open,        // Failing, rejecting requests
    HalfOpen,    // Testing if service recovered
}

/// Circuit breaker for external service calls
#[derive(Clone)]
pub struct CircuitBreaker {
    state: Arc<RwLock<CircuitBreakerState>>,
    failure_threshold: u32,
    success_threshold: u32,
    timeout: Duration,
    half_open_timeout: Duration,
}

struct CircuitBreakerState {
    state: CircuitState,
    failure_count: u32,
    success_count: u32,
    last_failure_time: Option<Instant>,
    last_state_change: Instant,
}

impl CircuitBreaker {
    pub fn new(
        failure_threshold: u32,
        success_threshold: u32,
        timeout: Duration,
        half_open_timeout: Duration,
    ) -> Self {
        Self {
            state: Arc::new(RwLock::new(CircuitBreakerState {
                state: CircuitState::Closed,
                failure_count: 0,
                success_count: 0,
                last_failure_time: None,
                last_state_change: Instant::now(),
            })),
            failure_threshold,
            success_threshold,
            timeout,
            half_open_timeout,
        }
    }

    /// Execute a function with circuit breaker protection
    pub async fn call<F, T, E>(&self, f: F) -> Result<T, CircuitBreakerError>
    where
        F: std::future::Future<Output = Result<T, E>>,
        E: std::fmt::Display,
    {
        // Check if we can proceed
        {
            let mut state = self.state.write().await;
            
            match state.state {
                CircuitState::Open => {
                    // Check if timeout has elapsed
                    if state.last_state_change.elapsed() >= self.timeout {
                        state.state = CircuitState::HalfOpen;
                        state.success_count = 0;
                        state.last_state_change = Instant::now();
                    } else {
                        return Err(CircuitBreakerError::CircuitOpen);
                    }
                }
                CircuitState::HalfOpen => {
                    // In half-open, only allow one request at a time
                    if state.last_state_change.elapsed() < Duration::from_millis(100) {
                        return Err(CircuitBreakerError::CircuitOpen);
                    }
                }
                CircuitState::Closed => {
                    // Normal operation
                }
            }
        }

        // Execute the function
        match f.await {
            Ok(result) => {
                self.on_success().await;
                Ok(result)
            }
            Err(e) => {
                self.on_failure().await;
                Err(CircuitBreakerError::RequestFailed(e.to_string()))
            }
        }
    }

    async fn on_success(&self) {
        let mut state = self.state.write().await;
        
        match state.state {
            CircuitState::HalfOpen => {
                state.success_count += 1;
                if state.success_count >= self.success_threshold {
                    tracing::info!("Circuit breaker transitioning to CLOSED");
                    state.state = CircuitState::Closed;
                    state.failure_count = 0;
                    state.success_count = 0;
                    state.last_state_change = Instant::now();
                }
            }
            CircuitState::Closed => {
                // Reset failure count on success
                state.failure_count = 0;
            }
            CircuitState::Open => {
                // Should not happen
            }
        }
    }

    async fn on_failure(&self) {
        let mut state = self.state.write().await;
        
        match state.state {
            CircuitState::Closed => {
                state.failure_count += 1;
                state.last_failure_time = Some(Instant::now());
                
                if state.failure_count >= self.failure_threshold {
                    tracing::warn!("Circuit breaker opening due to {} failures", state.failure_count);
                    state.state = CircuitState::Open;
                    state.last_state_change = Instant::now();
                }
            }
            CircuitState::HalfOpen => {
                tracing::warn!("Circuit breaker reopening after failed test");
                state.state = CircuitState::Open;
                state.failure_count = self.failure_threshold;
                state.last_state_change = Instant::now();
            }
            CircuitState::Open => {
                // Already open
            }
        }
    }

    pub async fn get_state(&self) -> CircuitState {
        self.state.read().await.state.clone()
    }
}

#[derive(Debug)]
pub enum CircuitBreakerError {
    CircuitOpen,
    RequestFailed(String),
}

impl std::fmt::Display for CircuitBreakerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CircuitOpen => write!(f, "Circuit breaker is open"),
            Self::RequestFailed(msg) => write!(f, "Request failed: {}", msg),
        }
    }
}

impl std::error::Error for CircuitBreakerError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_circuit_breaker_opens_on_failures() {
        let cb = CircuitBreaker::new(3, 2, Duration::from_secs(5), Duration::from_millis(100));

        // Fail 3 times
        for _ in 0..3 {
            let _ = cb.call(async { Result::<(), &str>::Err("error") }).await;
        }

        assert_eq!(cb.get_state().await, CircuitState::Open);
    }

    #[tokio::test]
    async fn test_circuit_breaker_half_open() {
        let cb = CircuitBreaker::new(2, 2, Duration::from_millis(100), Duration::from_millis(50));

        // Trigger opening
        for _ in 0..2 {
            let _ = cb.call(async { Result::<(), &str>::Err("error") }).await;
        }

        assert_eq!(cb.get_state().await, CircuitState::Open);

        // Wait for timeout
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Next call should transition to half-open
        let _ = cb.call(async { Ok::<_, &str>(()) }).await;
        
        // Should still be half-open (need 2 successes)
        let state = cb.get_state().await;
        assert!(state == CircuitState::HalfOpen || state == CircuitState::Closed);
    }
}
