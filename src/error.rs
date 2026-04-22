use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ClobError {
    #[error("Order not found: {0}")]
    OrderNotFound(String),
    
    #[error("Market not found: {0}")]
    MarketNotFound(String),
    
    #[error("Insufficient balance: required {required}, available {available}")]
    InsufficientBalance {
        required: rust_decimal::Decimal,
        available: rust_decimal::Decimal,
    },
    
    #[error("Invalid order: {0}")]
    InvalidOrder(String),
    
    #[error("Order size too large: {0}")]
    OrderTooLarge(rust_decimal::Decimal),
    
    #[error("Order size too small: {0}")]
    OrderTooSmall(rust_decimal::Decimal),
    
    #[error("Too many open orders: {0}")]
    TooManyOrders(usize),
    
    #[error("Invalid price: {0}")]
    InvalidPrice(String),
    
    #[error("Market is closed")]
    MarketClosed,
    
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
    
    #[error("Redis error: {0}")]
    Redis(#[from] redis::RedisError),

    #[error("Serialization error: {0}")]
    SerdeJson(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Other error: {0}")]
    Other(String),

    /// 409 Conflict — e.g. duplicate nullifier spend attempt.
    #[error("Conflict: {0}")]
    Conflict(String),

    /// 503 Service Unavailable — e.g. required external service not configured.
    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),

    #[error("Proof generation failed: {0}")]
    ProofGenerationFailed(String),

    #[error("Invalid hex: {0}")]
    InvalidHex(String),
    
    #[error("Internal error: {0}")]
    Internal(String),
}

impl IntoResponse for ClobError {
    fn into_response(self) -> Response {
        let (status, error_code, message) = match &self {
            ClobError::OrderNotFound(_) => (StatusCode::NOT_FOUND, "ORDER_NOT_FOUND", self.to_string()),
            ClobError::MarketNotFound(_) => (StatusCode::NOT_FOUND, "MARKET_NOT_FOUND", self.to_string()),
            ClobError::InsufficientBalance { .. } => (StatusCode::BAD_REQUEST, "INSUFFICIENT_BALANCE", self.to_string()),
            ClobError::InvalidOrder(_) => (StatusCode::BAD_REQUEST, "INVALID_ORDER", self.to_string()),
            ClobError::OrderTooLarge(_) => (StatusCode::BAD_REQUEST, "ORDER_TOO_LARGE", self.to_string()),
            ClobError::OrderTooSmall(_) => (StatusCode::BAD_REQUEST, "ORDER_TOO_SMALL", self.to_string()),
            ClobError::TooManyOrders(_) => (StatusCode::BAD_REQUEST, "TOO_MANY_ORDERS", self.to_string()),
            ClobError::InvalidPrice(_) => (StatusCode::BAD_REQUEST, "INVALID_PRICE", self.to_string()),
            ClobError::MarketClosed => (StatusCode::BAD_REQUEST, "MARKET_CLOSED", self.to_string()),
            ClobError::RateLimitExceeded => (StatusCode::TOO_MANY_REQUESTS, "RATE_LIMIT_EXCEEDED", self.to_string()),
            ClobError::Unauthorized(_) => (StatusCode::UNAUTHORIZED, "UNAUTHORIZED", self.to_string()),
            ClobError::Redis(_) => {
                tracing::error!(error = %self, "Redis error occurred");
                (StatusCode::INTERNAL_SERVER_ERROR, "DATABASE_ERROR", "Database error".to_string())
            },
            ClobError::SerdeJson(_) => (StatusCode::BAD_REQUEST, "INVALID_JSON", self.to_string()),
            ClobError::Io(_) => (StatusCode::INTERNAL_SERVER_ERROR, "IO_ERROR", self.to_string()),
            ClobError::Other(_) => (StatusCode::INTERNAL_SERVER_ERROR, "OTHER_ERROR", self.to_string()),
            ClobError::Conflict(_) => (StatusCode::CONFLICT, "CONFLICT", self.to_string()),
            ClobError::ServiceUnavailable(_) => (StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE", self.to_string()),
            ClobError::ProofGenerationFailed(_) => (StatusCode::INTERNAL_SERVER_ERROR, "PROOF_GENERATION_FAILED", self.to_string()),
            ClobError::InvalidHex(_) => (StatusCode::BAD_REQUEST, "INVALID_HEX", self.to_string()),
            ClobError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", "Internal error".to_string()),
        };

        let body = Json(json!({
            "error": {
                "code": error_code,
                "message": message,
            }
        }));

        (status, body).into_response()
    }
}

pub type ClobResult<T> = Result<T, ClobError>;
