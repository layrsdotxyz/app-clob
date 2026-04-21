use axum::{extract::State, http::StatusCode, Json};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::str::FromStr;

use crate::AppState;

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(crate) enum AmountValue {
    String(String),
    Number(i64),
    Float(f64),
}

impl AmountValue {
    fn to_decimal(&self) -> Result<Decimal, String> {
        match self {
            AmountValue::String(s) => Decimal::from_str(s).map_err(|e| e.to_string()),
            AmountValue::Number(n) => Ok(Decimal::from(*n)),
            AmountValue::Float(f) => Decimal::try_from(*f).map_err(|e| e.to_string()),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct DepositRequest {
    pub user_id: String,
    pub market_id: String,
    pub amount: AmountValue,
}

#[derive(Debug, Serialize)]
pub struct DepositResponse {
    pub success: bool,
    pub user_id: String,
    pub market_id: String,
    pub new_balance: String,
}

/// Test endpoint to deposit funds (simulates on-chain deposit)
/// In production, this would be triggered by monitoring LiquidityVaultV1 deposit events
pub async fn deposit_balance(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DepositRequest>,
) -> Result<Json<DepositResponse>, StatusCode> {
    let amount = req.amount.to_decimal()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    
    state.balance_service.deposit(&req.user_id, &req.market_id, amount);
    
    let new_balance = state.balance_service.get_total_balance(&req.user_id, &req.market_id);
    
    Ok(Json(DepositResponse {
        success: true,
        user_id: req.user_id,
        market_id: req.market_id,
        new_balance: new_balance.to_string(),
    }))
}

#[derive(Debug, Serialize)]
pub struct BalanceResponse {
    pub user_id: String,
    pub market_id: String,
    pub total: String,
    pub available: String,
    pub reserved: String,
}

/// Get balance for a user in a market
pub async fn get_balance(
    State(state): State<Arc<AppState>>,
    axum::extract::Path((user_id, market_id)): axum::extract::Path<(String, String)>,
) -> Json<BalanceResponse> {
    let total = state.balance_service.get_total_balance(&user_id, &market_id);
    let available = state.balance_service.get_available_balance(&user_id, &market_id);
    let reserved = state.balance_service.get_reserved_balance(&user_id, &market_id);
    
    Json(BalanceResponse {
        user_id,
        market_id,
        total: total.to_string(),
        available: available.to_string(),
        reserved: reserved.to_string(),
    })
}
