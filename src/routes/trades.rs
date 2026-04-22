use crate::{auth::AuthenticatedUser, error::ClobResult, models::PublicTrade, AppState};
use axum::{
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct TradesQuery {
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_limit() -> usize {
    50
}

pub async fn get_recent_trades(
    State(state): State<Arc<AppState>>,
    Path(market_id): Path<String>,
    Query(query): Query<TradesQuery>,
) -> ClobResult<impl IntoResponse> {
    let trades = state.orderbook_manager
        .store
        .get_recent_trades(&market_id, query.limit)
        .await?;
    
    Ok(Json(trades.iter().map(PublicTrade::from).collect::<Vec<_>>()))
}

#[derive(Debug, Deserialize)]
pub struct TradeHistoryQuery {
    #[serde(default = "default_history_limit")]
    pub limit: usize,
    pub from_timestamp: Option<i64>,
    pub to_timestamp: Option<i64>,
}

fn default_history_limit() -> usize {
    100
}

pub async fn get_trade_history(
    State(state): State<Arc<AppState>>,
    Path(market_id): Path<String>,
    Query(query): Query<TradeHistoryQuery>,
) -> ClobResult<impl IntoResponse> {
    let trades = state.orderbook_manager
        .store
        .get_recent_trades(&market_id, query.limit)
        .await?;
    
    let filtered_trades: Vec<_> = trades.into_iter()
        .filter(|trade| {
            let ts = trade.timestamp.timestamp();
            query.from_timestamp.map_or(true, |from| ts >= from) &&
            query.to_timestamp.map_or(true, |to| ts <= to)
        })
        .collect();
    
    let public_trades: Vec<PublicTrade> = filtered_trades.iter().map(PublicTrade::from).collect();
    Ok(Json(serde_json::json!({
        "trades": public_trades,
        "count": public_trades.len(),
    })))
}

pub async fn get_user_trades(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthenticatedUser>,
    Path(user_id): Path<String>,
    Query(query): Query<TradesQuery>,
) -> Result<Response, StatusCode> {
    // Self-scope: callers may only access their own trade history.
    if auth.user_id.to_lowercase() != user_id.to_lowercase() {
        return Err(StatusCode::FORBIDDEN);
    }

    let trades = state
        .orderbook_manager
        .store
        .get_user_trades(&user_id, query.limit)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(serde_json::json!({
        "trades": trades,
        "count": trades.len(),
    })).into_response())
}
