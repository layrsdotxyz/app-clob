use crate::{error::ClobResult, AppState};
use axum::{
    extract::{Path, Query, State},
    response::IntoResponse,
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
    
    Ok(Json(trades))
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
    // TODO: Implement time-range filtering
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
    
    Ok(Json(serde_json::json!({
        "trades": filtered_trades,
        "count": filtered_trades.len(),
    })))
}

pub async fn get_user_trades(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<String>,
    Query(query): Query<TradesQuery>,
) -> ClobResult<impl IntoResponse> {
    let trades = state
        .orderbook_manager
        .store
        .get_user_trades(&user_id, query.limit)
        .await?;

    Ok(Json(serde_json::json!({
        "trades": trades,
        "count": trades.len(),
    })))
}
