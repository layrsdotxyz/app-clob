use crate::{error::ClobResult, AppState};
use axum::{
    extract::{Path, Query, State},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct OrderBookQuery {
    #[serde(default = "default_depth")]
    pub depth: usize,
}

fn default_depth() -> usize {
    20
}

pub async fn get_orderbook(
    State(state): State<Arc<AppState>>,
    Path(market_id): Path<String>,
    Query(query): Query<OrderBookQuery>,
) -> ClobResult<impl IntoResponse> {
    let orderbook = state
        .orderbook_manager
        .get_orderbook(&market_id, query.depth)
        .await?;

    Ok(Json(orderbook))
}

#[derive(Debug, Deserialize)]
pub struct DepthQuery {
    #[serde(default = "default_depth_levels")]
    pub levels: usize,
}

fn default_depth_levels() -> usize {
    50
}

pub async fn get_depth(
    State(state): State<Arc<AppState>>,
    Path(market_id): Path<String>,
    Query(query): Query<DepthQuery>,
) -> ClobResult<impl IntoResponse> {
    let orderbook = state
        .orderbook_manager
        .get_orderbook(&market_id, query.levels)
        .await?;

    // Format as depth chart data
    let depth_data = serde_json::json!({
        "market_id": market_id,
        "bids": orderbook.bids.iter().scan(rust_decimal::Decimal::ZERO, |acc, level| {
            *acc += level.size;
            Some(serde_json::json!({
                "price": level.price,
                "size": level.size,
                "total": *acc,
            }))
        }).collect::<Vec<_>>(),
        "asks": orderbook.asks.iter().scan(rust_decimal::Decimal::ZERO, |acc, level| {
            *acc += level.size;
            Some(serde_json::json!({
                "price": level.price,
                "size": level.size,
                "total": *acc,
            }))
        }).collect::<Vec<_>>(),
        "timestamp": orderbook.timestamp,
    });

    Ok(Json(depth_data))
}
