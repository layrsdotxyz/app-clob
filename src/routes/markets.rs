use crate::{error::ClobResult, AppState};
use axum::{
    extract::{Path, State},
    response::IntoResponse,
    Json,
};
use std::sync::Arc;

pub async fn list_markets(
    State(state): State<Arc<AppState>>,
) -> ClobResult<impl IntoResponse> {
    let markets = state.orderbook_manager.get_active_markets();
    
    Ok(Json(serde_json::json!({
        "markets": markets,
        "count": markets.len(),
    })))
}

pub async fn get_market_stats(
    State(state): State<Arc<AppState>>,
    Path(market_id): Path<String>,
) -> ClobResult<impl IntoResponse> {
    // Get market stats
    let mut stats = state.orderbook_manager
        .store
        .get_market_stats(&market_id)
        .await?
        .ok_or_else(|| crate::error::ClobError::MarketNotFound(market_id.clone()))?;
    
    // Add best bid/ask
    stats.best_bid = state.orderbook_manager.get_best_bid(&market_id).await?;
    stats.best_ask = state.orderbook_manager.get_best_ask(&market_id).await?;
    
    // Calculate spread
    if let (Some(bid), Some(ask)) = (stats.best_bid, stats.best_ask) {
        stats.spread = Some(ask - bid);
    }
    
    Ok(Json(stats))
}

pub async fn get_market_resolution_audit(
    Path(market_id): Path<String>,
) -> ClobResult<impl IntoResponse> {
    // Placeholder endpoint to keep API compatibility while resolution audit
    // persistence is being wired through the route layer.
    Ok(Json(serde_json::json!({
        "market_id": market_id,
        "audit": null,
        "message": "resolution audit not available"
    })))
}
