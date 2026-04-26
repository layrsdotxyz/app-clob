use crate::{
    database::generate_market_slug,
    error::{ClobError, ClobResult},
    models::PublicMarketMetadata,
    AppState,
};
use axum::{
    extract::{Path, State},
    response::IntoResponse,
    Json,
};
use serde::Serialize;
use std::sync::Arc;

#[derive(Debug, Serialize)]
struct MarketsListResponse {
    markets: Vec<String>,
    count: usize,
    market_details: Vec<PublicMarketMetadata>,
}

fn legacy_market_metadata(market_id: &str) -> PublicMarketMetadata {
    PublicMarketMetadata {
        market_id: market_id.to_string(),
        slug: generate_market_slug(market_id, market_id, None),
        question: market_id.to_string(),
        expiry_ts: None,
        status: "open".to_string(),
        source: None,
        on_chain_market_id: None,
        asset_symbol: market_id
            .split('-')
            .next()
            .filter(|segment| !segment.is_empty())
            .map(|segment| segment.to_ascii_uppercase()),
    }
}

pub async fn list_markets(
    State(state): State<Arc<AppState>>,
) -> ClobResult<impl IntoResponse> {
    let markets = state.orderbook_manager.get_active_markets();
    let mut market_details = Vec::with_capacity(markets.len());

    if let Some(database) = state.database.as_ref() {
        for market_id in &markets {
            if let Some(metadata) = database.get_public_market_metadata(market_id).await? {
                market_details.push(metadata);
            } else {
                market_details.push(legacy_market_metadata(market_id));
            }
        }
    } else {
        market_details.extend(markets.iter().map(|market_id| legacy_market_metadata(market_id)));
    }

    Ok(Json(MarketsListResponse {
        count: markets.len(),
        markets,
        market_details,
    }))
}

pub async fn get_market_by_slug(
    State(state): State<Arc<AppState>>,
    Path(slug): Path<String>,
) -> ClobResult<impl IntoResponse> {
    let database = state.database.as_ref().ok_or_else(|| {
        ClobError::ServiceUnavailable("database is required for slug lookup".to_string())
    })?;

    let market = database
        .get_public_market_metadata_by_slug(&slug)
        .await?
        .ok_or_else(|| ClobError::MarketNotFound(slug.clone()))?;

    Ok(Json(market))
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
