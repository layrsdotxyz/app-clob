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
use std::{collections::HashSet, sync::Arc};

#[derive(Debug, Serialize)]
struct MarketsListResponse {
    markets: Vec<String>,
    count: usize,
    market_details: Vec<PublicMarketMetadata>,
}

fn merge_public_market_listing(
    prioritized_markets: Vec<PublicMarketMetadata>,
    additional_markets: Vec<PublicMarketMetadata>,
) -> MarketsListResponse {
    let mut seen_market_ids = HashSet::new();
    let mut markets = Vec::with_capacity(prioritized_markets.len() + additional_markets.len());
    let mut market_details =
        Vec::with_capacity(prioritized_markets.len() + additional_markets.len());

    for metadata in prioritized_markets.into_iter().chain(additional_markets) {
        if seen_market_ids.insert(metadata.market_id.clone()) {
            markets.push(metadata.market_id.clone());
            market_details.push(metadata);
        }
    }

    MarketsListResponse {
        count: markets.len(),
        markets,
        market_details,
    }
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

pub async fn list_markets(State(state): State<Arc<AppState>>) -> ClobResult<impl IntoResponse> {
    let mut orderbook_markets = state.orderbook_manager.get_active_markets();
    orderbook_markets.sort();

    if let Some(database) = state.database.as_ref() {
        let prioritized_markets = database.list_active_prediction_market_metadata().await?;
        let mut additional_markets = Vec::with_capacity(orderbook_markets.len());

        for market_id in &orderbook_markets {
            if let Some(metadata) = database.get_public_market_metadata(market_id).await? {
                additional_markets.push(metadata);
            } else {
                additional_markets.push(legacy_market_metadata(market_id));
            }
        }

        Ok(Json(merge_public_market_listing(
            prioritized_markets,
            additional_markets,
        )))
    } else {
        let additional_markets = orderbook_markets
            .iter()
            .map(|market_id| legacy_market_metadata(market_id))
            .collect();

        Ok(Json(merge_public_market_listing(
            Vec::new(),
            additional_markets,
        )))
    }
}

pub async fn get_market_by_slug(
    State(state): State<Arc<AppState>>,
    Path(slug): Path<String>,
) -> ClobResult<impl IntoResponse> {
    let database = state.database.as_ref().ok_or_else(|| {
        ClobError::ServiceUnavailable("database is required for slug lookup".to_string())
    })?;

    // Try exact slug match first
    if let Some(market) = database.get_public_market_metadata_by_slug(&slug).await? {
        return Ok(Json(market));
    }

    // Fallback: treat slug as market_id (handles short "btc-160" style slugs
    // returned by legacy_market_metadata when the DB-stored slug is description-based)
    let market_id_upper = slug.to_uppercase();
    if let Some(market) = database
        .get_public_market_metadata(&market_id_upper)
        .await?
    {
        return Ok(Json(market));
    }

    Err(ClobError::MarketNotFound(slug))
}

pub async fn get_market_stats(
    State(state): State<Arc<AppState>>,
    Path(market_id): Path<String>,
) -> ClobResult<impl IntoResponse> {
    // Get market stats
    let mut stats = state
        .orderbook_manager
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

pub async fn list_market_history(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> ClobResult<impl IntoResponse> {
    let database = state.database.as_ref().ok_or_else(|| {
        ClobError::ServiceUnavailable("database is required for market history".to_string())
    })?;

    let asset = params.get("asset").map(|s| s.as_str());
    let limit = params
        .get("limit")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(50)
        .min(200);

    let markets = database
        .list_resolved_prediction_market_metadata(asset, limit)
        .await?;
    Ok(Json(serde_json::json!({ "markets": markets })))
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

#[cfg(test)]
mod tests {
    use super::{legacy_market_metadata, merge_public_market_listing};
    use crate::models::PublicMarketMetadata;

    fn prediction_market(market_id: &str, slug: &str) -> PublicMarketMetadata {
        PublicMarketMetadata {
            market_id: market_id.to_string(),
            slug: slug.to_string(),
            question: format!("Question for {market_id}"),
            expiry_ts: Some(1),
            status: "active".to_string(),
            source: Some("pyth".to_string()),
            on_chain_market_id: market_id
                .rsplit('-')
                .next()
                .and_then(|value| value.parse().ok()),
            asset_symbol: market_id.split('-').next().map(|value| value.to_string()),
        }
    }

    #[test]
    fn merge_public_market_listing_prioritizes_predictions_and_dedupes() {
        let merged = merge_public_market_listing(
            vec![
                prediction_market("BTC-160", "btc-160"),
                prediction_market("ETH-161", "eth-161"),
            ],
            vec![
                legacy_market_metadata("BTC-USDC"),
                prediction_market("BTC-160", "btc-160"),
                legacy_market_metadata("SOL-USDC"),
            ],
        );

        assert_eq!(
            merged.markets,
            vec!["BTC-160", "ETH-161", "BTC-USDC", "SOL-USDC"]
        );
        assert_eq!(merged.count, 4);
        assert_eq!(merged.market_details[0].slug, "btc-160");
        assert_eq!(merged.market_details[1].slug, "eth-161");
    }
}
