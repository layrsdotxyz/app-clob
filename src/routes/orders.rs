use crate::{error::ClobResult, models::*, AppState};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct CreateOrderRequest {
    pub user_id: String,
    pub market_id: String,
    pub side: OrderSide,
    #[serde(default = "default_order_type")]
    pub order_type: OrderType,
    #[serde(default = "default_time_in_force")]
    pub time_in_force: TimeInForce,
    pub price: rust_decimal::Decimal,
    pub size: rust_decimal::Decimal,
}

fn default_order_type() -> OrderType {
    OrderType::Limit
}

fn default_time_in_force() -> TimeInForce {
    TimeInForce::Gtc
}

#[derive(Debug, Serialize)]
pub struct CreateOrderResponse {
    pub order: Order,
    pub fills: Vec<Fill>,
    pub trades: Vec<Trade>,
}

pub async fn create_order(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateOrderRequest>,
) -> ClobResult<impl IntoResponse> {
    // Create order
    let order = Order::new(
        req.user_id,
        req.market_id,
        req.side,
        req.order_type,
        req.time_in_force,
        req.price,
        req.size,
    );
    
    // Submit to matching engine
    let result = state.matching_engine.submit_order(order).await?;
    
    // Broadcast order updates
    state.ws_manager.send_order_update(&result.order.user_id, &result.order);
    
    // Broadcast trades
    for trade in &result.trades {
        state.ws_manager.broadcast_trade(trade);
    }
    
    let response = CreateOrderResponse {
        order: result.order,
        fills: result.fills,
        trades: result.trades,
    };
    
    Ok((StatusCode::CREATED, Json(response)))
}

pub async fn cancel_order(
    State(state): State<Arc<AppState>>,
    Path(order_id): Path<Uuid>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> ClobResult<impl IntoResponse> {
    let user_id = params.get("user_id")
        .ok_or_else(|| crate::error::ClobError::Unauthorized("user_id query parameter required".to_string()))?;
    
    let order = state.matching_engine.cancel_order(order_id, user_id).await?;
    
    // Broadcast order update
    state.ws_manager.send_order_update(&order.user_id, &order);
    
    Ok(Json(order))
}

pub async fn get_order(
    State(state): State<Arc<AppState>>,
    Path(order_id): Path<Uuid>,
) -> ClobResult<impl IntoResponse> {
    let order_store = &state.orderbook_manager.store;
    let order = order_store
        .get_order(order_id)
        .await?
        .ok_or_else(|| crate::error::ClobError::OrderNotFound(order_id.to_string()))?;
    
    Ok(Json(order))
}

pub async fn get_user_orders(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<String>,
) -> ClobResult<impl IntoResponse> {
    let orders = state.orderbook_manager.get_user_orders(&user_id).await?;
    
    Ok(Json(orders))
}
