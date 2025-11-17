use crate::{models::*, orderbook::OrderBookManager};
use axum::extract::ws::{Message, WebSocket};
use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::broadcast;
use uuid::Uuid;

pub struct WebSocketManager {
    // Channel -> subscribers
    channels: Arc<DashMap<String, broadcast::Sender<WsMessage>>>,
    // User-specific channels
    user_channels: Arc<DashMap<String, broadcast::Sender<WsMessage>>>,
}

impl WebSocketManager {
    pub fn new() -> Self {
        Self {
            channels: Arc::new(DashMap::new()),
            user_channels: Arc::new(DashMap::new()),
        }
    }

    /// Subscribe a WebSocket connection to channels
    pub async fn handle_connection(
        &self,
        mut ws: WebSocket,
        user_id: Option<String>,
    ) {
        let session_id = Uuid::new_v4();
        tracing::info!(session_id = %session_id, user_id = ?user_id, "WebSocket connected");

        // Subscribe to user-specific channel if authenticated
        let mut user_rx = user_id.as_ref().and_then(|uid| {
            self.user_channels
                .get(uid)
                .map(|tx| tx.subscribe())
        });

        let mut subscriptions: Vec<(String, broadcast::Receiver<WsMessage>)> = Vec::new();

        loop {
            tokio::select! {
                // Receive from WebSocket client
                msg = ws.recv() => {
                    match msg {
                        Some(Ok(Message::Text(text))) => {
                            if let Ok(client_msg) = serde_json::from_str::<WsClientMessage>(&text) {
                                self.handle_client_message(
                                    &mut ws,
                                    &mut subscriptions,
                                    client_msg,
                                ).await;
                            }
                        }
                        Some(Ok(Message::Close(_))) | None => {
                            tracing::info!(session_id = %session_id, "WebSocket closed");
                            break;
                        }
                        Some(Err(e)) => {
                            tracing::error!(session_id = %session_id, error = %e, "WebSocket error");
                            break;
                        }
                        _ => {}
                    }
                }

                // Broadcast from user channel
                user_msg = async {
                    if let Some(ref mut rx) = user_rx {
                        rx.recv().await.ok()
                    } else {
                        None
                    }
                }, if user_rx.is_some() => {
                    if let Some(msg) = user_msg {
                        if let Ok(json) = serde_json::to_string(&msg) {
                            let _ = ws.send(Message::Text(json)).await;
                        }
                    }
                }

                // Broadcast from subscribed channels
                channel_msg = async {
                    for (_, rx) in subscriptions.iter_mut() {
                        if let Ok(msg) = rx.try_recv() {
                            return Some(msg);
                        }
                    }
                    None
                } => {
                    if let Some(msg) = channel_msg {
                        if let Ok(json) = serde_json::to_string(&msg) {
                            let _ = ws.send(Message::Text(json)).await;
                        }
                    }
                }
            }
        }
    }

    async fn handle_client_message(
        &self,
        ws: &mut WebSocket,
        subscriptions: &mut Vec<(String, broadcast::Receiver<WsMessage>)>,
        msg: WsClientMessage,
    ) {
        match msg {
            WsClientMessage::Subscribe { channel, market_id } => {
                let channel_key = self.make_channel_key(&channel, market_id.as_deref());
                
                let tx = self.channels
                    .entry(channel_key.clone())
                    .or_insert_with(|| broadcast::channel(1000).0)
                    .clone();
                
                subscriptions.push((channel_key.clone(), tx.subscribe()));
                
                let response = WsMessage::Subscribed { channel, market_id };
                if let Ok(json) = serde_json::to_string(&response) {
                    let _ = ws.send(Message::Text(json)).await;
                }
                
                tracing::debug!(channel = %channel_key, "Subscribed to channel");
            }
            
            WsClientMessage::Unsubscribe { channel, market_id } => {
                let channel_key = self.make_channel_key(&channel, market_id.as_deref());
                
                subscriptions.retain(|(key, _)| key != &channel_key);
                
                let response = WsMessage::Unsubscribed { channel, market_id };
                if let Ok(json) = serde_json::to_string(&response) {
                    let _ = ws.send(Message::Text(json)).await;
                }
                
                tracing::debug!(channel = %channel_key, "Unsubscribed from channel");
            }
        }
    }

    /// Broadcast order book update
    pub fn broadcast_orderbook_update(&self, orderbook: &OrderBook) {
        let channel_key = format!("orderbook:{}", orderbook.market_id);
        
        if let Some(tx) = self.channels.get(&channel_key) {
            let msg = WsMessage::OrderBookUpdate {
                market_id: orderbook.market_id.clone(),
                bids: orderbook.bids.clone(),
                asks: orderbook.asks.clone(),
                timestamp: orderbook.timestamp,
            };
            
            let _ = tx.send(msg);
        }
    }

    /// Broadcast trade
    pub fn broadcast_trade(&self, trade: &Trade) {
        let channel_key = format!("trades:{}", trade.market_id);
        
        if let Some(tx) = self.channels.get(&channel_key) {
            let msg = WsMessage::Trade {
                trade: trade.clone(),
            };
            
            let _ = tx.send(msg);
        }
    }

    /// Send order update to user
    pub fn send_order_update(&self, user_id: &str, order: &Order) {
        let tx = self.user_channels
            .entry(user_id.to_string())
            .or_insert_with(|| broadcast::channel(100).0)
            .clone();
        
        let msg = WsMessage::OrderUpdate {
            order: order.clone(),
        };
        
        let _ = tx.send(msg);
    }

    fn make_channel_key(&self, channel: &str, market_id: Option<&str>) -> String {
        match market_id {
            Some(mid) => format!("{}:{}", channel, mid),
            None => channel.to_string(),
        }
    }
}

/// Background task to broadcast order book snapshots
pub async fn broadcast_task(
    ws_manager: Arc<WebSocketManager>,
    orderbook_manager: Arc<OrderBookManager>,
) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(100));
    
    loop {
        interval.tick().await;
        
        // Get active markets
        let markets = orderbook_manager.get_active_markets();
        
        for market_id in markets {
            if let Ok(orderbook) = orderbook_manager.get_orderbook(&market_id, 20).await {
                ws_manager.broadcast_orderbook_update(&orderbook);
            }
        }
    }
}
