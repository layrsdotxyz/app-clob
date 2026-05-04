use crate::{models::{PublicTrade, Trade, Order, OrderBook, WsMessage, WsClientMessage}, orderbook::OrderBookManager};
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

        // Subscribe to user-specific channel if authenticated.
        // Create the channel if it doesn't exist yet — this ensures balance_update,
        // order_update, and fill pushes reach clients who connect before placing any order.
        let mut user_rx = user_id.as_ref().map(|uid| {
            self.user_channels
                .entry(uid.clone())
                .or_insert_with(|| broadcast::channel(100).0)
                .subscribe()
        });

        let (agg_tx, mut agg_rx) = tokio::sync::mpsc::unbounded_channel::<WsMessage>();
        let mut subscriptions: std::collections::HashMap<String, tokio::task::JoinHandle<()>> = std::collections::HashMap::new();

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
                                    &agg_tx,
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
                    user_rx.as_mut().unwrap().recv().await.ok()
                }, if user_rx.is_some() => {
                    if let Some(msg) = user_msg {
                        if let Ok(json) = serde_json::to_string(&msg) {
                            let _ = ws.send(Message::Text(json)).await;
                        }
                    }
                }

                // Broadcast from subscribed channels
                channel_msg = agg_rx.recv() => {
                    if let Some(msg) = channel_msg {
                        if let Ok(json) = serde_json::to_string(&msg) {
                            let _ = ws.send(Message::Text(json)).await;
                        }
                    }
                }
            }
        }
        
        // Clean up spawned tasks when disconnected
        for (_, handle) in subscriptions.drain() {
            handle.abort();
        }
    }

    async fn handle_client_message(
        &self,
        ws: &mut WebSocket,
        subscriptions: &mut std::collections::HashMap<String, tokio::task::JoinHandle<()>>,
        agg_tx: &tokio::sync::mpsc::UnboundedSender<WsMessage>,
        msg: WsClientMessage,
    ) {
        match msg {
            WsClientMessage::Subscribe { channel, market_id } => {
                let channel_key = self.make_channel_key(&channel, market_id.as_deref());
                
                let tx = self.channels
                    .entry(channel_key.clone())
                    .or_insert_with(|| broadcast::channel(1000).0)
                    .clone();
                
                let mut rx = tx.subscribe();
                let snd = agg_tx.clone();
                let handle = tokio::spawn(async move {
                    while let Ok(msg) = rx.recv().await {
                        if snd.send(msg).is_err() {
                            break;
                        }
                    }
                });
                
                if let Some(old_handle) = subscriptions.insert(channel_key.clone(), handle) {
                    old_handle.abort();
                }
                
                let response = WsMessage::Subscribed { channel, market_id };
                if let Ok(json) = serde_json::to_string(&response) {
                    let _ = ws.send(Message::Text(json)).await;
                }
                
                tracing::debug!(channel = %channel_key, "Subscribed to channel");
            }
            
            WsClientMessage::Unsubscribe { channel, market_id } => {
                let channel_key = self.make_channel_key(&channel, market_id.as_deref());
                
                if let Some(handle) = subscriptions.remove(&channel_key) {
                    handle.abort();
                }
                
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

    /// Broadcast an anonymous trade tick — no user IDs or settlement hash.
    pub fn broadcast_trade(&self, trade: &Trade) {
        let channel_key = format!("trades:{}", trade.market_id);
        
        if let Some(tx) = self.channels.get(&channel_key) {
            let msg = WsMessage::Trade {
                trade: PublicTrade::from(trade),
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

    /// Send a fill event to a specific user (fire-and-forget; ignored if the user has no active channel).
    pub fn send_fill_event(
        &self,
        user_id: &str,
        market_id: &str,
        amount: &str,
        side: &str,
        trade_id: &str,
        tx_hash: &str,
    ) {
        let tx = self.user_channels
            .entry(user_id.to_string())
            .or_insert_with(|| broadcast::channel(100).0)
            .clone();

        let msg = WsMessage::Fill {
            market_id: market_id.to_string(),
            amount: amount.to_string(),
            side: side.to_string(),
            trade_id: trade_id.to_string(),
            tx_hash: tx_hash.to_string(),
        };

        let _ = tx.send(msg);
    }

    /// Push a balance update to a user's private WS channel.
    /// Creates the channel if it doesn't exist so the push is never silently dropped.
    pub fn send_balance_update(&self, user_id: &str, total: &str, reserved: &str, available: &str) {
        let tx = self.user_channels
            .entry(user_id.to_string())
            .or_insert_with(|| broadcast::channel(100).0)
            .clone();
        let msg = WsMessage::BalanceUpdate {
            total: total.to_string(),
            reserved: reserved.to_string(),
            available: available.to_string(),
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

/// Background task — kept for future use (e.g. market stats heartbeat).
/// Orderbook snapshots are intentionally NOT broadcast: revealing per-level sizes
/// would leak position concentration, violating the hidden-orderbook guarantee.
pub async fn broadcast_task(
    _ws_manager: Arc<WebSocketManager>,
    _orderbook_manager: Arc<OrderBookManager>,
) {
    // Parked — no public channel broadcasts at this time.
    std::future::pending::<()>().await;
}
