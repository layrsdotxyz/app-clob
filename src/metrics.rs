use crate::models::OrderSide;
use prometheus::{
    register_histogram_vec, register_int_counter_vec, register_int_gauge_vec,
    HistogramVec, IntCounterVec, IntGaugeVec, TextEncoder, Encoder,
};
use std::time::Duration;

pub struct Metrics {
    // Order metrics
    orders_submitted: IntCounterVec,
    orders_cancelled: IntCounterVec,
    orders_filled: IntCounterVec,
    orders_rejected: IntCounterVec,
    
    // Matching metrics
    matches_total: IntCounterVec,
    match_latency: HistogramVec,
    order_latency: HistogramVec,
    
    // Order book metrics
    orderbook_depth_bids: IntGaugeVec,
    orderbook_depth_asks: IntGaugeVec,
    orderbook_spread: HistogramVec,
    
    // Trade metrics
    trades_total: IntCounterVec,
    volume_total: HistogramVec,
    
    // WebSocket metrics
    ws_connections: IntGaugeVec,
    ws_messages: IntCounterVec,
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            orders_submitted: register_int_counter_vec!(
                "clob_orders_submitted_total",
                "Total number of orders submitted",
                &["market_id", "side"]
            ).unwrap(),
            
            orders_cancelled: register_int_counter_vec!(
                "clob_orders_cancelled_total",
                "Total number of orders cancelled",
                &["market_id"]
            ).unwrap(),
            
            orders_filled: register_int_counter_vec!(
                "clob_orders_filled_total",
                "Total number of orders filled",
                &["market_id"]
            ).unwrap(),
            
            orders_rejected: register_int_counter_vec!(
                "clob_orders_rejected_total",
                "Total number of orders rejected",
                &["market_id", "reason"]
            ).unwrap(),
            
            matches_total: register_int_counter_vec!(
                "clob_matches_total",
                "Total number of order matches",
                &["market_id"]
            ).unwrap(),
            
            match_latency: register_histogram_vec!(
                "clob_match_latency_seconds",
                "Latency of order matching",
                &["market_id"],
                vec![0.00001, 0.00005, 0.0001, 0.0005, 0.001, 0.005, 0.01]
            ).unwrap(),
            
            order_latency: register_histogram_vec!(
                "clob_order_latency_seconds",
                "End-to-end order processing latency",
                &["status"],
                vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0]
            ).unwrap(),
            
            orderbook_depth_bids: register_int_gauge_vec!(
                "clob_orderbook_depth_bids",
                "Number of bid orders in order book",
                &["market_id"]
            ).unwrap(),
            
            orderbook_depth_asks: register_int_gauge_vec!(
                "clob_orderbook_depth_asks",
                "Number of ask orders in order book",
                &["market_id"]
            ).unwrap(),
            
            orderbook_spread: register_histogram_vec!(
                "clob_orderbook_spread",
                "Bid-ask spread",
                &["market_id"],
                vec![0.0001, 0.001, 0.01, 0.1, 1.0, 10.0]
            ).unwrap(),
            
            trades_total: register_int_counter_vec!(
                "clob_trades_total",
                "Total number of trades executed",
                &["market_id"]
            ).unwrap(),
            
            volume_total: register_histogram_vec!(
                "clob_volume_total",
                "Trading volume",
                &["market_id"],
                vec![1.0, 10.0, 100.0, 1000.0, 10000.0, 100000.0]
            ).unwrap(),
            
            ws_connections: register_int_gauge_vec!(
                "clob_ws_connections",
                "Number of active WebSocket connections",
                &["type"]
            ).unwrap(),
            
            ws_messages: register_int_counter_vec!(
                "clob_ws_messages_total",
                "Total WebSocket messages sent",
                &["type"]
            ).unwrap(),
        }
    }

    // Order metrics
    pub fn record_order_submitted(&self, market_id: &str, side: &OrderSide) {
        let side_str = match side {
            OrderSide::Buy => "buy",
            OrderSide::Sell => "sell",
        };
        self.orders_submitted.with_label_values(&[market_id, side_str]).inc();
    }

    pub fn record_order_cancelled(&self, market_id: &str) {
        self.orders_cancelled.with_label_values(&[market_id]).inc();
    }

    pub fn record_order_filled(&self, market_id: &str) {
        self.orders_filled.with_label_values(&[market_id]).inc();
    }

    pub fn record_order_rejected(&self, market_id: &str, reason: &str) {
        self.orders_rejected.with_label_values(&[market_id, reason]).inc();
    }

    pub fn record_order_latency(&self, duration: Duration) {
        self.order_latency
            .with_label_values(&["processed"])
            .observe(duration.as_secs_f64());
    }

    // Matching metrics
    pub fn record_match(&self, market_id: &str, count: usize) {
        self.matches_total.with_label_values(&[market_id]).inc_by(count as u64);
    }

    pub fn record_match_latency(&self, market_id: &str, duration: Duration) {
        self.match_latency
            .with_label_values(&[market_id])
            .observe(duration.as_secs_f64());
    }

    // Order book metrics
    pub fn record_order_added(&self, market_id: &str, side: &OrderSide) {
        match side {
            OrderSide::Buy => self.orderbook_depth_bids.with_label_values(&[market_id]).inc(),
            OrderSide::Sell => self.orderbook_depth_asks.with_label_values(&[market_id]).inc(),
        }
    }

    pub fn record_order_removed(&self, market_id: &str, side: &OrderSide) {
        match side {
            OrderSide::Buy => self.orderbook_depth_bids.with_label_values(&[market_id]).dec(),
            OrderSide::Sell => self.orderbook_depth_asks.with_label_values(&[market_id]).dec(),
        }
    }

    pub fn record_spread(&self, market_id: &str, spread: f64) {
        self.orderbook_spread
            .with_label_values(&[market_id])
            .observe(spread);
    }

    // Trade metrics
    pub fn record_trade(&self, market_id: &str, volume: f64) {
        self.trades_total.with_label_values(&[market_id]).inc();
        self.volume_total.with_label_values(&[market_id]).observe(volume);
    }

    // WebSocket metrics
    pub fn record_ws_connection(&self, connected: bool) {
        if connected {
            self.ws_connections.with_label_values(&["active"]).inc();
        } else {
            self.ws_connections.with_label_values(&["active"]).dec();
        }
    }

    pub fn record_ws_message(&self, message_type: &str) {
        self.ws_messages.with_label_values(&[message_type]).inc();
    }

    /// Render metrics in Prometheus format
    pub fn render(&self) -> Result<String, prometheus::Error> {
        let encoder = TextEncoder::new();
        let metric_families = prometheus::gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer)?;
        Ok(String::from_utf8(buffer).unwrap())
    }
}

/// Serve metrics endpoint
pub async fn serve_metrics(metrics: std::sync::Arc<Metrics>) {
    let _ = metrics;
    // Metrics are exposed via /metrics route in main router
    tracing::info!("Metrics collection enabled");
}
