use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use ethers::types::{Address, Signature};

/// Order side
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum OrderSide {
    Buy,
    Sell,
}

impl OrderSide {
    /// Convert to smart contract uint8 (0 = BUY, 1 = SELL)
    pub fn to_u8(&self) -> u8 {
        match self {
            OrderSide::Buy => 0,
            OrderSide::Sell => 1,
        }
    }

    /// Create from smart contract uint8
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(OrderSide::Buy),
            1 => Some(OrderSide::Sell),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OrderType {
    Limit,      // Standard limit order
    Market,     // Market order (not supported in CLOB, converted to aggressive limit)
    PostOnly,   // Maker-only order (fails if would take)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TimeInForce {
    Gtc,  // Good-til-cancelled
    Ioc,  // Immediate-or-cancel
    Fok,  // Fill-or-kill
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OrderStatus {
    Open,       // Active in order book
    Partial,    // Partially filled
    Filled,     // Completely filled
    Cancelled,  // Cancelled by user
    Rejected,   // Rejected by system
    Expired,    // Expired (IOC/FOK)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Order {
    pub id: Uuid,
    pub user_id: String,
    pub market_id: String,
    pub side: OrderSide,
    pub order_type: OrderType,
    pub time_in_force: TimeInForce,
    pub price: Decimal,
    pub size: Decimal,
    pub filled: Decimal,
    pub remaining: Decimal,
    pub status: OrderStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub fills: Vec<Fill>,
    
    // Smart contract integration fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maker_address: Option<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<Signature>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub market_id_uint: Option<ethers::types::U256>,
}

impl Order {
    pub fn new(
        user_id: String,
        market_id: String,
        side: OrderSide,
        order_type: OrderType,
        time_in_force: TimeInForce,
        price: Decimal,
        size: Decimal,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            user_id,
            market_id,
            side,
            order_type,
            time_in_force,
            price,
            size,
            filled: Decimal::ZERO,
            remaining: size,
            status: OrderStatus::Open,
            created_at: now,
            updated_at: now,
            fills: Vec::new(),
            maker_address: None,
            signature: None,
            nonce: None,
            market_id_uint: None,
        }
    }

    pub fn is_active(&self) -> bool {
        matches!(self.status, OrderStatus::Open | OrderStatus::Partial)
    }

    pub fn can_match(&self) -> bool {
        self.is_active() && self.remaining > Decimal::ZERO
    }

    /// Check if order has valid EIP-712 signature
    pub fn has_signature(&self) -> bool {
        self.signature.is_some() && self.maker_address.is_some() && self.nonce.is_some()
    }

    /// Get order ID as U256 for smart contracts
    pub fn id_as_u256(&self) -> ethers::types::U256 {
        // Use UUID as bytes for deterministic U256
        let bytes = self.id.as_bytes();
        ethers::types::U256::from_big_endian(bytes)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fill {
    pub id: Uuid,
    pub order_id: Uuid,
    pub trade_id: Uuid,
    pub price: Decimal,
    pub size: Decimal,
    pub fee: Decimal,
    pub is_maker: bool,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Trade {
    pub id: Uuid,
    pub market_id: String,
    pub maker_order_id: Uuid,
    pub taker_order_id: Uuid,
    pub maker_user_id: String,
    pub taker_user_id: String,
    pub side: OrderSide, // Side of the taker
    pub price: Decimal,
    pub size: Decimal,
    pub timestamp: DateTime<Utc>,
    
    // Smart contract settlement fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maker_address: Option<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub taker_address: Option<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub market_id_uint: Option<ethers::types::U256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settlement_tx: Option<ethers::types::H256>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderBookLevel {
    pub price: Decimal,
    pub size: Decimal,
    pub order_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderBook {
    pub market_id: String,
    pub bids: Vec<OrderBookLevel>,
    pub asks: Vec<OrderBookLevel>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketStats {
    pub market_id: String,
    pub last_price: Option<Decimal>,
    pub volume_24h: Decimal,
    pub high_24h: Option<Decimal>,
    pub low_24h: Option<Decimal>,
    pub best_bid: Option<Decimal>,
    pub best_ask: Option<Decimal>,
    pub spread: Option<Decimal>,
    pub open_interest: Decimal,
}

// WebSocket message types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WsMessage {
    OrderBookUpdate {
        market_id: String,
        bids: Vec<OrderBookLevel>,
        asks: Vec<OrderBookLevel>,
        timestamp: DateTime<Utc>,
    },
    Trade {
        trade: Trade,
    },
    OrderUpdate {
        order: Order,
    },
    Subscribed {
        channel: String,
        market_id: Option<String>,
    },
    Unsubscribed {
        channel: String,
        market_id: Option<String>,
    },
    Error {
        message: String,
    },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WsClientMessage {
    Subscribe {
        channel: String,
        market_id: Option<String>,
    },
    Unsubscribe {
        channel: String,
        market_id: Option<String>,
    },
}
