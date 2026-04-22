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

    /// ZK privacy: Poseidon commitment to the user's USDC note backing this order.
    /// When present the matching engine locks this note on submit, unlocks on cancel,
    /// and marks it spent on fill (G1, G2, G3).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note_commitment: Option<String>,

    /// ZK privacy: full circuit witness for private_transfer_settlement.
    /// Clients that want server-side proof generation submit the snarkjs-format
    /// input object here (ownerKeyHash, inputAmount, inputBlind, inputNonce,
    /// assetDomain, Merkle siblings/pathIndices, receiver + change params).
    /// Never echoed back in API responses (skip_serializing).
    #[serde(default, skip_serializing, skip_serializing_if = "Option::is_none")]
    pub note_witness: Option<serde_json::Value>,
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
            note_commitment: None,
            note_witness: None,
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
    /// Internal only — never serialized to Redis or API responses (privacy G3/G14/G16).
    /// Used in-memory by SettlementEngine for balance debit/credit and user-trade index keys.
    /// PostgreSQL retains the full record for operator-side auditing.
    #[serde(default, skip_serializing)]
    pub maker_user_id: String,
    #[serde(default, skip_serializing)]
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

/// A trade tick safe for public broadcast — no user IDs, no settlement hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicTrade {
    pub id: Uuid,
    pub market_id: String,
    pub side: OrderSide,
    pub price: Decimal,
    pub size: Decimal,
    pub timestamp: DateTime<Utc>,
}

impl From<&Trade> for PublicTrade {
    fn from(t: &Trade) -> Self {
        Self {
            id: t.id,
            market_id: t.market_id.clone(),
            side: t.side,
            price: t.price,
            size: t.size,
            timestamp: t.timestamp,
        }
    }
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
        trade: PublicTrade,
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

/// Status of a PM note-lock (collateral locked on-chain for an order).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoteLockStatus {
    /// `lock_collateral` tx broadcast, awaiting fill.
    Locked,
    /// `unlock_collateral` tx broadcast (cancelled/expired).
    Unlocked,
    /// `settle_fill` tx broadcast (order matched and settled).
    Settled,
}

/// Tracks a single collateral note-lock on-chain.
/// Written to Redis by `POST /v1/pm/lock-collateral` and updated by
/// `unlock-collateral` / `settle-fill`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoteLockRecord {
    /// Unique key: order_commitment_low (identifies the lock on-chain).
    pub order_commitment_low: String,
    pub order_commitment_high: String,
    /// Nullifier emitted by the unlock/settle circuit (set after unlock/settle).
    pub note_nullifier_low: Option<String>,
    pub note_nullifier_high: Option<String>,
    /// The user who owns this lock (EVM address or user_id).
    pub user_id: String,
    pub market_id: String,
    pub side: String,
    pub required_amount_low: String,
    pub lock_expiry_ts: u64,
    pub commitment_expiry_ts: i64,
    pub status: NoteLockStatus,
    pub lock_tx_hash: String,
    pub settle_tx_hash: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
