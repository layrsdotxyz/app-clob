use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{CoreError, CoreResult, PRICE_SCALE};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Outcome {
    Up,
    Down,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum OrderAction {
    Buy,
    Sell,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum TimeInForce {
    Gtc,
    Gtd,
    Fok,
    Fak,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OrderStatus {
    Open,
    PartiallyFilled,
    Filled,
    Cancelled,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BookOrder {
    pub order_id: Uuid,
    pub private_user_id: String,
    pub market_id: String,
    pub outcome: Outcome,
    pub action: OrderAction,
    /// Probability price in millionths, strictly between 0 and 1_000_000.
    pub price_micros: u64,
    #[serde(with = "super::decimal_u128")]
    pub quantity_micros: u128,
    #[serde(with = "super::decimal_u128")]
    pub remaining_micros: u128,
    pub time_in_force: TimeInForce,
    pub expires_at_millis: Option<i64>,
    pub sequence: u64,
    pub status: OrderStatus,
}

impl BookOrder {
    pub fn new(
        private_user_id: impl Into<String>,
        market_id: impl Into<String>,
        outcome: Outcome,
        action: OrderAction,
        price_micros: u64,
        quantity_micros: u128,
        time_in_force: TimeInForce,
        expires_at_millis: Option<i64>,
    ) -> Self {
        Self::with_id(
            Uuid::new_v4(),
            private_user_id,
            market_id,
            outcome,
            action,
            price_micros,
            quantity_micros,
            time_in_force,
            expires_at_millis,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_id(
        order_id: Uuid,
        private_user_id: impl Into<String>,
        market_id: impl Into<String>,
        outcome: Outcome,
        action: OrderAction,
        price_micros: u64,
        quantity_micros: u128,
        time_in_force: TimeInForce,
        expires_at_millis: Option<i64>,
    ) -> Self {
        Self {
            order_id,
            private_user_id: private_user_id.into(),
            market_id: market_id.into(),
            outcome,
            action,
            price_micros,
            quantity_micros,
            remaining_micros: quantity_micros,
            time_in_force,
            expires_at_millis,
            sequence: 0,
            status: OrderStatus::Open,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fill {
    pub fill_id: Uuid,
    pub market_id: String,
    pub outcome: Outcome,
    pub maker_order_id: Uuid,
    pub taker_order_id: Uuid,
    pub maker_private_user_id: String,
    pub taker_private_user_id: String,
    pub price_micros: u64,
    #[serde(with = "super::decimal_u128")]
    pub quantity_micros: u128,
    pub sequence: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchResult {
    pub accepted_order: Option<BookOrder>,
    pub fills: Vec<Fill>,
    #[serde(with = "super::decimal_u128")]
    pub cancelled_remainder_micros: u128,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PriceTimeBook {
    orders: BTreeMap<Uuid, BookOrder>,
    active: BTreeSet<Uuid>,
    sequence: u64,
}

impl PriceTimeBook {
    pub fn submit(&mut self, mut incoming: BookOrder, now_millis: i64) -> CoreResult<MatchResult> {
        self.validate(&incoming, now_millis)?;
        if self.orders.contains_key(&incoming.order_id) {
            return Err(CoreError::InvalidOrder("duplicate order id".into()));
        }
        if incoming.time_in_force == TimeInForce::Fok
            && self.executable_quantity(&incoming, now_millis) < incoming.quantity_micros
        {
            incoming.status = OrderStatus::Rejected;
            return Ok(MatchResult {
                accepted_order: Some(incoming),
                fills: Vec::new(),
                cancelled_remainder_micros: 0,
            });
        }

        self.sequence += 1;
        incoming.sequence = self.sequence;
        let candidate_ids = self.matching_candidates(&incoming, now_millis);
        let mut fills = Vec::new();

        for candidate_id in candidate_ids {
            if incoming.remaining_micros == 0 {
                break;
            }
            let maker = self
                .orders
                .get_mut(&candidate_id)
                .expect("active candidate must exist");
            let quantity = incoming.remaining_micros.min(maker.remaining_micros);
            incoming.remaining_micros -= quantity;
            maker.remaining_micros -= quantity;
            maker.status = if maker.remaining_micros == 0 {
                OrderStatus::Filled
            } else {
                OrderStatus::PartiallyFilled
            };
            self.sequence += 1;
            let fill_sequence = self.sequence;
            let fill_id = deterministic_fill_id(
                &incoming.market_id,
                maker.order_id,
                incoming.order_id,
                fill_sequence,
            );
            fills.push(Fill {
                fill_id,
                market_id: incoming.market_id.clone(),
                outcome: incoming.outcome,
                maker_order_id: maker.order_id,
                taker_order_id: incoming.order_id,
                maker_private_user_id: maker.private_user_id.clone(),
                taker_private_user_id: incoming.private_user_id.clone(),
                price_micros: maker.price_micros,
                quantity_micros: quantity,
                sequence: fill_sequence,
            });
            if maker.remaining_micros == 0 {
                self.active.remove(&candidate_id);
            }
        }

        let cancelled_remainder_micros = match incoming.time_in_force {
            TimeInForce::Fak | TimeInForce::Fok => incoming.remaining_micros,
            TimeInForce::Gtc | TimeInForce::Gtd => 0,
        };

        if incoming.remaining_micros == 0 {
            incoming.status = OrderStatus::Filled;
        } else if cancelled_remainder_micros > 0 {
            incoming.status = if fills.is_empty() {
                OrderStatus::Cancelled
            } else {
                OrderStatus::PartiallyFilled
            };
            incoming.remaining_micros = 0;
        } else {
            incoming.status = if fills.is_empty() {
                OrderStatus::Open
            } else {
                OrderStatus::PartiallyFilled
            };
            self.active.insert(incoming.order_id);
        }

        self.orders.insert(incoming.order_id, incoming.clone());
        Ok(MatchResult {
            accepted_order: Some(incoming),
            fills,
            cancelled_remainder_micros,
        })
    }

    pub fn cancel(&mut self, order_id: Uuid, private_user_id: &str) -> CoreResult<BookOrder> {
        let order = self
            .orders
            .get_mut(&order_id)
            .ok_or_else(|| CoreError::InvalidOrder("order does not exist".into()))?;
        if order.private_user_id != private_user_id {
            return Err(CoreError::InvalidOrder("order owner mismatch".into()));
        }
        if !matches!(
            order.status,
            OrderStatus::Open | OrderStatus::PartiallyFilled
        ) {
            return Err(CoreError::InvalidOrder("order is not cancellable".into()));
        }
        order.status = OrderStatus::Cancelled;
        self.active.remove(&order_id);
        Ok(order.clone())
    }

    pub fn aggregate_depth(
        &self,
        market_id: &str,
        outcome: Outcome,
        now_millis: i64,
    ) -> (Vec<(u64, u128, usize)>, Vec<(u64, u128, usize)>) {
        let mut bids: BTreeMap<u64, (u128, usize)> = BTreeMap::new();
        let mut asks: BTreeMap<u64, (u128, usize)> = BTreeMap::new();
        for order_id in &self.active {
            let order = &self.orders[order_id];
            if order.market_id != market_id
                || order.outcome != outcome
                || is_expired(order, now_millis)
            {
                continue;
            }
            let side = match order.action {
                OrderAction::Buy => &mut bids,
                OrderAction::Sell => &mut asks,
            };
            let level = side.entry(order.price_micros).or_default();
            level.0 += order.remaining_micros;
            level.1 += 1;
        }
        let bids = bids
            .into_iter()
            .rev()
            .map(|(price, (size, count))| (price, size, count))
            .collect();
        let asks = asks
            .into_iter()
            .map(|(price, (size, count))| (price, size, count))
            .collect();
        (bids, asks)
    }

    pub fn order(&self, order_id: Uuid) -> Option<&BookOrder> {
        self.orders.get(&order_id)
    }

    pub fn orders_for_owner(&self, owner: &str) -> Vec<BookOrder> {
        self.orders
            .values()
            .filter(|order| order.private_user_id == owner)
            .cloned()
            .collect()
    }

    pub fn cancel_all(&mut self, market_id: &str) -> Vec<BookOrder> {
        let ids: Vec<Uuid> = self
            .active
            .iter()
            .filter(|id| self.orders[*id].market_id == market_id)
            .copied()
            .collect();
        let mut cancelled = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(order) = self.orders.get_mut(&id) {
                order.status = OrderStatus::Cancelled;
                cancelled.push(order.clone());
            }
            self.active.remove(&id);
        }
        cancelled
    }

    fn validate(&self, order: &BookOrder, now_millis: i64) -> CoreResult<()> {
        if order.price_micros == 0 || u128::from(order.price_micros) >= PRICE_SCALE {
            return Err(CoreError::InvalidOrder(
                "price must be within (0, 1_000_000)".into(),
            ));
        }
        if order.quantity_micros == 0 || order.remaining_micros != order.quantity_micros {
            return Err(CoreError::InvalidOrder("quantity is invalid".into()));
        }
        if order.private_user_id.is_empty() || order.market_id.is_empty() {
            return Err(CoreError::InvalidOrder(
                "identity and market are required".into(),
            ));
        }
        if order.time_in_force == TimeInForce::Gtd && order.expires_at_millis.is_none() {
            return Err(CoreError::InvalidOrder("GTD requires an expiry".into()));
        }
        if is_expired(order, now_millis) {
            return Err(CoreError::InvalidOrder("order is expired".into()));
        }
        Ok(())
    }

    fn executable_quantity(&self, incoming: &BookOrder, now_millis: i64) -> u128 {
        self.matching_candidates(incoming, now_millis)
            .iter()
            .map(|id| self.orders[id].remaining_micros)
            .sum()
    }

    fn matching_candidates(&self, incoming: &BookOrder, now_millis: i64) -> Vec<Uuid> {
        let mut candidates: Vec<&BookOrder> = self
            .active
            .iter()
            .filter_map(|id| self.orders.get(id))
            .filter(|resting| {
                resting.market_id == incoming.market_id
                    && resting.outcome == incoming.outcome
                    && resting.action != incoming.action
                    && resting.private_user_id != incoming.private_user_id
                    && !is_expired(resting, now_millis)
                    && crosses(incoming, resting)
            })
            .collect();
        candidates.sort_by(|left, right| {
            let price_order = match incoming.action {
                OrderAction::Buy => left.price_micros.cmp(&right.price_micros),
                OrderAction::Sell => right.price_micros.cmp(&left.price_micros),
            };
            price_order.then_with(|| left.sequence.cmp(&right.sequence))
        });
        candidates.into_iter().map(|order| order.order_id).collect()
    }
}

fn deterministic_fill_id(
    market_id: &str,
    maker_order_id: Uuid,
    taker_order_id: Uuid,
    sequence: u64,
) -> Uuid {
    let mut name = Vec::with_capacity(market_id.len() + 40);
    name.extend_from_slice(b"layrs.fill.v1\0");
    name.extend_from_slice(market_id.as_bytes());
    name.extend_from_slice(maker_order_id.as_bytes());
    name.extend_from_slice(taker_order_id.as_bytes());
    name.extend_from_slice(&sequence.to_be_bytes());
    Uuid::new_v5(&Uuid::NAMESPACE_OID, &name)
}

fn crosses(incoming: &BookOrder, resting: &BookOrder) -> bool {
    match incoming.action {
        OrderAction::Buy => incoming.price_micros >= resting.price_micros,
        OrderAction::Sell => incoming.price_micros <= resting.price_micros,
    }
}

fn is_expired(order: &BookOrder, now_millis: i64) -> bool {
    order
        .expires_at_millis
        .is_some_and(|expiry| expiry <= now_millis)
}
