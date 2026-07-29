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

/// The collateral operation represented by a fill.
///
/// NORMAL transfers one existing outcome claim between users. MINT combines
/// opposite-outcome BUY orders into one newly collateralized complete set.
/// MERGE combines opposite-outcome SELL orders and burns one complete set back
/// into settlement collateral.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MatchType {
    #[default]
    Normal,
    Mint,
    Merge,
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
    /// Cumulative executed quantity. This is persisted explicitly because a
    /// cancelled FAK/FOK remainder is no longer represented by
    /// `remaining_micros`, so `quantity - remaining` is not a safe fill
    /// calculation for historical orders.
    #[serde(default, with = "super::decimal_u128")]
    pub filled_micros: u128,
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
            filled_micros: 0,
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
    /// The incoming/taker outcome. For NORMAL the maker outcome is identical;
    /// for MINT/MERGE it is the opposite outcome.
    pub outcome: Outcome,
    /// Defaults to NORMAL so pre-complete-set journal records remain readable.
    #[serde(default)]
    pub match_type: MatchType,
    pub maker_order_id: Uuid,
    pub taker_order_id: Uuid,
    pub maker_private_user_id: String,
    pub taker_private_user_id: String,
    pub price_micros: u64,
    #[serde(with = "super::decimal_u128")]
    pub quantity_micros: u128,
    pub sequence: u64,
}

impl Fill {
    pub fn maker_outcome(&self) -> Outcome {
        match self.match_type {
            MatchType::Normal => self.outcome,
            MatchType::Mint | MatchType::Merge => opposite_outcome(self.outcome),
        }
    }

    /// Price paid/received by the incoming taker. NORMAL executes at the
    /// resting maker price. Complete-set matches execute the taker at the exact
    /// complement, so both legs always sum to PRICE_SCALE.
    pub fn taker_price_micros(&self) -> u64 {
        match self.match_type {
            MatchType::Normal => self.price_micros,
            MatchType::Mint | MatchType::Merge => PRICE_SCALE as u64 - self.price_micros,
        }
    }
}

fn opposite_outcome(outcome: Outcome) -> Outcome {
    match outcome {
        Outcome::Up => Outcome::Down,
        Outcome::Down => Outcome::Up,
    }
}

#[cfg(test)]
mod legacy_snapshot_tests {
    use super::*;

    #[test]
    fn legacy_book_bytes_match_the_pre_fill_history_schema_exactly() {
        let order_id = Uuid::parse_str("11111111-2222-4333-8444-555555555555").unwrap();
        let market_id = "layrs:v3:ZEN:15m:legacy-golden";
        let mut book = PriceTimeBook::default();
        book.submit(
            BookOrder::with_id(
                order_id,
                "usr_golden",
                market_id,
                Outcome::Up,
                OrderAction::Buy,
                400_000,
                1_000_000,
                TimeInForce::Gtc,
                None,
            ),
            1_000,
        )
        .unwrap();
        let books = BTreeMap::from([(market_id.to_owned(), book)]);
        let encoded = String::from_utf8(serialize_legacy_books(&books).unwrap()).unwrap();

        assert_eq!(
            encoded,
            concat!(
                "{\"layrs:v3:ZEN:15m:legacy-golden\":{\"orders\":{",
                "\"11111111-2222-4333-8444-555555555555\":{",
                "\"order_id\":\"11111111-2222-4333-8444-555555555555\",",
                "\"private_user_id\":\"usr_golden\",",
                "\"market_id\":\"layrs:v3:ZEN:15m:legacy-golden\",",
                "\"outcome\":\"UP\",\"action\":\"BUY\",\"price_micros\":400000,",
                "\"quantity_micros\":\"1000000\",\"remaining_micros\":\"1000000\",",
                "\"time_in_force\":\"GTC\",\"expires_at_millis\":null,",
                "\"sequence\":1,\"status\":\"OPEN\"}},",
                "\"active\":[\"11111111-2222-4333-8444-555555555555\"],",
                "\"sequence\":1}}"
            )
        );
    }
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

#[derive(Serialize)]
struct LegacyBookOrder<'a> {
    order_id: &'a Uuid,
    private_user_id: &'a str,
    market_id: &'a str,
    outcome: Outcome,
    action: OrderAction,
    price_micros: u64,
    #[serde(with = "super::decimal_u128")]
    quantity_micros: u128,
    #[serde(with = "super::decimal_u128")]
    remaining_micros: u128,
    time_in_force: TimeInForce,
    expires_at_millis: Option<i64>,
    sequence: u64,
    status: OrderStatus,
}

#[derive(Serialize)]
struct LegacyPriceTimeBook<'a> {
    orders: BTreeMap<&'a Uuid, LegacyBookOrder<'a>>,
    active: &'a BTreeSet<Uuid>,
    sequence: u64,
}

/// Serializes the exact pre-`filled_micros` book shape used in the committed
/// state root. This is intentionally private to snapshot migration; live state
/// roots always include cumulative fill history.
pub(crate) fn serialize_legacy_books(
    books: &BTreeMap<String, PriceTimeBook>,
) -> Result<Vec<u8>, serde_json::Error> {
    let legacy: BTreeMap<&str, LegacyPriceTimeBook<'_>> = books
        .iter()
        .map(|(market_id, book)| {
            let orders = book
                .orders
                .iter()
                .map(|(order_id, order)| {
                    (
                        order_id,
                        LegacyBookOrder {
                            order_id: &order.order_id,
                            private_user_id: &order.private_user_id,
                            market_id: &order.market_id,
                            outcome: order.outcome,
                            action: order.action,
                            price_micros: order.price_micros,
                            quantity_micros: order.quantity_micros,
                            remaining_micros: order.remaining_micros,
                            time_in_force: order.time_in_force,
                            expires_at_millis: order.expires_at_millis,
                            sequence: order.sequence,
                            status: order.status,
                        },
                    )
                })
                .collect();
            (
                market_id.as_str(),
                LegacyPriceTimeBook {
                    orders,
                    active: &book.active,
                    sequence: book.sequence,
                },
            )
        })
        .collect();
    serde_json::to_vec(&legacy)
}

impl PriceTimeBook {
    /// Reconstructs cumulative fill history when restoring a snapshot produced
    /// before `filled_micros` existed. FAK/FOK partial fills cannot be inferred
    /// after their remainder was discarded, so those snapshots fail closed
    /// instead of publishing invented history.
    pub(crate) fn migrate_legacy_fill_history(&mut self) -> CoreResult<()> {
        for order in self.orders.values_mut() {
            if order.filled_micros != 0 {
                continue;
            }
            order.filled_micros = match order.status {
                OrderStatus::Filled => order.quantity_micros,
                OrderStatus::PartiallyFilled
                    if matches!(order.time_in_force, TimeInForce::Fak | TimeInForce::Fok) =>
                {
                    return Err(CoreError::SnapshotMigrationRequired);
                }
                OrderStatus::Open | OrderStatus::PartiallyFilled | OrderStatus::Cancelled
                    if matches!(order.time_in_force, TimeInForce::Gtc | TimeInForce::Gtd) =>
                {
                    order
                        .quantity_micros
                        .checked_sub(order.remaining_micros)
                        .ok_or(CoreError::JournalChainMismatch)?
                }
                OrderStatus::Rejected | OrderStatus::Cancelled => 0,
                OrderStatus::Open | OrderStatus::PartiallyFilled => {
                    return Err(CoreError::SnapshotMigrationRequired);
                }
            };
        }
        Ok(())
    }

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

        for candidate in candidate_ids {
            if incoming.remaining_micros == 0 {
                break;
            }
            let maker = self
                .orders
                .get_mut(&candidate.order_id)
                .expect("active candidate must exist");
            let quantity = incoming.remaining_micros.min(maker.remaining_micros);
            incoming.remaining_micros -= quantity;
            incoming.filled_micros = incoming
                .filled_micros
                .checked_add(quantity)
                .ok_or_else(|| CoreError::InvalidOrder("filled quantity overflow".into()))?;
            maker.remaining_micros -= quantity;
            maker.filled_micros = maker
                .filled_micros
                .checked_add(quantity)
                .ok_or_else(|| CoreError::InvalidOrder("filled quantity overflow".into()))?;
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
                match_type: candidate.match_type,
                maker_order_id: maker.order_id,
                taker_order_id: incoming.order_id,
                maker_private_user_id: maker.private_user_id.clone(),
                taker_private_user_id: incoming.private_user_id.clone(),
                price_micros: maker.price_micros,
                quantity_micros: quantity,
                sequence: fill_sequence,
            });
            if maker.remaining_micros == 0 {
                self.active.remove(&candidate.order_id);
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
            .map(|candidate| self.orders[&candidate.order_id].remaining_micros)
            .sum()
    }

    /// Returns one deterministic queue spanning direct and complete-set
    /// liquidity. The taker receives the best effective price first. An exact
    /// effective-price tie prefers NORMAL to avoid an unnecessary mint/burn,
    /// then preserves resting time priority and finally UUID order.
    fn matching_candidates(&self, incoming: &BookOrder, now_millis: i64) -> Vec<MatchCandidate> {
        let mut candidates: Vec<MatchCandidate> = self
            .active
            .iter()
            .filter_map(|id| self.orders.get(id))
            .filter_map(|resting| {
                if resting.market_id != incoming.market_id
                    || resting.private_user_id == incoming.private_user_id
                    || is_expired(resting, now_millis)
                {
                    return None;
                }
                let match_type = classify_match(incoming, resting)?;
                Some(MatchCandidate {
                    order_id: resting.order_id,
                    match_type,
                    effective_taker_price_micros: effective_taker_price(resting, match_type),
                    maker_sequence: resting.sequence,
                })
            })
            .collect();
        candidates.sort_by(|left, right| {
            let price_order = match incoming.action {
                OrderAction::Buy => left
                    .effective_taker_price_micros
                    .cmp(&right.effective_taker_price_micros),
                OrderAction::Sell => right
                    .effective_taker_price_micros
                    .cmp(&left.effective_taker_price_micros),
            };
            price_order
                .then_with(|| {
                    match_type_priority(left.match_type).cmp(&match_type_priority(right.match_type))
                })
                .then_with(|| left.maker_sequence.cmp(&right.maker_sequence))
                .then_with(|| left.order_id.cmp(&right.order_id))
        });
        candidates
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MatchCandidate {
    order_id: Uuid,
    match_type: MatchType,
    effective_taker_price_micros: u64,
    maker_sequence: u64,
}

fn classify_match(incoming: &BookOrder, resting: &BookOrder) -> Option<MatchType> {
    if resting.outcome == incoming.outcome && resting.action != incoming.action {
        return crosses(incoming, resting).then_some(MatchType::Normal);
    }
    if resting.outcome == incoming.outcome || resting.action != incoming.action {
        return None;
    }
    let price_sum = incoming.price_micros.checked_add(resting.price_micros)?;
    match incoming.action {
        OrderAction::Buy if price_sum >= PRICE_SCALE as u64 => Some(MatchType::Mint),
        OrderAction::Sell if price_sum <= PRICE_SCALE as u64 => Some(MatchType::Merge),
        _ => None,
    }
}

fn effective_taker_price(resting: &BookOrder, match_type: MatchType) -> u64 {
    match match_type {
        MatchType::Normal => resting.price_micros,
        MatchType::Mint | MatchType::Merge => PRICE_SCALE as u64 - resting.price_micros,
    }
}

fn match_type_priority(match_type: MatchType) -> u8 {
    match match_type {
        MatchType::Normal => 0,
        MatchType::Mint => 1,
        MatchType::Merge => 2,
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
