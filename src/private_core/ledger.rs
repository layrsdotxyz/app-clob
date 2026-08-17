use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tiny_keccak::{Hasher, Keccak};

use super::{CoreError, CoreResult};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AccountBucket {
    UserAvailable,
    UserOrderHold,
    UserWithdrawalHold,
    UserPosition,
    MarketCollateral,
    PoolCash,
    VenueInventory,
    BridgeInTransit,
    FeeRevenue,
    RoundingReserve,
    Suspense,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AccountKey {
    /// Opaque enclave-local principal. Never a wallet address.
    pub owner: String,
    pub bucket: AccountBucket,
    pub asset: String,
    #[serde(default)]
    pub market_id: Option<String>,
    #[serde(default)]
    pub outcome: Option<String>,
}

impl AccountKey {
    pub fn new(owner: impl Into<String>, bucket: AccountBucket, asset: impl Into<String>) -> Self {
        Self {
            owner: owner.into(),
            bucket,
            asset: asset.into(),
            market_id: None,
            outcome: None,
        }
    }

    pub fn position(
        owner: impl Into<String>,
        asset: impl Into<String>,
        market_id: impl Into<String>,
        outcome: impl Into<String>,
    ) -> Self {
        Self {
            owner: owner.into(),
            bucket: AccountBucket::UserPosition,
            asset: asset.into(),
            market_id: Some(market_id.into()),
            outcome: Some(outcome.into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transfer {
    pub from: AccountKey,
    pub to: AccountKey,
    pub amount: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerTransaction {
    pub idempotency_key: String,
    pub business_reference: String,
    pub transfers: Vec<Transfer>,
}

/// Enclave-private economic legs for one NORMAL fill. The cash side and claim
/// side use different conserved assets, so each is represented as its own
/// balanced transfer pair. This type must never leave the encrypted journal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalFillPosting {
    pub fill_id: String,
    pub buyer_cash_hold: AccountKey,
    pub seller_available: AccountKey,
    pub seller_claim_hold: AccountKey,
    pub buyer_position: AccountKey,
    pub fee_revenue: AccountKey,
    pub seller_proceeds_atomic: u128,
    pub fee_atomic: u128,
    pub quantity_micros: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppliedLedgerTransaction {
    pub sequence: u64,
    pub idempotency_key: String,
    pub business_reference: String,
    pub prior_state_root: [u8; 32],
    pub state_root: [u8; 32],
    pub transfers: Vec<Transfer>,
    /// Explicit general-ledger legs. Internal transfers produce one debit and
    /// one credit per conserved asset movement; custody-boundary deposits use
    /// normal-side asset/liability postings because both balances increase.
    #[serde(default)]
    pub postings: Vec<LedgerPosting>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PostingSide {
    Debit,
    Credit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerPosting {
    pub account: AccountKey,
    pub side: PostingSide,
    pub amount: u128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExternalFlowDirection {
    Inflow,
    Outflow,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalFlowTransaction {
    pub idempotency_key: String,
    pub evidence_hash: [u8; 32],
    pub account: AccountKey,
    pub amount: u128,
    pub direction: ExternalFlowDirection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CompleteSetDirection {
    Mint,
    Burn,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompleteSetTransaction {
    pub idempotency_key: String,
    pub owner: String,
    pub market_id: String,
    pub settlement_asset: String,
    pub quantity_micros: u128,
    pub collateral_amount_atomic: u128,
    pub direction: CompleteSetDirection,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimPayout {
    pub claim_account: AccountKey,
    pub destination: AccountKey,
    pub claim_quantity_micros: u128,
    pub gross_payout_atomic: u128,
    pub winning_fee_atomic: u128,
}

#[derive(Debug, Clone, Default)]
pub struct Ledger {
    balances: BTreeMap<AccountKey, u128>,
    applied_idempotency_keys: BTreeSet<String>,
    sequence: u64,
}

#[derive(Serialize, Deserialize)]
struct LedgerWire {
    balances: Vec<(AccountKey, u128)>,
    applied_idempotency_keys: BTreeSet<String>,
    sequence: u64,
}

impl Serialize for Ledger {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        LedgerWire {
            balances: self
                .balances
                .iter()
                .map(|(account, amount)| (account.clone(), *amount))
                .collect(),
            applied_idempotency_keys: self.applied_idempotency_keys.clone(),
            sequence: self.sequence,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Ledger {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = LedgerWire::deserialize(deserializer)?;
        Ok(Self {
            balances: wire.balances.into_iter().collect(),
            applied_idempotency_keys: wire.applied_idempotency_keys,
            sequence: wire.sequence,
        })
    }
}

impl Ledger {
    pub fn balance(&self, account: &AccountKey) -> u128 {
        self.balances.get(account).copied().unwrap_or_default()
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Genesis/import operation. Runtime business code must use balanced transactions.
    pub fn seed_balance(&mut self, account: AccountKey, amount: u128) -> CoreResult<()> {
        if self.sequence != 0 || !self.applied_idempotency_keys.is_empty() {
            return Err(CoreError::InvalidOrder(
                "balances may be seeded only before the first ledger transaction".into(),
            ));
        }
        self.balances.insert(account, amount);
        Ok(())
    }

    pub fn apply(
        &mut self,
        transaction: LedgerTransaction,
    ) -> CoreResult<AppliedLedgerTransaction> {
        self.apply_with_replay_keys(transaction, BTreeSet::new())
    }

    /// Applies a batch of NORMAL fills plus the incoming order's reserve and
    /// remainder-release legs as one atomic ledger transition. Fill replay is
    /// bound to enclave-derived fill IDs rather than only the operator command
    /// key, so a committed fill cannot be posted again under a new request.
    pub fn apply_normal_fill_settlement(
        &mut self,
        transaction: LedgerTransaction,
        fills: Vec<NormalFillPosting>,
    ) -> CoreResult<AppliedLedgerTransaction> {
        if fills.is_empty() {
            return Err(CoreError::ZeroAmount);
        }

        let mut unmatched = transaction.transfers.clone();
        let mut replay_keys = BTreeSet::new();
        for fill in &fills {
            validate_normal_fill(fill)?;
            let replay_key = format!("normal-fill-evidence:{}", fill.fill_id);
            if !replay_keys.insert(replay_key.clone())
                || self.applied_idempotency_keys.contains(&replay_key)
            {
                return Err(CoreError::DuplicateCommand);
            }

            consume_transfer(
                &mut unmatched,
                &fill.buyer_cash_hold,
                &fill.seller_available,
                fill.seller_proceeds_atomic,
            )?;
            if fill.fee_atomic > 0 {
                consume_transfer(
                    &mut unmatched,
                    &fill.buyer_cash_hold,
                    &fill.fee_revenue,
                    fill.fee_atomic,
                )?;
            }
            consume_transfer(
                &mut unmatched,
                &fill.seller_claim_hold,
                &fill.buyer_position,
                fill.quantity_micros,
            )?;
        }

        // The only non-fill transfers permitted in this transaction are the
        // already-certified reserve/remainder-release transitions from S03.
        if unmatched
            .iter()
            .any(|transfer| !is_order_hold_transition(transfer))
        {
            return Err(CoreError::UnbalancedTransaction);
        }

        self.apply_with_replay_keys(transaction, replay_keys)
    }

    fn apply_with_replay_keys(
        &mut self,
        transaction: LedgerTransaction,
        additional_replay_keys: BTreeSet<String>,
    ) -> CoreResult<AppliedLedgerTransaction> {
        if transaction.transfers.is_empty() {
            return Err(CoreError::UnbalancedTransaction);
        }
        if self
            .applied_idempotency_keys
            .contains(&transaction.idempotency_key)
        {
            return Err(CoreError::DuplicateCommand);
        }

        let prior_state_root = self.state_root();
        let mut next = self.balances.clone();

        for transfer in &transaction.transfers {
            if transfer.amount == 0 {
                return Err(CoreError::ZeroAmount);
            }
            if transfer.from.asset != transfer.to.asset {
                return Err(CoreError::UnbalancedTransaction);
            }
            let from_balance = next.get(&transfer.from).copied().unwrap_or_default();
            let debited = from_balance
                .checked_sub(transfer.amount)
                .ok_or(CoreError::InsufficientBalance)?;
            let to_balance = next.get(&transfer.to).copied().unwrap_or_default();
            let credited = to_balance
                .checked_add(transfer.amount)
                .ok_or(CoreError::UnbalancedTransaction)?;
            next.insert(transfer.from.clone(), debited);
            next.insert(transfer.to.clone(), credited);
        }

        self.balances = next;
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(CoreError::UnbalancedTransaction)?;
        self.applied_idempotency_keys
            .insert(transaction.idempotency_key.clone());
        self.applied_idempotency_keys.extend(additional_replay_keys);
        let state_root = self.state_root();

        let postings = transaction
            .transfers
            .iter()
            .flat_map(|transfer| {
                [
                    LedgerPosting {
                        account: transfer.from.clone(),
                        side: PostingSide::Debit,
                        amount: transfer.amount,
                    },
                    LedgerPosting {
                        account: transfer.to.clone(),
                        side: PostingSide::Credit,
                        amount: transfer.amount,
                    },
                ]
            })
            .collect();

        Ok(AppliedLedgerTransaction {
            sequence: self.sequence,
            idempotency_key: transaction.idempotency_key,
            business_reference: transaction.business_reference,
            prior_state_root,
            state_root,
            transfers: transaction.transfers,
            postings,
        })
    }

    /// Records one finalized pool deposit as a balanced custody asset and
    /// user-liability pair. The caller must provide an opaque enclave-local
    /// user account and independent finality evidence for the canonical pool
    /// receipt. Provider progress, source-chain detection and quotes are not
    /// sufficient evidence for this operation.
    pub fn apply_confirmed_deposit(
        &mut self,
        transaction: ExternalFlowTransaction,
    ) -> CoreResult<AppliedLedgerTransaction> {
        if transaction.amount == 0 || transaction.evidence_hash == [0u8; 32] {
            return Err(CoreError::ZeroAmount);
        }
        if transaction.direction != ExternalFlowDirection::Inflow
            || transaction.account.bucket != AccountBucket::UserAvailable
            || transaction.account.owner.is_empty()
            || transaction.account.owner == "layrs"
            || transaction.account.market_id.is_some()
            || transaction.account.outcome.is_some()
        {
            return Err(CoreError::InvalidOrder(
                "confirmed deposit requires an opaque user-available liability".into(),
            ));
        }
        // The operator command key is useful for transport retries, but it is
        // not the financial replay boundary: the same finalized pool receipt
        // could otherwise be submitted under a different command key. Commit
        // the canonical finality-evidence hash into the ledger replay set.
        let evidence_replay_key = format!(
            "confirmed-deposit-evidence:{}",
            hex::encode(transaction.evidence_hash)
        );
        if self.applied_idempotency_keys.contains(&evidence_replay_key) {
            return Err(CoreError::DuplicateCommand);
        }

        let pool = AccountKey::new("layrs", AccountBucket::PoolCash, &transaction.account.asset);
        let prior_state_root = self.state_root();
        let mut next = self.balances.clone();
        credit(&mut next, &pool, transaction.amount)?;
        credit(&mut next, &transaction.account, transaction.amount)?;

        self.balances = next;
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(CoreError::UnbalancedTransaction)?;
        self.applied_idempotency_keys
            .insert(evidence_replay_key.clone());
        let state_root = self.state_root();
        Ok(AppliedLedgerTransaction {
            sequence: self.sequence,
            idempotency_key: evidence_replay_key,
            business_reference: format!(
                "confirmed-deposit:{}",
                hex::encode(transaction.evidence_hash)
            ),
            prior_state_root,
            state_root,
            transfers: Vec::new(),
            postings: vec![
                LedgerPosting {
                    account: pool,
                    side: PostingSide::Debit,
                    amount: transaction.amount,
                },
                LedgerPosting {
                    account: transaction.account,
                    side: PostingSide::Credit,
                    amount: transaction.amount,
                },
            ],
        })
    }

    /// Applies a custody boundary movement only after independent chain finality evidence.
    /// Unlike an internal transfer, this deliberately changes the total recognized asset and
    /// must be reconciled one-for-one to the relevant LayrsPool transaction.
    pub fn apply_external_flow(
        &mut self,
        transaction: ExternalFlowTransaction,
    ) -> CoreResult<AppliedLedgerTransaction> {
        if transaction.amount == 0 || transaction.evidence_hash == [0u8; 32] {
            return Err(CoreError::ZeroAmount);
        }
        if self
            .applied_idempotency_keys
            .contains(&transaction.idempotency_key)
        {
            return Err(CoreError::DuplicateCommand);
        }
        let prior_state_root = self.state_root();
        let current = self.balance(&transaction.account);
        let next = match transaction.direction {
            ExternalFlowDirection::Inflow => current
                .checked_add(transaction.amount)
                .ok_or(CoreError::UnbalancedTransaction)?,
            ExternalFlowDirection::Outflow => current
                .checked_sub(transaction.amount)
                .ok_or(CoreError::InsufficientBalance)?,
        };
        self.balances.insert(transaction.account.clone(), next);
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(CoreError::UnbalancedTransaction)?;
        self.applied_idempotency_keys
            .insert(transaction.idempotency_key.clone());
        let state_root = self.state_root();
        Ok(AppliedLedgerTransaction {
            sequence: self.sequence,
            idempotency_key: transaction.idempotency_key,
            business_reference: format!(
                "external:{}:{}",
                match transaction.direction {
                    ExternalFlowDirection::Inflow => "inflow",
                    ExternalFlowDirection::Outflow => "outflow",
                },
                hex::encode(transaction.evidence_hash)
            ),
            prior_state_root,
            state_root,
            transfers: Vec::new(),
            postings: Vec::new(),
        })
    }

    /// Locks one settlement unit and creates one UP plus one DOWN claim, or performs the
    /// exact reverse. This is the sole claim issuance path and keeps every binary market fully
    /// collateralized without exposing owners outside the enclave.
    pub fn apply_complete_set(
        &mut self,
        transaction: CompleteSetTransaction,
    ) -> CoreResult<AppliedLedgerTransaction> {
        if transaction.quantity_micros == 0 || transaction.collateral_amount_atomic == 0 {
            return Err(CoreError::ZeroAmount);
        }
        if self
            .applied_idempotency_keys
            .contains(&transaction.idempotency_key)
        {
            return Err(CoreError::DuplicateCommand);
        }

        let prior_state_root = self.state_root();
        let mut next = self.balances.clone();
        let available = AccountKey::new(
            &transaction.owner,
            AccountBucket::UserAvailable,
            &transaction.settlement_asset,
        );
        let mut collateral = AccountKey::new(
            "layrs",
            AccountBucket::MarketCollateral,
            &transaction.settlement_asset,
        );
        collateral.market_id = Some(transaction.market_id.clone());
        let up = AccountKey::position(
            &transaction.owner,
            format!("CLAIM:{}:UP", transaction.market_id),
            &transaction.market_id,
            "UP",
        );
        let down = AccountKey::position(
            &transaction.owner,
            format!("CLAIM:{}:DOWN", transaction.market_id),
            &transaction.market_id,
            "DOWN",
        );

        match transaction.direction {
            CompleteSetDirection::Mint => {
                debit(&mut next, &available, transaction.collateral_amount_atomic)?;
                credit(&mut next, &collateral, transaction.collateral_amount_atomic)?;
                credit(&mut next, &up, transaction.quantity_micros)?;
                credit(&mut next, &down, transaction.quantity_micros)?;
            }
            CompleteSetDirection::Burn => {
                debit(&mut next, &up, transaction.quantity_micros)?;
                debit(&mut next, &down, transaction.quantity_micros)?;
                debit(&mut next, &collateral, transaction.collateral_amount_atomic)?;
                credit(&mut next, &available, transaction.collateral_amount_atomic)?;
            }
        }

        self.commit_special(
            transaction.idempotency_key,
            format!(
                "complete-set:{}:{}",
                match transaction.direction {
                    CompleteSetDirection::Mint => "mint",
                    CompleteSetDirection::Burn => "burn",
                },
                transaction.market_id
            ),
            prior_state_root,
            next,
        )
    }

    /// Burns resolved claims and pays exclusively from the market's collateral account.
    /// Fee amounts are supplied by the deterministic position-cost engine and retained in the
    /// same settlement asset for independent reconciliation.
    pub fn apply_claim_payouts(
        &mut self,
        idempotency_key: String,
        business_reference: String,
        collateral: AccountKey,
        fee_revenue: AccountKey,
        payouts: Vec<ClaimPayout>,
    ) -> CoreResult<AppliedLedgerTransaction> {
        if payouts.is_empty() || self.applied_idempotency_keys.contains(&idempotency_key) {
            return Err(if payouts.is_empty() {
                CoreError::ZeroAmount
            } else {
                CoreError::DuplicateCommand
            });
        }
        let prior_state_root = self.state_root();
        let mut next = self.balances.clone();
        for payout in &payouts {
            if payout.claim_quantity_micros == 0
                || payout.winning_fee_atomic > payout.gross_payout_atomic
            {
                return Err(CoreError::UnbalancedTransaction);
            }
            debit(
                &mut next,
                &payout.claim_account,
                payout.claim_quantity_micros,
            )?;
            if payout.gross_payout_atomic > 0 {
                debit(&mut next, &collateral, payout.gross_payout_atomic)?;
                let net = payout.gross_payout_atomic - payout.winning_fee_atomic;
                if net > 0 {
                    credit(&mut next, &payout.destination, net)?;
                }
                if payout.winning_fee_atomic > 0 {
                    credit(&mut next, &fee_revenue, payout.winning_fee_atomic)?;
                }
            }
        }
        self.commit_special(idempotency_key, business_reference, prior_state_root, next)
    }

    pub fn positions_for_market(&self, market_id: &str) -> Vec<(AccountKey, u128)> {
        self.balances
            .iter()
            .filter(|(account, amount)| {
                account.bucket == AccountBucket::UserPosition
                    && account.market_id.as_deref() == Some(market_id)
                    && **amount > 0
            })
            .map(|(account, amount)| (account.clone(), *amount))
            .collect()
    }

    /// Returns claims that resolution must consume. This remains enclave-local:
    /// callers may aggregate it for diagnostics but must never expose owners.
    /// Order holds are included because resolution first cancels every resting
    /// order and returns those claims to the corresponding position account.
    pub fn claims_for_market(&self, market_id: &str) -> Vec<(AccountKey, u128)> {
        self.balances
            .iter()
            .filter(|(account, amount)| {
                (account.bucket == AccountBucket::UserPosition
                    || (account.bucket == AccountBucket::UserOrderHold
                        && account.asset.starts_with("CLAIM:")))
                    && account.market_id.as_deref() == Some(market_id)
                    && **amount > 0
            })
            .map(|(account, amount)| (account.clone(), *amount))
            .collect()
    }

    pub fn balances_for_owner(&self, owner: &str) -> Vec<(AccountKey, u128)> {
        self.balances
            .iter()
            .filter(|(account, amount)| account.owner == owner && **amount > 0)
            .map(|(account, amount)| (account.clone(), *amount))
            .collect()
    }

    fn commit_special(
        &mut self,
        idempotency_key: String,
        business_reference: String,
        prior_state_root: [u8; 32],
        balances: BTreeMap<AccountKey, u128>,
    ) -> CoreResult<AppliedLedgerTransaction> {
        self.balances = balances;
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(CoreError::UnbalancedTransaction)?;
        self.applied_idempotency_keys
            .insert(idempotency_key.clone());
        Ok(AppliedLedgerTransaction {
            sequence: self.sequence,
            idempotency_key,
            business_reference,
            prior_state_root,
            state_root: self.state_root(),
            transfers: Vec::new(),
            postings: Vec::new(),
        })
    }

    pub fn total_for_asset(&self, asset: &str) -> u128 {
        self.balances
            .iter()
            .filter(|(key, _)| key.asset == asset)
            .map(|(_, amount)| *amount)
            .sum()
    }

    pub fn total_for_owner_asset(&self, owner: &str, asset: &str) -> u128 {
        self.balances
            .iter()
            .filter(|(key, _)| key.owner == owner && key.asset == asset)
            .map(|(_, amount)| *amount)
            .sum()
    }

    pub fn state_root(&self) -> [u8; 32] {
        let mut hash = Keccak::v256();
        hash.update(b"layrs.private-ledger.v1");
        hash.update(&self.sequence.to_be_bytes());
        for (account, amount) in &self.balances {
            let encoded = serde_json::to_vec(account).expect("serializing AccountKey cannot fail");
            hash.update(&(encoded.len() as u64).to_be_bytes());
            hash.update(&encoded);
            hash.update(&amount.to_be_bytes());
        }
        let mut output = [0u8; 32];
        hash.finalize(&mut output);
        output
    }
}

fn validate_normal_fill(fill: &NormalFillPosting) -> CoreResult<()> {
    if fill.fill_id.is_empty() || fill.quantity_micros == 0 {
        return Err(CoreError::ZeroAmount);
    }
    let cash_debit = fill
        .seller_proceeds_atomic
        .checked_add(fill.fee_atomic)
        .ok_or(CoreError::UnbalancedTransaction)?;
    if cash_debit == 0 {
        return Err(CoreError::ZeroAmount);
    }

    let market_id = fill
        .buyer_cash_hold
        .market_id
        .as_deref()
        .ok_or(CoreError::UnbalancedTransaction)?;
    let outcome = fill
        .buyer_cash_hold
        .outcome
        .as_deref()
        .ok_or(CoreError::UnbalancedTransaction)?;
    let expected_claim_asset = format!("CLAIM:{market_id}:{outcome}");
    let valid_accounts = fill.buyer_cash_hold.bucket == AccountBucket::UserOrderHold
        && fill.seller_available.bucket == AccountBucket::UserAvailable
        && fill.seller_claim_hold.bucket == AccountBucket::UserOrderHold
        && fill.buyer_position.bucket == AccountBucket::UserPosition
        && fill.fee_revenue.bucket == AccountBucket::FeeRevenue
        && fill.fee_revenue.owner == "layrs"
        && !fill.buyer_cash_hold.owner.is_empty()
        && !fill.seller_available.owner.is_empty()
        && fill.buyer_cash_hold.owner != fill.seller_available.owner
        && fill.buyer_cash_hold.owner == fill.buyer_position.owner
        && fill.seller_available.owner == fill.seller_claim_hold.owner
        && fill.buyer_cash_hold.asset == fill.seller_available.asset
        && fill.buyer_cash_hold.asset == fill.fee_revenue.asset
        && fill.seller_claim_hold.asset == expected_claim_asset
        && fill.buyer_position.asset == expected_claim_asset
        && fill.seller_claim_hold.market_id.as_deref() == Some(market_id)
        && fill.buyer_position.market_id.as_deref() == Some(market_id)
        && fill.seller_claim_hold.outcome.as_deref() == Some(outcome)
        && fill.buyer_position.outcome.as_deref() == Some(outcome)
        && fill.seller_available.market_id.is_none()
        && fill.seller_available.outcome.is_none()
        && fill.fee_revenue.market_id.is_none()
        && fill.fee_revenue.outcome.is_none();
    if !valid_accounts {
        return Err(CoreError::UnbalancedTransaction);
    }
    Ok(())
}

fn consume_transfer(
    transfers: &mut Vec<Transfer>,
    from: &AccountKey,
    to: &AccountKey,
    amount: u128,
) -> CoreResult<()> {
    if amount == 0 {
        return Ok(());
    }
    let index = transfers
        .iter()
        .position(|transfer| {
            transfer.from == *from && transfer.to == *to && transfer.amount == amount
        })
        .ok_or(CoreError::UnbalancedTransaction)?;
    transfers.remove(index);
    Ok(())
}

fn is_order_hold_transition(transfer: &Transfer) -> bool {
    if transfer.amount == 0
        || transfer.from.owner != transfer.to.owner
        || transfer.from.asset != transfer.to.asset
    {
        return false;
    }
    match (&transfer.from.bucket, &transfer.to.bucket) {
        (AccountBucket::UserAvailable, AccountBucket::UserOrderHold) => {
            transfer.from.market_id.is_none()
                && transfer.from.outcome.is_none()
                && transfer.to.market_id.is_some()
                && transfer.to.outcome.is_some()
        }
        (AccountBucket::UserOrderHold, AccountBucket::UserAvailable) => {
            transfer.to.market_id.is_none()
                && transfer.to.outcome.is_none()
                && transfer.from.market_id.is_some()
                && transfer.from.outcome.is_some()
        }
        (AccountBucket::UserPosition, AccountBucket::UserOrderHold)
        | (AccountBucket::UserOrderHold, AccountBucket::UserPosition) => {
            transfer.from.market_id == transfer.to.market_id
                && transfer.from.outcome == transfer.to.outcome
        }
        _ => false,
    }
}

fn debit(
    balances: &mut BTreeMap<AccountKey, u128>,
    account: &AccountKey,
    amount: u128,
) -> CoreResult<()> {
    let current = balances.get(account).copied().unwrap_or_default();
    balances.insert(
        account.clone(),
        current
            .checked_sub(amount)
            .ok_or(CoreError::InsufficientBalance)?,
    );
    Ok(())
}

fn credit(
    balances: &mut BTreeMap<AccountKey, u128>,
    account: &AccountKey,
    amount: u128,
) -> CoreResult<()> {
    let current = balances.get(account).copied().unwrap_or_default();
    balances.insert(
        account.clone(),
        current
            .checked_add(amount)
            .ok_or(CoreError::UnbalancedTransaction)?,
    );
    Ok(())
}
