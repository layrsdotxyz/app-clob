use std::collections::{BTreeMap, BTreeSet};

use serde::{de::Error as DeError, Deserialize, Deserializer, Serialize, Serializer};
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
    /// Idle asset owned by one LP vault. This is deliberately distinct from
    /// `PoolCash`: strategy principal must never become synthetic trading
    /// liquidity merely because both are denominated in the same token.
    VaultCash,
    /// Principal that has left vault custody but has not yet reached the
    /// independently-finalized strategy boundary.
    VaultStrategyInTransit,
    /// Independently-finalized principal held by an approved external
    /// strategy on behalf of one vault.
    VaultStrategyReceivable,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VaultStrategyTransition {
    /// One-chain deployment whose receipt proves cash left the vault and the
    /// adapter received the same principal atomically.
    CashToReceivable,
    /// Source-chain finality for an asynchronous/cross-chain deployment.
    CashToTransit,
    /// Destination and adapter/report finality for deployed principal.
    TransitToReceivable,
    /// Finalized strategy recall that has not reached vault custody yet.
    ReceivableToTransit,
    /// One-chain recall whose receipt atomically proves the adapter released
    /// principal and vault custody received it.
    ReceivableToCash,
    /// Finalized return into vault custody.
    TransitToCash,
}

/// Enclave-private vault principal transition. Commitments are opaque hashes;
/// raw vault, strategy, adapter, bridge and transaction identifiers never
/// leave the encrypted journal or appear in the signed public receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultStrategyTransaction {
    pub idempotency_key: String,
    pub evidence_hash: [u8; 32],
    pub vault_commitment: [u8; 32],
    pub strategy_commitment: [u8; 32],
    pub operation_commitment: [u8; 32],
    pub asset: String,
    pub amount: u128,
    pub transition: VaultStrategyTransition,
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

/// Enclave-private economic legs for one complementary MINT or MERGE fill.
///
/// A complete-set fill has two independently conserved boundaries:
/// settlement cash is conserved exactly across holds/collateral/fees, while
/// the UP and DOWN claim quantities must be issued or burned in equal amounts.
/// The account interpretation depends on `direction`:
///
/// * MINT: `maker_hold`/`taker_hold` are cash holds and the destinations are
///   the two user claim positions.
/// * BURN: the holds are the two claim holds and the destinations are user
///   cash-available accounts.
///
/// This descriptor and every account owner remain inside the encrypted
/// journal. Only the existing aggregate fill artifact may leave the enclave.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompleteSetFillPosting {
    pub fill_id: String,
    pub direction: CompleteSetDirection,
    pub maker_hold: AccountKey,
    pub taker_hold: AccountKey,
    pub maker_destination: AccountKey,
    pub taker_destination: AccountKey,
    pub market_collateral: AccountKey,
    pub fee_revenue: AccountKey,
    pub quantity_micros: u128,
    pub collateral_amount_atomic: u128,
    pub maker_amount_atomic: u128,
    pub taker_amount_atomic: u128,
    pub taker_fee_atomic: u128,
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

/// Financial interpretation of a terminal market result.
///
/// `Invalid` is intentionally a ledger-only distinction. Public settlement
/// contracts encode an exposed invalid market as the governed `PUSH_REFUND`
/// outcome, while a zero-exposure market may be marked INVALIDATED without a
/// payout. Keeping the distinction here lets accounting tests prove that both
/// void paths refund symmetrically and never charge a winning fee.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResolutionPayoutKind {
    Up,
    Down,
    Push,
    Invalid,
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
        let mut balances = BTreeMap::new();
        for (account, amount) in wire.balances {
            validate_account_key(&account).map_err(D::Error::custom)?;
            if amount == 0 {
                return Err(D::Error::custom("ledger snapshot contains a zero balance"));
            }
            if balances.insert(account, amount).is_some() {
                return Err(D::Error::custom(
                    "ledger snapshot contains a duplicate account",
                ));
            }
        }
        validate_balance_model(&balances).map_err(D::Error::custom)?;
        validate_replay_keys(&wire.applied_idempotency_keys).map_err(D::Error::custom)?;
        Ok(Self {
            balances,
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
        if amount == 0 {
            return Err(CoreError::ZeroAmount);
        }
        validate_account_key(&account)?;
        if self.balances.contains_key(&account) {
            return Err(CoreError::DuplicateCommand);
        }
        let mut next = self.balances.clone();
        next.insert(account, amount);
        validate_balance_model(&next)?;
        self.balances = next;
        Ok(())
    }

    pub fn apply(
        &mut self,
        transaction: LedgerTransaction,
    ) -> CoreResult<AppliedLedgerTransaction> {
        self.apply_with_replay_keys(transaction, BTreeSet::new())
    }

    /// Reclassifies vault principal between mutually-exclusive cash,
    /// in-transit and external-receivable accounts. The total recognized
    /// principal is invariant, and trading pool cash is not reachable by any
    /// transition. Replay protection is derived from independent finality
    /// evidence rather than the operator's transport idempotency key.
    pub fn apply_vault_strategy_transition(
        &mut self,
        transaction: VaultStrategyTransaction,
    ) -> CoreResult<AppliedLedgerTransaction> {
        validate_vault_strategy_transaction(&transaction)?;
        let evidence_replay_key = format!(
            "vault-strategy-evidence:{}",
            hex::encode(transaction.evidence_hash)
        );
        if self.applied_idempotency_keys.contains(&evidence_replay_key) {
            return Err(CoreError::DuplicateCommand);
        }

        let vault_owner = format!("vault:{}", hex::encode(transaction.vault_commitment));
        let strategy_owner = format!(
            "vault:{}:strategy:{}",
            hex::encode(transaction.vault_commitment),
            hex::encode(transaction.strategy_commitment)
        );
        let transit_owner = format!(
            "vault:{}:operation:{}",
            hex::encode(transaction.vault_commitment),
            hex::encode(transaction.operation_commitment)
        );
        let cash = AccountKey::new(vault_owner, AccountBucket::VaultCash, &transaction.asset);
        let receivable = AccountKey::new(
            strategy_owner,
            AccountBucket::VaultStrategyReceivable,
            &transaction.asset,
        );
        let transit = AccountKey::new(
            transit_owner,
            AccountBucket::VaultStrategyInTransit,
            &transaction.asset,
        );
        let (from, to) = match transaction.transition {
            VaultStrategyTransition::CashToReceivable => (cash, receivable),
            VaultStrategyTransition::CashToTransit => (cash, transit),
            VaultStrategyTransition::TransitToReceivable => (transit, receivable),
            VaultStrategyTransition::ReceivableToTransit => (receivable, transit),
            VaultStrategyTransition::ReceivableToCash => (receivable, cash),
            VaultStrategyTransition::TransitToCash => (transit, cash),
        };
        let mut replay_keys = BTreeSet::new();
        replay_keys.insert(evidence_replay_key);
        self.apply_with_replay_keys(
            LedgerTransaction {
                idempotency_key: transaction.idempotency_key,
                business_reference: format!(
                    "vault-strategy:{}:{}",
                    vault_strategy_transition_name(transaction.transition),
                    hex::encode(transaction.evidence_hash)
                ),
                transfers: vec![Transfer {
                    from,
                    to,
                    amount: transaction.amount,
                }],
            },
            replay_keys,
        )
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

    /// Atomically applies one complete-set fill. Replay protection is derived
    /// from the enclave fill ID, independent of the operator request key, so a
    /// committed MINT/MERGE cannot be financially posted again after a lost
    /// response or under a different transport idempotency key.
    pub fn apply_complete_set_fill(
        &mut self,
        idempotency_key: String,
        business_reference: String,
        fill: CompleteSetFillPosting,
    ) -> CoreResult<AppliedLedgerTransaction> {
        validate_complete_set_fill(&fill)?;
        if self.applied_idempotency_keys.contains(&idempotency_key) {
            return Err(CoreError::DuplicateCommand);
        }
        let evidence_replay_key = format!("complete-set-fill-evidence:{}", fill.fill_id);
        if self.applied_idempotency_keys.contains(&evidence_replay_key) {
            return Err(CoreError::DuplicateCommand);
        }

        let prior_state_root = self.state_root();
        let mut next = self.balances.clone();
        let taker_cash_or_proceeds = fill
            .taker_amount_atomic
            .checked_sub(fill.taker_fee_atomic)
            .ok_or(CoreError::UnbalancedTransaction)?;
        let mut transfers = Vec::with_capacity(3);
        let mut postings = Vec::with_capacity(6);

        match fill.direction {
            CompleteSetDirection::Mint => {
                let taker_debit = fill
                    .taker_amount_atomic
                    .checked_add(fill.taker_fee_atomic)
                    .ok_or(CoreError::UnbalancedTransaction)?;
                debit(&mut next, &fill.maker_hold, fill.maker_amount_atomic)?;
                debit(&mut next, &fill.taker_hold, taker_debit)?;
                credit(
                    &mut next,
                    &fill.market_collateral,
                    fill.collateral_amount_atomic,
                )?;
                if fill.taker_fee_atomic > 0 {
                    credit(&mut next, &fill.fee_revenue, fill.taker_fee_atomic)?;
                }
                credit(&mut next, &fill.maker_destination, fill.quantity_micros)?;
                credit(&mut next, &fill.taker_destination, fill.quantity_micros)?;

                transfers.push(Transfer {
                    from: fill.maker_hold.clone(),
                    to: fill.market_collateral.clone(),
                    amount: fill.maker_amount_atomic,
                });
                transfers.push(Transfer {
                    from: fill.taker_hold.clone(),
                    to: fill.market_collateral.clone(),
                    amount: fill.taker_amount_atomic,
                });
                if fill.taker_fee_atomic > 0 {
                    transfers.push(Transfer {
                        from: fill.taker_hold.clone(),
                        to: fill.fee_revenue.clone(),
                        amount: fill.taker_fee_atomic,
                    });
                }

                postings.extend([
                    posting(
                        &fill.maker_hold,
                        PostingSide::Debit,
                        fill.maker_amount_atomic,
                    ),
                    posting(&fill.taker_hold, PostingSide::Debit, taker_debit),
                    posting(
                        &fill.market_collateral,
                        PostingSide::Credit,
                        fill.collateral_amount_atomic,
                    ),
                    posting(
                        &fill.maker_destination,
                        PostingSide::Credit,
                        fill.quantity_micros,
                    ),
                    posting(
                        &fill.taker_destination,
                        PostingSide::Credit,
                        fill.quantity_micros,
                    ),
                ]);
                if fill.taker_fee_atomic > 0 {
                    postings.push(posting(
                        &fill.fee_revenue,
                        PostingSide::Credit,
                        fill.taker_fee_atomic,
                    ));
                }
            }
            CompleteSetDirection::Burn => {
                debit(&mut next, &fill.maker_hold, fill.quantity_micros)?;
                debit(&mut next, &fill.taker_hold, fill.quantity_micros)?;
                debit(
                    &mut next,
                    &fill.market_collateral,
                    fill.collateral_amount_atomic,
                )?;
                credit(&mut next, &fill.maker_destination, fill.maker_amount_atomic)?;
                if taker_cash_or_proceeds > 0 {
                    credit(&mut next, &fill.taker_destination, taker_cash_or_proceeds)?;
                }
                if fill.taker_fee_atomic > 0 {
                    credit(&mut next, &fill.fee_revenue, fill.taker_fee_atomic)?;
                }

                transfers.push(Transfer {
                    from: fill.market_collateral.clone(),
                    to: fill.maker_destination.clone(),
                    amount: fill.maker_amount_atomic,
                });
                if taker_cash_or_proceeds > 0 {
                    transfers.push(Transfer {
                        from: fill.market_collateral.clone(),
                        to: fill.taker_destination.clone(),
                        amount: taker_cash_or_proceeds,
                    });
                }
                if fill.taker_fee_atomic > 0 {
                    transfers.push(Transfer {
                        from: fill.market_collateral.clone(),
                        to: fill.fee_revenue.clone(),
                        amount: fill.taker_fee_atomic,
                    });
                }

                postings.extend([
                    posting(&fill.maker_hold, PostingSide::Debit, fill.quantity_micros),
                    posting(&fill.taker_hold, PostingSide::Debit, fill.quantity_micros),
                    posting(
                        &fill.market_collateral,
                        PostingSide::Debit,
                        fill.collateral_amount_atomic,
                    ),
                    posting(
                        &fill.maker_destination,
                        PostingSide::Credit,
                        fill.maker_amount_atomic,
                    ),
                ]);
                if taker_cash_or_proceeds > 0 {
                    postings.push(posting(
                        &fill.taker_destination,
                        PostingSide::Credit,
                        taker_cash_or_proceeds,
                    ));
                }
                if fill.taker_fee_atomic > 0 {
                    postings.push(posting(
                        &fill.fee_revenue,
                        PostingSide::Credit,
                        fill.taker_fee_atomic,
                    ));
                }
            }
        }

        canonicalize_balances(&mut next);
        validate_balance_model(&next)?;
        self.balances = next;
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(CoreError::UnbalancedTransaction)?;
        self.applied_idempotency_keys
            .insert(idempotency_key.clone());
        self.applied_idempotency_keys.insert(evidence_replay_key);
        Ok(AppliedLedgerTransaction {
            sequence: self.sequence,
            idempotency_key,
            business_reference,
            prior_state_root,
            state_root: self.state_root(),
            transfers,
            postings,
        })
    }

    fn apply_with_replay_keys(
        &mut self,
        transaction: LedgerTransaction,
        additional_replay_keys: BTreeSet<String>,
    ) -> CoreResult<AppliedLedgerTransaction> {
        if transaction.transfers.is_empty() || transaction.idempotency_key.is_empty() {
            return Err(CoreError::UnbalancedTransaction);
        }
        if self
            .applied_idempotency_keys
            .contains(&transaction.idempotency_key)
        {
            return Err(CoreError::DuplicateCommand);
        }
        let mut all_new_replay_keys = additional_replay_keys.clone();
        all_new_replay_keys.insert(transaction.idempotency_key.clone());
        validate_replay_keys(&all_new_replay_keys)?;
        if additional_replay_keys
            .iter()
            .any(|key| self.applied_idempotency_keys.contains(key))
        {
            return Err(CoreError::DuplicateCommand);
        }

        let prior_state_root = self.state_root();
        let mut next = self.balances.clone();

        for transfer in &transaction.transfers {
            if transfer.amount == 0 {
                return Err(CoreError::ZeroAmount);
            }
            validate_account_key(&transfer.from)?;
            validate_account_key(&transfer.to)?;
            if transfer.from == transfer.to || transfer.from.asset != transfer.to.asset {
                return Err(CoreError::UnbalancedTransaction);
            }
            if transfer.to.bucket == AccountBucket::RoundingReserve {
                validate_rounding_dust_transfer(&transfer.to, transfer.amount)?;
            }
            debit(&mut next, &transfer.from, transfer.amount)?;
            credit(&mut next, &transfer.to, transfer.amount)?;
        }

        canonicalize_balances(&mut next);
        validate_balance_model(&next)?;
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

        canonicalize_balances(&mut next);
        validate_balance_model(&next)?;
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

    /// Records one finalized pool withdrawal as a balanced reduction of the
    /// pool asset and the corresponding user-withdrawal liability. A prepared
    /// or broadcast transaction is not sufficient: `evidence_hash` must bind
    /// the canonical successful finality event (or the delivered destination
    /// event for a routed withdrawal).
    pub fn apply_confirmed_withdrawal(
        &mut self,
        transaction: ExternalFlowTransaction,
    ) -> CoreResult<AppliedLedgerTransaction> {
        if transaction.amount == 0 || transaction.evidence_hash == [0u8; 32] {
            return Err(CoreError::ZeroAmount);
        }
        if transaction.direction != ExternalFlowDirection::Outflow
            || transaction.account.bucket != AccountBucket::UserWithdrawalHold
            || transaction.account.owner.is_empty()
            || transaction.account.owner == "layrs"
            || transaction.account.market_id.is_some()
            || transaction.account.outcome.is_some()
        {
            return Err(CoreError::InvalidOrder(
                "confirmed withdrawal requires an opaque user-withdrawal liability".into(),
            ));
        }
        let evidence_replay_key = format!(
            "confirmed-withdrawal-evidence:{}",
            hex::encode(transaction.evidence_hash)
        );
        if self.applied_idempotency_keys.contains(&evidence_replay_key) {
            return Err(CoreError::DuplicateCommand);
        }

        let pool = AccountKey::new("layrs", AccountBucket::PoolCash, &transaction.account.asset);
        let prior_state_root = self.state_root();
        let mut next = self.balances.clone();
        debit(&mut next, &transaction.account, transaction.amount)?;
        debit(&mut next, &pool, transaction.amount)?;

        canonicalize_balances(&mut next);
        validate_balance_model(&next)?;
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
                "confirmed-withdrawal:{}",
                hex::encode(transaction.evidence_hash)
            ),
            prior_state_root,
            state_root,
            transfers: Vec::new(),
            postings: vec![
                LedgerPosting {
                    account: transaction.account,
                    side: PostingSide::Debit,
                    amount: transaction.amount,
                },
                LedgerPosting {
                    account: pool,
                    side: PostingSide::Credit,
                    amount: transaction.amount,
                },
            ],
        })
    }

    /// Releases a failed withdrawal hold back to the same opaque user's
    /// available balance. The independent failure evidence is a financial
    /// replay key, so a committed release cannot be repeated with a different
    /// operator idempotency key after a lost response.
    pub fn release_withdrawal(
        &mut self,
        idempotency_key: String,
        evidence_hash: [u8; 32],
        hold: AccountKey,
        available: AccountKey,
        amount: u128,
    ) -> CoreResult<AppliedLedgerTransaction> {
        if amount == 0 || evidence_hash == [0u8; 32] {
            return Err(CoreError::ZeroAmount);
        }
        if hold.bucket != AccountBucket::UserWithdrawalHold
            || available.bucket != AccountBucket::UserAvailable
            || hold.owner.is_empty()
            || hold.owner == "layrs"
            || hold.owner != available.owner
            || hold.asset != available.asset
            || hold.market_id.is_some()
            || hold.outcome.is_some()
            || available.market_id.is_some()
            || available.outcome.is_some()
        {
            return Err(CoreError::InvalidOrder(
                "withdrawal release requires matching opaque user accounts".into(),
            ));
        }
        let evidence_replay_key =
            format!("withdrawal-release-evidence:{}", hex::encode(evidence_hash));
        if self.applied_idempotency_keys.contains(&evidence_replay_key) {
            return Err(CoreError::DuplicateCommand);
        }
        let mut replay_keys = BTreeSet::new();
        replay_keys.insert(evidence_replay_key);
        self.apply_with_replay_keys(
            LedgerTransaction {
                idempotency_key,
                business_reference: format!("withdrawal-release:{}", hex::encode(evidence_hash)),
                transfers: vec![Transfer {
                    from: hold,
                    to: available,
                    amount,
                }],
            },
            replay_keys,
        )
    }

    /// Applies a custody boundary movement only after independent chain finality evidence.
    /// Unlike an internal transfer, this deliberately changes the total recognized asset and
    /// must be reconciled one-for-one to the relevant LayrsPool transaction.
    pub fn apply_external_flow(
        &mut self,
        transaction: ExternalFlowTransaction,
    ) -> CoreResult<AppliedLedgerTransaction> {
        if matches!(
            transaction.account.bucket,
            AccountBucket::VaultCash
                | AccountBucket::VaultStrategyInTransit
                | AccountBucket::VaultStrategyReceivable
        ) {
            return Err(CoreError::InvalidOrder(
                "vault principal requires a balanced strategy transition".into(),
            ));
        }
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

        let (transfers, postings) = match transaction.direction {
            CompleteSetDirection::Mint => {
                debit(&mut next, &available, transaction.collateral_amount_atomic)?;
                credit(&mut next, &collateral, transaction.collateral_amount_atomic)?;
                credit(&mut next, &up, transaction.quantity_micros)?;
                credit(&mut next, &down, transaction.quantity_micros)?;
                (
                    vec![Transfer {
                        from: available.clone(),
                        to: collateral.clone(),
                        amount: transaction.collateral_amount_atomic,
                    }],
                    vec![
                        posting(
                            &available,
                            PostingSide::Debit,
                            transaction.collateral_amount_atomic,
                        ),
                        posting(
                            &collateral,
                            PostingSide::Credit,
                            transaction.collateral_amount_atomic,
                        ),
                        posting(&up, PostingSide::Credit, transaction.quantity_micros),
                        posting(&down, PostingSide::Credit, transaction.quantity_micros),
                    ],
                )
            }
            CompleteSetDirection::Burn => {
                debit(&mut next, &up, transaction.quantity_micros)?;
                debit(&mut next, &down, transaction.quantity_micros)?;
                debit(&mut next, &collateral, transaction.collateral_amount_atomic)?;
                credit(&mut next, &available, transaction.collateral_amount_atomic)?;
                (
                    vec![Transfer {
                        from: collateral.clone(),
                        to: available.clone(),
                        amount: transaction.collateral_amount_atomic,
                    }],
                    vec![
                        posting(&up, PostingSide::Debit, transaction.quantity_micros),
                        posting(&down, PostingSide::Debit, transaction.quantity_micros),
                        posting(
                            &collateral,
                            PostingSide::Debit,
                            transaction.collateral_amount_atomic,
                        ),
                        posting(
                            &available,
                            PostingSide::Credit,
                            transaction.collateral_amount_atomic,
                        ),
                    ],
                )
            }
        };

        self.commit_special_with_details(
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
            transfers,
            postings,
        )
    }

    /// Burns resolved claims and pays exclusively from the market's collateral account.
    /// Fee amounts are supplied by the deterministic position-cost engine and retained in the
    /// same settlement asset for independent reconciliation.
    pub fn apply_claim_payouts(
        &mut self,
        idempotency_key: String,
        business_reference: String,
        resolution_evidence_hash: [u8; 32],
        payout_kind: ResolutionPayoutKind,
        collateral: AccountKey,
        fee_revenue: AccountKey,
        payouts: Vec<ClaimPayout>,
    ) -> CoreResult<AppliedLedgerTransaction> {
        if payouts.is_empty()
            || resolution_evidence_hash == [0u8; 32]
            || self.applied_idempotency_keys.contains(&idempotency_key)
        {
            return Err(if payouts.is_empty() {
                CoreError::ZeroAmount
            } else if resolution_evidence_hash == [0u8; 32] {
                CoreError::InvalidResolution("resolution payout evidence is required".into())
            } else {
                CoreError::DuplicateCommand
            });
        }
        let evidence_replay_key = format!(
            "resolution-payout-evidence:{}",
            hex::encode(resolution_evidence_hash)
        );
        if self.applied_idempotency_keys.contains(&evidence_replay_key) {
            return Err(CoreError::DuplicateCommand);
        }
        let market_id = collateral
            .market_id
            .as_deref()
            .ok_or(CoreError::UnbalancedTransaction)?;
        if collateral.bucket != AccountBucket::MarketCollateral
            || collateral.owner != "layrs"
            || collateral.outcome.is_some()
            || fee_revenue.bucket != AccountBucket::FeeRevenue
            || fee_revenue.owner != "layrs"
            || fee_revenue.asset != collateral.asset
            || fee_revenue.market_id.is_some()
            || fee_revenue.outcome.is_some()
        {
            return Err(CoreError::UnbalancedTransaction);
        }
        let prior_state_root = self.state_root();
        let mut next = self.balances.clone();
        let mut transfers = Vec::with_capacity(payouts.len() * 2);
        let mut postings = Vec::with_capacity(payouts.len() * 4);
        for payout in &payouts {
            if payout.claim_quantity_micros == 0
                || payout.winning_fee_atomic > payout.gross_payout_atomic
            {
                return Err(CoreError::UnbalancedTransaction);
            }
            let claim_outcome = payout
                .claim_account
                .outcome
                .as_deref()
                .ok_or(CoreError::UnbalancedTransaction)?;
            let claim_is_winner = matches!(
                (payout_kind, claim_outcome),
                (ResolutionPayoutKind::Up, "UP") | (ResolutionPayoutKind::Down, "DOWN")
            );
            let valid_payout_shape = match payout_kind {
                ResolutionPayoutKind::Up | ResolutionPayoutKind::Down => {
                    (claim_is_winner && payout.gross_payout_atomic > 0)
                        || (!claim_is_winner && payout.gross_payout_atomic == 0)
                }
                ResolutionPayoutKind::Push | ResolutionPayoutKind::Invalid => {
                    payout.gross_payout_atomic > 0 && payout.winning_fee_atomic == 0
                }
            };
            let expected_claim_asset = format!("CLAIM:{market_id}:{claim_outcome}");
            if !matches!(claim_outcome, "UP" | "DOWN")
                || !valid_payout_shape
                || payout.claim_account.bucket != AccountBucket::UserPosition
                || payout.claim_account.owner.is_empty()
                || payout.claim_account.owner == "layrs"
                || payout.claim_account.asset != expected_claim_asset
                || payout.claim_account.market_id.as_deref() != Some(market_id)
                || payout.destination.bucket != AccountBucket::UserAvailable
                || payout.destination.owner != payout.claim_account.owner
                || payout.destination.asset != collateral.asset
                || payout.destination.market_id.is_some()
                || payout.destination.outcome.is_some()
            {
                return Err(CoreError::UnbalancedTransaction);
            }
            debit(
                &mut next,
                &payout.claim_account,
                payout.claim_quantity_micros,
            )?;
            postings.push(posting(
                &payout.claim_account,
                PostingSide::Debit,
                payout.claim_quantity_micros,
            ));
            if payout.gross_payout_atomic > 0 {
                debit(&mut next, &collateral, payout.gross_payout_atomic)?;
                let net = payout.gross_payout_atomic - payout.winning_fee_atomic;
                postings.push(posting(
                    &collateral,
                    PostingSide::Debit,
                    payout.gross_payout_atomic,
                ));
                if net > 0 {
                    credit(&mut next, &payout.destination, net)?;
                    transfers.push(Transfer {
                        from: collateral.clone(),
                        to: payout.destination.clone(),
                        amount: net,
                    });
                    postings.push(posting(&payout.destination, PostingSide::Credit, net));
                }
                if payout.winning_fee_atomic > 0 {
                    credit(&mut next, &fee_revenue, payout.winning_fee_atomic)?;
                    transfers.push(Transfer {
                        from: collateral.clone(),
                        to: fee_revenue.clone(),
                        amount: payout.winning_fee_atomic,
                    });
                    postings.push(posting(
                        &fee_revenue,
                        PostingSide::Credit,
                        payout.winning_fee_atomic,
                    ));
                }
            }
        }
        canonicalize_balances(&mut next);
        validate_balance_model(&next)?;
        self.balances = next;
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(CoreError::UnbalancedTransaction)?;
        self.applied_idempotency_keys
            .insert(idempotency_key.clone());
        self.applied_idempotency_keys.insert(evidence_replay_key);
        Ok(AppliedLedgerTransaction {
            sequence: self.sequence,
            idempotency_key,
            business_reference,
            prior_state_root,
            state_root: self.state_root(),
            transfers,
            postings,
        })
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
        self.commit_special_with_details(
            idempotency_key,
            business_reference,
            prior_state_root,
            balances,
            Vec::new(),
            Vec::new(),
        )
    }

    fn commit_special_with_details(
        &mut self,
        idempotency_key: String,
        business_reference: String,
        prior_state_root: [u8; 32],
        balances: BTreeMap<AccountKey, u128>,
        transfers: Vec<Transfer>,
        postings: Vec<LedgerPosting>,
    ) -> CoreResult<AppliedLedgerTransaction> {
        let mut balances = balances;
        canonicalize_balances(&mut balances);
        validate_balance_model(&balances)?;
        validate_posting_shape(&postings)?;
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
            transfers,
            postings,
        })
    }

    pub fn total_for_asset(&self, asset: &str) -> u128 {
        self.balances
            .iter()
            .filter(|(key, _)| key.asset == asset)
            .map(|(_, amount)| *amount)
            .fold(0u128, u128::saturating_add)
    }

    pub fn checked_total_for_asset(&self, asset: &str) -> CoreResult<u128> {
        self.balances
            .iter()
            .filter(|(key, _)| key.asset == asset)
            .try_fold(0u128, |total, (_, amount)| {
                total
                    .checked_add(*amount)
                    .ok_or(CoreError::UnbalancedTransaction)
            })
    }

    pub fn total_for_owner_asset(&self, owner: &str, asset: &str) -> u128 {
        self.balances
            .iter()
            .filter(|(key, _)| key.owner == owner && key.asset == asset)
            .map(|(_, amount)| *amount)
            .fold(0u128, u128::saturating_add)
    }

    pub fn checked_total_for_owner_asset(&self, owner: &str, asset: &str) -> CoreResult<u128> {
        self.balances
            .iter()
            .filter(|(key, _)| key.owner == owner && key.asset == asset)
            .try_fold(0u128, |total, (_, amount)| {
                total
                    .checked_add(*amount)
                    .ok_or(CoreError::UnbalancedTransaction)
            })
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

fn validate_complete_set_fill(fill: &CompleteSetFillPosting) -> CoreResult<()> {
    if fill.fill_id.is_empty()
        || fill.quantity_micros == 0
        || fill.collateral_amount_atomic == 0
        || fill.maker_amount_atomic == 0
        || fill.taker_amount_atomic == 0
    {
        return Err(CoreError::ZeroAmount);
    }
    if fill.taker_fee_atomic > fill.taker_amount_atomic
        || fill
            .maker_amount_atomic
            .checked_add(fill.taker_amount_atomic)
            != Some(fill.collateral_amount_atomic)
    {
        return Err(CoreError::UnbalancedTransaction);
    }

    let market_id = fill
        .market_collateral
        .market_id
        .as_deref()
        .ok_or(CoreError::UnbalancedTransaction)?;
    let maker_outcome = fill
        .maker_hold
        .outcome
        .as_deref()
        .ok_or(CoreError::UnbalancedTransaction)?;
    let taker_outcome = fill
        .taker_hold
        .outcome
        .as_deref()
        .ok_or(CoreError::UnbalancedTransaction)?;
    if !matches!(maker_outcome, "UP" | "DOWN")
        || !matches!(taker_outcome, "UP" | "DOWN")
        || maker_outcome == taker_outcome
        || fill.maker_hold.owner.is_empty()
        || fill.taker_hold.owner.is_empty()
        || fill.maker_hold.owner == "layrs"
        || fill.taker_hold.owner == "layrs"
        || fill.maker_hold.owner == fill.taker_hold.owner
        || fill.maker_hold.owner != fill.maker_destination.owner
        || fill.taker_hold.owner != fill.taker_destination.owner
        || fill.maker_hold.market_id.as_deref() != Some(market_id)
        || fill.taker_hold.market_id.as_deref() != Some(market_id)
        || fill.market_collateral.bucket != AccountBucket::MarketCollateral
        || fill.market_collateral.owner != "layrs"
        || fill.market_collateral.outcome.is_some()
        || fill.fee_revenue.bucket != AccountBucket::FeeRevenue
        || fill.fee_revenue.owner != "layrs"
        || fill.fee_revenue.market_id.is_some()
        || fill.fee_revenue.outcome.is_some()
        || fill.market_collateral.asset != fill.fee_revenue.asset
        || fill.market_collateral.asset.is_empty()
    {
        return Err(CoreError::UnbalancedTransaction);
    }

    let settlement_asset = &fill.market_collateral.asset;
    let maker_claim = format!("CLAIM:{market_id}:{maker_outcome}");
    let taker_claim = format!("CLAIM:{market_id}:{taker_outcome}");
    let valid = match fill.direction {
        CompleteSetDirection::Mint => {
            fill.maker_hold.bucket == AccountBucket::UserOrderHold
                && fill.taker_hold.bucket == AccountBucket::UserOrderHold
                && fill.maker_hold.asset == *settlement_asset
                && fill.taker_hold.asset == *settlement_asset
                && fill.maker_destination.bucket == AccountBucket::UserPosition
                && fill.taker_destination.bucket == AccountBucket::UserPosition
                && fill.maker_destination.asset == maker_claim
                && fill.taker_destination.asset == taker_claim
                && fill.maker_destination.market_id.as_deref() == Some(market_id)
                && fill.taker_destination.market_id.as_deref() == Some(market_id)
                && fill.maker_destination.outcome.as_deref() == Some(maker_outcome)
                && fill.taker_destination.outcome.as_deref() == Some(taker_outcome)
        }
        CompleteSetDirection::Burn => {
            fill.maker_hold.bucket == AccountBucket::UserOrderHold
                && fill.taker_hold.bucket == AccountBucket::UserOrderHold
                && fill.maker_hold.asset == maker_claim
                && fill.taker_hold.asset == taker_claim
                && fill.maker_destination.bucket == AccountBucket::UserAvailable
                && fill.taker_destination.bucket == AccountBucket::UserAvailable
                && fill.maker_destination.asset == *settlement_asset
                && fill.taker_destination.asset == *settlement_asset
                && fill.maker_destination.market_id.is_none()
                && fill.taker_destination.market_id.is_none()
                && fill.maker_destination.outcome.is_none()
                && fill.taker_destination.outcome.is_none()
        }
    };
    if !valid {
        return Err(CoreError::UnbalancedTransaction);
    }
    Ok(())
}

fn posting(account: &AccountKey, side: PostingSide, amount: u128) -> LedgerPosting {
    LedgerPosting {
        account: account.clone(),
        side,
        amount,
    }
}

fn validate_vault_strategy_transaction(transaction: &VaultStrategyTransaction) -> CoreResult<()> {
    if transaction.amount == 0 {
        return Err(CoreError::ZeroAmount);
    }
    if transaction.evidence_hash == [0u8; 32]
        || transaction.vault_commitment == [0u8; 32]
        || transaction.strategy_commitment == [0u8; 32]
        || transaction.operation_commitment == [0u8; 32]
        || transaction.idempotency_key.is_empty()
        || transaction.asset.is_empty()
        || transaction.asset.len() > 32
        || !transaction
            .asset
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(CoreError::InvalidOrder(
            "invalid vault strategy transition".into(),
        ));
    }
    Ok(())
}

fn vault_strategy_transition_name(transition: VaultStrategyTransition) -> &'static str {
    match transition {
        VaultStrategyTransition::CashToReceivable => "cash-to-receivable",
        VaultStrategyTransition::CashToTransit => "cash-to-transit",
        VaultStrategyTransition::TransitToReceivable => "transit-to-receivable",
        VaultStrategyTransition::ReceivableToTransit => "receivable-to-transit",
        VaultStrategyTransition::ReceivableToCash => "receivable-to-cash",
        VaultStrategyTransition::TransitToCash => "transit-to-cash",
    }
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
    if amount == 0 {
        return Err(CoreError::ZeroAmount);
    }
    validate_account_key(account)?;
    let next = current
        .checked_sub(amount)
        .ok_or(CoreError::InsufficientBalance)?;
    if next == 0 {
        balances.remove(account);
    } else {
        balances.insert(account.clone(), next);
    }
    Ok(())
}

fn credit(
    balances: &mut BTreeMap<AccountKey, u128>,
    account: &AccountKey,
    amount: u128,
) -> CoreResult<()> {
    if amount == 0 {
        return Err(CoreError::ZeroAmount);
    }
    validate_account_key(account)?;
    let current = balances.get(account).copied().unwrap_or_default();
    balances.insert(
        account.clone(),
        current
            .checked_add(amount)
            .ok_or(CoreError::UnbalancedTransaction)?,
    );
    Ok(())
}

const MAX_PRIVATE_KEY_COMPONENT_BYTES: usize = 256;
const MAX_REPLAY_KEY_BYTES: usize = 512;

fn validate_account_key(account: &AccountKey) -> CoreResult<()> {
    let valid_component = |value: &str| {
        !value.is_empty()
            && value.len() <= MAX_PRIVATE_KEY_COMPONENT_BYTES
            && !value
                .bytes()
                .any(|byte| byte == 0 || byte.is_ascii_control())
    };
    if !valid_component(&account.owner)
        || !valid_component(&account.asset)
        || account
            .market_id
            .as_deref()
            .is_some_and(|value| !valid_component(value))
        || account
            .outcome
            .as_deref()
            .is_some_and(|value| !valid_component(value))
    {
        return Err(CoreError::UnbalancedTransaction);
    }
    Ok(())
}

fn validate_replay_keys(keys: &BTreeSet<String>) -> CoreResult<()> {
    if keys.iter().any(|key| {
        key.is_empty()
            || key.len() > MAX_REPLAY_KEY_BYTES
            || key.bytes().any(|byte| byte == 0 || byte.is_ascii_control())
    }) {
        return Err(CoreError::UnbalancedTransaction);
    }
    Ok(())
}

fn canonicalize_balances(balances: &mut BTreeMap<AccountKey, u128>) {
    balances.retain(|_, amount| *amount > 0);
}

/// Rejects non-canonical snapshots and mutations. Asset and liability accounts
/// intentionally coexist for the same token, so their diagnostic aggregate
/// can exceed u128 even though every financial leg remains representable.
fn validate_balance_model(balances: &BTreeMap<AccountKey, u128>) -> CoreResult<()> {
    for (account, amount) in balances {
        validate_account_key(account)?;
        if *amount == 0 {
            return Err(CoreError::UnbalancedTransaction);
        }
    }
    Ok(())
}

fn validate_posting_shape(postings: &[LedgerPosting]) -> CoreResult<()> {
    for posting in postings {
        validate_account_key(&posting.account)?;
        if posting.amount == 0 {
            return Err(CoreError::ZeroAmount);
        }
    }
    Ok(())
}

fn validate_rounding_dust_transfer(account: &AccountKey, amount: u128) -> CoreResult<()> {
    if account.owner != "layrs" || account.market_id.is_some() || account.outcome.is_some() {
        return Err(CoreError::UnbalancedTransaction);
    }
    let limit = match account.asset.as_str() {
        // 0.001 of the settlement token. Larger residuals signal a broken
        // payout/precision invariant and must not be silently absorbed.
        "USDC" => 1_000,
        "ZEN" => 1_000_000_000_000_000,
        _ => return Err(CoreError::UnbalancedTransaction),
    };
    if amount > limit {
        return Err(CoreError::UnbalancedTransaction);
    }
    Ok(())
}
