use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Keccak};

use super::{CoreError, CoreResult};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AccountBucket {
    UserAvailable,
    UserOrderHold,
    UserWithdrawalHold,
    UserPosition,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub market_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppliedLedgerTransaction {
    pub sequence: u64,
    pub idempotency_key: String,
    pub business_reference: String,
    pub prior_state_root: [u8; 32],
    pub state_root: [u8; 32],
    pub transfers: Vec<Transfer>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Ledger {
    balances: BTreeMap<AccountKey, u128>,
    applied_idempotency_keys: BTreeSet<String>,
    sequence: u64,
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
        let state_root = self.state_root();

        Ok(AppliedLedgerTransaction {
            sequence: self.sequence,
            idempotency_key: transaction.idempotency_key,
            business_reference: transaction.business_reference,
            prior_state_root,
            state_root,
            transfers: transaction.transfers,
        })
    }

    pub fn total_for_asset(&self, asset: &str) -> u128 {
        self.balances
            .iter()
            .filter(|(key, _)| key.asset == asset)
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
