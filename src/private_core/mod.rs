//! Deterministic plaintext domain that is permitted to run only inside an attested enclave.
//!
//! Infrastructure adapters may transport ciphertext, persist encrypted journal records and
//! publish aggregate projections. They must never become the source of truth for these types.

pub mod journal;
pub mod ledger;
pub mod orderbook;
pub mod session;

pub use journal::{
    EnclaveReceipt, EncryptedJournal, EncryptedJournalRecord, JournalKey, ReceiptSigner,
};
pub use ledger::{AccountBucket, AccountKey, Ledger, LedgerTransaction, Transfer};
pub use orderbook::{
    BookOrder, Fill, OrderAction, OrderStatus, Outcome, PriceTimeBook, TimeInForce,
};
pub use session::{SessionGuard, SessionRequest};

use thiserror::Error;

pub const PRICE_SCALE: u128 = 1_000_000;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CoreError {
    #[error("amount must be greater than zero")]
    ZeroAmount,
    #[error("insufficient balance")]
    InsufficientBalance,
    #[error("transaction is not balanced")]
    UnbalancedTransaction,
    #[error("duplicate idempotency key")]
    DuplicateCommand,
    #[error("session sequence is stale or replayed")]
    ReplayedSequence,
    #[error("session request is expired")]
    ExpiredSession,
    #[error("invalid order: {0}")]
    InvalidOrder(String),
    #[error("journal cryptography failed")]
    JournalCrypto,
    #[error("journal chain mismatch")]
    JournalChainMismatch,
}

pub type CoreResult<T> = Result<T, CoreError>;
