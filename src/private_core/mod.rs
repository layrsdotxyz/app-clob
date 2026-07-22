//! Deterministic plaintext domain that is permitted to run only inside an attested enclave.
//!
//! Infrastructure adapters may transport ciphertext, persist encrypted journal records and
//! publish aggregate projections. They must never become the source of truth for these types.

pub mod engine;
pub mod journal;
pub mod ledger;
pub mod orderbook;
pub mod session;

pub use engine::{
    command_request_hash, resolution_signing_payload, BoundaryEvidence, CommandResult,
    CoreResponse, MarketConfig, MarketResolution, PrivateTradingCore, ResolutionOutcome,
    ResolutionStatement, SignedResolution, SystemResponse, UserCommand, UserCommandAction,
};
pub use journal::{
    EnclaveReceipt, EncryptedJournal, EncryptedJournalRecord, EncryptedSnapshot, JournalKey,
    ReceiptSigner,
};
pub use ledger::{
    AccountBucket, AccountKey, ClaimPayout, CompleteSetDirection, CompleteSetTransaction,
    ExternalFlowDirection, ExternalFlowTransaction, Ledger, LedgerTransaction, Transfer,
};
pub use orderbook::{
    BookOrder, Fill, MatchResult, OrderAction, OrderStatus, Outcome, PriceTimeBook, TimeInForce,
};
pub use session::{signing_payload, SessionGuard, SessionRequest, SignedSessionRequest};

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
    #[error("unknown or revoked private session")]
    UnknownSession,
    #[error("private session signature is invalid")]
    InvalidSessionSignature,
    #[error("request hash does not match the signed command")]
    RequestHashMismatch,
    #[error("oracle resolution signature is invalid")]
    InvalidOracleSignature,
    #[error("invalid resolution: {0}")]
    InvalidResolution(String),
    #[error("encrypted snapshot is older than the anchored checkpoint")]
    RollbackDetected,
    #[error("command was processed before the restored checkpoint; query its receipt archive")]
    PreviouslyProcessed,
}

pub type CoreResult<T> = Result<T, CoreError>;
