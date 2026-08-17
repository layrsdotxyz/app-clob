//! Deterministic plaintext domain that is permitted to run only inside an attested enclave.
//!
//! Infrastructure adapters may transport ciphertext, persist encrypted journal records and
//! publish aggregate projections. They must never become the source of truth for these types.

pub mod engine;
pub mod journal;
pub mod ledger;
pub mod orderbook;
mod rewards;
pub mod session;

pub mod decimal_u128 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &u128, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u128, D::Error> {
        let value = String::deserialize(deserializer)?;
        if value.is_empty()
            || (value.len() > 1 && value.starts_with('0'))
            || !value.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(serde::de::Error::custom(
                "expected canonical unsigned decimal string",
            ));
        }
        value.parse().map_err(serde::de::Error::custom)
    }
}

// `src/main.rs` still compiles this module tree directly for the retained migration server,
// while the release enclave imports these public types through the library crate. Keep the
// stable public facade without treating the migration binary's duplicate module instance as an
// unused-import error.
#[allow(unused_imports)]
pub use engine::{
    binance_resolution_signing_payload, command_request_hash, derive_resolution_outcome,
    exact_condition_resolution_signing_payload, polymarket_resolution_signing_payload,
    resolution_signing_payload, AuditFillStatement, BinanceBoundaryEvidence,
    BinanceResolutionStatement, BootstrapExecutionState, BootstrapExecutionView,
    BootstrapVenueIntent, BoundaryEvidence, CommandResult, CoreResponse,
    ExactConditionResolutionStatement, FeeProfileId, MarketConfig, MarketExecution,
    MarketResolution, MarketSettlementReadiness, PolymarketRedemptionIntent,
    PolymarketResolutionStatement, PortfolioSnapshot, PrivateActivityPage, PrivateActivitySnapshot,
    PrivateBalance, PrivateFillView, PrivateOrderHistoryState, PrivatePosition, PrivateTradingCore,
    ResolutionEvidence, ResolutionOutcome, ResolutionStatement, SignedAuditFillArtifact,
    SignedBinanceResolution, SignedExactConditionResolution, SignedPolymarketResolution,
    SignedResolution, SignedResolutionEvidence, SignedTaskQualificationArtifact, SystemResponse,
    TaskQualificationStatement, UserCommand, UserCommandAction, WithdrawalAuthorization,
    WithdrawalIntent,
};
pub use journal::{
    EnclaveReceipt, EncryptedJournal, EncryptedJournalRecord, EncryptedSnapshot, JournalKey,
    ReceiptSigner,
};
pub use ledger::{
    AccountBucket, AccountKey, ClaimPayout, CompleteSetDirection, CompleteSetTransaction,
    ExternalFlowDirection, ExternalFlowTransaction, Ledger, LedgerTransaction, Transfer,
};
#[allow(unused_imports)]
pub use orderbook::{
    BookOrder, Fill, MatchResult, MatchType, OrderAction, OrderStatus, Outcome, PriceTimeBook,
    TimeInForce,
};
#[allow(unused_imports)]
pub use rewards::{PrivateRewardEntitlement, RewardClaimAuthorization, RewardClaimIntent};
#[allow(unused_imports)]
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
    #[error("snapshot requires an explicit historical fill migration")]
    SnapshotMigrationRequired,
    #[error("unknown or revoked private session")]
    UnknownSession,
    #[error("private session signature is invalid")]
    InvalidSessionSignature,
    #[error("request hash does not match the signed command")]
    RequestHashMismatch,
    #[error("new trading risk is temporarily frozen")]
    TradingFrozen,
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
