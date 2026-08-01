use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tiny_keccak::{Hasher, Keccak};
use uuid::Uuid;

use super::orderbook::serialize_legacy_books;
use super::rewards::{
    PrivateRewardBook, PrivateRewardEntitlement, RewardClaimAuthorization, RewardClaimIntent,
};
use super::{
    AccountBucket, AccountKey, BookOrder, ClaimPayout, CompleteSetDirection,
    CompleteSetTransaction, CoreError, CoreResult, EnclaveReceipt, EncryptedJournal,
    EncryptedJournalRecord, EncryptedSnapshot, ExternalFlowDirection, ExternalFlowTransaction,
    Fill, JournalKey, Ledger, LedgerTransaction, MatchResult, MatchType, OrderAction, OrderStatus,
    Outcome, PriceTimeBook, ReceiptSigner, SessionGuard, SignedSessionRequest, Transfer,
    PRICE_SCALE,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarketConfig {
    pub market_id: String,
    pub settlement_asset: String,
    pub settlement_decimals: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_settlement_chain: Option<String>,
    pub opens_at_millis: i64,
    pub closes_at_millis: i64,
    #[serde(with = "super::decimal_u128")]
    pub minimum_quantity_micros: u128,
    #[serde(with = "super::decimal_u128")]
    pub maximum_quantity_micros: u128,
    /// Hard per-order quote-currency minimum. For ZEN this is expressed in six-decimal ZEN.
    #[serde(with = "super::decimal_u128")]
    pub minimum_order_notional_micros: u128,
    /// Hard per-order quote-currency notional cap, enforced inside the enclave.
    #[serde(with = "super::decimal_u128")]
    pub maximum_order_notional_micros: u128,
    /// Hard cap for one private user's position plus resting buy exposure per outcome.
    #[serde(with = "super::decimal_u128")]
    pub maximum_user_position_micros: u128,
    /// Aggregate notional that may be awaiting a Polymarket venue confirmation.
    #[serde(with = "super::decimal_u128")]
    pub maximum_pending_bootstrap_notional_micros: u128,
    pub tick_size_micros: u64,
    pub oracle_feed_id: u64,
    /// Determines where price discovery happens. The default preserves the native ZEN CLOB.
    #[serde(default)]
    pub execution: MarketExecution,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MarketExecution {
    #[default]
    NativeClob,
    PolymarketBootstrap {
        condition_id: String,
        up_token_id: String,
        down_token_id: String,
        up_outcome_index: u8,
        down_outcome_index: u8,
        #[serde(default)]
        neg_risk: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolymarketRedemptionIntent {
    pub market_id: String,
    pub condition_id: String,
    pub up_outcome_index: u8,
    pub down_outcome_index: u8,
    #[serde(with = "super::decimal_u128")]
    pub expected_redemption_amount_atomic: u128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BootstrapExecutionState {
    FundsReserved,
    VenueSubmitted,
    VenueConfirmed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapExecutionView {
    pub execution_id: Uuid,
    pub market_id: String,
    pub outcome: Outcome,
    pub action: OrderAction,
    pub limit_price_micros: u64,
    #[serde(with = "super::decimal_u128")]
    pub quantity_micros: u128,
    pub state: BootstrapExecutionState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirmed_price_micros: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct BootstrapExecution {
    view: BootstrapExecutionView,
    private_user_id: String,
    reserved_atomic: u128,
    venue_order_id: Option<String>,
    venue_evidence_hash: Option<[u8; 32]>,
    created_at_millis: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
struct PositionKey {
    owner: String,
    market_id: String,
    outcome: Outcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResolutionOutcome {
    Up,
    Down,
    Push,
}

pub fn derive_resolution_outcome(
    opening_median_e8: i64,
    closing_median_e8: i64,
) -> ResolutionOutcome {
    match layrs_settlement_proof_core::derive_resolution_outcome(
        opening_median_e8,
        closing_median_e8,
    ) {
        layrs_settlement_proof_core::ResolutionOutcome::Up => ResolutionOutcome::Up,
        layrs_settlement_proof_core::ResolutionOutcome::Down => ResolutionOutcome::Down,
        layrs_settlement_proof_core::ResolutionOutcome::Push => ResolutionOutcome::Push,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundaryEvidence {
    pub window_start_micros: i64,
    pub window_end_micros: i64,
    pub median_price_e8: i64,
    pub sample_count: u16,
    pub minimum_publisher_count: u16,
    pub signed_payload_commitment: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolutionStatement {
    pub market_id: String,
    pub oracle_feed_id: u64,
    pub opening: BoundaryEvidence,
    pub closing: BoundaryEvidence,
    pub issued_at_millis: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedResolution {
    pub statement: ResolutionStatement,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolymarketResolutionStatement {
    pub market_id: String,
    pub condition_id: String,
    pub outcome: ResolutionOutcome,
    #[serde(with = "super::decimal_u128")]
    pub redemption_amount_atomic: u128,
    pub redemption_transaction_hash: [u8; 32],
    pub redemption_block_number: u64,
    pub evidence_hash: [u8; 32],
    pub issued_at_millis: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedPolymarketResolution {
    pub statement: PolymarketResolutionStatement,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "signed", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SignedResolutionEvidence {
    Pyth(SignedResolution),
    Polymarket(SignedPolymarketResolution),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResolutionEvidence {
    PythHistoricalMedian {
        statement: ResolutionStatement,
    },
    PolymarketExactCondition {
        statement: PolymarketResolutionStatement,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarketResolution {
    pub outcome: ResolutionOutcome,
    pub evidence: ResolutionEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UserCommandAction {
    SubmitOrder {
        order: BookOrder,
    },
    CancelOrder {
        market_id: String,
        order_id: Uuid,
    },
    CompleteSet {
        market_id: String,
        #[serde(with = "super::decimal_u128")]
        quantity_micros: u128,
        direction: CompleteSetDirection,
    },
    Portfolio,
    Rewards,
    RequestRewardClaim {
        chain: String,
        account: String,
        recipient: String,
        reward_token: String,
        deadline_seconds: u64,
    },
    BootstrapStatus {
        execution_id: Uuid,
    },
    CancelBootstrap {
        execution_id: Uuid,
    },
    RequestWithdrawal {
        withdrawal_id: Uuid,
        chain: String,
        asset: String,
        #[serde(with = "super::decimal_u128")]
        amount_atomic: u128,
        destination: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateBalance {
    pub asset: String,
    pub bucket: AccountBucket,
    pub amount_atomic: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivatePosition {
    pub market_id: String,
    pub outcome: String,
    pub quantity_micros: String,
    pub cost_basis_micros: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortfolioSnapshot {
    pub balances: Vec<PrivateBalance>,
    pub positions: Vec<PrivatePosition>,
    pub orders: Vec<BookOrder>,
    pub as_of_millis: i64,
}

/// Privacy-safe aggregate preflight for a market settlement. It deliberately
/// excludes owners, orders, balances and position mappings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarketSettlementReadiness {
    pub market_id: String,
    #[serde(with = "super::decimal_u128")]
    pub collateral_atomic: u128,
    #[serde(with = "super::decimal_u128")]
    pub up_claim_quantity_micros: u128,
    #[serde(with = "super::decimal_u128")]
    pub down_claim_quantity_micros: u128,
    #[serde(with = "super::decimal_u128")]
    pub up_liability_atomic: u128,
    #[serde(with = "super::decimal_u128")]
    pub down_liability_atomic: u128,
    #[serde(with = "super::decimal_u128")]
    pub push_liability_atomic: u128,
    pub active_order_count: usize,
    pub cancellation_ready: bool,
    pub cancellation_error: Option<String>,
    pub up_solvent: bool,
    pub down_solvent: bool,
    pub push_solvent: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalIntent {
    pub protocol_version: String,
    pub withdrawal_id: Uuid,
    pub session_id: String,
    pub chain: String,
    pub asset: String,
    pub amount_atomic: String,
    pub destination: String,
    pub receipt_id: String,
    pub enclave_sequence: u64,
    pub state_root: [u8; 32],
    pub expires_at_millis: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalAuthorization {
    pub intent: WithdrawalIntent,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditFillStatement {
    pub protocol_version: String,
    pub chain: String,
    pub market_id: String,
    pub market_id_bytes32: String,
    pub buyer_one_time_pseudonym: String,
    pub seller_one_time_pseudonym: String,
    pub quantity_atomic: String,
    pub price_micros: u64,
    /// Privacy-safe public quote metadata. Optional so audit artifacts created
    /// before the quote-feed cutover remain verifiable byte-for-byte.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_type: Option<String>,
    pub fee_atomic: String,
    pub nonce: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedAuditFillArtifact {
    pub statement: AuditFillStatement,
    pub receipt_id: String,
    pub state_root: [u8; 32],
    pub receipt_public_key: [u8; 32],
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserCommand {
    pub command_id: String,
    pub idempotency_key: String,
    pub session: SignedSessionRequest,
    pub action: UserCommandAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CommandResult {
    Order {
        result: MatchResult,
    },
    Cancelled {
        order: BookOrder,
    },
    CompleteSet {
        market_id: String,
        #[serde(with = "super::decimal_u128")]
        quantity_micros: u128,
        direction: CompleteSetDirection,
    },
    Portfolio {
        snapshot: PortfolioSnapshot,
    },
    Rewards {
        entitlements: Vec<PrivateRewardEntitlement>,
    },
    RewardClaimAuthorized {
        intent: RewardClaimIntent,
    },
    BootstrapPending {
        execution: BootstrapExecutionView,
    },
    BootstrapStatus {
        execution: BootstrapExecutionView,
    },
    BootstrapCancelled {
        execution: BootstrapExecutionView,
    },
    WithdrawalReserved {
        withdrawal_id: Uuid,
        chain: String,
        asset: String,
        #[serde(with = "super::decimal_u128")]
        amount_atomic: u128,
        destination: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreResponse {
    pub result: CommandResult,
    pub receipt: EnclaveReceipt,
    pub encrypted_record: EncryptedJournalRecord,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withdrawal_authorization: Option<WithdrawalAuthorization>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reward_claim_authorization: Option<RewardClaimAuthorization>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audit_fills: Vec<SignedAuditFillArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemResponse {
    pub receipt: EnclaveReceipt,
    pub encrypted_record: EncryptedJournalRecord,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audit_fills: Vec<SignedAuditFillArtifact>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_commitment: Option<[u8; 32]>,
}

#[derive(Debug, Clone)]
struct AuditFillDraft {
    fill_id: Uuid,
    chain: String,
    market_id: String,
    buyer_private_user_id: String,
    seller_private_user_id: String,
    quantity_atomic: u128,
    price_micros: u64,
    outcome: String,
    match_type: String,
    fee_atomic: u128,
    nonce: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapVenueIntent {
    pub execution_id: Uuid,
    pub token_id: String,
    pub action: OrderAction,
    pub quantity_micros: u128,
    pub limit_price_micros: u64,
    pub negative_risk: bool,
    pub order_salt: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JournaledUserCommand {
    command: UserCommand,
    result: CommandResult,
}

#[derive(Debug, Clone)]
struct ProcessedCommand {
    request_hash: [u8; 32],
    response: Option<CoreResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
enum JournaledSystemCommand {
    SetTradingFreeze {
        idempotency_key: String,
        frozen: bool,
        reason_commitment: [u8; 32],
    },
    RegisterMarket {
        idempotency_key: String,
        market: MarketConfig,
    },
    RegisterSession {
        idempotency_key: String,
        session_id: String,
        identity_commitment: [u8; 32],
        public_key: [u8; 32],
        expires_at_millis: i64,
    },
    ExternalFlow {
        idempotency_key: String,
        flow: ExternalFlowTransaction,
    },
    AccrueReward {
        idempotency_key: String,
        identity_commitment: [u8; 32],
        chain: String,
        reward_token: String,
        #[serde(with = "super::decimal_u128")]
        amount_atomic: u128,
        evidence_hash: [u8; 32],
    },
    ReleaseWithdrawal {
        idempotency_key: String,
        identity_commitment: [u8; 32],
        asset: String,
        #[serde(with = "super::decimal_u128")]
        amount_atomic: u128,
        evidence_hash: [u8; 32],
    },
    PrepareWithdrawal {
        idempotency_key: String,
        withdrawal_id: Uuid,
        transaction_commitment: [u8; 32],
        raw_transaction_hex: String,
    },
    ResolveMarket {
        idempotency_key: String,
        resolution: MarketResolution,
    },
    MarkBootstrapSubmitted {
        idempotency_key: String,
        execution_id: Uuid,
        venue_order_commitment: [u8; 32],
    },
    ConfirmBootstrapFill {
        idempotency_key: String,
        execution_id: Uuid,
        fill_price_micros: u64,
        evidence_hash: [u8; 32],
    },
    FailBootstrapExecution {
        idempotency_key: String,
        execution_id: Uuid,
        failure_code: String,
        evidence_hash: [u8; 32],
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CoreStateSnapshot {
    ledger: Ledger,
    books: BTreeMap<String, PriceTimeBook>,
    markets: BTreeMap<String, MarketConfig>,
    sessions: SessionGuard,
    processed_hashes: BTreeMap<String, [u8; 32]>,
    system_keys: BTreeSet<String>,
    position_cost_basis: Vec<(PositionKey, u128)>,
    resolutions: BTreeMap<String, MarketResolution>,
    oracle_public_key: Option<[u8; 32]>,
    #[serde(default)]
    bootstrap_executions: BTreeMap<Uuid, BootstrapExecution>,
    #[serde(default)]
    private_rewards: PrivateRewardBook,
    #[serde(default)]
    trading_frozen: bool,
    sequence: u64,
}

pub struct PrivateTradingCore {
    ledger: Ledger,
    books: BTreeMap<String, PriceTimeBook>,
    markets: BTreeMap<String, MarketConfig>,
    sessions: SessionGuard,
    processed: BTreeMap<String, ProcessedCommand>,
    system_keys: BTreeSet<String>,
    journal: EncryptedJournal,
    receipt_signer: ReceiptSigner,
    position_cost_basis: BTreeMap<PositionKey, u128>,
    resolutions: BTreeMap<String, MarketResolution>,
    oracle_public_key: Option<[u8; 32]>,
    bootstrap_executions: BTreeMap<Uuid, BootstrapExecution>,
    private_rewards: PrivateRewardBook,
    trading_frozen: bool,
    sequence: u64,
    identity_key: [u8; 32],
}

impl PrivateTradingCore {
    pub fn new(journal_key: JournalKey, receipt_signer: ReceiptSigner) -> Self {
        let identity_key = journal_key.derive(b"private-user-id");
        Self {
            ledger: Ledger::default(),
            books: BTreeMap::new(),
            markets: BTreeMap::new(),
            sessions: SessionGuard::default(),
            processed: BTreeMap::new(),
            system_keys: BTreeSet::new(),
            journal: EncryptedJournal::new(journal_key),
            receipt_signer,
            position_cost_basis: BTreeMap::new(),
            resolutions: BTreeMap::new(),
            oracle_public_key: None,
            bootstrap_executions: BTreeMap::new(),
            private_rewards: PrivateRewardBook::default(),
            trading_frozen: false,
            sequence: 0,
            identity_key,
        }
    }

    pub fn new_with_oracle(
        journal_key: JournalKey,
        receipt_signer: ReceiptSigner,
        oracle_public_key: [u8; 32],
    ) -> CoreResult<Self> {
        VerifyingKey::from_bytes(&oracle_public_key)
            .map_err(|_| CoreError::InvalidOracleSignature)?;
        let mut core = Self::new(journal_key, receipt_signer);
        core.oracle_public_key = Some(oracle_public_key);
        Ok(core)
    }

    pub fn balance(&self, account: &AccountKey) -> u128 {
        self.ledger.balance(account)
    }

    /// Market specifications are public consensus inputs. This read is used by the
    /// idempotent signed-manifest importer to verify enclave registration after a retry.
    pub fn market_config(&self, market_id: &str) -> Option<MarketConfig> {
        self.markets.get(market_id).cloned()
    }

    /// Returns the immutable resolution already committed for a market.  This
    /// is deliberately read-only and lets the operator make a resolution
    /// command retry-safe after a network or process failure obscures the
    /// original response.
    pub fn market_resolution(&self, market_id: &str) -> Option<MarketResolution> {
        self.resolutions.get(market_id).cloned()
    }

    pub fn market_settlement_readiness(
        &self,
        market_id: &str,
        now_millis: i64,
    ) -> CoreResult<MarketSettlementReadiness> {
        let market = self
            .markets
            .get(market_id)
            .ok_or_else(|| CoreError::InvalidResolution("unknown market".into()))?;
        let mut ledger = self.ledger.clone();
        let mut books = self.books.clone();
        let mut active_order_count = 0usize;
        let mut cancellation_error = None;
        if let Some(book) = books.get_mut(market_id) {
            let cancelled = book.cancel_all(market_id, now_millis);
            active_order_count = cancelled.len();
            match cancellation_transfers(&ledger, book, market, &cancelled) {
                Ok(releases) if !releases.is_empty() => {
                    if let Err(error) = ledger.apply(LedgerTransaction {
                        idempotency_key: format!(
                            "diagnostic-resolution-cancel:{market_id}:{now_millis}"
                        ),
                        business_reference: market_id.into(),
                        transfers: releases,
                    }) {
                        cancellation_error = Some(error.to_string());
                    }
                }
                Ok(_) => {}
                Err(error) => cancellation_error = Some(error.to_string()),
            }
        }
        let mut claims = BTreeMap::<(String, Outcome), u128>::new();
        for (account, quantity) in ledger.claims_for_market(market_id) {
            let outcome = match account.outcome.as_deref() {
                Some("UP") => Outcome::Up,
                Some("DOWN") => Outcome::Down,
                _ => {
                    return Err(CoreError::InvalidResolution(
                        "invalid claim outcome in ledger".into(),
                    ));
                }
            };
            let entry = claims.entry((account.owner, outcome)).or_default();
            *entry = entry
                .checked_add(quantity)
                .ok_or(CoreError::UnbalancedTransaction)?;
        }
        let mut up_claim_quantity_micros = 0u128;
        let mut down_claim_quantity_micros = 0u128;
        let mut push_claim_quantity_micros = 0u128;
        for ((_, outcome), quantity) in claims {
            match outcome {
                Outcome::Up => {
                    up_claim_quantity_micros = up_claim_quantity_micros
                        .checked_add(quantity)
                        .ok_or(CoreError::UnbalancedTransaction)?;
                }
                Outcome::Down => {
                    down_claim_quantity_micros = down_claim_quantity_micros
                        .checked_add(quantity)
                        .ok_or(CoreError::UnbalancedTransaction)?;
                }
            }
            push_claim_quantity_micros = push_claim_quantity_micros
                .checked_add(quantity / 2)
                .ok_or(CoreError::UnbalancedTransaction)?;
        }
        let up_liability_atomic = settlement_atomic(market, up_claim_quantity_micros)?;
        let down_liability_atomic = settlement_atomic(market, down_claim_quantity_micros)?;
        let push_liability_atomic = settlement_atomic(market, push_claim_quantity_micros)?;
        let collateral_atomic =
            ledger.balance(&market_collateral(market_id, &market.settlement_asset));
        let cancellation_ready = cancellation_error.is_none();
        Ok(MarketSettlementReadiness {
            market_id: market_id.into(),
            collateral_atomic,
            up_claim_quantity_micros,
            down_claim_quantity_micros,
            up_liability_atomic,
            down_liability_atomic,
            push_liability_atomic,
            active_order_count,
            cancellation_ready,
            cancellation_error,
            up_solvent: cancellation_ready && collateral_atomic >= up_liability_atomic,
            down_solvent: cancellation_ready && collateral_atomic >= down_liability_atomic,
            push_solvent: cancellation_ready && collateral_atomic >= push_liability_atomic,
        })
    }

    pub fn export_encrypted_snapshot(&self) -> CoreResult<EncryptedSnapshot> {
        let (journal_sequence, _) = self.journal.chain_head();
        if journal_sequence != self.sequence {
            return Err(CoreError::JournalChainMismatch);
        }
        self.journal.seal_snapshot(
            self.state_root(),
            &CoreStateSnapshot {
                ledger: self.ledger.clone(),
                books: self.books.clone(),
                markets: self.markets.clone(),
                sessions: self.sessions.clone(),
                processed_hashes: processed_hashes(&self.processed),
                system_keys: self.system_keys.clone(),
                position_cost_basis: self
                    .position_cost_basis
                    .iter()
                    .map(|(key, value)| (key.clone(), *value))
                    .collect(),
                resolutions: self.resolutions.clone(),
                oracle_public_key: self.oracle_public_key,
                bootstrap_executions: self.bootstrap_executions.clone(),
                private_rewards: self.private_rewards.clone(),
                trading_frozen: self.trading_frozen,
                sequence: self.sequence,
            },
        )
    }

    #[cfg(test)]
    pub fn export_legacy_fill_history_snapshot_for_test(&self) -> CoreResult<EncryptedSnapshot> {
        let (journal_sequence, _) = self.journal.chain_head();
        if journal_sequence != self.sequence {
            return Err(CoreError::JournalChainMismatch);
        }
        let mut value = serde_json::to_value(CoreStateSnapshot {
            ledger: self.ledger.clone(),
            books: self.books.clone(),
            markets: self.markets.clone(),
            sessions: self.sessions.clone(),
            processed_hashes: processed_hashes(&self.processed),
            system_keys: self.system_keys.clone(),
            position_cost_basis: self
                .position_cost_basis
                .iter()
                .map(|(key, value)| (key.clone(), *value))
                .collect(),
            resolutions: self.resolutions.clone(),
            oracle_public_key: self.oracle_public_key,
            bootstrap_executions: self.bootstrap_executions.clone(),
            private_rewards: self.private_rewards.clone(),
            trading_frozen: self.trading_frozen,
            sequence: self.sequence,
        })
        .map_err(|_| CoreError::JournalCrypto)?;
        remove_json_field(&mut value, "filled_micros");
        self.journal.seal_snapshot(
            legacy_state_root(
                &self.ledger,
                &self.books,
                &self.markets,
                &self.sessions,
                &processed_hashes(&self.processed),
                &self.system_keys,
                &self.position_cost_basis,
                &self.resolutions,
                &self.oracle_public_key,
                &self.bootstrap_executions,
                &self.private_rewards,
                self.trading_frozen,
                self.sequence,
            ),
            &value,
        )
    }

    #[cfg(test)]
    pub fn export_production_legacy_snapshot_for_test(&self) -> CoreResult<EncryptedSnapshot> {
        let (journal_sequence, _) = self.journal.chain_head();
        if journal_sequence != self.sequence {
            return Err(CoreError::JournalChainMismatch);
        }
        let mut value = serde_json::to_value(CoreStateSnapshot {
            ledger: self.ledger.clone(),
            books: self.books.clone(),
            markets: self.markets.clone(),
            sessions: self.sessions.clone(),
            processed_hashes: processed_hashes(&self.processed),
            system_keys: self.system_keys.clone(),
            position_cost_basis: self
                .position_cost_basis
                .iter()
                .map(|(key, value)| (key.clone(), *value))
                .collect(),
            resolutions: self.resolutions.clone(),
            oracle_public_key: self.oracle_public_key,
            bootstrap_executions: self.bootstrap_executions.clone(),
            private_rewards: self.private_rewards.clone(),
            trading_frozen: self.trading_frozen,
            sequence: self.sequence,
        })
        .map_err(|_| CoreError::JournalCrypto)?;
        remove_json_field(&mut value, "filled_micros");
        remove_json_field(&mut value, "private_rewards");
        self.journal.seal_snapshot(
            production_legacy_state_root(
                &self.ledger,
                &self.books,
                &self.markets,
                &self.sessions,
                &processed_hashes(&self.processed),
                &self.system_keys,
                &self.position_cost_basis,
                &self.resolutions,
                &self.oracle_public_key,
                &self.bootstrap_executions,
                self.trading_frozen,
                self.sequence,
            ),
            &value,
        )
    }

    pub fn restore_encrypted_snapshot(
        journal_key: JournalKey,
        receipt_signer: ReceiptSigner,
        snapshot: &EncryptedSnapshot,
        minimum_anchored_sequence: u64,
    ) -> CoreResult<Self> {
        if snapshot.sequence < minimum_anchored_sequence {
            return Err(CoreError::RollbackDetected);
        }
        let identity_key = journal_key.derive(b"private-user-id");
        let mut journal = EncryptedJournal::new(journal_key);
        let mut state: CoreStateSnapshot = journal.open_snapshot(snapshot)?;
        if state.sequence != snapshot.sequence {
            return Err(CoreError::JournalChainMismatch);
        }
        let position_cost_basis: BTreeMap<PositionKey, u128> =
            state.position_cost_basis.into_iter().collect();
        let processed: BTreeMap<String, ProcessedCommand> = state
            .processed_hashes
            .into_iter()
            .map(|(key, request_hash)| {
                (
                    key,
                    ProcessedCommand {
                        request_hash,
                        response: None,
                    },
                )
            })
            .collect();
        let computed_root = state_root(
            &state.ledger,
            &state.books,
            &state.markets,
            &state.sessions,
            &processed_hashes(&processed),
            &state.system_keys,
            &position_cost_basis,
            &state.resolutions,
            &state.oracle_public_key,
            &state.bootstrap_executions,
            &state.private_rewards,
            state.trading_frozen,
            state.sequence,
        );
        if computed_root != snapshot.state_root {
            let legacy_root = legacy_state_root(
                &state.ledger,
                &state.books,
                &state.markets,
                &state.sessions,
                &processed_hashes(&processed),
                &state.system_keys,
                &position_cost_basis,
                &state.resolutions,
                &state.oracle_public_key,
                &state.bootstrap_executions,
                &state.private_rewards,
                state.trading_frozen,
                state.sequence,
            );
            let production_legacy_root = production_legacy_state_root(
                &state.ledger,
                &state.books,
                &state.markets,
                &state.sessions,
                &processed_hashes(&processed),
                &state.system_keys,
                &position_cost_basis,
                &state.resolutions,
                &state.oracle_public_key,
                &state.bootstrap_executions,
                state.trading_frozen,
                state.sequence,
            );
            if legacy_root != snapshot.state_root && production_legacy_root != snapshot.state_root {
                return Err(CoreError::JournalChainMismatch);
            }
            for book in state.books.values_mut() {
                book.migrate_legacy_fill_history()?;
            }
        }
        journal.restore_chain_head(snapshot.sequence, snapshot.journal_head)?;
        Ok(Self {
            ledger: state.ledger,
            books: state.books,
            markets: state.markets,
            sessions: state.sessions,
            processed,
            system_keys: state.system_keys,
            journal,
            receipt_signer,
            position_cost_basis,
            resolutions: state.resolutions,
            oracle_public_key: state.oracle_public_key,
            bootstrap_executions: state.bootstrap_executions,
            private_rewards: state.private_rewards,
            trading_frozen: state.trading_frozen,
            sequence: state.sequence,
            identity_key,
        })
    }

    pub fn state_root(&self) -> [u8; 32] {
        state_root(
            &self.ledger,
            &self.books,
            &self.markets,
            &self.sessions,
            &processed_hashes(&self.processed),
            &self.system_keys,
            &self.position_cost_basis,
            &self.resolutions,
            &self.oracle_public_key,
            &self.bootstrap_executions,
            &self.private_rewards,
            self.trading_frozen,
            self.sequence,
        )
    }

    pub fn trading_frozen(&self) -> bool {
        self.trading_frozen
    }

    pub fn set_trading_freeze(
        &mut self,
        idempotency_key: String,
        frozen: bool,
        reason_commitment: [u8; 32],
        now_millis: i64,
    ) -> CoreResult<SystemResponse> {
        self.validate_new_system_key(&idempotency_key)?;
        if reason_commitment == [0u8; 32] {
            return Err(CoreError::InvalidOrder(
                "trading freeze requires a non-zero reason commitment".into(),
            ));
        }
        let prior_root = self.state_root();
        let mut keys = self.system_keys.clone();
        keys.insert(idempotency_key.clone());
        let next_sequence = checked_sequence(self.sequence)?;
        let next_root = state_root(
            &self.ledger,
            &self.books,
            &self.markets,
            &self.sessions,
            &processed_hashes(&self.processed),
            &keys,
            &self.position_cost_basis,
            &self.resolutions,
            &self.oracle_public_key,
            &self.bootstrap_executions,
            &self.private_rewards,
            frozen,
            next_sequence,
        );
        let entry = JournaledSystemCommand::SetTradingFreeze {
            idempotency_key: idempotency_key.clone(),
            frozen,
            reason_commitment,
        };
        let record = self.journal.append(next_root, &entry)?;
        self.system_keys = keys;
        self.trading_frozen = frozen;
        self.sequence = next_sequence;
        Ok(self.system_response(
            if frozen {
                "trading-freeze"
            } else {
                "trading-unfreeze"
            },
            idempotency_key,
            prior_root,
            next_root,
            record,
            now_millis,
        ))
    }

    pub fn register_market(
        &mut self,
        idempotency_key: String,
        market: MarketConfig,
        now_millis: i64,
    ) -> CoreResult<SystemResponse> {
        self.validate_new_system_key(&idempotency_key)?;
        validate_market(&market, now_millis)?;
        if self.markets.contains_key(&market.market_id) {
            return Err(CoreError::InvalidOrder("market already exists".into()));
        }
        let prior_root = self.state_root();
        let mut markets = self.markets.clone();
        markets.insert(market.market_id.clone(), market.clone());
        let mut keys = self.system_keys.clone();
        keys.insert(idempotency_key.clone());
        let next_sequence = checked_sequence(self.sequence)?;
        let next_root = state_root(
            &self.ledger,
            &self.books,
            &markets,
            &self.sessions,
            &processed_hashes(&self.processed),
            &keys,
            &self.position_cost_basis,
            &self.resolutions,
            &self.oracle_public_key,
            &self.bootstrap_executions,
            &self.private_rewards,
            self.trading_frozen,
            next_sequence,
        );
        let entry = JournaledSystemCommand::RegisterMarket {
            idempotency_key: idempotency_key.clone(),
            market,
        };
        let record = self.journal.append(next_root, &entry)?;
        self.markets = markets;
        self.system_keys = keys;
        self.sequence = next_sequence;
        Ok(self.system_response(
            "register-market",
            idempotency_key,
            prior_root,
            next_root,
            record,
            now_millis,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn register_session(
        &mut self,
        idempotency_key: String,
        session_id: String,
        identity_commitment: [u8; 32],
        public_key: [u8; 32],
        expires_at_millis: i64,
        now_millis: i64,
    ) -> CoreResult<SystemResponse> {
        self.validate_new_system_key(&idempotency_key)?;
        let prior_root = self.state_root();
        let mut sessions = self.sessions.clone();
        let private_user_id = derive_private_user_id(&self.identity_key, &identity_commitment);
        sessions.register(
            session_id.clone(),
            private_user_id.clone(),
            public_key,
            expires_at_millis,
            now_millis,
        )?;
        let mut keys = self.system_keys.clone();
        keys.insert(idempotency_key.clone());
        let next_sequence = checked_sequence(self.sequence)?;
        let next_root = state_root(
            &self.ledger,
            &self.books,
            &self.markets,
            &sessions,
            &processed_hashes(&self.processed),
            &keys,
            &self.position_cost_basis,
            &self.resolutions,
            &self.oracle_public_key,
            &self.bootstrap_executions,
            &self.private_rewards,
            self.trading_frozen,
            next_sequence,
        );
        let entry = JournaledSystemCommand::RegisterSession {
            idempotency_key: idempotency_key.clone(),
            session_id,
            identity_commitment,
            public_key,
            expires_at_millis,
        };
        let record = self.journal.append(next_root, &entry)?;
        self.sessions = sessions;
        self.system_keys = keys;
        self.sequence = next_sequence;
        Ok(self.system_response(
            "register-session",
            idempotency_key,
            prior_root,
            next_root,
            record,
            now_millis,
        ))
    }

    pub fn apply_external_flow(
        &mut self,
        idempotency_key: String,
        account: AccountKey,
        amount: u128,
        direction: ExternalFlowDirection,
        evidence_hash: [u8; 32],
        now_millis: i64,
    ) -> CoreResult<SystemResponse> {
        self.validate_new_system_key(&idempotency_key)?;
        let prior_root = self.state_root();
        let flow = ExternalFlowTransaction {
            idempotency_key: format!("flow:{idempotency_key}"),
            evidence_hash,
            account,
            amount,
            direction,
        };
        let mut ledger = self.ledger.clone();
        ledger.apply_external_flow(flow.clone())?;
        let mut keys = self.system_keys.clone();
        keys.insert(idempotency_key.clone());
        let next_sequence = checked_sequence(self.sequence)?;
        let next_root = state_root(
            &ledger,
            &self.books,
            &self.markets,
            &self.sessions,
            &processed_hashes(&self.processed),
            &keys,
            &self.position_cost_basis,
            &self.resolutions,
            &self.oracle_public_key,
            &self.bootstrap_executions,
            &self.private_rewards,
            self.trading_frozen,
            next_sequence,
        );
        let entry = JournaledSystemCommand::ExternalFlow {
            idempotency_key: idempotency_key.clone(),
            flow,
        };
        let record = self.journal.append(next_root, &entry)?;
        self.ledger = ledger;
        self.system_keys = keys;
        self.sequence = next_sequence;
        Ok(self.system_response(
            "external-flow",
            idempotency_key,
            prior_root,
            next_root,
            record,
            now_millis,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn apply_user_external_flow(
        &mut self,
        idempotency_key: String,
        identity_commitment: [u8; 32],
        asset: String,
        bucket: AccountBucket,
        amount: u128,
        direction: ExternalFlowDirection,
        evidence_hash: [u8; 32],
        now_millis: i64,
    ) -> CoreResult<SystemResponse> {
        if !matches!(
            bucket,
            AccountBucket::UserAvailable | AccountBucket::UserWithdrawalHold
        ) {
            return Err(CoreError::InvalidOrder(
                "invalid external user-flow bucket".into(),
            ));
        }
        let owner = derive_private_user_id(&self.identity_key, &identity_commitment);
        self.apply_external_flow(
            idempotency_key,
            AccountKey::new(owner, bucket, asset),
            amount,
            direction,
            evidence_hash,
            now_millis,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn accrue_private_reward(
        &mut self,
        idempotency_key: String,
        identity_commitment: [u8; 32],
        chain: String,
        reward_token: String,
        amount_atomic: u128,
        evidence_hash: [u8; 32],
        now_millis: i64,
    ) -> CoreResult<SystemResponse> {
        self.validate_new_system_key(&idempotency_key)?;
        if evidence_hash == [0u8; 32] {
            return Err(CoreError::InvalidOrder(
                "reward accrual requires evidence".into(),
            ));
        }
        let owner = derive_private_user_id(&self.identity_key, &identity_commitment);
        let prior_root = self.state_root();
        let mut private_rewards = self.private_rewards.clone();
        private_rewards.accrue(&owner, &chain, &reward_token, amount_atomic)?;
        let mut keys = self.system_keys.clone();
        keys.insert(idempotency_key.clone());
        let next_sequence = checked_sequence(self.sequence)?;
        let next_root = state_root(
            &self.ledger,
            &self.books,
            &self.markets,
            &self.sessions,
            &processed_hashes(&self.processed),
            &keys,
            &self.position_cost_basis,
            &self.resolutions,
            &self.oracle_public_key,
            &self.bootstrap_executions,
            &private_rewards,
            self.trading_frozen,
            next_sequence,
        );
        let entry = JournaledSystemCommand::AccrueReward {
            idempotency_key: idempotency_key.clone(),
            identity_commitment,
            chain,
            reward_token,
            amount_atomic,
            evidence_hash,
        };
        let record = self.journal.append(next_root, &entry)?;
        self.private_rewards = private_rewards;
        self.system_keys = keys;
        self.sequence = next_sequence;
        Ok(self.system_response(
            "accrue-reward",
            idempotency_key,
            prior_root,
            next_root,
            record,
            now_millis,
        ))
    }

    pub fn release_user_withdrawal(
        &mut self,
        idempotency_key: String,
        identity_commitment: [u8; 32],
        asset: String,
        amount_atomic: u128,
        evidence_hash: [u8; 32],
        now_millis: i64,
    ) -> CoreResult<SystemResponse> {
        self.validate_new_system_key(&idempotency_key)?;
        if evidence_hash == [0u8; 32] {
            return Err(CoreError::InvalidOrder(
                "withdrawal release requires evidence".into(),
            ));
        }
        let owner = derive_private_user_id(&self.identity_key, &identity_commitment);
        let prior_root = self.state_root();
        let mut ledger = self.ledger.clone();
        ledger.apply(LedgerTransaction {
            idempotency_key: format!("withdrawal-release:{idempotency_key}"),
            business_reference: hex::encode(evidence_hash),
            transfers: vec![Transfer {
                from: AccountKey::new(&owner, AccountBucket::UserWithdrawalHold, &asset),
                to: AccountKey::new(owner, AccountBucket::UserAvailable, &asset),
                amount: amount_atomic,
            }],
        })?;
        let mut keys = self.system_keys.clone();
        keys.insert(idempotency_key.clone());
        let next_sequence = checked_sequence(self.sequence)?;
        let next_root = state_root(
            &ledger,
            &self.books,
            &self.markets,
            &self.sessions,
            &processed_hashes(&self.processed),
            &keys,
            &self.position_cost_basis,
            &self.resolutions,
            &self.oracle_public_key,
            &self.bootstrap_executions,
            &self.private_rewards,
            self.trading_frozen,
            next_sequence,
        );
        let entry = JournaledSystemCommand::ReleaseWithdrawal {
            idempotency_key: idempotency_key.clone(),
            identity_commitment,
            asset,
            amount_atomic,
            evidence_hash,
        };
        let record = self.journal.append(next_root, &entry)?;
        self.ledger = ledger;
        self.system_keys = keys;
        self.sequence = next_sequence;
        Ok(self.system_response(
            "release-withdrawal",
            idempotency_key,
            prior_root,
            next_root,
            record,
            now_millis,
        ))
    }

    pub fn validate_withdrawal_intent(&self, intent: &WithdrawalIntent) -> CoreResult<()> {
        if intent.protocol_version != "layrs.withdrawal.v1" {
            return Err(CoreError::InvalidOrder(
                "invalid withdrawal protocol".into(),
            ));
        }
        let marker = withdrawal_reservation_marker(
            &intent.session_id,
            intent.withdrawal_id,
            &intent.chain,
            &intent.asset,
            &intent.amount_atomic,
            &intent.destination,
        )?;
        if !self.system_keys.contains(&marker) {
            return Err(CoreError::InvalidOrder(
                "unknown withdrawal reservation".into(),
            ));
        }
        Ok(())
    }

    pub fn prepared_withdrawal(&self, withdrawal_id: Uuid) -> Option<([u8; 32], String)> {
        let prefix = format!("prepared-withdrawal:{withdrawal_id}:");
        self.system_keys.iter().find_map(|key| {
            let value = key.strip_prefix(&prefix)?;
            let (commitment, raw) = value.split_once(':')?;
            let commitment: [u8; 32] = hex::decode(commitment).ok()?.try_into().ok()?;
            Some((commitment, raw.to_owned()))
        })
    }

    pub fn record_prepared_withdrawal(
        &mut self,
        idempotency_key: String,
        withdrawal_id: Uuid,
        transaction_commitment: [u8; 32],
        raw_transaction_hex: String,
        now_millis: i64,
    ) -> CoreResult<SystemResponse> {
        self.validate_new_system_key(&idempotency_key)?;
        if !raw_transaction_hex.starts_with("0x02")
            || raw_transaction_hex.len() < 100
            || raw_transaction_hex.len() > 2_048
            || !raw_transaction_hex[2..]
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(CoreError::InvalidOrder(
                "invalid signed withdrawal transaction".into(),
            ));
        }
        if self.prepared_withdrawal(withdrawal_id).is_some() {
            return Err(CoreError::InvalidOrder(
                "withdrawal transaction already prepared".into(),
            ));
        }
        let prior_root = self.state_root();
        let mut keys = self.system_keys.clone();
        keys.insert(idempotency_key.clone());
        keys.insert(format!(
            "prepared-withdrawal:{withdrawal_id}:{}:{raw_transaction_hex}",
            hex::encode(transaction_commitment),
        ));
        let next_sequence = checked_sequence(self.sequence)?;
        let next_root = state_root(
            &self.ledger,
            &self.books,
            &self.markets,
            &self.sessions,
            &processed_hashes(&self.processed),
            &keys,
            &self.position_cost_basis,
            &self.resolutions,
            &self.oracle_public_key,
            &self.bootstrap_executions,
            &self.private_rewards,
            self.trading_frozen,
            next_sequence,
        );
        let entry = JournaledSystemCommand::PrepareWithdrawal {
            idempotency_key: idempotency_key.clone(),
            withdrawal_id,
            transaction_commitment,
            raw_transaction_hex,
        };
        let record = self.journal.append(next_root, &entry)?;
        self.system_keys = keys;
        self.sequence = next_sequence;
        Ok(self.system_response(
            "prepare-withdrawal",
            idempotency_key,
            prior_root,
            next_root,
            record,
            now_millis,
        ))
    }

    pub fn resolve_market(
        &mut self,
        idempotency_key: String,
        signed: SignedResolution,
        now_millis: i64,
    ) -> CoreResult<SystemResponse> {
        self.validate_new_system_key(&idempotency_key)?;
        let market = self
            .markets
            .get(&signed.statement.market_id)
            .ok_or_else(|| CoreError::InvalidResolution("unknown market".into()))?;
        validate_resolution(market, &signed, self.oracle_public_key, now_millis)?;
        let outcome = derive_resolution_outcome(
            signed.statement.opening.median_price_e8,
            signed.statement.closing.median_price_e8,
        );
        let resolution = MarketResolution {
            outcome,
            evidence: ResolutionEvidence::PythHistoricalMedian {
                statement: signed.statement,
            },
        };
        self.commit_market_resolution(idempotency_key, resolution, now_millis)
    }

    pub fn resolve_polymarket_market(
        &mut self,
        idempotency_key: String,
        signed: SignedPolymarketResolution,
        now_millis: i64,
    ) -> CoreResult<SystemResponse> {
        self.validate_new_system_key(&idempotency_key)?;
        let market = self
            .markets
            .get(&signed.statement.market_id)
            .ok_or_else(|| CoreError::InvalidResolution("unknown market".into()))?;
        validate_polymarket_resolution(market, &signed, self.oracle_public_key, now_millis)?;
        let resolution = MarketResolution {
            outcome: signed.statement.outcome,
            evidence: ResolutionEvidence::PolymarketExactCondition {
                statement: signed.statement,
            },
        };
        self.commit_market_resolution(idempotency_key, resolution, now_millis)
    }

    fn commit_market_resolution(
        &mut self,
        idempotency_key: String,
        resolution: MarketResolution,
        now_millis: i64,
    ) -> CoreResult<SystemResponse> {
        let market_id = match &resolution.evidence {
            ResolutionEvidence::PythHistoricalMedian { statement } => &statement.market_id,
            ResolutionEvidence::PolymarketExactCondition { statement } => &statement.market_id,
        };
        let market = self
            .markets
            .get(market_id)
            .ok_or_else(|| CoreError::InvalidResolution("unknown market".into()))?;
        if self.resolutions.contains_key(&market.market_id) {
            return Err(CoreError::InvalidResolution(
                "market is already resolved".into(),
            ));
        }
        let outcome = resolution.outcome;

        let prior_root = self.state_root();
        let mut ledger = self.ledger.clone();
        let mut books = self.books.clone();
        let mut position_cost_basis = self.position_cost_basis.clone();
        if let Some(book) = books.get_mut(&market.market_id) {
            let cancelled = book.cancel_all(&market.market_id, now_millis);
            let releases = cancellation_transfers(&ledger, book, market, &cancelled)?;
            if !releases.is_empty() {
                ledger.apply(LedgerTransaction {
                    idempotency_key: format!("resolution-cancel:{idempotency_key}"),
                    business_reference: market.market_id.clone(),
                    transfers: releases,
                })?;
            }
        }

        let positions = ledger.positions_for_market(&market.market_id);
        let mut payouts = Vec::with_capacity(positions.len());
        let mut total_gross_payout = 0u128;
        for (claim_account, quantity) in positions {
            let claim_outcome = match claim_account.outcome.as_deref() {
                Some("UP") => Outcome::Up,
                Some("DOWN") => Outcome::Down,
                _ => {
                    return Err(CoreError::InvalidResolution(
                        "invalid claim outcome in ledger".into(),
                    ));
                }
            };
            let key = position_key(&claim_account.owner, &market.market_id, claim_outcome);
            let basis = position_cost_basis.remove(&key).unwrap_or_default();
            let gross_micros = match outcome {
                ResolutionOutcome::Up if claim_outcome == Outcome::Up => quantity,
                ResolutionOutcome::Down if claim_outcome == Outcome::Down => quantity,
                ResolutionOutcome::Push => quantity / 2,
                _ => 0,
            };
            let gross = settlement_atomic(market, gross_micros)?;
            let winning_fee = if matches!(outcome, ResolutionOutcome::Push) {
                0
            } else {
                ceil_bps(gross.saturating_sub(basis), 500)?
            };
            total_gross_payout = total_gross_payout
                .checked_add(gross)
                .ok_or(CoreError::UnbalancedTransaction)?;
            payouts.push(ClaimPayout {
                claim_account,
                destination: available(&key.owner, &market.settlement_asset),
                claim_quantity_micros: quantity,
                gross_payout_atomic: gross,
                winning_fee_atomic: winning_fee,
            });
        }
        let collateral = market_collateral(&market.market_id, &market.settlement_asset);
        if let ResolutionEvidence::PolymarketExactCondition { statement } = &resolution.evidence {
            if statement.redemption_amount_atomic != total_gross_payout {
                return Err(CoreError::InvalidResolution(
                    "venue redemption does not equal the winning claim liability".into(),
                ));
            }
            if total_gross_payout > 0 {
                let pool =
                    AccountKey::new("layrs", AccountBucket::PoolCash, &market.settlement_asset);
                ledger.apply_external_flow(ExternalFlowTransaction {
                    idempotency_key: format!("resolution-redemption:{idempotency_key}"),
                    evidence_hash: statement.evidence_hash,
                    account: pool.clone(),
                    amount: total_gross_payout,
                    direction: ExternalFlowDirection::Inflow,
                })?;
                ledger.apply(LedgerTransaction {
                    idempotency_key: format!("resolution-collateralize:{idempotency_key}"),
                    business_reference: market.market_id.clone(),
                    transfers: vec![Transfer {
                        from: pool,
                        to: collateral.clone(),
                        amount: total_gross_payout,
                    }],
                })?;
            }
        }
        if !payouts.is_empty() {
            ledger.apply_claim_payouts(
                format!("resolution-payout:{idempotency_key}"),
                market.market_id.clone(),
                collateral.clone(),
                AccountKey::new("layrs", AccountBucket::FeeRevenue, &market.settlement_asset),
                payouts,
            )?;
        }
        let rounding = ledger.balance(&collateral);
        if rounding > 0 {
            ledger.apply(LedgerTransaction {
                idempotency_key: format!("resolution-rounding:{idempotency_key}"),
                business_reference: market.market_id.clone(),
                transfers: vec![Transfer {
                    from: collateral,
                    to: AccountKey::new(
                        "layrs",
                        AccountBucket::RoundingReserve,
                        &market.settlement_asset,
                    ),
                    amount: rounding,
                }],
            })?;
        }

        let mut resolutions = self.resolutions.clone();
        resolutions.insert(market.market_id.clone(), resolution.clone());
        let mut keys = self.system_keys.clone();
        keys.insert(idempotency_key.clone());
        let next_sequence = checked_sequence(self.sequence)?;
        let next_root = state_root(
            &ledger,
            &books,
            &self.markets,
            &self.sessions,
            &processed_hashes(&self.processed),
            &keys,
            &position_cost_basis,
            &resolutions,
            &self.oracle_public_key,
            &self.bootstrap_executions,
            &self.private_rewards,
            self.trading_frozen,
            next_sequence,
        );
        let entry = JournaledSystemCommand::ResolveMarket {
            idempotency_key: idempotency_key.clone(),
            resolution,
        };
        let record = self.journal.append(next_root, &entry)?;
        self.ledger = ledger;
        self.books = books;
        self.position_cost_basis = position_cost_basis;
        self.resolutions = resolutions;
        self.system_keys = keys;
        self.sequence = next_sequence;
        Ok(self.system_response(
            "resolve-market",
            idempotency_key,
            prior_root,
            next_root,
            record,
            now_millis,
        ))
    }

    pub fn bootstrap_venue_intent(&self, execution_id: Uuid) -> CoreResult<BootstrapVenueIntent> {
        let execution = self
            .bootstrap_executions
            .get(&execution_id)
            .ok_or_else(|| CoreError::InvalidOrder("unknown bootstrap execution".into()))?;
        if execution.view.state != BootstrapExecutionState::FundsReserved {
            return Err(CoreError::InvalidOrder(
                "bootstrap execution is not ready for venue submission".into(),
            ));
        }
        let market = self
            .markets
            .get(&execution.view.market_id)
            .ok_or_else(|| CoreError::InvalidOrder("unknown market".into()))?;
        let MarketExecution::PolymarketBootstrap {
            up_token_id,
            down_token_id,
            neg_risk,
            ..
        } = &market.execution
        else {
            return Err(CoreError::InvalidOrder(
                "market is not a bootstrap venue market".into(),
            ));
        };
        Ok(BootstrapVenueIntent {
            execution_id,
            token_id: match execution.view.outcome {
                Outcome::Up => up_token_id.clone(),
                Outcome::Down => down_token_id.clone(),
            },
            action: execution.view.action,
            quantity_micros: execution.view.quantity_micros,
            limit_price_micros: execution.view.limit_price_micros,
            negative_risk: *neg_risk,
            order_salt: bootstrap_order_salt(execution_id),
        })
    }

    /// Produces the exact public venue-redemption intent that backs the outstanding private
    /// claims. Signing and broadcasting are separate so the prepared raw transaction can be
    /// durably recorded before it is sent to Polygon.
    pub fn polymarket_redemption_intent(
        &self,
        market_id: &str,
        outcome: ResolutionOutcome,
        now_millis: i64,
    ) -> CoreResult<PolymarketRedemptionIntent> {
        let market = self
            .markets
            .get(market_id)
            .ok_or_else(|| CoreError::InvalidResolution("unknown market".into()))?;
        let MarketExecution::PolymarketBootstrap {
            condition_id,
            up_outcome_index,
            down_outcome_index,
            ..
        } = &market.execution
        else {
            return Err(CoreError::InvalidResolution(
                "market is not a Polymarket bootstrap market".into(),
            ));
        };
        if now_millis < market.closes_at_millis || self.resolutions.contains_key(market_id) {
            return Err(CoreError::InvalidResolution(
                "market is not ready for venue redemption".into(),
            ));
        }
        let total_micros = self
            .ledger
            .positions_for_market(market_id)
            .into_iter()
            .try_fold(0u128, |total, (claim, quantity)| {
                let claim_outcome = match claim.outcome.as_deref() {
                    Some("UP") => Outcome::Up,
                    Some("DOWN") => Outcome::Down,
                    _ => {
                        return Err(CoreError::InvalidResolution(
                            "invalid claim outcome in ledger".into(),
                        ));
                    }
                };
                let payout = match outcome {
                    ResolutionOutcome::Up if claim_outcome == Outcome::Up => quantity,
                    ResolutionOutcome::Down if claim_outcome == Outcome::Down => quantity,
                    ResolutionOutcome::Push => quantity / 2,
                    _ => 0,
                };
                total
                    .checked_add(payout)
                    .ok_or(CoreError::UnbalancedTransaction)
            })?;
        Ok(PolymarketRedemptionIntent {
            market_id: market_id.into(),
            condition_id: condition_id.clone(),
            up_outcome_index: *up_outcome_index,
            down_outcome_index: *down_outcome_index,
            expected_redemption_amount_atomic: settlement_atomic(market, total_micros)?,
        })
    }

    pub fn validate_onchain_resolution_authorization(
        &self,
        market_id: &str,
        outcome: ResolutionOutcome,
        evidence: &SignedResolutionEvidence,
        now_millis: i64,
    ) -> CoreResult<()> {
        let market = self
            .markets
            .get(market_id)
            .ok_or_else(|| CoreError::InvalidResolution("unknown market".into()))?;
        if self.resolutions.contains_key(market_id) {
            return Err(CoreError::InvalidResolution(
                "market is already resolved".into(),
            ));
        }
        match evidence {
            SignedResolutionEvidence::Pyth(signed) => {
                validate_resolution(market, signed, self.oracle_public_key, now_millis)?;
                let derived = derive_resolution_outcome(
                    signed.statement.opening.median_price_e8,
                    signed.statement.closing.median_price_e8,
                );
                if signed.statement.market_id != market_id || derived != outcome {
                    return Err(CoreError::InvalidResolution(
                        "on-chain outcome does not match Pyth evidence".into(),
                    ));
                }
            }
            SignedResolutionEvidence::Polymarket(signed) => {
                validate_polymarket_resolution(market, signed, self.oracle_public_key, now_millis)?;
                if signed.statement.market_id != market_id || signed.statement.outcome != outcome {
                    return Err(CoreError::InvalidResolution(
                        "on-chain outcome does not match Polymarket evidence".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn bootstrap_venue_order_id(&self, execution_id: Uuid) -> CoreResult<String> {
        let execution = self
            .bootstrap_executions
            .get(&execution_id)
            .ok_or_else(|| CoreError::InvalidOrder("unknown bootstrap execution".into()))?;
        if execution.view.state != BootstrapExecutionState::VenueSubmitted {
            return Err(CoreError::InvalidOrder(
                "bootstrap execution is not awaiting venue confirmation".into(),
            ));
        }
        execution
            .venue_order_id
            .clone()
            .ok_or_else(|| CoreError::InvalidOrder("venue order id is unavailable".into()))
    }

    pub fn bootstrap_execution_view(
        &self,
        execution_id: Uuid,
    ) -> CoreResult<BootstrapExecutionView> {
        self.bootstrap_executions
            .get(&execution_id)
            .map(|execution| execution.view.clone())
            .ok_or_else(|| CoreError::InvalidOrder("unknown bootstrap execution".into()))
    }

    pub fn bootstrap_execution_state_for_identity(
        &self,
        execution_id: Uuid,
        identity_commitment: [u8; 32],
    ) -> CoreResult<BootstrapExecutionState> {
        let expected = derive_private_user_id(&self.identity_key, &identity_commitment);
        self.bootstrap_executions
            .get(&execution_id)
            .filter(|execution| execution.private_user_id == expected)
            .map(|execution| execution.view.state)
            .ok_or_else(|| CoreError::InvalidOrder("unknown bootstrap execution".into()))
    }

    /// Records the venue's accepted order identifier as a one-way commitment. The plaintext
    /// identifier remains inside the enclave-owned executor and is never part of a public event.
    pub fn mark_bootstrap_submitted(
        &mut self,
        idempotency_key: String,
        execution_id: Uuid,
        venue_order_id: String,
        now_millis: i64,
    ) -> CoreResult<SystemResponse> {
        self.validate_new_system_key(&idempotency_key)?;
        if venue_order_id.is_empty()
            || venue_order_id.len() > 256
            || !venue_order_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
        {
            return Err(CoreError::InvalidOrder(
                "valid venue order id is required".into(),
            ));
        }
        let venue_order_commitment = Sha256::digest(venue_order_id.as_bytes()).into();
        let prior_root = self.state_root();
        let mut executions = self.bootstrap_executions.clone();
        let execution = executions
            .get_mut(&execution_id)
            .ok_or_else(|| CoreError::InvalidOrder("unknown bootstrap execution".into()))?;
        if execution.view.state != BootstrapExecutionState::FundsReserved {
            return Err(CoreError::InvalidOrder(
                "bootstrap execution is not awaiting venue submission".into(),
            ));
        }
        execution.view.state = BootstrapExecutionState::VenueSubmitted;
        execution.venue_order_id = Some(venue_order_id);

        let mut keys = self.system_keys.clone();
        keys.insert(idempotency_key.clone());
        let next_sequence = checked_sequence(self.sequence)?;
        let next_root = state_root(
            &self.ledger,
            &self.books,
            &self.markets,
            &self.sessions,
            &processed_hashes(&self.processed),
            &keys,
            &self.position_cost_basis,
            &self.resolutions,
            &self.oracle_public_key,
            &executions,
            &self.private_rewards,
            self.trading_frozen,
            next_sequence,
        );
        let entry = JournaledSystemCommand::MarkBootstrapSubmitted {
            idempotency_key: idempotency_key.clone(),
            execution_id,
            venue_order_commitment,
        };
        let record = self.journal.append(next_root, &entry)?;
        self.bootstrap_executions = executions;
        self.system_keys = keys;
        self.sequence = next_sequence;
        Ok(self.system_response(
            "bootstrap-submitted",
            idempotency_key,
            prior_root,
            next_root,
            record,
            now_millis,
        ))
    }

    /// Atomically recognizes a FOK venue fill and the matching user fill. No user claim or cash
    /// movement occurs before this transition, and the committed venue evidence is single-use.
    pub fn confirm_bootstrap_fill(
        &mut self,
        idempotency_key: String,
        execution_id: Uuid,
        fill_price_micros: u64,
        evidence_hash: [u8; 32],
        now_millis: i64,
    ) -> CoreResult<SystemResponse> {
        self.validate_new_system_key(&idempotency_key)?;
        if evidence_hash == [0u8; 32]
            || fill_price_micros == 0
            || fill_price_micros >= PRICE_SCALE as u64
        {
            return Err(CoreError::InvalidOrder(
                "valid venue fill evidence is required".into(),
            ));
        }
        let prior_root = self.state_root();
        let mut executions = self.bootstrap_executions.clone();
        let execution = executions
            .get_mut(&execution_id)
            .ok_or_else(|| CoreError::InvalidOrder("unknown bootstrap execution".into()))?;
        if execution.view.state != BootstrapExecutionState::VenueSubmitted
            || execution.venue_order_id.is_none()
        {
            return Err(CoreError::InvalidOrder(
                "bootstrap execution has no pending venue order".into(),
            ));
        }
        match execution.view.action {
            OrderAction::Buy if fill_price_micros > execution.view.limit_price_micros => {
                return Err(CoreError::InvalidOrder(
                    "venue buy fill exceeded the user's limit".into(),
                ));
            }
            OrderAction::Sell if fill_price_micros < execution.view.limit_price_micros => {
                return Err(CoreError::InvalidOrder(
                    "venue sell fill was below the user's limit".into(),
                ));
            }
            _ => {}
        }
        let market = self
            .markets
            .get(&execution.view.market_id)
            .ok_or_else(|| CoreError::InvalidOrder("unknown market".into()))?;
        if !matches!(
            market.execution,
            MarketExecution::PolymarketBootstrap { .. }
        ) {
            return Err(CoreError::InvalidOrder(
                "market is not a bootstrap venue market".into(),
            ));
        }

        let mut ledger = self.ledger.clone();
        let mut position_cost_basis = self.position_cost_basis.clone();
        let quantity = execution.view.quantity_micros;
        let fill_notional = notional(fill_price_micros, quantity)?;
        let taker_fee = ceil_bps(fill_notional, 20)?;
        let claim = claim_asset(&execution.view.market_id, execution.view.outcome);
        let inventory = venue_inventory(&execution.view.market_id, execution.view.outcome, &claim);
        let pool = AccountKey::new("layrs", AccountBucket::PoolCash, &market.settlement_asset);

        match execution.view.action {
            OrderAction::Buy => {
                let user_total = fill_notional
                    .checked_add(taker_fee)
                    .ok_or(CoreError::UnbalancedTransaction)?;
                let refund = execution
                    .reserved_atomic
                    .checked_sub(user_total)
                    .ok_or(CoreError::UnbalancedTransaction)?;
                ledger.apply_external_flow(ExternalFlowTransaction {
                    idempotency_key: format!("bootstrap-venue-cash:{idempotency_key}"),
                    evidence_hash,
                    account: pool.clone(),
                    amount: fill_notional,
                    direction: ExternalFlowDirection::Outflow,
                })?;
                ledger.apply_external_flow(ExternalFlowTransaction {
                    idempotency_key: format!("bootstrap-venue-claim:{idempotency_key}"),
                    evidence_hash,
                    account: inventory.clone(),
                    amount: quantity,
                    direction: ExternalFlowDirection::Inflow,
                })?;
                let hold = bootstrap_hold(execution, market);
                let mut transfers = vec![
                    Transfer {
                        from: hold.clone(),
                        to: pool,
                        amount: fill_notional,
                    },
                    Transfer {
                        from: inventory,
                        to: claim_position_for(
                            &execution.private_user_id,
                            &execution.view.market_id,
                            execution.view.outcome,
                        ),
                        amount: quantity,
                    },
                ];
                if taker_fee > 0 {
                    transfers.push(Transfer {
                        from: hold.clone(),
                        to: AccountKey::new(
                            "layrs",
                            AccountBucket::FeeRevenue,
                            &market.settlement_asset,
                        ),
                        amount: taker_fee,
                    });
                }
                if refund > 0 {
                    transfers.push(Transfer {
                        from: hold,
                        to: available(&execution.private_user_id, &market.settlement_asset),
                        amount: refund,
                    });
                }
                ledger.apply(LedgerTransaction {
                    idempotency_key: format!("bootstrap-user-fill:{idempotency_key}"),
                    business_reference: hex::encode(evidence_hash),
                    transfers,
                })?;
                add_basis(
                    &mut position_cost_basis,
                    position_key(
                        &execution.private_user_id,
                        &execution.view.market_id,
                        execution.view.outcome,
                    ),
                    fill_notional,
                )?;
            }
            OrderAction::Sell => {
                let key = position_key(
                    &execution.private_user_id,
                    &execution.view.market_id,
                    execution.view.outcome,
                );
                reduce_basis_for_held_quantity(
                    &ledger,
                    &mut position_cost_basis,
                    key,
                    &execution.private_user_id,
                    &execution.view.market_id,
                    execution.view.outcome,
                    quantity,
                )?;
                ledger.apply_external_flow(ExternalFlowTransaction {
                    idempotency_key: format!("bootstrap-venue-claim:{idempotency_key}"),
                    evidence_hash,
                    account: inventory.clone(),
                    amount: quantity,
                    direction: ExternalFlowDirection::Outflow,
                })?;
                ledger.apply_external_flow(ExternalFlowTransaction {
                    idempotency_key: format!("bootstrap-venue-cash:{idempotency_key}"),
                    evidence_hash,
                    account: pool.clone(),
                    amount: fill_notional,
                    direction: ExternalFlowDirection::Inflow,
                })?;
                let user_proceeds = fill_notional
                    .checked_sub(taker_fee)
                    .ok_or(CoreError::UnbalancedTransaction)?;
                let mut transfers = vec![
                    Transfer {
                        from: bootstrap_hold(execution, market),
                        to: inventory,
                        amount: quantity,
                    },
                    Transfer {
                        from: pool.clone(),
                        to: available(&execution.private_user_id, &market.settlement_asset),
                        amount: user_proceeds,
                    },
                ];
                if taker_fee > 0 {
                    transfers.push(Transfer {
                        from: pool,
                        to: AccountKey::new(
                            "layrs",
                            AccountBucket::FeeRevenue,
                            &market.settlement_asset,
                        ),
                        amount: taker_fee,
                    });
                }
                ledger.apply(LedgerTransaction {
                    idempotency_key: format!("bootstrap-user-fill:{idempotency_key}"),
                    business_reference: hex::encode(evidence_hash),
                    transfers,
                })?;
            }
        }
        execution.view.state = BootstrapExecutionState::VenueConfirmed;
        execution.view.confirmed_price_micros = Some(fill_price_micros);
        execution.venue_evidence_hash = Some(evidence_hash);
        let next_sequence = checked_sequence(self.sequence)?;
        let (buyer_private_user_id, seller_private_user_id) = match execution.view.action {
            OrderAction::Buy => (execution.private_user_id.clone(), "layrs".to_string()),
            OrderAction::Sell => ("layrs".to_string(), execution.private_user_id.clone()),
        };
        let audit_draft = AuditFillDraft {
            fill_id: execution_id,
            chain: effective_public_settlement_chain(market)?.into(),
            market_id: execution.view.market_id.clone(),
            buyer_private_user_id,
            seller_private_user_id,
            quantity_atomic: quantity,
            price_micros: fill_price_micros,
            outcome: outcome_name(execution.view.outcome).into(),
            match_type: "NORMAL".into(),
            fee_atomic: taker_fee,
            nonce: next_sequence,
        };

        let mut keys = self.system_keys.clone();
        keys.insert(idempotency_key.clone());
        let next_root = state_root(
            &ledger,
            &self.books,
            &self.markets,
            &self.sessions,
            &processed_hashes(&self.processed),
            &keys,
            &position_cost_basis,
            &self.resolutions,
            &self.oracle_public_key,
            &executions,
            &self.private_rewards,
            self.trading_frozen,
            next_sequence,
        );
        let entry = JournaledSystemCommand::ConfirmBootstrapFill {
            idempotency_key: idempotency_key.clone(),
            execution_id,
            fill_price_micros,
            evidence_hash,
        };
        let record = self.journal.append(next_root, &entry)?;
        self.ledger = ledger;
        self.position_cost_basis = position_cost_basis;
        self.bootstrap_executions = executions;
        self.system_keys = keys;
        self.sequence = next_sequence;
        let mut response = self.system_response(
            "bootstrap-confirmed",
            idempotency_key,
            prior_root,
            next_root,
            record,
            now_millis,
        );
        response.evidence_commitment = Some(evidence_hash);
        response.audit_fills = signed_audit_fills(
            &self.receipt_signer,
            &self.identity_key,
            &response.receipt,
            vec![audit_draft],
        )?;
        Ok(response)
    }

    /// Releases the user's reservation only after an authenticated venue rejection or confirmed
    /// cancellation. A host timeout alone is deliberately insufficient evidence.
    pub fn fail_bootstrap_execution(
        &mut self,
        idempotency_key: String,
        execution_id: Uuid,
        failure_code: String,
        evidence_hash: [u8; 32],
        now_millis: i64,
    ) -> CoreResult<SystemResponse> {
        self.validate_new_system_key(&idempotency_key)?;
        if evidence_hash == [0u8; 32]
            || failure_code.is_empty()
            || failure_code.len() > 64
            || !failure_code
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(CoreError::InvalidOrder(
                "authenticated venue failure evidence is required".into(),
            ));
        }
        let prior_root = self.state_root();
        let mut ledger = self.ledger.clone();
        let mut executions = self.bootstrap_executions.clone();
        let execution = executions
            .get_mut(&execution_id)
            .ok_or_else(|| CoreError::InvalidOrder("unknown bootstrap execution".into()))?;
        if !matches!(
            execution.view.state,
            BootstrapExecutionState::FundsReserved | BootstrapExecutionState::VenueSubmitted
        ) {
            return Err(CoreError::InvalidOrder(
                "bootstrap execution is already terminal".into(),
            ));
        }
        let market = self
            .markets
            .get(&execution.view.market_id)
            .ok_or_else(|| CoreError::InvalidOrder("unknown market".into()))?;
        release_bootstrap_hold(
            &mut ledger,
            execution,
            market,
            &format!("bootstrap-failure:{idempotency_key}"),
            &hex::encode(evidence_hash),
        )?;
        execution.view.state = BootstrapExecutionState::Failed;
        execution.view.failure_code = Some(failure_code.clone());
        execution.venue_evidence_hash = Some(evidence_hash);

        let mut keys = self.system_keys.clone();
        keys.insert(idempotency_key.clone());
        let next_sequence = checked_sequence(self.sequence)?;
        let next_root = state_root(
            &ledger,
            &self.books,
            &self.markets,
            &self.sessions,
            &processed_hashes(&self.processed),
            &keys,
            &self.position_cost_basis,
            &self.resolutions,
            &self.oracle_public_key,
            &executions,
            &self.private_rewards,
            self.trading_frozen,
            next_sequence,
        );
        let entry = JournaledSystemCommand::FailBootstrapExecution {
            idempotency_key: idempotency_key.clone(),
            execution_id,
            failure_code,
            evidence_hash,
        };
        let record = self.journal.append(next_root, &entry)?;
        self.ledger = ledger;
        self.bootstrap_executions = executions;
        self.system_keys = keys;
        self.sequence = next_sequence;
        Ok(self.system_response(
            "bootstrap-failed",
            idempotency_key,
            prior_root,
            next_root,
            record,
            now_millis,
        ))
    }

    pub fn execute(&mut self, command: UserCommand, now_millis: i64) -> CoreResult<CoreResponse> {
        let expected_hash = command_request_hash(
            &command.command_id,
            &command.idempotency_key,
            &command.action,
        )?;
        if command.session.request.request_hash != expected_hash {
            return Err(CoreError::RequestHashMismatch);
        }
        if let Some(processed) = self.processed.get(&command.idempotency_key) {
            if processed.request_hash != expected_hash {
                return Err(CoreError::DuplicateCommand);
            }
            return processed
                .response
                .clone()
                .ok_or(CoreError::PreviouslyProcessed);
        }
        if self.trading_frozen
            && matches!(
                &command.action,
                UserCommandAction::SubmitOrder { .. } | UserCommandAction::CompleteSet { .. }
            )
        {
            return Err(CoreError::TradingFrozen);
        }

        let prior_root = self.state_root();
        let mut sessions = self.sessions.clone();
        let private_user_id = sessions.accept_signed(&command.session, now_millis)?;
        let mut ledger = self.ledger.clone();
        let mut books = self.books.clone();
        let mut position_cost_basis = self.position_cost_basis.clone();
        let mut bootstrap_executions = self.bootstrap_executions.clone();
        let mut private_rewards = self.private_rewards.clone();
        let mut system_keys = self.system_keys.clone();
        let mut audit_drafts = Vec::new();
        let result = match &command.action {
            UserCommandAction::SubmitOrder { order } => {
                let mut order = order.clone();
                order.private_user_id = private_user_id.clone();
                let market = self
                    .markets
                    .get(&order.market_id)
                    .ok_or_else(|| CoreError::InvalidOrder("unknown market".into()))?;
                validate_order_for_market(&order, market, now_millis)?;
                enforce_user_position_limit(
                    &ledger,
                    &books,
                    &bootstrap_executions,
                    market,
                    &order,
                )?;
                match &market.execution {
                    MarketExecution::NativeClob => {
                        let book = books.entry(order.market_id.clone()).or_default();
                        let match_result = book.submit(order.clone(), now_millis)?;
                        if match_result
                            .accepted_order
                            .as_ref()
                            .is_some_and(|accepted| accepted.status != OrderStatus::Rejected)
                        {
                            if match_result
                                .fills
                                .iter()
                                .all(|fill| fill.match_type == MatchType::Normal)
                            {
                                // Preserve the exact legacy transition (including one ledger
                                // sequence increment) so old NORMAL-only journal replay remains
                                // byte-for-byte stable after the complete-set feature ships.
                                let transfers = settlement_transfers(
                                    &self.books,
                                    &books,
                                    market,
                                    &order,
                                    &match_result,
                                )?;
                                apply_fill_cost_basis(
                                    &self.ledger,
                                    &self.books,
                                    &books,
                                    market,
                                    &order,
                                    &match_result,
                                    &mut position_cost_basis,
                                )?;
                                ledger.apply(LedgerTransaction {
                                    idempotency_key: format!("order:{}", command.idempotency_key),
                                    business_reference: command.command_id.clone(),
                                    transfers,
                                })?;
                            } else {
                                apply_complete_set_match_settlement(
                                    &mut ledger,
                                    &self.books,
                                    &books,
                                    market,
                                    &order,
                                    &match_result,
                                    &mut position_cost_basis,
                                    &command.idempotency_key,
                                    &command.command_id,
                                )?;
                            }
                        }
                        audit_drafts = native_audit_drafts(&order, &match_result, market)?;
                        CommandResult::Order {
                            result: redact_match_result(match_result),
                        }
                    }
                    MarketExecution::PolymarketBootstrap { .. } => {
                        if !matches!(order.time_in_force, super::TimeInForce::Fok) {
                            return Err(CoreError::InvalidOrder(
                                "bootstrap execution requires fill-or-kill".into(),
                            ));
                        }
                        if bootstrap_executions.contains_key(&order.order_id) {
                            return Err(CoreError::DuplicateCommand);
                        }
                        enforce_pending_bootstrap_limit(&bootstrap_executions, market, &order)?;
                        let reserved_atomic = bootstrap_reservation(&order, market)?;
                        let (from, to) = match order.action {
                            OrderAction::Buy => (
                                available(&private_user_id, &market.settlement_asset),
                                cash_hold(&order, &market.settlement_asset),
                            ),
                            OrderAction::Sell => (claim_position(&order), claim_hold(&order)),
                        };
                        ledger.apply(LedgerTransaction {
                            idempotency_key: format!(
                                "bootstrap-reserve:{}",
                                command.idempotency_key
                            ),
                            business_reference: command.command_id.clone(),
                            transfers: vec![Transfer {
                                from,
                                to,
                                amount: reserved_atomic,
                            }],
                        })?;
                        let view = BootstrapExecutionView {
                            execution_id: order.order_id,
                            market_id: order.market_id.clone(),
                            outcome: order.outcome,
                            action: order.action,
                            limit_price_micros: order.price_micros,
                            quantity_micros: order.quantity_micros,
                            state: BootstrapExecutionState::FundsReserved,
                            confirmed_price_micros: None,
                            failure_code: None,
                        };
                        bootstrap_executions.insert(
                            order.order_id,
                            BootstrapExecution {
                                view: view.clone(),
                                private_user_id,
                                reserved_atomic,
                                venue_order_id: None,
                                venue_evidence_hash: None,
                                created_at_millis: now_millis,
                            },
                        );
                        CommandResult::BootstrapPending { execution: view }
                    }
                }
            }
            UserCommandAction::CancelOrder {
                market_id,
                order_id,
            } => {
                let market = self
                    .markets
                    .get(market_id)
                    .ok_or_else(|| CoreError::InvalidOrder("unknown market".into()))?;
                let book = books
                    .get_mut(market_id)
                    .ok_or_else(|| CoreError::InvalidOrder("order book does not exist".into()))?;
                let order = book.cancel(*order_id, &private_user_id, now_millis)?;
                let transfers =
                    cancellation_transfers(&ledger, book, market, std::slice::from_ref(&order))?;
                ledger.apply(LedgerTransaction {
                    idempotency_key: format!("cancel:{}", command.idempotency_key),
                    business_reference: command.command_id.clone(),
                    transfers,
                })?;
                let mut public_order = order;
                public_order.private_user_id.clear();
                CommandResult::Cancelled {
                    order: public_order,
                }
            }
            UserCommandAction::CompleteSet {
                market_id,
                quantity_micros,
                direction,
            } => {
                let market = self
                    .markets
                    .get(market_id)
                    .ok_or_else(|| CoreError::InvalidOrder("unknown market".into()))?;
                if now_millis < market.opens_at_millis || now_millis >= market.closes_at_millis {
                    return Err(CoreError::InvalidOrder("market is not open".into()));
                }
                if *quantity_micros < market.minimum_quantity_micros
                    || *quantity_micros > market.maximum_quantity_micros
                {
                    return Err(CoreError::InvalidOrder(
                        "complete set violates market limits".into(),
                    ));
                }
                if matches!(direction, CompleteSetDirection::Mint) {
                    for outcome in [Outcome::Up, Outcome::Down] {
                        let projected = ledger
                            .total_for_owner_asset(
                                &private_user_id,
                                &claim_asset(market_id, outcome),
                            )
                            .checked_add(*quantity_micros)
                            .ok_or(CoreError::UnbalancedTransaction)?;
                        if projected > market.maximum_user_position_micros {
                            return Err(CoreError::InvalidOrder(
                                "complete set exceeds the user position limit".into(),
                            ));
                        }
                    }
                }
                apply_complete_set_cost_basis(
                    &ledger,
                    &mut position_cost_basis,
                    &private_user_id,
                    market_id,
                    *quantity_micros,
                    settlement_atomic(market, *quantity_micros)?,
                    *direction,
                )?;
                ledger.apply_complete_set(CompleteSetTransaction {
                    idempotency_key: format!("complete-set:{}", command.idempotency_key),
                    owner: private_user_id,
                    market_id: market_id.clone(),
                    settlement_asset: market.settlement_asset.clone(),
                    quantity_micros: *quantity_micros,
                    collateral_amount_atomic: settlement_atomic(market, *quantity_micros)?,
                    direction: *direction,
                })?;
                CommandResult::CompleteSet {
                    market_id: market_id.clone(),
                    quantity_micros: *quantity_micros,
                    direction: *direction,
                }
            }
            UserCommandAction::Portfolio => CommandResult::Portfolio {
                snapshot: portfolio_snapshot(
                    &ledger,
                    &books,
                    &position_cost_basis,
                    &private_user_id,
                    now_millis,
                ),
            },
            UserCommandAction::Rewards => CommandResult::Rewards {
                entitlements: private_rewards.entitlements(&private_user_id),
            },
            UserCommandAction::RequestRewardClaim {
                chain,
                account,
                recipient,
                reward_token,
                deadline_seconds,
            } => {
                let now_seconds = u64::try_from(now_millis / 1_000).map_err(|_| {
                    CoreError::InvalidOrder("invalid reward claim timestamp".into())
                })?;
                if *deadline_seconds <= now_seconds
                    || *deadline_seconds > now_seconds.saturating_add(15 * 60)
                {
                    return Err(CoreError::InvalidOrder(
                        "reward claim deadline must be within 15 minutes".into(),
                    ));
                }
                CommandResult::RewardClaimAuthorized {
                    intent: private_rewards.authorize(
                        &private_user_id,
                        chain,
                        account,
                        recipient,
                        reward_token,
                        *deadline_seconds,
                        &command.idempotency_key,
                    )?,
                }
            }
            UserCommandAction::BootstrapStatus { execution_id } => {
                let execution = bootstrap_executions
                    .get(execution_id)
                    .filter(|execution| execution.private_user_id == private_user_id)
                    .ok_or_else(|| CoreError::InvalidOrder("unknown bootstrap execution".into()))?;
                CommandResult::BootstrapStatus {
                    execution: execution.view.clone(),
                }
            }
            UserCommandAction::CancelBootstrap { execution_id } => {
                let execution = bootstrap_executions
                    .get_mut(execution_id)
                    .filter(|execution| execution.private_user_id == private_user_id)
                    .ok_or_else(|| CoreError::InvalidOrder("unknown bootstrap execution".into()))?;
                if execution.view.state != BootstrapExecutionState::FundsReserved {
                    return Err(CoreError::InvalidOrder(
                        "venue-submitted execution requires confirmed venue cancellation".into(),
                    ));
                }
                let market = self
                    .markets
                    .get(&execution.view.market_id)
                    .ok_or_else(|| CoreError::InvalidOrder("unknown market".into()))?;
                release_bootstrap_hold(
                    &mut ledger,
                    execution,
                    market,
                    &format!("bootstrap-user-cancel:{}", command.idempotency_key),
                    &command.command_id,
                )?;
                execution.view.state = BootstrapExecutionState::Failed;
                execution.view.failure_code = Some("USER_CANCELLED".into());
                CommandResult::BootstrapCancelled {
                    execution: execution.view.clone(),
                }
            }
            UserCommandAction::RequestWithdrawal {
                withdrawal_id,
                chain,
                asset,
                amount_atomic,
                destination,
            } => {
                validate_withdrawal(chain, asset, *amount_atomic, destination)?;
                let reservation_marker = withdrawal_reservation_marker(
                    &command.session.request.session_id,
                    *withdrawal_id,
                    chain,
                    asset,
                    &amount_atomic.to_string(),
                    destination,
                )?;
                if system_keys
                    .iter()
                    .any(|key| key.starts_with(&format!("withdrawal-reservation:{withdrawal_id}:")))
                {
                    return Err(CoreError::DuplicateCommand);
                }
                system_keys.insert(reservation_marker);
                ledger.apply(LedgerTransaction {
                    idempotency_key: format!("withdrawal:{}", command.idempotency_key),
                    business_reference: withdrawal_id.to_string(),
                    transfers: vec![Transfer {
                        from: AccountKey::new(
                            &private_user_id,
                            AccountBucket::UserAvailable,
                            asset,
                        ),
                        to: AccountKey::new(
                            &private_user_id,
                            AccountBucket::UserWithdrawalHold,
                            asset,
                        ),
                        amount: *amount_atomic,
                    }],
                })?;
                CommandResult::WithdrawalReserved {
                    withdrawal_id: *withdrawal_id,
                    chain: chain.clone(),
                    asset: asset.clone(),
                    amount_atomic: *amount_atomic,
                    destination: destination.clone(),
                }
            }
        };

        let mut processed_hash_map = processed_hashes(&self.processed);
        processed_hash_map.insert(command.idempotency_key.clone(), expected_hash);
        let next_sequence = checked_sequence(self.sequence)?;
        let next_root = state_root(
            &ledger,
            &books,
            &self.markets,
            &sessions,
            &processed_hash_map,
            &system_keys,
            &position_cost_basis,
            &self.resolutions,
            &self.oracle_public_key,
            &bootstrap_executions,
            &private_rewards,
            self.trading_frozen,
            next_sequence,
        );
        let journal_value = JournaledUserCommand {
            command: command.clone(),
            result: result.clone(),
        };
        let record = self.journal.append(next_root, &journal_value)?;
        let receipt = self.receipt_signer.sign(
            command.command_id,
            command.idempotency_key.clone(),
            Some(expected_hash),
            Some(matches!(
                command.action,
                UserCommandAction::SubmitOrder { .. }
                    | UserCommandAction::CancelOrder { .. }
                    | UserCommandAction::CompleteSet { .. }
                    | UserCommandAction::RequestRewardClaim { .. }
                    | UserCommandAction::CancelBootstrap { .. }
                    | UserCommandAction::RequestWithdrawal { .. }
            )),
            next_sequence,
            prior_root,
            next_root,
            record.record_hash,
            now_millis,
        );
        let withdrawal_authorization = match &result {
            CommandResult::WithdrawalReserved {
                withdrawal_id,
                chain,
                asset,
                amount_atomic,
                destination,
            } => {
                let intent = WithdrawalIntent {
                    protocol_version: "layrs.withdrawal.v1".into(),
                    withdrawal_id: *withdrawal_id,
                    session_id: command.session.request.session_id.clone(),
                    chain: chain.clone(),
                    asset: asset.clone(),
                    amount_atomic: amount_atomic.to_string(),
                    destination: destination.clone(),
                    receipt_id: receipt.receipt_id.clone(),
                    enclave_sequence: next_sequence,
                    state_root: next_root,
                    expires_at_millis: now_millis.saturating_add(15 * 60_000),
                };
                Some(WithdrawalAuthorization {
                    signature: self
                        .receipt_signer
                        .sign_domain_payload(b"layrs.withdrawal-authorization.v1\0", &intent),
                    intent,
                })
            }
            _ => None,
        };
        let audit_fills = signed_audit_fills(
            &self.receipt_signer,
            &self.identity_key,
            &receipt,
            audit_drafts,
        )?;
        let response = CoreResponse {
            result,
            receipt,
            encrypted_record: record,
            withdrawal_authorization,
            reward_claim_authorization: None,
            audit_fills,
        };
        self.ledger = ledger;
        self.books = books;
        self.sessions = sessions;
        self.position_cost_basis = position_cost_basis;
        self.bootstrap_executions = bootstrap_executions;
        self.private_rewards = private_rewards;
        self.system_keys = system_keys;
        self.sequence = next_sequence;
        self.processed.insert(
            command.idempotency_key,
            ProcessedCommand {
                request_hash: expected_hash,
                response: Some(response.clone()),
            },
        );
        Ok(response)
    }

    pub fn aggregate_depth(
        &self,
        market_id: &str,
        outcome: Outcome,
        now_millis: i64,
        minimum_level_quantity_micros: u128,
    ) -> (Vec<(u64, u128)>, Vec<(u64, u128)>) {
        self.books.get(market_id).map_or_else(
            || (Vec::new(), Vec::new()),
            |book| {
                let (bids, asks) = book.aggregate_depth(market_id, outcome, now_millis);
                let filter = |levels: Vec<(u64, u128, usize)>| {
                    levels
                        .into_iter()
                        .filter(|(_, quantity, _)| *quantity >= minimum_level_quantity_micros)
                        .map(|(price, quantity, _)| (price, quantity))
                        .collect()
                };
                (filter(bids), filter(asks))
            },
        )
    }

    fn validate_new_system_key(&self, key: &str) -> CoreResult<()> {
        if key.is_empty() || self.system_keys.contains(key) {
            return Err(CoreError::DuplicateCommand);
        }
        Ok(())
    }

    fn system_response(
        &self,
        command_id: &str,
        idempotency_key: String,
        prior_root: [u8; 32],
        state_root: [u8; 32],
        encrypted_record: EncryptedJournalRecord,
        now_millis: i64,
    ) -> SystemResponse {
        let receipt = self.receipt_signer.sign(
            command_id.into(),
            idempotency_key,
            None,
            None,
            self.sequence,
            prior_root,
            state_root,
            encrypted_record.record_hash,
            now_millis,
        );
        SystemResponse {
            receipt,
            encrypted_record,
            audit_fills: Vec::new(),
            evidence_commitment: None,
        }
    }
}

pub fn command_request_hash(
    command_id: &str,
    idempotency_key: &str,
    action: &UserCommandAction,
) -> CoreResult<[u8; 32]> {
    let encoded = serde_json::to_vec(action).map_err(|_| CoreError::RequestHashMismatch)?;
    let mut hash = Sha256::new();
    hash.update(b"layrs.user-command.v1\0");
    hash.update((command_id.len() as u32).to_be_bytes());
    hash.update(command_id.as_bytes());
    hash.update((idempotency_key.len() as u32).to_be_bytes());
    hash.update(idempotency_key.as_bytes());
    hash.update(encoded);
    Ok(hash.finalize().into())
}

fn settlement_transfers(
    prior_books: &BTreeMap<String, PriceTimeBook>,
    next_books: &BTreeMap<String, PriceTimeBook>,
    market: &MarketConfig,
    incoming: &BookOrder,
    result: &MatchResult,
) -> CoreResult<Vec<Transfer>> {
    let mut transfers = Vec::new();
    let incoming_cash_hold = cash_hold(incoming, &market.settlement_asset);
    let incoming_claim_hold = claim_hold(incoming);
    let initial_notional_micros = notional(incoming.price_micros, incoming.quantity_micros)?;
    let initial_notional = settlement_atomic(market, initial_notional_micros)?;
    match incoming.action {
        OrderAction::Buy => transfers.push(Transfer {
            from: available(&incoming.private_user_id, &market.settlement_asset),
            to: incoming_cash_hold.clone(),
            amount: initial_notional
                .checked_add(settlement_atomic(
                    market,
                    ceil_bps(initial_notional_micros, 20)?,
                )?)
                .ok_or(CoreError::UnbalancedTransaction)?,
        }),
        OrderAction::Sell => transfers.push(Transfer {
            from: claim_position(incoming),
            to: incoming_claim_hold.clone(),
            amount: incoming.quantity_micros,
        }),
    }

    let next_book = next_books
        .get(&incoming.market_id)
        .ok_or_else(|| CoreError::InvalidOrder("book disappeared during settlement".into()))?;
    let prior_book = prior_books.get(&incoming.market_id);
    let mut incoming_cash_used = 0u128;
    let mut incoming_claim_used = 0u128;
    for fill in &result.fills {
        let maker = prior_book
            .and_then(|book| book.order(fill.maker_order_id))
            .or_else(|| next_book.order(fill.maker_order_id))
            .ok_or_else(|| CoreError::InvalidOrder("maker order missing".into()))?;
        let fill_notional_micros = notional(fill.price_micros, fill.quantity_micros)?;
        let fill_notional = settlement_atomic(market, fill_notional_micros)?;
        let taker_fee = settlement_atomic(market, ceil_bps(fill_notional_micros, 20)?)?;
        let (buyer, seller, buyer_hold, seller_hold) = match incoming.action {
            OrderAction::Buy => (
                incoming,
                maker,
                incoming_cash_hold.clone(),
                claim_hold(maker),
            ),
            OrderAction::Sell => (
                maker,
                incoming,
                cash_hold(maker, &market.settlement_asset),
                incoming_claim_hold.clone(),
            ),
        };
        let seller_proceeds = if incoming.action == OrderAction::Sell {
            fill_notional
                .checked_sub(taker_fee)
                .ok_or(CoreError::UnbalancedTransaction)?
        } else {
            fill_notional
        };
        transfers.push(Transfer {
            from: buyer_hold.clone(),
            to: available(&seller.private_user_id, &market.settlement_asset),
            amount: seller_proceeds,
        });
        if taker_fee > 0 {
            transfers.push(Transfer {
                from: buyer_hold,
                to: AccountKey::new("layrs", AccountBucket::FeeRevenue, &market.settlement_asset),
                amount: taker_fee,
            });
        }
        transfers.push(Transfer {
            from: seller_hold,
            to: claim_position_for(
                &buyer.private_user_id,
                &incoming.market_id,
                incoming.outcome,
            ),
            amount: fill.quantity_micros,
        });
        if incoming.action == OrderAction::Buy {
            incoming_cash_used = incoming_cash_used
                .checked_add(fill_notional)
                .and_then(|value| value.checked_add(taker_fee))
                .ok_or(CoreError::UnbalancedTransaction)?;
        } else {
            incoming_claim_used = incoming_claim_used
                .checked_add(fill.quantity_micros)
                .ok_or(CoreError::UnbalancedTransaction)?;
        }
    }

    let accepted = result
        .accepted_order
        .as_ref()
        .ok_or_else(|| CoreError::InvalidOrder("missing accepted order".into()))?;
    match incoming.action {
        OrderAction::Buy => {
            let initially_reserved = initial_notional
                .checked_add(settlement_atomic(
                    market,
                    ceil_bps(initial_notional_micros, 20)?,
                )?)
                .ok_or(CoreError::UnbalancedTransaction)?;
            let desired_hold = settlement_atomic(
                market,
                notional(incoming.price_micros, accepted.remaining_micros)?,
            )?;
            let refund = initially_reserved
                .checked_sub(incoming_cash_used)
                .and_then(|value| value.checked_sub(desired_hold))
                .ok_or(CoreError::UnbalancedTransaction)?;
            if refund > 0 {
                transfers.push(Transfer {
                    from: incoming_cash_hold,
                    to: available(&incoming.private_user_id, &market.settlement_asset),
                    amount: refund,
                });
            }
        }
        OrderAction::Sell => {
            let desired_hold = accepted.remaining_micros;
            let refund = incoming
                .quantity_micros
                .checked_sub(incoming_claim_used)
                .and_then(|value| value.checked_sub(desired_hold))
                .ok_or(CoreError::UnbalancedTransaction)?;
            if refund > 0 {
                transfers.push(Transfer {
                    from: incoming_claim_hold,
                    to: claim_position(incoming),
                    amount: refund,
                });
            }
        }
    }
    Ok(transfers)
}

/// Settles a match result containing at least one complete-set fill. The engine
/// mutates a command-local ledger clone, so these individually idempotent
/// transitions are committed to enclave state and journaled only if every leg
/// succeeds.
#[allow(clippy::too_many_arguments)]
fn apply_complete_set_match_settlement(
    ledger: &mut Ledger,
    prior_books: &BTreeMap<String, PriceTimeBook>,
    next_books: &BTreeMap<String, PriceTimeBook>,
    market: &MarketConfig,
    incoming: &BookOrder,
    result: &MatchResult,
    cost_basis: &mut BTreeMap<PositionKey, u128>,
    command_idempotency_key: &str,
    business_reference: &str,
) -> CoreResult<()> {
    let incoming_cash_hold = cash_hold(incoming, &market.settlement_asset);
    let incoming_claim_hold = claim_hold(incoming);
    let initial_notional_micros = notional(incoming.price_micros, incoming.quantity_micros)?;
    let initial_notional = settlement_atomic(market, initial_notional_micros)?;
    let reserve = match incoming.action {
        OrderAction::Buy => Transfer {
            from: available(&incoming.private_user_id, &market.settlement_asset),
            to: incoming_cash_hold.clone(),
            amount: initial_notional
                .checked_add(settlement_atomic(
                    market,
                    ceil_bps(initial_notional_micros, 20)?,
                )?)
                .ok_or(CoreError::UnbalancedTransaction)?,
        },
        OrderAction::Sell => Transfer {
            from: claim_position(incoming),
            to: incoming_claim_hold.clone(),
            amount: incoming.quantity_micros,
        },
    };
    ledger.apply(LedgerTransaction {
        idempotency_key: format!("order:{command_idempotency_key}:reserve"),
        business_reference: business_reference.into(),
        transfers: vec![reserve],
    })?;

    let next_book = next_books
        .get(&incoming.market_id)
        .ok_or_else(|| CoreError::InvalidOrder("book disappeared during settlement".into()))?;
    let prior_book = prior_books.get(&incoming.market_id);
    let mut incoming_cash_used = 0u128;
    let mut incoming_claim_used = 0u128;

    for fill in &result.fills {
        let maker = prior_book
            .and_then(|book| book.order(fill.maker_order_id))
            .or_else(|| next_book.order(fill.maker_order_id))
            .ok_or_else(|| CoreError::InvalidOrder("maker order missing".into()))?
            .clone();
        match fill.match_type {
            MatchType::Normal => {
                let single_fill = MatchResult {
                    accepted_order: result.accepted_order.clone(),
                    fills: vec![fill.clone()],
                    cancelled_remainder_micros: 0,
                };
                apply_fill_cost_basis(
                    ledger,
                    prior_books,
                    next_books,
                    market,
                    incoming,
                    &single_fill,
                    cost_basis,
                )?;

                let fill_notional_micros = notional(fill.price_micros, fill.quantity_micros)?;
                let fill_notional = settlement_atomic(market, fill_notional_micros)?;
                let taker_fee = settlement_atomic(market, ceil_bps(fill_notional_micros, 20)?)?;
                let mut transfers = Vec::with_capacity(3);
                match incoming.action {
                    OrderAction::Buy => {
                        transfers.push(Transfer {
                            from: incoming_cash_hold.clone(),
                            to: available(&maker.private_user_id, &market.settlement_asset),
                            amount: fill_notional,
                        });
                        if taker_fee > 0 {
                            transfers.push(Transfer {
                                from: incoming_cash_hold.clone(),
                                to: fee_revenue(&market.settlement_asset),
                                amount: taker_fee,
                            });
                        }
                        transfers.push(Transfer {
                            from: claim_hold(&maker),
                            to: claim_position_for(
                                &incoming.private_user_id,
                                &incoming.market_id,
                                incoming.outcome,
                            ),
                            amount: fill.quantity_micros,
                        });
                        incoming_cash_used = incoming_cash_used
                            .checked_add(fill_notional)
                            .and_then(|value| value.checked_add(taker_fee))
                            .ok_or(CoreError::UnbalancedTransaction)?;
                    }
                    OrderAction::Sell => {
                        let seller_proceeds = fill_notional
                            .checked_sub(taker_fee)
                            .ok_or(CoreError::UnbalancedTransaction)?;
                        if seller_proceeds > 0 {
                            transfers.push(Transfer {
                                from: cash_hold(&maker, &market.settlement_asset),
                                to: available(&incoming.private_user_id, &market.settlement_asset),
                                amount: seller_proceeds,
                            });
                        }
                        if taker_fee > 0 {
                            transfers.push(Transfer {
                                from: cash_hold(&maker, &market.settlement_asset),
                                to: fee_revenue(&market.settlement_asset),
                                amount: taker_fee,
                            });
                        }
                        transfers.push(Transfer {
                            from: incoming_claim_hold.clone(),
                            to: claim_position_for(
                                &maker.private_user_id,
                                &incoming.market_id,
                                incoming.outcome,
                            ),
                            amount: fill.quantity_micros,
                        });
                        incoming_claim_used = incoming_claim_used
                            .checked_add(fill.quantity_micros)
                            .ok_or(CoreError::UnbalancedTransaction)?;
                    }
                }
                ledger.apply(LedgerTransaction {
                    idempotency_key: format!(
                        "order:{command_idempotency_key}:normal:{}",
                        fill.sequence
                    ),
                    business_reference: business_reference.into(),
                    transfers,
                })?;
            }
            MatchType::Mint => {
                if incoming.action != OrderAction::Buy
                    || maker.action != OrderAction::Buy
                    || incoming.outcome == maker.outcome
                {
                    return Err(CoreError::InvalidOrder(
                        "invalid complete-set mint match".into(),
                    ));
                }
                let amounts = complete_set_fill_amounts(market, fill)?;
                let mut funding = vec![
                    Transfer {
                        from: cash_hold(&maker, &market.settlement_asset),
                        to: available(&maker.private_user_id, &market.settlement_asset),
                        amount: amounts.maker_atomic,
                    },
                    Transfer {
                        from: incoming_cash_hold.clone(),
                        to: available(&maker.private_user_id, &market.settlement_asset),
                        amount: amounts.taker_atomic,
                    },
                ];
                if amounts.taker_fee_atomic > 0 {
                    funding.push(Transfer {
                        from: incoming_cash_hold.clone(),
                        to: fee_revenue(&market.settlement_asset),
                        amount: amounts.taker_fee_atomic,
                    });
                }
                ledger.apply(LedgerTransaction {
                    idempotency_key: format!(
                        "order:{command_idempotency_key}:mint-fund:{}",
                        fill.sequence
                    ),
                    business_reference: business_reference.into(),
                    transfers: funding,
                })?;
                ledger.apply_complete_set(CompleteSetTransaction {
                    idempotency_key: format!(
                        "order:{command_idempotency_key}:mint-set:{}",
                        fill.sequence
                    ),
                    owner: maker.private_user_id.clone(),
                    market_id: incoming.market_id.clone(),
                    settlement_asset: market.settlement_asset.clone(),
                    quantity_micros: fill.quantity_micros,
                    collateral_amount_atomic: amounts.collateral_atomic,
                    direction: CompleteSetDirection::Mint,
                })?;
                ledger.apply(LedgerTransaction {
                    idempotency_key: format!(
                        "order:{command_idempotency_key}:mint-claim:{}",
                        fill.sequence
                    ),
                    business_reference: business_reference.into(),
                    transfers: vec![Transfer {
                        from: claim_position_for(
                            &maker.private_user_id,
                            &incoming.market_id,
                            incoming.outcome,
                        ),
                        to: claim_position_for(
                            &incoming.private_user_id,
                            &incoming.market_id,
                            incoming.outcome,
                        ),
                        amount: fill.quantity_micros,
                    }],
                })?;
                add_basis(
                    cost_basis,
                    position_key(&maker.private_user_id, &incoming.market_id, maker.outcome),
                    amounts.maker_atomic,
                )?;
                add_basis(
                    cost_basis,
                    position_key(
                        &incoming.private_user_id,
                        &incoming.market_id,
                        incoming.outcome,
                    ),
                    amounts.taker_atomic,
                )?;
                incoming_cash_used = incoming_cash_used
                    .checked_add(amounts.taker_atomic)
                    .and_then(|value| value.checked_add(amounts.taker_fee_atomic))
                    .ok_or(CoreError::UnbalancedTransaction)?;
            }
            MatchType::Merge => {
                if incoming.action != OrderAction::Sell
                    || maker.action != OrderAction::Sell
                    || incoming.outcome == maker.outcome
                {
                    return Err(CoreError::InvalidOrder(
                        "invalid complete-set merge match".into(),
                    ));
                }
                let amounts = complete_set_fill_amounts(market, fill)?;
                let taker_proceeds = amounts
                    .taker_atomic
                    .checked_sub(amounts.taker_fee_atomic)
                    .ok_or(CoreError::UnbalancedTransaction)?;

                reduce_basis_for_held_quantity(
                    ledger,
                    cost_basis,
                    position_key(&maker.private_user_id, &incoming.market_id, maker.outcome),
                    &maker.private_user_id,
                    &incoming.market_id,
                    maker.outcome,
                    fill.quantity_micros,
                )?;
                reduce_basis_for_held_quantity(
                    ledger,
                    cost_basis,
                    position_key(
                        &incoming.private_user_id,
                        &incoming.market_id,
                        incoming.outcome,
                    ),
                    &incoming.private_user_id,
                    &incoming.market_id,
                    incoming.outcome,
                    fill.quantity_micros,
                )?;

                ledger.apply(LedgerTransaction {
                    idempotency_key: format!(
                        "order:{command_idempotency_key}:merge-claims:{}",
                        fill.sequence
                    ),
                    business_reference: business_reference.into(),
                    transfers: vec![
                        Transfer {
                            from: claim_hold(&maker),
                            to: claim_position_for(
                                &maker.private_user_id,
                                &incoming.market_id,
                                maker.outcome,
                            ),
                            amount: fill.quantity_micros,
                        },
                        Transfer {
                            from: incoming_claim_hold.clone(),
                            to: claim_position_for(
                                &maker.private_user_id,
                                &incoming.market_id,
                                incoming.outcome,
                            ),
                            amount: fill.quantity_micros,
                        },
                    ],
                })?;
                ledger.apply_complete_set(CompleteSetTransaction {
                    idempotency_key: format!(
                        "order:{command_idempotency_key}:merge-set:{}",
                        fill.sequence
                    ),
                    owner: maker.private_user_id.clone(),
                    market_id: incoming.market_id.clone(),
                    settlement_asset: market.settlement_asset.clone(),
                    quantity_micros: fill.quantity_micros,
                    collateral_amount_atomic: amounts.collateral_atomic,
                    direction: CompleteSetDirection::Burn,
                })?;
                let mut payout = Vec::with_capacity(2);
                if taker_proceeds > 0 {
                    payout.push(Transfer {
                        from: available(&maker.private_user_id, &market.settlement_asset),
                        to: available(&incoming.private_user_id, &market.settlement_asset),
                        amount: taker_proceeds,
                    });
                }
                if amounts.taker_fee_atomic > 0 {
                    payout.push(Transfer {
                        from: available(&maker.private_user_id, &market.settlement_asset),
                        to: fee_revenue(&market.settlement_asset),
                        amount: amounts.taker_fee_atomic,
                    });
                }
                if payout.is_empty() {
                    return Err(CoreError::ZeroAmount);
                }
                ledger.apply(LedgerTransaction {
                    idempotency_key: format!(
                        "order:{command_idempotency_key}:merge-payout:{}",
                        fill.sequence
                    ),
                    business_reference: business_reference.into(),
                    transfers: payout,
                })?;
                incoming_claim_used = incoming_claim_used
                    .checked_add(fill.quantity_micros)
                    .ok_or(CoreError::UnbalancedTransaction)?;
            }
        }
    }

    let accepted = result
        .accepted_order
        .as_ref()
        .ok_or_else(|| CoreError::InvalidOrder("missing accepted order".into()))?;
    let refund = match incoming.action {
        OrderAction::Buy => {
            let initially_reserved = initial_notional
                .checked_add(settlement_atomic(
                    market,
                    ceil_bps(initial_notional_micros, 20)?,
                )?)
                .ok_or(CoreError::UnbalancedTransaction)?;
            let desired_hold = settlement_atomic(
                market,
                notional(incoming.price_micros, accepted.remaining_micros)?,
            )?;
            let amount = initially_reserved
                .checked_sub(incoming_cash_used)
                .and_then(|value| value.checked_sub(desired_hold))
                .ok_or(CoreError::UnbalancedTransaction)?;
            (
                incoming_cash_hold,
                available(&incoming.private_user_id, &market.settlement_asset),
                amount,
            )
        }
        OrderAction::Sell => {
            let desired_hold = accepted.remaining_micros;
            let amount = incoming
                .quantity_micros
                .checked_sub(incoming_claim_used)
                .and_then(|value| value.checked_sub(desired_hold))
                .ok_or(CoreError::UnbalancedTransaction)?;
            (incoming_claim_hold, claim_position(incoming), amount)
        }
    };
    if refund.2 > 0 {
        ledger.apply(LedgerTransaction {
            idempotency_key: format!("order:{command_idempotency_key}:refund"),
            business_reference: business_reference.into(),
            transfers: vec![Transfer {
                from: refund.0,
                to: refund.1,
                amount: refund.2,
            }],
        })?;
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CompleteSetFillAmounts {
    collateral_atomic: u128,
    maker_atomic: u128,
    taker_atomic: u128,
    taker_fee_atomic: u128,
}

fn complete_set_fill_amounts(
    market: &MarketConfig,
    fill: &Fill,
) -> CoreResult<CompleteSetFillAmounts> {
    let collateral_atomic = settlement_atomic(market, fill.quantity_micros)?;
    let maker_atomic =
        settlement_atomic(market, notional(fill.price_micros, fill.quantity_micros)?)?;
    let taker_atomic = collateral_atomic
        .checked_sub(maker_atomic)
        .ok_or(CoreError::UnbalancedTransaction)?;
    if maker_atomic == 0 || taker_atomic == 0 {
        return Err(CoreError::InvalidOrder(
            "complete-set fill is below settlement precision".into(),
        ));
    }
    let taker_notional_micros = notional(fill.taker_price_micros(), fill.quantity_micros)?;
    let taker_fee_atomic = settlement_atomic(market, ceil_bps(taker_notional_micros, 20)?)?;
    if taker_fee_atomic > taker_atomic {
        return Err(CoreError::InvalidOrder(
            "complete-set fee exceeds taker proceeds".into(),
        ));
    }
    Ok(CompleteSetFillAmounts {
        collateral_atomic,
        maker_atomic,
        taker_atomic,
        taker_fee_atomic,
    })
}

fn apply_fill_cost_basis(
    ledger: &Ledger,
    prior_books: &BTreeMap<String, PriceTimeBook>,
    next_books: &BTreeMap<String, PriceTimeBook>,
    market: &MarketConfig,
    incoming: &BookOrder,
    result: &MatchResult,
    cost_basis: &mut BTreeMap<PositionKey, u128>,
) -> CoreResult<()> {
    let next_book = next_books
        .get(&incoming.market_id)
        .ok_or_else(|| CoreError::InvalidOrder("book disappeared during accounting".into()))?;
    let prior_book = prior_books.get(&incoming.market_id);
    let mut seller_quantities: BTreeMap<PositionKey, u128> = BTreeMap::new();

    for fill in &result.fills {
        let maker = prior_book
            .and_then(|book| book.order(fill.maker_order_id))
            .or_else(|| next_book.order(fill.maker_order_id))
            .ok_or_else(|| CoreError::InvalidOrder("maker order missing".into()))?;
        let (buyer, seller) = match incoming.action {
            OrderAction::Buy => (incoming, maker),
            OrderAction::Sell => (maker, incoming),
        };
        let seller_key = position_key(&seller.private_user_id, &seller.market_id, seller.outcome);
        let seller_quantity = seller_quantities
            .entry(seller_key.clone())
            .or_insert_with(|| {
                ledger.total_for_owner_asset(
                    &seller.private_user_id,
                    &claim_asset(&seller.market_id, seller.outcome),
                )
            });
        if *seller_quantity < fill.quantity_micros {
            return Err(CoreError::InsufficientBalance);
        }
        let existing_basis = cost_basis.get(&seller_key).copied().unwrap_or_default();
        let removed_basis = if fill.quantity_micros == *seller_quantity {
            existing_basis
        } else {
            existing_basis
                .checked_mul(fill.quantity_micros)
                .ok_or(CoreError::UnbalancedTransaction)?
                / *seller_quantity
        };
        cost_basis.insert(seller_key, existing_basis - removed_basis);
        *seller_quantity -= fill.quantity_micros;

        let buyer_key = position_key(&buyer.private_user_id, &buyer.market_id, buyer.outcome);
        let acquisition_cost =
            settlement_atomic(market, notional(fill.price_micros, fill.quantity_micros)?)?;
        let buyer_basis = cost_basis.get(&buyer_key).copied().unwrap_or_default();
        cost_basis.insert(
            buyer_key,
            buyer_basis
                .checked_add(acquisition_cost)
                .ok_or(CoreError::UnbalancedTransaction)?,
        );
    }
    Ok(())
}

fn apply_complete_set_cost_basis(
    ledger: &Ledger,
    cost_basis: &mut BTreeMap<PositionKey, u128>,
    owner: &str,
    market_id: &str,
    quantity_micros: u128,
    collateral_amount_atomic: u128,
    direction: CompleteSetDirection,
) -> CoreResult<()> {
    let up_key = position_key(owner, market_id, Outcome::Up);
    let down_key = position_key(owner, market_id, Outcome::Down);
    match direction {
        CompleteSetDirection::Mint => {
            let up_allocation = collateral_amount_atomic / 2;
            let down_allocation = collateral_amount_atomic - up_allocation;
            add_basis(cost_basis, up_key, up_allocation)?;
            add_basis(cost_basis, down_key, down_allocation)?;
        }
        CompleteSetDirection::Burn => {
            reduce_basis_for_quantity(
                ledger,
                cost_basis,
                up_key,
                owner,
                market_id,
                Outcome::Up,
                quantity_micros,
            )?;
            reduce_basis_for_quantity(
                ledger,
                cost_basis,
                down_key,
                owner,
                market_id,
                Outcome::Down,
                quantity_micros,
            )?;
        }
    }
    Ok(())
}

fn reduce_basis_for_quantity(
    ledger: &Ledger,
    cost_basis: &mut BTreeMap<PositionKey, u128>,
    key: PositionKey,
    owner: &str,
    market_id: &str,
    outcome: Outcome,
    quantity_micros: u128,
) -> CoreResult<()> {
    let available_quantity = ledger.balance(&claim_position_for(owner, market_id, outcome));
    if available_quantity < quantity_micros {
        return Err(CoreError::InsufficientBalance);
    }
    let current_quantity = ledger.total_for_owner_asset(owner, &claim_asset(market_id, outcome));
    let current_basis = cost_basis.get(&key).copied().unwrap_or_default();
    let removed = if current_quantity == quantity_micros {
        current_basis
    } else {
        current_basis
            .checked_mul(quantity_micros)
            .ok_or(CoreError::UnbalancedTransaction)?
            / current_quantity
    };
    cost_basis.insert(key, current_basis - removed);
    Ok(())
}

fn reduce_basis_for_held_quantity(
    ledger: &Ledger,
    cost_basis: &mut BTreeMap<PositionKey, u128>,
    key: PositionKey,
    owner: &str,
    market_id: &str,
    outcome: Outcome,
    quantity_micros: u128,
) -> CoreResult<()> {
    let current_quantity = ledger.total_for_owner_asset(owner, &claim_asset(market_id, outcome));
    if current_quantity < quantity_micros {
        return Err(CoreError::InsufficientBalance);
    }
    let current_basis = cost_basis.get(&key).copied().unwrap_or_default();
    let removed = if current_quantity == quantity_micros {
        current_basis
    } else {
        current_basis
            .checked_mul(quantity_micros)
            .ok_or(CoreError::UnbalancedTransaction)?
            / current_quantity
    };
    cost_basis.insert(key, current_basis - removed);
    Ok(())
}

fn add_basis(
    cost_basis: &mut BTreeMap<PositionKey, u128>,
    key: PositionKey,
    amount: u128,
) -> CoreResult<()> {
    let current = cost_basis.get(&key).copied().unwrap_or_default();
    cost_basis.insert(
        key,
        current
            .checked_add(amount)
            .ok_or(CoreError::UnbalancedTransaction)?,
    );
    Ok(())
}

fn position_key(owner: &str, market_id: &str, outcome: Outcome) -> PositionKey {
    PositionKey {
        owner: owner.into(),
        market_id: market_id.into(),
        outcome,
    }
}

fn cancellation_transfers(
    ledger: &Ledger,
    book: &PriceTimeBook,
    market: &MarketConfig,
    cancelled: &[BookOrder],
) -> CoreResult<Vec<Transfer>> {
    let mut buckets = BTreeMap::<AccountKey, AccountKey>::new();
    for order in cancelled {
        let (hold, destination) = match order.action {
            OrderAction::Buy => (
                cash_hold(order, &market.settlement_asset),
                available(&order.private_user_id, &market.settlement_asset),
            ),
            OrderAction::Sell => (claim_hold(order), claim_position(order)),
        };
        if let Some(existing) = buckets.insert(hold, destination.clone()) {
            if existing != destination {
                return Err(CoreError::UnbalancedTransaction);
            }
        }
    }
    let mut transfers = Vec::with_capacity(buckets.len());
    for (hold, destination) in buckets {
        let action = if hold.asset == market.settlement_asset {
            OrderAction::Buy
        } else {
            OrderAction::Sell
        };
        let outcome = match hold.outcome.as_deref() {
            Some("UP") => Outcome::Up,
            Some("DOWN") => Outcome::Down,
            _ => return Err(CoreError::UnbalancedTransaction),
        };
        let required_remaining = book
            .orders_for_owner(&hold.owner)
            .into_iter()
            .filter(|remaining| {
                remaining.market_id == market.market_id
                    && remaining.outcome == outcome
                    && remaining.action == action
                    && matches!(
                        remaining.status,
                        OrderStatus::Open | OrderStatus::PartiallyFilled
                    )
            })
            .try_fold(0u128, |total, remaining| {
                let required = match action {
                    OrderAction::Buy => settlement_atomic(
                        market,
                        notional(remaining.price_micros, remaining.remaining_micros)?,
                    )?,
                    OrderAction::Sell => remaining.remaining_micros,
                };
                total
                    .checked_add(required)
                    .ok_or(CoreError::UnbalancedTransaction)
            })?;
        let amount = ledger
            .balance(&hold)
            .checked_sub(required_remaining)
            .ok_or(CoreError::InsufficientBalance)?;
        if amount > 0 {
            transfers.push(Transfer {
                from: hold,
                to: destination,
                amount,
            });
        }
    }
    Ok(transfers)
}

fn available(owner: &str, asset: &str) -> AccountKey {
    AccountKey::new(owner, AccountBucket::UserAvailable, asset)
}

fn fee_revenue(asset: &str) -> AccountKey {
    AccountKey::new("layrs", AccountBucket::FeeRevenue, asset)
}

fn market_collateral(market_id: &str, asset: &str) -> AccountKey {
    let mut account = AccountKey::new("layrs", AccountBucket::MarketCollateral, asset);
    account.market_id = Some(market_id.into());
    account
}

fn cash_hold(order: &BookOrder, asset: &str) -> AccountKey {
    let mut account = AccountKey::new(&order.private_user_id, AccountBucket::UserOrderHold, asset);
    account.market_id = Some(order.market_id.clone());
    account.outcome = Some(outcome_name(order.outcome).into());
    account
}

fn claim_asset(market_id: &str, outcome: Outcome) -> String {
    format!("CLAIM:{market_id}:{}", outcome_name(outcome))
}

fn claim_position(order: &BookOrder) -> AccountKey {
    claim_position_for(&order.private_user_id, &order.market_id, order.outcome)
}

fn claim_position_for(owner: &str, market_id: &str, outcome: Outcome) -> AccountKey {
    AccountKey::position(
        owner,
        claim_asset(market_id, outcome),
        market_id,
        outcome_name(outcome),
    )
}

fn claim_hold(order: &BookOrder) -> AccountKey {
    let mut account = AccountKey::new(
        &order.private_user_id,
        AccountBucket::UserOrderHold,
        claim_asset(&order.market_id, order.outcome),
    );
    account.market_id = Some(order.market_id.clone());
    account.outcome = Some(outcome_name(order.outcome).into());
    account
}

fn bootstrap_reservation(order: &BookOrder, market: &MarketConfig) -> CoreResult<u128> {
    match order.action {
        OrderAction::Buy => {
            let maximum_notional = notional(order.price_micros, order.quantity_micros)?;
            settlement_atomic(market, maximum_notional)?
                .checked_add(settlement_atomic(market, ceil_bps(maximum_notional, 20)?)?)
                .ok_or(CoreError::UnbalancedTransaction)
        }
        OrderAction::Sell => Ok(order.quantity_micros),
    }
}

fn enforce_user_position_limit(
    ledger: &Ledger,
    books: &BTreeMap<String, PriceTimeBook>,
    bootstrap_executions: &BTreeMap<Uuid, BootstrapExecution>,
    market: &MarketConfig,
    order: &BookOrder,
) -> CoreResult<()> {
    if order.action != OrderAction::Buy {
        return Ok(());
    }
    let current_position = ledger.total_for_owner_asset(
        &order.private_user_id,
        &claim_asset(&order.market_id, order.outcome),
    );
    let native_resting_buys = books
        .get(&order.market_id)
        .map(|book| {
            book.orders_for_owner(&order.private_user_id)
                .into_iter()
                .filter(|resting| {
                    resting.outcome == order.outcome
                        && resting.action == OrderAction::Buy
                        && matches!(
                            resting.status,
                            OrderStatus::Open | OrderStatus::PartiallyFilled
                        )
                })
                .try_fold(0u128, |total, resting| {
                    total
                        .checked_add(resting.remaining_micros)
                        .ok_or(CoreError::UnbalancedTransaction)
                })
        })
        .transpose()?
        .unwrap_or_default();
    let pending_bootstrap_buys = bootstrap_executions
        .values()
        .filter(|execution| {
            execution.private_user_id == order.private_user_id
                && execution.view.market_id == order.market_id
                && execution.view.outcome == order.outcome
                && execution.view.action == OrderAction::Buy
                && matches!(
                    execution.view.state,
                    BootstrapExecutionState::FundsReserved
                        | BootstrapExecutionState::VenueSubmitted
                )
        })
        .try_fold(0u128, |total, execution| {
            total
                .checked_add(execution.view.quantity_micros)
                .ok_or(CoreError::UnbalancedTransaction)
        })?;
    let projected = current_position
        .checked_add(native_resting_buys)
        .and_then(|value| value.checked_add(pending_bootstrap_buys))
        .and_then(|value| value.checked_add(order.quantity_micros))
        .ok_or(CoreError::UnbalancedTransaction)?;
    if projected > market.maximum_user_position_micros {
        return Err(CoreError::InvalidOrder(
            "order exceeds the user position limit".into(),
        ));
    }
    Ok(())
}

fn enforce_pending_bootstrap_limit(
    bootstrap_executions: &BTreeMap<Uuid, BootstrapExecution>,
    market: &MarketConfig,
    order: &BookOrder,
) -> CoreResult<()> {
    let pending = bootstrap_executions
        .values()
        .filter(|execution| {
            execution.view.market_id == order.market_id
                && matches!(
                    execution.view.state,
                    BootstrapExecutionState::FundsReserved
                        | BootstrapExecutionState::VenueSubmitted
                )
        })
        .try_fold(0u128, |total, execution| {
            total
                .checked_add(notional(
                    execution.view.limit_price_micros,
                    execution.view.quantity_micros,
                )?)
                .ok_or(CoreError::UnbalancedTransaction)
        })?;
    let projected = pending
        .checked_add(notional(order.price_micros, order.quantity_micros)?)
        .ok_or(CoreError::UnbalancedTransaction)?;
    if projected > market.maximum_pending_bootstrap_notional_micros {
        return Err(CoreError::InvalidOrder(
            "order exceeds the pending venue exposure limit".into(),
        ));
    }
    Ok(())
}

fn bootstrap_order_salt(execution_id: Uuid) -> u64 {
    let digest = Sha256::digest(
        [
            b"layrs.polymarket-order-salt.v1\0".as_slice(),
            execution_id.as_bytes(),
        ]
        .concat(),
    );
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    (u64::from_be_bytes(bytes) & ((1u64 << 53) - 1)).max(1)
}

fn bootstrap_hold(execution: &BootstrapExecution, market: &MarketConfig) -> AccountKey {
    let synthetic = BookOrder::with_id(
        execution.view.execution_id,
        &execution.private_user_id,
        &execution.view.market_id,
        execution.view.outcome,
        execution.view.action,
        execution.view.limit_price_micros,
        execution.view.quantity_micros,
        super::TimeInForce::Fok,
        None,
    );
    match execution.view.action {
        OrderAction::Buy => cash_hold(&synthetic, &market.settlement_asset),
        OrderAction::Sell => claim_hold(&synthetic),
    }
}

fn release_bootstrap_hold(
    ledger: &mut Ledger,
    execution: &BootstrapExecution,
    market: &MarketConfig,
    idempotency_key: &str,
    business_reference: &str,
) -> CoreResult<()> {
    let destination = match execution.view.action {
        OrderAction::Buy => available(&execution.private_user_id, &market.settlement_asset),
        OrderAction::Sell => claim_position_for(
            &execution.private_user_id,
            &execution.view.market_id,
            execution.view.outcome,
        ),
    };
    ledger.apply(LedgerTransaction {
        idempotency_key: idempotency_key.into(),
        business_reference: business_reference.into(),
        transfers: vec![Transfer {
            from: bootstrap_hold(execution, market),
            to: destination,
            amount: execution.reserved_atomic,
        }],
    })?;
    Ok(())
}

fn venue_inventory(market_id: &str, outcome: Outcome, asset: &str) -> AccountKey {
    let mut account = AccountKey::new("polymarket", AccountBucket::VenueInventory, asset);
    account.market_id = Some(market_id.into());
    account.outcome = Some(outcome_name(outcome).into());
    account
}

fn outcome_name(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::Up => "UP",
        Outcome::Down => "DOWN",
    }
}

fn notional(price_micros: u64, quantity_micros: u128) -> CoreResult<u128> {
    let product = u128::from(price_micros)
        .checked_mul(quantity_micros)
        .ok_or(CoreError::UnbalancedTransaction)?;
    Ok(product
        .checked_add(PRICE_SCALE - 1)
        .ok_or(CoreError::UnbalancedTransaction)?
        / PRICE_SCALE)
}

fn settlement_atomic(market: &MarketConfig, amount_micros: u128) -> CoreResult<u128> {
    let scale = match market.settlement_decimals {
        6 => 1,
        18 => 1_000_000_000_000,
        _ => {
            return Err(CoreError::InvalidOrder(
                "unsupported settlement decimals".into(),
            ))
        }
    };
    amount_micros
        .checked_mul(scale)
        .ok_or(CoreError::UnbalancedTransaction)
}

fn ceil_bps(amount: u128, bps: u128) -> CoreResult<u128> {
    if amount == 0 || bps == 0 {
        return Ok(0);
    }
    amount
        .checked_mul(bps)
        .and_then(|value| value.checked_add(9_999))
        .map(|value| value / 10_000)
        .ok_or(CoreError::UnbalancedTransaction)
}

fn native_audit_drafts(
    incoming: &BookOrder,
    result: &MatchResult,
    market: &MarketConfig,
) -> CoreResult<Vec<AuditFillDraft>> {
    let chain = effective_public_settlement_chain(market)?;
    result
        .fills
        .iter()
        .map(|fill| {
            // The audit rail records the incoming taker's execution price.
            // For complete-set fills this is the exact complement of the
            // resting maker price, while NORMAL remains unchanged.
            let taker_price_micros = fill.taker_price_micros();
            let fill_notional = notional(taker_price_micros, fill.quantity_micros)?;
            let (buyer, seller) = match incoming.action {
                OrderAction::Buy => (
                    fill.taker_private_user_id.clone(),
                    fill.maker_private_user_id.clone(),
                ),
                OrderAction::Sell => (
                    fill.maker_private_user_id.clone(),
                    fill.taker_private_user_id.clone(),
                ),
            };
            Ok(AuditFillDraft {
                fill_id: fill.fill_id,
                chain: chain.into(),
                market_id: fill.market_id.clone(),
                buyer_private_user_id: buyer,
                seller_private_user_id: seller,
                quantity_atomic: fill.quantity_micros,
                price_micros: taker_price_micros,
                outcome: outcome_name(fill.outcome).into(),
                match_type: match fill.match_type {
                    MatchType::Normal => "NORMAL",
                    MatchType::Mint => "MINT",
                    MatchType::Merge => "MERGE",
                }
                .into(),
                fee_atomic: settlement_atomic(market, ceil_bps(fill_notional, 20)?)?,
                nonce: fill.sequence,
            })
        })
        .collect()
}

fn effective_public_settlement_chain(market: &MarketConfig) -> CoreResult<&str> {
    if let Some(chain) = market.public_settlement_chain.as_deref() {
        return match chain {
            "base" | "horizen" => Ok(chain),
            _ => Err(CoreError::InvalidOrder(
                "unsupported public settlement chain".into(),
            )),
        };
    }
    match market.settlement_asset.as_str() {
        "USDC" => Ok("base"),
        "ZEN" => Ok("horizen"),
        _ => Err(CoreError::InvalidOrder(
            "unsupported public settlement asset".into(),
        )),
    }
}

fn redact_match_result(mut result: MatchResult) -> MatchResult {
    if let Some(order) = result.accepted_order.as_mut() {
        order.private_user_id.clear();
    }
    for fill in &mut result.fills {
        fill.maker_private_user_id.clear();
        fill.taker_private_user_id.clear();
    }
    result
}

fn signed_audit_fills(
    signer: &ReceiptSigner,
    identity_key: &[u8; 32],
    receipt: &EnclaveReceipt,
    drafts: Vec<AuditFillDraft>,
) -> CoreResult<Vec<SignedAuditFillArtifact>> {
    drafts
        .into_iter()
        .map(|draft| {
            if draft.price_micros == 0
                || draft.price_micros >= PRICE_SCALE as u64
                || draft.price_micros % 100 != 0
            {
                return Err(CoreError::InvalidOrder(
                    "fill price cannot be represented by the audited settlement rail".into(),
                ));
            }
            let statement = AuditFillStatement {
                protocol_version: "layrs.audit-fill.v1".into(),
                chain: draft.chain,
                market_id_bytes32: market_id_bytes32(&draft.market_id),
                market_id: draft.market_id,
                buyer_one_time_pseudonym: one_time_pseudonym(
                    identity_key,
                    draft.fill_id,
                    b"buyer",
                    &draft.buyer_private_user_id,
                ),
                seller_one_time_pseudonym: one_time_pseudonym(
                    identity_key,
                    draft.fill_id,
                    b"seller",
                    &draft.seller_private_user_id,
                ),
                quantity_atomic: draft.quantity_atomic.to_string(),
                price_micros: draft.price_micros,
                outcome: Some(draft.outcome),
                match_type: Some(draft.match_type),
                fee_atomic: draft.fee_atomic.to_string(),
                nonce: draft.nonce.to_string(),
            };
            let mut artifact = SignedAuditFillArtifact {
                statement,
                receipt_id: receipt.receipt_id.clone(),
                state_root: receipt.state_root,
                receipt_public_key: signer.verifying_key(),
                signature: Vec::new(),
            };
            artifact.signature =
                signer.sign_domain_payload(b"layrs.audit-fill-artifact.v1\0", &artifact);
            Ok(artifact)
        })
        .collect()
}

fn one_time_pseudonym(
    identity_key: &[u8; 32],
    fill_id: Uuid,
    role: &[u8],
    private_user_id: &str,
) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(identity_key)
        .expect("HMAC accepts the fixed identity key");
    mac.update(b"layrs.audit-one-time-pseudonym.v1\0");
    mac.update(fill_id.as_bytes());
    mac.update(&(role.len() as u32).to_be_bytes());
    mac.update(role);
    mac.update(private_user_id.as_bytes());
    let digest = mac.finalize().into_bytes();
    let mut address = [0u8; 20];
    address.copy_from_slice(&digest[digest.len() - 20..]);
    if address == [0u8; 20] {
        address[19] = 1;
    }
    format!("0x{}", hex::encode(address))
}

fn market_id_bytes32(market_id: &str) -> String {
    let mut hash = Keccak::v256();
    let mut output = [0u8; 32];
    hash.update(market_id.as_bytes());
    hash.finalize(&mut output);
    format!("0x{}", hex::encode(output))
}

fn validate_market(market: &MarketConfig, now_millis: i64) -> CoreResult<()> {
    if !valid_market_namespace(&market.market_id)
        || !matches!(
            (market.settlement_asset.as_str(), market.settlement_decimals),
            ("USDC", 6) | ("ZEN", 18)
        )
        || effective_public_settlement_chain(market).is_err()
        || market.opens_at_millis >= market.closes_at_millis
        || market.closes_at_millis <= now_millis
        || market.minimum_quantity_micros == 0
        || market.minimum_quantity_micros > market.maximum_quantity_micros
        || market.minimum_order_notional_micros == 0
        || market.minimum_order_notional_micros > market.maximum_order_notional_micros
        || market.maximum_order_notional_micros == 0
        || market.maximum_user_position_micros < market.maximum_quantity_micros
        || market.maximum_pending_bootstrap_notional_micros < market.maximum_order_notional_micros
        || market.tick_size_micros == 0
        || market.tick_size_micros >= PRICE_SCALE as u64
        || !market.tick_size_micros.is_multiple_of(100)
        || market.oracle_feed_id == 0
    {
        return Err(CoreError::InvalidOrder(
            "invalid market configuration".into(),
        ));
    }
    if let MarketExecution::PolymarketBootstrap {
        condition_id,
        up_token_id,
        down_token_id,
        up_outcome_index,
        down_outcome_index,
        ..
    } = &market.execution
    {
        if market.settlement_asset != "USDC"
            || !valid_hex32(condition_id)
            || !valid_decimal_token_id(up_token_id)
            || !valid_decimal_token_id(down_token_id)
            || up_token_id == down_token_id
            || up_outcome_index == down_outcome_index
        {
            return Err(CoreError::InvalidOrder(
                "invalid Polymarket bootstrap mapping".into(),
            ));
        }
    }
    Ok(())
}

fn valid_market_namespace(market_id: &str) -> bool {
    market_id.starts_with("layrs:v1:")
        || market_id.starts_with("layrs:v2:")
        || market_id.starts_with("layrs:v3:")
        || ["SPORTS", "ESPORTS", "POLITICS"]
            .iter()
            .any(|category| market_id.starts_with(&format!("layrs:v4:{category}:")))
}

fn valid_hex32(value: &str) -> bool {
    value.len() == 66
        && value.starts_with("0x")
        && value[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_decimal_token_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 78
        && !(value.len() > 1 && value.starts_with('0'))
        && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn validate_resolution(
    market: &MarketConfig,
    signed: &SignedResolution,
    oracle_public_key: Option<[u8; 32]>,
    now_millis: i64,
) -> CoreResult<()> {
    if !matches!(market.execution, MarketExecution::NativeClob) {
        return Err(CoreError::InvalidResolution(
            "Pyth boundary resolution is valid only for native markets".into(),
        ));
    }
    let statement = &signed.statement;
    if now_millis < market.closes_at_millis
        || statement.market_id != market.market_id
        || statement.oracle_feed_id != market.oracle_feed_id
        || statement.issued_at_millis < market.closes_at_millis
        || statement.issued_at_millis > now_millis + 30_000
    {
        return Err(CoreError::InvalidResolution(
            "resolution timing or identity is invalid".into(),
        ));
    }
    validate_boundary(&statement.opening, market.opens_at_millis)?;
    validate_boundary(&statement.closing, market.closes_at_millis)?;
    let key =
        VerifyingKey::from_bytes(&oracle_public_key.ok_or(CoreError::InvalidOracleSignature)?)
            .map_err(|_| CoreError::InvalidOracleSignature)?;
    let signature_bytes: [u8; 64] = signed
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| CoreError::InvalidOracleSignature)?;
    key.verify(
        &resolution_signing_payload(statement)?,
        &Signature::from_bytes(&signature_bytes),
    )
    .map_err(|_| CoreError::InvalidOracleSignature)
}

fn validate_polymarket_resolution(
    market: &MarketConfig,
    signed: &SignedPolymarketResolution,
    oracle_public_key: Option<[u8; 32]>,
    now_millis: i64,
) -> CoreResult<()> {
    let MarketExecution::PolymarketBootstrap { condition_id, .. } = &market.execution else {
        return Err(CoreError::InvalidResolution(
            "Polymarket condition resolution is valid only for bootstrap markets".into(),
        ));
    };
    let statement = &signed.statement;
    if now_millis < market.closes_at_millis
        || statement.market_id != market.market_id
        || &statement.condition_id != condition_id
        || statement.evidence_hash == [0u8; 32]
        || statement.redemption_transaction_hash == [0u8; 32]
        || statement.redemption_block_number == 0
        || statement.issued_at_millis < market.closes_at_millis
        || statement.issued_at_millis > now_millis + 30_000
    {
        return Err(CoreError::InvalidResolution(
            "Polymarket resolution timing, condition, or evidence is invalid".into(),
        ));
    }
    let key =
        VerifyingKey::from_bytes(&oracle_public_key.ok_or(CoreError::InvalidOracleSignature)?)
            .map_err(|_| CoreError::InvalidOracleSignature)?;
    let signature_bytes: [u8; 64] = signed
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| CoreError::InvalidOracleSignature)?;
    key.verify(
        &polymarket_resolution_signing_payload(statement)?,
        &Signature::from_bytes(&signature_bytes),
    )
    .map_err(|_| CoreError::InvalidOracleSignature)
}

fn validate_boundary(boundary: &BoundaryEvidence, target_millis: i64) -> CoreResult<()> {
    let target_micros = target_millis
        .checked_mul(1_000)
        .ok_or_else(|| CoreError::InvalidResolution("boundary time overflow".into()))?;
    if boundary.window_end_micros != target_micros
        || boundary.window_start_micros != target_micros - 5_000_000
        || boundary.sample_count != 25
        || boundary.minimum_publisher_count < 3
        || boundary.median_price_e8 <= 0
        || boundary.signed_payload_commitment == [0u8; 32]
    {
        return Err(CoreError::InvalidResolution(
            "Pyth boundary does not satisfy the 25-sample median policy".into(),
        ));
    }
    Ok(())
}

pub fn resolution_signing_payload(statement: &ResolutionStatement) -> CoreResult<Vec<u8>> {
    let encoded = serde_json::to_vec(statement)
        .map_err(|_| CoreError::InvalidResolution("cannot encode resolution".into()))?;
    let mut payload = Vec::with_capacity(encoded.len() + 40);
    payload.extend_from_slice(b"layrs.pyth-resolution.v1\0");
    payload.extend_from_slice(&(encoded.len() as u64).to_be_bytes());
    payload.extend_from_slice(&encoded);
    Ok(payload)
}

pub fn polymarket_resolution_signing_payload(
    statement: &PolymarketResolutionStatement,
) -> CoreResult<Vec<u8>> {
    let encoded = serde_json::to_vec(statement)
        .map_err(|_| CoreError::InvalidResolution("cannot encode resolution".into()))?;
    let mut payload = Vec::with_capacity(encoded.len() + 48);
    payload.extend_from_slice(b"layrs.polymarket-resolution.v1\0");
    payload.extend_from_slice(&(encoded.len() as u64).to_be_bytes());
    payload.extend_from_slice(&encoded);
    Ok(payload)
}

fn validate_order_for_market(
    order: &BookOrder,
    market: &MarketConfig,
    now_millis: i64,
) -> CoreResult<()> {
    if now_millis < market.opens_at_millis || now_millis >= market.closes_at_millis {
        return Err(CoreError::InvalidOrder("market is not open".into()));
    }
    if order.quantity_micros < market.minimum_quantity_micros
        || order.quantity_micros > market.maximum_quantity_micros
        || !order.price_micros.is_multiple_of(market.tick_size_micros)
    {
        return Err(CoreError::InvalidOrder(
            "order violates market limits".into(),
        ));
    }
    let order_notional = notional(order.price_micros, order.quantity_micros)?;
    if order_notional < market.minimum_order_notional_micros
        || order_notional > market.maximum_order_notional_micros
    {
        return Err(CoreError::InvalidOrder(
            "order violates the notional limits".into(),
        ));
    }
    if order
        .expires_at_millis
        .is_some_and(|expiry| expiry > market.closes_at_millis)
    {
        return Err(CoreError::InvalidOrder(
            "order survives its recurring window".into(),
        ));
    }
    Ok(())
}

fn checked_sequence(sequence: u64) -> CoreResult<u64> {
    sequence
        .checked_add(1)
        .ok_or(CoreError::UnbalancedTransaction)
}

fn validate_withdrawal(
    chain: &str,
    asset: &str,
    amount: u128,
    destination: &str,
) -> CoreResult<()> {
    if amount == 0
        || !matches!(
            (chain, asset),
            ("base", "USDC") | ("base", "ZEN") | ("horizen", "ZEN")
        )
        || !destination.starts_with("0x")
        || destination.len() != 42
        || !destination[2..]
            .bytes()
            .all(|value| value.is_ascii_hexdigit())
    {
        return Err(CoreError::InvalidOrder("invalid withdrawal request".into()));
    }
    Ok(())
}

fn derive_private_user_id(identity_key: &[u8; 32], commitment: &[u8; 32]) -> String {
    let mut hash = Sha256::new();
    hash.update(b"layrs.private-user-id.v1\0");
    hash.update(identity_key);
    hash.update(commitment);
    format!("usr_{}", hex::encode(hash.finalize()))
}

fn portfolio_snapshot(
    ledger: &Ledger,
    books: &BTreeMap<String, PriceTimeBook>,
    cost_basis: &BTreeMap<PositionKey, u128>,
    owner: &str,
    now_millis: i64,
) -> PortfolioSnapshot {
    let mut balances = Vec::new();
    let mut positions = Vec::new();
    for (account, amount) in ledger.balances_for_owner(owner) {
        if account.bucket == AccountBucket::UserPosition {
            if let (Some(market_id), Some(outcome)) = (account.market_id, account.outcome) {
                let parsed = if outcome == "UP" {
                    Outcome::Up
                } else {
                    Outcome::Down
                };
                positions.push(PrivatePosition {
                    cost_basis_micros: cost_basis
                        .get(&position_key(owner, &market_id, parsed))
                        .copied()
                        .unwrap_or_default()
                        .to_string(),
                    market_id,
                    outcome,
                    quantity_micros: amount.to_string(),
                });
            }
        } else {
            balances.push(PrivateBalance {
                asset: account.asset,
                bucket: account.bucket,
                amount_atomic: amount.to_string(),
            });
        }
    }
    let mut orders: Vec<BookOrder> = books
        .values()
        .flat_map(|book| book.orders_for_owner(owner))
        .collect();
    for order in &mut orders {
        order.private_user_id.clear();
    }
    orders.sort_by_key(|order| (order.market_id.clone(), order.sequence));
    PortfolioSnapshot {
        balances,
        positions,
        orders,
        as_of_millis: now_millis,
    }
}

fn processed_hashes(processed: &BTreeMap<String, ProcessedCommand>) -> BTreeMap<String, [u8; 32]> {
    processed
        .iter()
        .map(|(key, value)| (key.clone(), value.request_hash))
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn state_root(
    ledger: &Ledger,
    books: &BTreeMap<String, PriceTimeBook>,
    markets: &BTreeMap<String, MarketConfig>,
    sessions: &SessionGuard,
    processed: &BTreeMap<String, [u8; 32]>,
    system_keys: &BTreeSet<String>,
    position_cost_basis: &BTreeMap<PositionKey, u128>,
    resolutions: &BTreeMap<String, MarketResolution>,
    oracle_public_key: &Option<[u8; 32]>,
    bootstrap_executions: &BTreeMap<Uuid, BootstrapExecution>,
    private_rewards: &PrivateRewardBook,
    trading_frozen: bool,
    sequence: u64,
) -> [u8; 32] {
    state_root_with_serialized_books(
        ledger,
        serde_json::to_vec(books).expect("private core book serialization cannot fail"),
        markets,
        sessions,
        processed,
        system_keys,
        position_cost_basis,
        resolutions,
        oracle_public_key,
        bootstrap_executions,
        private_rewards,
        trading_frozen,
        sequence,
    )
}

#[allow(clippy::too_many_arguments)]
fn legacy_state_root(
    ledger: &Ledger,
    books: &BTreeMap<String, PriceTimeBook>,
    markets: &BTreeMap<String, MarketConfig>,
    sessions: &SessionGuard,
    processed: &BTreeMap<String, [u8; 32]>,
    system_keys: &BTreeSet<String>,
    position_cost_basis: &BTreeMap<PositionKey, u128>,
    resolutions: &BTreeMap<String, MarketResolution>,
    oracle_public_key: &Option<[u8; 32]>,
    bootstrap_executions: &BTreeMap<Uuid, BootstrapExecution>,
    private_rewards: &PrivateRewardBook,
    trading_frozen: bool,
    sequence: u64,
) -> [u8; 32] {
    state_root_with_serialized_books(
        ledger,
        serialize_legacy_books(books).expect("legacy private core book serialization cannot fail"),
        markets,
        sessions,
        processed,
        system_keys,
        position_cost_basis,
        resolutions,
        oracle_public_key,
        bootstrap_executions,
        private_rewards,
        trading_frozen,
        sequence,
    )
}

/// Reproduces the state-root layout used by production release
/// `2b85c2aaa6143395e69c5deea2f7423356a15cd0`. That release predates both
/// cumulative fill history and private reward accounting, so neither field may
/// be introduced while verifying its encrypted checkpoint.
#[allow(clippy::too_many_arguments)]
fn production_legacy_state_root(
    ledger: &Ledger,
    books: &BTreeMap<String, PriceTimeBook>,
    markets: &BTreeMap<String, MarketConfig>,
    sessions: &SessionGuard,
    processed: &BTreeMap<String, [u8; 32]>,
    system_keys: &BTreeSet<String>,
    position_cost_basis: &BTreeMap<PositionKey, u128>,
    resolutions: &BTreeMap<String, MarketResolution>,
    oracle_public_key: &Option<[u8; 32]>,
    bootstrap_executions: &BTreeMap<Uuid, BootstrapExecution>,
    trading_frozen: bool,
    sequence: u64,
) -> [u8; 32] {
    let mut hash = Keccak::v256();
    hash.update(b"layrs.private-trading-core.v1\0");
    hash.update(&sequence.to_be_bytes());
    hash.update(&[u8::from(trading_frozen)]);
    hash.update(&ledger.state_root());
    for value in [
        serialize_legacy_books(books),
        serde_json::to_vec(markets),
        serde_json::to_vec(sessions),
        serde_json::to_vec(processed),
        serde_json::to_vec(system_keys),
        serde_json::to_vec(&position_cost_basis.iter().collect::<Vec<_>>()),
        serde_json::to_vec(resolutions),
        serde_json::to_vec(oracle_public_key),
        serde_json::to_vec(bootstrap_executions),
    ] {
        let encoded = value.expect("production legacy state serialization cannot fail");
        hash.update(&(encoded.len() as u64).to_be_bytes());
        hash.update(&encoded);
    }
    let mut output = [0u8; 32];
    hash.finalize(&mut output);
    output
}

#[allow(clippy::too_many_arguments)]
fn state_root_with_serialized_books(
    ledger: &Ledger,
    serialized_books: Vec<u8>,
    markets: &BTreeMap<String, MarketConfig>,
    sessions: &SessionGuard,
    processed: &BTreeMap<String, [u8; 32]>,
    system_keys: &BTreeSet<String>,
    position_cost_basis: &BTreeMap<PositionKey, u128>,
    resolutions: &BTreeMap<String, MarketResolution>,
    oracle_public_key: &Option<[u8; 32]>,
    bootstrap_executions: &BTreeMap<Uuid, BootstrapExecution>,
    private_rewards: &PrivateRewardBook,
    trading_frozen: bool,
    sequence: u64,
) -> [u8; 32] {
    let mut hash = Keccak::v256();
    hash.update(b"layrs.private-trading-core.v1\0");
    hash.update(&sequence.to_be_bytes());
    hash.update(&[u8::from(trading_frozen)]);
    hash.update(&ledger.state_root());
    for value in [
        Ok(serialized_books),
        serde_json::to_vec(markets),
        serde_json::to_vec(sessions),
        serde_json::to_vec(processed),
        serde_json::to_vec(system_keys),
        serde_json::to_vec(&position_cost_basis.iter().collect::<Vec<_>>()),
        serde_json::to_vec(resolutions),
        serde_json::to_vec(oracle_public_key),
        serde_json::to_vec(bootstrap_executions),
        serde_json::to_vec(private_rewards),
    ] {
        let encoded = value.expect("private core state serialization cannot fail");
        hash.update(&(encoded.len() as u64).to_be_bytes());
        hash.update(&encoded);
    }
    let mut output = [0u8; 32];
    hash.finalize(&mut output);
    output
}

fn withdrawal_reservation_marker(
    session_id: &str,
    withdrawal_id: Uuid,
    chain: &str,
    asset: &str,
    amount_atomic: &str,
    destination: &str,
) -> CoreResult<String> {
    if session_id.is_empty()
        || session_id.len() > 128
        || !matches!(
            (chain, asset),
            ("base", "USDC") | ("base", "ZEN") | ("horizen", "ZEN")
        )
        || !amount_atomic.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(CoreError::InvalidOrder(
            "invalid withdrawal reservation".into(),
        ));
    }
    let canonical = serde_json::to_vec(&(
        "layrs.withdrawal-reservation.v1",
        session_id,
        withdrawal_id,
        chain,
        asset,
        amount_atomic,
        destination.to_ascii_lowercase(),
    ))
    .map_err(|_| CoreError::InvalidOrder("invalid withdrawal reservation".into()))?;
    Ok(format!(
        "withdrawal-reservation:{withdrawal_id}:{}",
        hex::encode(Sha256::digest(canonical)),
    ))
}

#[cfg(test)]
fn remove_json_field(value: &mut serde_json::Value, field: &str) {
    match value {
        serde_json::Value::Array(values) => {
            for value in values {
                remove_json_field(value, field);
            }
        }
        serde_json::Value::Object(values) => {
            values.remove(field);
            for value in values.values_mut() {
                remove_json_field(value, field);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod snapshot_migration_tests {
    use super::*;
    use crate::private_core::TimeInForce;

    #[test]
    fn restores_legacy_book_root_and_reconstructs_deterministic_fill_history() {
        let journal_key = JournalKey::from_bytes([201u8; 32]);
        let mut core =
            PrivateTradingCore::new(journal_key.clone(), ReceiptSigner::generate([202u8; 48]));
        let mut book = PriceTimeBook::default();
        let market_id = "layrs:v3:ZEN:15m:legacy-root";
        book.submit(
            BookOrder::new(
                "maker",
                market_id,
                Outcome::Up,
                OrderAction::Sell,
                400_000,
                1_000_000,
                TimeInForce::Gtc,
                None,
            ),
            1_000,
        )
        .unwrap();
        book.submit(
            BookOrder::new(
                "taker",
                market_id,
                Outcome::Up,
                OrderAction::Buy,
                400_000,
                1_000_000,
                TimeInForce::Gtc,
                None,
            ),
            1_001,
        )
        .unwrap();
        core.books.insert(market_id.into(), book);

        let current_root = core.state_root();
        let legacy = core.export_legacy_fill_history_snapshot_for_test().unwrap();
        assert_ne!(legacy.state_root, current_root);

        let restored = PrivateTradingCore::restore_encrypted_snapshot(
            journal_key,
            ReceiptSigner::generate([203u8; 48]),
            &legacy,
            0,
        )
        .unwrap();
        assert_eq!(restored.state_root(), current_root);
        let mut orders = restored.books[market_id].orders_for_owner("maker");
        orders.extend(restored.books[market_id].orders_for_owner("taker"));
        assert_eq!(orders.len(), 2);
        assert!(orders
            .iter()
            .all(|order| order.filled_micros == order.quantity_micros));
    }

    #[test]
    fn restores_actual_production_lineage_without_private_reward_root() {
        let journal_key = JournalKey::from_bytes([207u8; 32]);
        let mut core =
            PrivateTradingCore::new(journal_key.clone(), ReceiptSigner::generate([208u8; 48]));
        let mut book = PriceTimeBook::default();
        let market_id = "layrs:v3:ZEN:15m:production-legacy-root";
        book.submit(
            BookOrder::new(
                "maker",
                market_id,
                Outcome::Down,
                OrderAction::Sell,
                600_000,
                2_000_000,
                TimeInForce::Gtc,
                None,
            ),
            1_000,
        )
        .unwrap();
        book.submit(
            BookOrder::new(
                "taker",
                market_id,
                Outcome::Down,
                OrderAction::Buy,
                600_000,
                1_000_000,
                TimeInForce::Gtc,
                None,
            ),
            1_001,
        )
        .unwrap();
        core.books.insert(market_id.into(), book);

        let current_root = core.state_root();
        let production = core.export_production_legacy_snapshot_for_test().unwrap();
        assert_ne!(production.state_root, current_root);

        let restored = PrivateTradingCore::restore_encrypted_snapshot(
            journal_key,
            ReceiptSigner::generate([209u8; 48]),
            &production,
            0,
        )
        .unwrap();
        assert_eq!(restored.state_root(), current_root);
        let maker = restored.books[market_id]
            .orders_for_owner("maker")
            .pop()
            .unwrap();
        let taker = restored.books[market_id]
            .orders_for_owner("taker")
            .pop()
            .unwrap();
        assert_eq!(maker.filled_micros, 1_000_000);
        assert_eq!(taker.filled_micros, 1_000_000);
    }

    #[test]
    fn rejects_legacy_fak_partial_fill_that_cannot_be_reconstructed() {
        let journal_key = JournalKey::from_bytes([204u8; 32]);
        let mut core =
            PrivateTradingCore::new(journal_key.clone(), ReceiptSigner::generate([205u8; 48]));
        let mut book = PriceTimeBook::default();
        let market_id = "layrs:v3:ZEN:15m:legacy-fak";
        book.submit(
            BookOrder::new(
                "maker",
                market_id,
                Outcome::Up,
                OrderAction::Sell,
                400_000,
                400_000,
                TimeInForce::Gtc,
                None,
            ),
            1_000,
        )
        .unwrap();
        let partial = book
            .submit(
                BookOrder::new(
                    "taker",
                    market_id,
                    Outcome::Up,
                    OrderAction::Buy,
                    400_000,
                    1_000_000,
                    TimeInForce::Fak,
                    None,
                ),
                1_001,
            )
            .unwrap()
            .accepted_order
            .unwrap();
        assert_eq!(partial.status, OrderStatus::PartiallyFilled);
        core.books.insert(market_id.into(), book);
        let legacy = core.export_legacy_fill_history_snapshot_for_test().unwrap();

        assert!(matches!(
            PrivateTradingCore::restore_encrypted_snapshot(
                journal_key,
                ReceiptSigner::generate([206u8; 48]),
                &legacy,
                0,
            ),
            Err(CoreError::SnapshotMigrationRequired)
        ));
    }
}
