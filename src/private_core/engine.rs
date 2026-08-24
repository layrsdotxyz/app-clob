use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use ethers_core::types::U256;
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
    command_result_commitment, AccountBucket, AccountKey, BookOrder, ClaimPayout,
    CommandReceiptState, CompleteSetDirection, CompleteSetFillPosting, CompleteSetTransaction,
    CoreError, CoreResult, CustodyLedgerTotal, EnclaveReceipt, EncryptedJournal,
    EncryptedJournalRecord, EncryptedSnapshot, ExternalFlowDirection, ExternalFlowTransaction,
    Fill, JournalKey, Ledger, LedgerTransaction, MatchResult, MatchType, NormalFillPosting,
    OrderAction, OrderStatus, Outcome, PoolCashOpening, PriceTimeBook, PublicAssetTotal,
    PublicBucketTotal, ReceiptSigner, ResolutionPayoutKind, SessionGuard, SignedSessionRequest,
    TimeInForce, Transfer, VaultStrategyTransaction, VaultStrategyTransition, PRICE_SCALE,
};

/// Public depth is deliberately less precise than the enclave's private book.
/// A level must contain liquidity from at least this many independent private
/// owners before it can leave the enclave. This prevents a thin public level
/// from acting as an oracle for one user's exact order size and arrival time.
const MIN_PUBLIC_DEPTH_DISTINCT_OWNERS: usize = 3;
/// Position-close quotes are deliberately short lived. They commit to the
/// exact private book state and economics seen by the enclave, so a quote can
/// neither be replayed after the book moves nor extended by an API client.
const POSITION_CLOSE_QUOTE_TTL_MILLIS: i64 = 30_000;

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
    /// Immutable settlement-fee policy selected by the signed market release.
    /// Older snapshots and releases intentionally default to the legacy policy.
    #[serde(default, skip_serializing_if = "FeeProfileId::is_legacy")]
    pub fee_profile_id: FeeProfileId,
    /// Determines where price discovery happens. The default preserves the native ZEN CLOB.
    #[serde(default)]
    pub execution: MarketExecution,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FeeProfileId {
    #[default]
    LegacyProfitV1,
    CryptoV1,
    MacroV1,
    FinanceV1,
    PoliticsV1,
    SportsV1,
    EsportsV1,
    WeatherV1,
    TechnologyV1,
    ScienceV1,
    CultureV1,
    BusinessV1,
    GeopoliticsV1,
    GeneralV1,
    PolymarketCryptoV2,
    PolymarketMacroV2,
    PolymarketFinanceV2,
    PolymarketPoliticsV2,
    PolymarketSportsV2,
    PolymarketEsportsV2,
    PolymarketWeatherV2,
    PolymarketTechnologyV2,
    PolymarketMentionsV2,
    PolymarketScienceV2,
    PolymarketCultureV2,
    PolymarketBusinessV2,
    PolymarketGeneralV2,
    PolymarketGeopoliticsV2,
    LayrsCryptoV2,
    LayrsMacroV2,
    LayrsFinanceV2,
    LayrsPoliticsV2,
    LayrsSportsV2,
    LayrsEsportsV2,
    LayrsWeatherV2,
    LayrsTechnologyV2,
    LayrsMentionsV2,
    LayrsScienceV2,
    LayrsCultureV2,
    LayrsBusinessV2,
    LayrsGeneralV2,
    LayrsGeopoliticsV2,
}

impl FeeProfileId {
    fn is_legacy(&self) -> bool {
        matches!(self, Self::LegacyProfitV1)
    }

    /// Canonical immutable policy family persisted with each private fill.
    /// The legacy `POLYMARKET_*` enum aliases execute the same governed Layrs
    /// curve and are deliberately normalized so new evidence never revives the
    /// obsolete provider-facing policy name.
    fn fee_policy_version(self) -> &'static str {
        if self.has_layrs_curve_fees() {
            "LAYRS_FEE_V2"
        } else {
            "LAYRS_FEE_V1"
        }
    }

    fn immutable_profile_id(self) -> String {
        serde_json::to_string(&self)
            .expect("fee profile enum serialization cannot fail")
            .trim_matches('"')
            .replace("POLYMARKET_", "LAYRS_")
    }

    fn parameters(self) -> Option<FeeProfileParameters> {
        let parameters = match self {
            Self::LegacyProfitV1 => return None,
            Self::CryptoV1 => FeeProfileParameters::new(800, 100, 400),
            Self::MacroV1 | Self::FinanceV1 => FeeProfileParameters::new(600, 100, 300),
            Self::PoliticsV1
            | Self::WeatherV1
            | Self::TechnologyV1
            | Self::ScienceV1
            | Self::CultureV1
            | Self::BusinessV1
            | Self::GeneralV1 => FeeProfileParameters::new(500, 100, 250),
            Self::SportsV1 | Self::EsportsV1 => FeeProfileParameters::new(400, 100, 200),
            Self::GeopoliticsV1 => FeeProfileParameters::new(300, 100, 150),
            Self::PolymarketCryptoV2
            | Self::PolymarketMacroV2
            | Self::PolymarketFinanceV2
            | Self::PolymarketPoliticsV2
            | Self::PolymarketSportsV2
            | Self::PolymarketEsportsV2
            | Self::PolymarketWeatherV2
            | Self::PolymarketTechnologyV2
            | Self::PolymarketMentionsV2
            | Self::PolymarketScienceV2
            | Self::PolymarketCultureV2
            | Self::PolymarketBusinessV2
            | Self::PolymarketGeneralV2
            | Self::PolymarketGeopoliticsV2
            | Self::LayrsCryptoV2
            | Self::LayrsMacroV2
            | Self::LayrsFinanceV2
            | Self::LayrsPoliticsV2
            | Self::LayrsSportsV2
            | Self::LayrsEsportsV2
            | Self::LayrsWeatherV2
            | Self::LayrsTechnologyV2
            | Self::LayrsMentionsV2
            | Self::LayrsScienceV2
            | Self::LayrsCultureV2
            | Self::LayrsBusinessV2
            | Self::LayrsGeneralV2
            | Self::LayrsGeopoliticsV2 => return None,
        };
        Some(parameters)
    }

    fn taker_curve_rate_bps(self) -> Option<u128> {
        match self {
            Self::PolymarketCryptoV2 | Self::LayrsCryptoV2 => Some(700),
            Self::PolymarketMacroV2
            | Self::PolymarketWeatherV2
            | Self::PolymarketScienceV2
            | Self::PolymarketCultureV2
            | Self::PolymarketGeneralV2
            | Self::LayrsMacroV2
            | Self::LayrsWeatherV2
            | Self::LayrsScienceV2
            | Self::LayrsCultureV2
            | Self::LayrsGeneralV2 => Some(500),
            // Esports inherits the Layrs Sports schedule until governance
            // activates a distinct immutable profile.
            Self::PolymarketSportsV2
            | Self::PolymarketEsportsV2
            | Self::LayrsSportsV2
            | Self::LayrsEsportsV2 => Some(500),
            Self::PolymarketFinanceV2
            | Self::PolymarketPoliticsV2
            | Self::PolymarketTechnologyV2
            | Self::PolymarketMentionsV2
            | Self::PolymarketBusinessV2
            | Self::LayrsFinanceV2
            | Self::LayrsPoliticsV2
            | Self::LayrsTechnologyV2
            | Self::LayrsMentionsV2
            | Self::LayrsBusinessV2 => Some(400),
            Self::PolymarketGeopoliticsV2 | Self::LayrsGeopoliticsV2 => Some(0),
            _ => None,
        }
    }

    fn has_layrs_curve_fees(self) -> bool {
        self.taker_curve_rate_bps().is_some()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FeeProfileParameters {
    curve_coefficient_bps: u128,
    stake_floor_bps: u128,
    stake_cap_bps: u128,
    profit_cap_bps: u128,
}

impl FeeProfileParameters {
    const fn new(curve_coefficient_bps: u128, stake_floor_bps: u128, stake_cap_bps: u128) -> Self {
        Self {
            curve_coefficient_bps,
            stake_floor_bps,
            stake_cap_bps,
            profit_cap_bps: 500,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MarketExecution {
    #[default]
    NativeClob,
    /// Native private-CLOB execution with an externally observable binary
    /// condition used only as resolution evidence. No venue fill or venue
    /// redemption is part of the user trade or payout path.
    NativeExactCondition {
        condition_id: String,
        up_outcome_index: u8,
        down_outcome_index: u8,
    },
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
    VenueIntentDurable,
    VenueSubmissionAttempted,
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
pub struct BootstrapPreparedVenueOrder {
    pub deterministic_order_id: String,
    pub exact_request_body: String,
    pub request_body_sha256: [u8; 32],
    pub credential_generation_sha256: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct BootstrapExecution {
    view: BootstrapExecutionView,
    private_user_id: String,
    reserved_atomic: u128,
    venue_order_id: Option<String>,
    venue_evidence_hash: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    prepared_venue_order: Option<BootstrapPreparedVenueOrder>,
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
pub struct BinanceBoundaryEvidence {
    pub window_start_millis: i64,
    pub window_end_millis: i64,
    pub median_price_e8: i64,
    pub sample_count: u16,
    pub evidence_path_count: u16,
    pub evidence_commitment: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinanceResolutionStatement {
    pub market_id: String,
    pub oracle_source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opening: Option<BinanceBoundaryEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closing: Option<BinanceBoundaryEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<ResolutionOutcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opening_boundary_millis: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closing_boundary_millis: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_millis: Option<i64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_boundaries: Vec<String>,
    pub issued_at_millis: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedBinanceResolution {
    pub statement: BinanceResolutionStatement,
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
pub struct ExactConditionResolutionStatement {
    pub market_id: String,
    pub condition_id: String,
    pub outcome: ResolutionOutcome,
    pub evidence_hash: [u8; 32],
    pub issued_at_millis: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedExactConditionResolution {
    pub statement: ExactConditionResolutionStatement,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "signed", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SignedResolutionEvidence {
    Pyth(SignedResolution),
    Binance(SignedBinanceResolution),
    ExactCondition(SignedExactConditionResolution),
    Polymarket(SignedPolymarketResolution),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResolutionEvidence {
    PythHistoricalMedian {
        statement: ResolutionStatement,
    },
    BinanceSpotKlineMedian {
        statement: BinanceResolutionStatement,
    },
    PolymarketExactCondition {
        statement: PolymarketResolutionStatement,
    },
    PublicExactCondition {
        statement: ExactConditionResolutionStatement,
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
    ReplaceOrder {
        market_id: String,
        order_id: Uuid,
        replacement: BookOrder,
    },
    CancelOrder {
        market_id: String,
        order_id: Uuid,
    },
    CancelAllOrders {
        filter: CancelAllOrdersFilter,
    },
    PreviewPositionClose {
        position_id: String,
        market_id: String,
        outcome: Outcome,
        session_tag: String,
        #[serde(with = "super::decimal_u128")]
        quantity_micros: u128,
        minimum_price_micros: u64,
    },
    ClosePosition {
        position_id: String,
        market_id: String,
        outcome: Outcome,
        session_tag: String,
        #[serde(with = "super::decimal_u128")]
        quantity_micros: u128,
        minimum_price_micros: u64,
        quote: PositionClosePreview,
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
    TransferFunds {
        transfer_id: Uuid,
        recipient_account: String,
        asset: String,
        #[serde(with = "super::decimal_u128")]
        amount_atomic: u128,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scope", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CancelAllOrdersFilter {
    All,
    Market { market_id: String },
    Asset { asset: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancelledOrderOutcome {
    pub order_id: Uuid,
    pub market_id: String,
    pub status: OrderStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateBalance {
    pub asset: String,
    pub bucket: AccountBucket,
    pub amount_atomic: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivatePosition {
    pub position_id: String,
    pub market_id: String,
    pub outcome: String,
    pub quantity_micros: String,
    pub cost_basis_micros: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PositionClosePreview {
    pub position_id: String,
    #[serde(with = "super::decimal_u128")]
    pub quantity_micros: u128,
    pub minimum_price_micros: u64,
    pub average_price_micros: u64,
    #[serde(with = "super::decimal_u128")]
    pub gross_payout_atomic: u128,
    #[serde(with = "super::decimal_u128")]
    pub fee_atomic: u128,
    #[serde(with = "super::decimal_u128")]
    pub net_payout_atomic: u128,
    pub book_commitment_sha256: [u8; 32],
    pub book_sequence: u64,
    pub expires_at_millis: i64,
    pub quote_commitment_sha256: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortfolioSnapshot {
    pub balances: Vec<PrivateBalance>,
    pub positions: Vec<PrivatePosition>,
    pub orders: Vec<BookOrder>,
    pub as_of_millis: i64,
}

/// Aggregate-only custody view returned over the authenticated enclave
/// operator channel. It binds every amount to the exact private state root and
/// sequence without exposing owners, positions, markets or orders.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodyReconciliationSnapshot {
    pub checkpoint_commitment: [u8; 32],
    pub chain_finality_commitments: Vec<[u8; 32]>,
    pub enclave_sequence: u64,
    pub state_root: [u8; 32],
    pub totals: Vec<CustodyLedgerTotal>,
    pub receipt_public_key: [u8; 32],
    pub signature: Vec<u8>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_proof: Option<WithdrawalRecoveryProof>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalRecoveryProof {
    pub protocol_version: String,
    pub original_idempotency_key: String,
    pub terminal_enclave_sequence: u64,
    pub terminal_state_root: [u8; 32],
    pub terminal_journal_head: [u8; 32],
    pub terminal_record_hash: [u8; 32],
    pub recovered_at_millis: i64,
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
    OrdersCancelled {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        filter: Option<CancelAllOrdersFilter>,
        outcomes: Vec<CancelledOrderOutcome>,
    },
    PositionClosePreview {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        market_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        outcome: Option<Outcome>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session_tag: Option<String>,
        preview: PositionClosePreview,
    },
    PositionClosed {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        market_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        outcome: Option<Outcome>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session_tag: Option<String>,
        preview: PositionClosePreview,
        order_id: Uuid,
    },
    Replaced {
        cancelled: BookOrder,
        result: MatchResult,
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
    FundsTransferred {
        transfer_id: Uuid,
        recipient_account: String,
        asset: String,
        #[serde(with = "super::decimal_u128")]
        amount_atomic: u128,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreResponse {
    pub result: CommandResult,
    pub receipt: EnclaveReceipt,
    pub receipt_state: CommandReceiptState,
    pub receipt_disclosure_nonce: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_record: Option<EncryptedJournalRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withdrawal_authorization: Option<WithdrawalAuthorization>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reward_claim_authorization: Option<RewardClaimAuthorization>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audit_fills: Vec<SignedAuditFillArtifact>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub task_qualifications: Vec<SignedTaskQualificationArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryBridgeArtifact {
    pub protocol_version: String,
    pub environment: String,
    pub command_idempotency_key: String,
    pub result_digest: [u8; 32],
    pub enclave_sequence: u64,
    pub command_commitment_sha256: [u8; 32],
    pub state_root: [u8; 32],
    pub receipt_id: String,
    pub response_envelope_sha256: [u8; 32],
    pub response_envelope_bytes: u64,
    pub response_status: u16,
    pub content_type: String,
    pub observed_at_millis: i64,
    pub expires_at_millis: i64,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemResponse {
    pub receipt: EnclaveReceipt,
    pub encrypted_record: EncryptedJournalRecord,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audit_fills: Vec<SignedAuditFillArtifact>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_commitment: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_evidence: Option<RegistrationEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transfer_account: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferAccountStatus {
    pub transfer_account: String,
    pub registered: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrationEvidence {
    pub commitment: [u8; 32],
    pub nullifier: [u8; 32],
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

/// Privacy-minimized evidence that an encrypted order was accepted by the attested core.
///
/// The statement deliberately omits the user, side, outcome and limit price. A market identifier
/// is disclosed only for newly accepted orders so the backend can publish that exact active
/// market rather than spending registry gas on speculative inventory. Historical artifacts omit
/// it and remain byte-compatible.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskQualificationStatement {
    pub protocol_version: String,
    pub event_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub market_id: Option<String>,
    pub order_commitment: [u8; 32],
    pub settlement_asset: String,
    #[serde(with = "super::decimal_u128")]
    pub asset_notional_micros: u128,
    #[serde(with = "super::decimal_u128")]
    pub filled_quantity_micros: u128,
    pub occurred_at_millis: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTaskQualificationArtifact {
    pub statement: TaskQualificationStatement,
    pub receipt_id: String,
    pub state_root: [u8; 32],
    pub receipt_public_key: [u8; 32],
    pub signature: Vec<u8>,
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

const MAX_RECOVERY_CAPSULES: usize = 256;
const MAX_RECOVERY_CAPSULE_BYTES: usize = 64 * 1024;
const MAX_RECOVERY_WINDOW_BYTES: usize = 16 * 1024 * 1024;
const MAX_RECOVERY_FILLS: usize = 64;

/// A bounded, encrypted-snapshot recovery record for a committed private
/// command. The exact command/context binding remains in the rooted
/// `processed-command` marker; the result hash has its own rooted marker.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RecoveryCapsule {
    sequence: u64,
    request_hash: [u8; 32],
    result_digest: [u8; 32],
    result: CommandResult,
    receipt: EnclaveReceipt,
    #[serde(default)]
    receipt_state: CommandReceiptState,
    #[serde(default)]
    receipt_disclosure_nonce: [u8; 32],
    /// The exact signed withdrawal authorization returned by the committed
    /// command. Keeping it inside the encrypted snapshot lets an exact replay
    /// survive an enclave restart without minting a replacement withdrawal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    withdrawal_authorization: Option<WithdrawalAuthorization>,
    audit_fills: Vec<SignedAuditFillArtifact>,
    task_qualifications: Vec<SignedTaskQualificationArtifact>,
}

impl RecoveryCapsule {
    fn response(&self) -> CoreResponse {
        CoreResponse {
            result: self.result.clone(),
            receipt: self.receipt.clone(),
            receipt_state: self.receipt_state,
            receipt_disclosure_nonce: self.receipt_disclosure_nonce,
            encrypted_record: None,
            withdrawal_authorization: self.withdrawal_authorization.clone(),
            reward_claim_authorization: None,
            audit_fills: self.audit_fills.clone(),
            task_qualifications: self.task_qualifications.clone(),
        }
    }
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
        now_millis: i64,
    },
    RegisterTransferAccount {
        idempotency_key: String,
        identity_commitment: [u8; 32],
    },
    ExternalFlow {
        idempotency_key: String,
        flow: ExternalFlowTransaction,
    },
    ConfirmedDeposit {
        idempotency_key: String,
        flow: ExternalFlowTransaction,
    },
    ConfirmedWithdrawal {
        idempotency_key: String,
        flow: ExternalFlowTransaction,
    },
    VaultStrategyTransition {
        idempotency_key: String,
        transaction: VaultStrategyTransaction,
    },
    HistoricalPoolCashOpening {
        idempotency_key: String,
        evidence_hash: [u8; 32],
        openings: Vec<PoolCashOpening>,
        source_sequence: u64,
        source_state_root: [u8; 32],
        source_journal_head: [u8; 32],
    },
    AccrueReward {
        idempotency_key: String,
        identity_commitment: [u8; 32],
        chain: String,
        reward_token: String,
        #[serde(with = "super::decimal_u128")]
        amount_atomic: u128,
        evidence_hash: [u8; 32],
        source_id_hash: [u8; 32],
        program_id: String,
        program_type: String,
        policy_id: String,
        policy_version: u32,
        fee_policy_version: String,
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
    MarkBootstrapVenueIntentDurable {
        idempotency_key: String,
        execution_id: Uuid,
        deterministic_order_id: String,
        request_body_sha256: [u8; 32],
        credential_generation_sha256: [u8; 32],
    },
    AuthorizeBootstrapSubmissionAttempt {
        idempotency_key: String,
        execution_id: Uuid,
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
    AcknowledgeRecoveryArchive {
        idempotency_key: String,
        command_idempotency_key: String,
        result_digest: [u8; 32],
        archive_row_commitment: [u8; 32],
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CoreStateSnapshot {
    #[serde(deserialize_with = "Ledger::deserialize_snapshot_compatible")]
    ledger: Ledger,
    books: BTreeMap<String, PriceTimeBook>,
    markets: BTreeMap<String, MarketConfig>,
    sessions: SessionGuard,
    processed_hashes: BTreeMap<String, [u8; 32]>,
    /// Recent exact private results only. This window is deterministically
    /// bounded before a snapshot is sealed; older commands remain committed
    /// and return `PreviouslyProcessed` rather than being executed twice.
    #[serde(default)]
    recovery_capsules: BTreeMap<String, RecoveryCapsule>,
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

pub const EXACT_LIVE_976_RELEASE_COMMIT: &str = "97614f37c05089708f93bf50ac8831adde98ab2f";
pub const INCIDENT_TERMINAL_SEQUENCE: u64 = 161_919;
pub const INCIDENT_TERMINAL_STATE_ROOT_HEX: &str =
    "647bc1b6a8f48caf6460b8cafc20baedbb208815dc52c88e9bdde70191c67f6a";
pub const INCIDENT_TERMINAL_JOURNAL_HEAD_HEX: &str =
    "02c52dce702bd2e7e83b96bbe82f0169fc2fa961eef1c50ed5dc455cdd43c881";
pub const INCIDENT_TERMINAL_CIPHERTEXT_SHA256_HEX: &str =
    "cb284d9b13bc8b17d20c75d44e4e3b68a1d29dec3a7a5b9fd80871f340ea8da9";

/// Non-secret checkpoint fields supplied by the outer certification wrapper.
/// Artifact checksums are revalidated by the runner before this reaches the
/// private core; the core binds the semantic report to the same checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactLive976CheckpointBinding {
    pub source_release_commit: String,
    pub checkpoint_sha256: String,
    pub sequence: u64,
    pub state_root: [u8; 32],
    pub journal_head: [u8; 32],
}

/// Privacy-safe result of restoring an exact 976 snapshot in the cumulative
/// candidate. No account, order, market, session, balance or replay key is
/// serialized into this report; only equality decisions and digests leave the
/// attested recovery process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExactLive976RestoreReport {
    pub source_release_commit: String,
    pub checkpoint_sha256: String,
    pub source_checkpoint_equal: bool,
    pub sequence_equal: bool,
    pub journal_head_equal: bool,
    pub state_root_equal: bool,
    pub users_equal: bool,
    pub available_balances_equal: bool,
    pub order_holds_equal: bool,
    pub withdrawal_holds_equal: bool,
    pub positions_equal: bool,
    pub orders_equal: bool,
    pub fills_equal: bool,
    pub resolutions_equal: bool,
    pub rewards_equal: bool,
    pub fees_equal: bool,
    pub markets_equal: bool,
    pub replay_keys_equal: bool,
    pub legacy_zero_balance_count: usize,
    pub qualified_totals_digest: String,
    pub user_state_digest: String,
    pub pool_cash_opening_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExactTerminalCategoryDigests {
    pub users_and_sessions_sha256: String,
    pub available_balances_sha256: String,
    pub order_holds_sha256: String,
    pub withdrawal_holds_sha256: String,
    pub positions_and_cost_basis_sha256: String,
    pub order_books_sha256: String,
    pub snapshot_fill_state_sha256: String,
    pub resolutions_sha256: String,
    pub rewards_sha256: String,
    pub fees_sha256: String,
    pub markets_sha256: String,
    pub replay_state_sha256: String,
    pub custody_qualified_totals_sha256: String,
    pub composite_user_state_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExactTerminalCategoryEquality {
    pub users_and_sessions_equal: bool,
    pub available_balances_equal: bool,
    pub order_holds_equal: bool,
    pub withdrawal_holds_equal: bool,
    pub positions_and_cost_basis_equal: bool,
    pub order_books_equal: bool,
    pub snapshot_fill_state_equal: bool,
    pub resolutions_equal: bool,
    pub rewards_equal: bool,
    pub fees_equal: bool,
    pub markets_equal: bool,
    pub replay_state_equal: bool,
    pub custody_qualified_totals_equal: bool,
    pub composite_user_state_equal: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExactTerminalCategoryCounts {
    pub user_count: usize,
    pub registered_session_count: usize,
    pub sequenced_session_count: usize,
    pub ledger_record_count: usize,
    pub position_cost_basis_count: usize,
    pub order_count: usize,
    pub market_count: usize,
    pub resolution_count: usize,
    pub processed_command_count: usize,
    pub system_key_count: usize,
    pub aggregate_bucket_total_count: usize,
    pub aggregate_asset_total_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExactTerminalSnapshotRestoreReport {
    pub source_release_commit: String,
    pub restored_sequence: u64,
    pub restored_state_root: String,
    pub restored_journal_head: String,
    pub snapshot_ciphertext_sha256: String,
    pub aggregate_bucket_totals: Vec<PublicBucketTotal>,
    pub aggregate_asset_totals: Vec<PublicAssetTotal>,
    pub category_counts: ExactTerminalCategoryCounts,
    pub category_digests: ExactTerminalCategoryDigests,
    pub category_equality: ExactTerminalCategoryEquality,
    pub sequence_equal: bool,
    pub state_root_equal: bool,
    pub journal_head_equal: bool,
    pub aggregate_totals_equal: bool,
    pub aggregate_totals_zero_delta: bool,
    pub restore_floor_persisted: bool,
    pub no_external_state_mutation_performed: bool,
    pub pool_cash_opening_required: bool,
    pub historical_journal_replay_performed: bool,
    pub historical_fill_completeness_certified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TerminalSnapshotDigests {
    users_and_sessions: [u8; 32],
    available_balances: [u8; 32],
    order_holds: [u8; 32],
    withdrawal_holds: [u8; 32],
    positions_and_cost_basis: [u8; 32],
    order_books: [u8; 32],
    snapshot_fill_state: [u8; 32],
    resolutions: [u8; 32],
    rewards: [u8; 32],
    fees: [u8; 32],
    markets: [u8; 32],
    replay_state: [u8; 32],
    custody_qualified_totals: [u8; 32],
    composite_user_state: [u8; 32],
    pool_cash_opening_required: bool,
}

#[derive(Clone, Copy)]
struct TerminalSnapshotRestorePolicy {
    sequence: u64,
    state_root: [u8; 32],
    journal_head: [u8; 32],
    ciphertext_sha256: [u8; 32],
}

#[derive(Debug)]
struct OfflineStateDigests {
    users: [u8; 32],
    available_balances: [u8; 32],
    order_holds: [u8; 32],
    withdrawal_holds: [u8; 32],
    positions: [u8; 32],
    orders: [u8; 32],
    fills: [u8; 32],
    resolutions: [u8; 32],
    rewards: [u8; 32],
    fees: [u8; 32],
    markets: [u8; 32],
    replay_keys: [u8; 32],
    qualified_totals: [u8; 32],
    user_state: [u8; 32],
    pool_cash_opening_required: bool,
}

#[derive(Clone)]
pub struct PrivateTradingCore {
    ledger: Ledger,
    books: BTreeMap<String, PriceTimeBook>,
    markets: BTreeMap<String, MarketConfig>,
    sessions: SessionGuard,
    processed: BTreeMap<String, ProcessedCommand>,
    recovery_capsules: BTreeMap<String, RecoveryCapsule>,
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
    custody_totals_cache: RefCell<Option<(u64, [u8; 32], Vec<CustodyLedgerTotal>)>>,
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
            recovery_capsules: BTreeMap::new(),
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
            custody_totals_cache: RefCell::new(None),
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
                recovery_capsules: self.recovery_capsules.clone(),
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
            recovery_capsules: self.recovery_capsules.clone(),
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
            recovery_capsules: self.recovery_capsules.clone(),
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

    /// Emits the persisted JSON shape used by the exact production source
    /// release 97614f37. This synthetic fixture proves the additive
    /// `recovery_capsules` default and root continuity; release operations must
    /// still replay the real frozen production snapshot because the candidate
    /// ledger decoder intentionally enforces stricter legacy-data invariants.
    #[cfg(test)]
    pub fn export_live_976_snapshot_for_test(&self) -> CoreResult<EncryptedSnapshot> {
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
            recovery_capsules: self.recovery_capsules.clone(),
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
        value
            .as_object_mut()
            .ok_or(CoreError::JournalCrypto)?
            .remove("recovery_capsules");
        self.journal.seal_snapshot(self.state_root(), &value)
    }

    /// Restores and compares a frozen exact-976 checkpoint without exporting
    /// decrypted state. The supplied journal must be the complete immutable
    /// chain through the snapshot head. Category booleans are computed from
    /// independently digested source and restored candidate projections; they
    /// are never caller-controlled switches.
    pub fn certify_exact_live_976_restore(
        journal_key: JournalKey,
        receipt_signer: ReceiptSigner,
        snapshot: &EncryptedSnapshot,
        journal_records: &[EncryptedJournalRecord],
        checkpoint: ExactLive976CheckpointBinding,
    ) -> CoreResult<ExactLive976RestoreReport> {
        EncryptedJournal::verify_complete_export(
            journal_records,
            snapshot.sequence,
            snapshot.journal_head,
            snapshot.state_root,
        )?;

        let source_journal = EncryptedJournal::new(journal_key.clone());
        let (journal_fills, journal_fill_totals) = offline_journal_fill_evidence(
            source_journal.decrypt_complete_export_json(journal_records)?,
        )?;
        let source: CoreStateSnapshot = source_journal.open_snapshot(snapshot)?;
        if !source.recovery_capsules.is_empty() || source.sequence != snapshot.sequence {
            return Err(CoreError::JournalChainMismatch);
        }
        let source_digests = offline_state_digests(
            &source.ledger,
            &source.books,
            &source.markets,
            &source.sessions,
            &source.processed_hashes,
            &source.system_keys,
            &source.position_cost_basis,
            &source.resolutions,
            &source.private_rewards,
            &journal_fills,
        )?;

        let restored = Self::restore_encrypted_snapshot(
            journal_key,
            receipt_signer,
            snapshot,
            checkpoint.sequence,
        )?;
        let restored_processed = processed_hashes(&restored.processed);
        let restored_positions: Vec<(PositionKey, u128)> = restored
            .position_cost_basis
            .iter()
            .map(|(key, amount)| (key.clone(), *amount))
            .collect();
        let restored_digests = offline_state_digests(
            &restored.ledger,
            &restored.books,
            &restored.markets,
            &restored.sessions,
            &restored_processed,
            &restored.system_keys,
            &restored_positions,
            &restored.resolutions,
            &restored.private_rewards,
            &journal_fills,
        )?;
        let source_fills_consistent =
            offline_fill_totals_equal(&source.books, &journal_fill_totals);
        let restored_fills_consistent =
            offline_fill_totals_equal(&restored.books, &journal_fill_totals);

        let source_checkpoint_equal = checkpoint.source_release_commit
            == EXACT_LIVE_976_RELEASE_COMMIT
            && checkpoint.sequence == snapshot.sequence
            && checkpoint.state_root == snapshot.state_root
            && checkpoint.journal_head == snapshot.journal_head;
        let sequence_equal =
            source.sequence == restored.sequence && restored.sequence == checkpoint.sequence;
        let journal_head_equal =
            restored.journal.chain_head() == (checkpoint.sequence, checkpoint.journal_head);
        let state_root_equal = restored.state_root() == source_state_root(&source)
            && restored.state_root() == checkpoint.state_root;

        Ok(ExactLive976RestoreReport {
            source_release_commit: checkpoint.source_release_commit,
            checkpoint_sha256: checkpoint.checkpoint_sha256,
            source_checkpoint_equal,
            sequence_equal,
            journal_head_equal,
            state_root_equal,
            users_equal: source_digests.users == restored_digests.users,
            available_balances_equal: source_digests.available_balances
                == restored_digests.available_balances,
            order_holds_equal: source_digests.order_holds == restored_digests.order_holds,
            withdrawal_holds_equal: source_digests.withdrawal_holds
                == restored_digests.withdrawal_holds,
            positions_equal: source_digests.positions == restored_digests.positions,
            orders_equal: source_digests.orders == restored_digests.orders,
            fills_equal: source_digests.fills == restored_digests.fills
                && source_fills_consistent
                && restored_fills_consistent,
            resolutions_equal: source_digests.resolutions == restored_digests.resolutions,
            rewards_equal: source_digests.rewards == restored_digests.rewards,
            fees_equal: source_digests.fees == restored_digests.fees,
            markets_equal: source_digests.markets == restored_digests.markets,
            replay_keys_equal: source_digests.replay_keys == restored_digests.replay_keys,
            legacy_zero_balance_count: source.ledger.legacy_zero_balance_count(),
            qualified_totals_digest: hex::encode(source_digests.qualified_totals),
            user_state_digest: hex::encode(source_digests.user_state),
            pool_cash_opening_required: source_digests.pool_cash_opening_required,
        })
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
        validate_recovery_capsules(
            &state.recovery_capsules,
            &state.processed_hashes,
            &state.system_keys,
            &identity_key,
            state.sequence,
        )?;
        let processed: BTreeMap<String, ProcessedCommand> = state
            .processed_hashes
            .into_iter()
            .map(|(key, request_hash)| {
                let response = state
                    .recovery_capsules
                    .get(&key)
                    .map(RecoveryCapsule::response);
                (
                    key,
                    ProcessedCommand {
                        request_hash,
                        response,
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
            recovery_capsules: state.recovery_capsules,
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
            custody_totals_cache: RefCell::new(None),
        })
    }

    /// Restores only the immutable terminal snapshot approved for the
    /// 2026-08-25 incident. Every public checkpoint field is rejected before
    /// decryption unless it is the exact sequence-161919 tuple.
    pub fn restore_exact_incident_terminal_snapshot(
        journal_key: JournalKey,
        receipt_signer: ReceiptSigner,
        snapshot: &EncryptedSnapshot,
    ) -> CoreResult<(Self, ExactTerminalSnapshotRestoreReport)> {
        Self::restore_terminal_snapshot_against_policy(
            journal_key,
            receipt_signer,
            snapshot,
            incident_terminal_restore_policy(),
        )
    }

    fn restore_terminal_snapshot_against_policy(
        journal_key: JournalKey,
        receipt_signer: ReceiptSigner,
        snapshot: &EncryptedSnapshot,
        policy: TerminalSnapshotRestorePolicy,
    ) -> CoreResult<(Self, ExactTerminalSnapshotRestoreReport)> {
        validate_terminal_snapshot_against_policy(snapshot, policy)?;

        let source_journal = EncryptedJournal::new(journal_key.clone());
        let source: CoreStateSnapshot = source_journal.open_snapshot(snapshot)?;
        if source.sequence != policy.sequence || source_state_root(&source) != policy.state_root {
            return Err(CoreError::IncidentRecoveryPolicyMismatch);
        }
        let source_positions: Vec<(PositionKey, u128)> = source.position_cost_basis.to_vec();
        let source_digests = terminal_snapshot_digests(
            &source.ledger,
            &source.books,
            &source.markets,
            &source.sessions,
            &source.processed_hashes,
            &source.system_keys,
            &source_positions,
            &source.resolutions,
            &source.private_rewards,
        )?;
        let source_counts = terminal_category_counts(
            &source.ledger,
            &source.books,
            &source.markets,
            &source.sessions,
            &source.processed_hashes,
            &source.system_keys,
            &source_positions,
            &source.resolutions,
        )?;
        let aggregate_bucket_totals = source.ledger.terminal_public_bucket_totals()?;
        let aggregate_asset_totals = source.ledger.terminal_public_asset_totals()?;

        let restored = Self::restore_encrypted_snapshot(
            journal_key,
            receipt_signer,
            snapshot,
            policy.sequence,
        )?;
        if restored.sequence != policy.sequence
            || restored.state_root() != policy.state_root
            || restored.journal.chain_head() != (policy.sequence, policy.journal_head)
        {
            return Err(CoreError::IncidentRecoveryPolicyMismatch);
        }
        let restored_positions: Vec<(PositionKey, u128)> = restored
            .position_cost_basis
            .iter()
            .map(|(key, amount)| (key.clone(), *amount))
            .collect();
        let restored_processed = processed_hashes(&restored.processed);
        let restored_digests = terminal_snapshot_digests(
            &restored.ledger,
            &restored.books,
            &restored.markets,
            &restored.sessions,
            &restored_processed,
            &restored.system_keys,
            &restored_positions,
            &restored.resolutions,
            &restored.private_rewards,
        )?;
        let restored_counts = terminal_category_counts(
            &restored.ledger,
            &restored.books,
            &restored.markets,
            &restored.sessions,
            &restored_processed,
            &restored.system_keys,
            &restored_positions,
            &restored.resolutions,
        )?;
        let restored_bucket_totals = restored.ledger.terminal_public_bucket_totals()?;
        let restored_asset_totals = restored.ledger.terminal_public_asset_totals()?;
        if source_digests != restored_digests
            || source_counts != restored_counts
            || aggregate_bucket_totals != restored_bucket_totals
            || aggregate_asset_totals != restored_asset_totals
        {
            return Err(CoreError::IncidentRecoveryPolicyMismatch);
        }

        let category_equality = ExactTerminalCategoryEquality {
            users_and_sessions_equal: true,
            available_balances_equal: true,
            order_holds_equal: true,
            withdrawal_holds_equal: true,
            positions_and_cost_basis_equal: true,
            order_books_equal: true,
            snapshot_fill_state_equal: true,
            resolutions_equal: true,
            rewards_equal: true,
            fees_equal: true,
            markets_equal: true,
            replay_state_equal: true,
            custody_qualified_totals_equal: true,
            composite_user_state_equal: true,
        };
        let category_digests = ExactTerminalCategoryDigests {
            users_and_sessions_sha256: hex::encode(source_digests.users_and_sessions),
            available_balances_sha256: hex::encode(source_digests.available_balances),
            order_holds_sha256: hex::encode(source_digests.order_holds),
            withdrawal_holds_sha256: hex::encode(source_digests.withdrawal_holds),
            positions_and_cost_basis_sha256: hex::encode(source_digests.positions_and_cost_basis),
            order_books_sha256: hex::encode(source_digests.order_books),
            snapshot_fill_state_sha256: hex::encode(source_digests.snapshot_fill_state),
            resolutions_sha256: hex::encode(source_digests.resolutions),
            rewards_sha256: hex::encode(source_digests.rewards),
            fees_sha256: hex::encode(source_digests.fees),
            markets_sha256: hex::encode(source_digests.markets),
            replay_state_sha256: hex::encode(source_digests.replay_state),
            custody_qualified_totals_sha256: hex::encode(source_digests.custody_qualified_totals),
            composite_user_state_sha256: hex::encode(source_digests.composite_user_state),
        };

        Ok((
            restored,
            ExactTerminalSnapshotRestoreReport {
                source_release_commit: EXACT_LIVE_976_RELEASE_COMMIT.into(),
                restored_sequence: policy.sequence,
                restored_state_root: hex::encode(policy.state_root),
                restored_journal_head: hex::encode(policy.journal_head),
                snapshot_ciphertext_sha256: hex::encode(policy.ciphertext_sha256),
                aggregate_bucket_totals,
                aggregate_asset_totals,
                category_counts: source_counts,
                category_digests,
                category_equality,
                sequence_equal: true,
                state_root_equal: true,
                journal_head_equal: true,
                aggregate_totals_equal: true,
                aggregate_totals_zero_delta: true,
                restore_floor_persisted: true,
                no_external_state_mutation_performed: true,
                pool_cash_opening_required: source_digests.pool_cash_opening_required,
                historical_journal_replay_performed: false,
                historical_fill_completeness_certified: false,
            },
        ))
    }

    /// Restores an authenticated direct successor of the current committed
    /// state. This is used only by the durable-command finalizer after the
    /// encrypted successor snapshot and journal record have been made durable
    /// outside the enclave. It deliberately refuses gaps, forks and rollback.
    pub fn restore_successor_snapshot(&self, snapshot: &EncryptedSnapshot) -> CoreResult<Self> {
        if snapshot.sequence
            != self
                .sequence
                .checked_add(1)
                .ok_or(CoreError::JournalChainMismatch)?
        {
            return Err(CoreError::JournalChainMismatch);
        }
        let mut journal = self.journal.clone();
        let state: CoreStateSnapshot = journal.open_snapshot(snapshot)?;
        if state.sequence != snapshot.sequence {
            return Err(CoreError::JournalChainMismatch);
        }
        let position_cost_basis: BTreeMap<PositionKey, u128> =
            state.position_cost_basis.into_iter().collect();
        validate_recovery_capsules(
            &state.recovery_capsules,
            &state.processed_hashes,
            &state.system_keys,
            &self.identity_key,
            state.sequence,
        )?;
        let processed: BTreeMap<String, ProcessedCommand> = state
            .processed_hashes
            .into_iter()
            .map(|(key, request_hash)| {
                let response = state
                    .recovery_capsules
                    .get(&key)
                    .map(RecoveryCapsule::response);
                (
                    key,
                    ProcessedCommand {
                        request_hash,
                        response,
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
            return Err(CoreError::JournalChainMismatch);
        }
        journal.restore_chain_head(snapshot.sequence, snapshot.journal_head)?;
        Ok(Self {
            ledger: state.ledger,
            books: state.books,
            markets: state.markets,
            sessions: state.sessions,
            processed,
            recovery_capsules: state.recovery_capsules,
            system_keys: state.system_keys,
            journal,
            receipt_signer: self.receipt_signer.clone(),
            position_cost_basis,
            resolutions: state.resolutions,
            oracle_public_key: state.oracle_public_key,
            bootstrap_executions: state.bootstrap_executions,
            private_rewards: state.private_rewards,
            trading_frozen: state.trading_frozen,
            sequence: state.sequence,
            identity_key: self.identity_key,
            custody_totals_cache: RefCell::new(None),
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

    pub fn custody_reconciliation_snapshot(
        &self,
        checkpoint_commitment: [u8; 32],
        chain_finality_commitments: Vec<[u8; 32]>,
    ) -> CoreResult<CustodyReconciliationSnapshot> {
        if checkpoint_commitment == [0; 32]
            || chain_finality_commitments.len() != 2
            || chain_finality_commitments.contains(&[0; 32])
            || chain_finality_commitments[0] == chain_finality_commitments[1]
        {
            return Err(CoreError::InvalidOrder(
                "custody snapshot requires one checkpoint and two distinct finality commitments"
                    .into(),
            ));
        }
        let state_root = self.state_root();
        let totals = self
            .custody_totals_cache
            .borrow()
            .as_ref()
            .filter(|(sequence, root, _)| *sequence == self.sequence && *root == state_root)
            .map(|(_, _, totals)| totals.clone())
            .unwrap_or(self.ledger.custody_reconciliation_totals()?);
        *self.custody_totals_cache.borrow_mut() = Some((self.sequence, state_root, totals.clone()));
        let mut snapshot = CustodyReconciliationSnapshot {
            checkpoint_commitment,
            chain_finality_commitments,
            enclave_sequence: self.sequence,
            state_root,
            totals,
            receipt_public_key: self.receipt_signer.verifying_key(),
            signature: Vec::new(),
        };
        snapshot.signature = self
            .receipt_signer
            .sign_domain_payload(b"layrs.custody-reconciliation-snapshot.v1\0", &snapshot);
        Ok(snapshot)
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn trading_frozen(&self) -> bool {
        self.trading_frozen
    }

    /// Recovers only a byte-for-byte identical committed user command.
    ///
    /// This check is intentionally available before a fresh NSM clock read so a
    /// lost HTTP response can be recovered even during a temporary NSM failure.
    /// Legacy processed entries without the rooted full-command marker remain
    /// non-recoverable and return `PreviouslyProcessed`.
    pub fn recover_exact_user_command(
        &self,
        command: &UserCommand,
    ) -> CoreResult<Option<CoreResponse>> {
        let expected_hash = command_request_hash(
            &command.command_id,
            &command.idempotency_key,
            &command.action,
        )?;
        if command.session.request.request_hash != expected_hash {
            return Err(CoreError::RequestHashMismatch);
        }
        let Some(processed) = self.processed.get(&command.idempotency_key) else {
            return Ok(None);
        };
        if processed.request_hash != expected_hash {
            return Err(CoreError::DuplicateCommand);
        }
        if !self.system_keys.contains(&processed_command_marker(
            &command.idempotency_key,
            full_user_command_commitment(command)?,
        )) {
            return Err(CoreError::PreviouslyProcessed);
        }
        processed
            .response
            .clone()
            .map(Some)
            .ok_or(CoreError::PreviouslyProcessed)
    }

    /// Returns the exact cached response for a committed withdrawal, bound to
    /// both its public identifier and originating private session. This is a
    /// read-only operator recovery primitive: it never releases a hold, creates
    /// a replacement command, or advances the enclave sequence/state root.
    pub fn recover_withdrawal_authorization(
        &self,
        withdrawal_id: Uuid,
        session_id: &str,
    ) -> CoreResult<Option<CoreResponse>> {
        if session_id.is_empty() {
            return Err(CoreError::InvalidOrder(
                "withdrawal recovery requires a session".into(),
            ));
        }
        let mut match_found = None;
        for processed in self.processed.values() {
            let Some(response) = &processed.response else {
                continue;
            };
            let CommandResult::WithdrawalReserved {
                withdrawal_id: candidate_id,
                chain,
                asset,
                amount_atomic,
                destination,
            } = &response.result
            else {
                continue;
            };
            if *candidate_id != withdrawal_id {
                continue;
            }
            let authorization = response
                .withdrawal_authorization
                .as_ref()
                .ok_or(CoreError::InvalidRecoveryCapsule)?;
            if authorization.intent.session_id != session_id {
                continue;
            }
            if authorization.intent.withdrawal_id != withdrawal_id
                || authorization.intent.chain != *chain
                || authorization.intent.asset != *asset
                || authorization.intent.amount_atomic != amount_atomic.to_string()
                || authorization.intent.destination != *destination
                || authorization.intent.receipt_id != response.receipt.receipt_id
                || authorization.intent.enclave_sequence != response.receipt.enclave_sequence
                || authorization.intent.state_root != response.receipt.state_root
            {
                return Err(CoreError::InvalidRecoveryCapsule);
            }
            if match_found.replace(response.clone()).is_some() {
                return Err(CoreError::InvalidRecoveryCapsule);
            }
        }
        Ok(match_found)
    }

    /// Reissues a short-lived authorization for the exact withdrawal already
    /// committed by the terminal encrypted journal record. This is a read-only
    /// recovery: every command/result/marker/hold binding is verified and no
    /// ledger, sequence, root, journal, or processed-command state is changed.
    pub fn recover_terminal_withdrawal_authorization(
        &self,
        terminal_record: &EncryptedJournalRecord,
        withdrawal_id: Uuid,
        session_id: &str,
        now_millis: i64,
    ) -> CoreResult<CoreResponse> {
        let entry: JournaledUserCommand = self
            .journal
            .decrypt_current_head(terminal_record, self.state_root())?;
        let UserCommandAction::RequestWithdrawal {
            withdrawal_id: command_withdrawal_id,
            chain,
            asset,
            amount_atomic,
            destination,
        } = &entry.command.action
        else {
            return Err(CoreError::InvalidRecoveryCapsule);
        };
        let CommandResult::WithdrawalReserved {
            withdrawal_id: result_withdrawal_id,
            chain: result_chain,
            asset: result_asset,
            amount_atomic: result_amount,
            destination: result_destination,
        } = &entry.result
        else {
            return Err(CoreError::InvalidRecoveryCapsule);
        };
        if *command_withdrawal_id != withdrawal_id
            || *result_withdrawal_id != withdrawal_id
            || entry.command.session.request.session_id != session_id
            || chain != result_chain
            || asset != result_asset
            || amount_atomic != result_amount
            || destination != result_destination
        {
            return Err(CoreError::InvalidRecoveryCapsule);
        }
        let expected_hash = command_request_hash(
            &entry.command.command_id,
            &entry.command.idempotency_key,
            &entry.command.action,
        )?;
        if entry.command.session.request.request_hash != expected_hash
            || self
                .processed
                .get(&entry.command.idempotency_key)
                .map(|processed| processed.request_hash)
                != Some(expected_hash)
            || !self.system_keys.contains(&processed_command_marker(
                &entry.command.idempotency_key,
                full_user_command_commitment(&entry.command)?,
            ))
            || !self.system_keys.contains(&withdrawal_reservation_marker(
                session_id,
                withdrawal_id,
                chain,
                asset,
                &amount_atomic.to_string(),
                destination,
            )?)
        {
            return Err(CoreError::InvalidRecoveryCapsule);
        }
        let owner = self
            .sessions
            .registered_owner(session_id)
            .ok_or(CoreError::UnknownSession)?;
        if self.ledger.balance(&AccountKey::new(
            owner,
            AccountBucket::UserWithdrawalHold,
            asset,
        )) < *amount_atomic
        {
            return Err(CoreError::InvalidRecoveryCapsule);
        }
        let root = self.state_root();
        let recovery_receipt = self.receipt_signer.sign(
            format!("recover-withdrawal:{withdrawal_id}"),
            format!("recovery:{}", entry.command.idempotency_key),
            Some(expected_hash),
            Some(false),
            None,
            None,
            self.sequence,
            root,
            root,
            terminal_record.record_hash,
            now_millis,
        );
        let intent = WithdrawalIntent {
            protocol_version: "layrs.withdrawal-recovery.v1".into(),
            withdrawal_id,
            session_id: session_id.to_owned(),
            chain: chain.clone(),
            asset: asset.clone(),
            amount_atomic: amount_atomic.to_string(),
            destination: destination.clone(),
            receipt_id: recovery_receipt.receipt_id.clone(),
            enclave_sequence: self.sequence,
            state_root: root,
            expires_at_millis: now_millis.saturating_add(15 * 60_000),
            recovery_proof: Some(WithdrawalRecoveryProof {
                protocol_version: "layrs.withdrawal-terminal-journal-proof.v1".into(),
                original_idempotency_key: entry.command.idempotency_key,
                terminal_enclave_sequence: terminal_record.sequence,
                terminal_state_root: terminal_record.state_root,
                terminal_journal_head: terminal_record.record_hash,
                terminal_record_hash: terminal_record.record_hash,
                recovered_at_millis: now_millis,
            }),
        };
        let authorization = WithdrawalAuthorization {
            signature: self
                .receipt_signer
                .sign_domain_payload(b"layrs.withdrawal-recovery-authorization.v1\0", &intent),
            intent,
        };
        Ok(CoreResponse {
            result: entry.result,
            receipt: recovery_receipt,
            receipt_state: CommandReceiptState::Accepted,
            receipt_disclosure_nonce: [0; 32],
            encrypted_record: None,
            withdrawal_authorization: Some(authorization),
            reward_claim_authorization: None,
            audit_fills: Vec::new(),
            task_qualifications: Vec::new(),
        })
    }

    /// Attaches the chain signer output to the exact cached reward-claim
    /// response after signing succeeds outside the financial core.
    ///
    /// The financial mutation and its rooted request marker are already
    /// committed by `execute`. This method may only enrich that exact cached
    /// response with an authorization whose intent is byte-for-byte identical
    /// to the rooted command result. It does not alter financial state, journal
    /// sequence, or the state root. This makes a byte-identical transport retry
    /// return the original signed authorization instead of authorizing twice.
    pub fn attach_reward_claim_authorization(
        &mut self,
        command: &UserCommand,
        authorization: RewardClaimAuthorization,
    ) -> CoreResult<()> {
        let expected_hash = command_request_hash(
            &command.command_id,
            &command.idempotency_key,
            &command.action,
        )?;
        if command.session.request.request_hash != expected_hash {
            return Err(CoreError::RequestHashMismatch);
        }
        let processed = self
            .processed
            .get_mut(&command.idempotency_key)
            .ok_or(CoreError::PreviouslyProcessed)?;
        if processed.request_hash != expected_hash {
            return Err(CoreError::DuplicateCommand);
        }
        let response = processed
            .response
            .as_mut()
            .ok_or(CoreError::PreviouslyProcessed)?;
        let CommandResult::RewardClaimAuthorized { intent } = &response.result else {
            return Err(CoreError::InvalidOrder(
                "reward authorization does not match command result".into(),
            ));
        };
        if authorization.intent != *intent {
            return Err(CoreError::InvalidOrder(
                "reward authorization intent mismatch".into(),
            ));
        }
        match &response.reward_claim_authorization {
            Some(existing) if existing != &authorization => {
                return Err(CoreError::InvalidOrder(
                    "reward authorization already differs".into(),
                ));
            }
            Some(_) => return Ok(()),
            None => {}
        }
        response.reward_claim_authorization = Some(authorization);
        Ok(())
    }

    pub fn signed_recovery_bridge_artifact(
        &self,
        command_idempotency_key: &str,
        environment: &str,
        response_envelope_sha256: [u8; 32],
        response_envelope_bytes: u64,
    ) -> Option<RecoveryBridgeArtifact> {
        self.recovery_capsules
            .get(command_idempotency_key)
            .and_then(|capsule| {
                let mut artifact = RecoveryBridgeArtifact {
                    protocol_version: "layrs.private-response-recovery.v1".into(),
                    environment: environment.to_owned(),
                    command_idempotency_key: command_idempotency_key.to_owned(),
                    result_digest: capsule.result_digest,
                    enclave_sequence: capsule.sequence,
                    command_commitment_sha256: capsule.request_hash,
                    state_root: capsule.receipt.state_root,
                    receipt_id: capsule.receipt.receipt_id.clone(),
                    response_envelope_sha256,
                    response_envelope_bytes,
                    response_status: 200,
                    content_type: "application/json".into(),
                    observed_at_millis: capsule.receipt.occurred_at_millis,
                    expires_at_millis: capsule
                        .receipt
                        .occurred_at_millis
                        .checked_add(24 * 60 * 60 * 1_000)?,
                    signature: Vec::new(),
                };
                artifact.signature = self.receipt_signer.sign_domain_payload(
                    b"layrs.private-response-recovery-artifact.v1\0",
                    &artifact,
                );
                Some(artifact)
            })
    }

    /// Read-only reconciliation proof for an archive ACK whose response may
    /// have been lost after the enclave committed it. The exact marker is
    /// rooted by `acknowledge_recovery_archive`; absence never implies success.
    pub fn recovery_archive_acknowledged(
        &self,
        command_idempotency_key: &str,
        result_digest: [u8; 32],
        archive_row_commitment: [u8; 32],
    ) -> bool {
        self.system_keys.contains(&recovery_archive_ack_marker(
            command_idempotency_key,
            result_digest,
            archive_row_commitment,
        ))
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

    /// Removes one exact SubmitOrder recovery bridge only after the governed
    /// operator attests that the padded opaque response is durably archived.
    /// The archive commitment and result digest are rooted and journaled; an
    /// ACK for another command/result can never free capacity.
    pub fn acknowledge_recovery_archive(
        &mut self,
        idempotency_key: String,
        command_idempotency_key: String,
        result_digest: [u8; 32],
        archive_row_commitment: [u8; 32],
        now_millis: i64,
    ) -> CoreResult<SystemResponse> {
        self.validate_new_system_key(&idempotency_key)?;
        if archive_row_commitment == [0u8; 32] {
            return Err(CoreError::InvalidRecoveryCapsule);
        }
        let capsule = self
            .recovery_capsules
            .get(&command_idempotency_key)
            .ok_or(CoreError::InvalidRecoveryCapsule)?;
        if capsule.result_digest != result_digest {
            return Err(CoreError::InvalidRecoveryCapsule);
        }
        let capsule_request_hash = capsule.request_hash;

        let prior_root = self.state_root();
        let mut capsules = self.recovery_capsules.clone();
        capsules.remove(&command_idempotency_key);
        let mut processed = self.processed.clone();
        let processed_command = processed
            .get_mut(&command_idempotency_key)
            .ok_or(CoreError::InvalidRecoveryCapsule)?;
        if processed_command.request_hash != capsule_request_hash {
            return Err(CoreError::InvalidRecoveryCapsule);
        }
        processed_command.response = None;
        let mut keys = self.system_keys.clone();
        keys.remove(&recovery_result_marker(
            &command_idempotency_key,
            result_digest,
        ));
        keys.insert(idempotency_key.clone());
        keys.insert(recovery_archive_ack_marker(
            &command_idempotency_key,
            result_digest,
            archive_row_commitment,
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
        let entry = JournaledSystemCommand::AcknowledgeRecoveryArchive {
            idempotency_key: idempotency_key.clone(),
            command_idempotency_key,
            result_digest,
            archive_row_commitment,
        };
        let record = self.journal.append(next_root, &entry)?;
        self.recovery_capsules = capsules;
        self.processed = processed;
        self.system_keys = keys;
        self.sequence = next_sequence;
        Ok(self.system_response(
            "acknowledge-recovery-archive",
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
        sessions.prune_expired(now_millis);
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
            now_millis,
        };
        let command_commitment = system_command_commitment(&entry)?;
        let registration_evidence = registration_evidence(identity_commitment, public_key);
        let record = self.journal.append(next_root, &entry)?;
        self.sessions = sessions;
        self.system_keys = keys;
        self.sequence = next_sequence;
        let receipt = self.receipt_signer.sign(
            "register-session".into(),
            idempotency_key,
            Some(command_commitment),
            Some(true),
            None,
            None,
            next_sequence,
            prior_root,
            next_root,
            record.record_hash,
            now_millis,
        );
        Ok(SystemResponse {
            receipt,
            encrypted_record: record,
            audit_fills: Vec::new(),
            evidence_commitment: Some(registration_evidence.commitment),
            registration_evidence: Some(registration_evidence),
            transfer_account: None,
        })
    }

    /// Registers an opaque, stable receive handle for an enclave-local user.
    ///
    /// This is deliberately a separate journal command from session registration:
    /// historical REGISTER_SESSION records therefore retain their exact state roots.
    /// The handle is deterministically bound to the eligibility identity commitment,
    /// and the binding lives in the already-committed system key set.
    pub fn register_transfer_account(
        &mut self,
        idempotency_key: String,
        identity_commitment: [u8; 32],
        now_millis: i64,
    ) -> CoreResult<SystemResponse> {
        self.validate_new_system_key(&idempotency_key)?;
        let prior_root = self.state_root();
        let private_user_id = derive_private_user_id(&self.identity_key, &identity_commitment);
        let transfer_account = derive_transfer_account(&identity_commitment);
        let mut keys = self.system_keys.clone();
        keys.insert(idempotency_key.clone());
        keys.insert(transfer_account_marker(&transfer_account, &private_user_id));
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
        let entry = JournaledSystemCommand::RegisterTransferAccount {
            idempotency_key: idempotency_key.clone(),
            identity_commitment,
        };
        let record = self.journal.append(next_root, &entry)?;
        self.system_keys = keys;
        self.sequence = next_sequence;
        let mut response = self.system_response(
            "register-transfer-account",
            idempotency_key,
            prior_root,
            next_root,
            record,
            now_millis,
        );
        response.transfer_account = Some(transfer_account);
        Ok(response)
    }

    pub fn transfer_account_status(&self, identity_commitment: [u8; 32]) -> TransferAccountStatus {
        let private_user_id = derive_private_user_id(&self.identity_key, &identity_commitment);
        let transfer_account = derive_transfer_account(&identity_commitment);
        TransferAccountStatus {
            registered: self.system_keys.contains(&transfer_account_marker(
                &transfer_account,
                &private_user_id,
            )),
            transfer_account,
        }
    }

    /// Produce the owner-scoped portfolio projection used by an enclave-only
    /// delegated read. Authorization and response encryption are enforced by
    /// the enclave command boundary; this method only derives the private
    /// owner from the immutable identity commitment and never persists a
    /// plaintext identity-to-financial projection.
    pub fn portfolio_snapshot_for_identity(
        &self,
        identity_commitment: [u8; 32],
        now_millis: i64,
    ) -> PortfolioSnapshot {
        let private_user_id = derive_private_user_id(&self.identity_key, &identity_commitment);
        portfolio_snapshot(
            &self.ledger,
            &self.books,
            &self.position_cost_basis,
            &self.identity_key,
            &private_user_id,
            now_millis,
        )
    }

    /// Performs the one-time, freeze-only historical custody opening after an
    /// exact 976 checkpoint has been restored and independently reconciled.
    /// The expected checkpoint tuple prevents applying an opening to a drifted
    /// or substituted snapshot. No public operator command exposes this method;
    /// release tooling must add a separately reviewed, attested invocation.
    #[allow(clippy::too_many_arguments)]
    pub fn migrate_historical_pool_cash_opening(
        &mut self,
        idempotency_key: String,
        evidence_hash: [u8; 32],
        openings: Vec<PoolCashOpening>,
        expected_sequence: u64,
        expected_state_root: [u8; 32],
        expected_journal_head: [u8; 32],
        now_millis: i64,
    ) -> CoreResult<SystemResponse> {
        if !self.trading_frozen
            || self.sequence != expected_sequence
            || self.state_root() != expected_state_root
            || self.journal.chain_head() != (expected_sequence, expected_journal_head)
        {
            return Err(CoreError::JournalChainMismatch);
        }
        self.validate_new_system_key(&idempotency_key)?;
        let prior_root = self.state_root();
        let mut ledger = self.ledger.clone();
        ledger.apply_historical_pool_cash_opening(
            format!("historical-opening:{idempotency_key}"),
            evidence_hash,
            openings.clone(),
        )?;
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
        let entry = JournaledSystemCommand::HistoricalPoolCashOpening {
            idempotency_key: idempotency_key.clone(),
            evidence_hash,
            openings,
            source_sequence: expected_sequence,
            source_state_root: expected_state_root,
            source_journal_head: expected_journal_head,
        };
        let record = self.journal.append(next_root, &entry)?;
        self.ledger = ledger;
        self.system_keys = keys;
        self.sequence = next_sequence;
        Ok(self.system_response(
            "historical-pool-cash-opening",
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
        if matches!(
            account.bucket,
            AccountBucket::UserAvailable
                | AccountBucket::UserWithdrawalHold
                | AccountBucket::VaultCash
                | AccountBucket::VaultStrategyInTransit
                | AccountBucket::VaultStrategyReceivable
        ) {
            return Err(CoreError::InvalidOrder(
                "custody flows require their dedicated balanced command".into(),
            ));
        }
        self.apply_external_flow_internal(
            idempotency_key,
            account,
            amount,
            direction,
            evidence_hash,
            now_millis,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn apply_vault_strategy_transition(
        &mut self,
        idempotency_key: String,
        evidence_hash: [u8; 32],
        vault_commitment: [u8; 32],
        strategy_commitment: [u8; 32],
        operation_commitment: [u8; 32],
        asset: String,
        amount: u128,
        transition: VaultStrategyTransition,
        now_millis: i64,
    ) -> CoreResult<SystemResponse> {
        self.validate_new_system_key(&idempotency_key)?;
        let prior_root = self.state_root();
        let transaction = VaultStrategyTransaction {
            idempotency_key: format!("vault-strategy:{idempotency_key}"),
            evidence_hash,
            vault_commitment,
            strategy_commitment,
            operation_commitment,
            asset,
            amount,
            transition,
        };
        let mut ledger = self.ledger.clone();
        ledger.apply_vault_strategy_transition(transaction.clone())?;
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
        let entry = JournaledSystemCommand::VaultStrategyTransition {
            idempotency_key: idempotency_key.clone(),
            transaction,
        };
        let record = self.journal.append(next_root, &entry)?;
        self.ledger = ledger;
        self.system_keys = keys;
        self.sequence = next_sequence;
        Ok(self.system_response(
            "vault-strategy-transition",
            idempotency_key,
            prior_root,
            next_root,
            record,
            now_millis,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_external_flow_internal(
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

    fn apply_confirmed_deposit(
        &mut self,
        idempotency_key: String,
        account: AccountKey,
        amount: u128,
        evidence_hash: [u8; 32],
        now_millis: i64,
    ) -> CoreResult<SystemResponse> {
        self.validate_new_system_key(&idempotency_key)?;
        let prior_root = self.state_root();
        let flow = ExternalFlowTransaction {
            idempotency_key: format!("deposit:{idempotency_key}"),
            evidence_hash,
            account,
            amount,
            direction: ExternalFlowDirection::Inflow,
        };
        let mut ledger = self.ledger.clone();
        ledger.apply_confirmed_deposit(flow.clone())?;
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
        let entry = JournaledSystemCommand::ConfirmedDeposit {
            idempotency_key: idempotency_key.clone(),
            flow,
        };
        let record = self.journal.append(next_root, &entry)?;
        self.ledger = ledger;
        self.system_keys = keys;
        self.sequence = next_sequence;
        Ok(self.system_response(
            "confirmed-deposit",
            idempotency_key,
            prior_root,
            next_root,
            record,
            now_millis,
        ))
    }

    fn apply_confirmed_withdrawal(
        &mut self,
        idempotency_key: String,
        account: AccountKey,
        amount: u128,
        evidence_hash: [u8; 32],
        now_millis: i64,
    ) -> CoreResult<SystemResponse> {
        self.validate_new_system_key(&idempotency_key)?;
        let prior_root = self.state_root();
        let flow = ExternalFlowTransaction {
            idempotency_key: format!("withdrawal:{idempotency_key}"),
            evidence_hash,
            account,
            amount,
            direction: ExternalFlowDirection::Outflow,
        };
        let mut ledger = self.ledger.clone();
        ledger.apply_confirmed_withdrawal(flow.clone())?;
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
        let entry = JournaledSystemCommand::ConfirmedWithdrawal {
            idempotency_key: idempotency_key.clone(),
            flow,
        };
        let record = self.journal.append(next_root, &entry)?;
        self.ledger = ledger;
        self.system_keys = keys;
        self.sequence = next_sequence;
        // Keep the existing receipt command ID stable because the backend's
        // deterministic archive lookup uses this public protocol identifier.
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
        let account = AccountKey::new(owner, bucket.clone(), asset);
        match (bucket, direction) {
            (AccountBucket::UserAvailable, ExternalFlowDirection::Inflow) => self
                .apply_confirmed_deposit(
                    idempotency_key,
                    account,
                    amount,
                    evidence_hash,
                    now_millis,
                ),
            (AccountBucket::UserWithdrawalHold, ExternalFlowDirection::Outflow) => self
                .apply_confirmed_withdrawal(
                    idempotency_key,
                    account,
                    amount,
                    evidence_hash,
                    now_millis,
                ),
            _ => Err(CoreError::InvalidOrder(
                "invalid external user-flow direction".into(),
            )),
        }
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
        source_id_hash: [u8; 32],
        program_id: String,
        program_type: String,
        policy_id: String,
        policy_version: u32,
        fee_policy_version: String,
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
        private_rewards.accrue(
            &owner,
            &chain,
            &reward_token,
            amount_atomic,
            evidence_hash,
            source_id_hash,
            &program_id,
            &program_type,
            &policy_id,
            policy_version,
            &fee_policy_version,
        )?;
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
            source_id_hash,
            program_id,
            program_type,
            policy_id,
            policy_version,
            fee_policy_version,
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
        ledger.release_withdrawal(
            format!("withdrawal-release:{idempotency_key}"),
            evidence_hash,
            AccountKey::new(&owner, AccountBucket::UserWithdrawalHold, &asset),
            AccountKey::new(owner, AccountBucket::UserAvailable, &asset),
            amount_atomic,
        )?;
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

    pub fn resolve_binance_market(
        &mut self,
        idempotency_key: String,
        signed: SignedBinanceResolution,
        now_millis: i64,
    ) -> CoreResult<SystemResponse> {
        self.validate_new_system_key(&idempotency_key)?;
        let market = self
            .markets
            .get(&signed.statement.market_id)
            .ok_or_else(|| CoreError::InvalidResolution("unknown market".into()))?;
        let outcome =
            validate_binance_resolution(market, &signed, self.oracle_public_key, now_millis)?;
        let resolution = MarketResolution {
            outcome,
            evidence: ResolutionEvidence::BinanceSpotKlineMedian {
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

    pub fn resolve_exact_condition_market(
        &mut self,
        idempotency_key: String,
        signed: SignedExactConditionResolution,
        now_millis: i64,
    ) -> CoreResult<SystemResponse> {
        self.validate_new_system_key(&idempotency_key)?;
        let market = self
            .markets
            .get(&signed.statement.market_id)
            .ok_or_else(|| CoreError::InvalidResolution("unknown market".into()))?;
        validate_exact_condition_resolution(market, &signed, self.oracle_public_key, now_millis)?;
        let resolution = MarketResolution {
            outcome: signed.statement.outcome,
            evidence: ResolutionEvidence::PublicExactCondition {
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
            ResolutionEvidence::BinanceSpotKlineMedian { statement } => &statement.market_id,
            ResolutionEvidence::PolymarketExactCondition { statement } => &statement.market_id,
            ResolutionEvidence::PublicExactCondition { statement } => &statement.market_id,
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
        let payout_evidence_hash = resolution_payout_evidence_hash(&resolution)?;
        let payout_kind = match outcome {
            ResolutionOutcome::Up => ResolutionPayoutKind::Up,
            ResolutionOutcome::Down => ResolutionPayoutKind::Down,
            ResolutionOutcome::Push => ResolutionPayoutKind::Push,
        };

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
            let winning_fee = settlement_winning_fee(
                market.fee_profile_id,
                basis,
                gross,
                matches!(outcome, ResolutionOutcome::Push),
            )?;
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
                payout_evidence_hash,
                payout_kind,
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

    /// Commits the deterministic external-venue intent before any network I/O.
    /// The coordinator must finalize this transition before asking the enclave
    /// to submit the venue order.
    pub fn mark_bootstrap_venue_intent_durable(
        &mut self,
        idempotency_key: String,
        execution_id: Uuid,
        prepared_order: BootstrapPreparedVenueOrder,
        now_millis: i64,
    ) -> CoreResult<SystemResponse> {
        self.validate_new_system_key(&idempotency_key)?;
        let prior_root = self.state_root();
        let mut executions = self.bootstrap_executions.clone();
        let execution = executions
            .get_mut(&execution_id)
            .ok_or_else(|| CoreError::InvalidOrder("unknown bootstrap execution".into()))?;
        if execution.view.state != BootstrapExecutionState::FundsReserved {
            return Err(CoreError::InvalidOrder(
                "bootstrap execution is not awaiting a durable venue intent".into(),
            ));
        }
        if !prepared_order.deterministic_order_id.starts_with("0x")
            || prepared_order.deterministic_order_id.len() != 66
            || prepared_order.exact_request_body.len() < 64
            || prepared_order.exact_request_body.len() > 65_536
            || Sha256::digest(prepared_order.exact_request_body.as_bytes()).as_slice()
                != prepared_order.request_body_sha256
        {
            return Err(CoreError::InvalidOrder(
                "invalid prepared venue order".into(),
            ));
        }
        execution.view.state = BootstrapExecutionState::VenueIntentDurable;
        execution.prepared_venue_order = Some(prepared_order.clone());
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
        let entry = JournaledSystemCommand::MarkBootstrapVenueIntentDurable {
            idempotency_key: idempotency_key.clone(),
            execution_id,
            deterministic_order_id: prepared_order.deterministic_order_id,
            request_body_sha256: prepared_order.request_body_sha256,
            credential_generation_sha256: prepared_order.credential_generation_sha256,
        };
        let record = self.journal.append(next_root, &entry)?;
        self.bootstrap_executions = executions;
        self.system_keys = keys;
        self.sequence = next_sequence;
        Ok(self.system_response(
            "bootstrap-venue-intent-durable",
            idempotency_key,
            prior_root,
            next_root,
            record,
            now_millis,
        ))
    }

    pub fn bootstrap_prepared_venue_order(
        &self,
        execution_id: Uuid,
    ) -> CoreResult<BootstrapPreparedVenueOrder> {
        let execution = self
            .bootstrap_executions
            .get(&execution_id)
            .ok_or_else(|| CoreError::InvalidOrder("unknown bootstrap execution".into()))?;
        if execution.view.state != BootstrapExecutionState::VenueSubmissionAttempted {
            return Err(CoreError::InvalidOrder(
                "venue submission is not authorized".into(),
            ));
        }
        execution
            .prepared_venue_order
            .clone()
            .ok_or_else(|| CoreError::InvalidOrder("prepared venue order is unavailable".into()))
    }

    pub fn authorize_bootstrap_submission_attempt(
        &mut self,
        idempotency_key: String,
        execution_id: Uuid,
        now_millis: i64,
    ) -> CoreResult<SystemResponse> {
        self.validate_new_system_key(&idempotency_key)?;
        let prior_root = self.state_root();
        let mut executions = self.bootstrap_executions.clone();
        let execution = executions
            .get_mut(&execution_id)
            .ok_or_else(|| CoreError::InvalidOrder("unknown bootstrap execution".into()))?;
        if execution.view.state != BootstrapExecutionState::VenueIntentDurable
            || execution.prepared_venue_order.is_none()
        {
            return Err(CoreError::InvalidOrder(
                "durable venue intent is required".into(),
            ));
        }
        execution.view.state = BootstrapExecutionState::VenueSubmissionAttempted;
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
        let entry = JournaledSystemCommand::AuthorizeBootstrapSubmissionAttempt {
            idempotency_key: idempotency_key.clone(),
            execution_id,
        };
        let record = self.journal.append(next_root, &entry)?;
        self.bootstrap_executions = executions;
        self.system_keys = keys;
        self.sequence = next_sequence;
        Ok(self.system_response(
            "bootstrap-submission-attempt-authorized",
            idempotency_key,
            prior_root,
            next_root,
            record,
            now_millis,
        ))
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
            SignedResolutionEvidence::Binance(signed) => {
                let derived = validate_binance_resolution(
                    market,
                    signed,
                    self.oracle_public_key,
                    now_millis,
                )?;
                if signed.statement.market_id != market_id || derived != outcome {
                    return Err(CoreError::InvalidResolution(
                        "on-chain outcome does not match Binance evidence".into(),
                    ));
                }
            }
            SignedResolutionEvidence::ExactCondition(signed) => {
                validate_exact_condition_resolution(
                    market,
                    signed,
                    self.oracle_public_key,
                    now_millis,
                )?;
                if signed.statement.market_id != market_id || signed.statement.outcome != outcome {
                    return Err(CoreError::InvalidResolution(
                        "on-chain outcome does not match exact-condition evidence".into(),
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
        if let Some(committed) = self.resolutions.get(market_id) {
            let evidence_matches = match (&committed.evidence, evidence) {
                (
                    ResolutionEvidence::PythHistoricalMedian {
                        statement: committed,
                    },
                    SignedResolutionEvidence::Pyth(candidate),
                ) => committed == &candidate.statement,
                (
                    ResolutionEvidence::BinanceSpotKlineMedian {
                        statement: committed,
                    },
                    SignedResolutionEvidence::Binance(candidate),
                ) => committed == &candidate.statement,
                (
                    ResolutionEvidence::PublicExactCondition {
                        statement: committed,
                    },
                    SignedResolutionEvidence::ExactCondition(candidate),
                ) => committed == &candidate.statement,
                (
                    ResolutionEvidence::PolymarketExactCondition {
                        statement: committed,
                    },
                    SignedResolutionEvidence::Polymarket(candidate),
                ) => committed == &candidate.statement,
                _ => false,
            };
            if committed.outcome != outcome || !evidence_matches {
                return Err(CoreError::InvalidResolution(
                    "resolution evidence conflicts with committed resolution".into(),
                ));
            }
            // Signing and publishing evidence are intentionally retryable after
            // the ledger commit. A lost response must not strand the public
            // projection in RESOLUTION_PENDING. Only valid evidence containing
            // the exact statement and outcome already committed by the enclave
            // may be re-authorized.
            return Ok(());
        }
        Ok(())
    }

    pub fn bootstrap_venue_order_id(&self, execution_id: Uuid) -> CoreResult<String> {
        let execution = self
            .bootstrap_executions
            .get(&execution_id)
            .ok_or_else(|| CoreError::InvalidOrder("unknown bootstrap execution".into()))?;
        match execution.view.state {
            BootstrapExecutionState::VenueSubmitted => execution.venue_order_id.clone(),
            BootstrapExecutionState::VenueSubmissionAttempted => execution
                .prepared_venue_order
                .as_ref()
                .map(|prepared| prepared.deterministic_order_id.clone()),
            _ => None,
        }
        .ok_or_else(|| {
            CoreError::InvalidOrder("bootstrap execution is not awaiting venue confirmation".into())
        })
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
        if execution.view.state != BootstrapExecutionState::VenueSubmissionAttempted {
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
        let mut private_rewards = self.private_rewards.clone();
        let quantity = execution.view.quantity_micros;
        let fill_notional = notional(fill_price_micros, quantity)?;
        let taker_fee = taker_fee_micros(market.fee_profile_id, quantity, fill_price_micros)?;
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
        let (reward_chain, reward_token) = reward_rail(market)?;
        private_rewards.record_fill(
            &execution_id.to_string(),
            &execution.private_user_id,
            None,
            reward_chain,
            reward_token,
            market.fee_profile_id.fee_policy_version(),
            &market.fee_profile_id.immutable_profile_id(),
            "NORMAL",
            quantity,
            taker_fee,
            0,
            now_millis,
        )?;

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
            &private_rewards,
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
        self.private_rewards = private_rewards;
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
            BootstrapExecutionState::FundsReserved
                | BootstrapExecutionState::VenueIntentDurable
                | BootstrapExecutionState::VenueSubmissionAttempted
                | BootstrapExecutionState::VenueSubmitted
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
        if matches!(
            command.action,
            UserCommandAction::Portfolio
                | UserCommandAction::Rewards
                | UserCommandAction::BootstrapStatus { .. }
        ) {
            return self.execute_readonly(command, expected_hash, now_millis);
        }
        if let Some(processed) = self.processed.get(&command.idempotency_key) {
            if processed.request_hash != expected_hash {
                return Err(CoreError::DuplicateCommand);
            }
            if !self.system_keys.contains(&processed_command_marker(
                &command.idempotency_key,
                full_user_command_commitment(&command)?,
            )) {
                return Err(CoreError::PreviouslyProcessed);
            }
            return processed
                .response
                .clone()
                .ok_or(CoreError::PreviouslyProcessed);
        }
        if self.trading_frozen
            && matches!(
                &command.action,
                UserCommandAction::SubmitOrder { .. }
                    | UserCommandAction::ReplaceOrder { .. }
                    | UserCommandAction::ClosePosition { .. }
                    | UserCommandAction::CompleteSet { .. }
                    | UserCommandAction::RequestWithdrawal { .. }
            )
        {
            return Err(CoreError::TradingFrozen);
        }
        if matches!(
            command.action,
            UserCommandAction::SubmitOrder { .. } | UserCommandAction::RequestWithdrawal { .. }
        ) {
            reserve_recovery_capacity(&self.recovery_capsules)?;
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
        advance_trusted_time_high_water(&mut system_keys, now_millis)?;
        let mut audit_drafts = Vec::new();
        let task_order_commitment = match &command.action {
            UserCommandAction::SubmitOrder { order } => {
                Some(private_order_commitment(order, &private_user_id))
            }
            UserCommandAction::ReplaceOrder { replacement, .. } => {
                Some(private_order_commitment(replacement, &private_user_id))
            }
            _ => None,
        };
        let result = match &command.action {
            UserCommandAction::SubmitOrder { order } => {
                let mut order = order.clone();
                order.private_user_id = private_user_id.clone();
                let market = self
                    .markets
                    .get(&order.market_id)
                    .ok_or_else(|| CoreError::InvalidOrder("unknown market".into()))?;
                validate_order_for_market(&order, market, now_millis)?;
                match &market.execution {
                    MarketExecution::NativeClob | MarketExecution::NativeExactCondition { .. } => {
                        // GTD deadlines are consensus inputs, but wall-clock
                        // passage alone cannot mutate the enclave state. At the
                        // next valid write for this market, expire all elapsed
                        // orders and release their grouped holds atomically
                        // before position-limit validation or matching.
                        {
                            let book = books.entry(order.market_id.clone()).or_default();
                            let expired = book.cancel_expired(&order.market_id, now_millis);
                            let releases = cancellation_transfers(&ledger, book, market, &expired)?;
                            if !releases.is_empty() {
                                ledger.apply(LedgerTransaction {
                                    idempotency_key: format!(
                                        "expire-orders:{}",
                                        command.idempotency_key
                                    ),
                                    business_reference: command.command_id.clone(),
                                    transfers: releases,
                                })?;
                            }
                        }
                        enforce_user_position_limit(
                            &ledger,
                            &books,
                            &bootstrap_executions,
                            market,
                            &order,
                        )?;
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
                                let (transfers, fill_postings) = settlement_transfers(
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
                                let transaction = LedgerTransaction {
                                    idempotency_key: format!("order:{}", command.idempotency_key),
                                    business_reference: command.command_id.clone(),
                                    transfers,
                                };
                                if fill_postings.is_empty() {
                                    ledger.apply(transaction)?;
                                } else {
                                    ledger
                                        .apply_normal_fill_settlement(transaction, fill_postings)?;
                                }
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
                            record_native_fill_economics(
                                &mut private_rewards,
                                market,
                                &match_result,
                                now_millis,
                            )?;
                        }
                        audit_drafts = native_audit_drafts(&order, &match_result, market)?;
                        CommandResult::Order {
                            result: redact_match_result(match_result),
                        }
                    }
                    MarketExecution::PolymarketBootstrap { .. } => {
                        enforce_user_position_limit(
                            &ledger,
                            &books,
                            &bootstrap_executions,
                            market,
                            &order,
                        )?;
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
                                prepared_venue_order: None,
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
            UserCommandAction::CancelAllOrders { filter } => {
                let market_ids: Vec<String> = match filter {
                    CancelAllOrdersFilter::All => self.markets.keys().cloned().collect(),
                    CancelAllOrdersFilter::Market { market_id } => {
                        if !self.markets.contains_key(market_id) {
                            return Err(CoreError::InvalidOrder("unknown market".into()));
                        }
                        vec![market_id.clone()]
                    }
                    CancelAllOrdersFilter::Asset { asset } => {
                        if asset.is_empty() || asset.len() > 64 || !asset.is_ascii() {
                            return Err(CoreError::InvalidOrder("invalid asset filter".into()));
                        }
                        let matching: Vec<String> = self
                            .markets
                            .iter()
                            .filter(|(_, market)| market.settlement_asset == *asset)
                            .map(|(market_id, _)| market_id.clone())
                            .collect();
                        if matching.is_empty() {
                            return Err(CoreError::InvalidOrder("unknown asset".into()));
                        }
                        matching
                    }
                };

                let mut cancelled_by_market = BTreeMap::<String, Vec<BookOrder>>::new();
                for market_id in market_ids {
                    let Some(book) = books.get_mut(&market_id) else {
                        continue;
                    };
                    let mut owned: Vec<BookOrder> = book
                        .orders_for_owner(&private_user_id)
                        .into_iter()
                        .filter(|order| {
                            matches!(
                                order.status,
                                OrderStatus::Open | OrderStatus::PartiallyFilled
                            )
                        })
                        .collect();
                    owned.sort_by_key(|order| (order.sequence, order.order_id));
                    for order in owned {
                        let cancelled =
                            book.cancel(order.order_id, &private_user_id, now_millis)?;
                        cancelled_by_market
                            .entry(market_id.clone())
                            .or_default()
                            .push(cancelled);
                    }
                }

                let mut transfers = Vec::new();
                let mut outcomes = Vec::new();
                for (market_id, cancelled) in &cancelled_by_market {
                    let market = self
                        .markets
                        .get(market_id)
                        .ok_or_else(|| CoreError::InvalidOrder("unknown market".into()))?;
                    let book = books.get(market_id).ok_or_else(|| {
                        CoreError::InvalidOrder("order book does not exist".into())
                    })?;
                    transfers.extend(cancellation_transfers(&ledger, book, market, cancelled)?);
                    outcomes.extend(cancelled.iter().map(|order| CancelledOrderOutcome {
                        order_id: order.order_id,
                        market_id: order.market_id.clone(),
                        status: order.status,
                    }));
                }
                if !outcomes.is_empty() && transfers.is_empty() {
                    return Err(CoreError::UnbalancedTransaction);
                }
                if !transfers.is_empty() {
                    ledger.apply(LedgerTransaction {
                        idempotency_key: format!("cancel-all:{}", command.idempotency_key),
                        business_reference: command.command_id.clone(),
                        transfers,
                    })?;
                }
                CommandResult::OrdersCancelled {
                    filter: Some(filter.clone()),
                    outcomes,
                }
            }
            UserCommandAction::PreviewPositionClose {
                position_id,
                market_id,
                outcome,
                session_tag,
                quantity_micros,
                minimum_price_micros,
            } => {
                let order = position_close_order(
                    &self.identity_key,
                    &ledger,
                    &self.markets,
                    &self.resolutions,
                    &private_user_id,
                    position_id,
                    market_id,
                    *outcome,
                    *quantity_micros,
                    *minimum_price_micros,
                    position_close_order_id(
                        &command.command_id,
                        &command.idempotency_key,
                        position_id,
                    ),
                    now_millis,
                )?;
                let market = self
                    .markets
                    .get(market_id)
                    .ok_or_else(|| CoreError::InvalidOrder("unknown market".into()))?;
                if !matches!(
                    market.execution,
                    MarketExecution::NativeClob | MarketExecution::NativeExactCondition { .. }
                ) {
                    return Err(CoreError::InvalidOrder(
                        "position close is unavailable for bootstrap execution".into(),
                    ));
                }
                let prior_book = books.get(market_id).cloned().unwrap_or_default();
                let mut book = prior_book.clone();
                let match_result = book.submit(order.clone(), now_millis)?;
                CommandResult::PositionClosePreview {
                    market_id: Some(market_id.clone()),
                    outcome: Some(*outcome),
                    session_tag: Some(session_tag.clone()),
                    preview: position_close_preview(
                        &self.identity_key,
                        &private_user_id,
                        *outcome,
                        position_id,
                        market,
                        &prior_book,
                        &order,
                        &match_result,
                        now_millis.saturating_add(POSITION_CLOSE_QUOTE_TTL_MILLIS),
                    )?,
                }
            }
            UserCommandAction::ClosePosition {
                position_id,
                market_id,
                outcome,
                session_tag,
                quantity_micros,
                minimum_price_micros,
                quote,
            } => {
                let order_id = position_close_order_id(
                    &command.command_id,
                    &command.idempotency_key,
                    position_id,
                );
                let order = position_close_order(
                    &self.identity_key,
                    &ledger,
                    &self.markets,
                    &self.resolutions,
                    &private_user_id,
                    position_id,
                    market_id,
                    *outcome,
                    *quantity_micros,
                    *minimum_price_micros,
                    order_id,
                    now_millis,
                )?;
                let market = self
                    .markets
                    .get(market_id)
                    .ok_or_else(|| CoreError::InvalidOrder("unknown market".into()))?;
                if !matches!(
                    market.execution,
                    MarketExecution::NativeClob | MarketExecution::NativeExactCondition { .. }
                ) {
                    return Err(CoreError::InvalidOrder(
                        "position close is unavailable for bootstrap execution".into(),
                    ));
                }
                let prior_book = books.get(market_id).cloned().unwrap_or_default();
                let book = books.entry(market_id.clone()).or_default();
                let match_result = book.submit(order.clone(), now_millis)?;
                let preview = position_close_preview(
                    &self.identity_key,
                    &private_user_id,
                    *outcome,
                    position_id,
                    market,
                    &prior_book,
                    &order,
                    &match_result,
                    quote.expires_at_millis,
                )?;
                // Quote validity is half-open: it is valid strictly before the
                // enclave-trusted expiry instant and stale at equality.
                if quote.expires_at_millis <= now_millis || preview != *quote {
                    return Err(CoreError::InvalidOrder(
                        "position close quote is stale".into(),
                    ));
                }
                if match_result
                    .fills
                    .iter()
                    .all(|fill| fill.match_type == MatchType::Normal)
                {
                    let (transfers, fill_postings) =
                        settlement_transfers(&self.books, &books, market, &order, &match_result)?;
                    apply_fill_cost_basis(
                        &self.ledger,
                        &self.books,
                        &books,
                        market,
                        &order,
                        &match_result,
                        &mut position_cost_basis,
                    )?;
                    let transaction = LedgerTransaction {
                        idempotency_key: format!("position-close:{}", command.idempotency_key),
                        business_reference: command.command_id.clone(),
                        transfers,
                    };
                    if fill_postings.is_empty() {
                        ledger.apply(transaction)?;
                    } else {
                        ledger.apply_normal_fill_settlement(transaction, fill_postings)?;
                    }
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
                record_native_fill_economics(
                    &mut private_rewards,
                    market,
                    &match_result,
                    now_millis,
                )?;
                audit_drafts = native_audit_drafts(&order, &match_result, market)?;
                CommandResult::PositionClosed {
                    market_id: Some(market_id.clone()),
                    outcome: Some(*outcome),
                    session_tag: Some(session_tag.clone()),
                    preview,
                    order_id,
                }
            }
            UserCommandAction::ReplaceOrder {
                market_id,
                order_id,
                replacement,
            } => {
                let market = self
                    .markets
                    .get(market_id)
                    .ok_or_else(|| CoreError::InvalidOrder("unknown market".into()))?;
                if !matches!(
                    market.execution,
                    MarketExecution::NativeClob | MarketExecution::NativeExactCondition { .. }
                ) {
                    return Err(CoreError::InvalidOrder(
                        "order replacement is unavailable for bootstrap execution".into(),
                    ));
                }

                let book = books
                    .get_mut(market_id)
                    .ok_or_else(|| CoreError::InvalidOrder("order book does not exist".into()))?;
                let original = book
                    .order(*order_id)
                    .cloned()
                    .ok_or_else(|| CoreError::InvalidOrder("order does not exist".into()))?;
                if original.private_user_id != private_user_id {
                    return Err(CoreError::InvalidOrder("order owner mismatch".into()));
                }
                if replacement.order_id == *order_id {
                    return Err(CoreError::InvalidOrder(
                        "replacement requires a new order id".into(),
                    ));
                }
                if replacement.market_id != *market_id
                    || replacement.outcome != original.outcome
                    || replacement.action != original.action
                {
                    return Err(CoreError::InvalidOrder(
                        "replacement cannot change market, outcome, or action".into(),
                    ));
                }

                let cancelled = book.cancel(*order_id, &private_user_id, now_millis)?;
                let release = cancellation_transfers(
                    &ledger,
                    book,
                    market,
                    std::slice::from_ref(&cancelled),
                )?;
                ledger.apply(LedgerTransaction {
                    idempotency_key: format!("replace-cancel:{}", command.idempotency_key),
                    business_reference: command.command_id.clone(),
                    transfers: release,
                })?;

                // The replacement is always a new order and therefore receives fresh
                // sequence priority. Client-supplied timestamps, fill counters and owner
                // fields are discarded at this trust boundary.
                let mut incoming = replacement.clone();
                incoming.private_user_id = private_user_id.clone();
                incoming.created_at_millis = 0;
                incoming.updated_at_millis = 0;
                incoming.sequence = 0;
                incoming.filled_micros = 0;
                incoming.remaining_micros = incoming.quantity_micros;
                incoming.status = OrderStatus::Open;
                validate_order_for_market(&incoming, market, now_millis)?;
                enforce_user_position_limit(
                    &ledger,
                    &books,
                    &bootstrap_executions,
                    market,
                    &incoming,
                )?;

                let replacement_prior_books = books.clone();
                let match_result = books
                    .get_mut(market_id)
                    .expect("replacement book remains present")
                    .submit(incoming.clone(), now_millis)?;
                if match_result
                    .accepted_order
                    .as_ref()
                    .is_some_and(|accepted| accepted.status == OrderStatus::Rejected)
                {
                    return Err(CoreError::InvalidOrder(
                        "replacement order was rejected".into(),
                    ));
                }
                if match_result.accepted_order.as_ref().is_some() {
                    if match_result
                        .fills
                        .iter()
                        .all(|fill| fill.match_type == MatchType::Normal)
                    {
                        let (transfers, fill_postings) = settlement_transfers(
                            &replacement_prior_books,
                            &books,
                            market,
                            &incoming,
                            &match_result,
                        )?;
                        apply_fill_cost_basis(
                            &ledger,
                            &replacement_prior_books,
                            &books,
                            market,
                            &incoming,
                            &match_result,
                            &mut position_cost_basis,
                        )?;
                        let transaction = LedgerTransaction {
                            idempotency_key: format!("replace-order:{}", command.idempotency_key),
                            business_reference: command.command_id.clone(),
                            transfers,
                        };
                        if fill_postings.is_empty() {
                            ledger.apply(transaction)?;
                        } else {
                            ledger.apply_normal_fill_settlement(transaction, fill_postings)?;
                        }
                    } else {
                        apply_complete_set_match_settlement(
                            &mut ledger,
                            &replacement_prior_books,
                            &books,
                            market,
                            &incoming,
                            &match_result,
                            &mut position_cost_basis,
                            &format!("replace:{}", command.idempotency_key),
                            &command.command_id,
                        )?;
                    }
                    record_native_fill_economics(
                        &mut private_rewards,
                        market,
                        &match_result,
                        now_millis,
                    )?;
                }
                audit_drafts = native_audit_drafts(&incoming, &match_result, market)?;
                let mut public_cancelled = cancelled;
                public_cancelled.private_user_id.clear();
                CommandResult::Replaced {
                    cancelled: public_cancelled,
                    result: redact_match_result(match_result),
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
                    &self.identity_key,
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
            UserCommandAction::TransferFunds {
                transfer_id,
                recipient_account,
                asset,
                amount_atomic,
            } => {
                validate_private_transfer(recipient_account, asset, *amount_atomic)?;
                let recipient_private_user_id =
                    resolve_transfer_account(&system_keys, recipient_account)?;
                if recipient_private_user_id == private_user_id {
                    return Err(CoreError::InvalidOrder(
                        "sender and recipient must be different".into(),
                    ));
                }
                ledger.apply(LedgerTransaction {
                    idempotency_key: format!("private-transfer:{}", command.idempotency_key),
                    business_reference: transfer_id.to_string(),
                    transfers: vec![Transfer {
                        from: AccountKey::new(
                            &private_user_id,
                            AccountBucket::UserAvailable,
                            asset,
                        ),
                        to: AccountKey::new(
                            recipient_private_user_id,
                            AccountBucket::UserAvailable,
                            asset,
                        ),
                        amount: *amount_atomic,
                    }],
                })?;
                CommandResult::FundsTransferred {
                    transfer_id: *transfer_id,
                    recipient_account: recipient_account.clone(),
                    asset: asset.clone(),
                    amount_atomic: *amount_atomic,
                }
            }
        };

        if let CommandResult::Order { result } = &result {
            if result.fills.len() > MAX_RECOVERY_FILLS {
                return Err(CoreError::RecoveryCapsuleTooLarge);
            }
        }

        system_keys.insert(processed_command_marker(
            &command.idempotency_key,
            full_user_command_commitment(&command)?,
        ));
        let recovery_result_digest = matches!(
            command.action,
            UserCommandAction::SubmitOrder { .. } | UserCommandAction::RequestWithdrawal { .. }
        )
        .then(|| private_recovery_result_digest(&self.identity_key, &result))
        .transpose()?;
        if let Some(result_digest) = recovery_result_digest {
            system_keys.insert(recovery_result_marker(
                &command.idempotency_key,
                result_digest,
            ));
        }

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
        // Append against a command-local journal clone. Later audit/task
        // artifact construction remains fallible; assigning this clone only at
        // the final commit point prevents a failed command from advancing the
        // journal/time fence without its financial state.
        let mut journal = self.journal.clone();
        let record = journal.append(next_root, &journal_value)?;
        let command_state = command_receipt_state(&command.action, &result)?;
        let disclosure_nonce =
            self.receipt_signer
                .result_disclosure_nonce(expected_hash, next_sequence, next_root);
        let semantic_receipt = is_s08_semantic_result(&command.action, &result);
        let result_commitment = semantic_receipt
            .then(|| command_result_commitment(command_state, disclosure_nonce, &result))
            .transpose()?;
        // The leaf exposes only opaque commitments. A journal-committed FOK
        // rejection therefore remains safe to batch and can still be verified
        // after a governed receipt-key rotation.
        let publication_eligible = matches!(
            command.action,
            UserCommandAction::SubmitOrder { .. }
                | UserCommandAction::ReplaceOrder { .. }
                | UserCommandAction::CancelOrder { .. }
                | UserCommandAction::CancelAllOrders { .. }
                | UserCommandAction::ClosePosition { .. }
                | UserCommandAction::CompleteSet { .. }
                | UserCommandAction::RequestRewardClaim { .. }
                | UserCommandAction::CancelBootstrap { .. }
                | UserCommandAction::RequestWithdrawal { .. }
                | UserCommandAction::TransferFunds { .. }
        );
        let receipt = self.receipt_signer.sign(
            command.command_id,
            command.idempotency_key.clone(),
            Some(expected_hash),
            Some(publication_eligible),
            result_commitment,
            semantic_receipt.then_some(true),
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
                    recovery_proof: None,
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
        let task_qualifications = signed_task_qualifications(
            &self.receipt_signer,
            &receipt,
            &command.action,
            &result,
            &self.markets,
            task_order_commitment,
            now_millis,
        )?;
        let response = CoreResponse {
            result,
            receipt,
            receipt_state: command_state,
            receipt_disclosure_nonce: disclosure_nonce,
            encrypted_record: Some(record),
            withdrawal_authorization,
            reward_claim_authorization: None,
            audit_fills,
            task_qualifications,
        };
        let mut recovery_capsules = self.recovery_capsules.clone();
        if matches!(
            command.action,
            UserCommandAction::SubmitOrder { .. } | UserCommandAction::RequestWithdrawal { .. }
        ) {
            insert_recovery_capsule(
                &mut recovery_capsules,
                command.idempotency_key.clone(),
                RecoveryCapsule {
                    sequence: next_sequence,
                    request_hash: expected_hash,
                    result_digest: recovery_result_digest
                        .expect("SubmitOrder recovery digest was derived before commit"),
                    result: response.result.clone(),
                    receipt: response.receipt.clone(),
                    receipt_state: response.receipt_state,
                    receipt_disclosure_nonce: response.receipt_disclosure_nonce,
                    withdrawal_authorization: response.withdrawal_authorization.clone(),
                    audit_fills: response.audit_fills.clone(),
                    task_qualifications: response.task_qualifications.clone(),
                },
            )?;
        }
        self.ledger = ledger;
        self.books = books;
        self.sessions = sessions;
        self.position_cost_basis = position_cost_basis;
        self.bootstrap_executions = bootstrap_executions;
        self.private_rewards = private_rewards;
        self.system_keys = system_keys;
        self.journal = journal;
        self.sequence = next_sequence;
        self.processed.insert(
            command.idempotency_key,
            ProcessedCommand {
                request_hash: expected_hash,
                response: Some(response.clone()),
            },
        );
        self.recovery_capsules = recovery_capsules;
        Ok(response)
    }

    fn execute_readonly(
        &self,
        command: UserCommand,
        expected_hash: [u8; 32],
        now_millis: i64,
    ) -> CoreResult<CoreResponse> {
        if self.processed.contains_key(&command.idempotency_key) {
            return Err(CoreError::DuplicateCommand);
        }
        let private_user_id = self
            .sessions
            .verify_signed_readonly(&command.session, now_millis)?;
        let root = self.state_root();
        let result = match &command.action {
            UserCommandAction::Portfolio => CommandResult::Portfolio {
                snapshot: portfolio_snapshot(
                    &self.ledger,
                    &self.books,
                    &self.position_cost_basis,
                    &self.identity_key,
                    &private_user_id,
                    now_millis,
                ),
            },
            UserCommandAction::Rewards => CommandResult::Rewards {
                entitlements: self.private_rewards.entitlements(&private_user_id),
            },
            UserCommandAction::BootstrapStatus { execution_id } => {
                let execution = self
                    .bootstrap_executions
                    .get(execution_id)
                    .filter(|execution| execution.private_user_id == private_user_id)
                    .ok_or_else(|| CoreError::InvalidOrder("unknown bootstrap execution".into()))?;
                CommandResult::BootstrapStatus {
                    execution: execution.view.clone(),
                }
            }
            _ => return Err(CoreError::InvalidOrder("command is not read-only".into())),
        };
        let journal_hash = read_only_response_hash(&command, &result, root)?;
        let disclosure_nonce =
            self.receipt_signer
                .result_disclosure_nonce(expected_hash, self.sequence, root);
        let receipt = self.receipt_signer.sign(
            command.command_id,
            command.idempotency_key,
            Some(expected_hash),
            Some(false),
            None,
            None,
            self.sequence,
            root,
            root,
            journal_hash,
            now_millis,
        );
        Ok(CoreResponse {
            result,
            receipt,
            receipt_state: CommandReceiptState::Accepted,
            receipt_disclosure_nonce: disclosure_nonce,
            encrypted_record: None,
            withdrawal_authorization: None,
            reward_claim_authorization: None,
            audit_fills: Vec::new(),
            task_qualifications: Vec::new(),
        })
    }

    pub fn aggregate_depth(
        &self,
        market_id: &str,
        outcome: Outcome,
        now_millis: i64,
        minimum_level_quantity_micros: u128,
    ) -> (Vec<(u64, u128)>, Vec<(u64, u128)>) {
        let Some(market) = self.markets.get(market_id) else {
            return (Vec::new(), Vec::new());
        };
        // No closed-market liquidity is public, even if GTC orders remain in
        // the private book awaiting the deterministic lifecycle cancellation.
        if now_millis < market.opens_at_millis || now_millis >= market.closes_at_millis {
            return (Vec::new(), Vec::new());
        }
        self.books.get(market_id).map_or_else(
            || (Vec::new(), Vec::new()),
            |book| {
                let (bids, asks) = book.aggregate_depth(market_id, outcome, now_millis);
                let filter = |levels: Vec<(u64, u128, usize)>| {
                    levels
                        .into_iter()
                        .filter(|(_, quantity, distinct_owners)| {
                            *quantity >= minimum_level_quantity_micros
                                && *distinct_owners >= MIN_PUBLIC_DEPTH_DISTINCT_OWNERS
                        })
                        .filter_map(|(price, quantity, _)| {
                            // Publish only whole privacy buckets. Observers see
                            // a bounded range, never the enclave's exact size.
                            let bucketed = quantity
                                .checked_div(minimum_level_quantity_micros)?
                                .checked_mul(minimum_level_quantity_micros)?;
                            (bucketed > 0).then_some((price, bucketed))
                        })
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
            registration_evidence: None,
            transfer_account: None,
        }
    }
}

fn system_command_commitment(command: &JournaledSystemCommand) -> CoreResult<[u8; 32]> {
    let encoded = serde_json::to_vec(command).map_err(|_| CoreError::RequestHashMismatch)?;
    let mut hash = Sha256::new();
    hash.update(b"layrs.system-command.v1\0");
    hash.update((encoded.len() as u64).to_be_bytes());
    hash.update(encoded);
    Ok(hash.finalize().into())
}

/// Stable replay identity for the financial payout caused by signed resolution evidence.
/// This is deliberately independent of the operator-supplied command idempotency key: if the
/// enclave committed the payout but its response was lost, a redispatch with a new key cannot
/// debit market collateral a second time.
fn resolution_payout_evidence_hash(resolution: &MarketResolution) -> CoreResult<[u8; 32]> {
    let encoded = serde_json::to_vec(resolution)
        .map_err(|_| CoreError::InvalidResolution("cannot encode payout evidence".into()))?;
    let mut hash = Sha256::new();
    hash.update(b"layrs.resolution-payout.v1\0");
    hash.update((encoded.len() as u64).to_be_bytes());
    hash.update(encoded);
    Ok(hash.finalize().into())
}

fn registration_evidence(
    identity_commitment: [u8; 32],
    public_key: [u8; 32],
) -> RegistrationEvidence {
    let mut commitment = Sha256::new();
    commitment.update(b"layrs.registration-commitment.v1\0");
    commitment.update(identity_commitment);
    commitment.update(public_key);

    let mut nullifier = Sha256::new();
    nullifier.update(b"layrs.registration-nullifier.v1\0");
    nullifier.update(identity_commitment);

    RegistrationEvidence {
        commitment: commitment.finalize().into(),
        nullifier: nullifier.finalize().into(),
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
) -> CoreResult<(Vec<Transfer>, Vec<NormalFillPosting>)> {
    let mut transfers = Vec::new();
    let mut fill_postings = Vec::new();
    let incoming_cash_hold = cash_hold(incoming, &market.settlement_asset);
    let incoming_claim_hold = claim_hold(incoming);
    let initial_notional_micros = notional(incoming.price_micros, incoming.quantity_micros)?;
    let initial_notional = settlement_atomic(market, initial_notional_micros)?;
    match incoming.action {
        OrderAction::Buy => transfers.push(Transfer {
            from: available(&incoming.private_user_id, &market.settlement_asset),
            to: incoming_cash_hold.clone(),
            amount: initial_notional
                .checked_add(maximum_buy_taker_fee_atomic(
                    market,
                    incoming.quantity_micros,
                    incoming.price_micros,
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
        let taker_fee = taker_fee_atomic(market, fill.quantity_micros, fill.taker_price_micros())?;
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
        let seller_available = available(&seller.private_user_id, &market.settlement_asset);
        let buyer_position = claim_position_for(
            &buyer.private_user_id,
            &incoming.market_id,
            incoming.outcome,
        );
        let fee_account = fee_revenue(&market.settlement_asset);
        if seller_proceeds > 0 {
            transfers.push(Transfer {
                from: buyer_hold.clone(),
                to: seller_available.clone(),
                amount: seller_proceeds,
            });
        }
        if taker_fee > 0 {
            transfers.push(Transfer {
                from: buyer_hold.clone(),
                to: fee_account.clone(),
                amount: taker_fee,
            });
        }
        transfers.push(Transfer {
            from: seller_hold.clone(),
            to: buyer_position.clone(),
            amount: fill.quantity_micros,
        });
        fill_postings.push(NormalFillPosting {
            fill_id: fill.fill_id.to_string(),
            buyer_cash_hold: buyer_hold,
            seller_available,
            seller_claim_hold: seller_hold,
            buyer_position,
            fee_revenue: fee_account,
            seller_proceeds_atomic: seller_proceeds,
            fee_atomic: taker_fee,
            quantity_micros: fill.quantity_micros,
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
                .checked_add(maximum_buy_taker_fee_atomic(
                    market,
                    incoming.quantity_micros,
                    incoming.price_micros,
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
    Ok((transfers, fill_postings))
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
                .checked_add(maximum_buy_taker_fee_atomic(
                    market,
                    incoming.quantity_micros,
                    incoming.price_micros,
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
                let taker_fee =
                    taker_fee_atomic(market, fill.quantity_micros, fill.taker_price_micros())?;
                let mut transfers = Vec::with_capacity(3);
                let normal_posting;
                match incoming.action {
                    OrderAction::Buy => {
                        let seller_available =
                            available(&maker.private_user_id, &market.settlement_asset);
                        let seller_claim_hold = claim_hold(&maker);
                        let buyer_position = claim_position_for(
                            &incoming.private_user_id,
                            &incoming.market_id,
                            incoming.outcome,
                        );
                        transfers.push(Transfer {
                            from: incoming_cash_hold.clone(),
                            to: seller_available.clone(),
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
                            from: seller_claim_hold.clone(),
                            to: buyer_position.clone(),
                            amount: fill.quantity_micros,
                        });
                        normal_posting = NormalFillPosting {
                            fill_id: fill.fill_id.to_string(),
                            buyer_cash_hold: incoming_cash_hold.clone(),
                            seller_available,
                            seller_claim_hold,
                            buyer_position,
                            fee_revenue: fee_revenue(&market.settlement_asset),
                            seller_proceeds_atomic: fill_notional,
                            fee_atomic: taker_fee,
                            quantity_micros: fill.quantity_micros,
                        };
                        incoming_cash_used = incoming_cash_used
                            .checked_add(fill_notional)
                            .and_then(|value| value.checked_add(taker_fee))
                            .ok_or(CoreError::UnbalancedTransaction)?;
                    }
                    OrderAction::Sell => {
                        let seller_proceeds = fill_notional
                            .checked_sub(taker_fee)
                            .ok_or(CoreError::UnbalancedTransaction)?;
                        let buyer_cash_hold = cash_hold(&maker, &market.settlement_asset);
                        let seller_available =
                            available(&incoming.private_user_id, &market.settlement_asset);
                        let buyer_position = claim_position_for(
                            &maker.private_user_id,
                            &incoming.market_id,
                            incoming.outcome,
                        );
                        if seller_proceeds > 0 {
                            transfers.push(Transfer {
                                from: buyer_cash_hold.clone(),
                                to: seller_available.clone(),
                                amount: seller_proceeds,
                            });
                        }
                        if taker_fee > 0 {
                            transfers.push(Transfer {
                                from: buyer_cash_hold.clone(),
                                to: fee_revenue(&market.settlement_asset),
                                amount: taker_fee,
                            });
                        }
                        transfers.push(Transfer {
                            from: incoming_claim_hold.clone(),
                            to: buyer_position.clone(),
                            amount: fill.quantity_micros,
                        });
                        normal_posting = NormalFillPosting {
                            fill_id: fill.fill_id.to_string(),
                            buyer_cash_hold,
                            seller_available,
                            seller_claim_hold: incoming_claim_hold.clone(),
                            buyer_position,
                            fee_revenue: fee_revenue(&market.settlement_asset),
                            seller_proceeds_atomic: seller_proceeds,
                            fee_atomic: taker_fee,
                            quantity_micros: fill.quantity_micros,
                        };
                        incoming_claim_used = incoming_claim_used
                            .checked_add(fill.quantity_micros)
                            .ok_or(CoreError::UnbalancedTransaction)?;
                    }
                }
                ledger.apply_normal_fill_settlement(
                    LedgerTransaction {
                        idempotency_key: format!(
                            "order:{command_idempotency_key}:normal:{}",
                            fill.sequence
                        ),
                        business_reference: business_reference.into(),
                        transfers,
                    },
                    vec![normal_posting],
                )?;
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
                ledger.apply_complete_set_fill(
                    format!("order:{command_idempotency_key}:mint:{}", fill.sequence),
                    business_reference.into(),
                    CompleteSetFillPosting {
                        fill_id: fill.fill_id.to_string(),
                        direction: CompleteSetDirection::Mint,
                        maker_hold: cash_hold(&maker, &market.settlement_asset),
                        taker_hold: incoming_cash_hold.clone(),
                        maker_destination: claim_position_for(
                            &maker.private_user_id,
                            &incoming.market_id,
                            maker.outcome,
                        ),
                        taker_destination: claim_position_for(
                            &incoming.private_user_id,
                            &incoming.market_id,
                            incoming.outcome,
                        ),
                        market_collateral: market_collateral(
                            &incoming.market_id,
                            &market.settlement_asset,
                        ),
                        fee_revenue: fee_revenue(&market.settlement_asset),
                        quantity_micros: fill.quantity_micros,
                        collateral_amount_atomic: amounts.collateral_atomic,
                        maker_amount_atomic: amounts.maker_atomic,
                        taker_amount_atomic: amounts.taker_atomic,
                        taker_fee_atomic: amounts.taker_fee_atomic,
                    },
                )?;
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

                ledger.apply_complete_set_fill(
                    format!("order:{command_idempotency_key}:merge:{}", fill.sequence),
                    business_reference.into(),
                    CompleteSetFillPosting {
                        fill_id: fill.fill_id.to_string(),
                        direction: CompleteSetDirection::Burn,
                        maker_hold: claim_hold(&maker),
                        taker_hold: incoming_claim_hold.clone(),
                        maker_destination: available(
                            &maker.private_user_id,
                            &market.settlement_asset,
                        ),
                        taker_destination: available(
                            &incoming.private_user_id,
                            &market.settlement_asset,
                        ),
                        market_collateral: market_collateral(
                            &incoming.market_id,
                            &market.settlement_asset,
                        ),
                        fee_revenue: fee_revenue(&market.settlement_asset),
                        quantity_micros: fill.quantity_micros,
                        collateral_amount_atomic: amounts.collateral_atomic,
                        maker_amount_atomic: amounts.maker_atomic,
                        taker_amount_atomic: amounts.taker_atomic,
                        taker_fee_atomic: amounts.taker_fee_atomic,
                    },
                )?;
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
                .checked_add(maximum_buy_taker_fee_atomic(
                    market,
                    incoming.quantity_micros,
                    incoming.price_micros,
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
    let taker_fee_atomic =
        taker_fee_atomic(market, fill.quantity_micros, fill.taker_price_micros())?;
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
                .checked_add(maximum_buy_taker_fee_atomic(
                    market,
                    order.quantity_micros,
                    order.price_micros,
                )?)
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
                        | BootstrapExecutionState::VenueIntentDurable
                        | BootstrapExecutionState::VenueSubmissionAttempted
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
                        | BootstrapExecutionState::VenueIntentDurable
                        | BootstrapExecutionState::VenueSubmissionAttempted
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

fn floor_bps(amount: u128, bps: u128) -> CoreResult<u128> {
    amount
        .checked_mul(bps)
        .map(|value| value / 10_000)
        .ok_or(CoreError::UnbalancedTransaction)
}

/// Returns the taker fee in six-decimal settlement micros. V2 policies use
/// the Layrs curve C * rate * p * (1-p); historical policies retain the
/// deployed 20 bps notional fee so open markets cannot change economics after
/// an enclave rotation.
fn taker_fee_micros(
    profile_id: FeeProfileId,
    quantity_micros: u128,
    price_micros: u64,
) -> CoreResult<u128> {
    let price = u128::from(price_micros);
    if price == 0 || price >= PRICE_SCALE {
        return Err(CoreError::InvalidOrder(
            "fee price must be strictly between zero and one".into(),
        ));
    }
    let Some(rate_bps) = profile_id.taker_curve_rate_bps() else {
        return ceil_bps(notional(price_micros, quantity_micros)?, 20);
    };
    if rate_bps == 0 || quantity_micros == 0 {
        return Ok(0);
    }

    let denominator = U256::from(PRICE_SCALE)
        .checked_mul(U256::from(PRICE_SCALE))
        .and_then(|value| value.checked_mul(U256::from(10_000u128)))
        .ok_or(CoreError::UnbalancedTransaction)?;
    let numerator = U256::from(quantity_micros)
        .checked_mul(U256::from(price))
        .and_then(|value| value.checked_mul(U256::from(PRICE_SCALE - price)))
        .and_then(|value| value.checked_mul(U256::from(rate_bps)))
        .ok_or(CoreError::UnbalancedTransaction)?;
    // Layrs V2 rounds settlement-asset fees to five decimal places. The
    // private core represents one settlement unit with six decimals before
    // converting into the asset's native precision, so one fee quantum is ten
    // micros. Round half-up to that quantum; amounts below half a quantum
    // become zero and the smallest non-zero fee is 0.00001 settlement units.
    const FEE_QUANTUM_MICROS: u128 = 10;
    let quantum_denominator = denominator
        .checked_mul(U256::from(FEE_QUANTUM_MICROS))
        .ok_or(CoreError::UnbalancedTransaction)?;
    let half_quantum = denominator
        .checked_mul(U256::from(FEE_QUANTUM_MICROS / 2))
        .ok_or(CoreError::UnbalancedTransaction)?;
    let fee_quanta = numerator
        .checked_add(half_quantum)
        .map(|value| value / quantum_denominator)
        .ok_or(CoreError::UnbalancedTransaction)?;
    let fee = fee_quanta
        .checked_mul(U256::from(FEE_QUANTUM_MICROS))
        .ok_or(CoreError::UnbalancedTransaction)?;
    if fee > U256::from(u128::MAX) {
        return Err(CoreError::UnbalancedTransaction);
    }
    Ok(fee.as_u128())
}

fn taker_fee_atomic(
    market: &MarketConfig,
    quantity_micros: u128,
    price_micros: u64,
) -> CoreResult<u128> {
    settlement_atomic(
        market,
        taker_fee_micros(market.fee_profile_id, quantity_micros, price_micros)?,
    )
}

/// A buy order can execute at any price at or below its limit. The curve peaks
/// at 50c, so reserve against that peak whenever the executable range includes
/// it. Resting remainder needs no fee reserve because it becomes maker
/// liquidity and makers pay zero under V2.
fn maximum_buy_taker_fee_atomic(
    market: &MarketConfig,
    quantity_micros: u128,
    limit_price_micros: u64,
) -> CoreResult<u128> {
    let reserve_price = if market.fee_profile_id.has_layrs_curve_fees()
        && limit_price_micros >= (PRICE_SCALE / 2) as u64
    {
        (PRICE_SCALE / 2) as u64
    } else {
        limit_price_micros
    };
    taker_fee_atomic(market, quantity_micros, reserve_price)
}

fn maker_rebate_bps(profile_id: FeeProfileId) -> u128 {
    match profile_id {
        FeeProfileId::PolymarketCryptoV2 | FeeProfileId::LayrsCryptoV2 => 2_000,
        FeeProfileId::PolymarketSportsV2
        | FeeProfileId::PolymarketEsportsV2
        | FeeProfileId::LayrsSportsV2
        | FeeProfileId::LayrsEsportsV2 => 1_500,
        FeeProfileId::PolymarketMacroV2
        | FeeProfileId::PolymarketFinanceV2
        | FeeProfileId::PolymarketPoliticsV2
        | FeeProfileId::PolymarketWeatherV2
        | FeeProfileId::PolymarketTechnologyV2
        | FeeProfileId::PolymarketMentionsV2
        | FeeProfileId::PolymarketScienceV2
        | FeeProfileId::PolymarketCultureV2
        | FeeProfileId::PolymarketBusinessV2
        | FeeProfileId::PolymarketGeneralV2
        | FeeProfileId::LayrsMacroV2
        | FeeProfileId::LayrsFinanceV2
        | FeeProfileId::LayrsPoliticsV2
        | FeeProfileId::LayrsWeatherV2
        | FeeProfileId::LayrsTechnologyV2
        | FeeProfileId::LayrsMentionsV2
        | FeeProfileId::LayrsScienceV2
        | FeeProfileId::LayrsCultureV2
        | FeeProfileId::LayrsBusinessV2
        | FeeProfileId::LayrsGeneralV2 => 2_500,
        FeeProfileId::PolymarketGeopoliticsV2
        | FeeProfileId::LayrsGeopoliticsV2
        | FeeProfileId::LegacyProfitV1 => 0,
        FeeProfileId::CryptoV1
        | FeeProfileId::MacroV1
        | FeeProfileId::FinanceV1
        | FeeProfileId::PoliticsV1
        | FeeProfileId::SportsV1
        | FeeProfileId::EsportsV1
        | FeeProfileId::WeatherV1
        | FeeProfileId::TechnologyV1
        | FeeProfileId::ScienceV1
        | FeeProfileId::CultureV1
        | FeeProfileId::BusinessV1
        | FeeProfileId::GeopoliticsV1
        | FeeProfileId::GeneralV1 => 0,
    }
}

fn reward_rail(market: &MarketConfig) -> CoreResult<(&'static str, &'static str)> {
    match market.settlement_asset.as_str() {
        "USDC" => Ok(("base", "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913")),
        "ZEN" => Ok(("horizen", "0x57da2d504bf8b83ef304759d9f2648522d7a9280")),
        _ => Err(CoreError::InvalidOrder(
            "unsupported private reward rail".into(),
        )),
    }
}

fn record_native_fill_economics(
    rewards: &mut PrivateRewardBook,
    market: &MarketConfig,
    result: &MatchResult,
    occurred_at_millis: i64,
) -> CoreResult<()> {
    let (chain, reward_token) = reward_rail(market)?;
    let fee_profile_id = market.fee_profile_id.immutable_profile_id();
    for fill in &result.fills {
        let taker_fee = taker_fee_atomic(market, fill.quantity_micros, fill.taker_price_micros())?;
        let maker_rebate = floor_bps(taker_fee, maker_rebate_bps(market.fee_profile_id))?;
        rewards.record_fill(
            &fill.fill_id.to_string(),
            &fill.taker_private_user_id,
            Some(&fill.maker_private_user_id),
            chain,
            reward_token,
            market.fee_profile_id.fee_policy_version(),
            &fee_profile_id,
            match fill.match_type {
                MatchType::Normal => "NORMAL",
                MatchType::Mint => "MINT",
                MatchType::Merge => "MERGE",
            },
            fill.quantity_micros,
            taker_fee,
            maker_rebate,
            occurred_at_millis,
        )?;
    }
    Ok(())
}

fn settlement_winning_fee(
    profile_id: FeeProfileId,
    executed_stake_atomic: u128,
    gross_payout_atomic: u128,
    is_push: bool,
) -> CoreResult<u128> {
    if profile_id.has_layrs_curve_fees() {
        return Ok(0);
    }
    if is_push || gross_payout_atomic <= executed_stake_atomic {
        return Ok(0);
    }
    let profit = gross_payout_atomic - executed_stake_atomic;
    let Some(profile) = profile_id.parameters() else {
        return ceil_bps(profit, 500);
    };

    // curve = q * coefficient * p * (1-p), where q is gross payout and
    // p = executed stake / gross payout. U256 is already in the locked EIF
    // dependency closure. Reduce the BPS fraction first; because stake and
    // profit sum to gross, their product is at most gross^2/4 and the reduced
    // numerator multiplier (at most three for the governed profiles) fits
    // exactly in U256 for the complete u128 input domain.
    let divisor = gcd(profile.curve_coefficient_bps, 10_000);
    let coefficient_numerator = profile.curve_coefficient_bps / divisor;
    let coefficient_denominator = 10_000 / divisor;
    let numerator = U256::from(executed_stake_atomic)
        .checked_mul(U256::from(profit))
        .and_then(|value| value.checked_mul(U256::from(coefficient_numerator)))
        .ok_or(CoreError::UnbalancedTransaction)?;
    let denominator = U256::from(gross_payout_atomic)
        .checked_mul(U256::from(coefficient_denominator))
        .ok_or(CoreError::UnbalancedTransaction)?;
    let curve_fee_u256 = numerator
        .checked_add(denominator - U256::one())
        .map(|value| value / denominator)
        .ok_or(CoreError::UnbalancedTransaction)?;
    if curve_fee_u256 > U256::from(u128::MAX) {
        return Err(CoreError::UnbalancedTransaction);
    }
    let curve_fee = curve_fee_u256.as_u128();
    let stake_floor = ceil_bps(executed_stake_atomic, profile.stake_floor_bps)?;
    let stake_cap = floor_bps(executed_stake_atomic, profile.stake_cap_bps)?;
    let profit_cap = floor_bps(profit, profile.profit_cap_bps)?;

    Ok(curve_fee.max(stake_floor).min(stake_cap).min(profit_cap))
}

fn gcd(mut left: u128, mut right: u128) -> u128 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
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
                fee_atomic: taker_fee_atomic(market, fill.quantity_micros, taker_price_micros)?,
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

fn command_receipt_state(
    action: &UserCommandAction,
    result: &CommandResult,
) -> CoreResult<CommandReceiptState> {
    validate_trading_receipt_binding(action, result)?;
    let state = match result {
        CommandResult::Order { result } => match_receipt_state(result)?,
        CommandResult::Cancelled { .. } => CommandReceiptState::Cancelled,
        CommandResult::OrdersCancelled { outcomes, .. } => {
            if outcomes.is_empty() {
                CommandReceiptState::Accepted
            } else {
                CommandReceiptState::Cancelled
            }
        }
        CommandResult::Replaced { result, .. } => match_receipt_state(result)?,
        CommandResult::PositionClosed { .. } => CommandReceiptState::Filled,
        _ => CommandReceiptState::Accepted,
    };
    // A result must remain paired with the action which produced it. This
    // prevents a future refactor from signing a plausible state for the wrong
    // command variant while the result commitment still hashes correctly.
    let compatible = matches!(
        (action, result),
        (
            UserCommandAction::SubmitOrder { .. },
            CommandResult::Order { .. }
        ) | (
            UserCommandAction::CancelOrder { .. },
            CommandResult::Cancelled { .. }
        ) | (
            UserCommandAction::CancelAllOrders { .. },
            CommandResult::OrdersCancelled { .. }
        ) | (
            UserCommandAction::ReplaceOrder { .. },
            CommandResult::Replaced { .. }
        ) | (
            UserCommandAction::PreviewPositionClose { .. },
            CommandResult::PositionClosePreview { .. }
        ) | (
            UserCommandAction::ClosePosition { .. },
            CommandResult::PositionClosed { .. }
        ) | (
            UserCommandAction::CompleteSet { .. },
            CommandResult::CompleteSet { .. }
        ) | (
            UserCommandAction::Portfolio,
            CommandResult::Portfolio { .. }
        ) | (UserCommandAction::Rewards, CommandResult::Rewards { .. })
            | (
                UserCommandAction::RequestRewardClaim { .. },
                CommandResult::RewardClaimAuthorized { .. }
            )
            | (
                UserCommandAction::BootstrapStatus { .. },
                CommandResult::BootstrapStatus { .. }
            )
            | (
                UserCommandAction::CancelBootstrap { .. },
                CommandResult::BootstrapCancelled { .. }
            )
            | (
                UserCommandAction::RequestWithdrawal { .. },
                CommandResult::WithdrawalReserved { .. }
            )
            | (
                UserCommandAction::TransferFunds { .. },
                CommandResult::FundsTransferred { .. }
            )
            | (
                UserCommandAction::SubmitOrder { .. },
                CommandResult::BootstrapPending { .. }
            )
    );
    if !compatible {
        return Err(CoreError::InvalidOrder(
            "command result does not match the requested action".into(),
        ));
    }
    Ok(state)
}

fn is_s08_semantic_result(action: &UserCommandAction, result: &CommandResult) -> bool {
    matches!(
        (action, result),
        (
            UserCommandAction::SubmitOrder { .. },
            CommandResult::Order { .. }
        ) | (
            UserCommandAction::ReplaceOrder { .. },
            CommandResult::Replaced { .. }
        ) | (
            UserCommandAction::CancelOrder { .. },
            CommandResult::Cancelled { .. }
        ) | (
            UserCommandAction::CancelAllOrders { .. },
            CommandResult::OrdersCancelled { .. }
        ) | (
            UserCommandAction::ClosePosition { .. },
            CommandResult::PositionClosed { .. }
        )
    )
}

fn validate_trading_receipt_binding(
    action: &UserCommandAction,
    result: &CommandResult,
) -> CoreResult<()> {
    let valid = match (action, result) {
        (UserCommandAction::SubmitOrder { order }, CommandResult::Order { result }) => result
            .accepted_order
            .as_ref()
            .is_some_and(|accepted| order_intent_matches(order, accepted)),
        (
            UserCommandAction::ReplaceOrder {
                market_id,
                order_id,
                replacement,
            },
            CommandResult::Replaced { cancelled, result },
        ) => {
            cancelled.order_id == *order_id
                && cancelled.market_id == *market_id
                && cancelled.status == OrderStatus::Cancelled
                && result
                    .accepted_order
                    .as_ref()
                    .is_some_and(|accepted| order_intent_matches(replacement, accepted))
        }
        (
            UserCommandAction::CancelOrder {
                market_id,
                order_id,
            },
            CommandResult::Cancelled { order },
        ) => {
            order.order_id == *order_id
                && order.market_id == *market_id
                && order.status == OrderStatus::Cancelled
        }
        (
            UserCommandAction::CancelAllOrders { filter },
            CommandResult::OrdersCancelled {
                filter: echoed,
                outcomes,
            },
        ) => {
            Some(filter) == echoed.as_ref()
                && outcomes
                    .iter()
                    .all(|outcome| outcome.status == OrderStatus::Cancelled)
                && match filter {
                    CancelAllOrdersFilter::Market { market_id } => outcomes
                        .iter()
                        .all(|outcome| outcome.market_id == *market_id),
                    CancelAllOrdersFilter::All | CancelAllOrdersFilter::Asset { .. } => true,
                }
        }
        (
            UserCommandAction::PreviewPositionClose {
                position_id,
                market_id,
                outcome,
                session_tag,
                quantity_micros,
                minimum_price_micros,
            },
            CommandResult::PositionClosePreview {
                market_id: echoed_market,
                outcome: echoed_outcome,
                session_tag: echoed_session,
                preview,
            },
        ) => {
            preview.position_id == *position_id
                && preview.quantity_micros == *quantity_micros
                && preview.minimum_price_micros == *minimum_price_micros
                && echoed_market.as_ref() == Some(market_id)
                && echoed_outcome.as_ref() == Some(outcome)
                && echoed_session.as_ref() == Some(session_tag)
        }
        (
            UserCommandAction::ClosePosition {
                position_id,
                market_id,
                outcome,
                session_tag,
                quantity_micros,
                minimum_price_micros,
                quote,
            },
            CommandResult::PositionClosed {
                market_id: echoed_market,
                outcome: echoed_outcome,
                session_tag: echoed_session,
                preview,
                ..
            },
        ) => {
            preview == quote
                && preview.position_id == *position_id
                && preview.quantity_micros == *quantity_micros
                && preview.minimum_price_micros == *minimum_price_micros
                && echoed_market.as_ref() == Some(market_id)
                && echoed_outcome.as_ref() == Some(outcome)
                && echoed_session.as_ref() == Some(session_tag)
        }
        // Non-trading command/result compatibility is still enforced below,
        // but S08 does not advertise a semantic outcome proof for it.
        _ => true,
    };
    if valid {
        Ok(())
    } else {
        Err(CoreError::InvalidOrder(
            "command receipt action/result binding failed".into(),
        ))
    }
}

fn order_intent_matches(expected: &BookOrder, actual: &BookOrder) -> bool {
    expected.order_id == actual.order_id
        && expected.market_id == actual.market_id
        && expected.outcome == actual.outcome
        && expected.action == actual.action
        && expected.price_micros == actual.price_micros
        && expected.quantity_micros == actual.quantity_micros
        && expected.time_in_force == actual.time_in_force
        && expected.expires_at_millis == actual.expires_at_millis
}

fn match_receipt_state(result: &MatchResult) -> CoreResult<CommandReceiptState> {
    let order = result.accepted_order.as_ref().ok_or_else(|| {
        CoreError::InvalidOrder("order result must contain accepted_order".into())
    })?;
    let fill_quantity = result.fills.iter().try_fold(0u128, |total, fill| {
        total
            .checked_add(fill.quantity_micros)
            .ok_or_else(|| CoreError::InvalidOrder("order result fill quantity overflow".into()))
    })?;
    let accounted = order
        .filled_micros
        .checked_add(order.remaining_micros)
        .and_then(|value| value.checked_add(result.cancelled_remainder_micros))
        .ok_or_else(|| CoreError::InvalidOrder("order result quantity overflow".into()))?;
    let fills_match = fill_quantity == order.filled_micros;
    let quantity_matches = accounted == order.quantity_micros;

    let valid = match order.status {
        OrderStatus::Rejected | OrderStatus::Open => {
            result.fills.is_empty()
                && order.filled_micros == 0
                && order.remaining_micros == order.quantity_micros
                && result.cancelled_remainder_micros == 0
        }
        OrderStatus::Cancelled | OrderStatus::Expired => {
            result.fills.is_empty()
                && order.filled_micros == 0
                && order.remaining_micros == 0
                && result.cancelled_remainder_micros == order.quantity_micros
        }
        OrderStatus::PartiallyFilled => {
            !result.fills.is_empty()
                && order.filled_micros > 0
                && order.filled_micros < order.quantity_micros
                && fills_match
                && quantity_matches
        }
        OrderStatus::Filled => {
            !result.fills.is_empty()
                && order.filled_micros == order.quantity_micros
                && order.remaining_micros == 0
                && result.cancelled_remainder_micros == 0
                && fills_match
        }
    };
    if !valid {
        return Err(CoreError::InvalidOrder(
            "order result status/fill/remaining invariant failed".into(),
        ));
    }
    Ok(match order.status {
        OrderStatus::Rejected => CommandReceiptState::Rejected,
        OrderStatus::Cancelled | OrderStatus::Expired => CommandReceiptState::Cancelled,
        OrderStatus::Filled | OrderStatus::PartiallyFilled => CommandReceiptState::Filled,
        OrderStatus::Open => CommandReceiptState::Accepted,
    })
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

fn signed_task_qualifications(
    signer: &ReceiptSigner,
    receipt: &EnclaveReceipt,
    action: &UserCommandAction,
    result: &CommandResult,
    markets: &BTreeMap<String, MarketConfig>,
    order_commitment: Option<[u8; 32]>,
    now_millis: i64,
) -> CoreResult<Vec<SignedTaskQualificationArtifact>> {
    let UserCommandAction::SubmitOrder { order } = action else {
        return Ok(Vec::new());
    };
    let accepted = match result {
        CommandResult::Order { result } => result
            .accepted_order
            .as_ref()
            .is_some_and(|accepted| accepted.status != OrderStatus::Rejected),
        CommandResult::BootstrapPending { .. } => true,
        _ => false,
    };
    if !accepted {
        return Ok(Vec::new());
    }
    let market = markets
        .get(&order.market_id)
        .ok_or_else(|| CoreError::InvalidOrder("unknown market".into()))?;
    let asset_notional_micros = notional(order.price_micros, order.quantity_micros)?;
    let filled_quantity_micros = match result {
        CommandResult::Order { result } => result.fills.iter().try_fold(0u128, |total, fill| {
            total
                .checked_add(fill.quantity_micros)
                .ok_or(CoreError::UnbalancedTransaction)
        })?,
        _ => 0,
    };
    let statement = TaskQualificationStatement {
        protocol_version: "layrs.task-qualification.v1".into(),
        event_type: "ORDER_ACCEPTED".into(),
        market_id: Some(order.market_id.clone()),
        order_commitment: order_commitment
            .ok_or_else(|| CoreError::InvalidOrder("missing private order commitment".into()))?,
        settlement_asset: market.settlement_asset.clone(),
        asset_notional_micros,
        filled_quantity_micros,
        occurred_at_millis: now_millis,
    };
    let mut artifact = SignedTaskQualificationArtifact {
        statement,
        receipt_id: receipt.receipt_id.clone(),
        state_root: receipt.state_root,
        receipt_public_key: signer.verifying_key(),
        signature: Vec::new(),
    };
    artifact.signature =
        signer.sign_domain_payload(b"layrs.task-qualification-artifact.v1\0", &artifact);
    Ok(vec![artifact])
}

fn private_order_commitment(order: &BookOrder, private_user_id: &str) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"layrs.private-order-commitment.v1\0");
    hash.update(order.order_id.as_bytes());
    hash.update((private_user_id.len() as u32).to_be_bytes());
    hash.update(private_user_id.as_bytes());
    hash.update((order.market_id.len() as u32).to_be_bytes());
    hash.update(order.market_id.as_bytes());
    hash.update([match order.outcome {
        Outcome::Up => 0,
        Outcome::Down => 1,
    }]);
    hash.update([match order.action {
        OrderAction::Buy => 0,
        OrderAction::Sell => 1,
    }]);
    hash.update(order.price_micros.to_be_bytes());
    hash.update(order.quantity_micros.to_be_bytes());
    hash.finalize().into()
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
    if matches!(market.execution, MarketExecution::NativeClob) {
        if let Some(expected_feed_id) = recurring_market_feed_id(&market.market_id) {
            if market.oracle_feed_id != expected_feed_id {
                return Err(CoreError::InvalidOrder(
                    "market namespace does not match oracle feed".into(),
                ));
            }
        }
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
    if let MarketExecution::NativeExactCondition {
        condition_id,
        up_outcome_index,
        down_outcome_index,
    } = &market.execution
    {
        if market.settlement_asset != "USDC"
            || !valid_hex32(condition_id)
            || up_outcome_index == down_outcome_index
        {
            return Err(CoreError::InvalidOrder(
                "invalid native exact-condition mapping".into(),
            ));
        }
    }
    Ok(())
}

fn recurring_market_feed_id(market_id: &str) -> Option<u64> {
    if market_id.starts_with("layrs:v4:ZEN:") {
        return Some(9001);
    }
    let parts: Vec<&str> = market_id.split(':').collect();
    if parts.len() != 6 || parts[0] != "layrs" || parts[1] != "v5" {
        return None;
    }
    match parts[2] {
        "ZEN" => Some(9001),
        "BTC" => Some(9002),
        "ETH" => Some(9003),
        "SOL" => Some(9004),
        "ZEC" => Some(9005),
        "HYPE" => Some(9006),
        _ => None,
    }
}

fn valid_market_namespace(market_id: &str) -> bool {
    market_id.starts_with("layrs:v1:")
        || market_id.starts_with("layrs:v2:")
        || market_id.starts_with("layrs:v3:")
        || market_id.starts_with("layrs:v4:ZEN:")
        || ["BTC", "ETH", "SOL", "ZEN", "ZEC", "HYPE"]
            .iter()
            .any(|asset| {
                ["ZEN", "USDC"].iter().any(|collateral| {
                    market_id.starts_with(&format!("layrs:v5:{asset}:{collateral}:"))
                })
            })
        || ["SPORTS", "ESPORTS", "POLITICS", "MACRO"]
            .iter()
            .any(|category| {
                market_id.starts_with(&format!("layrs:v4:{category}:"))
                    || market_id.starts_with(&format!("layrs:v5:{category}:"))
            })
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

const BINANCE_FALLBACK_DELAY_MILLIS: i64 = 120_000;

fn spot_oracle_source_matches(feed_id: u64, source: &str) -> bool {
    match feed_id {
        // The first measured Binance release used the longer SPOT-prefixed
        // source name while the production manifest profile used the shorter
        // canonical name. Both identify the same immutable ZENUSDT v1
        // evidence format and must remain replay-compatible.
        9001 => matches!(
            source,
            "BINANCE_ZENUSDT_1S_V1" | "BINANCE_SPOT_ZENUSDT_1S_V1"
        ),
        9002 => source == "BINANCE_BTCUSDT_1S_V1",
        9003 => source == "BINANCE_ETHUSDT_1S_V1",
        9004 => source == "BINANCE_SOLUSDT_1S_V1",
        9005 => source == "BINANCE_ZECUSDT_1S_V1",
        9006 => source == "KRAKEN_HYPEUSD_1S_V1",
        _ => false,
    }
}

fn validate_binance_resolution(
    market: &MarketConfig,
    signed: &SignedBinanceResolution,
    oracle_public_key: Option<[u8; 32]>,
    now_millis: i64,
) -> CoreResult<ResolutionOutcome> {
    if !spot_oracle_source_matches(market.oracle_feed_id, &signed.statement.oracle_source) {
        return Err(CoreError::InvalidResolution(
            "spot boundary resolution is valid only for approved native markets".into(),
        ));
    }
    if !matches!(market.execution, MarketExecution::NativeClob) {
        return Err(CoreError::InvalidResolution(
            "spot boundary resolution requires the native CLOB".into(),
        ));
    }
    let statement = &signed.statement;
    if now_millis < market.closes_at_millis
        || statement.market_id != market.market_id
        || statement.issued_at_millis < market.closes_at_millis
        || statement.issued_at_millis > now_millis + 30_000
    {
        return Err(CoreError::InvalidResolution(
            "Binance resolution timing or identity is invalid".into(),
        ));
    }
    let outcome = match (&statement.opening, &statement.closing) {
        (Some(opening), Some(closing)) => {
            if statement.fallback.is_some()
                || statement.reason.is_some()
                || statement.outcome.is_some()
                || statement.opening_boundary_millis.is_some()
                || statement.closing_boundary_millis.is_some()
                || statement.deadline_millis.is_some()
                || !statement.missing_boundaries.is_empty()
            {
                return Err(CoreError::InvalidResolution(
                    "Binance primary evidence contains fallback fields".into(),
                ));
            }
            validate_binance_boundary(opening, market.opens_at_millis)?;
            validate_binance_boundary(closing, market.closes_at_millis)?;
            derive_resolution_outcome(opening.median_price_e8, closing.median_price_e8)
        }
        (None, None) => {
            let expected_deadline = market
                .closes_at_millis
                .checked_add(BINANCE_FALLBACK_DELAY_MILLIS)
                .ok_or_else(|| CoreError::InvalidResolution("fallback deadline overflow".into()))?;
            let missing = statement.missing_boundaries.as_slice();
            if statement.fallback.as_deref() != Some("PUSH_REFUND")
                || statement.reason.as_deref() != Some("BINANCE_EVIDENCE_TIMEOUT")
                || statement.outcome != Some(ResolutionOutcome::Push)
                || statement.opening_boundary_millis != Some(market.opens_at_millis)
                || statement.closing_boundary_millis != Some(market.closes_at_millis)
                || statement.deadline_millis != Some(expected_deadline)
                || statement.issued_at_millis != expected_deadline
                || now_millis < expected_deadline
                || missing.is_empty()
                || missing.len() > 2
                || missing
                    .iter()
                    .any(|value| value != "OPENING" && value != "CLOSING")
                || (missing.len() == 2 && missing[0] == missing[1])
            {
                return Err(CoreError::InvalidResolution(
                    "Binance timeout fallback is invalid".into(),
                ));
            }
            ResolutionOutcome::Push
        }
        _ => {
            return Err(CoreError::InvalidResolution(
                "Binance resolution has incomplete boundary evidence".into(),
            ))
        }
    };
    let key =
        VerifyingKey::from_bytes(&oracle_public_key.ok_or(CoreError::InvalidOracleSignature)?)
            .map_err(|_| CoreError::InvalidOracleSignature)?;
    let signature_bytes: [u8; 64] = signed
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| CoreError::InvalidOracleSignature)?;
    key.verify(
        &binance_resolution_signing_payload(statement)?,
        &Signature::from_bytes(&signature_bytes),
    )
    .map_err(|_| CoreError::InvalidOracleSignature)?;
    Ok(outcome)
}

fn validate_binance_boundary(
    boundary: &BinanceBoundaryEvidence,
    target_millis: i64,
) -> CoreResult<()> {
    if boundary.window_end_millis != target_millis
        || boundary.window_start_millis != target_millis - 5_000
        || boundary.sample_count != 5
        || boundary.evidence_path_count < 2
        || boundary.median_price_e8 <= 0
        || boundary.evidence_commitment == [0u8; 32]
    {
        return Err(CoreError::InvalidResolution(
            "Binance boundary does not satisfy the five-sample dual-evidence policy".into(),
        ));
    }
    Ok(())
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

fn validate_exact_condition_resolution(
    market: &MarketConfig,
    signed: &SignedExactConditionResolution,
    oracle_public_key: Option<[u8; 32]>,
    now_millis: i64,
) -> CoreResult<()> {
    let MarketExecution::NativeExactCondition { condition_id, .. } = &market.execution else {
        return Err(CoreError::InvalidResolution(
            "exact-condition resolution is valid only for native exact-condition markets".into(),
        ));
    };
    let statement = &signed.statement;
    if now_millis < market.closes_at_millis
        || statement.market_id != market.market_id
        || &statement.condition_id != condition_id
        || statement.evidence_hash == [0u8; 32]
        || statement.issued_at_millis < market.closes_at_millis
        || statement.issued_at_millis > now_millis + 30_000
    {
        return Err(CoreError::InvalidResolution(
            "exact-condition resolution timing, condition, or evidence is invalid".into(),
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
        &exact_condition_resolution_signing_payload(statement)?,
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

pub fn binance_resolution_signing_payload(
    statement: &BinanceResolutionStatement,
) -> CoreResult<Vec<u8>> {
    let encoded = serde_json::to_vec(statement)
        .map_err(|_| CoreError::InvalidResolution("cannot encode Binance resolution".into()))?;
    let mut payload = Vec::with_capacity(encoded.len() + 48);
    payload.extend_from_slice(b"layrs.binance-resolution.v1\0");
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

pub fn exact_condition_resolution_signing_payload(
    statement: &ExactConditionResolutionStatement,
) -> CoreResult<Vec<u8>> {
    let encoded = serde_json::to_vec(statement)
        .map_err(|_| CoreError::InvalidResolution("cannot encode resolution".into()))?;
    let mut payload = Vec::with_capacity(encoded.len() + 48);
    payload.extend_from_slice(b"layrs.exact-condition-resolution.v1\0");
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

fn derive_transfer_account(identity_commitment: &[u8; 32]) -> String {
    let mut hash = Sha256::new();
    hash.update(b"layrs.private-transfer-account.v1\0");
    hash.update(identity_commitment);
    format!("layrs_{}", hex::encode(hash.finalize()))
}

fn transfer_account_marker(transfer_account: &str, private_user_id: &str) -> String {
    format!("private-transfer-account:{transfer_account}:{private_user_id}")
}

fn resolve_transfer_account(
    system_keys: &BTreeSet<String>,
    transfer_account: &str,
) -> CoreResult<String> {
    let prefix = format!("private-transfer-account:{transfer_account}:");
    let mut matches = system_keys
        .range(prefix.clone()..)
        .take_while(|key| key.starts_with(&prefix));
    let marker = matches
        .next()
        .ok_or_else(|| CoreError::InvalidOrder("unknown transfer account".into()))?;
    if matches.next().is_some() {
        return Err(CoreError::InvalidOrder("ambiguous transfer account".into()));
    }
    let private_user_id = marker[prefix.len()..].to_string();
    if !private_user_id.starts_with("usr_") || private_user_id.len() != 68 {
        return Err(CoreError::InvalidOrder(
            "invalid transfer account binding".into(),
        ));
    }
    Ok(private_user_id)
}

fn validate_private_transfer(
    recipient_account: &str,
    asset: &str,
    amount_atomic: u128,
) -> CoreResult<()> {
    let account_suffix = recipient_account.strip_prefix("layrs_");
    if amount_atomic == 0
        || !matches!(asset, "USDC" | "ZEN")
        || account_suffix.is_none_or(|suffix| {
            suffix.len() != 64
                || !suffix
                    .bytes()
                    .all(|value| value.is_ascii_digit() || (b'a'..=b'f').contains(&value))
        })
    {
        return Err(CoreError::InvalidOrder(
            "invalid private transfer request".into(),
        ));
    }
    Ok(())
}

const TRUSTED_TIME_HIGH_WATER_PREFIX: &str = "trusted-time-high-water:";

/// Advances the enclave-trusted clock fence in command-local state.
///
/// `system_keys` is already encrypted in snapshots, committed by the state root,
/// and assigned to the live core only after the complete user command succeeds.
/// Keeping the single high-water marker here therefore makes a failed command
/// non-consuming while detecting rollback/regression after a restored snapshot.
fn advance_trusted_time_high_water(
    system_keys: &mut BTreeSet<String>,
    now_millis: i64,
) -> CoreResult<()> {
    if now_millis < 0 {
        return Err(CoreError::InvalidOrder(
            "trusted time is unavailable".into(),
        ));
    }
    let mut matching = system_keys
        .range(TRUSTED_TIME_HIGH_WATER_PREFIX.to_owned()..)
        .take_while(|key| key.starts_with(TRUSTED_TIME_HIGH_WATER_PREFIX));
    let existing = matching.next().cloned();
    if matching.next().is_some() {
        return Err(CoreError::RollbackDetected);
    }
    if let Some(marker) = existing.as_ref() {
        let encoded = marker
            .strip_prefix(TRUSTED_TIME_HIGH_WATER_PREFIX)
            .ok_or(CoreError::RollbackDetected)?;
        let high_water = encoded
            .parse::<i64>()
            .map_err(|_| CoreError::RollbackDetected)?;
        if now_millis < high_water {
            return Err(CoreError::RollbackDetected);
        }
        system_keys.remove(marker);
    }
    system_keys.insert(format!("{TRUSTED_TIME_HIGH_WATER_PREFIX}{now_millis:020}"));
    Ok(())
}

fn full_user_command_commitment(command: &UserCommand) -> CoreResult<[u8; 32]> {
    let encoded = serde_json::to_vec(command).map_err(|_| CoreError::RequestHashMismatch)?;
    let mut hash = Sha256::new();
    hash.update(b"layrs.full-user-command.v1\0");
    hash.update((encoded.len() as u64).to_be_bytes());
    hash.update(encoded);
    Ok(hash.finalize().into())
}

fn processed_command_marker(idempotency_key: &str, commitment: [u8; 32]) -> String {
    let mut key_hash = Sha256::new();
    key_hash.update(b"layrs.processed-command-key.v1\0");
    key_hash.update((idempotency_key.len() as u32).to_be_bytes());
    key_hash.update(idempotency_key.as_bytes());
    format!(
        "processed-command-commitment:{}:{}",
        hex::encode(key_hash.finalize()),
        hex::encode(commitment),
    )
}

fn derive_private_user_id(identity_key: &[u8; 32], commitment: &[u8; 32]) -> String {
    let mut hash = Sha256::new();
    hash.update(b"layrs.private-user-id.v1\0");
    hash.update(identity_key);
    hash.update(commitment);
    format!("usr_{}", hex::encode(hash.finalize()))
}

fn derive_private_position_id(
    identity_key: &[u8; 32],
    owner: &str,
    market_id: &str,
    outcome: Outcome,
) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(identity_key)
        .expect("identity key has fixed HMAC length");
    mac.update(b"layrs.private-position-id.v1\0");
    mac.update(&(owner.len() as u32).to_be_bytes());
    mac.update(owner.as_bytes());
    mac.update(&(market_id.len() as u32).to_be_bytes());
    mac.update(market_id.as_bytes());
    mac.update(match outcome {
        Outcome::Up => b"UP",
        Outcome::Down => b"DOWN",
    });
    format!("pos_{}", hex::encode(mac.finalize().into_bytes()))
}

fn position_close_order_id(command_id: &str, idempotency_key: &str, position_id: &str) -> Uuid {
    let mut name =
        Vec::with_capacity(command_id.len() + idempotency_key.len() + position_id.len() + 32);
    name.extend_from_slice(b"layrs.position-close-order.v1\0");
    name.extend_from_slice(command_id.as_bytes());
    name.push(0);
    name.extend_from_slice(idempotency_key.as_bytes());
    name.push(0);
    name.extend_from_slice(position_id.as_bytes());
    Uuid::new_v5(&Uuid::NAMESPACE_OID, &name)
}

#[allow(clippy::too_many_arguments)]
fn position_close_order(
    identity_key: &[u8; 32],
    ledger: &Ledger,
    markets: &BTreeMap<String, MarketConfig>,
    resolutions: &BTreeMap<String, MarketResolution>,
    owner: &str,
    position_id: &str,
    market_id: &str,
    outcome: Outcome,
    quantity_micros: u128,
    minimum_price_micros: u64,
    order_id: Uuid,
    now_millis: i64,
) -> CoreResult<BookOrder> {
    let market = markets
        .get(market_id)
        .ok_or_else(|| CoreError::InvalidOrder("unknown market".into()))?;
    if resolutions.contains_key(market_id) {
        return Err(CoreError::InvalidOrder(
            "market is resolving or resolved".into(),
        ));
    }
    if now_millis >= market.closes_at_millis {
        return Err(CoreError::InvalidOrder("market is closed".into()));
    }
    if now_millis < market.opens_at_millis {
        return Err(CoreError::InvalidOrder("market is not open".into()));
    }
    let expected_position_id = derive_private_position_id(identity_key, owner, market_id, outcome);
    if position_id != expected_position_id {
        return Err(CoreError::InvalidOrder("position owner mismatch".into()));
    }
    if quantity_micros == 0
        || ledger.balance(&claim_position_for(owner, market_id, outcome)) < quantity_micros
    {
        return Err(CoreError::InsufficientBalance);
    }
    let order = BookOrder::with_id(
        order_id,
        owner,
        market_id,
        outcome,
        OrderAction::Sell,
        minimum_price_micros,
        quantity_micros,
        TimeInForce::Fok,
        None,
    );
    validate_order_for_market(&order, market, now_millis)?;
    Ok(order)
}

fn position_close_preview(
    identity_key: &[u8; 32],
    owner: &str,
    outcome: Outcome,
    position_id: &str,
    market: &MarketConfig,
    prior_book: &PriceTimeBook,
    order: &BookOrder,
    result: &MatchResult,
    expires_at_millis: i64,
) -> CoreResult<PositionClosePreview> {
    let accepted = result
        .accepted_order
        .as_ref()
        .ok_or_else(|| CoreError::InvalidOrder("position close result is missing".into()))?;
    let executed_quantity = result.fills.iter().try_fold(0u128, |total, fill| {
        total
            .checked_add(fill.quantity_micros)
            .ok_or(CoreError::UnbalancedTransaction)
    })?;
    if accepted.status != OrderStatus::Filled || executed_quantity != order.quantity_micros {
        return Err(CoreError::InvalidOrder(
            "insufficient protected liquidity for position close".into(),
        ));
    }
    let mut weighted_price = 0u128;
    let mut gross_payout_atomic = 0u128;
    let mut fee_atomic = 0u128;
    for fill in &result.fills {
        let taker_price = fill.taker_price_micros();
        weighted_price = weighted_price
            .checked_add(
                u128::from(taker_price)
                    .checked_mul(fill.quantity_micros)
                    .ok_or(CoreError::UnbalancedTransaction)?,
            )
            .ok_or(CoreError::UnbalancedTransaction)?;
        gross_payout_atomic = gross_payout_atomic
            .checked_add(settlement_atomic(
                market,
                notional(taker_price, fill.quantity_micros)?,
            )?)
            .ok_or(CoreError::UnbalancedTransaction)?;
        fee_atomic = fee_atomic
            .checked_add(taker_fee_atomic(market, fill.quantity_micros, taker_price)?)
            .ok_or(CoreError::UnbalancedTransaction)?;
    }
    let average_price_micros = u64::try_from(weighted_price / executed_quantity)
        .map_err(|_| CoreError::UnbalancedTransaction)?;
    if average_price_micros < order.price_micros {
        return Err(CoreError::InvalidOrder(
            "position close violated price protection".into(),
        ));
    }
    // Commit only to the exact protected liquidity slice consumed by this FOK
    // close. Hashing the entire private book lets an unrelated dust order or
    // cancellation invalidate every outstanding quote, creating a cheap DoS.
    // Each contributing maker's immutable priority plus current executable
    // state is included, so altering/cancelling any consumed liquidity, or
    // introducing a better executable level, still changes the commitment.
    let mut book_hash = Sha256::new();
    book_hash.update(b"layrs.position-close-executable-slice.v2\0");
    book_hash.update((market.market_id.len() as u32).to_be_bytes());
    book_hash.update(market.market_id.as_bytes());
    book_hash.update((result.fills.len() as u32).to_be_bytes());
    let mut protected_sequence = 0u64;
    for fill in &result.fills {
        let maker = prior_book
            .order(fill.maker_order_id)
            .ok_or_else(|| CoreError::InvalidOrder("position close quote is unavailable".into()))?;
        protected_sequence = protected_sequence.max(maker.sequence);
        book_hash.update(fill.maker_order_id.as_bytes());
        book_hash.update([match fill.match_type {
            MatchType::Normal => 0,
            MatchType::Mint => 1,
            MatchType::Merge => 2,
        }]);
        book_hash.update([match maker.outcome {
            Outcome::Up => 0,
            Outcome::Down => 1,
        }]);
        book_hash.update([match maker.action {
            OrderAction::Buy => 0,
            OrderAction::Sell => 1,
        }]);
        book_hash.update(maker.price_micros.to_be_bytes());
        book_hash.update(maker.remaining_micros.to_be_bytes());
        book_hash.update(maker.sequence.to_be_bytes());
        book_hash.update(maker.expires_at_millis.unwrap_or(i64::MAX).to_be_bytes());
        book_hash.update(fill.quantity_micros.to_be_bytes());
    }
    let book_commitment_sha256: [u8; 32] = book_hash.finalize().into();
    let mut preview = PositionClosePreview {
        position_id: position_id.to_owned(),
        quantity_micros: executed_quantity,
        minimum_price_micros: order.price_micros,
        average_price_micros,
        gross_payout_atomic,
        fee_atomic,
        net_payout_atomic: gross_payout_atomic
            .checked_sub(fee_atomic)
            .ok_or(CoreError::UnbalancedTransaction)?,
        book_commitment_sha256,
        // This is the highest maker-priority sequence in the protected slice,
        // not the mutable whole-book sequence.
        book_sequence: protected_sequence,
        expires_at_millis,
        quote_commitment_sha256: [0u8; 32],
    };
    preview.quote_commitment_sha256 =
        position_close_quote_commitment(identity_key, owner, &market.market_id, outcome, &preview);
    Ok(preview)
}

fn position_close_quote_commitment(
    identity_key: &[u8; 32],
    owner: &str,
    market_id: &str,
    outcome: Outcome,
    preview: &PositionClosePreview,
) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(identity_key)
        .expect("identity key has fixed HMAC length");
    mac.update(b"layrs.position-close-quote.v1\0");
    mac.update(&(owner.len() as u32).to_be_bytes());
    mac.update(owner.as_bytes());
    mac.update(&(market_id.len() as u32).to_be_bytes());
    mac.update(market_id.as_bytes());
    mac.update(match outcome {
        Outcome::Up => b"UP",
        Outcome::Down => b"DOWN",
    });
    mac.update(&(preview.position_id.len() as u32).to_be_bytes());
    mac.update(preview.position_id.as_bytes());
    mac.update(&preview.quantity_micros.to_be_bytes());
    mac.update(&preview.minimum_price_micros.to_be_bytes());
    mac.update(&preview.average_price_micros.to_be_bytes());
    mac.update(&preview.gross_payout_atomic.to_be_bytes());
    mac.update(&preview.fee_atomic.to_be_bytes());
    mac.update(&preview.net_payout_atomic.to_be_bytes());
    mac.update(&preview.book_commitment_sha256);
    mac.update(&preview.book_sequence.to_be_bytes());
    mac.update(&preview.expires_at_millis.to_be_bytes());
    mac.finalize().into_bytes().into()
}

fn portfolio_snapshot(
    ledger: &Ledger,
    books: &BTreeMap<String, PriceTimeBook>,
    cost_basis: &BTreeMap<PositionKey, u128>,
    identity_key: &[u8; 32],
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
                    position_id: derive_private_position_id(
                        identity_key,
                        owner,
                        &market_id,
                        parsed,
                    ),
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

fn recovery_result_marker(idempotency_key: &str, digest: [u8; 32]) -> String {
    format!("recovery-result:{idempotency_key}:{}", hex::encode(digest))
}

fn private_recovery_result_digest(
    identity_key: &[u8; 32],
    result: &CommandResult,
) -> CoreResult<[u8; 32]> {
    let encoded = serde_json::to_vec(result).map_err(|_| CoreError::InvalidRecoveryCapsule)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(identity_key)
        .map_err(|_| CoreError::InvalidRecoveryCapsule)?;
    mac.update(b"layrs.private-recovery-result.v1\0");
    mac.update(&(encoded.len() as u64).to_be_bytes());
    mac.update(&encoded);
    Ok(mac.finalize().into_bytes().into())
}

fn recovery_archive_ack_marker(
    idempotency_key: &str,
    result_digest: [u8; 32],
    archive_row_commitment: [u8; 32],
) -> String {
    let mut hash = Sha256::new();
    hash.update(b"layrs.private-recovery-archive-ack.v1\0");
    hash.update((idempotency_key.len() as u64).to_be_bytes());
    hash.update(idempotency_key.as_bytes());
    hash.update(result_digest);
    hash.update(archive_row_commitment);
    format!("recovery-archive-ack:{}", hex::encode(hash.finalize()))
}

fn recovery_capsule_size(capsule: &RecoveryCapsule) -> CoreResult<usize> {
    serde_json::to_vec(capsule)
        .map(|encoded| encoded.len())
        .map_err(|_| CoreError::InvalidRecoveryCapsule)
}

fn recovery_window_size(capsules: &BTreeMap<String, RecoveryCapsule>) -> CoreResult<usize> {
    serde_json::to_vec(capsules)
        .map(|encoded| encoded.len())
        .map_err(|_| CoreError::InvalidRecoveryCapsule)
}

fn insert_recovery_capsule(
    capsules: &mut BTreeMap<String, RecoveryCapsule>,
    idempotency_key: String,
    capsule: RecoveryCapsule,
) -> CoreResult<()> {
    if recovery_capsule_size(&capsule)? > MAX_RECOVERY_CAPSULE_BYTES {
        return Err(CoreError::RecoveryCapsuleTooLarge);
    }
    capsules.insert(idempotency_key.clone(), capsule);
    if capsules.len() > MAX_RECOVERY_CAPSULES
        || recovery_window_size(capsules)? > MAX_RECOVERY_WINDOW_BYTES
    {
        capsules.remove(&idempotency_key);
        return Err(CoreError::RecoveryWindowFull);
    }
    Ok(())
}

fn reserve_recovery_capacity(capsules: &BTreeMap<String, RecoveryCapsule>) -> CoreResult<()> {
    if capsules.len() >= MAX_RECOVERY_CAPSULES
        || recovery_window_size(capsules)?
            .checked_add(MAX_RECOVERY_CAPSULE_BYTES + 128 + 8)
            .ok_or(CoreError::RecoveryWindowFull)?
            > MAX_RECOVERY_WINDOW_BYTES
    {
        return Err(CoreError::RecoveryWindowFull);
    }
    Ok(())
}

fn validate_recovery_capsules(
    capsules: &BTreeMap<String, RecoveryCapsule>,
    processed: &BTreeMap<String, [u8; 32]>,
    system_keys: &BTreeSet<String>,
    identity_key: &[u8; 32],
    snapshot_sequence: u64,
) -> CoreResult<()> {
    if capsules.len() > MAX_RECOVERY_CAPSULES
        || recovery_window_size(capsules)? > MAX_RECOVERY_WINDOW_BYTES
    {
        return Err(CoreError::InvalidRecoveryCapsule);
    }
    for (idempotency_key, capsule) in capsules {
        if recovery_capsule_size(capsule)? > MAX_RECOVERY_CAPSULE_BYTES
            || capsule.sequence > snapshot_sequence
            || capsule.receipt.idempotency_key != *idempotency_key
            || capsule.receipt.enclave_sequence != capsule.sequence
            || capsule.receipt.command_commitment_sha256 != Some(capsule.request_hash)
            || processed.get(idempotency_key).copied() != Some(capsule.request_hash)
            || private_recovery_result_digest(identity_key, &capsule.result)?
                != capsule.result_digest
            || !system_keys.contains(&recovery_result_marker(
                idempotency_key,
                capsule.result_digest,
            ))
        {
            return Err(CoreError::InvalidRecoveryCapsule);
        }
    }
    Ok(())
}

fn incident_terminal_state_root() -> [u8; 32] {
    hex::decode(INCIDENT_TERMINAL_STATE_ROOT_HEX)
        .expect("incident state root is compile-time checked hex")
        .try_into()
        .expect("incident state root is 32 bytes")
}

fn incident_terminal_journal_head() -> [u8; 32] {
    hex::decode(INCIDENT_TERMINAL_JOURNAL_HEAD_HEX)
        .expect("incident journal head is compile-time checked hex")
        .try_into()
        .expect("incident journal head is 32 bytes")
}

fn incident_terminal_ciphertext_sha256() -> [u8; 32] {
    hex::decode(INCIDENT_TERMINAL_CIPHERTEXT_SHA256_HEX)
        .expect("incident ciphertext hash is compile-time checked hex")
        .try_into()
        .expect("incident ciphertext hash is 32 bytes")
}

fn incident_terminal_restore_policy() -> TerminalSnapshotRestorePolicy {
    TerminalSnapshotRestorePolicy {
        sequence: INCIDENT_TERMINAL_SEQUENCE,
        state_root: incident_terminal_state_root(),
        journal_head: incident_terminal_journal_head(),
        ciphertext_sha256: incident_terminal_ciphertext_sha256(),
    }
}

#[cfg(test)]
fn validate_exact_incident_terminal_snapshot(snapshot: &EncryptedSnapshot) -> CoreResult<()> {
    validate_terminal_snapshot_against_policy(snapshot, incident_terminal_restore_policy())
}

fn validate_terminal_snapshot_against_policy(
    snapshot: &EncryptedSnapshot,
    policy: TerminalSnapshotRestorePolicy,
) -> CoreResult<()> {
    if snapshot.sequence != policy.sequence
        || snapshot.state_root != policy.state_root
        || snapshot.journal_head != policy.journal_head
        || snapshot.ciphertext_hash != policy.ciphertext_sha256
        || Sha256::digest(&snapshot.ciphertext).as_slice() != snapshot.ciphertext_hash
    {
        return Err(CoreError::IncidentRecoveryPolicyMismatch);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn terminal_category_counts(
    ledger: &Ledger,
    books: &BTreeMap<String, PriceTimeBook>,
    markets: &BTreeMap<String, MarketConfig>,
    sessions: &SessionGuard,
    processed_hashes: &BTreeMap<String, [u8; 32]>,
    system_keys: &BTreeSet<String>,
    position_cost_basis: &[(PositionKey, u128)],
    resolutions: &BTreeMap<String, MarketResolution>,
) -> CoreResult<ExactTerminalCategoryCounts> {
    let mut users = ledger.offline_user_owners();
    let mut order_count = 0usize;
    for book in books.values() {
        order_count = order_count
            .checked_add(book.offline_orders().len())
            .ok_or(CoreError::UnbalancedTransaction)?;
        for order in book.offline_orders().values() {
            users.insert(order.private_user_id.clone());
        }
    }
    let (registered_session_count, sequenced_session_count) = sessions.offline_counts();
    Ok(ExactTerminalCategoryCounts {
        user_count: users.len(),
        registered_session_count,
        sequenced_session_count,
        ledger_record_count: ledger.offline_record_count(),
        position_cost_basis_count: position_cost_basis.len(),
        order_count,
        market_count: markets.len(),
        resolution_count: resolutions.len(),
        processed_command_count: processed_hashes.len(),
        system_key_count: system_keys.len(),
        aggregate_bucket_total_count: ledger.terminal_public_bucket_totals()?.len(),
        aggregate_asset_total_count: ledger.terminal_public_asset_totals()?.len(),
    })
}

#[allow(clippy::too_many_arguments)]
fn terminal_snapshot_digests(
    ledger: &Ledger,
    books: &BTreeMap<String, PriceTimeBook>,
    markets: &BTreeMap<String, MarketConfig>,
    sessions: &SessionGuard,
    processed_hashes: &BTreeMap<String, [u8; 32]>,
    system_keys: &BTreeSet<String>,
    position_cost_basis: &[(PositionKey, u128)],
    resolutions: &BTreeMap<String, MarketResolution>,
    private_rewards: &PrivateRewardBook,
) -> CoreResult<TerminalSnapshotDigests> {
    let available = ledger.offline_balances_for_buckets(&[AccountBucket::UserAvailable]);
    let order_holds = ledger.offline_balances_for_buckets(&[AccountBucket::UserOrderHold]);
    let withdrawal_holds =
        ledger.offline_balances_for_buckets(&[AccountBucket::UserWithdrawalHold]);
    let position_balances = ledger.offline_balances_for_buckets(&[AccountBucket::UserPosition]);
    let fee_balances = ledger.offline_balances_for_buckets(&[AccountBucket::FeeRevenue]);
    let pool_cash = ledger.offline_balances_for_buckets(&[AccountBucket::PoolCash]);

    let mut users = ledger.offline_user_owners();
    let mut snapshot_fill_state = BTreeMap::<(String, Uuid), u128>::new();
    for (market_id, book) in books {
        for order in book.offline_orders().values() {
            users.insert(order.private_user_id.clone());
            snapshot_fill_state.insert((market_id.clone(), order.order_id), order.filled_micros);
        }
    }

    let users_and_sessions = terminal_digest(
        b"layrs.terminal-snapshot.users-and-sessions.v1\0",
        &(users, sessions),
    )?;
    let available_balances = terminal_digest(
        b"layrs.terminal-snapshot.available-balances.v1\0",
        &available,
    )?;
    let order_holds = terminal_digest(b"layrs.terminal-snapshot.order-holds.v1\0", &order_holds)?;
    let withdrawal_holds = terminal_digest(
        b"layrs.terminal-snapshot.withdrawal-holds.v1\0",
        &withdrawal_holds,
    )?;
    let positions_and_cost_basis = terminal_digest(
        b"layrs.terminal-snapshot.positions-and-cost-basis.v1\0",
        &(position_balances, position_cost_basis),
    )?;
    let order_books = terminal_digest(b"layrs.terminal-snapshot.order-books.v1\0", books)?;
    let snapshot_fill_state = terminal_digest(
        b"layrs.terminal-snapshot.fill-state.v1\0",
        &snapshot_fill_state,
    )?;
    let resolutions = terminal_digest(b"layrs.terminal-snapshot.resolutions.v1\0", resolutions)?;
    let rewards = terminal_digest(b"layrs.terminal-snapshot.rewards.v1\0", private_rewards)?;
    let fees = terminal_digest(
        b"layrs.terminal-snapshot.fees.v1\0",
        &(fee_balances, private_rewards),
    )?;
    let markets = terminal_digest(b"layrs.terminal-snapshot.markets.v1\0", markets)?;
    let replay_state = terminal_digest(
        b"layrs.terminal-snapshot.replay-state.v1\0",
        &(ledger.offline_replay_keys(), processed_hashes, system_keys),
    )?;
    let custody_qualified_totals = terminal_digest(
        b"layrs.terminal-snapshot.custody-qualified-totals.v1\0",
        &ledger.custody_reconciliation_totals()?,
    )?;
    let composite_user_state = terminal_digest(
        b"layrs.terminal-snapshot.composite-user-state.v1\0",
        &[
            users_and_sessions,
            available_balances,
            order_holds,
            withdrawal_holds,
            positions_and_cost_basis,
            order_books,
            snapshot_fill_state,
            resolutions,
            rewards,
            fees,
            markets,
            replay_state,
            custody_qualified_totals,
        ],
    )?;
    let has_user_liability = available.iter().any(|(_, amount)| *amount > 0)
        || position_cost_basis.iter().any(|(_, amount)| *amount > 0)
        || ledger
            .offline_balances_for_buckets(&[
                AccountBucket::UserOrderHold,
                AccountBucket::UserWithdrawalHold,
                AccountBucket::UserPosition,
            ])
            .iter()
            .any(|(_, amount)| *amount > 0);
    let has_pool_cash = pool_cash.iter().any(|(_, amount)| *amount > 0);

    Ok(TerminalSnapshotDigests {
        users_and_sessions,
        available_balances,
        order_holds,
        withdrawal_holds,
        positions_and_cost_basis,
        order_books,
        snapshot_fill_state,
        resolutions,
        rewards,
        fees,
        markets,
        replay_state,
        custody_qualified_totals,
        composite_user_state,
        pool_cash_opening_required: has_user_liability && !has_pool_cash,
    })
}

fn terminal_digest<T: Serialize + ?Sized>(domain: &[u8], value: &T) -> CoreResult<[u8; 32]> {
    let value = serde_json::to_value(value).map_err(|_| CoreError::JournalCrypto)?;
    let canonical = terminal_canonical_json(value);
    let encoded = serde_json::to_vec(&canonical).map_err(|_| CoreError::JournalCrypto)?;
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update((encoded.len() as u64).to_be_bytes());
    hash.update(encoded);
    Ok(hash.finalize().into())
}

fn terminal_canonical_json(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Number(number) => serde_json::Value::String(number.to_string()),
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.into_iter().map(terminal_canonical_json).collect())
        }
        serde_json::Value::Object(values) => serde_json::Value::Object(
            values
                .into_iter()
                .map(|(key, value)| (key, terminal_canonical_json(value)))
                .collect(),
        ),
        value => value,
    }
}

#[allow(clippy::too_many_arguments)]
fn offline_state_digests(
    ledger: &Ledger,
    books: &BTreeMap<String, PriceTimeBook>,
    markets: &BTreeMap<String, MarketConfig>,
    sessions: &SessionGuard,
    processed_hashes: &BTreeMap<String, [u8; 32]>,
    system_keys: &BTreeSet<String>,
    position_cost_basis: &[(PositionKey, u128)],
    resolutions: &BTreeMap<String, MarketResolution>,
    private_rewards: &PrivateRewardBook,
    journal_fills: &[Fill],
) -> CoreResult<OfflineStateDigests> {
    let available = ledger.offline_balances_for_buckets(&[AccountBucket::UserAvailable]);
    let order_holds = ledger.offline_balances_for_buckets(&[AccountBucket::UserOrderHold]);
    let withdrawal_holds =
        ledger.offline_balances_for_buckets(&[AccountBucket::UserWithdrawalHold]);
    let position_balances = ledger.offline_balances_for_buckets(&[AccountBucket::UserPosition]);
    let fee_balances = ledger.offline_balances_for_buckets(&[AccountBucket::FeeRevenue]);
    let pool_cash = ledger.offline_balances_for_buckets(&[AccountBucket::PoolCash]);

    let mut user_owners = ledger.offline_user_owners();
    for book in books.values() {
        for order in book.offline_orders().values() {
            user_owners.insert(order.private_user_id.clone());
        }
    }

    let users = offline_digest(
        b"layrs.restore-equality.users.v1\0",
        &(user_owners, sessions),
    )?;
    let available_balances = offline_digest(b"layrs.restore-equality.available.v1\0", &available)?;
    let order_holds = offline_digest(b"layrs.restore-equality.order-holds.v1\0", &order_holds)?;
    let withdrawal_holds = offline_digest(
        b"layrs.restore-equality.withdrawal-holds.v1\0",
        &withdrawal_holds,
    )?;
    let positions = offline_digest(
        b"layrs.restore-equality.positions.v1\0",
        &(position_balances, position_cost_basis),
    )?;
    let orders = offline_digest(b"layrs.restore-equality.orders.v1\0", books)?;
    let fills = offline_digest(b"layrs.restore-equality.fills.v1\0", journal_fills)?;
    let resolutions = offline_digest(b"layrs.restore-equality.resolutions.v1\0", resolutions)?;
    let rewards = offline_digest(b"layrs.restore-equality.rewards.v1\0", private_rewards)?;
    let fees = offline_digest(
        b"layrs.restore-equality.fees.v1\0",
        &(fee_balances, private_rewards),
    )?;
    let markets = offline_digest(b"layrs.restore-equality.markets.v1\0", markets)?;
    let replay_keys = offline_digest(
        b"layrs.restore-equality.replay-keys.v1\0",
        &(ledger.offline_replay_keys(), processed_hashes, system_keys),
    )?;
    let qualified_totals = offline_digest(
        b"layrs.restore-equality.qualified-totals.v1\0",
        &ledger.custody_reconciliation_totals()?,
    )?;
    let user_state = offline_digest(
        b"layrs.restore-equality.user-state.v1\0",
        &(
            users,
            available_balances,
            order_holds,
            withdrawal_holds,
            positions,
            orders,
            fills,
            resolutions,
            rewards,
            fees,
            markets,
            replay_keys,
        ),
    )?;
    let has_user_liability = available.iter().any(|(_, amount)| *amount > 0)
        || position_cost_basis.iter().any(|(_, amount)| *amount > 0)
        || ledger
            .offline_balances_for_buckets(&[
                AccountBucket::UserOrderHold,
                AccountBucket::UserWithdrawalHold,
                AccountBucket::UserPosition,
            ])
            .iter()
            .any(|(_, amount)| *amount > 0);
    let has_pool_cash = pool_cash.iter().any(|(_, amount)| *amount > 0);

    Ok(OfflineStateDigests {
        users,
        available_balances,
        order_holds,
        withdrawal_holds,
        positions,
        orders,
        fills,
        resolutions,
        rewards,
        fees,
        markets,
        replay_keys,
        qualified_totals,
        user_state,
        pool_cash_opening_required: has_user_liability && !has_pool_cash,
    })
}

fn offline_journal_fill_evidence(
    values: Vec<serde_json::Value>,
) -> CoreResult<(Vec<Fill>, BTreeMap<(String, Uuid), u128>)> {
    let mut fills = Vec::new();
    let mut totals = BTreeMap::<(String, Uuid), u128>::new();
    for value in values {
        let is_user_command = value.get("command").is_some() || value.get("result").is_some();
        if !is_user_command {
            continue;
        }
        let entry: JournaledUserCommand =
            serde_json::from_value(value).map_err(|_| CoreError::JournalCrypto)?;
        let CommandResult::Order { result } = entry.result else {
            continue;
        };
        for fill in result.fills {
            for order_id in [fill.maker_order_id, fill.taker_order_id] {
                let key = (fill.market_id.clone(), order_id);
                let next = totals
                    .get(&key)
                    .copied()
                    .unwrap_or_default()
                    .checked_add(fill.quantity_micros)
                    .ok_or(CoreError::JournalChainMismatch)?;
                totals.insert(key, next);
            }
            fills.push(fill);
        }
    }
    Ok((fills, totals))
}

fn offline_fill_totals_equal(
    books: &BTreeMap<String, PriceTimeBook>,
    expected: &BTreeMap<(String, Uuid), u128>,
) -> bool {
    let actual: BTreeMap<(String, Uuid), u128> = books
        .iter()
        .flat_map(|(market_id, book)| {
            book.offline_orders()
                .values()
                .map(|order| ((market_id.clone(), order.order_id), order.filled_micros))
        })
        .filter(|(_, amount)| *amount > 0)
        .collect();
    actual == *expected
}

fn offline_digest<T: Serialize + ?Sized>(domain: &[u8], value: &T) -> CoreResult<[u8; 32]> {
    let encoded = serde_json::to_vec(value).map_err(|_| CoreError::JournalCrypto)?;
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update((encoded.len() as u64).to_be_bytes());
    hash.update(encoded);
    Ok(hash.finalize().into())
}

fn source_state_root(source: &CoreStateSnapshot) -> [u8; 32] {
    let position_cost_basis: BTreeMap<PositionKey, u128> =
        source.position_cost_basis.iter().cloned().collect();
    state_root(
        &source.ledger,
        &source.books,
        &source.markets,
        &source.sessions,
        &source.processed_hashes,
        &source.system_keys,
        &position_cost_basis,
        &source.resolutions,
        &source.oracle_public_key,
        &source.bootstrap_executions,
        &source.private_rewards,
        source.trading_frozen,
        source.sequence,
    )
}

fn read_only_response_hash(
    command: &UserCommand,
    result: &CommandResult,
    state_root: [u8; 32],
) -> CoreResult<[u8; 32]> {
    let encoded =
        serde_json::to_vec(&(command, result)).map_err(|_| CoreError::RequestHashMismatch)?;
    let mut hash = Sha256::new();
    hash.update(b"layrs.read-only-response.v1\0");
    hash.update(state_root);
    hash.update(encoded);
    Ok(hash.finalize().into())
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
    // Preserve byte-for-byte legacy roots until the first enclave-trusted user
    // command installs the clock fence. Thereafter this explicit versioned
    // domain makes the accepted high-water part of every state root while the
    // encrypted snapshot continues to persist the marker in `system_keys`.
    if let Some(high_water) = trusted_time_high_water(system_keys) {
        hash.update(b"layrs.trusted-time-state.v1\0");
        hash.update(&high_water.to_be_bytes());
    }
    let mut output = [0u8; 32];
    hash.finalize(&mut output);
    output
}

fn trusted_time_high_water(system_keys: &BTreeSet<String>) -> Option<i64> {
    let mut matching = system_keys
        .range(TRUSTED_TIME_HIGH_WATER_PREFIX.to_owned()..)
        .take_while(|key| key.starts_with(TRUSTED_TIME_HIGH_WATER_PREFIX));
    let value = matching
        .next()?
        .strip_prefix(TRUSTED_TIME_HIGH_WATER_PREFIX)?
        .parse::<i64>()
        .ok()?;
    matching.next().is_none().then_some(value)
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
mod category_fee_tests {
    use super::*;

    const GROSS: u128 = 100_000_000;

    #[test]
    fn legacy_profile_preserves_five_percent_profit_fee() {
        assert_eq!(
            settlement_winning_fee(FeeProfileId::LegacyProfitV1, 80_000_000, GROSS, false).unwrap(),
            1_000_000
        );
    }

    #[test]
    fn category_profiles_follow_curve_and_caps_at_representative_prices() {
        let vectors = [
            // profile, stake, expected fee
            (FeeProfileId::CryptoV1, 50_000_000, 2_000_000),
            (FeeProfileId::MacroV1, 50_000_000, 1_500_000),
            (FeeProfileId::SportsV1, 50_000_000, 1_000_000),
            (FeeProfileId::EsportsV1, 50_000_000, 1_000_000),
            (FeeProfileId::GeneralV1, 50_000_000, 1_250_000),
            (FeeProfileId::CryptoV1, 80_000_000, 1_000_000),
            (FeeProfileId::MacroV1, 80_000_000, 960_000),
            (FeeProfileId::SportsV1, 80_000_000, 800_000),
            (FeeProfileId::CryptoV1, 20_000_000, 800_000),
            (FeeProfileId::MacroV1, 20_000_000, 600_000),
            (FeeProfileId::SportsV1, 20_000_000, 400_000),
            // The five-percent-profit safety cap overrides the one-percent
            // stake target for near-certain winners.
            (FeeProfileId::CryptoV1, 95_000_000, 250_000),
        ];
        for (profile, stake, expected) in vectors {
            assert_eq!(
                settlement_winning_fee(profile, stake, GROSS, false).unwrap(),
                expected,
                "unexpected fee for {profile:?} at stake {stake}"
            );
        }
    }

    #[test]
    fn no_performance_fee_is_charged_on_loss_break_even_or_push() {
        for profile in [FeeProfileId::LegacyProfitV1, FeeProfileId::CryptoV1] {
            assert_eq!(settlement_winning_fee(profile, GROSS, 0, false).unwrap(), 0);
            assert_eq!(
                settlement_winning_fee(profile, GROSS, GROSS, false).unwrap(),
                0
            );
            assert_eq!(
                settlement_winning_fee(profile, 20_000_000, GROSS, true).unwrap(),
                0
            );
        }
    }

    #[test]
    fn configured_profiles_never_exceed_stake_or_profit_caps() {
        let profiles = [
            FeeProfileId::CryptoV1,
            FeeProfileId::MacroV1,
            FeeProfileId::FinanceV1,
            FeeProfileId::PoliticsV1,
            FeeProfileId::SportsV1,
            FeeProfileId::EsportsV1,
            FeeProfileId::WeatherV1,
            FeeProfileId::TechnologyV1,
            FeeProfileId::ScienceV1,
            FeeProfileId::CultureV1,
            FeeProfileId::BusinessV1,
            FeeProfileId::GeopoliticsV1,
            FeeProfileId::GeneralV1,
        ];
        for gross in [1u128, 10, 1_000_000, 1_000_000_000_000, u64::MAX as u128] {
            for price_bps in 1u128..10_000 {
                let stake = gross.saturating_mul(price_bps) / 10_000;
                if stake == 0 || stake >= gross {
                    continue;
                }
                let profit = gross - stake;
                for profile in profiles {
                    let fee = settlement_winning_fee(profile, stake, gross, false).unwrap();
                    let parameters = profile.parameters().unwrap();
                    assert!(fee <= floor_bps(stake, parameters.stake_cap_bps).unwrap());
                    assert!(fee <= floor_bps(profit, parameters.profit_cap_bps).unwrap());
                    assert!(fee <= gross);
                }
            }
        }
    }

    #[test]
    fn calculation_is_deterministic_across_repeated_runs() {
        let expected = settlement_winning_fee(
            FeeProfileId::CryptoV1,
            12_345_678_901_234_567,
            98_765_432_109_876_543,
            false,
        )
        .unwrap();
        for _ in 0..1_000 {
            assert_eq!(
                settlement_winning_fee(
                    FeeProfileId::CryptoV1,
                    12_345_678_901_234_567,
                    98_765_432_109_876_543,
                    false,
                )
                .unwrap(),
                expected
            );
        }
    }

    #[test]
    fn layrs_v2_profiles_cover_every_supported_category() {
        let vectors = [
            (FeeProfileId::LayrsCryptoV2, 700),
            (FeeProfileId::LayrsMacroV2, 500),
            (FeeProfileId::LayrsFinanceV2, 400),
            (FeeProfileId::LayrsPoliticsV2, 400),
            (FeeProfileId::LayrsSportsV2, 500),
            (FeeProfileId::LayrsEsportsV2, 500),
            (FeeProfileId::LayrsWeatherV2, 500),
            (FeeProfileId::LayrsTechnologyV2, 400),
            (FeeProfileId::LayrsMentionsV2, 400),
            (FeeProfileId::LayrsScienceV2, 500),
            (FeeProfileId::LayrsCultureV2, 500),
            (FeeProfileId::LayrsBusinessV2, 400),
            (FeeProfileId::LayrsGeneralV2, 500),
            (FeeProfileId::LayrsGeopoliticsV2, 0),
        ];

        for (profile, expected_rate_bps) in vectors {
            assert!(profile.has_layrs_curve_fees());
            assert_eq!(profile.taker_curve_rate_bps(), Some(expected_rate_bps));
            assert_eq!(profile.parameters(), None);
            assert_eq!(settlement_winning_fee(profile, 10, 100, false).unwrap(), 0);
        }
    }

    #[test]
    fn layrs_v2_names_are_canonical_without_rewriting_legacy_signed_profiles() {
        let current = serde_json::to_string(&FeeProfileId::LayrsCryptoV2).unwrap();
        let legacy = serde_json::from_str::<FeeProfileId>("\"POLYMARKET_CRYPTO_V2\"").unwrap();
        assert_eq!(current, "\"LAYRS_CRYPTO_V2\"");
        assert_eq!(legacy, FeeProfileId::PolymarketCryptoV2);
        assert_eq!(legacy.taker_curve_rate_bps(), current_profile_rate());

        fn current_profile_rate() -> Option<u128> {
            FeeProfileId::LayrsCryptoV2.taker_curve_rate_bps()
        }
    }

    #[test]
    fn layrs_v2_curve_matches_public_fee_vectors() {
        const ONE_HUNDRED_SHARES: u128 = 100_000_000;
        let vectors = [
            (FeeProfileId::LayrsCryptoV2, 1_750_000),
            (FeeProfileId::LayrsSportsV2, 1_250_000),
            (FeeProfileId::LayrsFinanceV2, 1_000_000),
            (FeeProfileId::LayrsMacroV2, 1_250_000),
            (FeeProfileId::LayrsGeopoliticsV2, 0),
        ];

        for (profile, expected_at_fifty_cents) in vectors {
            assert_eq!(
                taker_fee_micros(profile, ONE_HUNDRED_SHARES, 500_000).unwrap(),
                expected_at_fifty_cents,
                "unexpected 50c fee for {profile:?}"
            );
        }
    }

    #[test]
    fn layrs_v2_curve_is_symmetric_and_peaks_at_fifty_cents() {
        const SHARES: u128 = 123_456_789;
        for profile in [
            FeeProfileId::LayrsCryptoV2,
            FeeProfileId::LayrsMacroV2,
            FeeProfileId::LayrsSportsV2,
            FeeProfileId::LayrsTechnologyV2,
        ] {
            let low = taker_fee_micros(profile, SHARES, 10_000).unwrap();
            let high = taker_fee_micros(profile, SHARES, 990_000).unwrap();
            let middle = taker_fee_micros(profile, SHARES, 500_000).unwrap();
            assert_eq!(low, high, "curve is not symmetric for {profile:?}");
            assert!(middle >= low, "curve does not peak at 50c for {profile:?}");
        }
    }

    #[test]
    fn layrs_v2_fee_rounds_to_five_decimal_places() {
        assert_eq!(
            taker_fee_micros(FeeProfileId::LayrsCryptoV2, 100_000_000, 10_000).unwrap(),
            69_300
        );
        assert_eq!(
            taker_fee_micros(FeeProfileId::LayrsCryptoV2, 1, 10_000).unwrap(),
            0
        );
        assert_eq!(
            taker_fee_micros(FeeProfileId::LayrsCryptoV2, 100, 500_000).unwrap(),
            0
        );
        assert_eq!(
            taker_fee_micros(FeeProfileId::LayrsCryptoV2, 1_000, 500_000).unwrap(),
            20
        );
    }

    #[test]
    fn legacy_taker_fee_remains_twenty_basis_points_of_notional() {
        assert_eq!(
            taker_fee_micros(FeeProfileId::LegacyProfitV1, 100_000_000, 500_000).unwrap(),
            100_000
        );
    }
}

#[cfg(test)]
mod snapshot_migration_tests {
    use super::*;
    use crate::private_core::TimeInForce;

    fn incident_snapshot_metadata(sequence: u64) -> EncryptedSnapshot {
        EncryptedSnapshot {
            sequence,
            journal_head: incident_terminal_journal_head(),
            state_root: incident_terminal_state_root(),
            nonce: [0; 12],
            ciphertext: Vec::new(),
            ciphertext_hash: incident_terminal_ciphertext_sha256(),
        }
    }

    #[test]
    fn terminal_restore_route_authenticates_and_compares_a_deterministic_fixture() {
        let journal_key = JournalKey::from_bytes([0x71; 32]);
        let mut source =
            PrivateTradingCore::new(journal_key.clone(), ReceiptSigner::generate([0x72; 48]));
        source
            .ledger
            .seed_balance(
                AccountKey::new("private-fixture-user", AccountBucket::UserAvailable, "USDC"),
                6_000_000,
            )
            .unwrap();
        source
            .set_trading_freeze("terminal-fixture-freeze".into(), true, [0x73; 32], 1_000)
            .unwrap();
        let snapshot = source.export_encrypted_snapshot().unwrap();
        let policy = TerminalSnapshotRestorePolicy {
            sequence: snapshot.sequence,
            state_root: snapshot.state_root,
            journal_head: snapshot.journal_head,
            ciphertext_sha256: snapshot.ciphertext_hash,
        };

        let (restored, report) = PrivateTradingCore::restore_terminal_snapshot_against_policy(
            journal_key,
            ReceiptSigner::generate([0x74; 48]),
            &snapshot,
            policy,
        )
        .unwrap();

        assert_eq!(restored.sequence(), snapshot.sequence);
        assert_eq!(restored.state_root(), snapshot.state_root);
        assert_eq!(report.restored_sequence, snapshot.sequence);
        assert_eq!(report.restored_state_root, hex::encode(snapshot.state_root));
        assert_eq!(
            report.restored_journal_head,
            hex::encode(snapshot.journal_head)
        );
        assert_eq!(
            report.snapshot_ciphertext_sha256,
            hex::encode(snapshot.ciphertext_hash)
        );
        assert!(report.sequence_equal);
        assert!(report.state_root_equal);
        assert!(report.journal_head_equal);
        assert!(report.aggregate_totals_equal);
        assert!(report.aggregate_totals_zero_delta);
        assert!(!report.historical_journal_replay_performed);
        assert!(!report.historical_fill_completeness_certified);
        assert_eq!(report.aggregate_asset_totals.len(), 1);
        assert_eq!(report.aggregate_asset_totals[0].amount, 6_000_000);
    }

    #[test]
    fn incident_terminal_restore_rejects_every_non_exact_sequence_before_decrypt() {
        for sequence in [161_891, 161_918, 161_920] {
            assert_eq!(
                validate_exact_incident_terminal_snapshot(&incident_snapshot_metadata(sequence)),
                Err(CoreError::IncidentRecoveryPolicyMismatch)
            );
        }
    }

    #[test]
    fn incident_terminal_restore_rejects_root_head_and_ciphertext_substitution() {
        let mut wrong_root = incident_snapshot_metadata(INCIDENT_TERMINAL_SEQUENCE);
        wrong_root.state_root[0] ^= 1;
        assert_eq!(
            validate_exact_incident_terminal_snapshot(&wrong_root),
            Err(CoreError::IncidentRecoveryPolicyMismatch)
        );

        let mut wrong_head = incident_snapshot_metadata(INCIDENT_TERMINAL_SEQUENCE);
        wrong_head.journal_head[0] ^= 1;
        assert_eq!(
            validate_exact_incident_terminal_snapshot(&wrong_head),
            Err(CoreError::IncidentRecoveryPolicyMismatch)
        );

        let mut wrong_ciphertext_hash = incident_snapshot_metadata(INCIDENT_TERMINAL_SEQUENCE);
        wrong_ciphertext_hash.ciphertext_hash[0] ^= 1;
        assert_eq!(
            validate_exact_incident_terminal_snapshot(&wrong_ciphertext_hash),
            Err(CoreError::IncidentRecoveryPolicyMismatch)
        );

        // Exact public metadata is still insufficient: the ciphertext bytes
        // themselves must hash to the immutable policy value before key use.
        assert_eq!(
            validate_exact_incident_terminal_snapshot(&incident_snapshot_metadata(
                INCIDENT_TERMINAL_SEQUENCE
            )),
            Err(CoreError::IncidentRecoveryPolicyMismatch)
        );
    }

    #[test]
    fn terminal_digest_decimalizes_numbers_and_separates_domains() {
        let value = serde_json::json!({"amount": 7, "nested": [0, -2]});
        let canonical = terminal_canonical_json(value);
        assert_eq!(canonical["amount"], "7");
        assert_eq!(canonical["nested"][0], "0");
        assert_eq!(canonical["nested"][1], "-2");
        assert_ne!(
            terminal_digest(b"layrs.test.category-a.v1\0", &canonical).unwrap(),
            terminal_digest(b"layrs.test.category-b.v1\0", &canonical).unwrap()
        );
    }

    #[test]
    fn terminal_aggregate_totals_never_emit_private_owners() {
        let mut ledger = Ledger::default();
        ledger
            .seed_balance(
                AccountKey::new("private-owner-alpha", AccountBucket::UserAvailable, "USDC"),
                7,
            )
            .unwrap();
        ledger
            .seed_balance(
                AccountKey::new("private-owner-beta", AccountBucket::UserAvailable, "USDC"),
                11,
            )
            .unwrap();
        let totals = ledger.terminal_public_bucket_totals().unwrap();
        assert_eq!(totals.len(), 1);
        assert_eq!(totals[0].amount, 18);
        let encoded = serde_json::to_string(&totals).unwrap();
        assert!(!encoded.contains("private-owner-alpha"));
        assert!(!encoded.contains("private-owner-beta"));
        assert!(encoded.contains("\"amount\":\"18\""));
    }

    #[test]
    fn terminal_certificate_schema_rejects_unknown_fields() {
        let digests = ExactTerminalCategoryDigests {
            users_and_sessions_sha256: "00".repeat(32),
            available_balances_sha256: "00".repeat(32),
            order_holds_sha256: "00".repeat(32),
            withdrawal_holds_sha256: "00".repeat(32),
            positions_and_cost_basis_sha256: "00".repeat(32),
            order_books_sha256: "00".repeat(32),
            snapshot_fill_state_sha256: "00".repeat(32),
            resolutions_sha256: "00".repeat(32),
            rewards_sha256: "00".repeat(32),
            fees_sha256: "00".repeat(32),
            markets_sha256: "00".repeat(32),
            replay_state_sha256: "00".repeat(32),
            custody_qualified_totals_sha256: "00".repeat(32),
            composite_user_state_sha256: "00".repeat(32),
        };
        let equality = ExactTerminalCategoryEquality {
            users_and_sessions_equal: true,
            available_balances_equal: true,
            order_holds_equal: true,
            withdrawal_holds_equal: true,
            positions_and_cost_basis_equal: true,
            order_books_equal: true,
            snapshot_fill_state_equal: true,
            resolutions_equal: true,
            rewards_equal: true,
            fees_equal: true,
            markets_equal: true,
            replay_state_equal: true,
            custody_qualified_totals_equal: true,
            composite_user_state_equal: true,
        };
        let report = ExactTerminalSnapshotRestoreReport {
            source_release_commit: EXACT_LIVE_976_RELEASE_COMMIT.into(),
            restored_sequence: INCIDENT_TERMINAL_SEQUENCE,
            restored_state_root: INCIDENT_TERMINAL_STATE_ROOT_HEX.into(),
            restored_journal_head: INCIDENT_TERMINAL_JOURNAL_HEAD_HEX.into(),
            snapshot_ciphertext_sha256: INCIDENT_TERMINAL_CIPHERTEXT_SHA256_HEX.into(),
            aggregate_bucket_totals: Vec::new(),
            aggregate_asset_totals: Vec::new(),
            category_counts: ExactTerminalCategoryCounts {
                user_count: 0,
                registered_session_count: 0,
                sequenced_session_count: 0,
                ledger_record_count: 0,
                position_cost_basis_count: 0,
                order_count: 0,
                market_count: 0,
                resolution_count: 0,
                processed_command_count: 0,
                system_key_count: 0,
                aggregate_bucket_total_count: 0,
                aggregate_asset_total_count: 0,
            },
            category_digests: digests,
            category_equality: equality,
            sequence_equal: true,
            state_root_equal: true,
            journal_head_equal: true,
            aggregate_totals_equal: true,
            aggregate_totals_zero_delta: true,
            restore_floor_persisted: true,
            no_external_state_mutation_performed: true,
            pool_cash_opening_required: false,
            historical_journal_replay_performed: false,
            historical_fill_completeness_certified: false,
        };
        let mut value = serde_json::to_value(report).unwrap();
        value["privateState"] = serde_json::json!({"unexpected": true});
        assert!(serde_json::from_value::<ExactTerminalSnapshotRestoreReport>(value).is_err());
    }

    fn exact_976_binding(snapshot: &EncryptedSnapshot) -> ExactLive976CheckpointBinding {
        ExactLive976CheckpointBinding {
            source_release_commit: EXACT_LIVE_976_RELEASE_COMMIT.into(),
            checkpoint_sha256: "ab".repeat(32),
            sequence: snapshot.sequence,
            state_root: snapshot.state_root,
            journal_head: snapshot.journal_head,
        }
    }

    fn assert_exact_restore_pass(report: &ExactLive976RestoreReport) {
        assert!(report.source_checkpoint_equal);
        assert!(report.sequence_equal);
        assert!(report.journal_head_equal);
        assert!(report.state_root_equal);
        assert!(report.users_equal);
        assert!(report.available_balances_equal);
        assert!(report.order_holds_equal);
        assert!(report.withdrawal_holds_equal);
        assert!(report.positions_equal);
        assert!(report.orders_equal);
        assert!(report.fills_equal);
        assert!(report.resolutions_equal);
        assert!(report.rewards_equal);
        assert!(report.fees_equal);
        assert!(report.markets_equal);
        assert!(report.replay_keys_equal);
    }

    #[test]
    fn attested_runner_core_derives_every_wrapper_equality_field() {
        let journal_key = JournalKey::from_bytes([220u8; 32]);
        let mut core =
            PrivateTradingCore::new(journal_key.clone(), ReceiptSigner::generate([221u8; 48]));
        core.ledger
            .seed_balance(
                AccountKey::new(
                    "private-user-never-exported",
                    AccountBucket::UserAvailable,
                    "USDC",
                ),
                7_654_321,
            )
            .unwrap();
        let freeze = core
            .set_trading_freeze("offline-cert-freeze".into(), true, [8u8; 32], 1_000)
            .unwrap();
        let snapshot = core.export_live_976_snapshot_for_test().unwrap();
        let report = PrivateTradingCore::certify_exact_live_976_restore(
            journal_key,
            ReceiptSigner::generate([222u8; 48]),
            &snapshot,
            &[freeze.encrypted_record],
            exact_976_binding(&snapshot),
        )
        .unwrap();

        assert_exact_restore_pass(&report);
        assert!(report.pool_cash_opening_required);
        assert_eq!(report.legacy_zero_balance_count, 0);
        assert_eq!(report.qualified_totals_digest.len(), 64);
        assert_eq!(report.user_state_digest.len(), 64);
        let public_report = serde_json::to_string(&report).unwrap();
        assert!(!public_report.contains("private-user-never-exported"));
        assert!(!public_report.contains("7654321"));
    }

    #[test]
    fn attested_runner_core_rejects_a_tampered_immutable_journal() {
        let journal_key = JournalKey::from_bytes([223u8; 32]);
        let mut core =
            PrivateTradingCore::new(journal_key.clone(), ReceiptSigner::generate([224u8; 48]));
        let freeze = core
            .set_trading_freeze("offline-cert-freeze".into(), true, [9u8; 32], 1_000)
            .unwrap();
        let snapshot = core.export_live_976_snapshot_for_test().unwrap();
        let mut record = freeze.encrypted_record;
        record.ciphertext[0] ^= 1;

        assert!(matches!(
            PrivateTradingCore::certify_exact_live_976_restore(
                journal_key,
                ReceiptSigner::generate([225u8; 48]),
                &snapshot,
                &[record],
                exact_976_binding(&snapshot),
            ),
            Err(CoreError::JournalChainMismatch)
        ));
    }

    #[test]
    fn attested_runner_core_cannot_claim_a_substituted_checkpoint_is_equal() {
        let journal_key = JournalKey::from_bytes([226u8; 32]);
        let mut core =
            PrivateTradingCore::new(journal_key.clone(), ReceiptSigner::generate([227u8; 48]));
        let freeze = core
            .set_trading_freeze("offline-cert-freeze".into(), true, [10u8; 32], 1_000)
            .unwrap();
        let snapshot = core.export_live_976_snapshot_for_test().unwrap();
        let mut binding = exact_976_binding(&snapshot);
        binding.state_root = [0x55; 32];
        let report = PrivateTradingCore::certify_exact_live_976_restore(
            journal_key,
            ReceiptSigner::generate([228u8; 48]),
            &snapshot,
            &[freeze.encrypted_record],
            binding,
        )
        .unwrap();

        assert!(!report.source_checkpoint_equal);
        assert!(!report.state_root_equal);
    }

    #[test]
    fn attested_runner_fill_equality_requires_every_journaled_fill_total() {
        let market_id = "layrs:v3:ZEN:15m:offline-fill-equality";
        let maker_id = Uuid::from_u128(1);
        let taker_id = Uuid::from_u128(2);
        let mut book = PriceTimeBook::default();
        book.submit(
            BookOrder::with_id(
                maker_id,
                "private-maker",
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
        let result = book
            .submit(
                BookOrder::with_id(
                    taker_id,
                    "private-taker",
                    market_id,
                    Outcome::Up,
                    OrderAction::Buy,
                    400_000,
                    1_000_000,
                    TimeInForce::Gtc,
                    None,
                ),
                2_000,
            )
            .unwrap();
        let books = BTreeMap::from([(market_id.into(), book)]);
        let fill = result.fills.first().unwrap();
        let exact = BTreeMap::from([
            (
                (market_id.into(), fill.maker_order_id),
                fill.quantity_micros,
            ),
            (
                (market_id.into(), fill.taker_order_id),
                fill.quantity_micros,
            ),
        ]);
        assert!(offline_fill_totals_equal(&books, &exact));

        let mut diluted = exact;
        *diluted.get_mut(&(market_id.into(), maker_id)).unwrap() -= 1;
        assert!(!offline_fill_totals_equal(&books, &diluted));
    }

    #[test]
    fn restores_exact_live_976_snapshot_shape_without_changing_checkpoint() {
        let journal_key = JournalKey::from_bytes([210u8; 32]);
        let mut core =
            PrivateTradingCore::new(journal_key.clone(), ReceiptSigner::generate([211u8; 48]));
        core.ledger
            .seed_balance(
                AccountKey::new("private-user", AccountBucket::UserAvailable, "USDC"),
                5_000_000,
            )
            .unwrap();

        let expected_sequence = core.sequence();
        let expected_root = core.state_root();
        let snapshot = core.export_live_976_snapshot_for_test().unwrap();
        let expected_head = snapshot.journal_head;

        let restored = PrivateTradingCore::restore_encrypted_snapshot(
            journal_key,
            ReceiptSigner::generate([212u8; 48]),
            &snapshot,
            expected_sequence,
        )
        .unwrap();

        assert_eq!(restored.sequence(), expected_sequence);
        assert_eq!(restored.state_root(), expected_root);
        assert_eq!(
            restored.journal.chain_head(),
            (expected_sequence, expected_head)
        );
        assert!(restored.recovery_capsules.is_empty());
    }

    #[test]
    fn restores_976_zero_balance_and_journals_pool_cash_opening_without_user_drift() {
        let journal_key = JournalKey::from_bytes([213u8; 32]);
        let mut core =
            PrivateTradingCore::new(journal_key.clone(), ReceiptSigner::generate([214u8; 48]));
        let user = AccountKey::new("private-user", AccountBucket::UserAvailable, "USDC");
        let depleted = AccountKey::new("depleted-user", AccountBucket::UserAvailable, "USDC");
        core.ledger.seed_balance(user.clone(), 5_000_000).unwrap();
        core.ledger
            .insert_legacy_zero_balance_for_test(depleted.clone());
        core.set_trading_freeze("freeze-for-opening".into(), true, [9u8; 32], 1_000)
            .unwrap();
        let snapshot = core.export_live_976_snapshot_for_test().unwrap();

        let mut restored = PrivateTradingCore::restore_encrypted_snapshot(
            journal_key,
            ReceiptSigner::generate([215u8; 48]),
            &snapshot,
            snapshot.sequence,
        )
        .unwrap();
        assert_eq!(restored.ledger.legacy_zero_balance_count(), 1);
        assert_eq!(restored.balance(&user), 5_000_000);
        assert_eq!(restored.balance(&depleted), 0);

        let source_sequence = restored.sequence();
        let source_root = restored.state_root();
        let source_head = restored.journal.chain_head().1;
        let response = restored
            .migrate_historical_pool_cash_opening(
                "opening-usdc".into(),
                [10u8; 32],
                vec![PoolCashOpening {
                    asset: "USDC".into(),
                    amount: 25_000_000,
                }],
                source_sequence,
                source_root,
                source_head,
                2_000,
            )
            .unwrap();

        assert_eq!(restored.balance(&user), 5_000_000);
        assert_eq!(restored.balance(&depleted), 0);
        assert_eq!(restored.ledger.legacy_zero_balance_count(), 0);
        assert_eq!(
            restored.balance(&AccountKey::new("layrs", AccountBucket::PoolCash, "USDC")),
            25_000_000
        );
        assert_eq!(restored.sequence(), source_sequence + 1);
        assert_eq!(response.receipt.prior_state_root, source_root);
        assert_eq!(response.receipt.state_root, restored.state_root());
        assert_eq!(
            restored.journal.chain_head(),
            (restored.sequence(), response.encrypted_record.record_hash)
        );

        assert!(matches!(
            restored.migrate_historical_pool_cash_opening(
                "opening-usdc-replay".into(),
                [10u8; 32],
                vec![PoolCashOpening {
                    asset: "USDC".into(),
                    amount: 25_000_000,
                }],
                source_sequence,
                source_root,
                source_head,
                3_000,
            ),
            Err(CoreError::JournalChainMismatch)
        ));
    }

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
