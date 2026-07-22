use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tiny_keccak::{Hasher, Keccak};
use uuid::Uuid;

use super::{
    AccountBucket, AccountKey, BookOrder, ClaimPayout, CompleteSetDirection,
    CompleteSetTransaction, CoreError, CoreResult, EnclaveReceipt, EncryptedJournal,
    EncryptedJournalRecord, EncryptedSnapshot, ExternalFlowDirection, ExternalFlowTransaction,
    JournalKey, Ledger, LedgerTransaction, MatchResult, OrderAction, OrderStatus, Outcome,
    PriceTimeBook, ReceiptSigner, SessionGuard, SignedSessionRequest, Transfer, PRICE_SCALE,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarketConfig {
    pub market_id: String,
    pub settlement_asset: String,
    pub opens_at_millis: i64,
    pub closes_at_millis: i64,
    #[serde(with = "super::decimal_u128")]
    pub minimum_quantity_micros: u128,
    #[serde(with = "super::decimal_u128")]
    pub maximum_quantity_micros: u128,
    pub tick_size_micros: u64,
    pub oracle_feed_id: u64,
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
pub struct MarketResolution {
    pub outcome: ResolutionOutcome,
    pub statement: ResolutionStatement,
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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemResponse {
    pub receipt: EnclaveReceipt,
    pub encrypted_record: EncryptedJournalRecord,
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
    RegisterMarket {
        idempotency_key: String,
        market: MarketConfig,
    },
    RegisterSession {
        idempotency_key: String,
        session_id: String,
        private_user_id: String,
        public_key: [u8; 32],
        expires_at_millis: i64,
    },
    ExternalFlow {
        idempotency_key: String,
        flow: ExternalFlowTransaction,
    },
    ResolveMarket {
        idempotency_key: String,
        resolution: MarketResolution,
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
    sequence: u64,
}

impl PrivateTradingCore {
    pub fn new(journal_key: JournalKey, receipt_signer: ReceiptSigner) -> Self {
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
            sequence: 0,
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
                sequence: self.sequence,
            },
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
        let mut journal = EncryptedJournal::new(journal_key);
        let state: CoreStateSnapshot = journal.open_snapshot(snapshot)?;
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
            system_keys: state.system_keys,
            journal,
            receipt_signer,
            position_cost_basis,
            resolutions: state.resolutions,
            oracle_public_key: state.oracle_public_key,
            sequence: state.sequence,
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
            self.sequence,
        )
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
        private_user_id: String,
        public_key: [u8; 32],
        expires_at_millis: i64,
        now_millis: i64,
    ) -> CoreResult<SystemResponse> {
        self.validate_new_system_key(&idempotency_key)?;
        let prior_root = self.state_root();
        let mut sessions = self.sessions.clone();
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
            next_sequence,
        );
        let entry = JournaledSystemCommand::RegisterSession {
            idempotency_key: idempotency_key.clone(),
            session_id,
            private_user_id,
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
        if self.resolutions.contains_key(&market.market_id) {
            return Err(CoreError::InvalidResolution(
                "market is already resolved".into(),
            ));
        }
        validate_resolution(market, &signed, self.oracle_public_key, now_millis)?;
        let outcome = if signed.statement.closing.median_price_e8
            > signed.statement.opening.median_price_e8
        {
            ResolutionOutcome::Up
        } else if signed.statement.closing.median_price_e8
            < signed.statement.opening.median_price_e8
        {
            ResolutionOutcome::Down
        } else {
            ResolutionOutcome::Push
        };
        let resolution = MarketResolution {
            outcome,
            statement: signed.statement,
        };

        let prior_root = self.state_root();
        let mut ledger = self.ledger.clone();
        let mut books = self.books.clone();
        let mut position_cost_basis = self.position_cost_basis.clone();
        if let Some(book) = books.get_mut(&market.market_id) {
            let cancelled = book.cancel_all(&market.market_id);
            let mut releases = Vec::with_capacity(cancelled.len());
            for order in &cancelled {
                releases.extend(cancellation_transfers(market, order)?);
            }
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
            let gross = match outcome {
                ResolutionOutcome::Up if claim_outcome == Outcome::Up => quantity,
                ResolutionOutcome::Down if claim_outcome == Outcome::Down => quantity,
                ResolutionOutcome::Push => quantity / 2,
                _ => 0,
            };
            let winning_fee = if matches!(outcome, ResolutionOutcome::Push) {
                0
            } else {
                ceil_bps(gross.saturating_sub(basis), 500)?
            };
            payouts.push(ClaimPayout {
                claim_account,
                destination: available(&key.owner, &market.settlement_asset),
                claim_quantity_micros: quantity,
                gross_payout_micros: gross,
                winning_fee_micros: winning_fee,
            });
        }
        let collateral = market_collateral(&market.market_id, &market.settlement_asset);
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

        let prior_root = self.state_root();
        let mut sessions = self.sessions.clone();
        let private_user_id = sessions.accept_signed(&command.session, now_millis)?;
        let mut ledger = self.ledger.clone();
        let mut books = self.books.clone();
        let mut position_cost_basis = self.position_cost_basis.clone();
        let result = match &command.action {
            UserCommandAction::SubmitOrder { order } => {
                if order.private_user_id != private_user_id {
                    return Err(CoreError::InvalidOrder(
                        "order owner does not match session".into(),
                    ));
                }
                let market = self
                    .markets
                    .get(&order.market_id)
                    .ok_or_else(|| CoreError::InvalidOrder("unknown market".into()))?;
                validate_order_for_market(order, market, now_millis)?;
                let book = books.entry(order.market_id.clone()).or_default();
                let match_result = book.submit(order.clone(), now_millis)?;
                if match_result
                    .accepted_order
                    .as_ref()
                    .is_some_and(|accepted| accepted.status != OrderStatus::Rejected)
                {
                    let transfers =
                        settlement_transfers(&self.books, &books, market, order, &match_result)?;
                    apply_fill_cost_basis(
                        &self.ledger,
                        &self.books,
                        &books,
                        order,
                        &match_result,
                        &mut position_cost_basis,
                    )?;
                    ledger.apply(LedgerTransaction {
                        idempotency_key: format!("order:{}", command.idempotency_key),
                        business_reference: command.command_id.clone(),
                        transfers,
                    })?;
                }
                CommandResult::Order {
                    result: match_result,
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
                let order = book.cancel(*order_id, &private_user_id)?;
                let transfers = cancellation_transfers(market, &order)?;
                ledger.apply(LedgerTransaction {
                    idempotency_key: format!("cancel:{}", command.idempotency_key),
                    business_reference: command.command_id.clone(),
                    transfers,
                })?;
                CommandResult::Cancelled { order }
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
                apply_complete_set_cost_basis(
                    &ledger,
                    &mut position_cost_basis,
                    &private_user_id,
                    market_id,
                    *quantity_micros,
                    *direction,
                )?;
                ledger.apply_complete_set(CompleteSetTransaction {
                    idempotency_key: format!("complete-set:{}", command.idempotency_key),
                    owner: private_user_id,
                    market_id: market_id.clone(),
                    settlement_asset: market.settlement_asset.clone(),
                    quantity_micros: *quantity_micros,
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
            UserCommandAction::RequestWithdrawal {
                withdrawal_id,
                chain,
                asset,
                amount_atomic,
                destination,
            } => {
                validate_withdrawal(chain, asset, *amount_atomic, destination)?;
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
            &self.system_keys,
            &position_cost_basis,
            &self.resolutions,
            &self.oracle_public_key,
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
        let response = CoreResponse {
            result,
            receipt,
            encrypted_record: record,
            withdrawal_authorization,
        };
        self.ledger = ledger;
        self.books = books;
        self.sessions = sessions;
        self.position_cost_basis = position_cost_basis;
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
            self.sequence,
            prior_root,
            state_root,
            encrypted_record.record_hash,
            now_millis,
        );
        SystemResponse {
            receipt,
            encrypted_record,
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
    let initial_notional = notional(incoming.price_micros, incoming.quantity_micros)?;
    match incoming.action {
        OrderAction::Buy => transfers.push(Transfer {
            from: available(&incoming.private_user_id, &market.settlement_asset),
            to: incoming_cash_hold.clone(),
            amount: initial_notional
                .checked_add(ceil_bps(initial_notional, 20)?)
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
        let fill_notional = notional(fill.price_micros, fill.quantity_micros)?;
        let taker_fee = ceil_bps(fill_notional, 20)?;
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
                .checked_add(ceil_bps(initial_notional, 20)?)
                .ok_or(CoreError::UnbalancedTransaction)?;
            let desired_hold = notional(incoming.price_micros, accepted.remaining_micros)?;
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

fn apply_fill_cost_basis(
    ledger: &Ledger,
    prior_books: &BTreeMap<String, PriceTimeBook>,
    next_books: &BTreeMap<String, PriceTimeBook>,
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
        let acquisition_cost = notional(fill.price_micros, fill.quantity_micros)?;
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
    direction: CompleteSetDirection,
) -> CoreResult<()> {
    let up_key = position_key(owner, market_id, Outcome::Up);
    let down_key = position_key(owner, market_id, Outcome::Down);
    match direction {
        CompleteSetDirection::Mint => {
            let up_allocation = quantity_micros / 2;
            let down_allocation = quantity_micros - up_allocation;
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

fn cancellation_transfers(market: &MarketConfig, order: &BookOrder) -> CoreResult<Vec<Transfer>> {
    let transfer = match order.action {
        OrderAction::Buy => Transfer {
            from: cash_hold(order, &market.settlement_asset),
            to: available(&order.private_user_id, &market.settlement_asset),
            amount: notional(order.price_micros, order.remaining_micros)?,
        },
        OrderAction::Sell => Transfer {
            from: claim_hold(order),
            to: claim_position(order),
            amount: order.remaining_micros,
        },
    };
    Ok(vec![transfer])
}

fn available(owner: &str, asset: &str) -> AccountKey {
    AccountKey::new(owner, AccountBucket::UserAvailable, asset)
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

fn validate_market(market: &MarketConfig, now_millis: i64) -> CoreResult<()> {
    if !market.market_id.starts_with("layrs:v1:")
        || market.settlement_asset.is_empty()
        || market.opens_at_millis >= market.closes_at_millis
        || market.closes_at_millis <= now_millis
        || market.minimum_quantity_micros == 0
        || market.minimum_quantity_micros > market.maximum_quantity_micros
        || market.tick_size_micros == 0
        || market.tick_size_micros >= PRICE_SCALE as u64
        || market.oracle_feed_id == 0
    {
        return Err(CoreError::InvalidOrder(
            "invalid market configuration".into(),
        ));
    }
    Ok(())
}

fn validate_resolution(
    market: &MarketConfig,
    signed: &SignedResolution,
    oracle_public_key: Option<[u8; 32]>,
    now_millis: i64,
) -> CoreResult<()> {
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
        || order.price_micros % market.tick_size_micros != 0
    {
        return Err(CoreError::InvalidOrder(
            "order violates market limits".into(),
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
        || !matches!((chain, asset), ("base", "USDC") | ("horizen", "ZEN"))
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
    sequence: u64,
) -> [u8; 32] {
    let mut hash = Keccak::v256();
    hash.update(b"layrs.private-trading-core.v1\0");
    hash.update(&sequence.to_be_bytes());
    hash.update(&ledger.state_root());
    for value in [
        serde_json::to_vec(books),
        serde_json::to_vec(markets),
        serde_json::to_vec(sessions),
        serde_json::to_vec(processed),
        serde_json::to_vec(system_keys),
        serde_json::to_vec(&position_cost_basis.iter().collect::<Vec<_>>()),
        serde_json::to_vec(resolutions),
        serde_json::to_vec(oracle_public_key),
    ] {
        let encoded = value.expect("private core state serialization cannot fail");
        hash.update(&(encoded.len() as u64).to_be_bytes());
        hash.update(&encoded);
    }
    let mut output = [0u8; 32];
    hash.finalize(&mut output);
    output
}
