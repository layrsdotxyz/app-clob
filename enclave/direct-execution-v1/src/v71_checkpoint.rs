//! Bounded authenticated checkpoints for the v71 journal lineage.
//!
//! Unlike v70, this snapshot serializes current financial state exactly once
//! and never embeds historical request results. Active withdrawal holds and
//! conditional deposits are explicit so restore does not reconstruct money
//! state from prunable history.

use std::collections::{BTreeMap, BTreeSet};

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;

use crate::{
    amount, sha256, valid_bus_deposit_reference, valid_bus_withdrawal_id,
    valid_layrs_withdrawal_destination, ConditionalUsdcDeposit, DirectMarketResolutionRecord,
    DirectRuntime, MarketConfig, OrderReservation, Outcome, PriceTimeBook, UsdcBusHold, EPOCH_ID,
};

pub const DIRECT_V71_CHECKPOINT_PROTOCOL: &str = "layrs.direct-execution.checkpoint.v71";
const CHECKPOINT_NONCE_DOMAIN: &[u8] = b"layrs.direct-execution.checkpoint-nonce.v71\0";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum V71CheckpointError {
    #[error("v71 checkpoint input is invalid")]
    Invalid,
    #[error("v71 checkpoint authentication failed")]
    Authentication,
    #[error("v71 checkpoint could not be decrypted")]
    Decryption,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectV71Checkpoint {
    pub protocol: String,
    pub epoch_id: String,
    pub writer_epoch: String,
    pub sequence: u64,
    pub record_hash: String,
    pub transition_root: String,
    pub request_index_root: String,
    pub financial_state_root: String,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub ciphertext_hash: String,
    pub signature: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct V71FinancialState {
    opening_state_hash: String,
    balances: BTreeMap<String, BTreeMap<(String, String), u128>>,
    subject_identities: BTreeMap<String, BTreeSet<String>>,
    subject_wallets: BTreeMap<String, BTreeSet<String>>,
    markets: BTreeMap<String, MarketConfig>,
    books: BTreeMap<String, PriceTimeBook>,
    orders: BTreeMap<String, OrderReservation>,
    positions: BTreeMap<(String, String, Outcome), u128>,
    position_holds: BTreeMap<String, u128>,
    position_cost_basis: BTreeMap<(String, String, Outcome), u128>,
    market_collateral: BTreeMap<String, u128>,
    resolved_markets: BTreeMap<String, DirectMarketResolutionRecord>,
    fee_revenue_atomic: u128,
    zen_fee_revenue_atomic: u128,
    zen_rounding_reserve_atomic: u128,
    rounding_reserve_atomic: u128,
    credited_custody_references: BTreeSet<String>,
    usdc_bus_withdrawals: BTreeMap<String, UsdcBusHold>,
    conditional_usdc_deposits: BTreeMap<String, ConditionalUsdcDeposit>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CheckpointAssociatedData<'a> {
    protocol: &'a str,
    epoch_id: &'a str,
    writer_epoch: &'a str,
    sequence: u64,
    record_hash: &'a str,
    transition_root: &'a str,
    request_index_root: &'a str,
    financial_state_root: &'a str,
}

impl DirectV71Checkpoint {
    pub fn checkpoint_hash(&self) -> Result<String, V71CheckpointError> {
        serde_cbor::to_vec(self)
            .map(|bytes| sha256(&bytes))
            .map_err(|_| V71CheckpointError::Invalid)
    }

    fn signature_bytes(&self) -> Result<Vec<u8>, V71CheckpointError> {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        serde_cbor::to_vec(&unsigned).map_err(|_| V71CheckpointError::Invalid)
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn seal_checkpoint(
    runtime: &DirectRuntime,
    writer_epoch: &str,
    sequence: u64,
    record_hash: &str,
    transition_root: &str,
    request_index_root: &str,
    state_key: &[u8],
    signing_key_seed: &[u8],
) -> Result<DirectV71Checkpoint, V71CheckpointError> {
    if writer_epoch.is_empty()
        || writer_epoch.len() > 128
        || !runtime.requests.is_empty()
        || ![record_hash, transition_root, request_index_root]
            .into_iter()
            .all(digest)
        || state_key.len() != 32
        || signing_key_seed.len() != 32
    {
        return Err(V71CheckpointError::Invalid);
    }
    let state = V71FinancialState::from_runtime(runtime);
    state.validate()?;
    let plaintext = serde_cbor::to_vec(&state).map_err(|_| V71CheckpointError::Invalid)?;
    let financial_state_root = sha256(&plaintext);
    let associated_data = associated_data(
        writer_epoch,
        sequence,
        record_hash,
        transition_root,
        request_index_root,
        &financial_state_root,
    )?;
    let nonce = checkpoint_nonce(state_key, &associated_data, &plaintext)?;
    let ciphertext = ChaCha20Poly1305::new(Key::from_slice(state_key))
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: &associated_data,
            },
        )
        .map_err(|_| V71CheckpointError::Invalid)?;
    let mut checkpoint = DirectV71Checkpoint {
        protocol: DIRECT_V71_CHECKPOINT_PROTOCOL.into(),
        epoch_id: EPOCH_ID.into(),
        writer_epoch: writer_epoch.into(),
        sequence,
        record_hash: record_hash.into(),
        transition_root: transition_root.into(),
        request_index_root: request_index_root.into(),
        financial_state_root,
        nonce,
        ciphertext_hash: sha256(&ciphertext),
        ciphertext,
        signature: String::new(),
    };
    checkpoint.signature = sign(signing_key_seed, &checkpoint.signature_bytes()?)?;
    Ok(checkpoint)
}

pub(crate) fn restore_checkpoint(
    mut runtime: DirectRuntime,
    checkpoint: &DirectV71Checkpoint,
    state_key: &[u8],
    verification_key: &[u8],
) -> Result<DirectRuntime, V71CheckpointError> {
    if checkpoint.protocol != DIRECT_V71_CHECKPOINT_PROTOCOL
        || checkpoint.epoch_id != EPOCH_ID
        || checkpoint.writer_epoch.is_empty()
        || checkpoint.writer_epoch.len() > 128
        || checkpoint.nonce.len() != 12
        || state_key.len() != 32
        || verification_key.len() != 32
        || ![
            checkpoint.record_hash.as_str(),
            checkpoint.transition_root.as_str(),
            checkpoint.request_index_root.as_str(),
            checkpoint.financial_state_root.as_str(),
            checkpoint.ciphertext_hash.as_str(),
        ]
        .into_iter()
        .all(digest)
        || checkpoint.ciphertext_hash != sha256(&checkpoint.ciphertext)
    {
        return Err(V71CheckpointError::Invalid);
    }
    verify_signature(
        verification_key,
        &checkpoint.signature_bytes()?,
        &checkpoint.signature,
    )?;
    let associated_data = associated_data(
        &checkpoint.writer_epoch,
        checkpoint.sequence,
        &checkpoint.record_hash,
        &checkpoint.transition_root,
        &checkpoint.request_index_root,
        &checkpoint.financial_state_root,
    )?;
    let plaintext = ChaCha20Poly1305::new(Key::from_slice(state_key))
        .decrypt(
            Nonce::from_slice(&checkpoint.nonce),
            Payload {
                msg: &checkpoint.ciphertext,
                aad: &associated_data,
            },
        )
        .map_err(|_| V71CheckpointError::Decryption)?;
    if checkpoint.nonce != checkpoint_nonce(state_key, &associated_data, &plaintext)?
        || checkpoint.financial_state_root != sha256(&plaintext)
    {
        return Err(V71CheckpointError::Authentication);
    }
    let state: V71FinancialState =
        serde_cbor::from_slice(&plaintext).map_err(|_| V71CheckpointError::Invalid)?;
    state.validate()?;
    if runtime.opening_state_hash != state.opening_state_hash || !runtime.requests.is_empty() {
        return Err(V71CheckpointError::Authentication);
    }
    state.apply(&mut runtime);
    Ok(runtime)
}

pub(crate) fn financial_state_root(runtime: &DirectRuntime) -> Result<String, V71CheckpointError> {
    if !runtime.requests.is_empty() {
        return Err(V71CheckpointError::Invalid);
    }
    let state = V71FinancialState::from_runtime(runtime);
    state.validate()?;
    serde_cbor::to_vec(&state)
        .map(|bytes| sha256(&bytes))
        .map_err(|_| V71CheckpointError::Invalid)
}

impl V71FinancialState {
    fn from_runtime(runtime: &DirectRuntime) -> Self {
        Self {
            opening_state_hash: runtime.opening_state_hash.clone(),
            balances: runtime.balances.clone(),
            subject_identities: runtime.subject_identities.clone(),
            subject_wallets: runtime.subject_wallets.clone(),
            markets: runtime.markets.clone(),
            books: runtime.books.clone(),
            orders: runtime.orders.clone(),
            positions: runtime.positions.clone(),
            position_holds: runtime.position_holds.clone(),
            position_cost_basis: runtime.position_cost_basis.clone(),
            market_collateral: runtime.market_collateral.clone(),
            resolved_markets: runtime.resolved_markets.clone(),
            fee_revenue_atomic: runtime.fee_revenue_atomic,
            zen_fee_revenue_atomic: runtime.zen_fee_revenue_atomic,
            zen_rounding_reserve_atomic: runtime.zen_rounding_reserve_atomic,
            rounding_reserve_atomic: runtime.rounding_reserve_atomic,
            credited_custody_references: runtime.credited_custody_references.clone(),
            usdc_bus_withdrawals: runtime.usdc_bus_withdrawals.clone(),
            conditional_usdc_deposits: runtime.conditional_usdc_deposits.clone(),
        }
    }

    fn validate(&self) -> Result<(), V71CheckpointError> {
        if !digest(&self.opening_state_hash) {
            return Err(V71CheckpointError::Invalid);
        }
        let mut hold_totals = BTreeMap::<(String, String), u128>::new();
        let mut hold_identities = BTreeSet::new();
        for (withdrawal_id, hold) in &self.usdc_bus_withdrawals {
            let value = amount(&hold.amount_atomic).map_err(|_| V71CheckpointError::Invalid)?;
            if !valid_bus_withdrawal_id(withdrawal_id)
                || value.to_string() != hold.amount_atomic
                || !self
                    .subject_identities
                    .get(&hold.account_id)
                    .is_some_and(|identities| identities.contains(&hold.identity_commitment))
                || !valid_layrs_withdrawal_destination(
                    &hold.destination_chain,
                    &hold.asset,
                    &hold.destination,
                )
                || !hold_identities.insert(hold.identity_commitment.clone())
            {
                return Err(V71CheckpointError::Invalid);
            }
            let ledger_asset = if hold.asset == "ZEN" { "ZEN" } else { "USDC" };
            let total = hold_totals
                .entry((hold.identity_commitment.clone(), ledger_asset.into()))
                .or_default();
            *total = total
                .checked_add(value)
                .ok_or(V71CheckpointError::Invalid)?;
        }
        for (identity, balances) in &self.balances {
            for asset in ["USDC", "ZEN"] {
                let actual = balances
                    .get(&(asset.into(), "USER_WITHDRAWAL_HOLD".into()))
                    .copied()
                    .unwrap_or_default();
                if actual
                    != hold_totals
                        .remove(&(identity.clone(), asset.into()))
                        .unwrap_or_default()
                {
                    return Err(V71CheckpointError::Invalid);
                }
            }
        }
        if !hold_totals.is_empty() {
            return Err(V71CheckpointError::Invalid);
        }

        let mut pending_wallets = BTreeSet::new();
        for (operation, pending) in &self.conditional_usdc_deposits {
            let value = amount(&pending.amount_atomic).map_err(|_| V71CheckpointError::Invalid)?;
            if !valid_bus_withdrawal_id(operation)
                || value < 5_000_000
                || value.to_string() != pending.amount_atomic
                || !valid_bus_deposit_reference(&pending.boarding_reference)
                || !self
                    .subject_identities
                    .get(&pending.account_id)
                    .is_some_and(|identities| identities.contains(&pending.identity_commitment))
                || !self
                    .subject_wallets
                    .get(&pending.account_id)
                    .is_some_and(|wallets| wallets.contains(&pending.wallet_address))
                || !self
                    .credited_custody_references
                    .contains(&pending.boarding_reference)
                || !self
                    .credited_custody_references
                    .contains(&format!("arbitrum-usdc-bus-operation:{operation}"))
                || !pending_wallets.insert(pending.wallet_address.clone())
            {
                return Err(V71CheckpointError::Invalid);
            }
        }
        Ok(())
    }

    fn apply(self, runtime: &mut DirectRuntime) {
        runtime.balances = self.balances;
        runtime.subject_identities = self.subject_identities;
        runtime.subject_wallets = self.subject_wallets;
        runtime.markets = self.markets;
        runtime.books = self.books;
        runtime.orders = self.orders;
        runtime.positions = self.positions;
        runtime.position_holds = self.position_holds;
        runtime.position_cost_basis = self.position_cost_basis;
        runtime.market_collateral = self.market_collateral;
        runtime.resolved_markets = self.resolved_markets;
        runtime.fee_revenue_atomic = self.fee_revenue_atomic;
        runtime.zen_fee_revenue_atomic = self.zen_fee_revenue_atomic;
        runtime.zen_rounding_reserve_atomic = self.zen_rounding_reserve_atomic;
        runtime.rounding_reserve_atomic = self.rounding_reserve_atomic;
        runtime.credited_custody_references = self.credited_custody_references;
        runtime.usdc_bus_withdrawals = self.usdc_bus_withdrawals;
        runtime.conditional_usdc_deposits = self.conditional_usdc_deposits;
        runtime.requests.clear();
    }
}

fn associated_data(
    writer_epoch: &str,
    sequence: u64,
    record_hash: &str,
    transition_root: &str,
    request_index_root: &str,
    financial_state_root: &str,
) -> Result<Vec<u8>, V71CheckpointError> {
    serde_cbor::to_vec(&CheckpointAssociatedData {
        protocol: DIRECT_V71_CHECKPOINT_PROTOCOL,
        epoch_id: EPOCH_ID,
        writer_epoch,
        sequence,
        record_hash,
        transition_root,
        request_index_root,
        financial_state_root,
    })
    .map_err(|_| V71CheckpointError::Invalid)
}

fn checkpoint_nonce(
    state_key: &[u8],
    associated_data: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, V71CheckpointError> {
    if state_key.len() != 32 || associated_data.is_empty() || plaintext.is_empty() {
        return Err(V71CheckpointError::Invalid);
    }
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(state_key)
        .map_err(|_| V71CheckpointError::Invalid)?;
    mac.update(CHECKPOINT_NONCE_DOMAIN);
    mac.update(&(associated_data.len() as u64).to_be_bytes());
    mac.update(associated_data);
    mac.update(&(plaintext.len() as u64).to_be_bytes());
    mac.update(plaintext);
    Ok(mac.finalize().into_bytes()[..12].to_vec())
}

fn sign(seed: &[u8], bytes: &[u8]) -> Result<String, V71CheckpointError> {
    let seed: [u8; 32] = seed.try_into().map_err(|_| V71CheckpointError::Invalid)?;
    Ok(hex::encode(
        SigningKey::from_bytes(&seed).sign(bytes).to_bytes(),
    ))
}

fn verify_signature(key: &[u8], bytes: &[u8], signature: &str) -> Result<(), V71CheckpointError> {
    let key: [u8; 32] = key
        .try_into()
        .map_err(|_| V71CheckpointError::Authentication)?;
    let signature: [u8; 64] = hex::decode(signature)
        .map_err(|_| V71CheckpointError::Authentication)?
        .try_into()
        .map_err(|_| V71CheckpointError::Authentication)?;
    VerifyingKey::from_bytes(&key)
        .map_err(|_| V71CheckpointError::Authentication)?
        .verify(bytes, &Signature::from_bytes(&signature))
        .map_err(|_| V71CheckpointError::Authentication)
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
