//! Immutable recovery binding for an irreversible custody effect.
//!
//! This module deliberately has no command status, queue, lease, retry record,
//! scheduler, or coordinator.  An intent is a write-once cryptographic binding
//! that exists before a provider call.  Recovery derives its sole action from
//! the immutable intent plus the provider's current observation; it never uses
//! a database command record as financial authority.

use crate::{sha256, RuntimeError, EPOCH_ID, TRANSACTION_MODEL};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
};

pub const EXTERNAL_EFFECT_INTENT_PROTOCOL_VERSION: &str = "layrs.external-effect-intent.v1";
/// Privy's documented idempotency guarantee is 24 hours.  Keep a one-hour
/// safety margin so recovery never rebroadcasts after that guarantee expires.
pub const MAX_PROVIDER_IDEMPOTENCY_WINDOW_SECONDS: u64 = 23 * 60 * 60;

/// Immutable Relay quote/route inputs for a Base-origin cross-chain payout.
/// The BFF obtains the one-time route, but PostgreSQL is not relied on during
/// custody or recovery: every field required to validate Relay's terminal
/// destination result is copied into this hash-bound value before the Base
/// pool transfer can be submitted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RelayWithdrawalBinding {
    pub route_id: String,
    pub request_id: String,
    pub deposit_address: String,
    pub destination_chain_id: u64,
    pub destination_currency: String,
    pub recipient: String,
    pub quoted_destination_amount_atomic: String,
    pub minimum_destination_amount_atomic: String,
    pub quote_payload_sha256: String,
    pub expires_at_unix: u64,
}

impl RelayWithdrawalBinding {
    pub fn verify(&self, source_amount_atomic: &str) -> Result<(), RuntimeError> {
        let quoted = positive_atomic(&self.quoted_destination_amount_atomic)
            .ok_or(RuntimeError::StateArtifact)?;
        let minimum = positive_atomic(&self.minimum_destination_amount_atomic)
            .ok_or(RuntimeError::StateArtifact)?;
        if positive_atomic(source_amount_atomic).is_none()
            || self.route_id.len() != 36
            || !self
                .route_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
            || !valid_relay_request_id(&self.request_id)
            || !valid_evm_address(&self.deposit_address)
            || !valid_relay_destination(
                self.destination_chain_id,
                &self.destination_currency,
                &self.recipient,
            )
            || minimum > quoted
            || self.quote_payload_sha256.len() != 64
            || !self
                .quote_payload_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || self.expires_at_unix == 0
        {
            return Err(RuntimeError::StateArtifact);
        }
        Ok(())
    }

    pub fn binding_hash(&self) -> String {
        sha256(
            &[
                b"layrs.relay-withdrawal-binding.v1\0".as_slice(),
                serde_cbor::to_vec(self)
                    .expect("Relay withdrawal binding serializes")
                    .as_slice(),
            ]
            .concat(),
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExternalEffectIntent {
    pub protocol_version: String,
    pub intent_hash: String,
    pub epoch_id: String,
    pub runtime: String,
    pub prior_state_hash: String,
    pub request_id: String,
    pub request_hash: String,
    pub account_id: String,
    pub identity_commitment: String,
    pub chain: String,
    pub asset: String,
    pub destination: String,
    pub amount_atomic: String,
    /// Existing operational wallet identity, not a newly created signer.
    pub provider_wallet_id: String,
    pub custody_target: String,
    pub transaction_nonce: String,
    pub gas_limit: String,
    pub max_fee_per_gas: String,
    pub max_priority_fee_per_gas: String,
    /// Stable provider lookup key.  It is deterministic, <=64 ASCII chars,
    /// and is also used as the provider idempotency key.
    pub external_effect_reference: String,
    pub provider_idempotency_key: String,
    /// No recovery may submit after this deadline.  It is intentionally
    /// bounded by the provider's documented idempotency window.
    pub submit_not_after_unix: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<RelayWithdrawalBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zen_destination_chain: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UnsignedIntent<'a> {
    protocol_version: &'a str,
    epoch_id: &'a str,
    runtime: &'a str,
    prior_state_hash: &'a str,
    request_id: &'a str,
    request_hash: &'a str,
    account_id: &'a str,
    identity_commitment: &'a str,
    chain: &'a str,
    asset: &'a str,
    destination: &'a str,
    amount_atomic: &'a str,
    provider_wallet_id: &'a str,
    custody_target: &'a str,
    transaction_nonce: &'a str,
    gas_limit: &'a str,
    max_fee_per_gas: &'a str,
    max_priority_fee_per_gas: &'a str,
    submit_not_after_unix: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    relay: Option<&'a RelayWithdrawalBinding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    zen_destination_chain: Option<&'a String>,
}

impl ExternalEffectIntent {
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        prior_state_hash: String,
        request_id: String,
        request_hash: String,
        account_id: String,
        identity_commitment: String,
        chain: String,
        asset: String,
        destination: String,
        amount_atomic: String,
        provider_wallet_id: String,
        custody_target: String,
        transaction_nonce: String,
        gas_limit: String,
        max_fee_per_gas: String,
        max_priority_fee_per_gas: String,
        now_unix: u64,
    ) -> Result<Self, RuntimeError> {
        Self::create_bound(
            prior_state_hash,
            request_id,
            request_hash,
            account_id,
            identity_commitment,
            chain,
            asset,
            destination,
            amount_atomic,
            provider_wallet_id,
            custody_target,
            transaction_nonce,
            gas_limit,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            now_unix,
            None,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_relay_withdrawal(
        prior_state_hash: String,
        request_id: String,
        request_hash: String,
        account_id: String,
        identity_commitment: String,
        amount_atomic: String,
        provider_wallet_id: String,
        custody_target: String,
        transaction_nonce: String,
        gas_limit: String,
        max_fee_per_gas: String,
        max_priority_fee_per_gas: String,
        now_unix: u64,
        relay: RelayWithdrawalBinding,
    ) -> Result<Self, RuntimeError> {
        relay.verify(&amount_atomic)?;
        Self::create_bound(
            prior_state_hash,
            request_id,
            request_hash,
            account_id,
            identity_commitment,
            "base".into(),
            "USDC".into(),
            relay.deposit_address.clone(),
            amount_atomic,
            provider_wallet_id,
            custody_target,
            transaction_nonce,
            gas_limit,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            now_unix,
            Some(relay),
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_zen_withdrawal(
        prior_state_hash: String, request_id: String, request_hash: String, account_id: String,
        identity_commitment: String, destination_chain: String, destination: String, amount_atomic: String,
        provider_wallet_id: String, custody_target: String, transaction_nonce: String, gas_limit: String,
        max_fee_per_gas: String, max_priority_fee_per_gas: String, now_unix: u64,
    ) -> Result<Self, RuntimeError> {
        Self::create_bound(prior_state_hash, request_id, request_hash, account_id, identity_commitment,
            "horizen".into(), "ZEN".into(), destination, amount_atomic, provider_wallet_id, custody_target,
            transaction_nonce, gas_limit, max_fee_per_gas, max_priority_fee_per_gas, now_unix, None, Some(destination_chain))
    }

    #[allow(clippy::too_many_arguments)]
    fn create_bound(
        prior_state_hash: String,
        request_id: String,
        request_hash: String,
        account_id: String,
        identity_commitment: String,
        chain: String,
        asset: String,
        destination: String,
        amount_atomic: String,
        provider_wallet_id: String,
        custody_target: String,
        transaction_nonce: String,
        gas_limit: String,
        max_fee_per_gas: String,
        max_priority_fee_per_gas: String,
        now_unix: u64,
        relay: Option<RelayWithdrawalBinding>,
        zen_destination_chain: Option<String>,
    ) -> Result<Self, RuntimeError> {
        if zen_destination_chain.as_ref().is_some_and(|destination_chain|
            chain != "horizen" || asset != "ZEN" || relay.is_some()
            || !matches!(destination_chain.as_str(), "base" | "horizen")
            || (destination_chain == "base" && amount_atomic.parse::<u128>().map_or(true, |value| value % 1_000_000_000_000 != 0))) {
            return Err(RuntimeError::InvalidRequest);
        }
        if prior_state_hash.len() != 64
            || request_hash.len() != 64
            || request_id.is_empty()
            || account_id.is_empty()
            || identity_commitment.is_empty()
            || provider_wallet_id.is_empty()
            || custody_target.len() != 42
            || !custody_target.starts_with("0x")
            || !matches!(chain.as_str(), "base" | "horizen")
            || !matches!(asset.as_str(), "USDC" | "ZEN")
            || destination.len() != 42
            || !destination.starts_with("0x")
            || amount_atomic
                .parse::<u128>()
                .ok()
                .filter(|value| *value > 0)
                .is_none()
            || transaction_nonce.parse::<u128>().is_err()
            || gas_limit
                .parse::<u128>()
                .ok()
                .filter(|value| *value > 0)
                .is_none()
            || max_fee_per_gas
                .parse::<u128>()
                .ok()
                .filter(|value| *value > 0)
                .is_none()
            || max_priority_fee_per_gas
                .parse::<u128>()
                .ok()
                .filter(|value| *value > 0)
                .is_none()
        {
            return Err(RuntimeError::InvalidRequest);
        }
        let submit_not_after_unix = now_unix
            .checked_add(MAX_PROVIDER_IDEMPOTENCY_WINDOW_SECONDS)
            .ok_or(RuntimeError::InvalidRequest)?
            .min(
                relay
                    .as_ref()
                    .map_or(u64::MAX, |binding| binding.expires_at_unix),
            );
        if submit_not_after_unix <= now_unix {
            return Err(RuntimeError::InvalidRequest);
        }
        let normalized_destination = destination.to_ascii_lowercase();
        let external_effect_reference = match relay.as_ref() {
            Some(binding) => relay_reference_for(
                &prior_state_hash,
                &request_id,
                &account_id,
                &identity_commitment,
                &amount_atomic,
                &provider_wallet_id,
                binding,
            ),
            None => reference_for(
                &prior_state_hash,
                &request_id,
                &account_id,
                &identity_commitment,
                &zen_destination_chain.as_ref().map_or_else(|| chain.clone(), |destination_chain| format!("horizen-zen-{destination_chain}")),
                &asset,
                &normalized_destination,
                &amount_atomic,
                &provider_wallet_id,
            ),
        };
        let unsigned = UnsignedIntent {
            protocol_version: EXTERNAL_EFFECT_INTENT_PROTOCOL_VERSION,
            epoch_id: EPOCH_ID,
            runtime: TRANSACTION_MODEL,
            prior_state_hash: &prior_state_hash,
            request_id: &request_id,
            request_hash: &request_hash,
            account_id: &account_id,
            identity_commitment: &identity_commitment,
            chain: &chain,
            asset: &asset,
            destination: &normalized_destination,
            amount_atomic: &amount_atomic,
            provider_wallet_id: &provider_wallet_id,
            custody_target: &custody_target.to_ascii_lowercase(),
            transaction_nonce: &transaction_nonce,
            gas_limit: &gas_limit,
            max_fee_per_gas: &max_fee_per_gas,
            max_priority_fee_per_gas: &max_priority_fee_per_gas,
            submit_not_after_unix,
            relay: relay.as_ref(),
            zen_destination_chain: zen_destination_chain.as_ref(),
        };
        let intent_hash = intent_hash(&unsigned)?;
        Ok(Self {
            protocol_version: EXTERNAL_EFFECT_INTENT_PROTOCOL_VERSION.into(),
            intent_hash,
            epoch_id: EPOCH_ID.into(),
            runtime: TRANSACTION_MODEL.into(),
            prior_state_hash,
            request_id,
            request_hash,
            account_id,
            identity_commitment,
            chain,
            asset,
            destination: normalized_destination,
            amount_atomic,
            provider_wallet_id,
            custody_target: custody_target.to_ascii_lowercase(),
            transaction_nonce,
            gas_limit,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            provider_idempotency_key: external_effect_reference.clone(),
            external_effect_reference,
            submit_not_after_unix,
            relay,
            zen_destination_chain,
        })
    }

    pub fn verify(&self) -> Result<(), RuntimeError> {
        if self.protocol_version != EXTERNAL_EFFECT_INTENT_PROTOCOL_VERSION
            || self.epoch_id != EPOCH_ID
            || self.runtime != TRANSACTION_MODEL
            || self.external_effect_reference.len() != 64
            || self.provider_idempotency_key != self.external_effect_reference
            || self.custody_target.len() != 42
            || !self.custody_target.starts_with("0x")
            || self.transaction_nonce.parse::<u128>().is_err()
            || self
                .gas_limit
                .parse::<u128>()
                .ok()
                .filter(|value| *value > 0)
                .is_none()
            || self
                .max_fee_per_gas
                .parse::<u128>()
                .ok()
                .filter(|value| *value > 0)
                .is_none()
            || self
                .max_priority_fee_per_gas
                .parse::<u128>()
                .ok()
                .filter(|value| *value > 0)
                .is_none()
            || !self.external_effect_reference.starts_with("lei-")
            || !self.external_effect_reference[4..]
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(RuntimeError::StateArtifact);
        }
        let unsigned = UnsignedIntent {
            protocol_version: &self.protocol_version,
            epoch_id: &self.epoch_id,
            runtime: &self.runtime,
            prior_state_hash: &self.prior_state_hash,
            request_id: &self.request_id,
            request_hash: &self.request_hash,
            account_id: &self.account_id,
            identity_commitment: &self.identity_commitment,
            chain: &self.chain,
            asset: &self.asset,
            destination: &self.destination,
            amount_atomic: &self.amount_atomic,
            provider_wallet_id: &self.provider_wallet_id,
            custody_target: &self.custody_target,
            transaction_nonce: &self.transaction_nonce,
            gas_limit: &self.gas_limit,
            max_fee_per_gas: &self.max_fee_per_gas,
            max_priority_fee_per_gas: &self.max_priority_fee_per_gas,
            submit_not_after_unix: self.submit_not_after_unix,
            relay: self.relay.as_ref(),
            zen_destination_chain: self.zen_destination_chain.as_ref(),
        };
        if let Some(binding) = &self.relay {
            binding.verify(&self.amount_atomic)?;
            if self.destination != binding.deposit_address.to_ascii_lowercase()
                || self.submit_not_after_unix > binding.expires_at_unix
            {
                return Err(RuntimeError::StateArtifact);
            }
        }
        if self.zen_destination_chain.as_ref().is_some_and(|destination_chain|
            self.chain != "horizen" || self.asset != "ZEN" || self.relay.is_some()
            || !matches!(destination_chain.as_str(), "base" | "horizen")
            || (destination_chain == "base" && self.amount_atomic.parse::<u128>().map_or(true, |value| value % 1_000_000_000_000 != 0))) {
            return Err(RuntimeError::StateArtifact);
        }
        let expected_reference = match self.relay.as_ref() {
            Some(binding) => relay_reference_for(
                &self.prior_state_hash,
                &self.request_id,
                &self.account_id,
                &self.identity_commitment,
                &self.amount_atomic,
                &self.provider_wallet_id,
                binding,
            ),
            None => reference_for(
                &self.prior_state_hash,
                &self.request_id,
                &self.account_id,
                &self.identity_commitment,
                &self.zen_destination_chain.as_ref().map_or_else(|| self.chain.clone(), |destination_chain| format!("horizen-zen-{destination_chain}")),
                &self.asset,
                &self.destination,
                &self.amount_atomic,
                &self.provider_wallet_id,
            ),
        };
        if self.intent_hash != intent_hash(&unsigned)?
            || self.external_effect_reference != expected_reference
        {
            return Err(RuntimeError::StateArtifact);
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
pub fn relay_reference_for(
    prior_state_hash: &str,
    request_id: &str,
    account_id: &str,
    identity_commitment: &str,
    amount_atomic: &str,
    provider_wallet_id: &str,
    relay: &RelayWithdrawalBinding,
) -> String {
    let bytes = serde_cbor::to_vec(&(
        EXTERNAL_EFFECT_INTENT_PROTOCOL_VERSION,
        EPOCH_ID,
        TRANSACTION_MODEL,
        prior_state_hash,
        request_id,
        account_id,
        identity_commitment,
        "base",
        "USDC",
        amount_atomic,
        provider_wallet_id,
        relay.binding_hash(),
    ))
    .expect("Relay external-effect reference serializes");
    format!(
        "lei-{}",
        &sha256(&[b"layrs.external-effect-reference.v1\0", bytes.as_slice()].concat())[..60]
    )
}

pub fn relay_result_hash(
    intent: &ExternalEffectIntent,
    intake_transaction_hash: &str,
    destination_transaction_hash: &str,
    destination_amount_atomic: &str,
) -> Option<String> {
    let relay = intent.relay.as_ref()?;
    Some(relay_terminal_result_hash(
        relay,
        &intent.external_effect_reference,
        intake_transaction_hash,
        destination_transaction_hash,
        destination_amount_atomic,
    ))
}

pub fn relay_terminal_result_hash(
    relay: &RelayWithdrawalBinding,
    external_effect_reference: &str,
    intake_transaction_hash: &str,
    destination_transaction_hash: &str,
    destination_amount_atomic: &str,
) -> String {
    sha256(
        &serde_cbor::to_vec(&(
            "layrs.relay-destination-result.v1",
            external_effect_reference,
            relay.request_id.as_str(),
            relay.destination_chain_id,
            relay.destination_currency.as_str(),
            relay.recipient.as_str(),
            intake_transaction_hash,
            destination_transaction_hash,
            destination_amount_atomic,
        ))
        .expect("Relay destination result serializes"),
    )
}

pub fn relay_reverted_result_hash(
    relay: &RelayWithdrawalBinding,
    external_effect_reference: &str,
    intake_transaction_hash: &str,
    terminal_status: &str,
) -> String {
    sha256(
        &serde_cbor::to_vec(&(
            "layrs.relay-reverted-result.v1",
            external_effect_reference,
            relay.request_id.as_str(),
            relay.destination_chain_id,
            relay.destination_currency.as_str(),
            relay.recipient.as_str(),
            intake_transaction_hash,
            terminal_status,
        ))
        .expect("Relay reverted result serializes"),
    )
}

fn positive_atomic(value: &str) -> Option<u128> {
    value.parse::<u128>().ok().filter(|amount| *amount > 0)
}

fn valid_evm_address(value: &str) -> bool {
    value.len() == 42
        && value.starts_with("0x")
        && value[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
        && !value[2..].bytes().all(|byte| byte == b'0')
}

fn valid_relay_request_id(value: &str) -> bool {
    value.len() == 66
        && value.starts_with("0x")
        && value[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_relay_destination(chain_id: u64, currency: &str, recipient: &str) -> bool {
    let evm_currency = valid_evm_address(currency);
    match chain_id {
        10 | 137 | 143 | 4_663 | 42_161 => evm_currency && valid_evm_address(recipient),
        792_703_809 => {
            currency.len() >= 32
                && currency.len() <= 44
                && recipient.len() >= 32
                && recipient.len() <= 44
                && currency.bytes().all(is_base58)
                && recipient.bytes().all(is_base58)
        }
        _ => false,
    }
}

pub(crate) fn is_base58(byte: u8) -> bool {
    matches!(byte,
        b'1'..=b'9' | b'A'..=b'H' | b'J'..=b'N' | b'P'..=b'Z'
        | b'a'..=b'k' | b'm'..=b'z')
}

/// The provider reference must exist before a final transaction hash exists.
/// It intentionally binds only immutable request inputs; the full intent hash
/// subsequently binds this reference and the final direct-request hash.
pub fn reference_for(
    prior_state_hash: &str,
    request_id: &str,
    account_id: &str,
    identity_commitment: &str,
    chain: &str,
    asset: &str,
    destination: &str,
    amount_atomic: &str,
    provider_wallet_id: &str,
) -> String {
    let bytes = serde_cbor::to_vec(&(
        EXTERNAL_EFFECT_INTENT_PROTOCOL_VERSION,
        EPOCH_ID,
        TRANSACTION_MODEL,
        prior_state_hash,
        request_id,
        account_id,
        identity_commitment,
        chain,
        asset,
        destination.to_ascii_lowercase(),
        amount_atomic,
        provider_wallet_id,
    ))
    .expect("external-effect reference serializes");
    format!(
        "lei-{}",
        &sha256(&[b"layrs.external-effect-reference.v1\0", bytes.as_slice()].concat())[..60]
    )
}

fn intent_hash(unsigned: &UnsignedIntent<'_>) -> Result<String, RuntimeError> {
    let bytes = serde_cbor::to_vec(unsigned).map_err(|_| RuntimeError::StateArtifact)?;
    Ok(sha256(
        &[b"layrs.external-effect-intent.v1\0", bytes.as_slice()].concat(),
    ))
}

/// An external observation is not a private financial state.  It is a narrow
/// transcription of the provider/RPC result bound to the intent's reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExternalEffectObservation {
    NotFound,
    Pending {
        provider_transaction_id: String,
    },
    Finalized {
        provider_transaction_id: String,
        transaction_hash: String,
    },
    Reverted {
        provider_transaction_id: String,
        transaction_hash: String,
    },
    /// Relay's authoritative terminal destination-chain result.  The Base
    /// transaction is only the intake leg and is deliberately carried as
    /// evidence rather than treated as private-ledger finality.
    RelayFinalized {
        provider_transaction_id: String,
        intake_transaction_hash: String,
        relay_request_id: String,
        destination_transaction_hash: String,
        destination_amount_atomic: String,
        result_hash: String,
    },
    /// Relay has terminally failed/refunded the route.  Recording this result
    /// changes no customer balance; it only closes the immutable intent.
    RelayReverted {
        provider_transaction_id: String,
        intake_transaction_hash: String,
        relay_request_id: String,
        terminal_status: String,
        result_hash: String,
    },
    Conflict,
}

/// The only permitted recovery decisions.  `SubmitWithStableReference` is
/// allowed only inside the provider-guaranteed idempotency window; otherwise
/// the runtime must fail closed and never rebroadcast.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExternalEffectRecovery {
    SubmitWithStableReference,
    AwaitExternalFinality,
    BindFinalized {
        provider_transaction_id: String,
        transaction_hash: String,
    },
    BindReverted {
        provider_transaction_id: String,
        transaction_hash: String,
    },
    BindRelayFinalized {
        provider_transaction_id: String,
        intake_transaction_hash: String,
        relay_request_id: String,
        destination_transaction_hash: String,
        destination_amount_atomic: String,
        result_hash: String,
    },
    BindRelayReverted {
        provider_transaction_id: String,
        intake_transaction_hash: String,
        relay_request_id: String,
        terminal_status: String,
        result_hash: String,
    },
    FailClosed,
}

impl ExternalEffectIntent {
    pub fn recovery_action(
        &self,
        now_unix: u64,
        observation: ExternalEffectObservation,
    ) -> ExternalEffectRecovery {
        match observation {
            ExternalEffectObservation::NotFound if now_unix <= self.submit_not_after_unix => {
                ExternalEffectRecovery::SubmitWithStableReference
            }
            ExternalEffectObservation::NotFound | ExternalEffectObservation::Conflict => {
                ExternalEffectRecovery::FailClosed
            }
            ExternalEffectObservation::Pending { .. } => {
                ExternalEffectRecovery::AwaitExternalFinality
            }
            ExternalEffectObservation::Finalized {
                provider_transaction_id,
                transaction_hash,
            } => ExternalEffectRecovery::BindFinalized {
                provider_transaction_id,
                transaction_hash,
            },
            ExternalEffectObservation::Reverted {
                provider_transaction_id,
                transaction_hash,
            } => ExternalEffectRecovery::BindReverted {
                provider_transaction_id,
                transaction_hash,
            },
            ExternalEffectObservation::RelayFinalized {
                provider_transaction_id,
                intake_transaction_hash,
                relay_request_id,
                destination_transaction_hash,
                destination_amount_atomic,
                result_hash,
            } => ExternalEffectRecovery::BindRelayFinalized {
                provider_transaction_id,
                intake_transaction_hash,
                relay_request_id,
                destination_transaction_hash,
                destination_amount_atomic,
                result_hash,
            },
            ExternalEffectObservation::RelayReverted {
                provider_transaction_id,
                intake_transaction_hash,
                relay_request_id,
                terminal_status,
                result_hash,
            } => ExternalEffectRecovery::BindRelayReverted {
                provider_transaction_id,
                intake_transaction_hash,
                relay_request_id,
                terminal_status,
                result_hash,
            },
        }
    }
}

pub trait ImmutableExternalEffectIntentStore {
    fn put_if_absent_readback(
        &self,
        intent: &ExternalEffectIntent,
    ) -> Result<ExternalEffectIntent, RuntimeError>;
    fn load_all(&self) -> Result<Vec<ExternalEffectIntent>, RuntimeError>;
}

/// Same encrypted-archive write-once contract as state artifacts.  Intent
/// files are immutable evidence only; they are not a job table or state queue.
#[derive(Debug, Clone)]
pub struct FilesystemImmutableIntentStore {
    root: PathBuf,
}

impl FilesystemImmutableIntentStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }
    fn path_for(&self, intent: &ExternalEffectIntent) -> PathBuf {
        self.root
            .join(format!("{}.intent.cbor", intent.intent_hash))
    }
}

impl ImmutableExternalEffectIntentStore for FilesystemImmutableIntentStore {
    fn put_if_absent_readback(
        &self,
        intent: &ExternalEffectIntent,
    ) -> Result<ExternalEffectIntent, RuntimeError> {
        intent.verify()?;
        fs::create_dir_all(&self.root).map_err(|_| RuntimeError::StatePersistence)?;
        let bytes = serde_cbor::to_vec(intent).map_err(|_| RuntimeError::StatePersistence)?;
        let path = self.path_for(intent);
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => file
                .write_all(&bytes)
                .and_then(|_| file.sync_all())
                .map_err(|_| RuntimeError::StatePersistence)?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(RuntimeError::StatePersistence),
        }
        let restored: ExternalEffectIntent =
            serde_cbor::from_slice(&fs::read(&path).map_err(|_| RuntimeError::StatePersistence)?)
                .map_err(|_| RuntimeError::StatePersistence)?;
        if restored != *intent {
            return Err(RuntimeError::StatePersistence);
        }
        restored.verify()?;
        Ok(restored)
    }

    fn load_all(&self) -> Result<Vec<ExternalEffectIntent>, RuntimeError> {
        let entries = match fs::read_dir(&self.root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(_) => return Err(RuntimeError::StatePersistence),
        };
        let mut intents = BTreeMap::new();
        for entry in entries {
            let entry = entry.map_err(|_| RuntimeError::StatePersistence)?;
            if !entry
                .file_name()
                .to_string_lossy()
                .ends_with(".intent.cbor")
            {
                continue;
            }
            let intent: ExternalEffectIntent = serde_cbor::from_slice(
                &fs::read(entry.path()).map_err(|_| RuntimeError::StatePersistence)?,
            )
            .map_err(|_| RuntimeError::StatePersistence)?;
            intent.verify()?;
            if entry.path() != self.path_for(&intent)
                || intents.insert(intent.intent_hash.clone(), intent).is_some()
            {
                return Err(RuntimeError::StatePersistence);
            }
        }
        Ok(intents.into_values().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn intent(now: u64) -> ExternalEffectIntent {
        ExternalEffectIntent::create(
            "a".repeat(64),
            "request-1".into(),
            "b".repeat(64),
            "subject".into(),
            "identity".into(),
            "base".into(),
            "USDC".into(),
            "0xCCB96357dEB4cbF0808208d55916774f0B51a908".into(),
            "1000000".into(),
            "existing-base-pool-wallet".into(),
            "0x1111111111111111111111111111111111111111".into(),
            "7".into(),
            "180000".into(),
            "2000000000".into(),
            "1000000000".into(),
            now,
        )
        .unwrap()
    }

    fn relay_intent(now: u64) -> ExternalEffectIntent {
        ExternalEffectIntent::create_relay_withdrawal(
            "a".repeat(64),
            "relay-withdrawal:11111111-2222-4333-8444-555555555555".into(),
            "b".repeat(64),
            "subject".into(),
            "identity".into(),
            "5000000".into(),
            "existing-base-pool-wallet".into(),
            "0x1111111111111111111111111111111111111111".into(),
            "7".into(),
            "180000".into(),
            "2000000000".into(),
            "1000000000".into(),
            now,
            RelayWithdrawalBinding {
                route_id: "11111111-2222-4333-8444-555555555555".into(),
                request_id: format!("0x{}", "aa".repeat(32)),
                deposit_address: "0x2222222222222222222222222222222222222222".into(),
                destination_chain_id: 42_161,
                destination_currency: "0xaf88d065e77c8cc2239327c5edb3a432268e5831".into(),
                recipient: "0x3333333333333333333333333333333333333333".into(),
                quoted_destination_amount_atomic: "4990000".into(),
                minimum_destination_amount_atomic: "4980000".into(),
                quote_payload_sha256: "44".repeat(32),
                expires_at_unix: now + 600,
            },
        )
        .unwrap()
    }

    #[test]
    fn immutable_intent_is_hash_bound_write_once_and_readback_verified() {
        let root = std::env::temp_dir().join(format!(
            "layrs-intent-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let store = FilesystemImmutableIntentStore::new(&root);
        let value = intent(100);
        assert_eq!(store.put_if_absent_readback(&value).unwrap(), value);
        assert_eq!(store.put_if_absent_readback(&value).unwrap(), value);
        assert_eq!(store.load_all().unwrap(), vec![value]);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn transaction_parameters_are_immutable_before_provider_submission() {
        let value = intent(100);
        assert!(value.verify().is_ok());
        let mut altered = value.clone();
        altered.max_fee_per_gas = "2000000001".into();
        assert_eq!(altered.verify(), Err(RuntimeError::StateArtifact));
    }

    #[test]
    fn recovery_never_rebroadcasts_after_provider_idempotency_window() {
        let value = intent(100);
        assert_eq!(
            value.recovery_action(100, ExternalEffectObservation::NotFound),
            ExternalEffectRecovery::SubmitWithStableReference
        );
        assert_eq!(
            value.recovery_action(
                value.submit_not_after_unix + 1,
                ExternalEffectObservation::NotFound
            ),
            ExternalEffectRecovery::FailClosed
        );
    }

    #[test]
    fn recovery_binds_only_exact_terminal_external_outcomes() {
        let value = intent(100);
        assert_eq!(
            value.recovery_action(
                101,
                ExternalEffectObservation::Pending {
                    provider_transaction_id: "provider-1".into()
                }
            ),
            ExternalEffectRecovery::AwaitExternalFinality
        );
        assert_eq!(
            value.recovery_action(101, ExternalEffectObservation::Conflict),
            ExternalEffectRecovery::FailClosed
        );
        assert!(matches!(
            value.recovery_action(
                101,
                ExternalEffectObservation::Finalized {
                    provider_transaction_id: "provider-1".into(),
                    transaction_hash: "0xabc".into()
                }
            ),
            ExternalEffectRecovery::BindFinalized { .. }
        ));
        assert!(matches!(
            value.recovery_action(
                101,
                ExternalEffectObservation::Reverted {
                    provider_transaction_id: "provider-1".into(),
                    transaction_hash: "0xabc".into()
                }
            ),
            ExternalEffectRecovery::BindReverted { .. }
        ));
    }

    #[derive(Default)]
    struct ProviderFixture {
        records: BTreeMap<String, ExternalEffectObservation>,
        submitted_references: BTreeSet<String>,
        payouts: usize,
    }
    impl ProviderFixture {
        fn observe(&self, intent: &ExternalEffectIntent) -> ExternalEffectObservation {
            self.records
                .get(&intent.external_effect_reference)
                .cloned()
                .unwrap_or(ExternalEffectObservation::NotFound)
        }
        fn submit_once(&mut self, intent: &ExternalEffectIntent) {
            // Models the provider-owned idempotency/reference primitive: every
            // duplicate submission of the same immutable reference resolves to
            // the original provider transaction, never a second payout.
            if self
                .submitted_references
                .insert(intent.external_effect_reference.clone())
            {
                self.payouts += 1;
            }
            self.records
                .entry(intent.external_effect_reference.clone())
                .or_insert_with(|| ExternalEffectObservation::Pending {
                    provider_transaction_id: "provider-1".into(),
                });
        }
        fn resume(&mut self, intent: &ExternalEffectIntent, now: u64) -> ExternalEffectRecovery {
            let decision = intent.recovery_action(now, self.observe(intent));
            if decision == ExternalEffectRecovery::SubmitWithStableReference {
                self.submit_once(intent);
                return ExternalEffectRecovery::AwaitExternalFinality;
            }
            decision
        }
    }

    #[test]
    fn crash_windows_preserve_one_intent_one_payout_one_terminal_binding() {
        let value = intent(100);
        // A. Before persistence there is no intent/reference and therefore no
        // provider call to make or recover.
        let empty = ProviderFixture::default();
        assert_eq!(empty.payouts, 0);

        // B. Persisted before broadcast: restart submits once with the fixed
        // reference. C/D. A broadcast whose response is lost is retried with
        // the same reference; provider idempotency prevents a second payout.
        let mut provider = ProviderFixture::default();
        assert_eq!(
            provider.resume(&value, 101),
            ExternalEffectRecovery::AwaitExternalFinality
        );
        assert_eq!(provider.payouts, 1);
        provider.records.remove(&value.external_effect_reference); // lookup lag after response loss
        assert_eq!(
            provider.resume(&value, 102),
            ExternalEffectRecovery::AwaitExternalFinality
        );
        assert_eq!(provider.payouts, 1);

        // E/F/G. Pending blocks financial service; finalized/reverted bind
        // exactly one terminal outcome to this same immutable intent.
        provider.records.insert(
            value.external_effect_reference.clone(),
            ExternalEffectObservation::Pending {
                provider_transaction_id: "provider-1".into(),
            },
        );
        assert_eq!(
            provider.resume(&value, 103),
            ExternalEffectRecovery::AwaitExternalFinality
        );
        provider.records.insert(
            value.external_effect_reference.clone(),
            ExternalEffectObservation::Finalized {
                provider_transaction_id: "provider-1".into(),
                transaction_hash: "0x11".into(),
            },
        );
        assert!(matches!(
            provider.resume(&value, 104),
            ExternalEffectRecovery::BindFinalized { .. }
        ));
        provider.records.insert(
            value.external_effect_reference.clone(),
            ExternalEffectObservation::Reverted {
                provider_transaction_id: "provider-1".into(),
                transaction_hash: "0x11".into(),
            },
        );
        assert!(matches!(
            provider.resume(&value, 105),
            ExternalEffectRecovery::BindReverted { .. }
        ));

        // H/I. Finalized retry is a re-bind, never a payout; a timeout beyond
        // Privy's idempotency guarantee fails closed rather than rebroadcasts.
        provider.records.insert(
            value.external_effect_reference.clone(),
            ExternalEffectObservation::Finalized {
                provider_transaction_id: "provider-1".into(),
                transaction_hash: "0x11".into(),
            },
        );
        assert!(matches!(
            provider.resume(&value, 106),
            ExternalEffectRecovery::BindFinalized { .. }
        ));
        provider.records.remove(&value.external_effect_reference);
        assert_eq!(
            provider.resume(&value, value.submit_not_after_unix + 1),
            ExternalEffectRecovery::FailClosed
        );
        assert_eq!(provider.payouts, 1);

        // J. Any conflicting provider record is an immediate fail-closed.
        provider.records.insert(
            value.external_effect_reference.clone(),
            ExternalEffectObservation::Conflict,
        );
        assert_eq!(
            provider.resume(&value, 107),
            ExternalEffectRecovery::FailClosed
        );
    }

    #[test]
    fn relay_route_is_immutable_and_bounds_the_submit_window() {
        let value = relay_intent(100);
        assert_eq!(value.submit_not_after_unix, 700);
        assert!(value.verify().is_ok());
        let mut changed = value.clone();
        changed.relay.as_mut().unwrap().recipient =
            "0x9999999999999999999999999999999999999999".into();
        assert_eq!(changed.verify(), Err(RuntimeError::StateArtifact));
    }

    #[test]
    fn relay_restart_waits_for_destination_terminal_result_and_never_resubmits() {
        let value = relay_intent(100);
        let intake = format!("0x{}", "11".repeat(32));
        let destination = format!("0x{}", "22".repeat(32));
        let relay = value.relay.as_ref().unwrap();
        let result_hash = relay_result_hash(&value, &intake, &destination, "4985000").unwrap();
        let mut provider = ProviderFixture::default();

        // Persisted intent with no provider record may make one stable,
        // idempotent submission. A restart during destination processing sees
        // Pending and therefore never creates another payout.
        assert_eq!(
            provider.resume(&value, 101),
            ExternalEffectRecovery::AwaitExternalFinality
        );
        assert_eq!(provider.payouts, 1);
        provider.records.insert(
            value.external_effect_reference.clone(),
            ExternalEffectObservation::Pending {
                provider_transaction_id: "privy-transaction".into(),
            },
        );
        assert_eq!(
            provider.resume(&value, 102),
            ExternalEffectRecovery::AwaitExternalFinality
        );
        assert_eq!(provider.payouts, 1);

        provider.records.insert(
            value.external_effect_reference.clone(),
            ExternalEffectObservation::RelayFinalized {
                provider_transaction_id: "privy-transaction".into(),
                intake_transaction_hash: intake,
                relay_request_id: relay.request_id.clone(),
                destination_transaction_hash: destination,
                destination_amount_atomic: "4985000".into(),
                result_hash,
            },
        );
        let terminal = provider.resume(&value, 103);
        assert!(matches!(
            terminal,
            ExternalEffectRecovery::BindRelayFinalized { .. }
        ));
        assert_eq!(provider.payouts, 1);
        assert_eq!(provider.resume(&value, 104), terminal);
        assert_eq!(provider.payouts, 1);
    }
}
