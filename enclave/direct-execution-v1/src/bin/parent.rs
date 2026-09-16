//! Parent boundary for the clean direct runtime.  A Privy-verified BFF mints
//! short-lived signed sessions; the browser never supplies an auth subject or enclave frame.
use aws_sdk_kms::{
    primitives::Blob as KmsBlob,
    types::{DataKeySpec, KeyEncryptionMechanism, RecipientInfo},
    Client as KmsClient,
};
use aws_sdk_s3::{
    primitives::ByteStream,
    types::{ObjectLockMode, ServerSideEncryption},
    Client as S3Client,
};
use aws_smithy_types::DateTime;
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use hmac::{Hmac, Mac};
use layrs_direct_execution_v1::{
    artifact_hash, identity_commitment_for, reference_for, relay_reference_for, relay_result_hash,
    relay_reverted_result_hash, request_hash, sha256, sign, DirectAction, DirectReceipt,
    DirectRequest, DirectResult, DirectStateArtifact, DurabilityAck, ExternalEffectIntent,
    ExternalEffectRecovery, FilesystemImmutableArtifactStore, FilesystemImmutableIntentStore,
    GovernedBalanceRecovery, GovernedKeyReleaseArtifact, GovernedMarketRegistration,
    GovernedMarketResolution, ImmutableExternalEffectIntentStore, OrderAction, Outcome,
    ProjectionBalanceRow, ProjectionIdentityRow, ProjectionWalletRow, RelayWithdrawalBinding,
    RuntimeMeasurementBinding, RuntimeRequest, RuntimeResponse, SealedEpoch, TimeInForce,
    WriterGrant, EPOCH_ID, POSTGRES_PROJECTION_DDL,
};
use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    pkcs8::DecodePrivateKey,
};
use postgres_native_tls::MakeTlsConnector;
use reqwest::header::{HeaderMap as ReqwestHeaderMap, HeaderValue, ACCEPT};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use sha3::{Digest as KeccakDigest, Keccak256};
use std::{
    collections::{BTreeMap, HashSet},
    env,
    fs::{self, OpenOptions},
    io,
    net::IpAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Mutex,
    time::timeout,
};
use tokio_postgres::{Client, NoTls};
use tokio_vsock::{VsockAddr, VsockStream};
const ENCLOSURE_PORT: u32 = 5_003;
// Must match the enclave's finite parent-only VSOCK recovery ceiling.
const MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;
const SESSION_AUDIENCE: &str = "layrs.direct-execution.v1";
const DIRECT_SESSION_KEY_DERIVATION_DOMAIN: &[u8] = b"layrs.direct-session.v1\0";
const BASE_USDC_ADDRESS: &str = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
const ERC20_TRANSFER_TOPIC: &str =
    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const POOL_WITHDRAW_TOPIC: &str =
    "0xcbcdbdf10631a43cc99c80acace8232649421c3f4f73919f16013d47c83a687a";
const USER_OPERATION_EVENT_TOPIC: &str =
    "0x49628fd1471006c1482da88028e9ce4dbb080b815c9b0344d39e5a8e6ec1419f";
#[path = "../zen_custody.rs"]
mod zen_custody;
use zen_custody::ZenCustodyAdapter;
#[derive(Clone)]
struct AppState {
    enclave_cid: u32,
    session_key: Vec<u8>,
    isolated_test: bool,
    projection: Option<Projection>,
    local_used_sessions: Arc<Mutex<HashSet<(String, String)>>>,
    artifact_store: Option<ArchiveStore>,
    commit_ack_key: Vec<u8>,
    custody: Option<PrivyBaseCustodyAdapter>,
    zen_custody: Option<ZenCustodyAdapter>,
    /// Serializes only the bounded synchronous request and an unresolved
    /// external intent.  It is process memory, never durable workflow state.
    financial_gate: Arc<Mutex<()>>,
    committed_state_root: Arc<Mutex<Option<String>>>,
    unresolved_external_effects: Arc<Mutex<BTreeMap<String, ExternalEffectIntent>>>,
    governed_bootstrap: Option<GovernedBootstrapConfig>,
}

#[derive(Clone)]
struct GovernedBootstrapConfig {
    grant: WriterGrant,
    binding: RuntimeMeasurementBinding,
    kms_key_id: String,
    requested_mode: String,
}

#[derive(Clone)]
enum ArchiveStore {
    Filesystem(FilesystemImmutableArtifactStore),
    S3(S3ImmutableArtifactStore),
}

#[derive(Clone)]
struct S3ImmutableArtifactStore {
    client: S3Client,
    bucket: String,
    prefix: String,
    kms_key_id: String,
    retention_seconds: i64,
    // Receipt-only cache built after full encrypted-chain verification. It is
    // never a state-restore input and never contains private ledger plaintext.
    verified_receipt_records: Arc<Mutex<Option<Vec<DirectStateArtifact>>>>,
}

/// Direct, synchronous adapter for the existing Base pool-ledger Privy
/// wallet.  It has no local task state: all recovery derives from the
/// immutable intent and Privy's own reference lookup plus Base finality.
#[derive(Clone)]
struct PrivyBaseCustodyAdapter {
    client: reqwest::Client,
    app_id: String,
    app_secret: String,
    wallet_id: String,
    wallet_address: String,
    authorization_key_pem: String,
    rpc_url: String,
    pool_address: String,
    confirmations: u64,
    api_base_url: String,
    relay_api_key: Option<String>,
    relay_api_base_url: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DepositFinality {
    Pending,
    Finalized,
    Reverted,
    Conflict,
}

impl PrivyBaseCustodyAdapter {
    fn from_environment() -> Result<Option<Self>, String> {
        match env::var("LAYRS_DIRECT_CUSTODY_PROVIDER").as_deref() {
            Err(_) | Ok("") => Ok(None),
            Ok("privy-base-existing-pool-ledger") => {
                let required =
                    |name: &str| env::var(name).map_err(|_| format!("{name} is required"));
                let wallet_address =
                    canonical_evm_address(&required("LAYRSV2_BASE_POOL_LEDGER_PRIVY_ADDRESS")?)?;
                let pool_address = canonical_evm_address(&required("LAYRSV2_BASE_POOL_ADDRESS")?)?;
                // Reuse the established Base finality setting.  There is no
                // direct-runtime default: accepting a weaker confirmation
                // threshold than the operational custody path would weaken
                // the withdrawal invariant.
                let confirmations = required("LAYRSV2_BASE_CONFIRMATIONS")?
                    .parse::<u64>()
                    .map_err(|_| "invalid Base confirmation count")?;
                if confirmations == 0 {
                    return Err("invalid Base confirmation count".into());
                }
                let mut default_headers = ReqwestHeaderMap::new();
                // Match the existing operational Privy client exactly.  This
                // is a provider routing contract, not a new credential or a
                // weaker authorization scheme.
                default_headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
                Ok(Some(Self {
                    client: reqwest::Client::builder()
                        .https_only(true)
                        .timeout(Duration::from_secs(15))
                        .user_agent("layrsv2-public-api/1.0")
                        .default_headers(default_headers)
                        .build()
                        .map_err(|_| "custody HTTP client unavailable")?,
                    app_id: required("LAYRSV2_PRIVY_APP_ID")?,
                    app_secret: required("LAYRSV2_PRIVY_APP_SECRET")?,
                    wallet_id: required("LAYRSV2_BASE_POOL_LEDGER_PRIVY_WALLET_ID")?,
                    wallet_address,
                    authorization_key_pem: required(
                        "LAYRSV2_BASE_POOL_LEDGER_PRIVY_AUTH_PRIVATE_KEY_PEM",
                    )?
                    .replace("\\n", "\n"),
                    rpc_url: required("LAYRSV2_BASE_RPC_URL")?,
                    pool_address,
                    confirmations,
                    api_base_url: env::var("LAYRS_DIRECT_PRIVY_API_BASE_URL")
                        .unwrap_or_else(|_| "https://api.privy.io".into())
                        .trim_end_matches('/')
                        .into(),
                    relay_api_key: env::var("LAYRSV2_RELAY_API_KEY")
                        .ok()
                        .filter(|value| !value.trim().is_empty()),
                    relay_api_base_url: env::var("LAYRSV2_RELAY_BASE_URL")
                        .unwrap_or_else(|_| "https://api.relay.link".into())
                        .trim_end_matches('/')
                        .into(),
                }))
            }
            Ok(_) => Err("unsupported direct custody provider".into()),
        }
    }

    async fn settle(
        &self,
        intent: &ExternalEffectIntent,
        now: u64,
    ) -> Result<layrs_direct_execution_v1::ExternalEffectRecovery, String> {
        self.validate_intent(intent)?;
        let observation = self.observe(intent).await?;
        match intent.recovery_action(now, observation) {
            layrs_direct_execution_v1::ExternalEffectRecovery::SubmitWithStableReference => {
                self.submit_once(intent).await?;
                let observed = self.observe(intent).await?;
                Ok(match observed {
                    // The provider may not index a just-accepted sponsored
                    // transaction immediately.  Never issue a second send in
                    // this request; wait for the same stable reference.
                    layrs_direct_execution_v1::ExternalEffectObservation::NotFound => {
                        ExternalEffectRecovery::AwaitExternalFinality
                    }
                    observed => intent.recovery_action(now, observed),
                })
            }
            decision => Ok(decision),
        }
    }

    /// Historical reconciliation must have no path to submit_once, even if
    /// the provider temporarily loses its reference index.
    async fn observe_terminal_only(&self, intent: &ExternalEffectIntent) -> Result<ExternalEffectRecovery, String> {
        self.validate_intent(intent)?;
        let outcome = intent.recovery_action(now_unix(), self.observe(intent).await?);
        match outcome {
            terminal @ (ExternalEffectRecovery::BindFinalized { .. } | ExternalEffectRecovery::BindReverted { .. }) => Ok(terminal),
            _ => Err("historical custody effect is not authoritatively terminal".into()),
        }
    }

    fn validate_intent(&self, intent: &ExternalEffectIntent) -> Result<(), String> {
        intent
            .verify()
            .map_err(|_| "external-effect intent invalid")?;
        if intent.chain != "base"
            || intent.asset != "USDC"
            || intent.provider_wallet_id != self.wallet_id
            || intent.custody_target != self.pool_address
        {
            return Err("existing Base custody adapter cannot settle this intent".into());
        }
        Ok(())
    }

    async fn observe(
        &self,
        intent: &ExternalEffectIntent,
    ) -> Result<layrs_direct_execution_v1::ExternalEffectObservation, String> {
        let url = format!("{}/v1/transactions", self.api_base_url);
        let response = self
            .client
            .get(url)
            .query(&[("reference_id", intent.external_effect_reference.as_str())])
            .header("authorization", self.basic_authorization())
            .header("privy-app-id", &self.app_id)
            .send()
            .await
            .map_err(|_| "custody provider lookup failed")?;
        if !response.status().is_success() {
            return Err("custody provider lookup rejected".into());
        }
        let body: Value = response
            .json()
            .await
            .map_err(|_| "custody provider lookup malformed")?;
        let records = body
            .as_array()
            .or_else(|| body.get("data").and_then(Value::as_array))
            .or_else(|| body.get("transactions").and_then(Value::as_array))
            .ok_or("custody provider lookup malformed")?;
        let matching: Vec<&Value> = records
            .iter()
            .filter(|record| {
                record.get("wallet_id").and_then(Value::as_str) == Some(self.wallet_id.as_str())
                    && record.get("caip2").and_then(Value::as_str) == Some("eip155:8453")
                    && record.get("reference_id").and_then(Value::as_str)
                        == Some(intent.external_effect_reference.as_str())
            })
            .collect();
        if matching.is_empty() {
            return Ok(layrs_direct_execution_v1::ExternalEffectObservation::NotFound);
        }
        if matching.len() != 1 {
            return Ok(layrs_direct_execution_v1::ExternalEffectObservation::Conflict);
        }
        let record = matching[0];
        let id = record
            .get("id")
            .and_then(Value::as_str)
            .ok_or("custody provider transaction ID missing")?
            .to_owned();
        let status = record
            .get("status")
            .and_then(Value::as_str)
            .ok_or("custody provider status missing")?;
        let transaction_hash = record
            .get("transaction_hash")
            .and_then(Value::as_str)
            .filter(|value| valid_transaction_hash(value))
            .map(str::to_owned);
        let sponsored = record.get("sponsored").and_then(Value::as_bool) == Some(true);
        let user_operation_hash = record
            .get("user_operation_hash")
            .and_then(Value::as_str)
            .filter(|value| valid_transaction_hash(value))
            .map(str::to_owned);
        match status {
            "pending" | "broadcasted" => Ok(
                layrs_direct_execution_v1::ExternalEffectObservation::Pending {
                    provider_transaction_id: id,
                },
            ),
            "confirmed" | "finalized" => match transaction_hash {
                Some(transaction_hash) => {
                    self.authoritative_finality(
                        intent,
                        id,
                        transaction_hash,
                        sponsored,
                        user_operation_hash,
                    )
                    .await
                }
                None => Ok(
                    layrs_direct_execution_v1::ExternalEffectObservation::Pending {
                        provider_transaction_id: id,
                    },
                ),
            },
            "execution_reverted" => match transaction_hash {
                Some(transaction_hash) => {
                    self.authoritative_finality(
                        intent,
                        id,
                        transaction_hash,
                        sponsored,
                        user_operation_hash,
                    )
                    .await
                }
                None => Ok(layrs_direct_execution_v1::ExternalEffectObservation::Conflict),
            },
            "failed" | "replaced" | "provider_error" => {
                Ok(layrs_direct_execution_v1::ExternalEffectObservation::Conflict)
            }
            _ => Ok(layrs_direct_execution_v1::ExternalEffectObservation::Conflict),
        }
    }

    async fn submit_once(&self, intent: &ExternalEffectIntent) -> Result<(), String> {
        let data = pool_withdraw_calldata(&intent.destination, &intent.amount_atomic)?;
        let body = json!({
            "method": "eth_sendTransaction",
            "caip2": "eip155:8453",
            "chain_type": "ethereum",
            "sponsor": true,
            "reference_id": intent.external_effect_reference,
            "params": { "transaction": {
                "from": self.wallet_address,
                "to": intent.custody_target,
                "value": "0x0",
                "chain_id": 8453,
                "data": data,
                "gas_limit": quantity(intent.gas_limit.parse::<u128>().map_err(|_| "intent gas limit invalid")?),
                "nonce": quantity(intent.transaction_nonce.parse::<u128>().map_err(|_| "intent nonce invalid")?),
                "max_fee_per_gas": quantity(intent.max_fee_per_gas.parse::<u128>().map_err(|_| "intent fee invalid")?),
                "max_priority_fee_per_gas": quantity(intent.max_priority_fee_per_gas.parse::<u128>().map_err(|_| "intent priority fee invalid")?),
            }}
        });
        let url = format!("{}/v1/wallets/{}/rpc", self.api_base_url, self.wallet_id);
        let response = self
            .client
            .post(&url)
            .headers(self.privy_authorization_headers(
                &url,
                &body,
                &intent.provider_idempotency_key,
            )?)
            .json(&body)
            .send()
            .await
            .map_err(|_| "custody provider submission failed")?;
        if !response.status().is_success() {
            return Err("custody provider submission rejected".into());
        }
        let response: Value = response
            .json()
            .await
            .map_err(|_| "custody provider submission malformed")?;
        let data = response
            .get("data")
            .ok_or("custody provider submission malformed")?;
        if data.get("caip2").and_then(Value::as_str) != Some("eip155:8453")
            || data.get("transaction_id").and_then(Value::as_str).is_none()
            || data.get("reference_id").and_then(Value::as_str)
                != Some(intent.external_effect_reference.as_str())
        {
            return Err("custody provider submission binding mismatch".into());
        }
        Ok(())
    }

    async fn transaction_parameters(&self) -> Result<(u128, u128, u128, u128), String> {
        let chain = self
            .rpc("eth_chainId", json!([]))
            .await?
            .as_str()
            .and_then(parse_quantity)
            .ok_or("Base RPC chain ID malformed")?;
        if chain != 8453 {
            return Err("Base RPC chain ID mismatch".into());
        }
        let nonce = self
            .rpc(
                "eth_getTransactionCount",
                json!([self.wallet_address, "pending"]),
            )
            .await?
            .as_str()
            .and_then(parse_quantity)
            .ok_or("Base RPC nonce malformed")?;
        let block = self
            .rpc("eth_getBlockByNumber", json!(["latest", false]))
            .await?;
        let base_fee = block
            .get("baseFeePerGas")
            .and_then(Value::as_str)
            .and_then(parse_quantity)
            .or_else(|| None)
            .ok_or("Base RPC fee data missing")?;
        let priority = match self.rpc("eth_maxPriorityFeePerGas", json!([])).await {
            Ok(value) => value
                .as_str()
                .and_then(parse_quantity)
                .unwrap_or(1_000_000_000),
            Err(_) => 1_000_000_000,
        };
        Ok((
            nonce,
            180_000,
            base_fee.saturating_mul(2).saturating_add(priority),
            priority,
        ))
    }

    async fn authoritative_finality(
        &self,
        intent: &ExternalEffectIntent,
        provider_transaction_id: String,
        transaction_hash: String,
        sponsored: bool,
        user_operation_hash: Option<String>,
    ) -> Result<layrs_direct_execution_v1::ExternalEffectObservation, String> {
        let transaction = self
            .rpc("eth_getTransactionByHash", json!([transaction_hash]))
            .await?;
        if transaction.is_null() {
            return Ok(
                layrs_direct_execution_v1::ExternalEffectObservation::Pending {
                    provider_transaction_id,
                },
            );
        }
        if !sponsored {
            let expected_data = pool_withdraw_calldata(&intent.destination, &intent.amount_atomic)?;
            if transaction
                .get("from")
                .and_then(Value::as_str)
                .and_then(|value| canonical_evm_address(value).ok())
                .as_deref()
                != Some(self.wallet_address.as_str())
                || transaction
                    .get("to")
                    .and_then(Value::as_str)
                    .and_then(|value| canonical_evm_address(value).ok())
                    .as_deref()
                    != Some(self.pool_address.as_str())
                || transaction
                    .get("input")
                    .and_then(Value::as_str)
                    .map(|value| value.eq_ignore_ascii_case(&expected_data))
                    != Some(true)
            {
                return Ok(layrs_direct_execution_v1::ExternalEffectObservation::Conflict);
            }
        }
        let receipt = self
            .rpc("eth_getTransactionReceipt", json!([transaction_hash]))
            .await?;
        if receipt.is_null() {
            return Ok(
                layrs_direct_execution_v1::ExternalEffectObservation::Pending {
                    provider_transaction_id,
                },
            );
        }
        let block_number = receipt
            .get("blockNumber")
            .and_then(Value::as_str)
            .and_then(parse_quantity)
            .ok_or("Base receipt block number malformed")?;
        let block_hash = receipt
            .get("blockHash")
            .and_then(Value::as_str)
            .filter(|value| valid_transaction_hash(value))
            .ok_or("Base receipt block hash malformed")?;
        let status = receipt
            .get("status")
            .and_then(Value::as_str)
            .ok_or("Base receipt status malformed")?;
        let head = self
            .rpc("eth_blockNumber", json!([]))
            .await?
            .as_str()
            .and_then(parse_quantity)
            .ok_or("Base RPC head malformed")?;
        if head
            .checked_sub(block_number)
            .and_then(|value| value.checked_add(1))
            .unwrap_or(0)
            < u128::from(self.confirmations)
        {
            return Ok(
                layrs_direct_execution_v1::ExternalEffectObservation::Pending {
                    provider_transaction_id,
                },
            );
        }
        // A receipt must be bound to its reported block hash before it can be
        // terminally transcribed into a private artifact.
        if block_hash.len() != 66 {
            return Ok(layrs_direct_execution_v1::ExternalEffectObservation::Conflict);
        }
        match status {
            "0x1"
                if !sponsored
                    || sponsored_withdrawal_receipt_matches(
                        intent,
                        &self.wallet_address,
                        &self.pool_address,
                        user_operation_hash.as_deref(),
                        &receipt,
                    ) =>
            {
                if intent.relay.is_some() {
                    return self
                        .relay_destination_finality(
                            intent,
                            provider_transaction_id,
                            transaction_hash,
                        )
                        .await;
                }
                Ok(
                    layrs_direct_execution_v1::ExternalEffectObservation::Finalized {
                        provider_transaction_id,
                        transaction_hash,
                    },
                )
            }
            "0x0" => Ok(
                layrs_direct_execution_v1::ExternalEffectObservation::Reverted {
                    provider_transaction_id,
                    transaction_hash,
                },
            ),
            _ => Ok(layrs_direct_execution_v1::ExternalEffectObservation::Conflict),
        }
    }

    /// Relay intake on Base is not withdrawal finality.  Once the intake leg
    /// has authoritative Base finality, synchronously observe Relay's
    /// provider-owned request and bind the destination result.  This function
    /// creates no job or persisted lifecycle; restart calls the same lookup
    /// from the write-once external-effect intent.
    async fn relay_destination_finality(
        &self,
        intent: &ExternalEffectIntent,
        provider_transaction_id: String,
        intake_transaction_hash: String,
    ) -> Result<layrs_direct_execution_v1::ExternalEffectObservation, String> {
        let relay = intent
            .relay
            .as_ref()
            .ok_or("Relay binding missing from external-effect intent")?;
        let api_key = self
            .relay_api_key
            .as_deref()
            .ok_or("Relay authoritative observation is not configured")?;
        let status: Value = self
            .client
            .get(format!("{}/intents/status/v3", self.relay_api_base_url))
            .query(&[("requestId", relay.request_id.as_str())])
            .header("x-api-key", api_key)
            .send()
            .await
            .map_err(|_| "Relay status lookup failed")?
            .error_for_status()
            .map_err(|_| "Relay status lookup rejected")?
            .json()
            .await
            .map_err(|_| "Relay status lookup malformed")?;
        let details: Value = self
            .client
            .get(format!("{}/requests/v3", self.relay_api_base_url))
            .query(&[("id", relay.request_id.as_str())])
            .header("x-api-key", api_key)
            .send()
            .await
            .map_err(|_| "Relay request lookup failed")?
            .error_for_status()
            .map_err(|_| "Relay request lookup rejected")?
            .json()
            .await
            .map_err(|_| "Relay request lookup malformed")?;
        classify_relay_destination_finality(
            intent,
            provider_transaction_id,
            intake_transaction_hash,
            &status,
            &details,
        )
    }

    /// Verify one inbound Base USDC transfer from the authenticated embedded
    /// wallet into the existing pool custody address. This is a synchronous
    /// chain observation only: it creates no job, queue, lease, or database
    /// command state. The enclave consumes the transaction hash exactly once.
    async fn deposit_finality(
        &self,
        source_wallet: &str,
        transaction_hash: &str,
        amount_atomic: &str,
    ) -> Result<DepositFinality, String> {
        let source_wallet = canonical_evm_address(source_wallet)?;
        if !valid_transaction_hash(transaction_hash) {
            return Err("deposit transaction hash invalid".into());
        }
        let amount = amount_atomic
            .parse::<u128>()
            .ok()
            .filter(|value| *value > 0)
            .ok_or("deposit amount invalid")?;
        let transaction = self
            .rpc("eth_getTransactionByHash", json!([transaction_hash]))
            .await?;
        if transaction.is_null() {
            return Ok(DepositFinality::Pending);
        }
        let receipt = self
            .rpc("eth_getTransactionReceipt", json!([transaction_hash]))
            .await?;
        if receipt.is_null() {
            return Ok(DepositFinality::Pending);
        }
        let head = self
            .rpc("eth_blockNumber", json!([]))
            .await?
            .as_str()
            .and_then(parse_quantity)
            .ok_or("Base RPC head malformed")?;
        classify_base_deposit(
            &source_wallet,
            &self.pool_address,
            transaction_hash,
            amount,
            self.confirmations,
            &transaction,
            &receipt,
            head,
        )
    }

    async fn rpc(&self, method: &str, params: Value) -> Result<Value, String> {
        let response = self
            .client
            .post(&self.rpc_url)
            .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
            .send()
            .await
            .map_err(|_| "Base RPC unavailable")?;
        let success = response.status().is_success();
        let body: Value = response.json().await.map_err(|_| "Base RPC malformed")?;
        if !success || body.get("error").is_some() {
            return Err("Base RPC rejected request".into());
        }
        body.get("result")
            .cloned()
            .ok_or("Base RPC result missing".into())
    }

    fn basic_authorization(&self) -> String {
        format!(
            "Basic {}",
            STANDARD.encode(format!("{}:{}", self.app_id, self.app_secret))
        )
    }
    fn privy_authorization_headers(
        &self,
        url: &str,
        body: &Value,
        idempotency_key: &str,
    ) -> Result<reqwest::header::HeaderMap, String> {
        let expiry = now_unix_millis()
            .checked_add(60_000)
            .ok_or("clock invalid")?
            .to_string();
        let headers = json!({"privy-app-id": self.app_id, "privy-request-expiry": expiry, "privy-idempotency-key": idempotency_key});
        let payload = json!({"version":1,"method":"POST","url":url,"body":body,"headers":headers});
        let signing_key = SigningKey::from_pkcs8_pem(&self.authorization_key_pem)
            .map_err(|_| "existing Privy authorization key invalid")?;
        let signature: Signature = signing_key.sign(canonical_json(&payload).as_bytes());
        let mut result = reqwest::header::HeaderMap::new();
        result.insert(
            "authorization",
            self.basic_authorization()
                .parse()
                .map_err(|_| "custody authorization invalid")?,
        );
        result.insert("content-type", "application/json".parse().unwrap());
        result.insert("accept", "application/json".parse().unwrap());
        result.insert(
            "privy-app-id",
            self.app_id.parse().map_err(|_| "custody app ID invalid")?,
        );
        result.insert(
            "privy-request-expiry",
            expiry.parse().map_err(|_| "custody expiry invalid")?,
        );
        result.insert(
            "privy-idempotency-key",
            idempotency_key
                .parse()
                .map_err(|_| "custody idempotency key invalid")?,
        );
        result.insert(
            "privy-authorization-signature",
            STANDARD
                .encode(signature.to_der().as_bytes())
                .parse()
                .map_err(|_| "custody signature invalid")?,
        );
        Ok(result)
    }
}

fn classify_relay_destination_finality(
    intent: &ExternalEffectIntent,
    provider_transaction_id: String,
    intake_transaction_hash: String,
    status: &Value,
    details: &Value,
) -> Result<layrs_direct_execution_v1::ExternalEffectObservation, String> {
    let relay = intent
        .relay
        .as_ref()
        .ok_or("Relay binding missing from external-effect intent")?;
    relay
        .verify(&intent.amount_atomic)
        .map_err(|_| "Relay binding invalid")?;
    if !valid_transaction_hash(&intake_transaction_hash) {
        return Err("Relay intake transaction hash invalid".into());
    }
    let status_name = status
        .get("status")
        .and_then(Value::as_str)
        .ok_or("Relay status missing")?;
    if let Some(request_id) = status.get("requestId").and_then(Value::as_str) {
        if !request_id.eq_ignore_ascii_case(&relay.request_id) {
            return Ok(layrs_direct_execution_v1::ExternalEffectObservation::Conflict);
        }
    }
    let origin_chain = status.get("originChainId").and_then(Value::as_u64);
    let destination_chain = status.get("destinationChainId").and_then(Value::as_u64);
    if origin_chain.is_some_and(|chain| chain != 8453)
        || destination_chain.is_some_and(|chain| chain != relay.destination_chain_id)
    {
        return Ok(layrs_direct_execution_v1::ExternalEffectObservation::Conflict);
    }
    let status_intake_hashes = relay_hashes(status.get("inTxHashes"));
    if !status_intake_hashes.is_empty()
        && !status_intake_hashes
            .iter()
            .any(|hash| hash.eq_ignore_ascii_case(&intake_transaction_hash))
    {
        return Ok(layrs_direct_execution_v1::ExternalEffectObservation::Conflict);
    }
    if matches!(
        status_name,
        "waiting" | "depositing" | "pending" | "submitted" | "delayed"
    ) {
        return Ok(
            layrs_direct_execution_v1::ExternalEffectObservation::Pending {
                provider_transaction_id,
            },
        );
    }
    let requests = details
        .get("requests")
        .and_then(Value::as_array)
        .ok_or("Relay request details malformed")?;
    if requests.len() != 1 {
        return Ok(layrs_direct_execution_v1::ExternalEffectObservation::Conflict);
    }
    let request = &requests[0];
    if request
        .get("id")
        .and_then(Value::as_str)
        .is_none_or(|id| !id.eq_ignore_ascii_case(&relay.request_id))
        || request
            .get("recipient")
            .and_then(Value::as_str)
            .is_none_or(|recipient| {
                !relay_address_eq(recipient, &relay.recipient, relay.destination_chain_id)
            })
        || request
            .pointer("/depositAddress/address")
            .and_then(Value::as_str)
            .is_none_or(|address| !address.eq_ignore_ascii_case(&relay.deposit_address))
        || !relay_route_quote_matches(request, relay, &intent.amount_atomic)
        || !relay_request_has_intake(request, &intake_transaction_hash)
    {
        return Ok(layrs_direct_execution_v1::ExternalEffectObservation::Conflict);
    }
    match status_name {
        "success" => {
            if request.get("status").and_then(Value::as_str) != Some("success") {
                return Ok(layrs_direct_execution_v1::ExternalEffectObservation::Conflict);
            }
            let status_destination_hashes = relay_hashes(status.get("txHashes"));
            let request_destination_hashes =
                relay_destination_hashes(request, relay.destination_chain_id);
            if status_destination_hashes.len() != 1
                || request_destination_hashes.len() != 1
                || status_destination_hashes[0] != request_destination_hashes[0]
            {
                return Ok(layrs_direct_execution_v1::ExternalEffectObservation::Conflict);
            }
            let destination_amount_atomic = relay_actual_destination_amount(request, relay)?;
            let minimum = relay
                .minimum_destination_amount_atomic
                .parse::<u128>()
                .map_err(|_| "Relay minimum amount invalid")?;
            if destination_amount_atomic
                .parse::<u128>()
                .ok()
                .is_none_or(|amount| amount < minimum)
            {
                return Ok(layrs_direct_execution_v1::ExternalEffectObservation::Conflict);
            }
            let result_hash = relay_result_hash(
                intent,
                &intake_transaction_hash,
                &request_destination_hashes[0],
                &destination_amount_atomic,
            )
            .ok_or("Relay result binding unavailable")?;
            Ok(
                layrs_direct_execution_v1::ExternalEffectObservation::RelayFinalized {
                    provider_transaction_id,
                    intake_transaction_hash,
                    relay_request_id: relay.request_id.clone(),
                    destination_transaction_hash: request_destination_hashes[0].clone(),
                    destination_amount_atomic,
                    result_hash,
                },
            )
        }
        "refund" | "refunded" | "failure" => {
            let request_status = request.get("status").and_then(Value::as_str);
            if !matches!(request_status, Some("refund" | "refunded" | "failure")) {
                return Ok(layrs_direct_execution_v1::ExternalEffectObservation::Conflict);
            }
            let result_hash = relay_reverted_result_hash(
                relay,
                &intent.external_effect_reference,
                &intake_transaction_hash,
                status_name,
            );
            Ok(
                layrs_direct_execution_v1::ExternalEffectObservation::RelayReverted {
                    provider_transaction_id,
                    intake_transaction_hash,
                    relay_request_id: relay.request_id.clone(),
                    terminal_status: status_name.into(),
                    result_hash,
                },
            )
        }
        _ => Ok(layrs_direct_execution_v1::ExternalEffectObservation::Conflict),
    }
}

fn relay_hashes(value: Option<&Value>) -> Vec<String> {
    let mut hashes = value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter(|hash| valid_relay_transaction_hash(hash))
        .map(|hash| {
            if hash.starts_with("0x") {
                hash.to_ascii_lowercase()
            } else {
                hash.to_owned()
            }
        })
        .collect::<Vec<_>>();
    hashes.sort();
    hashes.dedup();
    hashes
}

fn relay_request_has_intake(request: &Value, intake_transaction_hash: &str) -> bool {
    request
        .pointer("/data/inTxs")
        .and_then(Value::as_array)
        .is_some_and(|transactions| {
            transactions.iter().any(|transaction| {
                transaction.get("chainId").and_then(Value::as_u64) == Some(8453)
                    && transaction.get("status").and_then(Value::as_str) == Some("success")
                    && transaction
                        .get("txHash")
                        .and_then(Value::as_str)
                        .is_some_and(|hash| hash.eq_ignore_ascii_case(intake_transaction_hash))
            })
        })
}

fn relay_destination_hashes(request: &Value, destination_chain_id: u64) -> Vec<String> {
    let values = request
        .pointer("/data/outTxs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|transaction| {
            transaction.get("chainId").and_then(Value::as_u64) == Some(destination_chain_id)
                && transaction.get("status").and_then(Value::as_str) == Some("success")
        })
        .filter_map(|transaction| transaction.get("txHash").and_then(Value::as_str))
        .collect::<Vec<_>>();
    relay_hashes(Some(&Value::Array(
        values
            .into_iter()
            .map(|value| Value::String(value.into()))
            .collect(),
    )))
}

fn relay_route_quote_matches(
    request: &Value,
    relay: &RelayWithdrawalBinding,
    source_amount_atomic: &str,
) -> bool {
    let origin = request.pointer("/data/route/quoted/origin/inputCurrency");
    let destination = request.pointer("/data/route/quoted/destination/outputCurrency");
    relay_currency_matches(origin, 8453, BASE_USDC_ADDRESS, source_amount_atomic)
        && relay_currency_matches(
            destination,
            relay.destination_chain_id,
            &relay.destination_currency,
            &relay.quoted_destination_amount_atomic,
        )
}

fn relay_actual_destination_amount(
    request: &Value,
    relay: &RelayWithdrawalBinding,
) -> Result<String, String> {
    let output = request
        .pointer("/data/route/actual/destination/outputCurrency")
        .ok_or("Relay actual destination result missing")?;
    let amount = output
        .get("amount")
        .and_then(Value::as_str)
        .ok_or("Relay actual destination amount missing")?;
    if !relay_currency_matches(
        Some(output),
        relay.destination_chain_id,
        &relay.destination_currency,
        amount,
    ) || amount
        .parse::<u128>()
        .ok()
        .filter(|value| *value > 0)
        .is_none()
    {
        return Err("Relay actual destination result mismatch".into());
    }
    Ok(amount.into())
}

fn relay_currency_matches(
    value: Option<&Value>,
    chain_id: u64,
    currency: &str,
    amount: &str,
) -> bool {
    value.is_some_and(|value| {
        value.pointer("/currency/chainId").and_then(Value::as_u64) == Some(chain_id)
            && value
                .pointer("/currency/address")
                .and_then(Value::as_str)
                .is_some_and(|address| relay_address_eq(address, currency, chain_id))
            && value.get("amount").and_then(Value::as_str) == Some(amount)
    })
}

fn relay_address_eq(left: &str, right: &str, chain_id: u64) -> bool {
    if chain_id == 792_703_809 {
        left == right
    } else {
        left.eq_ignore_ascii_case(right)
    }
}

fn valid_relay_transaction_hash(value: &str) -> bool {
    valid_transaction_hash(value)
        || ((64..=96).contains(&value.len())
            && value.bytes().all(|byte| {
                matches!(byte,
                b'1'..=b'9' | b'A'..=b'H' | b'J'..=b'N' | b'P'..=b'Z'
                | b'a'..=b'k' | b'm'..=b'z')
            }))
}

fn canonical_evm_address(value: &str) -> Result<String, String> {
    if value.len() == 42
        && value.starts_with("0x")
        && value[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        Ok(value.to_ascii_lowercase())
    } else {
        Err("invalid EVM address".into())
    }
}
fn valid_transaction_hash(value: &str) -> bool {
    value.len() == 66
        && value.starts_with("0x")
        && value[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
}
fn parse_quantity(value: &str) -> Option<u128> {
    value
        .strip_prefix("0x")
        .and_then(|value| u128::from_str_radix(value, 16).ok())
}
fn quantity(value: u128) -> String {
    format!("0x{value:x}")
}
fn pool_withdraw_calldata(destination: &str, amount_atomic: &str) -> Result<String, String> {
    let destination = canonical_evm_address(destination)?;
    let amount = amount_atomic
        .parse::<u128>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or("invalid withdrawal amount")?;
    let mut hasher = Keccak256::new();
    hasher.update(b"withdraw(address,uint256)");
    let selector = hasher.finalize();
    Ok(format!(
        "0x{}{:0>64}{:0>64}",
        hex::encode(&selector[..4]),
        &destination[2..],
        format!("{amount:x}")
    ))
}

fn erc20_transfer_calldata(destination: &str, amount: u128) -> Result<String, String> {
    let destination = canonical_evm_address(destination)?;
    Ok(format!(
        "0xa9059cbb{:0>64}{amount:0>64x}",
        &destination[2..]
    ))
}

fn address_topic(address: &str) -> String {
    format!("0x{:0>64}", &address[2..].to_ascii_lowercase())
}

/// Privy gas sponsorship wraps the authorized pool call in an ERC-4337
/// transaction, so the outer transaction is sent by the bundler to the Entry
/// Point rather than directly by the operational wallet to the pool.  Bind
/// finality to the provider-owned user-operation hash and to the exact
/// successful inner financial effect instead of weakening the direct-call
/// checks above.
fn sponsored_withdrawal_receipt_matches(
    intent: &ExternalEffectIntent,
    operational_wallet: &str,
    pool_address: &str,
    user_operation_hash: Option<&str>,
    receipt: &Value,
) -> bool {
    let Some(user_operation_hash) = user_operation_hash else {
        return false;
    };
    let Some(logs) = receipt.get("logs").and_then(Value::as_array) else {
        return false;
    };
    let Ok(amount) = intent.amount_atomic.parse::<u128>() else {
        return false;
    };
    let wallet_topic = address_topic(operational_wallet);
    let pool_topic = address_topic(pool_address);
    let destination_topic = address_topic(&intent.destination);
    let mut matching_user_operations = 0usize;
    let mut matching_transfers = 0usize;
    let mut matching_withdrawals = 0usize;
    for log in logs {
        let address = log
            .get("address")
            .and_then(Value::as_str)
            .and_then(|value| canonical_evm_address(value).ok());
        let topics = log.get("topics").and_then(Value::as_array);
        let data = log.get("data").and_then(Value::as_str);
        let topic = |index: usize| {
            topics
                .and_then(|values| values.get(index))
                .and_then(Value::as_str)
        };
        if topic(0).is_some_and(|value| value.eq_ignore_ascii_case(USER_OPERATION_EVENT_TOPIC))
            && topic(1).is_some_and(|value| value.eq_ignore_ascii_case(user_operation_hash))
            && topic(2).is_some_and(|value| value.eq_ignore_ascii_case(&wallet_topic))
            && data
                .and_then(|value| value.strip_prefix("0x"))
                .filter(|value| value.len() >= 128)
                .and_then(|value| u128::from_str_radix(&value[64..128], 16).ok())
                == Some(1)
        {
            matching_user_operations += 1;
        }
        if address.as_deref() == Some(BASE_USDC_ADDRESS)
            && topic(0).is_some_and(|value| value.eq_ignore_ascii_case(ERC20_TRANSFER_TOPIC))
            && topic(1).is_some_and(|value| value.eq_ignore_ascii_case(&pool_topic))
            && topic(2).is_some_and(|value| value.eq_ignore_ascii_case(&destination_topic))
            && data.and_then(parse_quantity) == Some(amount)
        {
            matching_transfers += 1;
        }
        if address.as_deref() == Some(pool_address)
            && topic(0).is_some_and(|value| value.eq_ignore_ascii_case(POOL_WITHDRAW_TOPIC))
            && topic(1).is_some_and(|value| value.eq_ignore_ascii_case(&destination_topic))
            && topic(2).is_some_and(|value| value.eq_ignore_ascii_case(&wallet_topic))
            && data.and_then(parse_quantity) == Some(amount)
        {
            matching_withdrawals += 1;
        }
    }
    matching_user_operations == 1 && matching_transfers == 1 && matching_withdrawals == 1
}

#[allow(clippy::too_many_arguments)]
fn classify_base_deposit(
    source_wallet: &str,
    pool_address: &str,
    transaction_hash: &str,
    amount: u128,
    confirmations: u64,
    transaction: &Value,
    receipt: &Value,
    head: u128,
) -> Result<DepositFinality, String> {
    let expected_input = erc20_transfer_calldata(pool_address, amount)?;
    if transaction
        .get("from")
        .and_then(Value::as_str)
        .and_then(|value| canonical_evm_address(value).ok())
        .as_deref()
        != Some(source_wallet)
        || transaction
            .get("to")
            .and_then(Value::as_str)
            .and_then(|value| canonical_evm_address(value).ok())
            .as_deref()
            != Some(BASE_USDC_ADDRESS)
        || transaction
            .get("input")
            .and_then(Value::as_str)
            .map(|value| value.eq_ignore_ascii_case(&expected_input))
            != Some(true)
        || transaction
            .get("value")
            .and_then(Value::as_str)
            .and_then(parse_quantity)
            != Some(0)
        || receipt
            .get("transactionHash")
            .and_then(Value::as_str)
            .map(|value| value.eq_ignore_ascii_case(transaction_hash))
            != Some(true)
        || receipt.get("blockHash").and_then(Value::as_str)
            != transaction.get("blockHash").and_then(Value::as_str)
    {
        return Ok(DepositFinality::Conflict);
    }
    match receipt.get("status").and_then(Value::as_str) {
        Some("0x0") => return Ok(DepositFinality::Reverted),
        Some("0x1") => {}
        _ => return Ok(DepositFinality::Conflict),
    }
    let expected_from_topic = address_topic(source_wallet);
    let expected_to_topic = address_topic(pool_address);
    let exact_transfer = receipt
        .get("logs")
        .and_then(Value::as_array)
        .is_some_and(|logs| {
            logs.iter().any(|log| {
                log.get("address")
                    .and_then(Value::as_str)
                    .is_some_and(|value| value.eq_ignore_ascii_case(BASE_USDC_ADDRESS))
                    && log
                        .get("topics")
                        .and_then(Value::as_array)
                        .is_some_and(|topics| {
                            topics.len() >= 3
                                && topics[0].as_str().is_some_and(|value| {
                                    value.eq_ignore_ascii_case(ERC20_TRANSFER_TOPIC)
                                })
                                && topics[1].as_str().is_some_and(|value| {
                                    value.eq_ignore_ascii_case(&expected_from_topic)
                                })
                                && topics[2].as_str().is_some_and(|value| {
                                    value.eq_ignore_ascii_case(&expected_to_topic)
                                })
                        })
                    && log
                        .get("data")
                        .and_then(Value::as_str)
                        .and_then(parse_quantity)
                        == Some(amount)
            })
        });
    if !exact_transfer {
        return Ok(DepositFinality::Conflict);
    }
    let block_number = receipt
        .get("blockNumber")
        .and_then(Value::as_str)
        .and_then(parse_quantity)
        .ok_or("Base deposit receipt block number malformed")?;
    if head
        .checked_sub(block_number)
        .and_then(|value| value.checked_add(1))
        .unwrap_or(0)
        < u128::from(confirmations)
    {
        return Ok(DepositFinality::Pending);
    }
    Ok(DepositFinality::Finalized)
}
fn canonical_json(value: &Value) -> String {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            serde_json::to_string(value).expect("canonical scalar serializes")
        }
        Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",")
        ),
        Value::Object(values) => format!(
            "{{{}}}",
            values
                .iter()
                .map(|(key, value)| format!(
                    "{}:{}",
                    serde_json::to_string(key).expect("canonical key serializes"),
                    canonical_json(value)
                ))
                .collect::<Vec<_>>()
                .join(",")
        ),
    }
}

impl ArchiveStore {
    async fn from_environment(
        local_filesystem_permitted: bool,
    ) -> Result<Option<Self>, Box<dyn std::error::Error>> {
        match env::var("LAYRS_DIRECT_ARCHIVE_BACKEND").as_deref() {
            Ok("s3-object-lock") => Ok(Some(Self::S3(
                S3ImmutableArtifactStore::from_environment().await?,
            ))),
            // A package started in dormant mode can expose only health and
            // attestation.  It cannot execute a financial request, so its
            // predeclared local directory is safe for sealed-epoch recovery.
            // An enabled writer must always use the immutable S3/Object-Lock
            // archive below.
            Ok("filesystem") if local_filesystem_permitted => {
                Ok(env::var("LAYRS_DIRECT_ARTIFACT_DIR")
                    .ok()
                    .filter(|value| !value.is_empty())
                    .map(PathBuf::from)
                    .map(FilesystemImmutableArtifactStore::new)
                    .map(Self::Filesystem))
            }
            Ok("filesystem") => {
                Err("filesystem archive is prohibited outside isolated test".into())
            }
            Ok(_) => Err("invalid direct archive backend".into()),
            Err(_) if local_filesystem_permitted => Ok(env::var("LAYRS_DIRECT_ARTIFACT_DIR")
                .ok()
                .filter(|value| !value.is_empty())
                .map(PathBuf::from)
                .map(FilesystemImmutableArtifactStore::new)
                .map(Self::Filesystem)),
            Err(_) => Err("production direct archive backend is required".into()),
        }
    }
    async fn persist_readback(
        &self,
        artifact: &DirectStateArtifact,
    ) -> Result<DirectStateArtifact, String> {
        match self {
            Self::Filesystem(store) => store
                .persist_readback(artifact)
                .map_err(|error| error.to_string()),
            Self::S3(store) => store.persist_readback(artifact).await,
        }
    }
    async fn load_committed(&self) -> Result<Vec<DirectStateArtifact>, String> {
        match self {
            Self::Filesystem(store) => store.load_committed().map_err(|error| error.to_string()),
            Self::S3(store) => store.load_committed().await,
        }
    }
    async fn receipt_sequence(&self, receipt: &DirectReceipt) -> Result<i64, ProjectionError> {
        match self {
            Self::S3(store) => {
                let records = store.verified_receipt_records.lock().await;
                verified_receipt_sequence(records.as_deref().ok_or(ProjectionError::Database)?, receipt)
            }
            Self::Filesystem(store) => verified_receipt_sequence(
                &store.load_committed().map_err(|_| ProjectionError::Database)?, receipt),
        }
    }
    async fn persist_intent_readback(
        &self,
        intent: &ExternalEffectIntent,
    ) -> Result<ExternalEffectIntent, String> {
        match self {
            Self::Filesystem(store) => {
                FilesystemImmutableIntentStore::new(store.root().join("external-effect-intents"))
                    .put_if_absent_readback(intent)
                    .map_err(|error| error.to_string())
            }
            Self::S3(store) => store.persist_intent_readback(intent).await,
        }
    }
    async fn load_intents(&self) -> Result<Vec<ExternalEffectIntent>, String> {
        match self {
            Self::Filesystem(store) => {
                FilesystemImmutableIntentStore::new(store.root().join("external-effect-intents"))
                    .load_all()
                    .map_err(|error| error.to_string())
            }
            Self::S3(store) => store.load_intents().await,
        }
    }

    async fn persist_extra_payout(&self, evidence: &ExtraPayoutEvidence) -> Result<(), String> {
        let bytes = serde_json::to_vec(evidence).map_err(|_| "extra payout evidence encoding failed")?;
        match self {
            Self::S3(store) => store.write_once(&format!("{}/external-effect-reconciliations/{}.json", store.prefix, evidence.intent_hash), bytes).await,
            Self::Filesystem(store) => {
                let directory = store.root().join("external-effect-reconciliations");
                fs::create_dir_all(&directory).map_err(|_| "extra payout directory unavailable")?;
                let path = directory.join(format!("{}.json", evidence.intent_hash));
                match OpenOptions::new().write(true).create_new(true).open(&path) {
                    Ok(mut file) => {
                        std::io::Write::write_all(&mut file, &bytes).and_then(|_| file.sync_all()).map_err(|_| "extra payout evidence persistence failed")?;
                    }
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {},
                    Err(_) => return Err("extra payout evidence persistence failed".into()),
                }
                if fs::read(path).map_err(|_| "extra payout readback failed")? != bytes { return Err("extra payout immutable evidence conflict".into()); }
                Ok(())
            }
        }
    }
    async fn load_key_release(
        &self,
        activation_id: &str,
    ) -> Result<Option<GovernedKeyReleaseArtifact>, String> {
        match self {
            Self::Filesystem(store) => {
                let path = store
                    .root()
                    .join("authorization")
                    .join(format!("{activation_id}.cbor"));
                match fs::read(path) {
                    Ok(bytes) => serde_cbor::from_slice(&bytes)
                        .map(Some)
                        .map_err(|_| "key-release artifact decode failed".into()),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
                    Err(_) => Err("key-release artifact read failed".into()),
                }
            }
            Self::S3(store) => store.load_key_release(activation_id).await,
        }
    }
    async fn persist_key_release(
        &self,
        artifact: &GovernedKeyReleaseArtifact,
    ) -> Result<GovernedKeyReleaseArtifact, String> {
        match self {
            Self::Filesystem(store) => {
                let directory = store.root().join("authorization");
                fs::create_dir_all(&directory).map_err(|_| "key-release directory unavailable")?;
                let path = directory.join(format!("{}.cbor", artifact.activation_id));
                let bytes = serde_cbor::to_vec(artifact)
                    .map_err(|_| "key-release artifact encoding failed")?;
                match OpenOptions::new().create_new(true).write(true).open(&path) {
                    Ok(mut file) => {
                        std::io::Write::write_all(&mut file, &bytes)
                            .and_then(|_| file.sync_all())
                            .map_err(|_| "key-release artifact write failed")?;
                    }
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(_) => return Err("key-release artifact immutable write failed".into()),
                }
                let restored: GovernedKeyReleaseArtifact = serde_cbor::from_slice(
                    &fs::read(path).map_err(|_| "key-release artifact readback failed")?,
                )
                .map_err(|_| "key-release artifact decode failed")?;
                if restored != *artifact {
                    return Err("key-release artifact conflict".into());
                }
                Ok(restored)
            }
            Self::S3(store) => store.persist_key_release(artifact).await,
        }
    }
}

fn receipt_only_record(artifact:&DirectStateArtifact)->DirectStateArtifact {
    let mut record=artifact.clone();
    // clear() leaves the entire snapshot allocation alive. This cache is only
    // receipt metadata; release the encrypted snapshot allocation completely.
    record.ciphertext=Vec::new();
    record
}

impl S3ImmutableArtifactStore {
    async fn from_environment() -> Result<Self, Box<dyn std::error::Error>> {
        let bucket = env::var("LAYRS_DIRECT_ARCHIVE_BUCKET")?;
        let prefix = env::var("LAYRS_DIRECT_ARCHIVE_PREFIX")?;
        let kms_key_id = env::var("LAYRS_DIRECT_ARCHIVE_KMS_KEY_ID")?;
        let retention_seconds =
            env::var("LAYRS_DIRECT_ARCHIVE_RETENTION_SECONDS")?.parse::<i64>()?;
        if bucket.is_empty()
            || prefix.is_empty()
            || kms_key_id.is_empty()
            || retention_seconds < 86_400
        {
            return Err("invalid immutable archive configuration".into());
        }
        let client =
            S3Client::new(&aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await);
        client
            .get_object_lock_configuration()
            .bucket(&bucket)
            .send()
            .await?;
        Ok(Self {
            client,
            bucket,
            prefix: prefix.trim_end_matches('/').into(),
            kms_key_id,
            retention_seconds,
            verified_receipt_records: Arc::new(Mutex::new(None)),
        })
    }
    fn artifact_key(&self, artifact: &DirectStateArtifact) -> String {
        format!(
            "{}/artifacts/{:020}-{}.cbor",
            self.prefix,
            artifact.sequence,
            artifact_hash(artifact)
        )
    }
    fn head_key(&self, artifact: &DirectStateArtifact) -> String {
        format!(
            "{}/heads/{:020}-{}.cbor",
            self.prefix,
            artifact.sequence,
            artifact_hash(artifact)
        )
    }
    fn intent_key(&self, intent: &ExternalEffectIntent) -> String {
        format!(
            "{}/external-effect-intents/{}.cbor",
            self.prefix, intent.intent_hash
        )
    }
    fn key_release_key(&self, activation_id: &str) -> String {
        format!("{}/authorization/{}.cbor", self.prefix, activation_id)
    }
    async fn read(&self, key: &str) -> Result<Vec<u8>, String> {
        // SDK request retries do not retry a response stream after headers.
        // Discard an incomplete body and GET the same immutable key again;
        // no partial bytes ever reach the encrypted successor verifier.
        for attempt in 0..5 {
            let result=timeout(Duration::from_secs(60),async {
                let response=self.client.get_object().bucket(&self.bucket).key(key)
                    .send().await.map_err(|_|"archive read failed")?;
                let length=response.content_length.filter(|length|*length>0 && *length<=MAX_FRAME_BYTES as i64)
                    .ok_or("archive read size invalid")?;
                let bytes=response.body.collect().await.map_err(|_|"archive read body failed")?.into_bytes();
                if bytes.len()!=length as usize {return Err("archive read body length mismatch");}
                Ok(bytes.to_vec())
            }).await;
            if let Ok(Ok(bytes))=result {return Ok(bytes);}
            if attempt<4 {
                eprintln!("ARCHIVE_READ_RETRY {}/5",attempt+2);
                tokio::time::sleep(Duration::from_millis(100u64<<attempt)).await;
            }
        }
        Err("archive complete read retries exhausted".into())
    }
    async fn write_once(&self, key: &str, bytes: Vec<u8>) -> Result<(), String> {
        let until = DateTime::from_secs(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| "clock invalid")?
                .as_secs() as i64
                + self.retention_seconds,
        );
        let put = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(ByteStream::from(bytes.clone()))
            .if_none_match("*")
            .server_side_encryption(ServerSideEncryption::AwsKms)
            .ssekms_key_id(&self.kms_key_id)
            .object_lock_mode(ObjectLockMode::Compliance)
            .object_lock_retain_until_date(until)
            .send()
            .await;
        if put.is_err() && self.read(key).await? != bytes {
            return Err("archive immutable write failed".into());
        }
        if self.read(key).await? != bytes {
            return Err("archive readback mismatch".into());
        }
        Ok(())
    }
    async fn persist_readback(
        &self,
        artifact: &DirectStateArtifact,
    ) -> Result<DirectStateArtifact, String> {
        let bytes = serde_cbor::to_vec(artifact).map_err(|_| "artifact encoding failed")?;
        self.write_once(&self.artifact_key(artifact), bytes.clone())
            .await?;
        self.write_once(&self.head_key(artifact), bytes).await?;
        let restored: DirectStateArtifact =
            serde_cbor::from_slice(&self.read(&self.artifact_key(artifact)).await?)
                .map_err(|_| "artifact decode failed")?;
        if restored != *artifact || artifact_hash(&restored) != artifact_hash(artifact) {
            return Err("artifact integrity mismatch".into());
        }
        if let Some(records)=self.verified_receipt_records.lock().await.as_mut() {
            if !records.iter().any(|record|record.sequence==artifact.sequence) {
                records.push(receipt_only_record(&restored));
            }
        }
        Ok(restored)
    }
    async fn load_committed(&self) -> Result<Vec<DirectStateArtifact>, String> {
        self.verified_receipt_records.lock().await.clone().ok_or("verified archive receipt cache unavailable".into())
    }
    async fn list_restore_keys(&self,namespace:&str)->Result<Vec<String>,String> {
        let mut token=None;let mut seen_tokens=HashSet::new();let mut keys=Vec::new();
        loop {
            let page=self.client.list_objects_v2().bucket(&self.bucket).prefix(format!("{}/{namespace}/",self.prefix)).set_continuation_token(token).send().await.map_err(|_|"archive listing failed")?;
            for object in page.contents(){keys.push(object.key().ok_or("archive object key missing")?.to_string());}
            if keys.len()>100_000 {return Err("archive exceeds finite restore bound".into());}
            if !page.is_truncated.unwrap_or(false){break;}
            let next=page.next_continuation_token().filter(|s|!s.is_empty()).ok_or("archive pagination token missing")?.to_string();
            if !seen_tokens.insert(next.clone()){return Err("archive pagination token repeated".into());}token=Some(next);
        }
        keys.sort();if keys.windows(2).any(|pair|pair[0]==pair[1]){return Err("archive duplicate key".into());}Ok(keys)
    }
    async fn restore_streamed(&self,state:&AppState)->Result<(),String> {
        let keys=self.list_restore_keys("artifacts").await?;
        let heads=self.list_restore_keys("heads").await?;
        if keys.len()!=heads.len(){return Err("archive artifact/head count mismatch".into());}
        let begin=exchange(state,RuntimeRequest::BeginCommittedRestore).await.map_err(|_|"restore begin transport failed")?;
        let RuntimeResponse::RestoreProgress {recovered_sequence:0,recovered_state_hash:mut root}=begin else {return Err("restore begin rejected".into());};
        let mut records=Vec::with_capacity(keys.len());
        for (index,key) in keys.iter().enumerate(){
            let bytes=self.read(key).await?;
            let artifact:DirectStateArtifact=serde_cbor::from_slice(&bytes).map_err(|_|"artifact decode failed")?;
            if artifact.sequence!=index as u64+1 || artifact.prior_state_hash!=root || key!=&self.artifact_key(&artifact) || heads[index]!=self.head_key(&artifact) || self.read(&heads[index]).await?!=bytes {return Err("archive encrypted successor/head mismatch".into());}
            root=artifact.state_hash.clone();let sequence=artifact.sequence;
            records.push(receipt_only_record(&artifact));
            let response=exchange(state,RuntimeRequest::AppendCommittedRestore {artifact}).await.map_err(|_|"restore successor transport failed")?;
            if !matches!(response,RuntimeResponse::RestoreProgress {recovered_sequence,recovered_state_hash} if recovered_sequence==sequence && recovered_state_hash==root){return Err("restore encrypted successor rejected".into());}
            if sequence%250==0 {eprintln!("VERIFIED_ARCHIVE_RESTORE_PROGRESS {sequence}/{}",keys.len());}
        }
        let result=exchange(state,RuntimeRequest::FinishCommittedRestore {expected_sequence:keys.len() as u64,expected_state_hash:root.clone()}).await.map_err(|_|"restore finish transport failed")?;
        if !matches!(result,RuntimeResponse::RecoveryComplete {recovered_sequence,recovered_state_hash} if recovered_sequence==keys.len() as u64 && recovered_state_hash==root){return Err("restore final encrypted head rejected".into());}
        *self.verified_receipt_records.lock().await=Some(records);
        *state.committed_state_root.lock().await=Some(root);
        eprintln!("VERIFIED_ARCHIVE_RESTORE_COMPLETE {}",keys.len());Ok(())
    }
    async fn persist_intent_readback(
        &self,
        intent: &ExternalEffectIntent,
    ) -> Result<ExternalEffectIntent, String> {
        intent
            .verify()
            .map_err(|_| "external-effect intent invalid")?;
        let bytes =
            serde_cbor::to_vec(intent).map_err(|_| "external-effect intent encoding failed")?;
        let key = self.intent_key(intent);
        self.write_once(&key, bytes.clone()).await?;
        let restored: ExternalEffectIntent = serde_cbor::from_slice(&self.read(&key).await?)
            .map_err(|_| "external-effect intent decode failed")?;
        if restored != *intent {
            return Err("external-effect intent readback mismatch".into());
        }
        restored
            .verify()
            .map_err(|_| "external-effect intent integrity mismatch")?;
        Ok(restored)
    }
    async fn load_intents(&self) -> Result<Vec<ExternalEffectIntent>, String> {
        let listing = self
            .client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(format!("{}/external-effect-intents/", self.prefix))
            .send()
            .await
            .map_err(|_| "external-effect intent listing failed")?;
        if listing.is_truncated.unwrap_or(false) {
            return Err("external-effect intent listing exceeds bounded recovery set".into());
        }
        let mut intents = std::collections::BTreeMap::new();
        for object in listing.contents() {
            let key = object.key().ok_or("external-effect intent key missing")?;
            let intent: ExternalEffectIntent = serde_cbor::from_slice(&self.read(key).await?)
                .map_err(|_| "external-effect intent decode failed")?;
            intent
                .verify()
                .map_err(|_| "external-effect intent integrity mismatch")?;
            if key != self.intent_key(&intent)
                || intents.insert(intent.intent_hash.clone(), intent).is_some()
            {
                return Err("duplicate or conflicting external-effect intent".into());
            }
        }
        Ok(intents.into_values().collect())
    }
    async fn load_key_release(
        &self,
        activation_id: &str,
    ) -> Result<Option<GovernedKeyReleaseArtifact>, String> {
        let key = self.key_release_key(activation_id);
        let listing = self
            .client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(&key)
            .send()
            .await
            .map_err(|_| "key-release artifact listing failed")?;
        let matching: Vec<_> = listing
            .contents()
            .iter()
            .filter(|object| object.key() == Some(key.as_str()))
            .collect();
        if matching.is_empty() {
            return Ok(None);
        }
        if matching.len() != 1 {
            return Err("duplicate key-release artifacts".into());
        }
        serde_cbor::from_slice(&self.read(&key).await?)
            .map(Some)
            .map_err(|_| "key-release artifact decode failed".into())
    }
    async fn persist_key_release(
        &self,
        artifact: &GovernedKeyReleaseArtifact,
    ) -> Result<GovernedKeyReleaseArtifact, String> {
        let key = self.key_release_key(&artifact.activation_id);
        let bytes =
            serde_cbor::to_vec(artifact).map_err(|_| "key-release artifact encoding failed")?;
        self.write_once(&key, bytes).await?;
        let restored: GovernedKeyReleaseArtifact = serde_cbor::from_slice(&self.read(&key).await?)
            .map_err(|_| "key-release artifact decode failed")?;
        if restored != *artifact || restored.artifact_hash() != artifact.artifact_hash() {
            return Err("key-release artifact readback mismatch".into());
        }
        Ok(restored)
    }
}

#[derive(Clone)]
struct Projection {
    client: Arc<Mutex<Client>>,
}
#[derive(Deserialize)]
struct AttestationQuery {
    nonce: String,
}
#[derive(Deserialize)]
struct BalanceQuery {
    bucket: Option<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CustomerCommand {
    identity_commitment: String,
    action: CustomerAction,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MarketRegistrationCommand {
    registration: GovernedMarketRegistration,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MarketResolutionCommand {
    resolution: GovernedMarketResolution,
}
#[derive(Deserialize)]
#[serde(
    tag = "type",
    rename_all = "SCREAMING_SNAKE_CASE",
    rename_all_fields = "camelCase"
)]
enum CustomerAction {
    CreditDeposit {
        transaction_hash: String,
        amount_atomic: String,
    },
    CreditZenDeposit { transaction_hash: String, amount_atomic: String },
    ReserveZenWithdrawal { destination_chain: String, destination: String, amount_atomic: String },
    PlaceOrder {
        order_id: String,
        market_id: String,
        outcome: Outcome,
        action: OrderAction,
        price_micros: u64,
        quantity_micros: String,
        time_in_force: TimeInForce,
        expires_at_millis: Option<i64>,
        now_millis: i64,
    },
    CancelOrder {
        order_id: String,
    },
    ReserveWithdrawal {
        destination: String,
        amount_atomic: String,
        #[serde(default)]
        relay_route: Option<RelayWithdrawalBinding>,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionClaims {
    /// Identifier generated by the Privy-verifying BFF.  It is command scoped
    /// and persisted for replay detection; it is never a raw Privy ID.
    session_id: String,
    subject_hash: String,
    privy_user_id_hash: String,
    audience: String,
    epoch_id: String,
    epoch_state_sha256: String,
    /// Privy's embedded wallet remains an authentication/identity binding
    /// only. For a direct Base withdrawal, the BFF copies the independently
    /// customer-provided destination into this signed field without requiring
    /// ownership proof. The parent requires it to equal the action destination
    /// so a signed session for destination A cannot authorize destination B.
    wallet_address: String,
    #[serde(default)]
    financial_wallet_address: Option<String>,
    identity_commitment: String,
    expires_at_unix: u64,
    response_key: String,
    signature: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EncryptedResponse {
    algorithm: &'static str,
    nonce: String,
    ciphertext: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let epoch = SealedEpoch::load_with_evidence(
        env::var("LAYRS_OPENING_EPOCH_PATH")?,
        env::var("LAYRS_OPENING_EVIDENCE_PATH")?,
    )?;
    let session_key = env::var("LAYRS_DIRECT_SESSION_HMAC_KEY_HEX")
        .ok()
        .and_then(|value| hex::decode(value).ok())
        .filter(|key| key.len() >= 32)
        .or_else(|| {
            // The direct BFF and parent already require the existing Privy app
            // secret.  A domain-separated derivation avoids minting or
            // repurposing another operational key, and binds assertions to
            // this runtime's fixed opening epoch.  The parent never receives
            // raw Privy JWTs.
            env::var("LAYRSV2_PRIVY_APP_SECRET")
                .ok()
                .filter(|secret| secret.len() >= 32)
                .map(|secret| derive_direct_session_key(secret.as_bytes()))
        })
        // A dormant image can answer health, status, and attestation without a
        // session secret. Customer routes fail closed until an isolated test or
        // later governed activation injects the BFF verification key.
        .unwrap_or_default();
    let isolated_test = env::var("LAYRS_DIRECT_ISOLATED_TEST").as_deref() == Ok("true");
    let execution_mode = env::var("LAYRS_DIRECT_EXECUTION_MODE").ok();
    let dormant = matches!(execution_mode.as_deref(), None | Some("dormant"));
    let financial_enabled = execution_mode.as_deref() == Some("production-enabled");
    let projection = match env::var("LAYRS_DIRECT_PROJECTION_DATABASE_URL") {
        Ok(url) => Some(Projection::connect(&url, &epoch, isolated_test).await?),
        // This is restricted to a named isolated-package fixture.  It permits
        // the parent/enclave/artifact restart test to run without inventing a
        // second database fixture; production always requires its projection.
        Err(_)
            if isolated_test
                && env::var("LAYRS_DIRECT_ISOLATED_NO_PROJECTION").as_deref() == Ok("true") =>
        {
            None
        }
        Err(_) if isolated_test => {
            return Err("isolated direct execution requires an isolated projection database".into())
        }
        Err(_) => None,
    };
    let governed_bootstrap = if matches!(
        execution_mode.as_deref(),
        Some("admission-enabled" | "production-enabled")
    ) {
        let grant: WriterGrant = env::var("LAYRS_DIRECT_WRITER_GRANT_JSON")
            .ok()
            .and_then(|value| serde_json::from_str(&value).ok())
            .ok_or("production writer grant is required")?;
        let binding: RuntimeMeasurementBinding =
            env::var("LAYRS_DIRECT_APPROVED_RUNTIME_BINDING_JSON")
                .ok()
                .and_then(|value| serde_json::from_str(&value).ok())
                .ok_or("approved runtime binding is required")?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_secs())
            .unwrap_or(0);
        if !grant.verify(now, &binding) {
            return Err("production writer grant signature is invalid".into());
        }
        let kms_key_id = env::var("LAYRS_DIRECT_KEY_RELEASE_KMS_KEY_ID")
            .map_err(|_| "production key-release KMS reference is required")?;
        if kms_key_id != grant.key_release_kms_key_id {
            return Err("production key-release KMS reference mismatch".into());
        }
        projection
            .as_ref()
            .ok_or("production projection is required")?
            .verify_governed_runtime_mode(&grant, financial_enabled)
            .await
            .map_err(|_| "runtime authorization and writer fence verification failed")?;
        Some(GovernedBootstrapConfig {
            grant,
            binding,
            kms_key_id,
            requested_mode: execution_mode.clone().unwrap_or_default(),
        })
    } else {
        None
    };
    let state = AppState {
        enclave_cid: env::var("LAYRS_ENCLAVE_CID")
            .unwrap_or_else(|_| "16".into())
            .parse()?,
        session_key: session_key.clone(),
        isolated_test,
        projection,
        local_used_sessions: Arc::new(Mutex::new(HashSet::new())),
        // Filesystem storage is accepted only for an explicitly isolated test
        // or a dormant package.  The production-enabled path remains S3 with
        // Object Lock and KMS only.
        artifact_store: ArchiveStore::from_environment(isolated_test || dormant).await?,
        commit_ack_key: env::var("LAYRS_DIRECT_COMMIT_ACK_KEY_HEX")
            .ok()
            .and_then(|value| hex::decode(value).ok())
            .filter(|value| value.len() == 32)
            .unwrap_or_default(),
        // A read-only runtime must not construct a custody adapter at all.
        // This removes both execution capability and any reason to load an
        // operational payout signer before the separately governed canary.
        custody: if financial_enabled {
            PrivyBaseCustodyAdapter::from_environment()
                .map_err(|error| format!("direct custody configuration invalid: {error}"))?
        } else {
            None
        },
        zen_custody: if financial_enabled {
            ZenCustodyAdapter::from_environment(&session_key).map_err(|error| format!("ZEN custody configuration invalid:{error}"))?
        } else { None },
        financial_gate: Arc::new(Mutex::new(())),
        committed_state_root: Arc::new(Mutex::new(None)),
        unresolved_external_effects: Arc::new(Mutex::new(BTreeMap::new())),
        governed_bootstrap,
    };
    // A Nitro EIF does not inherit the parent's systemd environment.  The
    // isolated test key material therefore crosses the existing VSOCK channel
    // once, before recovery; production never uses this bootstrap.
    bootstrap_isolated_enclave(&state).await?;
    bootstrap_governed_enclave(&state).await?;
    // The HTTP parent never accepts a financial command until it has supplied
    // the immutable archive's complete, head-verified recovery set and the
    // enclave has independently reconstructed it.  PostgreSQL is excluded.
    recover_enclave(&state).await?;
    // Reconciliation starts only after the old projection is proven equal to
    // the fully recovered private state, not from database balance guesses.
    verify_recovered_projection(&state).await?;
    recover_external_effect_intents(&state).await?;
    verify_recovered_projection(&state).await?;
    let port = env::var("PORT").unwrap_or_else(|_| "8443".into()).parse()?;
    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/attestation", get(attestation))
        .route("/v1/runtime/status", get(status))
        .route("/v1/operator/markets", post(register_market))
        .route("/v1/operator/markets/resolve", post(resolve_market))
        .route("/v1/operator/markets/:market_id", get(market_status))
        .route(
            "/v1/operator/balance-recoveries",
            post(apply_balance_recovery),
        )
        .route("/v1/direct/admissions", post(admit_identity))
        .route("/v1/direct/commands", post(command))
        .route("/v1/direct/balances/:identity", get(balance))
        .route("/v1/direct/portfolio/:identity", get(portfolio))
        .with_state(state);
    // The packaged and dormant runtime is loopback-only.  A governed BFF
    // deployment may opt in to a VPC listener only when production mode is
    // explicitly enabled; its security group is the other enforcement layer.
    let bind_address = runtime_bind_address(
        env::var("LAYRS_DIRECT_BIND_ADDRESS").ok().as_deref(),
        env::var("LAYRS_DIRECT_EXECUTION_MODE").ok().as_deref(),
        env::var("LAYRS_DIRECT_READ_ONLY_VPC_BIND").as_deref() == Ok("true"),
    )?;
    let listener = tokio::net::TcpListener::bind((bind_address, port)).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn derive_direct_session_key(privy_app_secret: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(privy_app_secret)
        .expect("HMAC accepts arbitrary key material");
    mac.update(DIRECT_SESSION_KEY_DERIVATION_DOMAIN);
    mac.update(EPOCH_ID.as_bytes());
    mac.update(&[0]);
    mac.update(layrs_direct_execution_v1::EPOCH_STATE_SHA256.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

fn runtime_bind_address(
    requested: Option<&str>,
    mode: Option<&str>,
    read_only_vpc_bind: bool,
) -> Result<IpAddr, &'static str> {
    let address = requested
        .unwrap_or("127.0.0.1")
        .parse::<IpAddr>()
        .map_err(|_| "invalid direct runtime bind address")?;
    // The governed read-only BFF needs a VPC path to obtain encrypted balance
    // responses.  It is explicitly limited to a dormant enclave: direct
    // execution rejects every mutation before a candidate, custody call, or
    // artifact can be created.  Any writable listener still requires the
    // WriterGrant-gated production-enabled mode.
    let read_only_listener = mode == Some("dormant") && read_only_vpc_bind;
    if !address.is_loopback()
        && !matches!(mode, Some("admission-enabled" | "production-enabled"))
        && !read_only_listener
    {
        return Err("non-loopback direct runtime listener requires production-enabled mode");
    }
    Ok(address)
}

fn direct_writer_route_enabled(isolated_test: bool, mode: Option<&str>) -> bool {
    isolated_test || mode == Some("production-enabled")
}

fn direct_admission_route_enabled(isolated_test: bool, mode: Option<&str>) -> bool {
    isolated_test || matches!(mode, Some("admission-enabled" | "production-enabled"))
}

async fn attestation(
    State(state): State<AppState>,
    Query(query): Query<AttestationQuery>,
) -> impl IntoResponse {
    let nonce = match URL_SAFE_NO_PAD.decode(query.nonce) {
        Ok(value) if (16..=512).contains(&value.len()) => value,
        _ => return (StatusCode::BAD_REQUEST, "INVALID_NONCE").into_response(),
    };
    let request_nonce = URL_SAFE_NO_PAD.encode(&nonce);
    match exchange(&state, RuntimeRequest::Attestation { nonce }).await {
        Ok(RuntimeResponse::Attestation {
            document,
            binding,
            binding_commitment,
        }) => Json(serde_json::json!({
            "attestationDocument": URL_SAFE_NO_PAD.encode(document),
            "requestNonce": request_nonce,
            "binding": binding,
            "bindingCommitmentSha256": hex::encode(binding_commitment),
        }))
        .into_response(),
        Ok(RuntimeResponse::Error { code }) => (StatusCode::BAD_GATEWAY, code).into_response(),
        _ => (StatusCode::BAD_GATEWAY, "UNEXPECTED_RESPONSE").into_response(),
    }
}
async fn status(State(state): State<AppState>) -> impl IntoResponse {
    match exchange(&state, RuntimeRequest::Status).await {
        Ok(RuntimeResponse::Status { status }) => Json(status).into_response(),
        Ok(RuntimeResponse::Error { code }) => (StatusCode::BAD_GATEWAY, code).into_response(),
        _ => (StatusCode::BAD_GATEWAY, "UNEXPECTED_RESPONSE").into_response(),
    }
}
async fn command(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CustomerCommand>,
) -> impl IntoResponse {
    let claims = match authenticated(&headers, &state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    // Do not let a read-only deployment reach candidate creation, custody, or
    // archive persistence merely because a BFF can reach its VPC listener.
    // Dormant state remains independently enforced inside the enclave.
    if !direct_writer_route_enabled(
        state.isolated_test,
        env::var("LAYRS_DIRECT_EXECUTION_MODE").ok().as_deref(),
    ) {
        return (StatusCode::SERVICE_UNAVAILABLE, "WRITER_DISABLED").into_response();
    }
    let request_id = match headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty() && value.len() <= 200)
    {
        Some(value) => value.to_string(),
        None => return (StatusCode::BAD_REQUEST, "IDEMPOTENCY_KEY_REQUIRED").into_response(),
    };
    if body.identity_commitment != claims.identity_commitment {
        return (StatusCode::FORBIDDEN, "DIRECT_IDENTITY_BINDING_DENIED").into_response();
    }
    let _financial_guard = state.financial_gate.lock().await;
    let external_effect_pending = !state.unresolved_external_effects.lock().await.is_empty();
    let action = match body.action {
        CustomerAction::CreditZenDeposit { transaction_hash, amount_atomic } if !external_effect_pending => {
            let Some(source) = claims.financial_wallet_address.as_deref() else {return (StatusCode::FORBIDDEN,"DIRECT_FINANCIAL_WALLET_REQUIRED").into_response();};
            let hash = transaction_hash.to_ascii_lowercase();
            let reference = format!("horizen-zen-deposit:{hash}");
            if request_id != reference {return (StatusCode::BAD_REQUEST,"DEPOSIT_IDEMPOTENCY_KEY_MISMATCH").into_response();}
            let Some(custody) = &state.zen_custody else {return (StatusCode::SERVICE_UNAVAILABLE,"ZEN_CUSTODY_ADAPTER_NOT_ENABLED").into_response();};
            match custody.deposit_finality(source,&hash,&amount_atomic).await {
                Ok(DepositFinality::Finalized) => DirectAction::CreditZenDeposit {amount_atomic,custody_reference:reference},
                Ok(DepositFinality::Pending) => return (StatusCode::SERVICE_UNAVAILABLE,"DEPOSIT_FINALITY_PENDING").into_response(),
                Ok(DepositFinality::Reverted | DepositFinality::Conflict) => return (StatusCode::CONFLICT,"DEPOSIT_TRANSACTION_BINDING_CONFLICT").into_response(),
                Err(_) => return (StatusCode::SERVICE_UNAVAILABLE,"DEPOSIT_FINALITY_UNAVAILABLE").into_response(),
            }
        }
        CustomerAction::CreditZenDeposit {..} => return (StatusCode::SERVICE_UNAVAILABLE,"EXTERNAL_EFFECT_FINALITY_PENDING").into_response(),
        CustomerAction::ReserveZenWithdrawal {destination_chain,destination,amount_atomic} => {
            if !matches!(destination_chain.as_str(),"base"|"horizen") {return (StatusCode::BAD_REQUEST,"ZEN_ROUTE_UNSUPPORTED").into_response();}
            if !claims.financial_wallet_address.as_deref().is_some_and(|signed| signed_base_withdrawal_destination_matches(&destination,signed)) {return (StatusCode::FORBIDDEN,"SIGNED_WITHDRAWAL_DESTINATION_MISMATCH").into_response();}
            match prepare_zen_withdrawal(&state,&claims,&body.identity_commitment,&request_id,destination_chain,destination,amount_atomic).await {
                Ok(action)=>action,Err((status,code))=>return (status,code).into_response(),
            }
        }
        CustomerAction::CreditDeposit {
            transaction_hash,
            amount_atomic,
        } if !external_effect_pending => {
            let Some(financial_wallet_address) = claims.financial_wallet_address.as_deref() else {
                return (StatusCode::FORBIDDEN, "DIRECT_FINANCIAL_WALLET_REQUIRED").into_response();
            };
            let canonical_hash = transaction_hash.to_ascii_lowercase();
            let required_request_id = format!("base-deposit:{canonical_hash}");
            if request_id != required_request_id {
                return (StatusCode::BAD_REQUEST, "DEPOSIT_IDEMPOTENCY_KEY_MISMATCH")
                    .into_response();
            }
            let Some(custody) = &state.custody else {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CUSTODY_ADAPTER_NOT_ENABLED",
                )
                    .into_response();
            };
            match custody
                .deposit_finality(financial_wallet_address, &canonical_hash, &amount_atomic)
                .await
            {
                Ok(DepositFinality::Finalized) => DirectAction::CreditDeposit {
                    amount_atomic,
                    custody_reference: required_request_id,
                },
                Ok(DepositFinality::Pending) => {
                    return (StatusCode::SERVICE_UNAVAILABLE, "DEPOSIT_FINALITY_PENDING")
                        .into_response()
                }
                Ok(DepositFinality::Reverted) => {
                    return (
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "DEPOSIT_TRANSACTION_REVERTED",
                    )
                        .into_response()
                }
                Ok(DepositFinality::Conflict) => {
                    return (StatusCode::CONFLICT, "DEPOSIT_TRANSACTION_BINDING_CONFLICT")
                        .into_response()
                }
                Err(_) => {
                    return (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "DEPOSIT_FINALITY_UNAVAILABLE",
                    )
                        .into_response()
                }
            }
        }
        CustomerAction::CreditDeposit { .. } => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "EXTERNAL_EFFECT_FINALITY_PENDING",
            )
                .into_response()
        }
        CustomerAction::PlaceOrder {
            order_id,
            market_id,
            outcome,
            action,
            price_micros,
            quantity_micros,
            time_in_force,
            expires_at_millis,
            now_millis,
        } if !external_effect_pending => DirectAction::PlaceOrder {
            order_id,
            market_id,
            outcome,
            action,
            price_micros,
            quantity_micros,
            time_in_force,
            expires_at_millis,
            now_millis,
        },
        CustomerAction::CancelOrder { order_id } if !external_effect_pending => {
            DirectAction::CancelOrder { order_id }
        }
        CustomerAction::PlaceOrder { .. } | CustomerAction::CancelOrder { .. } => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "EXTERNAL_EFFECT_FINALITY_PENDING",
            )
                .into_response()
        }
        CustomerAction::ReserveWithdrawal {
            destination,
            amount_atomic,
            relay_route,
        } => {
            if let Some(relay) = relay_route.as_ref() {
                if !destination.eq_ignore_ascii_case(&relay.deposit_address)
                    || relay.verify(&amount_atomic).is_err()
                {
                    return (StatusCode::CONFLICT, "INVALID_RELAY_WITHDRAWAL_BINDING")
                        .into_response();
                }
            } else {
                // A direct Base withdrawal may target any syntactically valid
                // customer-provided address. The BFF signs that exact value
                // into the session and the action/intent bind it again. Privy
                // neither selects nor restricts the destination.
                let Some(signed_destination) = claims.financial_wallet_address.as_deref() else {
                    return (
                        StatusCode::FORBIDDEN,
                        "SIGNED_WITHDRAWAL_DESTINATION_REQUIRED",
                    )
                        .into_response();
                };
                if !signed_base_withdrawal_destination_matches(&destination, signed_destination) {
                    return (
                        StatusCode::FORBIDDEN,
                        "SIGNED_WITHDRAWAL_DESTINATION_MISMATCH",
                    )
                        .into_response();
                }
            }
            match prepare_external_withdrawal(
                &state,
                &claims,
                &body.identity_commitment,
                &request_id,
                destination,
                amount_atomic,
                relay_route,
            )
            .await
            {
                Ok(action) => action,
                Err((status, code)) => return (status, code).into_response(),
            }
        }
    };
    let mut request = DirectRequest {
        account_id: claims.subject_hash.clone(),
        identity_commitment: body.identity_commitment,
        request_id,
        request_hash: String::new(),
        financial_wallet_address: claims.financial_wallet_address.clone(),
        action,
    };
    request.request_hash = request_hash(&request);
    match exchange_direct(&state, request).await {
        Ok(RuntimeResponse::Execute { result }) => {
            // Session consumption is projection/audit only and happens after
            // authoritative adoption.  A crash after external submission can
            // therefore be recovered from the immutable intent rather than a
            // PostgreSQL session row.
            if let Some(projection) = &state.projection {
                if projection
                    .consume_session(&claims, &result.receipt.request_hash)
                    .await
                    .is_err()
                {
                    return (StatusCode::SERVICE_UNAVAILABLE, "PROJECTION_UNAVAILABLE")
                        .into_response();
                }
            } else if !state.isolated_test {
                return (StatusCode::SERVICE_UNAVAILABLE, "PROJECTION_NOT_CONFIGURED")
                    .into_response();
            } else {
                let mut used = state.local_used_sessions.lock().await;
                if used.iter().any(|(session_id, request_hash)| {
                    session_id == &claims.session_id && request_hash != &result.receipt.request_hash
                }) {
                    return (StatusCode::CONFLICT, "SESSION_REPLAY_REJECTED").into_response();
                }
                used.insert((
                    claims.session_id.clone(),
                    result.receipt.request_hash.clone(),
                ));
            }
            if let Some(projection) = &state.projection {
                if projection.record_result(&state, &result).await.is_err() {
                    return (StatusCode::SERVICE_UNAVAILABLE, "PROJECTION_UNAVAILABLE")
                        .into_response();
                }
            }
            // Retain both asset gates through private adoption AND atomic
            // projection; failures cannot open a second payout path.
            if matches!(result.receipt.effect.as_str(),"WITHDRAWAL_SETTLED"|"WITHDRAWAL_REVERTED") {
                state.unresolved_external_effects.lock().await.retain(|_, intent| !(intent.account_id == result.receipt.account_id
                    && intent.identity_commitment == result.receipt.identity_commitment && intent.request_id == result.receipt.request_id
                    && result.receipt.amount_atomic.as_deref() == Some(intent.amount_atomic.as_str())
                    && result.receipt.custody_reference.as_deref().is_some_and(|reference| reference.starts_with(&format!("{}:",intent.external_effect_reference)))));
            }
            encrypted(&claims, &result)
        }
        Ok(RuntimeResponse::Error { code }) => {
            (StatusCode::UNPROCESSABLE_ENTITY, code).into_response()
        }
        _ => (StatusCode::BAD_GATEWAY, "ENCLOSURE_UNAVAILABLE").into_response(),
    }
}

async fn admit_identity(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let claims = match authenticated(&headers, &state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    if !direct_admission_route_enabled(
        state.isolated_test,
        env::var("LAYRS_DIRECT_EXECUTION_MODE").ok().as_deref(),
    ) {
        return (StatusCode::SERVICE_UNAVAILABLE, "ADMISSION_DISABLED").into_response();
    }
    if claims.identity_commitment
        != identity_commitment_for(&claims.subject_hash, &claims.wallet_address)
    {
        return (StatusCode::FORBIDDEN, "DIRECT_IDENTITY_BINDING_DENIED").into_response();
    }
    let request_id = match headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty() && value.len() <= 200)
    {
        Some(value) => value.to_string(),
        None => return (StatusCode::BAD_REQUEST, "IDEMPOTENCY_KEY_REQUIRED").into_response(),
    };
    let _guard = state.financial_gate.lock().await;
    let mut request = DirectRequest {
        account_id: claims.subject_hash.clone(),
        identity_commitment: claims.identity_commitment.clone(),
        request_id,
        request_hash: String::new(),
        financial_wallet_address: None,
        action: DirectAction::AdmitIdentity {
            wallet_address: claims.wallet_address.clone(),
        },
    };
    request.request_hash = request_hash(&request);
    match exchange_direct(&state, request).await {
        Ok(RuntimeResponse::Execute { result }) => {
            let Some(projection) = &state.projection else {
                return (StatusCode::SERVICE_UNAVAILABLE, "PROJECTION_NOT_CONFIGURED")
                    .into_response();
            };
            if projection
                .consume_session(&claims, &result.receipt.request_hash)
                .await
                .is_err()
                || projection.record_result(&state, &result).await.is_err()
                || projection
                    .record_identity_admission(
                        &claims.subject_hash,
                        &claims.identity_commitment,
                        &claims.wallet_address,
                        &result.receipt.receipt_id,
                    )
                    .await
                    .is_err()
            {
                return (StatusCode::SERVICE_UNAVAILABLE, "PROJECTION_UNAVAILABLE").into_response();
            }
            encrypted(&claims, &result)
        }
        Ok(RuntimeResponse::Error { code }) => {
            (StatusCode::UNPROCESSABLE_ENTITY, code).into_response()
        }
        _ => (StatusCode::BAD_GATEWAY, "ENCLOSURE_UNAVAILABLE").into_response(),
    }
}

async fn register_market(
    State(state): State<AppState>,
    Json(body): Json<MarketRegistrationCommand>,
) -> impl IntoResponse {
    if !direct_admission_route_enabled(
        state.isolated_test,
        env::var("LAYRS_DIRECT_EXECUTION_MODE").ok().as_deref(),
    ) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "MARKET_REGISTRATION_DISABLED",
        )
            .into_response();
    }
    let now = now_unix();
    if !state.isolated_test && !body.registration.verify(now) {
        return (
            StatusCode::FORBIDDEN,
            "MARKET_REGISTRATION_SIGNATURE_INVALID",
        )
            .into_response();
    }
    let mut request = DirectRequest {
        account_id: "governance".into(),
        identity_commitment: "governance".into(),
        request_id: body.registration.registration_id.clone(),
        request_hash: String::new(),
        financial_wallet_address: None,
        action: DirectAction::RegisterMarket {
            registration: body.registration,
            now_unix: now,
        },
    };
    request.request_hash = request_hash(&request);
    let _guard = state.financial_gate.lock().await;
    match exchange_direct(&state, request).await {
        Ok(RuntimeResponse::Execute { result }) => {
            if let Some(projection) = &state.projection {
                if projection.record_result(&state, &result).await.is_err() {
                    return (StatusCode::SERVICE_UNAVAILABLE, "PROJECTION_UNAVAILABLE")
                        .into_response();
                }
            }
            Json(result).into_response()
        }
        Ok(RuntimeResponse::Error { code }) => {
            (StatusCode::UNPROCESSABLE_ENTITY, code).into_response()
        }
        _ => (StatusCode::BAD_GATEWAY, "ENCLOSURE_UNAVAILABLE").into_response(),
    }
}

async fn market_status(
    State(state): State<AppState>,
    Path(market_id): Path<String>,
) -> impl IntoResponse {
    match exchange(&state, RuntimeRequest::MarketStatus { market_id }).await {
        Ok(RuntimeResponse::MarketStatus { market }) => Json(serde_json::json!({
            "market": market
        }))
        .into_response(),
        Ok(RuntimeResponse::Error { code }) => {
            (StatusCode::SERVICE_UNAVAILABLE, code).into_response()
        }
        _ => (StatusCode::BAD_GATEWAY, "ENCLOSURE_UNAVAILABLE").into_response(),
    }
}

async fn resolve_market(
    State(state): State<AppState>,
    Json(body): Json<MarketResolutionCommand>,
) -> impl IntoResponse {
    if !direct_writer_route_enabled(
        state.isolated_test,
        env::var("LAYRS_DIRECT_EXECUTION_MODE").ok().as_deref(),
    ) {
        return (StatusCode::SERVICE_UNAVAILABLE, "WRITER_DISABLED").into_response();
    }
    let now = now_unix();
    if !state.isolated_test && !body.resolution.verify(now) {
        return (StatusCode::FORBIDDEN, "MARKET_RESOLUTION_SIGNATURE_INVALID").into_response();
    }
    let mut request = DirectRequest {
        account_id: "governance".into(),
        identity_commitment: "governance".into(),
        request_id: body.resolution.resolution_id.clone(),
        request_hash: String::new(),
        financial_wallet_address: None,
        action: DirectAction::ResolveMarket {
            resolution: body.resolution,
            now_unix: now,
        },
    };
    request.request_hash = request_hash(&request);
    let _guard = state.financial_gate.lock().await;
    match exchange_direct(&state, request).await {
        Ok(RuntimeResponse::Execute { result }) => {
            if let Some(projection) = &state.projection {
                if projection.record_result(&state, &result).await.is_err() {
                    return (StatusCode::SERVICE_UNAVAILABLE, "PROJECTION_UNAVAILABLE")
                        .into_response();
                }
            } else if !state.isolated_test {
                return (StatusCode::SERVICE_UNAVAILABLE, "PROJECTION_NOT_CONFIGURED")
                    .into_response();
            }
            Json(result).into_response()
        }
        Ok(RuntimeResponse::Error { code }) => {
            (StatusCode::UNPROCESSABLE_ENTITY, code).into_response()
        }
        _ => (StatusCode::BAD_GATEWAY, "ENCLOSURE_UNAVAILABLE").into_response(),
    }
}

async fn apply_balance_recovery(
    State(state): State<AppState>,
    Json(recovery): Json<GovernedBalanceRecovery>,
) -> impl IntoResponse {
    if env::var("LAYRS_DIRECT_EXECUTION_MODE").as_deref() != Ok("production-enabled") {
        return (StatusCode::SERVICE_UNAVAILABLE, "WRITER_DISABLED").into_response();
    }
    let now = now_unix();
    if !recovery.verify(now) {
        return (StatusCode::FORBIDDEN, "BALANCE_RECOVERY_SIGNATURE_INVALID").into_response();
    }
    let mut request = DirectRequest {
        account_id: recovery.account_id.clone(),
        identity_commitment: recovery.identity_commitment.clone(),
        request_id: recovery.recovery_id.clone(),
        request_hash: String::new(),
        financial_wallet_address: None,
        action: DirectAction::GovernedBalanceRecovery {
            recovery,
            now_unix: now,
        },
    };
    request.request_hash = request_hash(&request);
    let _guard = state.financial_gate.lock().await;
    match exchange_direct(&state, request).await {
        Ok(RuntimeResponse::Execute { result }) => {
            if let Some(projection) = &state.projection {
                if projection.record_result(&state, &result).await.is_err() {
                    return (StatusCode::SERVICE_UNAVAILABLE, "PROJECTION_UNAVAILABLE")
                        .into_response();
                }
            } else if !state.isolated_test {
                return (StatusCode::SERVICE_UNAVAILABLE, "PROJECTION_NOT_CONFIGURED")
                    .into_response();
            }
            Json(result).into_response()
        }
        Ok(RuntimeResponse::Error { code }) => {
            (StatusCode::UNPROCESSABLE_ENTITY, code).into_response()
        }
        _ => (StatusCode::BAD_GATEWAY, "ENCLOSURE_UNAVAILABLE").into_response(),
    }
}

async fn prepare_zen_withdrawal(
    state: &AppState, claims: &SessionClaims, identity: &str, request_id: &str,
    destination_chain: String, destination: String, amount_atomic: String,
) -> Result<DirectAction,(StatusCode,&'static str)> {
    let amount = amount_atomic.parse::<u128>().ok().filter(|value|*value>0)
        .ok_or((StatusCode::BAD_REQUEST,"ZEN_AMOUNT_INVALID"))?;
    if destination_chain == "base" && amount % 1_000_000_000_000 != 0 {return Err((StatusCode::BAD_REQUEST,"ZEN_BRIDGE_PRECISION_EXCEEDED"));}
    let custody=state.zen_custody.as_ref().ok_or((StatusCode::SERVICE_UNAVAILABLE,"ZEN_CUSTODY_ADAPTER_NOT_ENABLED"))?;
    let store=state.artifact_store.as_ref().ok_or((StatusCode::SERVICE_UNAVAILABLE,"DIRECT_ARTIFACT_STORE_NOT_CONFIGURED"))?;
    let intents=store.load_intents().await.map_err(|_|(StatusCode::SERVICE_UNAVAILABLE,"EXTERNAL_EFFECT_INTENT_RECOVERY_FAILED"))?;
    let artifacts=store.load_committed().await.map_err(|_|(StatusCode::SERVICE_UNAVAILABLE,"DIRECT_STATE_RECOVERY_FAILED"))?;
    let related=intents.iter().filter(|intent|intent.account_id==claims.subject_hash && intent.request_id==request_id).collect::<Vec<_>>();
    if related.iter().any(|intent|intent.identity_commitment!=identity || intent.asset!="ZEN" || intent.chain!="horizen"
        || intent.zen_destination_chain.as_ref()!=Some(&destination_chain) || !intent.destination.eq_ignore_ascii_case(&destination)
        || intent.amount_atomic!=amount_atomic || intent.provider_wallet_id!=custody.wallet_id || intent.custody_target!=custody.pool_address) {
        return Err((StatusCode::CONFLICT,"EXTERNAL_EFFECT_REPLAY_CONFLICT"));
    }
    for intent in &related {
        if let Some(artifact)=artifacts.iter().find(|artifact|artifact.receipt.account_id==claims.subject_hash && artifact.receipt.request_id==request_id
            && artifact.receipt.request_hash==intent.request_hash && artifact.receipt.custody_reference.as_deref().is_some_and(|reference|reference.starts_with(&format!("{}:",intent.external_effect_reference)))) {
            let reference=artifact.receipt.custody_reference.clone().ok_or((StatusCode::CONFLICT,"EXTERNAL_EFFECT_RESULT_CONFLICT"))?;
            return match artifact.receipt.effect.as_str() {
                "WITHDRAWAL_SETTLED"=>Ok(DirectAction::ReserveZenWithdrawal {destination_chain,destination,amount_atomic,custody_reference:reference}),
                "WITHDRAWAL_REVERTED"=>Ok(DirectAction::RecordZenWithdrawalReverted {destination_chain,destination,amount_atomic,custody_reference:reference}),
                _=>Err((StatusCode::CONFLICT,"EXTERNAL_EFFECT_RESULT_CONFLICT")),
            };
        }
    }
    let root=state.committed_state_root.lock().await.clone().ok_or((StatusCode::SERVICE_UNAVAILABLE,"DIRECT_STATE_ROOT_UNAVAILABLE"))?;
    let intent=if let Some(intent)=related.first() {
        if related.len()!=1 || intent.prior_state_hash!=root {return Err((StatusCode::CONFLICT,"EXTERNAL_EFFECT_LINEAGE_CONFLICT"));}
        (*intent).clone()
    } else {
        if !state.unresolved_external_effects.lock().await.is_empty() {return Err((StatusCode::SERVICE_UNAVAILABLE,"EXTERNAL_EFFECT_FINALITY_PENDING"));}
        // Balance comes from the recovered private enclave, not Aurora or UI.
        let balance=exchange(state,RuntimeRequest::Balance {account_id:claims.subject_hash.clone(),identity_commitment:identity.into(),asset:"ZEN".into(),bucket:"USER_AVAILABLE".into()})
            .await.map_err(|_|(StatusCode::SERVICE_UNAVAILABLE,"ZEN_BALANCE_UNAVAILABLE"))?;
        if !matches!(balance,RuntimeResponse::Balance {amount_atomic:available} if available.parse::<u128>().is_ok_and(|value|value>=amount)) {
            return Err((StatusCode::UNPROCESSABLE_ENTITY,"INSUFFICIENT_AVAILABLE"));
        }
        let (nonce,gas,fee,priority)=custody.transaction_parameters().await.map_err(|_|(StatusCode::SERVICE_UNAVAILABLE,"CUSTODY_TRANSACTION_PARAMETERS_UNAVAILABLE"))?;
        let reference=reference_for(&root,request_id,&claims.subject_hash,identity,&format!("horizen-zen-{destination_chain}"),"ZEN",&destination,&amount_atomic,&custody.wallet_id);
        let mut request=DirectRequest {account_id:claims.subject_hash.clone(),identity_commitment:identity.into(),request_id:request_id.into(),request_hash:String::new(),
            financial_wallet_address:claims.financial_wallet_address.clone(),action:DirectAction::ReserveZenWithdrawal {destination_chain:destination_chain.clone(),destination:destination.clone(),amount_atomic:amount_atomic.clone(),custody_reference:reference}};
        request.request_hash=request_hash(&request);
        let intent=ExternalEffectIntent::create_zen_withdrawal(root,request_id.into(),request.request_hash,claims.subject_hash.clone(),identity.into(),destination_chain,destination,amount_atomic,
            custody.wallet_id.clone(),custody.pool_address.clone(),nonce.to_string(),gas.to_string(),fee.to_string(),priority.to_string(),now_unix())
            .map_err(|_|(StatusCode::BAD_REQUEST,"INVALID_WITHDRAWAL_INTENT"))?;
        store.persist_intent_readback(&intent).await.map_err(|_|(StatusCode::SERVICE_UNAVAILABLE,"EXTERNAL_EFFECT_INTENT_PERSISTENCE_FAILED"))?
    };
    // Keep the gate on every ambiguous error and until authoritative adoption.
    state.unresolved_external_effects.lock().await.insert(intent.intent_hash.clone(),intent.clone());
    match custody.settle(&intent,now_unix()).await.map_err(|_|(StatusCode::SERVICE_UNAVAILABLE,"CUSTODY_FINALITY_UNAVAILABLE"))? {
        terminal @ (ExternalEffectRecovery::BindFinalized {..}|ExternalEffectRecovery::BindReverted {..}) => direct_action_for_external_effect(&intent,terminal).map_err(|_|(StatusCode::CONFLICT,"EXTERNAL_EFFECT_RESULT_CONFLICT")),
        _=>Err((StatusCode::SERVICE_UNAVAILABLE,"CUSTODY_FINALITY_PENDING_FAIL_CLOSED")),
    }
}

async fn prepare_external_withdrawal(
    state: &AppState,
    claims: &SessionClaims,
    identity_commitment: &str,
    request_id: &str,
    destination: String,
    amount_atomic: String,
    relay_route: Option<RelayWithdrawalBinding>,
) -> Result<DirectAction, (StatusCode, &'static str)> {
    let Some(custody) = &state.custody else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "CUSTODY_ADAPTER_NOT_ENABLED",
        ));
    };
    let Some(store) = state.artifact_store.as_ref() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "DIRECT_ARTIFACT_STORE_NOT_CONFIGURED",
        ));
    };
    // Resolve an already-terminal request from the immutable private-state
    // lineage before doing any custody work. The external-effect reference is
    // part of the signed request hash, so recreating an intent from the newer
    // state root on replay would produce a different reference even though the
    // customer request is already terminal.
    let retained_intents = store.load_intents().await.map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "EXTERNAL_EFFECT_INTENT_RECOVERY_FAILED",
        )
    })?;
    let committed_artifacts = store.load_committed().await.map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "DIRECT_STATE_RECOVERY_FAILED",
        )
    })?;
    if let Some(action) = committed_external_effect_action(
        &retained_intents,
        &committed_artifacts,
        &claims.subject_hash,
        identity_commitment,
        request_id,
        &destination,
        &amount_atomic,
        relay_route.as_ref(),
    )
    .map_err(|_| (StatusCode::CONFLICT, "EXTERNAL_EFFECT_REPLAY_CONFLICT"))?
    {
        return Ok(action);
    }
    let prior_state_hash = state.committed_state_root.lock().await.clone().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "DIRECT_STATE_ROOT_UNAVAILABLE",
    ))?;
    if let Some(existing) = state
        .unresolved_external_effects
        .lock()
        .await
        .values()
        .find(|intent| {
            intent.account_id == claims.subject_hash
                && intent.request_id == request_id
                && intent.identity_commitment == identity_commitment
                && intent.destination.eq_ignore_ascii_case(&destination)
                && intent.amount_atomic == amount_atomic
                && intent.relay == relay_route
        })
        .cloned()
    {
        match custody.settle(&existing, now_unix()).await.map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "CUSTODY_FINALITY_UNAVAILABLE",
            )
        })? {
            terminal @ (ExternalEffectRecovery::BindFinalized { .. }
            | ExternalEffectRecovery::BindReverted { .. }
            | ExternalEffectRecovery::BindRelayFinalized { .. }
            | ExternalEffectRecovery::BindRelayReverted { .. }) => {
                return direct_action_for_external_effect(&existing, terminal)
                    .map_err(|_| (StatusCode::CONFLICT, "EXTERNAL_EFFECT_RESULT_CONFLICT"));
            }
            ExternalEffectRecovery::AwaitExternalFinality
            | ExternalEffectRecovery::SubmitWithStableReference
            | ExternalEffectRecovery::FailClosed => {
                return Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    "CUSTODY_FINALITY_PENDING_FAIL_CLOSED",
                ));
            }
        }
    }
    if !state.unresolved_external_effects.lock().await.is_empty() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "EXTERNAL_EFFECT_FINALITY_PENDING",
        ));
    }
    let (nonce, gas_limit, max_fee_per_gas, max_priority_fee_per_gas) =
        custody.transaction_parameters().await.map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "CUSTODY_TRANSACTION_PARAMETERS_UNAVAILABLE",
            )
        })?;
    let reference = match relay_route.as_ref() {
        Some(relay) => relay_reference_for(
            &prior_state_hash,
            request_id,
            &claims.subject_hash,
            identity_commitment,
            &amount_atomic,
            &custody.wallet_id,
            relay,
        ),
        None => reference_for(
            &prior_state_hash,
            request_id,
            &claims.subject_hash,
            identity_commitment,
            "base",
            "USDC",
            &destination,
            &amount_atomic,
            &custody.wallet_id,
        ),
    };
    let provisional_action = match relay_route.as_ref() {
        Some(relay) => DirectAction::SettleRelayWithdrawal {
            relay: relay.clone(),
            amount_atomic: amount_atomic.clone(),
            custody_reference: reference.clone(),
        },
        None => DirectAction::ReserveWithdrawal {
            destination: destination.clone(),
            amount_atomic: amount_atomic.clone(),
            custody_reference: reference.clone(),
        },
    };
    let provisional = DirectRequest {
        account_id: claims.subject_hash.clone(),
        identity_commitment: identity_commitment.into(),
        request_id: request_id.into(),
        request_hash: String::new(),
        financial_wallet_address: claims.financial_wallet_address.clone(),
        action: provisional_action,
    };
    let mut provisional = provisional;
    provisional.request_hash = request_hash(&provisional);
    let intent = match relay_route {
        Some(relay) => ExternalEffectIntent::create_relay_withdrawal(
            prior_state_hash,
            request_id.into(),
            provisional.request_hash.clone(),
            claims.subject_hash.clone(),
            identity_commitment.into(),
            amount_atomic.clone(),
            custody.wallet_id.clone(),
            custody.pool_address.clone(),
            nonce.to_string(),
            gas_limit.to_string(),
            max_fee_per_gas.to_string(),
            max_priority_fee_per_gas.to_string(),
            now_unix(),
            relay,
        ),
        None => ExternalEffectIntent::create(
            prior_state_hash,
            request_id.into(),
            provisional.request_hash.clone(),
            claims.subject_hash.clone(),
            identity_commitment.into(),
            "base".into(),
            "USDC".into(),
            destination.clone(),
            amount_atomic.clone(),
            custody.wallet_id.clone(),
            custody.pool_address.clone(),
            nonce.to_string(),
            gas_limit.to_string(),
            max_fee_per_gas.to_string(),
            max_priority_fee_per_gas.to_string(),
            now_unix(),
        ),
    }
    .map_err(|_| (StatusCode::BAD_REQUEST, "INVALID_WITHDRAWAL_INTENT"))?;
    let intent = store.persist_intent_readback(&intent).await.map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "EXTERNAL_EFFECT_INTENT_PERSISTENCE_FAILED",
        )
    })?;
    // Establish the gate BEFORE custody may submit or return an ambiguous
    // error, not only after a provider pending response.
    state.unresolved_external_effects.lock().await.insert(intent.intent_hash.clone(), intent.clone());
    match custody.settle(&intent, now_unix()).await.map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "CUSTODY_FINALITY_UNAVAILABLE",
        )
    })? {
        terminal @ (ExternalEffectRecovery::BindFinalized { .. }
        | ExternalEffectRecovery::BindReverted { .. }
        | ExternalEffectRecovery::BindRelayFinalized { .. }
        | ExternalEffectRecovery::BindRelayReverted { .. }) => {
            direct_action_for_external_effect(&intent, terminal)
                .map_err(|_| (StatusCode::CONFLICT, "EXTERNAL_EFFECT_RESULT_CONFLICT"))
        }
        ExternalEffectRecovery::AwaitExternalFinality
        | ExternalEffectRecovery::SubmitWithStableReference
        | ExternalEffectRecovery::FailClosed => {
            state
                .unresolved_external_effects
                .lock()
                .await
                .insert(intent.intent_hash.clone(), intent);
            Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "CUSTODY_FINALITY_PENDING_FAIL_CLOSED",
            ))
        }
    }
}

fn valid_base_withdrawal_destination(value: &str) -> bool {
    value.len() == 42
        && value.starts_with("0x")
        && value[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
        && value[2..].bytes().any(|byte| byte != b'0')
}

fn signed_base_withdrawal_destination_matches(
    action_destination: &str,
    signed_destination: &str,
) -> bool {
    valid_base_withdrawal_destination(action_destination)
        && valid_base_withdrawal_destination(signed_destination)
        && action_destination.eq_ignore_ascii_case(signed_destination)
}
async fn balance(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(identity): Path<String>,
    Query(query): Query<BalanceQuery>,
) -> impl IntoResponse {
    let claims = match authenticated(&headers, &state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    match exchange(
        &state,
        RuntimeRequest::Balance {
            account_id: claims.subject_hash.clone(),
            identity_commitment: identity,
            asset: "USDC".into(),
            bucket: query.bucket.unwrap_or_else(|| "USER_AVAILABLE".into()),
        },
    )
    .await
    {
        Ok(RuntimeResponse::Balance { amount_atomic }) => encrypted(
            &claims,
            &serde_json::json!({"asset":"USDC", "amountAtomic": amount_atomic}),
        ),
        Ok(RuntimeResponse::Error { code }) => (StatusCode::FORBIDDEN, code).into_response(),
        _ => (StatusCode::BAD_GATEWAY, "ENCLOSURE_UNAVAILABLE").into_response(),
    }
}
async fn portfolio(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(identity): Path<String>,
) -> impl IntoResponse {
    let claims = match authenticated(&headers, &state) {
        Ok(value) => value,
        Err(response) => return response,
    };
    match exchange(
        &state,
        RuntimeRequest::Portfolio {
            account_id: claims.subject_hash.clone(),
            identity_commitment: identity,
        },
    )
    .await
    {
        Ok(RuntimeResponse::Portfolio { portfolio }) => encrypted(&claims, &portfolio),
        Ok(RuntimeResponse::Error { code }) => (StatusCode::FORBIDDEN, code).into_response(),
        _ => (StatusCode::BAD_GATEWAY, "ENCLOSURE_UNAVAILABLE").into_response(),
    }
}
fn authenticated(
    headers: &HeaderMap,
    state: &AppState,
) -> Result<SessionClaims, axum::response::Response> {
    if state.session_key.len() < 32 {
        return Err((StatusCode::SERVICE_UNAVAILABLE, "AUTH_NOT_CONFIGURED").into_response());
    }
    let encoded = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "AUTH_REQUIRED").into_response())?;
    let claims: SessionClaims = URL_SAFE_NO_PAD
        .decode(encoded)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "INVALID_SESSION").into_response())?;
    let mut unsigned = claims.clone();
    unsigned.signature.clear();
    let bytes = serde_json::to_vec(&unsigned)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "INVALID_SESSION").into_response())?;
    if claims.audience != SESSION_AUDIENCE
        || claims.epoch_id != EPOCH_ID
        || claims.epoch_state_sha256 != layrs_direct_execution_v1::EPOCH_STATE_SHA256
        || !claims.wallet_address.starts_with("0x")
        || claims.wallet_address.len() != 42
        || !claims.wallet_address[2..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || claims
            .financial_wallet_address
            .as_ref()
            .is_some_and(|address| !valid_base_withdrawal_destination(address))
        || claims.identity_commitment.len() != 64
        || !claims
            .identity_commitment
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || claims.session_id.len() < 16
        || claims.subject_hash.len() != 64
        || claims.privy_user_id_hash.len() != 64
        || claims.expires_at_unix <= now_unix()
        || !constant_time_eq(&sign(&state.session_key, &bytes), &claims.signature)
        || URL_SAFE_NO_PAD
            .decode(&claims.response_key)
            .map_or(true, |key| key.len() != 32)
    {
        return Err((StatusCode::UNAUTHORIZED, "INVALID_SESSION").into_response());
    }
    Ok(claims)
}

#[derive(Debug)]
enum ProjectionError {
    Database,
    SessionReplay,
    OpeningMismatch,
}

fn verified_receipt_sequence(records: &[DirectStateArtifact], receipt: &DirectReceipt) -> Result<i64, ProjectionError> {
    let mut matching = records.iter().filter(|record| record.receipt.receipt_id == receipt.receipt_id);
    let record = matching.next().ok_or(ProjectionError::Database)?;
    if matching.next().is_some() || record.receipt != *receipt || record.epoch_id != EPOCH_ID || record.sequence == 0 {
        return Err(ProjectionError::Database);
    }
    i64::try_from(record.sequence).map_err(|_| ProjectionError::Database)
}

impl Projection {
    async fn record_extra_payout(&self, evidence: &ExtraPayoutEvidence) -> Result<(), ProjectionError> {
        let json = serde_json::to_string(evidence).map_err(|_| ProjectionError::Database)?;
        let digest = sha256(&serde_json::to_vec(evidence).map_err(|_| ProjectionError::Database)?);
        let mut client = self.client.lock().await;
        let tx = client.transaction().await.map_err(|_| ProjectionError::Database)?;
        tx.execute("INSERT INTO direct_execution_extra_payouts(epoch_id,intent_hash,original_receipt_id,transaction_hash,amount_atomic,evidence_sha256,evidence_json,disposition) VALUES($1,$2,$3,$4,$5::text::numeric,$6,$7::text::jsonb,'PROTOCOL_OVERPAYMENT_UNRECOVERED') ON CONFLICT DO NOTHING", &[&evidence.epoch_id,&evidence.intent_hash,&evidence.original_receipt_id,&evidence.transaction_hash,&evidence.amount_atomic,&digest,&json]).await.map_err(|_| ProjectionError::Database)?;
        let row = tx.query_opt("SELECT evidence_json::text,evidence_sha256,customer_debit_atomic::text FROM direct_execution_extra_payouts WHERE epoch_id=$1 AND intent_hash=$2", &[&evidence.epoch_id,&evidence.intent_hash]).await.map_err(|_| ProjectionError::Database)?.ok_or(ProjectionError::Database)?;
        let stored: ExtraPayoutEvidence = serde_json::from_str(&row.get::<_,String>(0)).map_err(|_|ProjectionError::Database)?;
        if stored != *evidence || row.get::<_, String>(1) != digest || row.get::<_, String>(2) != "0" { return Err(ProjectionError::Database); }
        tx.commit().await.map_err(|_| ProjectionError::Database)
    }

    async fn connect(
        url: &str,
        epoch: &SealedEpoch,
        isolated_test: bool,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let client = if isolated_test {
            let (client, connection) = tokio_postgres::connect(url, NoTls).await?;
            tokio::spawn(async move {
                let _ = connection.await;
            });
            client
        } else {
            let ca_pem = env::var("LAYRS_DIRECT_PROJECTION_DATABASE_CA_PEM")
                .map_err(|_| "production projection CA is required")?;
            // Secrets Manager JSON commonly stores PEM newlines as the two
            // characters `\\n`. Normalize that representation in memory;
            // never write or log the certificate or database credentials.
            let ca_pem = ca_pem.replace("\\n", "\n");
            let certificate = native_tls::Certificate::from_pem(ca_pem.as_bytes())?;
            let connector = native_tls::TlsConnector::builder()
                .add_root_certificate(certificate)
                .build()?;
            let connector = MakeTlsConnector::new(connector);
            let (client, connection) = tokio_postgres::connect(url, connector).await?;
            tokio::spawn(async move {
                let _ = connection.await;
            });
            client
        };
        let projection = Self {
            client: Arc::new(Mutex::new(client)),
        };
        if isolated_test {
            projection.client.lock().await
                .batch_execute(POSTGRES_PROJECTION_DDL)
                .await?;
            projection.client.lock().await.batch_execute(include_str!("../../sql/005_projection_frontier.sql")).await?;
            projection.client.lock().await.batch_execute(include_str!("../../sql/006_external_effect_reconciliation.sql")).await?;
        } else {
            // Production schema changes are applied once through the existing
            // migration principal. The long-running runtime receives only the
            // established projection-writer duty and fails closed if that
            // migration or its least-privilege grants are absent.
            if let Err(error) = projection.verify_schema_and_privileges().await {
                return Err(format!("projection schema verification failed: {error:?}").into());
            }
        }
        projection.client.lock().await
            .batch_execute("SET search_path TO layrs_direct_v1, pg_catalog")
            .await?;
        if let Err(error) = projection.import_opening(epoch).await {
            return Err(format!("opening projection import failed: {error:?}").into());
        }
        Ok(projection)
    }

    async fn verify_schema_and_privileges(&self) -> Result<(), ProjectionError> {
        let frontier = self.client.lock().await.query_one(
            "SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='layrs_direct_v1' AND table_name='direct_execution_epoch_balances' AND column_name='projection_sequence' AND data_type='bigint' AND is_nullable='NO')", &[]
        ).await.map_err(|_| ProjectionError::Database)?;
        if !frontier.get::<_, bool>(0) { return Err(ProjectionError::OpeningMismatch); }
        let tables = [
            ("direct_execution_receipts", "SELECT,INSERT"),
            ("direct_execution_epoch_balances", "SELECT,INSERT,UPDATE"),
            ("direct_execution_identities", "SELECT,INSERT"),
            ("direct_execution_privy_wallets", "SELECT,INSERT"),
            ("direct_execution_identity_admissions", "SELECT,INSERT"),
            ("direct_execution_sessions", "SELECT,INSERT"),
            ("direct_execution_custody_events", "SELECT,INSERT"),
            ("direct_execution_accounting_events", "SELECT,INSERT"),
            ("direct_execution_order_events", "SELECT,INSERT"),
            ("direct_execution_trade_events", "SELECT,INSERT"),
            ("direct_execution_market_resolutions", "SELECT,INSERT"),
            ("direct_execution_writer_fence", "SELECT"),
            ("direct_execution_writer_grants", "SELECT"),
            ("direct_execution_extra_payouts", "SELECT,INSERT"),
        ];
        for (table, privileges) in tables {
            let qualified = format!("layrs_direct_v1.{table}");
            let row = self.client.lock().await
                .query_one(
                    "SELECT to_regclass($1)::text, has_table_privilege(current_user,$1,$2)",
                    &[&qualified, &privileges],
                )
                .await
                .map_err(|_| ProjectionError::Database)?;
            let relation: Option<String> = row.get(0);
            let allowed: bool = row.get(1);
            if relation.is_none() || !allowed {
                return Err(ProjectionError::OpeningMismatch);
            }
        }
        Ok(())
    }

    async fn import_opening(&self, epoch: &SealedEpoch) -> Result<(), ProjectionError> {
        let balances = epoch.projection_rows();
        let identities = epoch.projection_identity_rows();
        let wallets = epoch.projection_wallet_rows();
        for row in &identities {
            self.client.lock().await.execute(
                "INSERT INTO direct_execution_identities (epoch_id, auth_subject_hash, identity_commitment, admitted_post_genesis) VALUES ($1,$2,$3,false) ON CONFLICT (epoch_id, identity_commitment) DO NOTHING",
                &[&EPOCH_ID, &row.auth_subject_hash, &row.identity_commitment],
            ).await.map_err(|_| ProjectionError::Database)?;
        }
        for row in &balances {
            self.client.lock().await.execute(
                "INSERT INTO direct_execution_epoch_balances (epoch_id, auth_subject_hash, identity_commitment, asset, bucket, amount_atomic) VALUES ($1,$2,$3,$4,$5,$6::text::numeric) ON CONFLICT (epoch_id, identity_commitment, asset, bucket) DO NOTHING",
                &[&EPOCH_ID, &row.auth_subject_hash, &row.identity_commitment, &row.asset, &row.bucket, &row.amount_atomic],
            ).await.map_err(|_| ProjectionError::Database)?;
        }
        for row in &wallets {
            self.client.lock().await.execute(
                "INSERT INTO direct_execution_privy_wallets (epoch_id, auth_subject_hash, wallet_address) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING",
                &[&EPOCH_ID, &row.auth_subject_hash, &row.wallet_address],
            ).await.map_err(|_| ProjectionError::Database)?;
        }
        self.verify_opening(&identities, &balances, &wallets).await
    }

    async fn verify_opening(
        &self,
        identities: &[ProjectionIdentityRow],
        balances: &[ProjectionBalanceRow],
        wallets: &[ProjectionWalletRow],
    ) -> Result<(), ProjectionError> {
        for row in identities {
            let actual = self.client.lock().await.query_opt(
                "SELECT auth_subject_hash, admitted_post_genesis FROM direct_execution_identities WHERE epoch_id=$1 AND identity_commitment=$2",
                &[&EPOCH_ID, &row.identity_commitment],
            ).await.map_err(|_| ProjectionError::Database)?.ok_or(ProjectionError::OpeningMismatch)?;
            let subject: String = actual.get(0);
            let admitted: bool = actual.get(1);
            if subject != row.auth_subject_hash || admitted {
                return Err(ProjectionError::OpeningMismatch);
            }
        }
        for row in balances {
            let actual = self.client.lock().await.query_opt(
                "SELECT amount_atomic::text, auth_subject_hash FROM direct_execution_epoch_balances WHERE epoch_id=$1 AND identity_commitment=$2 AND asset=$3 AND bucket=$4",
                &[&EPOCH_ID, &row.identity_commitment, &row.asset, &row.bucket],
            ).await.map_err(|_| ProjectionError::Database)?.ok_or(ProjectionError::OpeningMismatch)?;
            let _amount: String = actual.get(0);
            let subject: String = actual.get(1);
            // A committed direct request legitimately advances this disposable
            // projection beyond genesis. Startup reconciles every current row
            // against the recovered enclave before serving; this opening pass
            // therefore verifies ownership and row presence without treating
            // the genesis amount as permanently authoritative.
            if subject != row.auth_subject_hash {
                return Err(ProjectionError::OpeningMismatch);
            }
        }
        for row in wallets {
            let found = self.client.lock().await.query_opt(
                "SELECT 1 FROM direct_execution_privy_wallets WHERE epoch_id=$1 AND auth_subject_hash=$2 AND wallet_address=$3",
                &[&EPOCH_ID, &row.auth_subject_hash, &row.wallet_address],
            ).await.map_err(|_| ProjectionError::Database)?.is_some();
            if !found {
                return Err(ProjectionError::OpeningMismatch);
            }
        }
        Ok(())
    }

    async fn consume_session(
        &self,
        claims: &SessionClaims,
        request_hash: &str,
    ) -> Result<(), ProjectionError> {
        let inserted = self.client.lock().await.execute(
            "INSERT INTO direct_execution_sessions (epoch_id, session_id, auth_subject_hash, request_hash, expires_at_unix) VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING",
            &[&EPOCH_ID, &claims.session_id, &claims.subject_hash, &request_hash, &(claims.expires_at_unix as i64)],
        ).await.map_err(|_| ProjectionError::Database)?;
        if inserted == 1 {
            return Ok(());
        }
        let existing = self.client.lock().await.query_opt(
            "SELECT auth_subject_hash, request_hash FROM direct_execution_sessions WHERE epoch_id=$1 AND session_id=$2",
            &[&EPOCH_ID, &claims.session_id],
        ).await.map_err(|_| ProjectionError::Database)?.ok_or(ProjectionError::Database)?;
        let subject: String = existing.get(0);
        let previous: String = existing.get(1);
        if subject == claims.subject_hash && previous == request_hash {
            Ok(())
        } else {
            Err(ProjectionError::SessionReplay)
        }
    }

    async fn record_result(&self, state: &AppState, result: &DirectResult) -> Result<(), ProjectionError> {
        let receipt = &result.receipt;
        // Ordering is bound to the fully verified immutable artifact, never a
        // user-supplied sequence or PostgreSQL's disposable receipt ordering.
        let sequence = state.artifact_store.as_ref().ok_or(ProjectionError::Database)?.receipt_sequence(receipt).await?;
        let mut client = self.client.lock().await;
        let transaction = client.transaction().await.map_err(|_| ProjectionError::Database)?;
        transaction.execute(
            "INSERT INTO direct_execution_receipts (receipt_id, epoch_id, auth_subject_hash, identity_commitment, request_id, request_hash, terminal_status, effect, custody_reference, receipt_json) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::text::jsonb) ON CONFLICT (receipt_id) DO NOTHING",
            &[&receipt.receipt_id, &EPOCH_ID, &receipt.account_id, &receipt.identity_commitment, &receipt.request_id, &receipt.request_hash, &format!("{:?}", receipt.status).to_uppercase(), &receipt.effect, &receipt.custody_reference, &serde_json::to_string(receipt).map_err(|_| ProjectionError::Database)?],
        ).await.map_err(|_| ProjectionError::Database)?;
        for update in &receipt.projection_balance_updates {
            transaction.execute(
                "INSERT INTO direct_execution_epoch_balances (epoch_id, auth_subject_hash, identity_commitment, asset, bucket, amount_atomic, projection_sequence) VALUES ($1,$2,$3,$4,$5,$6::text::numeric,$7) ON CONFLICT (epoch_id, identity_commitment, asset, bucket) DO UPDATE SET auth_subject_hash=EXCLUDED.auth_subject_hash, amount_atomic=EXCLUDED.amount_atomic, projection_sequence=EXCLUDED.projection_sequence, updated_at=now() WHERE direct_execution_epoch_balances.projection_sequence<=EXCLUDED.projection_sequence",
                &[&EPOCH_ID, &update.auth_subject_hash, &update.identity_commitment, &update.asset, &update.bucket, &update.amount_atomic, &sequence],
            ).await.map_err(|_| ProjectionError::Database)?;
        }
        let accounting_amount = receipt.amount_atomic.clone();
        let (direction, amount) = receipt_custody(receipt);
        if let (Some(reference), Some(direction), Some(amount)) =
            (&receipt.custody_reference, direction, amount)
        {
            let (custody_chain_id, custody_transaction_hash) =
                custody_projection_binding(reference);
            transaction.execute(
                "INSERT INTO direct_execution_custody_events (epoch_id, custody_reference, direction, state, chain_id, tx_hash, auth_subject_hash, identity_commitment, amount_atomic) VALUES ($1,$2,$3,'FINAL',$4,$5,$6,$7,$8::text::numeric) ON CONFLICT DO NOTHING",
                &[&EPOCH_ID, reference, &direction, &custody_chain_id, &custody_transaction_hash, &receipt.account_id, &receipt.identity_commitment, &amount],
            ).await.map_err(|_| ProjectionError::Database)?;
        }
        transaction.execute(
            "INSERT INTO direct_execution_accounting_events (receipt_id, epoch_id, auth_subject_hash, identity_commitment, effect, amount_atomic) VALUES ($1,$2,$3,$4,$5,$6::text::numeric) ON CONFLICT DO NOTHING",
            &[&receipt.receipt_id, &EPOCH_ID, &receipt.account_id, &receipt.identity_commitment, &receipt.effect, &accounting_amount],
        ).await.map_err(|_| ProjectionError::Database)?;
        if let Some(execution) = &receipt.execution {
            let status = enum_name(&execution.status)?;
            let outcome = enum_name(&execution.outcome)?;
            let action = enum_name(&execution.action)?;
            transaction.execute(
                "INSERT INTO direct_execution_order_events (receipt_id, epoch_id, order_id, auth_subject_hash, identity_commitment, market_id, outcome, action, status, limit_price_micros, quantity_micros, executed_quantity_micros, remaining_quantity_micros, fee_atomic, resulting_position_micros, resulting_available_atomic) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::text::numeric,$12::text::numeric,$13::text::numeric,$14::text::numeric,$15::text::numeric,$16::text::numeric) ON CONFLICT DO NOTHING",
                &[&receipt.receipt_id, &EPOCH_ID, &execution.order_id, &receipt.account_id, &receipt.identity_commitment, &execution.market_id, &outcome, &action, &status, &(execution.limit_price_micros as i64), &execution.quantity_micros, &execution.executed_quantity_micros, &execution.remaining_quantity_micros, &execution.total_fee_atomic, &execution.resulting_position_micros, &execution.resulting_available_atomic],
            ).await.map_err(|_| ProjectionError::Database)?;
            for trade in &execution.trades {
                let trade_outcome = enum_name(&trade.outcome)?;
                let match_type = enum_name(&trade.match_type)?;
                transaction.execute(
                    "INSERT INTO direct_execution_trade_events (trade_id, receipt_id, epoch_id, market_id, maker_order_id, taker_order_id, outcome, match_type, executed_quantity_micros, execution_price_micros, fee_atomic) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::text::numeric,$10,$11::text::numeric) ON CONFLICT DO NOTHING",
                    &[&trade.trade_id, &receipt.receipt_id, &EPOCH_ID, &trade.market_id, &trade.maker_order_id, &trade.taker_order_id, &trade_outcome, &match_type, &trade.executed_quantity_micros, &(trade.execution_price_micros as i64), &trade.fee_atomic],
                ).await.map_err(|_| ProjectionError::Database)?;
            }
        }
        if let Some(resolution) = &receipt.resolution {
            let outcome = enum_name(&resolution.outcome)?;
            let cancelled_order_count = i64::try_from(resolution.cancelled_order_count)
                .map_err(|_| ProjectionError::Database)?;
            let settled_position_count = i64::try_from(resolution.settled_position_count)
                .map_err(|_| ProjectionError::Database)?;
            transaction.execute(
                "INSERT INTO direct_execution_market_resolutions (receipt_id, epoch_id, resolution_id, market_id, outcome, evidence_sha256, cancelled_order_count, settled_position_count, gross_payout_atomic, rounding_reserve_atomic) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::text::numeric,$10::text::numeric) ON CONFLICT DO NOTHING",
                &[&receipt.receipt_id, &EPOCH_ID, &resolution.resolution_id, &resolution.market_id, &outcome, &resolution.evidence_sha256, &cancelled_order_count, &settled_position_count, &resolution.gross_payout_atomic, &resolution.rounding_reserve_atomic],
            ).await.map_err(|_| ProjectionError::Database)?;
        }
        transaction.commit().await.map_err(|_| ProjectionError::Database)?;
        Ok(())
    }

    async fn record_identity_admission(
        &self,
        auth_subject_hash: &str,
        identity_commitment: &str,
        wallet_address: &str,
        receipt_id: &str,
    ) -> Result<(), ProjectionError> {
        self.client.lock().await.execute(
            "INSERT INTO direct_execution_identities (epoch_id, auth_subject_hash, identity_commitment, admitted_post_genesis) VALUES ($1,$2,$3,true) ON CONFLICT (epoch_id, identity_commitment) DO NOTHING",
            &[&EPOCH_ID, &auth_subject_hash, &identity_commitment],
        ).await.map_err(|_| ProjectionError::Database)?;
        self.client.lock().await.execute(
            "INSERT INTO direct_execution_epoch_balances (epoch_id, auth_subject_hash, identity_commitment, asset, bucket, amount_atomic) VALUES ($1,$2,$3,'USDC','USER_AVAILABLE',0) ON CONFLICT (epoch_id, identity_commitment, asset, bucket) DO NOTHING",
            &[&EPOCH_ID, &auth_subject_hash, &identity_commitment],
        ).await.map_err(|_| ProjectionError::Database)?;
        self.client.lock().await.execute(
            "INSERT INTO direct_execution_privy_wallets (epoch_id, auth_subject_hash, wallet_address) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING",
            &[&EPOCH_ID, &auth_subject_hash, &wallet_address],
        ).await.map_err(|_| ProjectionError::Database)?;
        self.client.lock().await.execute(
            "INSERT INTO direct_execution_identity_admissions (receipt_id, epoch_id, auth_subject_hash, identity_commitment, wallet_address) VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING",
            &[&receipt_id, &EPOCH_ID, &auth_subject_hash, &identity_commitment, &wallet_address],
        ).await.map_err(|_| ProjectionError::Database)?;
        let row = self.client.lock().await.query_opt(
            "SELECT identity.auth_subject_hash, wallet.wallet_address, admission.receipt_id FROM direct_execution_identities identity JOIN direct_execution_epoch_balances balance ON balance.epoch_id=identity.epoch_id AND balance.identity_commitment=identity.identity_commitment JOIN direct_execution_privy_wallets wallet ON wallet.epoch_id=identity.epoch_id AND wallet.auth_subject_hash=identity.auth_subject_hash JOIN direct_execution_identity_admissions admission ON admission.epoch_id=identity.epoch_id AND admission.identity_commitment=identity.identity_commitment WHERE identity.epoch_id=$1 AND identity.identity_commitment=$2 AND identity.admitted_post_genesis=true AND balance.asset='USDC' AND balance.bucket='USER_AVAILABLE' AND balance.amount_atomic=0",
            &[&EPOCH_ID, &identity_commitment],
        ).await.map_err(|_| ProjectionError::Database)?.ok_or(ProjectionError::OpeningMismatch)?;
        let actual_subject: String = row.get(0);
        let actual_wallet: String = row.get(1);
        let actual_receipt: String = row.get(2);
        if actual_subject == auth_subject_hash
            && actual_wallet.eq_ignore_ascii_case(wallet_address)
            && actual_receipt == receipt_id
        {
            Ok(())
        } else {
            Err(ProjectionError::OpeningMismatch)
        }
    }

    async fn verify_governed_runtime_mode(
        &self,
        grant: &WriterGrant,
        financial_writer_enabled: bool,
    ) -> Result<(), ProjectionError> {
        let row = self.client.lock().await.query_opt(
            "SELECT old_writer_fence_evidence_sha256, old_writer_authorized, target_writer_enabled, activation_id FROM direct_execution_writer_fence WHERE epoch_id=$1",
            &[&EPOCH_ID],
        ).await.map_err(|_| ProjectionError::Database)?.ok_or(ProjectionError::OpeningMismatch)?;
        let fence_hash: String = row.get(0);
        let old_authorized: bool = row.get(1);
        let target_enabled: bool = row.get(2);
        let activation: Option<String> = row.get(3);
        if old_authorized
            || target_enabled != financial_writer_enabled
            || fence_hash != grant.old_writer_fence_evidence_sha256
            || activation.as_deref() != Some(&grant.activation_id)
        {
            return Err(ProjectionError::OpeningMismatch);
        }
        let grant_row = self.client.lock().await.query_opt(
            "SELECT 1 FROM direct_execution_writer_grants WHERE activation_id=$1 AND epoch_id=$2 AND old_writer_fence_evidence_sha256=$3 AND expires_at_unix=$4",
            &[&grant.activation_id, &EPOCH_ID, &grant.old_writer_fence_evidence_sha256, &(grant.expires_at_unix as i64)],
        ).await.map_err(|_| ProjectionError::Database)?.is_some();
        if grant_row {
            Ok(())
        } else {
            Err(ProjectionError::OpeningMismatch)
        }
    }
}

fn custody_projection_binding(reference: &str) -> (i64, String) {
    let parts = reference.split(':').collect::<Vec<_>>();
    if parts.get(1) == Some(&"relay") {
        if let (Some(chain), Some(hash)) = (
            parts.get(3).and_then(|value| value.parse::<i64>().ok()),
            parts.get(5),
        ) {
            return (chain, (*hash).into());
        }
    }
    (8453, reference.into())
}

fn enum_name<T: Serialize>(value: &T) -> Result<String, ProjectionError> {
    serde_json::to_string(value)
        .map(|value| value.trim_matches('"').to_string())
        .map_err(|_| ProjectionError::Database)
}

fn receipt_custody(receipt: &DirectReceipt) -> (Option<&'static str>, Option<String>) {
    match receipt.effect.as_str() {
        "WITHDRAWAL_SETTLED" => (Some("WITHDRAWAL"), receipt.amount_atomic.clone()),
        "DEPOSIT_CREDITED" => (Some("DEPOSIT"), receipt.amount_atomic.clone()),
        _ => (None, None),
    }
}
fn encrypted<T: Serialize>(claims: &SessionClaims, body: &T) -> axum::response::Response {
    let key = match URL_SAFE_NO_PAD.decode(&claims.response_key) {
        Ok(value) if value.len() == 32 => value,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "SESSION_ENCRYPTION_KEY_INVALID",
            )
                .into_response()
        }
    };
    let bytes = match serde_json::to_vec(body) {
        Ok(value) => value,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "RESPONSE_ENCODING_FAILED",
            )
                .into_response()
        }
    };
    let digest = sha256(format!("{}:{}", claims.subject_hash, bytes.len()).as_bytes());
    let nonce_bytes = match hex::decode(&digest[..24]) {
        Ok(value) => value,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "RESPONSE_ENCRYPTION_FAILED",
            )
                .into_response()
        }
    };
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    match cipher.encrypt(Nonce::from_slice(&nonce_bytes), bytes.as_ref()) {
        Ok(ciphertext) => Json(EncryptedResponse {
            algorithm: "CHACHA20_POLY1305",
            nonce: URL_SAFE_NO_PAD.encode(nonce_bytes),
            ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
        })
        .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "RESPONSE_ENCRYPTION_FAILED",
        )
            .into_response(),
    }
}
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or(0)
}
fn now_unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|value| u64::try_from(value.as_millis()).ok())
        .unwrap_or(0)
}
fn constant_time_eq(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.as_bytes()
            .iter()
            .zip(b.as_bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}
async fn exchange(state: &AppState, request: RuntimeRequest) -> io::Result<RuntimeResponse> {
    timeout(Duration::from_secs(10), async {
        let mut stream =
            VsockStream::connect(VsockAddr::new(state.enclave_cid, ENCLOSURE_PORT)).await?;
        write_frame(&mut stream, &serde_cbor::to_vec(&request).map_err(invalid)?).await?;
        serde_cbor::from_slice(&read_frame(&mut stream).await?).map_err(invalid)
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "enclave timeout"))?
}

async fn recover_enclave(state: &AppState) -> io::Result<()> {
    let store = state.artifact_store.as_ref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "DIRECT_ARTIFACT_STORE_NOT_CONFIGURED",
        )
    })?;
    if let ArchiveStore::S3(s3)=store {return s3.restore_streamed(state).await.map_err(|error|invalid(format!("DIRECT_STATE_RECOVERY_FAILED:{error}")));}
    let artifacts = store.load_committed().await.map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("DIRECT_STATE_RECOVERY_FAILED:{error}"),
        )
    })?;
    let expected = artifacts.last().map(|artifact| {
        (
            artifact.sequence,
            artifact.state_hash.clone(),
            artifact.epoch_id.clone(),
        )
    });
    match exchange(state, RuntimeRequest::RecoverCommitted { artifacts }).await? {
        RuntimeResponse::RecoveryComplete {
            recovered_sequence,
            recovered_state_hash,
        } => match expected {
            Some((sequence, state_hash, epoch_id))
                if epoch_id == EPOCH_ID
                    && sequence == recovered_sequence
                    && state_hash == recovered_state_hash =>
            {
                *state.committed_state_root.lock().await = Some(recovered_state_hash);
                Ok(())
            }
            None if recovered_sequence == 0 => {
                *state.committed_state_root.lock().await = Some(recovered_state_hash);
                Ok(())
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DIRECT_STATE_RECOVERY_MISMATCH",
            )),
        },
        RuntimeResponse::Error { code } => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("DIRECT_STATE_RECOVERY_FAILED:{code}"),
        )),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DIRECT_STATE_RECOVERY_UNEXPECTED_RESPONSE",
        )),
    }
}

fn intent_is_committed(intent: &ExternalEffectIntent, artifacts: &[DirectStateArtifact]) -> bool {
    let prefix = format!("{}:", intent.external_effect_reference);
    artifacts.iter().any(|artifact| {
        artifact
            .receipt
            .custody_reference
            .as_deref()
            .is_some_and(|value| value.starts_with(&prefix))
    })
}

fn same_external_effect_request(a: &ExternalEffectIntent, b: &ExternalEffectIntent) -> bool {
    a.account_id == b.account_id
        && a.request_id == b.request_id
        && a.identity_commitment == b.identity_commitment
        && a.chain == b.chain
        && a.asset == b.asset
        && a.destination.eq_ignore_ascii_case(&b.destination)
        && a.amount_atomic == b.amount_atomic
        && a.provider_wallet_id == b.provider_wallet_id
        && a.custody_target.eq_ignore_ascii_case(&b.custody_target)
        && a.relay == b.relay
        && a.zen_destination_chain == b.zen_destination_chain
}

/// This is external cash evidence, never a fabricated enclave receipt or a
/// second debit of the already-completed customer request. Stable fields make
/// write-once persistence and restart replay byte-identical.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct ExtraPayoutEvidence {
    protocol_version: String,
    epoch_id: String,
    intent_hash: String,
    original_intent_hash: String,
    original_receipt_id: String,
    original_transaction_hash: String,
    provider_transaction_id: String,
    transaction_hash: String,
    account_id: String,
    request_id: String,
    destination: String,
    chain: String,
    asset: String,
    amount_atomic: String,
    customer_debit_atomic: String,
    disposition: String,
}

fn extra_payout_evidence(intent: &ExternalEffectIntent, original: &ExternalEffectIntent, artifacts: &[DirectStateArtifact], outcome: ExternalEffectRecovery) -> io::Result<Option<ExtraPayoutEvidence>> {
    intent.verify().map_err(invalid)?;
    original.verify().map_err(invalid)?;
    if !same_external_effect_request(intent, original) || intent.intent_hash == original.intent_hash || intent.chain != "base" || intent.asset != "USDC" || intent.relay.is_some() || intent.zen_destination_chain.is_some() { return Err(invalid("extra payout binding conflict")); }
    let prefix = format!("{}:", original.external_effect_reference);
    let committed = artifacts.iter().find(|a| a.epoch_id == EPOCH_ID && a.receipt.account_id == original.account_id && a.receipt.request_id == original.request_id && a.receipt.request_hash == original.request_hash && a.receipt.effect == "WITHDRAWAL_SETTLED" && a.receipt.amount_atomic.as_deref() == Some(original.amount_atomic.as_str()) && a.receipt.custody_reference.as_deref().is_some_and(|r|r.starts_with(&prefix))).ok_or_else(|| invalid("original payout is not committed"))?;
    let original_hash = committed.receipt.custody_reference.as_deref().and_then(|r|r.strip_prefix(&prefix)).filter(|r|valid_transaction_hash(r)).ok_or_else(||invalid("original payout hash invalid"))?;
    let ExternalEffectRecovery::BindFinalized {provider_transaction_id,transaction_hash} = outcome else {return Err(invalid("extra payout is not canonically finalized"));};
    if !valid_transaction_hash(&transaction_hash) { return Err(invalid("extra payout hash invalid")); }
    if original_hash.eq_ignore_ascii_case(&transaction_hash) { return Ok(None); } // Two references to one tx are not two payments.
    Ok(Some(ExtraPayoutEvidence {protocol_version:"layrs.external-extra-payout.v1".into(),epoch_id:EPOCH_ID.into(),intent_hash:intent.intent_hash.clone(),original_intent_hash:original.intent_hash.clone(),original_receipt_id:committed.receipt.receipt_id.clone(),original_transaction_hash:original_hash.to_ascii_lowercase(),provider_transaction_id,transaction_hash:transaction_hash.to_ascii_lowercase(),account_id:intent.account_id.clone(),request_id:intent.request_id.clone(),destination:intent.destination.to_ascii_lowercase(),chain:intent.chain.clone(),asset:intent.asset.clone(),amount_atomic:intent.amount_atomic.clone(),customer_debit_atomic:"0".into(),disposition:"PROTOCOL_OVERPAYMENT_UNRECOVERED".into()}))
}

/// Rebase ONLY a confirmed direct Base USDC outcome across an independently
/// verified successor chain with no intervening change to that user's USDC.
/// Unknown roots, gaps, request collisions and balance changes fail closed.
fn historical_intent_lineage_safe(intent: &ExternalEffectIntent, artifacts: &[DirectStateArtifact], current_root: &str) -> bool {
    if intent.chain != "base" || intent.asset != "USDC" || intent.relay.is_some() || intent.zen_destination_chain.is_some() || artifacts.is_empty() || artifacts.last().is_none_or(|a|a.state_hash != current_root) { return false; }
    if artifacts.iter().enumerate().any(|(i,a)|a.epoch_id != EPOCH_ID || a.sequence != i as u64+1 || (i>0 && a.prior_state_hash != artifacts[i-1].state_hash)) { return false; }
    let starts = artifacts.iter().enumerate().filter(|(_,a)|a.prior_state_hash == intent.prior_state_hash).map(|(i,_)|i).collect::<Vec<_>>();
    if starts.len()!=1 { return false; }
    artifacts[starts[0]..].iter().all(|a| {
        !(a.receipt.account_id == intent.account_id && a.receipt.request_id == intent.request_id)
        && !a.receipt.projection_balance_updates.iter().any(|b|b.identity_commitment == intent.identity_commitment && b.asset == intent.asset)
    })
}

fn committed_external_effect_action(
    intents: &[ExternalEffectIntent],
    artifacts: &[DirectStateArtifact],
    account_id: &str,
    identity_commitment: &str,
    request_id: &str,
    destination: &str,
    amount_atomic: &str,
    relay_route: Option<&RelayWithdrawalBinding>,
) -> Result<Option<DirectAction>, io::Error> {
    let related = intents
        .iter()
        .filter(|intent| intent.account_id == account_id && intent.request_id == request_id)
        .collect::<Vec<_>>();
    if related.is_empty() {
        return Ok(None);
    }
    if related.iter().any(|intent| {
        intent.identity_commitment != identity_commitment
            || intent.chain != "base"
            || intent.asset != "USDC"
            || !intent.destination.eq_ignore_ascii_case(destination)
            || intent.amount_atomic != amount_atomic
            || intent.relay.as_ref() != relay_route
    }) {
        return Err(invalid("external-effect replay binding conflict"));
    }
    for intent in related {
        let prefix = format!("{}:", intent.external_effect_reference);
        let Some(artifact) = artifacts.iter().find(|artifact| {
            artifact.receipt.account_id == account_id
                && artifact.receipt.identity_commitment == identity_commitment
                && artifact.receipt.request_id == request_id
                && artifact.receipt.amount_atomic.as_deref() == Some(amount_atomic)
                && artifact
                    .receipt
                    .custody_reference
                    .as_deref()
                    .is_some_and(|value| value.starts_with(&prefix))
        }) else {
            continue;
        };
        let custody_reference = artifact
            .receipt
            .custody_reference
            .clone()
            .ok_or_else(|| invalid("committed withdrawal is missing custody binding"))?;
        let action = match (intent.relay.as_ref(), artifact.receipt.effect.as_str()) {
            (Some(relay), "WITHDRAWAL_SETTLED") => DirectAction::SettleRelayWithdrawal {
                relay: relay.clone(),
                amount_atomic: amount_atomic.into(),
                custody_reference,
            },
            (Some(relay), "WITHDRAWAL_REVERTED") => DirectAction::RecordRelayWithdrawalReverted {
                relay: relay.clone(),
                amount_atomic: amount_atomic.into(),
                custody_reference,
            },
            (None, "WITHDRAWAL_SETTLED") => DirectAction::ReserveWithdrawal {
                destination: destination.into(),
                amount_atomic: amount_atomic.into(),
                custody_reference,
            },
            (None, "WITHDRAWAL_REVERTED") => DirectAction::RecordWithdrawalReverted {
                destination: destination.into(),
                amount_atomic: amount_atomic.into(),
                custody_reference,
            },
            _ => return Err(invalid("committed external effect has unexpected effect")),
        };
        let mut request = DirectRequest {
            account_id: account_id.into(),
            identity_commitment: identity_commitment.into(),
            request_id: request_id.into(),
            request_hash: String::new(),
            financial_wallet_address: intent
                .relay
                .is_none()
                .then(|| destination.to_ascii_lowercase()),
            action: action.clone(),
        };
        request.request_hash = request_hash(&request);
        if request.request_hash != intent.request_hash
            || request.request_hash != artifact.receipt.request_hash
        {
            return Err(invalid("committed external-effect replay hash mismatch"));
        }
        return Ok(Some(action));
    }
    Ok(None)
}

fn direct_action_for_external_effect(
    intent: &ExternalEffectIntent,
    outcome: ExternalEffectRecovery,
) -> Result<DirectAction, io::Error> {
    if let Some(chain)=&intent.zen_destination_chain {
        return match outcome {
            ExternalEffectRecovery::BindFinalized {transaction_hash,..}=>Ok(DirectAction::ReserveZenWithdrawal {destination_chain:chain.clone(),destination:intent.destination.clone(),amount_atomic:intent.amount_atomic.clone(),custody_reference:format!("{}:{transaction_hash}",intent.external_effect_reference)}),
            ExternalEffectRecovery::BindReverted {transaction_hash,..}=>Ok(DirectAction::RecordZenWithdrawalReverted {destination_chain:chain.clone(),destination:intent.destination.clone(),amount_atomic:intent.amount_atomic.clone(),custody_reference:format!("{}:{transaction_hash}",intent.external_effect_reference)}),
            _=>Err(invalid("ZEN external result is not terminal")),
        };
    }
    match (intent.relay.as_ref(), outcome) {
        (
            Some(relay),
            ExternalEffectRecovery::BindRelayFinalized {
                intake_transaction_hash,
                relay_request_id,
                destination_transaction_hash,
                destination_amount_atomic,
                result_hash,
                ..
            },
        ) if relay_request_id.eq_ignore_ascii_case(&relay.request_id)
            && result_hash
                == relay_result_hash(
                    intent,
                    &intake_transaction_hash,
                    &destination_transaction_hash,
                    &destination_amount_atomic,
                )
                .ok_or_else(|| invalid("Relay result binding missing"))? =>
        {
            Ok(DirectAction::SettleRelayWithdrawal {
                relay: relay.clone(),
                amount_atomic: intent.amount_atomic.clone(),
                custody_reference: format!(
                    "{}:relay:{}:{}:{}:{}:{}:{}:{}",
                    intent.external_effect_reference,
                    relay.request_id,
                    relay.destination_chain_id,
                    intake_transaction_hash,
                    destination_transaction_hash,
                    destination_amount_atomic,
                    result_hash,
                    relay.binding_hash(),
                ),
            })
        }
        (
            Some(relay),
            ExternalEffectRecovery::BindRelayReverted {
                intake_transaction_hash,
                relay_request_id,
                terminal_status,
                result_hash,
                ..
            },
        ) if relay_request_id.eq_ignore_ascii_case(&relay.request_id)
            && result_hash
                == relay_reverted_result_hash(
                    relay,
                    &intent.external_effect_reference,
                    &intake_transaction_hash,
                    &terminal_status,
                ) =>
        {
            Ok(DirectAction::RecordRelayWithdrawalReverted {
                relay: relay.clone(),
                amount_atomic: intent.amount_atomic.clone(),
                custody_reference: format!(
                    "{}:relay-reverted:{}:{}:{}:{}:{}:{}",
                    intent.external_effect_reference,
                    relay.request_id,
                    relay.destination_chain_id,
                    intake_transaction_hash,
                    terminal_status,
                    result_hash,
                    relay.binding_hash(),
                ),
            })
        }
        (
            Some(relay),
            ExternalEffectRecovery::BindReverted {
                transaction_hash, ..
            },
        ) => {
            let terminal_status = "failure";
            let result_hash = relay_reverted_result_hash(
                relay,
                &intent.external_effect_reference,
                &transaction_hash,
                terminal_status,
            );
            Ok(DirectAction::RecordRelayWithdrawalReverted {
                relay: relay.clone(),
                amount_atomic: intent.amount_atomic.clone(),
                custody_reference: format!(
                    "{}:relay-reverted:{}:{}:{}:{}:{}:{}",
                    intent.external_effect_reference,
                    relay.request_id,
                    relay.destination_chain_id,
                    transaction_hash,
                    terminal_status,
                    result_hash,
                    relay.binding_hash(),
                ),
            })
        }
        (Some(_), _) => Err(invalid("Relay external-effect result mismatch")),
        (
            None,
            ExternalEffectRecovery::BindFinalized {
                transaction_hash, ..
            },
        ) => Ok(DirectAction::ReserveWithdrawal {
            destination: intent.destination.clone(),
            amount_atomic: intent.amount_atomic.clone(),
            custody_reference: format!("{}:{}", intent.external_effect_reference, transaction_hash),
        }),
        (
            None,
            ExternalEffectRecovery::BindReverted {
                transaction_hash, ..
            },
        ) => Ok(DirectAction::RecordWithdrawalReverted {
            destination: intent.destination.clone(),
            amount_atomic: intent.amount_atomic.clone(),
            custody_reference: format!("{}:{}", intent.external_effect_reference, transaction_hash),
        }),
        (None, _) => Err(invalid("external effect is not terminal")),
    }
}

fn request_for_external_effect(
    intent: &ExternalEffectIntent,
    outcome: ExternalEffectRecovery,
) -> Result<DirectRequest, io::Error> {
    let action = direct_action_for_external_effect(intent, outcome)?;
    let mut request = DirectRequest {
        account_id: intent.account_id.clone(),
        identity_commitment: intent.identity_commitment.clone(),
        request_id: intent.request_id.clone(),
        request_hash: String::new(),
        financial_wallet_address: intent
            .relay
            .is_none()
            .then(|| intent.destination.to_ascii_lowercase()),
        action,
    };
    request.request_hash = request_hash(&request);
    if request.request_hash != intent.request_hash {
        return Err(invalid("external-effect request binding mismatch"));
    }
    Ok(request)
}

async fn recover_external_effect_intents(state: &AppState) -> io::Result<()> {
    let Some(store) = state.artifact_store.as_ref() else {
        return Ok(());
    };
    let intents = store
        .load_intents()
        .await
        .map_err(|error| invalid(format!("external-effect intent recovery failed:{error}")))?;
    if intents.is_empty() {
        return Ok(());
    }
    let artifacts = store
        .load_committed()
        .await
        .map_err(|error| invalid(format!("direct artifact recovery failed:{error}")))?;
    for intent in intents.iter().cloned() {
        if intent_is_committed(&intent, &artifacts) {
            continue;
        }
        if let Some(committed_sibling) = intents.iter().find(|candidate| {
            candidate.account_id == intent.account_id
                && candidate.request_id == intent.request_id
                && intent_is_committed(candidate, &artifacts)
        }) {
            if same_external_effect_request(&intent, committed_sibling) {
                // A second intent is NOT proof that it remained unsubmitted.
                // Observe canonical finality without any submission capability.
                let custody = state.custody.as_ref().ok_or_else(|| invalid("duplicate custody effect cannot be verified"))?;
                custody.validate_intent(&intent).map_err(invalid)?;
                let observation = custody.observe(&intent).await.map_err(invalid)?;
                match observation {
                    layrs_direct_execution_v1::ExternalEffectObservation::NotFound => return Err(invalid("duplicate custody reference is missing; no-effect cannot be assumed")),
                    finalized @ layrs_direct_execution_v1::ExternalEffectObservation::Finalized { .. } => {
                        let terminal = intent.recovery_action(now_unix(), finalized);
                        if let Some(evidence) = extra_payout_evidence(&intent, committed_sibling, &artifacts, terminal)? {
                            store.persist_extra_payout(&evidence).await.map_err(invalid)?;
                            state.projection.as_ref().ok_or_else(|| invalid("extra payout projection unavailable"))?.record_extra_payout(&evidence).await.map_err(|_|invalid("extra payout projection reconciliation failed"))?;
                            eprintln!("VERIFIED_EXTRA_PAYOUT_RECONCILED {} customer_debit=0", evidence.intent_hash);
                        }
                    }
                    layrs_direct_execution_v1::ExternalEffectObservation::Reverted { .. } => {}, // Canonical revert: no principal payout.
                    _ => return Err(invalid("duplicate custody effect remains ambiguous")),
                }
                continue;
            }
            return Err(invalid(
                "conflicting external-effect intent follows a committed request",
            ));
        }
        let root = state.committed_state_root.lock().await.clone();
        let historical = root.as_deref() != Some(intent.prior_state_hash.as_str());
        if historical && !root.as_deref().is_some_and(|r|historical_intent_lineage_safe(&intent,&artifacts,r)) {
            return Err(invalid(
                "unresolved external-effect intent does not match committed lineage",
            ));
        }
        let settled = if historical {
            // This branch cannot rebroadcast, even inside an old provider
            // idempotency window. Only an existing canonical result can bind.
            match &state.custody {Some(custody)=>Some(custody.observe_terminal_only(&intent).await),None=>None}
        } else if intent.asset == "ZEN" {
            match &state.zen_custody {Some(custody)=>Some(custody.settle(&intent,now_unix()).await),None=>None}
        } else {match &state.custody {Some(custody)=>Some(custody.settle(&intent,now_unix()).await),None=>None}};
        let Some(settled) = settled else {
            state
                .unresolved_external_effects
                .lock()
                .await
                .insert(intent.intent_hash.clone(), intent);
            continue;
        };
        match settled.map_err(invalid)? {
            terminal @ (ExternalEffectRecovery::BindFinalized { .. }
            | ExternalEffectRecovery::BindReverted { .. }
            | ExternalEffectRecovery::BindRelayFinalized { .. }
            | ExternalEffectRecovery::BindRelayReverted { .. }) => {
                let request = request_for_external_effect(&intent, terminal)?;
                let response = exchange_direct(state, request).await?;
                let RuntimeResponse::Execute { result } = response else {
                    return Err(invalid("external-effect recovery execution failed"));
                };
                if let Some(projection) = &state.projection {
                    projection.record_result(&state, &result).await.map_err(|_| {
                        invalid("projection unavailable during external-effect recovery")
                    })?;
                }
                if historical { eprintln!("VERIFIED_HISTORICAL_WITHDRAWAL_RECONCILED {}", intent.intent_hash); }
            }
            ExternalEffectRecovery::AwaitExternalFinality
            | ExternalEffectRecovery::SubmitWithStableReference
            | ExternalEffectRecovery::FailClosed => {
                state
                    .unresolved_external_effects
                    .lock()
                    .await
                    .insert(intent.intent_hash.clone(), intent);
            }
        }
    }
    Ok(())
}

/// Compare the disposable PostgreSQL projection with the private state only
/// after the enclave has recovered the authoritative encrypted lineage.
async fn verify_recovered_projection(state: &AppState) -> io::Result<()> {
    let Some(projection) = &state.projection else {
        return Ok(());
    };
    let rows = projection
        .client
        .lock().await
        .query(
            "SELECT auth_subject_hash, identity_commitment, asset, bucket, amount_atomic::text FROM direct_execution_epoch_balances WHERE epoch_id=$1 ORDER BY identity_commitment,asset,bucket",
            &[&EPOCH_ID],
        )
        .await
        .map_err(|_| invalid("projection reconciliation query failed"))?;
    let mut projected_keys = HashSet::new();
    for row in rows {
        let account_id: String = row.get(0);
        let identity_commitment: String = row.get(1);
        let asset: String = row.get(2);
        let bucket: String = row.get(3);
        let expected: String = row.get(4);
        projected_keys.insert(format!("{identity_commitment}\0{asset}\0{bucket}"));
        match exchange(
            state,
            RuntimeRequest::Balance {
                account_id,
                identity_commitment,
                asset,
                bucket,
            },
        )
        .await?
        {
            RuntimeResponse::Balance { amount_atomic } if amount_atomic == expected => {}
            _ => return Err(invalid("projection does not match recovered private state")),
        }
    }
    let receipts = projection
        .client
        .lock().await
        .query(
            "SELECT receipt_json::text FROM direct_execution_receipts WHERE epoch_id=$1",
            &[&EPOCH_ID],
        )
        .await
        .map_err(|_| invalid("projection receipt reconciliation query failed"))?;
    for row in receipts {
        let encoded: String = row.get(0);
        let receipt: DirectReceipt = serde_json::from_str(&encoded)
            .map_err(|_| invalid("projection receipt is malformed"))?;
        for update in receipt.projection_balance_updates {
            let key = format!(
                "{}\0{}\0{}",
                update.identity_commitment, update.asset, update.bucket
            );
            if !projected_keys.contains(&key) {
                return Err(invalid("projection is missing a committed balance row"));
            }
        }
    }
    // Legacy rows have no ordering metadata. Stamp only after every amount
    // was independently compared with the recovered private state above.
    // This changes no financial amount and prevents an old first-time retry
    // from overwriting a newer, already-reconciled projection.
    let records = state.artifact_store.as_ref().ok_or_else(|| invalid("projection archive unavailable"))?.load_committed().await.map_err(invalid)?;
    let sequence = records.last().map_or(0, |record| record.sequence);
    let sequence = i64::try_from(sequence).map_err(|_| invalid("projection sequence overflow"))?;
    let invalid_frontier = projection.client.lock().await.query_one(
        "SELECT EXISTS (SELECT 1 FROM direct_execution_epoch_balances WHERE epoch_id=$1 AND (projection_sequence<0 OR projection_sequence>$2))", &[&EPOCH_ID, &sequence]
    ).await.map_err(|_| invalid("projection ordering verification failed"))?;
    if invalid_frontier.get::<_, bool>(0) { return Err(invalid("projection ordering exceeds recovered private state")); }
    projection.client.lock().await.execute(
        "UPDATE direct_execution_epoch_balances SET projection_sequence=$2 WHERE epoch_id=$1 AND projection_sequence<$2", &[&EPOCH_ID, &sequence]
    ).await.map_err(|_| invalid("projection ordering initialization failed"))?;
    Ok(())
}

async fn bootstrap_isolated_enclave(state: &AppState) -> io::Result<()> {
    if !state.isolated_test {
        return Ok(());
    }
    let receipt_key = env::var("LAYRS_DIRECT_RECEIPT_KEY_HEX")
        .ok()
        .and_then(|value| hex::decode(value).ok())
        .filter(|value| value.len() == 32)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "DIRECT_RECEIPT_KEY_NOT_CONFIGURED",
            )
        })?;
    let state_key = env::var("LAYRS_DIRECT_STATE_KEY_HEX")
        .ok()
        .and_then(|value| hex::decode(value).ok())
        .filter(|value| value.len() == 32)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "DIRECT_STATE_KEY_NOT_CONFIGURED",
            )
        })?;
    if state.commit_ack_key.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "DIRECT_COMMIT_ACK_KEY_NOT_CONFIGURED",
        ));
    }
    match exchange(
        state,
        RuntimeRequest::BootstrapIsolated {
            receipt_key,
            state_key,
            commit_ack_key: state.commit_ack_key.clone(),
        },
    )
    .await?
    {
        RuntimeResponse::BootstrapComplete => Ok(()),
        RuntimeResponse::Error { code } => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("ISOLATED_BOOTSTRAP_FAILED:{code}"),
        )),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ISOLATED_BOOTSTRAP_UNEXPECTED_RESPONSE",
        )),
    }
}

async fn bootstrap_governed_enclave(state: &AppState) -> io::Result<()> {
    let Some(config) = &state.governed_bootstrap else {
        return Ok(());
    };
    if state.commit_ack_key.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "DIRECT_COMMIT_ACK_KEY_NOT_CONFIGURED",
        ));
    }
    let expected_commitment = config.grant.commitment();
    let begin = exchange(
        state,
        RuntimeRequest::BeginGovernedBootstrap {
            grant: config.grant.clone(),
            binding: config.binding.clone(),
            kms_key_id: config.kms_key_id.clone(),
            requested_mode: config.requested_mode.clone(),
        },
    )
    .await?;
    if matches!(begin, RuntimeResponse::Error { ref code } if code == "WRITER_GRANT_REPLAY") {
        return match exchange(state, RuntimeRequest::Status).await? {
            RuntimeResponse::Status { status }
                if status.writer_grant_commitment.as_deref()
                    == Some(expected_commitment.as_str())
                    && ((config.requested_mode == "production-enabled"
                        && status.writer_enabled)
                        || (config.requested_mode == "admission-enabled"
                            && status.admission_enabled
                            && !status.writer_enabled)) =>
            {
                Ok(())
            }
            _ => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "GOVERNED_BOOTSTRAP_REPLAY_MISMATCH",
            )),
        };
    }
    let RuntimeResponse::GovernedKeyRecipient {
        attestation_document,
        writer_grant_commitment,
        kms_key_id,
        encryption_context,
    } = begin
    else {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "GOVERNED_BOOTSTRAP_BEGIN_FAILED",
        ));
    };
    if writer_grant_commitment != expected_commitment
        || kms_key_id != config.kms_key_id
        || attestation_document.is_empty()
        || encryption_context
            .get("layrs-writer-grant")
            .map(String::as_str)
            != Some(expected_commitment.as_str())
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "GOVERNED_BOOTSTRAP_RECIPIENT_MISMATCH",
        ));
    }
    let store = state.artifact_store.as_ref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "DIRECT_ARTIFACT_STORE_NOT_CONFIGURED",
        )
    })?;
    let aws = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let kms = KmsClient::new(&aws);
    let recipient = RecipientInfo::builder()
        .key_encryption_algorithm(KeyEncryptionMechanism::RsaesOaepSha256)
        .attestation_document(KmsBlob::new(attestation_document))
        .build();
    let encryption_context_map: std::collections::HashMap<String, String> =
        encryption_context.clone().into_iter().collect();
    let (artifact, ciphertext_for_recipient) = match store
        .load_key_release(&config.grant.activation_id)
        .await
        .map_err(invalid)?
    {
        Some(artifact) => {
            if !artifact.verify_for(&config.grant, &config.binding, &config.kms_key_id) {
                return Err(invalid("KEY_RELEASE_ARTIFACT_INVALID"));
            }
            let output = kms
                .decrypt()
                .key_id(&config.kms_key_id)
                .ciphertext_blob(KmsBlob::new(artifact.ciphertext_blob.clone()))
                .set_encryption_context(Some(encryption_context_map.clone()))
                .recipient(recipient)
                .send()
                .await
                .map_err(|_| invalid("KMS_ATTESTED_KEY_RELEASE_FAILED"))?;
            if output.plaintext().is_some() {
                return Err(invalid("KMS_RETURNED_PARENT_PLAINTEXT"));
            }
            let ciphertext = output
                .ciphertext_for_recipient()
                .ok_or_else(|| invalid("KMS_RECIPIENT_CIPHERTEXT_MISSING"))?
                .as_ref()
                .to_vec();
            (artifact, ciphertext)
        }
        None => {
            let (ciphertext_blob, ciphertext_for_recipient) = if let Some(predecessor) =
                &config.grant.key_release_predecessor
            {
                let predecessor_artifact = store
                    .load_key_release(&predecessor.activation_id)
                    .await
                    .map_err(invalid)?
                    .ok_or_else(|| invalid("KEY_RELEASE_PREDECESSOR_MISSING"))?;
                if !predecessor_artifact.verify_as_predecessor(predecessor, &config.kms_key_id) {
                    return Err(invalid("KEY_RELEASE_PREDECESSOR_INVALID"));
                }
                let source_context: std::collections::HashMap<String, String> =
                    predecessor_artifact
                        .encryption_context
                        .clone()
                        .into_iter()
                        .collect();
                // KMS changes only the authenticated encryption context of
                // the same enclave root key. The parent receives no
                // plaintext and the signed grant binds the exact immutable
                // predecessor artifact and commitment.
                let reencrypted = kms
                    .re_encrypt()
                    .ciphertext_blob(KmsBlob::new(predecessor_artifact.ciphertext_blob.clone()))
                    .source_key_id(&config.kms_key_id)
                    .destination_key_id(&config.kms_key_id)
                    .set_source_encryption_context(Some(source_context))
                    .set_destination_encryption_context(Some(encryption_context_map.clone()))
                    .send()
                    .await
                    .map_err(|_| invalid("KMS_KEY_CONTINUITY_REENCRYPT_FAILED"))?;
                let ciphertext_blob = reencrypted
                    .ciphertext_blob()
                    .ok_or_else(|| invalid("KMS_REENCRYPTED_BLOB_MISSING"))?
                    .as_ref()
                    .to_vec();
                let released = kms
                    .decrypt()
                    .key_id(&config.kms_key_id)
                    .ciphertext_blob(KmsBlob::new(ciphertext_blob.clone()))
                    .set_encryption_context(Some(encryption_context_map.clone()))
                    .recipient(recipient)
                    .send()
                    .await
                    .map_err(|_| invalid("KMS_ATTESTED_KEY_RELEASE_FAILED"))?;
                if released.plaintext().is_some() {
                    return Err(invalid("KMS_RETURNED_PARENT_PLAINTEXT"));
                }
                let ciphertext_for_recipient = released
                    .ciphertext_for_recipient()
                    .ok_or_else(|| invalid("KMS_RECIPIENT_CIPHERTEXT_MISSING"))?
                    .as_ref()
                    .to_vec();
                (ciphertext_blob, ciphertext_for_recipient)
            } else {
                let output = kms
                    .generate_data_key()
                    .key_id(&config.kms_key_id)
                    .key_spec(DataKeySpec::Aes256)
                    .set_encryption_context(Some(encryption_context_map.clone()))
                    .recipient(recipient)
                    .send()
                    .await
                    .map_err(|_| invalid("KMS_ATTESTED_DATA_KEY_FAILED"))?;
                if output.plaintext().is_some() {
                    return Err(invalid("KMS_RETURNED_PARENT_PLAINTEXT"));
                }
                let ciphertext_blob = output
                    .ciphertext_blob()
                    .ok_or_else(|| invalid("KMS_CIPHERTEXT_BLOB_MISSING"))?
                    .as_ref()
                    .to_vec();
                let ciphertext_for_recipient = output
                    .ciphertext_for_recipient()
                    .ok_or_else(|| invalid("KMS_RECIPIENT_CIPHERTEXT_MISSING"))?
                    .as_ref()
                    .to_vec();
                (ciphertext_blob, ciphertext_for_recipient)
            };
            let artifact = GovernedKeyReleaseArtifact {
                protocol: "layrs.direct-execution.key-release.v1".into(),
                activation_id: config.grant.activation_id.clone(),
                writer_grant_commitment: expected_commitment.clone(),
                runtime_measurement: config.binding.clone(),
                kms_key_id: config.kms_key_id.clone(),
                encryption_context: encryption_context.clone(),
                ciphertext_blob,
            };
            if !artifact.verify_for(&config.grant, &config.binding, &config.kms_key_id) {
                return Err(invalid("KEY_RELEASE_ARTIFACT_INVALID"));
            }
            let artifact = store
                .persist_key_release(&artifact)
                .await
                .map_err(invalid)?;
            (artifact, ciphertext_for_recipient)
        }
    };
    let artifact_hash = artifact.artifact_hash();
    match exchange(
        state,
        RuntimeRequest::CompleteGovernedBootstrap {
            writer_grant_commitment: expected_commitment.clone(),
            key_release_artifact_hash: artifact_hash,
            ciphertext_for_recipient,
            commit_ack_key: state.commit_ack_key.clone(),
        },
    )
    .await?
    {
        RuntimeResponse::GovernedBootstrapComplete {
            writer_grant_commitment,
        } if writer_grant_commitment == expected_commitment => Ok(()),
        RuntimeResponse::Error { code } => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("GOVERNED_BOOTSTRAP_FAILED:{code}"),
        )),
        _ => Err(invalid("GOVERNED_BOOTSTRAP_UNEXPECTED_RESPONSE")),
    }
}

/// One bounded direct request.  The first response is deliberately not a
/// customer result: it is an opaque encrypted successor that must be stored
/// immutably and read back before this parent can issue an acknowledgement.
async fn exchange_direct(state: &AppState, request: DirectRequest) -> io::Result<RuntimeResponse> {
    let store = state.artifact_store.as_ref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "DIRECT_ARTIFACT_STORE_NOT_CONFIGURED",
        )
    })?;
    if state.commit_ack_key.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "DIRECT_COMMIT_ACK_KEY_NOT_CONFIGURED",
        ));
    }
    timeout(Duration::from_secs(10), async {
        let mut stream =
            VsockStream::connect(VsockAddr::new(state.enclave_cid, ENCLOSURE_PORT)).await?;
        write_frame(
            &mut stream,
            &serde_cbor::to_vec(&RuntimeRequest::Execute { request }).map_err(invalid)?,
        )
        .await?;
        let first: RuntimeResponse =
            serde_cbor::from_slice(&read_frame(&mut stream).await?).map_err(invalid)?;
        let RuntimeResponse::CommitCandidate { artifact } = first else {
            return Ok(first);
        };
        // `persist_readback` uses create_new, fsyncs the write, rereads the
        // opaque bytes, decodes them, and compares the complete artifact plus
        // its CBOR hash before this acknowledgement exists.
        let restored = store.persist_readback(&artifact).await.map_err(|error| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("IMMUTABLE_PERSISTENCE_FAILED:{error}"),
            )
        })?;
        if restored != artifact {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ARTIFACT_READBACK_MISMATCH",
            ));
        }
        let ack = DurabilityAck::issue(&restored, &state.commit_ack_key);
        write_frame(
            &mut stream,
            &serde_cbor::to_vec(&RuntimeRequest::DurabilityAck { ack }).map_err(invalid)?,
        )
        .await?;
        let terminal: RuntimeResponse =
            serde_cbor::from_slice(&read_frame(&mut stream).await?).map_err(invalid)?;
        if matches!(terminal, RuntimeResponse::Execute { .. }) {
            *state.committed_state_root.lock().await = Some(restored.state_hash.clone());
        }
        Ok(terminal)
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "enclave timeout"))?
}
fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}
async fn read_frame(stream: &mut VsockStream) -> io::Result<Vec<u8>> {
    let length = stream.read_u32().await? as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(invalid("invalid frame"));
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}
async fn write_frame(stream: &mut VsockStream, bytes: &[u8]) -> io::Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err(invalid("invalid frame"));
    }
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(bytes).await?;
    stream.flush().await
}
#[cfg(test)]
mod tests {
    use super::*;
    fn reconciled_intent(root: &str) -> ExternalEffectIntent {
        ExternalEffectIntent::create(root.into(),"reconciliation-request".into(),"f".repeat(64),"c".repeat(64),"identity".into(),"base".into(),"USDC".into(),"0x2222222222222222222222222222222222222222".into(),"5000000".into(),"existing-wallet".into(),"0x1111111111111111111111111111111111111111".into(),"1".into(),"180000".into(),"11000000".into(),"1000000".into(),now_unix()).unwrap()
    }
    fn nonfinancial_chain() -> Vec<DirectStateArtifact> {
        (0..3).map(|i| { let mut a=projection_sequence_fixture(); a.sequence=i+1; a.prior_state_hash=((b'a'+i as u8) as char).to_string().repeat(64);a.state_hash=((b'b'+i as u8) as char).to_string().repeat(64);a.receipt.account_id="governance".into();a.receipt.request_id=format!("register-{i}");a.receipt.effect="MARKET_REGISTERED".into();a }).collect()
    }
    #[test]
    fn historical_withdrawal_requires_exact_unchanged_verified_ancestry() {
        let intent=reconciled_intent(&"b".repeat(64));let records=nonfinancial_chain();
        assert!(historical_intent_lineage_safe(&intent,&records,&"d".repeat(64)));
        assert!(!historical_intent_lineage_safe(&intent,&records,&"e".repeat(64)));
        assert!(!historical_intent_lineage_safe(&reconciled_intent(&"e".repeat(64)),&records,&"d".repeat(64)));
        let mut gap=records.clone();gap[1].sequence=7;assert!(!historical_intent_lineage_safe(&intent,&gap,&"d".repeat(64)));
        let mut fork=records.clone();fork[1].prior_state_hash="e".repeat(64);assert!(!historical_intent_lineage_safe(&intent,&fork,&"d".repeat(64)));
        let mut collision=records.clone();collision[2].receipt.account_id=intent.account_id.clone();collision[2].receipt.request_id=intent.request_id.clone();assert!(!historical_intent_lineage_safe(&intent,&collision,&"d".repeat(64)));
        let mut changed=records.clone();changed[2].receipt.projection_balance_updates.push(layrs_direct_execution_v1::ProjectionBalanceUpdate {auth_subject_hash:intent.account_id.clone(),identity_commitment:intent.identity_commitment.clone(),asset:"USDC".into(),bucket:"USER_AVAILABLE".into(),amount_atomic:"1".into()});assert!(!historical_intent_lineage_safe(&intent,&changed,&"d".repeat(64)));
    }
    #[test]
    fn confirmed_extra_payout_never_becomes_a_second_customer_debit() {
        let original=reconciled_intent(&"a".repeat(64));let extra=reconciled_intent(&"b".repeat(64));let mut committed=projection_sequence_fixture();
        committed.receipt.account_id=original.account_id.clone();committed.receipt.identity_commitment=original.identity_commitment.clone();committed.receipt.request_id=original.request_id.clone();committed.receipt.request_hash=original.request_hash.clone();committed.receipt.effect="WITHDRAWAL_SETTLED".into();committed.receipt.amount_atomic=Some(original.amount_atomic.clone());committed.receipt.custody_reference=Some(format!("{}:0x{}",original.external_effect_reference,"11".repeat(32)));
        let outcome=ExternalEffectRecovery::BindFinalized {provider_transaction_id:"provider-2".into(),transaction_hash:format!("0x{}","22".repeat(32))};
        let evidence=extra_payout_evidence(&extra,&original,&[committed.clone()],outcome.clone()).unwrap().unwrap();assert_eq!(evidence.amount_atomic,"5000000");assert_eq!(evidence.customer_debit_atomic,"0");assert_eq!(evidence.disposition,"PROTOCOL_OVERPAYMENT_UNRECOVERED");
        assert_eq!(evidence,extra_payout_evidence(&extra,&original,&[committed.clone()],outcome).unwrap().unwrap());
        assert!(extra_payout_evidence(&extra,&original,&[committed.clone()],ExternalEffectRecovery::BindFinalized {provider_transaction_id:"alias".into(),transaction_hash:format!("0x{}","11".repeat(32))}).unwrap().is_none());
        assert!(extra_payout_evidence(&extra,&original,&[committed.clone()],ExternalEffectRecovery::SubmitWithStableReference).is_err());
        assert!(extra_payout_evidence(&extra,&original,&[committed],ExternalEffectRecovery::BindReverted {provider_transaction_id:"reverted".into(),transaction_hash:format!("0x{}","22".repeat(32))}).is_err());
    }
    fn projection_sequence_fixture() -> DirectStateArtifact {
        DirectStateArtifact {
            epoch_id: EPOCH_ID.into(), sequence: 7, prior_state_hash: "a".repeat(64), state_hash: "b".repeat(64), request_hash: "c".repeat(64),
            nonce: vec![1;12], ciphertext: vec![], ciphertext_hash: "d".repeat(64),
            receipt: DirectReceipt { receipt_id: "receipt".into(), account_id: "account".into(), identity_commitment: "identity".into(), request_id: "request".into(), request_hash: "c".repeat(64), status: layrs_direct_execution_v1::TerminalStatus::Applied, effect: "BALANCE_READ".into(), amount_atomic: None, custody_reference: None, execution: None, resolution: None, projection_balance_updates: vec![], genesis_ordinal: 0, signature: "signature".into() }
        }
    }
    #[test]
    fn projection_sequence_requires_exact_verified_receipt() {
        let artifact = projection_sequence_fixture();
        assert_eq!(verified_receipt_sequence(&[artifact.clone()], &artifact.receipt).unwrap(), 7);
        let mut altered = artifact.receipt.clone(); altered.effect = "OTHER".into();
        assert!(verified_receipt_sequence(&[artifact.clone()], &altered).is_err());
        assert!(verified_receipt_sequence(&[], &artifact.receipt).is_err());
        assert!(verified_receipt_sequence(&[artifact.clone(), artifact.clone()], &artifact.receipt).is_err());
    }
    #[test]
    fn projection_sequence_rejects_foreign_zero_and_overflow_artifacts() {
        let original = projection_sequence_fixture();
        for sequence in [0, i64::MAX as u64 + 1] {
            let mut artifact = original.clone(); artifact.sequence = sequence;
            assert!(verified_receipt_sequence(&[artifact], &original.receipt).is_err());
        }
        let mut foreign = original.clone(); foreign.epoch_id = "foreign".into();
        assert!(verified_receipt_sequence(&[foreign], &original.receipt).is_err());
    }
    #[test]
    fn receipt_cache_releases_entire_snapshot_allocation() {
        let artifact=DirectStateArtifact {epoch_id:EPOCH_ID.into(),sequence:1,prior_state_hash:"a".repeat(64),state_hash:"b".repeat(64),request_hash:"c".repeat(64),nonce:vec![1;12],ciphertext:vec![7;2_000_000],ciphertext_hash:"d".repeat(64),
            receipt:DirectReceipt {receipt_id:"receipt".into(),account_id:"account".into(),identity_commitment:"identity".into(),request_id:"request".into(),request_hash:"c".repeat(64),status:layrs_direct_execution_v1::TerminalStatus::Applied,effect:"BALANCE_READ".into(),amount_atomic:None,custody_reference:None,execution:None,resolution:None,projection_balance_updates:vec![],genesis_ordinal:0,signature:"signature".into()}};
        let record=receipt_only_record(&artifact);
        assert_eq!(record.ciphertext.capacity(),0);
        assert!(record.ciphertext.is_empty());
        assert_eq!(record.receipt,artifact.receipt);
        assert_eq!(record.state_hash,artifact.state_hash);
        assert_eq!(artifact.ciphertext.len(),2_000_000);
    }
    #[tokio::test]
    async fn s3_archive_read_discards_truncated_body_and_retries_same_immutable_key() {
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let address=listener.local_addr().unwrap();
        let server=tokio::spawn(async move {
            for attempt in 0..2 {
                let (mut socket,_)=listener.accept().await.unwrap();let mut buffer=vec![0;8192];let size=socket.read(&mut buffer).await.unwrap();
                assert!(String::from_utf8_lossy(&buffer[..size]).contains("/unit-test/epoch/immutable.cbor"));
                let body=if attempt==0 {"bad"}else{"complete-opaque-ciphertext"};
                let length=if attempt==0 {64}else{body.len()};
                socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n{body}").as_bytes()).await.unwrap();
            }
        });
        let configuration=aws_sdk_s3::config::Builder::new().behavior_version_latest().region(aws_sdk_s3::config::Region::new("us-east-1")).credentials_provider(aws_sdk_s3::config::Credentials::new("unit-test","unit-test",None,None,"local-only")).endpoint_url(format!("http://{address}")).force_path_style(true).build();
        let store=S3ImmutableArtifactStore {client:S3Client::from_conf(configuration),bucket:"unit-test".into(),prefix:"epoch".into(),kms_key_id:"not-used".into(),retention_seconds:86400,verified_receipt_records:Arc::new(Mutex::new(None))};
        assert_eq!(store.read("epoch/immutable.cbor").await.unwrap(),b"complete-opaque-ciphertext");server.await.unwrap();
    }
    #[tokio::test]
    async fn s3_archive_read_fails_closed_after_five_truncated_bodies() {
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let address=listener.local_addr().unwrap();
        let server=tokio::spawn(async move {
            for _ in 0..5 {
                let (mut socket,_)=listener.accept().await.unwrap();let mut buffer=vec![0;8192];socket.read(&mut buffer).await.unwrap();
                socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 64\r\nConnection: close\r\n\r\nbad").await.unwrap();
            }
        });
        let configuration=aws_sdk_s3::config::Builder::new().behavior_version_latest().region(aws_sdk_s3::config::Region::new("us-east-1")).credentials_provider(aws_sdk_s3::config::Credentials::new("unit-test","unit-test",None,None,"local-only")).endpoint_url(format!("http://{address}")).force_path_style(true).build();
        let store=S3ImmutableArtifactStore {client:S3Client::from_conf(configuration),bucket:"unit-test".into(),prefix:"epoch".into(),kms_key_id:"not-used".into(),retention_seconds:86400,verified_receipt_records:Arc::new(Mutex::new(None))};
        assert_eq!(store.read("epoch/immutable.cbor").await.unwrap_err(),"archive complete read retries exhausted");server.await.unwrap();
    }
    #[tokio::test]
    async fn s3_restore_listing_reads_beyond_the_first_thousand_without_skipping_keys() {
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let address=listener.local_addr().unwrap();
        let server=tokio::spawn(async move {
            for page in 0..2 {
                let (mut socket,_)=listener.accept().await.unwrap();let mut buffer=vec![0;8192];let size=socket.read(&mut buffer).await.unwrap();let request=String::from_utf8_lossy(&buffer[..size]);
                if page==1 {assert!(request.contains("continuation-token=page-two"));}
                let start=page*1000;let end=if page==0 {1000}else{1250};
                let objects=(start..end).map(|i|format!("<Contents><Key>epoch/artifacts/{:020}.cbor</Key><Size>1</Size></Contents>",i+1)).collect::<String>();
                let next=if page==0 {"<NextContinuationToken>page-two</NextContinuationToken>"}else{""};
                let body=format!("<?xml version=\"1.0\"?><ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><IsTruncated>{}</IsTruncated>{next}{objects}</ListBucketResult>",page==0);
                socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
            }
        });
        let configuration=aws_sdk_s3::config::Builder::new().behavior_version_latest().region(aws_sdk_s3::config::Region::new("us-east-1")).credentials_provider(aws_sdk_s3::config::Credentials::new("unit-test","unit-test",None,None,"local-only")).endpoint_url(format!("http://{address}")).force_path_style(true).build();
        let store=S3ImmutableArtifactStore {client:S3Client::from_conf(configuration),bucket:"unit-test".into(),prefix:"epoch".into(),kms_key_id:"not-used".into(),retention_seconds:86400,verified_receipt_records:Arc::new(Mutex::new(None))};
        let keys=store.list_restore_keys("artifacts").await.unwrap();assert_eq!(keys.len(),1250);assert!(keys.first().unwrap().contains("00000000000000000001"));assert!(keys.last().unwrap().contains("00000000000000001250"));server.await.unwrap();
    }

    fn relay_binding() -> RelayWithdrawalBinding {
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
            expires_at_unix: 10_000,
        }
    }

    fn relay_intent() -> ExternalEffectIntent {
        let relay = relay_binding();
        let reference = relay_reference_for(
            &"a".repeat(64),
            "relay-withdrawal:11111111-2222-4333-8444-555555555555",
            &"b".repeat(64),
            "identity",
            "5000000",
            "existing-wallet",
            &relay,
        );
        let mut request = DirectRequest {
            account_id: "b".repeat(64),
            identity_commitment: "identity".into(),
            request_id: "relay-withdrawal:11111111-2222-4333-8444-555555555555".into(),
            request_hash: String::new(),
            financial_wallet_address: None,
            action: DirectAction::SettleRelayWithdrawal {
                relay: relay.clone(),
                amount_atomic: "5000000".into(),
                custody_reference: reference,
            },
        };
        request.request_hash = request_hash(&request);
        ExternalEffectIntent::create_relay_withdrawal(
            "a".repeat(64),
            request.request_id,
            request.request_hash,
            request.account_id,
            request.identity_commitment,
            "5000000".into(),
            "existing-wallet".into(),
            "0x1111111111111111111111111111111111111111".into(),
            "7".into(),
            "180000".into(),
            "2000000000".into(),
            "1000000000".into(),
            100,
            relay,
        )
        .unwrap()
    }

    fn relay_success_evidence(intent: &ExternalEffectIntent) -> (Value, Value, String, String) {
        let relay = intent.relay.as_ref().unwrap();
        let intake = format!("0x{}", "55".repeat(32));
        let destination = format!("0x{}", "66".repeat(32));
        let status = json!({
            "status": "success",
            "requestId": relay.request_id,
            "inTxHashes": [intake],
            "txHashes": [destination],
            "originChainId": 8453,
            "destinationChainId": relay.destination_chain_id,
        });
        let details = json!({"requests": [{
            "id": relay.request_id,
            "status": "success",
            "recipient": relay.recipient,
            "depositAddress": {"address": relay.deposit_address, "type": "strict"},
            "data": {
                "inTxs": [{"txHash": intake, "chainId": 8453, "status": "success"}],
                "outTxs": [{"txHash": destination, "chainId": relay.destination_chain_id, "status": "success"}],
                "route": {
                    "quoted": {
                        "origin": {"inputCurrency": {"currency": {"chainId": 8453, "address": BASE_USDC_ADDRESS}, "amount": intent.amount_atomic}},
                        "destination": {"outputCurrency": {"currency": {"chainId": relay.destination_chain_id, "address": relay.destination_currency}, "amount": relay.quoted_destination_amount_atomic}}
                    },
                    "actual": {
                        "destination": {"outputCurrency": {"currency": {"chainId": relay.destination_chain_id, "address": relay.destination_currency}, "amount": "4985000"}}
                    }
                }
            }
        }]});
        (status, details, intake, destination)
    }

    #[test]
    fn relay_intake_never_finalizes_private_withdrawal_while_destination_is_pending() {
        let intent = relay_intent();
        let relay = intent.relay.as_ref().unwrap();
        let intake = format!("0x{}", "55".repeat(32));
        let observation = classify_relay_destination_finality(
            &intent,
            "privy-transaction".into(),
            intake.clone(),
            &json!({
                "status": "pending", "requestId": relay.request_id,
                "inTxHashes": [intake], "originChainId": 8453,
                "destinationChainId": relay.destination_chain_id,
            }),
            &Value::Null,
        )
        .unwrap();
        assert!(matches!(
            intent.recovery_action(200, observation),
            ExternalEffectRecovery::AwaitExternalFinality
        ));
    }

    #[test]
    fn relay_success_binds_exact_route_destination_result_and_replays_identically() {
        let intent = relay_intent();
        let (status, details, intake, destination) = relay_success_evidence(&intent);
        let observation = classify_relay_destination_finality(
            &intent,
            "privy-transaction".into(),
            intake,
            &status,
            &details,
        )
        .unwrap();
        let terminal = intent.recovery_action(200, observation);
        assert!(matches!(
            terminal,
            ExternalEffectRecovery::BindRelayFinalized { .. }
        ));
        let first = request_for_external_effect(&intent, terminal.clone()).unwrap();
        let replay = request_for_external_effect(&intent, terminal).unwrap();
        assert_eq!(first, replay);
        assert_eq!(first.request_hash, intent.request_hash);
        assert!(
            matches!(first.action, DirectAction::SettleRelayWithdrawal { custody_reference, .. }
            if custody_reference.contains(&destination))
        );
    }

    #[test]
    fn relay_conflicting_recipient_amount_or_transaction_fails_closed() {
        let intent = relay_intent();
        let (status, mut details, intake, _) = relay_success_evidence(&intent);
        details["requests"][0]["recipient"] = json!("0x9999999999999999999999999999999999999999");
        assert_eq!(
            classify_relay_destination_finality(
                &intent,
                "privy-transaction".into(),
                intake.clone(),
                &status,
                &details,
            )
            .unwrap(),
            layrs_direct_execution_v1::ExternalEffectObservation::Conflict,
        );
        let (status, mut details, _, _) = relay_success_evidence(&intent);
        details["requests"][0]["data"]["route"]["actual"]["destination"]["outputCurrency"]
            ["amount"] = json!("1");
        assert_eq!(
            classify_relay_destination_finality(
                &intent,
                "privy-transaction".into(),
                intake,
                &status,
                &details,
            )
            .unwrap(),
            layrs_direct_execution_v1::ExternalEffectObservation::Conflict,
        );
    }
    #[test]
    fn privy_session_derivation_is_epoch_bound_and_deterministic() {
        let secret = b"p".repeat(32);
        let first = derive_direct_session_key(&secret);
        let second = derive_direct_session_key(&secret);
        assert_eq!(first, second);
        assert_eq!(
            hex::encode(&first),
            "4fe34632da8b4234bc67e743148300263046ab646abc3cd1e49a3c8c6ad6abd9"
        );
        assert_eq!(first.len(), 32);
        assert_ne!(first, secret);
    }
    #[test]
    fn privy_request_expiry_uses_milliseconds() {
        let before = now_unix_millis();
        let expiry = now_unix_millis().checked_add(60_000).unwrap();
        let after = now_unix_millis();
        assert!(expiry >= before + 60_000);
        assert!(expiry <= after + 60_000);
        assert!(expiry >= 1_000_000_000_000);
    }
    #[test]
    fn bff_listener_is_loopback_until_governed_production_mode() {
        assert_eq!(
            runtime_bind_address(None, Some("dormant"), false).unwrap(),
            std::net::Ipv4Addr::LOCALHOST,
        );
        assert!(runtime_bind_address(Some("0.0.0.0"), Some("dormant"), false).is_err());
        assert_eq!(
            runtime_bind_address(Some("0.0.0.0"), Some("dormant"), true).unwrap(),
            "0.0.0.0".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            runtime_bind_address(Some("0.0.0.0"), Some("production-enabled"), false).unwrap(),
            std::net::Ipv4Addr::UNSPECIFIED,
        );
    }
    #[test]
    fn packaged_isolated_routes_are_test_only_and_production_routes_remain_grant_scoped() {
        assert!(direct_writer_route_enabled(true, Some("dormant")));
        assert!(direct_admission_route_enabled(true, Some("dormant")));
        assert!(!direct_writer_route_enabled(false, Some("dormant")));
        assert!(!direct_admission_route_enabled(false, Some("dormant")));
        assert!(!direct_writer_route_enabled(
            false,
            Some("admission-enabled")
        ));
        assert!(direct_admission_route_enabled(
            false,
            Some("admission-enabled")
        ));
        assert!(direct_writer_route_enabled(
            false,
            Some("production-enabled")
        ));
        assert!(direct_admission_route_enabled(
            false,
            Some("production-enabled")
        ));
    }
    #[test]
    fn signed_session_rejects_tampering() {
        let key = vec![9; 32];
        let mut claims = SessionClaims {
            session_id: "isolated-parent-session-0001".into(),
            subject_hash: "a".repeat(64),
            privy_user_id_hash: "b".repeat(64),
            audience: SESSION_AUDIENCE.into(),
            epoch_id: EPOCH_ID.into(),
            epoch_state_sha256: layrs_direct_execution_v1::EPOCH_STATE_SHA256.into(),
            wallet_address: "0x1111111111111111111111111111111111111111".into(),
            financial_wallet_address: None,
            identity_commitment: "c".repeat(64),
            expires_at_unix: now_unix() + 60,
            response_key: URL_SAFE_NO_PAD.encode([3u8; 32]),
            signature: String::new(),
        };
        claims.signature = sign(&key, &serde_json::to_vec(&claims).unwrap());
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            format!(
                "Bearer {}",
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
            )
            .parse()
            .unwrap(),
        );
        let state = AppState {
            enclave_cid: 16,
            session_key: key,
            isolated_test: true,
            projection: None,
            local_used_sessions: Arc::new(Mutex::new(HashSet::new())),
            artifact_store: None,
            commit_ack_key: Vec::new(),
            custody: None,
            zen_custody: None,
            financial_gate: Arc::new(Mutex::new(())),
            committed_state_root: Arc::new(Mutex::new(None)),
            unresolved_external_effects: Arc::new(Mutex::new(BTreeMap::new())),
            governed_bootstrap: None,
        };
        assert!(authenticated(&headers, &state).is_ok());

        claims.financial_wallet_address = Some(claims.wallet_address.clone());
        claims.signature.clear();
        claims.signature = sign(&state.session_key, &serde_json::to_vec(&claims).unwrap());
        headers.insert(
            "authorization",
            format!(
                "Bearer {}",
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
            )
            .parse()
            .unwrap(),
        );
        // Equality with the Privy auth wallet is not an authorization error:
        // this optional field does not select or restrict a withdrawal
        // destination. The signed action supplies that destination.
        assert!(authenticated(&headers, &state).is_ok());

        claims.financial_wallet_address = Some("0x2222222222222222222222222222222222222222".into());
        claims.signature.clear();
        claims.signature = sign(&state.session_key, &serde_json::to_vec(&claims).unwrap());
        headers.insert(
            "authorization",
            format!(
                "Bearer {}",
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
            )
            .parse()
            .unwrap(),
        );
        assert!(authenticated(&headers, &state).is_ok());

        claims.financial_wallet_address = Some("not-an-address".into());
        claims.signature.clear();
        claims.signature = sign(&state.session_key, &serde_json::to_vec(&claims).unwrap());
        headers.insert(
            "authorization",
            format!(
                "Bearer {}",
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
            )
            .parse()
            .unwrap(),
        );
        assert!(authenticated(&headers, &state).is_err());

        headers.insert("authorization", "Bearer bad".parse().unwrap());
        assert!(authenticated(&headers, &state).is_err());
    }

    #[test]
    fn customer_command_accepts_documented_camel_case_fields() {
        let command: CustomerCommand = serde_json::from_value(serde_json::json!({
            "identityCommitment": "identity",
            "action": {
                "type": "RESERVE_WITHDRAWAL",
                "destination": "0xCCB96357dEB4cbF0808208d55916774f0B51a908",
                "amountAtomic": "1000000"
            }
        }))
        .unwrap();
        assert!(matches!(
            command.action,
            CustomerAction::ReserveWithdrawal { amount_atomic, .. } if amount_atomic == "1000000"
        ));
    }

    #[test]
    fn customer_deposit_requires_transaction_hash_and_exact_amount() {
        let command: CustomerCommand = serde_json::from_value(serde_json::json!({
            "identityCommitment": "identity",
            "action": {
                "type": "CREDIT_DEPOSIT",
                "transactionHash": format!("0x{}", "11".repeat(32)),
                "amountAtomic": "5000000"
            }
        }))
        .unwrap();
        assert!(matches!(
            command.action,
            CustomerAction::CreditDeposit { amount_atomic, .. } if amount_atomic == "5000000"
        ));
    }

    #[test]
    fn finalized_deposit_is_bound_to_wallet_pool_token_amount_and_confirmations() {
        let source = "0xd5d8f363b2122c1fcedaff313990b049fbd11e61";
        let pool = "0xb07627b0d646f5c82c8e30975a37650dc272a35f";
        let hash = format!("0x{}", "11".repeat(32));
        let block_hash = format!("0x{}", "22".repeat(32));
        let amount = 5_000_000u128;
        let transaction = json!({
            "from": source,
            "to": BASE_USDC_ADDRESS,
            "input": erc20_transfer_calldata(pool, amount).unwrap(),
            "value": "0x0",
            "blockHash": block_hash,
        });
        let receipt = json!({
            "transactionHash": hash,
            "blockHash": block_hash,
            "blockNumber": "0x64",
            "status": "0x1",
            "logs": [{
                "address": BASE_USDC_ADDRESS,
                "topics": [ERC20_TRANSFER_TOPIC, address_topic(source), address_topic(pool)],
                "data": quantity(amount),
            }],
        });
        assert_eq!(
            classify_base_deposit(source, pool, &hash, amount, 20, &transaction, &receipt, 118)
                .unwrap(),
            DepositFinality::Pending
        );
        assert_eq!(
            classify_base_deposit(source, pool, &hash, amount, 20, &transaction, &receipt, 119)
                .unwrap(),
            DepositFinality::Finalized
        );
        let mut wrong_amount = receipt.clone();
        wrong_amount["logs"][0]["data"] = json!(quantity(amount - 1));
        assert_eq!(
            classify_base_deposit(
                source,
                pool,
                &hash,
                amount,
                20,
                &transaction,
                &wrong_amount,
                119
            )
            .unwrap(),
            DepositFinality::Conflict
        );
        let mut reverted = receipt;
        reverted["status"] = json!("0x0");
        assert_eq!(
            classify_base_deposit(
                source,
                pool,
                &hash,
                amount,
                20,
                &transaction,
                &reverted,
                119
            )
            .unwrap(),
            DepositFinality::Reverted
        );
    }

    #[test]
    fn sponsored_withdrawal_binds_user_operation_and_exact_financial_logs() {
        let wallet = "0x2aeba31935ea5f8993cac56af2ac4dee74cfe13d";
        let pool = "0xb07627b0d646f5c82c8e30975a37650dc272a35f";
        let destination = "0xb69ac21b8a96234a09ba6c7644f1c2b106fd4a01";
        let user_operation_hash = format!("0x{}", "11".repeat(32));
        let amount = 5_000_000u128;
        let intent = ExternalEffectIntent::create(
            "a".repeat(64),
            "sponsored-withdrawal".into(),
            "b".repeat(64),
            "c".repeat(64),
            "identity".into(),
            "base".into(),
            "USDC".into(),
            destination.into(),
            amount.to_string(),
            "existing-wallet".into(),
            pool.into(),
            "1".into(),
            "180000".into(),
            "11000000".into(),
            "1000000".into(),
            now_unix(),
        )
        .unwrap();
        let receipt = json!({
            "logs": [
                {
                    "address": "0x0000000071727de22e5e9d8baf0edac6f37da032",
                    "topics": [USER_OPERATION_EVENT_TOPIC, user_operation_hash, address_topic(wallet)],
                    "data": format!("0x{:064x}{:064x}{:064x}{:064x}", 7, 1, 0, 129_564),
                },
                {
                    "address": BASE_USDC_ADDRESS,
                    "topics": [ERC20_TRANSFER_TOPIC, address_topic(pool), address_topic(destination)],
                    "data": quantity(amount),
                },
                {
                    "address": pool,
                    "topics": [POOL_WITHDRAW_TOPIC, address_topic(destination), address_topic(wallet)],
                    "data": quantity(amount),
                }
            ]
        });
        assert!(sponsored_withdrawal_receipt_matches(
            &intent,
            wallet,
            pool,
            Some(&user_operation_hash),
            &receipt,
        ));
        assert!(!sponsored_withdrawal_receipt_matches(
            &intent,
            wallet,
            pool,
            Some(&format!("0x{}", "22".repeat(32))),
            &receipt,
        ));
        let mut wrong_amount = receipt;
        wrong_amount["logs"][1]["data"] = json!(quantity(amount - 1));
        assert!(!sponsored_withdrawal_receipt_matches(
            &intent,
            wallet,
            pool,
            Some(&user_operation_hash),
            &wrong_amount,
        ));
    }

    #[test]
    fn immutable_intent_rebuilds_the_same_terminal_direct_request() {
        let reference = reference_for(
            &"a".repeat(64),
            "request-1",
            &"b".repeat(64),
            "identity",
            "base",
            "USDC",
            "0x2222222222222222222222222222222222222222",
            "1000000",
            "existing-wallet",
        );
        let mut provisional = DirectRequest {
            account_id: "b".repeat(64),
            identity_commitment: "identity".into(),
            request_id: "request-1".into(),
            request_hash: String::new(),
            financial_wallet_address: Some("0x2222222222222222222222222222222222222222".into()),
            action: DirectAction::ReserveWithdrawal {
                destination: "0x2222222222222222222222222222222222222222".into(),
                amount_atomic: "1000000".into(),
                custody_reference: reference,
            },
        };
        provisional.request_hash = request_hash(&provisional);
        let intent = ExternalEffectIntent::create(
            "a".repeat(64),
            "request-1".into(),
            provisional.request_hash.clone(),
            "b".repeat(64),
            "identity".into(),
            "base".into(),
            "USDC".into(),
            "0x2222222222222222222222222222222222222222".into(),
            "1000000".into(),
            "existing-wallet".into(),
            "0x1111111111111111111111111111111111111111".into(),
            "7".into(),
            "180000".into(),
            "2000000000".into(),
            "1000000000".into(),
            100,
        )
        .unwrap();
        let rebuilt = request_for_external_effect(
            &intent,
            ExternalEffectRecovery::BindFinalized {
                provider_transaction_id: "provider-1".into(),
                transaction_hash: format!("0x{}", "11".repeat(32)),
            },
        )
        .unwrap();
        assert_eq!(rebuilt.request_hash, intent.request_hash);
        assert!(
            matches!(rebuilt.action, DirectAction::ReserveWithdrawal { custody_reference, .. } if custody_reference.starts_with(&format!("{}:", intent.external_effect_reference)))
        );
    }

    #[test]
    fn committed_withdrawal_replay_precedes_a_duplicate_unsubmitted_intent() {
        let account = "b".repeat(64);
        let destination = "0xCCB96357dEB4cbF0808208d55916774f0B51a908";
        let reference = reference_for(
            &"a".repeat(64),
            "request-1",
            &account,
            "identity",
            "base",
            "USDC",
            destination,
            "1000000",
            "existing-wallet",
        );
        let custody_reference = format!("{}:0x{}", reference, "11".repeat(32));
        let mut request = DirectRequest {
            account_id: account.clone(),
            identity_commitment: "identity".into(),
            request_id: "request-1".into(),
            request_hash: String::new(),
            financial_wallet_address: Some(destination.to_ascii_lowercase()),
            action: DirectAction::ReserveWithdrawal {
                destination: destination.into(),
                amount_atomic: "1000000".into(),
                custody_reference: custody_reference.clone(),
            },
        };
        request.request_hash = request_hash(&request);
        let committed = ExternalEffectIntent::create(
            "a".repeat(64),
            "request-1".into(),
            request.request_hash.clone(),
            account.clone(),
            "identity".into(),
            "base".into(),
            "USDC".into(),
            destination.into(),
            "1000000".into(),
            "existing-wallet".into(),
            "0x1111111111111111111111111111111111111111".into(),
            "7".into(),
            "180000".into(),
            "2000000000".into(),
            "1000000000".into(),
            100,
        )
        .unwrap();
        let duplicate = ExternalEffectIntent::create(
            "d".repeat(64),
            "request-1".into(),
            "e".repeat(64),
            account.clone(),
            "identity".into(),
            "base".into(),
            "USDC".into(),
            destination.into(),
            "1000000".into(),
            "existing-wallet".into(),
            "0x1111111111111111111111111111111111111111".into(),
            "8".into(),
            "180000".into(),
            "2000000000".into(),
            "1000000000".into(),
            101,
        )
        .unwrap();
        assert!(same_external_effect_request(&committed, &duplicate));
        let artifact = DirectStateArtifact {
            epoch_id: EPOCH_ID.into(),
            sequence: 2,
            prior_state_hash: "a".repeat(64),
            state_hash: "d".repeat(64),
            request_hash: request.request_hash.clone(),
            nonce: vec![1; 12],
            ciphertext: vec![2; 16],
            ciphertext_hash: "f".repeat(64),
            receipt: DirectReceipt {
                receipt_id: "receipt".into(),
                account_id: account.clone(),
                identity_commitment: "identity".into(),
                request_id: "request-1".into(),
                request_hash: request.request_hash,
                status: layrs_direct_execution_v1::TerminalStatus::Applied,
                effect: "WITHDRAWAL_SETTLED".into(),
                amount_atomic: Some("1000000".into()),
                custody_reference: Some(custody_reference.clone()),
                execution: None,
                resolution: None,
                projection_balance_updates: vec![],
                genesis_ordinal: 0,
                signature: "signature".into(),
            },
        };
        let replay = committed_external_effect_action(
            &[committed, duplicate],
            &[artifact],
            &account,
            "identity",
            "request-1",
            destination,
            "1000000",
            None,
        )
        .unwrap();
        assert!(matches!(
            replay,
            Some(DirectAction::ReserveWithdrawal {
                custody_reference: value,
                ..
            }) if value == custody_reference
        ));
    }

    #[test]
    fn pool_calldata_is_bound_to_exact_destination_and_amount() {
        let data = pool_withdraw_calldata("0xCCB96357dEB4cbF0808208d55916774f0B51a908", "1000000")
            .unwrap();
        assert_eq!(data.len(), 2 + 8 + 64 + 64);
        assert!(data.ends_with(&format!("{:0>64}", "f4240")));
        assert!(data.contains("000000000000000000000000ccb96357deb4cbf0808208d55916774f0b51a908"));
        assert!(pool_withdraw_calldata("bad", "1000000").is_err());
        assert!(pool_withdraw_calldata("0xCCB96357dEB4cbF0808208d55916774f0B51a908", "0").is_err());
    }

    #[test]
    fn base_withdrawal_requires_signed_action_equality_without_an_allowlist() {
        let destination = "0xCCB96357dEB4cbF0808208d55916774f0B51a908";
        assert!(signed_base_withdrawal_destination_matches(
            destination,
            "0xccb96357deb4cbf0808208d55916774f0b51a908"
        ));

        // Both are valid Base addresses, but a session signed for one may not
        // authorize the other.
        assert!(!signed_base_withdrawal_destination_matches(
            destination,
            "0x1cBE2DDB7C7AC4C67BC692CB463f759D0D7b4dED"
        ));
        assert!(!signed_base_withdrawal_destination_matches(
            "not-an-address",
            "not-an-address"
        ));
        assert!(!signed_base_withdrawal_destination_matches(
            "0x0000000000000000000000000000000000000000",
            "0x0000000000000000000000000000000000000000"
        ));
    }
}
