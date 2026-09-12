//! Parent boundary for the clean direct runtime.  A Privy-verified BFF mints
//! short-lived signed sessions; the browser never supplies an auth subject or enclave frame.
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
use layrs_direct_execution_v1::{
    artifact_hash, reference_for, request_hash, sha256, sign, DirectAction, DirectReceipt,
    DirectRequest, DirectResult, DirectStateArtifact, DurabilityAck, ExternalEffectIntent,
    ExternalEffectRecovery, FilesystemImmutableArtifactStore, FilesystemImmutableIntentStore,
    ImmutableExternalEffectIntentStore, ProjectionBalanceRow, ProjectionWalletRow, RuntimeRequest,
    RuntimeResponse, SealedEpoch, WriterGrant, EPOCH_ID, POSTGRES_PROJECTION_DDL,
};
use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    pkcs8::DecodePrivateKey,
};
use reqwest::header::{HeaderMap as ReqwestHeaderMap, HeaderValue, ACCEPT};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha3::{Digest as KeccakDigest, Keccak256};
use std::{
    collections::{BTreeMap, HashSet},
    env, io,
    net::Ipv4Addr,
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
const MAX_FRAME_BYTES: usize = 1024 * 1024;
const SESSION_AUDIENCE: &str = "layrs.direct-execution.v1";
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
    /// Serializes only the bounded synchronous request and an unresolved
    /// external intent.  It is process memory, never durable workflow state.
    financial_gate: Arc<Mutex<()>>,
    committed_state_root: Arc<Mutex<Option<String>>>,
    unresolved_external_effects: Arc<Mutex<BTreeMap<String, ExternalEffectIntent>>>,
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
        match status {
            "pending" | "broadcasted" => Ok(
                layrs_direct_execution_v1::ExternalEffectObservation::Pending {
                    provider_transaction_id: id,
                },
            ),
            "confirmed" | "finalized" => match transaction_hash {
                Some(transaction_hash) => {
                    self.authoritative_finality(intent, id, transaction_hash)
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
                    self.authoritative_finality(intent, id, transaction_hash)
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
            "0x1" => Ok(
                layrs_direct_execution_v1::ExternalEffectObservation::Finalized {
                    provider_transaction_id,
                    transaction_hash,
                },
            ),
            "0x0" => Ok(
                layrs_direct_execution_v1::ExternalEffectObservation::Reverted {
                    provider_transaction_id,
                    transaction_hash,
                },
            ),
            _ => Ok(layrs_direct_execution_v1::ExternalEffectObservation::Conflict),
        }
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
        let expiry = now_unix()
            .checked_add(60)
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
    async fn read(&self, key: &str) -> Result<Vec<u8>, String> {
        Ok(self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|_| "archive read failed")?
            .body
            .collect()
            .await
            .map_err(|_| "archive read body failed")?
            .into_bytes()
            .to_vec())
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
        Ok(restored)
    }
    async fn load_committed(&self) -> Result<Vec<DirectStateArtifact>, String> {
        let listing = self
            .client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(format!("{}/artifacts/", self.prefix))
            .send()
            .await
            .map_err(|_| "archive listing failed")?;
        if listing.is_truncated.unwrap_or(false) {
            return Err("archive listing exceeds bounded recovery set".into());
        }
        let mut artifacts = Vec::new();
        let mut object_hashes = HashSet::new();
        let mut sequences = HashSet::new();
        for object in listing.contents() {
            let key = object.key().ok_or("archive object key missing")?;
            let artifact: DirectStateArtifact = serde_cbor::from_slice(&self.read(key).await?)
                .map_err(|_| "artifact decode failed")?;
            // The object name is part of the immutable commitment.  Accepting
            // a second spelling for the same encrypted artifact could hide a
            // duplicate or a conflicting archive object from recovery.
            if key != self.artifact_key(&artifact)
                || !object_hashes.insert(artifact_hash(&artifact))
                || !sequences.insert(artifact.sequence)
            {
                return Err("duplicate or conflicting archive artifact".into());
            }
            artifacts.push(artifact);
        }
        artifacts.sort_by_key(|artifact: &DirectStateArtifact| artifact.sequence);
        for artifact in &artifacts {
            let head = self.read(&self.head_key(artifact)).await?;
            if head != serde_cbor::to_vec(artifact).map_err(|_| "head encoding failed")? {
                return Err("archive head mismatch".into());
            }
        }
        Ok(artifacts)
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
}

#[derive(Clone)]
struct Projection {
    client: Arc<Client>,
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
#[serde(
    tag = "type",
    rename_all = "SCREAMING_SNAKE_CASE",
    rename_all_fields = "camelCase"
)]
enum CustomerAction {
    PlaceOrder {
        order_id: String,
        market_id: String,
        reserve_atomic: String,
    },
    CancelOrder {
        order_id: String,
    },
    ReserveWithdrawal {
        destination: String,
        amount_atomic: String,
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
    wallet_address: String,
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
        // A dormant image can answer health, status, and attestation without a
        // session secret. Customer routes fail closed until an isolated test or
        // later governed activation injects the BFF verification key.
        .unwrap_or_default();
    let isolated_test = env::var("LAYRS_DIRECT_ISOLATED_TEST").as_deref() == Ok("true");
    let dormant = matches!(
        env::var("LAYRS_DIRECT_EXECUTION_MODE").as_deref(),
        Err(_) | Ok("dormant")
    );
    let projection = match env::var("LAYRS_DIRECT_PROJECTION_DATABASE_URL") {
        Ok(url) => Some(Projection::connect(&url, &epoch).await?),
        Err(_) if isolated_test => {
            return Err("isolated direct execution requires an isolated projection database".into())
        }
        Err(_) => None,
    };
    if env::var("LAYRS_DIRECT_EXECUTION_MODE").as_deref() == Ok("production-enabled") {
        let grant: WriterGrant = env::var("LAYRS_DIRECT_WRITER_GRANT_JSON")
            .ok()
            .and_then(|value| serde_json::from_str(&value).ok())
            .ok_or("production writer grant is required")?;
        projection
            .as_ref()
            .ok_or("production projection is required")?
            .verify_active_writer_grant(&grant)
            .await
            .map_err(|_| "writer fence verification failed")?;
    }
    let state = AppState {
        enclave_cid: env::var("LAYRS_ENCLAVE_CID")
            .unwrap_or_else(|_| "16".into())
            .parse()?,
        session_key,
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
        custody: PrivyBaseCustodyAdapter::from_environment()
            .map_err(|error| format!("direct custody configuration invalid: {error}"))?,
        financial_gate: Arc::new(Mutex::new(())),
        committed_state_root: Arc::new(Mutex::new(None)),
        unresolved_external_effects: Arc::new(Mutex::new(BTreeMap::new())),
    };
    // A Nitro EIF does not inherit the parent's systemd environment.  The
    // isolated test key material therefore crosses the existing VSOCK channel
    // once, before recovery; production never uses this bootstrap.
    bootstrap_isolated_enclave(&state).await?;
    // The HTTP parent never accepts a financial command until it has supplied
    // the immutable archive's complete, head-verified recovery set and the
    // enclave has independently reconstructed it.  PostgreSQL is excluded.
    recover_enclave(&state).await?;
    recover_external_effect_intents(&state).await?;
    let port = env::var("PORT").unwrap_or_else(|_| "8443".into()).parse()?;
    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/attestation", get(attestation))
        .route("/v1/runtime/status", get(status))
        .route("/v1/direct/commands", post(command))
        .route("/v1/direct/balances/:identity", get(balance))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
async fn attestation(
    State(state): State<AppState>,
    Query(query): Query<AttestationQuery>,
) -> impl IntoResponse {
    let nonce = match URL_SAFE_NO_PAD.decode(query.nonce) {
        Ok(value) if (16..=512).contains(&value.len()) => value,
        _ => return (StatusCode::BAD_REQUEST, "INVALID_NONCE").into_response(),
    };
    match exchange(&state, RuntimeRequest::Attestation { nonce }).await { Ok(RuntimeResponse::Attestation { document, binding }) => Json(serde_json::json!({"attestationDocument": URL_SAFE_NO_PAD.encode(document), "binding": binding})).into_response(), Ok(RuntimeResponse::Error { code }) => (StatusCode::BAD_GATEWAY, code).into_response(), _ => (StatusCode::BAD_GATEWAY, "UNEXPECTED_RESPONSE").into_response() }
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
    let request_id = match headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty() && value.len() <= 200)
    {
        Some(value) => value.to_string(),
        None => return (StatusCode::BAD_REQUEST, "IDEMPOTENCY_KEY_REQUIRED").into_response(),
    };
    let _financial_guard = state.financial_gate.lock().await;
    let external_effect_pending = !state.unresolved_external_effects.lock().await.is_empty();
    let action = match body.action {
        CustomerAction::PlaceOrder {
            order_id,
            market_id,
            reserve_atomic,
        } if !external_effect_pending => DirectAction::PlaceOrder {
            order_id,
            market_id,
            reserve_atomic,
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
        } => {
            // A direct withdrawal is deliberately not a general-purpose
            // transfer instruction.  The Privy-verifying BFF has bound this
            // short-lived assertion to one embedded EVM wallet, and the
            // parent must enforce that binding before a candidate exists.
            // Comparing canonical EVM spellings is case-insensitive only;
            // no alternate destination can be authorized by this route.
            if !withdrawal_destination_matches(&destination, &claims.wallet_address) {
                return (StatusCode::FORBIDDEN, "DIRECT_DESTINATION_BINDING_DENIED")
                    .into_response();
            }
            match prepare_external_withdrawal(
                &state,
                &claims,
                &body.identity_commitment,
                &request_id,
                destination,
                amount_atomic,
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
                if projection.record_result(&result).await.is_err() {
                    return (StatusCode::SERVICE_UNAVAILABLE, "PROJECTION_UNAVAILABLE")
                        .into_response();
                }
            }
            encrypted(&claims, &result)
        }
        Ok(RuntimeResponse::Error { code }) => {
            (StatusCode::UNPROCESSABLE_ENTITY, code).into_response()
        }
        _ => (StatusCode::BAD_GATEWAY, "ENCLOSURE_UNAVAILABLE").into_response(),
    }
}

async fn prepare_external_withdrawal(
    state: &AppState,
    claims: &SessionClaims,
    identity_commitment: &str,
    request_id: &str,
    destination: String,
    amount_atomic: String,
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
        })
        .cloned()
    {
        match custody.settle(&existing, now_unix()).await.map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "CUSTODY_FINALITY_UNAVAILABLE",
            )
        })? {
            ExternalEffectRecovery::BindFinalized {
                transaction_hash, ..
            } => {
                state
                    .unresolved_external_effects
                    .lock()
                    .await
                    .remove(&existing.intent_hash);
                return Ok(DirectAction::ReserveWithdrawal {
                    destination,
                    amount_atomic,
                    custody_reference: format!(
                        "{}:{}",
                        existing.external_effect_reference, transaction_hash
                    ),
                });
            }
            ExternalEffectRecovery::BindReverted {
                transaction_hash, ..
            } => {
                state
                    .unresolved_external_effects
                    .lock()
                    .await
                    .remove(&existing.intent_hash);
                return Ok(DirectAction::RecordWithdrawalReverted {
                    destination,
                    amount_atomic,
                    custody_reference: format!(
                        "{}:{}",
                        existing.external_effect_reference, transaction_hash
                    ),
                });
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
    let reference = reference_for(
        &prior_state_hash,
        request_id,
        &claims.subject_hash,
        identity_commitment,
        "base",
        "USDC",
        &destination,
        &amount_atomic,
        &custody.wallet_id,
    );
    let provisional = DirectRequest {
        account_id: claims.subject_hash.clone(),
        identity_commitment: identity_commitment.into(),
        request_id: request_id.into(),
        request_hash: String::new(),
        action: DirectAction::ReserveWithdrawal {
            destination: destination.clone(),
            amount_atomic: amount_atomic.clone(),
            custody_reference: reference,
        },
    };
    let mut provisional = provisional;
    provisional.request_hash = request_hash(&provisional);
    let intent = ExternalEffectIntent::create(
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
    )
    .map_err(|_| (StatusCode::BAD_REQUEST, "INVALID_WITHDRAWAL_INTENT"))?;
    let intent = store.persist_intent_readback(&intent).await.map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "EXTERNAL_EFFECT_INTENT_PERSISTENCE_FAILED",
        )
    })?;
    match custody.settle(&intent, now_unix()).await.map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "CUSTODY_FINALITY_UNAVAILABLE",
        )
    })? {
        ExternalEffectRecovery::BindFinalized {
            transaction_hash, ..
        } => Ok(DirectAction::ReserveWithdrawal {
            destination,
            amount_atomic,
            custody_reference: format!("{}:{}", intent.external_effect_reference, transaction_hash),
        }),
        ExternalEffectRecovery::BindReverted {
            transaction_hash, ..
        } => Ok(DirectAction::RecordWithdrawalReverted {
            destination,
            amount_atomic,
            custody_reference: format!("{}:{}", intent.external_effect_reference, transaction_hash),
        }),
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

fn withdrawal_destination_matches(destination: &str, verified_wallet: &str) -> bool {
    destination.len() == 42
        && verified_wallet.len() == 42
        && destination.starts_with("0x")
        && verified_wallet.starts_with("0x")
        && destination.eq_ignore_ascii_case(verified_wallet)
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

impl Projection {
    async fn connect(url: &str, epoch: &SealedEpoch) -> Result<Self, Box<dyn std::error::Error>> {
        let (client, connection) = tokio_postgres::connect(url, NoTls).await?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let projection = Self {
            client: Arc::new(client),
        };
        projection
            .client
            .batch_execute(POSTGRES_PROJECTION_DDL)
            .await?;
        if let Err(error) = projection.import_opening(epoch).await {
            return Err(format!("opening projection import failed: {error:?}").into());
        }
        Ok(projection)
    }

    async fn import_opening(&self, epoch: &SealedEpoch) -> Result<(), ProjectionError> {
        let balances = epoch.projection_rows();
        let wallets = epoch.projection_wallet_rows();
        for row in &balances {
            self.client.execute(
                "INSERT INTO direct_execution_epoch_balances (epoch_id, auth_subject_hash, identity_commitment, asset, bucket, amount_atomic) VALUES ($1,$2,$3,$4,$5,$6::text::numeric) ON CONFLICT (epoch_id, identity_commitment, asset, bucket) DO NOTHING",
                &[&EPOCH_ID, &row.auth_subject_hash, &row.identity_commitment, &row.asset, &row.bucket, &row.amount_atomic],
            ).await.map_err(|_| ProjectionError::Database)?;
        }
        for row in &wallets {
            self.client.execute(
                "INSERT INTO direct_execution_privy_wallets (epoch_id, auth_subject_hash, wallet_address) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING",
                &[&EPOCH_ID, &row.auth_subject_hash, &row.wallet_address],
            ).await.map_err(|_| ProjectionError::Database)?;
        }
        self.verify_opening(&balances, &wallets).await
    }

    async fn verify_opening(
        &self,
        balances: &[ProjectionBalanceRow],
        wallets: &[ProjectionWalletRow],
    ) -> Result<(), ProjectionError> {
        for row in balances {
            let actual = self.client.query_opt(
                "SELECT amount_atomic::text, auth_subject_hash FROM direct_execution_epoch_balances WHERE epoch_id=$1 AND identity_commitment=$2 AND asset=$3 AND bucket=$4",
                &[&EPOCH_ID, &row.identity_commitment, &row.asset, &row.bucket],
            ).await.map_err(|_| ProjectionError::Database)?.ok_or(ProjectionError::OpeningMismatch)?;
            let amount: String = actual.get(0);
            let subject: String = actual.get(1);
            if amount != row.amount_atomic || subject != row.auth_subject_hash {
                return Err(ProjectionError::OpeningMismatch);
            }
        }
        for row in wallets {
            let found = self.client.query_opt(
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
        let inserted = self.client.execute(
            "INSERT INTO direct_execution_sessions (epoch_id, session_id, auth_subject_hash, request_hash, expires_at_unix) VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING",
            &[&EPOCH_ID, &claims.session_id, &claims.subject_hash, &request_hash, &(claims.expires_at_unix as i64)],
        ).await.map_err(|_| ProjectionError::Database)?;
        if inserted == 1 {
            return Ok(());
        }
        let existing = self.client.query_opt(
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

    async fn record_result(&self, result: &DirectResult) -> Result<(), ProjectionError> {
        let receipt = &result.receipt;
        self.client.execute(
            "INSERT INTO direct_execution_receipts (receipt_id, epoch_id, auth_subject_hash, identity_commitment, request_id, request_hash, terminal_status, effect, custody_reference, receipt_json) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::text::jsonb) ON CONFLICT (receipt_id) DO NOTHING",
            &[&receipt.receipt_id, &EPOCH_ID, &receipt.account_id, &receipt.identity_commitment, &receipt.request_id, &receipt.request_hash, &format!("{:?}", receipt.status).to_uppercase(), &receipt.effect, &receipt.custody_reference, &serde_json::to_string(receipt).map_err(|_| ProjectionError::Database)?],
        ).await.map_err(|_| ProjectionError::Database)?;
        let accounting_amount = receipt.amount_atomic.clone();
        let (direction, amount) = receipt_custody(receipt);
        if let (Some(reference), Some(direction), Some(amount)) =
            (&receipt.custody_reference, direction, amount)
        {
            self.client.execute(
                "INSERT INTO direct_execution_custody_events (epoch_id, custody_reference, direction, state, chain_id, tx_hash, auth_subject_hash, identity_commitment, amount_atomic) VALUES ($1,$2,$3,'FINAL',8453,$4,$5,$6,$7::text::numeric) ON CONFLICT DO NOTHING",
                &[&EPOCH_ID, reference, &direction, reference, &receipt.account_id, &receipt.identity_commitment, &amount],
            ).await.map_err(|_| ProjectionError::Database)?;
        }
        self.client.execute(
            "INSERT INTO direct_execution_accounting_events (receipt_id, epoch_id, auth_subject_hash, identity_commitment, effect, amount_atomic) VALUES ($1,$2,$3,$4,$5,$6::text::numeric) ON CONFLICT DO NOTHING",
            &[&receipt.receipt_id, &EPOCH_ID, &receipt.account_id, &receipt.identity_commitment, &receipt.effect, &accounting_amount],
        ).await.map_err(|_| ProjectionError::Database)?;
        Ok(())
    }

    async fn verify_active_writer_grant(&self, grant: &WriterGrant) -> Result<(), ProjectionError> {
        let row = self.client.query_opt(
            "SELECT old_writer_fence_evidence_sha256, old_writer_authorized, target_writer_enabled, activation_id FROM direct_execution_writer_fence WHERE epoch_id=$1",
            &[&EPOCH_ID],
        ).await.map_err(|_| ProjectionError::Database)?.ok_or(ProjectionError::OpeningMismatch)?;
        let fence_hash: String = row.get(0);
        let old_authorized: bool = row.get(1);
        let target_enabled: bool = row.get(2);
        let activation: Option<String> = row.get(3);
        if old_authorized
            || !target_enabled
            || fence_hash != grant.old_writer_fence_evidence_sha256
            || activation.as_deref() != Some(&grant.activation_id)
        {
            return Err(ProjectionError::OpeningMismatch);
        }
        let grant_row = self.client.query_opt(
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

fn request_for_external_effect(
    intent: &ExternalEffectIntent,
    outcome: ExternalEffectRecovery,
) -> Result<DirectRequest, io::Error> {
    let (action, transaction_hash) = match outcome {
        ExternalEffectRecovery::BindFinalized {
            transaction_hash, ..
        } => ("final", transaction_hash),
        ExternalEffectRecovery::BindReverted {
            transaction_hash, ..
        } => ("reverted", transaction_hash),
        _ => return Err(invalid("external effect is not terminal")),
    };
    let custody_reference = format!("{}:{}", intent.external_effect_reference, transaction_hash);
    let action = if action == "final" {
        DirectAction::ReserveWithdrawal {
            destination: intent.destination.clone(),
            amount_atomic: intent.amount_atomic.clone(),
            custody_reference,
        }
    } else {
        DirectAction::RecordWithdrawalReverted {
            destination: intent.destination.clone(),
            amount_atomic: intent.amount_atomic.clone(),
            custody_reference,
        }
    };
    let mut request = DirectRequest {
        account_id: intent.account_id.clone(),
        identity_commitment: intent.identity_commitment.clone(),
        request_id: intent.request_id.clone(),
        request_hash: String::new(),
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
    for intent in intents {
        if intent_is_committed(&intent, &artifacts) {
            continue;
        }
        let root = state.committed_state_root.lock().await.clone();
        if root.as_deref() != Some(intent.prior_state_hash.as_str()) {
            return Err(invalid(
                "unresolved external-effect intent does not match committed lineage",
            ));
        }
        let Some(custody) = &state.custody else {
            state
                .unresolved_external_effects
                .lock()
                .await
                .insert(intent.intent_hash.clone(), intent);
            continue;
        };
        match custody.settle(&intent, now_unix()).await.map_err(invalid)? {
            terminal @ (ExternalEffectRecovery::BindFinalized { .. }
            | ExternalEffectRecovery::BindReverted { .. }) => {
                let request = request_for_external_effect(&intent, terminal)?;
                let response = exchange_direct(state, request).await?;
                let RuntimeResponse::Execute { result } = response else {
                    return Err(invalid("external-effect recovery execution failed"));
                };
                if let Some(projection) = &state.projection {
                    projection.record_result(&result).await.map_err(|_| {
                        invalid("projection unavailable during external-effect recovery")
                    })?;
                }
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
            financial_gate: Arc::new(Mutex::new(())),
            committed_state_root: Arc::new(Mutex::new(None)),
            unresolved_external_effects: Arc::new(Mutex::new(BTreeMap::new())),
        };
        assert!(authenticated(&headers, &state).is_ok());
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
    fn immutable_intent_rebuilds_the_same_terminal_direct_request() {
        let reference = reference_for(
            &"a".repeat(64),
            "request-1",
            &"b".repeat(64),
            "identity",
            "base",
            "USDC",
            "0xCCB96357dEB4cbF0808208d55916774f0B51a908",
            "1000000",
            "existing-wallet",
        );
        let mut provisional = DirectRequest {
            account_id: "b".repeat(64),
            identity_commitment: "identity".into(),
            request_id: "request-1".into(),
            request_hash: String::new(),
            action: DirectAction::ReserveWithdrawal {
                destination: "0xCCB96357dEB4cbF0808208d55916774f0B51a908".into(),
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
            "0xCCB96357dEB4cbF0808208d55916774f0B51a908".into(),
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
    fn withdrawal_destination_must_equal_session_bound_privy_wallet() {
        assert!(withdrawal_destination_matches(
            "0xCCB96357dEB4cbF0808208d55916774f0B51a908",
            "0xccb96357deb4cbf0808208d55916774f0b51a908"
        ));
        assert!(!withdrawal_destination_matches(
            "0xCCB96357dEB4cbF0808208d55916774f0B51a908",
            "0x1cBE2DDB7C7AC4C67BC692CB463f759D0D7b4dED"
        ));
    }
}
