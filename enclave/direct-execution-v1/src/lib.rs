use std::{collections::BTreeMap, fs, path::Path};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const EPOCH_ID: &str = "layrs-opening-epoch-20260911-941107537728c98b";
pub const EPOCH_STATE_SHA256: &str =
    "84835da82210671d87321a21246317d898afd35381c57be8522df1a516dc3590";
pub const TRANSACTION_MODEL: &str = "layrs.direct-execution.v1";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RuntimeError {
    #[error("opening epoch cannot be read")]
    Read,
    #[error("opening epoch hash mismatch")]
    EpochHash,
    #[error("opening epoch schema or safety controls mismatch")]
    EpochSchema,
    #[error("financial effects are disabled in dormant mode")]
    Dormant,
    #[error("request id was reused with different content")]
    RequestReuse,
    #[error("invalid direct request")]
    InvalidRequest,
    #[error("insufficient available balance")]
    InsufficientAvailable,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawEpoch {
    epoch_id: String,
    lineage: Lineage,
    architecture: serde_json::Value,
    identities: Vec<Identity>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Lineage {
    #[serde(rename = "type")]
    lineage_type: String,
    genesis_ordinal: u64,
    predecessor_lineage_claim: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Identity {
    identity_commitment: String,
    balances: Vec<Balance>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Balance {
    asset: String,
    bucket: String,
    amount_atomic: String,
}

#[derive(Debug, Clone)]
pub struct SealedEpoch {
    identities: BTreeMap<String, BTreeMap<(String, String), u128>>,
}

impl SealedEpoch {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, RuntimeError> {
        let bytes = fs::read(path).map_err(|_| RuntimeError::Read)?;
        if sha256(&bytes) != EPOCH_STATE_SHA256 {
            return Err(RuntimeError::EpochHash);
        }
        let raw: RawEpoch =
            serde_json::from_slice(&bytes).map_err(|_| RuntimeError::EpochSchema)?;
        let valid = raw.epoch_id == EPOCH_ID
            && raw.lineage.lineage_type == "GOVERNED_FRESH_OPENING_STATE"
            && raw.lineage.genesis_ordinal == 0
            && raw.lineage.predecessor_lineage_claim.is_none()
            && raw
                .architecture
                .get("transactionModel")
                .and_then(serde_json::Value::as_str)
                == Some(TRANSACTION_MODEL);
        if !valid {
            return Err(RuntimeError::EpochSchema);
        }
        let identities = raw
            .identities
            .into_iter()
            .map(|identity| {
                let balances = identity
                    .balances
                    .into_iter()
                    .map(|balance| {
                        let amount = balance
                            .amount_atomic
                            .parse()
                            .map_err(|_| RuntimeError::EpochSchema)?;
                        Ok(((balance.asset, balance.bucket), amount))
                    })
                    .collect::<Result<BTreeMap<_, _>, RuntimeError>>()?;
                Ok((identity.identity_commitment, balances))
            })
            .collect::<Result<BTreeMap<_, _>, RuntimeError>>()?;
        Ok(Self { identities })
    }

    pub fn identity_count(&self) -> usize {
        self.identities.len()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeMode {
    Dormant,
    IsolatedTest,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DirectRequest {
    pub account_id: String,
    pub request_id: String,
    pub request_hash: String,
    pub action: DirectAction,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DirectAction {
    ReserveWithdrawal {
        identity_commitment: String,
        amount_atomic: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TerminalStatus {
    Applied,
    RejectedEffectNone,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DirectResult {
    pub status: TerminalStatus,
    pub effect: String,
    pub genesis_ordinal: u64,
}

pub struct DirectRuntime {
    balances: BTreeMap<String, BTreeMap<(String, String), u128>>,
    mode: RuntimeMode,
    requests: BTreeMap<(String, String), (String, DirectResult)>,
}

impl DirectRuntime {
    pub fn new(epoch: SealedEpoch, mode: RuntimeMode) -> Self {
        Self {
            balances: epoch.identities,
            mode,
            requests: BTreeMap::new(),
        }
    }

    pub fn execute(&mut self, request: DirectRequest) -> Result<DirectResult, RuntimeError> {
        if request.account_id.is_empty()
            || request.request_id.is_empty()
            || request.request_hash != request_hash(&request)
        {
            return Err(RuntimeError::InvalidRequest);
        }
        let key = (request.account_id.clone(), request.request_id.clone());
        if let Some((prior_hash, result)) = self.requests.get(&key) {
            return if *prior_hash == request.request_hash {
                Ok(result.clone())
            } else {
                Err(RuntimeError::RequestReuse)
            };
        }
        if self.mode == RuntimeMode::Dormant {
            return Err(RuntimeError::Dormant);
        }
        let (identity, amount) = match &request.action {
            DirectAction::ReserveWithdrawal {
                identity_commitment,
                amount_atomic,
            } => (
                identity_commitment,
                amount_atomic
                    .parse::<u128>()
                    .map_err(|_| RuntimeError::InvalidRequest)?,
            ),
        };
        if amount == 0 {
            return Err(RuntimeError::InvalidRequest);
        }
        let balance = self
            .balances
            .get_mut(identity)
            .ok_or(RuntimeError::InvalidRequest)?;
        let available = balance
            .entry(("USDC".into(), "USER_AVAILABLE".into()))
            .or_default();
        if *available < amount {
            return Err(RuntimeError::InsufficientAvailable);
        }
        *available -= amount;
        *balance
            .entry(("USDC".into(), "USER_WITHDRAWAL_HOLD".into()))
            .or_default() += amount;
        let result = DirectResult {
            status: TerminalStatus::Applied,
            effect: "WITHDRAWAL_RESERVED".into(),
            genesis_ordinal: 0,
        };
        self.requests
            .insert(key, (request.request_hash, result.clone()));
        Ok(result)
    }

    pub fn balance(&self, identity: &str, asset: &str, bucket: &str) -> u128 {
        self.balances
            .get(identity)
            .and_then(|row| row.get(&(asset.into(), bucket.into())))
            .copied()
            .unwrap_or(0)
    }
}

pub struct DirectParent {
    runtime: DirectRuntime,
}

impl DirectParent {
    pub fn new(epoch: SealedEpoch, mode: RuntimeMode) -> Self {
        Self {
            runtime: DirectRuntime::new(epoch, mode),
        }
    }
    pub fn handle(&mut self, request: DirectRequest) -> Result<DirectResult, RuntimeError> {
        self.runtime.execute(request)
    }
}

pub fn request_hash(request: &DirectRequest) -> String {
    let body = serde_json::to_vec(&(
        request.account_id.as_str(),
        request.request_id.as_str(),
        &request.action,
    ))
    .expect("serializable direct request");
    sha256(&body)
}

pub fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn epoch_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../../.codex-review-bundles/unified-direct-execution-20260905/new-epoch-20260911/OPENING_EPOCH_STATE_20260911.json")
    }
    fn request(id: &str, amount: &str) -> DirectRequest {
        let mut request = DirectRequest {
            account_id: "88fff7d9668cf8b00cd7faa0680d05c6415221e6ab28c5be7fa71e047054d8fc".into(),
            request_id: id.into(),
            request_hash: String::new(),
            action: DirectAction::ReserveWithdrawal {
                identity_commitment:
                    "0bafc03d08d4951d769d58284db85c7ac2ee3c79de87ec680f58edc03017c418".into(),
                amount_atomic: amount.into(),
            },
        };
        request.request_hash = request_hash(&request);
        request
    }

    #[test]
    fn loads_exact_sealed_epoch() {
        let epoch = SealedEpoch::load(epoch_path()).unwrap();
        assert_eq!(epoch.identity_count(), 438);
    }

    #[test]
    fn direct_request_is_immediate_and_idempotent() {
        let mut runtime = DirectRuntime::new(
            SealedEpoch::load(epoch_path()).unwrap(),
            RuntimeMode::IsolatedTest,
        );
        let request = request("isolated-direct-1", "1000000");
        assert_eq!(
            runtime.execute(request.clone()).unwrap().status,
            TerminalStatus::Applied
        );
        assert_eq!(
            runtime.execute(request).unwrap().effect,
            "WITHDRAWAL_RESERVED"
        );
        assert_eq!(
            runtime.balance(
                "0bafc03d08d4951d769d58284db85c7ac2ee3c79de87ec680f58edc03017c418",
                "USDC",
                "USER_AVAILABLE"
            ),
            4000000
        );
        assert_eq!(
            runtime.balance(
                "0bafc03d08d4951d769d58284db85c7ac2ee3c79de87ec680f58edc03017c418",
                "USDC",
                "USER_WITHDRAWAL_HOLD"
            ),
            1000000
        );
    }

    #[test]
    fn dormant_mode_has_no_financial_effect() {
        let mut runtime = DirectRuntime::new(
            SealedEpoch::load(epoch_path()).unwrap(),
            RuntimeMode::Dormant,
        );
        assert_eq!(
            runtime.execute(request("dormant-1", "1")).unwrap_err(),
            RuntimeError::Dormant
        );
        assert_eq!(
            runtime.balance(
                "0bafc03d08d4951d769d58284db85c7ac2ee3c79de87ec680f58edc03017c418",
                "USDC",
                "USER_AVAILABLE"
            ),
            5000000
        );
    }

    #[test]
    fn request_reuse_with_changed_content_fails_closed() {
        let mut runtime = DirectRuntime::new(
            SealedEpoch::load(epoch_path()).unwrap(),
            RuntimeMode::IsolatedTest,
        );
        let original = request("isolated-direct-2", "1");
        runtime.execute(original.clone()).unwrap();
        let changed = request("isolated-direct-2", "2");
        assert_eq!(
            runtime.execute(changed).unwrap_err(),
            RuntimeError::RequestReuse
        );
    }

    #[test]
    fn parent_has_the_same_single_immediate_handler() {
        let mut parent = DirectParent::new(
            SealedEpoch::load(epoch_path()).unwrap(),
            RuntimeMode::IsolatedTest,
        );
        assert_eq!(
            parent
                .handle(request("parent-direct-1", "1"))
                .unwrap()
                .status,
            TerminalStatus::Applied
        );
    }
}
