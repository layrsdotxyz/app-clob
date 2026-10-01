//! Independent source-chain proof for unified USDC wallet deposits. The
//! backend may discover a transfer, but only canonical RPC evidence can turn
//! it into an enclave credit. Several transfers are verified as one batch so
//! the five-USDC wallet threshold is crossed atomically.
use super::*;

const TRANSFER_TOPIC: &str =
    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const ZERO_ADDRESS_TOPIC: &str =
    "0x0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct UnifiedSourceTransferProof {
    pub transaction_hash: String,
    pub log_index: String,
    pub amount_atomic: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct UnifiedSourceDepositProof {
    pub source_chain: String,
    pub transfers: Vec<UnifiedSourceTransferProof>,
}

#[derive(Clone)]
struct ChainConfig {
    chain_id: u64,
    token: String,
    rpc_url: String,
    confirmations: u64,
}

#[derive(Clone)]
pub(super) struct UnifiedDepositCustodyAdapter {
    client: reqwest::Client,
    chains: BTreeMap<String, ChainConfig>,
}

impl UnifiedDepositCustodyAdapter {
    pub fn from_environment() -> Result<Option<Self>, String> {
        if env::var("LAYRS_UNIFIED_DEPOSITS_ENABLED").as_deref() != Ok("true") {
            return Ok(None);
        }
        let mut chains = BTreeMap::new();
        for chain in ["ethereum", "base", "arbitrum", "optimism", "polygon", "bnb", "tempo", "robinhood", "horizen"] {
            let prefix = format!("LAYRS_UNIFIED_{}", chain.to_ascii_uppercase());
            let rpc_url = match env::var(format!("{prefix}_RPC_URL")) {
                Ok(value) if !value.trim().is_empty() => value,
                _ if matches!(chain, "tempo" | "robinhood") => continue,
                _ => return Err(format!("{prefix}_RPC_URL required")),
            };
            let parsed = reqwest::Url::parse(&rpc_url).map_err(|_| format!("{prefix}_RPC_URL invalid"))?;
            if parsed.scheme() != "https"
                && !(parsed.scheme() == "http" && matches!(parsed.host_str(), Some("127.0.0.1" | "localhost")))
            {
                return Err(format!("{prefix}_RPC_URL requires HTTPS or localhost"));
            }
            let chain_id = env::var(format!("{prefix}_CHAIN_ID")).map_err(|_| format!("{prefix}_CHAIN_ID required"))?
                .parse::<u64>().ok().filter(|value| *value > 0).ok_or_else(|| format!("{prefix}_CHAIN_ID invalid"))?;
            let confirmations = env::var(format!("{prefix}_CONFIRMATIONS")).map_err(|_| format!("{prefix}_CONFIRMATIONS required"))?
                .parse::<u64>().ok().filter(|value| *value > 0 && *value <= 10_000)
                .ok_or_else(|| format!("{prefix}_CONFIRMATIONS invalid"))?;
            let token = canonical_evm_address(&env::var(format!("{prefix}_TOKEN_ADDRESS"))
                .map_err(|_| format!("{prefix}_TOKEN_ADDRESS required"))?)?;
            chains.insert(chain.into(), ChainConfig { chain_id, token, rpc_url, confirmations });
        }
        Ok(Some(Self {
            client: reqwest::Client::builder().timeout(Duration::from_secs(8)).build()
                .map_err(|_| "unified deposit RPC client unavailable")?,
            chains,
        }))
    }

    async fn rpc(&self, config: &ChainConfig, method: &str, params: Value) -> Result<Value, String> {
        let body: Value = self.client.post(&config.rpc_url)
            .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
            .send().await.map_err(|_| "unified deposit RPC unavailable")?
            .error_for_status().map_err(|_| "unified deposit RPC rejected")?
            .json().await.map_err(|_| "unified deposit RPC malformed")?;
        if body.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
            || body.get("id").and_then(Value::as_u64) != Some(1)
            || body.get("error").is_some()
        {
            return Err("unified deposit RPC rejected".into());
        }
        body.get("result").cloned().ok_or_else(|| "unified deposit RPC result missing".into())
    }

    pub async fn source_finality(
        &self,
        wallet: &str,
        expected_amount: &str,
        proof: &UnifiedSourceDepositProof,
    ) -> Result<Option<(String, Vec<String>)>, String> {
        let wallet = canonical_evm_address(wallet)?;
        let config = self.chains.get(&proof.source_chain).ok_or("unified deposit chain unsupported")?;
        let expected = expected_amount.parse::<u128>().ok().filter(|value| *value >= 5_000_000)
            .ok_or("unified deposit batch below minimum")?;
        if proof.transfers.is_empty() || proof.transfers.len() > 100 {
            return Err("unified deposit transfer batch invalid".into());
        }
        let chain_id = self.rpc(config, "eth_chainId", json!([])).await?
            .as_str().and_then(parse_quantity).ok_or("unified deposit chain ID malformed")?;
        if chain_id != u128::from(config.chain_id) {
            return Err("unified deposit RPC chain mismatch".into());
        }
        let head = self.rpc(config, "eth_blockNumber", json!([])).await?
            .as_str().and_then(parse_quantity).ok_or("unified deposit head malformed")?;
        let mut references = Vec::with_capacity(proof.transfers.len());
        let mut total = 0u128;
        for transfer in &proof.transfers {
            let hash = transfer.transaction_hash.to_ascii_lowercase();
            if !valid_transaction_hash(&hash) || hash != transfer.transaction_hash {
                return Err("unified deposit transaction hash invalid".into());
            }
            let log_index = transfer.log_index.parse::<u64>().ok()
                .filter(|value| value.to_string() == transfer.log_index)
                .ok_or("unified deposit log index invalid")?;
            let amount = transfer.amount_atomic.parse::<u128>().ok().filter(|value| *value > 0)
                .ok_or("unified deposit amount invalid")?;
            let receipt = self.rpc(config, "eth_getTransactionReceipt", json!([hash])).await?;
            if receipt.is_null() {
                return Ok(None);
            }
            let block_number = receipt.get("blockNumber").and_then(Value::as_str).and_then(parse_quantity)
                .ok_or("unified deposit block missing")?;
            if head.checked_sub(block_number).and_then(|distance| distance.checked_add(1)).unwrap_or(0)
                < u128::from(config.confirmations)
            {
                return Ok(None);
            }
            let block = self.rpc(config, "eth_getBlockByNumber", json!([quantity(block_number), false])).await?;
            if block.get("hash").and_then(Value::as_str) != receipt.get("blockHash").and_then(Value::as_str)
                || receipt.get("status").and_then(Value::as_str) != Some("0x1")
                || receipt.get("transactionHash").and_then(Value::as_str)
                    .is_none_or(|value| !value.eq_ignore_ascii_case(&hash))
            {
                return Err("unified deposit canonical receipt conflict".into());
            }
            let exact = receipt.get("logs").and_then(Value::as_array).map_or(0, |logs| logs.iter().filter(|log| {
                log.get("removed").and_then(Value::as_bool) != Some(true)
                    && log.get("logIndex").and_then(Value::as_str).and_then(parse_quantity) == Some(u128::from(log_index))
                    && log.get("transactionHash").and_then(Value::as_str).is_some_and(|value| value.eq_ignore_ascii_case(&hash))
                    && log.get("blockHash") == receipt.get("blockHash")
                    && log.get("blockNumber") == receipt.get("blockNumber")
                    && log.get("address").and_then(Value::as_str).is_some_and(|value| value.eq_ignore_ascii_case(&config.token))
                    && log.get("topics").and_then(Value::as_array).is_some_and(|topics| topics.len() == 3
                        && topics[0].as_str().is_some_and(|value| value.eq_ignore_ascii_case(TRANSFER_TOPIC))
                        && topics[1].as_str().is_some_and(|value| !value.eq_ignore_ascii_case(ZERO_ADDRESS_TOPIC))
                        && topics[2].as_str().is_some_and(|value| value.eq_ignore_ascii_case(&address_topic(&wallet))))
                    && log.get("data").and_then(Value::as_str).and_then(parse_quantity) == Some(amount)
            }).count());
            if exact != 1 {
                return Err("unified deposit transfer proof conflict".into());
            }
            total = total.checked_add(amount).ok_or("unified deposit amount overflow")?;
            references.push(format!("unified-usdc-transfer:{}:{hash}:{log_index}:{amount}", proof.source_chain));
        }
        if total != expected {
            return Err("unified deposit batch amount conflict".into());
        }
        references.sort();
        references.dedup();
        if references.len() != proof.transfers.len() {
            return Err("unified deposit transfer proof reused".into());
        }
        let digest = sha256(&serde_json::to_vec(&(proof.source_chain.as_str(), &references))
            .map_err(|_| "unified deposit binding unavailable")?);
        Ok(Some((format!("unified-usdc-source:{}:{digest}", proof.source_chain), references)))
    }
}
