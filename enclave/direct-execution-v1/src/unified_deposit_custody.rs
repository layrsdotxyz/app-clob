//! Independent source-chain proof for unified wallet deposits. The
//! backend may discover a transfer, but only canonical RPC evidence can turn
//! it into an enclave credit. Several USDC transfers are verified as one batch
//! so the five-USDC wallet threshold is crossed atomically; ZEN uses the same
//! proof boundary on its two supported source chains.
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
    tokens: BTreeMap<String, TokenConfig>,
    rpc_urls: Vec<String>,
    confirmations: u64,
}

#[derive(Clone)]
struct TokenConfig { address: String, source_decimals: u32, ledger_decimals: u32 }

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
        for chain in ["ethereum", "base", "arbitrum", "optimism", "polygon", "bnb", "horizen"] {
            let prefix = format!("LAYRS_UNIFIED_{}", chain.to_ascii_uppercase());
            let rpc_url = match env::var(format!("{prefix}_RPC_URL")) {
                Ok(value) if !value.trim().is_empty() => value,
                _ => return Err(format!("{prefix}_RPC_URL required")),
            };
            let mut rpc_urls = vec![rpc_url];
            if chain != "horizen" {
                if let Ok(fallback) = env::var(format!("{prefix}_RPC_FALLBACK_URL")) {
                    if !fallback.trim().is_empty() {
                        rpc_urls.push(fallback);
                    }
                }
            }
            if rpc_urls.len() == 2 && rpc_urls[0] == rpc_urls[1] {
                return Err(format!("{prefix}_RPC_FALLBACK_URL duplicates primary"));
            }
            for rpc_url in &rpc_urls {
                let parsed = reqwest::Url::parse(rpc_url).map_err(|_| format!("{prefix}_RPC_URL invalid"))?;
                if parsed.scheme() != "https"
                    && !(parsed.scheme() == "http" && matches!(parsed.host_str(), Some("127.0.0.1" | "localhost")))
                {
                    return Err(format!("{prefix}_RPC_URL requires HTTPS or localhost"));
                }
            }
            let chain_id = env::var(format!("{prefix}_CHAIN_ID")).map_err(|_| format!("{prefix}_CHAIN_ID required"))?
                .parse::<u64>().ok().filter(|value| *value > 0).ok_or_else(|| format!("{prefix}_CHAIN_ID invalid"))?;
            let confirmations = env::var(format!("{prefix}_CONFIRMATIONS")).map_err(|_| format!("{prefix}_CONFIRMATIONS required"))?
                .parse::<u64>().ok().filter(|value| *value > 0 && *value <= 10_000)
                .ok_or_else(|| format!("{prefix}_CONFIRMATIONS invalid"))?;
            let usdc = canonical_evm_address(&env::var(format!("{prefix}_TOKEN_ADDRESS"))
                .map_err(|_| format!("{prefix}_TOKEN_ADDRESS required"))?)?;
            let mut tokens = BTreeMap::from([("USDC".into(),TokenConfig {address:usdc,
                source_decimals:if chain=="bnb" {18}else{6},ledger_decimals:6})]);
            if matches!(chain, "base" | "horizen") {
                let zen = canonical_evm_address(&env::var(format!("{prefix}_ZEN_TOKEN_ADDRESS"))
                    .map_err(|_| format!("{prefix}_ZEN_TOKEN_ADDRESS required"))?)?;
                let expected = if chain == "base" {
                    "0xf43eb8de897fbc7f2502483b2bef7bb9ea179229"
                } else {
                    "0x57da2d504bf8b83ef304759d9f2648522d7a9280"
                };
                if zen != expected { return Err(format!("{prefix}_ZEN_TOKEN_ADDRESS invalid")); }
                tokens.insert("ZEN".into(),TokenConfig {address:zen,source_decimals:18,ledger_decimals:18});
            }
            chains.insert(chain.into(), ChainConfig { chain_id, tokens, rpc_urls, confirmations });
        }
        Ok(Some(Self {
            client: reqwest::Client::builder().timeout(Duration::from_secs(8)).build()
                .map_err(|_| "unified deposit RPC client unavailable")?,
            chains,
        }))
    }

    async fn rpc(&self, config: &ChainConfig, method: &str, params: Value) -> Result<Value, String> {
        for rpc_url in &config.rpc_urls {
            let Ok(response) = self.client.post(rpc_url)
                .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params.clone()}))
                .send().await else { continue; };
            let Ok(response) = response.error_for_status() else { continue; };
            let Ok(body) = response.json::<Value>().await else { continue; };
            if body.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
                || body.get("id").and_then(Value::as_u64) != Some(1)
                || body.get("error").is_some()
            {
                continue;
            }
            if let Some(result) = body.get("result") {
                return Ok(result.clone());
            }
        }
        Err("unified deposit RPC unavailable".into())
    }

    pub async fn source_finality(
        &self,
        wallet: &str,
        asset: &str,
        expected_amount: &str,
        proof: &UnifiedSourceDepositProof,
    ) -> Result<Option<(String, Vec<String>)>, String> {
        let wallet = canonical_evm_address(wallet)?;
        let config = self.chains.get(&proof.source_chain).ok_or("unified deposit chain unsupported")?;
        let token = config.tokens.get(asset).ok_or("unified deposit asset unsupported")?;
        let expected = expected_amount.parse::<u128>().ok().filter(|value| match asset {
            "USDC" => *value >= 5_000_000,
            "ZEN" => *value > 0,
            _ => false,
        })
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
                    && log.get("address").and_then(Value::as_str).is_some_and(|value| value.eq_ignore_ascii_case(&token.address))
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
            references.push(format!("unified-{}-transfer:{}:{hash}:{log_index}:{amount}", asset.to_ascii_lowercase(), proof.source_chain));
        }
        if normalize_source_amount(total,token.source_decimals,token.ledger_decimals)? != expected {
            return Err("unified deposit batch amount conflict".into());
        }
        references.sort();
        references.dedup();
        if references.len() != proof.transfers.len() {
            return Err("unified deposit transfer proof reused".into());
        }
        let digest = sha256(&serde_json::to_vec(&(proof.source_chain.as_str(), &references))
            .map_err(|_| "unified deposit binding unavailable")?);
        Ok(Some((format!("unified-{}-source:{}:{digest}", asset.to_ascii_lowercase(), proof.source_chain), references)))
    }
}

fn normalize_source_amount(amount:u128,source_decimals:u32,ledger_decimals:u32)->Result<u128,String>{
    if source_decimals==ledger_decimals{return Ok(amount);}
    if source_decimals<ledger_decimals{let scale=10u128.checked_pow(ledger_decimals-source_decimals)
        .ok_or("unified deposit amount overflow")?;return amount.checked_mul(scale)
        .ok_or_else(||"unified deposit amount overflow".into());}
    let scale=10u128.checked_pow(source_decimals-ledger_decimals).ok_or("unified deposit amount overflow")?;
    if amount%scale!=0{return Err("unified deposit source precision invalid".into());}Ok(amount/scale)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{http::StatusCode, routing::post, Json, Router};

    #[test]
    fn bnb_usdc_normalizes_to_six_decimal_ledger_units_without_rounding(){
        assert_eq!(normalize_source_amount(5_000_000_000_000_000_000,18,6).unwrap(),5_000_000);
        assert!(normalize_source_amount(5_000_000_000_000_000_001,18,6).is_err());
    }

    #[tokio::test]
    async fn rpc_uses_the_second_provider_after_primary_failure() {
        let primary = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let primary_address = primary.local_addr().unwrap();
        let primary_task = tokio::spawn(async move {
            axum::serve(primary, Router::new().route("/", post(|| async { StatusCode::SERVICE_UNAVAILABLE })))
                .await.unwrap();
        });
        let fallback = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fallback_address = fallback.local_addr().unwrap();
        let fallback_task = tokio::spawn(async move {
            axum::serve(fallback, Router::new().route("/", post(|| async {
                Json(json!({"jsonrpc":"2.0","id":1,"result":"0x1"}))
            }))).await.unwrap();
        });
        let adapter = UnifiedDepositCustodyAdapter {
            client: reqwest::Client::builder().timeout(Duration::from_secs(1)).build().unwrap(),
            chains: BTreeMap::new(),
        };
        let config = ChainConfig {
            chain_id: 1,
            tokens: BTreeMap::new(),
            rpc_urls: vec![format!("http://{primary_address}"), format!("http://{fallback_address}")],
            confirmations: 1,
        };
        assert_eq!(adapter.rpc(&config, "eth_chainId", json!([])).await.unwrap(), json!("0x1"));
        primary_task.abort();
        fallback_task.abort();
    }
}
