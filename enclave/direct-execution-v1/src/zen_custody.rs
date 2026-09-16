//! Normal ZEN custody boundary. Executes through the current BFF adapter;
//! terminal financial authority is independently observed mainnet finality.
use super::*;
const ZEN: &str = "0x57da2d504bf8b83ef304759d9f2648522d7a9280";

#[derive(Clone)]
pub(super) struct ZenCustodyAdapter {
    client: reqwest::Client,
    url: String,
    key: Vec<u8>,
    pub wallet_id: String,
    pub wallet_address: String,
    pub pool_address: String,
    base_rpc: String,
    horizen_rpc: String,
    base_confirmations: u64,
    horizen_confirmations: u64,
}

impl ZenCustodyAdapter {
    pub fn from_environment(key: &[u8]) -> Result<Option<Self>, String> {
        if env::var("LAYRS_DIRECT_ZEN_CUSTODY_ENABLED").as_deref() != Ok("true") { return Ok(None); }
        let required = |name: &str| env::var(name).map_err(|_| format!("{name} is required"));
        let url = required("LAYRS_DIRECT_ZEN_CUSTODY_URL")?;
        let parsed = reqwest::Url::parse(&url).map_err(|_| "invalid ZEN custody URL")?;
        if parsed.scheme() != "https" && !(parsed.scheme() == "http" && matches!(parsed.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"))) {
            return Err("ZEN custody requires HTTPS or localhost".into());
        }
        if key.len() != 32 { return Err("ZEN custody assertion key invalid".into()); }
        let base_confirmations = required("LAYRSV2_BASE_CONFIRMATIONS")?.parse().map_err(|_| "invalid Base finality")?;
        let horizen_confirmations = required("LAYRSV2_HORIZEN_CONFIRMATIONS")?.parse().map_err(|_| "invalid Horizen finality")?;
        if base_confirmations == 0 || horizen_confirmations == 0 { return Err("ZEN finality cannot be zero".into()); }
        Ok(Some(Self {
            client: reqwest::Client::builder().timeout(Duration::from_secs(45)).build().map_err(|_| "ZEN custody client unavailable")?,
            url: url.trim_end_matches('/').into(), key: key.to_vec(),
            wallet_id: required("LAYRSV2_HORIZEN_POOL_LEDGER_PRIVY_WALLET_ID")?,
            wallet_address: canonical_evm_address(&required("LAYRSV2_HORIZEN_POOL_LEDGER_PRIVY_ADDRESS")?)?,
            pool_address: canonical_evm_address(&required("LAYRSV2_HORIZEN_ZEN_POOL_ADDRESS")?)?,
            base_rpc: required("LAYRSV2_BASE_RPC_URL")?, horizen_rpc: required("LAYRSV2_HORIZEN_RPC_URL")?,
            base_confirmations, horizen_confirmations,
        }))
    }

    async fn rpc(&self, chain: &str, method: &str, params: Value) -> Result<Value, String> {
        let url = match chain { "base" => &self.base_rpc, "horizen" => &self.horizen_rpc, _ => return Err("ZEN chain unsupported".into()) };
        let response = self.client.post(url).json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
            .send().await.map_err(|_| "ZEN RPC unavailable")?.error_for_status().map_err(|_| "ZEN RPC rejected")?;
        let body: Value = response.json().await.map_err(|_| "ZEN RPC malformed")?;
        if body.get("jsonrpc").and_then(Value::as_str) != Some("2.0") || body.get("id").and_then(Value::as_u64) != Some(1) || body.get("error").is_some() { return Err("ZEN RPC rejected".into()); }
        body.get("result").cloned().ok_or("ZEN RPC result missing".into())
    }

    async fn verify_chain(&self, chain: &str) -> Result<(), String> {
        let value = self.rpc(chain, "eth_chainId", json!([])).await?;
        if value.as_str().and_then(parse_quantity) != Some(if chain == "base" {8453} else {26514}) { return Err("ZEN RPC chain mismatch".into()); }
        Ok(())
    }

    async fn verify_asset(&self) -> Result<(), String> {
        self.verify_chain("horizen").await?;
        let selector = selector("asset()");
        let value = self.rpc("horizen", "eth_call", json!([{"to":self.pool_address,"data":selector},"latest"])).await?;
        if value.as_str().map(|value| value.to_ascii_lowercase()) != Some(address_topic(ZEN)) { return Err("ZEN pool asset mismatch".into()); }
        Ok(())
    }

    pub async fn transaction_parameters(&self) -> Result<(u128,u128,u128,u128), String> {
        self.verify_asset().await?;
        let nonce = self.rpc("horizen", "eth_getTransactionCount", json!([self.wallet_address,"pending"])).await?.as_str().and_then(parse_quantity).ok_or("ZEN nonce malformed")?;
        let price = self.rpc("horizen", "eth_gasPrice", json!([])).await?.as_str().and_then(parse_quantity).filter(|value| *value > 0).ok_or("ZEN fee malformed")?;
        Ok((nonce, 320_000, price.checked_mul(2).ok_or("ZEN fee overflow")?, 1))
    }

    async fn receipt(&self, chain: &str, hash: &str) -> Result<Option<Value>, String> {
        if !valid_transaction_hash(hash) { return Err("ZEN transaction hash invalid".into()); }
        self.verify_chain(chain).await?;
        let receipt = self.rpc(chain, "eth_getTransactionReceipt", json!([hash])).await?;
        if receipt.is_null() { return Ok(None); }
        if receipt.get("transactionHash").and_then(Value::as_str).map(|value| value.eq_ignore_ascii_case(hash)) != Some(true) { return Err("ZEN receipt conflict".into()); }
        let number = receipt.get("blockNumber").and_then(Value::as_str).and_then(parse_quantity).ok_or("ZEN block missing")?;
        let head = self.rpc(chain,"eth_blockNumber",json!([])).await?.as_str().and_then(parse_quantity).ok_or("ZEN head missing")?;
        let confirmations = if chain == "base" {self.base_confirmations} else {self.horizen_confirmations};
        if head.checked_sub(number).and_then(|value| value.checked_add(1)).unwrap_or(0) < u128::from(confirmations) { return Ok(None); }
        let block = self.rpc(chain,"eth_getBlockByNumber",json!([quantity(number),false])).await?;
        if block.get("hash").and_then(Value::as_str) != receipt.get("blockHash").and_then(Value::as_str)
            || receipt.get("blockHash").and_then(Value::as_str).filter(|value| valid_transaction_hash(value)).is_none() { return Err("ZEN canonical block conflict".into()); }
        Ok(Some(receipt))
    }

    pub async fn deposit_finality(&self, source: &str, hash: &str, amount: &str) -> Result<DepositFinality, String> {
        self.verify_asset().await?;
        let Some(receipt) = self.receipt("horizen", hash).await? else { return Ok(DepositFinality::Pending); };
        let transaction = self.rpc("horizen","eth_getTransactionByHash",json!([hash])).await?;
        if !transaction_matches(&transaction, hash, source, &self.pool_address, &deposit_calldata(amount)?, None) { return Ok(DepositFinality::Conflict); }
        if receipt.get("status").and_then(Value::as_str) == Some("0x0") { return Ok(DepositFinality::Reverted); }
        let value = amount.parse::<u128>().map_err(|_| "ZEN amount invalid")?;
        let transfer = event_count(&receipt, ZEN, ERC20_TRANSFER_TOPIC, &[address_topic(source), address_topic(&self.pool_address)], &format!("0x{value:064x}"));
        let deposit = event_count(&receipt, &self.pool_address, &topic("Deposited(address,uint256)"), &[address_topic(source)], &format!("0x{value:064x}"));
        Ok(if receipt.get("status").and_then(Value::as_str) == Some("0x1") && transfer == 1 && deposit == 1 { DepositFinality::Finalized } else { DepositFinality::Conflict })
    }

    pub async fn settle(&self, intent: &ExternalEffectIntent, now: u64) -> Result<ExternalEffectRecovery, String> {
        intent.verify().map_err(|_| "ZEN intent invalid")?;
        let chain = intent.zen_destination_chain.as_deref().ok_or("ZEN destination binding missing")?;
        if intent.asset != "ZEN" || intent.chain != "horizen" || intent.provider_wallet_id != self.wallet_id || intent.custody_target != self.pool_address { return Err("ZEN custody binding denied".into()); }
        self.verify_asset().await?;
        let expires = now.checked_add(60).ok_or("ZEN assertion overflow")?;
        let body = serde_json::to_vec(&json!({"expiresAtUnix":expires,"intent":intent})).map_err(|_| "ZEN assertion serialization failed")?;
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.key).map_err(|_| "ZEN assertion key invalid")?;
        mac.update(b"layrs.direct-zen-custody.v1\0"); mac.update(&body);
        let proof: Value = self.client.post(format!("{}/v1/internal/direct-zen/settle",self.url))
            .header("content-type","application/json").header("x-layrs-zen-signature",hex::encode(mac.finalize().into_bytes())).body(body)
            .send().await.map_err(|_| "ZEN custody submission unresolved")?.error_for_status().map_err(|_| "ZEN custody unavailable")?
            .json().await.map_err(|_| "ZEN custody result malformed")?;
        if proof.get("status").and_then(Value::as_str) == Some("pending") { return Ok(ExternalEffectRecovery::AwaitExternalFinality); }
        let pool_hash = required_string(&proof,"poolTransactionHash")?;
        let Some(pool_receipt) = self.receipt("horizen",pool_hash).await? else {return Ok(ExternalEffectRecovery::AwaitExternalFinality);};
        let pool_recipient = if chain == "base" {&self.wallet_address} else {&intent.destination};
        let transaction = self.rpc("horizen","eth_getTransactionByHash",json!([pool_hash])).await?;
        if !transaction_matches(&transaction,pool_hash,&self.wallet_address,&self.pool_address,&pool_withdraw_calldata(pool_recipient,&intent.amount_atomic)?,Some(&intent.transaction_nonce)) { return Err("ZEN pool transaction conflict".into()); }
        if pool_receipt.get("status").and_then(Value::as_str) == Some("0x0") {
            return Ok(ExternalEffectRecovery::BindReverted {provider_transaction_id: required_string(&proof,"providerTransactionId")?.into(),transaction_hash: pool_hash.into()});
        }
        let value = intent.amount_atomic.parse::<u128>().map_err(|_| "ZEN amount invalid")?;
        if pool_receipt.get("status").and_then(Value::as_str) != Some("0x1")
            || event_count(&pool_receipt,ZEN,ERC20_TRANSFER_TOPIC,&[address_topic(&self.pool_address),address_topic(pool_recipient)],&format!("0x{value:064x}")) != 1
            || event_count(&pool_receipt,&self.pool_address,POOL_WITHDRAW_TOPIC,&[address_topic(pool_recipient),address_topic(&self.wallet_address)],&format!("0x{value:064x}")) != 1 { return Err("ZEN pool effect conflict".into()); }
        if chain == "horizen" {return Ok(ExternalEffectRecovery::BindFinalized {provider_transaction_id: required_string(&proof,"providerTransactionId")?.into(),transaction_hash: pool_hash.into()});}
        if proof.get("status").and_then(Value::as_str) != Some("settled") {return Ok(ExternalEffectRecovery::AwaitExternalFinality);}
        let bridge = proof.get("bridge").ok_or("ZEN delivery proof missing")?;
        if required_string(bridge,"accountId")? != intent.account_id || required_string(bridge,"identityCommitment")? != intent.identity_commitment
            || required_string(bridge,"recipientAddress")? != intent.destination || required_string(bridge,"amountAtomic")? != intent.amount_atomic
            || required_string(bridge,"direction")? != "HORIZEN_TO_BASE" {return Err("ZEN delivery owner conflict".into());}
        let source_hash = required_string(bridge,"sourceTransactionHash")?;
        let destination_hash = required_string(bridge,"destinationTransactionHash")?;
        let guid = required_string(bridge,"guid")?;
        if !valid_transaction_hash(guid) {return Err("ZEN GUID invalid".into());}
        let Some(source) = self.receipt("horizen",source_hash).await? else {return Ok(ExternalEffectRecovery::AwaitExternalFinality);};
        let Some(destination) = self.receipt("base",destination_hash).await? else {return Ok(ExternalEffectRecovery::AwaitExternalFinality);};
        let sent = event_count(&source,ZEN,&topic("OFTSent(bytes32,uint32,address,uint256,uint256)"),&[guid.into(),address_topic(&self.wallet_address)],&format!("0x{:064x}{value:064x}{value:064x}",30184));
        let received = event_count(&destination,ZEN,&topic("OFTReceived(bytes32,uint32,address,uint256)"),&[guid.into(),address_topic(&intent.destination)],&format!("0x{:064x}{value:064x}",30399));
        let source_block = source.get("blockNumber").and_then(Value::as_str).and_then(parse_quantity).ok_or("ZEN source block missing")?;
        let pool_block = pool_receipt.get("blockNumber").and_then(Value::as_str).and_then(parse_quantity).ok_or("ZEN pool block missing")?;
        if source.get("status").and_then(Value::as_str) != Some("0x1") || destination.get("status").and_then(Value::as_str) != Some("0x1") || sent != 1 || received != 1 || source_block < pool_block {return Err("ZEN destination finality conflict".into());}
        Ok(ExternalEffectRecovery::BindFinalized {provider_transaction_id: required_string(&proof,"providerTransactionId")?.into(),transaction_hash: destination_hash.into()})
    }
}

fn required_string<'a>(value: &'a Value,key: &str) -> Result<&'a str,String> {value.get(key).and_then(Value::as_str).ok_or_else(|| format!("ZEN {key} missing"))}
fn selector(value: &str) -> String {format!("0x{}",hex::encode(&Keccak256::digest(value.as_bytes())[..4]))}
fn topic(value: &str) -> String {format!("0x{}",hex::encode(Keccak256::digest(value.as_bytes())))}
fn deposit_calldata(amount: &str) -> Result<String,String> {let value=amount.parse::<u128>().map_err(|_|"ZEN amount invalid")?;if value==0{return Err("ZEN amount invalid".into());}Ok(format!("{}{value:064x}",selector("deposit(uint256)")))}
fn transaction_matches(transaction:&Value,hash:&str,from:&str,to:&str,data:&str,nonce:Option<&String>)->bool {
    transaction.get("hash").and_then(Value::as_str).map(|value|value.eq_ignore_ascii_case(hash))==Some(true)
        && transaction.get("from").and_then(Value::as_str).map(|value|value.eq_ignore_ascii_case(from))==Some(true)
        && transaction.get("to").and_then(Value::as_str).map(|value|value.eq_ignore_ascii_case(to))==Some(true)
        && transaction.get("input").and_then(Value::as_str).map(|value|value.eq_ignore_ascii_case(data))==Some(true)
        && transaction.get("value").and_then(Value::as_str).and_then(parse_quantity)==Some(0)
        && nonce.map_or(true,|nonce|transaction.get("nonce").and_then(Value::as_str).and_then(parse_quantity)==nonce.parse::<u128>().ok())
}
fn event_count(receipt:&Value,contract:&str,topic:&str,suffix:&[String],data:&str)->usize {
    receipt.get("logs").and_then(Value::as_array).map_or(0,|logs|logs.iter().filter(|log| {
        log.get("removed").and_then(Value::as_bool)!=Some(true)
            && log.get("address").and_then(Value::as_str).map(|value|value.eq_ignore_ascii_case(contract))==Some(true)
            && log.get("data").and_then(Value::as_str).map(|value|value.eq_ignore_ascii_case(data))==Some(true)
            && log.get("topics").and_then(Value::as_array).is_some_and(|topics| topics.len()==suffix.len()+1
                && topics[0].as_str().map(|value|value.eq_ignore_ascii_case(topic))==Some(true)
                && suffix.iter().zip(topics.iter().skip(1)).all(|(expected,actual)|actual.as_str().map(|value|value.eq_ignore_ascii_case(expected))==Some(true)))
    }).count())
}
