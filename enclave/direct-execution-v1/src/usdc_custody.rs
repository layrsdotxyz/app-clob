//! Scoped Horizen USDC.e finality verifier. This does not trust an API stage,
//! Bus ticket, wallet balance or worker assertion as a ledger credit.
use super::*;
const USDC:&str="0xdf7108f8b10f9b9ec1aba01cca057268cbf86b6c";
const POOL:&str="0xb412f63299ccff4fe57714ee580895cca74dd284";
#[derive(Clone)]
pub(super) struct UsdcCustodyAdapter {client:reqwest::Client,rpc_url:String,confirmations:u64,
    usdc_ledger_wallet:Option<String>,zen_ledger_wallet:Option<String>}
impl UsdcCustodyAdapter {
    pub fn from_environment()->Result<Option<Self>,String> {
        if env::var("LAYRS_DIRECT_USDC_CUSTODY_ENABLED").as_deref()!=Ok("true")
            &&env::var("LAYRS_UNIFIED_USDC_FINALITY_ENABLED").as_deref()!=Ok("true") {return Ok(None);}
        let rpc_url=env::var("LAYRSV2_HORIZEN_RPC_URL").map_err(|_|"Horizen RPC required")?;
        let parsed=reqwest::Url::parse(&rpc_url).map_err(|_|"Horizen RPC configuration invalid")?;
        if parsed.scheme()!="https"&&!(parsed.scheme()=="http"&&matches!(parsed.host_str(),Some("127.0.0.1"|"localhost"))) {
            return Err("Horizen RPC requires HTTPS or localhost".into());
        }
        let confirmations=env::var("LAYRSV2_HORIZEN_CONFIRMATIONS").map_err(|_|"Horizen finality required")?
            .parse::<u64>().ok().filter(|value|*value>0&&*value<=10_000).ok_or("Horizen finality invalid")?;
        let client=reqwest::Client::builder().timeout(Duration::from_secs(5)).build().map_err(|_|"Horizen RPC client unavailable")?;
        let usdc_ledger_wallet=env::var("LAYRS_DIRECT_USDC_LEDGER_WALLET_ADDRESS").ok()
            .and_then(|value|canonical_evm_address(&value).ok());
        let zen_ledger_wallet=env::var("LAYRSV2_HORIZEN_POOL_LEDGER_PRIVY_ADDRESS").ok()
            .and_then(|value|canonical_evm_address(&value).ok());
        Ok(Some(Self {client,rpc_url,confirmations,usdc_ledger_wallet,zen_ledger_wallet}))
    }
    async fn rpc(&self,method:&str,params:Value)->Result<Value,String> {
        let response=self.client.post(&self.rpc_url).json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
            .send().await.map_err(|_|"USDC RPC unavailable")?.error_for_status().map_err(|_|"USDC RPC rejected")?;
        let body:Value=response.json().await.map_err(|_|"USDC RPC malformed")?;
        if body.get("jsonrpc").and_then(Value::as_str)!=Some("2.0")||body.get("id").and_then(Value::as_u64)!=Some(1)||body.get("error").is_some() {
            return Err("USDC RPC rejected".into());
        }
        body.get("result").cloned().ok_or("USDC RPC result missing".into())
    }
    pub async fn deposit_finality(&self,wallet:&str,hash:&str,amount:&str)->Result<DepositFinality,String> {
        if !valid_transaction_hash(hash)||canonical_evm_address(wallet).is_err()||amount.parse::<u128>().ok().filter(|amount|*amount>0).is_none() {
            return Ok(DepositFinality::Conflict);
        }
        let chain=self.rpc("eth_chainId",json!([])).await?;
        if chain.as_str().and_then(parse_quantity)!=Some(26514) {return Err("USDC RPC chain mismatch".into());}
        let asset=self.rpc("eth_call",json!([{"to":POOL,"data":selector("asset()")},"latest"])).await?;
        if asset.as_str().map(|asset|asset.to_ascii_lowercase())!=Some(address_topic(USDC)) {return Err("USDC pool asset mismatch".into());}
        let receipt=self.rpc("eth_getTransactionReceipt",json!([hash])).await?;
        if receipt.is_null() {return Ok(DepositFinality::Pending);}
        let block_number=receipt.get("blockNumber").and_then(Value::as_str).and_then(parse_quantity).ok_or("USDC block missing")?;
        let head=self.rpc("eth_blockNumber",json!([])).await?.as_str().and_then(parse_quantity).ok_or("USDC head missing")?;
        if head.checked_sub(block_number).and_then(|distance|distance.checked_add(1)).unwrap_or(0)<u128::from(self.confirmations) {
            return Ok(DepositFinality::Pending);
        }
        let block=self.rpc("eth_getBlockByNumber",json!([quantity(block_number),false])).await?;
        if block.get("hash").and_then(Value::as_str)!=receipt.get("blockHash").and_then(Value::as_str)
            ||receipt.get("blockHash").and_then(Value::as_str).filter(|hash|valid_transaction_hash(hash)).is_none() {
            return Ok(DepositFinality::Conflict);
        }
        let tx=self.rpc("eth_getTransactionByHash",json!([hash])).await?;
        Ok(deposit_effect(wallet,hash,amount,&receipt,&tx))
    }
    /// Independently proves the existing pool's exact `withdraw` call before the
    /// parent asks the enclave to consume one hold. A missing receipt or an
    /// insufficient confirmation depth remains pending for this operation.
    pub async fn signed_withdrawal_finality(&self,payout_destination:&str,amount_atomic:&str,hash:&str,
        pool:&str,token:&str)->Result<DepositFinality,String> {
        let Some(asset)=approved_signed_withdrawal_asset(pool,token) else {return Ok(DepositFinality::Conflict);};
        let ledger_wallet=match asset {SignedWithdrawalAsset::Usdc=>self.usdc_ledger_wallet.as_deref(),
            SignedWithdrawalAsset::Zen=>self.zen_ledger_wallet.as_deref()}.ok_or("withdrawal ledger wallet missing")?;
        if !valid_transaction_hash(hash)||canonical_evm_address(payout_destination).is_err()
            ||amount_atomic.parse::<u128>().ok().filter(|value|*value>0).is_none() {
            return Ok(DepositFinality::Conflict);
        }
        if self.rpc("eth_chainId",json!([])).await?.as_str().and_then(parse_quantity)!=Some(26514) {
            return Err("USDC RPC chain mismatch".into());
        }
        let asset=self.rpc("eth_call",json!([{"to":pool,"data":selector("asset()")},"latest"])).await?;
        if asset.as_str().map(|asset|asset.to_ascii_lowercase())!=Some(address_topic(token)) {
            return Err("withdrawal pool asset mismatch".into());
        }
        let receipt=self.rpc("eth_getTransactionReceipt",json!([hash])).await?;
        if receipt.is_null() {return Ok(DepositFinality::Pending);}
        let block_number=receipt.get("blockNumber").and_then(Value::as_str).and_then(parse_quantity).ok_or("USDC block missing")?;
        let head=self.rpc("eth_blockNumber",json!([])).await?.as_str().and_then(parse_quantity).ok_or("USDC head missing")?;
        if head.checked_sub(block_number).and_then(|distance|distance.checked_add(1)).unwrap_or(0)<u128::from(self.confirmations) {
            return Ok(DepositFinality::Pending);
        }
        let block=self.rpc("eth_getBlockByNumber",json!([quantity(block_number),false])).await?;
        if block.get("hash").and_then(Value::as_str)!=receipt.get("blockHash").and_then(Value::as_str)
            ||receipt.get("blockHash").and_then(Value::as_str).filter(|value|valid_transaction_hash(value)).is_none() {
            return Ok(DepositFinality::Conflict);
        }
        let tx=self.rpc("eth_getTransactionByHash",json!([hash])).await?;
        Ok(signed_withdrawal_effect(ledger_wallet,payout_destination,amount_atomic,hash,pool,token,&receipt,&tx))
    }
    /// Proves that a finalized canonical block is later than the signed
    /// expiry. The BFF invokes this release only when the stable Privy payout
    /// reference has no submission; once any payout is submitted, expiry can
    /// no longer release the hold because the existing pool has no nonce.
    pub async fn signed_withdrawal_expiry(&self,intent:&SignedWithdrawalIntent,block_number:&str,block_hash:&str)->Result<DepositFinality,String> {
        if intent.validate().is_err()||!valid_transaction_hash(block_hash)
            ||block_number.parse::<u128>().ok().filter(|value|value.to_string()==block_number).is_none() {
            return Ok(DepositFinality::Conflict);
        }
        if self.rpc("eth_chainId",json!([])).await?.as_str().and_then(parse_quantity)!=Some(26514) {
            return Err("USDC RPC chain mismatch".into());
        }
        let number=block_number.parse::<u128>().map_err(|_|"USDC block invalid")?;
        let head=self.rpc("eth_blockNumber",json!([])).await?.as_str().and_then(parse_quantity).ok_or("USDC head missing")?;
        if head.checked_sub(number).and_then(|distance|distance.checked_add(1)).unwrap_or(0)<u128::from(self.confirmations) {
            return Ok(DepositFinality::Pending);
        }
        let block=self.rpc("eth_getBlockByNumber",json!([quantity(number),false])).await?;
        signed_withdrawal_expiry_effect(intent,block_hash,&block)
    }
    pub async fn finalized_block_timestamp(&self,block_number:&str,block_hash:&str)->Result<u64,String> {
        let number=block_number.parse::<u128>().map_err(|_|"USDC block invalid")?;
        let block=self.rpc("eth_getBlockByNumber",json!([quantity(number),false])).await?;
        if !equals(block.get("hash").and_then(Value::as_str),block_hash) {return Err("USDC block changed".into());}
        block.get("timestamp").and_then(Value::as_str).and_then(parse_quantity)
            .and_then(|value|u64::try_from(value).ok()).ok_or("USDC block timestamp missing".into())
    }
}
fn selector(value:&str)->String {format!("0x{}",&topic(value)[2..10])}
fn topic(value:&str)->String {
    use sha3::{Digest,Keccak256};format!("0x{}",hex::encode(Keccak256::digest(value.as_bytes())))
}
fn address_topic(value:&str)->String {format!("0x{:0>64}",value.trim_start_matches("0x").to_ascii_lowercase())}
fn equals(value:Option<&str>,expected:&str)->bool {value.is_some_and(|value|value.eq_ignore_ascii_case(expected))}
fn event_count(receipt:&Value,contract:&str,signature:&str,accounts:&[&str],value:u128)->usize {
    receipt.get("logs").and_then(Value::as_array).map_or(0,|logs|logs.iter().filter(|log|{
        log.get("removed").and_then(Value::as_bool)!=Some(true)
            &&equals(log.get("address").and_then(Value::as_str),contract)
            &&equals(log.get("data").and_then(Value::as_str),&format!("0x{value:064x}"))
            &&log.get("topics").and_then(Value::as_array).is_some_and(|topics|topics.len()==accounts.len()+1
                &&equals(topics[0].as_str(),signature)
                &&accounts.iter().zip(topics.iter().skip(1)).all(|(expected,actual)|equals(actual.as_str(),&address_topic(expected))))
    }).count())
}
fn deposit_effect(wallet:&str,hash:&str,amount:&str,receipt:&Value,tx:&Value)->DepositFinality {
    let Some(value)=amount.parse::<u128>().ok().filter(|value|*value>0) else {return DepositFinality::Conflict;};
    let data=format!("{}{value:064x}",selector("deposit(uint256)"));
    if !equals(tx.get("hash").and_then(Value::as_str),hash)||!equals(receipt.get("transactionHash").and_then(Value::as_str),hash)
        ||!equals(tx.get("from").and_then(Value::as_str),wallet)||!equals(receipt.get("from").and_then(Value::as_str),wallet)
        ||!equals(tx.get("to").and_then(Value::as_str),POOL)||!equals(receipt.get("to").and_then(Value::as_str),POOL)
        ||!equals(tx.get("input").and_then(Value::as_str),&data)||tx.get("value").and_then(Value::as_str).and_then(parse_quantity)!=Some(0)
        ||tx.get("chainId").and_then(Value::as_str).and_then(parse_quantity)!=Some(26514)
        ||tx.get("blockHash")!=receipt.get("blockHash")||tx.get("blockNumber")!=receipt.get("blockNumber") {
        return DepositFinality::Conflict;
    }
    match receipt.get("status").and_then(Value::as_str) {
        Some("0x0")=>DepositFinality::Reverted,
        Some("0x1") if event_count(receipt,USDC,ERC20_TRANSFER_TOPIC,&[wallet,POOL],value)==1
            &&event_count(receipt,POOL,&topic("Deposited(address,uint256)"),&[wallet],value)==1=>DepositFinality::Finalized,
        _=>DepositFinality::Conflict,
    }
}
fn signed_withdrawal_effect(ledger_wallet:&str,payout_destination:&str,amount_atomic:&str,hash:&str,pool:&str,token:&str,
    receipt:&Value,tx:&Value)->DepositFinality {
    let Ok(expected_input)=pool_withdraw_calldata(payout_destination,amount_atomic) else {return DepositFinality::Conflict;};
    let Ok(value)=amount_atomic.parse::<u128>() else {return DepositFinality::Conflict;};
    if !equals(tx.get("hash").and_then(Value::as_str),hash)||!equals(receipt.get("transactionHash").and_then(Value::as_str),hash)
        ||!equals(tx.get("from").and_then(Value::as_str),ledger_wallet)||!equals(receipt.get("from").and_then(Value::as_str),ledger_wallet)
        ||!equals(tx.get("to").and_then(Value::as_str),pool)||!equals(receipt.get("to").and_then(Value::as_str),pool)
        ||tx.get("input").and_then(Value::as_str).is_none_or(|input|!input.eq_ignore_ascii_case(&expected_input))
        ||tx.get("value").and_then(Value::as_str).and_then(parse_quantity)!=Some(0)
        ||tx.get("chainId").and_then(Value::as_str).and_then(parse_quantity)!=Some(26514)
        ||tx.get("blockHash")!=receipt.get("blockHash")||tx.get("blockNumber")!=receipt.get("blockNumber") {
        return DepositFinality::Conflict;
    }
    if receipt.get("status").and_then(Value::as_str)==Some("0x0") {return DepositFinality::Reverted;}
    let withdrawal_count=event_count(receipt,pool,&topic("Withdrawn(address,uint256,address)"),
        &[payout_destination,ledger_wallet],value);
    let transfer_count=event_count(receipt,token,ERC20_TRANSFER_TOPIC,&[pool,payout_destination],value);
    if receipt.get("status").and_then(Value::as_str)==Some("0x1")&&withdrawal_count==1&&transfer_count==1 {
        DepositFinality::Finalized
    }else{DepositFinality::Conflict}
}
fn signed_withdrawal_expiry_effect(intent:&SignedWithdrawalIntent,block_hash:&str,block:&Value)->Result<DepositFinality,String> {
    if !equals(block.get("hash").and_then(Value::as_str),block_hash) {return Ok(DepositFinality::Conflict);}
    let timestamp=block.get("timestamp").and_then(Value::as_str).and_then(parse_quantity).ok_or("USDC block timestamp missing")?;
    if timestamp<=u128::from(intent.expiry_unix) {return Ok(DepositFinality::Pending);}
    Ok(DepositFinality::Finalized)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture()->(String,String,Value,Value) {
        let wallet="0x1111111111111111111111111111111111111111".to_string();let hash=format!("0x{}","a".repeat(64));
        let tx=json!({"hash":hash,"from":wallet,"to":POOL,"input":format!("{}{:064x}",selector("deposit(uint256)"),5_000_000u128),
            "value":"0x0","chainId":"0x6792","blockNumber":"0x10","blockHash":format!("0x{}","b".repeat(64))});
        let receipt=json!({"transactionHash":hash,"from":wallet,"to":POOL,"status":"0x1","blockNumber":"0x10","blockHash":tx["blockHash"],"logs":[
            {"address":USDC,"topics":[ERC20_TRANSFER_TOPIC,address_topic(&wallet),address_topic(POOL)],"data":format!("0x{:064x}",5_000_000u128)},
            {"address":POOL,"topics":[topic("Deposited(address,uint256)"),address_topic(&wallet)],"data":format!("0x{:064x}",5_000_000u128)}]});
        (wallet,hash,receipt,tx)
    }
    #[test]
    fn accepts_only_exact_individual_usdc_pool_effect() {let (wallet,hash,receipt,tx)=fixture();assert!(matches!(deposit_effect(&wallet,&hash,"5000000",&receipt,&tx),DepositFinality::Finalized));}
    #[test]
    fn rejects_wrong_asset_amount_wallet_chain_target_and_call() {
        for field in ["from","to","input","chainId","value","blockHash","blockNumber"] {
            let (wallet,hash,receipt,mut tx)=fixture();tx[field]=json!(if field=="value" {"0x1"} else {"0x0"});
            assert!(matches!(deposit_effect(&wallet,&hash,"5000000",&receipt,&tx),DepositFinality::Conflict),"field {field}");
        }
        let (wallet,hash,receipt,tx)=fixture();assert!(matches!(deposit_effect(&wallet,&hash,"0",&receipt,&tx),DepositFinality::Conflict));
    }
    #[test]
    fn accepts_an_exact_sub_five_usdc_pool_effect() {
        let (wallet,hash,mut receipt,mut tx)=fixture();
        let value=1u128;
        tx["input"]=json!(format!("{}{:064x}",selector("deposit(uint256)"),value));
        receipt["logs"][0]["data"]=json!(format!("0x{:064x}",value));
        receipt["logs"][1]["data"]=json!(format!("0x{:064x}",value));
        assert!(matches!(deposit_effect(&wallet,&hash,"1",&receipt,&tx),DepositFinality::Finalized));
    }
    #[test]
    fn receipt_requires_exactly_one_transfer_and_pool_deposit() {
        let (wallet,hash,mut receipt,tx)=fixture();receipt["logs"][0]["removed"]=json!(true);
        assert!(matches!(deposit_effect(&wallet,&hash,"5000000",&receipt,&tx),DepositFinality::Conflict));
        let (wallet,hash,mut receipt,tx)=fixture();let duplicate=receipt["logs"][1].clone();receipt["logs"].as_array_mut().unwrap().push(duplicate);
        assert!(matches!(deposit_effect(&wallet,&hash,"5000000",&receipt,&tx),DepositFinality::Conflict));
    }
    #[test]
    fn signed_withdrawal_requires_exact_pool_call_and_event() {
        let ledger="0x1111111111111111111111111111111111111111";let destination="0x2222222222222222222222222222222222222222";
        let hash=format!("0x{}","a".repeat(64));let block=format!("0x{}","b".repeat(64));let amount="2000000";
        let input=pool_withdraw_calldata(destination,amount).unwrap();
        let tx=json!({"hash":hash,"from":ledger,"to":POOL,"input":input,"value":"0x0","chainId":"0x6792","blockNumber":"0x10","blockHash":block});
        let receipt=json!({"transactionHash":hash,"from":ledger,"to":POOL,"status":"0x1","blockNumber":"0x10","blockHash":block,"logs":[
            {"address":POOL,"topics":[topic("Withdrawn(address,uint256,address)"),address_topic(destination),address_topic(ledger)],
                "data":format!("0x{:064x}",2_000_000u128)},
            {"address":USDC,"topics":[ERC20_TRANSFER_TOPIC,address_topic(POOL),address_topic(destination)],
                "data":format!("0x{:064x}",2_000_000u128)}]});
        assert!(matches!(signed_withdrawal_effect(ledger,destination,amount,&hash,POOL,USDC,&receipt,&tx),DepositFinality::Finalized));
        let mut wrong=receipt.clone();wrong["logs"][0]["topics"][1]=json!(address_topic(ledger));
        assert!(matches!(signed_withdrawal_effect(ledger,destination,amount,&hash,POOL,USDC,&wrong,&tx),DepositFinality::Conflict));
    }
    #[test]
    fn expired_unsubmitted_release_requires_a_later_canonical_block() {
        let key=k256::ecdsa::SigningKey::from_bytes((&[7u8;32]).into()).unwrap();
        let public=key.verifying_key().to_encoded_point(false);
        let account=format!("0x{}",hex::encode(&Keccak256::digest(&public.as_bytes()[1..])[12..]));
        let intent=SignedWithdrawalIntent {account,pool:POOL.into(),token:USDC.into(),route_wallet:"0x2222222222222222222222222222222222222222".into(),
            amount_atomic:"20000000".into(),recipient:"0x3333333333333333333333333333333333333333".into(),destination_chain:"base".into(),nonce:"42".into(),expiry_unix:100};
        let hash=format!("0x{}","b".repeat(64));let block=json!({"hash":hash,"timestamp":"0x65"});
        assert!(matches!(signed_withdrawal_expiry_effect(&intent,&hash,&block).unwrap(),DepositFinality::Finalized));
        let early=json!({"hash":hash,"timestamp":"0x64"});
        assert!(matches!(signed_withdrawal_expiry_effect(&intent,&hash,&early).unwrap(),DepositFinality::Pending));
    }
}
