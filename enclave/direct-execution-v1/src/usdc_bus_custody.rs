//! Independent terminal Bus custody verification. Worker stages and balance
//! snapshots are not settlement evidence. No transaction is sent by this port.
use super::*;
use sha3::{Digest,Keccak256};
const POOL:&str="0xb412f63299ccff4fe57714ee580895cca74dd284";
const HZ_TOKEN:&str="0xdf7108f8b10f9b9ec1aba01cca057268cbf86b6c";
const HZ_BRIDGE:&str="0x3a1293bdb83bbbdd5ebf4fac96605ad2021bbc0f";
const HZ_MESSAGING:&str="0x88853d410299bcbfe5fcc9eef93c03115e908279";
const ARB_TOKEN:&str="0xaf88d065e77c8cc2239327c5edb3a432268e5831";
const ARB_BRIDGE:&str="0xe8cdf27acd73a434d661c84887215f7598e7d0d3";
const ARB_MESSAGING:&str="0x19cfce47ed54a88614648dc3f19a5980097007dd";
const ENTRY_POINT:&str="0x0000000071727de22e5e9d8baf0edac6f37da032";
const ENTRY_POINT_CODE_HASH:&str="8db5ff695839d655407cc8490bb7a5d82337a86a6b39c3f0258aa6c3b582fc58";
const ZERO:&str="0x0000000000000000000000000000000000000000";
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct BusWithdrawalProof {
    pub pool_transaction_hash:String,pub boarding_transaction_hash:String,
    pub driving_transaction_hash:String,pub destination_transaction_hash:String,
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct BusDepositProof {
    pub boarding_transaction_hash:String,pub ticket_id:String,pub user_operation_hash:Option<String>,
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct BusDepositFinalizationProof {
    pub boarding:BusDepositProof,pub driving_transaction_hash:String,
    pub destination_transaction_hash:String,pub pool_transaction_hash:String,
}
struct VerifiedDepositTicket {reference:String,ticket:u128,received:u128,passenger:String}
#[derive(Clone)]
pub(super) struct UsdcBusCustodyAdapter {
    client:reqwest::Client,horizen_url:String,arbitrum_url:String,horizen_confirmations:u64,arbitrum_confirmations:u64,
    ledger:String,maximum_subsidy:u128,maximum_native:u128,
}
struct Confirmed {receipt:Value,tx:Value}
fn denied()->String {"USDC Bus custody proof conflict".into()}
fn topic(value:&str)->String {format!("0x{}",hex::encode(Keccak256::digest(value.as_bytes())))}
fn selector(value:&str)->String {topic(value)[..10].into()}
fn eq(value:&Value,expected:&str)->bool {value.as_str().is_some_and(|value|value.eq_ignore_ascii_case(expected))}
fn word(value:u128)->String {format!("{value:064x}")}
fn address_word(value:&str)->String {format!("{:0>64}",value.trim_start_matches("0x"))}
fn at(data:&Value,index:usize)->Result<String,String>{
    let data=data.as_str().ok_or_else(denied)?;
    if !data.starts_with("0x")||data.len()%2!=0||!data[2..].bytes().all(|byte|byte.is_ascii_hexdigit()) {return Err(denied());}
    data.get(2+index*64..2+(index+1)*64).map(str::to_ascii_lowercase).ok_or_else(denied)
}
fn integer(data:&Value,index:usize)->Result<u128,String>{
    let value=at(data,index)?;
    if value[..32].bytes().any(|byte|byte!=b'0') {return Err(denied());}
    u128::from_str_radix(&value[32..],16).map_err(|_|denied())
}
fn events<'a>(receipt:&'a Value,contract:&str,event:&str)->Vec<&'a Value>{
    let event=topic(event);
    receipt["logs"].as_array().map_or_else(Vec::new,|logs|logs.iter().filter(|log|eq(&log["address"],contract)&&eq(&log["topics"][0],&event)).collect())
}
fn transfer<'a>(receipt:&'a Value,token:&str,from:&str,to:&str,amount:u128)->Vec<&'a Value>{
    events(receipt,token,"Transfer(address,address,uint256)").into_iter().filter(|log|
        log["topics"].as_array().is_some_and(|topics|topics.len()==3)
            &&eq(&log["topics"][1],&format!("0x{}",address_word(from)))&&eq(&log["topics"][2],&format!("0x{}",address_word(to)))
            &&eq(&log["data"],&format!("0x{}",word(amount)))).collect()
}
fn bytes_argument(bytes:&str)->Result<String,String>{
    if bytes.len()%2!=0||!bytes.bytes().all(|byte|byte.is_ascii_hexdigit()) {return Err(denied());}
    Ok(format!("{}{:0<width$}",word((bytes.len()/2) as u128),bytes,width=((bytes.len()+63)/64)*64))
}
fn coherence(value:&Confirmed,chain:u128,hash:&str)->Result<(),String>{
    let tx=&value.tx;let receipt=&value.receipt;
    if !valid_transaction_hash(hash)||hash!=hash.to_ascii_lowercase()
        ||!eq(&tx["hash"],hash)||!eq(&receipt["transactionHash"],hash)
        ||tx["chainId"].as_str().and_then(parse_quantity)!=Some(chain)
        ||tx["blockHash"]!=receipt["blockHash"]||tx["blockNumber"]!=receipt["blockNumber"]
        ||!valid_transaction_hash(receipt["blockHash"].as_str().unwrap_or(""))
        ||receipt["blockNumber"].as_str().and_then(parse_quantity).filter(|number|*number>0).is_none()
        ||tx["from"]!=receipt["from"]||tx["to"]!=receipt["to"]||!eq(&receipt["status"],"0x1") {return Err(denied());}
    canonical_evm_address(tx["from"].as_str().unwrap_or("")).map_err(|_|denied())?;
    canonical_evm_address(tx["to"].as_str().unwrap_or("")).map_err(|_|denied())?;
    let logs=receipt["logs"].as_array().filter(|logs|logs.len()<=10000).ok_or_else(denied)?;
    let mut indices=HashSet::new();
    for log in logs {
        let index=log["logIndex"].as_str().and_then(parse_quantity).ok_or_else(denied)?;
        if !indices.insert(index)||log["removed"].as_bool()==Some(true)||log["transactionHash"]!=receipt["transactionHash"]
            ||log["blockHash"]!=receipt["blockHash"]||log["blockNumber"]!=receipt["blockNumber"] {return Err(denied());}
    }
    Ok(())
}
impl UsdcBusCustodyAdapter {
    pub fn from_environment()->Result<Option<Self>,String>{
        if env::var("LAYRS_DIRECT_USDC_CUSTODY_ENABLED").as_deref()!=Ok("true") {return Ok(None);}
        let required=|name:&str|env::var(name).map_err(|_|format!("{name} required"));
        let url=|name:&str|->Result<String,String>{
            let value=required(name)?;let parsed=reqwest::Url::parse(&value).map_err(|_|"USDC RPC configuration invalid")?;
            if !parsed.username().is_empty()||parsed.password().is_some()
                ||(parsed.scheme()!="https"&&!(parsed.scheme()=="http"&&matches!(parsed.host_str(),Some("localhost"|"127.0.0.1")))) {
                return Err("USDC RPC configuration invalid".into());
            }Ok(value)
        };
        let positive=|name:&str|->Result<u128,String>{required(name)?.parse().ok().filter(|value|*value>0).ok_or_else(||format!("{name} invalid"))};
        let confirmations=|name:&str|->Result<u64,String>{let value=positive(name)?;if value>10000 {return Err("USDC finality invalid".into());}Ok(value as u64)};
        Ok(Some(Self {client:reqwest::Client::builder().timeout(Duration::from_secs(5)).build().map_err(|_|"USDC RPC client unavailable")?,
            horizen_url:url("LAYRSV2_HORIZEN_RPC_URL")?,arbitrum_url:url("LAYRSV2_ARBITRUM_RPC_URL")?,
            horizen_confirmations:confirmations("LAYRSV2_HORIZEN_CONFIRMATIONS")?,arbitrum_confirmations:confirmations("LAYRSV2_ARBITRUM_CONFIRMATIONS")?,
            ledger:canonical_evm_address(&required("LAYRS_DIRECT_USDC_LEDGER_WALLET_ADDRESS")?).map_err(|_|"USDC ledger wallet invalid")?,
            maximum_subsidy:positive("LAYRS_DIRECT_USDC_MAX_SUBSIDY_ATOMIC")?,maximum_native:positive("LAYRS_DIRECT_USDC_MAX_BRIDGE_FEE_WEI")?}))
    }
    async fn rpc(&self,url:&str,method:&str,params:Value)->Result<Value,String>{
        let response=self.client.post(url).json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params})).send().await
            .map_err(|_|"USDC Bus RPC unavailable")?.error_for_status().map_err(|_|"USDC Bus RPC rejected")?;
        if response.content_length().is_some_and(|size|size>8_000_000) {return Err("USDC Bus RPC limit".into());}
        let bytes=response.bytes().await.map_err(|_|"USDC Bus RPC unavailable")?;
        if bytes.len()>8_000_000 {return Err("USDC Bus RPC limit".into());}
        let body:Value=serde_json::from_slice(&bytes).map_err(|_|"USDC Bus RPC malformed")?;
        if body["jsonrpc"]!="2.0"||body["id"]!=1||body.get("error").is_some() {return Err("USDC Bus RPC rejected".into());}
        body.get("result").cloned().ok_or("USDC Bus RPC result missing".into())
    }
    async fn confirmed(&self,arbitrum:bool,hash:&str)->Result<Option<Confirmed>,String>{
        if !valid_transaction_hash(hash)||hash!=hash.to_ascii_lowercase() {return Err(denied());}
        let (url,chain,confirmations)=if arbitrum {(&self.arbitrum_url,42161,self.arbitrum_confirmations)} else {(&self.horizen_url,26514,self.horizen_confirmations)};
        if self.rpc(url,"eth_chainId",json!([])).await?.as_str().and_then(parse_quantity)!=Some(chain) {return Err("USDC Bus RPC chain mismatch".into());}
        let receipt=self.rpc(url,"eth_getTransactionReceipt",json!([hash])).await?;
        if receipt.is_null() {return Ok(None);}
        let number=receipt["blockNumber"].as_str().and_then(parse_quantity).ok_or_else(denied)?;
        let head=self.rpc(url,"eth_blockNumber",json!([])).await?.as_str().and_then(parse_quantity).ok_or_else(denied)?;
        if head.checked_sub(number).and_then(|value|value.checked_add(1)).unwrap_or(0)<u128::from(confirmations) {return Ok(None);}
        let block=self.rpc(url,"eth_getBlockByNumber",json!([quantity(number),false])).await?;
        if block["hash"]!=receipt["blockHash"] {return Err("USDC Bus RPC reorg".into());}
        let tx=self.rpc(url,"eth_getTransactionByHash",json!([hash])).await?;
        let result=Confirmed {receipt,tx};coherence(&result,chain,hash)?;Ok(Some(result))
    }
    pub async fn settlement(&self,destination:&str,amount:&str,proof:&BusWithdrawalProof)->Result<Option<String>,String>{
        let asset=self.rpc(&self.horizen_url,"eth_call",json!([{"to":POOL,"data":selector("asset()")},"latest"])).await?;
        if !eq(&asset,&format!("0x{}",address_word(HZ_TOKEN))) {return Err(denied());}
        let Some(pool)=self.confirmed(false,&proof.pool_transaction_hash).await? else {return Ok(None);};
        let Some(boarding)=self.confirmed(false,&proof.boarding_transaction_hash).await? else {return Ok(None);};
        let Some(driving)=self.confirmed(false,&proof.driving_transaction_hash).await? else {return Ok(None);};
        let Some(arrival)=self.confirmed(true,&proof.destination_transaction_hash).await? else {return Ok(None);};
        terminal_effect(&self.ledger,destination,amount,self.maximum_subsidy,self.maximum_native,proof,&pool,&boarding,&driving,&arrival).map(Some)
    }
    async fn deposit_ticket(&self,wallet:&str,amount:&str,proof:&BusDepositProof)->Result<Option<VerifiedDepositTicket>,String>{
        let Some(boarding)=self.confirmed(true,&proof.boarding_transaction_hash).await? else {return Ok(None);};
        let trace=if proof.user_operation_hash.is_some(){
            let code=self.rpc(&self.arbitrum_url,"eth_getCode",json!([ENTRY_POINT,boarding.receipt["blockNumber"]])).await?;
            let bytes=hex::decode(code.as_str().ok_or_else(denied)?.strip_prefix("0x").ok_or_else(denied)?).map_err(|_|denied())?;
            if hex::encode(Keccak256::digest(&bytes))!=ENTRY_POINT_CODE_HASH {return Err(denied());}
            Some(self.rpc(&self.arbitrum_url,"debug_traceTransaction",json!([proof.boarding_transaction_hash,
                {"tracer":"callTracer","timeout":"5s","tracerConfig":{"onlyTopCall":false}}])).await?)
        }else{None};
        let ticket=normal_deposit_effect(wallet,amount,self.maximum_subsidy,self.maximum_native,proof,&boarding,trace.as_ref())?;
        let Some(fresh)=self.confirmed(true,&proof.boarding_transaction_hash).await? else {return Ok(None);};
        if fresh.receipt["blockHash"]!=boarding.receipt["blockHash"] {return Err(denied());}Ok(Some(ticket))
    }
    pub async fn conditional_deposit(&self,wallet:&str,amount:&str,proof:&BusDepositProof)->Result<Option<String>,String>{
        Ok(self.deposit_ticket(wallet,amount,proof).await?.map(|ticket|ticket.reference))
    }
    pub async fn deposit_finalization(&self,wallet:&str,amount:&str,proof:&BusDepositFinalizationProof)->Result<Option<(String,String)>,String>{
        let Some(ticket)=self.deposit_ticket(wallet,amount,&proof.boarding).await? else {return Ok(None);};
        let Some(drive)=self.confirmed(true,&proof.driving_transaction_hash).await? else {return Ok(None);};
        let Some(arrival)=self.confirmed(false,&proof.destination_transaction_hash).await? else {return Ok(None);};
        let Some(pool)=self.confirmed(false,&proof.pool_transaction_hash).await? else {return Ok(None);};
        let reference=normal_deposit_finalization(wallet,amount,proof,&ticket,&drive,&arrival,&pool)?;
        Ok(Some((ticket.reference,reference)))
    }
}

fn scoped_deposit_boarding(boarding:&Confirmed,proof:&BusDepositProof,wallet:&str,trace:Option<&Value>)->Result<(Value,Value),String>{
    coherence(boarding,42161,&proof.boarding_transaction_hash)?;
    if proof.user_operation_hash.is_none(){
        if !eq(&boarding.tx["from"],wallet)||!eq(&boarding.tx["to"],ARB_BRIDGE)||trace.is_some(){return Err(denied());}
        return Ok((boarding.receipt.clone(),boarding.tx.clone()));
    }
    let hash=proof.user_operation_hash.as_deref().filter(|hash|valid_transaction_hash(hash)&&*hash==hash.to_ascii_lowercase()).ok_or_else(denied)?;
    if !eq(&boarding.tx["to"],ENTRY_POINT){return Err(denied());}
    let mut markers=events(&boarding.receipt,ENTRY_POINT,"UserOperationEvent(bytes32,address,address,uint256,bool,uint256,uint256)");
    markers.sort_by_key(|log|log["logIndex"].as_str().and_then(parse_quantity).unwrap());
    let owned=markers.iter().filter(|log|eq(&log["topics"][2],&format!("0x{}",address_word(wallet)))).collect::<Vec<_>>();
    if owned.len()!=1||owned[0]["topics"].as_array().map(Vec::len)!=Some(4)||!eq(&owned[0]["topics"][1],hash)
        ||!eq(&owned[0]["topics"][3],&format!("0x{}",word(0)))||integer(&owned[0]["data"],1)?!=1
        ||integer(&owned[0]["data"],2)?!=0||integer(&owned[0]["data"],3)?==0 {return Err(denied());}
    let before=events(&boarding.receipt,ENTRY_POINT,"BeforeExecution()");
    if before.len()!=1 {return Err(denied());}
    let end=owned[0]["logIndex"].as_str().and_then(parse_quantity).ok_or_else(denied)?;
    let mut start=before[0]["logIndex"].as_str().and_then(parse_quantity).ok_or_else(denied)?;
    if start>=end{return Err(denied());}
    for log in &markers {let i=log["logIndex"].as_str().and_then(parse_quantity).ok_or_else(denied)?;
        if i>start&&i<end {start=i;}}
    let root=trace.ok_or_else(denied)?;
    if root["type"]!="CALL"||!eq(&root["from"],boarding.receipt["from"].as_str().ok_or_else(denied)?)||!eq(&root["to"],ENTRY_POINT)
        ||root["input"]!=boarding.tx["input"]||root["value"].as_str().and_then(parse_quantity)!=boarding.tx["value"].as_str().and_then(parse_quantity) {return Err(denied());}
    fn visit<'a>(node:&'a Value,wallet:&str,depth:usize,reverted:bool,count:&mut usize,matches:&mut Vec<&'a Value>)->Result<(),String>{
        *count+=1;if *count>10000||depth>64||!node.is_object(){return Err(denied());}
        let failed=reverted||node.get("error").is_some_and(|value|!value.is_null());
        if !failed&&node["type"]=="CALL"&&eq(&node["from"],wallet)&&eq(&node["to"],ARB_BRIDGE){matches.push(node);}
        if let Some(children)=node.get("calls"){for child in children.as_array().ok_or_else(denied)? {visit(child,wallet,depth+1,failed,count,matches)?;}}
        Ok(())
    }
    let mut matches=Vec::new();visit(root,wallet,0,false,&mut 0,&mut matches)?;
    if matches.len()!=1{return Err(denied());}
    let mut receipt=boarding.receipt.clone();receipt["logs"]=json!(receipt["logs"].as_array().ok_or_else(denied)?.iter().filter(|log|
        log["logIndex"].as_str().and_then(parse_quantity).is_some_and(|i|i>start&&i<end)).cloned().collect::<Vec<_>>());
    let call=json!({"from":wallet,"to":ARB_BRIDGE,"input":matches[0]["input"],"value":matches[0]["value"]});
    Ok((receipt,call))
}
fn normal_deposit_effect(wallet:&str,amount:&str,max_subsidy:u128,max_native:u128,proof:&BusDepositProof,boarding:&Confirmed,trace:Option<&Value>)->Result<VerifiedDepositTicket,String>{
    let wallet=canonical_evm_address(wallet).map_err(|_|denied())?;
    let principal=amount.parse::<u128>().ok().filter(|value|*value>=5_000_000&&value.to_string()==amount).ok_or_else(denied)?;
    let (receipt,call)=scoped_deposit_boarding(boarding,proof,&wallet,trace)?;
    let sends=events(&receipt,ARB_BRIDGE,"OFTSent(bytes32,uint32,address,uint256,uint256)");
    let rides=events(&receipt,ARB_MESSAGING,"BusRode(uint32,uint72,uint80,bytes)");
    if sends.len()!=1||rides.len()!=1||sends[0]["topics"].as_array().map(Vec::len)!=Some(3)
        ||!eq(&sends[0]["topics"][1],&format!("0x{}",word(0)))||!eq(&sends[0]["topics"][2],&format!("0x{}",address_word(&wallet)))
        ||integer(&sends[0]["data"],0)?!=30399 {return Err(denied());}
    let gross=integer(&sends[0]["data"],1)?;let received=integer(&sends[0]["data"],2)?;
    let native=call["value"].as_str().and_then(parse_quantity).ok_or_else(denied)?;
    if gross<principal||gross-principal>max_subsidy||received<principal||received>u128::from(u64::MAX)||native>max_native {return Err(denied());}
    let ticket=integer(&rides[0]["data"],1)?;let fare=integer(&rides[0]["data"],2)?;
    let passenger=format!("0001{}{:016x}00",address_word(&wallet),received);
    let ride_data=format!("0x{}{}{}{}{}",word(30399),word(ticket),word(fare),word(128),bytes_argument(&passenger)?);
    let send_call=format!("{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}",selector("sendToken((uint32,bytes32,uint256,uint256,bytes,bytes,bytes),(uint256,uint256),address)"),
        word(128),word(native),word(0),address_word(&wallet),word(30399),address_word(&wallet),word(gross),word(principal),
        word(224),word(256),word(288),word(0),word(0),word(1),format!("01{}","0".repeat(62)));
    if ticket>=1u128<<72||ticket.to_string()!=proof.ticket_id||fare>native||!eq(&rides[0]["data"],&ride_data)
        ||rides[0]["topics"].as_array().map(Vec::len)!=Some(1)||!eq(&call["input"],&send_call)
        ||transfer(&receipt,ARB_TOKEN,&wallet,ARB_BRIDGE,gross).len()!=1 {return Err(denied());}
    Ok(VerifiedDepositTicket {reference:format!("arbitrum-usdc-bus-deposit:{}:{ticket}",proof.boarding_transaction_hash),ticket,received,passenger})
}
fn normal_deposit_finalization(wallet:&str,amount:&str,proof:&BusDepositFinalizationProof,ticket:&VerifiedDepositTicket,drive:&Confirmed,arrival:&Confirmed,pool:&Confirmed)->Result<String,String>{
    let wallet=canonical_evm_address(wallet).map_err(|_|denied())?;
    let principal=amount.parse::<u128>().ok().filter(|value|*value>=5_000_000&&value.to_string()==amount).ok_or_else(denied)?;
    coherence(drive,42161,&proof.driving_transaction_hash)?;coherence(arrival,26514,&proof.destination_transaction_hash)?;coherence(pool,26514,&proof.pool_transaction_hash)?;
    let drives=events(&drive.receipt,ARB_MESSAGING,"BusDriven(uint32,uint72,uint8,bytes32)");
    if drives.len()!=1||drives[0]["topics"].as_array().map(Vec::len)!=Some(1)||integer(&drives[0]["data"],0)?!=30399 {return Err(denied());}
    let start=integer(&drives[0]["data"],1)?;let count=integer(&drives[0]["data"],2)?;
    let guid=format!("0x{}",at(&drives[0]["data"],3)?);
    let seat=ticket.ticket.checked_sub(start).filter(|seat|*seat<count).ok_or_else(denied)?;
    if start>=1u128<<72||count==0||count>255||guid==format!("0x{}",word(0))||!eq(&drive.tx["to"],ARB_MESSAGING){return Err(denied());}
    let input=drive.tx["input"].as_str().ok_or_else(denied)?;
    let tail=input.get(10..).map(|tail|Value::String(format!("0x{tail}"))).ok_or_else(denied)?;
    if integer(&tail,0)?!=30399||integer(&tail,1)?!=64||integer(&tail,2)?!=count*43 {return Err(denied());}
    let passengers=input.get(202..202+count as usize*86).ok_or_else(denied)?.to_ascii_lowercase();
    let expected=format!("{}{}{}{}",selector("driveBus(uint32,bytes)"),word(30399),word(64),bytes_argument(&passengers)?);
    if !eq(&drive.tx["input"],&expected)||passengers.get(seat as usize*86..(seat as usize+1)*86)!=Some(ticket.passenger.as_str()) {return Err(denied());}
    // Allocate identical receiver/amount passengers by ordered seat outcomes.
    // An explicit cached failure occupies its seat and must not steal another
    // successful passenger's transfer. Exact retry calldata provides the index.
    let mut receives=events(&arrival.receipt,HZ_BRIDGE,"OFTReceived(bytes32,uint32,address,uint256)").into_iter().filter(|log|
        log["topics"].as_array().map(Vec::len)==Some(3)&&eq(&log["topics"][1],&guid)
        &&eq(&log["topics"][2],&format!("0x{}",address_word(&wallet)))
        &&integer(&log["data"],0).ok()==Some(30110)&&integer(&log["data"],1).ok()==Some(ticket.received)).collect::<Vec<_>>();
    receives.sort_by_key(|log|log["logIndex"].as_str().and_then(parse_quantity).unwrap());
    let mut transfers=transfer(&arrival.receipt,HZ_TOKEN,ZERO,&wallet,ticket.received);
    transfers.sort_by_key(|log|log["logIndex"].as_str().and_then(parse_quantity).unwrap());
    if receives.is_empty()||transfers.len()!=receives.len() {return Err(denied());}
    for (index,receive) in receives.iter().enumerate(){
        let transfer_index=transfers[index]["logIndex"].as_str().and_then(parse_quantity).unwrap();
        let receive_index=receive["logIndex"].as_str().and_then(parse_quantity).unwrap();
        if transfer_index>=receive_index||(index>0&&transfer_index<=receives[index-1]["logIndex"].as_str().and_then(parse_quantity).unwrap()) {return Err(denied());}
    }
    let retry_selector=selector("retryReceiveToken(bytes32,uint8,uint32,address,uint256,bytes)");
    let _selected=if arrival.tx["input"].as_str().is_some_and(|input|input.starts_with(&retry_selector)) {
        let call=format!("{}{}{}{}{}{}{}{}",retry_selector,guid.trim_start_matches("0x"),word(seat),word(30110),address_word(&wallet),word(ticket.received),word(192),word(0));
        if receives.len()!=1||!eq(&arrival.tx["to"],HZ_BRIDGE)||!eq(&arrival.tx["input"],&call) {return Err(denied());}0
    }else{
        let matching=(0..count as usize).filter(|index|passengers.get(index*86..index*86+84)==ticket.passenger.get(..84)).collect::<Vec<_>>();
        let caches=events(&arrival.receipt,HZ_BRIDGE,"UnreceivedTokenCached(bytes32,uint8,uint32,address,uint256,bytes)").into_iter().filter(|log|
            at(&log["data"],0).ok().is_some_and(|hash|format!("0x{hash}")==guid)
            &&integer(&log["data"],2).ok()==Some(30110)&&at(&log["data"],3).ok()==Some(address_word(&wallet))
            &&integer(&log["data"],4).ok()==Some(ticket.received)).collect::<Vec<_>>();
        let mut outcomes=receives.iter().map(|log|(*log,false)).chain(caches.iter().map(|log|(*log,true))).collect::<Vec<_>>();
        outcomes.sort_by_key(|(log,_)|log["logIndex"].as_str().and_then(parse_quantity).unwrap());
        if outcomes.len()!=matching.len() {return Err(denied());}
        let mut successful=0;let mut selected=None;
        for (index,(log,failed)) in outcomes.iter().enumerate(){
            if *failed&&(integer(&log["data"],1)?!=matching[index] as u128||integer(&log["data"],5)?!=192||integer(&log["data"],6)?!=0) {return Err(denied());}
            if matching[index]==seat as usize {if *failed {return Err("USDC Bus token cached".into());}selected=Some(successful);}
            if !failed {successful+=1;}
        }selected.ok_or_else(denied)?
    };
    let arrival_block=arrival.receipt["blockNumber"].as_str().and_then(parse_quantity).ok_or_else(denied)?;
    let pool_block=pool.receipt["blockNumber"].as_str().and_then(parse_quantity).ok_or_else(denied)?;
    if pool_block<arrival_block {return Err(denied());}
    if pool_block==arrival_block {
        let arrival_index=arrival.receipt["transactionIndex"].as_str().and_then(parse_quantity).ok_or_else(denied)?;
        let pool_index=pool.receipt["transactionIndex"].as_str().and_then(parse_quantity).ok_or_else(denied)?;
        if pool_index<=arrival_index {return Err(denied());}
    }
    let expected_pool=format!("{}{}",selector("deposit(uint256)"),word(principal));
    let deposits=events(&pool.receipt,POOL,"Deposited(address,uint256)");
    if !eq(&pool.tx["from"],&wallet)||!eq(&pool.tx["to"],POOL)||!eq(&pool.tx["input"],&expected_pool)
        ||pool.tx["value"].as_str().and_then(parse_quantity)!=Some(0)||deposits.len()!=1
        ||deposits[0]["topics"].as_array().map(Vec::len)!=Some(2)||!eq(&deposits[0]["topics"][1],&format!("0x{}",address_word(&wallet)))
        ||integer(&deposits[0]["data"],0)?!=principal||transfer(&pool.receipt,HZ_TOKEN,&wallet,POOL,principal).len()!=1 {return Err(denied());}
    Ok(format!("horizen-usdc-deposit:{}",proof.pool_transaction_hash))
}

fn terminal_effect(ledger:&str,destination:&str,amount:&str,max_subsidy:u128,max_native:u128,proof:&BusWithdrawalProof,
    pool:&Confirmed,boarding:&Confirmed,driving:&Confirmed,arrival:&Confirmed)->Result<String,String>{
    let recipient=canonical_evm_address(destination).map_err(|_|denied())?;
    let principal=amount.parse::<u128>().ok().filter(|value|*value>0&&value.to_string()==amount).ok_or_else(denied)?;
    coherence(pool,26514,&proof.pool_transaction_hash)?;coherence(boarding,26514,&proof.boarding_transaction_hash)?;
    coherence(driving,26514,&proof.driving_transaction_hash)?;coherence(arrival,42161,&proof.destination_transaction_hash)?;
    let pool_call=format!("{}{}{}",selector("withdraw(address,uint256)"),address_word(ledger),word(principal));
    let withdrawals=events(&pool.receipt,POOL,"Withdrawn(address,uint256,address)");
    if !eq(&pool.tx["from"],ledger)||!eq(&pool.tx["to"],POOL)||!eq(&pool.tx["input"],&pool_call)
        ||pool.tx["value"].as_str().and_then(parse_quantity)!=Some(0)||withdrawals.len()!=1
        ||withdrawals[0]["topics"].as_array().map(Vec::len)!=Some(3)
        ||!eq(&withdrawals[0]["topics"][1],&format!("0x{}",address_word(ledger)))
        ||!eq(&withdrawals[0]["topics"][2],&format!("0x{}",address_word(ledger)))
        ||!eq(&withdrawals[0]["data"],&format!("0x{}",word(principal)))
        ||transfer(&pool.receipt,HZ_TOKEN,POOL,ledger,principal).len()!=1 {return Err(denied());}
    let sends=events(&boarding.receipt,HZ_BRIDGE,"OFTSent(bytes32,uint32,address,uint256,uint256)");
    let rides=events(&boarding.receipt,HZ_MESSAGING,"BusRode(uint32,uint72,uint80,bytes)");
    if sends.len()!=1||rides.len()!=1||sends[0]["topics"].as_array().map(Vec::len)!=Some(3)
        ||!eq(&sends[0]["topics"][1],&format!("0x{}",word(0)))||!eq(&sends[0]["topics"][2],&format!("0x{}",address_word(ledger)))
        ||integer(&sends[0]["data"],0)?!=30110 {return Err(denied());}
    let gross=integer(&sends[0]["data"],1)?;let received=integer(&sends[0]["data"],2)?;
    let native=boarding.tx["value"].as_str().and_then(parse_quantity).ok_or_else(denied)?;
    if gross<principal||gross-principal>max_subsidy||received<principal||received>u128::from(u64::MAX)||native>max_native {return Err(denied());}
    let passenger=format!("0001{}{:016x}00",address_word(&recipient),received);
    let ticket=integer(&rides[0]["data"],1)?;let fare=integer(&rides[0]["data"],2)?;
    let ride_data=format!("0x{}{}{}{}{}",word(30110),word(ticket),word(fare),word(128),bytes_argument(&passenger)?);
    let send_call=format!("{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}",selector("sendToken((uint32,bytes32,uint256,uint256,bytes,bytes,bytes),(uint256,uint256),address)"),
        word(128),word(native),word(0),address_word(ledger),word(30110),address_word(&recipient),word(gross),word(principal),
        word(224),word(256),word(288),word(0),word(0),word(1),format!("01{}","0".repeat(62)),"");
    if ticket>=1u128<<72||fare>native||!eq(&rides[0]["data"],&ride_data)||rides[0]["topics"].as_array().map(Vec::len)!=Some(1)
        ||!eq(&boarding.tx["from"],ledger)||!eq(&boarding.tx["to"],HZ_BRIDGE)||!eq(&boarding.tx["input"],&send_call)
        {return Err(denied());}
    let direct_burn=transfer(&boarding.receipt,HZ_TOKEN,ledger,ZERO,gross);
    if direct_burn.len()!=1 {
        let pulls=transfer(&boarding.receipt,HZ_TOKEN,ledger,HZ_BRIDGE,gross);
        let burns=transfer(&boarding.receipt,HZ_TOKEN,HZ_BRIDGE,ZERO,gross);
        if !direct_burn.is_empty()||pulls.len()!=1||burns.len()!=1 {return Err(denied());}
        let index=|log:&Value|log["logIndex"].as_str().and_then(parse_quantity).ok_or_else(denied);
        if index(pulls[0])?>=index(burns[0])?||index(burns[0])?>=index(rides[0])? {return Err(denied());}
    }
    let drives=events(&driving.receipt,HZ_MESSAGING,"BusDriven(uint32,uint72,uint8,bytes32)");
    if drives.len()!=1||drives[0]["topics"].as_array().map(Vec::len)!=Some(1)||integer(&drives[0]["data"],0)?!=30110 {return Err(denied());}
    let start=integer(&drives[0]["data"],1)?;let count=integer(&drives[0]["data"],2)?;
    let guid=format!("0x{}",at(&drives[0]["data"],3)?);
    let seat=ticket.checked_sub(start).filter(|seat|*seat<count).ok_or_else(denied)?;
    if start>=1u128<<72||count==0||count>255||guid==format!("0x{}",word(0))||!eq(&driving.tx["to"],HZ_MESSAGING) {return Err(denied());}
    let input=driving.tx["input"].as_str().ok_or_else(denied)?;
    let tail=input.get(10..).map(|tail|Value::String(format!("0x{tail}"))).ok_or_else(denied)?;
    if integer(&tail,0)?!=30110||integer(&tail,1)?!=64||integer(&tail,2)?!=count*43 {return Err(denied());}
    let passengers=input.get(10+192..10+192+count as usize*86).ok_or_else(denied)?.to_ascii_lowercase();
    let drive_call=format!("{}{}{}{}",selector("driveBus(uint32,bytes)"),word(30110),word(64),bytes_argument(&passengers)?);
    if !eq(&driving.tx["input"],&drive_call)||passengers.get(seat as usize*86..(seat as usize+1)*86)!=Some(passenger.as_str()) {return Err(denied());}
    // Allocate identical receiver/amount passengers by ordered seat outcomes.
    // An explicit cached failure occupies its seat and must not steal another
    // successful passenger's transfer. Exact retry calldata provides the index.
    let mut receives=events(&arrival.receipt,ARB_BRIDGE,"OFTReceived(bytes32,uint32,address,uint256)").into_iter().filter(|log|
        log["topics"].as_array().map(Vec::len)==Some(3)&&eq(&log["topics"][1],&guid)
        &&eq(&log["topics"][2],&format!("0x{}",address_word(&recipient)))
        &&integer(&log["data"],0).ok()==Some(30399)&&integer(&log["data"],1).ok()==Some(received)).collect::<Vec<_>>();
    receives.sort_by_key(|log|log["logIndex"].as_str().and_then(parse_quantity).unwrap());
    let mut transfers=transfer(&arrival.receipt,ARB_TOKEN,ARB_BRIDGE,&recipient,received);
    transfers.sort_by_key(|log|log["logIndex"].as_str().and_then(parse_quantity).unwrap());
    if receives.is_empty()||transfers.len()!=receives.len() {return Err(denied());}
    for (index,receive) in receives.iter().enumerate(){
        let transfer_index=transfers[index]["logIndex"].as_str().and_then(parse_quantity).unwrap();
        let receive_index=receive["logIndex"].as_str().and_then(parse_quantity).unwrap();
        if transfer_index>=receive_index||(index>0&&transfer_index<=receives[index-1]["logIndex"].as_str().and_then(parse_quantity).unwrap()) {return Err(denied());}
    }
    let retry_selector=selector("retryReceiveToken(bytes32,uint8,uint32,address,uint256,bytes)");
    let selected=if arrival.tx["input"].as_str().is_some_and(|input|input.starts_with(&retry_selector)) {
        let call=format!("{}{}{}{}{}{}{}{}",retry_selector,guid.trim_start_matches("0x"),word(seat),word(30399),address_word(&recipient),word(received),word(192),word(0));
        if receives.len()!=1||!eq(&arrival.tx["to"],ARB_BRIDGE)||!eq(&arrival.tx["input"],&call) {return Err(denied());}0
    }else{
        let matching=(0..count as usize).filter(|index|passengers.get(index*86..index*86+84)==passenger.get(..84)).collect::<Vec<_>>();
        let caches=events(&arrival.receipt,ARB_BRIDGE,"UnreceivedTokenCached(bytes32,uint8,uint32,address,uint256,bytes)").into_iter().filter(|log|
            at(&log["data"],0).ok().is_some_and(|hash|format!("0x{hash}")==guid)
            &&integer(&log["data"],2).ok()==Some(30399)&&at(&log["data"],3).ok()==Some(address_word(&recipient))
            &&integer(&log["data"],4).ok()==Some(received)).collect::<Vec<_>>();
        let mut outcomes=receives.iter().map(|log|(*log,false)).chain(caches.iter().map(|log|(*log,true))).collect::<Vec<_>>();
        outcomes.sort_by_key(|(log,_)|log["logIndex"].as_str().and_then(parse_quantity).unwrap());
        if outcomes.len()!=matching.len() {return Err(denied());}
        let mut successful=0;let mut selected=None;
        for (index,(log,failed)) in outcomes.iter().enumerate(){
            if *failed&&(integer(&log["data"],1)?!=matching[index] as u128||integer(&log["data"],5)?!=192||integer(&log["data"],6)?!=0) {return Err(denied());}
            if matching[index]==seat as usize {if *failed {return Err("USDC Bus token cached".into());}selected=Some(successful);}
            if !failed {successful+=1;}
        }selected.ok_or_else(denied)?
    };
    let index=receives[selected]["logIndex"].as_str().and_then(parse_quantity).ok_or_else(denied)?;
    if index>u128::from(u64::MAX) {return Err(denied());}
    Ok(format!("horizen-usdc-bus:{}:{guid}:{}:{seat}:{index}",proof.pool_transaction_hash,proof.destination_transaction_hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn deposit_fixture()->Value {serde_json::from_str(include_str!("../fixtures/usdc-bus-deposit-funded-base-golden.json")).unwrap()}
    fn verify_deposit(value:&Value)->Result<VerifiedDepositTicket,String>{
        let proof:BusDepositProof=serde_json::from_value(value["proof"].clone()).unwrap();
        normal_deposit_effect(value["wallet"].as_str().unwrap(),value["amountAtomic"].as_str().unwrap(),10000,1000000000000000,
            &proof,&material(value,"boarding"),Some(&value["trace"]))
    }
    #[test]
    fn funded_base_deposit_boarding_is_independently_verified(){
        let value=deposit_fixture();let ticket=verify_deposit(&value).unwrap();
        assert_eq!(ticket.ticket,3);assert_eq!(ticket.received,6365257);
        assert_eq!(ticket.reference,format!("arbitrum-usdc-bus-deposit:{}:3",value["proof"]["boardingTransactionHash"].as_str().unwrap()));
    }
    #[test]
    fn funded_base_deposit_finalization_verifies_actual_delivery_and_pool_deposit(){
        let value=deposit_fixture();let ticket=verify_deposit(&value).unwrap();
        let proof:BusDepositFinalizationProof=serde_json::from_value(value["finalizationProof"].clone()).unwrap();
        let reference=normal_deposit_finalization(value["wallet"].as_str().unwrap(),value["amountAtomic"].as_str().unwrap(),&proof,&ticket,
            &material(&value,"drive"),&material(&value,"arrival"),&material(&value,"pool")).unwrap();
        assert_eq!(reference,format!("horizen-usdc-deposit:{}",proof.pool_transaction_hash));
    }
    #[test]
    fn funded_base_deposit_rejects_altered_wallet_ticket_amount_and_trace(){
        for variant in ["wallet","ticket","amount","operation","reverted","trace"] {
            let mut value=deposit_fixture();match variant {
                "wallet"=>value["wallet"]=json!("0x1111111111111111111111111111111111111111"),
                "ticket"=>value["proof"]["ticketId"]=json!("4"),
                "amount"=>value["amountAtomic"]=json!("6365258"),
                "operation"=>value["proof"]["userOperationHash"]=json!(format!("0x{}","1".repeat(64))),
                "reverted"=>value["trace"]["error"]=json!("execution reverted"),
                _=>value["trace"]["input"]=json!("0x")
            };assert!(verify_deposit(&value).is_err(),"{variant}");
        }
    }
    fn fixture()->Value {serde_json::from_str(include_str!("../fixtures/usdc-bus-withdrawal-node-golden.json")).unwrap()}
    fn material(value:&Value,name:&str)->Confirmed {Confirmed {receipt:value[name]["receipt"].clone(),tx:value[name]["tx"].clone()}}
    fn verify(value:&Value)->Result<String,String>{
        let proof:BusWithdrawalProof=serde_json::from_value(value["proof"].clone()).unwrap();
        terminal_effect(value["ledger"].as_str().unwrap(),value["recipient"].as_str().unwrap(),value["amountAtomic"].as_str().unwrap(),10000,1000,&proof,
            &material(value,"pool"),&material(value,"boarding"),&material(value,"driving"),&material(value,"arrival"))
    }
    fn duplicate_prefix(value:&mut Value){
        let input=value["driving"]["tx"]["input"].as_str().unwrap();
        let second=input[202+86..202+172].to_string();
        value["driving"]["tx"]["input"]=json!(format!("{}{}{}",&input[..202],second,&input[202+86..]));
    }
    #[test]
    fn node_abi_golden_links_pool_burn_ticket_foreign_driver_seat_and_actual_native_usdc_delivery(){
        let value=fixture();let reference=verify(&value).unwrap();
        assert_eq!(reference,format!("horizen-usdc-bus:{}:0x{}:{}:1:1",value["proof"]["poolTransactionHash"].as_str().unwrap(),"f".repeat(64),value["proof"]["destinationTransactionHash"].as_str().unwrap()));
    }
    #[test]
    fn deployed_horizen_adapter_pull_then_burn_is_bound_to_the_same_exact_gross(){
        let mut value=fixture();let logs=value["boarding"]["receipt"]["logs"].as_array_mut().unwrap();
        let mut burn=logs[0].clone();burn["topics"][1]=json!(format!("0x{}",address_word(HZ_BRIDGE)));burn["logIndex"]=json!("0x1");
        logs[0]["topics"][2]=json!(format!("0x{}",address_word(HZ_BRIDGE)));
        for log in logs.iter_mut().skip(1){let n=log["logIndex"].as_str().and_then(parse_quantity).unwrap();log["logIndex"]=json!(format!("0x{:x}",n+1));}
        logs.insert(1,burn);assert!(verify(&value).is_ok());
        for kind in ["missing","short","duplicate","reordered"]{
            let mut wrong=value.clone();let logs=wrong["boarding"]["receipt"]["logs"].as_array_mut().unwrap();
            match kind {"missing"=>{logs.remove(1);},"short"=>logs[1]["data"]=json!(format!("0x{}",word(1))),
                "duplicate"=>{let mut extra=logs[1].clone();extra["logIndex"]=json!("0x9");logs.push(extra);},
                _=>{logs[0]["logIndex"]=json!("0x1");logs[1]["logIndex"]=json!("0x0");}}
            assert!(verify(&wrong).is_err(),"{kind}");
        }
    }
    #[test]
    fn rejects_receipt_preimage_rebinding_or_canonical_log_corruption_at_every_stage(){
        for stage in ["pool","boarding","driving","arrival"] {
            for field in ["hash","chainId","input","blockNumber","blockHash"] {
                let mut value=fixture();value[stage]["tx"][field]=json!("0x0");
                // Normal destination delivery calldata is arbitrary LayerZero
                // calldata; it is not inferred from a public send selector.
                if stage=="arrival"&&field=="input" {continue;}
                assert!(verify(&value).is_err(),"{stage}:{field}");
            }
            for kind in ["removed","status","foreign_log","duplicate_index"] {
                let mut value=fixture();match kind {
                    "removed"=>value[stage]["receipt"]["logs"][0]["removed"]=json!(true),
                    "status"=>value[stage]["receipt"]["status"]=json!("0x0"),
                    "foreign_log"=>value[stage]["receipt"]["logs"][0]["transactionHash"]=json!(format!("0x{}","0".repeat(64))),
                    _=>{let log=value[stage]["receipt"]["logs"][0].clone();value[stage]["receipt"]["logs"].as_array_mut().unwrap().push(log);}
                }assert!(verify(&value).is_err(),"{stage}:{kind}");
            }
        }
    }
    #[test]
    fn rejects_wrong_custodian_token_recipient_principal_subsidy_fare_and_zero_guid(){
        for kind in ["ledger","recipient","principal","pool_token","burn","arrival_token","short_delivery","fare","guid"] {
            let mut value=fixture();match kind {
                "ledger"=>value["ledger"]=json!("0x4444444444444444444444444444444444444444"),
                "recipient"=>value["recipient"]=json!("0x4444444444444444444444444444444444444444"),
                "principal"=>value["amountAtomic"]=json!("0"),
                "pool_token"=>value["pool"]["receipt"]["logs"][0]["address"]=json!(ARB_TOKEN),
                "burn"=>value["boarding"]["receipt"]["logs"][0]["topics"][2]=json!(format!("0x{}",address_word(HZ_BRIDGE))),
                "arrival_token"=>value["arrival"]["receipt"]["logs"][0]["address"]=json!(HZ_TOKEN),
                "short_delivery"=>value["arrival"]["receipt"]["logs"][0]["data"]=json!(format!("0x{}",word(4_999_999))),
                "fare"=>value["boarding"]["tx"]["value"]=json!("0x3e9"),
                _=>{let data=value["driving"]["receipt"]["logs"][0]["data"].as_str().unwrap();value["driving"]["receipt"]["logs"][0]["data"]=json!(format!("{}{}",&data[..194],word(0)));}
            }assert!(verify(&value).is_err(),"{kind}");
        }
        let value=fixture();let proof:BusWithdrawalProof=serde_json::from_value(value["proof"].clone()).unwrap();
        assert!(terminal_effect(value["ledger"].as_str().unwrap(),value["recipient"].as_str().unwrap(),"5000000",3001,1000,&proof,
            &material(&value,"pool"),&material(&value,"boarding"),&material(&value,"driving"),&material(&value,"arrival")).is_err());
    }
    #[test]
    fn assigns_identical_receiver_amount_passengers_to_their_own_event_indices(){
        let mut value=fixture();duplicate_prefix(&mut value);
        assert!(verify(&value).is_err()); // One transfer cannot satisfy two seats.
        let mut transfer=value["arrival"]["receipt"]["logs"][0].clone();transfer["logIndex"]=json!("0x2");
        let mut receive=value["arrival"]["receipt"]["logs"][1].clone();receive["logIndex"]=json!("0x3");
        value["arrival"]["receipt"]["logs"].as_array_mut().unwrap().extend([transfer,receive]);
        assert!(verify(&value).unwrap().ends_with(":1:3"));
    }
    #[test]
    fn cached_failures_occupy_their_seat_and_retry_requires_exact_index_calldata(){
        let mut value=fixture();duplicate_prefix(&mut value);
        let recipient=value["recipient"].as_str().unwrap();
        let mut cached=value["arrival"]["receipt"]["logs"][0].clone();
        cached["address"]=json!(ARB_BRIDGE);cached["topics"]=json!([topic("UnreceivedTokenCached(bytes32,uint8,uint32,address,uint256,bytes)")]);
        cached["data"]=json!(format!("0x{}{}{}{}{}{}{}","f".repeat(64),word(0),word(30399),address_word(recipient),word(5_000_000),word(192),word(0)));
        value["arrival"]["receipt"]["logs"][0]["logIndex"]=json!("0x1");
        value["arrival"]["receipt"]["logs"][1]["logIndex"]=json!("0x2");
        value["arrival"]["receipt"]["logs"].as_array_mut().unwrap().insert(0,cached);
        assert!(verify(&value).unwrap().ends_with(":1:2"));
        let recipient=value["recipient"].as_str().unwrap().to_string();
        let data=format!("0x{}{}{}{}{}{}{}","f".repeat(64),word(1),word(30399),address_word(&recipient),word(5_000_000),word(192),word(0));
        value["arrival"]["receipt"]["logs"][0]["data"]=json!(data);
        assert!(verify(&value).is_err()); // Cache now falsely names our own seat.
        value["arrival"]["receipt"]["logs"].as_array_mut().unwrap().remove(0);
        value["arrival"]["tx"]["to"]=json!(ARB_BRIDGE);value["arrival"]["receipt"]["to"]=json!(ARB_BRIDGE);
        let selector=selector("retryReceiveToken(bytes32,uint8,uint32,address,uint256,bytes)");
        let retry=|seat|format!("{}{}{}{}{}{}{}{}",selector,"f".repeat(64),word(seat),word(30399),address_word(&recipient),word(5_000_000),word(192),word(0));
        value["arrival"]["tx"]["input"]=json!(retry(1));assert!(verify(&value).unwrap().ends_with(":1:2"));
        value["arrival"]["tx"]["input"]=json!(retry(0));assert!(verify(&value).is_err());
    }
    #[test]
    fn rejects_unknown_proof_fields_instead_of_worker_selected_finality(){
        let mut value=fixture()["proof"].clone();value["finalized"]=json!(true);
        assert!(serde_json::from_value::<BusWithdrawalProof>(value).is_err());
    }
    #[tokio::test]
    async fn rpc_finality_rejects_wrong_chain_reorg_and_bad_envelopes_and_waits_for_confirmations(){
        for mode in ["confirmed","pending","missing","wrong_chain","reorg","malformed"] {
            let fixture=fixture();let proof:BusWithdrawalProof=serde_json::from_value(fixture["proof"].clone()).unwrap();
            let calls=Arc::new(Mutex::new(Vec::<String>::new()));let observed=calls.clone();
            let state=fixture.clone();
            let app=axum::Router::new().route("/",post(move |Json(body):Json<Value>| {
                let state=state.clone();let observed=observed.clone();async move {
                    let method=body["method"].as_str().unwrap_or("");observed.lock().await.push(method.into());
                    let result=match method {
                        "eth_chainId"=>json!(if mode=="wrong_chain" {"0x1"} else {"0x6792"}),
                        "eth_getTransactionReceipt"=>if mode=="missing" {Value::Null} else {state["pool"]["receipt"].clone()},
                        "eth_getTransactionByHash"=>state["pool"]["tx"].clone(),
                        "eth_blockNumber"=>json!(if mode=="pending" {"0x64"} else {"0x65"}),
                        "eth_getBlockByNumber"=>json!({"hash":if mode=="reorg" {format!("0x{}","0".repeat(64))} else {state["pool"]["receipt"]["blockHash"].as_str().unwrap().into()}}),
                        _=>Value::Null,
                    };
                    Json(json!({"jsonrpc":"2.0","id":if mode=="malformed" {2} else {1},"result":result}))
                }
            }));
            let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();let url=format!("http://{}/",listener.local_addr().unwrap());
            let server=tokio::spawn(async move {axum::serve(listener,app).await.unwrap();});
            let adapter=UsdcBusCustodyAdapter {client:reqwest::Client::builder().timeout(Duration::from_secs(2)).build().unwrap(),
                horizen_url:url.clone(),arbitrum_url:url,horizen_confirmations:2,arbitrum_confirmations:2,
                ledger:fixture["ledger"].as_str().unwrap().into(),maximum_subsidy:10000,maximum_native:1000};
            let result=adapter.confirmed(false,&proof.pool_transaction_hash).await;
            server.abort();
            match mode {"confirmed"=>assert!(result.unwrap().is_some()),"pending"|"missing"=>assert!(result.unwrap().is_none()),_=>assert!(result.is_err(),"{mode}")}
            assert!(calls.lock().await.iter().all(|method|!method.contains("send")&&!method.contains("sign")));
        }
    }
}
