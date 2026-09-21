//! Local synthetic lineage only. Never reads a production key or state store.
use layrs_direct_execution_v1::{DirectAction,DirectRequest,DirectRuntime,FilesystemImmutableArtifactStore,
  RuntimeMode,SealedEpoch,identity_commitment_for,request_hash};
use std::{env,path::PathBuf};
fn main()->Result<(),Box<dyn std::error::Error>>{
 let args:Vec<String>=env::args().collect();if args.len()!=4{return Err("epoch path, isolated fixture directory, pending|drained required".into());}
 let root=PathBuf::from(&args[2]);if !root.starts_with(env::temp_dir())||root.file_name().and_then(|n|n.to_str()).map_or(true,|n|!n.starts_with("layrs-quest-fallback-"))
   ||!root.is_dir()||std::fs::read_dir(&root)?.next().is_some(){return Err("new empty isolated temporary directory required".into());}
 let mut store=FilesystemImmutableArtifactStore::new(root.join("artifacts"));
 let mut runtime=DirectRuntime::new(SealedEpoch::load(&args[1])?,RuntimeMode::IsolatedTest,vec![7;32])?;
 let (account,wallet)=("a".repeat(64),"0x1111111111111111111111111111111111111111".to_string());
 let identity=identity_commitment_for(&account,&wallet);
 let command=|id:&str,action:DirectAction,financial:Option<String>|{let mut request=DirectRequest{account_id:account.clone(),identity_commitment:identity.clone(),
   request_id:id.into(),request_hash:String::new(),financial_wallet_address:financial,action};request.request_hash=request_hash(&request);request};
 runtime.execute_committed(command("fixture-admission",DirectAction::AdmitIdentity{wallet_address:wallet.clone()},None),&[8;32],&mut store)?;
 runtime.execute_committed(command("fixture-credit",DirectAction::CreditHorizenUsdcDeposit{amount_atomic:"5000000".into(),
   custody_reference:format!("horizen-usdc-deposit:0x{}","ab".repeat(32))},Some(wallet.clone())),&[8;32],&mut store)?;
 let replacement="0x2222222222222222222222222222222222222222".to_string();
 runtime.execute_committed(command("fixture-link",DirectAction::LinkFinancialWallet{wallet_address:replacement},None),&[8;32],&mut store)?;
 let id="11111111-2222-4333-8444-555555555555";
 runtime.execute_committed(command(id,DirectAction::BeginUsdcBusWithdrawal{withdrawal_id:id.into(),destination_chain:"arbitrum".into(),asset:"USDC".into(),destination:wallet.clone(),amount_atomic:"4840000".into()},Some(wallet.clone())),&[8;32],&mut store)?;
 if args[3]=="drained"{runtime.execute_committed(command(&format!("usdc-bus-settle:{id}"),DirectAction::SettleUsdcBusWithdrawal{withdrawal_id:id.into(),
   destination_chain:"arbitrum".into(),asset:"USDC".into(),destination:wallet.clone(),amount_atomic:"4840000".into(),custody_reference:format!("horizen-usdc-bus:0x{}:0x{}:0x{}:0:1","11".repeat(32),"22".repeat(32),"33".repeat(32))},Some(wallet.clone())),&[8;32],&mut store)?;}
 else if args[3]!="pending"{return Err("invalid fixture mode".into());}
 let manifest=serde_json::json!({"stateHash":runtime.committed_state_hash(),"sequence":runtime.committed_sequence(),"account":account,"identity":identity,
   "available":runtime.balance(&identity,"USDC","USER_AVAILABLE").to_string(),"hold":runtime.balance(&identity,"USDC","USER_WITHDRAWAL_HOLD").to_string(),
   "settled":runtime.balance(&identity,"USDC","USER_SETTLED").to_string(),"portfolio":runtime.portfolio(&identity)?});
 std::fs::write(root.join("manifest.json"),serde_json::to_vec_pretty(&manifest)?)?;
 println!("synthetic {} fixture committed at sequence {}",args[3],runtime.committed_sequence());Ok(())
}
