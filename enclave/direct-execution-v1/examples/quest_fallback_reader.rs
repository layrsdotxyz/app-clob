//! Run against the exact previous source baseline, not just the upgraded core.
use layrs_direct_execution_v1::{DirectRuntime,FilesystemImmutableArtifactStore,RuntimeMode,SealedEpoch};
use std::{env,path::PathBuf};
fn main()->Result<(),Box<dyn std::error::Error>>{
 let args:Vec<String>=env::args().collect();if args.len()!=3{return Err("epoch path and synthetic fixture required".into());}
 let root=PathBuf::from(&args[2]);if !root.starts_with(env::temp_dir())||root.file_name().and_then(|n|n.to_str()).map_or(true,|n|!n.starts_with("layrs-quest-fallback-")){
   return Err("isolated fixture only".into());}
 let expected:serde_json::Value=serde_json::from_slice(&std::fs::read(root.join("manifest.json"))?)?;
 let runtime=DirectRuntime::restore_committed(SealedEpoch::load(&args[1])?,RuntimeMode::IsolatedTest,vec![7;32],&[8;32],&FilesystemImmutableArtifactStore::new(root.join("artifacts")))?;
 let identity=expected["identity"].as_str().ok_or("fixture identity missing")?;
 if runtime.committed_state_hash()!=expected["stateHash"].as_str().ok_or("fixture hash missing")?
   ||runtime.committed_sequence()!=expected["sequence"].as_u64().ok_or("fixture sequence missing")?
   ||!runtime.owns(expected["account"].as_str().ok_or("fixture owner missing")?,identity)
   ||serde_json::to_value(runtime.portfolio(identity)?)?!=expected["portfolio"]{return Err("previous core changed current lineage/account/portfolio".into());}
 for (bucket,key) in [("USER_AVAILABLE","available"),("USER_WITHDRAWAL_HOLD","hold"),("USER_SETTLED","settled")]{
   if runtime.balance(identity,"USDC",bucket).to_string()!=expected[key].as_str().ok_or("fixture balance missing")?{return Err("previous core changed a balance".into());}}
 if runtime.balance(identity,"USDC","USER_WITHDRAWAL_HOLD")!=0{return Err("FALLBACK_DENIED_ACTIVE_BUS_HOLD".into());}
 println!("previous core restores complete drained lineage, canonical account and exact portfolio without resetting opening state");Ok(())
}
