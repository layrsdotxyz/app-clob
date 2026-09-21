//! Administrative permission is distinct from ordinary worker signing.
//! Grants authorize only adding a funding wallet to the existing identity;
//! they cannot alter balances, transfer custody or create another identity.
use super::*;
use base64::engine::general_purpose::STANDARD;
use p256::{ecdsa::{signature::Verifier,VerifyingKey},pkcs8::DecodePublicKey};

#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub(super) struct WalletLinkGrant {
    pub protocol_version:String,pub app_id:String,pub policy_version:String,
    pub account_id:String,pub identity_commitment:String,pub privy_user_id_hash:String,pub canonical_wallet:String,
    pub wallet_id:String,pub wallet_address:String,pub owner_quorum_id:String,pub policy_id:String,
    pub snapshot_sha256:String,pub request_id:String,pub expires_at_unix:u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture()->(WalletLinkAuthority,WalletLinkGrant,String,SessionClaims) {
        let value:serde_json::Value=serde_json::from_str(include_str!("../fixtures/usdc-wallet-link-node-golden.json")).unwrap();
        let grant:WalletLinkGrant=serde_json::from_value(value["grant"].clone()).unwrap();
        let public=STANDARD.decode(value["publicKeyDerBase64"].as_str().unwrap()).unwrap();
        let authority=WalletLinkAuthority {key:VerifyingKey::from_public_key_der(&public).unwrap(),app_id:grant.app_id.clone()};
        let claims=SessionClaims {session_id:"fixture-session".into(),subject_hash:grant.account_id.clone(),privy_user_id_hash:grant.privy_user_id_hash.clone(),
            audience:"fixture".into(),epoch_id:"fixture-epoch".into(),epoch_state_sha256:"e".repeat(64),wallet_address:grant.canonical_wallet.clone(),
            financial_wallet_address:None,identity_commitment:grant.identity_commitment.clone(),expires_at_unix:1200,response_key:String::new(),signature:String::new()};
        (authority,grant,value["signature"].as_str().unwrap().into(),claims)
    }
    #[test]
    fn node_administrative_signature_links_only_existing_identity() {
        let (authority,grant,signature,claims)=fixture();
        let action=authority.verify(&grant,&signature,&claims,&grant.request_id,1000).unwrap();
        assert!(matches!(action,DirectAction::LinkFinancialWallet {wallet_address} if wallet_address==grant.wallet_address));
    }
    #[test]
    fn administrative_grant_rejects_tampering_rebinding_expiry_and_financial_destination() {
        let (authority,grant,signature,claims)=fixture();
        for field in ["accountId","identityCommitment","privyUserIdHash","canonicalWallet","walletAddress","walletId","ownerQuorumId","policyId","snapshotSha256","appId","protocolVersion","policyVersion","requestId"] {
            let mut value=serde_json::to_value(&grant).unwrap();
            value[field]=serde_json::Value::String(if field.ends_with("Wallet")||field=="walletAddress" {"0x0000000000000000000000000000000000000003".into()} else {"z".repeat(64)});
            let changed:WalletLinkGrant=serde_json::from_value(value).unwrap();
            assert!(authority.verify(&changed,&signature,&claims,&grant.request_id,1000).is_err(),"{field}");
        }
        assert!(authority.verify(&grant,"AAAA",&claims,&grant.request_id,1000).is_err());
        assert!(authority.verify(&grant,&signature,&claims,"wallet-link:wrong",1000).is_err());
        assert!(authority.verify(&grant,&signature,&claims,&grant.request_id,1180).is_err());
        assert!(authority.verify(&grant,&signature,&claims,&grant.request_id,980).is_err());
        let mut financial=claims;financial.financial_wallet_address=Some(grant.wallet_address.clone());
        assert!(authority.verify(&grant,&signature,&financial,&grant.request_id,1000).is_err());
    }
    #[test]
    fn grant_rejects_unknown_financial_fields() {
        let (_,grant,_,_)=fixture();
        let mut value=serde_json::to_value(grant).unwrap();value["amountMicros"]=serde_json::json!(5_000_000);
        assert!(serde_json::from_value::<WalletLinkGrant>(value).is_err());
    }
}
#[derive(Clone)]
pub(super) struct WalletLinkAuthority {key:VerifyingKey,app_id:String}
impl WalletLinkAuthority {
    pub fn from_environment()->Result<Option<Self>,String>{
        if env::var("LAYRS_DIRECT_USDC_CUSTODY_ENABLED").as_deref()!=Ok("true") {return Ok(None);}
        let public=env::var("LAYRS_DIRECT_USDC_ADMIN_PUBLIC_KEY_DER_BASE64").map_err(|_|"USDC link public authority required")?;
        let key=STANDARD.decode(public.trim()).ok().and_then(|der|VerifyingKey::from_public_key_der(&der).ok()).ok_or("USDC link public authority invalid")?;
        let app_id=env::var("LAYRSV2_PRIVY_APP_ID").map_err(|_|"USDC link app binding required")?;
        if app_id.len()<8||app_id.len()>128 {return Err("USDC link app binding invalid".into());}
        Ok(Some(Self {key,app_id}))
    }
    pub fn verify(&self,grant:&WalletLinkGrant,signature:&str,claims:&SessionClaims,request_id:&str,now:u64)->Result<DirectAction,String>{
        let hash=|value:&str|value.len()==64&&value.bytes().all(|byte|byte.is_ascii_digit()||(b'a'..=b'f').contains(&byte));
        let identifier=|value:&str|(12..=64).contains(&value.len())&&value.bytes().all(|byte|byte.is_ascii_alphanumeric());
        let wallet=canonical_evm_address(&grant.wallet_address).map_err(|_|"USDC link wallet invalid")?;
        let canonical=canonical_evm_address(&grant.canonical_wallet).map_err(|_|"USDC link canonical wallet invalid")?;
        let expected_id=format!("wallet-link:{}",sha256(format!("{}:usdc-quest-arb-own-wallet-v1:{}",claims.subject_hash,grant.wallet_id).as_bytes()));
        if grant.protocol_version!="layrs.usdc-wallet-link.v1"||grant.policy_version!="usdc-quest-arb-own-wallet-v1"
            ||grant.app_id!=self.app_id||grant.account_id!=claims.subject_hash||grant.identity_commitment!=claims.identity_commitment
            ||grant.privy_user_id_hash!=claims.privy_user_id_hash||canonical!=claims.wallet_address||canonical!=grant.canonical_wallet
            ||wallet!=grant.wallet_address||wallet=="0x0000000000000000000000000000000000000000"
            ||!hash(&grant.snapshot_sha256)||!identifier(&grant.wallet_id)||!identifier(&grant.owner_quorum_id)||!identifier(&grant.policy_id)
            ||grant.request_id!=request_id||request_id!=expected_id||grant.expires_at_unix<=now||grant.expires_at_unix>now.saturating_add(195)
            ||claims.financial_wallet_address.is_some() {return Err("USDC link binding denied".into());}
        // Flat strings/u64 only, exactly the administrative service's sorted
        // canonical JSON. Unknown fields are denied by deserialization.
        let value=serde_json::to_value(grant).map_err(|_|"USDC link encoding failed")?;
        let fields=value.as_object().ok_or("USDC link encoding failed")?.iter().collect::<BTreeMap<_,_>>();
        let bytes=serde_json::to_vec(&fields).map_err(|_|"USDC link encoding failed")?;
        let signature=STANDARD.decode(signature).ok().and_then(|bytes|Signature::from_der(&bytes).ok()).ok_or("USDC link signature invalid")?;
        self.key.verify(&bytes,&signature).map_err(|_|"USDC link signature denied")?;
        Ok(DirectAction::LinkFinancialWallet {wallet_address:wallet})
    }
}
