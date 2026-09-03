//! Minimal Polymarket CLOB v2 client for the Nitro enclave.
//!
//! TLS terminates in this module. The parent only relays opaque TLS records through a fixed
//! VSOCK capability and cannot choose a destination or inspect credentials, orders, or replies.

use std::str::FromStr;
use std::{collections::BTreeMap, sync::Arc, time::Duration};

use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE},
    Engine,
};
use ethers_core::{
    abi::{encode, Token},
    types::{
        transaction::{
            eip2718::TypedTransaction,
            eip712::{Eip712, TypedData},
        },
        Address, Bytes, TransactionRequest, U256,
    },
    utils::keccak256,
};
use ethers_signers::{LocalWallet, Signer};
use hmac::{Hmac, Mac};
use rust_decimal::{prelude::ToPrimitive, Decimal};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};
use tokio_rustls::{
    rustls::{pki_types::ServerName, ClientConfig, RootCertStore},
    TlsConnector,
};
use tokio_vsock::{VsockAddr, VsockStream, VMADDR_CID_HOST};
use zeroize::{Zeroize, ZeroizeOnDrop};

const EGRESS_PORT: u32 = 5_004;
const EGRESS_PREFACE: &[u8] = b"LAYRS_EGRESS_V1\n";
const POLYMARKET_SELECTOR: u8 = 1;
const HOST: &str = "clob.polymarket.com";
const MAX_RESPONSE_BYTES: u64 = 2 * 1_048_576;
const ZERO_ADDRESS: &str = "0x0000000000000000000000000000000000000000";
const EXCHANGE: &str = "0x4bFb41d5B3570DeFd03C39a9A4D8dE6Bd8B8982E";
const NEG_RISK_EXCHANGE: &str = "0xC5d563A36AE78145C45a50134d48A1215220f80a";
const CTF_COLLATERAL_ADAPTER: &str = "0xAdA100Db00Ca00073811820692005400218FcE1f";
const PUSD: &str = "0xC011a7E12a19f7B1f670d46F03B03f3342E82DFB";

#[derive(Debug, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PolymarketSecretBundle {
    pub eoa_private_key_hex: String,
    pub api_key: String,
    pub api_secret_base64: String,
    pub api_passphrase: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VenueSide {
    Buy,
    Sell,
}

#[derive(Debug, Clone)]
pub struct VenueOrderIntent {
    pub token_id: String,
    pub side: VenueSide,
    pub quantity_atomic: u128,
    pub limit_price_micros: u64,
    pub fee_rate_bps: u64,
    pub negative_risk: bool,
    pub order_salt: u64,
}

#[derive(Debug, Clone)]
pub struct PreparedPolymarketOrder {
    pub deterministic_order_id: String,
    pub exact_request_body: String,
    pub request_body_sha256: [u8; 32],
    pub credential_generation_sha256: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct VenueRedemptionTransactionIntent {
    pub condition_id: String,
    pub up_outcome_index: u8,
    pub down_outcome_index: u8,
    pub nonce: u64,
    pub gas_limit: u64,
    pub gas_price_wei: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SignedVenueRedemptionTransaction {
    pub raw_transaction: String,
    pub transaction_hash: String,
    pub signer_address: String,
    pub nonce: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SignedOrder {
    salt: u64,
    maker: String,
    signer: String,
    taker: &'static str,
    token_id: String,
    maker_amount: String,
    taker_amount: String,
    expiration: &'static str,
    nonce: &'static str,
    fee_rate_bps: String,
    side: &'static str,
    signature_type: u8,
    signature: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PostOrder<'a> {
    order: &'a SignedOrder,
    owner: &'a str,
    order_type: &'static str,
    defer_exec: bool,
    post_only: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolymarketOrderResponse {
    pub success: bool,
    #[serde(default)]
    pub error_msg: String,
    #[serde(rename = "orderID")]
    pub order_id: String,
    #[serde(default)]
    pub transactions_hashes: Vec<String>,
    pub status: String,
    pub taking_amount: String,
    pub making_amount: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VenueConfirmation {
    Pending,
    Confirmed {
        fill_price_micros: u64,
        evidence_hash: [u8; 32],
    },
    Rejected {
        failure_code: String,
        evidence_hash: [u8; 32],
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VenueOrderObservation {
    Found,
    AuthoritativelyAbsent,
}

#[derive(Debug, Deserialize, Serialize)]
struct OpenOrder {
    id: String,
    status: String,
    original_size: String,
    size_matched: String,
    price: String,
    #[serde(default)]
    associate_trades: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct TradeRecord {
    id: String,
    status: String,
    size: String,
    price: String,
    #[serde(default)]
    transaction_hash: String,
}

pub struct EnclavePolymarketClient {
    secrets: PolymarketSecretBundle,
    wallet: LocalWallet,
}

impl EnclavePolymarketClient {
    pub fn new(secrets: PolymarketSecretBundle) -> Result<Self, String> {
        if !secrets.api_key.is_ascii()
            || secrets.api_key.is_empty()
            || secrets.api_passphrase.is_empty()
            || decode_hmac_secret(&secrets.api_secret_base64).is_err()
        {
            return Err("invalid Polymarket API credentials".into());
        }
        let wallet = secrets
            .eoa_private_key_hex
            .parse::<LocalWallet>()
            .map_err(|_| "invalid Polymarket EOA key")?
            .with_chain_id(137u64);
        Ok(Self { secrets, wallet })
    }

    pub async fn submit_fok(
        &self,
        intent: &VenueOrderIntent,
        timestamp_seconds: u64,
    ) -> Result<(PolymarketOrderResponse, [u8; 32]), String> {
        let prepared = self.prepare_fok(intent).await?;
        self.submit_prepared_fok(&prepared, timestamp_seconds).await
    }

    pub async fn prepare_fok(
        &self,
        intent: &VenueOrderIntent,
    ) -> Result<PreparedPolymarketOrder, String> {
        validate_intent(intent)?;
        let (order, deterministic_order_id) = build_signed_order(&self.wallet, intent).await?;
        let body = serde_json::to_string(&PostOrder {
            order: &order,
            owner: &self.secrets.api_key,
            order_type: "FOK",
            defer_exec: false,
            post_only: false,
        })
        .map_err(|_| "cannot encode Polymarket order")?;
        let credential_generation_sha256 = Sha256::digest(
            [
                b"layrs.polymarket-credential-generation.v1\0".as_slice(),
                format!("{:#x}", self.wallet.address()).as_bytes(),
                self.secrets.api_key.as_bytes(),
            ]
            .concat(),
        )
        .into();
        Ok(PreparedPolymarketOrder {
            deterministic_order_id,
            request_body_sha256: Sha256::digest(body.as_bytes()).into(),
            exact_request_body: body,
            credential_generation_sha256,
        })
    }

    pub async fn submit_prepared_fok(
        &self,
        prepared: &PreparedPolymarketOrder,
        timestamp_seconds: u64,
    ) -> Result<(PolymarketOrderResponse, [u8; 32]), String> {
        if Sha256::digest(prepared.exact_request_body.as_bytes()).as_slice()
            != prepared.request_body_sha256
        {
            return Err("prepared Polymarket body mismatch".into());
        }
        let current_generation: [u8; 32] = Sha256::digest(
            [
                b"layrs.polymarket-credential-generation.v1\0".as_slice(),
                format!("{:#x}", self.wallet.address()).as_bytes(),
                self.secrets.api_key.as_bytes(),
            ]
            .concat(),
        )
        .into();
        if current_generation != prepared.credential_generation_sha256 {
            return Err("POLYMARKET_CREDENTIAL_GENERATION_CHANGED".into());
        }
        // A pre-attempt lookup may prove that the deterministic signed order
        // already exists. Any non-404 lookup error is UNKNOWN and forbids POST.
        let path = format!("/data/order/{}", prepared.deterministic_order_id);
        let lookup_headers = authenticated_headers(
            &self.wallet,
            &self.secrets,
            timestamp_seconds,
            "GET",
            &path,
            None,
        )?;
        let lookup = request("GET", &path, &lookup_headers, None).await?;
        if (200..300).contains(&lookup.status) {
            let parsed: OpenOrder = serde_json::from_slice(&lookup.body)
                .map_err(|_| "invalid existing Polymarket order".to_string())?;
            if parsed.id != prepared.deterministic_order_id {
                return Err("Polymarket deterministic order identity mismatch".into());
            }
            let order_id = parsed.id.clone();
            return Ok((
                PolymarketOrderResponse {
                    success: true,
                    error_msg: String::new(),
                    order_id: order_id.clone(),
                    transactions_hashes: Vec::new(),
                    status: parsed.status,
                    taking_amount: parsed.size_matched,
                    making_amount: parsed.original_size,
                },
                Sha256::digest(order_id.as_bytes()).into(),
            ));
        }
        if lookup.status != 404 {
            return Err("POLYMARKET_ORDER_LOOKUP_UNKNOWN".into());
        }
        let headers = authenticated_headers(
            &self.wallet,
            &self.secrets,
            timestamp_seconds,
            "POST",
            "/order",
            Some(&prepared.exact_request_body),
        )?;
        let response = match request(
            "POST",
            "/order",
            &headers,
            Some(&prepared.exact_request_body),
        )
        .await
        {
            Ok(response) => response,
            Err(_) => {
                // Never blindly resend after an ambiguous network outcome. A
                // later execution attempt will query the deterministic hash.
                return Err("POLYMARKET_SUBMISSION_OUTCOME_UNKNOWN".into());
            }
        };
        if !(200..300).contains(&response.status) {
            return Err(format!("Polymarket HTTP status {}", response.status));
        }
        let parsed: PolymarketOrderResponse = serde_json::from_slice(&response.body)
            .map_err(|_| "invalid Polymarket order response")?;
        if !parsed.success || parsed.order_id != prepared.deterministic_order_id {
            return Err("Polymarket rejected FOK order".into());
        }
        let commitment = Sha256::digest(parsed.order_id.as_bytes()).into();
        Ok((parsed, commitment))
    }

    pub async fn order_status(
        &self,
        order_id: &str,
        timestamp_seconds: u64,
    ) -> Result<serde_json::Value, String> {
        if order_id.is_empty()
            || order_id.len() > 256
            || !order_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
        {
            return Err("invalid Polymarket order id".into());
        }
        let path = format!("/data/order/{order_id}");
        let headers = authenticated_headers(
            &self.wallet,
            &self.secrets,
            timestamp_seconds,
            "GET",
            &path,
            None,
        )?;
        let response = request("GET", &path, &headers, None).await?;
        if !(200..300).contains(&response.status) {
            return Err(format!("Polymarket HTTP status {}", response.status));
        }
        serde_json::from_slice(&response.body)
            .map_err(|_| "invalid Polymarket status response".into())
    }

    pub async fn observe_order(
        &self,
        order_id: &str,
        timestamp_seconds: u64,
    ) -> Result<VenueOrderObservation, String> {
        if !order_id.starts_with("0x") || order_id.len() != 66 {
            return Err("invalid deterministic Polymarket order id".into());
        }
        let path = format!("/data/order/{order_id}");
        let headers = authenticated_headers(
            &self.wallet,
            &self.secrets,
            timestamp_seconds,
            "GET",
            &path,
            None,
        )?;
        let response = request("GET", &path, &headers, None).await?;
        if response.status == 404 {
            return Ok(VenueOrderObservation::AuthoritativelyAbsent);
        }
        if !(200..300).contains(&response.status) {
            return Err("POLYMARKET_ORDER_LOOKUP_UNKNOWN".into());
        }
        let order: OpenOrder = serde_json::from_slice(&response.body)
            .map_err(|_| "invalid Polymarket order response".to_string())?;
        if order.id != order_id {
            return Err("Polymarket order identity mismatch".into());
        }
        Ok(VenueOrderObservation::Found)
    }

    pub async fn confirmed_fill(
        &self,
        order_id: &str,
        expected_quantity_atomic: u128,
        timestamp_seconds: u64,
    ) -> Result<VenueConfirmation, String> {
        let raw = self.order_status(order_id, timestamp_seconds).await?;
        let order: OpenOrder =
            serde_json::from_value(raw).map_err(|_| "invalid Polymarket open-order response")?;
        if order.id != order_id {
            return Err("Polymarket order identity mismatch".into());
        }
        let status = order.status.to_ascii_uppercase();
        if matches!(
            status.as_str(),
            "CANCELLED" | "CANCELED" | "REJECTED" | "EXPIRED"
        ) {
            let evidence_hash = canonical_evidence_hash(&order, &[])?;
            return Ok(VenueConfirmation::Rejected {
                failure_code: format!("VENUE_{status}"),
                evidence_hash,
            });
        }
        if order.associate_trades.is_empty()
            || decimal_atomic(&order.original_size)? != expected_quantity_atomic
            || decimal_atomic(&order.size_matched)? != expected_quantity_atomic
        {
            return Ok(VenueConfirmation::Pending);
        }

        let mut trades = Vec::new();
        for trade_id in &order.associate_trades {
            validate_query_identifier(trade_id)?;
            let path = format!("/data/trades?id={trade_id}");
            let headers = authenticated_headers(
                &self.wallet,
                &self.secrets,
                timestamp_seconds,
                "GET",
                "/data/trades",
                None,
            )?;
            let response = request("GET", &path, &headers, None).await?;
            if !(200..300).contains(&response.status) {
                return Err(format!("Polymarket HTTP status {}", response.status));
            }
            let value: serde_json::Value = serde_json::from_slice(&response.body)
                .map_err(|_| "invalid Polymarket trade response")?;
            let rows = value
                .as_array()
                .cloned()
                .or_else(|| value.get("data").and_then(|data| data.as_array()).cloned())
                .ok_or_else(|| "invalid Polymarket trade list".to_string())?;
            let trade = rows
                .into_iter()
                .filter_map(|value| serde_json::from_value::<TradeRecord>(value).ok())
                .find(|trade| trade.id == *trade_id)
                .ok_or_else(|| "Polymarket associated trade is missing".to_string())?;
            if !trade.status.eq_ignore_ascii_case("CONFIRMED")
                || !trade.transaction_hash.starts_with("0x")
            {
                return Ok(VenueConfirmation::Pending);
            }
            trades.push(trade);
        }
        trades.sort_by(|left, right| left.id.cmp(&right.id));
        let mut total_quantity = 0u128;
        let mut total_notional = 0u128;
        for trade in &trades {
            let quantity = decimal_atomic(&trade.size)?;
            let price = decimal_micros(&trade.price)?;
            total_quantity = total_quantity
                .checked_add(quantity)
                .ok_or_else(|| "Polymarket fill quantity overflow".to_string())?;
            total_notional = total_notional
                .checked_add(
                    quantity
                        .checked_mul(u128::from(price))
                        .ok_or_else(|| "Polymarket fill notional overflow".to_string())?,
                )
                .ok_or_else(|| "Polymarket fill notional overflow".to_string())?;
        }
        if total_quantity != expected_quantity_atomic {
            return Err("Polymarket FOK quantity mismatch".into());
        }
        let fill_price_micros = (total_notional / total_quantity)
            .try_into()
            .map_err(|_| "Polymarket VWAP overflow")?;
        Ok(VenueConfirmation::Confirmed {
            fill_price_micros,
            evidence_hash: canonical_evidence_hash(&order, &trades)?,
        })
    }

    /// Signs the public Polygon redemption transaction without releasing the venue key. The raw
    /// transaction is safe to persist before broadcast, closing the crash window between signing
    /// and submission. The caller must independently finalize and verify its receipt.
    pub async fn sign_redemption_transaction(
        &self,
        intent: &VenueRedemptionTransactionIntent,
    ) -> Result<SignedVenueRedemptionTransaction, String> {
        if !valid_hex32(&intent.condition_id)
            || intent.up_outcome_index == intent.down_outcome_index
            || intent.gas_limit < 50_000
            || intent.gas_limit > 1_000_000
        {
            return Err("invalid Polymarket redemption intent".into());
        }
        let gas_price =
            U256::from_dec_str(&intent.gas_price_wei).map_err(|_| "invalid Polygon gas price")?;
        if gas_price.is_zero() || gas_price > U256::from(10_000_000_000_000u64) {
            return Err("invalid Polygon gas price".into());
        }
        let condition = hex::decode(&intent.condition_id[2..])
            .map_err(|_| "invalid Polymarket condition id")?;
        let index_sets = vec![
            Token::Uint(U256::one() << usize::from(intent.up_outcome_index)),
            Token::Uint(U256::one() << usize::from(intent.down_outcome_index)),
        ];
        let mut calldata =
            keccak256(b"redeemPositions(address,bytes32,bytes32,uint256[])")[..4].to_vec();
        calldata.extend_from_slice(&encode(&[
            Token::Address(Address::from_str(PUSD).map_err(|_| "invalid pUSD address")?),
            Token::FixedBytes(vec![0u8; 32]),
            Token::FixedBytes(condition),
            Token::Array(index_sets),
        ]));
        let adapter = Address::from_str(CTF_COLLATERAL_ADAPTER)
            .map_err(|_| "invalid CTF collateral adapter address")?;
        let transaction: TypedTransaction = TransactionRequest::new()
            .from(self.wallet.address())
            .to(adapter)
            .nonce(intent.nonce)
            .gas(intent.gas_limit)
            .gas_price(gas_price)
            .data(Bytes::from(calldata))
            .chain_id(137u64)
            .into();
        let signature = self
            .wallet
            .sign_transaction(&transaction)
            .await
            .map_err(|_| "cannot sign Polymarket redemption")?;
        let raw = transaction.rlp_signed(&signature);
        let transaction_hash = keccak256(raw.as_ref());
        Ok(SignedVenueRedemptionTransaction {
            raw_transaction: format!("0x{}", hex::encode(raw)),
            transaction_hash: format!("0x{}", hex::encode(transaction_hash)),
            signer_address: format!("{:#x}", self.wallet.address()),
            nonce: intent.nonce,
        })
    }
}

fn valid_hex32(value: &str) -> bool {
    value.len() == 66
        && value.starts_with("0x")
        && value[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn canonical_evidence_hash(order: &OpenOrder, trades: &[TradeRecord]) -> Result<[u8; 32], String> {
    let bytes =
        serde_json::to_vec(&(order, trades)).map_err(|_| "cannot encode Polymarket evidence")?;
    let mut digest = Sha256::new();
    digest.update(b"layrs.polymarket-confirmation.v1\0");
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
    Ok(digest.finalize().into())
}

fn validate_query_identifier(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
    {
        return Err("invalid Polymarket query identifier".into());
    }
    Ok(())
}

fn decimal_atomic(value: &str) -> Result<u128, String> {
    let scaled = Decimal::from_str(value)
        .map_err(|_| "invalid Polymarket decimal amount")?
        .checked_mul(Decimal::from(1_000_000u64))
        .ok_or_else(|| "Polymarket decimal amount overflow".to_string())?;
    if scaled.fract() != Decimal::ZERO || scaled.is_sign_negative() {
        return Err("non-canonical Polymarket decimal amount".into());
    }
    scaled
        .to_u128()
        .ok_or_else(|| "Polymarket decimal amount overflow".into())
}

fn decimal_micros(value: &str) -> Result<u64, String> {
    let amount = decimal_atomic(value)?;
    if amount == 0 || amount >= 1_000_000 {
        return Err("invalid Polymarket decimal price".into());
    }
    amount
        .try_into()
        .map_err(|_| "Polymarket decimal price overflow".into())
}

fn validate_intent(intent: &VenueOrderIntent) -> Result<(), String> {
    if intent.quantity_atomic == 0
        || intent.limit_price_micros == 0
        || intent.limit_price_micros >= 1_000_000
        || intent.fee_rate_bps > 10_000
        || intent.token_id.is_empty()
        || intent.order_salt == 0
        || intent.order_salt >= (1u64 << 53)
        || intent.token_id.len() > 78
        || !intent.token_id.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("invalid Polymarket order intent".into());
    }
    Ok(())
}

async fn build_signed_order(
    wallet: &LocalWallet,
    intent: &VenueOrderIntent,
) -> Result<(SignedOrder, String), String> {
    let notional = intent
        .quantity_atomic
        .checked_mul(u128::from(intent.limit_price_micros))
        .ok_or_else(|| "Polymarket amount overflow".to_string())?
        / 1_000_000;
    if notional == 0 {
        return Err("Polymarket notional rounds to zero".into());
    }
    let (maker_amount, taker_amount, side_number, side) = match intent.side {
        VenueSide::Buy => (notional, intent.quantity_atomic, 0u8, "BUY"),
        VenueSide::Sell => (intent.quantity_atomic, notional, 1u8, "SELL"),
    };
    let salt = intent.order_salt;
    let maker = format!("{:#x}", wallet.address());
    let exchange = if intent.negative_risk {
        NEG_RISK_EXCHANGE
    } else {
        EXCHANGE
    };
    let typed: TypedData = serde_json::from_value(json!({
        "types": {
            "EIP712Domain": [
                { "name": "name", "type": "string" },
                { "name": "version", "type": "string" },
                { "name": "chainId", "type": "uint256" },
                { "name": "verifyingContract", "type": "address" }
            ],
            "Order": [
                { "name": "salt", "type": "uint256" },
                { "name": "maker", "type": "address" },
                { "name": "signer", "type": "address" },
                { "name": "taker", "type": "address" },
                { "name": "tokenId", "type": "uint256" },
                { "name": "makerAmount", "type": "uint256" },
                { "name": "takerAmount", "type": "uint256" },
                { "name": "expiration", "type": "uint256" },
                { "name": "nonce", "type": "uint256" },
                { "name": "feeRateBps", "type": "uint256" },
                { "name": "side", "type": "uint8" },
                { "name": "signatureType", "type": "uint8" }
            ]
        },
        "primaryType": "Order",
        "domain": {
            "name": "Polymarket CTF Exchange",
            "version": "1",
            "chainId": 137,
            "verifyingContract": exchange
        },
        "message": {
            "salt": salt.to_string(),
            "maker": maker,
            "signer": maker,
            "taker": ZERO_ADDRESS,
            "tokenId": intent.token_id,
            "makerAmount": maker_amount.to_string(),
            "takerAmount": taker_amount.to_string(),
            "expiration": "0",
            "nonce": "0",
            "feeRateBps": intent.fee_rate_bps.to_string(),
            "side": side_number,
            "signatureType": 0
        }
    }))
    .map_err(|_| "cannot construct Polymarket EIP-712 order")?;
    let deterministic_order_id = format!(
        "0x{}",
        hex::encode(
            typed
                .encode_eip712()
                .map_err(|_| "cannot hash Polymarket order")?
        ),
    );
    let signature = wallet
        .sign_typed_data(&typed)
        .await
        .map_err(|_| "cannot sign Polymarket order")?;
    Ok((
        SignedOrder {
            salt,
            maker: maker.clone(),
            signer: maker,
            taker: ZERO_ADDRESS,
            token_id: intent.token_id.clone(),
            maker_amount: maker_amount.to_string(),
            taker_amount: taker_amount.to_string(),
            expiration: "0",
            nonce: "0",
            fee_rate_bps: intent.fee_rate_bps.to_string(),
            side,
            signature_type: 0,
            signature: signature.to_string(),
        },
        deterministic_order_id,
    ))
}

fn authenticated_headers(
    wallet: &LocalWallet,
    secrets: &PolymarketSecretBundle,
    timestamp_seconds: u64,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> Result<BTreeMap<String, String>, String> {
    let mut headers = BTreeMap::new();
    headers.insert("POLY_ADDRESS".into(), format!("{:#x}", wallet.address()));
    headers.insert(
        "POLY_SIGNATURE".into(),
        hmac_signature(
            &secrets.api_secret_base64,
            timestamp_seconds,
            method,
            path,
            body,
        )?,
    );
    headers.insert("POLY_TIMESTAMP".into(), timestamp_seconds.to_string());
    headers.insert("POLY_API_KEY".into(), secrets.api_key.clone());
    headers.insert("POLY_PASSPHRASE".into(), secrets.api_passphrase.clone());
    Ok(headers)
}

pub fn hmac_signature(
    secret_base64: &str,
    timestamp_seconds: u64,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> Result<String, String> {
    let secret = decode_hmac_secret(secret_base64)?;
    let mut message = format!("{timestamp_seconds}{method}{path}");
    if let Some(body) = body {
        message.push_str(body);
    }
    let mut mac =
        Hmac::<Sha256>::new_from_slice(&secret).map_err(|_| "invalid Polymarket HMAC secret")?;
    mac.update(message.as_bytes());
    Ok(URL_SAFE.encode(mac.finalize().into_bytes()))
}

fn decode_hmac_secret(value: &str) -> Result<Vec<u8>, String> {
    let normalized: String = value
        .chars()
        .filter_map(|character| match character {
            '-' => Some('+'),
            '_' => Some('/'),
            value
                if value.is_ascii_alphanumeric()
                    || value == '+'
                    || value == '/'
                    || value == '=' =>
            {
                Some(value)
            }
            _ => None,
        })
        .collect();
    STANDARD
        .decode(&normalized)
        .or_else(|_| STANDARD_NO_PAD.decode(normalized.trim_end_matches('=')))
        .map_err(|_| "invalid Polymarket HMAC secret".into())
}

struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

async fn request(
    method: &str,
    path: &str,
    headers: &BTreeMap<String, String>,
    body: Option<&str>,
) -> Result<HttpResponse, String> {
    let mut vsock = timeout(
        Duration::from_secs(3),
        VsockStream::connect(VsockAddr::new(VMADDR_CID_HOST, EGRESS_PORT)),
    )
    .await
    .map_err(|_| "Polymarket egress VSOCK timeout")?
    .map_err(|_| "Polymarket egress VSOCK unavailable")?;
    vsock
        .write_all(EGRESS_PREFACE)
        .await
        .map_err(|_| "Polymarket egress handshake failed")?;
    vsock
        .write_u8(POLYMARKET_SELECTOR)
        .await
        .map_err(|_| "Polymarket egress handshake failed")?;
    vsock
        .flush()
        .await
        .map_err(|_| "Polymarket egress handshake failed")?;
    if vsock
        .read_u8()
        .await
        .map_err(|_| "Polymarket egress handshake failed")?
        != 0
    {
        return Err("Polymarket egress denied".into());
    }

    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_name =
        ServerName::try_from(HOST.to_owned()).map_err(|_| "invalid Polymarket TLS name")?;
    let mut tls = timeout(
        Duration::from_secs(5),
        TlsConnector::from(Arc::new(tls_config)).connect(server_name, vsock),
    )
    .await
    .map_err(|_| "Polymarket TLS timeout")?
    .map_err(|_| "Polymarket TLS verification failed")?;

    let body = body.unwrap_or_default();
    let mut encoded = format!(
        "{method} {path} HTTP/1.1\r\nHost: {HOST}\r\nUser-Agent: layrsv2-enclave/1\r\nAccept: application/json\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len(),
    );
    for (name, value) in headers {
        if name.contains(['\r', '\n']) || value.contains(['\r', '\n']) {
            return Err("invalid Polymarket HTTP header".into());
        }
        encoded.push_str(name);
        encoded.push_str(": ");
        encoded.push_str(value);
        encoded.push_str("\r\n");
    }
    encoded.push_str("\r\n");
    encoded.push_str(body);
    tls.write_all(encoded.as_bytes())
        .await
        .map_err(|_| "Polymarket request write failed")?;
    tls.flush()
        .await
        .map_err(|_| "Polymarket request write failed")?;
    let mut response = Vec::new();
    timeout(
        Duration::from_secs(15),
        tls.take(MAX_RESPONSE_BYTES + 1).read_to_end(&mut response),
    )
    .await
    .map_err(|_| "Polymarket response timeout")?
    .map_err(|_| "Polymarket response read failed")?;
    if response.len() as u64 > MAX_RESPONSE_BYTES {
        return Err("Polymarket response too large".into());
    }
    parse_http_response(&response)
}

fn parse_http_response(response: &[u8]) -> Result<HttpResponse, String> {
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| "invalid Polymarket HTTP response".to_string())?;
    let head =
        std::str::from_utf8(&response[..split]).map_err(|_| "invalid Polymarket HTTP headers")?;
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| "invalid Polymarket HTTP status".to_string())?;
    let chunked = lines.any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("transfer-encoding")
                && value.to_ascii_lowercase().contains("chunked")
        })
    });
    let raw_body = &response[split + 4..];
    let body = if chunked {
        decode_chunked(raw_body)?
    } else {
        raw_body.to_vec()
    };
    Ok(HttpResponse { status, body })
}

fn decode_chunked(mut input: &[u8]) -> Result<Vec<u8>, String> {
    let mut output = Vec::new();
    loop {
        let line_end = input
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| "invalid chunked response".to_string())?;
        let size_text = std::str::from_utf8(&input[..line_end])
            .map_err(|_| "invalid chunk size")?
            .split(';')
            .next()
            .unwrap_or_default();
        let size = usize::from_str_radix(size_text, 16).map_err(|_| "invalid chunk size")?;
        input = &input[line_end + 2..];
        if size == 0 {
            break;
        }
        if input.len() < size + 2 || &input[size..size + 2] != b"\r\n" {
            return Err("truncated chunked response".into());
        }
        output.extend_from_slice(&input[..size]);
        input = &input[size + 2..];
        if output.len() as u64 > MAX_RESPONSE_BYTES {
            return Err("Polymarket response too large".into());
        }
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_matches_the_official_typescript_client_fixture() {
        let signature = hmac_signature(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            1_000_000,
            "test-sign",
            "/orders",
            Some("{\"hash\": \"0x123\"}"),
        )
        .unwrap();
        assert_eq!(signature, "ZwAdJKvoYRlEKDkNMwd5BuwNNtg93kNaR_oU2HrfVvc=");
    }

    #[test]
    fn parser_decodes_chunked_json_without_trusting_content_length() {
        let parsed = parse_http_response(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\n{\"a\r\n4\r\n\":1}\r\n0\r\n\r\n",
        )
        .unwrap();
        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.body, b"{\"a\":1}");
    }
}
