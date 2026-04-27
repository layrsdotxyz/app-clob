// Wallet registration for Layrs EVM users.
//
// Auth flow:
//   1. User connects via Dynamic.xyz (isConnected state — no JWT session required).
//   2. Dynamic exposes primaryWallet.address — the user's EVM address.
//   3. The frontend sends that address as both X-Wallet-Address header and user_id.
//   4. The CLOB uses the EVM address as the canonical user identity throughout.
//
// This endpoint is used by operator tooling / future AA upgrades. The frontend
// does not call it — orders are placed directly with the EVM address as user_id.
//
// Deposits:
//   Users deposit ETH / USDC / ZEN directly to the relevant PredictionMarketTreasury
//   contract on Horizen EVM from their connected wallet.
//   ZK deposit proofs are generated client-side (browser) or by the vault-service.

use axum::{
    extract::{Path, State},
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{
    error::{ClobError, ClobResult},
    AppState,
};

#[derive(Debug, Deserialize)]
pub struct RegisterWalletRequest {
    /// User ID — in practice the EVM wallet address (Dynamic isConnected flow).
    pub user_id: String,
    /// User's EVM address (checksummed, 0x-prefixed, 42 chars).
    pub evm_address: String,
    /// Auth provider: "email" | "google" | "twitter" | "discord" | "wallet" | etc.
    pub auth_provider: Option<String>,
    /// ZeroDev smart account address (may differ from evm_address if using AA).
    /// If provided, this is the address that owns on-chain positions.
    pub smart_account_address: Option<String>,
    /// Chain ID the user registered on (default: 1663 = Horizen Gobi testnet).
    pub chain_id: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct RegisterWalletResponse {
    pub success: bool,
    pub user_id: String,
    /// The signer address (Privy embedded wallet or external wallet).
    pub evm_address: String,
    /// The effective on-chain address for deposits and positions.
    /// This is the ZeroDev smart account if AA is used, otherwise evm_address.
    pub account_address: String,
    /// The treasury deposit instruction for this user.
    pub deposit_instruction: DepositInstruction,
}

#[derive(Debug, Serialize)]
pub struct DepositInstruction {
    pub message: String,
    /// EVM address of the PredictionMarketTreasury for USDC (on Horizen).
    pub usdc_vault: String,
    /// EVM address of PrivacyVaultWeth (on Horizen).
    pub eth_vault: String,
    /// EVM address of the active ZEN vault (on Horizen).
    pub zen_vault: String,
    /// Chain ID to deposit on.
    pub chain_id: u64,
    pub chain_name: String,
}

/// Register an EVM wallet address for a user.
/// Called after Privy authentication and ZeroDev smart account creation.
pub async fn register_wallet(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterWalletRequest>,
) -> ClobResult<Json<RegisterWalletResponse>> {
    // Validate EVM address format (0x + 40 hex chars)
    if !req.evm_address.starts_with("0x") || req.evm_address.len() != 42 {
        return Err(ClobError::InvalidOrder(
            "Invalid EVM address (expected 0x-prefixed 42-char checksummed address)".into(),
        ));
    }

    // The effective on-chain account — smart account if AA, otherwise EOA
    let account_address = req
        .smart_account_address
        .clone()
        .filter(|a| a.starts_with("0x") && a.len() == 42)
        .unwrap_or_else(|| req.evm_address.clone());

    let wallet_key = format!("wallet:user:{}", req.user_id);

    // Return existing registration without error (idempotent)
    if let Ok(existing) = state.redis_store.get(&wallet_key).await {
        if !existing.is_empty() {
            tracing::info!(user_id = %req.user_id, address = %existing, "User already registered");
            return Ok(Json(RegisterWalletResponse {
                success: true,
                user_id: req.user_id,
                evm_address: existing.clone(),
                account_address: existing,
                deposit_instruction: build_deposit_instruction(),
            }));
        }
    }

    // Persist forward and reverse mappings
    state.redis_store.set(&wallet_key, &account_address).await?;
    state
        .redis_store
        .set(&format!("wallet:address:{}", account_address), &req.user_id)
        .await?;
    // Also map the signer address (EOA) to the user in case it differs from the AA address
    if account_address != req.evm_address {
        state
            .redis_store
            .set(&format!("wallet:signer:{}", req.evm_address), &req.user_id)
            .await?;
    }

    if let Some(provider) = &req.auth_provider {
        let _ = state
            .redis_store
            .set(&format!("wallet:auth_provider:{}", req.user_id), provider)
            .await;
    }

    let chain_id = req.chain_id.unwrap_or(1663);
    let _ = state
        .redis_store
        .set(
            &format!("wallet:chain_id:{}", req.user_id),
            &chain_id.to_string(),
        )
        .await;

    tracing::info!(
        user_id = %req.user_id,
        evm_address = %req.evm_address,
        account_address = %account_address,
        chain_id,
        "EVM wallet registered (Privy + ZeroDev)"
    );

    Ok(Json(RegisterWalletResponse {
        success: true,
        user_id: req.user_id,
        evm_address: req.evm_address,
        account_address,
        deposit_instruction: build_deposit_instruction(),
    }))
}

fn build_deposit_instruction() -> DepositInstruction {
    let usdc_vault = first_env(&[
        "PM_USDC_TREASURY_ADDRESS",
        "PREDICTION_MARKET_TREASURY_ADDRESS",
        "PM_TREASURY_ADDRESS",
        "PM_USDC_VAULT_ADDRESS",
        "USDC_VAULT_ADDRESS",
        "PREDICTION_MARKET_VAULT_ADDRESS",
        "PM_VAULT_ADDRESS",
    ]);
    let eth_vault = first_env(&[
        "PRIVACY_WETH_VAULT_ADDRESS",
        "WETH_VAULT_ADDRESS",
        "ETH_VAULT_ADDRESS",
        "LP_VAULT_ADDRESS",
    ]);
    let zen_vault = first_env(&[
        "PRIVACY_ZEN_VAULT_ADDRESS",
        "PM_ZEN_TREASURY_ADDRESS",
        "ZEN_PM_TREASURY_ADDRESS",
        "ZEN_TREASURY_ADDRESS",
        "PM_ZEN_VAULT_ADDRESS",
        "ZEN_PM_VAULT_ADDRESS",
        "ZEN_VAULT_ADDRESS",
    ]);
    let chain_id: u64 = std::env::var("EVM_CHAIN_ID")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1663);

    DepositInstruction {
        message: "Deposit USDC and ZEN to the configured market/privacy vaults, and deposit WETH only to PrivacyVaultWeth on Horizen. \
                  The Layrs backend will generate your ZK deposit proof automatically."
            .into(),
        usdc_vault,
        eth_vault,
        zen_vault,
        chain_id,
        chain_name: if chain_id == 1663 { "Horizen Gobi Testnet".into() } else { "Horizen EON".into() },
    }
}

fn first_env(names: &[&str]) -> String {
    names
        .iter()
        .find_map(|name| std::env::var(name).ok())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "0x (not deployed)".into())
}

/// Deploy ZeroDev smart account — returns the counterfactual smart account address.
/// The smart account is deployed lazily on first transaction (ERC-4337 standard).
#[derive(Debug, Deserialize)]
pub struct DeploySmartAccountRequest {
    pub user_id: String,
    /// The signer address (Privy embedded wallet EOA).
    pub signer_address: String,
}

#[derive(Debug, Serialize)]
pub struct DeploySmartAccountResponse {
    pub success: bool,
    /// Counterfactual smart account address (deployed lazily on first tx).
    pub smart_account_address: String,
    pub message: String,
}

pub async fn deploy_smart_account(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DeploySmartAccountRequest>,
) -> ClobResult<Json<DeploySmartAccountResponse>> {
    // In a full implementation this would call ZeroDev's API to get the
    // counterfactual smart account address for the signer.
    // For now we return a placeholder — the frontend handles this via @zerodev/sdk.
    let wallet_key = format!("wallet:user:{}", req.user_id);
    let existing_account = state.redis_store.get(&wallet_key).await.unwrap_or_default();

    tracing::info!(
        user_id = %req.user_id,
        signer = %req.signer_address,
        existing_account = %existing_account,
        "deploy_smart_account: smart account deployment is handled client-side via ZeroDev SDK"
    );

    Ok(Json(DeploySmartAccountResponse {
        success: true,
        smart_account_address: if existing_account.is_empty() {
            req.signer_address
        } else {
            existing_account
        },
        message: "Smart account deployment is handled client-side via @zerodev/sdk. \
                  Call /wallet/register with the smart_account_address once obtained."
            .into(),
    }))
}

/// Get wallet info for a user — balances in each vault.
#[derive(Debug, Serialize)]
pub struct WalletInfoResponse {
    pub account_address: String,
    pub auth_provider: String,
    pub chain_id: u64,
    /// Off-chain CLOB balance (unshielded, for UI display).
    pub balance_usdc: String,
    pub balance_eth: String,
    pub balance_zen: String,
}

pub async fn get_wallet_info(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<String>,
) -> ClobResult<Json<WalletInfoResponse>> {
    let wallet_key = format!("wallet:user:{}", user_id);
    let account_address = state.redis_store.get(&wallet_key).await.unwrap_or_default();

    if account_address.is_empty() {
        return Err(ClobError::OrderNotFound(format!(
            "No wallet registered for user {}. Call POST /wallet/register first.",
            user_id
        )));
    }

    let auth_provider = state
        .redis_store
        .get(&format!("wallet:auth_provider:{}", user_id))
        .await
        .unwrap_or_else(|_| "unknown".into());

    let chain_id: u64 = state
        .redis_store
        .get(&format!("wallet:chain_id:{}", user_id))
        .await
        .unwrap_or_default()
        .parse()
        .unwrap_or(1663);

    let balance_usdc = state
        .redis_store
        .get(&format!("balance:{}:USDC", account_address))
        .await
        .unwrap_or_else(|_| "0".into());

    let balance_eth = state
        .redis_store
        .get(&format!("balance:{}:ETH", account_address))
        .await
        .unwrap_or_else(|_| "0".into());

    let balance_zen = state
        .redis_store
        .get(&format!("balance:{}:ZEN", account_address))
        .await
        .unwrap_or_else(|_| "0".into());

    Ok(Json(WalletInfoResponse {
        account_address,
        auth_provider,
        chain_id,
        balance_usdc,
        balance_eth,
        balance_zen,
    }))
}
