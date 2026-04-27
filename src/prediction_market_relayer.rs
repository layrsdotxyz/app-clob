/// Prediction market on-chain relayer — EVM edition.
///
/// Encodes and submits calls to `PredictionMarketTreasury.sol` on Horizen EVM.
/// Proof format: UltraHonk flat `bytes` proof + `bytes32[]` public inputs.
use std::sync::Arc;

use ethers::{
    abi::{encode, Token},
    types::{Address, Bytes, U256},
};
use tracing::info;

use crate::{
    error::{ClobError, ClobResult},
    evm_relayer::EvmRelayer,
    proof_generation::HonkProof,
};

pub struct PredictionMarketRelayer {
    relayer: Arc<EvmRelayer>,
    /// Default PM USDC treasury address.
    treasury_addr: Address,
}

impl PredictionMarketRelayer {
    pub fn from_env(_treasury_address: Option<String>) -> Option<Self> {
        let relayer = EvmRelayer::from_env()?;
        let treasury_addr = relayer.treasury_address()?;
        Some(Self {
            relayer: Arc::new(relayer),
            treasury_addr,
        })
    }

    pub fn treasury_address(&self) -> String {
        format!("{:?}", self.treasury_addr)
    }

    /// Resolve the effective treasury address to use for a call.
    ///
    /// 1. If `override_addr` is a non-empty, valid EVM address, use it.
    /// 2. Otherwise fall back to `self.treasury_addr` (from env).
    fn effective_treasury(&self, override_addr: Option<&str>) -> ClobResult<Address> {
        if let Some(addr_str) = override_addr.filter(|s| !s.trim().is_empty()) {
            addr_str
                .trim()
                .parse::<Address>()
                .map_err(|e| ClobError::Internal(format!("invalid treasury override '{}': {}", addr_str, e)))
        } else {
            Ok(self.treasury_addr)
        }
    }

    // ─── lockCollateral(bytes32 orderCommitment, uint256 requiredAmount,
    //                   uint64 lockExpiryTs,
    //                   bytes proof, bytes32[6] inputs)
    //
    // `vault_address_override`: if non-empty, route to this vault instead of the
    // default one from env. Pass `None` or `Some("")` to use the default.
    pub async fn lock_collateral(
        &self,
        order_commitment: [u8; 32],
        required_amount: U256,
        lock_expiry_ts: u64,
        proof: &HonkProof,
        vault_address_override: Option<&str>,
    ) -> ClobResult<String> {
        let vault = self.effective_treasury(vault_address_override)?;
        let selector = &ethers::utils::keccak256(
            b"lockCollateral(bytes32,uint256,uint64,bytes,bytes32[6])",
        )[..4];

        let tokens = encode_lock_collateral(order_commitment, required_amount, lock_expiry_ts, proof)?;
        let data = Bytes::from([selector, &encode(&tokens)].concat());
        info!(vault = ?vault, "lockCollateral → sending tx");
        self.relayer.send_tx(vault, data).await
    }

    // ─── unlockCollateral(bytes32 noteNullifier, bytes32 orderCommitment)
    //
    // `vault_address_override`: if non-empty, route to this vault instead of default.
    pub async fn unlock_collateral(
        &self,
        note_nullifier: [u8; 32],
        order_commitment: [u8; 32],
        vault_address_override: Option<&str>,
    ) -> ClobResult<String> {
        let vault = self.effective_treasury(vault_address_override)?;
        let selector = &ethers::utils::keccak256(b"unlockCollateral(bytes32,bytes32)")[..4];
        let tokens = vec![
            Token::FixedBytes(note_nullifier.to_vec()),
            Token::FixedBytes(order_commitment.to_vec()),
        ];
        let data = Bytes::from([selector, &encode(&tokens)].concat());
        info!(vault = ?vault, "unlockCollateral → sending tx");
        self.relayer.send_tx(vault, data).await
    }

    // ─── settleFill(uint64 marketId, bool positionSide, bytes32 spentNullifier,
    //               uint128 potContribution, uint128 positionPayoutUnits,
    //               uint128 tradeFeeAmount,
    //               bytes proof, bytes32[4] inputs)
    //
    // `vault_address_override`: read from the order's compatibility field.
    // Falls back to the configured PM treasury if empty.
    pub async fn settle_fill(
        &self,
        market_id: u64,
        position_side: bool,
        spent_nullifier: [u8; 32],
        pot_contribution: u128,
        position_payout_units: u128,
        trade_fee_amount: u128,
        proof: &HonkProof,
        vault_address_override: Option<&str>,
    ) -> ClobResult<String> {
        let vault = self.effective_treasury(vault_address_override)?;
        let selector = &ethers::utils::keccak256(
            b"settleFill(uint64,bool,bytes32,uint128,uint128,uint128,bytes,bytes32[4])",
        )[..4];

        let tokens = encode_settle_fill(
            market_id,
            position_side,
            spent_nullifier,
            pot_contribution,
            position_payout_units,
            trade_fee_amount,
            proof,
        )?;
        let data = Bytes::from([selector, &encode(&tokens)].concat());
        info!(
            vault = ?vault,
            market_id,
            side = position_side,
            "settleFill → sending tx"
        );
        self.relayer.send_tx(vault, data).await
    }

    // ─── claimWinnings(address recipient,
    //                   bytes proof, bytes32[7] inputs)
    //
    // `vault_address_override`: read from the claim request body.
    // Falls back to the configured PM treasury if empty.
    pub async fn claim_winnings(
        &self,
        recipient: Address,
        proof: &HonkProof,
        vault_address_override: Option<&str>,
    ) -> ClobResult<String> {
        let vault = self.effective_treasury(vault_address_override)?;
        let selector = &ethers::utils::keccak256(
            b"claimWinnings(address,bytes,bytes32[7])",
        )[..4];

        let tokens = encode_claim_winnings(recipient, proof)?;
        let data = Bytes::from([selector, &encode(&tokens)].concat());
        info!(vault = ?vault, %recipient, "claimWinnings → sending tx");
        self.relayer.send_tx(vault, data).await
    }
}

// ─── ABI encoding helpers ──────────────────────────────────────────────────

/// Decode a `0x`-prefixed hex proof string into raw bytes.
fn decode_proof_hex(hex: &str) -> ClobResult<Vec<u8>> {
    let stripped = hex
        .strip_prefix("0x")
        .or_else(|| hex.strip_prefix("0X"))
        .ok_or_else(|| ClobError::Internal("proof_hex must be 0x-prefixed".to_string()))?;
    hex::decode(stripped)
        .map_err(|e| ClobError::Internal(format!("invalid proof_hex: {}", e)))
}

/// Decode a `0x`-prefixed 32-byte hex string into `[u8; 32]`.
pub fn decode_bytes32_pub(s: &str, label: &str) -> ClobResult<[u8; 32]> {
    decode_bytes32(s, label)
}

fn decode_bytes32(s: &str, label: &str) -> ClobResult<[u8; 32]> {
    let stripped = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .ok_or_else(|| ClobError::Internal(format!("{label} must be 0x-prefixed")))?;
    let bytes = hex::decode(stripped)
        .map_err(|e| ClobError::Internal(format!("{label} invalid hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(ClobError::Internal(format!(
            "{label} must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Encode a `HonkProof` as `(bytes proof, bytes32[N] inputs)` ABI tokens.
/// The fixed-array size N must match the number of public inputs in the proof.
fn honk_tokens(proof: &HonkProof) -> ClobResult<(Token, Token)> {
    let proof_bytes = decode_proof_hex(&proof.proof_hex)?;
    let input_tokens: ClobResult<Vec<Token>> = proof
        .public_inputs
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let b32 = decode_bytes32(s, &format!("public_inputs[{}]", i))?;
            Ok(Token::FixedBytes(b32.to_vec()))
        })
        .collect();
    Ok((
        Token::Bytes(proof_bytes),
        Token::FixedArray(input_tokens?),
    ))
}

fn encode_lock_collateral(
    order_commitment: [u8; 32],
    required_amount: U256,
    lock_expiry_ts: u64,
    proof: &HonkProof,
) -> ClobResult<Vec<Token>> {
    let (proof_token, inputs_token) = honk_tokens(proof)?;
    Ok(vec![
        Token::FixedBytes(order_commitment.to_vec()),
        Token::Uint(required_amount),
        Token::Uint(U256::from(lock_expiry_ts)),
        proof_token,
        inputs_token,
    ])
}

fn encode_settle_fill(
    market_id: u64,
    position_side: bool,
    spent_nullifier: [u8; 32],
    pot_contribution: u128,
    position_payout_units: u128,
    trade_fee_amount: u128,
    proof: &HonkProof,
) -> ClobResult<Vec<Token>> {
    let (proof_token, inputs_token) = honk_tokens(proof)?;
    Ok(vec![
        Token::Uint(U256::from(market_id)),
        Token::Bool(position_side),
        Token::FixedBytes(spent_nullifier.to_vec()),
        Token::Uint(U256::from(pot_contribution)),
        Token::Uint(U256::from(position_payout_units)),
        Token::Uint(U256::from(trade_fee_amount)),
        proof_token,
        inputs_token,
    ])
}

fn encode_claim_winnings(recipient: Address, proof: &HonkProof) -> ClobResult<Vec<Token>> {
    let (proof_token, inputs_token) = honk_tokens(proof)?;
    Ok(vec![
        Token::Address(recipient),
        proof_token,
        inputs_token,
    ])
}
