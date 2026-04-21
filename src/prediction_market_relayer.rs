/// Prediction market on-chain relayer — EVM edition.
///
/// Encodes and submits calls to `PredictionMarketVault.sol` on Horizen EVM.
/// Proof format: standard Groth16 pA/pB/pC/pubSignals (snarkjs JSON).
use std::sync::Arc;

use ethers::{
    abi::{encode, Token},
    types::{Address, Bytes, U256},
};
use tracing::info;

use crate::{
    error::{ClobError, ClobResult},
    evm_relayer::EvmRelayer,
    proof_generation::EvmGroth16Proof,
};

pub struct PredictionMarketRelayer {
    relayer: Arc<EvmRelayer>,
    /// Default vault address (from PM_VAULT_ADDRESS / PREDICTION_MARKET_VAULT_ADDRESS).
    vault_addr: Address,
}

impl PredictionMarketRelayer {
    pub fn from_env(_vault_address: Option<String>) -> Option<Self> {
        let relayer = EvmRelayer::from_env()?;
        let vault_addr = relayer.vault_address()?;
        Some(Self {
            relayer: Arc::new(relayer),
            vault_addr,
        })
    }

    pub fn vault_address(&self) -> String {
        format!("{:?}", self.vault_addr)
    }

    /// Resolve the effective vault address to use for a call.
    ///
    /// 1. If `override_addr` is a non-empty, valid EVM address, use it.
    /// 2. Otherwise fall back to `self.vault_addr` (from env).
    fn effective_vault(&self, override_addr: Option<&str>) -> ClobResult<Address> {
        if let Some(addr_str) = override_addr.filter(|s| !s.trim().is_empty()) {
            addr_str
                .trim()
                .parse::<Address>()
                .map_err(|e| ClobError::Internal(format!("invalid vault_address '{}': {}", addr_str, e)))
        } else {
            Ok(self.vault_addr)
        }
    }

    // ─── lockCollateral(bytes32 orderCommitment, uint256 requiredAmount,
    //                   uint64 lockExpiryTs,
    //                   uint256[2] pA, uint256[2][2] pB, uint256[2] pC,
    //                   uint256[6] pubSignals)
    //
    // selector: keccak256("lockCollateral(bytes32,uint256,uint64,(uint256[2],uint256[2][2],uint256[2]),uint256[6])")
    //   — we use manual abi::encode here to avoid generating full bindings.
    //
    // `vault_address_override`: if non-empty, route to this vault instead of the
    // default one from env. Pass `None` or `Some("")` to use the default.
    pub async fn lock_collateral(
        &self,
        order_commitment: [u8; 32],
        required_amount: U256,
        lock_expiry_ts: u64,
        proof: &EvmGroth16Proof,
        vault_address_override: Option<&str>,
    ) -> ClobResult<String> {
        let vault = self.effective_vault(vault_address_override)?;
        let selector = &ethers::utils::keccak256(
            b"lockCollateral(bytes32,uint256,uint64,uint256[2],uint256[2][2],uint256[2],uint256[6])",
        )[..4];

        let tokens = encode_lock_collateral(order_commitment, required_amount, lock_expiry_ts, proof);
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
        let vault = self.effective_vault(vault_address_override)?;
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
    //               uint256[2] pA, uint256[2][2] pB, uint256[2] pC,
    //               uint256[5] pubSignals)
    //
    // `vault_address_override`: read from the order's `vault_address` field.
    // Falls back to PM_VAULT_ADDRESS if empty.
    pub async fn settle_fill(
        &self,
        market_id: u64,
        position_side: bool,
        spent_nullifier: [u8; 32],
        pot_contribution: u128,
        position_payout_units: u128,
        trade_fee_amount: u128,
        proof: &EvmGroth16Proof,
        vault_address_override: Option<&str>,
    ) -> ClobResult<String> {
        let vault = self.effective_vault(vault_address_override)?;
        let selector = &ethers::utils::keccak256(
            b"settleFill(uint64,bool,bytes32,uint128,uint128,uint128,uint256[2],uint256[2][2],uint256[2],uint256[5])",
        )[..4];

        let tokens = encode_settle_fill(
            market_id,
            position_side,
            spent_nullifier,
            pot_contribution,
            position_payout_units,
            trade_fee_amount,
            proof,
        );
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
    //                   uint256[2] pA, uint256[2][2] pB, uint256[2] pC,
    //                   uint256[8] pubSignals)
    //
    // `vault_address_override`: read from the claim request body.
    // Falls back to PM_VAULT_ADDRESS if empty.
    pub async fn claim_winnings(
        &self,
        recipient: Address,
        proof: &EvmGroth16Proof,
        vault_address_override: Option<&str>,
    ) -> ClobResult<String> {
        let vault = self.effective_vault(vault_address_override)?;
        let selector = &ethers::utils::keccak256(
            b"claimWinnings(address,uint256[2],uint256[2][2],uint256[2],uint256[8])",
        )[..4];

        let tokens = encode_claim_winnings(recipient, proof);
        let data = Bytes::from([selector, &encode(&tokens)].concat());
        info!(vault = ?vault, %recipient, "claimWinnings → sending tx");
        self.relayer.send_tx(vault, data).await
    }
}

// ─── ABI encoding helpers ──────────────────────────────────────────────────

fn groth16_tokens(proof: &EvmGroth16Proof) -> Vec<Token> {
    // pA: uint256[2]
    let pa = Token::FixedArray(vec![
        Token::Uint(U256::from_str_radix(&proof.pa[0], 10).unwrap_or_default()),
        Token::Uint(U256::from_str_radix(&proof.pa[1], 10).unwrap_or_default()),
    ]);
    // pB: uint256[2][2]
    let pb = Token::FixedArray(vec![
        Token::FixedArray(vec![
            Token::Uint(U256::from_str_radix(&proof.pb[0][0], 10).unwrap_or_default()),
            Token::Uint(U256::from_str_radix(&proof.pb[0][1], 10).unwrap_or_default()),
        ]),
        Token::FixedArray(vec![
            Token::Uint(U256::from_str_radix(&proof.pb[1][0], 10).unwrap_or_default()),
            Token::Uint(U256::from_str_radix(&proof.pb[1][1], 10).unwrap_or_default()),
        ]),
    ]);
    // pC: uint256[2]
    let pc = Token::FixedArray(vec![
        Token::Uint(U256::from_str_radix(&proof.pc[0], 10).unwrap_or_default()),
        Token::Uint(U256::from_str_radix(&proof.pc[1], 10).unwrap_or_default()),
    ]);
    // pubSignals: uint256[N]
    let pub_signals = Token::FixedArray(
        proof
            .pub_signals
            .iter()
            .map(|s| Token::Uint(U256::from_str_radix(s, 10).unwrap_or_default()))
            .collect(),
    );
    vec![pa, pb, pc, pub_signals]
}

fn encode_lock_collateral(
    order_commitment: [u8; 32],
    required_amount: U256,
    lock_expiry_ts: u64,
    proof: &EvmGroth16Proof,
) -> Vec<Token> {
    let mut tokens = vec![
        Token::FixedBytes(order_commitment.to_vec()),
        Token::Uint(required_amount),
        Token::Uint(U256::from(lock_expiry_ts)),
    ];
    tokens.extend(groth16_tokens(proof));
    tokens
}

fn encode_settle_fill(
    market_id: u64,
    position_side: bool,
    spent_nullifier: [u8; 32],
    pot_contribution: u128,
    position_payout_units: u128,
    trade_fee_amount: u128,
    proof: &EvmGroth16Proof,
) -> Vec<Token> {
    let mut tokens = vec![
        Token::Uint(U256::from(market_id)),
        Token::Bool(position_side),
        Token::FixedBytes(spent_nullifier.to_vec()),
        Token::Uint(U256::from(pot_contribution)),
        Token::Uint(U256::from(position_payout_units)),
        Token::Uint(U256::from(trade_fee_amount)),
    ];
    tokens.extend(groth16_tokens(proof));
    tokens
}

fn encode_claim_winnings(recipient: Address, proof: &EvmGroth16Proof) -> Vec<Token> {
    let mut tokens = vec![Token::Address(recipient)];
    tokens.extend(groth16_tokens(proof));
    tokens
}
