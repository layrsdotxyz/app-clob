/// Parse snarkjs Groth16 proof JSON into EVM-ready pA/pB/pC/pubSignals arrays.
///
/// snarkjs writes two JSON files per proof:
///   - `proof.json`        — { "pi_a": [x,y,1], "pi_b": [[x0,y0],[x1,y1],[1,0]], "pi_c": [x,y,1] }
///   - `public.json`       — ["sig0", "sig1", ...]
///
/// The EVM verifier (Groth16Verifier.sol) expects the negated pA coordinates
/// in exactly the same order that snarkjs outputs (Groth16 negation handled inside verifier).
use std::path::Path;

use serde::Deserialize;
use serde_json::Value;

use crate::error::{ClobError, ClobResult};

// ─── EVM byte helpers ──────────────────────────────────────────────────────

/// Combine a Cairo-style u256 split (low 128-bit, high 128-bit hex strings)
/// into a big-endian `[u8; 32]` as expected by `bytes32` on EVM.
pub fn low_high_hex_to_bytes32(low_hex: &str, high_hex: &str) -> ClobResult<[u8; 32]> {
    let low = parse_u128_hex(low_hex, "nullifier_low")?;
    let high = parse_u128_hex(high_hex, "nullifier_high")?;
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&high.to_be_bytes());
    out[16..].copy_from_slice(&low.to_be_bytes());
    Ok(out)
}

/// Parse a hex or decimal string (Cairo felt, 128-bit) into `u128`.
pub fn parse_u128_hex(s: &str, label: &str) -> ClobResult<u128> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u128::from_str_radix(hex, 16)
    } else {
        s.parse::<u128>()
    }
    .map_err(|e| ClobError::Internal(format!("parse {label} '{s}': {e}")))
}

/// Parse an `EvmGroth16Proof` from the JSON output produced by the prover worker.
/// The output contains `"proof": { "pi_a": [...], ... }` and `"public_signals": [...]`.
pub fn parse_evm_proof_from_output(output: &str) -> ClobResult<EvmGroth16Proof> {
    let v: Value = serde_json::from_str(output)
        .map_err(|e| ClobError::Internal(format!("parse prover output: {e}")))?;

    let proof = v
        .get("proof")
        .ok_or_else(|| ClobError::Internal("prover output missing 'proof' field".to_string()))?;

    let pi_a = proof
        .get("pi_a")
        .and_then(|a| a.as_array())
        .ok_or_else(|| ClobError::Internal("proof missing pi_a".to_string()))?;
    let pi_b = proof
        .get("pi_b")
        .and_then(|b| b.as_array())
        .ok_or_else(|| ClobError::Internal("proof missing pi_b".to_string()))?;
    let pi_c = proof
        .get("pi_c")
        .and_then(|c| c.as_array())
        .ok_or_else(|| ClobError::Internal("proof missing pi_c".to_string()))?;

    if pi_a.len() < 2 || pi_b.len() < 2 || pi_c.len() < 2 {
        return Err(ClobError::Internal("malformed proof coordinates".to_string()));
    }
    let pi_b0 = pi_b[0]
        .as_array()
        .ok_or_else(|| ClobError::Internal("pi_b[0] not array".to_string()))?;
    let pi_b1 = pi_b[1]
        .as_array()
        .ok_or_else(|| ClobError::Internal("pi_b[1] not array".to_string()))?;
    if pi_b0.len() < 2 || pi_b1.len() < 2 {
        return Err(ClobError::Internal("pi_b rows too short".to_string()));
    }

    let pub_signals = v
        .get("public_signals")
        .and_then(|ps| ps.as_array())
        .ok_or_else(|| ClobError::Internal("prover output missing 'public_signals'".to_string()))?
        .iter()
        .map(val_to_decimal)
        .collect::<ClobResult<Vec<_>>>()?;

    Ok(EvmGroth16Proof {
        pa: [val_to_decimal(&pi_a[0])?, val_to_decimal(&pi_a[1])?],
        pb: [
            [val_to_decimal(&pi_b0[0])?, val_to_decimal(&pi_b0[1])?],
            [val_to_decimal(&pi_b1[0])?, val_to_decimal(&pi_b1[1])?],
        ],
        pc: [val_to_decimal(&pi_c[0])?, val_to_decimal(&pi_c[1])?],
        pub_signals,
    })
}

/// EVM-ready Groth16 proof. All field elements as decimal strings.
#[derive(Debug, Clone)]
pub struct EvmGroth16Proof {
    pub pa: [String; 2],
    pub pb: [[String; 2]; 2],
    pub pc: [String; 2],
    pub pub_signals: Vec<String>,
}

#[derive(Deserialize)]
struct SnarkjsProof {
    pi_a: Vec<Value>,
    pi_b: Vec<Vec<Value>>,
    pi_c: Vec<Value>,
}

fn val_to_decimal(v: &Value) -> ClobResult<String> {
    match v {
        Value::String(s) => Ok(s.clone()),
        Value::Number(n) => Ok(n.to_string()),
        _ => Err(ClobError::Internal(format!("unexpected proof field value: {v}"))),
    }
}

/// Parse `proof.json` and `public.json` produced by `snarkjs groth16 prove`.
pub fn parse_snarkjs_proof(
    proof_path: &Path,
    public_path: &Path,
) -> ClobResult<EvmGroth16Proof> {
    let proof_bytes = std::fs::read(proof_path)
        .map_err(|e| ClobError::Internal(format!("read proof.json: {e}")))?;
    let public_bytes = std::fs::read(public_path)
        .map_err(|e| ClobError::Internal(format!("read public.json: {e}")))?;

    let proof: SnarkjsProof = serde_json::from_slice(&proof_bytes)
        .map_err(|e| ClobError::Internal(format!("parse proof.json: {e}")))?;
    let public: Vec<Value> = serde_json::from_slice(&public_bytes)
        .map_err(|e| ClobError::Internal(format!("parse public.json: {e}")))?;

    // pi_a: [x, y, 1] — take first two elements
    if proof.pi_a.len() < 2 {
        return Err(ClobError::Internal("pi_a too short".to_string()));
    }
    let pa = [
        val_to_decimal(&proof.pi_a[0])?,
        val_to_decimal(&proof.pi_a[1])?,
    ];

    // pi_b: [[x0, y0], [x1, y1], [1, 0]] — take first two rows, each two elements
    // Note: the EVM verifier expects the coordinates in the order snarkjs outputs them.
    if proof.pi_b.len() < 2 || proof.pi_b[0].len() < 2 || proof.pi_b[1].len() < 2 {
        return Err(ClobError::Internal("pi_b too short".to_string()));
    }
    let pb = [
        [
            val_to_decimal(&proof.pi_b[0][0])?,
            val_to_decimal(&proof.pi_b[0][1])?,
        ],
        [
            val_to_decimal(&proof.pi_b[1][0])?,
            val_to_decimal(&proof.pi_b[1][1])?,
        ],
    ];

    // pi_c: [x, y, 1] — take first two elements
    if proof.pi_c.len() < 2 {
        return Err(ClobError::Internal("pi_c too short".to_string()));
    }
    let pc = [
        val_to_decimal(&proof.pi_c[0])?,
        val_to_decimal(&proof.pi_c[1])?,
    ];

    // public signals
    let pub_signals = public
        .iter()
        .map(val_to_decimal)
        .collect::<ClobResult<Vec<_>>>()?;

    Ok(EvmGroth16Proof { pa, pb, pc, pub_signals })
}
