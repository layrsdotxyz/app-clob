/// Helpers for normalizing EVM-bound public inputs and parsing UltraHonk proofs.
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

// ─── UltraHonk proof types ────────────────────────────────────────────────

/// EVM-ready UltraHonk proof produced by `bb prove --scheme ultra_honk`.
///
/// `proof_hex` — `0x`-prefixed hex of the raw proof bytes (as written by bb to `<dir>/proof`).
/// `public_inputs` — ordered `0x`-prefixed `bytes32` hex strings (one per public input).
#[derive(Debug, Clone)]
pub struct HonkProof {
    pub proof_hex: String,
    pub public_inputs: Vec<String>,
}

/// Parse a `HonkProof` from the JSON blob emitted by `generate_barretenberg_output()`.
///
/// Expected JSON fields:
/// ```json
/// {
///   "proof_format": "ultra_honk",
///   "proof_hex": "0x...",
///   "public_inputs": ["0x...", ...]
/// }
/// ```
pub fn parse_honk_proof_from_output(output: &str) -> ClobResult<HonkProof> {
    let v: Value = serde_json::from_str(output)
        .map_err(|e| ClobError::Internal(format!("parse honk prover output: {e}")))?;

    // Sanity-check the proof format field when present.
    if let Some(fmt) = v.get("proof_format").and_then(|f| f.as_str()) {
        if fmt != "ultra_honk" {
            return Err(ClobError::Internal(format!(
                "unexpected proof_format '{}', expected 'ultra_honk'",
                fmt
            )));
        }
    }

    let proof_hex = v
        .get("proof_hex")
        .and_then(|h| h.as_str())
        .ok_or_else(|| ClobError::Internal("honk output missing 'proof_hex'".to_string()))?
        .to_string();

    // Validate minimal hex structure.
    let hex_body = proof_hex
        .strip_prefix("0x")
        .or_else(|| proof_hex.strip_prefix("0X"))
        .ok_or_else(|| {
            ClobError::Internal("proof_hex must be 0x-prefixed hex string".to_string())
        })?;
    if hex_body.is_empty() || hex_body.len() % 2 != 0 {
        return Err(ClobError::Internal(
            "proof_hex has odd or zero length".to_string(),
        ));
    }

    let public_inputs = v
        .get("public_inputs")
        .and_then(|pi| pi.as_array())
        .ok_or_else(|| ClobError::Internal("honk output missing 'public_inputs'".to_string()))?
        .iter()
        .enumerate()
        .map(|(i, item)| {
            let s = item.as_str().ok_or_else(|| {
                ClobError::Internal(format!("public_inputs[{}] is not a string", i))
            })?;
            // Must be 0x-prefixed 32-byte hex (66 chars).
            let hex = s
                .strip_prefix("0x")
                .or_else(|| s.strip_prefix("0X"))
                .ok_or_else(|| {
                    ClobError::Internal(format!("public_inputs[{}] '{}' is not 0x-prefixed", i, s))
                })?;
            if hex.len() != 64 {
                return Err(ClobError::Internal(format!(
                    "public_inputs[{}] '{}' is not 32 bytes (64 hex chars)",
                    i, s
                )));
            }
            Ok(s.to_lowercase())
        })
        .collect::<ClobResult<Vec<_>>>()?;

    Ok(HonkProof {
        proof_hex,
        public_inputs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── parse_u128_hex ────────────────────────────────────────────────────

    #[test]
    fn test_parse_u128_zero() {
        assert_eq!(parse_u128_hex("0x0", "v").unwrap(), 0u128);
    }

    #[test]
    fn test_parse_u128_decimal() {
        assert_eq!(parse_u128_hex("12345", "v").unwrap(), 12345u128);
    }

    #[test]
    fn test_parse_u128_hex_lowercase() {
        assert_eq!(parse_u128_hex("0xff", "v").unwrap(), 255u128);
    }

    #[test]
    fn test_parse_u128_hex_uppercase_prefix() {
        assert_eq!(parse_u128_hex("0XFF", "v").unwrap(), 255u128);
    }

    #[test]
    fn test_parse_u128_overflow_is_error() {
        // 2^128 overflows u128.
        let result = parse_u128_hex("0x100000000000000000000000000000000", "v");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_u128_non_hex_garbage() {
        assert!(parse_u128_hex("0xzzzz", "v").is_err());
    }

    // ─── low_high_hex_to_bytes32 ──────────────────────────────────────────

    #[test]
    fn test_low_high_zero_zero() {
        assert_eq!(low_high_hex_to_bytes32("0x0", "0x0").unwrap(), [0u8; 32]);
    }

    #[test]
    fn test_low_high_known_values() {
        // high=1 fills bytes [0..16] as big-endian 1; low=2 fills bytes [16..32] as big-endian 2.
        let result = low_high_hex_to_bytes32("0x2", "0x1").unwrap();
        let mut expected = [0u8; 32];
        expected[..16].copy_from_slice(&1u128.to_be_bytes());
        expected[16..].copy_from_slice(&2u128.to_be_bytes());
        assert_eq!(result, expected);
    }

    #[test]
    fn test_low_high_max_u128() {
        let max = format!("0x{:x}", u128::MAX);
        assert_eq!(low_high_hex_to_bytes32(&max, &max).unwrap(), [0xffu8; 32]);
    }

    #[test]
    fn test_low_high_decimal_strings() {
        // parse_u128_hex accepts decimal notation.
        let result = low_high_hex_to_bytes32("1", "0").unwrap();
        let mut expected = [0u8; 32];
        expected[31] = 1; // low=1 placed in the last byte
        assert_eq!(result, expected);
    }

    #[test]
    fn test_low_high_invalid_hex_is_error() {
        assert!(low_high_hex_to_bytes32("0xzzzz", "0x0").is_err());
    }

    // ─── parse_honk_proof_from_output ─────────────────────────────────────

    fn valid_honk_json() -> String {
        let pi = format!("0x{}", "ab".repeat(32));
        serde_json::json!({
            "proof_format": "ultra_honk",
            "proof_hex": "0xdeadbeef00",
            "public_inputs": [pi.clone(), pi],
        })
        .to_string()
    }

    #[test]
    fn test_parse_honk_valid_proof() {
        let proof = parse_honk_proof_from_output(&valid_honk_json()).unwrap();
        assert!(proof.proof_hex.starts_with("0x"));
        assert_eq!(proof.public_inputs.len(), 2);
    }

    #[test]
    fn test_parse_honk_no_proof_format_field_accepted() {
        // proof_format is optional — omitting it should succeed.
        let pi = format!("0x{}", "cd".repeat(32));
        let json = serde_json::json!({
            "proof_hex": "0xdeadbeef00",
            "public_inputs": [pi],
        })
        .to_string();
        assert!(parse_honk_proof_from_output(&json).is_ok());
    }

    #[test]
    fn test_parse_honk_wrong_proof_format_rejected() {
        let json = serde_json::json!({
            "proof_format": "groth16",
            "proof_hex": "0xdeadbeef00",
            "public_inputs": [],
        })
        .to_string();
        let err = parse_honk_proof_from_output(&json).unwrap_err().to_string();
        assert!(
            err.contains("unexpected proof_format") || err.contains("ultra_honk"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_parse_honk_missing_proof_hex_is_error() {
        let pi = format!("0x{}", "ab".repeat(32));
        let json = serde_json::json!({
            "proof_format": "ultra_honk",
            "public_inputs": [pi],
        })
        .to_string();
        assert!(parse_honk_proof_from_output(&json).is_err());
    }

    #[test]
    fn test_parse_honk_empty_proof_hex_is_error() {
        let json = serde_json::json!({
            "proof_format": "ultra_honk",
            "proof_hex": "0x",
            "public_inputs": [],
        })
        .to_string();
        assert!(parse_honk_proof_from_output(&json).is_err());
    }

    #[test]
    fn test_parse_honk_odd_length_hex_is_error() {
        let json = serde_json::json!({
            "proof_format": "ultra_honk",
            "proof_hex": "0xabc",  // 3 hex chars — odd
            "public_inputs": [],
        })
        .to_string();
        assert!(parse_honk_proof_from_output(&json).is_err());
    }

    #[test]
    fn test_parse_honk_proof_hex_no_0x_prefix_is_error() {
        let json = serde_json::json!({
            "proof_format": "ultra_honk",
            "proof_hex": "deadbeef",  // missing 0x
            "public_inputs": [],
        })
        .to_string();
        assert!(parse_honk_proof_from_output(&json).is_err());
    }

    #[test]
    fn test_parse_honk_public_input_too_short_is_error() {
        // Public input is only 4 hex chars (2 bytes), not 64 chars (32 bytes).
        let json = serde_json::json!({
            "proof_format": "ultra_honk",
            "proof_hex": "0xdeadbeef00",
            "public_inputs": ["0xabcd"],
        })
        .to_string();
        assert!(parse_honk_proof_from_output(&json).is_err());
    }

    #[test]
    fn test_parse_honk_public_input_no_0x_prefix_is_error() {
        // 64 hex chars but missing the 0x prefix.
        let pi = "ab".repeat(32); // 64 chars, no 0x
        let json = serde_json::json!({
            "proof_format": "ultra_honk",
            "proof_hex": "0xdeadbeef00",
            "public_inputs": [pi],
        })
        .to_string();
        assert!(parse_honk_proof_from_output(&json).is_err());
    }

    #[test]
    fn test_parse_honk_missing_public_inputs_field_is_error() {
        let json = serde_json::json!({
            "proof_format": "ultra_honk",
            "proof_hex": "0xdeadbeef00",
        })
        .to_string();
        assert!(parse_honk_proof_from_output(&json).is_err());
    }

    #[test]
    fn test_parse_honk_empty_public_inputs_allowed() {
        // Circuits are allowed to have zero public inputs.
        let json = serde_json::json!({
            "proof_format": "ultra_honk",
            "proof_hex": "0xdeadbeef00",
            "public_inputs": [],
        })
        .to_string();
        let proof = parse_honk_proof_from_output(&json).unwrap();
        assert!(proof.public_inputs.is_empty());
    }
}
