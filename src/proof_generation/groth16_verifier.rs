/// Server-side Groth16 proof verifier (BN254 / snarkjs compatible).
///
/// After the prover worker generates a proof via `snarkjs groth16 fullprove`,
/// this module re-verifies the proof using arkworks so that invalid proofs are
/// rejected **before** they are persisted or trigger on-chain transactions.
///
/// VK format: snarkjs `vk.json` (decimal strings, G2 in [c1, c0] order).
/// Proof format: parsed `EvmGroth16Proof` from `parse_snarkjs_proof`.
///
/// NOTE: G2 coordinate ordering in snarkjs JSON:
///   `[[x_c1, x_c0], [y_c1, y_c0], ...]`
///   where the Fp2 element is `x_c0 + x_c1 * u` (real part last, imaginary first).
///   Arkworks `Fq2::new(c0, c1)` takes real part first → we must swap.
use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ff::PrimeField;
use ark_groth16::{prepare_verifying_key, Groth16, Proof, VerifyingKey};
use num_bigint::BigUint;
use num_traits::Num;
use serde_json::Value;

use crate::error::{ClobError, ClobResult};
use super::EvmGroth16Proof;

// ─── Field element parsers ─────────────────────────────────────────────────

/// Parse a decimal (or 0x-prefixed hex) string into an Fq base-field element.
fn parse_fq(s: &str) -> ClobResult<Fq> {
    let s = s.trim();
    // "1" and "0" appear as homogeneous coordinates; short-circuit for speed.
    if s == "1" { return Ok(Fq::from(1u64)); }
    if s == "0" { return Ok(Fq::from(0u64)); }

    let (bi, _radix) = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        (BigUint::from_str_radix(hex, 16), 16u32)
    } else {
        (BigUint::from_str_radix(s, 10), 10u32)
    };

    let bi = bi.map_err(|e| ClobError::Internal(format!("parse Fq '{s}': {e}")))?;
    let bytes = bi.to_bytes_be();
    Ok(Fq::from_be_bytes_mod_order(&bytes))
}

/// Parse a decimal (or 0x-prefixed hex) string into an Fr scalar-field element.
fn parse_fr(s: &str) -> ClobResult<Fr> {
    let s = s.trim();
    if s == "0" { return Ok(Fr::from(0u64)); }

    let bi = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        BigUint::from_str_radix(hex, 16)
    } else {
        BigUint::from_str_radix(s, 10)
    };

    let bi = bi.map_err(|e| ClobError::Internal(format!("parse Fr '{s}': {e}")))?;
    let bytes = bi.to_bytes_be();
    Ok(Fr::from_be_bytes_mod_order(&bytes))
}

// ─── Point parsers ─────────────────────────────────────────────────────────

/// Parse a G1 affine point from a snarkjs JSON array `[x, y, "1"]`.
fn parse_g1_from_json(arr: &[Value]) -> ClobResult<G1Affine> {
    if arr.len() < 2 {
        return Err(ClobError::Internal("G1 array too short (need x,y)".into()));
    }
    let x = parse_fq(arr[0].as_str().ok_or_else(|| ClobError::Internal("G1 x not string".into()))?)?;
    let y = parse_fq(arr[1].as_str().ok_or_else(|| ClobError::Internal("G1 y not string".into()))?)?;
    Ok(G1Affine::new(x, y))
}

/// Parse a G2 affine point from a snarkjs JSON array `[[x_c1,x_c0],[y_c1,y_c0],["1","0"]]`.
/// snarkjs stores Fp2 coefficients as [imaginary, real]; arkworks Fq2::new(c0, c1).
fn parse_g2_from_json(outer: &[Value]) -> ClobResult<G2Affine> {
    if outer.len() < 2 {
        return Err(ClobError::Internal("G2 outer array too short".into()));
    }
    let x_row = outer[0].as_array().ok_or_else(|| ClobError::Internal("G2 x row not array".into()))?;
    let y_row = outer[1].as_array().ok_or_else(|| ClobError::Internal("G2 y row not array".into()))?;
    if x_row.len() < 2 || y_row.len() < 2 {
        return Err(ClobError::Internal("G2 coordinate rows too short".into()));
    }
    // snarkjs: x = [x_c1, x_c0] → c0 = x_row[1], c1 = x_row[0]
    let x_c1 = parse_fq(x_row[0].as_str().unwrap_or("0"))?;
    let x_c0 = parse_fq(x_row[1].as_str().unwrap_or("0"))?;
    let y_c1 = parse_fq(y_row[0].as_str().unwrap_or("0"))?;
    let y_c0 = parse_fq(y_row[1].as_str().unwrap_or("0"))?;

    let x = Fq2::new(x_c0, x_c1); // Fq2 { c0: real, c1: imaginary }
    let y = Fq2::new(y_c0, y_c1);
    Ok(G2Affine::new(x, y))
}

/// Parse a G2 point from the `pb` field of an `EvmGroth16Proof`.
///
/// `pb = [[pb_0_0, pb_0_1], [pb_1_0, pb_1_1]]` where each row comes from
/// `pi_b[row][col]` in snarkjs `proof.json`.  snarkjs stores pi_b as:
///   pi_b[0] = [x_c1, x_c0], pi_b[1] = [y_c1, y_c0]
/// So pb[0][0] = x_c1, pb[0][1] = x_c0, pb[1][0] = y_c1, pb[1][1] = y_c0.
fn parse_g2_from_proof(pb: &[[String; 2]; 2]) -> ClobResult<G2Affine> {
    // pb[0] = [x_c1, x_c0], pb[1] = [y_c1, y_c0]
    let x_c1 = parse_fq(&pb[0][0])?;
    let x_c0 = parse_fq(&pb[0][1])?;
    let y_c1 = parse_fq(&pb[1][0])?;
    let y_c0 = parse_fq(&pb[1][1])?;
    let x = Fq2::new(x_c0, x_c1);
    let y = Fq2::new(y_c0, y_c1);
    Ok(G2Affine::new(x, y))
}

// ─── Public API ────────────────────────────────────────────────────────────

/// Load a snarkjs `vk.json` from disk and verify a Groth16 proof.
///
/// Called by the prover worker immediately after `snarkjs groth16 fullprove`
/// completes, so that any invalid proof is rejected before it can be acted upon.
///
/// Returns `Ok(())` if the proof is valid, `Err(ClobError::Internal(_))` otherwise.
pub fn verify_snarkjs_proof(vk_path: &str, proof: &EvmGroth16Proof) -> ClobResult<()> {
    // ── 1. Load and parse vk.json ──────────────────────────────────────────
    let vk_raw = std::fs::read_to_string(vk_path)
        .map_err(|e| ClobError::Internal(format!("read vk.json at '{vk_path}': {e}")))?;
    let vk_val: Value = serde_json::from_str(&vk_raw)
        .map_err(|e| ClobError::Internal(format!("parse vk.json: {e}")))?;

    let alpha_g1 = parse_g1_from_json(
        vk_val["vk_alpha_1"]
            .as_array()
            .ok_or_else(|| ClobError::Internal("vk missing vk_alpha_1".into()))?,
    )?;

    let beta_g2 = parse_g2_from_json(
        vk_val["vk_beta_2"]
            .as_array()
            .ok_or_else(|| ClobError::Internal("vk missing vk_beta_2".into()))?,
    )?;

    let gamma_g2 = parse_g2_from_json(
        vk_val["vk_gamma_2"]
            .as_array()
            .ok_or_else(|| ClobError::Internal("vk missing vk_gamma_2".into()))?,
    )?;

    let delta_g2 = parse_g2_from_json(
        vk_val["vk_delta_2"]
            .as_array()
            .ok_or_else(|| ClobError::Internal("vk missing vk_delta_2".into()))?,
    )?;

    let ic_arr = vk_val["IC"]
        .as_array()
        .ok_or_else(|| ClobError::Internal("vk missing IC".into()))?;
    let gamma_abc_g1: Vec<G1Affine> = ic_arr
        .iter()
        .enumerate()
        .map(|(i, pt)| {
            let arr = pt.as_array().ok_or_else(|| {
                ClobError::Internal(format!("IC[{i}] not array"))
            })?;
            parse_g1_from_json(arr)
        })
        .collect::<ClobResult<Vec<_>>>()?;

    let vk = VerifyingKey::<Bn254> {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        gamma_abc_g1,
    };

    // ── 2. Parse the proof ─────────────────────────────────────────────────
    let a = {
        let x = parse_fq(&proof.pa[0])?;
        let y = parse_fq(&proof.pa[1])?;
        G1Affine::new(x, y)
    };
    let b = parse_g2_from_proof(&proof.pb)?;
    let c = {
        let x = parse_fq(&proof.pc[0])?;
        let y = parse_fq(&proof.pc[1])?;
        G1Affine::new(x, y)
    };
    let ark_proof = Proof::<Bn254> { a, b, c };

    // ── 3. Parse public inputs ─────────────────────────────────────────────
    let public_inputs: Vec<Fr> = proof
        .pub_signals
        .iter()
        .enumerate()
        .map(|(i, s)| {
            parse_fr(s).map_err(|e| {
                ClobError::Internal(format!("public_signal[{i}]: {e}"))
            })
        })
        .collect::<ClobResult<Vec<_>>>()?;

    // ── 4. Verify ──────────────────────────────────────────────────────────
    let pvk = prepare_verifying_key(&vk);

    let valid = Groth16::<Bn254>::verify_proof(&pvk, &ark_proof, &public_inputs)
        .map_err(|e| ClobError::Internal(format!("groth16 pairing error: {e:?}")))?;

    if !valid {
        return Err(ClobError::Internal(
            "groth16 proof verification failed: pairing check did not pass".to_string(),
        ));
    }

    Ok(())
}
