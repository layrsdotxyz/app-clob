/// BN254 Poseidon hash — iden3 / circomlibjs compatible.
///
/// This is the **same hash function used by all circom circuits** in the system
/// (private_order_commitment, private_deposit, private_withdraw, etc.).
/// It MUST be used anywhere the backend recomputes a hash that a circuit will
/// also compute, so that the two sides agree.  The previous keccak256 usage
/// caused a mismatch: any commitment computed off-chain would differ from the
/// one the circuit produces, breaking the commit-reveal verification.
///
/// Implementation: light-poseidon 0.2 with ark-bn254::Fr, which implements the
/// iden3 specification (same round constants + MDS matrix as circomlibjs).
use ark_bn254::Fr;
use ark_ff::PrimeField;
use light_poseidon::{Poseidon, PoseidonHasher};

use crate::error::{ClobError, ClobResult};

/// Hash one or more 32-byte big-endian field elements with BN254 Poseidon.
///
/// Each `[u8; 32]` is interpreted as a big-endian unsigned integer and reduced
/// mod the BN254 scalar field prime before hashing (exactly as circom does
/// when it treats circuit inputs as `Fr` signals).
///
/// Returns the 32-byte big-endian representation of the Poseidon output.
///
/// Supports 1–12 inputs (the range supported by the circom Poseidon gadget).
pub fn poseidon_hash(inputs: &[[u8; 32]]) -> ClobResult<[u8; 32]> {
    if inputs.is_empty() {
        return Err(ClobError::Internal(
            "poseidon_hash: at least one input required".to_string(),
        ));
    }
    if inputs.len() > 12 {
        return Err(ClobError::Internal(format!(
            "poseidon_hash: too many inputs ({}); circom gadget supports up to 12",
            inputs.len()
        )));
    }

    let field_elems: Vec<Fr> = inputs
        .iter()
        .map(|b| Fr::from_be_bytes_mod_order(b))
        .collect();

    let mut hasher = Poseidon::<Fr>::new_circom(field_elems.len()).map_err(|e| {
        ClobError::Internal(format!(
            "poseidon init (n={}): {:?}",
            field_elems.len(),
            e
        ))
    })?;

    let result = hasher
        .hash(&field_elems)
        .map_err(|e| ClobError::Internal(format!("poseidon hash: {:?}", e)))?;

    // Convert Fr → big-endian bytes32
    let repr = result.into_bigint();
    // BigInt::to_bytes_be() — padded to the canonical size of Fr (32 bytes on BN254)
    let bytes = ark_ff::BigInteger::to_bytes_be(&repr);
    let mut out = [0u8; 32];
    // Defensive: bytes might be shorter if the value is small
    let copy_len = bytes.len().min(32);
    out[32 - copy_len..].copy_from_slice(&bytes[bytes.len() - copy_len..]);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u64_bytes(n: u64) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[24..32].copy_from_slice(&n.to_be_bytes());
        b
    }

    #[test]
    fn test_poseidon_deterministic() {
        let a = u64_bytes(1);
        let b = u64_bytes(2);
        let h1 = poseidon_hash(&[a, b]).unwrap();
        let h2 = poseidon_hash(&[a, b]).unwrap();
        assert_eq!(h1, h2, "Poseidon must be deterministic");
    }

    #[test]
    fn test_poseidon_differs_from_keccak() {
        use tiny_keccak::{Hasher, Keccak};
        let a = u64_bytes(42);
        let b = u64_bytes(99);

        let poseidon = poseidon_hash(&[a, b]).unwrap();

        let mut k = Keccak::v256();
        k.update(&a);
        k.update(&b);
        let mut keccak = [0u8; 32];
        k.finalize(&mut keccak);

        assert_ne!(
            poseidon, keccak,
            "Poseidon and keccak256 should produce different outputs"
        );
    }

    #[test]
    fn test_poseidon_6_inputs() {
        let inputs: Vec<[u8; 32]> = (1u64..=6).map(u64_bytes).collect();
        let result = poseidon_hash(&inputs).unwrap();
        // Just verify it doesn't error and is non-zero
        assert_ne!(result, [0u8; 32]);
    }

    #[test]
    fn test_poseidon_nonzero_output() {
        // Poseidon of zeros should still be non-zero (domain separation via capacity)
        let result = poseidon_hash(&[[0u8; 32], [0u8; 32]]).unwrap();
        assert_ne!(result, [0u8; 32]);
    }

    #[test]
    fn test_poseidon_input_order_matters() {
        let a = u64_bytes(7);
        let b = u64_bytes(13);
        let h_ab = poseidon_hash(&[a, b]).unwrap();
        let h_ba = poseidon_hash(&[b, a]).unwrap();
        assert_ne!(h_ab, h_ba, "Input order must affect hash output");
    }

    #[test]
    fn test_poseidon_empty_fails() {
        assert!(poseidon_hash(&[]).is_err());
    }

    #[test]
    fn test_poseidon_too_many_inputs_fails() {
        let inputs: Vec<[u8; 32]> = (0u64..13).map(u64_bytes).collect();
        assert!(poseidon_hash(&inputs).is_err());
    }
}
