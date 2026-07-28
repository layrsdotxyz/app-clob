use std::{
    env, fs,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Context, Result};
use layrs_settlement_proof_core::{
    encode_public_journal, prove_resolution, SettlementProofInput, SettlementProofOutput,
};
use layrs_settlement_proof_methods::{LAYRS_SETTLEMENT_GUEST_ELF, LAYRS_SETTLEMENT_GUEST_ID};
use risc0_zkvm::{default_prover, ExecutorEnv, InnerReceipt};
use serde::Serialize;
use sha2::{Digest, Sha256};

const MAX_PROOF_INPUT_BYTES: u64 = 128 * 1024;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProofArtifact {
    proof_system: &'static str,
    proof_version: &'static str,
    image_id: String,
    proof_hash: String,
    journal_hash: String,
    proof_cbor_file: &'static str,
    public_inputs_file: &'static str,
    output_file: &'static str,
    output: SettlementProofOutput,
}

fn main() -> Result<()> {
    let mut args = env::args().skip(1);
    let input_path = PathBuf::from(
        args.next()
            .ok_or_else(|| anyhow!("usage: host <input.json> <output-dir>"))?,
    );
    let output_dir = PathBuf::from(
        args.next()
            .ok_or_else(|| anyhow!("usage: host <input.json> <output-dir>"))?,
    );
    if args.next().is_some() {
        return Err(anyhow!("unexpected extra arguments"));
    }

    let metadata = fs::metadata(&input_path)
        .with_context(|| format!("stat proof input {}", input_path.display()))?;
    validate_input_shape(metadata.is_file(), metadata.len())?;
    let input_bytes = fs::read(&input_path)
        .with_context(|| format!("read proof input {}", input_path.display()))?;
    let input = decode_canonical_input(&input_bytes)?;
    fs::create_dir_all(&output_dir)
        .with_context(|| format!("create output directory {}", output_dir.display()))?;

    let expected_output = prove_resolution(input.clone())
        .map_err(|error| anyhow!("invalid settlement proof input: {error:?}"))?;
    let env = ExecutorEnv::builder()
        .write(&input)
        .context("encode proof input")?
        .build()
        .context("build RISC Zero executor environment")?;
    let receipt = default_prover()
        .prove(env, LAYRS_SETTLEMENT_GUEST_ELF)
        .context("generate RISC Zero receipt")?
        .receipt;
    receipt
        .verify(LAYRS_SETTLEMENT_GUEST_ID)
        .context("verify generated receipt locally")?;
    let output: SettlementProofOutput = expected_output;
    let expected_journal = encode_public_journal(&output);
    if receipt.journal.bytes.as_slice() != expected_journal {
        return Err(anyhow!(
            "verified proof journal does not match expected settlement output"
        ));
    }

    // zkVerify's RISC Zero verifier deserializes a proof wrapper containing
    // `inner`. The journal is supplied separately as public inputs.
    let proof_cbor = encode_zkverify_proof(&receipt.inner)?;
    let public_inputs = receipt.journal.bytes.clone();
    let image_id = image_id_hex();
    let proof_hash = hash_hex(&proof_cbor);
    let journal_hash = hash_hex(&public_inputs);

    write_atomic(&output_dir.join("proof.cbor"), &proof_cbor)?;
    write_atomic(&output_dir.join("public-inputs.bin"), &public_inputs)?;
    write_json(&output_dir.join("output.json"), &output)?;
    write_json(
        &output_dir.join("artifact.json"),
        &ProofArtifact {
            proof_system: "RISC_ZERO",
            proof_version: "2.2.0",
            image_id,
            proof_hash,
            journal_hash,
            proof_cbor_file: "proof.cbor",
            public_inputs_file: "public-inputs.bin",
            output_file: "output.json",
            output,
        },
    )?;
    Ok(())
}

fn decode_canonical_input(input_bytes: &[u8]) -> Result<SettlementProofInput> {
    let input: SettlementProofInput =
        serde_json::from_slice(input_bytes).context("decode settlement proof input")?;
    let canonical =
        serde_json::to_vec(&input).context("encode canonical settlement proof input")?;
    if input_bytes != canonical {
        return Err(anyhow!(
            "settlement proof input must use canonical compact JSON encoding"
        ));
    }
    Ok(input)
}

fn validate_input_shape(is_file: bool, byte_len: u64) -> Result<()> {
    if !is_file || byte_len == 0 || byte_len > MAX_PROOF_INPUT_BYTES {
        return Err(anyhow!(
            "proof input must be a non-empty regular file no larger than {MAX_PROOF_INPUT_BYTES} bytes"
        ));
    }
    Ok(())
}

#[derive(Serialize)]
struct ZkVerifyProof<'a> {
    inner: &'a InnerReceipt,
}

fn encode_zkverify_proof(inner: &InnerReceipt) -> Result<Vec<u8>> {
    let mut encoded = Vec::new();
    ciborium::into_writer(&ZkVerifyProof { inner }, &mut encoded)
        .context("CBOR-encode zkVerify RISC Zero proof wrapper")?;
    Ok(encoded)
}

fn image_id_hex() -> String {
    let mut bytes = Vec::with_capacity(32);
    for word in LAYRS_SETTLEMENT_GUEST_ID {
        // RISC Zero digests expose their eight u32 words in host order while
        // zkVerify's Vk is the digest's canonical byte representation.
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    format!("0x{}", hex::encode(bytes))
}

fn hash_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(Sha256::digest(bytes)))
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let encoded = serde_json::to_vec_pretty(value).context("encode JSON artifact")?;
    write_atomic(path, &encoded)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, bytes).with_context(|| format!("write {}", temporary.display()))?;
    fs::rename(&temporary, path).with_context(|| format!("publish artifact {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{decode_canonical_input, validate_input_shape, MAX_PROOF_INPUT_BYTES};

    fn canonical_fixture() -> Vec<u8> {
        let value: layrs_settlement_proof_core::SettlementProofInput = serde_json::from_str(
            include_str!("../../fixtures/layrs-v3-zen-15m-1785196800.json"),
        )
        .expect("decode fixture");
        serde_json::to_vec(&value).expect("canonicalize fixture")
    }

    #[test]
    fn accepts_canonical_compact_witness() {
        decode_canonical_input(&canonical_fixture()).expect("canonical witness");
    }

    #[test]
    fn rejects_non_canonical_witness() {
        let mut bytes = canonical_fixture();
        bytes.push(b'\n');
        let error = decode_canonical_input(&bytes).expect_err("non-canonical witness");
        assert!(error
            .to_string()
            .contains("canonical compact JSON encoding"));
    }

    #[test]
    fn rejects_unknown_witness_fields() {
        let mut value: serde_json::Value =
            serde_json::from_slice(&canonical_fixture()).expect("decode fixture");
        value
            .as_object_mut()
            .expect("fixture object")
            .insert("unexpected".into(), serde_json::json!(true));
        let bytes = serde_json::to_vec(&value).expect("encode malformed fixture");
        assert!(decode_canonical_input(&bytes).is_err());
    }

    #[test]
    fn rejects_empty_oversized_and_non_file_inputs() {
        assert!(validate_input_shape(true, 0).is_err());
        assert!(validate_input_shape(true, MAX_PROOF_INPUT_BYTES + 1).is_err());
        assert!(validate_input_shape(false, 1).is_err());
        validate_input_shape(true, MAX_PROOF_INPUT_BYTES).expect("bounded input");
    }

    #[test]
    fn rejects_truncated_witness() {
        let mut bytes = canonical_fixture();
        bytes.truncate(bytes.len() / 2);
        assert!(decode_canonical_input(&bytes).is_err());
    }
}
