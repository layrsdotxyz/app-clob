use layrs_direct_execution_v1::{
    GovernedKeyReleaseArtifact, RuntimeMeasurementBinding, WriterGrant,
};
use std::{
    env,
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

fn parse_grant(path: &Path) -> Result<WriterGrant, String> {
    let bytes =
        fs::read(path).map_err(|error| format!("could not read {}: {error}", path.display()))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("could not parse {} as WriterGrant: {error}", path.display()))
}

fn parse_artifact(path: &Path) -> Result<GovernedKeyReleaseArtifact, String> {
    let bytes = fs::read(path)
        .map_err(|error| format!("could not read {}: {error}", path.display()))?;
    serde_cbor::from_slice(&bytes)
        .map_err(|error| format!("could not parse {} as key release artifact: {error}", path.display()))
}

fn parse_binding(path: &Path) -> Result<RuntimeMeasurementBinding, String> {
    let bytes =
        fs::read(path).map_err(|error| format!("could not read {}: {error}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|error| {
        format!(
            "could not parse {} as RuntimeMeasurementBinding: {error}",
            path.display()
        )
    })
}

fn unsigned_bytes(grant: &WriterGrant) -> Result<Vec<u8>, String> {
    let mut unsigned = grant.clone();
    unsigned.signature.clear();
    // WriterGrant::unsigned_bytes uses this exact serde_json serialization.
    // Serializing the concrete Rust type preserves its declared field order.
    serde_json::to_vec(&unsigned)
        .map_err(|error| format!("could not serialize WriterGrant: {error}"))
}

fn finalize_grant(
    mut grant: WriterGrant,
    signature: String,
    now_unix: u64,
) -> Result<WriterGrant, String> {
    if !grant.signature.is_empty() {
        return Err("finalize input must have an empty signature".into());
    }
    if signature.is_empty()
        || signature.len() > 1_024
        || signature
            .chars()
            .any(|character| character.is_ascii_whitespace())
    {
        return Err("signature file must contain one bounded base64 value".into());
    }
    grant.signature = signature;
    if !grant.verify(now_unix, &grant.runtime_measurement) {
        return Err("WriterGrant::verify rejected the finalized grant".into());
    }
    Ok(grant)
}

fn verify_grant(grant: &WriterGrant, now_unix: u64) -> Result<(), String> {
    if grant.verify(now_unix, &grant.runtime_measurement) {
        Ok(())
    } else {
        Err("WriterGrant::verify rejected the grant".into())
    }
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(path)
        .map_err(|error| format!("could not create {}: {error}", path.display()))?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("could not write {}: {error}", path.display()))
}

fn parse_now(value: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .map_err(|_| "NOW_UNIX must be an unsigned integer".into())
}

fn read_signature(path: &Path) -> Result<String, String> {
    let value = fs::read_to_string(path)
        .map_err(|error| format!("could not read signature file {}: {error}", path.display()))?;
    Ok(value.trim().to_owned())
}

fn print_verified_metadata(grant: &WriterGrant) {
    println!("writerGrantCommitment={}", grant.commitment());
    println!("activationId={}", grant.activation_id);
    println!("expiresAtUnix={}", grant.expires_at_unix);
}

fn print_unsigned_metadata(grant: &WriterGrant) {
    println!("activationId={}", grant.activation_id);
    println!("expiresAtUnix={}", grant.expires_at_unix);
}

fn usage() -> &'static str {
    "usage:\n  layrs-writer-grant-helper unsigned INPUT_GRANT_JSON OUTPUT_UNSIGNED_BYTES\n  layrs-writer-grant-helper finalize INPUT_UNSIGNED_GRANT_JSON SIGNATURE_FILE OUTPUT_SIGNED_GRANT_JSON NOW_UNIX\n  layrs-writer-grant-helper verify SIGNED_GRANT_JSON NOW_UNIX\n  layrs-writer-grant-helper inspect-artifact INPUT_ARTIFACT_CBOR\n  layrs-writer-grant-helper verify-artifact SIGNED_GRANT_JSON INPUT_ARTIFACT_CBOR NOW_UNIX\n  layrs-writer-grant-helper verify-predecessor CURRENT_GRANT_JSON INPUT_ARTIFACT_CBOR PREDECESSOR_VERIFY_UNIX\n  layrs-writer-grant-helper verify-successor CURRENT_GRANT_JSON INPUT_ARTIFACT_CBOR SUCCESSOR_GRANT_JSON EXPECTED_RUNTIME_BINDING_JSON PREDECESSOR_VERIFY_UNIX NOW_UNIX"
}

fn run(args: &[String]) -> Result<(), String> {
    match args {
        [command, input, output] if command == "unsigned" => {
            let grant = parse_grant(Path::new(input))?;
            write_new(Path::new(output), &unsigned_bytes(&grant)?)?;
            print_unsigned_metadata(&grant);
            Ok(())
        }
        [command, input, signature_file, output, now] if command == "finalize" => {
            let grant = parse_grant(Path::new(input))?;
            let signature = read_signature(Path::new(signature_file))?;
            let grant = finalize_grant(grant, signature, parse_now(now)?)?;
            let bytes = serde_json::to_vec(&grant)
                .map_err(|error| format!("could not serialize WriterGrant: {error}"))?;
            write_new(Path::new(output), &bytes)?;
            print_verified_metadata(&grant);
            Ok(())
        }
        [command, input, now] if command == "verify" => {
            let grant = parse_grant(Path::new(input))?;
            verify_grant(&grant, parse_now(now)?)?;
            print_verified_metadata(&grant);
            Ok(())
        }
        [command, input] if command == "inspect-artifact" => {
            let artifact = parse_artifact(Path::new(input))?;
            println!("artifactHash={}", artifact.artifact_hash());
            println!("activationId={}", artifact.activation_id);
            println!("writerGrantCommitment={}", artifact.writer_grant_commitment);
            println!("kmsKeyId={}", artifact.kms_key_id);
            Ok(())
        }
        [command, grant, artifact, now] if command == "verify-artifact" => {
            let grant = parse_grant(Path::new(grant))?;
            verify_grant(&grant, parse_now(now)?)?;
            let artifact = parse_artifact(Path::new(artifact))?;
            if !artifact.verify_for(
                &grant,
                &grant.runtime_measurement,
                &grant.key_release_kms_key_id,
            ) {
                return Err("key release artifact does not verify for the signed grant".into());
            }
            println!("artifactHash={}", artifact.artifact_hash());
            print_verified_metadata(&grant);
            Ok(())
        }
        [command, current, artifact, now] if command == "verify-predecessor" => {
            let current = parse_grant(Path::new(current))?;
            let now = parse_now(now)?;
            verify_grant(&current, now)?;
            let artifact = parse_artifact(Path::new(artifact))?;
            if !artifact.verify_for(
                &current,
                &current.runtime_measurement,
                &current.key_release_kms_key_id,
            ) {
                return Err("key release artifact does not verify for the current live grant".into());
            }
            println!("artifactHash={}", artifact.artifact_hash());
            println!("activationId={}", artifact.activation_id);
            println!("writerGrantCommitment={}", artifact.writer_grant_commitment);
            println!("currentGrantCommitment={}", current.commitment());
            Ok(())
        }
        [command, current, artifact, successor, expected_binding, predecessor_verify, now]
            if command == "verify-successor" =>
        {
            let current = parse_grant(Path::new(current))?;
            let successor = parse_grant(Path::new(successor))?;
            let expected_binding = parse_binding(Path::new(expected_binding))?;
            let now = parse_now(now)?;
            let predecessor_verify = parse_now(predecessor_verify)?;
            if predecessor_verify > now {
                return Err("predecessor verification time is in the future".into());
            }
            verify_grant(&current, predecessor_verify)?;
            verify_grant(&successor, now)?;
            let artifact = parse_artifact(Path::new(artifact))?;
            if !artifact.verify_for(
                &current,
                &current.runtime_measurement,
                &current.key_release_kms_key_id,
            ) {
                return Err("key release artifact does not verify for the current live grant".into());
            }
            if successor.activation_id == current.activation_id
                || successor.environment != current.environment
                || successor.authorization_scope != current.authorization_scope
                || successor.epoch_id != current.epoch_id
                || successor.runtime != current.runtime
                || successor.opening_epoch_sha256 != current.opening_epoch_sha256
                || successor.opening_evidence_manifest_sha256
                    != current.opening_evidence_manifest_sha256
                || successor.old_writer_fence_evidence_sha256
                    != current.old_writer_fence_evidence_sha256
                || successor.key_release_kms_key_id != current.key_release_kms_key_id
                || successor.committed_restore_frontier != current.committed_restore_frontier
                || successor.governance_key_id != current.governance_key_id
                || successor.signing_algorithm != current.signing_algorithm
                || successor.expires_at_unix <= now
            {
                return Err("successor changed a field outside activation, predecessor, expiry, or signature".into());
            }
            if successor.runtime_measurement != expected_binding {
                return Err("successor runtime measurement differs from the independently supplied expected binding".into());
            }
            let predecessor = successor
                .key_release_predecessor
                .as_ref()
                .ok_or("successor predecessor is missing")?;
            if predecessor.activation_id != current.activation_id
                || predecessor.artifact_sha256 != artifact.artifact_hash()
                || predecessor.writer_grant_commitment != current.commitment()
            {
                return Err("successor predecessor fields do not match live verified sources".into());
            }
            println!("predecessorArtifactHash={}", artifact.artifact_hash());
            println!("predecessorActivationId={}", current.activation_id);
            println!("predecessorGrantCommitment={}", current.commitment());
            println!("successorActivationId={}", successor.activation_id);
            println!("successorGrantCommitment={}", successor.commitment());
            println!("expiresAtUnix={}", successor.expires_at_unix);
            Ok(())
        }
        _ => Err(usage().into()),
    }
}

fn main() {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if let Err(error) = run(&args) {
        eprintln!("grant helper failed: {error}");
        std::process::exit(2);
    }
}
