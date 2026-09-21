//! One-time checkpoint preparation for a predecessor without checkpoint RPCs.
//! Does not retrieve receipt/state keys, adopt runtime state, or move money.
//! `prepare ANCHOR OUTPUT` is read-only remotely; `certify INPUT OUTPUT`
//! signs ONLY the exact prepared checkpoint using the existing governance KMS
//! key. Upload/cutover are separate governed release steps.
use aws_smithy_types::Blob;
use base64::{engine::general_purpose::STANDARD, Engine};
use layrs_direct_execution_v1::{
    artifact_hash, sha256, CheckpointBootstrapCertificate, DirectCheckpoint, DirectRuntime,
    DirectStateArtifact, RuntimeMode, SealedEpoch, EPOCH_ID, GOVERNANCE_KEY_ID,
};
use serde::Deserialize;
use std::{fs, io::Write, os::unix::fs::OpenOptionsExt, path::Path};

const BUCKET: &str = "layrs-production-082223548516-us-east-1-immutable";
const FRAME_LIMIT: usize = 64 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Anchor {
    protocol: String,
    sequence: u64,
    state_hash: String,
    source_commit: String,
    writer_grant_commitment: String,
    full_history_restore_verified: bool,
    all_balances_verified: bool,
    nonce_bound_nitro_attestation_verified: bool,
}
fn valid_hash(hash: &str, size: usize) -> bool {
    hash.len() == size
        && hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_anchor(anchor: &Anchor) -> bool {
    anchor.protocol == "layrs.direct-execution.checkpoint-anchor.v1"
        && anchor.sequence > 0
        && anchor.sequence <= 100_000
        && valid_hash(&anchor.state_hash, 64)
        && valid_hash(&anchor.source_commit, 40)
        && valid_hash(&anchor.writer_grant_commitment, 64)
        && anchor.full_history_restore_verified
        && anchor.all_balances_verified
        && anchor.nonce_bound_nitro_attestation_verified
}
fn create_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if bytes.is_empty() || bytes.len() > FRAME_LIMIT {
        return Err("CHECKPOINT_FRAME_BOUND".into());
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| "CHECKPOINT_OUTPUT_EXISTS_OR_DENIED")?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| "CHECKPOINT_OUTPUT_FAILED".into())
}
async fn read(client: &aws_sdk_s3::Client, key: &str) -> Result<Vec<u8>, String> {
    let object = client
        .get_object()
        .bucket(BUCKET)
        .key(key)
        .send()
        .await
        .map_err(|_| "CHECKPOINT_ARCHIVE_READ_FAILED")?;
    let length = object
        .content_length()
        .ok_or("CHECKPOINT_ARCHIVE_LENGTH_MISSING")?;
    if length <= 0 || length as usize > FRAME_LIMIT {
        return Err("CHECKPOINT_ARCHIVE_LENGTH_INVALID".into());
    }
    let bytes = object
        .body
        .collect()
        .await
        .map_err(|_| "CHECKPOINT_ARCHIVE_BODY_FAILED")?
        .into_bytes()
        .to_vec();
    if bytes.len() != length as usize {
        return Err("CHECKPOINT_ARCHIVE_BODY_TRUNCATED".into());
    }
    Ok(bytes)
}
async fn list(client: &aws_sdk_s3::Client, prefix: &str) -> Result<Vec<String>, String> {
    let mut keys = Vec::new();
    let mut token = None;
    let mut seen = std::collections::BTreeSet::new();
    loop {
        let page = client
            .list_objects_v2()
            .bucket(BUCKET)
            .prefix(prefix)
            .set_continuation_token(token)
            .send()
            .await
            .map_err(|_| "CHECKPOINT_ARCHIVE_LIST_FAILED")?;
        for object in page.contents() {
            keys.push(
                object
                    .key()
                    .ok_or("CHECKPOINT_ARCHIVE_KEY_MISSING")?
                    .to_string(),
            );
        }
        if keys.len() > 100_000 {
            return Err("CHECKPOINT_ARCHIVE_COUNT_BOUND".into());
        }
        if !page.is_truncated.unwrap_or(false) {
            break;
        }
        let next = page
            .next_continuation_token()
            .filter(|value| !value.is_empty())
            .ok_or("CHECKPOINT_ARCHIVE_TOKEN_MISSING")?
            .to_string();
        if !seen.insert(next.clone()) {
            return Err("CHECKPOINT_ARCHIVE_TOKEN_REPEATED".into());
        }
        token = Some(next);
    }
    keys.sort();
    if keys.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("CHECKPOINT_ARCHIVE_DUPLICATE".into());
    }
    Ok(keys)
}
async fn prepare(
    configuration: &aws_config::SdkConfig,
    anchor: Anchor,
) -> Result<DirectCheckpoint, String> {
    if !valid_anchor(&anchor) {
        return Err("CHECKPOINT_REQUIRES_VERIFIED_PREDECESSOR_ANCHOR".into());
    }
    let client = aws_sdk_s3::Client::new(configuration);
    let prefix = format!("direct-execution/{EPOCH_ID}");
    let keys = list(&client, &format!("{prefix}/artifacts/")).await?;
    let heads = list(&client, &format!("{prefix}/heads/")).await?;
    let sequence = anchor.sequence as usize;
    if keys.len() != heads.len() || sequence > keys.len() {
        return Err("CHECKPOINT_ANCHOR_OUTSIDE_ARCHIVE".into());
    }
    let epoch_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../.codex-review-bundles/unified-direct-execution-20260905/new-epoch-20260911/OPENING_EPOCH_STATE_20260911.json");
    // Public opening fixture only; these dummy keys NEVER decrypt or certify
    // anything. This obtains the independently pinned opening state hash.
    let opening = DirectRuntime::new(
        SealedEpoch::load(epoch_path).map_err(|_| "CHECKPOINT_OPENING_INVALID")?,
        RuntimeMode::Dormant,
        vec![0; 32],
    )
    .map_err(|_| "CHECKPOINT_OPENING_INVALID")?;
    let opening_state_hash = opening.committed_state_hash();
    let mut root = opening_state_hash.clone();
    let mut records = Vec::with_capacity(sequence);
    let mut hashes = Vec::with_capacity(sequence);
    let mut last = None;
    for start in (0..sequence).step_by(16) {
        let mut tasks = Vec::new();
        for index in start..(start + 16).min(sequence) {
            let client = client.clone();
            let key = keys[index].clone();
            let head = heads[index].clone();
            tasks.push((
                index,
                tokio::spawn(async move {
                    let (bytes, head_bytes) =
                        tokio::try_join!(read(&client, &key), read(&client, &head))?;
                    if bytes != head_bytes {
                        return Err("CHECKPOINT_ARCHIVE_HEAD_BYTES_DIFFER".to_string());
                    }
                    serde_cbor::from_slice::<DirectStateArtifact>(&bytes)
                        .map_err(|_| "CHECKPOINT_ARTIFACT_DECODE_FAILED".to_string())
                }),
            ));
        }
        for (index, task) in tasks {
            let mut artifact = task.await.map_err(|_| "CHECKPOINT_DOWNLOAD_FAILED")??;
            let hash = artifact_hash(&artifact);
            if artifact.epoch_id != EPOCH_ID
                || artifact.sequence != index as u64 + 1
                || artifact.prior_state_hash != root
                || artifact.ciphertext_hash != sha256(&artifact.ciphertext)
                || artifact.nonce.len() != 12
                || artifact.request_hash != artifact.receipt.request_hash
                || keys[index]
                    != format!("{prefix}/artifacts/{:020}-{hash}.cbor", artifact.sequence)
                || heads[index] != format!("{prefix}/heads/{:020}-{hash}.cbor", artifact.sequence)
            {
                return Err("CHECKPOINT_ARCHIVE_PREFIX_INVALID".into());
            }
            root = artifact.state_hash.clone();
            hashes.push(hash);
            if artifact.sequence == anchor.sequence {
                last = Some(artifact.clone());
            }
            artifact.ciphertext = Vec::new();
            records.push(artifact);
        }
    }
    if root != anchor.state_hash {
        return Err("CHECKPOINT_VERIFIED_ANCHOR_HASH_DIFFERS".into());
    }
    let mut checkpoint = DirectCheckpoint {
        protocol: "layrs.direct-execution.checkpoint.v1".into(),
        opening_state_hash,
        artifact: last.ok_or("CHECKPOINT_HEAD_MISSING")?,
        receipt_records: records,
        artifact_hashes: hashes,
        bootstrap_certificate: None,
        signature: String::new(),
    };
    checkpoint.bootstrap_certificate = Some(
        CheckpointBootstrapCertificate::for_checkpoint(&checkpoint)
            .map_err(|_| "CHECKPOINT_CERTIFICATE_FAILED")?,
    );
    Ok(checkpoint)
}
async fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 4 || !["prepare", "certify"].contains(&args[1].as_str()) {
        return Err("USAGE_PREPARE_ANCHOR_OUTPUT_OR_CERTIFY_INPUT_OUTPUT".into());
    }
    let identity = std::process::Command::new("aws")
        .args([
            "--profile",
            "predifi-root",
            "--region",
            "us-east-1",
            "sts",
            "get-caller-identity",
            "--query",
            "Account",
            "--output",
            "text",
        ])
        .stderr(std::process::Stdio::null())
        .output()
        .map_err(|_| "CHECKPOINT_ACCOUNT_CHECK_FAILED")?;
    if !identity.status.success()
        || String::from_utf8_lossy(&identity.stdout).trim() != "082223548516"
    {
        return Err("CHECKPOINT_ACCOUNT_DENIED".into());
    }
    let configuration = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .profile_name("predifi-root")
        .region(aws_config::Region::new("us-east-1"))
        .load()
        .await;
    let input = fs::read(&args[2]).map_err(|_| "CHECKPOINT_INPUT_FAILED")?;
    if input.is_empty() || input.len() > FRAME_LIMIT {
        return Err("CHECKPOINT_INPUT_BOUND".into());
    }
    let checkpoint = if args[1] == "prepare" {
        prepare(
            &configuration,
            serde_json::from_slice(&input).map_err(|_| "CHECKPOINT_ANCHOR_INVALID")?,
        )
        .await?
    } else {
        let mut checkpoint: DirectCheckpoint =
            serde_cbor::from_slice(&input).map_err(|_| "CHECKPOINT_INPUT_INVALID")?;
        let expected = CheckpointBootstrapCertificate::for_checkpoint(&checkpoint)
            .map_err(|_| "CHECKPOINT_CERTIFICATE_FAILED")?;
        if !checkpoint.signature.is_empty()
            || checkpoint.bootstrap_certificate.as_ref() != Some(&expected)
        {
            return Err("CHECKPOINT_CERTIFICATE_CONTENT_CHANGED".into());
        }
        let result = aws_sdk_kms::Client::new(&configuration)
            .sign()
            .key_id(GOVERNANCE_KEY_ID)
            .signing_algorithm(aws_sdk_kms::types::SigningAlgorithmSpec::EcdsaSha256)
            .message_type(aws_sdk_kms::types::MessageType::Raw)
            .message(Blob::new(
                expected
                    .unsigned_bytes()
                    .map_err(|_| "CHECKPOINT_CERTIFICATE_FAILED")?,
            ))
            .send()
            .await
            .map_err(|_| "CHECKPOINT_GOVERNANCE_SIGN_FAILED")?;
        let mut certificate = expected;
        certificate.signature = STANDARD.encode(
            result
                .signature()
                .ok_or("CHECKPOINT_SIGNATURE_MISSING")?
                .as_ref(),
        );
        if !certificate.verify(&checkpoint) {
            return Err("CHECKPOINT_GOVERNANCE_KEY_MISMATCH".into());
        }
        checkpoint.bootstrap_certificate = Some(certificate);
        checkpoint
    };
    let bytes = serde_cbor::to_vec(&checkpoint).map_err(|_| "CHECKPOINT_ENCODING_FAILED")?;
    create_private(Path::new(&args[3]), &bytes)?;
    println!(
        "CHECKPOINT_{} sequence={} stateHash={} bytes={} financialWrites=false",
        args[1].to_uppercase(),
        checkpoint.artifact.sequence,
        checkpoint.artifact.state_hash,
        bytes.len()
    );
    Ok(())
}
#[tokio::main]
async fn main() {
    if let Err(code) = run().await {
        eprintln!("{code}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn anchor() -> Anchor {
        Anchor {
            protocol: "layrs.direct-execution.checkpoint-anchor.v1".into(),
            sequence: 4827,
            state_hash: "a".repeat(64),
            source_commit: "b".repeat(40),
            writer_grant_commitment: "c".repeat(64),
            full_history_restore_verified: true,
            all_balances_verified: true,
            nonce_bound_nitro_attestation_verified: true,
        }
    }
    #[test]
    fn bootstrap_requires_restore_balances_and_genuine_attestation() {
        assert!(valid_anchor(&anchor()));
        let mut changed = anchor();
        changed.full_history_restore_verified = false;
        assert!(!valid_anchor(&changed));
        let mut changed = anchor();
        changed.all_balances_verified = false;
        assert!(!valid_anchor(&changed));
        let mut changed = anchor();
        changed.nonce_bound_nitro_attestation_verified = false;
        assert!(!valid_anchor(&changed));
    }
    #[test]
    fn bootstrap_rejects_wrong_domain_zero_unbounded_sequence_and_unpinned_inputs() {
        let mut changed = anchor();
        changed.protocol = "writer-grant".into();
        assert!(!valid_anchor(&changed));
        let mut changed = anchor();
        changed.sequence = 0;
        assert!(!valid_anchor(&changed));
        let mut changed = anchor();
        changed.sequence = 100001;
        assert!(!valid_anchor(&changed));
        let mut changed = anchor();
        changed.state_hash = "A".repeat(64);
        assert!(!valid_anchor(&changed));
        let mut changed = anchor();
        changed.source_commit.clear();
        assert!(!valid_anchor(&changed));
        let mut changed = anchor();
        changed.writer_grant_commitment.clear();
        assert!(!valid_anchor(&changed));
    }
    #[test]
    fn checkpoint_output_is_private_and_cannot_overwrite_existing_evidence() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!(
            "layrs-checkpoint-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        create_private(&path, b"synthetic encrypted evidence").unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(create_private(&path, b"overwrite").is_err());
        assert_eq!(fs::read(&path).unwrap(), b"synthetic encrypted evidence");
        fs::remove_file(path).unwrap();
    }
}
