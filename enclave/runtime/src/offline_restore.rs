use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{BufReader, Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use aws_nitro_enclaves_nsm_api::{
    api::{Request as NsmRequest, Response as NsmResponse},
    driver::{nsm_exit, nsm_init, nsm_process_request},
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use clob_service::private_core::{
    EncryptedJournalRecord, EncryptedSnapshot, ExactLive976CheckpointBinding,
    ExactLive976RestoreReport, JournalKey, PrivateTradingCore, ReceiptSigner,
    EXACT_LIVE_976_RELEASE_COMMIT,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

const DEFAULT_KEY_FD: i32 = 3;

#[derive(Debug)]
struct Arguments {
    snapshot: PathBuf,
    journal: PathBuf,
    checkpoint: PathBuf,
    report: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Checkpoint {
    source_release_commit: String,
    sequence: u64,
    state_root: String,
    journal_head: String,
    snapshot_sha256: String,
    journal_sha256: String,
    eif_sha384: String,
    pcr0: String,
    pcr1: String,
    pcr2: String,
    parent_ami_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum JournalExport {
    Records(Vec<EncryptedJournalRecord>),
    Envelope {
        records: Vec<EncryptedJournalRecord>,
    },
}

impl JournalExport {
    fn into_records(self) -> Vec<EncryptedJournalRecord> {
        match self {
            Self::Records(records) | Self::Envelope { records } => records,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AttestedReport {
    #[serde(flatten)]
    equality: ExactLive976RestoreReport,
    evidence_sha256: String,
    artifact_binding_sha256: String,
    attestation_document_sha256: String,
    attestation_document_base64: String,
}

struct NsmGuard(i32);

impl Drop for NsmGuard {
    fn drop(&mut self) {
        nsm_exit(self.0);
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = parse_arguments()?;
    require_regular_file(&arguments.snapshot)?;
    require_regular_file(&arguments.journal)?;
    require_regular_file(&arguments.checkpoint)?;
    require_regular_file(&arguments.report)?;

    let nsm = NsmGuard(nsm_init());
    if nsm.0 < 0 {
        return Err("Nitro Secure Module is unavailable".into());
    }
    let pcr0: [u8; 48] = match nsm_process_request(nsm.0, NsmRequest::DescribePCR { index: 0 }) {
        NsmResponse::DescribePCR { data, .. } => data
            .try_into()
            .map_err(|_| "NSM PCR0 is not a SHA-384 measurement")?,
        _ => return Err("unable to read NSM PCR0".into()),
    };

    let checkpoint_bytes = fs::read(&arguments.checkpoint)?;
    let checkpoint: Checkpoint = serde_json::from_slice(&checkpoint_bytes)?;
    validate_checkpoint_shape(&checkpoint)?;
    let checkpoint_sha256 = sha256_hex(&checkpoint_bytes);

    let snapshot_bytes = fs::read(&arguments.snapshot)?;
    let journal_bytes = fs::read(&arguments.journal)?;
    if sha256_hex(&snapshot_bytes) != checkpoint.snapshot_sha256
        || sha256_hex(&journal_bytes) != checkpoint.journal_sha256
    {
        return Err("artifact checksum does not match checkpoint".into());
    }
    let snapshot: EncryptedSnapshot = serde_json::from_slice(&snapshot_bytes)?;
    let records =
        serde_json::from_reader::<_, JournalExport>(BufReader::new(journal_bytes.as_slice()))?
            .into_records();

    let mut key_bytes = read_journal_key_from_inherited_fd()?;
    let journal_key = JournalKey::from_bytes(key_bytes);
    key_bytes.zeroize();
    let equality = PrivateTradingCore::certify_exact_live_976_restore(
        journal_key,
        ReceiptSigner::generate(pcr0),
        &snapshot,
        &records,
        ExactLive976CheckpointBinding {
            source_release_commit: checkpoint.source_release_commit,
            checkpoint_sha256,
            sequence: checkpoint.sequence,
            state_root: decode_hex_array(&checkpoint.state_root, "stateRoot")?,
            journal_head: decode_hex_array(&checkpoint.journal_head, "journalHead")?,
        },
    )?;

    let equality_bytes = serde_json::to_vec(&equality)?;
    let evidence_sha256 = Sha256::digest(&equality_bytes);
    let artifact_binding = artifact_binding(
        &snapshot_bytes,
        &journal_bytes,
        &checkpoint_bytes,
        &evidence_sha256,
    );
    let document = match nsm_process_request(
        nsm.0,
        NsmRequest::Attestation {
            user_data: Some(evidence_sha256.to_vec().into()),
            nonce: Some(artifact_binding.to_vec().into()),
            public_key: None,
        },
    ) {
        NsmResponse::Attestation { document } => document,
        _ => return Err("NSM equality-report attestation failed".into()),
    };
    let attested = AttestedReport {
        equality,
        evidence_sha256: hex::encode(evidence_sha256),
        artifact_binding_sha256: hex::encode(artifact_binding),
        attestation_document_sha256: sha256_hex(&document),
        attestation_document_base64: BASE64.encode(document),
    };
    write_report(&arguments.report, &serde_json::to_vec(&attested)?)?;
    Ok(())
}

fn parse_arguments() -> Result<Arguments, Box<dyn std::error::Error>> {
    let mut snapshot = None;
    let mut journal = None;
    let mut checkpoint = None;
    let mut report = None;
    let mut arguments = env::args_os().skip(1);
    while let Some(argument) = arguments.next() {
        let value = arguments.next().ok_or("argument value is missing")?;
        match argument.to_str() {
            Some("--snapshot") if snapshot.is_none() => snapshot = Some(value.into()),
            Some("--journal") if journal.is_none() => journal = Some(value.into()),
            Some("--checkpoint") if checkpoint.is_none() => checkpoint = Some(value.into()),
            Some("--report") if report.is_none() => report = Some(value.into()),
            _ => return Err("unknown or duplicate argument".into()),
        }
    }
    Ok(Arguments {
        snapshot: snapshot.ok_or("--snapshot is required")?,
        journal: journal.ok_or("--journal is required")?,
        checkpoint: checkpoint.ok_or("--checkpoint is required")?,
        report: report.ok_or("--report is required")?,
    })
}

fn require_regular_file(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if !fs::symlink_metadata(path)?.file_type().is_file() {
        return Err(format!("artifact path is not a regular file: {}", path.display()).into());
    }
    Ok(())
}

fn validate_checkpoint_shape(checkpoint: &Checkpoint) -> Result<(), Box<dyn std::error::Error>> {
    if checkpoint.source_release_commit != EXACT_LIVE_976_RELEASE_COMMIT
        || checkpoint.sequence == 0
        || !is_lower_hex(&checkpoint.state_root, 64)
        || !is_lower_hex(&checkpoint.journal_head, 64)
        || !is_lower_hex(&checkpoint.snapshot_sha256, 64)
        || !is_lower_hex(&checkpoint.journal_sha256, 64)
        || !is_lower_hex(&checkpoint.eif_sha384, 96)
        || !is_lower_hex(&checkpoint.pcr0, 96)
        || !is_lower_hex(&checkpoint.pcr1, 96)
        || !is_lower_hex(&checkpoint.pcr2, 96)
        || !checkpoint.parent_ami_id.starts_with("ami-")
        || checkpoint.parent_ami_id.len() <= 4
        || !is_lower_hex(
            &checkpoint.parent_ami_id[4..],
            checkpoint.parent_ami_id.len() - 4,
        )
    {
        return Err("checkpoint shape is invalid or not exact live 976".into());
    }
    Ok(())
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn decode_hex_array<const N: usize>(
    value: &str,
    field: &str,
) -> Result<[u8; N], Box<dyn std::error::Error>> {
    hex::decode(value)?
        .try_into()
        .map_err(|_| format!("{field} has the wrong length").into())
}

fn read_journal_key_from_inherited_fd() -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let fd = match env::var("LAYRS_OFFLINE_RESTORE_KEY_FD") {
        Ok(value) => value.parse::<i32>()?,
        Err(_) => DEFAULT_KEY_FD,
    };
    if fd < 3 {
        return Err("journal-key descriptor must not be stdin, stdout or stderr".into());
    }
    let mut key = Vec::with_capacity(33);
    File::open(format!("/proc/self/fd/{fd}"))?
        .take(33)
        .read_to_end(&mut key)?;
    if key.len() != 32 {
        key.zeroize();
        return Err("journal-key descriptor must contain exactly 32 bytes".into());
    }
    let result = key.as_slice().try_into()?;
    key.zeroize();
    Ok(result)
}

fn artifact_binding(
    snapshot: &[u8],
    journal: &[u8],
    checkpoint: &[u8],
    evidence_sha256: &[u8],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"layrs.attested-offline-restore.v1\0");
    hash.update(Sha256::digest(snapshot));
    hash.update(Sha256::digest(journal));
    hash.update(Sha256::digest(checkpoint));
    hash.update(evidence_sha256);
    hash.finalize().into()
}

fn sha256_hex(value: &[u8]) -> String {
    hex::encode(Sha256::digest(value))
}

fn write_report(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_checkpoint() -> Checkpoint {
        Checkpoint {
            source_release_commit: EXACT_LIVE_976_RELEASE_COMMIT.into(),
            sequence: 159_300,
            state_root: "11".repeat(32),
            journal_head: "22".repeat(32),
            snapshot_sha256: "33".repeat(32),
            journal_sha256: "44".repeat(32),
            eif_sha384: "55".repeat(48),
            pcr0: "66".repeat(48),
            pcr1: "77".repeat(48),
            pcr2: "88".repeat(48),
            parent_ami_id: "ami-0123456789abcdef0".into(),
        }
    }

    #[test]
    fn checkpoint_validation_is_bound_to_exact_976_and_complete_measurements() {
        assert!(validate_checkpoint_shape(&valid_checkpoint()).is_ok());

        let mut wrong_release = valid_checkpoint();
        wrong_release.source_release_commit = "00".repeat(20);
        assert!(validate_checkpoint_shape(&wrong_release).is_err());

        let mut missing_ami = valid_checkpoint();
        missing_ami.parent_ami_id = "ami-".into();
        assert!(validate_checkpoint_shape(&missing_ami).is_err());
    }

    #[test]
    fn attestation_nonce_binding_changes_for_every_certification_input() {
        let baseline = artifact_binding(b"snapshot", b"journal", b"checkpoint", &[9; 32]);
        assert_ne!(
            baseline,
            artifact_binding(b"snapshot-2", b"journal", b"checkpoint", &[9; 32])
        );
        assert_ne!(
            baseline,
            artifact_binding(b"snapshot", b"journal-2", b"checkpoint", &[9; 32])
        );
        assert_ne!(
            baseline,
            artifact_binding(b"snapshot", b"journal", b"checkpoint-2", &[9; 32])
        );
        assert_ne!(
            baseline,
            artifact_binding(b"snapshot", b"journal", b"checkpoint", &[8; 32])
        );
    }
}
