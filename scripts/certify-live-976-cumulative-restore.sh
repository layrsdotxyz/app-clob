#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/certify-live-976-cumulative-restore.sh \
    --client <authenticated-incident-restore-client> \
    --kms-key-id <kms-key-arn-or-alias> \
    --kms-ciphertext-blob <encrypted-journal-key> \
    --certifier-release-manifest <signed-release-manifest> \
    --expected-pcr0 <96-lowercase-hex> \
    --evidence-dir <existing-persistent-directory> \
    --snapshot-name <new-snapshot-basename.json> \
    --report-name <new-report-basename.json>

The client must implement the integrated BEGIN/COMPLETE_INCIDENT_TERMINAL_RESTORE
operator flow. This wrapper supplies only the exact immutable descriptor, raw
encrypted snapshot, KMS ciphertext and a fresh persistent challenge. It never
accepts plaintext keys, journals, /tmp paths, or an implicit report location.
EOF
}

client=""
kms_key_id=""
kms_ciphertext_blob=""
certifier_release_manifest=""
expected_pcr0=""
evidence_dir=""
snapshot_name=""
report_name=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --client) client="${2:-}"; shift 2 ;;
    --kms-key-id) kms_key_id="${2:-}"; shift 2 ;;
    --kms-ciphertext-blob) kms_ciphertext_blob="${2:-}"; shift 2 ;;
    --certifier-release-manifest) certifier_release_manifest="${2:-}"; shift 2 ;;
    --expected-pcr0) expected_pcr0="${2:-}"; shift 2 ;;
    --evidence-dir) evidence_dir="${2:-}"; shift 2 ;;
    --snapshot-name) snapshot_name="${2:-}"; shift 2 ;;
    --report-name) report_name="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument." >&2; usage >&2; exit 2 ;;
  esac
done

for value in "$client" "$kms_key_id" "$kms_ciphertext_blob" "$certifier_release_manifest" \
  "$expected_pcr0" "$evidence_dir" "$snapshot_name" "$report_name"; do
  [[ -n "$value" ]] || { usage >&2; exit 2; }
done
[[ -f "$kms_ciphertext_blob" && -f "$certifier_release_manifest" ]] || {
  echo "A required immutable input file is missing." >&2
  exit 2
}
[[ -x "$client" ]] || { echo "Incident restore client is not executable." >&2; exit 2; }
[[ -d "$evidence_dir" ]] || { echo "Evidence directory must already exist." >&2; exit 2; }
[[ "$evidence_dir" != /tmp && "$evidence_dir" != /tmp/* ]] || {
  echo "Evidence directory must not be under /tmp." >&2
  exit 2
}
[[ "$report_name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*\.json$ && "$report_name" != *..* ]] || {
  echo "Report name must be one safe JSON basename." >&2
  exit 2
}
[[ "$snapshot_name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*\.json$ && "$snapshot_name" != *..* ]] || {
  echo "Snapshot name must be one safe JSON basename." >&2
  exit 2
}
[[ "$expected_pcr0" =~ ^[0-9a-f]{96}$ ]] || {
  echo "Expected certifier PCR0 must be 96 lowercase hex characters." >&2
  exit 2
}
command -v jq >/dev/null || { echo "jq is required." >&2; exit 2; }
command -v aws >/dev/null || { echo "aws is required." >&2; exit 2; }
command -v openssl >/dev/null || { echo "openssl is required." >&2; exit 2; }
command -v sha256sum >/dev/null || { echo "sha256sum is required." >&2; exit 2; }

policy="$(dirname "$0")/../enclave/recovery-policies/2026-08-25-seq161919.json"
expected_policy_sha="64f95c19acaf1cc760c28b598fcd7609101f756a706357ec8ec7b7c2d1cc3d95"
[[ -f "$policy" && "$(sha256sum "$policy" | awk '{print $1}')" == "$expected_policy_sha" ]] || {
  echo "Embedded incident policy checksum mismatch." >&2
  exit 1
}
snapshot="$evidence_dir/$snapshot_name"
snapshot_metadata="$evidence_dir/${snapshot_name%.json}.s3-get-object.json"
[[ ! -e "$snapshot" && ! -e "$snapshot_metadata" ]] || {
  echo "Snapshot or S3 metadata evidence already exists; refusing overwrite." >&2
  exit 1
}
account="$(aws sts get-caller-identity --query Account --output text)"
[[ "$account" == "082223548516" ]] || {
  echo "AWS account is not the exact Layrs production account." >&2
  exit 1
}
umask 077
aws s3api get-object \
  --bucket "layrs-production-082223548516-us-east-1-immutable" \
  --key "enclave/snapshot/00000000000000161919-cb284d9b13bc8b17d20c75d44e4e3b68a1d29dec3a7a5b9fd80871f340ea8da9.json" \
  --version-id "nHXxPKfOHWlyZ1UzcYeBjFpXLzq2c1Bu" \
  --checksum-mode ENABLED \
  "$snapshot" > "$snapshot_metadata"
jq -e '
  .VersionId == "nHXxPKfOHWlyZ1UzcYeBjFpXLzq2c1Bu" and
  .ContentLength == 39930295 and
  .ChecksumSHA256 == "koOjIAfZbCumcL8JMZHY5hmvItqIi+pOzlWcZZ5o0pA=" and
  .ServerSideEncryption == "aws:kms" and
  .Metadata["content-sha256"] == "9283a32007d96c2ba670bf093191d8e619af22da888bea4ece559c659e68d290"
' "$snapshot_metadata" >/dev/null || {
  echo "Exact S3 VersionId metadata mismatch." >&2
  exit 1
}
[[ "$(wc -c < "$snapshot" | tr -d ' ')" == "39930295" ]] || {
  echo "Exact terminal snapshot size mismatch." >&2
  exit 1
}
[[ "$(sha256sum "$snapshot" | awk '{print $1}')" == \
  "9283a32007d96c2ba670bf093191d8e619af22da888bea4ece559c659e68d290" ]] || {
  echo "Exact terminal snapshot body checksum mismatch." >&2
  exit 1
}

report="$evidence_dir/$report_name"
challenge_file="$evidence_dir/${report_name%.json}.challenge"
[[ ! -e "$report" && ! -e "$challenge_file" ]] || {
  echo "Report or challenge evidence already exists; refusing overwrite." >&2
  exit 1
}
challenge="$(openssl rand -hex 32)"
set -o noclobber
printf '%s\n' "$challenge" > "$challenge_file"
set +o noclobber

"$client" incident-terminal-restore \
  --snapshot "$snapshot" \
  --bucket "layrs-production-082223548516-us-east-1-immutable" \
  --key "enclave/snapshot/00000000000000161919-cb284d9b13bc8b17d20c75d44e4e3b68a1d29dec3a7a5b9fd80871f340ea8da9.json" \
  --version-id "nHXxPKfOHWlyZ1UzcYeBjFpXLzq2c1Bu" \
  --kms-key-id "$kms_key_id" \
  --kms-ciphertext-blob "$kms_ciphertext_blob" \
  --external-challenge "$challenge" \
  --certifier-release-manifest "$certifier_release_manifest" \
  --expected-pcr0 "$expected_pcr0" \
  --output "$report"

[[ -f "$report" ]] || { echo "Client did not create the requested report." >&2; exit 1; }
jq -e --arg policy "$expected_policy_sha" '
  .type == "INCIDENT_TERMINAL_RESTORE_CERTIFIED" and
  .envelope.certificate.incidentPolicySha256 == $policy and
  .envelope.certificate.sourceReleaseCommit == "97614f37c05089708f93bf50ac8831adde98ab2f" and
  .envelope.certificate.snapshotVersionId == "nHXxPKfOHWlyZ1UzcYeBjFpXLzq2c1Bu" and
  .envelope.certificate.restoredSequence == 161919 and
  .envelope.certificate.restoredStateRoot == "647bc1b6a8f48caf6460b8cafc20baedbb208815dc52c88e9bdde70191c67f6a" and
  .envelope.certificate.restoredJournalHead == "02c52dce702bd2e7e83b96bbe82f0169fc2fa961eef1c50ed5dc455cdd43c881" and
  .envelope.certificate.artifactEqual == true and
  .envelope.certificate.policyEqual == true and
  .envelope.certificate.sourceReleaseEqual == true and
  .envelope.certificate.certifierPcr0Equal == true and
  .envelope.certificate.sequenceEqual == true and
  .envelope.certificate.stateRootEqual == true and
  .envelope.certificate.journalHeadEqual == true and
  .envelope.certificate.aggregateTotalsEqual == true and
  .envelope.certificate.aggregateTotalsZeroDelta == true and
  .envelope.certificate.restoreFloorPersisted == true and
  .envelope.certificate.noExternalStateMutationPerformed == true and
  .envelope.certificate.historicalJournalReplayPerformed == false and
  .envelope.certificate.historicalFillCompletenessCertified == false and
  (.envelope.attestationDocumentSha256 | test("^[0-9a-f]{64}$"))
' "$report" >/dev/null || {
  echo "Incident terminal restore certificate failed closed." >&2
  exit 1
}

jq '{status:"PASS_INCIDENT_TERMINAL_RESTORE_ONLY",certificate:.envelope.certificate,certificateSha256:.envelope.certificateSha256,artifactBindingSha256:.envelope.artifactBindingSha256,attestationDocumentSha256:.envelope.attestationDocumentSha256}' "$report"
