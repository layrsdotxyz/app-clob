#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/certify-live-976-cumulative-restore.sh \
    --snapshot <encrypted-snapshot> \
    --journal <immutable-journal-export> \
    --checkpoint <checkpoint.json> \
    --runner <attested-offline-restore-runner>

The runner receives the same four artifact paths plus --report <temporary-path>.
It must write the privacy-safe JSON report described in the cumulative migration
document. This wrapper never accepts keys and never decrypts account data.
EOF
}

snapshot=""
journal=""
checkpoint=""
runner=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --snapshot) snapshot="${2:-}"; shift 2 ;;
    --journal) journal="${2:-}"; shift 2 ;;
    --checkpoint) checkpoint="${2:-}"; shift 2 ;;
    --runner) runner="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

for value in "$snapshot" "$journal" "$checkpoint" "$runner"; do
  [[ -n "$value" ]] || { usage >&2; exit 2; }
done
[[ -f "$snapshot" && -f "$journal" && -f "$checkpoint" ]] || {
  echo "Snapshot, journal, or checkpoint file is missing." >&2
  exit 2
}
[[ -x "$runner" ]] || { echo "Restore runner is not executable: $runner" >&2; exit 2; }
command -v jq >/dev/null || { echo "jq is required." >&2; exit 2; }
command -v sha256sum >/dev/null || { echo "sha256sum is required." >&2; exit 2; }

expected_release="97614f37c05089708f93bf50ac8831adde98ab2f"
jq -e --arg release "$expected_release" '
  .sourceReleaseCommit == $release and
  (.sequence | type == "number") and .sequence >= 0 and
  (.stateRoot | test("^[0-9a-f]{64}$")) and
  (.journalHead | test("^[0-9a-f]{64}$")) and
  (.snapshotSha256 | test("^[0-9a-f]{64}$")) and
  (.journalSha256 | test("^[0-9a-f]{64}$")) and
  (.eifSha384 | test("^[0-9a-f]{96}$")) and
  (.pcr0 | test("^[0-9a-f]{96}$")) and
  (.pcr1 | test("^[0-9a-f]{96}$")) and
  (.pcr2 | test("^[0-9a-f]{96}$")) and
  (.parentAmiId | test("^ami-[0-9a-f]+$"))
' "$checkpoint" >/dev/null || {
  echo "Checkpoint is incomplete or is not bound to exact live release $expected_release." >&2
  exit 1
}

snapshot_sha="$(sha256sum "$snapshot" | awk '{print $1}')"
journal_sha="$(sha256sum "$journal" | awk '{print $1}')"
checkpoint_sha="$(sha256sum "$checkpoint" | awk '{print $1}')"
[[ "$snapshot_sha" == "$(jq -r .snapshotSha256 "$checkpoint")" ]] || {
  echo "Encrypted snapshot checksum mismatch." >&2
  exit 1
}
[[ "$journal_sha" == "$(jq -r .journalSha256 "$checkpoint")" ]] || {
  echo "Immutable journal checksum mismatch." >&2
  exit 1
}

report="$(mktemp)"
trap 'rm -f "$report"' EXIT
"$runner" \
  --snapshot "$snapshot" \
  --journal "$journal" \
  --checkpoint "$checkpoint" \
  --report "$report"

jq -e --arg release "$expected_release" --arg checkpoint "$checkpoint_sha" '
  .sourceReleaseCommit == $release and
  .checkpointSha256 == $checkpoint and
  .sourceCheckpointEqual == true and
  .sequenceEqual == true and
  .journalHeadEqual == true and
  .stateRootEqual == true and
  .usersEqual == true and
  .availableBalancesEqual == true and
  .orderHoldsEqual == true and
  .withdrawalHoldsEqual == true and
  .positionsEqual == true and
  .ordersEqual == true and
  .fillsEqual == true and
  .resolutionsEqual == true and
  .rewardsEqual == true and
  .feesEqual == true and
  .marketsEqual == true and
  .replayKeysEqual == true and
  (.legacyZeroBalanceCount | type == "number") and
  (.qualifiedTotalsDigest | test("^[0-9a-f]{64}$")) and
  (.userStateDigest | test("^[0-9a-f]{64}$")) and
  (.poolCashOpeningRequired | type == "boolean") and
  (.evidenceSha256 | test("^[0-9a-f]{64}$")) and
  (.artifactBindingSha256 | test("^[0-9a-f]{64}$")) and
  (.attestationDocumentSha256 | test("^[0-9a-f]{64}$")) and
  (.attestationDocumentBase64 | type == "string") and
  (.attestationDocumentBase64 | length > 128)
' "$report" >/dev/null || {
  echo "Exact-live cumulative restore certification failed closed." >&2
  jq '{sourceCheckpointEqual,sequenceEqual,journalHeadEqual,stateRootEqual,usersEqual,availableBalancesEqual,orderHoldsEqual,withdrawalHoldsEqual,positionsEqual,ordersEqual,fillsEqual,resolutionsEqual,rewardsEqual,feesEqual,marketsEqual,replayKeysEqual,legacyZeroBalanceCount,poolCashOpeningRequired}' "$report" >&2 || true
  exit 1
}

jq '{status:"PASS_OFFLINE_RESTORE_ONLY",sourceReleaseCommit,sourceCheckpointEqual,sequenceEqual,journalHeadEqual,stateRootEqual,legacyZeroBalanceCount,poolCashOpeningRequired,qualifiedTotalsDigest,userStateDigest,evidenceSha256,artifactBindingSha256,attestationDocumentSha256,attestationDocumentBase64}' "$report"
