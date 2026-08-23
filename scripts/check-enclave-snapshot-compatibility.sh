#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/check-enclave-snapshot-compatibility.sh --base <commit-ish> [--head <commit-ish>] [--mode ci|release] [--allow-state-schema-change|--allow-stateless-terminal-recovery]

Purpose:
  Prevent an enclave transport/provisioning hotfix from accidentally carrying
  private-core state or journal changes that can break production snapshot replay.

Examples:
  scripts/check-enclave-snapshot-compatibility.sh --base "$GITHUB_BASE_SHA"
  scripts/check-enclave-snapshot-compatibility.sh --base e0473171 --head HEAD --mode release
  scripts/check-enclave-snapshot-compatibility.sh --base e0473171 --allow-state-schema-change
EOF
}

base_ref=""
head_ref="HEAD"
mode="ci"
allow_state_schema_change="false"
allow_stateless_terminal_recovery="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --base)
      base_ref="${2:-}"
      shift 2
      ;;
    --head)
      head_ref="${2:-}"
      shift 2
      ;;
    --mode)
      mode="${2:-}"
      shift 2
      ;;
    --allow-state-schema-change)
      allow_state_schema_change="true"
      shift
      ;;
    --allow-stateless-terminal-recovery)
      allow_stateless_terminal_recovery="true"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "$base_ref" ]]; then
  echo "Missing required --base <commit-ish>." >&2
  usage >&2
  exit 2
fi

if [[ "$mode" != "ci" && "$mode" != "release" ]]; then
  echo "--mode must be ci or release; got: $mode" >&2
  exit 2
fi
if [[ "$allow_state_schema_change" == "true" && "$allow_stateless_terminal_recovery" == "true" ]]; then
  echo "Choose only one snapshot compatibility exception mode." >&2
  exit 2
fi

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

if ! git rev-parse --verify --quiet "${base_ref}^{commit}" >/dev/null; then
  echo "Base ref does not resolve to a commit: $base_ref" >&2
  exit 2
fi

if ! git rev-parse --verify --quiet "${head_ref}^{commit}" >/dev/null; then
  echo "Head ref does not resolve to a commit: $head_ref" >&2
  exit 2
fi

base_sha="$(git rev-parse "${base_ref}^{commit}")"
head_sha="$(git rev-parse "${head_ref}^{commit}")"

if [[ "$base_sha" == "$head_sha" ]]; then
  echo "enclave snapshot compatibility: OK — base and head are identical ($head_sha)."
  exit 0
fi

if git merge-base --is-ancestor "$base_sha" "$head_sha"; then
  diff_range="${base_sha}..${head_sha}"
else
  diff_range="${base_sha}...${head_sha}"
fi

mapfile -t changed_files < <(git diff --name-only --diff-filter=ACMRTUXB "$diff_range" | sort)

if [[ "${#changed_files[@]}" -eq 0 ]]; then
  echo "enclave snapshot compatibility: OK — no changed files in $diff_range."
  exit 0
fi

snapshot_sensitive_regex='^(src/private_core/|enclave/runtime/src/|enclave/snapshot-schema/)'
transport_sensitive_regex='^(src/bin/layrs-enclave\.rs|enclave/(Dockerfile|Dockerfile\.parent|build-eif\.sh|build-host-artifacts\.sh|packer/|parent-runtime/|runtime/))'
migration_doc_regex='^enclave/snapshot-migrations/[^/]+\.md$'

snapshot_sensitive_files=()
transport_sensitive_files=()
migration_docs=()

for file in "${changed_files[@]}"; do
  if [[ "$file" =~ $snapshot_sensitive_regex ]]; then
    snapshot_sensitive_files+=("$file")
  fi
  if [[ "$file" =~ $transport_sensitive_regex ]]; then
    transport_sensitive_files+=("$file")
  fi
  if [[ "$file" =~ $migration_doc_regex && "$file" != "enclave/snapshot-migrations/README.md" ]]; then
    migration_docs+=("$file")
  fi
done

if [[ "${#transport_sensitive_files[@]}" -gt 0 ]]; then
  echo "enclave release-surface files changed in $diff_range:"
  printf '  - %s\n' "${transport_sensitive_files[@]}"
fi

if [[ "${#snapshot_sensitive_files[@]}" -eq 0 ]]; then
  echo "enclave snapshot compatibility: OK — no private-core/runtime state-surface files changed."
  exit 0
fi

echo "enclave snapshot compatibility: BLOCKED — snapshot-sensitive files changed in $diff_range:"
printf '  - %s\n' "${snapshot_sensitive_files[@]}"

if [[ "$allow_stateless_terminal_recovery" == "true" ]]; then
  allowed_recovery_files_regex='^src/private_core/(engine|journal|mod|session)\.rs$'
  unexpected_recovery_files=()
  for file in "${snapshot_sensitive_files[@]}"; do
    if [[ ! "$file" =~ $allowed_recovery_files_regex ]]; then
      unexpected_recovery_files+=("$file")
    fi
  done
  if [[ "${#unexpected_recovery_files[@]}" -gt 0 ]]; then
    echo "Stateless terminal recovery touched an unapproved state-surface file:" >&2
    printf '  - %s\n' "${unexpected_recovery_files[@]}" >&2
    exit 1
  fi
  approved_doc=""
  for doc in "${migration_docs[@]}"; do
    if git grep -q 'STATE_SCHEMA_UNCHANGED:[[:space:]]*true' "${head_sha}" -- "$doc" \
      && git grep -q 'STATE_ROOT_MATERIAL_UNCHANGED:[[:space:]]*true' "${head_sha}" -- "$doc" \
      && git grep -q 'TERMINAL_RECOVERY_ONLY:[[:space:]]*true' "${head_sha}" -- "$doc" \
      && git grep -q "BASE_RELEASE_COMMIT:[[:space:]]*${base_sha}" "${head_sha}" -- "$doc" \
      && git grep -q 'EXACT_SNAPSHOT_TEST:[[:space:]]*exact_terminal_snapshot_reissues_withdrawal_proof_without_state_change' "${head_sha}" -- "$doc"; then
      approved_doc="$doc"
      break
    fi
  done
  if [[ -z "$approved_doc" ]]; then
    echo "No changed recovery document contains the required stateless terminal-recovery markers." >&2
    exit 1
  fi
  echo "enclave snapshot compatibility: APPROVED stateless terminal recovery via $approved_doc."
  exit 0
fi

if [[ "$allow_state_schema_change" != "true" ]]; then
  cat >&2 <<'EOF'

This is the guard that would have caught the replay-hotfix incident:
a transport fix must not silently include private CLOB engine, journal, ledger,
session, runtime state, or snapshot schema changes.

If this is a pure hotfix, branch from the live app-clob release and exclude these files.
If this is an intentional state/schema migration, re-run with
--allow-state-schema-change and include a new migration document under:
  enclave/snapshot-migrations/*.md

The migration document must include:
  SNAPSHOT_SCHEMA_CHANGE_APPROVED: true
  BASE_RELEASE_COMMIT: <the exact deployed app-clob base commit>
  PRODUCTION_REPLAY_PLAN: true
  ROLLBACK_PLAN: true
EOF
  exit 1
fi

if [[ "${#migration_docs[@]}" -eq 0 ]]; then
  echo "No migration document changed under enclave/snapshot-migrations/*.md." >&2
  exit 1
fi

approved_doc=""
for doc in "${migration_docs[@]}"; do
  if git grep -q 'SNAPSHOT_SCHEMA_CHANGE_APPROVED:[[:space:]]*true' "${head_sha}" -- "$doc" \
    && git grep -q "BASE_RELEASE_COMMIT:[[:space:]]*${base_sha}" "${head_sha}" -- "$doc" \
    && git grep -q 'PRODUCTION_REPLAY_PLAN:[[:space:]]*true' "${head_sha}" -- "$doc" \
    && git grep -q 'ROLLBACK_PLAN:[[:space:]]*true' "${head_sha}" -- "$doc"; then
    approved_doc="$doc"
    break
  fi
done

if [[ -z "$approved_doc" ]]; then
  cat >&2 <<EOF
No changed migration document contains the required approval markers for base:
  $base_sha

Changed migration docs checked:
$(printf '  - %s\n' "${migration_docs[@]}")
EOF
  exit 1
fi

echo "enclave snapshot compatibility: APPROVED intentional state/schema change via $approved_doc."
exit 0
