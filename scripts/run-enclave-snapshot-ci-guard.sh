#!/usr/bin/env bash
set -euo pipefail

git fetch --no-tags origin main:refs/remotes/origin/main || true
default_base="$(git merge-base origin/main HEAD 2>/dev/null || git rev-parse HEAD^)"

mapfile -t migration_docs < <(
  git diff --name-only --diff-filter=ACMRTUXB "origin/main...HEAD" -- \
    'enclave/snapshot-migrations/*.md' \
    | grep -v '/README\.md$' \
    | sort
)

if [[ "${#migration_docs[@]}" -eq 0 ]]; then
  exec scripts/check-enclave-snapshot-compatibility.sh \
    --base "$default_base" \
    --mode ci
fi

selected_doc=""
declared_base=""
selected_distance=""
for candidate_doc in "${migration_docs[@]}"; do
  candidate_base="$(
    sed -n 's/^BASE_RELEASE_COMMIT:[[:space:]]*//p' "$candidate_doc" \
      | head -n 1 \
      | tr -d '[:space:]'
  )"
  [[ "$candidate_base" =~ ^[0-9a-f]{40}$ ]] || continue
  git fetch --no-tags origin "$candidate_base" || true
  git cat-file -e "${candidate_base}^{commit}" 2>/dev/null || continue
  # Production EIFs are cut from immutable release branches, so the exact
  # deployed commit need not be an ancestor of main. The compatibility checker
  # deliberately supports both linear and divergent histories; retain that
  # property here instead of silently substituting main's merge base.
  if git merge-base --is-ancestor "$candidate_base" HEAD; then
    candidate_distance="$(git rev-list --count "${candidate_base}..HEAD")"
  else
    candidate_distance="$(git rev-list --count "${candidate_base}...HEAD")"
  fi
  if [[ -z "$selected_distance" || "$candidate_distance" -lt "$selected_distance" ]]; then
    selected_doc="$candidate_doc"
    declared_base="$candidate_base"
    selected_distance="$candidate_distance"
  fi
done

if [[ -z "$selected_doc" ]]; then
  echo "No changed migration document identifies an available release commit." >&2
  exit 1
fi

exception_flag="--allow-state-schema-change"
if grep -Eq '^TERMINAL_RECOVERY_ONLY:[[:space:]]*true[[:space:]]*$' "$selected_doc"; then
  exception_flag="--allow-stateless-terminal-recovery"
fi

exec scripts/check-enclave-snapshot-compatibility.sh \
  --base "$declared_base" \
  --mode ci \
  "$exception_flag"
