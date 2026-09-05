#!/usr/bin/env bash
set -euo pipefail

if [[ -n "${CI_MERGE_REQUEST_TARGET_BRANCH_NAME:-}" ]]; then
  target_branch="$CI_MERGE_REQUEST_TARGET_BRANCH_NAME"
  git check-ref-format --branch "$target_branch" >/dev/null
  base_ref="origin/$target_branch"
  git fetch --no-tags origin "$target_branch:refs/remotes/$base_ref"
  default_base="$(git rev-parse "${base_ref}^{commit}")"
else
  base_ref="origin/main"
  git fetch --no-tags origin main:refs/remotes/origin/main || true
  default_base="$(git merge-base "$base_ref" HEAD 2>/dev/null || git rev-parse HEAD^)"
fi

mapfile -t migration_docs < <(
  git diff --name-only --diff-filter=ACMRTUXB "$base_ref...HEAD" -- \
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
selected_cumulative="false"
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
  candidate_cumulative="false"
  if grep -q 'CUMULATIVE_STATE_MIGRATION:[[:space:]]*true' "$candidate_doc"; then
    candidate_cumulative="true"
  fi
  if [[ -z "$selected_distance" \
    || "$candidate_cumulative" == "true" && "$selected_cumulative" != "true" \
    || "$candidate_cumulative" == "$selected_cumulative" && "$candidate_distance" -lt "$selected_distance" ]]; then
    selected_doc="$candidate_doc"
    declared_base="$candidate_base"
    selected_distance="$candidate_distance"
    selected_cumulative="$candidate_cumulative"
  fi
done

if [[ -z "$selected_doc" ]]; then
  echo "No changed migration document identifies an available release commit." >&2
  exit 1
fi

exec scripts/check-enclave-snapshot-compatibility.sh \
  --base "$declared_base" \
  --mode ci \
  --allow-state-schema-change
