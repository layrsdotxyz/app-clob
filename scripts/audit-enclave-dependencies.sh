#!/usr/bin/env bash
set -euo pipefail

readonly INACTIVE_RKYV_ADVISORY="RUSTSEC-2026-0235"

# rust_decimal declares rkyv as an optional dependency, so Cargo records it in
# Cargo.lock even when the enclave does not compile or link it. Keep the audit
# exception valid only while rkyv remains absent from the active dependency
# graph. If a future feature activates rkyv, fail before cargo-audit is run.
if cargo tree \
  --manifest-path enclave/runtime/Cargo.toml \
  --locked \
  --target all \
  -e all \
  -i rkyv 2>/dev/null | grep -q '[^[:space:]]'; then
  echo "rkyv is active in the enclave dependency graph; remove the ${INACTIVE_RKYV_ADVISORY} exception" >&2
  exit 1
fi

cargo audit \
  --file enclave/runtime/Cargo.lock \
  --ignore "${INACTIVE_RKYV_ADVISORY}"
cargo audit --file enclave/parent-runtime/Cargo.lock
