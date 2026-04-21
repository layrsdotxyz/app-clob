#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${SCRIPT_DIR}"

echo "[privacy-gate] Running EIP-712 cryptographic checks"
cargo test eip712 -- --nocapture

echo "[privacy-gate] Running nonce/replay checks"
cargo test chain_types -- --nocapture

echo "[privacy-gate] Building Foundry contracts"
cd "${ROOT_DIR}/contracts"
forge build

cd "${SCRIPT_DIR}"
echo "[privacy-gate] Running privacy integration/runtime checks"
cargo test --features integration-tests -- --ignored --nocapture

echo "[privacy-gate] ✅ All privacy gates passed"
