#!/usr/bin/env bash
set -euo pipefail

if [[ ${#LAYRS_OPERATOR_PUBLIC_KEY_HEX:-0} -ne 64 ]]; then
  echo "LAYRS_OPERATOR_PUBLIC_KEY_HEX must be a 32-byte hex Ed25519 key" >&2
  exit 1
fi

mkdir -p build
parent_image="${LAYRS_PARENT_IMAGE_TAG:-layrsv2-enclave-parent:build}"
docker build --file enclave/Dockerfile.parent --tag "${parent_image}" .
container_id=$(docker create "${parent_image}")
cleanup() { docker rm -f "${container_id}" >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker cp "${container_id}:/usr/local/bin/layrs-enclave-parent" build/layrs-enclave-parent
chmod 0755 build/layrs-enclave-parent
LAYRS_EIF_OUTPUT=build/layrsv2-clob.eif \
LAYRS_MEASUREMENT_OUTPUT=build/layrsv2-clob-measurements.json \
  enclave/build-eif.sh
sha384sum build/layrs-enclave-parent build/layrsv2-clob.eif > build/layrsv2-host-artifacts.sha384
chmod 0600 build/layrsv2-clob.eif build/layrsv2-clob-measurements.json build/layrsv2-host-artifacts.sha384
