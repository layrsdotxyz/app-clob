#!/usr/bin/env bash
set -euo pipefail

if [[ ${#LAYRS_OPERATOR_PUBLIC_KEY_HEX:-0} -ne 64 ]]; then
  echo "LAYRS_OPERATOR_PUBLIC_KEY_HEX must be a 32-byte hex Ed25519 key" >&2
  exit 1
fi

if [[ ${LAYRS_OPERATOR_PUBLIC_KEY_HEX} == d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a ]]; then
  echo "Refusing to build a release EIF with the documented test operator key" >&2
  exit 1
fi

image_tag=${LAYRS_ENCLAVE_IMAGE_TAG:-layrsv2-clob-enclave:local}
output_eif=${LAYRS_EIF_OUTPUT:-build/layrsv2-clob.eif}
measurement_file=${LAYRS_MEASUREMENT_OUTPUT:-build/layrsv2-clob-measurements.json}
mkdir -p "$(dirname "${output_eif}")" "$(dirname "${measurement_file}")"

docker build \
  --file enclave/Dockerfile \
  --build-arg "LAYRS_OPERATOR_PUBLIC_KEY_HEX=${LAYRS_OPERATOR_PUBLIC_KEY_HEX}" \
  --tag "${image_tag}" \
  .

nitro-cli build-enclave \
  --docker-uri "${image_tag}" \
  --output-file "${output_eif}" \
  | tee "${measurement_file}"

chmod 0600 "${output_eif}" "${measurement_file}"
