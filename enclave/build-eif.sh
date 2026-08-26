#!/usr/bin/env bash
set -euo pipefail

if [[ -z ${LAYRS_OPERATOR_PUBLIC_KEY_HEX:-} || ${#LAYRS_OPERATOR_PUBLIC_KEY_HEX} -ne 64 ]]; then
  echo "LAYRS_OPERATOR_PUBLIC_KEY_HEX must be a 32-byte hex Ed25519 key" >&2
  exit 1
fi

if [[ ${LAYRS_OPERATOR_PUBLIC_KEY_HEX} == d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a ]]; then
  echo "Refusing to build a release EIF with the documented test operator key" >&2
  exit 1
fi

case "${LAYRS_RECOVERY_ENVIRONMENT:-}" in
  development|staging|production) ;;
  *) echo "LAYRS_RECOVERY_ENVIRONMENT must be development, staging, or production" >&2; exit 1 ;;
esac

if [[ -n ${LAYRS_ENCLAVE_TRANSITION_POLICY_SHA256:-}
      && ! ${LAYRS_ENCLAVE_TRANSITION_POLICY_SHA256} =~ ^[0-9a-f]{64}$ ]]; then
  echo "LAYRS_ENCLAVE_TRANSITION_POLICY_SHA256 must be empty or a 32-byte lowercase hex policy" >&2
  exit 1
fi

case "${LAYRS_ENCLAVE_DEPLOYMENT_MODE:-INCIDENT_RECOVERY}" in
  INCIDENT_RECOVERY|FRESH_EPOCH) ;;
  *) echo "LAYRS_ENCLAVE_DEPLOYMENT_MODE must be INCIDENT_RECOVERY or FRESH_EPOCH" >&2; exit 1 ;;
esac

image_tag=${LAYRS_ENCLAVE_IMAGE_TAG:-layrsv2-clob-enclave:local}
output_eif=${LAYRS_EIF_OUTPUT:-build/layrsv2-clob.eif}
measurement_file=${LAYRS_MEASUREMENT_OUTPUT:-build/layrsv2-clob-measurements.json}
nitro_cli_artifacts=${NITRO_CLI_ARTIFACTS:-/usr/share/nitro_enclaves/blobs}
source_date_epoch=${SOURCE_DATE_EPOCH:-1787611129}
mkdir -p "$(dirname "${output_eif}")" "$(dirname "${measurement_file}")"

if [[ ${source_date_epoch} != 1787611129 ]]; then
  echo "SOURCE_DATE_EPOCH must equal the frozen release epoch 1787611129" >&2
  exit 1
fi

if [[ ! -d ${nitro_cli_artifacts} ]]; then
  echo "Nitro CLI artifacts directory does not exist: ${nitro_cli_artifacts}" >&2
  exit 1
fi

export NITRO_CLI_ARTIFACTS=${nitro_cli_artifacts}

docker build \
  --file enclave/Dockerfile \
  --build-arg "LAYRS_OPERATOR_PUBLIC_KEY_HEX=${LAYRS_OPERATOR_PUBLIC_KEY_HEX}" \
  --build-arg "LAYRS_RECOVERY_ENVIRONMENT=${LAYRS_RECOVERY_ENVIRONMENT}" \
  --build-arg "LAYRS_ENCLAVE_TRANSITION_POLICY_SHA256=${LAYRS_ENCLAVE_TRANSITION_POLICY_SHA256:-}" \
  --build-arg "LAYRS_ENCLAVE_DEPLOYMENT_MODE=${LAYRS_ENCLAVE_DEPLOYMENT_MODE:-INCIDENT_RECOVERY}" \
  --build-arg "SOURCE_DATE_EPOCH=${source_date_epoch}" \
  --tag "${image_tag}" \
  .

nitro-cli build-enclave \
  --docker-uri "${image_tag}" \
  --output-file "${output_eif}" \
  | tee "${measurement_file}"

chmod 0600 "${output_eif}" "${measurement_file}"
