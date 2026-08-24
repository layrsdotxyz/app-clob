#!/usr/bin/env bash
set -euo pipefail

umask 077

readonly RECOVERY_ACCOUNT_ID="082223548516"
readonly RECOVERY_REGION="us-east-1"
readonly RECOVERY_SOURCE_COMMIT="f282583cae7a5c873a26aa8d0c1bec10c490eb8e"
readonly REMEDIATION_EVIDENCE_COMMIT="540fc566c83dee2c3226862cc71a95541bc69af7"
readonly REMEDIATION_INDEX_VERSION_ID="oBGf0odkWa6tzYpml_UtGemDwXI6GdXy"
readonly EXPECTED_PARENT_SHA384="d9506bf11627b04bd5d220e18e78584cd5e649952fe380309346d9c6bbecd511eb318cdcdee6a1d0db989d581a742db1"
readonly EXPECTED_EIF_SHA384="958e084e0a66d0aca6773193a74d40659cd258fcffa116b0117fed1fab8361046ffea6411379b72fc72c97b86f611290"
readonly REJECTED_BUILD_A_EIF_SHA384="110c31235f36fa85e4a50d61fb89ab3a08e5b18587a35dfe4818c3615eed5a79513082df101e5c655fce8c7640d66ad8"
readonly EXPECTED_PCR0_SHA384="57fc48ad4d755edda38665bc8f0a16e7fd9dc485e3b57a2bce9070f60bd3b9724711ff973175340d5ebbfed4d63b7fac"
readonly AL2023_OWNER_ID="137112412989"
readonly AL2023_AMI_ID="ami-0332d564d76dbd8d6"
readonly IMMUTABLE_EVIDENCE_BUCKET="layrs-production-082223548516-us-east-1-immutable"

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
readonly PACKER_TEMPLATE="${REPO_ROOT}/enclave/packer/layrs-seq159300-recovery-parent.pkr.hcl"
readonly PARENT_BINARY="${REPO_ROOT}/build/layrs-enclave-parent"
readonly EIF_BINARY="${REPO_ROOT}/build/layrsv2-clob.eif"
readonly EIF_MEASUREMENTS="${REPO_ROOT}/build/layrsv2-clob-measurements.json"
readonly NITRO_PACKAGE_SET_MANIFEST="${REPO_ROOT}/build/seq159300-nitro-package-set.json"
readonly NITRO_PACKAGE_SET_ARCHIVE="${REPO_ROOT}/build/seq159300-nitro-packages.tar"
readonly NITRO_PACKAGE_DIRECTORY="${REPO_ROOT}/build/seq159300-nitro-packages"
readonly EVIDENCE_RENDERER="${REPO_ROOT}/scripts/render-seq159300-recovery-parent-evidence.mjs"
readonly PREFLIGHT_VALIDATOR="${REPO_ROOT}/scripts/lib/seq159300-recovery-parent-preflight.mjs"
EVIDENCE_INPUT_TEMP=""
PREFLIGHT_TEMP_DIR=""
BUILDER_COMMIT=""
PACKER_TEMPLATE_SHA384=""
EXPECTED_PACKAGE_INVENTORY_SHA384=""
NITRO_PACKAGE_SET_SHA384=""
NITRO_PACKAGE_SET_EVIDENCE_SHA384=""
NITRO_CLI_NEVRA=""
NITRO_CLI_RPM_SHA384=""
NITRO_CLI_RPM_OBJECT_KEY=""
NITRO_CLI_RPM_OBJECT_VERSION_ID=""
PACKAGE_INSTALL_PLAN=""
SOURCE_AMI_PROVENANCE_SHA384=""
BUILD_SUBNET_INVENTORY_SHA384=""
BUILD_SECURITY_GROUP_INVENTORY_SHA384=""
BUILD_INSTANCE_PROFILE_INVENTORY_SHA384=""
OUTPUT_AMI_INVENTORY_SHA384=""

die() {
  printf 'seq159300 recovery AMI gate: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command is unavailable: $1"
}

require_env() {
  local name="$1"
  [[ -n "${!name:-}" ]] || die "${name} is required"
}

require_exact() {
  local name="$1"
  local actual="$2"
  local expected="$3"
  [[ "${actual}" == "${expected}" ]] || die "${name} does not match the reviewed recovery binding"
}

sha384_file() {
  sha384sum --binary "$1" | awk '{print $1}'
}

cleanup() {
  if [[ -n "${EVIDENCE_INPUT_TEMP}" ]]; then
    rm -f -- "${EVIDENCE_INPUT_TEMP}"
  fi
  if [[ -n "${PACKAGE_INSTALL_PLAN}" ]]; then
    rm -f -- "${PACKAGE_INSTALL_PLAN}"
  fi
  if [[ -n "${PREFLIGHT_TEMP_DIR}" && -d "${PREFLIGHT_TEMP_DIR}" \
      && "$(basename -- "${PREFLIGHT_TEMP_DIR}")" == layrs-seq159300-parent-preflight.* ]]; then
    rm -f -- "${PREFLIGHT_TEMP_DIR}"/*
    rmdir -- "${PREFLIGHT_TEMP_DIR}"
  fi
}

verify_nitro_package_set() {
  local input output package_count filename expected_sha expected_nevra expected_key actual_nevra check_output archive_listing
  [[ -f "${NITRO_PACKAGE_SET_MANIFEST}" && ! -L "${NITRO_PACKAGE_SET_MANIFEST}" ]] \
    || die "missing immutable Nitro dependency-closure manifest"
  [[ -d "${NITRO_PACKAGE_DIRECTORY}" && ! -L "${NITRO_PACKAGE_DIRECTORY}" ]] \
    || die "missing offline Nitro dependency-closure directory"
  [[ -f "${NITRO_PACKAGE_SET_ARCHIVE}" && ! -L "${NITRO_PACKAGE_SET_ARCHIVE}" ]] \
    || die "missing immutable offline Nitro dependency-closure archive"
  input="$(mktemp "${TMPDIR:-/tmp}/layrs-seq159300-package-set.XXXXXX")"
  output="$(mktemp "${TMPDIR:-/tmp}/layrs-seq159300-package-set-output.XXXXXX")"
  rm -f -- "${output}"
  jq -n --slurpfile manifest "${NITRO_PACKAGE_SET_MANIFEST}" \
    '{kind:"nitro-package-set",payload:{manifest:$manifest[0]}}' >"${input}"
  node "${PREFLIGHT_VALIDATOR}" --input "${input}" --output "${output}" \
    || { rm -f -- "${input}" "${output}"; die "Nitro package-set manifest is invalid"; }
  rm -f -- "${input}"
  cmp -s -- "${NITRO_PACKAGE_SET_MANIFEST}" "${output}" \
    || die "Nitro package-set manifest is not the exact canonical JSON encoding"
  NITRO_PACKAGE_SET_SHA384="$(sha384_file "${NITRO_PACKAGE_SET_ARCHIVE}")"
  NITRO_PACKAGE_SET_EVIDENCE_SHA384="$(sha384_file "${NITRO_PACKAGE_SET_MANIFEST}")"
  package_count="$(jq -er '.packages | length' "${output}")"
  [[ "$(find "${NITRO_PACKAGE_DIRECTORY}" -mindepth 1 -maxdepth 1 -type f -name '*.rpm' | wc -l)" == "${package_count}" ]] \
    || die "offline Nitro package directory differs from the exact manifest closure"
  [[ -z "$(find "${NITRO_PACKAGE_DIRECTORY}" -mindepth 1 -maxdepth 1 ! -type f -print -quit)" ]] \
    || die "offline Nitro package directory contains a non-regular entry"
  archive_listing="$(tar -tf "${NITRO_PACKAGE_SET_ARCHIVE}")" \
    || die "Nitro package-set archive cannot be read"
  [[ "${archive_listing}" == "$(jq -r '.packages[].filename' "${output}")" ]] \
    || die "Nitro package-set archive membership/order differs from the canonical manifest"
  PACKAGE_INSTALL_PLAN="$(mktemp "${TMPDIR:-/tmp}/layrs-seq159300-package-plan.XXXXXX")"
  while IFS=$'\t' read -r filename expected_sha expected_nevra expected_key; do
    [[ -f "${NITRO_PACKAGE_DIRECTORY}/${filename}" && ! -L "${NITRO_PACKAGE_DIRECTORY}/${filename}" ]] \
      || die "offline Nitro package is missing or unsafe: ${filename}"
    require_exact "RPM SHA384 for ${filename}" "$(sha384_file "${NITRO_PACKAGE_DIRECTORY}/${filename}")" "${expected_sha}"
    require_exact "archived RPM SHA384 for ${filename}" \
      "$(tar -xOf "${NITRO_PACKAGE_SET_ARCHIVE}" -- "${filename}" | sha384sum --binary | awk '{print $1}')" \
      "${expected_sha}"
    check_output="$(rpmkeys --checksig --verbose "${NITRO_PACKAGE_DIRECTORY}/${filename}" 2>&1)" \
      || die "RPM signature/header verification failed for ${filename}"
    [[ "${check_output,,}" == *"key id ${expected_key,,}"* && "${check_output}" == *": OK"* ]] \
      || die "RPM signature does not bind the reviewed key for ${filename}"
    actual_nevra="$(rpm -qp --qf '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}' \
      "${NITRO_PACKAGE_DIRECTORY}/${filename}")" || die "RPM header query failed for ${filename}"
    require_exact "RPM NEVRA for ${filename}" "${actual_nevra}" "${expected_nevra}"
    printf '%s\t%s\t%s\t%s\n' "${filename}" "${expected_sha}" "${expected_nevra}" "${expected_key}" >>"${PACKAGE_INSTALL_PLAN}"
  done < <(jq -r '.packages[] | [.filename,.sha384,.nevra,.signatureKeyId] | @tsv' "${output}")
  EXPECTED_PACKAGE_INVENTORY_SHA384="$(awk -F '\t' '{print $3 "\t" $2}' "${PACKAGE_INSTALL_PLAN}" \
    | sha384sum --binary | awk '{print $1}')"
  NITRO_CLI_NEVRA="$(jq -er '.packages[] | select(.nevra | startswith("aws-nitro-enclaves-cli-")) | .nevra' "${output}")"
  [[ "$(jq '[.packages[] | select(.nevra | startswith("aws-nitro-enclaves-cli-"))] | length' "${output}")" == "1" ]] \
    || die "Nitro package set must contain exactly one CLI package"
  NITRO_CLI_RPM_SHA384="$(jq -er '.packages[] | select(.nevra | startswith("aws-nitro-enclaves-cli-")) | .sha384' "${output}")"
  NITRO_CLI_RPM_OBJECT_KEY="$(jq -er '.packages[] | select(.nevra | startswith("aws-nitro-enclaves-cli-")) | .objectKey' "${output}")"
  NITRO_CLI_RPM_OBJECT_VERSION_ID="$(jq -er '.packages[] | select(.nevra | startswith("aws-nitro-enclaves-cli-")) | .objectVersionId' "${output}")"
  rm -f -- "${output}"
}

verify_immutable_package_objects() {
  local key version expected_sha filename downloaded response
  require_exact LAYRS_RECOVERY_EVIDENCE_BUCKET "${LAYRS_RECOVERY_EVIDENCE_BUCKET}" \
    "${IMMUTABLE_EVIDENCE_BUCKET}"
  downloaded="${PREFLIGHT_TEMP_DIR}/nitro-package-set.tar"
  response="${PREFLIGHT_TEMP_DIR}/nitro-package-set-readback.json"
  aws_read_json s3api get-object --bucket "${IMMUTABLE_EVIDENCE_BUCKET}" \
    --key "${LAYRS_RECOVERY_NITRO_PACKAGE_SET_OBJECT_KEY}" \
    --version-id "${LAYRS_RECOVERY_NITRO_PACKAGE_SET_OBJECT_VERSION_ID}" \
    "${downloaded}" >"${response}"
  require_exact "remote Nitro package-set VersionId" "$(jq -er '.VersionId' "${response}")" \
    "${LAYRS_RECOVERY_NITRO_PACKAGE_SET_OBJECT_VERSION_ID}"
  require_exact "remote Nitro package-set SHA384" "$(sha384_file "${downloaded}")" \
    "${LAYRS_RECOVERY_NITRO_PACKAGE_SET_SHA384}"
  cmp -s -- "${downloaded}" "${NITRO_PACKAGE_SET_ARCHIVE}" \
    || die "local Nitro package-set archive bytes differ from the exact immutable object version"

  downloaded="${PREFLIGHT_TEMP_DIR}/nitro-package-set-evidence.json"
  response="${PREFLIGHT_TEMP_DIR}/nitro-package-set-evidence-readback.json"
  aws_read_json s3api get-object --bucket "${IMMUTABLE_EVIDENCE_BUCKET}" \
    --key "${LAYRS_RECOVERY_NITRO_PACKAGE_SET_EVIDENCE_OBJECT_KEY}" \
    --version-id "${LAYRS_RECOVERY_NITRO_PACKAGE_SET_EVIDENCE_OBJECT_VERSION_ID}" \
    "${downloaded}" >"${response}"
  require_exact "remote Nitro package-set evidence VersionId" "$(jq -er '.VersionId' "${response}")" \
    "${LAYRS_RECOVERY_NITRO_PACKAGE_SET_EVIDENCE_OBJECT_VERSION_ID}"
  require_exact "remote Nitro package-set evidence SHA384" "$(sha384_file "${downloaded}")" \
    "${LAYRS_RECOVERY_NITRO_PACKAGE_SET_EVIDENCE_SHA384}"
  cmp -s -- "${downloaded}" "${NITRO_PACKAGE_SET_MANIFEST}" \
    || die "local Nitro package-set manifest differs from immutable evidence bytes"

  while IFS=$'\t' read -r filename key version expected_sha; do
    downloaded="${PREFLIGHT_TEMP_DIR}/remote-${filename}"
    response="${PREFLIGHT_TEMP_DIR}/remote-${filename}.json"
    aws_read_json s3api get-object --bucket "${IMMUTABLE_EVIDENCE_BUCKET}" \
      --key "${key}" --version-id "${version}" "${downloaded}" >"${response}"
    require_exact "remote RPM VersionId for ${filename}" "$(jq -er '.VersionId' "${response}")" "${version}"
    require_exact "remote RPM SHA384 for ${filename}" "$(sha384_file "${downloaded}")" "${expected_sha}"
    cmp -s -- "${downloaded}" "${NITRO_PACKAGE_DIRECTORY}/${filename}" \
      || die "local RPM bytes differ from immutable object version for ${filename}"
  done < <(jq -r '.packages[] | [.filename,.objectKey,.objectVersionId,.sha384] | @tsv' \
    "${NITRO_PACKAGE_SET_MANIFEST}")
}

trap cleanup EXIT

canonical_pcr0() {
  local value
  value="$(jq -er '.Measurements.PCR0 // .measurements.PCR0 // .PCR0 // empty' "$1")" \
    || die "the EIF measurements file has no PCR0"
  value="${value#0x}"
  printf '%s' "${value,,}"
}

verify_repository() {
  local head changed dirty
  head="$(git -C "${REPO_ROOT}" rev-parse HEAD)"
  require_env LAYRS_RECOVERY_BUILDER_COMMIT
  require_exact LAYRS_RECOVERY_BUILDER_COMMIT "${LAYRS_RECOVERY_BUILDER_COMMIT}" "${head}"
  BUILDER_COMMIT="${head}"
  [[ "${BUILDER_COMMIT}" != "${RECOVERY_SOURCE_COMMIT}" ]] \
    || die "builder source commit must differ from the exact f282 runtime source commit"
  git -C "${REPO_ROOT}" merge-base --is-ancestor "${RECOVERY_SOURCE_COMMIT}" "${BUILDER_COMMIT}" \
    || die "HEAD does not descend from exact recovery source ${RECOVERY_SOURCE_COMMIT}"

  dirty="$(git -C "${REPO_ROOT}" status --porcelain=v1 --untracked-files=all)"
  [[ -z "${dirty}" ]] || die "source worktree must be clean before validation or build"

  changed="$(git -C "${REPO_ROOT}" diff --name-only "${RECOVERY_SOURCE_COMMIT}..HEAD")"
  while IFS= read -r file; do
    [[ -z "${file}" ]] && continue
    case "${file}" in
      docs/runbooks/LAYRS_SEQ159300_RECOVERY_PARENT_AMI.md | \
      enclave/packer/layrs-seq159300-recovery-parent.pkr.hcl | \
      scripts/build-seq159300-recovery-parent-ami.sh | \
      scripts/lib/seq159300-recovery-parent-preflight.mjs | \
      scripts/render-seq159300-recovery-parent-evidence.mjs | \
      scripts/tests/seq159300-recovery-parent.test.mjs)
        ;;
      *)
        die "non-recovery source differs from f282: ${file}"
        ;;
    esac
  done <<<"${changed}"
}

verify_inputs() {
  local parent_sha eif_sha pcr0 phase2_template_sha
  require_env LAYRS_RECOVERY_EXPECTED_PARENT_SHA384
  require_exact LAYRS_RECOVERY_EXPECTED_PARENT_SHA384 \
    "${LAYRS_RECOVERY_EXPECTED_PARENT_SHA384}" "${EXPECTED_PARENT_SHA384}"

  require_env LAYRS_RECOVERY_ACCOUNT_ID
  require_env LAYRS_RECOVERY_AWS_REGION
  require_env LAYRS_RECOVERY_SOURCE_AMI_ID
  require_env LAYRS_RECOVERY_SOURCE_AMI_OWNER
  require_env LAYRS_RECOVERY_IMPLEMENTATION_COMMIT
  require_env LAYRS_RECOVERY_PHASE2_TEMPLATE_FILE
  require_env LAYRS_RECOVERY_EXPECTED_PHASE2_TEMPLATE_SHA384
  require_env LAYRS_RECOVERY_PHASE2_TEMPLATE_COMMIT
  require_env LAYRS_RECOVERY_PHASE2_EVIDENCE_OBJECT_KEY
  require_env LAYRS_RECOVERY_PHASE2_EVIDENCE_OBJECT_VERSION_ID
  require_env LAYRS_RECOVERY_PHASE2_EVIDENCE_OBJECT_SHA384
  require_env LAYRS_RECOVERY_IMPLEMENTATION_EVIDENCE_OBJECT_KEY
  require_env LAYRS_RECOVERY_IMPLEMENTATION_EVIDENCE_OBJECT_VERSION_ID
  require_env LAYRS_RECOVERY_IMPLEMENTATION_EVIDENCE_OBJECT_SHA384
  require_env LAYRS_RECOVERY_NITRO_PACKAGE_SET_OBJECT_KEY
  require_env LAYRS_RECOVERY_NITRO_PACKAGE_SET_OBJECT_VERSION_ID
  require_env LAYRS_RECOVERY_NITRO_PACKAGE_SET_SHA384
  require_env LAYRS_RECOVERY_NITRO_PACKAGE_SET_EVIDENCE_OBJECT_KEY
  require_env LAYRS_RECOVERY_NITRO_PACKAGE_SET_EVIDENCE_OBJECT_VERSION_ID
  require_env LAYRS_RECOVERY_NITRO_PACKAGE_SET_EVIDENCE_SHA384
  require_env LAYRS_RECOVERY_EVIDENCE_BUCKET

  [[ -f "${PREFLIGHT_VALIDATOR}" && ! -L "${PREFLIGHT_VALIDATOR}" ]] \
    || die "the recovery-parent preflight validator is missing or unsafe"

  require_exact LAYRS_RECOVERY_ACCOUNT_ID "${LAYRS_RECOVERY_ACCOUNT_ID}" "${RECOVERY_ACCOUNT_ID}"
  require_exact LAYRS_RECOVERY_AWS_REGION "${LAYRS_RECOVERY_AWS_REGION}" "${RECOVERY_REGION}"
  require_exact LAYRS_RECOVERY_SOURCE_AMI_OWNER "${LAYRS_RECOVERY_SOURCE_AMI_OWNER}" "${AL2023_OWNER_ID}"
  require_exact LAYRS_RECOVERY_SOURCE_AMI_ID "${LAYRS_RECOVERY_SOURCE_AMI_ID}" "${AL2023_AMI_ID}"
  [[ "${LAYRS_RECOVERY_IMPLEMENTATION_COMMIT}" =~ ^[0-9a-f]{40}$ ]] \
    || die "LAYRS_RECOVERY_IMPLEMENTATION_COMMIT must be an exact lowercase commit"
  [[ "${LAYRS_RECOVERY_PHASE2_TEMPLATE_COMMIT}" =~ ^[0-9a-f]{40}$ ]] \
    || die "LAYRS_RECOVERY_PHASE2_TEMPLATE_COMMIT must be an exact lowercase commit"
  [[ "${LAYRS_RECOVERY_PHASE2_TEMPLATE_COMMIT}" != "${LAYRS_RECOVERY_IMPLEMENTATION_COMMIT}" ]] \
    || die "Phase2 IaC commit and final implementation commit are distinct reviewed bindings"
  [[ "${LAYRS_RECOVERY_EXPECTED_PHASE2_TEMPLATE_SHA384}" =~ ^[0-9a-f]{96}$ ]] \
    || die "LAYRS_RECOVERY_EXPECTED_PHASE2_TEMPLATE_SHA384 is malformed"
  [[ "${LAYRS_RECOVERY_PHASE2_EVIDENCE_OBJECT_SHA384}" =~ ^[0-9a-f]{96}$ \
      && "${LAYRS_RECOVERY_IMPLEMENTATION_EVIDENCE_OBJECT_SHA384}" =~ ^[0-9a-f]{96}$ ]] \
    || die "immutable Phase2 or implementation evidence SHA384 is malformed"
  [[ "${LAYRS_RECOVERY_PHASE2_EVIDENCE_OBJECT_KEY}" =~ ^evidence/seq159300/recovery-only/phase2/[A-Za-z0-9._/-]+$ \
      && "${LAYRS_RECOVERY_IMPLEMENTATION_EVIDENCE_OBJECT_KEY}" =~ ^evidence/seq159300/recovery-only/implementation/[A-Za-z0-9._/-]+$ \
      && "${LAYRS_RECOVERY_PHASE2_EVIDENCE_OBJECT_KEY}" != *".."* \
      && "${LAYRS_RECOVERY_IMPLEMENTATION_EVIDENCE_OBJECT_KEY}" != *".."* ]] \
    || die "immutable evidence object key is malformed"
  [[ "${LAYRS_RECOVERY_PHASE2_EVIDENCE_OBJECT_VERSION_ID}" =~ ^[A-Za-z0-9._-]{8,256}$ \
      && "${LAYRS_RECOVERY_IMPLEMENTATION_EVIDENCE_OBJECT_VERSION_ID}" =~ ^[A-Za-z0-9._-]{8,256}$ ]] \
    || die "immutable evidence object VersionId is malformed"
  for value in "${LAYRS_RECOVERY_NITRO_PACKAGE_SET_SHA384}" \
      "${LAYRS_RECOVERY_NITRO_PACKAGE_SET_EVIDENCE_SHA384}"; do
    [[ "${value}" =~ ^[0-9a-f]{96}$ ]] || die "immutable Nitro package-set SHA384 is malformed"
  done
  for value in "${LAYRS_RECOVERY_NITRO_PACKAGE_SET_OBJECT_KEY}" \
      "${LAYRS_RECOVERY_NITRO_PACKAGE_SET_EVIDENCE_OBJECT_KEY}"; do
    [[ "${value}" =~ ^evidence/seq159300/recovery-only/phase2/[A-Za-z0-9._/-]+$ && "${value}" != *".."* ]] \
      || die "immutable Nitro package-set object key is malformed"
  done
  for value in "${LAYRS_RECOVERY_NITRO_PACKAGE_SET_OBJECT_VERSION_ID}" \
      "${LAYRS_RECOVERY_NITRO_PACKAGE_SET_EVIDENCE_OBJECT_VERSION_ID}"; do
    [[ "${value}" =~ ^[A-Za-z0-9._-]{8,256}$ ]] \
      || die "immutable Nitro package-set VersionId is malformed"
  done

  [[ -f "${LAYRS_RECOVERY_PHASE2_TEMPLATE_FILE}" && ! -L "${LAYRS_RECOVERY_PHASE2_TEMPLATE_FILE}" ]] \
    || die "the reviewed Phase2 template is not a regular file"
  phase2_template_sha="$(sha384_file "${LAYRS_RECOVERY_PHASE2_TEMPLATE_FILE}")"
  require_exact "reviewed Phase2 template SHA384" "${phase2_template_sha}" \
    "${LAYRS_RECOVERY_EXPECTED_PHASE2_TEMPLATE_SHA384}"
  PACKER_TEMPLATE_SHA384="$(sha384_file "${PACKER_TEMPLATE}")"
  verify_nitro_package_set
  require_exact "Nitro package-set immutable object SHA384" "${NITRO_PACKAGE_SET_SHA384}" \
    "${LAYRS_RECOVERY_NITRO_PACKAGE_SET_SHA384}"
  require_exact "Nitro package-set immutable evidence SHA384" "${NITRO_PACKAGE_SET_EVIDENCE_SHA384}" \
    "${LAYRS_RECOVERY_NITRO_PACKAGE_SET_EVIDENCE_SHA384}"

  [[ -f "${PARENT_BINARY}" && ! -L "${PARENT_BINARY}" ]] \
    || die "missing already-built exact-f282 parent binary"
  [[ -f "${EIF_BINARY}" && ! -L "${EIF_BINARY}" ]] \
    || die "missing already-built exact-f282 EIF"
  [[ -f "${EIF_MEASUREMENTS}" && ! -L "${EIF_MEASUREMENTS}" ]] \
    || die "missing already-built exact-f282 EIF measurements"
  parent_sha="$(sha384_file "${PARENT_BINARY}")"
  require_exact "parent binary SHA384" "${parent_sha}" "${EXPECTED_PARENT_SHA384}"

  eif_sha="$(sha384_file "${EIF_BINARY}")"
  if [[ "${eif_sha}" == "${REJECTED_BUILD_A_EIF_SHA384}" ]]; then
    die "rejected build-a EIF supplied; only the exact accepted build-b EIF may be used"
  fi
  require_exact "EIF SHA384" "${eif_sha}" "${EXPECTED_EIF_SHA384}"

  pcr0="$(canonical_pcr0 "${EIF_MEASUREMENTS}")"
  require_exact "EIF PCR0" "${pcr0}" "${EXPECTED_PCR0_SHA384}"
}

aws_read_json() {
  PYTHONNOUSERSITE=1 aws --no-cli-pager --region "${RECOVERY_REGION}" --output json "$@"
}

render_preflight_inventory() {
  local input="$1"
  local output="$2"
  [[ -f "${input}" && ! -L "${input}" && ! -e "${output}" ]] \
    || die "preflight input/output path is unsafe"
  node "${PREFLIGHT_VALIDATOR}" --input "${input}" --output "${output}"
  [[ -f "${output}" && ! -L "${output}" ]] || die "preflight inventory was not emitted"
}

preflight_source_ami() {
  local response snapshot_response input output
  response="${PREFLIGHT_TEMP_DIR}/source-ami-response.json"
  input="${PREFLIGHT_TEMP_DIR}/source-ami-input.json"
  output="${PREFLIGHT_TEMP_DIR}/source-ami-inventory.json"
  snapshot_response="${PREFLIGHT_TEMP_DIR}/source-snapshot-response.json"
  aws_read_json ec2 describe-images \
    --image-ids "${LAYRS_RECOVERY_SOURCE_AMI_ID}" \
    --owners "${LAYRS_RECOVERY_SOURCE_AMI_OWNER}" >"${response}"
  aws_read_json ec2 describe-snapshots \
    --snapshot-ids "snap-0bc9cf3f9e4893b60" --owner-ids "${LAYRS_RECOVERY_SOURCE_AMI_OWNER}" \
    >"${snapshot_response}"
  jq -n \
    --arg expectedImageId "${LAYRS_RECOVERY_SOURCE_AMI_ID}" \
    --arg expectedOwnerId "${LAYRS_RECOVERY_SOURCE_AMI_OWNER}" \
    --slurpfile response "${response}" \
    --slurpfile snapshotResponse "${snapshot_response}" \
    '{kind:"source-ami",payload:{expectedImageId:$expectedImageId,
      expectedOwnerId:$expectedOwnerId,response:$response[0],snapshotResponse:$snapshotResponse[0]}}' >"${input}"
  render_preflight_inventory "${input}" "${output}"
  SOURCE_AMI_PROVENANCE_SHA384="$(sha384_file "${output}")"
}

preflight_build_network() {
  local subnet_response routes_response security_group_response endpoints_response interfaces_response input output vpc_id
  local -a referenced_group_ids all_group_ids
  subnet_response="${PREFLIGHT_TEMP_DIR}/subnet-response.json"
  routes_response="${PREFLIGHT_TEMP_DIR}/routes-response.json"
  security_group_response="${PREFLIGHT_TEMP_DIR}/security-groups-response.json"
  endpoints_response="${PREFLIGHT_TEMP_DIR}/vpc-endpoints-response.json"
  interfaces_response="${PREFLIGHT_TEMP_DIR}/network-interfaces-response.json"
  input="${PREFLIGHT_TEMP_DIR}/network-input.json"
  output="${PREFLIGHT_TEMP_DIR}/network-inventory.json"

  aws_read_json ec2 describe-subnets \
    --subnet-ids "${LAYRS_RECOVERY_BUILD_SUBNET_ID}" >"${subnet_response}"
  vpc_id="$(jq -er '.Subnets | select(length == 1) | .[0].VpcId' "${subnet_response}")" \
    || die "build subnet did not resolve to one VPC"
  aws_read_json ec2 describe-route-tables \
    --filters "Name=association.subnet-id,Values=${LAYRS_RECOVERY_BUILD_SUBNET_ID}" >"${routes_response}"
  if [[ "$(jq -er '.RouteTables | length' "${routes_response}")" == "0" ]]; then
    aws_read_json ec2 describe-route-tables \
      --filters "Name=vpc-id,Values=${vpc_id}" "Name=association.main,Values=true" >"${routes_response}"
  fi

  aws_read_json ec2 describe-security-groups \
    --group-ids "${LAYRS_RECOVERY_BUILD_SECURITY_GROUP_ID}" >"${security_group_response}"
  mapfile -t referenced_group_ids < <(jq -er \
    '.SecurityGroups | select(length == 1) | .[0].IpPermissionsEgress[]?.UserIdGroupPairs[]?.GroupId' \
    "${security_group_response}" | sort -u)
  (( ${#referenced_group_ids[@]} > 0 )) \
    || die "build security group must egress only to recovery endpoint security groups"
  all_group_ids=("${LAYRS_RECOVERY_BUILD_SECURITY_GROUP_ID}" "${referenced_group_ids[@]}")
  aws_read_json ec2 describe-security-groups --group-ids "${all_group_ids[@]}" >"${security_group_response}"
  aws_read_json ec2 describe-vpc-endpoints \
    --filters "Name=vpc-id,Values=${vpc_id}" >"${endpoints_response}"
  aws_read_json ec2 describe-network-interfaces \
    --filters "Name=group-id,Values=$(IFS=,; printf '%s' "${referenced_group_ids[*]}")" \
    >"${interfaces_response}"

  jq -n \
    --arg expectedSubnetId "${LAYRS_RECOVERY_BUILD_SUBNET_ID}" \
    --arg expectedSecurityGroupId "${LAYRS_RECOVERY_BUILD_SECURITY_GROUP_ID}" \
    --slurpfile subnetsResponse "${subnet_response}" \
    --slurpfile routeTablesResponse "${routes_response}" \
    --slurpfile securityGroupsResponse "${security_group_response}" \
    --slurpfile vpcEndpointsResponse "${endpoints_response}" \
    --slurpfile networkInterfacesResponse "${interfaces_response}" \
    '{kind:"build-network",payload:{expectedSubnetId:$expectedSubnetId,
      expectedSecurityGroupId:$expectedSecurityGroupId,subnetsResponse:$subnetsResponse[0],
      routeTablesResponse:$routeTablesResponse[0],securityGroupsResponse:$securityGroupsResponse[0],
      vpcEndpointsResponse:$vpcEndpointsResponse[0],networkInterfacesResponse:$networkInterfacesResponse[0]}}' \
    >"${input}"
  render_preflight_inventory "${input}" "${output}"
  jq -cS '{subnet,routeTables,routes}' "${output}" \
    >"${PREFLIGHT_TEMP_DIR}/subnet-inventory.json"
  jq -cS '{securityGroups,endpoints}' "${output}" \
    >"${PREFLIGHT_TEMP_DIR}/security-group-inventory.json"
  BUILD_SUBNET_INVENTORY_SHA384="$(sha384_file "${PREFLIGHT_TEMP_DIR}/subnet-inventory.json")"
  BUILD_SECURITY_GROUP_INVENTORY_SHA384="$(sha384_file "${PREFLIGHT_TEMP_DIR}/security-group-inventory.json")"
}

preflight_instance_profile() {
  local profile_response attached_response inline_response input output role_name policy_json
  local policy_arn policy_name default_version document_response inline_name
  profile_response="${PREFLIGHT_TEMP_DIR}/instance-profile-response.json"
  attached_response="${PREFLIGHT_TEMP_DIR}/attached-policies-response.json"
  inline_response="${PREFLIGHT_TEMP_DIR}/inline-policies-response.json"
  input="${PREFLIGHT_TEMP_DIR}/instance-profile-input.json"
  output="${PREFLIGHT_TEMP_DIR}/instance-profile-inventory.json"

  aws_read_json iam get-instance-profile \
    --instance-profile-name "${LAYRS_RECOVERY_BUILD_INSTANCE_PROFILE}" >"${profile_response}"
  role_name="$(jq -er '.InstanceProfile.Roles | select(length == 1) | .[0].RoleName' "${profile_response}")" \
    || die "build instance profile must resolve to exactly one role"
  aws_read_json iam list-attached-role-policies --role-name "${role_name}" >"${attached_response}"
  aws_read_json iam list-role-policies --role-name "${role_name}" >"${inline_response}"
  policy_json='[]'

  while IFS=$'\t' read -r policy_arn policy_name; do
    [[ -z "${policy_arn}" ]] && continue
    default_version="$(aws_read_json iam get-policy --policy-arn "${policy_arn}" \
      | jq -er '.Policy.DefaultVersionId')" || die "attached policy default version is unavailable"
    document_response="$(aws_read_json iam get-policy-version \
      --policy-arn "${policy_arn}" --version-id "${default_version}")"
    policy_json="$(jq -cn \
      --argjson policies "${policy_json}" --arg name "${policy_name}" --arg source "attached:${policy_arn}:${default_version}" \
      --argjson document "$(jq -c '.PolicyVersion.Document' <<<"${document_response}")" \
      '$policies + [{name:$name,source:$source,document:$document}]')"
  done < <(jq -r '.AttachedPolicies[]? | [.PolicyArn,.PolicyName] | @tsv' "${attached_response}")

  while IFS= read -r inline_name; do
    [[ -z "${inline_name}" ]] && continue
    document_response="$(aws_read_json iam get-role-policy \
      --role-name "${role_name}" --policy-name "${inline_name}")"
    policy_json="$(jq -cn \
      --argjson policies "${policy_json}" --arg name "${inline_name}" --arg source "inline:${role_name}:${inline_name}" \
      --argjson document "$(jq -c '.PolicyDocument' <<<"${document_response}")" \
      '$policies + [{name:$name,source:$source,document:$document}]')"
  done < <(jq -r '.PolicyNames[]?' "${inline_response}")

  jq -n \
    --arg expectedInstanceProfileName "${LAYRS_RECOVERY_BUILD_INSTANCE_PROFILE}" \
    --argjson policies "${policy_json}" \
    --slurpfile response "${profile_response}" \
    '{kind:"instance-profile",payload:{expectedInstanceProfileName:$expectedInstanceProfileName,
      policies:$policies,response:$response[0]}}' >"${input}"
  render_preflight_inventory "${input}" "${output}"
  BUILD_INSTANCE_PROFILE_INVENTORY_SHA384="$(sha384_file "${output}")"
}

readback_output_ami() {
  local ami_id="$1"
  local response input output
  response="${PREFLIGHT_TEMP_DIR}/output-ami-response.json"
  input="${PREFLIGHT_TEMP_DIR}/output-ami-input.json"
  output="${PREFLIGHT_TEMP_DIR}/output-ami-inventory.json"
  aws_read_json ec2 describe-images --image-ids "${ami_id}" --owners self >"${response}"
  jq -n \
    --arg imageId "${ami_id}" \
    --arg sourceAmiId "${LAYRS_RECOVERY_SOURCE_AMI_ID}" \
    --arg sourceCommit "${RECOVERY_SOURCE_COMMIT}" \
    --arg builderSourceCommit "${BUILDER_COMMIT}" \
    --arg implementationCommit "${LAYRS_RECOVERY_IMPLEMENTATION_COMMIT}" \
    --arg parentSha384 "${EXPECTED_PARENT_SHA384}" \
    --arg eifSha384 "${EXPECTED_EIF_SHA384}" \
    --arg pcr0Sha384 "${EXPECTED_PCR0_SHA384}" \
    --arg phase2TemplateSha384 "${LAYRS_RECOVERY_EXPECTED_PHASE2_TEMPLATE_SHA384}" \
    --arg phase2TemplateCommit "${LAYRS_RECOVERY_PHASE2_TEMPLATE_COMMIT}" \
    --arg sourceAmiProvenanceSha384 "${SOURCE_AMI_PROVENANCE_SHA384}" \
    --arg buildSubnetInventorySha384 "${BUILD_SUBNET_INVENTORY_SHA384}" \
    --arg buildSecurityGroupInventorySha384 "${BUILD_SECURITY_GROUP_INVENTORY_SHA384}" \
    --arg buildInstanceProfileInventorySha384 "${BUILD_INSTANCE_PROFILE_INVENTORY_SHA384}" \
    --arg packerTemplateSha384 "${PACKER_TEMPLATE_SHA384}" \
    --arg nitroCliRpmSha384 "${NITRO_CLI_RPM_SHA384}" \
    --arg nitroPackageInventorySha384 "${EXPECTED_PACKAGE_INVENTORY_SHA384}" \
    --arg nitroPackageSetSha384 "${NITRO_PACKAGE_SET_SHA384}" \
    --slurpfile response "${response}" \
    '{kind:"output-ami",payload:{expected:{imageId:$imageId,sourceAmiId:$sourceAmiId,
      sourceCommit:$sourceCommit,builderSourceCommit:$builderSourceCommit,
      implementationCommit:$implementationCommit,
      parentSha384:$parentSha384,eifSha384:$eifSha384,pcr0Sha384:$pcr0Sha384,
      phase2TemplateCommit:$phase2TemplateCommit,
      phase2TemplateSha384:$phase2TemplateSha384,
      sourceAmiProvenanceSha384:$sourceAmiProvenanceSha384,
      buildSubnetInventorySha384:$buildSubnetInventorySha384,
      buildSecurityGroupInventorySha384:$buildSecurityGroupInventorySha384,
      buildInstanceProfileInventorySha384:$buildInstanceProfileInventorySha384,
      packerTemplateSha384:$packerTemplateSha384,nitroCliRpmSha384:$nitroCliRpmSha384,
      nitroPackageInventorySha384:$nitroPackageInventorySha384,
      nitroPackageSetSha384:$nitroPackageSetSha384},response:$response[0]}}' >"${input}"
  render_preflight_inventory "${input}" "${output}"
  OUTPUT_AMI_INVENTORY_SHA384="$(sha384_file "${output}")"
}

run_aws_preflight() {
  local caller_account caller_arn caller_identity
  PREFLIGHT_TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/layrs-seq159300-parent-preflight.XXXXXX")"
  require_env LAYRS_RECOVERY_PACKER_CALLER_ROLE_ARN
  [[ "${LAYRS_RECOVERY_PACKER_CALLER_ROLE_ARN}" =~ ^arn:aws:iam::082223548516:role/layrs-production-recovery-seq159300-packer-[A-Za-z0-9+=,.@_-]+$ ]] \
    || die "the Packer caller must be the exact dedicated recovery control-plane role"
  caller_identity="$(aws_read_json sts get-caller-identity)"
  caller_account="$(jq -er '.Account' <<<"${caller_identity}")" \
    || die "AWS caller identity could not be read"
  caller_arn="$(jq -er '.Arn' <<<"${caller_identity}")" || die "AWS caller ARN could not be read"
  require_exact "active AWS account" "${caller_account}" "${RECOVERY_ACCOUNT_ID}"
  [[ "${caller_arn}" =~ ^arn:aws:sts::082223548516:assumed-role/([^/]+)/[^/]+$ ]] \
    || die "Packer caller is not an assumed dedicated role"
  require_exact "Packer caller role" "arn:aws:iam::${RECOVERY_ACCOUNT_ID}:role/${BASH_REMATCH[1]}" \
    "${LAYRS_RECOVERY_PACKER_CALLER_ROLE_ARN}"
  preflight_source_ami
  preflight_build_network
  preflight_instance_profile
  verify_immutable_package_objects
}

summary() {
  jq -n -c \
    --arg accountId "${RECOVERY_ACCOUNT_ID}" \
    --arg region "${RECOVERY_REGION}" \
    --arg purpose "layrs-seq159300-recovery" \
    --arg sourceCommit "${RECOVERY_SOURCE_COMMIT}" \
    --arg builderSourceCommit "${BUILDER_COMMIT}" \
    --arg sourceAmiId "${LAYRS_RECOVERY_SOURCE_AMI_ID}" \
    --arg sourceAmiOwner "${LAYRS_RECOVERY_SOURCE_AMI_OWNER}" \
    --arg parentBinarySha384 "${EXPECTED_PARENT_SHA384}" \
    --arg eifSha384 "${EXPECTED_EIF_SHA384}" \
    --arg pcr0Sha384 "${EXPECTED_PCR0_SHA384}" \
    --arg phase2TemplateSha384 "${LAYRS_RECOVERY_EXPECTED_PHASE2_TEMPLATE_SHA384}" \
    --arg phase2TemplateCommit "${LAYRS_RECOVERY_PHASE2_TEMPLATE_COMMIT}" \
    --arg phase2EvidenceObjectKey "${LAYRS_RECOVERY_PHASE2_EVIDENCE_OBJECT_KEY}" \
    --arg phase2EvidenceObjectVersionId "${LAYRS_RECOVERY_PHASE2_EVIDENCE_OBJECT_VERSION_ID}" \
    --arg phase2EvidenceObjectSha384 "${LAYRS_RECOVERY_PHASE2_EVIDENCE_OBJECT_SHA384}" \
    --arg implementationCommit "${LAYRS_RECOVERY_IMPLEMENTATION_COMMIT}" \
    --arg implementationEvidenceObjectKey "${LAYRS_RECOVERY_IMPLEMENTATION_EVIDENCE_OBJECT_KEY}" \
    --arg implementationEvidenceObjectVersionId "${LAYRS_RECOVERY_IMPLEMENTATION_EVIDENCE_OBJECT_VERSION_ID}" \
    --arg implementationEvidenceObjectSha384 "${LAYRS_RECOVERY_IMPLEMENTATION_EVIDENCE_OBJECT_SHA384}" \
    --arg packerTemplateSha384 "${PACKER_TEMPLATE_SHA384}" \
    --arg nitroCliNevra "${NITRO_CLI_NEVRA}" \
    --arg nitroPackageInventorySha384 "${EXPECTED_PACKAGE_INVENTORY_SHA384}" \
    --arg nitroCliRpmObjectKey "${NITRO_CLI_RPM_OBJECT_KEY}" \
    --arg nitroCliRpmObjectVersionId "${NITRO_CLI_RPM_OBJECT_VERSION_ID}" \
    --arg nitroCliRpmSha384 "${NITRO_CLI_RPM_SHA384}" \
    --arg nitroPackageSetObjectKey "${LAYRS_RECOVERY_NITRO_PACKAGE_SET_OBJECT_KEY}" \
    --arg nitroPackageSetObjectVersionId "${LAYRS_RECOVERY_NITRO_PACKAGE_SET_OBJECT_VERSION_ID}" \
    --arg nitroPackageSetSha384 "${LAYRS_RECOVERY_NITRO_PACKAGE_SET_SHA384}" \
    --arg nitroPackageSetEvidenceObjectKey "${LAYRS_RECOVERY_NITRO_PACKAGE_SET_EVIDENCE_OBJECT_KEY}" \
    --arg nitroPackageSetEvidenceObjectVersionId "${LAYRS_RECOVERY_NITRO_PACKAGE_SET_EVIDENCE_OBJECT_VERSION_ID}" \
    --arg nitroPackageSetEvidenceSha384 "${LAYRS_RECOVERY_NITRO_PACKAGE_SET_EVIDENCE_SHA384}" \
    '{accountId:$accountId,region:$region,purpose:$purpose,sourceCommit:$sourceCommit,builderSourceCommit:$builderSourceCommit,
      sourceAmiId:$sourceAmiId,sourceAmiOwner:$sourceAmiOwner,
      parentBinarySha384:$parentBinarySha384,eifSha384:$eifSha384,pcr0Sha384:$pcr0Sha384,
      phase2TemplateCommit:$phase2TemplateCommit,phase2TemplateSha384:$phase2TemplateSha384,
      phase2EvidenceObjectKey:$phase2EvidenceObjectKey,
      phase2EvidenceObjectVersionId:$phase2EvidenceObjectVersionId,phase2EvidenceObjectSha384:$phase2EvidenceObjectSha384,
      implementationCommit:$implementationCommit,implementationEvidenceObjectKey:$implementationEvidenceObjectKey,
      implementationEvidenceObjectVersionId:$implementationEvidenceObjectVersionId,
      implementationEvidenceObjectSha384:$implementationEvidenceObjectSha384,packerTemplateSha384:$packerTemplateSha384,
      nitroCliNevra:$nitroCliNevra,nitroPackageInventorySha384:$nitroPackageInventorySha384,
      nitroCliRpmObjectKey:$nitroCliRpmObjectKey,nitroCliRpmObjectVersionId:$nitroCliRpmObjectVersionId,
      nitroCliRpmSha384:$nitroCliRpmSha384,
      nitroPackageSetObjectKey:$nitroPackageSetObjectKey,
      nitroPackageSetObjectVersionId:$nitroPackageSetObjectVersionId,
      nitroPackageSetSha384:$nitroPackageSetSha384,
      nitroPackageSetEvidenceObjectKey:$nitroPackageSetEvidenceObjectKey,
      nitroPackageSetEvidenceObjectVersionId:$nitroPackageSetEvidenceObjectVersionId,
      nitroPackageSetEvidenceSha384:$nitroPackageSetEvidenceSha384,
      productionRouteAttached:false,validated:true}'
}

build_ami() {
  local packer_bin build_time build_completed_at artifact_id ami_id
  local packer_manifest_sha384 installed_package_inventory installed_package_inventory_sha384
  require_env LAYRS_RECOVERY_BUILD_SUBNET_ID
  require_env LAYRS_RECOVERY_BUILD_SECURITY_GROUP_ID
  require_env LAYRS_RECOVERY_BUILD_INSTANCE_PROFILE
  require_env LAYRS_RECOVERY_PACKER_MANIFEST
  require_env LAYRS_RECOVERY_BUILD_EVIDENCE_OUTPUT
  require_command aws
  require_command packer
  require_command sort
  require_command cat

  [[ "${LAYRS_RECOVERY_BUILD_SUBNET_ID}" =~ ^subnet-[0-9a-f]{8,17}$ ]] \
    || die "LAYRS_RECOVERY_BUILD_SUBNET_ID is malformed"
  [[ "${LAYRS_RECOVERY_BUILD_SECURITY_GROUP_ID}" =~ ^sg-[0-9a-f]{8,17}$ ]] \
    || die "LAYRS_RECOVERY_BUILD_SECURITY_GROUP_ID is malformed"
  [[ "${LAYRS_RECOVERY_BUILD_INSTANCE_PROFILE}" =~ ^layrs-production-recovery-seq159300-[A-Za-z0-9+=,.@_-]+$ ]] \
    || die "the build instance profile must be recovery-specific"
  [[ ! -e "${LAYRS_RECOVERY_PACKER_MANIFEST}" && ! -L "${LAYRS_RECOVERY_PACKER_MANIFEST}" ]] \
    || die "the Packer manifest output must not already exist"
  [[ ! -e "${LAYRS_RECOVERY_BUILD_EVIDENCE_OUTPUT}" && ! -L "${LAYRS_RECOVERY_BUILD_EVIDENCE_OUTPUT}" ]] \
    || die "the build evidence output must not already exist"
  [[ "${LAYRS_RECOVERY_PACKER_MANIFEST}" != "${LAYRS_RECOVERY_BUILD_EVIDENCE_OUTPUT}" ]] \
    || die "manifest and evidence outputs must be distinct"

  run_aws_preflight
  packer_bin="$(command -v packer)" || die "packer is unavailable"
  "${packer_bin}" init "${PACKER_TEMPLATE}"
  "${packer_bin}" validate \
    -var "aws_region=${RECOVERY_REGION}" \
    -var "source_ami_id=${LAYRS_RECOVERY_SOURCE_AMI_ID}" \
    -var "source_ami_owner=${LAYRS_RECOVERY_SOURCE_AMI_OWNER}" \
    -var "source_ami_provenance_sha384=${SOURCE_AMI_PROVENANCE_SHA384}" \
    -var "build_subnet_id=${LAYRS_RECOVERY_BUILD_SUBNET_ID}" \
    -var "build_security_group_id=${LAYRS_RECOVERY_BUILD_SECURITY_GROUP_ID}" \
    -var "build_instance_profile=${LAYRS_RECOVERY_BUILD_INSTANCE_PROFILE}" \
    -var "build_subnet_inventory_sha384=${BUILD_SUBNET_INVENTORY_SHA384}" \
    -var "build_security_group_inventory_sha384=${BUILD_SECURITY_GROUP_INVENTORY_SHA384}" \
    -var "build_instance_profile_inventory_sha384=${BUILD_INSTANCE_PROFILE_INVENTORY_SHA384}" \
    -var "builder_source_commit=${BUILDER_COMMIT}" \
    -var "parent_sha384=${EXPECTED_PARENT_SHA384}" \
    -var "phase2_template_commit=${LAYRS_RECOVERY_PHASE2_TEMPLATE_COMMIT}" \
    -var "phase2_template_sha384=${LAYRS_RECOVERY_EXPECTED_PHASE2_TEMPLATE_SHA384}" \
    -var "implementation_commit=${LAYRS_RECOVERY_IMPLEMENTATION_COMMIT}" \
    -var "packer_template_sha384=${PACKER_TEMPLATE_SHA384}" \
    -var "nitro_cli_nevra=${NITRO_CLI_NEVRA}" \
    -var "nitro_cli_rpm_sha384=${NITRO_CLI_RPM_SHA384}" \
    -var "nitro_package_inventory_sha384=${EXPECTED_PACKAGE_INVENTORY_SHA384}" \
    -var "nitro_package_set_sha384=${NITRO_PACKAGE_SET_SHA384}" \
    -var "package_install_plan=${PACKAGE_INSTALL_PLAN}" \
    -var "package_inventory_output=${PREFLIGHT_TEMP_DIR}/installed-package-inventory.txt" \
    -var "manifest_output=${LAYRS_RECOVERY_PACKER_MANIFEST}" \
    "${PACKER_TEMPLATE}"
  "${packer_bin}" build -color=false -force=false \
    -var "aws_region=${RECOVERY_REGION}" \
    -var "source_ami_id=${LAYRS_RECOVERY_SOURCE_AMI_ID}" \
    -var "source_ami_owner=${LAYRS_RECOVERY_SOURCE_AMI_OWNER}" \
    -var "source_ami_provenance_sha384=${SOURCE_AMI_PROVENANCE_SHA384}" \
    -var "build_subnet_id=${LAYRS_RECOVERY_BUILD_SUBNET_ID}" \
    -var "build_security_group_id=${LAYRS_RECOVERY_BUILD_SECURITY_GROUP_ID}" \
    -var "build_instance_profile=${LAYRS_RECOVERY_BUILD_INSTANCE_PROFILE}" \
    -var "build_subnet_inventory_sha384=${BUILD_SUBNET_INVENTORY_SHA384}" \
    -var "build_security_group_inventory_sha384=${BUILD_SECURITY_GROUP_INVENTORY_SHA384}" \
    -var "build_instance_profile_inventory_sha384=${BUILD_INSTANCE_PROFILE_INVENTORY_SHA384}" \
    -var "builder_source_commit=${BUILDER_COMMIT}" \
    -var "parent_sha384=${EXPECTED_PARENT_SHA384}" \
    -var "phase2_template_commit=${LAYRS_RECOVERY_PHASE2_TEMPLATE_COMMIT}" \
    -var "phase2_template_sha384=${LAYRS_RECOVERY_EXPECTED_PHASE2_TEMPLATE_SHA384}" \
    -var "implementation_commit=${LAYRS_RECOVERY_IMPLEMENTATION_COMMIT}" \
    -var "packer_template_sha384=${PACKER_TEMPLATE_SHA384}" \
    -var "nitro_cli_nevra=${NITRO_CLI_NEVRA}" \
    -var "nitro_cli_rpm_sha384=${NITRO_CLI_RPM_SHA384}" \
    -var "nitro_package_inventory_sha384=${EXPECTED_PACKAGE_INVENTORY_SHA384}" \
    -var "nitro_package_set_sha384=${NITRO_PACKAGE_SET_SHA384}" \
    -var "package_install_plan=${PACKAGE_INSTALL_PLAN}" \
    -var "package_inventory_output=${PREFLIGHT_TEMP_DIR}/installed-package-inventory.txt" \
    -var "manifest_output=${LAYRS_RECOVERY_PACKER_MANIFEST}" \
    "${PACKER_TEMPLATE}"

  [[ -f "${LAYRS_RECOVERY_PACKER_MANIFEST}" ]] || die "Packer manifest was not emitted"
  [[ "$(jq -er '.builds | length' "${LAYRS_RECOVERY_PACKER_MANIFEST}")" == "1" ]] \
    || die "Packer manifest must contain exactly one AMI build"
  jq -e \
    --arg purpose "layrs-seq159300-recovery" \
    --arg sourceCommit "${RECOVERY_SOURCE_COMMIT}" \
    --arg builderSourceCommit "${BUILDER_COMMIT}" \
    --arg sourceAmiId "${LAYRS_RECOVERY_SOURCE_AMI_ID}" \
    --arg sourceAmiOwner "${LAYRS_RECOVERY_SOURCE_AMI_OWNER}" \
    --arg sourceAmiProvenanceSha384 "${SOURCE_AMI_PROVENANCE_SHA384}" \
    --arg buildSubnetInventorySha384 "${BUILD_SUBNET_INVENTORY_SHA384}" \
    --arg buildSecurityGroupInventorySha384 "${BUILD_SECURITY_GROUP_INVENTORY_SHA384}" \
    --arg buildInstanceProfileInventorySha384 "${BUILD_INSTANCE_PROFILE_INVENTORY_SHA384}" \
    --arg parentSha384 "${EXPECTED_PARENT_SHA384}" \
    --arg eifSha384 "${EXPECTED_EIF_SHA384}" \
    --arg pcr0Sha384 "${EXPECTED_PCR0_SHA384}" \
    --arg phase2TemplateSha384 "${LAYRS_RECOVERY_EXPECTED_PHASE2_TEMPLATE_SHA384}" \
    --arg phase2TemplateCommit "${LAYRS_RECOVERY_PHASE2_TEMPLATE_COMMIT}" \
    --arg implementationCommit "${LAYRS_RECOVERY_IMPLEMENTATION_COMMIT}" \
    --arg packerTemplateSha384 "${PACKER_TEMPLATE_SHA384}" \
    --arg nitroCliNevra "${NITRO_CLI_NEVRA}" \
    --arg nitroCliRpmSha384 "${NITRO_CLI_RPM_SHA384}" \
    --arg nitroPackageSetSha384 "${NITRO_PACKAGE_SET_SHA384}" \
    --arg nitroPackageInventorySha384 "${EXPECTED_PACKAGE_INVENTORY_SHA384}" \
    '.builds[0].custom_data == {
      purpose:$purpose,sourceCommit:$sourceCommit,builderSourceCommit:$builderSourceCommit,sourceAmiId:$sourceAmiId,
      sourceAmiOwner:$sourceAmiOwner,sourceAmiProvenanceSha384:$sourceAmiProvenanceSha384,
      buildSubnetInventorySha384:$buildSubnetInventorySha384,
      buildSecurityGroupInventorySha384:$buildSecurityGroupInventorySha384,
      buildInstanceProfileInventorySha384:$buildInstanceProfileInventorySha384,
      parentSha384:$parentSha384,eifSha384:$eifSha384,
      pcr0Sha384:$pcr0Sha384,phase2TemplateCommit:$phase2TemplateCommit,
      phase2TemplateSha384:$phase2TemplateSha384,
      implementationCommit:$implementationCommit,packerTemplateSha384:$packerTemplateSha384,
      nitroCliNevra:$nitroCliNevra,nitroCliRpmSha384:$nitroCliRpmSha384,
      nitroPackageSetSha384:$nitroPackageSetSha384,
      nitroPackageInventorySha384:$nitroPackageInventorySha384,
      productionRouteAttached:"false",
      recoveryServicesUnchanged:"true"}' \
    "${LAYRS_RECOVERY_PACKER_MANIFEST}" >/dev/null \
    || die "Packer manifest custom data does not match reviewed recovery bindings"

  artifact_id="$(jq -er '.builds[0].artifact_id' "${LAYRS_RECOVERY_PACKER_MANIFEST}")"
  [[ "${artifact_id}" =~ ^us-east-1:ami-[0-9a-f]{8,17}$ ]] \
    || die "Packer manifest artifact ID is invalid or from the wrong region"
  ami_id="${artifact_id#us-east-1:}"
  build_time="$(jq -er '.builds[0].build_time' "${LAYRS_RECOVERY_PACKER_MANIFEST}")"
  [[ "${build_time}" =~ ^[0-9]{10,13}$ ]] || die "Packer build timestamp is invalid"
  if (( ${#build_time} == 13 )); then
    build_time="$((build_time / 1000))"
  fi
  build_completed_at="$(date -u -d "@${build_time}" '+%Y-%m-%dT%H:%M:%S.000Z')"
  packer_manifest_sha384="$(sha384_file "${LAYRS_RECOVERY_PACKER_MANIFEST}")"
  installed_package_inventory="${PREFLIGHT_TEMP_DIR}/installed-package-inventory.txt"
  [[ -f "${installed_package_inventory}" && ! -L "${installed_package_inventory}" ]] \
    || die "installed-package inventory was not downloaded from the build instance"
  installed_package_inventory_sha384="$(sha384_file "${installed_package_inventory}")"
  require_exact "installed-package inventory SHA384" "${installed_package_inventory_sha384}" \
    "${EXPECTED_PACKAGE_INVENTORY_SHA384}"
  readback_output_ami "${ami_id}"

  EVIDENCE_INPUT_TEMP="$(mktemp "${TMPDIR:-/tmp}/layrs-seq159300-parent-evidence.XXXXXX.json")"
  jq -n \
    --arg accountId "${RECOVERY_ACCOUNT_ID}" \
    --arg amiId "${ami_id}" \
    --arg buildCompletedAt "${build_completed_at}" \
    --arg eifSha384 "${EXPECTED_EIF_SHA384}" \
    --arg implementationCommit "${LAYRS_RECOVERY_IMPLEMENTATION_COMMIT}" \
    --arg parentBinarySha384 "${EXPECTED_PARENT_SHA384}" \
    --arg pcr0Sha384 "${EXPECTED_PCR0_SHA384}" \
    --arg region "${RECOVERY_REGION}" \
    --arg remediationEvidenceCommit "${REMEDIATION_EVIDENCE_COMMIT}" \
    --arg remediationIndexObjectVersionId "${REMEDIATION_INDEX_VERSION_ID}" \
    --arg sourceCommit "${RECOVERY_SOURCE_COMMIT}" \
    --arg builderSourceCommit "${BUILDER_COMMIT}" \
    --arg sourceAmiId "${LAYRS_RECOVERY_SOURCE_AMI_ID}" \
    --arg sourceAmiOwner "${LAYRS_RECOVERY_SOURCE_AMI_OWNER}" \
    --arg sourceAmiProvenanceSha384 "${SOURCE_AMI_PROVENANCE_SHA384}" \
    --arg buildSubnetInventorySha384 "${BUILD_SUBNET_INVENTORY_SHA384}" \
    --arg buildSecurityGroupInventorySha384 "${BUILD_SECURITY_GROUP_INVENTORY_SHA384}" \
    --arg buildInstanceProfileInventorySha384 "${BUILD_INSTANCE_PROFILE_INVENTORY_SHA384}" \
    --arg outputAmiInventorySha384 "${OUTPUT_AMI_INVENTORY_SHA384}" \
    --arg phase2TemplateSha384 "${LAYRS_RECOVERY_EXPECTED_PHASE2_TEMPLATE_SHA384}" \
    --arg phase2TemplateCommit "${LAYRS_RECOVERY_PHASE2_TEMPLATE_COMMIT}" \
    --arg phase2EvidenceObjectKey "${LAYRS_RECOVERY_PHASE2_EVIDENCE_OBJECT_KEY}" \
    --arg phase2EvidenceObjectVersionId "${LAYRS_RECOVERY_PHASE2_EVIDENCE_OBJECT_VERSION_ID}" \
    --arg phase2EvidenceObjectSha384 "${LAYRS_RECOVERY_PHASE2_EVIDENCE_OBJECT_SHA384}" \
    --arg implementationEvidenceObjectKey "${LAYRS_RECOVERY_IMPLEMENTATION_EVIDENCE_OBJECT_KEY}" \
    --arg implementationEvidenceObjectVersionId "${LAYRS_RECOVERY_IMPLEMENTATION_EVIDENCE_OBJECT_VERSION_ID}" \
    --arg implementationEvidenceObjectSha384 "${LAYRS_RECOVERY_IMPLEMENTATION_EVIDENCE_OBJECT_SHA384}" \
    --arg packerTemplateSha384 "${PACKER_TEMPLATE_SHA384}" \
    --arg packerManifestSha384 "${packer_manifest_sha384}" \
    --arg nitroCliNevra "${NITRO_CLI_NEVRA}" \
    --arg nitroCliRpmObjectKey "${NITRO_CLI_RPM_OBJECT_KEY}" \
    --arg nitroCliRpmObjectVersionId "${NITRO_CLI_RPM_OBJECT_VERSION_ID}" \
    --arg nitroCliRpmSha384 "${NITRO_CLI_RPM_SHA384}" \
    --arg nitroPackageSetObjectKey "${LAYRS_RECOVERY_NITRO_PACKAGE_SET_OBJECT_KEY}" \
    --arg nitroPackageSetObjectVersionId "${LAYRS_RECOVERY_NITRO_PACKAGE_SET_OBJECT_VERSION_ID}" \
    --arg nitroPackageSetSha384 "${LAYRS_RECOVERY_NITRO_PACKAGE_SET_SHA384}" \
    --arg nitroPackageSetEvidenceObjectKey "${LAYRS_RECOVERY_NITRO_PACKAGE_SET_EVIDENCE_OBJECT_KEY}" \
    --arg nitroPackageSetEvidenceObjectVersionId "${LAYRS_RECOVERY_NITRO_PACKAGE_SET_EVIDENCE_OBJECT_VERSION_ID}" \
    --arg nitroPackageSetEvidenceSha384 "${LAYRS_RECOVERY_NITRO_PACKAGE_SET_EVIDENCE_SHA384}" \
    --arg nitroPackageInventorySha384 "${installed_package_inventory_sha384}" \
    '{protocol:"layrs.seq159300.recovery-parent-build-evidence.v1",
      accountId:$accountId,amiId:$amiId,buildCompletedAt:$buildCompletedAt,
      eifSha384:$eifSha384,environment:"production",implementationCommit:$implementationCommit,
      parentBinarySha384:$parentBinarySha384,pcr0Sha384:$pcr0Sha384,region:$region,
      remediationEvidenceCommit:$remediationEvidenceCommit,
      remediationIndexObjectVersionId:$remediationIndexObjectVersionId,
      sourceCommit:$sourceCommit,builderSourceCommit:$builderSourceCommit,sourceAmiId:$sourceAmiId,
      sourceAmiOwner:$sourceAmiOwner,sourceAmiProvenanceSha384:$sourceAmiProvenanceSha384,
      buildSubnetInventorySha384:$buildSubnetInventorySha384,
      buildSecurityGroupInventorySha384:$buildSecurityGroupInventorySha384,
      buildInstanceProfileInventorySha384:$buildInstanceProfileInventorySha384,
      outputAmiInventorySha384:$outputAmiInventorySha384,
      phase2TemplateCommit:$phase2TemplateCommit,phase2TemplateSha384:$phase2TemplateSha384,
      phase2EvidenceObjectKey:$phase2EvidenceObjectKey,
      phase2EvidenceObjectVersionId:$phase2EvidenceObjectVersionId,
      phase2EvidenceObjectSha384:$phase2EvidenceObjectSha384,
      implementationEvidenceObjectKey:$implementationEvidenceObjectKey,
      implementationEvidenceObjectVersionId:$implementationEvidenceObjectVersionId,
      implementationEvidenceObjectSha384:$implementationEvidenceObjectSha384,
      packerTemplateSha384:$packerTemplateSha384,packerManifestSha384:$packerManifestSha384,
      nitroCliNevra:$nitroCliNevra,nitroPackageInventorySha384:$nitroPackageInventorySha384,
      nitroCliRpmObjectKey:$nitroCliRpmObjectKey,
      nitroCliRpmObjectVersionId:$nitroCliRpmObjectVersionId,nitroCliRpmSha384:$nitroCliRpmSha384,
      nitroPackageSetObjectKey:$nitroPackageSetObjectKey,
      nitroPackageSetObjectVersionId:$nitroPackageSetObjectVersionId,
      nitroPackageSetSha384:$nitroPackageSetSha384,
      nitroPackageSetEvidenceObjectKey:$nitroPackageSetEvidenceObjectKey,
      nitroPackageSetEvidenceObjectVersionId:$nitroPackageSetEvidenceObjectVersionId,
      nitroPackageSetEvidenceSha384:$nitroPackageSetEvidenceSha384}' \
    >"${EVIDENCE_INPUT_TEMP}"
  node "${EVIDENCE_RENDERER}" --input "${EVIDENCE_INPUT_TEMP}" \
    --output "${LAYRS_RECOVERY_BUILD_EVIDENCE_OUTPUT}"
  printf 'buildEvidenceSha384=%s\n' "$(sha384_file "${LAYRS_RECOVERY_BUILD_EVIDENCE_OUTPUT}")"
}

main() {
  require_command git
  require_command jq
  require_command sha384sum
  require_command awk
  require_command date
  require_command mktemp
  require_command basename
  require_command rmdir
  require_command node
  require_command rpm
  require_command rpmkeys
  require_command find
  require_command wc
  require_command cmp
  require_command tar
  cd -- "${REPO_ROOT}"
  verify_repository
  verify_inputs

  case "${1:-}" in
    --validate-only)
      [[ "$#" == "1" ]] || die "--validate-only accepts no additional arguments"
      summary
      ;;
    --build)
      [[ "$#" == "1" ]] || die "--build accepts no additional arguments"
      build_ami
      ;;
    *)
      die "use exactly --validate-only or --build"
      ;;
  esac
}

main "$@"
