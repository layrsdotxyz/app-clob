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

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
readonly PACKER_TEMPLATE="${REPO_ROOT}/enclave/packer/layrs-seq159300-recovery-parent.pkr.hcl"
readonly PARENT_BINARY="${REPO_ROOT}/build/layrs-enclave-parent"
readonly EIF_BINARY="${REPO_ROOT}/build/layrsv2-clob.eif"
readonly EIF_MEASUREMENTS="${REPO_ROOT}/build/layrsv2-clob-measurements.json"
readonly EVIDENCE_RENDERER="${REPO_ROOT}/scripts/render-seq159300-recovery-parent-evidence.mjs"
EVIDENCE_INPUT_TEMP=""

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
  git -C "${REPO_ROOT}" merge-base --is-ancestor "${RECOVERY_SOURCE_COMMIT}" "${head}" \
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

  require_exact LAYRS_RECOVERY_ACCOUNT_ID "${LAYRS_RECOVERY_ACCOUNT_ID}" "${RECOVERY_ACCOUNT_ID}"
  require_exact LAYRS_RECOVERY_AWS_REGION "${LAYRS_RECOVERY_AWS_REGION}" "${RECOVERY_REGION}"
  require_exact LAYRS_RECOVERY_SOURCE_AMI_OWNER "${LAYRS_RECOVERY_SOURCE_AMI_OWNER}" "${AL2023_OWNER_ID}"
  [[ "${LAYRS_RECOVERY_SOURCE_AMI_ID}" =~ ^ami-[0-9a-f]{8,17}$ ]] \
    || die "LAYRS_RECOVERY_SOURCE_AMI_ID must be one exact pinned AMI ID"
  [[ "${LAYRS_RECOVERY_IMPLEMENTATION_COMMIT}" =~ ^[0-9a-f]{40}$ ]] \
    || die "LAYRS_RECOVERY_IMPLEMENTATION_COMMIT must be an exact lowercase commit"
  [[ "${LAYRS_RECOVERY_EXPECTED_PHASE2_TEMPLATE_SHA384}" =~ ^[0-9a-f]{96}$ ]] \
    || die "LAYRS_RECOVERY_EXPECTED_PHASE2_TEMPLATE_SHA384 is malformed"

  [[ -f "${LAYRS_RECOVERY_PHASE2_TEMPLATE_FILE}" && ! -L "${LAYRS_RECOVERY_PHASE2_TEMPLATE_FILE}" ]] \
    || die "the reviewed Phase2 template is not a regular file"
  phase2_template_sha="$(sha384_file "${LAYRS_RECOVERY_PHASE2_TEMPLATE_FILE}")"
  require_exact "reviewed Phase2 template SHA384" "${phase2_template_sha}" \
    "${LAYRS_RECOVERY_EXPECTED_PHASE2_TEMPLATE_SHA384}"

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

summary() {
  jq -n -c \
    --arg accountId "${RECOVERY_ACCOUNT_ID}" \
    --arg region "${RECOVERY_REGION}" \
    --arg purpose "layrs-seq159300-recovery" \
    --arg sourceCommit "${RECOVERY_SOURCE_COMMIT}" \
    --arg sourceAmiId "${LAYRS_RECOVERY_SOURCE_AMI_ID}" \
    --arg sourceAmiOwner "${LAYRS_RECOVERY_SOURCE_AMI_OWNER}" \
    --arg parentBinarySha384 "${EXPECTED_PARENT_SHA384}" \
    --arg eifSha384 "${EXPECTED_EIF_SHA384}" \
    --arg pcr0Sha384 "${EXPECTED_PCR0_SHA384}" \
    --arg phase2TemplateSha384 "${LAYRS_RECOVERY_EXPECTED_PHASE2_TEMPLATE_SHA384}" \
    --arg implementationCommit "${LAYRS_RECOVERY_IMPLEMENTATION_COMMIT}" \
    '{accountId:$accountId,region:$region,purpose:$purpose,sourceCommit:$sourceCommit,
      sourceAmiId:$sourceAmiId,sourceAmiOwner:$sourceAmiOwner,
      parentBinarySha384:$parentBinarySha384,eifSha384:$eifSha384,pcr0Sha384:$pcr0Sha384,
      phase2TemplateSha384:$phase2TemplateSha384,implementationCommit:$implementationCommit,
      productionRouteAttached:false,validated:true}'
}

build_ami() {
  local packer_bin build_time build_completed_at artifact_id ami_id
  require_env LAYRS_RECOVERY_BUILD_SUBNET_ID
  require_env LAYRS_RECOVERY_BUILD_SECURITY_GROUP_ID
  require_env LAYRS_RECOVERY_BUILD_INSTANCE_PROFILE
  require_env LAYRS_RECOVERY_PACKER_MANIFEST
  require_env LAYRS_RECOVERY_BUILD_EVIDENCE_OUTPUT

  [[ "${LAYRS_RECOVERY_BUILD_SUBNET_ID}" =~ ^subnet-[0-9a-f]{8,17}$ ]] \
    || die "LAYRS_RECOVERY_BUILD_SUBNET_ID is malformed"
  [[ "${LAYRS_RECOVERY_BUILD_SECURITY_GROUP_ID}" =~ ^sg-[0-9a-f]{8,17}$ ]] \
    || die "LAYRS_RECOVERY_BUILD_SECURITY_GROUP_ID is malformed"
  [[ "${LAYRS_RECOVERY_BUILD_INSTANCE_PROFILE}" =~ ^layrs-seq159300-recovery-[A-Za-z0-9+=,.@_-]+$ ]] \
    || die "the build instance profile must be recovery-specific"
  [[ ! -e "${LAYRS_RECOVERY_PACKER_MANIFEST}" && ! -L "${LAYRS_RECOVERY_PACKER_MANIFEST}" ]] \
    || die "the Packer manifest output must not already exist"
  [[ ! -e "${LAYRS_RECOVERY_BUILD_EVIDENCE_OUTPUT}" && ! -L "${LAYRS_RECOVERY_BUILD_EVIDENCE_OUTPUT}" ]] \
    || die "the build evidence output must not already exist"
  [[ "${LAYRS_RECOVERY_PACKER_MANIFEST}" != "${LAYRS_RECOVERY_BUILD_EVIDENCE_OUTPUT}" ]] \
    || die "manifest and evidence outputs must be distinct"

  packer_bin="$(command -v packer)" || die "packer is unavailable"
  "${packer_bin}" init "${PACKER_TEMPLATE}"
  "${packer_bin}" validate \
    -var "aws_region=${RECOVERY_REGION}" \
    -var "source_ami_id=${LAYRS_RECOVERY_SOURCE_AMI_ID}" \
    -var "source_ami_owner=${LAYRS_RECOVERY_SOURCE_AMI_OWNER}" \
    -var "build_subnet_id=${LAYRS_RECOVERY_BUILD_SUBNET_ID}" \
    -var "build_security_group_id=${LAYRS_RECOVERY_BUILD_SECURITY_GROUP_ID}" \
    -var "build_instance_profile=${LAYRS_RECOVERY_BUILD_INSTANCE_PROFILE}" \
    -var "parent_sha384=${EXPECTED_PARENT_SHA384}" \
    -var "phase2_template_sha384=${LAYRS_RECOVERY_EXPECTED_PHASE2_TEMPLATE_SHA384}" \
    -var "implementation_commit=${LAYRS_RECOVERY_IMPLEMENTATION_COMMIT}" \
    -var "manifest_output=${LAYRS_RECOVERY_PACKER_MANIFEST}" \
    "${PACKER_TEMPLATE}"
  "${packer_bin}" build -color=false -force=false \
    -var "aws_region=${RECOVERY_REGION}" \
    -var "source_ami_id=${LAYRS_RECOVERY_SOURCE_AMI_ID}" \
    -var "source_ami_owner=${LAYRS_RECOVERY_SOURCE_AMI_OWNER}" \
    -var "build_subnet_id=${LAYRS_RECOVERY_BUILD_SUBNET_ID}" \
    -var "build_security_group_id=${LAYRS_RECOVERY_BUILD_SECURITY_GROUP_ID}" \
    -var "build_instance_profile=${LAYRS_RECOVERY_BUILD_INSTANCE_PROFILE}" \
    -var "parent_sha384=${EXPECTED_PARENT_SHA384}" \
    -var "phase2_template_sha384=${LAYRS_RECOVERY_EXPECTED_PHASE2_TEMPLATE_SHA384}" \
    -var "implementation_commit=${LAYRS_RECOVERY_IMPLEMENTATION_COMMIT}" \
    -var "manifest_output=${LAYRS_RECOVERY_PACKER_MANIFEST}" \
    "${PACKER_TEMPLATE}"

  [[ -f "${LAYRS_RECOVERY_PACKER_MANIFEST}" ]] || die "Packer manifest was not emitted"
  [[ "$(jq -er '.builds | length' "${LAYRS_RECOVERY_PACKER_MANIFEST}")" == "1" ]] \
    || die "Packer manifest must contain exactly one AMI build"
  jq -e \
    --arg purpose "layrs-seq159300-recovery" \
    --arg sourceCommit "${RECOVERY_SOURCE_COMMIT}" \
    --arg sourceAmiId "${LAYRS_RECOVERY_SOURCE_AMI_ID}" \
    --arg sourceAmiOwner "${LAYRS_RECOVERY_SOURCE_AMI_OWNER}" \
    --arg parentSha384 "${EXPECTED_PARENT_SHA384}" \
    --arg eifSha384 "${EXPECTED_EIF_SHA384}" \
    --arg pcr0Sha384 "${EXPECTED_PCR0_SHA384}" \
    --arg phase2TemplateSha384 "${LAYRS_RECOVERY_EXPECTED_PHASE2_TEMPLATE_SHA384}" \
    --arg implementationCommit "${LAYRS_RECOVERY_IMPLEMENTATION_COMMIT}" \
    '.builds[0].custom_data == {
      purpose:$purpose,sourceCommit:$sourceCommit,sourceAmiId:$sourceAmiId,
      sourceAmiOwner:$sourceAmiOwner,parentSha384:$parentSha384,eifSha384:$eifSha384,
      pcr0Sha384:$pcr0Sha384,phase2TemplateSha384:$phase2TemplateSha384,
      implementationCommit:$implementationCommit,productionRouteAttached:"false",
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
    '{protocol:"layrs.seq159300.recovery-parent-build-evidence.v1",
      accountId:$accountId,amiId:$amiId,buildCompletedAt:$buildCompletedAt,
      eifSha384:$eifSha384,environment:"production",implementationCommit:$implementationCommit,
      parentBinarySha384:$parentBinarySha384,pcr0Sha384:$pcr0Sha384,region:$region,
      remediationEvidenceCommit:$remediationEvidenceCommit,
      remediationIndexObjectVersionId:$remediationIndexObjectVersionId,
      sourceCommit:$sourceCommit}' >"${EVIDENCE_INPUT_TEMP}"
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
  require_command node
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
