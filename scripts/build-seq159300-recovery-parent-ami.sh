#!/usr/bin/env bash
set -euo pipefail

umask 077

readonly RECOVERY_ACCOUNT_ID="082223548516"
readonly RECOVERY_REGION="us-east-1"
readonly RECOVERY_SOURCE_COMMIT="f282583cae7a5c873a26aa8d0c1bec10c490eb8e"
readonly REMEDIATION_EVIDENCE_COMMIT="540fc566c83dee2c3226862cc71a95541bc69af7"
readonly REMEDIATION_INDEX_VERSION_ID="oBGf0odkWa6tzYpml_UtGemDwXI6GdXy"
readonly ACCEPTED_PHASE2_TEMPLATE_COMMIT="23f92bc64171862abc410af953321a991e5e1515"
readonly ACCEPTED_BUILDER_TEMPLATE_SHA384="75e536d6d138b88aaf7ef29fece2f67f3e6ffbda02841092de73726795b4d55a6fe01af492d8d8d1f0d3dc7f8db105d7"
readonly ACCEPTED_INVOKER_TEMPLATE_SHA384="d67e4f78be6bd679b4ab61e316215fce24035e89508baaefcf3b2df6209682fd94dc0fcd84bac1530664f02aaf7723e1"
readonly ACCEPTED_TEMPLATE_PUBLISHER_SHA384="6eefb0154b78e08949ffb677a5179782cd17ab3f9a2f3d68ddf65789ce085b73aa9f76ad13821aff06fe9d853153d529"
readonly ACCEPTED_CLEANUP_TEMPLATE_SHA384="72c5872db412726d8e56c0c078067bae19c8cf316bba204f0849a6ae34bc504792b12601f023f76efdf81b750a6aa77c"
readonly EXPECTED_PARENT_SHA384="d9506bf11627b04bd5d220e18e78584cd5e649952fe380309346d9c6bbecd511eb318cdcdee6a1d0db989d581a742db1"
readonly EXPECTED_EIF_SHA384="958e084e0a66d0aca6773193a74d40659cd258fcffa116b0117fed1fab8361046ffea6411379b72fc72c97b86f611290"
readonly REJECTED_BUILD_A_EIF_SHA384="110c31235f36fa85e4a50d61fb89ab3a08e5b18587a35dfe4818c3615eed5a79513082df101e5c655fce8c7640d66ad8"
readonly EXPECTED_PCR0_SHA384="57fc48ad4d755edda38665bc8f0a16e7fd9dc485e3b57a2bce9070f60bd3b9724711ff973175340d5ebbfed4d63b7fac"
readonly AL2023_OWNER_ID="137112412989"
readonly AL2023_AMI_ID="ami-0332d564d76dbd8d6"
readonly IMMUTABLE_EVIDENCE_BUCKET="layrs-production-082223548516-us-east-1-immutable"
readonly PACKER_CONTROL_ROLE_NAME="layrs-production-recovery-seq159300-packer-control"
readonly AMAZON_LINUX_SIGNING_KEY_ID="D832C631"
readonly AMAZON_LINUX_SIGNING_KEY_FINGERPRINT="B21C50FA44A99720EAA72F7FE951904AD832C631"
readonly AMAZON_LINUX_SIGNING_KEY_SHA256="664b632018bd84f9b249be7bd26937c560edb2f2bfc0cbc01ec5a7b4e06aad56"
readonly PACKER_CLI_VERSION="1.16.0"
readonly PACKER_CLI_ARCHIVE_SHA256="5edcd14ab59b535040c512dbecd6ec9ef976a000b073c19d93e4c431c948581e"
readonly PACKER_CLI_SHA256="1c327cd37ce76790c9c10ebda1af3981554cc4eceaed1d6fdfdb59d5ccfe25d5"
readonly PACKER_CLI_SHA384="acdd742a9f7a9e32715e81e72c8d0622ac1a700779e2b1480d89544bec89761655fa07a1fc75edaf35d337fcd318d126"
readonly PACKER_CLI_CHECKSUMS_SHA256="643b26ebd70a17ee487f789c594fc9ac87007e7aba9e863df6a10c266bdc7da0"
readonly PACKER_CLI_SIGNATURE_SHA256="3a40ebe8397ef0a2fddb5214a6051d021c9b89db58af9cd1eac21d3e6c80f982"
readonly PACKER_AMAZON_PLUGIN_VERSION="1.3.9"
readonly PACKER_AMAZON_PLUGIN_FILENAME="packer-plugin-amazon_v1.3.9_x5.0_linux_amd64"
readonly PACKER_AMAZON_PLUGIN_ARCHIVE_SHA256="c4de5f441958d02ca2a6efa6d156e3a2a8c2f556b68f7fd1832e53c90d1e605d"
readonly PACKER_AMAZON_PLUGIN_SHA256="a46e0d719dfc34e51ecaf50b9b575087a8007e3df2d856ed19fb91714539b87b"
readonly PACKER_AMAZON_PLUGIN_SHA384="72d1f95616192ce9b5f7f4011b43e2fee43c48c464fd03b99b5d1bd23b49940a9b41a2151a2240a670d063b9aa53e973"
readonly PACKER_AMAZON_PLUGIN_CHECKSUMS_SHA256="6d8797b95727c3ce85afae0dfedbbf27f6ff8a8cd780467b9fa74d2c20414083"
readonly PACKER_AMAZON_PLUGIN_SIGNATURE_SHA256="e103534fafb5f4702f08123e0a5e190fef193e3db2c9ae26f4f80a35c12f9e3a"
readonly PACKER_TOOLCHAIN_PROVENANCE_SHA256="9f116d64eba294c61582335d74a4812b287d9a9c601787ea7454cb030ebebb33"
readonly PACKER_TOOLCHAIN_MANIFEST_SHA256="6a6d597535481836605a4cc9762755038e56e524af621356e5f5f65519c6858e"
readonly HASHICORP_SIGNING_KEY_SHA256="c2f5bc1163bd8d15a711616b587bcede212d045a5b8b52df01c74095897cd065"
readonly HASHICORP_PRIMARY_FINGERPRINT="C874011F0AB405110D02105534365D9472D7468F"
readonly HASHICORP_RELEASE_FINGERPRINT="374EC75B485913604A831CC7C820C6D5CD27AB87"

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
readonly PACKER_TEMPLATE="${REPO_ROOT}/enclave/packer/layrs-seq159300-recovery-parent.pkr.hcl"
readonly PACKER_TOOLCHAIN_MANIFEST="${REPO_ROOT}/enclave/packer/layrs-seq159300-packer-toolchain-provenance.v1.json"
readonly PARENT_BINARY="${REPO_ROOT}/build/layrs-enclave-parent"
readonly EIF_BINARY="${REPO_ROOT}/build/layrsv2-clob.eif"
readonly EIF_MEASUREMENTS="${REPO_ROOT}/build/layrsv2-clob-measurements.json"
readonly NITRO_PACKAGE_SET_MANIFEST="${REPO_ROOT}/build/seq159300-nitro-package-set.json"
readonly NITRO_PACKAGE_SET_ARCHIVE="${REPO_ROOT}/build/seq159300-nitro-packages.tar"
readonly NITRO_PACKAGE_DIRECTORY="${REPO_ROOT}/build/seq159300-nitro-packages"
readonly EVIDENCE_RENDERER="${REPO_ROOT}/scripts/render-seq159300-recovery-parent-evidence.mjs"
readonly POST_BUILD_EVIDENCE_RENDERER="${REPO_ROOT}/scripts/render-seq159300-recovery-parent-post-build-cleanup-evidence.mjs"
readonly PREFLIGHT_VALIDATOR="${REPO_ROOT}/scripts/lib/seq159300-recovery-parent-preflight.mjs"
readonly RECOVERY_RUNBOOK="${REPO_ROOT}/docs/runbooks/LAYRS_SEQ159300_RECOVERY_PARENT_AMI.md"
EVIDENCE_INPUT_TEMP=""
PREFLIGHT_TEMP_DIR=""
PACKER_TOOLCHAIN_TEMP_DIR=""
PACKER_BINARY=""
PACKER_PLUGIN_BINARY=""
PARENT_PACKAGE_COMMIT=""
PARENT_BUILD_WRAPPER_SHA384=""
PARENT_PREFLIGHT_SHA384=""
PARENT_BUILD_EVIDENCE_RENDERER_SHA384=""
PARENT_POST_BUILD_CLEANUP_EVIDENCE_RENDERER_SHA384=""
PARENT_RUNBOOK_SHA384=""
PACKER_TEMPLATE_SHA384=""
EXPECTED_PACKAGE_INVENTORY_SHA384=""
NITRO_PACKAGE_SET_SHA384=""
NITRO_PACKAGE_SET_EVIDENCE_SHA384=""
NITRO_PACKAGE_CLOSURE_SHA384=""
NITRO_CLI_NEVRA=""
NITRO_CLI_RPM_SHA384=""
NITRO_CLI_RPM_OBJECT_KEY=""
NITRO_CLI_RPM_OBJECT_VERSION_ID=""
PACKAGE_INSTALL_PLAN=""
SOURCE_AMI_PROVENANCE_SHA384=""
BUILD_SUBNET_INVENTORY_SHA384=""
BUILD_SECURITY_GROUP_INVENTORY_SHA384=""
BUILD_INSTANCE_PROFILE_INVENTORY_SHA384=""
BUILD_CONTROL_PLANE_ROLE_INVENTORY_SHA384=""
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

sha256_file() {
  sha256sum --binary "$1" | awk '{print $1}'
}

require_canonical_json_file() {
  local file="$1"
  local canonical
  canonical="$(jq -cS . "${file}")" || die "immutable JSON evidence cannot be parsed"
  cmp -s -- "${file}" <(printf '%s\n' "${canonical}") \
    || die "immutable JSON evidence is not exact canonical JSON plus one newline"
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
  if [[ -n "${PACKER_TOOLCHAIN_TEMP_DIR}" && -d "${PACKER_TOOLCHAIN_TEMP_DIR}" \
      && "$(basename -- "${PACKER_TOOLCHAIN_TEMP_DIR}")" == layrs-seq159300-packer-toolchain.* ]]; then
    find "${PACKER_TOOLCHAIN_TEMP_DIR}" -depth -delete
  fi
}

require_local_toolchain_file() {
  local label="$1" path="$2" mode="$3"
  [[ -f "${path}" && ! -L "${path}" ]] || die "${label} is missing, linked or not a regular file"
  require_exact "${label} owner" "$(stat -c '%u' -- "${path}")" "$(id -u)"
  require_exact "${label} mode" "$(stat -c '%a' -- "${path}")" "${mode}"
  require_exact "${label} link count" "$(stat -c '%h' -- "${path}")" "1"
}

assert_isolated_packer_toolchain() {
  local installed_output
  [[ -n "${PACKER_BINARY}" && -n "${PACKER_PLUGIN_BINARY}" ]] \
    || die "the exact reviewed Packer toolchain was not initialized"
  require_local_toolchain_file "isolated Packer CLI" "${PACKER_BINARY}" "500"
  require_local_toolchain_file "isolated Amazon plugin" "${PACKER_PLUGIN_BINARY}" "500"
  require_exact "isolated Packer CLI SHA256" "$(sha256_file "${PACKER_BINARY}")" "${PACKER_CLI_SHA256}"
  require_exact "isolated Packer CLI SHA384" "$(sha384_file "${PACKER_BINARY}")" "${PACKER_CLI_SHA384}"
  require_exact "isolated Amazon plugin SHA256" "$(sha256_file "${PACKER_PLUGIN_BINARY}")" \
    "${PACKER_AMAZON_PLUGIN_SHA256}"
  require_exact "isolated Amazon plugin SHA384" "$(sha384_file "${PACKER_PLUGIN_BINARY}")" \
    "${PACKER_AMAZON_PLUGIN_SHA384}"
  require_exact "Packer plugin path" "${PACKER_PLUGIN_PATH:-}" "${PACKER_TOOLCHAIN_TEMP_DIR}"
  require_exact "Packer checkpoint mode" "${CHECKPOINT_DISABLE:-}" "1"
  installed_output="$("${PACKER_BINARY}" plugins installed)"
  require_exact "isolated installed Packer plugin" "${installed_output}" "${PACKER_PLUGIN_BINARY}"
}

verify_packer_toolchain() {
  local plugin_dir checksum_file version_output manifest_input manifest_output keyring_dir
  local cli_archive_name plugin_archive_name valid_signature primary_fingerprint
  for name in LAYRS_RECOVERY_PACKER_BINARY LAYRS_RECOVERY_PACKER_CLI_ARCHIVE \
      LAYRS_RECOVERY_PACKER_CLI_CHECKSUMS LAYRS_RECOVERY_PACKER_CLI_CHECKSUMS_SIGNATURE \
      LAYRS_RECOVERY_PACKER_AMAZON_PLUGIN_BINARY LAYRS_RECOVERY_PACKER_AMAZON_PLUGIN_ARCHIVE \
      LAYRS_RECOVERY_PACKER_AMAZON_PLUGIN_CHECKSUMS \
      LAYRS_RECOVERY_PACKER_AMAZON_PLUGIN_CHECKSUMS_SIGNATURE \
      LAYRS_RECOVERY_HASHICORP_SIGNING_KEY LAYRS_RECOVERY_PACKER_TOOLCHAIN_EVIDENCE_FILE; do
    require_env "${name}"
  done
  require_local_toolchain_file "reviewed Packer CLI" "${LAYRS_RECOVERY_PACKER_BINARY}" "755"
  require_local_toolchain_file "reviewed Packer CLI archive" "${LAYRS_RECOVERY_PACKER_CLI_ARCHIVE}" "644"
  require_local_toolchain_file "reviewed Packer CLI checksums" "${LAYRS_RECOVERY_PACKER_CLI_CHECKSUMS}" "644"
  require_local_toolchain_file "reviewed Packer CLI signature" \
    "${LAYRS_RECOVERY_PACKER_CLI_CHECKSUMS_SIGNATURE}" "644"
  require_local_toolchain_file "reviewed Amazon plugin" \
    "${LAYRS_RECOVERY_PACKER_AMAZON_PLUGIN_BINARY}" "755"
  require_local_toolchain_file "reviewed Amazon plugin archive" \
    "${LAYRS_RECOVERY_PACKER_AMAZON_PLUGIN_ARCHIVE}" "644"
  require_local_toolchain_file "reviewed Amazon plugin checksums" \
    "${LAYRS_RECOVERY_PACKER_AMAZON_PLUGIN_CHECKSUMS}" "644"
  require_local_toolchain_file "reviewed Amazon plugin signature" \
    "${LAYRS_RECOVERY_PACKER_AMAZON_PLUGIN_CHECKSUMS_SIGNATURE}" "644"
  require_local_toolchain_file "reviewed HashiCorp signing key" \
    "${LAYRS_RECOVERY_HASHICORP_SIGNING_KEY}" "644"
  require_local_toolchain_file "reviewed Packer toolchain evidence" \
    "${LAYRS_RECOVERY_PACKER_TOOLCHAIN_EVIDENCE_FILE}" "644"

  require_exact "Packer toolchain manifest SHA256" "$(sha256_file "${PACKER_TOOLCHAIN_MANIFEST}")" \
    "${PACKER_TOOLCHAIN_MANIFEST_SHA256}"
  require_exact "Packer CLI archive name" "$(basename -- "${LAYRS_RECOVERY_PACKER_CLI_ARCHIVE}")" \
    "packer_1.16.0_linux_amd64.zip"
  require_exact "Packer CLI binary name" "$(basename -- "${LAYRS_RECOVERY_PACKER_BINARY}")" "packer"
  require_exact "Packer CLI checksum-list name" \
    "$(basename -- "${LAYRS_RECOVERY_PACKER_CLI_CHECKSUMS}")" "packer_1.16.0_SHA256SUMS"
  require_exact "Packer CLI signature name" \
    "$(basename -- "${LAYRS_RECOVERY_PACKER_CLI_CHECKSUMS_SIGNATURE}")" \
    "packer_1.16.0_SHA256SUMS.sig"
  require_exact "Amazon plugin archive name" \
    "$(basename -- "${LAYRS_RECOVERY_PACKER_AMAZON_PLUGIN_ARCHIVE}")" \
    "packer-plugin-amazon_v1.3.9_x5.0_linux_amd64.zip"
  require_exact "Amazon plugin binary name" \
    "$(basename -- "${LAYRS_RECOVERY_PACKER_AMAZON_PLUGIN_BINARY}")" \
    "${PACKER_AMAZON_PLUGIN_FILENAME}"
  require_exact "Amazon plugin checksum-list name" \
    "$(basename -- "${LAYRS_RECOVERY_PACKER_AMAZON_PLUGIN_CHECKSUMS}")" \
    "packer-plugin-amazon_v1.3.9_SHA256SUMS"
  require_exact "Amazon plugin signature name" \
    "$(basename -- "${LAYRS_RECOVERY_PACKER_AMAZON_PLUGIN_CHECKSUMS_SIGNATURE}")" \
    "packer-plugin-amazon_v1.3.9_SHA256SUMS.sig"
  require_exact "HashiCorp signing-key name" \
    "$(basename -- "${LAYRS_RECOVERY_HASHICORP_SIGNING_KEY}")" "hashicorp-pgp-key.txt"
  require_exact "Packer toolchain review-evidence name" \
    "$(basename -- "${LAYRS_RECOVERY_PACKER_TOOLCHAIN_EVIDENCE_FILE}")" \
    "LAYRS_SEQ159300_PACKER_TOOLCHAIN_PROVENANCE_20260824.md"
  require_exact "Packer CLI archive SHA256" "$(sha256_file "${LAYRS_RECOVERY_PACKER_CLI_ARCHIVE}")" \
    "${PACKER_CLI_ARCHIVE_SHA256}"
  require_exact "Packer CLI checksums SHA256" "$(sha256_file "${LAYRS_RECOVERY_PACKER_CLI_CHECKSUMS}")" \
    "${PACKER_CLI_CHECKSUMS_SHA256}"
  require_exact "Packer CLI signature SHA256" \
    "$(sha256_file "${LAYRS_RECOVERY_PACKER_CLI_CHECKSUMS_SIGNATURE}")" \
    "${PACKER_CLI_SIGNATURE_SHA256}"
  require_exact "Amazon plugin archive SHA256" \
    "$(sha256_file "${LAYRS_RECOVERY_PACKER_AMAZON_PLUGIN_ARCHIVE}")" \
    "${PACKER_AMAZON_PLUGIN_ARCHIVE_SHA256}"
  require_exact "Amazon plugin checksums SHA256" \
    "$(sha256_file "${LAYRS_RECOVERY_PACKER_AMAZON_PLUGIN_CHECKSUMS}")" \
    "${PACKER_AMAZON_PLUGIN_CHECKSUMS_SHA256}"
  require_exact "Amazon plugin signature SHA256" \
    "$(sha256_file "${LAYRS_RECOVERY_PACKER_AMAZON_PLUGIN_CHECKSUMS_SIGNATURE}")" \
    "${PACKER_AMAZON_PLUGIN_SIGNATURE_SHA256}"
  require_exact "HashiCorp signing key SHA256" "$(sha256_file "${LAYRS_RECOVERY_HASHICORP_SIGNING_KEY}")" \
    "${HASHICORP_SIGNING_KEY_SHA256}"
  require_exact "Packer toolchain review evidence SHA256" \
    "$(sha256_file "${LAYRS_RECOVERY_PACKER_TOOLCHAIN_EVIDENCE_FILE}")" \
    "${PACKER_TOOLCHAIN_PROVENANCE_SHA256}"

  PACKER_TOOLCHAIN_TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/layrs-seq159300-packer-toolchain.XXXXXX")"
  manifest_input="${PACKER_TOOLCHAIN_TEMP_DIR}/manifest-input.json"
  manifest_output="${PACKER_TOOLCHAIN_TEMP_DIR}/manifest-output.json"
  jq -n --slurpfile manifest "${PACKER_TOOLCHAIN_MANIFEST}" \
    '{kind:"packer-toolchain",payload:$manifest[0]}' >"${manifest_input}"
  node "${PREFLIGHT_VALIDATOR}" --input "${manifest_input}" --output "${manifest_output}" \
    || die "Packer toolchain provenance manifest is invalid"
  require_exact "canonical Packer toolchain provenance manifest" \
    "$(cat -- "${PACKER_TOOLCHAIN_MANIFEST}")" "$(cat -- "${manifest_output}")"

  keyring_dir="${PACKER_TOOLCHAIN_TEMP_DIR}/gnupg"
  install -d -m 0700 "${keyring_dir}"
  GNUPGHOME="${keyring_dir}" gpg --batch --quiet --import "${LAYRS_RECOVERY_HASHICORP_SIGNING_KEY}"
  primary_fingerprint="$(GNUPGHOME="${keyring_dir}" gpg --batch --with-colons --fingerprint \
    | awk -F: '$1 == "fpr" {print $10; exit}')"
  require_exact "HashiCorp primary signing fingerprint" "${primary_fingerprint}" \
    "${HASHICORP_PRIMARY_FINGERPRINT}"
  valid_signature="$(GNUPGHOME="${keyring_dir}" gpg --batch --status-fd 1 \
    --verify "${LAYRS_RECOVERY_PACKER_CLI_CHECKSUMS_SIGNATURE}" \
    "${LAYRS_RECOVERY_PACKER_CLI_CHECKSUMS}" 2>/dev/null \
    | awk '$1 == "[GNUPG:]" && $2 == "VALIDSIG" {print $3 ":" $NF}')"
  require_exact "Packer CLI checksum signature" "${valid_signature}" \
    "${HASHICORP_RELEASE_FINGERPRINT}:${HASHICORP_PRIMARY_FINGERPRINT}"
  valid_signature="$(GNUPGHOME="${keyring_dir}" gpg --batch --status-fd 1 \
    --verify "${LAYRS_RECOVERY_PACKER_AMAZON_PLUGIN_CHECKSUMS_SIGNATURE}" \
    "${LAYRS_RECOVERY_PACKER_AMAZON_PLUGIN_CHECKSUMS}" 2>/dev/null \
    | awk '$1 == "[GNUPG:]" && $2 == "VALIDSIG" {print $3 ":" $NF}')"
  require_exact "Amazon plugin checksum signature" "${valid_signature}" \
    "${HASHICORP_RELEASE_FINGERPRINT}:${HASHICORP_PRIMARY_FINGERPRINT}"
  cli_archive_name="$(basename -- "${LAYRS_RECOVERY_PACKER_CLI_ARCHIVE}")"
  plugin_archive_name="$(basename -- "${LAYRS_RECOVERY_PACKER_AMAZON_PLUGIN_ARCHIVE}")"
  [[ "$(awk -v hash="${PACKER_CLI_ARCHIVE_SHA256}" -v file="${cli_archive_name}" \
      '$1 == hash && $2 == file {count++} END {print count + 0}' \
      "${LAYRS_RECOVERY_PACKER_CLI_CHECKSUMS}")" == "1" ]] \
    || die "Packer CLI archive is not bound exactly once by the signed checksum list"
  [[ "$(awk -v hash="${PACKER_AMAZON_PLUGIN_ARCHIVE_SHA256}" -v file="${plugin_archive_name}" \
      '$1 == hash && $2 == file {count++} END {print count + 0}' \
      "${LAYRS_RECOVERY_PACKER_AMAZON_PLUGIN_CHECKSUMS}")" == "1" ]] \
    || die "Amazon plugin archive is not bound exactly once by the signed checksum list"
  unzip -p "${LAYRS_RECOVERY_PACKER_CLI_ARCHIVE}" packer \
    | cmp -s - "${LAYRS_RECOVERY_PACKER_BINARY}" \
    || die "reviewed Packer CLI does not equal the signed archive member"
  unzip -p "${LAYRS_RECOVERY_PACKER_AMAZON_PLUGIN_ARCHIVE}" "${PACKER_AMAZON_PLUGIN_FILENAME}" \
    | cmp -s - "${LAYRS_RECOVERY_PACKER_AMAZON_PLUGIN_BINARY}" \
    || die "reviewed Amazon plugin does not equal the signed archive member"

  plugin_dir="${PACKER_TOOLCHAIN_TEMP_DIR}/github.com/hashicorp/amazon"
  install -d -m 0700 "${PACKER_TOOLCHAIN_TEMP_DIR}/bin" "${plugin_dir}"
  PACKER_BINARY="${PACKER_TOOLCHAIN_TEMP_DIR}/bin/packer"
  PACKER_PLUGIN_BINARY="${plugin_dir}/${PACKER_AMAZON_PLUGIN_FILENAME}"
  checksum_file="${PACKER_PLUGIN_BINARY}_SHA256SUM"
  install -m 0500 "${LAYRS_RECOVERY_PACKER_BINARY}" "${PACKER_BINARY}"
  install -m 0500 "${LAYRS_RECOVERY_PACKER_AMAZON_PLUGIN_BINARY}" "${PACKER_PLUGIN_BINARY}"
  printf '%s' "${PACKER_AMAZON_PLUGIN_SHA256}" >"${checksum_file}"
  chmod 0400 "${checksum_file}"
  unset PACKER_CACHE_DIR PACKER_CONFIG PACKER_CONFIG_DIR PACKER_GITHUB_API_TOKEN PACKER_HOME_DIR
  unset PACKER_LOG PACKER_LOG_PATH PACKER_LOG_SECRET_FILTER HCP_CLIENT_ID HCP_CLIENT_SECRET
  unset PACKER_PLUGIN_PATH CHECKPOINT_DISABLE PACKER_NO_COLOR
  [[ -z "$(compgen -e | awk '/^(PACKER_|HCP_|CHECKPOINT_)/ {print; exit}')" ]] \
    || die "unreviewed Packer, HCP or checkpoint environment overrides remain set"
  export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  export PACKER_PLUGIN_PATH="${PACKER_TOOLCHAIN_TEMP_DIR}"
  export CHECKPOINT_DISABLE=1
  export PACKER_NO_COLOR=1
  export LC_ALL=C LANG=C
  version_output="$("${PACKER_BINARY}" version | sed -n '1p')"
  require_exact "Packer CLI version" "${version_output}" "Packer v${PACKER_CLI_VERSION}"
  assert_isolated_packer_toolchain
}

verify_nitro_package_set() {
  local input output package_count filename package_name expected_sha expected_nevra actual_nevra check_output archive_listing
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
    --arg expectedPackageClosureSha384 "${LAYRS_RECOVERY_EXPECTED_NITRO_PACKAGE_CLOSURE_SHA384}" \
    '{kind:"nitro-package-set",payload:{expectedPackageClosureSha384:$expectedPackageClosureSha384,
      manifest:$manifest[0]}}' >"${input}"
  node "${PREFLIGHT_VALIDATOR}" --input "${input}" --output "${output}" \
    || { rm -f -- "${input}" "${output}"; die "Nitro package-set manifest is invalid"; }
  rm -f -- "${input}"
  cmp -s -- "${NITRO_PACKAGE_SET_MANIFEST}" "${output}" \
    || die "Nitro package-set manifest is not the exact canonical JSON encoding"
  NITRO_PACKAGE_SET_SHA384="$(sha384_file "${NITRO_PACKAGE_SET_ARCHIVE}")"
  NITRO_PACKAGE_SET_EVIDENCE_SHA384="$(sha384_file "${NITRO_PACKAGE_SET_MANIFEST}")"
  NITRO_PACKAGE_CLOSURE_SHA384="$(jq -er '.packageClosureSha384' "${output}")"
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
  while IFS=$'\t' read -r filename package_name expected_sha expected_nevra; do
    [[ -f "${NITRO_PACKAGE_DIRECTORY}/${filename}" && ! -L "${NITRO_PACKAGE_DIRECTORY}/${filename}" ]] \
      || die "offline Nitro package is missing or unsafe: ${filename}"
    require_exact "RPM SHA384 for ${filename}" "$(sha384_file "${NITRO_PACKAGE_DIRECTORY}/${filename}")" "${expected_sha}"
    require_exact "archived RPM SHA384 for ${filename}" \
      "$(tar -xOf "${NITRO_PACKAGE_SET_ARCHIVE}" -- "${filename}" | sha384sum --binary | awk '{print $1}')" \
      "${expected_sha}"
    check_output="$(rpmkeys --checksig --verbose "${NITRO_PACKAGE_DIRECTORY}/${filename}" 2>&1)" \
      || die "RPM signature/header verification failed for ${filename}"
    [[ "${check_output,,}" == *"key id ${AMAZON_LINUX_SIGNING_KEY_ID,,}"* && "${check_output}" == *": OK"* ]] \
      || die "RPM signature does not bind the reviewed key for ${filename}"
    actual_nevra="$(rpm -qp --qf '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}' \
      "${NITRO_PACKAGE_DIRECTORY}/${filename}")" || die "RPM header query failed for ${filename}"
    require_exact "RPM NEVRA for ${filename}" "${actual_nevra}" "${expected_nevra}"
    require_exact "RPM name for ${filename}" \
      "$(rpm -qp --qf '%{NAME}' "${NITRO_PACKAGE_DIRECTORY}/${filename}")" "${package_name}"
    printf '%s\t%s\t%s\t%s\n' "${filename}" "${expected_sha}" "${expected_nevra}" "${package_name}" >>"${PACKAGE_INSTALL_PLAN}"
  done < <(jq -r '.packages[] | [.filename,.name,.sha384,.nevra] | @tsv' "${output}")
  EXPECTED_PACKAGE_INVENTORY_SHA384="$(awk -F '\t' '{print $3 "\t" $2}' "${PACKAGE_INSTALL_PLAN}" \
    | sha384sum --binary | awk '{print $1}')"
  NITRO_CLI_NEVRA="$(jq -er '.packages[] | select(.name == "aws-nitro-enclaves-cli") | .nevra' "${output}")"
  [[ "$(jq '[.packages[] | select(.name == "aws-nitro-enclaves-cli")] | length' "${output}")" == "1" ]] \
    || die "Nitro package set must contain exactly one CLI package"
  NITRO_CLI_RPM_SHA384="$(jq -er '.packages[] | select(.name == "aws-nitro-enclaves-cli") | .sha384' "${output}")"
  NITRO_CLI_RPM_OBJECT_KEY="$(jq -er '.packages[] | select(.name == "aws-nitro-enclaves-cli") | .objectKey' "${output}")"
  NITRO_CLI_RPM_OBJECT_VERSION_ID="$(jq -er '.packages[] | select(.name == "aws-nitro-enclaves-cli") | .objectVersionId' "${output}")"
  rm -f -- "${output}"
}

verify_immutable_package_objects() {
  local downloaded response
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
}

verify_builder_contract_objects() {
  local downloaded response
  downloaded="${PREFLIGHT_TEMP_DIR}/packer-invoker-template.yml"
  response="${PREFLIGHT_TEMP_DIR}/packer-invoker-template-readback.json"
  aws_read_json s3api get-object --bucket "${IMMUTABLE_EVIDENCE_BUCKET}" \
    --key "${LAYRS_RECOVERY_PACKER_INVOKER_EVIDENCE_OBJECT_KEY}" \
    --version-id "${LAYRS_RECOVERY_PACKER_INVOKER_EVIDENCE_OBJECT_VERSION_ID}" \
    "${downloaded}" >"${response}"
  require_exact "remote Packer invoker template VersionId" "$(jq -er '.VersionId' "${response}")" \
    "${LAYRS_RECOVERY_PACKER_INVOKER_EVIDENCE_OBJECT_VERSION_ID}"
  require_exact "remote Packer invoker template SHA384" "$(sha384_file "${downloaded}")" \
    "${LAYRS_RECOVERY_PACKER_INVOKER_EVIDENCE_SHA384}"
  cmp -s -- "${downloaded}" "${LAYRS_RECOVERY_PACKER_INVOKER_TEMPLATE_FILE}" \
    || die "reviewed Packer invoker template differs from its exact immutable object version"

  downloaded="${PREFLIGHT_TEMP_DIR}/builder-template.yml"
  response="${PREFLIGHT_TEMP_DIR}/builder-template-readback.json"
  aws_read_json s3api get-object --bucket "${IMMUTABLE_EVIDENCE_BUCKET}" \
    --key "${LAYRS_RECOVERY_BUILDER_TEMPLATE_EVIDENCE_OBJECT_KEY}" \
    --version-id "${LAYRS_RECOVERY_BUILDER_TEMPLATE_EVIDENCE_OBJECT_VERSION_ID}" \
    "${downloaded}" >"${response}"
  require_exact "remote builder template VersionId" "$(jq -er '.VersionId' "${response}")" \
    "${LAYRS_RECOVERY_BUILDER_TEMPLATE_EVIDENCE_OBJECT_VERSION_ID}"
  require_exact "remote builder template SHA384" "$(sha384_file "${downloaded}")" \
    "${LAYRS_RECOVERY_BUILDER_TEMPLATE_EVIDENCE_SHA384}"
  cmp -s -- "${downloaded}" "${LAYRS_RECOVERY_BUILDER_TEMPLATE_FILE}" \
    || die "reviewed builder template differs from its exact immutable object version"

  downloaded="${PREFLIGHT_TEMP_DIR}/builder-evidence-index.json"
  response="${PREFLIGHT_TEMP_DIR}/builder-evidence-index-readback.json"
  aws_read_json s3api get-object --bucket "${IMMUTABLE_EVIDENCE_BUCKET}" \
    --key "${LAYRS_RECOVERY_BUILDER_EVIDENCE_INDEX_OBJECT_KEY}" \
    --version-id "${LAYRS_RECOVERY_BUILDER_EVIDENCE_INDEX_OBJECT_VERSION_ID}" \
    "${downloaded}" >"${response}"
  require_exact "remote builder evidence index VersionId" "$(jq -er '.VersionId' "${response}")" \
    "${LAYRS_RECOVERY_BUILDER_EVIDENCE_INDEX_OBJECT_VERSION_ID}"
  require_exact "remote builder evidence index SHA384" "$(sha384_file "${downloaded}")" \
    "${LAYRS_RECOVERY_BUILDER_EVIDENCE_INDEX_SHA384}"
  jq -e 'type == "object" and (keys | length) > 0' "${downloaded}" >/dev/null \
    || die "immutable builder evidence index is not a nonempty JSON object"
}

verify_cleanup_contract_object() {
  local canonical downloaded expected_hash expected_role hash_variable key_variable object_key
  local object_version policy_name prefix response version_variable
  downloaded="${PREFLIGHT_TEMP_DIR}/cleanup-template.yml"
  response="${PREFLIGHT_TEMP_DIR}/cleanup-template-readback.json"
  aws_read_json s3api get-object --bucket "${IMMUTABLE_EVIDENCE_BUCKET}" \
    --key "${LAYRS_RECOVERY_CLEANUP_TEMPLATE_EVIDENCE_OBJECT_KEY}" \
    --version-id "${LAYRS_RECOVERY_CLEANUP_TEMPLATE_EVIDENCE_OBJECT_VERSION_ID}" \
    "${downloaded}" >"${response}"
  require_exact "remote cleanup template VersionId" "$(jq -er '.VersionId' "${response}")" \
    "${LAYRS_RECOVERY_CLEANUP_TEMPLATE_EVIDENCE_OBJECT_VERSION_ID}"
  require_exact "remote cleanup template SHA384" "$(sha384_file "${downloaded}")" \
    "${LAYRS_RECOVERY_CLEANUP_TEMPLATE_EVIDENCE_SHA384}"
  cmp -s -- "${downloaded}" "${LAYRS_RECOVERY_CLEANUP_TEMPLATE_FILE}" \
    || die "reviewed cleanup template differs from its exact immutable object version"

  for prefix in EXECUTION SUBMITTER; do
    if [[ "${prefix}" == "EXECUTION" ]]; then
      expected_role="layrs-production-recovery-seq159300-cleanup-execution"
      policy_name="layrs-seq159300-read-delete-only"
    else
      expected_role="layrs-production-recovery-seq159300-cleanup-submitter"
      policy_name="layrs-seq159300-delete-exact-builder-stack-once"
    fi
    downloaded="${PREFLIGHT_TEMP_DIR}/cleanup-role-inventory-${prefix,,}.json"
    response="${PREFLIGHT_TEMP_DIR}/cleanup-role-inventory-${prefix,,}-readback.json"
    hash_variable="LAYRS_RECOVERY_CLEANUP_${prefix}_ROLE_INVENTORY_SHA384"
    key_variable="LAYRS_RECOVERY_CLEANUP_${prefix}_ROLE_INVENTORY_OBJECT_KEY"
    version_variable="LAYRS_RECOVERY_CLEANUP_${prefix}_ROLE_INVENTORY_OBJECT_VERSION_ID"
    expected_hash="${!hash_variable}"
    object_key="${!key_variable}"
    object_version="${!version_variable}"
    aws_read_json s3api get-object --bucket "${IMMUTABLE_EVIDENCE_BUCKET}" \
      --key "${object_key}" --version-id "${object_version}" "${downloaded}" >"${response}"
    require_exact "remote cleanup ${prefix,,} role inventory VersionId" \
      "$(jq -er '.VersionId' "${response}")" "${object_version}"
    require_exact "remote cleanup ${prefix,,} role inventory SHA384" \
      "$(sha384_file "${downloaded}")" "${expected_hash}"
    jq -e --arg role "${expected_role}" --arg policy "${policy_name}" '
      type == "object"
      and (keys | sort) == (["attachedPolicies","inlinePolicies","instanceProfiles",
        "maxSessionDuration","path","permissionsBoundaryArn","roleArn","roleId","roleName",
        "tags","trust"] | sort)
      and .roleName == $role
      and .roleArn == ("arn:aws:iam::082223548516:role/" + $role)
      and .path == "/" and .maxSessionDuration == 3600
      and .permissionsBoundaryArn == "" and .attachedPolicies == [] and .instanceProfiles == []
      and (.roleId | type == "string" and test("^ARO[A-Z0-9]{16,}$"))
      and (.inlinePolicies | length) == 1 and .inlinePolicies[0].name == $policy
      and (.inlinePolicies[0] | keys | sort) == ["document","name"]
      and (.inlinePolicies[0].document | type == "object")
      and (.tags | type == "array")
      and (.tags == (.tags | sort_by(.Key)))
      and ([.tags[].Key] | length) == ([.tags[].Key] | unique | length)
      and ([.tags[] | (keys | sort) == ["Key","Value"]] | all)
      and ([.tags[] | select(.Key == "RoleInventorySha384")] | length) == 0
    ' "${downloaded}" >/dev/null \
      || die "cleanup ${prefix,,} role inventory is noncanonical or self-referential"
    if grep -Fq -- "${expected_hash}" "${downloaded}"; then
      die "cleanup ${prefix,,} role inventory embeds its own SHA384"
    fi
    canonical="$(jq -cS . "${downloaded}")" \
      || die "cleanup ${prefix,,} role inventory cannot be canonicalized"
    require_exact "cleanup ${prefix,,} role inventory canonical bytes" \
      "$(<"${downloaded}")" "${canonical}"
  done
}

verify_publication_evidence_objects() {
  local canonical downloaded expected_hash expected_role hash_variable key_variable object_key
  local object_version prefix publication_input publication_output response version_variable
  downloaded="${PREFLIGHT_TEMP_DIR}/publisher-template.yml"
  response="${PREFLIGHT_TEMP_DIR}/publisher-template-readback.json"
  aws_read_json s3api get-object --bucket "${IMMUTABLE_EVIDENCE_BUCKET}" \
    --key "${LAYRS_RECOVERY_PUBLISHER_TEMPLATE_EVIDENCE_OBJECT_KEY}" \
    --version-id "${LAYRS_RECOVERY_PUBLISHER_TEMPLATE_EVIDENCE_OBJECT_VERSION_ID}" \
    "${downloaded}" >"${response}"
  require_exact "remote publisher template VersionId" "$(jq -er '.VersionId' "${response}")" \
    "${LAYRS_RECOVERY_PUBLISHER_TEMPLATE_EVIDENCE_OBJECT_VERSION_ID}"
  require_exact "remote publisher template SHA384" "$(sha384_file "${downloaded}")" \
    "${LAYRS_RECOVERY_PUBLISHER_TEMPLATE_EVIDENCE_SHA384}"
  cmp -s -- "${downloaded}" "${LAYRS_RECOVERY_PUBLISHER_TEMPLATE_FILE}" \
    || die "reviewed publisher template differs from its exact immutable object version"

  for prefix in TEMPLATE_PUBLISHER CLOUDFORMATION_EXECUTION; do
    if [[ "${prefix}" == "TEMPLATE_PUBLISHER" ]]; then
      expected_role="layrs-production-recovery-seq159300-template-publisher"
    else
      expected_role="layrs-production-recovery-seq159300-cloudformation-execution"
    fi
    downloaded="${PREFLIGHT_TEMP_DIR}/publisher-role-inventory-${prefix,,}.json"
    response="${PREFLIGHT_TEMP_DIR}/publisher-role-inventory-${prefix,,}-readback.json"
    hash_variable="LAYRS_RECOVERY_${prefix}_ROLE_INVENTORY_SHA384"
    key_variable="LAYRS_RECOVERY_${prefix}_ROLE_INVENTORY_OBJECT_KEY"
    version_variable="LAYRS_RECOVERY_${prefix}_ROLE_INVENTORY_OBJECT_VERSION_ID"
    expected_hash="${!hash_variable}"
    object_key="${!key_variable}"
    object_version="${!version_variable}"
    aws_read_json s3api get-object --bucket "${IMMUTABLE_EVIDENCE_BUCKET}" \
      --key "${object_key}" --version-id "${object_version}" "${downloaded}" >"${response}"
    require_exact "remote ${prefix,,} role inventory VersionId" \
      "$(jq -er '.VersionId' "${response}")" "${object_version}"
    require_exact "remote ${prefix,,} role inventory SHA384" \
      "$(sha384_file "${downloaded}")" "${expected_hash}"
    jq -e --arg role "${expected_role}" '
      type == "object"
      and (keys | sort) == (["attachedPolicies","inlinePolicies","instanceProfiles",
        "maxSessionDuration","path","permissionsBoundaryArn","roleArn","roleId","roleName",
        "tags","trust"] | sort)
      and .roleName == $role
      and .roleArn == ("arn:aws:iam::082223548516:role/" + $role)
      and .path == "/" and .maxSessionDuration == 3600
      and .permissionsBoundaryArn == "" and .instanceProfiles == []
      and (.roleId | type == "string" and test("^ARO[A-Z0-9]{16,}$"))
      and (.attachedPolicies | type == "array") and (.inlinePolicies | type == "array")
      and (.tags | type == "array")
      and (.tags == (.tags | sort_by(.Key)))
      and ([.tags[].Key] | length) == ([.tags[].Key] | unique | length)
      and ([.tags[] | (keys | sort) == ["Key","Value"]] | all)
      and ([.tags[] | select(.Key == "RoleInventorySha384")] | length) == 0
    ' "${downloaded}" >/dev/null \
      || die "${prefix,,} role inventory is noncanonical or self-referential"
    if grep -Fq -- "${expected_hash}" "${downloaded}"; then
      die "${prefix,,} role inventory embeds its own SHA384"
    fi
    canonical="$(jq -cS . "${downloaded}")" \
      || die "${prefix,,} role inventory cannot be canonicalized"
    require_exact "${prefix,,} role inventory canonical bytes" "$(<"${downloaded}")" "${canonical}"
  done

  downloaded="${PREFLIGHT_TEMP_DIR}/template-upload-receipt.json"
  response="${PREFLIGHT_TEMP_DIR}/template-upload-receipt-readback.json"
  aws_read_json s3api get-object --bucket "${IMMUTABLE_EVIDENCE_BUCKET}" \
    --key "${LAYRS_RECOVERY_TEMPLATE_UPLOAD_RECEIPT_OBJECT_KEY}" \
    --version-id "${LAYRS_RECOVERY_TEMPLATE_UPLOAD_RECEIPT_OBJECT_VERSION_ID}" \
    "${downloaded}" >"${response}"
  require_exact "remote template-upload receipt VersionId" "$(jq -er '.VersionId' "${response}")" \
    "${LAYRS_RECOVERY_TEMPLATE_UPLOAD_RECEIPT_OBJECT_VERSION_ID}"
  require_exact "remote template-upload receipt SHA384" "$(sha384_file "${downloaded}")" \
    "${LAYRS_RECOVERY_TEMPLATE_UPLOAD_RECEIPT_SHA384}"
  require_canonical_json_file "${downloaded}"
  jq -e \
    --arg accountId "${RECOVERY_ACCOUNT_ID}" --arg region "${RECOVERY_REGION}" \
    --arg bucket "${IMMUTABLE_EVIDENCE_BUCKET}" \
    --arg key "${LAYRS_RECOVERY_BUILDER_TEMPLATE_EVIDENCE_OBJECT_KEY}" \
    --arg versionId "${LAYRS_RECOVERY_BUILDER_TEMPLATE_EVIDENCE_OBJECT_VERSION_ID}" \
    --arg sha384 "${LAYRS_RECOVERY_BUILDER_TEMPLATE_SHA384}" \
    --arg publisherTemplateKey "${LAYRS_RECOVERY_PUBLISHER_TEMPLATE_EVIDENCE_OBJECT_KEY}" \
    --arg publisherTemplateVersionId "${LAYRS_RECOVERY_PUBLISHER_TEMPLATE_EVIDENCE_OBJECT_VERSION_ID}" \
    --arg publisherTemplateSha384 "${LAYRS_RECOVERY_PUBLISHER_TEMPLATE_SHA384}" \
    --arg publisherRoleInventorySha384 "${LAYRS_RECOVERY_TEMPLATE_PUBLISHER_ROLE_INVENTORY_SHA384}" \
    'keys == ["accountId","bucket","bucketControlsSha384","bucketKeyEnabled","bucketPolicySha384","createOnly","kmsKeyArn","kmsKeyPolicySha384","objectKey","objectSha384","objectVersionId","protocol","publisherPolicySha384","publisherRoleInventorySha384","publisherTemplateObject","region","retainUntil"]
      and .protocol == "layrs.seq159300.recovery-builder-template-upload-receipt.v1"
      and .accountId == $accountId and .region == $region and .bucket == $bucket
      and .objectKey == $key and .objectVersionId == $versionId and .objectSha384 == $sha384
      and .bucketKeyEnabled == false and .createOnly == true
      and .publisherRoleInventorySha384 == $publisherRoleInventorySha384
      and .publisherTemplateObject == {bucket:$bucket,key:$publisherTemplateKey,
        versionId:$publisherTemplateVersionId,sha384:$publisherTemplateSha384}
      and (.publisherPolicySha384 | test("^[0-9a-f]{96}$"))
      and (.publisherRoleInventorySha384 | test("^[0-9a-f]{96}$"))
      and (.bucketControlsSha384 | test("^[0-9a-f]{96}$"))
      and (.bucketPolicySha384 | test("^[0-9a-f]{96}$"))
      and (.kmsKeyPolicySha384 | test("^[0-9a-f]{96}$"))
      and (.kmsKeyArn | test("^arn:aws:kms:us-east-1:082223548516:key/[0-9a-f-]{36}$"))
      and (.retainUntil | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T"))' "${downloaded}" >/dev/null \
    || die "immutable template-upload receipt is malformed or not bound to the exact builder template version"

  downloaded="${PREFLIGHT_TEMP_DIR}/change-set-receipt.json"
  response="${PREFLIGHT_TEMP_DIR}/change-set-receipt-readback.json"
  aws_read_json s3api get-object --bucket "${IMMUTABLE_EVIDENCE_BUCKET}" \
    --key "${LAYRS_RECOVERY_CHANGE_SET_RECEIPT_OBJECT_KEY}" \
    --version-id "${LAYRS_RECOVERY_CHANGE_SET_RECEIPT_OBJECT_VERSION_ID}" \
    "${downloaded}" >"${response}"
  require_exact "remote change-set receipt VersionId" "$(jq -er '.VersionId' "${response}")" \
    "${LAYRS_RECOVERY_CHANGE_SET_RECEIPT_OBJECT_VERSION_ID}"
  require_exact "remote change-set receipt SHA384" "$(sha384_file "${downloaded}")" \
    "${LAYRS_RECOVERY_CHANGE_SET_RECEIPT_SHA384}"
  require_canonical_json_file "${downloaded}"
  jq -e \
    --arg accountId "${RECOVERY_ACCOUNT_ID}" --arg region "${RECOVERY_REGION}" \
    --arg bucket "${IMMUTABLE_EVIDENCE_BUCKET}" \
    --arg key "${LAYRS_RECOVERY_BUILDER_TEMPLATE_EVIDENCE_OBJECT_KEY}" \
    --arg versionId "${LAYRS_RECOVERY_BUILDER_TEMPLATE_EVIDENCE_OBJECT_VERSION_ID}" \
    --arg sha384 "${LAYRS_RECOVERY_BUILDER_TEMPLATE_SHA384}" \
    --arg publisherTemplateKey "${LAYRS_RECOVERY_PUBLISHER_TEMPLATE_EVIDENCE_OBJECT_KEY}" \
    --arg publisherTemplateVersionId "${LAYRS_RECOVERY_PUBLISHER_TEMPLATE_EVIDENCE_OBJECT_VERSION_ID}" \
    --arg publisherTemplateSha384 "${LAYRS_RECOVERY_PUBLISHER_TEMPLATE_SHA384}" \
    --arg publisherRoleInventorySha384 "${LAYRS_RECOVERY_TEMPLATE_PUBLISHER_ROLE_INVENTORY_SHA384}" \
    --arg cloudFormationExecutionRoleInventorySha384 "${LAYRS_RECOVERY_CLOUDFORMATION_EXECUTION_ROLE_INVENTORY_SHA384}" \
    'keys == ["accountId","bucketControlsSha384","bucketPolicySha384","changeSetId","changeSetName","changeSetStatus","changesSha384","cloudFormationExecutionPolicies","cloudFormationExecutionPolicySha384","cloudFormationExecutionRoleInventorySha384","executed","executionRoleArn","executionStatus","kms","kmsKeyPolicySha384","parameters","parametersSha384","protocol","publisherPolicySha384","publisherRoleArn","publisherRoleInventorySha384","publisherTemplateObject","region","stable","templateObject","templateUrl","validationSha384"]
      and .protocol == "layrs.seq159300.recovery-builder-change-set-receipt.v1"
      and .accountId == $accountId and .region == $region and .executed == false
      and .executionStatus == "AVAILABLE" and .changeSetStatus == "CREATE_COMPLETE" and .stable == true
      and (.changeSetName | test("^layrs-seq159300-builder-[0-9a-f]{12}$"))
      and (.changeSetId | test("^arn:aws:cloudformation:us-east-1:082223548516:changeSet/layrs-seq159300-builder-[0-9a-f]{12}/[0-9a-f-]{36}$"))
      and .templateObject == {bucket:$bucket,key:$key,versionId:$versionId,sha384:$sha384}
      and .publisherTemplateObject == {bucket:$bucket,key:$publisherTemplateKey,
        versionId:$publisherTemplateVersionId,sha384:$publisherTemplateSha384}
      and .templateUrl == ("https://" + $bucket + ".s3.us-east-1.amazonaws.com/" + $key + "?versionId=" + $versionId)
      and .kms.bucketKeyEnabled == false
      and .publisherRoleInventorySha384 == $publisherRoleInventorySha384
      and .cloudFormationExecutionRoleInventorySha384 == $cloudFormationExecutionRoleInventorySha384
      and .publisherRoleArn == "arn:aws:iam::082223548516:role/layrs-production-recovery-seq159300-template-publisher"
      and .executionRoleArn == "arn:aws:iam::082223548516:role/layrs-production-recovery-seq159300-cloudformation-execution"
      and (.publisherPolicySha384 | test("^[0-9a-f]{96}$"))
      and (.cloudFormationExecutionPolicySha384 | test("^[0-9a-f]{96}$"))
      and (.cloudFormationExecutionPolicies | type == "object")
      and (.bucketControlsSha384 | test("^[0-9a-f]{96}$"))
      and (.changesSha384 | test("^[0-9a-f]{96}$"))
      and (.parameters | type == "object") and (.parameters | length > 0)
      and (.parametersSha384 | test("^[0-9a-f]{96}$"))
      and (.validationSha384 | test("^[0-9a-f]{96}$"))' "${downloaded}" >/dev/null \
    || die "immutable change-set receipt is malformed or not bound to the exact unexecuted builder change set"

  publication_input="${PREFLIGHT_TEMP_DIR}/publication-evidence-input.json"
  publication_output="${PREFLIGHT_TEMP_DIR}/publication-evidence-inventory.json"
  jq -n \
    --arg builderTemplateObjectKey "${LAYRS_RECOVERY_BUILDER_TEMPLATE_EVIDENCE_OBJECT_KEY}" \
    --arg builderTemplateObjectVersionId "${LAYRS_RECOVERY_BUILDER_TEMPLATE_EVIDENCE_OBJECT_VERSION_ID}" \
    --arg builderTemplateSha384 "${LAYRS_RECOVERY_BUILDER_TEMPLATE_SHA384}" \
    --arg publisherTemplateObjectKey "${LAYRS_RECOVERY_PUBLISHER_TEMPLATE_EVIDENCE_OBJECT_KEY}" \
    --arg publisherTemplateObjectVersionId "${LAYRS_RECOVERY_PUBLISHER_TEMPLATE_EVIDENCE_OBJECT_VERSION_ID}" \
    --arg publisherTemplateSha384 "${LAYRS_RECOVERY_PUBLISHER_TEMPLATE_SHA384}" \
    --arg publisherRoleInventorySha384 "${LAYRS_RECOVERY_TEMPLATE_PUBLISHER_ROLE_INVENTORY_SHA384}" \
    --arg cloudFormationExecutionRoleInventorySha384 "${LAYRS_RECOVERY_CLOUDFORMATION_EXECUTION_ROLE_INVENTORY_SHA384}" \
    --slurpfile templateUploadReceipt "${PREFLIGHT_TEMP_DIR}/template-upload-receipt.json" \
    --slurpfile changeSetReceipt "${PREFLIGHT_TEMP_DIR}/change-set-receipt.json" \
    '{kind:"publication-evidence",payload:{builderTemplateObjectKey:$builderTemplateObjectKey,
      builderTemplateObjectVersionId:$builderTemplateObjectVersionId,
      builderTemplateSha384:$builderTemplateSha384,
      publisherTemplateObjectKey:$publisherTemplateObjectKey,
      publisherTemplateObjectVersionId:$publisherTemplateObjectVersionId,
      publisherTemplateSha384:$publisherTemplateSha384,
      publisherRoleInventorySha384:$publisherRoleInventorySha384,
      cloudFormationExecutionRoleInventorySha384:$cloudFormationExecutionRoleInventorySha384,
      templateUploadReceipt:$templateUploadReceipt[0],changeSetReceipt:$changeSetReceipt[0]}}' \
    >"${publication_input}"
  render_preflight_inventory "${publication_input}" "${publication_output}"
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
  local head changed dirty source_file
  head="$(git -C "${REPO_ROOT}" rev-parse HEAD)"
  require_env LAYRS_RECOVERY_PARENT_PACKAGE_COMMIT
  require_exact LAYRS_RECOVERY_PARENT_PACKAGE_COMMIT \
    "${LAYRS_RECOVERY_PARENT_PACKAGE_COMMIT}" "${head}"
  PARENT_PACKAGE_COMMIT="${head}"
  [[ "${PARENT_PACKAGE_COMMIT}" != "${RECOVERY_SOURCE_COMMIT}" ]] \
    || die "parent package commit must differ from the exact f282 runtime source commit"
  git -C "${REPO_ROOT}" merge-base --is-ancestor "${RECOVERY_SOURCE_COMMIT}" "${PARENT_PACKAGE_COMMIT}" \
    || die "HEAD does not descend from exact recovery source ${RECOVERY_SOURCE_COMMIT}"

  dirty="$(git -C "${REPO_ROOT}" status --porcelain=v1 --untracked-files=all)"
  [[ -z "${dirty}" ]] || die "source worktree must be clean before validation or build"

  changed="$(git -C "${REPO_ROOT}" diff --name-only "${RECOVERY_SOURCE_COMMIT}..HEAD")"
  while IFS= read -r file; do
    [[ -z "${file}" ]] && continue
    case "${file}" in
      docs/runbooks/LAYRS_SEQ159300_RECOVERY_PARENT_AMI.md | \
      enclave/packer/layrs-seq159300-packer-toolchain-provenance.v1.json | \
      enclave/packer/layrs-seq159300-recovery-parent.pkr.hcl | \
      scripts/build-seq159300-recovery-parent-ami.sh | \
      scripts/lib/seq159300-recovery-parent-preflight.mjs | \
      scripts/render-seq159300-recovery-parent-evidence.mjs | \
      scripts/render-seq159300-recovery-parent-post-build-cleanup-evidence.mjs | \
      scripts/tests/seq159300-recovery-parent.test.mjs)
        ;;
      *)
        die "non-recovery source differs from f282: ${file}"
        ;;
    esac
  done <<<"${changed}"

  for source_file in "${BASH_SOURCE[0]}" "${PREFLIGHT_VALIDATOR}" "${EVIDENCE_RENDERER}" \
      "${POST_BUILD_EVIDENCE_RENDERER}" "${RECOVERY_RUNBOOK}" "${PACKER_TEMPLATE}"; do
    [[ -f "${source_file}" && ! -L "${source_file}" ]] \
      || die "parent package source is missing, linked or not a regular file: ${source_file}"
  done
  PARENT_BUILD_WRAPPER_SHA384="$(sha384_file "${BASH_SOURCE[0]}")"
  PARENT_PREFLIGHT_SHA384="$(sha384_file "${PREFLIGHT_VALIDATOR}")"
  PARENT_BUILD_EVIDENCE_RENDERER_SHA384="$(sha384_file "${EVIDENCE_RENDERER}")"
  PARENT_POST_BUILD_CLEANUP_EVIDENCE_RENDERER_SHA384="$(sha384_file "${POST_BUILD_EVIDENCE_RENDERER}")"
  PARENT_RUNBOOK_SHA384="$(sha384_file "${RECOVERY_RUNBOOK}")"
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
  require_env LAYRS_RECOVERY_EXPECTED_NITRO_PACKAGE_CLOSURE_SHA384
  require_env LAYRS_RECOVERY_BUILDER_STACK_NAME
  require_env LAYRS_RECOVERY_BUILDER_TEMPLATE_FILE
  require_env LAYRS_RECOVERY_BUILDER_TEMPLATE_SHA384
  require_env LAYRS_RECOVERY_BUILDER_TEMPLATE_EVIDENCE_OBJECT_KEY
  require_env LAYRS_RECOVERY_BUILDER_TEMPLATE_EVIDENCE_OBJECT_VERSION_ID
  require_env LAYRS_RECOVERY_BUILDER_TEMPLATE_EVIDENCE_SHA384
  require_env LAYRS_RECOVERY_PUBLISHER_TEMPLATE_FILE
  require_env LAYRS_RECOVERY_PUBLISHER_TEMPLATE_SHA384
  require_env LAYRS_RECOVERY_PUBLISHER_TEMPLATE_EVIDENCE_OBJECT_KEY
  require_env LAYRS_RECOVERY_PUBLISHER_TEMPLATE_EVIDENCE_OBJECT_VERSION_ID
  require_env LAYRS_RECOVERY_PUBLISHER_TEMPLATE_EVIDENCE_SHA384
  require_env LAYRS_RECOVERY_TEMPLATE_PUBLISHER_ROLE_INVENTORY_SHA384
  require_env LAYRS_RECOVERY_TEMPLATE_PUBLISHER_ROLE_INVENTORY_OBJECT_KEY
  require_env LAYRS_RECOVERY_TEMPLATE_PUBLISHER_ROLE_INVENTORY_OBJECT_VERSION_ID
  require_env LAYRS_RECOVERY_CLOUDFORMATION_EXECUTION_ROLE_INVENTORY_SHA384
  require_env LAYRS_RECOVERY_CLOUDFORMATION_EXECUTION_ROLE_INVENTORY_OBJECT_KEY
  require_env LAYRS_RECOVERY_CLOUDFORMATION_EXECUTION_ROLE_INVENTORY_OBJECT_VERSION_ID
  require_env LAYRS_RECOVERY_TRUSTED_PRINCIPAL_INVENTORY_SHA384
  require_env LAYRS_RECOVERY_TEMPLATE_UPLOAD_RECEIPT_OBJECT_KEY
  require_env LAYRS_RECOVERY_TEMPLATE_UPLOAD_RECEIPT_OBJECT_VERSION_ID
  require_env LAYRS_RECOVERY_TEMPLATE_UPLOAD_RECEIPT_SHA384
  require_env LAYRS_RECOVERY_CHANGE_SET_RECEIPT_OBJECT_KEY
  require_env LAYRS_RECOVERY_CHANGE_SET_RECEIPT_OBJECT_VERSION_ID
  require_env LAYRS_RECOVERY_CHANGE_SET_RECEIPT_SHA384
  require_env LAYRS_RECOVERY_CLEANUP_TEMPLATE_FILE
  require_env LAYRS_RECOVERY_CLEANUP_TEMPLATE_SHA384
  require_env LAYRS_RECOVERY_CLEANUP_TEMPLATE_EVIDENCE_OBJECT_KEY
  require_env LAYRS_RECOVERY_CLEANUP_TEMPLATE_EVIDENCE_OBJECT_VERSION_ID
  require_env LAYRS_RECOVERY_CLEANUP_TEMPLATE_EVIDENCE_SHA384
  require_env LAYRS_RECOVERY_CLEANUP_EXECUTION_ROLE_INVENTORY_SHA384
  require_env LAYRS_RECOVERY_CLEANUP_EXECUTION_ROLE_INVENTORY_OBJECT_KEY
  require_env LAYRS_RECOVERY_CLEANUP_EXECUTION_ROLE_INVENTORY_OBJECT_VERSION_ID
  require_env LAYRS_RECOVERY_CLEANUP_SUBMITTER_ROLE_INVENTORY_SHA384
  require_env LAYRS_RECOVERY_CLEANUP_SUBMITTER_ROLE_INVENTORY_OBJECT_KEY
  require_env LAYRS_RECOVERY_CLEANUP_SUBMITTER_ROLE_INVENTORY_OBJECT_VERSION_ID
  require_env LAYRS_RECOVERY_PACKER_INVOKER_ROLE_ARN
  require_env LAYRS_RECOVERY_PACKER_INVOKER_ROLE_INVENTORY_SHA384
  require_env LAYRS_RECOVERY_PACKER_INVOKER_TEMPLATE_FILE
  require_env LAYRS_RECOVERY_PACKER_INVOKER_TEMPLATE_SHA384
  require_env LAYRS_RECOVERY_PACKER_INVOKER_EVIDENCE_OBJECT_KEY
  require_env LAYRS_RECOVERY_PACKER_INVOKER_EVIDENCE_OBJECT_VERSION_ID
  require_env LAYRS_RECOVERY_PACKER_INVOKER_EVIDENCE_SHA384
  require_env LAYRS_RECOVERY_PACKER_CONTROL_INVENTORY_POLICY_SHA384
  require_env LAYRS_RECOVERY_PACKER_CONTROL_LAUNCH_POLICY_SHA384
  require_env LAYRS_RECOVERY_PACKER_CONTROL_ARTIFACT_POLICY_SHA384
  require_env LAYRS_RECOVERY_PACKER_CONTROL_APPROVED_AT
  require_env LAYRS_RECOVERY_PACKER_CONTROL_EXPIRES_AT
  require_env LAYRS_RECOVERY_INVOKER_APPROVED_AT
  require_env LAYRS_RECOVERY_INVOKER_EXPIRES_AT
  require_env LAYRS_RECOVERY_TEMPLATE_PUBLISHER_APPROVED_AT
  require_env LAYRS_RECOVERY_TEMPLATE_PUBLISHER_EXPIRES_AT
  require_env LAYRS_RECOVERY_BUILDER_EVIDENCE_INDEX_SHA384
  require_env LAYRS_RECOVERY_BUILDER_EVIDENCE_INDEX_OBJECT_KEY
  require_env LAYRS_RECOVERY_BUILDER_EVIDENCE_INDEX_OBJECT_VERSION_ID
  require_env LAYRS_RECOVERY_EXPECTED_BUILD_CONTROL_PLANE_ROLE_INVENTORY_SHA384
  require_env LAYRS_RECOVERY_EVIDENCE_BUCKET

  [[ -f "${PREFLIGHT_VALIDATOR}" && ! -L "${PREFLIGHT_VALIDATOR}" ]] \
    || die "the recovery-parent preflight validator is missing or unsafe"

  require_exact LAYRS_RECOVERY_ACCOUNT_ID "${LAYRS_RECOVERY_ACCOUNT_ID}" "${RECOVERY_ACCOUNT_ID}"
  require_exact LAYRS_RECOVERY_AWS_REGION "${LAYRS_RECOVERY_AWS_REGION}" "${RECOVERY_REGION}"
  require_exact LAYRS_RECOVERY_SOURCE_AMI_OWNER "${LAYRS_RECOVERY_SOURCE_AMI_OWNER}" "${AL2023_OWNER_ID}"
  require_exact LAYRS_RECOVERY_SOURCE_AMI_ID "${LAYRS_RECOVERY_SOURCE_AMI_ID}" "${AL2023_AMI_ID}"
  require_exact LAYRS_RECOVERY_PHASE2_TEMPLATE_COMMIT \
    "${LAYRS_RECOVERY_PHASE2_TEMPLATE_COMMIT}" "${ACCEPTED_PHASE2_TEMPLATE_COMMIT}"
  require_exact LAYRS_RECOVERY_BUILDER_TEMPLATE_SHA384 \
    "${LAYRS_RECOVERY_BUILDER_TEMPLATE_SHA384}" "${ACCEPTED_BUILDER_TEMPLATE_SHA384}"
  require_exact LAYRS_RECOVERY_PACKER_INVOKER_TEMPLATE_SHA384 \
    "${LAYRS_RECOVERY_PACKER_INVOKER_TEMPLATE_SHA384}" "${ACCEPTED_INVOKER_TEMPLATE_SHA384}"
  require_exact LAYRS_RECOVERY_PUBLISHER_TEMPLATE_SHA384 \
    "${LAYRS_RECOVERY_PUBLISHER_TEMPLATE_SHA384}" "${ACCEPTED_TEMPLATE_PUBLISHER_SHA384}"
  require_exact LAYRS_RECOVERY_CLEANUP_TEMPLATE_SHA384 \
    "${LAYRS_RECOVERY_CLEANUP_TEMPLATE_SHA384}" "${ACCEPTED_CLEANUP_TEMPLATE_SHA384}"
  require_exact LAYRS_RECOVERY_BUILDER_STACK_NAME "${LAYRS_RECOVERY_BUILDER_STACK_NAME}" \
    "layrs-production-recovery-seq159300-builder"
  [[ "${LAYRS_RECOVERY_PACKER_INVOKER_ROLE_ARN}" =~ ^arn:aws:iam::082223548516:role/layrs-production-recovery-seq159300-[A-Za-z0-9+=,.@_-]{1,64}$ ]] \
    || die "LAYRS_RECOVERY_PACKER_INVOKER_ROLE_ARN is outside the exact recovery namespace"
  [[ "${LAYRS_RECOVERY_PACKER_CONTROL_APPROVED_AT}" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ \
      && "${LAYRS_RECOVERY_PACKER_CONTROL_EXPIRES_AT}" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] \
    || die "Packer control approval or expiry timestamp is malformed"
  for value in "${LAYRS_RECOVERY_INVOKER_APPROVED_AT}" "${LAYRS_RECOVERY_INVOKER_EXPIRES_AT}" \
      "${LAYRS_RECOVERY_TEMPLATE_PUBLISHER_APPROVED_AT}" "${LAYRS_RECOVERY_TEMPLATE_PUBLISHER_EXPIRES_AT}"; do
    [[ "${value}" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] \
      || die "invoker or template-publisher approval/expiry timestamp is malformed"
  done
  for value in "${LAYRS_RECOVERY_EXPECTED_NITRO_PACKAGE_CLOSURE_SHA384}" \
      "${LAYRS_RECOVERY_BUILDER_EVIDENCE_INDEX_SHA384}" \
      "${LAYRS_RECOVERY_BUILDER_TEMPLATE_SHA384}" \
      "${LAYRS_RECOVERY_BUILDER_TEMPLATE_EVIDENCE_SHA384}" \
      "${LAYRS_RECOVERY_PUBLISHER_TEMPLATE_SHA384}" \
      "${LAYRS_RECOVERY_PUBLISHER_TEMPLATE_EVIDENCE_SHA384}" \
      "${LAYRS_RECOVERY_TEMPLATE_PUBLISHER_ROLE_INVENTORY_SHA384}" \
      "${LAYRS_RECOVERY_CLOUDFORMATION_EXECUTION_ROLE_INVENTORY_SHA384}" \
      "${LAYRS_RECOVERY_TRUSTED_PRINCIPAL_INVENTORY_SHA384}" \
      "${LAYRS_RECOVERY_TEMPLATE_UPLOAD_RECEIPT_SHA384}" \
      "${LAYRS_RECOVERY_CHANGE_SET_RECEIPT_SHA384}" \
      "${LAYRS_RECOVERY_CLEANUP_TEMPLATE_SHA384}" \
      "${LAYRS_RECOVERY_CLEANUP_TEMPLATE_EVIDENCE_SHA384}" \
      "${LAYRS_RECOVERY_CLEANUP_EXECUTION_ROLE_INVENTORY_SHA384}" \
      "${LAYRS_RECOVERY_CLEANUP_SUBMITTER_ROLE_INVENTORY_SHA384}" \
      "${LAYRS_RECOVERY_PACKER_INVOKER_ROLE_INVENTORY_SHA384}" \
      "${LAYRS_RECOVERY_PACKER_INVOKER_TEMPLATE_SHA384}" \
      "${LAYRS_RECOVERY_PACKER_INVOKER_EVIDENCE_SHA384}" \
      "${LAYRS_RECOVERY_PACKER_CONTROL_INVENTORY_POLICY_SHA384}" \
      "${LAYRS_RECOVERY_PACKER_CONTROL_LAUNCH_POLICY_SHA384}" \
      "${LAYRS_RECOVERY_PACKER_CONTROL_ARTIFACT_POLICY_SHA384}" \
      "${LAYRS_RECOVERY_EXPECTED_BUILD_CONTROL_PLANE_ROLE_INVENTORY_SHA384}"; do
    [[ "${value}" =~ ^[0-9a-f]{96}$ ]] || die "reviewed package, builder or control-role SHA384 is malformed"
  done
  [[ "${LAYRS_RECOVERY_CLEANUP_EXECUTION_ROLE_INVENTORY_OBJECT_KEY}" =~ ^evidence/seq159300/recovery-only/phase2/builder/cleanup/roles/cleanup-execution/inventory/[0-9a-f]{40}-[0-9a-f]{96}\.json$ ]] \
    || die "cleanup execution role inventory object key is outside the exact immutable contract"
  [[ "${LAYRS_RECOVERY_CLEANUP_SUBMITTER_ROLE_INVENTORY_OBJECT_KEY}" =~ ^evidence/seq159300/recovery-only/phase2/builder/cleanup/roles/cleanup-submitter/inventory/[0-9a-f]{40}-[0-9a-f]{96}\.json$ ]] \
    || die "cleanup submitter role inventory object key is outside the exact immutable contract"
  require_exact "cleanup role inventory stable key suffix" \
    "${LAYRS_RECOVERY_CLEANUP_EXECUTION_ROLE_INVENTORY_OBJECT_KEY##*/}" \
    "${LAYRS_RECOVERY_CLEANUP_SUBMITTER_ROLE_INVENTORY_OBJECT_KEY##*/}"
  [[ "${LAYRS_RECOVERY_TEMPLATE_PUBLISHER_ROLE_INVENTORY_OBJECT_KEY}" =~ ^evidence/seq159300/recovery-only/phase2/builder/publisher/roles/template-publisher/inventory/[0-9a-f]{40}-[0-9a-f]{96}\.json$ ]] \
    || die "template publisher role inventory object key is outside the exact immutable contract"
  [[ "${LAYRS_RECOVERY_CLOUDFORMATION_EXECUTION_ROLE_INVENTORY_OBJECT_KEY}" =~ ^evidence/seq159300/recovery-only/phase2/builder/publisher/roles/cloudformation-execution/inventory/[0-9a-f]{40}-[0-9a-f]{96}\.json$ ]] \
    || die "CloudFormation execution role inventory object key is outside the exact immutable contract"
  require_exact "publisher role inventory stable key suffix" \
    "${LAYRS_RECOVERY_TEMPLATE_PUBLISHER_ROLE_INVENTORY_OBJECT_KEY##*/}" \
    "${LAYRS_RECOVERY_CLOUDFORMATION_EXECUTION_ROLE_INVENTORY_OBJECT_KEY##*/}"
  require_exact "cleanup and publisher role inventory stable key suffix" \
    "${LAYRS_RECOVERY_CLEANUP_EXECUTION_ROLE_INVENTORY_OBJECT_KEY##*/}" \
    "${LAYRS_RECOVERY_TEMPLATE_PUBLISHER_ROLE_INVENTORY_OBJECT_KEY##*/}"
  require_exact "builder template immutable evidence SHA384" \
    "${LAYRS_RECOVERY_BUILDER_TEMPLATE_EVIDENCE_SHA384}" \
    "${LAYRS_RECOVERY_BUILDER_TEMPLATE_SHA384}"
  require_exact "Packer invoker immutable evidence SHA384" \
    "${LAYRS_RECOVERY_PACKER_INVOKER_EVIDENCE_SHA384}" \
    "${LAYRS_RECOVERY_PACKER_INVOKER_TEMPLATE_SHA384}"
  require_exact "publisher template immutable evidence SHA384" \
    "${LAYRS_RECOVERY_PUBLISHER_TEMPLATE_EVIDENCE_SHA384}" \
    "${LAYRS_RECOVERY_PUBLISHER_TEMPLATE_SHA384}"
  require_exact "cleanup template immutable evidence SHA384" \
    "${LAYRS_RECOVERY_CLEANUP_TEMPLATE_EVIDENCE_SHA384}" \
    "${LAYRS_RECOVERY_CLEANUP_TEMPLATE_SHA384}"
  [[ -f "${LAYRS_RECOVERY_BUILDER_TEMPLATE_FILE}" && ! -L "${LAYRS_RECOVERY_BUILDER_TEMPLATE_FILE}" ]] \
    || die "the reviewed builder template is not a regular file"
  require_exact "reviewed builder template SHA384" \
    "$(sha384_file "${LAYRS_RECOVERY_BUILDER_TEMPLATE_FILE}")" \
    "${LAYRS_RECOVERY_BUILDER_TEMPLATE_SHA384}"
  [[ -f "${LAYRS_RECOVERY_PACKER_INVOKER_TEMPLATE_FILE}" && ! -L "${LAYRS_RECOVERY_PACKER_INVOKER_TEMPLATE_FILE}" ]] \
    || die "the reviewed Packer invoker template is not a regular file"
  require_exact "reviewed Packer invoker template SHA384" \
    "$(sha384_file "${LAYRS_RECOVERY_PACKER_INVOKER_TEMPLATE_FILE}")" \
    "${LAYRS_RECOVERY_PACKER_INVOKER_TEMPLATE_SHA384}"
  require_exact "builder template immutable evidence key" \
    "${LAYRS_RECOVERY_BUILDER_TEMPLATE_EVIDENCE_OBJECT_KEY}" \
    "evidence/seq159300/recovery-only/phase2/builder/templates/layrs-seq159300-recovery-builder-${LAYRS_RECOVERY_BUILDER_TEMPLATE_SHA384}.yml"
  [[ "${LAYRS_RECOVERY_PACKER_INVOKER_EVIDENCE_OBJECT_KEY}" =~ ^evidence/seq159300/recovery-only/phase2/invoker/[A-Za-z0-9._/-]+$ \
      && "${LAYRS_RECOVERY_PACKER_INVOKER_EVIDENCE_OBJECT_KEY}" != *".."* \
      && "${LAYRS_RECOVERY_BUILDER_EVIDENCE_INDEX_OBJECT_KEY}" =~ ^evidence/seq159300/recovery-only/phase2/builder/[A-Za-z0-9._/-]+$ \
      && "${LAYRS_RECOVERY_BUILDER_EVIDENCE_INDEX_OBJECT_KEY}" != *".."* ]] \
    || die "immutable invoker or builder evidence key is malformed"
  require_exact "publisher template immutable evidence key" \
    "${LAYRS_RECOVERY_PUBLISHER_TEMPLATE_EVIDENCE_OBJECT_KEY}" \
    "evidence/seq159300/recovery-only/phase2/builder/publisher/layrs-seq159300-recovery-template-publisher-${LAYRS_RECOVERY_PUBLISHER_TEMPLATE_SHA384}.yml"
  require_exact "cleanup template immutable evidence key" \
    "${LAYRS_RECOVERY_CLEANUP_TEMPLATE_EVIDENCE_OBJECT_KEY}" \
    "evidence/seq159300/recovery-only/phase2/builder/cleanup/templates/layrs-seq159300-recovery-builder-cleanup-${LAYRS_RECOVERY_CLEANUP_TEMPLATE_SHA384}.yml"
  [[ "${LAYRS_RECOVERY_PUBLISHER_TEMPLATE_EVIDENCE_OBJECT_KEY}" =~ ^evidence/seq159300/recovery-only/phase2/builder/publisher/[A-Za-z0-9._/-]+$ \
      && "${LAYRS_RECOVERY_TEMPLATE_UPLOAD_RECEIPT_OBJECT_KEY}" =~ ^evidence/seq159300/recovery-only/phase2/builder/publisher/receipts/[A-Za-z0-9._/-]+$ \
      && "${LAYRS_RECOVERY_CHANGE_SET_RECEIPT_OBJECT_KEY}" =~ ^evidence/seq159300/recovery-only/phase2/builder/publisher/receipts/[A-Za-z0-9._/-]+$ \
      && "${LAYRS_RECOVERY_PUBLISHER_TEMPLATE_EVIDENCE_OBJECT_KEY}" != *".."* \
      && "${LAYRS_RECOVERY_TEMPLATE_UPLOAD_RECEIPT_OBJECT_KEY}" != *".."* \
      && "${LAYRS_RECOVERY_CHANGE_SET_RECEIPT_OBJECT_KEY}" != *".."* ]] \
    || die "immutable publisher template or receipt key is malformed"
  for value in "${LAYRS_RECOVERY_BUILDER_TEMPLATE_EVIDENCE_OBJECT_VERSION_ID}" \
      "${LAYRS_RECOVERY_PACKER_INVOKER_EVIDENCE_OBJECT_VERSION_ID}" \
      "${LAYRS_RECOVERY_BUILDER_EVIDENCE_INDEX_OBJECT_VERSION_ID}" \
      "${LAYRS_RECOVERY_PUBLISHER_TEMPLATE_EVIDENCE_OBJECT_VERSION_ID}" \
      "${LAYRS_RECOVERY_TEMPLATE_UPLOAD_RECEIPT_OBJECT_VERSION_ID}" \
      "${LAYRS_RECOVERY_CHANGE_SET_RECEIPT_OBJECT_VERSION_ID}" \
      "${LAYRS_RECOVERY_CLEANUP_TEMPLATE_EVIDENCE_OBJECT_VERSION_ID}"; do
    [[ "${value}" =~ ^[A-Za-z0-9._-]{8,256}$ ]] \
      || die "immutable builder or invoker evidence VersionId is malformed"
  done
  [[ "${LAYRS_RECOVERY_IMPLEMENTATION_COMMIT}" =~ ^[0-9a-f]{40}$ ]] \
    || die "LAYRS_RECOVERY_IMPLEMENTATION_COMMIT must be an exact lowercase commit"
  [[ "${LAYRS_RECOVERY_PHASE2_TEMPLATE_COMMIT}" =~ ^[0-9a-f]{40}$ ]] \
    || die "LAYRS_RECOVERY_PHASE2_TEMPLATE_COMMIT must be an exact lowercase commit"
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
  [[ -f "${LAYRS_RECOVERY_PUBLISHER_TEMPLATE_FILE}" && ! -L "${LAYRS_RECOVERY_PUBLISHER_TEMPLATE_FILE}" ]] \
    || die "the reviewed publisher template is not a regular file"
  require_exact "reviewed publisher template SHA384" \
    "$(sha384_file "${LAYRS_RECOVERY_PUBLISHER_TEMPLATE_FILE}")" \
    "${LAYRS_RECOVERY_PUBLISHER_TEMPLATE_SHA384}"
  [[ -f "${LAYRS_RECOVERY_CLEANUP_TEMPLATE_FILE}" && ! -L "${LAYRS_RECOVERY_CLEANUP_TEMPLATE_FILE}" ]] \
    || die "the reviewed cleanup template is not a regular file"
  require_exact "reviewed cleanup template SHA384" \
    "$(sha384_file "${LAYRS_RECOVERY_CLEANUP_TEMPLATE_FILE}")" \
    "${LAYRS_RECOVERY_CLEANUP_TEMPLATE_SHA384}"
  local immutable_reference_count
  immutable_reference_count="$(printf '%s\n' \
    "${LAYRS_RECOVERY_BUILDER_TEMPLATE_EVIDENCE_OBJECT_KEY}@${LAYRS_RECOVERY_BUILDER_TEMPLATE_EVIDENCE_OBJECT_VERSION_ID}" \
    "${LAYRS_RECOVERY_PACKER_INVOKER_EVIDENCE_OBJECT_KEY}@${LAYRS_RECOVERY_PACKER_INVOKER_EVIDENCE_OBJECT_VERSION_ID}" \
    "${LAYRS_RECOVERY_BUILDER_EVIDENCE_INDEX_OBJECT_KEY}@${LAYRS_RECOVERY_BUILDER_EVIDENCE_INDEX_OBJECT_VERSION_ID}" \
    "${LAYRS_RECOVERY_PUBLISHER_TEMPLATE_EVIDENCE_OBJECT_KEY}@${LAYRS_RECOVERY_PUBLISHER_TEMPLATE_EVIDENCE_OBJECT_VERSION_ID}" \
    "${LAYRS_RECOVERY_TEMPLATE_UPLOAD_RECEIPT_OBJECT_KEY}@${LAYRS_RECOVERY_TEMPLATE_UPLOAD_RECEIPT_OBJECT_VERSION_ID}" \
    "${LAYRS_RECOVERY_CHANGE_SET_RECEIPT_OBJECT_KEY}@${LAYRS_RECOVERY_CHANGE_SET_RECEIPT_OBJECT_VERSION_ID}" \
    "${LAYRS_RECOVERY_CLEANUP_TEMPLATE_EVIDENCE_OBJECT_KEY}@${LAYRS_RECOVERY_CLEANUP_TEMPLATE_EVIDENCE_OBJECT_VERSION_ID}" \
    "${LAYRS_RECOVERY_PHASE2_EVIDENCE_OBJECT_KEY}@${LAYRS_RECOVERY_PHASE2_EVIDENCE_OBJECT_VERSION_ID}" \
    "${LAYRS_RECOVERY_IMPLEMENTATION_EVIDENCE_OBJECT_KEY}@${LAYRS_RECOVERY_IMPLEMENTATION_EVIDENCE_OBJECT_VERSION_ID}" \
    "${LAYRS_RECOVERY_NITRO_CLI_RPM_OBJECT_KEY}@${LAYRS_RECOVERY_NITRO_CLI_RPM_OBJECT_VERSION_ID}" \
    "${LAYRS_RECOVERY_NITRO_PACKAGE_SET_OBJECT_KEY}@${LAYRS_RECOVERY_NITRO_PACKAGE_SET_OBJECT_VERSION_ID}" \
    "${LAYRS_RECOVERY_NITRO_PACKAGE_SET_EVIDENCE_OBJECT_KEY}@${LAYRS_RECOVERY_NITRO_PACKAGE_SET_EVIDENCE_OBJECT_VERSION_ID}" \
    | sort -u | wc -l)"
  [[ "${immutable_reference_count}" == "12" ]] || die "immutable publisher/build evidence references are not unique"
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
  local subnet_response vpc_response routes_response security_group_response endpoints_response interfaces_response input output vpc_id
  local -a referenced_group_ids all_group_ids
  subnet_response="${PREFLIGHT_TEMP_DIR}/subnet-response.json"
  vpc_response="${PREFLIGHT_TEMP_DIR}/vpc-response.json"
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
  aws_read_json ec2 describe-vpcs --vpc-ids "${vpc_id}" >"${vpc_response}"
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
    --slurpfile vpcsResponse "${vpc_response}" \
    --slurpfile routeTablesResponse "${routes_response}" \
    --slurpfile securityGroupsResponse "${security_group_response}" \
    --slurpfile vpcEndpointsResponse "${endpoints_response}" \
    --slurpfile networkInterfacesResponse "${interfaces_response}" \
    '{kind:"build-network",payload:{expectedSubnetId:$expectedSubnetId,
      expectedSecurityGroupId:$expectedSecurityGroupId,subnetsResponse:$subnetsResponse[0],
      vpcsResponse:$vpcsResponse[0],
      routeTablesResponse:$routeTablesResponse[0],securityGroupsResponse:$securityGroupsResponse[0],
      vpcEndpointsResponse:$vpcEndpointsResponse[0],networkInterfacesResponse:$networkInterfacesResponse[0]}}' \
    >"${input}"
  render_preflight_inventory "${input}" "${output}"
  jq -cS '{subnet,vpc,routeTables,routes}' "${output}" \
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

preflight_packer_control_role() {
  local role_response attached_response inline_response stack_response input output inline_name document_response
  local managed_json policy_name policy_arn policy_hash_var policy_hash metadata_response version_response
  role_response="${PREFLIGHT_TEMP_DIR}/packer-control-role-response.json"
  attached_response="${PREFLIGHT_TEMP_DIR}/packer-control-attached-policies-response.json"
  inline_response="${PREFLIGHT_TEMP_DIR}/packer-control-inline-policies-response.json"
  stack_response="${PREFLIGHT_TEMP_DIR}/packer-control-stack-response.json"
  input="${PREFLIGHT_TEMP_DIR}/packer-control-input.json"
  output="${PREFLIGHT_TEMP_DIR}/packer-control-inventory.json"

  aws_read_json iam get-role --role-name "${PACKER_CONTROL_ROLE_NAME}" >"${role_response}"
  aws_read_json iam list-attached-role-policies --role-name "${PACKER_CONTROL_ROLE_NAME}" \
    >"${attached_response}"
  aws_read_json iam list-role-policies --role-name "${PACKER_CONTROL_ROLE_NAME}" >"${inline_response}"
  [[ "$(jq -er '.AttachedPolicies | length' "${attached_response}")" == "3" ]] \
    || die "Packer control role must have exactly three managed policy attachments"
  inline_name="$(jq -er '.PolicyNames | select(length == 1) | .[0]' "${inline_response}")" \
    || die "Packer control role must have exactly one inline policy"
  require_exact "Packer control inline policy name" "${inline_name}" "${PACKER_CONTROL_ROLE_NAME}"
  document_response="$(aws_read_json iam get-role-policy \
    --role-name "${PACKER_CONTROL_ROLE_NAME}" --policy-name "${inline_name}")"
  managed_json='[]'
  while IFS='|' read -r policy_name policy_hash_var; do
    policy_arn="arn:aws:iam::${RECOVERY_ACCOUNT_ID}:policy/${policy_name}"
    jq -e --arg arn "${policy_arn}" '.AttachedPolicies | any(.PolicyArn == $arn)' \
      "${attached_response}" >/dev/null \
      || die "Packer control role managed policy attachment set is not exact"
    policy_hash="${!policy_hash_var}"
    metadata_response="$(aws_read_json iam get-policy --policy-arn "${policy_arn}")"
    require_exact "Packer control managed policy ARN" \
      "$(jq -er '.Policy.Arn' <<<"${metadata_response}")" "${policy_arn}"
    require_exact "Packer control managed policy name" \
      "$(jq -er '.Policy.PolicyName' <<<"${metadata_response}")" "${policy_name}"
    [[ "$(jq -er '.Policy.Path' <<<"${metadata_response}")" == "/" \
        && "$(jq -er '.Policy.IsAttachable' <<<"${metadata_response}")" == "true" \
        && "$(jq -er '.Policy.AttachmentCount' <<<"${metadata_response}")" == "1" ]] \
      || die "Packer control managed policy metadata is not exact"
    version_response="$(aws_read_json iam get-policy-version --policy-arn "${policy_arn}" \
      --version-id "$(jq -er '.Policy.DefaultVersionId' <<<"${metadata_response}")")"
    [[ "$(jq -er '.PolicyVersion.IsDefaultVersion' <<<"${version_response}")" == "true" ]] \
      || die "Packer control managed policy version is not the exact default"
    managed_json="$(jq -n -c \
      --argjson policies "${managed_json}" --arg arn "${policy_arn}" \
      --arg defaultVersionId "$(jq -er '.Policy.DefaultVersionId' <<<"${metadata_response}")" \
      --argjson document "$(jq -c '.PolicyVersion.Document' <<<"${version_response}")" \
      --arg name "${policy_name}" --arg sha384 "${policy_hash}" \
      '$policies + [{arn:$arn,defaultVersionId:$defaultVersionId,document:$document,name:$name,sha384:$sha384}]')"
  done <<'POLICIES'
layrs-production-recovery-seq159300-packer-artifacts|LAYRS_RECOVERY_PACKER_CONTROL_ARTIFACT_POLICY_SHA384
layrs-production-recovery-seq159300-packer-inventory|LAYRS_RECOVERY_PACKER_CONTROL_INVENTORY_POLICY_SHA384
layrs-production-recovery-seq159300-packer-launch|LAYRS_RECOVERY_PACKER_CONTROL_LAUNCH_POLICY_SHA384
POLICIES
  aws_read_json cloudformation describe-stacks --stack-name "${LAYRS_RECOVERY_BUILDER_STACK_NAME}" \
    >"${stack_response}"

  jq -n \
    --arg approvedAt "${LAYRS_RECOVERY_PACKER_CONTROL_APPROVED_AT}" \
    --arg builderEvidenceIndexSha384 "${LAYRS_RECOVERY_BUILDER_EVIDENCE_INDEX_SHA384}" \
    --arg builderTemplateSha384 "${LAYRS_RECOVERY_BUILDER_TEMPLATE_SHA384}" \
    --arg evaluatedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg expectedInvokerRoleArn "${LAYRS_RECOVERY_PACKER_INVOKER_ROLE_ARN}" \
    --arg invokerRoleInventorySha384 "${LAYRS_RECOVERY_PACKER_INVOKER_ROLE_INVENTORY_SHA384}" \
    --arg packerInvokerTemplateSha384 "${LAYRS_RECOVERY_PACKER_INVOKER_TEMPLATE_SHA384}" \
    --arg packerInvokerEvidenceSha384 "${LAYRS_RECOVERY_PACKER_INVOKER_EVIDENCE_SHA384}" \
    --arg packerControlInventoryPolicySha384 "${LAYRS_RECOVERY_PACKER_CONTROL_INVENTORY_POLICY_SHA384}" \
    --arg packerControlLaunchPolicySha384 "${LAYRS_RECOVERY_PACKER_CONTROL_LAUNCH_POLICY_SHA384}" \
    --arg packerControlArtifactPolicySha384 "${LAYRS_RECOVERY_PACKER_CONTROL_ARTIFACT_POLICY_SHA384}" \
    --arg packerControlPlaneApprovedAt "${LAYRS_RECOVERY_PACKER_CONTROL_APPROVED_AT}" \
    --arg packerControlPlaneExpiresAt "${LAYRS_RECOVERY_PACKER_CONTROL_EXPIRES_AT}" \
    --arg invokerApprovedAt "${LAYRS_RECOVERY_INVOKER_APPROVED_AT}" \
    --arg invokerExpiresAt "${LAYRS_RECOVERY_INVOKER_EXPIRES_AT}" \
    --arg templatePublisherApprovedAt "${LAYRS_RECOVERY_TEMPLATE_PUBLISHER_APPROVED_AT}" \
    --arg templatePublisherExpiresAt "${LAYRS_RECOVERY_TEMPLATE_PUBLISHER_EXPIRES_AT}" \
    --arg packerAmazonPluginVersion "${PACKER_AMAZON_PLUGIN_VERSION}" \
    --arg packerAmazonPluginSourceCommit "2a769c39a05940e25143098f071490732fa24f4f" \
    --arg phase2TemplateSha384 "${LAYRS_RECOVERY_EXPECTED_PHASE2_TEMPLATE_SHA384}" \
    --arg publisherTemplateObjectKey "${LAYRS_RECOVERY_PUBLISHER_TEMPLATE_EVIDENCE_OBJECT_KEY}" \
    --arg publisherTemplateObjectVersionId "${LAYRS_RECOVERY_PUBLISHER_TEMPLATE_EVIDENCE_OBJECT_VERSION_ID}" \
    --arg publisherTemplateSha384 "${LAYRS_RECOVERY_PUBLISHER_TEMPLATE_SHA384}" \
    --arg templateUploadReceiptObjectKey "${LAYRS_RECOVERY_TEMPLATE_UPLOAD_RECEIPT_OBJECT_KEY}" \
    --arg templateUploadReceiptObjectVersionId "${LAYRS_RECOVERY_TEMPLATE_UPLOAD_RECEIPT_OBJECT_VERSION_ID}" \
    --arg templateUploadReceiptSha384 "${LAYRS_RECOVERY_TEMPLATE_UPLOAD_RECEIPT_SHA384}" \
    --arg changeSetReceiptObjectKey "${LAYRS_RECOVERY_CHANGE_SET_RECEIPT_OBJECT_KEY}" \
    --arg changeSetReceiptObjectVersionId "${LAYRS_RECOVERY_CHANGE_SET_RECEIPT_OBJECT_VERSION_ID}" \
    --arg changeSetReceiptSha384 "${LAYRS_RECOVERY_CHANGE_SET_RECEIPT_SHA384}" \
    --arg expiresAt "${LAYRS_RECOVERY_PACKER_CONTROL_EXPIRES_AT}" \
    --arg offlinePackageClosureSha384 "${NITRO_PACKAGE_CLOSURE_SHA384}" \
    --arg offlinePackageSetSha384 "${NITRO_PACKAGE_SET_SHA384}" \
    --arg inlineName "${inline_name}" \
    --argjson inlineDocument "$(jq -c '.PolicyDocument' <<<"${document_response}")" \
    --argjson managedPolicies "${managed_json}" \
    --slurpfile roleResponse "${role_response}" \
    --slurpfile stackResponse "${stack_response}" \
    '{kind:"packer-control-role",payload:{approvedAt:$approvedAt,attachedPolicies:$managedPolicies,
      builderEvidenceIndexSha384:$builderEvidenceIndexSha384,
      builderTemplateSha384:$builderTemplateSha384,evaluatedAt:$evaluatedAt,
      expectedInvokerRoleArn:$expectedInvokerRoleArn,expiresAt:$expiresAt,
      invokerRoleInventorySha384:$invokerRoleInventorySha384,
      packerInvokerTemplateSha384:$packerInvokerTemplateSha384,
      packerInvokerEvidenceSha384:$packerInvokerEvidenceSha384,
      packerAmazonPluginVersion:$packerAmazonPluginVersion,
      packerAmazonPluginSourceCommit:$packerAmazonPluginSourceCommit,
      packerControlInventoryPolicySha384:$packerControlInventoryPolicySha384,
      packerControlLaunchPolicySha384:$packerControlLaunchPolicySha384,
      packerControlArtifactPolicySha384:$packerControlArtifactPolicySha384,
      packerControlPlaneApprovedAt:$packerControlPlaneApprovedAt,
      packerControlPlaneExpiresAt:$packerControlPlaneExpiresAt,
      invokerApprovedAt:$invokerApprovedAt,invokerExpiresAt:$invokerExpiresAt,
      templatePublisherApprovedAt:$templatePublisherApprovedAt,
      templatePublisherExpiresAt:$templatePublisherExpiresAt,
      phase2TemplateSha384:$phase2TemplateSha384,
      publisherTemplateObjectKey:$publisherTemplateObjectKey,
      publisherTemplateObjectVersionId:$publisherTemplateObjectVersionId,
      publisherTemplateSha384:$publisherTemplateSha384,
      templateUploadReceiptObjectKey:$templateUploadReceiptObjectKey,
      templateUploadReceiptObjectVersionId:$templateUploadReceiptObjectVersionId,
      templateUploadReceiptSha384:$templateUploadReceiptSha384,
      changeSetReceiptObjectKey:$changeSetReceiptObjectKey,
      changeSetReceiptObjectVersionId:$changeSetReceiptObjectVersionId,
      changeSetReceiptSha384:$changeSetReceiptSha384,
      inlinePolicies:[{name:$inlineName,document:$inlineDocument}],
      offlinePackageClosureSha384:$offlinePackageClosureSha384,
      offlinePackageSetSha384:$offlinePackageSetSha384,
      roleResponse:$roleResponse[0],stackResponse:$stackResponse[0]}}' >"${input}"
  render_preflight_inventory "${input}" "${output}"
  BUILD_CONTROL_PLANE_ROLE_INVENTORY_SHA384="$(sha384_file "${output}")"
  require_exact "Packer control role inventory SHA384" \
    "${BUILD_CONTROL_PLANE_ROLE_INVENTORY_SHA384}" \
    "${LAYRS_RECOVERY_EXPECTED_BUILD_CONTROL_PLANE_ROLE_INVENTORY_SHA384}"
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
    --arg parentPackageCommit "${PARENT_PACKAGE_COMMIT}" \
    --arg builderTemplateSha384 "${LAYRS_RECOVERY_BUILDER_TEMPLATE_SHA384}" \
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
    --arg buildControlPlaneRoleInventorySha384 "${BUILD_CONTROL_PLANE_ROLE_INVENTORY_SHA384}" \
    --arg packerInvokerRoleInventorySha384 "${LAYRS_RECOVERY_PACKER_INVOKER_ROLE_INVENTORY_SHA384}" \
    --arg packerTemplateSha384 "${PACKER_TEMPLATE_SHA384}" \
    --arg nitroCliRpmSha384 "${NITRO_CLI_RPM_SHA384}" \
    --arg nitroPackageInventorySha384 "${EXPECTED_PACKAGE_INVENTORY_SHA384}" \
    --arg nitroPackageSetSha384 "${NITRO_PACKAGE_SET_SHA384}" \
    --arg nitroPackageClosureSha384 "${NITRO_PACKAGE_CLOSURE_SHA384}" \
    --arg recoveryEvidenceIndexSha384 "${LAYRS_RECOVERY_BUILDER_EVIDENCE_INDEX_SHA384}" \
    --slurpfile response "${response}" \
    '{kind:"output-ami",payload:{expected:{imageId:$imageId,sourceAmiId:$sourceAmiId,
      sourceCommit:$sourceCommit,parentPackageCommit:$parentPackageCommit,
      implementationCommit:$implementationCommit,
      parentSha384:$parentSha384,eifSha384:$eifSha384,pcr0Sha384:$pcr0Sha384,
      phase2TemplateCommit:$phase2TemplateCommit,
      phase2TemplateSha384:$phase2TemplateSha384,
      sourceAmiProvenanceSha384:$sourceAmiProvenanceSha384,
      buildSubnetInventorySha384:$buildSubnetInventorySha384,
      buildSecurityGroupInventorySha384:$buildSecurityGroupInventorySha384,
      buildInstanceProfileInventorySha384:$buildInstanceProfileInventorySha384,
      buildControlPlaneRoleInventorySha384:$buildControlPlaneRoleInventorySha384,
      packerInvokerRoleInventorySha384:$packerInvokerRoleInventorySha384,
      builderTemplateSha384:$builderTemplateSha384,
      packerTemplateSha384:$packerTemplateSha384,nitroCliRpmSha384:$nitroCliRpmSha384,
      nitroPackageInventorySha384:$nitroPackageInventorySha384,
      nitroPackageSetSha384:$nitroPackageSetSha384,
      nitroPackageClosureSha384:$nitroPackageClosureSha384,
      recoveryEvidenceIndexSha384:$recoveryEvidenceIndexSha384},response:$response[0]}}' >"${input}"
  render_preflight_inventory "${input}" "${output}"
  OUTPUT_AMI_INVENTORY_SHA384="$(sha384_file "${output}")"
}

assume_packer_control_role() {
  local assume_response caller_identity caller_account caller_arn expires_epoch now_epoch duration_seconds credential_expiry
  assume_response="${PREFLIGHT_TEMP_DIR}/packer-control-assume-response.json"
  now_epoch="$(date -u +%s)"
  expires_epoch="$(date -u -d "${LAYRS_RECOVERY_PACKER_CONTROL_EXPIRES_AT}" +%s)" \
    || die "Packer control expiry cannot be parsed"
  duration_seconds="$((expires_epoch - now_epoch))"
  (( duration_seconds >= 900 && duration_seconds <= 3600 )) \
    || die "Packer control role has less than the safe STS minimum or exceeds 3600 seconds"
  aws_read_json sts assume-role \
    --role-arn "arn:aws:iam::${RECOVERY_ACCOUNT_ID}:role/${PACKER_CONTROL_ROLE_NAME}" \
    --role-session-name "layrs-seq159300-packer" \
    --external-id "${LAYRS_RECOVERY_BUILDER_EVIDENCE_INDEX_SHA384}" \
    --duration-seconds "${duration_seconds}" >"${assume_response}"
  export AWS_ACCESS_KEY_ID="$(jq -er '.Credentials.AccessKeyId' "${assume_response}")"
  export AWS_SECRET_ACCESS_KEY="$(jq -er '.Credentials.SecretAccessKey' "${assume_response}")"
  export AWS_SESSION_TOKEN="$(jq -er '.Credentials.SessionToken' "${assume_response}")"
  credential_expiry="$(jq -er '.Credentials.Expiration' "${assume_response}")"
  (( $(date -u -d "${credential_expiry}" +%s) <= expires_epoch )) \
    || die "assumed Packer credentials outlive the exact reviewed expiry"
  caller_identity="$(aws_read_json sts get-caller-identity)"
  caller_account="$(jq -er '.Account' <<<"${caller_identity}")" \
    || die "assumed Packer account could not be read"
  caller_arn="$(jq -er '.Arn' <<<"${caller_identity}")" \
    || die "assumed Packer caller ARN could not be read"
  require_exact "assumed Packer account" "${caller_account}" "${RECOVERY_ACCOUNT_ID}"
  [[ "${caller_arn}" =~ ^arn:aws:sts::082223548516:assumed-role/layrs-production-recovery-seq159300-packer-control/layrs-seq159300-packer$ ]] \
    || die "Packer process credentials are not the exact dedicated control role and session"
}

run_aws_preflight() {
  local caller_account caller_arn caller_identity
  PREFLIGHT_TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/layrs-seq159300-parent-preflight.XXXXXX")"
  caller_identity="$(aws_read_json sts get-caller-identity)"
  caller_account="$(jq -er '.Account' <<<"${caller_identity}")" \
    || die "AWS caller identity could not be read"
  caller_arn="$(jq -er '.Arn' <<<"${caller_identity}")" || die "AWS caller ARN could not be read"
  require_exact "active AWS account" "${caller_account}" "${RECOVERY_ACCOUNT_ID}"
  [[ "${caller_arn}" =~ ^arn:aws:sts::082223548516:assumed-role/([^/]+)/[^/]+$ ]] \
    || die "preflight caller is not an assumed dedicated invoker role"
  require_exact "preflight invoker role" "arn:aws:iam::${RECOVERY_ACCOUNT_ID}:role/${BASH_REMATCH[1]}" \
    "${LAYRS_RECOVERY_PACKER_INVOKER_ROLE_ARN}"
  preflight_packer_control_role
  preflight_instance_profile
  verify_immutable_package_objects
  verify_builder_contract_objects
  verify_cleanup_contract_object
  verify_publication_evidence_objects
  assume_packer_control_role
  preflight_source_ami
  preflight_build_network
}

summary() {
  jq -n -c \
    --arg accountId "${RECOVERY_ACCOUNT_ID}" \
    --arg region "${RECOVERY_REGION}" \
    --arg purpose "layrs-seq159300-recovery" \
    --arg trustedPrincipalInventorySha384 "${LAYRS_RECOVERY_TRUSTED_PRINCIPAL_INVENTORY_SHA384}" \
    --arg sourceCommit "${RECOVERY_SOURCE_COMMIT}" \
    --arg parentPackageCommit "${PARENT_PACKAGE_COMMIT}" \
    --arg parentBuildWrapperSha384 "${PARENT_BUILD_WRAPPER_SHA384}" \
    --arg parentPreflightSha384 "${PARENT_PREFLIGHT_SHA384}" \
    --arg parentBuildEvidenceRendererSha384 "${PARENT_BUILD_EVIDENCE_RENDERER_SHA384}" \
    --arg parentPostBuildCleanupEvidenceRendererSha384 "${PARENT_POST_BUILD_CLEANUP_EVIDENCE_RENDERER_SHA384}" \
    --arg parentRunbookSha384 "${PARENT_RUNBOOK_SHA384}" \
    --arg builderEvidenceIndexSha384 "${LAYRS_RECOVERY_BUILDER_EVIDENCE_INDEX_SHA384}" \
    --arg builderEvidenceIndexObjectKey "${LAYRS_RECOVERY_BUILDER_EVIDENCE_INDEX_OBJECT_KEY}" \
    --arg builderEvidenceIndexObjectVersionId "${LAYRS_RECOVERY_BUILDER_EVIDENCE_INDEX_OBJECT_VERSION_ID}" \
    --arg builderTemplateSha384 "${LAYRS_RECOVERY_BUILDER_TEMPLATE_SHA384}" \
    --arg builderTemplateEvidenceObjectKey "${LAYRS_RECOVERY_BUILDER_TEMPLATE_EVIDENCE_OBJECT_KEY}" \
    --arg builderTemplateEvidenceObjectVersionId "${LAYRS_RECOVERY_BUILDER_TEMPLATE_EVIDENCE_OBJECT_VERSION_ID}" \
    --arg builderTemplateEvidenceSha384 "${LAYRS_RECOVERY_BUILDER_TEMPLATE_EVIDENCE_SHA384}" \
    --arg publisherTemplateSha384 "${LAYRS_RECOVERY_PUBLISHER_TEMPLATE_SHA384}" \
    --arg publisherTemplateEvidenceObjectKey "${LAYRS_RECOVERY_PUBLISHER_TEMPLATE_EVIDENCE_OBJECT_KEY}" \
    --arg publisherTemplateEvidenceObjectVersionId "${LAYRS_RECOVERY_PUBLISHER_TEMPLATE_EVIDENCE_OBJECT_VERSION_ID}" \
    --arg publisherTemplateEvidenceSha384 "${LAYRS_RECOVERY_PUBLISHER_TEMPLATE_EVIDENCE_SHA384}" \
    --arg templatePublisherRoleInventorySha384 "${LAYRS_RECOVERY_TEMPLATE_PUBLISHER_ROLE_INVENTORY_SHA384}" \
    --arg templatePublisherRoleInventoryObjectKey "${LAYRS_RECOVERY_TEMPLATE_PUBLISHER_ROLE_INVENTORY_OBJECT_KEY}" \
    --arg templatePublisherRoleInventoryObjectVersionId "${LAYRS_RECOVERY_TEMPLATE_PUBLISHER_ROLE_INVENTORY_OBJECT_VERSION_ID}" \
    --arg cloudFormationExecutionRoleInventoryObjectKey "${LAYRS_RECOVERY_CLOUDFORMATION_EXECUTION_ROLE_INVENTORY_OBJECT_KEY}" \
    --arg cloudFormationExecutionRoleInventoryObjectVersionId "${LAYRS_RECOVERY_CLOUDFORMATION_EXECUTION_ROLE_INVENTORY_OBJECT_VERSION_ID}" \
    --arg cloudFormationExecutionRoleInventorySha384 "${LAYRS_RECOVERY_CLOUDFORMATION_EXECUTION_ROLE_INVENTORY_SHA384}" \
    --arg templateUploadReceiptObjectKey "${LAYRS_RECOVERY_TEMPLATE_UPLOAD_RECEIPT_OBJECT_KEY}" \
    --arg templateUploadReceiptObjectVersionId "${LAYRS_RECOVERY_TEMPLATE_UPLOAD_RECEIPT_OBJECT_VERSION_ID}" \
    --arg templateUploadReceiptSha384 "${LAYRS_RECOVERY_TEMPLATE_UPLOAD_RECEIPT_SHA384}" \
    --arg changeSetReceiptObjectKey "${LAYRS_RECOVERY_CHANGE_SET_RECEIPT_OBJECT_KEY}" \
    --arg changeSetReceiptObjectVersionId "${LAYRS_RECOVERY_CHANGE_SET_RECEIPT_OBJECT_VERSION_ID}" \
    --arg changeSetReceiptSha384 "${LAYRS_RECOVERY_CHANGE_SET_RECEIPT_SHA384}" \
    --arg cleanupTemplateSha384 "${LAYRS_RECOVERY_CLEANUP_TEMPLATE_SHA384}" \
    --arg cleanupTemplateEvidenceObjectKey "${LAYRS_RECOVERY_CLEANUP_TEMPLATE_EVIDENCE_OBJECT_KEY}" \
    --arg cleanupTemplateEvidenceObjectVersionId "${LAYRS_RECOVERY_CLEANUP_TEMPLATE_EVIDENCE_OBJECT_VERSION_ID}" \
    --arg cleanupTemplateEvidenceSha384 "${LAYRS_RECOVERY_CLEANUP_TEMPLATE_EVIDENCE_SHA384}" \
    --arg cleanupExecutionRoleInventorySha384 "${LAYRS_RECOVERY_CLEANUP_EXECUTION_ROLE_INVENTORY_SHA384}" \
    --arg cleanupExecutionRoleInventoryObjectKey "${LAYRS_RECOVERY_CLEANUP_EXECUTION_ROLE_INVENTORY_OBJECT_KEY}" \
    --arg cleanupExecutionRoleInventoryObjectVersionId "${LAYRS_RECOVERY_CLEANUP_EXECUTION_ROLE_INVENTORY_OBJECT_VERSION_ID}" \
    --arg cleanupSubmitterRoleInventorySha384 "${LAYRS_RECOVERY_CLEANUP_SUBMITTER_ROLE_INVENTORY_SHA384}" \
    --arg cleanupSubmitterRoleInventoryObjectKey "${LAYRS_RECOVERY_CLEANUP_SUBMITTER_ROLE_INVENTORY_OBJECT_KEY}" \
    --arg cleanupSubmitterRoleInventoryObjectVersionId "${LAYRS_RECOVERY_CLEANUP_SUBMITTER_ROLE_INVENTORY_OBJECT_VERSION_ID}" \
    --arg packerInvokerRoleInventorySha384 "${LAYRS_RECOVERY_PACKER_INVOKER_ROLE_INVENTORY_SHA384}" \
    --arg packerInvokerTemplateSha384 "${LAYRS_RECOVERY_PACKER_INVOKER_TEMPLATE_SHA384}" \
    --arg packerInvokerEvidenceObjectKey "${LAYRS_RECOVERY_PACKER_INVOKER_EVIDENCE_OBJECT_KEY}" \
    --arg packerInvokerEvidenceObjectVersionId "${LAYRS_RECOVERY_PACKER_INVOKER_EVIDENCE_OBJECT_VERSION_ID}" \
    --arg packerInvokerEvidenceSha384 "${LAYRS_RECOVERY_PACKER_INVOKER_EVIDENCE_SHA384}" \
    --arg packerControlInventoryPolicySha384 "${LAYRS_RECOVERY_PACKER_CONTROL_INVENTORY_POLICY_SHA384}" \
    --arg packerControlLaunchPolicySha384 "${LAYRS_RECOVERY_PACKER_CONTROL_LAUNCH_POLICY_SHA384}" \
    --arg packerControlArtifactPolicySha384 "${LAYRS_RECOVERY_PACKER_CONTROL_ARTIFACT_POLICY_SHA384}" \
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
    --arg nitroPackageClosureSha384 "${NITRO_PACKAGE_CLOSURE_SHA384}" \
    --arg nitroPackageSigningKeyFingerprint "${AMAZON_LINUX_SIGNING_KEY_FINGERPRINT}" \
    --arg nitroPackageSigningKeySha256 "${AMAZON_LINUX_SIGNING_KEY_SHA256}" \
    --arg nitroPackageSetEvidenceObjectKey "${LAYRS_RECOVERY_NITRO_PACKAGE_SET_EVIDENCE_OBJECT_KEY}" \
    --arg nitroPackageSetEvidenceObjectVersionId "${LAYRS_RECOVERY_NITRO_PACKAGE_SET_EVIDENCE_OBJECT_VERSION_ID}" \
    --arg nitroPackageSetEvidenceSha384 "${LAYRS_RECOVERY_NITRO_PACKAGE_SET_EVIDENCE_SHA384}" \
    '{accountId:$accountId,region:$region,purpose:$purpose,
      trustedPrincipalInventorySha384:$trustedPrincipalInventorySha384,
      sourceCommit:$sourceCommit,
      parentPackageCommit:$parentPackageCommit,
      parentBuildWrapperSha384:$parentBuildWrapperSha384,
      parentPreflightSha384:$parentPreflightSha384,
      parentBuildEvidenceRendererSha384:$parentBuildEvidenceRendererSha384,
      parentPostBuildCleanupEvidenceRendererSha384:$parentPostBuildCleanupEvidenceRendererSha384,
      parentRunbookSha384:$parentRunbookSha384,
      builderEvidenceIndexSha384:$builderEvidenceIndexSha384,
      builderEvidenceIndexObjectKey:$builderEvidenceIndexObjectKey,
      builderEvidenceIndexObjectVersionId:$builderEvidenceIndexObjectVersionId,
      builderTemplateSha384:$builderTemplateSha384,
      builderTemplateEvidenceObjectKey:$builderTemplateEvidenceObjectKey,
      builderTemplateEvidenceObjectVersionId:$builderTemplateEvidenceObjectVersionId,
      builderTemplateEvidenceSha384:$builderTemplateEvidenceSha384,
      publisherTemplateSha384:$publisherTemplateSha384,
      publisherTemplateEvidenceObjectKey:$publisherTemplateEvidenceObjectKey,
      publisherTemplateEvidenceObjectVersionId:$publisherTemplateEvidenceObjectVersionId,
      publisherTemplateEvidenceSha384:$publisherTemplateEvidenceSha384,
      templatePublisherRoleInventorySha384:$templatePublisherRoleInventorySha384,
      templatePublisherRoleInventoryObjectKey:$templatePublisherRoleInventoryObjectKey,
      templatePublisherRoleInventoryObjectVersionId:$templatePublisherRoleInventoryObjectVersionId,
      cloudFormationExecutionRoleInventoryObjectKey:$cloudFormationExecutionRoleInventoryObjectKey,
      cloudFormationExecutionRoleInventoryObjectVersionId:$cloudFormationExecutionRoleInventoryObjectVersionId,
      cloudFormationExecutionRoleInventorySha384:$cloudFormationExecutionRoleInventorySha384,
      templateUploadReceiptObjectKey:$templateUploadReceiptObjectKey,
      templateUploadReceiptObjectVersionId:$templateUploadReceiptObjectVersionId,
      templateUploadReceiptSha384:$templateUploadReceiptSha384,
      changeSetReceiptObjectKey:$changeSetReceiptObjectKey,
      changeSetReceiptObjectVersionId:$changeSetReceiptObjectVersionId,
      changeSetReceiptSha384:$changeSetReceiptSha384,
      cleanupTemplateSha384:$cleanupTemplateSha384,
      cleanupTemplateEvidenceObjectKey:$cleanupTemplateEvidenceObjectKey,
      cleanupTemplateEvidenceObjectVersionId:$cleanupTemplateEvidenceObjectVersionId,
      cleanupTemplateEvidenceSha384:$cleanupTemplateEvidenceSha384,
      cleanupExecutionRoleInventorySha384:$cleanupExecutionRoleInventorySha384,
      cleanupExecutionRoleInventoryObjectKey:$cleanupExecutionRoleInventoryObjectKey,
      cleanupExecutionRoleInventoryObjectVersionId:$cleanupExecutionRoleInventoryObjectVersionId,
      cleanupSubmitterRoleInventorySha384:$cleanupSubmitterRoleInventorySha384,
      cleanupSubmitterRoleInventoryObjectKey:$cleanupSubmitterRoleInventoryObjectKey,
      cleanupSubmitterRoleInventoryObjectVersionId:$cleanupSubmitterRoleInventoryObjectVersionId,
      packerInvokerTemplateSha384:$packerInvokerTemplateSha384,
      packerInvokerEvidenceObjectKey:$packerInvokerEvidenceObjectKey,
      packerInvokerEvidenceObjectVersionId:$packerInvokerEvidenceObjectVersionId,
      packerInvokerEvidenceSha384:$packerInvokerEvidenceSha384,
      packerInvokerRoleInventorySha384:$packerInvokerRoleInventorySha384,
      packerControlInventoryPolicySha384:$packerControlInventoryPolicySha384,
      packerControlLaunchPolicySha384:$packerControlLaunchPolicySha384,
      packerControlArtifactPolicySha384:$packerControlArtifactPolicySha384,
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
      nitroPackageClosureSha384:$nitroPackageClosureSha384,
      nitroPackageSigningKeyFingerprint:$nitroPackageSigningKeyFingerprint,
      nitroPackageSigningKeySha256:$nitroPackageSigningKeySha256,
      nitroPackageSetEvidenceObjectKey:$nitroPackageSetEvidenceObjectKey,
      nitroPackageSetEvidenceObjectVersionId:$nitroPackageSetEvidenceObjectVersionId,
      nitroPackageSetEvidenceSha384:$nitroPackageSetEvidenceSha384,
      productionRouteAttached:false,validated:true}'
}

build_ami() {
  local build_time build_completed_at artifact_id ami_id
  local packer_manifest_sha384 installed_package_inventory installed_package_inventory_sha384
  require_env LAYRS_RECOVERY_BUILD_SUBNET_ID
  require_env LAYRS_RECOVERY_BUILD_SECURITY_GROUP_ID
  require_env LAYRS_RECOVERY_BUILD_INSTANCE_PROFILE
  require_env LAYRS_RECOVERY_PACKER_MANIFEST
  require_env LAYRS_RECOVERY_BUILD_EVIDENCE_OUTPUT
  require_command aws
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
  [[ -n "${PACKER_BINARY}" ]] || die "the exact reviewed Packer CLI was not initialized"
  assert_isolated_packer_toolchain
  "${PACKER_BINARY}" validate \
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
    -var "build_control_plane_role_inventory_sha384=${BUILD_CONTROL_PLANE_ROLE_INVENTORY_SHA384}" \
    -var "builder_template_sha384=${LAYRS_RECOVERY_BUILDER_TEMPLATE_SHA384}" \
    -var "packer_invoker_role_inventory_sha384=${LAYRS_RECOVERY_PACKER_INVOKER_ROLE_INVENTORY_SHA384}" \
    -var "parent_package_commit=${PARENT_PACKAGE_COMMIT}" \
    -var "parent_sha384=${EXPECTED_PARENT_SHA384}" \
    -var "phase2_template_commit=${LAYRS_RECOVERY_PHASE2_TEMPLATE_COMMIT}" \
    -var "phase2_template_sha384=${LAYRS_RECOVERY_EXPECTED_PHASE2_TEMPLATE_SHA384}" \
    -var "implementation_commit=${LAYRS_RECOVERY_IMPLEMENTATION_COMMIT}" \
    -var "packer_template_sha384=${PACKER_TEMPLATE_SHA384}" \
    -var "nitro_cli_nevra=${NITRO_CLI_NEVRA}" \
    -var "nitro_cli_rpm_sha384=${NITRO_CLI_RPM_SHA384}" \
    -var "nitro_package_inventory_sha384=${EXPECTED_PACKAGE_INVENTORY_SHA384}" \
    -var "nitro_package_set_sha384=${NITRO_PACKAGE_SET_SHA384}" \
    -var "nitro_package_closure_sha384=${NITRO_PACKAGE_CLOSURE_SHA384}" \
    -var "recovery_evidence_index_sha384=${LAYRS_RECOVERY_BUILDER_EVIDENCE_INDEX_SHA384}" \
    -var "package_install_plan=${PACKAGE_INSTALL_PLAN}" \
    -var "package_inventory_output=${PREFLIGHT_TEMP_DIR}/installed-package-inventory.txt" \
    -var "manifest_output=${LAYRS_RECOVERY_PACKER_MANIFEST}" \
    "${PACKER_TEMPLATE}"
  assert_isolated_packer_toolchain
  "${PACKER_BINARY}" build -color=false -force=false \
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
    -var "build_control_plane_role_inventory_sha384=${BUILD_CONTROL_PLANE_ROLE_INVENTORY_SHA384}" \
    -var "builder_template_sha384=${LAYRS_RECOVERY_BUILDER_TEMPLATE_SHA384}" \
    -var "packer_invoker_role_inventory_sha384=${LAYRS_RECOVERY_PACKER_INVOKER_ROLE_INVENTORY_SHA384}" \
    -var "parent_package_commit=${PARENT_PACKAGE_COMMIT}" \
    -var "parent_sha384=${EXPECTED_PARENT_SHA384}" \
    -var "phase2_template_commit=${LAYRS_RECOVERY_PHASE2_TEMPLATE_COMMIT}" \
    -var "phase2_template_sha384=${LAYRS_RECOVERY_EXPECTED_PHASE2_TEMPLATE_SHA384}" \
    -var "implementation_commit=${LAYRS_RECOVERY_IMPLEMENTATION_COMMIT}" \
    -var "packer_template_sha384=${PACKER_TEMPLATE_SHA384}" \
    -var "nitro_cli_nevra=${NITRO_CLI_NEVRA}" \
    -var "nitro_cli_rpm_sha384=${NITRO_CLI_RPM_SHA384}" \
    -var "nitro_package_inventory_sha384=${EXPECTED_PACKAGE_INVENTORY_SHA384}" \
    -var "nitro_package_set_sha384=${NITRO_PACKAGE_SET_SHA384}" \
    -var "nitro_package_closure_sha384=${NITRO_PACKAGE_CLOSURE_SHA384}" \
    -var "recovery_evidence_index_sha384=${LAYRS_RECOVERY_BUILDER_EVIDENCE_INDEX_SHA384}" \
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
    --arg parentPackageCommit "${PARENT_PACKAGE_COMMIT}" \
    --arg builderEvidenceIndexSha384 "${LAYRS_RECOVERY_BUILDER_EVIDENCE_INDEX_SHA384}" \
    --arg sourceAmiId "${LAYRS_RECOVERY_SOURCE_AMI_ID}" \
    --arg sourceAmiOwner "${LAYRS_RECOVERY_SOURCE_AMI_OWNER}" \
    --arg sourceAmiProvenanceSha384 "${SOURCE_AMI_PROVENANCE_SHA384}" \
    --arg buildSubnetInventorySha384 "${BUILD_SUBNET_INVENTORY_SHA384}" \
    --arg buildSecurityGroupInventorySha384 "${BUILD_SECURITY_GROUP_INVENTORY_SHA384}" \
    --arg buildInstanceProfileInventorySha384 "${BUILD_INSTANCE_PROFILE_INVENTORY_SHA384}" \
    --arg buildControlPlaneRoleInventorySha384 "${BUILD_CONTROL_PLANE_ROLE_INVENTORY_SHA384}" \
    --arg builderTemplateSha384 "${LAYRS_RECOVERY_BUILDER_TEMPLATE_SHA384}" \
    --arg packerInvokerRoleInventorySha384 "${LAYRS_RECOVERY_PACKER_INVOKER_ROLE_INVENTORY_SHA384}" \
    --arg parentSha384 "${EXPECTED_PARENT_SHA384}" \
    --arg eifSha384 "${EXPECTED_EIF_SHA384}" \
    --arg pcr0Sha384 "${EXPECTED_PCR0_SHA384}" \
    --arg phase2TemplateSha384 "${LAYRS_RECOVERY_EXPECTED_PHASE2_TEMPLATE_SHA384}" \
    --arg phase2TemplateCommit "${LAYRS_RECOVERY_PHASE2_TEMPLATE_COMMIT}" \
    --arg implementationCommit "${LAYRS_RECOVERY_IMPLEMENTATION_COMMIT}" \
    --arg packerTemplateSha384 "${PACKER_TEMPLATE_SHA384}" \
    --arg packerCliVersion "${PACKER_CLI_VERSION}" \
    --arg packerCliArchiveSha256 "${PACKER_CLI_ARCHIVE_SHA256}" \
    --arg packerCliSha384 "${PACKER_CLI_SHA384}" \
    --arg packerAmazonPluginVersion "${PACKER_AMAZON_PLUGIN_VERSION}" \
    --arg packerAmazonPluginSha384 "${PACKER_AMAZON_PLUGIN_SHA384}" \
    --arg packerToolchainProvenanceSha256 "${PACKER_TOOLCHAIN_PROVENANCE_SHA256}" \
    --arg packerToolchainManifestSha256 "${PACKER_TOOLCHAIN_MANIFEST_SHA256}" \
    --arg nitroCliNevra "${NITRO_CLI_NEVRA}" \
    --arg nitroCliRpmSha384 "${NITRO_CLI_RPM_SHA384}" \
    --arg nitroPackageSetSha384 "${NITRO_PACKAGE_SET_SHA384}" \
    --arg nitroPackageClosureSha384 "${NITRO_PACKAGE_CLOSURE_SHA384}" \
    --arg nitroPackageInventorySha384 "${EXPECTED_PACKAGE_INVENTORY_SHA384}" \
    '.builds[0].custom_data == {
      purpose:$purpose,sourceCommit:$sourceCommit,parentPackageCommit:$parentPackageCommit,sourceAmiId:$sourceAmiId,
      sourceAmiOwner:$sourceAmiOwner,sourceAmiProvenanceSha384:$sourceAmiProvenanceSha384,
      buildSubnetInventorySha384:$buildSubnetInventorySha384,
      buildSecurityGroupInventorySha384:$buildSecurityGroupInventorySha384,
      buildInstanceProfileInventorySha384:$buildInstanceProfileInventorySha384,
      buildControlPlaneRoleInventorySha384:$buildControlPlaneRoleInventorySha384,
      builderEvidenceIndexSha384:$builderEvidenceIndexSha384,
      builderTemplateSha384:$builderTemplateSha384,
      packerInvokerRoleInventorySha384:$packerInvokerRoleInventorySha384,
      parentSha384:$parentSha384,eifSha384:$eifSha384,
      pcr0Sha384:$pcr0Sha384,phase2TemplateCommit:$phase2TemplateCommit,
      phase2TemplateSha384:$phase2TemplateSha384,
      implementationCommit:$implementationCommit,packerTemplateSha384:$packerTemplateSha384,
      packerCliVersion:$packerCliVersion,packerCliArchiveSha256:$packerCliArchiveSha256,
      packerCliSha384:$packerCliSha384,
      packerAmazonPluginVersion:$packerAmazonPluginVersion,
      packerAmazonPluginSha384:$packerAmazonPluginSha384,
      packerToolchainProvenanceSha256:$packerToolchainProvenanceSha256,
      packerToolchainManifestSha256:$packerToolchainManifestSha256,
      nitroCliNevra:$nitroCliNevra,nitroCliRpmSha384:$nitroCliRpmSha384,
      nitroPackageSetSha384:$nitroPackageSetSha384,
      nitroPackageClosureSha384:$nitroPackageClosureSha384,
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
  build_completed_at="$(date -u -d "@${build_time}" '+%Y-%m-%dT%H:%M:%SZ')"
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
    --arg trustedPrincipalInventorySha384 "${LAYRS_RECOVERY_TRUSTED_PRINCIPAL_INVENTORY_SHA384}" \
    --arg sourceCommit "${RECOVERY_SOURCE_COMMIT}" \
    --arg parentPackageCommit "${PARENT_PACKAGE_COMMIT}" \
    --arg parentBuildWrapperSha384 "${PARENT_BUILD_WRAPPER_SHA384}" \
    --arg parentPreflightSha384 "${PARENT_PREFLIGHT_SHA384}" \
    --arg parentBuildEvidenceRendererSha384 "${PARENT_BUILD_EVIDENCE_RENDERER_SHA384}" \
    --arg parentPostBuildCleanupEvidenceRendererSha384 "${PARENT_POST_BUILD_CLEANUP_EVIDENCE_RENDERER_SHA384}" \
    --arg parentRunbookSha384 "${PARENT_RUNBOOK_SHA384}" \
    --arg builderEvidenceIndexSha384 "${LAYRS_RECOVERY_BUILDER_EVIDENCE_INDEX_SHA384}" \
    --arg builderEvidenceIndexObjectKey "${LAYRS_RECOVERY_BUILDER_EVIDENCE_INDEX_OBJECT_KEY}" \
    --arg builderEvidenceIndexObjectVersionId "${LAYRS_RECOVERY_BUILDER_EVIDENCE_INDEX_OBJECT_VERSION_ID}" \
    --arg builderTemplateSha384 "${LAYRS_RECOVERY_BUILDER_TEMPLATE_SHA384}" \
    --arg builderTemplateEvidenceObjectKey "${LAYRS_RECOVERY_BUILDER_TEMPLATE_EVIDENCE_OBJECT_KEY}" \
    --arg builderTemplateEvidenceObjectVersionId "${LAYRS_RECOVERY_BUILDER_TEMPLATE_EVIDENCE_OBJECT_VERSION_ID}" \
    --arg builderTemplateEvidenceSha384 "${LAYRS_RECOVERY_BUILDER_TEMPLATE_EVIDENCE_SHA384}" \
    --arg packerInvokerRoleInventorySha384 "${LAYRS_RECOVERY_PACKER_INVOKER_ROLE_INVENTORY_SHA384}" \
    --arg packerInvokerTemplateSha384 "${LAYRS_RECOVERY_PACKER_INVOKER_TEMPLATE_SHA384}" \
    --arg packerInvokerEvidenceObjectKey "${LAYRS_RECOVERY_PACKER_INVOKER_EVIDENCE_OBJECT_KEY}" \
    --arg packerInvokerEvidenceObjectVersionId "${LAYRS_RECOVERY_PACKER_INVOKER_EVIDENCE_OBJECT_VERSION_ID}" \
    --arg packerInvokerEvidenceSha384 "${LAYRS_RECOVERY_PACKER_INVOKER_EVIDENCE_SHA384}" \
    --arg packerControlInventoryPolicySha384 "${LAYRS_RECOVERY_PACKER_CONTROL_INVENTORY_POLICY_SHA384}" \
    --arg packerControlLaunchPolicySha384 "${LAYRS_RECOVERY_PACKER_CONTROL_LAUNCH_POLICY_SHA384}" \
    --arg packerControlArtifactPolicySha384 "${LAYRS_RECOVERY_PACKER_CONTROL_ARTIFACT_POLICY_SHA384}" \
    --arg publisherTemplateSha384 "${LAYRS_RECOVERY_PUBLISHER_TEMPLATE_SHA384}" \
    --arg publisherTemplateEvidenceObjectKey "${LAYRS_RECOVERY_PUBLISHER_TEMPLATE_EVIDENCE_OBJECT_KEY}" \
    --arg publisherTemplateEvidenceObjectVersionId "${LAYRS_RECOVERY_PUBLISHER_TEMPLATE_EVIDENCE_OBJECT_VERSION_ID}" \
    --arg publisherTemplateEvidenceSha384 "${LAYRS_RECOVERY_PUBLISHER_TEMPLATE_EVIDENCE_SHA384}" \
    --arg templatePublisherRoleInventorySha384 "${LAYRS_RECOVERY_TEMPLATE_PUBLISHER_ROLE_INVENTORY_SHA384}" \
    --arg templatePublisherRoleInventoryObjectKey "${LAYRS_RECOVERY_TEMPLATE_PUBLISHER_ROLE_INVENTORY_OBJECT_KEY}" \
    --arg templatePublisherRoleInventoryObjectVersionId "${LAYRS_RECOVERY_TEMPLATE_PUBLISHER_ROLE_INVENTORY_OBJECT_VERSION_ID}" \
    --arg cloudFormationExecutionRoleInventoryObjectKey "${LAYRS_RECOVERY_CLOUDFORMATION_EXECUTION_ROLE_INVENTORY_OBJECT_KEY}" \
    --arg cloudFormationExecutionRoleInventoryObjectVersionId "${LAYRS_RECOVERY_CLOUDFORMATION_EXECUTION_ROLE_INVENTORY_OBJECT_VERSION_ID}" \
    --arg cloudFormationExecutionRoleInventorySha384 "${LAYRS_RECOVERY_CLOUDFORMATION_EXECUTION_ROLE_INVENTORY_SHA384}" \
    --arg templateUploadReceiptObjectKey "${LAYRS_RECOVERY_TEMPLATE_UPLOAD_RECEIPT_OBJECT_KEY}" \
    --arg templateUploadReceiptObjectVersionId "${LAYRS_RECOVERY_TEMPLATE_UPLOAD_RECEIPT_OBJECT_VERSION_ID}" \
    --arg templateUploadReceiptSha384 "${LAYRS_RECOVERY_TEMPLATE_UPLOAD_RECEIPT_SHA384}" \
    --arg changeSetReceiptObjectKey "${LAYRS_RECOVERY_CHANGE_SET_RECEIPT_OBJECT_KEY}" \
    --arg changeSetReceiptObjectVersionId "${LAYRS_RECOVERY_CHANGE_SET_RECEIPT_OBJECT_VERSION_ID}" \
    --arg changeSetReceiptSha384 "${LAYRS_RECOVERY_CHANGE_SET_RECEIPT_SHA384}" \
    --arg cleanupTemplateSha384 "${LAYRS_RECOVERY_CLEANUP_TEMPLATE_SHA384}" \
    --arg cleanupTemplateEvidenceObjectKey "${LAYRS_RECOVERY_CLEANUP_TEMPLATE_EVIDENCE_OBJECT_KEY}" \
    --arg cleanupTemplateEvidenceObjectVersionId "${LAYRS_RECOVERY_CLEANUP_TEMPLATE_EVIDENCE_OBJECT_VERSION_ID}" \
    --arg cleanupTemplateEvidenceSha384 "${LAYRS_RECOVERY_CLEANUP_TEMPLATE_EVIDENCE_SHA384}" \
    --arg cleanupExecutionRoleInventorySha384 "${LAYRS_RECOVERY_CLEANUP_EXECUTION_ROLE_INVENTORY_SHA384}" \
    --arg cleanupExecutionRoleInventoryObjectKey "${LAYRS_RECOVERY_CLEANUP_EXECUTION_ROLE_INVENTORY_OBJECT_KEY}" \
    --arg cleanupExecutionRoleInventoryObjectVersionId "${LAYRS_RECOVERY_CLEANUP_EXECUTION_ROLE_INVENTORY_OBJECT_VERSION_ID}" \
    --arg cleanupSubmitterRoleInventorySha384 "${LAYRS_RECOVERY_CLEANUP_SUBMITTER_ROLE_INVENTORY_SHA384}" \
    --arg cleanupSubmitterRoleInventoryObjectKey "${LAYRS_RECOVERY_CLEANUP_SUBMITTER_ROLE_INVENTORY_OBJECT_KEY}" \
    --arg cleanupSubmitterRoleInventoryObjectVersionId "${LAYRS_RECOVERY_CLEANUP_SUBMITTER_ROLE_INVENTORY_OBJECT_VERSION_ID}" \
    --arg sourceAmiId "${LAYRS_RECOVERY_SOURCE_AMI_ID}" \
    --arg sourceAmiOwner "${LAYRS_RECOVERY_SOURCE_AMI_OWNER}" \
    --arg sourceAmiProvenanceSha384 "${SOURCE_AMI_PROVENANCE_SHA384}" \
    --arg buildSubnetInventorySha384 "${BUILD_SUBNET_INVENTORY_SHA384}" \
    --arg buildSecurityGroupInventorySha384 "${BUILD_SECURITY_GROUP_INVENTORY_SHA384}" \
    --arg buildInstanceProfileInventorySha384 "${BUILD_INSTANCE_PROFILE_INVENTORY_SHA384}" \
    --arg buildControlPlaneRoleInventorySha384 "${BUILD_CONTROL_PLANE_ROLE_INVENTORY_SHA384}" \
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
    --arg packerAmazonPluginVersion "${PACKER_AMAZON_PLUGIN_VERSION}" \
    --arg packerAmazonPluginSourceCommit "2a769c39a05940e25143098f071490732fa24f4f" \
    --arg packerToolchainManifestSha256 "${PACKER_TOOLCHAIN_MANIFEST_SHA256}" \
    --arg nitroCliNevra "${NITRO_CLI_NEVRA}" \
    --arg nitroCliRpmObjectKey "${NITRO_CLI_RPM_OBJECT_KEY}" \
    --arg nitroCliRpmObjectVersionId "${NITRO_CLI_RPM_OBJECT_VERSION_ID}" \
    --arg nitroCliRpmSha384 "${NITRO_CLI_RPM_SHA384}" \
    --arg nitroPackageSetObjectKey "${LAYRS_RECOVERY_NITRO_PACKAGE_SET_OBJECT_KEY}" \
    --arg nitroPackageSetObjectVersionId "${LAYRS_RECOVERY_NITRO_PACKAGE_SET_OBJECT_VERSION_ID}" \
    --arg nitroPackageSetSha384 "${LAYRS_RECOVERY_NITRO_PACKAGE_SET_SHA384}" \
    --arg nitroPackageClosureSha384 "${NITRO_PACKAGE_CLOSURE_SHA384}" \
    --arg nitroPackageSetEvidenceObjectKey "${LAYRS_RECOVERY_NITRO_PACKAGE_SET_EVIDENCE_OBJECT_KEY}" \
    --arg nitroPackageSetEvidenceObjectVersionId "${LAYRS_RECOVERY_NITRO_PACKAGE_SET_EVIDENCE_OBJECT_VERSION_ID}" \
    --arg nitroPackageSetEvidenceSha384 "${LAYRS_RECOVERY_NITRO_PACKAGE_SET_EVIDENCE_SHA384}" \
    --arg nitroPackageInventorySha384 "${installed_package_inventory_sha384}" \
    '{protocol:"layrs.seq159300.recovery-parent-build-evidence.v1",
      accountId:$accountId,amiId:$amiId,buildCompletedAt:$buildCompletedAt,
      eifSha384:$eifSha384,environment:"production",implementationCommit:$implementationCommit,
      trustedPrincipalInventorySha384:$trustedPrincipalInventorySha384,
      parentBinarySha384:$parentBinarySha384,pcr0Sha384:$pcr0Sha384,region:$region,
      remediationEvidenceCommit:$remediationEvidenceCommit,
      remediationIndexObjectVersionId:$remediationIndexObjectVersionId,
      sourceCommit:$sourceCommit,
      parentPackageCommit:$parentPackageCommit,
      parentBuildWrapperSha384:$parentBuildWrapperSha384,
      parentPreflightSha384:$parentPreflightSha384,
      parentBuildEvidenceRendererSha384:$parentBuildEvidenceRendererSha384,
      parentPostBuildCleanupEvidenceRendererSha384:$parentPostBuildCleanupEvidenceRendererSha384,
      parentRunbookSha384:$parentRunbookSha384,
      builderEvidenceIndexObjectKey:$builderEvidenceIndexObjectKey,
      builderEvidenceIndexObjectVersionId:$builderEvidenceIndexObjectVersionId,
      builderEvidenceIndexSha384:$builderEvidenceIndexSha384,
      builderTemplateEvidenceObjectKey:$builderTemplateEvidenceObjectKey,
      builderTemplateEvidenceObjectVersionId:$builderTemplateEvidenceObjectVersionId,
      builderTemplateEvidenceSha384:$builderTemplateEvidenceSha384,
      builderTemplateSha384:$builderTemplateSha384,sourceAmiId:$sourceAmiId,
      packerInvokerTemplateSha384:$packerInvokerTemplateSha384,
      packerInvokerEvidenceObjectKey:$packerInvokerEvidenceObjectKey,
      packerInvokerEvidenceObjectVersionId:$packerInvokerEvidenceObjectVersionId,
      packerInvokerEvidenceSha384:$packerInvokerEvidenceSha384,
      packerInvokerRoleInventorySha384:$packerInvokerRoleInventorySha384,
      packerControlInventoryPolicySha384:$packerControlInventoryPolicySha384,
      packerControlLaunchPolicySha384:$packerControlLaunchPolicySha384,
      packerControlArtifactPolicySha384:$packerControlArtifactPolicySha384,
      publisherTemplateSha384:$publisherTemplateSha384,
      publisherTemplateEvidenceObjectKey:$publisherTemplateEvidenceObjectKey,
      publisherTemplateEvidenceObjectVersionId:$publisherTemplateEvidenceObjectVersionId,
      publisherTemplateEvidenceSha384:$publisherTemplateEvidenceSha384,
      templatePublisherRoleInventorySha384:$templatePublisherRoleInventorySha384,
      templatePublisherRoleInventoryObjectKey:$templatePublisherRoleInventoryObjectKey,
      templatePublisherRoleInventoryObjectVersionId:$templatePublisherRoleInventoryObjectVersionId,
      cloudFormationExecutionRoleInventoryObjectKey:$cloudFormationExecutionRoleInventoryObjectKey,
      cloudFormationExecutionRoleInventoryObjectVersionId:$cloudFormationExecutionRoleInventoryObjectVersionId,
      cloudFormationExecutionRoleInventorySha384:$cloudFormationExecutionRoleInventorySha384,
      templateUploadReceiptObjectKey:$templateUploadReceiptObjectKey,
      templateUploadReceiptObjectVersionId:$templateUploadReceiptObjectVersionId,
      templateUploadReceiptSha384:$templateUploadReceiptSha384,
      changeSetReceiptObjectKey:$changeSetReceiptObjectKey,
      changeSetReceiptObjectVersionId:$changeSetReceiptObjectVersionId,
      changeSetReceiptSha384:$changeSetReceiptSha384,
      cleanupTemplateSha384:$cleanupTemplateSha384,
      cleanupTemplateEvidenceObjectKey:$cleanupTemplateEvidenceObjectKey,
      cleanupTemplateEvidenceObjectVersionId:$cleanupTemplateEvidenceObjectVersionId,
      cleanupTemplateEvidenceSha384:$cleanupTemplateEvidenceSha384,
      cleanupExecutionRoleInventorySha384:$cleanupExecutionRoleInventorySha384,
      cleanupExecutionRoleInventoryObjectKey:$cleanupExecutionRoleInventoryObjectKey,
      cleanupExecutionRoleInventoryObjectVersionId:$cleanupExecutionRoleInventoryObjectVersionId,
      cleanupSubmitterRoleInventorySha384:$cleanupSubmitterRoleInventorySha384,
      cleanupSubmitterRoleInventoryObjectKey:$cleanupSubmitterRoleInventoryObjectKey,
      cleanupSubmitterRoleInventoryObjectVersionId:$cleanupSubmitterRoleInventoryObjectVersionId,
      sourceAmiOwner:$sourceAmiOwner,sourceAmiProvenanceSha384:$sourceAmiProvenanceSha384,
      buildSubnetInventorySha384:$buildSubnetInventorySha384,
      buildSecurityGroupInventorySha384:$buildSecurityGroupInventorySha384,
      buildInstanceProfileInventorySha384:$buildInstanceProfileInventorySha384,
      buildControlPlaneRoleInventorySha384:$buildControlPlaneRoleInventorySha384,
      outputAmiInventorySha384:$outputAmiInventorySha384,
      phase2TemplateCommit:$phase2TemplateCommit,phase2TemplateSha384:$phase2TemplateSha384,
      phase2EvidenceObjectKey:$phase2EvidenceObjectKey,
      phase2EvidenceObjectVersionId:$phase2EvidenceObjectVersionId,
      phase2EvidenceObjectSha384:$phase2EvidenceObjectSha384,
      implementationEvidenceObjectKey:$implementationEvidenceObjectKey,
      implementationEvidenceObjectVersionId:$implementationEvidenceObjectVersionId,
      implementationEvidenceObjectSha384:$implementationEvidenceObjectSha384,
      packerTemplateSha384:$packerTemplateSha384,packerManifestSha384:$packerManifestSha384,
      packerAmazonPluginVersion:$packerAmazonPluginVersion,
      packerAmazonPluginSourceCommit:$packerAmazonPluginSourceCommit,
      packerToolchainManifestSha256:$packerToolchainManifestSha256,
      nitroCliNevra:$nitroCliNevra,nitroPackageInventorySha384:$nitroPackageInventorySha384,
      nitroCliRpmObjectKey:$nitroCliRpmObjectKey,
      nitroCliRpmObjectVersionId:$nitroCliRpmObjectVersionId,nitroCliRpmSha384:$nitroCliRpmSha384,
      nitroPackageSetObjectKey:$nitroPackageSetObjectKey,
      nitroPackageSetObjectVersionId:$nitroPackageSetObjectVersionId,
      nitroPackageSetSha384:$nitroPackageSetSha384,
      nitroPackageClosureSha384:$nitroPackageClosureSha384,
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
  require_command sha256sum
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
  require_command cat
  require_command chmod
  require_command install
  require_command sed
  require_command stat
  require_command id
  require_command gpg
  require_command unzip
  require_command tar
  cd -- "${REPO_ROOT}"
  verify_repository
  verify_inputs
  verify_packer_toolchain

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
