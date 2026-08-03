#!/usr/bin/env sh

# Sign pushed image digests and attach their locally generated SPDX SBOMs.

set -u

readonly cosign_binary="${COSIGN:-cosign}"
readonly cosign_key="${COSIGN_KEY:-}"

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  return 1
}

validate_input_pair() {
  image_reference=${1}
  metadata_file=${2}

  if ! printf '%s\n' "${image_reference}" \
    | grep -E -q '^[^[:space:]@]+/[^[:space:]@]+@sha256:[0-9a-f]{64}$'; then
    fail "Image reference must be a registry digest, not a tag: ${image_reference}"
    return 64
  fi
  if [ ! -f "${metadata_file}" ] || [ -L "${metadata_file}" ] || [ ! -r "${metadata_file}" ]; then
    fail "Metadata is not a readable regular file: ${metadata_file}"
    return 66
  fi

  metadata_digest=$(jq -er '.oci_manifest_digest | strings' "${metadata_file}") || return 66
  if [ "${image_reference##*@}" != "${metadata_digest}" ]; then
    fail "Registry digest does not match release metadata: ${image_reference}"
    return 65
  fi

  policy_result=$(jq -er '.security_report.policy | strings' "${metadata_file}") || return 66
  if [ "${policy_result}" != passed ]; then
    fail "Release metadata did not pass security policy: ${metadata_file}"
    return 65
  fi
  release_policy=$(jq -er '.release_policy | strings' "${metadata_file}") || return 66
  if [ "${release_policy}" != passed ]; then
    fail "Complete release policy did not pass: ${metadata_file}"
    return 65
  fi

  metadata_directory=$(CDPATH='' cd "$(dirname "${metadata_file}")" && pwd -P) || return 66
  sbom_name=$(jq -er '.spdx_sbom.path | strings' "${metadata_file}") || return 66
  case "${sbom_name}" in
    */* | '.' | '..')
      fail 'SPDX SBOM metadata must contain a file name without a directory'
      return 66
      ;;
    *) ;;
  esac
  sbom_file="${metadata_directory}/${sbom_name}"
  if [ ! -f "${sbom_file}" ] || [ -L "${sbom_file}" ] || [ ! -r "${sbom_file}" ]; then
    fail "SPDX SBOM is not a readable regular file: ${sbom_file}"
    return 66
  fi
  expected_sbom_sha256=$(jq -er '.spdx_sbom.sha256 | strings' "${metadata_file}") || return 66
  actual_sbom_sha256=$(sha256sum "${sbom_file}" | cut -d ' ' -f 1) || return 66
  if [ "${actual_sbom_sha256}" != "${expected_sbom_sha256}" ]; then
    fail "SPDX SBOM digest does not match release metadata: ${sbom_file}"
    return 65
  fi
}

main() {
  if [ "$#" -eq 0 ] || [ $(($# % 2)) -ne 0 ]; then
    printf 'Usage: %s IMAGE_DIGEST METADATA_FILE [IMAGE_DIGEST METADATA_FILE ...]\n' \
      "${0##*/}" >&2
    return 64
  fi
  if [ -z "${cosign_key}" ]; then
    fail 'COSIGN_KEY must name a private key file or KMS URI'
    return 64
  fi
  for required_command in "${cosign_binary}" jq sha256sum; do
    if ! command -v "${required_command}" >/dev/null 2>&1; then
      fail "Required command is unavailable: ${required_command}"
      return 69
    fi
  done

  while [ "$#" -gt 0 ]; do
    image_reference=${1}
    metadata_file=${2}
    validate_input_pair "${image_reference}" "${metadata_file}" || return $?
    metadata_directory=$(CDPATH='' cd "$(dirname "${metadata_file}")" && pwd -P) || return 66
    sbom_name=$(jq -er '.spdx_sbom.path | strings' "${metadata_file}") || return 66
    sbom_file="${metadata_directory}/${sbom_name}"

    printf 'Signing %s\n' "${image_reference}"
    "${cosign_binary}" sign --yes --key "${cosign_key}" "${image_reference}" || return 1
    printf 'Attesting SPDX SBOM for %s\n' "${image_reference}"
    "${cosign_binary}" attest --yes \
      --key "${cosign_key}" \
      --type spdxjson \
      --predicate "${sbom_file}" \
      "${image_reference}" || return 1

    shift 2
  done
}

main "$@"
