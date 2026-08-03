#!/usr/bin/env sh

# Move a convenience tag only after verifying the immutable release digest.

set -u

readonly cosign_binary="${COSIGN:-cosign}"
readonly cosign_verify_key="${COSIGN_VERIFY_KEY:-}"
readonly skopeo_binary="${SKOPEO:-skopeo}"

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  return 1
}

main() {
  if [ "$#" -ne 2 ] || [ -z "${1}" ] || [ -z "${2}" ]; then
    printf 'Usage: %s IMAGE_DIGEST CONVENIENCE_TAG\n' "${0##*/}" >&2
    return 64
  fi
  image_reference=${1}
  convenience_tag=${2}

  if ! printf '%s\n' "${image_reference}" \
    | grep -E -q '^quay\.io/[^[:space:]@]+/[^[:space:]@]+@sha256:[0-9a-f]{64}$'; then
    fail "Source must be an immutable Quay digest: ${image_reference}"
    return 64
  fi
  if ! printf '%s\n' "${convenience_tag}" \
    | grep -E -q '^quay\.io/[^[:space:]@:]+/[^[:space:]@:]+:[a-zA-Z0-9._-]+$'; then
    fail "Destination must be a Quay tag: ${convenience_tag}"
    return 64
  fi
  if [ "${image_reference%@*}" != "${convenience_tag%:*}" ]; then
    fail 'Convenience tags may only refer to the verified source repository'
    return 64
  fi
  if [ -z "${cosign_verify_key}" ]; then
    fail 'COSIGN_VERIFY_KEY must name the trusted public key or KMS URI'
    return 64
  fi
  for required_command in "${cosign_binary}" "${skopeo_binary}" grep; do
    if ! command -v "${required_command}" >/dev/null 2>&1; then
      fail "Required command is unavailable: ${required_command}"
      return 69
    fi
  done

  "${cosign_binary}" verify --key "${cosign_verify_key}" \
    "${image_reference}" >/dev/null || return 1
  "${cosign_binary}" verify-attestation --key "${cosign_verify_key}" \
    --type spdxjson "${image_reference}" >/dev/null || return 1
  "${cosign_binary}" verify-attestation --key "${cosign_verify_key}" \
    --type slsaprovenance "${image_reference}" >/dev/null || return 1

  "${skopeo_binary}" copy --preserve-digests \
    "docker://${image_reference}" "docker://${convenience_tag}" || return 1
  promoted_digest=$("${skopeo_binary}" inspect --format '{{.Digest}}' \
    "docker://${convenience_tag}") || return 1
  if [ "${promoted_digest}" != "${image_reference##*@}" ]; then
    fail "Convenience tag did not resolve to the verified digest: ${convenience_tag}"
    return 65
  fi
}

main "$@"
