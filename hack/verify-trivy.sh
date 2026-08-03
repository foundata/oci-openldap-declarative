#!/usr/bin/env sh

# Verify the reviewed upstream Trivy image before adopting or mirroring it.

set -u

readonly expected_digest="sha256:cffe3f5161a47a6823fbd23d985795b3ed72a4c806da4c4df16266c02accdd6f"
readonly trivy_upstream_image="${TRIVY_UPSTREAM_IMAGE:-ghcr.io/aquasecurity/trivy@sha256:cffe3f5161a47a6823fbd23d985795b3ed72a4c806da4c4df16266c02accdd6f}"
readonly cosign_binary="${COSIGN:-cosign}"
readonly certificate_identity='https://github\.com/aquasecurity/trivy/\.github/workflows/.+'
readonly certificate_issuer='https://token.actions.githubusercontent.com'

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  return 1
}

main() {
  if [ "$#" -ne 0 ]; then
    printf 'Usage: %s\n' "${0##*/}" >&2
    return 64
  fi
  case "${trivy_upstream_image}" in
    *@"${expected_digest}") ;;
    *)
      fail "TRIVY_UPSTREAM_IMAGE must use the reviewed scanner digest: ${expected_digest}"
      return 64
      ;;
  esac
  if ! command -v "${cosign_binary}" >/dev/null 2>&1; then
    fail "Required command is unavailable: ${cosign_binary}"
    return 69
  fi

  "${cosign_binary}" verify "${trivy_upstream_image}" \
    --certificate-identity-regexp "${certificate_identity}" \
    --certificate-oidc-issuer "${certificate_issuer}"
}

main "$@"
