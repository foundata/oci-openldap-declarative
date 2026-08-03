#!/usr/bin/env sh

# Exercise release input validation without contacting a registry.

set -u

project_dir=$(CDPATH='' cd "$(dirname "$0")/.." && pwd) || exit 1
readonly project_dir
readonly release_script="${project_dir}/hack/release-artifacts.sh"
readonly sign_script="${project_dir}/hack/sign-release.sh"
readonly verify_trivy_script="${project_dir}/hack/verify-trivy.sh"

workspace=''

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  if [ -n "${workspace}" ] && [ -d "${workspace}" ]; then
    rm -rf "${workspace}"
  fi
}

write_cosign_stub() {
  cat >"${workspace}/cosign" <<'EOF'
#!/usr/bin/env sh
set -u
printf '%s\n' "$*" >>"${COSIGN_CALLS}"
EOF
  chmod 0755 "${workspace}/cosign"
}

write_release_fixture() {
  fixture_digest='sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
  printf '%s\n' '{"spdxVersion":"SPDX-2.3"}' >"${workspace}/runtime.spdx.json" || return 1
  fixture_sbom_sha256=$(sha256sum "${workspace}/runtime.spdx.json" | cut -d ' ' -f 1) || return 1
  jq -n \
    --arg digest "${fixture_digest}" \
    --arg sbom_sha256 "${fixture_sbom_sha256}" \
    '{
      oci_manifest_digest: $digest,
      spdx_sbom: {path: "runtime.spdx.json", sha256: $sbom_sha256},
      security_report: {policy: "passed"},
      release_policy: "passed"
    }' >"${workspace}/runtime.metadata.json"
}

main() {
  trap cleanup EXIT
  trap 'exit 130' HUP INT TERM

  workspace=$(mktemp -d /tmp/openldap-release-test.XXXXXX) \
    || fail 'Cannot create test directory'
  write_cosign_stub || fail 'Cannot create Cosign test double'
  write_release_fixture || fail 'Cannot create release fixture'

  mkdir "${workspace}/existing-output" || fail 'Cannot create existing output fixture'
  if "${release_script}" "${workspace}/existing-output" >/dev/null 2>&1; then
    fail 'Release command accepted an existing output path'
  fi

  if TRIVY_SEVERITIES='high,critical' \
    "${release_script}" "${workspace}/severity-output" >/dev/null 2>&1; then
    fail 'Release command accepted invalid Trivy severity names'
  fi
  if [ -e "${workspace}/severity-output" ]; then
    fail 'Rejected Trivy severity input left an output directory'
  fi

  if TRIVY_IMAGE='registry.example.org/trivy@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
    "${release_script}" "${workspace}/scanner-output" >/dev/null 2>&1; then
    fail 'Release command accepted an unreviewed Trivy digest'
  fi
  if [ -e "${workspace}/scanner-output" ]; then
    fail 'Rejected Trivy digest left an output directory'
  fi

  ln -s "${workspace}/missing-vex.json" "${workspace}/vex-link.json" \
    || fail 'Cannot create VEX symlink fixture'
  if TRIVY_VEX_FILE="${workspace}/vex-link.json" \
    "${release_script}" "${workspace}/vex-output" >/dev/null 2>&1; then
    fail 'Release command accepted a symbolic-link VEX input'
  fi
  if [ -e "${workspace}/vex-output" ]; then
    fail 'Rejected VEX input left an output directory'
  fi

  printf '%s\n' 'not-json' >"${workspace}/invalid-vex.json"
  if TRIVY_VEX_FILE="${workspace}/invalid-vex.json" \
    "${release_script}" "${workspace}/invalid-vex-output" >/dev/null 2>&1; then
    fail 'Release command accepted invalid VEX JSON'
  fi
  if [ -e "${workspace}/invalid-vex-output" ]; then
    fail 'Invalid VEX JSON left an output directory'
  fi

  : >"${workspace}/cosign-calls"
  COSIGN="${workspace}/cosign" \
    COSIGN_CALLS="${workspace}/cosign-calls" \
    "${verify_trivy_script}" >/dev/null \
    || fail 'Reviewed Trivy image was rejected'
  grep -F -q 'verify ghcr.io/aquasecurity/trivy@sha256:cffe3f5161a47a6823fbd23d985795b3ed72a4c806da4c4df16266c02accdd6f' \
    "${workspace}/cosign-calls" || fail 'Trivy signature verification was not issued'
  grep -F -q -- '--certificate-oidc-issuer https://token.actions.githubusercontent.com' \
    "${workspace}/cosign-calls" || fail 'Trivy certificate issuer was not constrained'
  if TRIVY_UPSTREAM_IMAGE='ghcr.io/aquasecurity/trivy:0.72.0' \
    COSIGN="${workspace}/cosign" \
    COSIGN_CALLS="${workspace}/cosign-calls" \
    "${verify_trivy_script}" >/dev/null 2>&1; then
    fail 'Mutable Trivy tag was accepted for signature verification'
  fi

  : >"${workspace}/cosign-calls"
  COSIGN="${workspace}/cosign" \
    COSIGN_CALLS="${workspace}/cosign-calls" \
    COSIGN_KEY='test-kms://release-key' \
    "${sign_script}" \
    'registry.example.org/openldap@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' \
    "${workspace}/runtime.metadata.json" >/dev/null \
    || fail 'Valid release evidence was rejected'
  grep -F -q 'sign --yes --key test-kms://release-key registry.example.org/openldap@sha256:' \
    "${workspace}/cosign-calls" || fail 'Image signature command was not issued'
  grep -F -q 'attest --yes --key test-kms://release-key --type spdxjson' \
    "${workspace}/cosign-calls" || fail 'SBOM attestation command was not issued'

  : >"${workspace}/cosign-calls"
  if COSIGN="${workspace}/cosign" \
    COSIGN_CALLS="${workspace}/cosign-calls" \
    COSIGN_KEY='test-kms://release-key' \
    "${sign_script}" registry.example.org/openldap:latest \
    "${workspace}/runtime.metadata.json" >/dev/null 2>&1; then
    fail 'Mutable image tag was accepted for signing'
  fi
  if [ -s "${workspace}/cosign-calls" ]; then
    fail 'Cosign was called for a mutable image tag'
  fi

  printf '%s\n' 'tampered' >>"${workspace}/runtime.spdx.json"
  if COSIGN="${workspace}/cosign" \
    COSIGN_CALLS="${workspace}/cosign-calls" \
    COSIGN_KEY='test-kms://release-key' \
    "${sign_script}" \
    'registry.example.org/openldap@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' \
    "${workspace}/runtime.metadata.json" >/dev/null 2>&1; then
    fail 'Changed SPDX SBOM was accepted for signing'
  fi

  printf '%s\n' '{"spdxVersion":"SPDX-2.3"}' >"${workspace}/runtime.spdx.json" \
    || fail 'Cannot restore SPDX fixture'
  jq '.security_report.policy = "rejected"' \
    "${workspace}/runtime.metadata.json" >"${workspace}/rejected.metadata.json" \
    || fail 'Cannot create rejected metadata fixture'
  if COSIGN="${workspace}/cosign" \
    COSIGN_CALLS="${workspace}/cosign-calls" \
    COSIGN_KEY='test-kms://release-key' \
    "${sign_script}" \
    'registry.example.org/openldap@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' \
    "${workspace}/rejected.metadata.json" >/dev/null 2>&1; then
    fail 'Security-rejected metadata was accepted for signing'
  fi

  jq '.release_policy = "rejected"' \
    "${workspace}/runtime.metadata.json" >"${workspace}/release-rejected.metadata.json" \
    || fail 'Cannot create release-rejected metadata fixture'
  if COSIGN="${workspace}/cosign" \
    COSIGN_CALLS="${workspace}/cosign-calls" \
    COSIGN_KEY='test-kms://release-key' \
    "${sign_script}" \
    'registry.example.org/openldap@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' \
    "${workspace}/release-rejected.metadata.json" >/dev/null 2>&1; then
    fail 'Release-rejected metadata was accepted for signing'
  fi

  printf '%s\n' 'Release script tests passed'
}

main "$@"
