#!/usr/bin/env sh

# Exercise release input validation without contacting a registry.

set -u

project_dir=$(CDPATH='' cd "$(dirname "$0")/.." && pwd) || exit 1
readonly project_dir
readonly release_script="${project_dir}/hack/release-artifacts.sh"
readonly publish_script="${project_dir}/hack/publish-release.sh"
readonly promote_script="${project_dir}/hack/promote-release.sh"
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

write_publish_stubs() {
  cat >"${workspace}/podman" <<'EOF'
#!/usr/bin/env sh
set -u
printf '%s\n' "$*" >>"${PUBLISH_CALLS}"
case "${1:-} ${2:-}" in
  'image exists' | 'save --format') exit 0 ;;
  *) exit 2 ;;
esac
EOF
  cat >"${workspace}/skopeo" <<'EOF'
#!/usr/bin/env sh
set -u
printf '%s\n' "$*" >>"${PUBLISH_CALLS}"
case "${1:-}" in
  copy) exit 0 ;;
  inspect)
    case "$*" in
      *docker://*)
        if [ "${PUBLISH_MISMATCH:-false}" = true ]; then
          printf '%s\n' 'sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
        else
          printf '%s\n' "${PUBLISH_DIGEST}"
        fi
        ;;
      *) printf '%s\n' "${PUBLISH_DIGEST}" ;;
    esac
    ;;
  *) exit 2 ;;
esac
EOF
  chmod 0755 "${workspace}/podman" "${workspace}/skopeo"
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
  jq -n '{
    buildDefinition: {
      buildType: "https://example.org/buildtypes/oci/v1",
      externalParameters: {},
      internalParameters: {},
      resolvedDependencies: [{
        uri: "git+https://github.com/foundata/oci-openldap-declarative@0123456789abcdef",
        digest: {sha1: "0123456789abcdef"}
      }]
    },
    runDetails: {
      builder: {id: "https://ci.example.org/builders/oci-release"},
      metadata: {
        invocationId: "test-invocation",
        startedOn: "2026-08-04T00:00:00Z",
        finishedOn: "2026-08-04T00:01:00Z"
      }
    }
  }' >"${workspace}/runtime.slsa.json"
}

main() {
  trap cleanup EXIT
  trap 'exit 130' HUP INT TERM

  workspace=$(mktemp -d /tmp/openldap-release-test.XXXXXX) \
    || fail 'Cannot create test directory'
  write_cosign_stub || fail 'Cannot create Cosign test double'
  write_publish_stubs || fail 'Cannot create publication test doubles'
  write_release_fixture || fail 'Cannot create release fixture'
  runtime_reference='registry.example.org/openldap@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
  generator_reference='registry.example.org/generator@sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789'

  mkdir "${workspace}/existing-output" || fail 'Cannot create existing output fixture'
  if "${release_script}" "${workspace}/existing-output" \
    "${runtime_reference}" "${generator_reference}" >/dev/null 2>&1; then
    fail 'Release command accepted an existing output path'
  fi

  if TRIVY_SEVERITIES='high,critical' \
    "${release_script}" "${workspace}/severity-output" \
    "${runtime_reference}" "${generator_reference}" >/dev/null 2>&1; then
    fail 'Release command accepted invalid Trivy severity names'
  fi
  if [ -e "${workspace}/severity-output" ]; then
    fail 'Rejected Trivy severity input left an output directory'
  fi

  if TRIVY_IMAGE='registry.example.org/trivy@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
    "${release_script}" "${workspace}/scanner-output" \
    "${runtime_reference}" "${generator_reference}" >/dev/null 2>&1; then
    fail 'Release command accepted an unreviewed Trivy digest'
  fi
  if [ -e "${workspace}/scanner-output" ]; then
    fail 'Rejected Trivy digest left an output directory'
  fi

  ln -s "${workspace}/missing-vex.json" "${workspace}/vex-link.json" \
    || fail 'Cannot create VEX symlink fixture'
  if TRIVY_VEX_FILE="${workspace}/vex-link.json" \
    "${release_script}" "${workspace}/vex-output" \
    "${runtime_reference}" "${generator_reference}" >/dev/null 2>&1; then
    fail 'Release command accepted a symbolic-link VEX input'
  fi
  if [ -e "${workspace}/vex-output" ]; then
    fail 'Rejected VEX input left an output directory'
  fi

  printf '%s\n' 'not-json' >"${workspace}/invalid-vex.json"
  if TRIVY_VEX_FILE="${workspace}/invalid-vex.json" \
    "${release_script}" "${workspace}/invalid-vex-output" \
    "${runtime_reference}" "${generator_reference}" >/dev/null 2>&1; then
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
  grep -F -q -- \
    '--certificate-identity-regexp ^https://github\.com/aquasecurity/trivy/\.github/workflows/reusable-release\.yaml@refs/tags/v0\.72\.0$' \
    "${workspace}/cosign-calls" || fail 'Trivy workflow identity was not pinned'
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
    COSIGN_VERIFY_KEY='test-kms://verification-key' \
    "${sign_script}" \
    'registry.example.org/openldap@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' \
    "${workspace}/runtime.metadata.json" \
    "${workspace}/runtime.slsa.json" >/dev/null \
    || fail 'Valid release evidence was rejected'
  grep -F -q 'sign --yes --key test-kms://release-key registry.example.org/openldap@sha256:' \
    "${workspace}/cosign-calls" || fail 'Image signature command was not issued'
  grep -F -q 'attest --yes --key test-kms://release-key --type spdxjson' \
    "${workspace}/cosign-calls" || fail 'SBOM attestation command was not issued'
  grep -F -q 'attest --yes --key test-kms://release-key --type slsaprovenance' \
    "${workspace}/cosign-calls" || fail 'SLSA provenance attestation was not issued'
  grep -F -q 'verify --key test-kms://verification-key registry.example.org/openldap@sha256:' \
    "${workspace}/cosign-calls" || fail 'Post-signature verification was not issued'
  grep -F -q 'verify-attestation --key test-kms://verification-key --type spdxjson' \
    "${workspace}/cosign-calls" || fail 'SBOM attestation verification was not issued'
  grep -F -q 'verify-attestation --key test-kms://verification-key --type slsaprovenance' \
    "${workspace}/cosign-calls" || fail 'SLSA attestation verification was not issued'

  : >"${workspace}/cosign-calls"
  if COSIGN="${workspace}/cosign" \
    COSIGN_CALLS="${workspace}/cosign-calls" \
    COSIGN_KEY='test-kms://release-key' \
    COSIGN_VERIFY_KEY='test-kms://verification-key' \
    "${sign_script}" registry.example.org/openldap:latest \
    "${workspace}/runtime.metadata.json" \
    "${workspace}/runtime.slsa.json" >/dev/null 2>&1; then
    fail 'Mutable image tag was accepted for signing'
  fi
  if [ -s "${workspace}/cosign-calls" ]; then
    fail 'Cosign was called for a mutable image tag'
  fi

  printf '%s\n' 'tampered' >>"${workspace}/runtime.spdx.json"
  if COSIGN="${workspace}/cosign" \
    COSIGN_CALLS="${workspace}/cosign-calls" \
    COSIGN_KEY='test-kms://release-key' \
    COSIGN_VERIFY_KEY='test-kms://verification-key' \
    "${sign_script}" \
    'registry.example.org/openldap@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' \
    "${workspace}/runtime.metadata.json" \
    "${workspace}/runtime.slsa.json" >/dev/null 2>&1; then
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
    COSIGN_VERIFY_KEY='test-kms://verification-key' \
    "${sign_script}" \
    'registry.example.org/openldap@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' \
    "${workspace}/rejected.metadata.json" \
    "${workspace}/runtime.slsa.json" >/dev/null 2>&1; then
    fail 'Security-rejected metadata was accepted for signing'
  fi

  jq '.release_policy = "rejected"' \
    "${workspace}/runtime.metadata.json" >"${workspace}/release-rejected.metadata.json" \
    || fail 'Cannot create release-rejected metadata fixture'
  if COSIGN="${workspace}/cosign" \
    COSIGN_CALLS="${workspace}/cosign-calls" \
    COSIGN_KEY='test-kms://release-key' \
    COSIGN_VERIFY_KEY='test-kms://verification-key' \
    "${sign_script}" \
    'registry.example.org/openldap@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' \
    "${workspace}/release-rejected.metadata.json" \
    "${workspace}/runtime.slsa.json" >/dev/null 2>&1; then
    fail 'Release-rejected metadata was accepted for signing'
  fi

  printf '%s\n' '{}' >"${workspace}/invalid.slsa.json"
  if COSIGN="${workspace}/cosign" \
    COSIGN_CALLS="${workspace}/cosign-calls" \
    COSIGN_KEY='test-kms://release-key' \
    COSIGN_VERIFY_KEY='test-kms://verification-key' \
    "${sign_script}" \
    'registry.example.org/openldap@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' \
    "${workspace}/runtime.metadata.json" \
    "${workspace}/invalid.slsa.json" >/dev/null 2>&1; then
    fail 'Incomplete SLSA provenance was accepted'
  fi

  if "${publish_script}" \
    quay.io/foundata/openldap-declarative:latest \
    quay.io/foundata/openldap-declarative-generator:1.0.0 >/dev/null 2>&1; then
    fail 'Moving release tag was accepted for initial publication'
  fi

  : >"${workspace}/publish-calls"
  publish_digest='sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
  publication_output=$(PODMAN="${workspace}/podman" \
    SKOPEO="${workspace}/skopeo" \
    PUBLISH_CALLS="${workspace}/publish-calls" \
    PUBLISH_DIGEST="${publish_digest}" \
    "${publish_script}" \
    quay.io/foundata/openldap-declarative:1.0.0 \
    quay.io/foundata/openldap-declarative-generator:1.0.0) \
    || fail 'Immutable version publication was rejected'
  printf '%s\n' "${publication_output}" \
    | grep -F -q "quay.io/foundata/openldap-declarative@${publish_digest}" \
    || fail 'Publisher did not return the runtime registry digest'
  grep -F -q 'copy --preserve-digests oci:' "${workspace}/publish-calls" \
    || fail 'Publisher did not preserve the reviewed manifest digest'

  if PODMAN="${workspace}/podman" \
    SKOPEO="${workspace}/skopeo" \
    PUBLISH_CALLS="${workspace}/publish-calls" \
    PUBLISH_DIGEST="${publish_digest}" \
    PUBLISH_MISMATCH=true \
    "${publish_script}" \
    quay.io/foundata/openldap-declarative:1.0.1 \
    quay.io/foundata/openldap-declarative-generator:1.0.1 >/dev/null 2>&1; then
    fail 'Publisher accepted a changed registry digest'
  fi

  : >"${workspace}/cosign-calls"
  : >"${workspace}/publish-calls"
  COSIGN="${workspace}/cosign" \
    COSIGN_CALLS="${workspace}/cosign-calls" \
    COSIGN_VERIFY_KEY='test-kms://verification-key' \
    SKOPEO="${workspace}/skopeo" \
    PUBLISH_CALLS="${workspace}/publish-calls" \
    PUBLISH_DIGEST="${publish_digest}" \
    "${promote_script}" \
    "quay.io/foundata/openldap@${publish_digest}" \
    quay.io/foundata/openldap:stable \
    || fail 'Verified convenience-tag promotion was rejected'
  grep -F -q "copy --preserve-digests docker://quay.io/foundata/openldap@${publish_digest}" \
    "${workspace}/publish-calls" || fail 'Convenience tag was not copied from the digest'

  if COSIGN="${workspace}/cosign" \
    COSIGN_CALLS="${workspace}/cosign-calls" \
    COSIGN_VERIFY_KEY='test-kms://verification-key' \
    SKOPEO=false \
    "${promote_script}" \
    'quay.io/foundata/openldap@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' \
    quay.io/another/openldap:latest >/dev/null 2>&1; then
    fail 'Cross-repository convenience-tag promotion was accepted'
  fi

  printf '%s\n' 'Release script tests passed'
}

main "$@"
