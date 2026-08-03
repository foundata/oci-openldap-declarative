#!/usr/bin/env sh

# Publish local release images without changing their reviewed OCI digests.

set -u

readonly runtime_image="${RUNTIME_IMAGE:-localhost/openldap-declarative:latest}"
readonly generator_image="${GENERATOR_IMAGE:-localhost/openldap-declarative-generator:latest}"
readonly podman_binary="${PODMAN:-podman}"
readonly skopeo_binary="${SKOPEO:-skopeo}"

workspace=''

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  return 1
}

cleanup() {
  if [ -n "${workspace}" ] && [ -d "${workspace}" ]; then
    rm -rf "${workspace}"
  fi
}

validate_destination() {
  destination=${1}

  if ! printf '%s\n' "${destination}" \
    | grep -E -q '^quay\.io/[a-z0-9._-]+/[a-z0-9._/-]+:v?[0-9]+\.[0-9]+\.[0-9]+([._+-][a-zA-Z0-9.-]+)?$'; then
    fail "Destination must be an immutable version tag below quay.io: ${destination}"
    return 64
  fi
}

publish_image() {
  image_slug=${1}
  local_image=${2}
  destination=${3}
  layout_path="${workspace}/${image_slug}.oci"

  if ! "${podman_binary}" image exists "${local_image}"; then
    fail "Local release image does not exist: ${local_image}"
    return 66
  fi
  "${podman_binary}" save --format oci-dir \
    --output "${layout_path}" "${local_image}" || return 1
  local_digest=$("${skopeo_binary}" inspect --format '{{.Digest}}' \
    "oci:${layout_path}") || return 1

  printf 'Publishing %s as %s\n' "${local_image}" "${destination}" >&2
  "${skopeo_binary}" copy --preserve-digests \
    "oci:${layout_path}" "docker://${destination}" || return 1
  registry_digest=$("${skopeo_binary}" inspect --format '{{.Digest}}' \
    "docker://${destination}") || return 1
  if [ "${registry_digest}" != "${local_digest}" ]; then
    fail "Registry digest differs from the reviewed build output: ${destination}"
    return 65
  fi

  printf '%s@%s\n' "${destination%:*}" "${registry_digest}"
}

main() {
  if [ "$#" -ne 2 ] || [ -z "${1}" ] || [ -z "${2}" ]; then
    printf 'Usage: %s RUNTIME_VERSION_TAG GENERATOR_VERSION_TAG\n' "${0##*/}" >&2
    return 64
  fi
  runtime_destination=${1}
  generator_destination=${2}

  validate_destination "${runtime_destination}" || return $?
  validate_destination "${generator_destination}" || return $?
  for required_command in "${podman_binary}" "${skopeo_binary}" grep mktemp; do
    if ! command -v "${required_command}" >/dev/null 2>&1; then
      fail "Required command is unavailable: ${required_command}"
      return 69
    fi
  done

  umask 077
  trap cleanup EXIT
  trap 'exit 130' HUP INT TERM
  workspace=$(mktemp -d /tmp/openldap-release-publish.XXXXXX) || return 1

  publish_image runtime "${runtime_image}" "${runtime_destination}" || return $?
  publish_image generator "${generator_image}" "${generator_destination}" || return $?
}

main "$@"
