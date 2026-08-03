#!/usr/bin/env sh

# Build the runtime and snapshot-generator images with Podman.

set -u

project_dir=$(CDPATH='' cd "$(dirname "$0")/.." && pwd) || exit 1
readonly project_dir
readonly runtime_image="${RUNTIME_IMAGE:-localhost/openldap-declarative:latest}"
readonly generator_image="${GENERATOR_IMAGE:-localhost/openldap-declarative-generator:latest}"

main() {
  printf 'Building %s\n' "${runtime_image}"
  podman build --tag "${runtime_image}" "${project_dir}" || return 1

  printf 'Building %s\n' "${generator_image}"
  podman build --tag "${generator_image}" \
    --file "${project_dir}/Containerfile.generator" "${project_dir}" || return 1
}

main "$@"
