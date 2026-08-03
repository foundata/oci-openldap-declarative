#!/usr/bin/env sh

# Build the runtime and snapshot-generator images with Podman.

set -u

project_dir=$(CDPATH='' cd "$(dirname "$0")/.." && pwd) || exit 1
readonly project_dir
readonly runtime_image="${RUNTIME_IMAGE:-localhost/openldap-declarative:latest}"
readonly generator_image="${GENERATOR_IMAGE:-localhost/openldap-declarative-generator:latest}"
readonly image_version="${IMAGE_VERSION:-development}"
readonly podman_binary="${PODMAN:-podman}"

image_created=''
image_revision=''
source_tree_state='unknown'

collect_source_metadata() {
  image_created=${IMAGE_CREATED:-}
  if [ -z "${image_created}" ]; then
    source_date_epoch=${SOURCE_DATE_EPOCH:-}
    if [ -z "${source_date_epoch}" ]; then
      source_date_epoch=$(git -C "${project_dir}" show -s --format=%ct HEAD 2>/dev/null) \
        || source_date_epoch=''
    fi
    if [ -n "${source_date_epoch}" ]; then
      if ! printf '%s\n' "${source_date_epoch}" | grep -E -q '^[0-9]+$'; then
        printf 'ERROR: SOURCE_DATE_EPOCH must be a non-negative integer\n' >&2
        return 64
      fi
      image_created=$(date -u -d "@${source_date_epoch}" '+%Y-%m-%dT%H:%M:%SZ') || return 1
    else
      image_created=$(date -u '+%Y-%m-%dT%H:%M:%SZ') || return 1
    fi
  fi

  image_revision=${IMAGE_REVISION:-}
  if [ -z "${image_revision}" ]; then
    image_revision=$(git -C "${project_dir}" rev-parse HEAD 2>/dev/null) \
      || image_revision=unknown
  fi

  untracked_build_inputs=$(git -C "${project_dir}" ls-files \
    --others --exclude-standard -- \
    .containerignore Containerfile Containerfile.generator LICENSES generator scripts) \
    || return 1
  if git -C "${project_dir}" diff --quiet --ignore-submodules -- \
    && git -C "${project_dir}" diff --cached --quiet --ignore-submodules -- \
    && [ -z "${untracked_build_inputs}" ]; then
    source_tree_state=clean
  else
    source_tree_state=dirty
  fi
}

build_image() {
  image_reference=${1}
  containerfile=${2}

  "${podman_binary}" build \
    --build-arg "OCI_IMAGE_CREATED=${image_created}" \
    --build-arg "OCI_IMAGE_REVISION=${image_revision}" \
    --build-arg "OCI_IMAGE_VERSION=${image_version}" \
    --build-arg "SOURCE_TREE_STATE=${source_tree_state}" \
    --file "${containerfile}" \
    --tag "${image_reference}" \
    "${project_dir}"
}

main() {
  collect_source_metadata || return 1

  printf 'Building %s\n' "${runtime_image}"
  build_image "${runtime_image}" "${project_dir}/Containerfile" || return 1

  printf 'Building %s\n' "${generator_image}"
  build_image "${generator_image}" "${project_dir}/Containerfile.generator" || return 1
}

main "$@"
