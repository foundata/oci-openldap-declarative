#!/usr/bin/env sh

# Validate and record the accepted snapshot revision and manifest digest.

set -u

# shellcheck disable=SC2034,SC2154  # Sourced constants and result variables are shared with callers.

validate_snapshot_revision() {
  revision_manifest_file=${1}
  revision_state_path=${2}

  snapshot_revision=$(jq -r '.revision' "${revision_manifest_file}") || return "${EXIT_INTERNAL}"
  snapshot_manifest_digest=$(sha256sum "${revision_manifest_file}" | cut -d ' ' -f 1) || return "${EXIT_INTERNAL}"
  revision_disposition=new

  if [ ! -e "${revision_state_path}" ] && [ ! -L "${revision_state_path}" ]; then
    return 0
  fi
  if [ ! -f "${revision_state_path}" ] || [ -L "${revision_state_path}" ] || [ ! -r "${revision_state_path}" ]; then
    log_error "Revision state is not a readable regular file: ${revision_state_path}"
    return "${EXIT_INPUT}"
  fi

  # Bound the entire record before shell arithmetic; retain revision-only legacy state.
  state_size=$(wc -c <"${revision_state_path}") || return "${EXIT_INPUT}"
  if [ "${state_size}" -gt 82 ] || ! jq -eRs '
    test("\\A[1-9][0-9]{0,15}( [0-9a-f]{64})?\\n?\\z")
    and ((split(" ")[0] | tonumber) <= 9007199254740991)
  ' "${revision_state_path}" >/dev/null 2>&1; then
    log_error 'Revision state must contain one revision in 1..9007199254740991 and an optional SHA-256 digest'
    return "${EXIT_INPUT}"
  fi
  highest_revision=''
  highest_manifest_digest=''
  # read returns nonzero for a valid final line without a newline.
  IFS=' ' read -r highest_revision highest_manifest_digest <"${revision_state_path}" || true
  if [ "${snapshot_revision}" -lt "${highest_revision}" ]; then
    log_error "Snapshot revision ${snapshot_revision} is older than accepted revision ${highest_revision}"
    return "${EXIT_SNAPSHOT}"
  fi
  if [ "${snapshot_revision}" -eq "${highest_revision}" ] \
    && [ -n "${highest_manifest_digest}" ] \
    && [ "${snapshot_manifest_digest}" != "${highest_manifest_digest}" ]; then
    log_error "Snapshot revision ${snapshot_revision} was already accepted with different content"
    return "${EXIT_SNAPSHOT}"
  fi

  if [ "${snapshot_revision}" -eq "${highest_revision}" ]; then
    if [ -n "${highest_manifest_digest}" ]; then
      revision_disposition=exact-replay
    else
      revision_disposition=legacy-state-migration
    fi
  fi
  return 0
}

record_snapshot_revision() {
  revision_manifest_file=${1}
  revision_state_path=${2}

  snapshot_revision=$(jq -r '.revision' "${revision_manifest_file}") || return "${EXIT_INTERNAL}"
  snapshot_manifest_digest=$(sha256sum "${revision_manifest_file}" | cut -d ' ' -f 1) || return "${EXIT_INTERNAL}"
  revision_directory=$(dirname "${revision_state_path}") || return "${EXIT_INTERNAL}"
  mkdir -p "${revision_directory}" || return "${EXIT_INTERNAL}"
  temporary_revision=$(mktemp "${revision_directory}/highest-revision.XXXXXX") || return "${EXIT_INTERNAL}"

  if ! printf '%s %s\n' "${snapshot_revision}" "${snapshot_manifest_digest}" >"${temporary_revision}"; then
    unlink "${temporary_revision}"
    return "${EXIT_INTERNAL}"
  fi
  chmod 0600 "${temporary_revision}" || {
    unlink "${temporary_revision}"
    return "${EXIT_INTERNAL}"
  }
  mv "${temporary_revision}" "${revision_state_path}" || return "${EXIT_INTERNAL}"

  return 0
}
