#!/usr/bin/env sh

# Check slapd, snapshot freshness, revision, and the expected base entry.

set -u

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd) || exit 1
# shellcheck source=scripts/common.sh
. "${script_dir}/common.sh"

readonly runtime_dir="${LDAP_RUNTIME_DIR:-/run/openldap}"
readonly active_manifest_file="${runtime_dir}/active-manifest.json"

main() {
  if [ ! -f "${active_manifest_file}" ]; then
    printf '%s\n' 'Active snapshot metadata is missing' >&2
    return 1
  fi

  current_epoch=$(date -u +%s) || return 1
  soft_expires_epoch=$(jq -r '.soft_expires_at | fromdateiso8601' "${active_manifest_file}") || return 1
  expires_epoch=$(jq -r '.expires_at | fromdateiso8601' "${active_manifest_file}") || return 1
  base_dn=$(jq -r '.base_dn' "${active_manifest_file}") || return 1
  revision=$(jq -r '.revision' "${active_manifest_file}") || return 1

  if [ "${current_epoch}" -ge "${expires_epoch}" ]; then
    printf 'Snapshot revision %s has expired\n' "${revision}" >&2
    return 1
  fi

  if ! ldap_is_available "${base_dn}"; then
    printf 'Expected base DN is not readable for snapshot revision %s\n' "${revision}" >&2
    return 1
  fi

  if [ "${current_epoch}" -ge "${soft_expires_epoch}" ]; then
    printf 'Snapshot revision %s is past its soft deadline\n' "${revision}" >&2
  else
    printf 'Snapshot revision %s is healthy\n' "${revision}"
  fi

  return 0
}

main "$@"
