#!/usr/bin/env sh

# Shared constants and logging for the container runtime scripts.

set -u

# shellcheck disable=SC2034  # These constants are consumed by sourcing scripts.
readonly EXIT_USAGE=64
# shellcheck disable=SC2034
readonly EXIT_SNAPSHOT=65
# shellcheck disable=SC2034
readonly EXIT_INPUT=66
# shellcheck disable=SC2034
readonly EXIT_INTERNAL=70
# shellcheck disable=SC2034
readonly EXIT_RUNTIME=75
# shellcheck disable=SC2034
readonly EXIT_EXPIRED=78

log_info() {
  printf '%s: %s\n' 'INFO' "$*"
}

log_warning() {
  printf '%s: %s\n' 'WARNING' "$*" >&2
}

log_error() {
  printf '%s: %s\n' 'ERROR' "$*" >&2
}

die() {
  exit_code="${1}"
  shift

  log_error "$*"
  exit "${exit_code}"
}

ldap_is_available() {
  # A successful base-scope lookup proves DN equivalence, regardless of LDIF spelling.
  ldap_base_result=$(ldapsearch -LLL -Q -Y EXTERNAL \
    -H "${LDAP_LDAPI_URI:-ldapi://%2Frun%2Fopenldap%2Fldapi}" \
    -b "${1}" -s base '(objectClass=*)' dn 2>/dev/null) || return 1
  printf '%s\n' "${ldap_base_result}" | grep -E -q '^dn::? '
}

remove_verified_snapshot() {
  cleanup_runtime_dir=${1}
  cleanup_snapshot_dir=${cleanup_runtime_dir}/verified-snapshot
  cleanup_files_file=${cleanup_runtime_dir}/verified-files

  if [ -L "${cleanup_snapshot_dir}" ] || [ -f "${cleanup_snapshot_dir}" ]; then
    unlink "${cleanup_snapshot_dir}" || return "${EXIT_INTERNAL}"
  elif [ -d "${cleanup_snapshot_dir}" ]; then
    find "${cleanup_snapshot_dir}" -mindepth 1 -delete || return "${EXIT_INTERNAL}"
    rmdir "${cleanup_snapshot_dir}" || return "${EXIT_INTERNAL}"
  fi

  if [ -e "${cleanup_files_file}" ] || [ -L "${cleanup_files_file}" ]; then
    unlink "${cleanup_files_file}" || return "${EXIT_INTERNAL}"
  fi

  return 0
}
