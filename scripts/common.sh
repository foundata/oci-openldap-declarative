#!/usr/bin/env sh

# Shared validation, probes and logging for the container runtime scripts.

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

validate_search_limits() {
  for limit_name in LDAP_SEARCH_SIZE_LIMIT LDAP_SEARCH_TIME_LIMIT; do
    case "${limit_name}" in
      LDAP_SEARCH_SIZE_LIMIT) limit_value=${LDAP_SEARCH_SIZE_LIMIT-500} ;;
      LDAP_SEARCH_TIME_LIMIT) limit_value=${LDAP_SEARCH_TIME_LIMIT-10} ;;
      *) return "${EXIT_INTERNAL}" ;;
    esac
    case "${limit_value}" in
      unlimited) continue ;;
      '' | 0* | *[!0-9]*) ;;
      *)
        if [ "${#limit_value}" -le 10 ] && [ "${limit_value}" -le 2147483647 ]; then
          continue
        fi
        ;;
    esac
    log_error "${limit_name} must be an integer from 1 through 2147483647 or unlimited"
    return "${EXIT_USAGE}"
  done
  return 0
}

ldap_is_available() {
  # A successful base-scope lookup proves DN equivalence, regardless of LDIF spelling.
  ldap_base_result=$(ldapsearch -LLL -Q -Y EXTERNAL \
    -H "${LDAP_LDAPI_URI:-ldapi://%2Frun%2Fopenldap%2Fldapi}" \
    -b "${1}" -s base '(objectClass=*)' dn 2>/dev/null) || return 1
  printf '%s\n' "${ldap_base_result}" | grep -E -q '^dn::? '
}

check_snapshot_expiry() {
  deadline_epoch=$(jq -er '.expires_at | fromdateiso8601' "${1}") || return "${EXIT_INTERNAL}"
  deadline_now=$(date -u +%s) || return "${EXIT_INTERNAL}"
  if [ "${deadline_now}" -ge "${deadline_epoch}" ]; then
    log_error 'Snapshot has expired'
    return "${EXIT_EXPIRED}"
  fi
  return 0
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
