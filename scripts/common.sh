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

validate_password_hashes() {
  # PHC base64 is unpadded: check decoded lengths and zero unused trailing bits.
  # Keep these bounds aligned with generator.validate_password_hash.
  LC_ALL=C awk '
    function valid_base64(value, minimum, size, remainder, last) {
      size = length(value)
      remainder = size % 4
      last = substr(value, size, 1)
      return value ~ /^[A-Za-z0-9+\/]+$/ && int(size * 3 / 4) >= minimum \
        && remainder != 1 \
        && (remainder != 2 || last ~ /^[AQgw]$/) \
        && (remainder != 3 || last ~ /^[AEIMQUYcgkosw048]$/)
    }
    {
      if (length($0) > 4096 || split($0, fields, "\\$") != 6 \
          || fields[1] != "{ARGON2}" || fields[2] != "argon2id" \
          || fields[3] != "v=19" \
          || fields[4] !~ /^m=[1-9][0-9]*,t=[1-9][0-9]*,p=[1-9][0-9]*$/) exit 1
      split(fields[4], costs, ",")
      memory = substr(costs[1], 3) + 0
      iterations = substr(costs[2], 3) + 0
      parallelism = substr(costs[3], 3) + 0
      if (memory < 19456 || memory > 4294967295 \
          || iterations < 2 || iterations > 4294967295 \
          || parallelism < 1 || parallelism > 16777215 \
          || memory < 8 * parallelism \
          || !valid_base64(fields[5], 16) || !valid_base64(fields[6], 32)) exit 1
    }
  ' "${1}"
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
