#!/usr/bin/env sh

# Verify the snapshot, build the directory offline, and supervise slapd.

set -u

script_dir=$(CDPATH='' cd "$(dirname "$0")" && pwd) || exit 70
readonly script_dir
# shellcheck source=scripts/common.sh
. "${script_dir}/common.sh"

readonly runtime_dir="${LDAP_RUNTIME_DIR:-/run/openldap}"
readonly config_dir="${runtime_dir}/slapd.d"
readonly verified_manifest_file="${runtime_dir}/verified-manifest.json"
readonly revision_state_file="${LDAP_REVISION_STATE_FILE:-/state/highest-revision}"
readonly expected_service_id="${LDAP_EXPECTED_SERVICE_ID:-}"

slapd_pid=''
watchdog_pid=''
snapshot_expired=0
shutdown_requested=0

validate_runtime_configuration() {
  validation_errors=0

  case "${LDAP_TRANSPORT:-ldap}" in
    ldap | ldaps | both) ;;
    *)
      log_error 'LDAP_TRANSPORT must be ldap, ldaps, or both'
      validation_errors=$((validation_errors + 1))
      ;;
  esac

  case "${LDAP_LISTEN_HOST:-127.0.0.1}" in
    127.0.0.1 | 0.0.0.0) ;;
    *)
      log_error 'LDAP_LISTEN_HOST must be 127.0.0.1 or 0.0.0.0'
      validation_errors=$((validation_errors + 1))
      ;;
  esac

  for port_value in "${LDAP_PORT:-1389}" "${LDAP_LDAPS_PORT:-1636}"; do
    if ! printf '%s\n' "${port_value}" | grep -E -q '^[0-9]+$' \
      || [ "${port_value}" -lt 1024 ] || [ "${port_value}" -gt 65535 ]; then
      log_error "LDAP listener port is not an unprivileged TCP port: ${port_value}"
      validation_errors=$((validation_errors + 1))
    fi
  done

  if ! printf '%s\n' "${LDAP_LOG_LEVEL:-256}" | grep -E -q '^-?[0-9]+$'; then
    log_error 'LDAP_LOG_LEVEL must be an integer'
    validation_errors=$((validation_errors + 1))
  fi

  if [ -n "${LDAP_ADMIN_PASSWORD_FILE:-}" ] && [ "${LDAP_ADMIN_PASSWORD+x}" = x ]; then
    log_error 'LDAP_ADMIN_PASSWORD_FILE and LDAP_ADMIN_PASSWORD are mutually exclusive'
    validation_errors=$((validation_errors + 1))
  fi

  if [ "${validation_errors}" -ne 0 ]; then
    return "${EXIT_USAGE}"
  fi

  return 0
}

validate_revision() {
  snapshot_revision=$(jq -r '.revision' "${verified_manifest_file}") || return "${EXIT_INTERNAL}"

  if [ -e "${revision_state_file}" ]; then
    if [ ! -f "${revision_state_file}" ] || [ -L "${revision_state_file}" ] || [ ! -r "${revision_state_file}" ]; then
      log_error "Revision state is not a readable regular file: ${revision_state_file}"
      return "${EXIT_INPUT}"
    fi
    highest_revision=$(cat "${revision_state_file}") || return "${EXIT_INTERNAL}"
    if ! printf '%s\n' "${highest_revision}" | grep -E -q '^[0-9]+$'; then
      log_error 'Revision state does not contain a non-negative integer'
      return "${EXIT_INPUT}"
    fi
    if [ "${snapshot_revision}" -lt "${highest_revision}" ]; then
      log_error "Snapshot revision ${snapshot_revision} is older than accepted revision ${highest_revision}"
      return "${EXIT_SNAPSHOT}"
    fi
  fi

  return 0
}

record_revision() {
  snapshot_revision=$(jq -r '.revision' "${verified_manifest_file}") || return "${EXIT_INTERNAL}"
  revision_directory=$(dirname "${revision_state_file}") || return "${EXIT_INTERNAL}"
  mkdir -p "${revision_directory}" || return "${EXIT_INTERNAL}"
  temporary_revision=$(mktemp "${revision_directory}/highest-revision.XXXXXX") || return "${EXIT_INTERNAL}"

  if ! printf '%s\n' "${snapshot_revision}" >"${temporary_revision}"; then
    unlink "${temporary_revision}"
    return "${EXIT_INTERNAL}"
  fi
  chmod 0600 "${temporary_revision}" || {
    unlink "${temporary_revision}"
    return "${EXIT_INTERNAL}"
  }
  mv "${temporary_revision}" "${revision_state_file}" || return "${EXIT_INTERNAL}"

  return 0
}

build_listener_urls() {
  listen_host=${LDAP_LISTEN_HOST:-127.0.0.1}
  listener_urls=${LDAP_LDAPI_URI:-ldapi://%2Frun%2Fopenldap%2Fldapi}

  case "${LDAP_TRANSPORT:-ldap}" in
    ldap)
      listener_urls="ldap://${listen_host}:${LDAP_PORT:-1389}/ ${listener_urls}"
      ;;
    ldaps)
      listener_urls="ldaps://${listen_host}:${LDAP_LDAPS_PORT:-1636}/ ${listener_urls}"
      ;;
    both)
      listener_urls="ldap://${listen_host}:${LDAP_PORT:-1389}/ ldaps://${listen_host}:${LDAP_LDAPS_PORT:-1636}/ ${listener_urls}"
      ;;
    *)
      return "${EXIT_USAGE}"
      ;;
  esac

  printf '%s\n' "${listener_urls}"
}

watch_snapshot_expiry() {
  parent_pid="${1}"
  expires_epoch=$(jq -r '.expires_at | fromdateiso8601' "${verified_manifest_file}") || return "${EXIT_INTERNAL}"

  while :; do
    current_epoch=$(date -u +%s) || return "${EXIT_INTERNAL}"
    remaining_seconds=$((expires_epoch - current_epoch))

    if [ "${remaining_seconds}" -le 0 ]; then
      kill -USR1 "${parent_pid}" 2>/dev/null || true
      return 0
    fi

    sleep_seconds=${remaining_seconds}
    if [ "${sleep_seconds}" -gt 60 ]; then
      sleep_seconds=60
    fi
    sleep "${sleep_seconds}" || return 0
  done
}

forward_shutdown() {
  shutdown_requested=1
  if [ -n "${slapd_pid}" ]; then
    kill -TERM "${slapd_pid}" 2>/dev/null || true
  fi
}

expire_snapshot() {
  snapshot_expired=1
  log_error 'The active directory snapshot has expired; stopping slapd'
  if [ -n "${slapd_pid}" ]; then
    kill -TERM "${slapd_pid}" 2>/dev/null || true
  fi
}

stop_watchdog() {
  if [ -n "${watchdog_pid}" ]; then
    kill "${watchdog_pid}" 2>/dev/null || true
    wait "${watchdog_pid}" 2>/dev/null || true
  fi
}

supervise_slapd() {
  listener_urls=$(build_listener_urls) || return "${EXIT_INTERNAL}"
  trap forward_shutdown TERM INT HUP
  trap expire_snapshot USR1

  log_info "Starting slapd for service ${expected_service_id}"
  /usr/sbin/slapd \
    -F "${config_dir}" \
    -h "${listener_urls}" \
    -d "${LDAP_LOG_LEVEL:-256}" &
  slapd_pid=$!

  watch_snapshot_expiry "$$" &
  watchdog_pid=$!

  wait "${slapd_pid}"
  slapd_status=$?
  if kill -0 "${slapd_pid}" 2>/dev/null; then
    wait "${slapd_pid}"
    slapd_status=$?
  fi
  stop_watchdog

  if [ "${snapshot_expired}" -eq 1 ]; then
    return "${EXIT_EXPIRED}"
  fi
  if [ "${shutdown_requested}" -eq 1 ]; then
    return 0
  fi
  if [ "${slapd_status}" -ne 0 ]; then
    log_error "slapd exited unexpectedly with status ${slapd_status}"
    return "${EXIT_RUNTIME}"
  fi

  return 0
}

main() {
  umask 077
  mkdir -p "${runtime_dir}" || die "${EXIT_INTERNAL}" 'Cannot create the runtime directory'
  validate_runtime_configuration || exit $?
  "${script_dir}/verify-snapshot.sh" || exit $?
  validate_revision || exit $?
  "${script_dir}/init-slapd.sh" || exit $?
  record_revision || die "${EXIT_INTERNAL}" 'Cannot record the accepted snapshot revision'
  cp "${verified_manifest_file}" "${runtime_dir}/active-manifest.json" || die "${EXIT_INTERNAL}" 'Cannot record active snapshot metadata'
  supervise_slapd || exit $?
}

main "$@"
