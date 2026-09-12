#!/usr/bin/env sh

# Verify the snapshot, build the directory offline, and supervise slapd.

set -u

script_dir=$(CDPATH='' cd "$(dirname "$0")" && pwd) || exit 70
readonly script_dir
# shellcheck source=scripts/common.sh
. "${script_dir}/common.sh"
# shellcheck source=scripts/revision-state.sh
. "${script_dir}/revision-state.sh"

readonly runtime_dir="${LDAP_RUNTIME_DIR:-/run/openldap}"
readonly config_dir="${runtime_dir}/slapd.d"
readonly verified_manifest_file="${runtime_dir}/verified-manifest.json"
readonly revision_state_file="${LDAP_REVISION_STATE_FILE:-/state/highest-revision}"
readonly expected_directory_id="${LDAP_EXPECTED_DIRECTORY_ID:-}"

slapd_pid=''
watchdog_pid=''
startup_phase_pid=''
snapshot_expired=0
shutdown_requested=0
watchdog_failed=0

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

  if [ "${LDAP_TRANSPORT:-ldap}" = both ] \
    && [ "${LDAP_PORT:-1389}" = "${LDAP_LDAPS_PORT:-1636}" ]; then
    log_error 'LDAP_PORT and LDAP_LDAPS_PORT must differ when LDAP_TRANSPORT is both'
    validation_errors=$((validation_errors + 1))
  fi

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
  if [ -n "${startup_phase_pid}" ]; then
    kill -TERM "${startup_phase_pid}" 2>/dev/null || true
  fi
  if [ -n "${slapd_pid}" ]; then
    kill -TERM "${slapd_pid}" 2>/dev/null || true
  fi
}

run_startup_phase() {
  "$@" &
  startup_phase_pid=$!
  wait "${startup_phase_pid}"
  startup_phase_status=$?
  # A trapped shutdown signal interrupts wait; keep waiting so the phase can
  # finish its own cleanup before this process exits.
  while kill -0 "${startup_phase_pid}" 2>/dev/null; do
    wait "${startup_phase_pid}"
    startup_phase_status=$?
  done
  startup_phase_pid=''
  return "${startup_phase_status}"
}

expire_snapshot() {
  snapshot_expired=1
  log_error 'The active directory snapshot has expired; stopping slapd'
  if [ -n "${slapd_pid}" ]; then
    kill -TERM "${slapd_pid}" 2>/dev/null || true
  fi
}

fail_watchdog() {
  watchdog_failed=1
  log_error 'The snapshot expiry watchdog failed; stopping slapd'
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

process_is_running() {
  process_pid=${1}

  if ! kill -0 "${process_pid}" 2>/dev/null; then
    return 1
  fi
  process_state=$(awk '/^State:/ { print $2 }' "/proc/${process_pid}/status" 2>/dev/null) || return 1
  [ "${process_state}" != Z ] && [ "${process_state}" != X ]
}

supervise_slapd() {
  listener_urls=$(build_listener_urls) || return "${EXIT_INTERNAL}"
  trap forward_shutdown TERM INT HUP
  trap expire_snapshot USR1
  trap fail_watchdog USR2

  log_info "Starting slapd for directory ${expected_directory_id}"
  /usr/sbin/slapd \
    -F "${config_dir}" \
    -h "${listener_urls}" \
    -d "${LDAP_LOG_LEVEL:-256}" &
  slapd_pid=$!

  if [ "${shutdown_requested}" -eq 1 ]; then
    kill -TERM "${slapd_pid}" 2>/dev/null || true
    wait "${slapd_pid}" 2>/dev/null || true
    return 0
  fi

  (
    watch_snapshot_expiry "$$"
    watchdog_status=$?
    if [ "${watchdog_status}" -ne 0 ]; then
      kill -USR2 "$$" 2>/dev/null || true
    fi
  ) &
  watchdog_pid=$!
  if ! printf '%s\n' "${watchdog_pid}" >"${runtime_dir}/watchdog.pid"; then
    kill "${watchdog_pid}" "${slapd_pid}" 2>/dev/null || true
    wait "${slapd_pid}" 2>/dev/null || true
    return "${EXIT_INTERNAL}"
  fi

  while process_is_running "${slapd_pid}"; do
    if ! process_is_running "${watchdog_pid}" \
      && [ "${snapshot_expired}" -eq 0 ] \
      && [ "${shutdown_requested}" -eq 0 ]; then
      fail_watchdog
    fi
    sleep 1 || true
  done

  wait "${slapd_pid}"
  slapd_status=$?
  stop_watchdog

  if [ "${snapshot_expired}" -eq 1 ]; then
    return "${EXIT_EXPIRED}"
  fi
  if [ "${watchdog_failed}" -eq 1 ]; then
    return "${EXIT_RUNTIME}"
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
  trap forward_shutdown TERM INT HUP
  python3 "${script_dir}/runtime_limits.py" "$$" || return $?
  mkdir -p "${runtime_dir}" || die "${EXIT_INTERNAL}" 'Cannot create the runtime directory'
  remove_verified_snapshot "${runtime_dir}" || die "${EXIT_INTERNAL}" 'Cannot remove stale verified snapshot data'
  validate_runtime_configuration || exit $?
  log_info "Starting snapshot initialization for directory ${expected_directory_id}"
  run_startup_phase "${script_dir}/verify-snapshot.sh"
  verification_status=$?
  if [ "${shutdown_requested}" -eq 1 ]; then
    remove_verified_snapshot "${runtime_dir}" || true
    return 0
  fi
  if [ "${verification_status}" -ne 0 ]; then
    remove_verified_snapshot "${runtime_dir}" || true
    return "${verification_status}"
  fi
  validate_snapshot_revision "${verified_manifest_file}" "${revision_state_file}"
  revision_status=$?
  if [ "${revision_status}" -ne 0 ]; then
    remove_verified_snapshot "${runtime_dir}" || true
    return "${revision_status}"
  fi
  run_startup_phase "${script_dir}/init-slapd.sh"
  initialization_status=$?
  if [ "${shutdown_requested}" -eq 1 ]; then
    remove_verified_snapshot "${runtime_dir}" || true
    return 0
  fi
  if [ "${initialization_status}" -ne 0 ]; then
    remove_verified_snapshot "${runtime_dir}" || true
    return "${initialization_status}"
  fi
  remove_verified_snapshot "${runtime_dir}" || die "${EXIT_INTERNAL}" 'Cannot remove verified snapshot data'
  check_snapshot_expiry "${verified_manifest_file}" || return $?
  record_snapshot_revision "${verified_manifest_file}" "${revision_state_file}" \
    || die "${EXIT_INTERNAL}" 'Cannot record the accepted snapshot revision'
  cp "${verified_manifest_file}" "${runtime_dir}/active-manifest.json" || die "${EXIT_INTERNAL}" 'Cannot record active snapshot metadata'
  supervise_slapd
  supervision_status=$?
  remove_verified_snapshot "${runtime_dir}" || true
  return "${supervision_status}"
}

main "$@"
