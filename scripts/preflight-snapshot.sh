#!/usr/bin/env sh

# Validate a staged snapshot against existing revision state without listening.

set -u

script_dir=$(CDPATH='' cd "$(dirname "$0")" && pwd) || exit 70
readonly script_dir
# shellcheck source=scripts/common.sh
. "${script_dir}/common.sh"
# shellcheck source=scripts/revision-state.sh
. "${script_dir}/revision-state.sh"

readonly runtime_dir="${LDAP_RUNTIME_DIR:-/run/openldap}"
preflight_workspace=''
preflight_status=0

cleanup_preflight() {
  if [ -n "${preflight_workspace}" ] && [ -d "${preflight_workspace}" ]; then
    find "${preflight_workspace}" -mindepth 1 -delete || return "${EXIT_INTERNAL}"
    rmdir "${preflight_workspace}" || return "${EXIT_INTERNAL}"
  fi
}

main() {
  if [ "$#" -ne 4 ]; then
    log_error 'Usage: preflight-snapshot.sh SNAPSHOT KEY SERVICE_ID REVISION_STATE'
    return "${EXIT_USAGE}"
  fi

  LDAP_SNAPSHOT_DIR=${1}
  verification_key=${2}
  LDAP_EXPECTED_SERVICE_ID=${3}
  revision_state_file=${4}
  LDAP_SNAPSHOT_PUBLIC_KEY_FILE=''
  LDAP_SNAPSHOT_PUBLIC_KEY_DIR=''
  if [ -d "${verification_key}" ] && [ ! -L "${verification_key}" ]; then
    LDAP_SNAPSHOT_PUBLIC_KEY_DIR=${verification_key}
  else
    LDAP_SNAPSHOT_PUBLIC_KEY_FILE=${verification_key}
  fi
  export LDAP_EXPECTED_SERVICE_ID LDAP_SNAPSHOT_DIR LDAP_SNAPSHOT_PUBLIC_KEY_DIR
  export LDAP_SNAPSHOT_PUBLIC_KEY_FILE

  umask 077
  mkdir -p "${runtime_dir}" || return "${EXIT_INTERNAL}"
  preflight_workspace=$(mktemp -d "${runtime_dir}/preflight.XXXXXX") || return "${EXIT_INTERNAL}"
  trap 'preflight_status=$?; cleanup_preflight || exit 70; exit "${preflight_status}"' 0
  trap 'exit 70' HUP INT TERM
  LDAP_RUNTIME_DIR=${preflight_workspace}
  export LDAP_RUNTIME_DIR

  "${script_dir}/verify-snapshot.sh" || return $?
  validate_snapshot_revision "${preflight_workspace}/verified-manifest.json" "${revision_state_file}" || return $?
  "${script_dir}/init-slapd.sh" || return $?
  expires_epoch=$(jq -r '.expires_at | fromdateiso8601' "${preflight_workspace}/verified-manifest.json") || return "${EXIT_INTERNAL}"
  current_epoch=$(date -u +%s) || return "${EXIT_INTERNAL}"
  if [ "${current_epoch}" -ge "${expires_epoch}" ]; then
    log_error 'Snapshot expired during offline preflight'
    return "${EXIT_EXPIRED}"
  fi
  log_info "Preflight accepted snapshot revision ${snapshot_revision} (${revision_disposition}); manifest sha256:${snapshot_manifest_digest}"
  return 0
}

main "$@"
