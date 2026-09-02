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

cleanup_preflight() {
  remove_verified_snapshot "${runtime_dir}" || true
  for output in verified-manifest.json verification-keys; do
    if [ -e "${runtime_dir}/${output}" ] || [ -L "${runtime_dir}/${output}" ]; then
      unlink "${runtime_dir}/${output}" || true
    fi
  done
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
  cleanup_preflight
  trap cleanup_preflight 0
  trap 'exit 70' HUP INT TERM

  "${script_dir}/verify-snapshot.sh" || return $?
  validate_snapshot_revision "${runtime_dir}/verified-manifest.json" "${revision_state_file}" || return $?
  log_info "Preflight accepted snapshot revision ${snapshot_revision} (${revision_disposition}); manifest sha256:${snapshot_manifest_digest}"
  return 0
}

main "$@"
