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
custom_workspace=0

cleanup_preflight() {
  if [ "${custom_workspace}" -eq 1 ]; then
    # This directory was empty except for this invocation's verification workspace.
    find "${runtime_dir}" -mindepth 1 -delete || return "${EXIT_INTERNAL}"
    return 0
  fi
  if [ -n "${preflight_workspace}" ] && [ -d "${preflight_workspace}" ]; then
    find "${preflight_workspace}" -mindepth 1 -delete || return "${EXIT_INTERNAL}"
    rmdir "${preflight_workspace}" || return "${EXIT_INTERNAL}"
  fi
}

prepare_custom_workspace() {
  if [ "${runtime_dir}" != /run/openldap ]; then
    log_error 'Custom LDIF preflight requires a fresh container with /run/openldap scratch storage'
    return "${EXIT_USAGE}"
  fi
  existing_input=$(find "${runtime_dir}" -mindepth 1 -maxdepth 1 ! -path "${preflight_workspace}" -print -quit) || return "${EXIT_INTERNAL}"
  if [ -n "${existing_input}" ]; then
    log_error 'Custom LDIF preflight requires an unused runtime directory; run it in a separate container'
    return "${EXIT_USAGE}"
  fi
  custom_workspace=1
  for verified_input in verified-manifest.json verified-files verified-snapshot; do
    mv "${preflight_workspace}/${verified_input}" "${runtime_dir}/${verified_input}" || return "${EXIT_INTERNAL}"
  done
  LDAP_RUNTIME_DIR=${runtime_dir}
  export LDAP_RUNTIME_DIR
  return 0
}

main() {
  if [ "$#" -ne 4 ]; then
    log_error 'Usage: preflight-snapshot.sh SNAPSHOT KEY DIRECTORY_ID REVISION_STATE'
    return "${EXIT_USAGE}"
  fi

  LDAP_SNAPSHOT_DIR=${1}
  verification_key=${2}
  LDAP_EXPECTED_DIRECTORY_ID=${3}
  revision_state_file=${4}
  LDAP_SNAPSHOT_PUBLIC_KEY_FILE=''
  LDAP_SNAPSHOT_PUBLIC_KEY_DIR=''
  if [ -d "${verification_key}" ] && [ ! -L "${verification_key}" ]; then
    LDAP_SNAPSHOT_PUBLIC_KEY_DIR=${verification_key}
  else
    LDAP_SNAPSHOT_PUBLIC_KEY_FILE=${verification_key}
  fi
  export LDAP_EXPECTED_DIRECTORY_ID LDAP_SNAPSHOT_DIR LDAP_SNAPSHOT_PUBLIC_KEY_DIR
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
  input_type=$(jq -r '.input_type' "${preflight_workspace}/verified-manifest.json") || return "${EXIT_INTERNAL}"
  if [ "${input_type}" = ldif ]; then
    prepare_custom_workspace || return $?
  fi
  "${script_dir}/init-slapd.sh" || return $?
  check_snapshot_expiry "${LDAP_RUNTIME_DIR}/verified-manifest.json" || return $?
  log_info "Preflight accepted snapshot revision ${snapshot_revision} (${revision_disposition}); manifest sha256:${snapshot_manifest_digest}"
  return 0
}

main "$@"
