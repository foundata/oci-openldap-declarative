#!/usr/bin/env sh

# Verify a signed directory snapshot without interpreting unsigned input.

set -u

script_dir=$(CDPATH='' cd "$(dirname "$0")" && pwd) || exit 70
readonly script_dir
# shellcheck source=scripts/common.sh
. "${script_dir}/common.sh"

readonly SNAPSHOT_DIR="${LDAP_SNAPSHOT_DIR:-/snapshot}"
readonly MANIFEST_FILE="${SNAPSHOT_DIR}/manifest.json"
readonly SIGNATURE_FILE="${SNAPSHOT_DIR}/manifest.json.minisig"
readonly PUBLIC_KEY_FILE="${LDAP_SNAPSHOT_PUBLIC_KEY_FILE:-}"
readonly PUBLIC_KEY_DIR="${LDAP_SNAPSHOT_PUBLIC_KEY_DIR:-}"
readonly DEFAULT_PUBLIC_KEY_FILE=/run/credentials/snapshot-public-key
readonly VERIFIED_MANIFEST_FILE="${LDAP_RUNTIME_DIR:-/run/openldap}/verified-manifest.json"
readonly VERIFIED_FILES_FILE="${LDAP_RUNTIME_DIR:-/run/openldap}/verified-files"
readonly VERIFIED_SNAPSHOT_DIR="${LDAP_RUNTIME_DIR:-/run/openldap}/verified-snapshot"
readonly VERIFICATION_KEYS_FILE="${LDAP_RUNTIME_DIR:-/run/openldap}/verification-keys"

validate_input_files() {
  validation_errors=0

  if [ -z "${LDAP_EXPECTED_SERVICE_ID:-}" ]; then
    log_error 'LDAP_EXPECTED_SERVICE_ID is required'
    validation_errors=$((validation_errors + 1))
  fi

  for required_file in "${MANIFEST_FILE}" "${SIGNATURE_FILE}"; do
    if [ ! -f "${required_file}" ]; then
      log_error "Required input is not a regular file: ${required_file}"
      validation_errors=$((validation_errors + 1))
    elif [ -L "${required_file}" ]; then
      log_error "Symbolic links are not accepted as trust inputs: ${required_file}"
      validation_errors=$((validation_errors + 1))
    elif [ ! -r "${required_file}" ]; then
      log_error "Required input is not readable: ${required_file}"
      validation_errors=$((validation_errors + 1))
    fi
  done

  if [ "${validation_errors}" -ne 0 ]; then
    return "${EXIT_INPUT}"
  fi

  return 0
}

prepare_verification_keys() {
  if [ -n "${PUBLIC_KEY_FILE}" ] && [ -n "${PUBLIC_KEY_DIR}" ]; then
    log_error 'LDAP_SNAPSHOT_PUBLIC_KEY_FILE and LDAP_SNAPSHOT_PUBLIC_KEY_DIR are mutually exclusive'
    return "${EXIT_USAGE}"
  fi

  : >"${VERIFICATION_KEYS_FILE}" || return "${EXIT_INTERNAL}"
  if [ -n "${PUBLIC_KEY_DIR}" ]; then
    if [ ! -d "${PUBLIC_KEY_DIR}" ] || [ -L "${PUBLIC_KEY_DIR}" ] \
      || [ ! -r "${PUBLIC_KEY_DIR}" ] || [ ! -x "${PUBLIC_KEY_DIR}" ]; then
      log_error 'LDAP_SNAPSHOT_PUBLIC_KEY_DIR must name a readable directory, not a symbolic link'
      return "${EXIT_INPUT}"
    fi
    if find "${PUBLIC_KEY_DIR}" -maxdepth 1 -type l -name '*.pub' -print -quit | grep -q .; then
      log_error 'Symbolic links are not accepted as snapshot public keys'
      return "${EXIT_INPUT}"
    fi
    find "${PUBLIC_KEY_DIR}" -maxdepth 1 -type f -name '*.pub' -print \
      | sort >"${VERIFICATION_KEYS_FILE}" || return "${EXIT_INTERNAL}"
    while IFS= read -r verification_key; do
      if [ ! -r "${verification_key}" ]; then
        log_error "Snapshot public key is not readable: ${verification_key}"
        return "${EXIT_INPUT}"
      fi
    done <"${VERIFICATION_KEYS_FILE}"
  else
    selected_public_key=${PUBLIC_KEY_FILE:-${DEFAULT_PUBLIC_KEY_FILE}}
    if [ ! -f "${selected_public_key}" ] || [ -L "${selected_public_key}" ] || [ ! -r "${selected_public_key}" ]; then
      log_error "Snapshot public key is not a readable regular file: ${selected_public_key}"
      return "${EXIT_INPUT}"
    fi
    printf '%s\n' "${selected_public_key}" >"${VERIFICATION_KEYS_FILE}" || return "${EXIT_INTERNAL}"
  fi

  if [ ! -s "${VERIFICATION_KEYS_FILE}" ]; then
    log_error 'No snapshot public keys were found'
    return "${EXIT_INPUT}"
  fi

  return 0
}

verify_signature() {
  temporary_manifest=$(mktemp "${LDAP_RUNTIME_DIR:-/run/openldap}/verified-manifest.XXXXXX") || return "${EXIT_INTERNAL}"
  if ! cp "${MANIFEST_FILE}" "${temporary_manifest}"; then
    unlink "${temporary_manifest}"
    return "${EXIT_INTERNAL}"
  fi

  signature_verified=0
  while IFS= read -r verification_key; do
    if minisign -V -q \
      -p "${verification_key}" \
      -m "${temporary_manifest}" \
      -x "${SIGNATURE_FILE}" >/dev/null 2>&1; then
      signature_verified=1
      break
    fi
  done <"${VERIFICATION_KEYS_FILE}"

  if [ "${signature_verified}" -ne 1 ]; then
    unlink "${temporary_manifest}"
    log_error 'Snapshot manifest signature verification failed'
    return "${EXIT_SNAPSHOT}"
  fi

  chmod 0600 "${temporary_manifest}" || {
    unlink "${temporary_manifest}"
    return "${EXIT_INTERNAL}"
  }
  mv "${temporary_manifest}" "${VERIFIED_MANIFEST_FILE}" || return "${EXIT_INTERNAL}"

  return 0
}

validate_manifest_schema() {
  if ! jq -e '
    type == "object" and
    ((keys | sort) == ["base_dn", "expires_at", "files", "format_version", "generated_at", "revision", "service_id", "soft_expires_at", "uuid_namespace"]) and
    (.format_version == 1) and
    (.service_id | type == "string" and test("^[a-z0-9][a-z0-9._-]{0,127}$")) and
    (.base_dn | type == "string" and length > 0 and length <= 1024) and
    (.revision | type == "number" and floor == . and . >= 1 and . <= 9007199254740991) and
    (.generated_at | type == "string" and fromdateiso8601 >= 0) and
    (.soft_expires_at | type == "string" and fromdateiso8601 >= 0) and
    (.expires_at | type == "string" and fromdateiso8601 >= 0) and
    (.uuid_namespace | type == "string" and test("^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")) and
    (.files | type == "array" and length > 0) and
    (all(.files[];
      type == "object" and
      ((keys | sort) == ["path", "sha256"]) and
      (.path | type == "string" and test("^[A-Za-z0-9][A-Za-z0-9._-]*\\.ldif$")) and
      (.sha256 | type == "string" and test("^[0-9a-f]{64}$"))
    )) and
    ([.files[].path] | length == (unique | length)) and
    ((.generated_at | fromdateiso8601) <= (.soft_expires_at | fromdateiso8601)) and
    ((.soft_expires_at | fromdateiso8601) < (.expires_at | fromdateiso8601))
  ' "${VERIFIED_MANIFEST_FILE}" >/dev/null; then
    log_error 'Snapshot manifest does not match format version 1'
    return "${EXIT_SNAPSHOT}"
  fi

  return 0
}

validate_manifest_identity() {
  manifest_service_id=$(jq -r '.service_id' "${VERIFIED_MANIFEST_FILE}") || return "${EXIT_SNAPSHOT}"

  if [ "${manifest_service_id}" != "${LDAP_EXPECTED_SERVICE_ID}" ]; then
    log_error "Snapshot service ID does not match LDAP_EXPECTED_SERVICE_ID"
    return "${EXIT_SNAPSHOT}"
  fi

  return 0
}

validate_manifest_times() {
  current_epoch=$(date -u +%s) || return "${EXIT_INTERNAL}"
  generated_epoch=$(jq -r '.generated_at | fromdateiso8601' "${VERIFIED_MANIFEST_FILE}") || return "${EXIT_SNAPSHOT}"
  expires_epoch=$(jq -r '.expires_at | fromdateiso8601' "${VERIFIED_MANIFEST_FILE}") || return "${EXIT_SNAPSHOT}"

  if [ "${generated_epoch}" -gt $((current_epoch + 300)) ]; then
    log_error 'Snapshot generation time is more than five minutes in the future'
    return "${EXIT_SNAPSHOT}"
  fi

  if [ "${current_epoch}" -ge "${expires_epoch}" ]; then
    log_error 'Snapshot has expired'
    return "${EXIT_EXPIRED}"
  fi

  return 0
}

validate_manifest_files() {
  if [ -L "${VERIFIED_SNAPSHOT_DIR}" ]; then
    log_error "Verified snapshot path must not be a symbolic link: ${VERIFIED_SNAPSHOT_DIR}"
    return "${EXIT_INTERNAL}"
  fi
  mkdir -p "${VERIFIED_SNAPSHOT_DIR}" || return "${EXIT_INTERNAL}"
  find "${VERIFIED_SNAPSHOT_DIR}" -mindepth 1 -delete || return "${EXIT_INTERNAL}"
  : >"${VERIFIED_FILES_FILE}" || return "${EXIT_INTERNAL}"

  jq -r '.files[].path' "${VERIFIED_MANIFEST_FILE}" \
    | while IFS= read -r relative_path; do
      snapshot_file=${SNAPSHOT_DIR}/${relative_path}
      verified_snapshot_file=${VERIFIED_SNAPSHOT_DIR}/${relative_path}

      if [ ! -f "${snapshot_file}" ] || [ -L "${snapshot_file}" ] || [ ! -r "${snapshot_file}" ]; then
        log_error "Snapshot data file is missing, unreadable, or a symbolic link: ${relative_path}"
        exit "${EXIT_SNAPSHOT}"
      fi

      if ! cp "${snapshot_file}" "${verified_snapshot_file}"; then
        exit "${EXIT_INTERNAL}"
      fi
      chmod 0600 "${verified_snapshot_file}" || exit "${EXIT_INTERNAL}"

      expected_digest=$(jq -r --arg path "${relative_path}" \
        '.files[] | select(.path == $path) | .sha256' "${VERIFIED_MANIFEST_FILE}") || exit "${EXIT_SNAPSHOT}"
      actual_digest=$(sha256sum "${verified_snapshot_file}" | cut -d ' ' -f 1) || exit "${EXIT_INTERNAL}"

      if [ "${actual_digest}" != "${expected_digest}" ]; then
        log_error "Snapshot data digest does not match the manifest: ${relative_path}"
        exit "${EXIT_SNAPSHOT}"
      fi

      printf '%s\n' "${relative_path}" >>"${VERIFIED_FILES_FILE}" || exit "${EXIT_INTERNAL}"
    done
  validation_status=$?

  if [ "${validation_status}" -ne 0 ]; then
    return "${validation_status}"
  fi

  manifest_file_names=$(mktemp "${LDAP_RUNTIME_DIR:-/run/openldap}/manifest-files.XXXXXX") || return "${EXIT_INTERNAL}"
  actual_file_names=$(mktemp "${LDAP_RUNTIME_DIR:-/run/openldap}/actual-files.XXXXXX") || {
    unlink "${manifest_file_names}"
    return "${EXIT_INTERNAL}"
  }

  sort "${VERIFIED_FILES_FILE}" >"${manifest_file_names}" || validation_status=${EXIT_INTERNAL}
  find "${SNAPSHOT_DIR}" -maxdepth 1 -type f -name '*.ldif' -printf '%f\n' \
    | sort >"${actual_file_names}" || validation_status=${EXIT_INTERNAL}

  if [ "${validation_status:-0}" -eq 0 ] && ! cmp -s "${manifest_file_names}" "${actual_file_names}"; then
    log_error 'Snapshot contains unlisted LDIF files or omits a listed LDIF file'
    validation_status=${EXIT_SNAPSHOT}
  fi

  unlink "${manifest_file_names}"
  unlink "${actual_file_names}"

  if [ "${validation_status:-0}" -ne 0 ]; then
    return "${validation_status}"
  fi

  return 0
}

main() {
  mkdir -p "${LDAP_RUNTIME_DIR:-/run/openldap}" || die "${EXIT_INTERNAL}" 'Cannot create the runtime directory'
  umask 077

  validate_input_files || exit $?
  prepare_verification_keys || exit $?
  verify_signature || exit $?
  validate_manifest_schema || exit $?
  validate_manifest_identity || exit $?
  validate_manifest_times || exit $?
  validate_manifest_files || exit $?

  log_info "Accepted signed snapshot for service ${LDAP_EXPECTED_SERVICE_ID}"
}

main "$@"
