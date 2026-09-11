#!/usr/bin/env sh

# Build a fresh OpenLDAP configuration and database from a verified snapshot.

set -u

script_dir=$(CDPATH='' cd "$(dirname "$0")" && pwd) || exit 70
readonly script_dir
# shellcheck source=scripts/common.sh
. "${script_dir}/common.sh"

readonly runtime_dir="${LDAP_RUNTIME_DIR:-/run/openldap}"
readonly config_dir="${runtime_dir}/slapd.d"
readonly data_dir="${runtime_dir}/data"
readonly verified_manifest_file="${runtime_dir}/verified-manifest.json"
readonly verified_files_file="${runtime_dir}/verified-files"
readonly root_password_input="${runtime_dir}/root-password"
readonly verified_snapshot_dir="${runtime_dir}/verified-snapshot"

config_file=''
directory_dump=''
group_memberships=''
user_memberships=''
normalized_memberships=''
input_type=''

remove_build_artifacts() {
  for build_artifact in \
    "${root_password_input}" "${config_file}" "${directory_dump}" \
    "${group_memberships}" "${user_memberships}" "${normalized_memberships}"; do
    if [ -n "${build_artifact}" ] && [ -e "${build_artifact}" ]; then
      unlink "${build_artifact}" || return "${EXIT_INTERNAL}"
    fi
  done

  return 0
}

cleanup_initialization() {
  remove_build_artifacts || true
  remove_verified_snapshot "${runtime_dir}" || true
}

validate_compatibility_inputs() {
  base_dn="${1}"
  validation_errors=0

  if [ -n "${LDAP_BASE_DN:-}" ] && [ "${LDAP_BASE_DN}" != "${base_dn}" ]; then
    log_error 'LDAP_BASE_DN contradicts the signed snapshot manifest'
    validation_errors=$((validation_errors + 1))
  fi

  if [ -n "${LDAP_DOMAIN:-}" ]; then
    if ! printf '%s\n' "${LDAP_DOMAIN}" | grep -E -q '^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$'; then
      log_error 'LDAP_DOMAIN has an invalid compatibility value'
      validation_errors=$((validation_errors + 1))
    else
      derived_base_dn=dc=$(printf '%s' "${LDAP_DOMAIN}" | sed 's/\./,dc=/g')
      if [ "${derived_base_dn}" != "${base_dn}" ]; then
        log_error 'LDAP_DOMAIN contradicts the signed snapshot manifest'
        validation_errors=$((validation_errors + 1))
      fi
    fi
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

validate_custom_inputs() {
  if [ "${runtime_dir}" != /run/openldap ]; then
    log_error 'Custom LDIF requires LDAP_RUNTIME_DIR=/run/openldap'
    return "${EXIT_USAGE}"
  fi
  for setting in LDAP_SEARCH_SIZE_LIMIT LDAP_SEARCH_TIME_LIMIT \
    LDAP_TLS_CERT_FILE LDAP_TLS_KEY_FILE LDAP_TLS_CA_FILE \
    LDAP_ADMIN_PASSWORD_FILE LDAP_ADMIN_PASSWORD; do
    if printenv "${setting}" >/dev/null 2>&1; then
      log_error "${setting} conflicts with administrator-owned custom LDIF configuration"
      return "${EXIT_USAGE}"
    fi
  done
  return 0
}

prepare_root_password() {
  umask 077

  if [ -n "${LDAP_ADMIN_PASSWORD_FILE:-}" ]; then
    if [ ! -f "${LDAP_ADMIN_PASSWORD_FILE}" ] || [ -L "${LDAP_ADMIN_PASSWORD_FILE}" ] || [ ! -r "${LDAP_ADMIN_PASSWORD_FILE}" ]; then
      log_error 'LDAP_ADMIN_PASSWORD_FILE must name a readable regular file, not a symbolic link'
      return "${EXIT_INPUT}"
    fi
    password_line_count=$(awk 'END { print NR }' "${LDAP_ADMIN_PASSWORD_FILE}") || return "${EXIT_INTERNAL}"
    if [ "${password_line_count}" -gt 1 ]; then
      log_error 'LDAP_ADMIN_PASSWORD_FILE must contain exactly one line'
      return "${EXIT_INPUT}"
    fi
    password_value=''
    IFS= read -r password_value <"${LDAP_ADMIN_PASSWORD_FILE}" || {
      if [ -z "${password_value}" ]; then
        log_error 'LDAP_ADMIN_PASSWORD_FILE must contain exactly one non-empty line'
        return "${EXIT_INPUT}"
      fi
    }
    carriage_return=$(printf '\r') || return "${EXIT_INTERNAL}"
    case "${password_value}" in
      *"${carriage_return}") password_value=${password_value%"${carriage_return}"} ;;
      *) ;;
    esac
    if ! printf '%s' "${password_value}" >"${root_password_input}"; then
      return "${EXIT_INTERNAL}"
    fi
    unset password_value
  elif [ "${LDAP_ADMIN_PASSWORD+x}" = x ]; then
    if [ -z "${LDAP_ADMIN_PASSWORD}" ]; then
      log_error 'LDAP_ADMIN_PASSWORD must not be empty'
      return "${EXIT_USAGE}"
    fi
    log_warning 'LDAP_ADMIN_PASSWORD is deprecated; use LDAP_ADMIN_PASSWORD_FILE'
    if ! printf '%s' "${LDAP_ADMIN_PASSWORD}" >"${root_password_input}"; then
      return "${EXIT_INTERNAL}"
    fi
    unset LDAP_ADMIN_PASSWORD
  fi

  if [ ! -s "${root_password_input}" ]; then
    log_error 'The recovery root password must not be empty'
    return "${EXIT_INPUT}"
  fi

  chmod 0600 "${root_password_input}" || return "${EXIT_INTERNAL}"
  return 0
}

hash_root_password() {
  if ! root_password_hash=$(slappasswd \
    -o module-path=/usr/lib/ldap \
    -o 'module-load=argon2 m=19456 t=2 p=1' \
    -h '{ARGON2}' \
    -T "${root_password_input}"); then
    return "${EXIT_INTERNAL}"
  fi

  unlink "${root_password_input}"
  printf '%s\n' "${root_password_hash}"
}

append_tls_configuration() {
  config_file="${1}"

  if [ "${LDAP_TRANSPORT:-ldap}" = ldap ]; then
    return 0
  fi

  if { [ "${LDAP_TLS_CERT_FILE+x}" = x ] && [ -z "${LDAP_TLS_CERT_FILE}" ]; } \
    || { [ "${LDAP_TLS_KEY_FILE+x}" = x ] && [ -z "${LDAP_TLS_KEY_FILE}" ]; } \
    || { [ "${LDAP_TLS_CA_FILE+x}" = x ] && [ -z "${LDAP_TLS_CA_FILE}" ]; }; then
    log_error 'Explicit TLS file paths must not be empty'
    return "${EXIT_USAGE}"
  fi

  tls_certificate_file=${LDAP_TLS_CERT_FILE:-/tls/cert.pem}
  tls_key_file=${LDAP_TLS_KEY_FILE:-/tls/cert.key}
  tls_ca_file=${LDAP_TLS_CA_FILE:-/tls/ca.pem}
  include_tls_ca=0

  for certificate_file in "${tls_certificate_file}" "${tls_key_file}"; do
    if [ ! -f "${certificate_file}" ] || [ -L "${certificate_file}" ] || [ ! -r "${certificate_file}" ]; then
      log_error "TLS input must be a readable regular file, not a symbolic link: ${certificate_file}"
      return "${EXIT_INPUT}"
    fi
  done
  if [ "${LDAP_TLS_CA_FILE+x}" = x ] || [ -e "${tls_ca_file}" ] || [ -L "${tls_ca_file}" ]; then
    if [ ! -f "${tls_ca_file}" ] || [ -L "${tls_ca_file}" ] || [ ! -r "${tls_ca_file}" ]; then
      log_error "TLS CA input must be a readable regular file, not a symbolic link: ${tls_ca_file}"
      return "${EXIT_INPUT}"
    fi
    include_tls_ca=1
  fi

  {
    printf 'olcTLSCertificateFile: %s\n' "${tls_certificate_file}"
    printf 'olcTLSCertificateKeyFile: %s\n' "${tls_key_file}"
    printf '%s\n' 'olcTLSProtocolMin: 3.3'
    printf '%s\n' 'olcTLSCipherSuite: TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305'
    if [ "${include_tls_ca}" -eq 1 ]; then
      printf 'olcTLSCACertificateFile: %s\n' "${tls_ca_file}"
    fi
  } >>"${config_file}" || return "${EXIT_INTERNAL}"

  return 0
}

write_base_configuration() {
  base_dn="${1}"
  root_password_hash="${2}"
  config_file="${3}"
  current_uid=$(id -u) || return "${EXIT_INTERNAL}"
  current_gid=$(id -g) || return "${EXIT_INTERNAL}"
  external_identity="gidNumber=${current_gid}+uidNumber=${current_uid},cn=peercred,cn=external,cn=auth"
  read_attributes=$(jq -r '.read_attributes | join(",")' "${verified_manifest_file}") || return "${EXIT_INTERNAL}"

  {
    printf '%s\n' \
      'dn: cn=config' \
      'objectClass: olcGlobal' \
      'cn: config' \
      "olcArgsFile: ${runtime_dir}/slapd.args" \
      "olcPidFile: ${runtime_dir}/slapd.pid" \
      "olcLogLevel: ${LDAP_LOG_LEVEL:-256}" \
      'olcThreads: 4' \
      'olcToolThreads: 2' \
      'olcConnMaxPending: 50' \
      'olcConnMaxPendingAuth: 10' \
      'olcIdleTimeout: 60' \
      'olcWriteTimeout: 10'
  } >"${config_file}" || return "${EXIT_INTERNAL}"

  append_tls_configuration "${config_file}" || return $?

  {
    printf '%s\n' \
      '' \
      'dn: cn=schema,cn=config' \
      'objectClass: olcSchemaConfig' \
      'cn: schema' \
      '' \
      'include: file:///etc/ldap/schema/core.ldif' \
      'include: file:///etc/ldap/schema/cosine.ldif' \
      'include: file:///etc/ldap/schema/inetorgperson.ldif' \
      'include: file:///etc/ldap/schema/nis.ldif' \
      'include: file:///usr/local/share/openldap-declarative/schema/application-user.ldif' \
      ''
    printf '%s\n' \
      'dn: cn=module{0},cn=config' \
      'objectClass: olcModuleList' \
      'cn: module{0}' \
      'olcModulePath: /usr/lib/ldap' \
      'olcModuleLoad: back_mdb' \
      'olcModuleLoad: argon2' \
      'olcModuleLoad: memberof' \
      ''
    while IFS= read -r relative_path; do
      file_kind=$(jq -r --arg path "${relative_path}" '.files[] | select(.path == $path) | .kind' "${verified_manifest_file}") || return "${EXIT_INTERNAL}"
      if [ "${file_kind}" = schema ]; then
        printf 'include: file://%s/%s\n\n' "${verified_snapshot_dir}" "${relative_path}"
      fi
    done <"${verified_files_file}"
    printf '%s\n' \
      'dn: olcDatabase={-1}frontend,cn=config' \
      'objectClass: olcDatabaseConfig' \
      'objectClass: olcFrontendConfig' \
      'olcDatabase: {-1}frontend' \
      "olcSizeLimit: ${LDAP_SEARCH_SIZE_LIMIT-500}" \
      "olcTimeLimit: ${LDAP_SEARCH_TIME_LIMIT-10}" \
      "olcAccess: {0}to * by dn.exact=${external_identity} read by * break" \
      '' \
      'dn: olcDatabase={0}config,cn=config' \
      'objectClass: olcDatabaseConfig' \
      'olcDatabase: {0}config' \
      "olcAccess: {0}to * by dn.exact=${external_identity} read by * none" \
      '' \
      'dn: olcDatabase={1}mdb,cn=config' \
      'objectClass: olcDatabaseConfig' \
      'objectClass: olcMdbConfig' \
      'olcDatabase: {1}mdb' \
      "olcDbDirectory: ${data_dir}" \
      "olcSuffix: ${base_dn}"
    if [ -n "${root_password_hash}" ]; then
      printf 'olcRootDN: cn=admin,%s\n' "${base_dn}"
      printf 'olcRootPW: %s\n' "${root_password_hash}"
    fi
    printf '%s\n' \
      'olcDbIndex: objectClass eq' \
      'olcDbIndex: cn,uid eq' \
      'olcDbIndex: mail eq,sub' \
      'olcDbIndex: member,memberOf eq' \
      'olcDbIndex: entryUUID eq' \
      'olcDbMaxSize: 67108864' \
      "olcAccess: {0}to attrs=userPassword by self auth by anonymous auth by * none" \
      "olcAccess: {1}to attrs=entry,children,${read_attributes} by dn.exact=${external_identity} read by users read by * none" \
      "olcAccess: {2}to * by dn.exact=${external_identity} read by * none"
  } >>"${config_file}" || return "${EXIT_INTERNAL}"

  return 0
}

reset_runtime_database() {
  for directory in "${config_dir}" "${data_dir}"; do
    if [ -L "${directory}" ]; then
      log_error "Runtime database path must not be a symbolic link: ${directory}"
      return "${EXIT_INTERNAL}"
    fi
    mkdir -p "${directory}" || return "${EXIT_INTERNAL}"
    find "${directory}" -mindepth 1 -delete || return "${EXIT_INTERNAL}"
  done

  return 0
}

import_directory_data() {
  while IFS= read -r relative_path; do
    file_kind=$(jq -r --arg path "${relative_path}" '.files[] | select(.path == $path) | .kind' "${verified_manifest_file}") || return "${EXIT_INTERNAL}"
    if [ "${file_kind}" != data ]; then
      continue
    fi
    log_info "Importing signed LDIF file ${relative_path}"
    if ! slapadd -F "${config_dir}" -b "${base_dn}" -o value-check=yes -l "${verified_snapshot_dir}/${relative_path}"; then
      log_error "Offline import failed for ${relative_path}"
      return "${EXIT_SNAPSHOT}"
    fi
  done <"${verified_files_file}"

  return 0
}

validate_directory_inputs() {
  set -- --base-dn "${1}"
  if [ "${input_type}" = ldif ]; then
    set -- "$@" --native
  fi
  while IFS= read -r relative_path; do
    file_kind=$(jq -r --arg path "${relative_path}" '.files[] | select(.path == $path) | .kind' "${verified_manifest_file}") || return "${EXIT_INTERNAL}"
    case "${file_kind}" in
      schema) set -- "$@" --schema "${verified_snapshot_dir}/${relative_path}" ;;
      data) set -- "$@" "${verified_snapshot_dir}/${relative_path}" ;;
      config)
        config_file=${verified_snapshot_dir}/${relative_path}
        python3 "${script_dir}/server_config.py" --base-dn "${base_dn}" "${config_file}" || return $?
        ;;
      *) return "${EXIT_SNAPSHOT}" ;;
    esac
  done <"${verified_files_file}"
  python3 "${script_dir}/directory_data.py" "$@"
}

verify_built_database() {
  base_dn="${1}"
  directory_dump=$(mktemp "${runtime_dir}/directory.XXXXXX") || return "${EXIT_INTERNAL}"
  group_memberships=$(mktemp "${runtime_dir}/group-memberships.XXXXXX") || return "${EXIT_INTERNAL}"
  user_memberships=$(mktemp "${runtime_dir}/user-memberships.XXXXXX") || return "${EXIT_INTERNAL}"
  normalized_memberships=$(mktemp "${runtime_dir}/normalized-memberships.XXXXXX") || return "${EXIT_INTERNAL}"

  if ! slaptest -F "${config_dir}" -u; then
    log_error 'Generated slapd configuration failed validation'
    return "${EXIT_INTERNAL}"
  fi

  if ! slapcat -F "${config_dir}" -b "${base_dn}" -o ldif-wrap=no >"${directory_dump}"; then
    log_error 'Generated directory could not be read back'
    return "${EXIT_INTERNAL}"
  fi

  set -- --base-dn "${base_dn}"
  if [ "${input_type}" = ldif ]; then
    set -- "$@" --native
  fi
  if ! python3 "${script_dir}/directory_data.py" "$@" "${directory_dump}"; then
    log_error 'Generated directory failed data validation'
    return "${EXIT_SNAPSHOT}"
  fi

  if [ "${input_type}" = ldif ]; then
    return 0
  fi

  awk '
    /^dn: / { dn = substr($0, 5) }
    /^member: / { print substr($0, 9) "\n" dn }
  ' "${directory_dump}" >"${group_memberships}" || return "${EXIT_INTERNAL}"
  awk '
    /^dn: / { dn = substr($0, 5) }
    /^memberOf: / { print dn "\n" substr($0, 11) }
  ' "${directory_dump}" >"${user_memberships}" || return "${EXIT_INTERNAL}"

  # Normalize both DNs of each relationship using OpenLDAP's schema-aware rules.
  for memberships in "${group_memberships}" "${user_memberships}"; do
    if [ -s "${memberships}" ]; then
      xargs -r -d '\n' slapdn -F "${config_dir}" -N -- \
        <"${memberships}" >"${normalized_memberships}" || return "${EXIT_SNAPSHOT}"
      awk 'NR % 2 { member = $0; next } { print member "\t" $0 }' \
        "${normalized_memberships}" | sort >"${memberships}" || return "${EXIT_INTERNAL}"
    fi
  done

  if ! cmp -s "${group_memberships}" "${user_memberships}"; then
    log_error 'member and memberOf attributes must describe the same relationships'
    return "${EXIT_SNAPSHOT}"
  fi

  return 0
}

main() {
  trap cleanup_initialization 0
  trap 'exit 70' HUP INT TERM
  if [ ! -f "${verified_manifest_file}" ] || [ ! -f "${verified_files_file}" ]; then
    die "${EXIT_INTERNAL}" 'Snapshot verification output is missing'
  fi

  base_dn=$(jq -r '.base_dn' "${verified_manifest_file}") || die "${EXIT_INTERNAL}" 'Cannot read the verified base DN'
  input_type=$(jq -r '.input_type' "${verified_manifest_file}") || exit "${EXIT_INTERNAL}"
  if [ "${input_type}" = ldif ]; then
    validate_custom_inputs || exit $?
  else
    validate_search_limits || exit $?
  fi
  validate_compatibility_inputs "${base_dn}" || exit $?
  validate_directory_inputs "${base_dn}" || exit $?
  reset_runtime_database || exit $?
  root_password_hash=''
  if [ "${input_type}" = users-groups ]; then
    if [ -n "${LDAP_ADMIN_PASSWORD_FILE:-}" ] || [ "${LDAP_ADMIN_PASSWORD+x}" = x ]; then
      prepare_root_password || exit $?
      root_password_hash=$(hash_root_password) || exit $?
    fi
    config_file=$(mktemp "${runtime_dir}/config.XXXXXX") || die "${EXIT_INTERNAL}" 'Cannot create the configuration input'
    write_base_configuration "${base_dn}" "${root_password_hash}" "${config_file}" || exit $?
  fi

  if ! slapadd -F "${config_dir}" -n 0 -l "${config_file}"; then
    die "${EXIT_SNAPSHOT}" 'Cannot create the slapd configuration database from the snapshot policy'
  fi
  if [ "${input_type}" = users-groups ]; then
    unlink "${config_file}" || die "${EXIT_INTERNAL}" 'Cannot remove the configuration input'
  fi

  import_directory_data || exit $?
  slapindex -F "${config_dir}" -b "${base_dn}" || die "${EXIT_INTERNAL}" 'Cannot build directory indexes'
  verify_built_database "${base_dn}" || exit $?
  if [ "${input_type}" = ldif ]; then
    python3 "${script_dir}/server_config.py" --base-dn "${base_dn}" \
      --check-health "${config_dir}" --ldapi-uri "${LDAP_LDAPI_URI:-ldapi://%2Frun%2Fopenldap%2Fldapi}" \
      "${config_file}" || exit $?
  fi
  remove_build_artifacts || die "${EXIT_INTERNAL}" 'Cannot remove initialization artifacts'
  remove_verified_snapshot "${runtime_dir}" \
    || die "${EXIT_INTERNAL}" 'Cannot remove verified snapshot data after import'

  log_info 'Built and validated the directory without opening a listener'
}

main "$@"
