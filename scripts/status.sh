#!/usr/bin/env sh

# Report the active snapshot revision, freshness, and LDAP availability as JSON.

set -u

readonly runtime_dir="${LDAP_RUNTIME_DIR:-/run/openldap}"
readonly active_manifest_file="${runtime_dir}/active-manifest.json"

read_manifest_field() {
  field_name=${1}
  jq -er --arg field_name "${field_name}" '.[$field_name] | strings | select(length > 0)' \
    "${active_manifest_file}"
}

ldap_is_available() {
  base_dn=${1}

  ldapsearch -LLL -Q -Y EXTERNAL \
    -H "${LDAP_LDAPI_URI:-ldapi://%2Frun%2Fopenldap%2Fldapi}" \
    -b "${base_dn}" -s base '(objectClass=*)' dn 2>/dev/null \
    | grep -F -q "dn: ${base_dn}"
}

write_status() {
  state=${1}
  ldap_state=${2}
  current_epoch=${3}
  soft_expires_epoch=${4}
  expires_epoch=${5}
  service_id=${6}
  revision=${7}
  generated_at=${8}
  soft_expires_at=${9}
  shift 9
  expires_at=${1}

  jq -cn \
    --arg state "${state}" \
    --arg ldap_state "${ldap_state}" \
    --arg service_id "${service_id}" \
    --arg revision "${revision}" \
    --arg generated_at "${generated_at}" \
    --arg soft_expires_at "${soft_expires_at}" \
    --arg expires_at "${expires_at}" \
    --argjson seconds_until_soft_expiry "$((soft_expires_epoch - current_epoch))" \
    --argjson seconds_until_hard_expiry "$((expires_epoch - current_epoch))" \
    '{
      state: $state,
      ldap: $ldap_state,
      service_id: $service_id,
      revision: ($revision | tonumber),
      generated_at: $generated_at,
      soft_expires_at: $soft_expires_at,
      expires_at: $expires_at,
      seconds_until_soft_expiry: $seconds_until_soft_expiry,
      seconds_until_hard_expiry: $seconds_until_hard_expiry
    }'
}

main() {
  if [ ! -f "${active_manifest_file}" ] \
    || [ -L "${active_manifest_file}" ] \
    || [ ! -r "${active_manifest_file}" ]; then
    printf '%s\n' '{"state":"unavailable","reason":"active manifest is unavailable"}'
    return 2
  fi

  current_epoch=$(date -u +%s) || return 2
  service_id=$(read_manifest_field service_id) || return 2
  revision=$(jq -er '.revision | numbers' "${active_manifest_file}") || return 2
  generated_at=$(read_manifest_field generated_at) || return 2
  soft_expires_at=$(read_manifest_field soft_expires_at) || return 2
  expires_at=$(read_manifest_field expires_at) || return 2
  soft_expires_epoch=$(jq -r '.soft_expires_at | fromdateiso8601' "${active_manifest_file}") || return 2
  expires_epoch=$(jq -r '.expires_at | fromdateiso8601' "${active_manifest_file}") || return 2
  base_dn=$(read_manifest_field base_dn) || return 2

  ldap_state=unavailable
  if ldap_is_available "${base_dn}"; then
    ldap_state=available
  fi

  state=healthy
  exit_status=0
  if [ "${current_epoch}" -ge "${expires_epoch}" ]; then
    state=expired
    exit_status=2
  elif [ "${ldap_state}" != available ]; then
    state=unavailable
    exit_status=2
  elif [ "${current_epoch}" -ge "${soft_expires_epoch}" ]; then
    state=soft-expired
    exit_status=1
  fi

  write_status \
    "${state}" \
    "${ldap_state}" \
    "${current_epoch}" \
    "${soft_expires_epoch}" \
    "${expires_epoch}" \
    "${service_id}" \
    "${revision}" \
    "${generated_at}" \
    "${soft_expires_at}" \
    "${expires_at}" || return 2

  return "${exit_status}"
}

main "$@"
