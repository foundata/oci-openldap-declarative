#!/usr/bin/env sh

# Shared isolated Podman storage and resource journaling for integration tests.

set -u

podman_binary=$(command -v podman) || exit 1
readonly podman_binary

testlib_record() {
  resource_kind=${1}
  resource_identifier=${2}
  resource_timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ) || return 1

  printf '%s | %s | %s\n' "${resource_timestamp}" \
    "${resource_kind}" "${resource_identifier}" >>"${resource_manifest}"
}

testlib_init() {
  requested_mode=${1}
  suite_name=${2}

  case "${requested_mode}" in
    --conclear | --conclear-generator | --conclear-runtime)
      if [ -z "${CC_TEST_INPUT_MANIFEST:-}" ] \
        || [ ! -f "${CC_TEST_INPUT_MANIFEST}" ] \
        || [ -L "${CC_TEST_INPUT_MANIFEST}" ]; then
        printf '%s\n' 'ERROR: ConClear mode requires CC_TEST_INPUT_MANIFEST' >&2
        return 64
      fi
      test_base=$(dirname "${CC_TEST_INPUT_MANIFEST}") || return 1
      ;;
    --developer-build)
      if [ -z "${OPENLDAP_TEST_RUN_DIR:-}" ] \
        || [ ! -d "${OPENLDAP_TEST_RUN_DIR}" ] \
        || [ -L "${OPENLDAP_TEST_RUN_DIR}" ]; then
        printf '%s\n' \
          'ERROR: --developer-build requires an existing OPENLDAP_TEST_RUN_DIR' >&2
        return 64
      fi
      test_base=${OPENLDAP_TEST_RUN_DIR}
      ;;
    *)
      printf '%s\n' \
        'ERROR: select --conclear, --conclear-generator, --conclear-runtime, or --developer-build' >&2
      return 64
      ;;
  esac

  run_key=$(printf '%s/%s' "${test_base}" "${suite_name}" | sha256sum | cut -c 1-12) || return 1
  resource_prefix=openldap-${suite_name}-${run_key}
  resource_manifest=${test_base}/${suite_name}-resources.md
  workspace=${test_base}/${suite_name}-workspace
  podman_root=${test_base}/${suite_name}-podman-root
  podman_runroot=${test_base}/${suite_name}-podman-runroot

  for planned_path in "${resource_manifest}" "${workspace}" "${podman_root}" "${podman_runroot}"; do
    if [ -e "${planned_path}" ] || [ -L "${planned_path}" ]; then
      printf 'ERROR: refusing to reuse test path: %s\n' "${planned_path}" >&2
      return 1
    fi
  done

  umask 077
  {
    printf '# OpenLDAP integration resource manifest\n\n'
    printf 'Run key: %s\n\n' "${run_key}"
    printf 'Timestamp | Kind | Identifier\n'
    printf '%s\n' '--- | --- | ---'
  } >"${resource_manifest}" || return 1
  testlib_record directory "${workspace}"
  mkdir -m 0700 "${workspace}" || return 1
  printf '%s\n' "${run_key}" >"${workspace}/.openldap-test-owner" || return 1
  testlib_record podman-storage "${podman_root}"
  testlib_record podman-runroot "${podman_runroot}"
  mkdir -m 0700 "${podman_root}" "${podman_runroot}" || return 1
  printf '%s\n' "${run_key}" >"${podman_root}/.openldap-test-owner" || return 1
  printf '%s\n' "${run_key}" >"${podman_runroot}/.openldap-test-owner" || return 1

  export resource_manifest resource_prefix run_key workspace podman_root podman_runroot
}

podman() {
  if [ "${1:-}" = run ]; then
    shift
    transient_suffix=$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n') || return 1
    transient_name=${resource_prefix}-run-${transient_suffix}
    if command "${podman_binary}" --root "${podman_root}" --runroot "${podman_runroot}" \
      container exists "${transient_name}"; then
      printf 'ERROR: Podman container name collision: %s\n' "${transient_name}" >&2
      return 1
    fi
    testlib_record container "${transient_name}"
    command "${podman_binary}" --root "${podman_root}" --runroot "${podman_runroot}" \
      run --name "${transient_name}" "$@"
    return $?
  fi

  command "${podman_binary}" --root "${podman_root}" --runroot "${podman_runroot}" "$@"
}

testlib_plan_container() {
  planned_name=${1}
  if podman container exists "${planned_name}"; then
    printf 'ERROR: Podman container name collision: %s\n' "${planned_name}" >&2
    return 1
  fi
  testlib_record container "${planned_name}"
}

testlib_plan_volume() {
  planned_name=${1}
  if podman volume exists "${planned_name}"; then
    printf 'ERROR: Podman volume name collision: %s\n' "${planned_name}" >&2
    return 1
  fi
  testlib_record volume "${planned_name}"
}

testlib_import_image() {
  manifest_role=${1}
  expected_image_id=${2}
  image_name=${3}

  case "${manifest_role}" in
    primary)
      selector='.primary'
      ;;
    dependency)
      # shellcheck disable=SC2016  # jq expands this variable, not the shell.
      selector='.dependencies[] | select(.imageId == $image_id)'
      ;;
    *) return 1 ;;
  esac
  image_record=$(jq -ce --arg image_id "${expected_image_id}" "${selector}" \
    "${CC_TEST_INPUT_MANIFEST}") || return 1
  observed_image_id=$(printf '%s' "${image_record}" | jq -r '.imageId') || return 1
  if [ "${observed_image_id}" != "${expected_image_id}" ]; then
    printf 'ERROR: exact image input has the wrong image ID: %s\n' "${expected_image_id}" >&2
    return 1
  fi
  layout=$(printf '%s' "${image_record}" | jq -r '.layout') || return 1
  expected_digest=$(printf '%s' "${image_record}" | jq -r '.digest') || return 1
  if [ ! -d "${layout}" ] \
    || ! printf '%s\n' "${expected_digest}" | grep -E -q '^sha256:[0-9a-f]{64}$'; then
    printf 'ERROR: exact image input is malformed: %s\n' "${expected_image_id}" >&2
    return 1
  fi

  testlib_record oci-layout "${layout}@${expected_digest}"
  testlib_record imported-image "${image_name}"
  pull_output=$(podman pull --quiet "oci:${layout}:qualified") || return 1
  imported_identifier=$(printf '%s\n' "${pull_output}" | tail -n 1) || return 1
  [ -n "${imported_identifier}" ] || return 1
  podman tag "${imported_identifier}" "${image_name}" || return 1
  observed_digest=$(podman image inspect "${image_name}" --format '{{.Digest}}') || return 1
  if [ "${observed_digest}" != "${expected_digest}" ]; then
    printf 'ERROR: imported digest %s differs from declared digest %s\n' \
      "${observed_digest}" "${expected_digest}" >&2
    return 1
  fi
}

testlib_validate_owned_directory() {
  owned_path=${1}
  marker=${owned_path}/.openldap-test-owner

  if [ ! -d "${owned_path}" ] || [ -L "${owned_path}" ]; then
    return 0
  fi
  if [ ! -f "${marker}" ] || [ -L "${marker}" ]; then
    printf 'ERROR: refusing to remove path without the run ownership marker: %s\n' \
      "${owned_path}" >&2
    return 1
  fi
  marker_value=$(cat "${marker}") || return 1
  if [ "${marker_value}" != "${run_key}" ]; then
    printf 'ERROR: refusing to remove path without the run ownership marker: %s\n' \
      "${owned_path}" >&2
    return 1
  fi
}

testlib_remove_owned_directory() {
  owned_path=${1}

  testlib_validate_owned_directory "${owned_path}" || return 1
  if [ ! -d "${owned_path}" ]; then
    return 0
  fi
  rm -rf "${owned_path}"
}

testlib_finish() {
  if [ "${KEEP_TEST_RESOURCES:-false}" = true ]; then
    printf 'Retained resource manifest: %s\n' "${resource_manifest}" >&2
    printf 'Inspect with: podman --root %s --runroot %s ps --all\n' \
      "${podman_root}" "${podman_runroot}" >&2
    return 0
  fi

  testlib_validate_owned_directory "${workspace}" || return 1
  testlib_validate_owned_directory "${podman_root}" || return 1
  testlib_validate_owned_directory "${podman_runroot}" || return 1

  command "${podman_binary}" --root "${podman_root}" --runroot "${podman_runroot}" \
    system reset --force >/dev/null || return 1
  testlib_remove_owned_directory "${workspace}" || return 1
  rm -rf "${podman_root}" "${podman_runroot}"
}
