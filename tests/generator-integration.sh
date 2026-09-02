#!/usr/bin/env sh

# Exercise YAML generation and consume its output with the runtime image.

set -u

project_dir=$(CDPATH='' cd "$(dirname "$0")/.." && pwd) || exit 1
readonly project_dir
# shellcheck source=tests/test-lib.sh
. "${project_dir}/tests/test-lib.sh"

test_mode=${1:-}
runtime_image=''
generator_image=''
host_uid=$(id -u) || exit 1
readonly host_uid
host_gid=$(id -g) || exit 1
readonly host_gid

container_name=''
runtime_volume=''
state_volume=''

log() {
  printf '%s\n' "==> $*"
}

fail() {
  printf '%s: %s\n' 'ERROR' "$*" >&2
  exit 1
}

cleanup() {
  if [ "${KEEP_TEST_RESOURCES:-false}" = true ]; then
    testlib_finish
    return 0
  fi

  if [ -n "${container_name}" ] && podman container exists "${container_name}"; then
    podman stop --ignore --time 3 "${container_name}" >/dev/null 2>&1 || true
    podman container rm --volumes "${container_name}" >/dev/null 2>&1 || true
  fi
  for volume_name in "${runtime_volume}" "${state_volume}"; do
    if [ -n "${volume_name}" ] && podman volume exists "${volume_name}"; then
      podman volume rm "${volume_name}" >/dev/null 2>&1 || true
    fi
  done
  podman image rm "${generator_image}" >/dev/null 2>&1 || true
  if [ -n "${runtime_image}" ]; then
    podman image rm "${runtime_image}" >/dev/null 2>&1 || true
  fi
  testlib_finish
}

cleanup_on_exit() {
  exit_status=$?
  trap - EXIT
  if ! cleanup; then
    printf '%s\n' 'ERROR: test resource cleanup failed' >&2
    if [ "${exit_status}" -eq 0 ]; then
      exit_status=1
    fi
  fi
  exit "${exit_status}"
}

check_generator_image() {
  podman run --rm --entrypoint sh "${generator_image}" -c '
    test "$(id -u):$(id -g)" = 1001:1001 || exit 1
    test -s /usr/local/share/openldap-declarative/package-versions.txt || exit 1
    test -s /usr/local/share/openldap-declarative/LICENSE.txt || exit 1
    test -s /usr/share/doc/python3-ldap/copyright || exit 1
    test "$(stat -c "%u:%g:%a" /usr/local/bin/openldap-snapshot-generator)" \
      = 0:0:555 || exit 1
    test "$(stat -c "%u:%g:%a" /usr/local/share/openldap-declarative/LICENSE.txt)" \
      = 0:0:444 || exit 1
    test "$(stat -c "%u:%g:%a" /input)" = 0:0:555 || exit 1
    test "$(stat -c "%u:%g:%a" /run/credentials)" = 0:0:555 || exit 1
    test "$(stat -c "%u:%g:%a" /output)" = 1001:1001:700 || exit 1
  ' || return 1
}

prepare_inputs() {
  mkdir -p "${workspace}/credentials" "${workspace}/output" || return 1
  cp "${project_dir}/examples/generator/credentials.yaml.example" \
    "${workspace}/credentials/credentials.yaml" || return 1

  printf '%s\n' 'TEST-ONLY-default-user' >"${workspace}/credentials/person-0001" || return 1
  printf '%s\n' 'TEST-ONLY-app-user' >"${workspace}/credentials/person-0001-example-app" || return 1
  printf '%s\n' 'TEST-ONLY-mail-user' >"${workspace}/credentials/person-0001-example-mail" || return 1
  printf '%s\n' 'TEST-ONLY-bob-mail' >"${workspace}/credentials/person-0003-example-mail" || return 1
  printf '%s\n' 'TEST-ONLY-app-bind' >"${workspace}/credentials/bind-example-app" || return 1
  printf '%s\n' 'TEST-ONLY-mail-bind' >"${workspace}/credentials/bind-example-mail" || return 1
  chmod 0600 "${workspace}/credentials"/* || return 1

  podman run --rm \
    --user 0:0 \
    --entrypoint minisign \
    --volume "${workspace}:/work:Z" \
    "${generator_image}" \
    -G -W \
    -p /work/credentials/snapshot.pub \
    -s /work/credentials/snapshot.key >/dev/null || return 1
}

generate_snapshots() {
  podman run --rm \
    --userns=keep-id \
    --user "${host_uid}:${host_gid}" \
    --network none \
    --volume "${project_dir}/examples/generator:/input:ro,Z" \
    --volume "${workspace}/credentials:/run/credentials:ro,Z" \
    --volume "${workspace}/output:/output:Z" \
    "${generator_image}" \
    --directory /input/directory.yaml \
    --credentials /run/credentials/credentials.yaml \
    --signing-key /run/credentials/snapshot.key \
    --output /output/generated >/dev/null || return 1

  for service_id in example-app example-mail; do
    for required_file in directory.ldif manifest.json manifest.json.minisig; do
      [ -f "${workspace}/output/generated/${service_id}/${required_file}" ] || return 1
    done
  done
  if find "${workspace}/output/generated" -type f ! -perm 0600 -print -quit | grep -q .; then
    return 1
  fi
  if find "${workspace}/output/generated" -type d ! -perm 0700 -print -quit | grep -q .; then
    return 1
  fi

  app_ldif=${workspace}/output/generated/example-app/directory.ldif
  mail_ldif=${workspace}/output/generated/example-mail/directory.ldif
  grep -F -q 'uid: alice' "${app_ldif}" || return 1
  if grep -F -q 'uid: bob' "${app_ldif}" || grep -F -q 'uid: disabled' "${app_ldif}"; then
    return 1
  fi
  grep -F -q 'uid: bob' "${mail_ldif}" || return 1
  if grep -F -q 'uid: disabled' "${mail_ldif}"; then
    return 1
  fi
  alice_app_uuid=$(awk '/^dn: uid=alice,/{found=1} found && /^entryUUID: /{print $2; exit}' "${app_ldif}") || return 1
  alice_mail_uuid=$(awk '/^dn: uid=alice,/{found=1} found && /^entryUUID: /{print $2; exit}' "${mail_ldif}") || return 1
  [ -n "${alice_app_uuid}" ] && [ "${alice_app_uuid}" = "${alice_mail_uuid}" ] || return 1

  if grep -R -F -q \
    -e 'TEST-ONLY-default-user' \
    -e 'TEST-ONLY-app-user' \
    -e 'TEST-ONLY-mail-user' \
    -e 'TEST-ONLY-bob-mail' \
    -e 'TEST-ONLY-app-bind' \
    -e 'TEST-ONLY-mail-bind' -- \
    "${workspace}/output/generated"; then
    return 1
  fi
}

validate_generated_manifests() {
  schema_environment=${workspace}/schema-venv
  testlib_record python-environment "${schema_environment}"
  for service_id in example-app example-mail; do
    UV_PROJECT_ENVIRONMENT="${schema_environment}" uv run --frozen \
      python tests/validate_snapshot_manifest.py \
      "${workspace}/output/generated/${service_id}/manifest.json" || return 1
  done

  app_manifest=${workspace}/output/generated/example-app/manifest.json
  mail_manifest=${workspace}/output/generated/example-mail/manifest.json
  app_generated=$(jq -r '.generated_at | fromdateiso8601' "${app_manifest}") || return 1
  app_soft=$(jq -r '.soft_expires_at | fromdateiso8601' "${app_manifest}") || return 1
  app_hard=$(jq -r '.expires_at | fromdateiso8601' "${app_manifest}") || return 1
  mail_generated=$(jq -r '.generated_at | fromdateiso8601' "${mail_manifest}") || return 1
  mail_soft=$(jq -r '.soft_expires_at | fromdateiso8601' "${mail_manifest}") || return 1
  mail_hard=$(jq -r '.expires_at | fromdateiso8601' "${mail_manifest}") || return 1
  [ "${app_generated}" -eq "${mail_generated}" ] || return 1
  [ $((app_soft - app_generated)) -eq 21600 ] || return 1
  [ $((app_hard - app_generated)) -eq 43200 ] || return 1
  [ $((mail_soft - mail_generated)) -eq 21000 ] || return 1
  [ $((mail_hard - mail_generated)) -eq 42600 ] || return 1
  [ $((app_soft - mail_soft)) -eq 600 ] || return 1
  [ $((app_hard - mail_hard)) -eq 600 ] || return 1
}

test_controlled_expiry_output() {
  podman run --rm \
    --userns=keep-id \
    --user "${host_uid}:${host_gid}" \
    --network none \
    --volume "${project_dir}/examples/generator:/input:ro,Z" \
    --volume "${workspace}/credentials:/run/credentials:ro,Z" \
    --volume "${workspace}/output:/output:Z" \
    "${generator_image}" \
    --directory /input/directory.yaml \
    --credentials /run/credentials/credentials.yaml \
    --signing-key /run/credentials/snapshot.key \
    --generated-at 2030-01-01T00:00:00Z \
    --output /output/controlled >/dev/null || return 1

  jq -e '
    .generated_at == "2030-01-01T00:00:00Z" and
    .soft_expires_at == "2030-01-01T06:00:00Z" and
    .expires_at == "2030-01-01T12:00:00Z"
  ' "${workspace}/output/controlled/example-app/manifest.json" >/dev/null || return 1
  jq -e '
    .generated_at == "2030-01-01T00:00:00Z" and
    .soft_expires_at == "2030-01-01T05:50:00Z" and
    .expires_at == "2030-01-01T11:50:00Z"
  ' "${workspace}/output/controlled/example-mail/manifest.json" >/dev/null
}

expect_expiry_offset_rejection() {
  test_name=${1}
  offset=${2}
  expected_message=${3}
  input_file=${workspace}/${test_name}.yaml

  sed "0,/expiry_offset_seconds: 0/s//expiry_offset_seconds: ${offset}/" \
    "${project_dir}/examples/generator/directory.yaml" >"${input_file}" || return 1
  rejection_output=$(podman run --rm \
    --userns=keep-id \
    --user "${host_uid}:${host_gid}" \
    --network none \
    --volume "${input_file}:/input/directory.yaml:ro,Z" \
    --volume "${workspace}/credentials:/run/credentials:ro,Z" \
    --volume "${workspace}/output:/output:Z" \
    "${generator_image}" \
    --directory /input/directory.yaml \
    --credentials /run/credentials/credentials.yaml \
    --signing-key /run/credentials/snapshot.key \
    --output "/output/${test_name}" 2>&1)
  rejection_status=$?
  [ "${rejection_status}" -eq 2 ] || return 1
  printf '%s\n' "${rejection_output}" | grep -F -q "${expected_message}" || return 1
  [ ! -e "${workspace}/output/${test_name}" ]
}

test_expiry_offset_rejections() {
  expect_expiry_offset_rejection negative-offset -1 \
    'expiry_offset_seconds must be an integer from 0 through 86400' || return 1
  expect_expiry_offset_rejection excessive-offset 86401 \
    'expiry_offset_seconds must be an integer from 0 through 86400' || return 1
  expect_expiry_offset_rejection soft-boundary 21600 \
    'expiry_offset_seconds must be less than soft_ttl_seconds'
}

generate_update_snapshot() {
  directory_file=${1}
  output_name=${2}

  podman run --rm \
    --userns=keep-id \
    --user "${host_uid}:${host_gid}" \
    --network none \
    --volume "${project_dir}/tests/fixtures:/input:ro,Z" \
    --volume "${workspace}/credentials:/run/credentials:ro,Z" \
    --volume "${workspace}/output:/output:Z" \
    "${generator_image}" \
    --directory "/input/${directory_file}" \
    --credentials /run/credentials/credentials.yaml \
    --signing-key /run/credentials/snapshot.key \
    --service example-app \
    --output "/output/${output_name}" >/dev/null
}

test_generator_rejections() {
  rejection_output=$(podman run --rm \
    --userns=keep-id \
    --user "${host_uid}:${host_gid}" \
    --network none \
    --volume "${project_dir}/examples/generator:/input:ro,Z" \
    --volume "${workspace}/credentials:/run/credentials:ro,Z" \
    --volume "${workspace}/output:/output:Z" \
    "${generator_image}" \
    --directory /input/directory.yaml \
    --credentials /run/credentials/credentials.yaml \
    --signing-key /run/credentials/snapshot.key \
    --service unknown-service \
    --output /output/rejected 2>&1)
  rejection_status=$?
  [ "${rejection_status}" -eq 2 ] || return 1
  printf '%s\n' "${rejection_output}" \
    | grep -F -q 'unknown selected services: unknown-service' || return 1
  [ ! -e "${workspace}/output/rejected" ] || return 1

  rejection_output=$(podman run --rm \
    --userns=keep-id \
    --user "${host_uid}:${host_gid}" \
    --network none \
    --volume "${project_dir}/examples/generator:/input:ro,Z" \
    --volume "${workspace}/credentials:/run/credentials:ro,Z" \
    --volume "${workspace}/output:/output:Z" \
    "${generator_image}" \
    --directory /input/directory.yaml \
    --credentials /run/credentials/credentials.yaml \
    --signing-key /run/credentials/snapshot.key \
    --output /output/generated 2>&1)
  rejection_status=$?
  [ "${rejection_status}" -eq 2 ] || return 1
  printf '%s\n' "${rejection_output}" \
    | grep -F -q 'output path already exists: /output/generated'
}

wait_until_healthy() {
  wait_iteration=0
  while [ "${wait_iteration}" -lt 80 ]; do
    container_state=$(podman inspect "${container_name}" --format '{{.State.Status}}') || return 1
    if [ "${container_state}" != running ]; then
      podman logs "${container_name}" >&2 || true
      return 1
    fi
    if podman exec "${container_name}" \
      /usr/local/lib/openldap-declarative/healthcheck.sh >/dev/null 2>&1; then
      return 0
    fi
    wait_iteration=$((wait_iteration + 1))
    sleep 0.25
  done
  podman logs "${container_name}" >&2 || true
  return 1
}

start_runtime_snapshot() {
  snapshot_directory=${1}

  if podman container exists "${container_name}"; then
    podman stop --time 3 "${container_name}" >/dev/null || return 1
    podman container rm "${container_name}" >/dev/null || return 1
  fi
  podman create \
    --name "${container_name}" \
    --userns=keep-id:uid=1001,gid=1001 \
    --network none \
    --read-only \
    --read-only-tmpfs=false \
    --ulimit nofile=1024:1024 \
    --memory=256m \
    --pids-limit=128 \
    --cap-drop=all \
    --security-opt=no-new-privileges \
    --env LDAP_EXPECTED_SERVICE_ID=example-app \
    --mount "type=volume,source=${runtime_volume},destination=/run/openldap" \
    --mount "type=volume,source=${state_volume},destination=/state" \
    --volume "${snapshot_directory}:/snapshot:ro,Z" \
    --volume "${workspace}/credentials/snapshot.pub:/run/credentials/snapshot-public-key:ro,Z" \
    "${runtime_image}" >/dev/null || return 1
  podman start "${container_name}" >/dev/null || return 1
  wait_until_healthy || return 1
  podman exec "${container_name}" sh -c '
    test ! -e /run/openldap/verified-snapshot
    test ! -e /run/openldap/verified-files
    if grep -R -F -q "nis.ldif" /run/openldap/slapd.d; then
      exit 1
    fi
  '
}

alice_bind_succeeds() {
  password=${1}

  podman exec "${container_name}" ldapwhoami \
    -x -H ldap://127.0.0.1:1389 \
    -D uid=alice,ou=people,dc=example-app,dc=services,dc=example,dc=org \
    -w "${password}" >/dev/null 2>&1
}

consume_generated_snapshot() {
  container_name=${resource_prefix}-runtime
  runtime_volume=${container_name}-runtime
  state_volume=${container_name}-state
  testlib_plan_container "${container_name}" || return 1
  testlib_plan_volume "${runtime_volume}" || return 1
  podman volume create "${runtime_volume}" >/dev/null || return 1
  testlib_plan_volume "${state_volume}" || return 1
  podman volume create "${state_volume}" >/dev/null || return 1

  start_runtime_snapshot \
    "${workspace}/output/generated/example-app" || return 1

  podman exec "${container_name}" ldapwhoami \
    -x -H ldap://127.0.0.1:1389 \
    -D uid=alice,ou=people,dc=example-app,dc=services,dc=example,dc=org \
    -w TEST-ONLY-app-user \
    | grep -F -q 'dn:uid=alice,ou=people,dc=example-app,dc=services,dc=example,dc=org' || return 1
  if podman exec "${container_name}" ldapwhoami \
    -x -H ldap://127.0.0.1:1389 \
    -D uid=alice,ou=people,dc=example-app,dc=services,dc=example,dc=org \
    -w TEST-ONLY-default-user >/dev/null 2>&1; then
    return 1
  fi
  podman exec "${container_name}" ldapsearch \
    -LLL -x -H ldap://127.0.0.1:1389 \
    -D cn=application,ou=services,dc=example-app,dc=services,dc=example,dc=org \
    -w TEST-ONLY-app-bind \
    -b uid=alice,ou=people,dc=example-app,dc=services,dc=example,dc=org -s base \
    uid memberOf \
    | grep -F -q 'memberOf: cn=staff,ou=groups,dc=example-app,dc=services,dc=example,dc=org' || return 1

  enumeration_output=$(podman exec "${container_name}" ldapsearch \
    -LLL -x -H ldap://127.0.0.1:1389 \
    -D cn=application,ou=services,dc=example-app,dc=services,dc=example,dc=org \
    -w TEST-ONLY-app-bind \
    -b dc=example-app,dc=services,dc=example,dc=org -s sub \
    '(objectClass=*)' dn uid cn userPassword) || return 1
  printf '%s\n' "${enumeration_output}" \
    | grep -F -q 'dn: uid=alice,ou=people,dc=example-app,dc=services,dc=example,dc=org' \
    || return 1
  if printf '%s\n' "${enumeration_output}" | grep -F -q 'userPassword:'; then
    return 1
  fi
}

test_password_rotation_and_offboarding() {
  initial_uuid=$(podman exec "${container_name}" ldapsearch \
    -LLL -x -H ldap://127.0.0.1:1389 \
    -D cn=application,ou=services,dc=example-app,dc=services,dc=example,dc=org \
    -w TEST-ONLY-app-bind \
    -b uid=alice,ou=people,dc=example-app,dc=services,dc=example,dc=org -s base \
    entryUUID | awk '/^entryUUID: / { print $2 }') || return 1
  [ -n "${initial_uuid}" ] || return 1

  printf '%s\n' 'TEST-ONLY-rotated-app-user' \
    >"${workspace}/credentials/person-0001-example-app" || return 1
  chmod 0600 "${workspace}/credentials/person-0001-example-app" || return 1
  generate_update_snapshot directory-revision-2.yaml generated-2 || return 1
  start_runtime_snapshot \
    "${workspace}/output/generated-2/example-app" || return 1
  if alice_bind_succeeds TEST-ONLY-app-user; then
    return 1
  fi
  alice_bind_succeeds TEST-ONLY-rotated-app-user || return 1
  rotated_uuid=$(podman exec "${container_name}" ldapsearch \
    -LLL -x -H ldap://127.0.0.1:1389 \
    -D cn=application,ou=services,dc=example-app,dc=services,dc=example,dc=org \
    -w TEST-ONLY-app-bind \
    -b uid=alice,ou=people,dc=example-app,dc=services,dc=example,dc=org -s base \
    entryUUID | awk '/^entryUUID: / { print $2 }') || return 1
  [ "${rotated_uuid}" = "${initial_uuid}" ] || return 1

  generate_update_snapshot directory-revision-3.yaml generated-3 || return 1
  start_runtime_snapshot \
    "${workspace}/output/generated-3/example-app" || return 1
  if alice_bind_succeeds TEST-ONLY-app-user \
    || alice_bind_succeeds TEST-ONLY-rotated-app-user; then
    return 1
  fi
  if podman exec "${container_name}" ldapsearch \
    -LLL -x -H ldap://127.0.0.1:1389 \
    -D cn=application,ou=services,dc=example-app,dc=services,dc=example,dc=org \
    -w TEST-ONLY-app-bind \
    -b uid=alice,ou=people,dc=example-app,dc=services,dc=example,dc=org -s base \
    uid 2>/dev/null | grep -F -q 'uid: alice'; then
    return 1
  fi
  accepted_revision=$(podman exec "${container_name}" \
    awk '{ print $1 }' /state/highest-revision) || return 1
  [ "${accepted_revision}" = 3 ]
}

main() {
  if [ "$#" -ne 1 ]; then
    fail 'Select exactly one test mode'
  fi
  testlib_init "${test_mode}" generator-integration || exit $?
  trap cleanup_on_exit EXIT
  trap 'exit 130' HUP INT TERM

  generator_image=localhost/${resource_prefix}:generator
  case "${test_mode}" in
    --conclear-generator)
      testlib_import_image primary generator "${generator_image}" \
        || fail 'Cannot import the exact ConClear generator layout'
      ;;
    --conclear-runtime)
      runtime_image=localhost/${resource_prefix}:runtime
      testlib_import_image primary runtime "${runtime_image}" \
        || fail 'Cannot import the exact ConClear runtime layout'
      testlib_import_image dependency generator "${generator_image}" \
        || fail 'Cannot import the exact same-revision generator layout'
      ;;
    --developer-build)
      runtime_image=localhost/${resource_prefix}:runtime
      revision=$(git -C "${project_dir}" rev-parse HEAD) || fail 'Cannot resolve source revision'
      created=$(date -u +%Y-%m-%dT%H:%M:%SZ) || fail 'Cannot determine build time'
      testlib_record developer-image "${runtime_image}"
      log 'Building non-release images for developer testing'
      podman build --pull=always --tag "${runtime_image}" \
        --build-arg "IMAGE_CREATED=${created}" \
        --build-arg "IMAGE_REVISION=${revision}" \
        --build-arg IMAGE_VERSION=developer-test \
        "${project_dir}" >/dev/null || fail 'Runtime image build failed'
      testlib_record developer-image "${generator_image}"
      podman build --pull=always --tag "${generator_image}" \
        --file "${project_dir}/Containerfile.generator" \
        --build-arg "IMAGE_CREATED=${created}" \
        --build-arg "IMAGE_REVISION=${revision}" \
        --build-arg IMAGE_VERSION=developer-test \
        "${project_dir}" >/dev/null || fail 'Generator image build failed'
      ;;
    *) fail 'The selected mode is not valid for the generator integration suite' ;;
  esac

  check_generator_image || fail 'Generator image contents do not match the declared boundary'
  prepare_inputs || fail 'Cannot prepare generator inputs'
  log 'Generating signed service-specific snapshots'
  generate_snapshots || fail 'Snapshot generation test failed'
  validate_generated_manifests || fail 'Generated manifests do not match the JSON Schema contract'
  test_controlled_expiry_output || fail 'Controlled expiry staggering test failed'
  test_expiry_offset_rejections || fail 'Expiry staggering boundary test failed'
  log 'Testing generator rejection paths'
  test_generator_rejections || fail 'Generator rejection test failed'
  if [ -n "${runtime_image}" ]; then
    log 'Importing and authenticating against generated output'
    consume_generated_snapshot || fail 'Generated snapshot runtime test failed'
    log 'Testing password rotation and offboarding revisions'
    test_password_rotation_and_offboarding || fail 'Lifecycle update test failed'
  fi
  log 'Generator integration tests passed'
}

main "$@"
