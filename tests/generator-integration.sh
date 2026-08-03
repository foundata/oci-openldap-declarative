#!/usr/bin/env sh

# Exercise YAML generation and consume its output with the runtime image.

set -u

project_dir=$(CDPATH='' cd "$(dirname "$0")/.." && pwd) || exit 1
readonly project_dir
readonly runtime_image="${RUNTIME_IMAGE:-localhost/oci-openldap-declarative:generator-integration}"
readonly generator_image="${GENERATOR_IMAGE:-localhost/oci-openldap-declarative-generator:integration-test}"
readonly resource_prefix=ldap-generator-test-$$
host_uid=$(id -u) || exit 1
readonly host_uid
host_gid=$(id -g) || exit 1
readonly host_gid

workspace=''
container_name=''
runtime_volume=''
state_volume=''
built_runtime_image=0
built_generator_image=0

log() {
  printf '%s\n' "==> $*"
}

fail() {
  printf '%s: %s\n' 'ERROR' "$*" >&2
  exit 1
}

cleanup() {
  if [ "${KEEP_TEST_RESOURCES:-false}" = true ]; then
    log "Keeping test resources with prefix ${resource_prefix}"
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
  if [ -n "${workspace}" ] && [ -d "${workspace}" ]; then
    rm -rf "${workspace}"
  fi
  if [ "${built_generator_image}" -eq 1 ]; then
    podman image rm "${generator_image}" >/dev/null 2>&1 || true
  fi
  if [ "${built_runtime_image}" -eq 1 ]; then
    podman image rm "${runtime_image}" >/dev/null 2>&1 || true
  fi
}

build_images() {
  if [ "${BUILD_RUNTIME_IMAGE:-true}" = true ]; then
    log 'Building the runtime image'
    podman build --pull=never --tag "${runtime_image}" "${project_dir}" >/dev/null || return 1
    built_runtime_image=1
  fi
  if [ "${BUILD_GENERATOR_IMAGE:-true}" = true ]; then
    log 'Building the generator image'
    podman build --pull=never --tag "${generator_image}" \
      --file "${project_dir}/Containerfile.generator" "${project_dir}" >/dev/null || return 1
    built_generator_image=1
  fi
}

prepare_inputs() {
  workspace=$(mktemp -d /tmp/openldap-generator-integration.XXXXXX) || return 1
  mkdir -p "${workspace}/credentials" "${workspace}/output" || return 1
  cp "${project_dir}/examples/generator/credentials.yaml.example" \
    "${workspace}/credentials/credentials.yaml" || return 1

  printf '%s\n' 'default-user-password' >"${workspace}/credentials/person-0001" || return 1
  printf '%s\n' 'app-user-password' >"${workspace}/credentials/person-0001-example-app" || return 1
  printf '%s\n' 'mail-user-password' >"${workspace}/credentials/person-0001-example-mail" || return 1
  printf '%s\n' 'bob-mail-password' >"${workspace}/credentials/person-0003-example-mail" || return 1
  printf '%s\n' 'app-bind-password' >"${workspace}/credentials/bind-example-app" || return 1
  printf '%s\n' 'mail-bind-password' >"${workspace}/credentials/bind-example-mail" || return 1
  chmod 0600 "${workspace}/credentials"/* || return 1

  podman run --rm \
    --user 0:0 \
    --entrypoint minisign \
    --volume "${workspace}:/work:Z" \
    "${runtime_image}" \
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
    -e 'default-user-password' \
    -e 'app-user-password' \
    -e 'mail-user-password' \
    -e 'bob-mail-password' \
    -e 'app-bind-password' \
    -e 'mail-bind-password' -- \
    "${workspace}/output/generated"; then
    return 1
  fi
}

test_generator_rejections() {
  if podman run --rm \
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
    --output /output/rejected >/dev/null 2>&1; then
    return 1
  fi
  [ ! -e "${workspace}/output/rejected" ] || return 1

  if podman run --rm \
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
    --output /output/generated >/dev/null 2>&1; then
    return 1
  fi
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

consume_generated_snapshot() {
  container_name=${resource_prefix}-runtime
  runtime_volume=${container_name}-runtime
  state_volume=${container_name}-state
  podman volume create "${runtime_volume}" >/dev/null || return 1
  podman volume create "${state_volume}" >/dev/null || return 1

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
    --volume "${workspace}/output/generated/example-app:/snapshot:ro,Z" \
    --volume "${workspace}/credentials/snapshot.pub:/run/credentials/snapshot-public-key:ro,Z" \
    "${runtime_image}" >/dev/null || return 1
  podman start "${container_name}" >/dev/null || return 1
  wait_until_healthy || return 1

  podman exec "${container_name}" ldapwhoami \
    -x -H ldap://127.0.0.1:1389 \
    -D uid=alice,ou=people,dc=example-app,dc=services,dc=example,dc=org \
    -w app-user-password \
    | grep -F -q 'dn:uid=alice,ou=people,dc=example-app,dc=services,dc=example,dc=org' || return 1
  if podman exec "${container_name}" ldapwhoami \
    -x -H ldap://127.0.0.1:1389 \
    -D uid=alice,ou=people,dc=example-app,dc=services,dc=example,dc=org \
    -w default-user-password >/dev/null 2>&1; then
    return 1
  fi
  podman exec "${container_name}" ldapsearch \
    -LLL -x -H ldap://127.0.0.1:1389 \
    -D cn=application,ou=services,dc=example-app,dc=services,dc=example,dc=org \
    -w app-bind-password \
    -b uid=alice,ou=people,dc=example-app,dc=services,dc=example,dc=org -s base \
    uid memberOf \
    | grep -F -q 'memberOf: cn=staff,ou=groups,dc=example-app,dc=services,dc=example,dc=org' || return 1
}

main() {
  trap cleanup EXIT
  trap 'exit 130' HUP INT TERM

  build_images || fail 'Cannot build test images'
  prepare_inputs || fail 'Cannot prepare generator inputs'
  log 'Generating signed service-specific snapshots'
  generate_snapshots || fail 'Snapshot generation test failed'
  log 'Testing generator rejection paths'
  test_generator_rejections || fail 'Generator rejection test failed'
  log 'Importing and authenticating against generated output'
  consume_generated_snapshot || fail 'Generated snapshot runtime test failed'
  log 'Generator integration tests passed'
}

main "$@"
