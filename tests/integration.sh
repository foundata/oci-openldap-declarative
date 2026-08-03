#!/usr/bin/env sh

# Exercise the signed snapshot contract in rootless Podman containers.

set -u

project_dir=$(CDPATH='' cd "$(dirname "$0")/.." && pwd) || exit 1
readonly project_dir
readonly image_ref="${IMAGE_REF:-localhost/oci-openldap-declarative:integration-test}"
readonly resource_prefix=ldap-declarative-test-$$

workspace=''
container_names=''
volume_names=''
created_container_name=''
valid_state_volume=''
built_image=0

log() {
  printf '%s\n' "==> $*"
}

fail() {
  printf '%s: %s\n' 'ERROR' "$*" >&2
  exit 1
}

remember_container() {
  container_names="${container_names} ${1}"
}

remember_volume() {
  volume_names="${volume_names} ${1}"
}

cleanup() {
  if [ "${KEEP_TEST_RESOURCES:-false}" = true ]; then
    log "Keeping test resources with prefix ${resource_prefix}"
    return 0
  fi

  for container_name in ${container_names}; do
    if podman container exists "${container_name}"; then
      podman container rm --force --volumes "${container_name}" >/dev/null 2>&1 || true
    fi
  done
  for volume_name in ${volume_names}; do
    if podman volume exists "${volume_name}"; then
      podman volume rm "${volume_name}" >/dev/null 2>&1 || true
    fi
  done
  if [ -n "${workspace}" ] && [ -d "${workspace}" ]; then
    rm -rf "${workspace}"
  fi
  if [ "${built_image}" -eq 1 ]; then
    podman image rm "${image_ref}" >/dev/null 2>&1 || true
  fi
}

run_image_tool() {
  tool_name=${1}
  shift

  podman run --rm \
    --user 0:0 \
    --entrypoint "${tool_name}" \
    --volume "${workspace}:/work:Z" \
    "${image_ref}" "$@"
}

write_directory_ldif() {
  destination=${1}
  user_hash=$(run_image_tool slappasswd \
    -o module-path=/usr/lib/ldap \
    -o 'module-load=argon2 m=19456 t=2 p=1' \
    -h '{ARGON2}' \
    -s 'test-user-password') || return 1
  service_hash=$(run_image_tool slappasswd \
    -o module-path=/usr/lib/ldap \
    -o 'module-load=argon2 m=19456 t=2 p=1' \
    -h '{ARGON2}' \
    -s 'test-bind-password') || return 1

  {
    printf '%s\n' \
      'dn: dc=example,dc=org' \
      'objectClass: top' \
      'objectClass: dcObject' \
      'objectClass: organization' \
      'dc: example' \
      'o: Example' \
      'entryUUID: 032e4d5a-6605-5d20-8d88-370c02d99f91' \
      '' \
      'dn: ou=people,dc=example,dc=org' \
      'objectClass: organizationalUnit' \
      'ou: people' \
      'entryUUID: 58b79d55-a592-57dc-839f-019da88df033' \
      '' \
      'dn: ou=groups,dc=example,dc=org' \
      'objectClass: organizationalUnit' \
      'ou: groups' \
      'entryUUID: 91d893b5-0871-5158-8548-3b7011e29444' \
      '' \
      'dn: ou=services,dc=example,dc=org' \
      'objectClass: organizationalUnit' \
      'ou: services' \
      'entryUUID: 107f56d7-a8c4-5b73-b0f6-44bd2194b221' \
      '' \
      'dn: uid=test,ou=people,dc=example,dc=org' \
      'objectClass: inetOrgPerson' \
      'uid: test' \
      'cn: Test User' \
      'sn: User' \
      'entryUUID: a4bcb5de-4982-51e9-b7e8-7e8d6b6f4c22' \
      'memberOf: cn=users,ou=groups,dc=example,dc=org' \
      "userPassword: ${user_hash}" \
      '' \
      'dn: cn=app,ou=services,dc=example,dc=org' \
      'objectClass: organizationalRole' \
      'objectClass: simpleSecurityObject' \
      'cn: app' \
      'entryUUID: f04d74d9-4295-5226-a6cb-72b3a94d92ef' \
      "userPassword: ${service_hash}" \
      '' \
      'dn: cn=users,ou=groups,dc=example,dc=org' \
      'objectClass: groupOfNames' \
      'cn: users' \
      'entryUUID: 03f6d440-aabe-59f5-83fb-3fa8bd132942' \
      'member: uid=test,ou=people,dc=example,dc=org'
  } >"${destination}"
}

sign_manifest() {
  snapshot_dir=${1}
  relative_snapshot=${snapshot_dir#"${workspace}"/}

  rm -f "${snapshot_dir}/manifest.json.minisig"
  run_image_tool minisign \
    -S -W \
    -s /work/private/snapshot.key \
    -m "/work/${relative_snapshot}/manifest.json" \
    -x "/work/${relative_snapshot}/manifest.json.minisig" \
    -t 'integration test snapshot' >/dev/null
}

refresh_snapshot_signature() {
  snapshot_dir=${1}
  digest=$(sha256sum "${snapshot_dir}/directory.ldif" | cut -d ' ' -f 1) || return 1
  jq --arg digest "${digest}" '.files[0].sha256 = $digest' \
    "${snapshot_dir}/manifest.json" >"${snapshot_dir}/manifest.json.new" || return 1
  mv "${snapshot_dir}/manifest.json.new" "${snapshot_dir}/manifest.json" || return 1
  sign_manifest "${snapshot_dir}" || return 1
}

create_snapshot() {
  snapshot_name=${1}
  revision=${2}
  soft_offset=${3}
  hard_offset=${4}
  generated_offset=${5:-now}
  snapshot_dir=${workspace}/${snapshot_name}

  mkdir -p "${snapshot_dir}" || return 1
  cp "${workspace}/directory.ldif" "${snapshot_dir}/directory.ldif" || return 1
  digest=$(sha256sum "${snapshot_dir}/directory.ldif" | cut -d ' ' -f 1) || return 1
  if [ "${generated_offset}" = now ]; then
    generated_at=$(date -u +%Y-%m-%dT%H:%M:%SZ) || return 1
  else
    generated_at=$(date -u -d "${generated_offset}" +%Y-%m-%dT%H:%M:%SZ) || return 1
  fi
  soft_expires_at=$(date -u -d "${soft_offset}" +%Y-%m-%dT%H:%M:%SZ) || return 1
  expires_at=$(date -u -d "${hard_offset}" +%Y-%m-%dT%H:%M:%SZ) || return 1

  jq -n \
    --arg generated_at "${generated_at}" \
    --arg soft_expires_at "${soft_expires_at}" \
    --arg expires_at "${expires_at}" \
    --arg digest "${digest}" \
    --argjson revision "${revision}" \
    '{
      format_version: 1,
      service_id: "test-service",
      base_dn: "dc=example,dc=org",
      revision: $revision,
      generated_at: $generated_at,
      soft_expires_at: $soft_expires_at,
      expires_at: $expires_at,
      uuid_namespace: "7f38d690-8427-5ca2-98b4-bd5ee71ac31f",
      files: [{path: "directory.ldif", sha256: $digest}]
    }' >"${snapshot_dir}/manifest.json" || return 1

  sign_manifest "${snapshot_dir}" || return 1
  chmod 0755 "${snapshot_dir}"
  chmod 0644 "${snapshot_dir}"/*
}

create_volume() {
  volume_name=${1}
  podman volume create "${volume_name}" >/dev/null || return 1
  remember_volume "${volume_name}"
}

create_container() {
  test_name=${1}
  snapshot_name=${2}
  expected_service_id=${3}
  state_volume=${4}
  transport=${5:-ldap}
  container_name=${resource_prefix}-${test_name}
  runtime_volume=${container_name}-runtime

  create_volume "${runtime_volume}" || return 1
  if ! podman volume exists "${state_volume}"; then
    create_volume "${state_volume}" || return 1
  fi

  podman create \
    --name "${container_name}" \
    --network none \
    --read-only \
    --read-only-tmpfs=false \
    --ulimit nofile=1024:1024 \
    --memory=256m \
    --pids-limit=128 \
    --cap-drop=all \
    --security-opt=no-new-privileges \
    --env "LDAP_EXPECTED_SERVICE_ID=${expected_service_id}" \
    --env "LDAP_TRANSPORT=${transport}" \
    --mount "type=volume,source=${runtime_volume},destination=/run/openldap" \
    --mount "type=volume,source=${state_volume},destination=/state" \
    --volume "${workspace}/${snapshot_name}:/snapshot:ro,Z" \
    --volume "${workspace}/public/snapshot.pub:/run/credentials/snapshot-public-key:ro,Z" \
    --volume "${workspace}/tls:/tls:ro,Z" \
    "${image_ref}" >/dev/null || return 1
  remember_container "${container_name}"
  created_container_name=${container_name}
}

wait_until_healthy() {
  container_name=${1}

  wait_iteration=0
  while [ "${wait_iteration}" -lt 80 ]; do
    container_state=$(podman inspect "${container_name}" --format '{{.State.Status}}') || return 1
    if [ "${container_state}" != running ]; then
      podman logs "${container_name}" >&2 || true
      return 1
    fi
    if podman exec "${container_name}" /usr/local/lib/openldap-declarative/healthcheck.sh >/dev/null 2>&1; then
      return 0
    fi
    wait_iteration=$((wait_iteration + 1))
    sleep 0.25
  done

  podman logs "${container_name}" >&2 || true
  return 1
}

expect_container_exit() {
  container_name=${1}
  expected_status=${2}

  podman start "${container_name}" >/dev/null || return 1
  actual_status=$(podman wait "${container_name}") || return 1
  if [ "${actual_status}" -ne "${expected_status}" ]; then
    podman logs "${container_name}" >&2 || true
    printf 'Expected %s to exit %s, got %s\n' "${container_name}" "${expected_status}" "${actual_status}" >&2
    return 1
  fi

  return 0
}

assert_valid_runtime() {
  container_name=${1}

  podman exec "${container_name}" ldapwhoami \
    -x -H ldap://127.0.0.1:1389 \
    -D uid=test,ou=people,dc=example,dc=org \
    -w test-user-password \
    | grep -F -q 'dn:uid=test,ou=people,dc=example,dc=org' || return 1

  search_output=$(podman exec "${container_name}" ldapsearch \
    -LLL -x -H ldap://127.0.0.1:1389 \
    -D cn=app,ou=services,dc=example,dc=org \
    -w test-bind-password \
    -b uid=test,ou=people,dc=example,dc=org -s base \
    uid entryUUID memberOf userPassword) || return 1
  printf '%s\n' "${search_output}" | grep -F -q 'entryUUID: a4bcb5de-4982-51e9-b7e8-7e8d6b6f4c22' || return 1
  printf '%s\n' "${search_output}" | grep -F -q 'memberOf: cn=users,ou=groups,dc=example,dc=org' || return 1
  if printf '%s\n' "${search_output}" | grep -F -q 'userPassword'; then
    return 1
  fi

  if podman exec "${container_name}" ldapsearch \
    -LLL -x -H ldap://127.0.0.1:1389 \
    -b dc=example,dc=org -s base dn >/dev/null 2>&1; then
    return 1
  fi

  readonly_root=$(podman inspect "${container_name}" --format '{{.HostConfig.ReadonlyRootfs}}') || return 1
  [ "${readonly_root}" = true ] || return 1
  podman exec "${container_name}" sh -c '
    slapd_pid=$(cat /run/openldap/slapd.pid) || exit 1
    grep -F -q "Max open files            1024                 1024" "/proc/${slapd_pid}/limits"
  ' || return 1

  return 0
}

prepare_workspace() {
  workspace=$(mktemp -d /tmp/openldap-declarative-integration.XXXXXX) || return 1
  mkdir -p "${workspace}/private" "${workspace}/public" "${workspace}/tls" || return 1

  run_image_tool minisign \
    -G -W \
    -p /work/public/snapshot.pub \
    -s /work/private/snapshot.key >/dev/null || return 1
  write_directory_ldif "${workspace}/directory.ldif" || return 1

  openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 \
    -subj '/CN=localhost' \
    -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
    -keyout "${workspace}/tls/cert.key" \
    -out "${workspace}/tls/cert.pem" >/dev/null 2>&1 || return 1
  cp "${workspace}/tls/cert.pem" "${workspace}/tls/ca.pem" || return 1
  chmod 0755 "${workspace}" "${workspace}/public" "${workspace}/tls"
  chmod 0644 "${workspace}/public/snapshot.pub" "${workspace}/tls/cert.pem" "${workspace}/tls/ca.pem"
  chmod 0600 "${workspace}/private/snapshot.key"
  # This test-only key is mounted read-only into a user-namespaced container.
  chmod 0644 "${workspace}/tls/cert.key"
}

test_valid_snapshot() {
  state_volume=${resource_prefix}-state
  create_snapshot valid 1 '+10 minutes' '+20 minutes' || return 1
  create_container valid valid test-service "${state_volume}" ldap || return 1
  container_name=${created_container_name}
  podman start "${container_name}" >/dev/null || return 1
  wait_until_healthy "${container_name}" || return 1
  assert_valid_runtime "${container_name}" || return 1
  podman stop --time 3 "${container_name}" >/dev/null || return 1
  exit_status=$(podman inspect "${container_name}" --format '{{.State.ExitCode}}') || return 1
  [ "${exit_status}" -eq 0 ] || return 1

  valid_state_volume=${state_volume}
}

test_revision_replay() {
  state_volume=${1}
  create_snapshot revision-2 2 '+10 minutes' '+20 minutes' || return 1
  create_container revision-2 revision-2 test-service "${state_volume}" ldap || return 1
  revision_two_container=${created_container_name}
  podman start "${revision_two_container}" >/dev/null || return 1
  wait_until_healthy "${revision_two_container}" || return 1
  podman stop --time 3 "${revision_two_container}" >/dev/null || return 1

  create_container replay valid test-service "${state_volume}" ldap || return 1
  replay_container=${created_container_name}
  expect_container_exit "${replay_container}" 65 || return 1
}

test_rejected_snapshots() {
  cp -R "${workspace}/valid" "${workspace}/tampered" || return 1
  printf '%s\n' '# tampered' >>"${workspace}/tampered/directory.ldif"
  create_container tampered tampered test-service "${resource_prefix}-tampered-state" ldap || return 1
  tampered_container=${created_container_name}
  expect_container_exit "${tampered_container}" 65 || return 1

  create_container wrong-service valid another-service "${resource_prefix}-wrong-state" ldap || return 1
  wrong_service_container=${created_container_name}
  expect_container_exit "${wrong_service_container}" 65 || return 1

  create_snapshot expired 3 '-2 minutes' '-1 minute' '-3 minutes' || return 1
  create_container expired expired test-service "${resource_prefix}-expired-state" ldap || return 1
  expired_container=${created_container_name}
  expect_container_exit "${expired_container}" 78 || return 1

  create_snapshot missing-uuid 4 '+10 minutes' '+20 minutes' || return 1
  sed -i '/entryUUID: a4bcb5de-4982-51e9-b7e8-7e8d6b6f4c22/d' \
    "${workspace}/missing-uuid/directory.ldif" || return 1
  refresh_snapshot_signature "${workspace}/missing-uuid" || return 1
  create_container missing-uuid missing-uuid test-service "${resource_prefix}-uuid-state" ldap || return 1
  missing_uuid_container=${created_container_name}
  expect_container_exit "${missing_uuid_container}" 65 || return 1

  create_snapshot weak-password 5 '+10 minutes' '+20 minutes' || return 1
  sed -i '0,/^userPassword: /s|^userPassword: .*|userPassword: {CLEARTEXT}weak|' \
    "${workspace}/weak-password/directory.ldif" || return 1
  refresh_snapshot_signature "${workspace}/weak-password" || return 1
  create_container weak-password weak-password test-service "${resource_prefix}-password-state" ldap || return 1
  weak_password_container=${created_container_name}
  expect_container_exit "${weak_password_container}" 65 || return 1

  create_snapshot inconsistent-membership 6 '+10 minutes' '+20 minutes' || return 1
  sed -i '/^memberOf: cn=users,ou=groups,dc=example,dc=org$/d' \
    "${workspace}/inconsistent-membership/directory.ldif" || return 1
  refresh_snapshot_signature "${workspace}/inconsistent-membership" || return 1
  create_container inconsistent-membership inconsistent-membership test-service \
    "${resource_prefix}-membership-state" ldap || return 1
  inconsistent_membership_container=${created_container_name}
  expect_container_exit "${inconsistent_membership_container}" 65 || return 1
}

test_runtime_expiry() {
  create_snapshot short-lived 7 '+3 seconds' '+8 seconds' || return 1
  create_container expiry short-lived test-service "${resource_prefix}-expiry-state" ldap || return 1
  container_name=${created_container_name}
  expect_container_exit "${container_name}" 78 || return 1
  podman logs "${container_name}" 2>&1 | grep -F -q 'active directory snapshot has expired' || return 1
}

test_tls() {
  create_container tls valid test-service "${resource_prefix}-tls-state" ldaps || return 1
  container_name=${created_container_name}
  podman start "${container_name}" >/dev/null || return 1
  wait_until_healthy "${container_name}" || return 1
  podman exec "${container_name}" sh -c '
    openssl s_client \
      -connect 127.0.0.1:1636 \
      -servername localhost \
      -CAfile /tls/ca.pem \
      -verify_return_error \
      -tls1_2 </dev/null 2>&1 |
      grep -F -q "Verify return code: 0 (ok)"
  ' || return 1
  podman stop --time 3 "${container_name}" >/dev/null || return 1
}

test_image_contents() {
  image_size=$(podman image inspect "${image_ref}" --format '{{.Size}}') || return 1
  [ "${image_size}" -lt 170000000 ] || return 1

  podman run --rm --entrypoint sh "${image_ref}" -c '
    for unwanted_tool in cc gcc make sudo vim ip ping ps; do
      if command -v "${unwanted_tool}" >/dev/null 2>&1; then
        printf "Unexpected runtime tool: %s\n" "${unwanted_tool}" >&2
        exit 1
      fi
    done
  ' || return 1
}

main() {
  trap cleanup EXIT
  trap 'exit 130' HUP INT TERM

  if [ "${BUILD_IMAGE:-true}" = true ]; then
    log 'Building the runtime image'
    podman build --pull=never --tag "${image_ref}" "${project_dir}" >/dev/null || fail 'Image build failed'
    built_image=1
  fi

  prepare_workspace || fail 'Cannot prepare signed test snapshots'
  test_image_contents || fail 'Runtime image contents do not match the production package boundary'

  log 'Testing a valid signed snapshot and graceful shutdown'
  test_valid_snapshot || fail 'Valid snapshot test failed'
  log 'Testing monotonic revision enforcement'
  test_revision_replay "${valid_state_volume}" || fail 'Revision replay test failed'
  log 'Testing tampering, service identity, and startup expiry'
  test_rejected_snapshots || fail 'Rejected snapshot test failed'
  log 'Testing enforced runtime expiry'
  test_runtime_expiry || fail 'Runtime expiry test failed'
  log 'Testing certificate-validated LDAPS'
  test_tls || fail 'TLS test failed'

  log 'All integration tests passed'
}

main "$@"
