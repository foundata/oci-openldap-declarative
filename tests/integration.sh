#!/usr/bin/env sh

# Exercise the signed snapshot contract in rootless Podman containers.

set -u

project_dir=$(CDPATH='' cd "$(dirname "$0")/.." && pwd) || exit 1
readonly project_dir
readonly backstop_script="${project_dir}/examples/systemd/openldap-expiry-backstop"
# shellcheck source=tests/test-lib.sh
. "${project_dir}/tests/test-lib.sh"

test_mode=${1:-}
image_ref=''
container_names=''
volume_names=''
created_container_name=''
created_runtime_volume=''
valid_state_volume=''

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
    testlib_finish
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
  podman image rm "${image_ref}" >/dev/null 2>&1 || true
  testlib_finish
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
      'description: internal snapshot metadata' \
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
  testlib_plan_volume "${volume_name}" || return 1
  podman volume create "${volume_name}" >/dev/null || return 1
  remember_volume "${volume_name}"
}

create_container() {
  test_name=${1}
  snapshot_name=${2}
  expected_service_id=${3}
  state_volume=${4}
  transport=${5:-ldap}
  key_mode=${6:-file}
  extra_environment=${7:-LDAP_TLS_CA_FILE=/tls/ca.pem}
  container_name=${resource_prefix}-${test_name}
  runtime_volume=${container_name}-runtime

  case "${key_mode}" in
    directory)
      public_key_environment=LDAP_SNAPSHOT_PUBLIC_KEY_DIR=/run/credentials/snapshot-public-keys
      public_key_mount=${workspace}/public:/run/credentials/snapshot-public-keys:ro,Z
      ;;
    file)
      public_key_environment=LDAP_SNAPSHOT_PUBLIC_KEY_FILE=/run/credentials/snapshot-public-key
      public_key_mount=${workspace}/public/snapshot.pub:/run/credentials/snapshot-public-key:ro,Z
      ;;
    rotated)
      public_key_environment=LDAP_SNAPSHOT_PUBLIC_KEY_FILE=/run/credentials/snapshot-public-key
      public_key_mount=${workspace}/public/rotated.pub:/run/credentials/snapshot-public-key:ro,Z
      ;;
    *) return 1 ;;
  esac

  create_volume "${runtime_volume}" || return 1
  if ! podman volume exists "${state_volume}"; then
    create_volume "${state_volume}" || return 1
  fi

  testlib_plan_container "${container_name}" || return 1
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
    --health-cmd /usr/local/lib/openldap-declarative/healthcheck.sh \
    --health-timeout 3s \
    --env "LDAP_EXPECTED_SERVICE_ID=${expected_service_id}" \
    --env "LDAP_TRANSPORT=${transport}" \
    --env "${public_key_environment}" \
    --env "${extra_environment}" \
    --mount "type=volume,source=${runtime_volume},destination=/run/openldap" \
    --mount "type=volume,source=${state_volume},destination=/state" \
    --volume "${workspace}/${snapshot_name}:/snapshot:ro,Z" \
    --volume "${public_key_mount}" \
    --volume "${workspace}/admin:/run/credentials/admin:ro,Z" \
    --volume "${workspace}/tls:/tls:ro,Z" \
    "${image_ref}" >/dev/null || return 1
  remember_container "${container_name}"
  created_container_name=${container_name}
  created_runtime_volume=${runtime_volume}
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
  expected_message=${3:-}

  podman start "${container_name}" >/dev/null || return 1
  actual_status=$(timeout 180 podman wait "${container_name}") || {
    podman logs "${container_name}" >&2 || true
    return 1
  }
  if [ "${actual_status}" -ne "${expected_status}" ]; then
    podman logs "${container_name}" >&2 || true
    printf 'Expected %s to exit %s, got %s\n' "${container_name}" "${expected_status}" "${actual_status}" >&2
    return 1
  fi
  if [ -n "${expected_message}" ] \
    && ! podman logs "${container_name}" 2>&1 | grep -F -q "${expected_message}"; then
    podman logs "${container_name}" >&2 || true
    printf 'Expected %s to log: %s\n' "${container_name}" "${expected_message}" >&2
    return 1
  fi

  assert_verified_plaintext_absent "${container_name}-runtime" || return 1

  return 0
}

assert_verified_plaintext_absent() {
  inspected_volume=${1}

  podman run --rm \
    --network none \
    --read-only \
    --cap-drop=all \
    --security-opt=no-new-privileges \
    --entrypoint sh \
    --mount "type=volume,source=${inspected_volume},destination=/inspect,ro" \
    "${image_ref}" -c \
    'test ! -e /inspect/verified-snapshot && test ! -e /inspect/verified-files'
}

assert_valid_runtime() {
  container_name=${1}

  status_output=$(podman exec "${container_name}" \
    /usr/local/lib/openldap-declarative/status.sh) || return 1
  printf '%s\n' "${status_output}" | jq -e \
    '.state == "healthy"
      and .ldap == "available"
      and .service_id == "test-service"
      and .revision == 1
      and .seconds_until_hard_expiry > 0' >/dev/null || return 1

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
    uid entryUUID memberOf description userPassword) || return 1
  printf '%s\n' "${search_output}" | grep -F -q 'entryUUID: a4bcb5de-4982-51e9-b7e8-7e8d6b6f4c22' || return 1
  printf '%s\n' "${search_output}" | grep -F -q 'memberOf: cn=users,ou=groups,dc=example,dc=org' || return 1
  if printf '%s\n' "${search_output}" | grep -F -q 'userPassword'; then
    return 1
  fi
  if printf '%s\n' "${search_output}" | grep -F -q 'description:'; then
    return 1
  fi

  enumeration_output=$(podman exec "${container_name}" ldapsearch \
    -LLL -x -H ldap://127.0.0.1:1389 \
    -D cn=app,ou=services,dc=example,dc=org \
    -w test-bind-password \
    -b dc=example,dc=org -s sub '(objectClass=*)' \
    dn uid cn description userPassword) || return 1
  printf '%s\n' "${enumeration_output}" \
    | grep -F -q 'dn: uid=test,ou=people,dc=example,dc=org' || return 1
  printf '%s\n' "${enumeration_output}" \
    | grep -F -q 'dn: cn=users,ou=groups,dc=example,dc=org' || return 1
  if printf '%s\n' "${enumeration_output}" \
    | grep -E -q '^(description|userPassword):'; then
    return 1
  fi
  if podman exec "${container_name}" ldapsearch \
    -LLL -x -H ldap://127.0.0.1:1389 \
    -D cn=app,ou=services,dc=example,dc=org \
    -w test-bind-password \
    -b cn=config -s base olcRootPW >/dev/null 2>&1; then
    return 1
  fi

  if printf '%s\n' \
    'dn: dc=example,dc=org' \
    'changetype: modify' \
    'replace: description' \
    'description: changed at runtime' \
    | podman exec -i "${container_name}" ldapmodify \
      -Q -Y EXTERNAL -H ldapi://%2Frun%2Fopenldap%2Fldapi >/dev/null 2>&1; then
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
    test ! -e /run/openldap/verified-snapshot
    test ! -e /run/openldap/verified-files
    if grep -R -F -q "nis.ldif" /run/openldap/slapd.d; then
      exit 1
    fi
  ' || return 1

  return 0
}

prepare_workspace() {
  mkdir -p "${workspace}/admin" "${workspace}/private" "${workspace}/public" "${workspace}/tls" || return 1

  run_image_tool minisign \
    -G -W \
    -p /work/public/snapshot.pub \
    -s /work/private/snapshot.key >/dev/null || return 1
  run_image_tool minisign \
    -G -W \
    -p /work/public/rotated.pub \
    -s /work/private/rotated.key >/dev/null || return 1
  write_directory_ldif "${workspace}/directory.ldif" || return 1

  openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 \
    -subj '/CN=localhost' \
    -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
    -keyout "${workspace}/tls/cert.key" \
    -out "${workspace}/tls/cert.pem" >/dev/null 2>&1 || return 1
  cp "${workspace}/tls/cert.pem" "${workspace}/tls/ca.pem" || return 1
  printf '%s\n' 'recovery-root-password' >"${workspace}/admin/lf-password"
  printf '%s\r\n' 'recovery-root-password' >"${workspace}/admin/crlf-password"
  chmod 0755 "${workspace}" "${workspace}/admin" "${workspace}/public" "${workspace}/tls"
  chmod 0644 "${workspace}/admin/lf-password" "${workspace}/admin/crlf-password"
  chmod 0644 "${workspace}/public/snapshot.pub" "${workspace}/tls/cert.pem" "${workspace}/tls/ca.pem"
  chmod 0600 "${workspace}/private/snapshot.key" "${workspace}/private/rotated.key"
  # This test-only key is mounted read-only into a user-namespaced container.
  chmod 0644 "${workspace}/tls/cert.key"

  backstop_container=${resource_prefix}-backstop
  testlib_plan_container "${backstop_container}" || return 1
  cat >"${workspace}/podman-backstop" <<EOF
#!/usr/bin/env sh
if [ "\${1:-}" = run ]; then
  shift
  exec "${podman_binary}" --root "${podman_root}" --runroot "${podman_runroot}" \\
    run --name "${backstop_container}" "\$@"
fi
exec "${podman_binary}" --root "${podman_root}" --runroot "${podman_runroot}" "\$@"
EOF
  chmod 0700 "${workspace}/podman-backstop" || return 1
}

test_valid_snapshot() {
  state_volume=${resource_prefix}-state
  create_snapshot valid 1 '+10 minutes' '+20 minutes' || return 1
  create_container valid valid test-service "${state_volume}" ldap || return 1
  container_name=${created_container_name}
  podman start "${container_name}" >/dev/null || return 1
  wait_until_healthy "${container_name}" || return 1
  assert_valid_runtime "${container_name}" || return 1
  PODMAN="${workspace}/podman-backstop" \
    "${backstop_script}" "${container_name}" \
    "${workspace}/valid" "${workspace}/public/snapshot.pub" test-service || return 1
  podman stop --time 3 "${container_name}" >/dev/null || return 1
  exit_status=$(podman inspect "${container_name}" --format '{{.State.ExitCode}}') || return 1
  [ "${exit_status}" -eq 0 ] || return 1
  assert_verified_plaintext_absent "${created_runtime_volume}" || return 1

  create_container key-directory valid test-service "${resource_prefix}-key-directory-state" ldap directory || return 1
  key_directory_container=${created_container_name}
  podman start "${key_directory_container}" >/dev/null || return 1
  wait_until_healthy "${key_directory_container}" || return 1
  podman stop --time 3 "${key_directory_container}" >/dev/null || return 1

  valid_state_volume=${state_volume}
}

test_admin_password_files() {
  for password_file in lf-password crlf-password; do
    create_container "admin-${password_file}" valid test-service \
      "${resource_prefix}-admin-${password_file}-state" ldap file \
      "LDAP_ADMIN_PASSWORD_FILE=/run/credentials/admin/${password_file}" || return 1
    container_name=${created_container_name}
    podman start "${container_name}" >/dev/null || return 1
    wait_until_healthy "${container_name}" || return 1
    podman exec "${container_name}" ldapwhoami \
      -x -H ldap://127.0.0.1:1389 \
      -D cn=admin,dc=example,dc=org \
      -w recovery-root-password \
      | grep -F -q 'dn:cn=admin,dc=example,dc=org' || return 1
    podman stop --time 3 "${container_name}" >/dev/null || return 1
  done
}

test_immediate_shutdown() {
  create_container immediate-stop valid test-service \
    "${resource_prefix}-immediate-stop-state" ldap || return 1
  container_name=${created_container_name}
  podman start "${container_name}" >/dev/null || return 1
  podman stop --time 3 "${container_name}" >/dev/null || return 1
  exit_status=$(podman inspect "${container_name}" --format '{{.State.ExitCode}}') || return 1
  [ "${exit_status}" -eq 0 ] || return 1
}

test_revision_replay() {
  state_volume=${1}
  create_snapshot revision-2 2 '+10 minutes' '+20 minutes' || return 1
  create_container revision-2 revision-2 test-service "${state_volume}" ldap || return 1
  revision_two_container=${created_container_name}
  podman start "${revision_two_container}" >/dev/null || return 1
  wait_until_healthy "${revision_two_container}" || return 1
  podman stop --time 3 "${revision_two_container}" >/dev/null || return 1

  create_container revision-2-repeat revision-2 test-service "${state_volume}" ldap || return 1
  revision_two_repeat_container=${created_container_name}
  podman start "${revision_two_repeat_container}" >/dev/null || return 1
  wait_until_healthy "${revision_two_repeat_container}" || return 1
  podman stop --time 3 "${revision_two_repeat_container}" >/dev/null || return 1

  cp -R "${workspace}/revision-2" "${workspace}/revision-2-conflict" || return 1
  sed -i '/^o: Example$/a description: conflicting content' \
    "${workspace}/revision-2-conflict/directory.ldif" || return 1
  refresh_snapshot_signature "${workspace}/revision-2-conflict" || return 1
  create_container revision-2-conflict revision-2-conflict test-service "${state_volume}" ldap || return 1
  revision_two_conflict_container=${created_container_name}
  expect_container_exit "${revision_two_conflict_container}" 65 \
    'was already accepted with different content' || return 1

  create_container replay valid test-service "${state_volume}" ldap || return 1
  replay_container=${created_container_name}
  expect_container_exit "${replay_container}" 65 'is older than accepted revision' || return 1
}

run_revision_preflight_case() {
  case_name=${1}
  state_content=${2}
  expected_status=${3}
  expected_message=${4}
  state_directory=${workspace}/preflight-${case_name}
  state_path=${state_directory}/highest-revision

  mkdir -m 0755 "${state_directory}" || return 1
  if [ "${state_content}" != absent ]; then
    printf '%s\n' "${state_content}" >"${state_path}" || return 1
    chmod 0644 "${state_path}" || return 1
    state_digest_before=$(sha256sum "${state_path}") || return 1
  else
    state_digest_before=absent
  fi

  preflight_output=$(podman run --rm \
    --network none \
    --read-only \
    --userns keep-id:uid=1001,gid=1001 \
    --user 1001:1001 \
    --cap-drop=all \
    --security-opt=no-new-privileges \
    --tmpfs /run/openldap:rw,noexec,nosuid,nodev,size=20m,mode=0700 \
    --volume "${workspace}/valid:/candidate:ro,Z" \
    --volume "${workspace}/public/snapshot.pub:/keys/snapshot.pub:ro,Z" \
    --volume "${state_directory}:/existing-state:ro,Z" \
    --entrypoint /usr/local/lib/openldap-declarative/preflight-snapshot.sh \
    "${image_ref}" \
    /candidate /keys/snapshot.pub test-service /existing-state/highest-revision 2>&1)
  preflight_status=$?
  if [ "${preflight_status}" -ne "${expected_status}" ] \
    || ! printf '%s\n' "${preflight_output}" | grep -F -q "${expected_message}"; then
    printf '%s\n' "${preflight_output}" >&2
    return 1
  fi

  if [ "${state_content}" = absent ]; then
    [ ! -e "${state_path}" ] || return 1
  else
    state_digest_after=$(sha256sum "${state_path}") || return 1
    [ "${state_digest_after}" = "${state_digest_before}" ] || return 1
  fi
}

test_revision_preflight() {
  manifest_digest=$(sha256sum "${workspace}/valid/manifest.json" | cut -d ' ' -f 1) || return 1
  run_revision_preflight_case new absent 0 '(new)' || return 1
  run_revision_preflight_case exact "1 ${manifest_digest}" 0 '(exact-replay)' || return 1
  run_revision_preflight_case legacy 1 0 '(legacy-state-migration)' || return 1
  run_revision_preflight_case lower "2 ${manifest_digest}" 65 \
    'is older than accepted revision 2' || return 1
  run_revision_preflight_case malformed 'not-a-revision' 66 \
    'does not contain a non-negative integer' || return 1
  run_revision_preflight_case conflict "1 0000000000000000000000000000000000000000000000000000000000000000" 65 \
    'was already accepted with different content'
}

test_rejected_snapshots() {
  cp -R "${workspace}/valid" "${workspace}/tampered" || return 1
  printf '%s\n' '# tampered' >>"${workspace}/tampered/directory.ldif"
  create_container tampered tampered test-service "${resource_prefix}-tampered-state" ldap || return 1
  tampered_container=${created_container_name}
  expect_container_exit "${tampered_container}" 65 \
    'Snapshot data digest does not match the manifest' || return 1

  cp -R "${workspace}/valid" "${workspace}/tampered-manifest" || return 1
  jq '.revision = 99' "${workspace}/tampered-manifest/manifest.json" \
    >"${workspace}/tampered-manifest/manifest.json.new" || return 1
  mv "${workspace}/tampered-manifest/manifest.json.new" \
    "${workspace}/tampered-manifest/manifest.json" || return 1
  create_container tampered-manifest tampered-manifest test-service \
    "${resource_prefix}-tampered-manifest-state" ldap || return 1
  tampered_manifest_container=${created_container_name}
  expect_container_exit "${tampered_manifest_container}" 65 \
    'Snapshot manifest signature verification failed' || return 1

  cp -R "${workspace}/valid" "${workspace}/unsigned" || return 1
  unlink "${workspace}/unsigned/manifest.json.minisig" || return 1
  create_container unsigned unsigned test-service \
    "${resource_prefix}-unsigned-state" ldap || return 1
  unsigned_container=${created_container_name}
  expect_container_exit "${unsigned_container}" 66 \
    'Required input is not a regular file: /snapshot/manifest.json.minisig' || return 1

  create_container wrong-key valid test-service \
    "${resource_prefix}-wrong-key-state" ldap rotated || return 1
  wrong_key_container=${created_container_name}
  expect_container_exit "${wrong_key_container}" 65 \
    'Snapshot manifest signature verification failed' || return 1

  create_container wrong-service valid another-service "${resource_prefix}-wrong-state" ldap || return 1
  wrong_service_container=${created_container_name}
  expect_container_exit "${wrong_service_container}" 65 \
    'Snapshot service ID does not match LDAP_EXPECTED_SERVICE_ID' || return 1

  create_snapshot expired 3 '-2 minutes' '-1 minute' '-3 minutes' || return 1
  create_container expired expired test-service "${resource_prefix}-expired-state" ldap || return 1
  expired_container=${created_container_name}
  expect_container_exit "${expired_container}" 78 'Snapshot has expired' || return 1

  create_snapshot missing-uuid 4 '+10 minutes' '+20 minutes' || return 1
  sed -i '/entryUUID: a4bcb5de-4982-51e9-b7e8-7e8d6b6f4c22/d' \
    "${workspace}/missing-uuid/directory.ldif" || return 1
  refresh_snapshot_signature "${workspace}/missing-uuid" || return 1
  create_container missing-uuid missing-uuid test-service "${resource_prefix}-uuid-state" ldap || return 1
  missing_uuid_container=${created_container_name}
  expect_container_exit "${missing_uuid_container}" 65 \
    'Every directory entryUUID must be a lowercase UUIDv5 value' || return 1

  create_snapshot weak-password 5 '+10 minutes' '+20 minutes' || return 1
  sed -i '0,/^userPassword: /s|^userPassword: .*|userPassword: {CLEARTEXT}weak|' \
    "${workspace}/weak-password/directory.ldif" || return 1
  refresh_snapshot_signature "${workspace}/weak-password" || return 1
  create_container weak-password weak-password test-service "${resource_prefix}-password-state" ldap || return 1
  weak_password_container=${created_container_name}
  expect_container_exit "${weak_password_container}" 65 \
    'Every userPassword must use a valid Argon2id verifier' || return 1

  create_snapshot inconsistent-membership 6 '+10 minutes' '+20 minutes' || return 1
  sed -i '/^memberOf: cn=users,ou=groups,dc=example,dc=org$/d' \
    "${workspace}/inconsistent-membership/directory.ldif" || return 1
  refresh_snapshot_signature "${workspace}/inconsistent-membership" || return 1
  create_container inconsistent-membership inconsistent-membership test-service \
    "${resource_prefix}-membership-state" ldap || return 1
  inconsistent_membership_container=${created_container_name}
  expect_container_exit "${inconsistent_membership_container}" 65 \
    'member and memberOf attributes must describe the same relationships' || return 1

  cp -R "${workspace}/valid" "${workspace}/too-many-files" || return 1
  digest=$(sha256sum "${workspace}/too-many-files/directory.ldif" | cut -d ' ' -f 1) || return 1
  jq --arg digest "${digest}" \
    '.files = [range(0; 33) as $index | {path: ("directory-" + ($index | tostring) + ".ldif"), sha256: $digest}]' \
    "${workspace}/too-many-files/manifest.json" >"${workspace}/too-many-files/manifest.json.new" || return 1
  mv "${workspace}/too-many-files/manifest.json.new" \
    "${workspace}/too-many-files/manifest.json" || return 1
  sign_manifest "${workspace}/too-many-files" || return 1
  create_container too-many-files too-many-files test-service "${resource_prefix}-file-count-state" ldap || return 1
  too_many_files_container=${created_container_name}
  expect_container_exit "${too_many_files_container}" 65 \
    'Snapshot manifest does not match format version 1' || return 1
}

test_runtime_expiry() {
  create_snapshot short-lived 7 '+10 seconds' '+30 seconds' || return 1
  create_container expiry short-lived test-service "${resource_prefix}-expiry-state" ldap || return 1
  container_name=${created_container_name}
  expect_container_exit "${container_name}" 78 || return 1
  podman logs "${container_name}" 2>&1 | grep -F -q 'active directory snapshot has expired' || return 1
}

test_soft_deadline_status() {
  create_snapshot soft-deadline 8 '+10 seconds' '+2 minutes' || return 1
  create_container soft-deadline soft-deadline test-service \
    "${resource_prefix}-soft-deadline-state" ldap || return 1
  container_name=${created_container_name}
  podman start "${container_name}" >/dev/null || return 1
  wait_until_healthy "${container_name}" || return 1

  wait_iteration=0
  while [ "${wait_iteration}" -lt 40 ]; do
    status_output=$(podman exec "${container_name}" \
      /usr/local/lib/openldap-declarative/status.sh 2>/dev/null)
    status_exit=$?
    if [ "${status_exit}" -eq 1 ]; then
      printf '%s\n' "${status_output}" | jq -e \
        '.state == "soft-expired"
          and .ldap == "available"
          and .revision == 8
          and .seconds_until_soft_expiry <= 0
          and .seconds_until_hard_expiry > 0' >/dev/null || return 1
      podman exec "${container_name}" \
        /usr/local/lib/openldap-declarative/healthcheck.sh >/dev/null 2>&1 || return 1
      podman stop --time 3 "${container_name}" >/dev/null || return 1
      return 0
    fi
    if [ "${status_exit}" -eq 2 ]; then
      return 1
    fi
    wait_iteration=$((wait_iteration + 1))
    sleep 0.25
  done

  return 1
}

test_watchdog_failure() {
  create_container watchdog-failure valid test-service "${resource_prefix}-watchdog-state" ldap || return 1
  container_name=${created_container_name}
  podman start "${container_name}" >/dev/null || return 1
  wait_until_healthy "${container_name}" || return 1
  podman exec "${container_name}" sh -c 'kill "$(cat /run/openldap/watchdog.pid)"' || return 1
  actual_status=$(timeout 180 podman wait "${container_name}") || return 1
  [ "${actual_status}" -eq 75 ] || return 1
  podman logs "${container_name}" 2>&1 \
    | grep -F -q 'snapshot expiry watchdog failed' || return 1
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
      -verify_hostname localhost \
      -tls1_2 </dev/null 2>&1 |
      grep -F -q "Verify return code: 0 (ok)"
  ' || return 1
  if podman exec "${container_name}" sh -c '
    openssl s_client \
      -connect 127.0.0.1:1636 \
      -servername localhost \
      -CAfile /tls/ca.pem \
      -verify_return_error \
      -tls1_1 </dev/null >/dev/null 2>&1
  '; then
    return 1
  fi
  podman stop --time 3 "${container_name}" >/dev/null || return 1

  create_container tls-missing-ca valid test-service "${resource_prefix}-tls-missing-ca-state" \
    ldaps file LDAP_TLS_CA_FILE=/tls/missing.pem || return 1
  tls_missing_ca_container=${created_container_name}
  expect_container_exit "${tls_missing_ca_container}" 66 || return 1
}

test_image_contents() {
  image_size=$(podman image inspect "${image_ref}" --format '{{.Size}}') || return 1
  [ "${image_size}" -lt 170000000 ] || return 1

  podman run --rm --entrypoint sh "${image_ref}" -c '
    test "$(id -u):$(id -g)" = 1001:1001 || exit 1
    test -s /usr/local/share/openldap-declarative/package-versions.txt || exit 1
    test -s /usr/local/share/openldap-declarative/LICENSE.txt || exit 1
    test -s /usr/share/doc/slapd/copyright || exit 1
    test ! -e /DESIGN.md || exit 1
    test ! -e /TEMP-Notes || exit 1
    test -s /usr/lib/ldap/back_mdb.so || exit 1
    test -s /usr/lib/ldap/argon2.so || exit 1
    test -s /usr/lib/ldap/memberof.so || exit 1
    for input_path in /snapshot /tls /run/credentials; do
      test "$(stat -c "%u:%g:%a" "${input_path}")" = 0:0:555 || exit 1
    done
    for writable_path in /run/openldap /state; do
      test "$(stat -c "%u:%g:%a" "${writable_path}")" = 1001:1001:700 || exit 1
    done
    test "$(stat -c "%u:%g:%a" /usr/local/share/openldap-declarative/LICENSE.txt)" \
      = 0:0:444 || exit 1
    for immutable_file in /usr/local/lib/openldap-declarative/*.sh; do
      ownership_and_mode=$(stat -c "%u:%g:%a" "${immutable_file}") || exit 1
      if [ "${ownership_and_mode}" != 0:0:555 ]; then
        printf "Unexpected ownership or mode for %s: %s\n" \
          "${immutable_file}" "${ownership_and_mode}" >&2
        exit 1
      fi
      if chmod u+w "${immutable_file}" 2>/dev/null; then
        printf "Runtime user can make immutable file writable: %s\n" \
          "${immutable_file}" >&2
        exit 1
      fi
    done
    if find /usr/lib/ldap -mindepth 1 \
      ! -name "back_mdb.*" \
      ! -name "argon2.*" \
      ! -name "memberof.*" | grep -q .; then
      printf "%s\n" "Unexpected OpenLDAP module in runtime image" >&2
      exit 1
    fi
    for unwanted_tool in cc gcc make sudo vim ip ping ps; do
      if command -v "${unwanted_tool}" >/dev/null 2>&1; then
        printf "Unexpected runtime tool: %s\n" "${unwanted_tool}" >&2
        exit 1
      fi
    done
  ' || return 1
}

main() {
  if [ "$#" -ne 1 ]; then
    fail 'Select exactly one test mode'
  fi
  testlib_init "${test_mode}" runtime-integration || exit $?
  trap cleanup EXIT
  trap 'exit 130' HUP INT TERM

  image_ref=localhost/${resource_prefix}:runtime
  case "${test_mode}" in
    --conclear)
      testlib_import_image primary runtime "${image_ref}" \
        || fail 'Cannot import the exact ConClear runtime layout'
      ;;
    --developer-build)
      testlib_record developer-image "${image_ref}"
      revision=$(git -C "${project_dir}" rev-parse HEAD) || fail 'Cannot resolve source revision'
      created=$(date -u +%Y-%m-%dT%H:%M:%SZ) || fail 'Cannot determine build time'
      log 'Building a non-release runtime image for developer testing'
      podman build --pull=always --tag "${image_ref}" \
        --build-arg "IMAGE_CREATED=${created}" \
        --build-arg "IMAGE_REVISION=${revision}" \
        --build-arg IMAGE_VERSION=developer-test \
        "${project_dir}" >/dev/null || fail 'Image build failed'
      ;;
    *) fail 'The selected mode is not valid for the runtime integration suite' ;;
  esac

  prepare_workspace || fail 'Cannot prepare signed test snapshots'
  test_image_contents || fail 'Runtime image contents do not match the production package boundary'

  log 'Testing a valid signed snapshot and graceful shutdown'
  test_valid_snapshot || fail 'Valid snapshot test failed'
  log 'Testing newline-terminated recovery password files'
  test_admin_password_files || fail 'Recovery password file test failed'
  log 'Testing shutdown during early initialization'
  test_immediate_shutdown || fail 'Immediate shutdown test failed'
  log 'Testing monotonic revision enforcement'
  test_revision_replay "${valid_state_volume}" || fail 'Revision replay test failed'
  log 'Testing non-listening staged revision preflight'
  test_revision_preflight || fail 'Revision preflight test failed'
  log 'Testing tampering, service identity, and startup expiry'
  test_rejected_snapshots || fail 'Rejected snapshot test failed'
  log 'Testing enforced runtime expiry'
  test_runtime_expiry || fail 'Runtime expiry test failed'
  log 'Testing soft-deadline monitoring status'
  test_soft_deadline_status || fail 'Soft-deadline status test failed'
  log 'Testing fail-closed watchdog supervision'
  test_watchdog_failure || fail 'Watchdog supervision test failed'
  log 'Testing certificate-validated LDAPS'
  test_tls || fail 'TLS test failed'

  log 'All integration tests passed'
}

main "$@"
