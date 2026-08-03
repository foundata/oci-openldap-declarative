#!/usr/bin/env sh

# Exercise the rootless host backstop without touching real Podman resources.

set -u

project_dir=$(CDPATH='' cd "$(dirname "$0")/.." && pwd) || exit 1
readonly project_dir
readonly backstop_script="${project_dir}/examples/systemd/openldap-expiry-backstop"

workspace=''

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  if [ -n "${workspace}" ] && [ -d "${workspace}" ]; then
    rm -rf "${workspace}"
  fi
}

write_podman_stub() {
  cat >"${workspace}/podman" <<'EOF'
#!/usr/bin/env sh
set -u

printf '%s\n' "$*" >>"${PODMAN_CALLS}"

case "$*" in
  'container exists test-directory')
    [ "${CONTAINER_EXISTS}" = true ]
    ;;
  'container inspect --format {{.State.Running}} test-directory')
    printf '%s\n' "${CONTAINER_RUNNING}"
    ;;
  'healthcheck run test-directory')
    [ "${CONTAINER_HEALTHY}" = true ]
    ;;
  'stop --time 10 test-directory')
    exit 0
    ;;
  *)
    exit 2
    ;;
esac
EOF
  chmod 0755 "${workspace}/podman"
}

run_backstop() {
  CONTAINER_EXISTS=${1} \
    CONTAINER_RUNNING=${2} \
    CONTAINER_HEALTHY=${3} \
    PODMAN_CALLS="${workspace}/calls" \
    PODMAN="${workspace}/podman" \
    "${backstop_script}" test-directory
}

main() {
  trap cleanup EXIT
  trap 'exit 130' HUP INT TERM

  workspace=$(mktemp -d /tmp/openldap-backstop-test.XXXXXX) || fail 'Cannot create test directory'
  write_podman_stub || fail 'Cannot create Podman test double'

  : >"${workspace}/calls"
  run_backstop true true true || fail 'Healthy container was rejected'
  if grep -F -q 'stop --time' "${workspace}/calls"; then
    fail 'Healthy container was stopped'
  fi

  : >"${workspace}/calls"
  if run_backstop true true false >/dev/null 2>&1; then
    fail 'Unhealthy container was accepted'
  fi
  grep -F -q 'stop --time 10 test-directory' "${workspace}/calls" \
    || fail 'Unhealthy container was not stopped'

  : >"${workspace}/calls"
  if run_backstop true false false >/dev/null 2>&1; then
    fail 'Stopped container was accepted'
  fi
  if grep -F -q 'stop --time' "${workspace}/calls"; then
    fail 'Already stopped container received another stop request'
  fi

  : >"${workspace}/calls"
  if run_backstop false false false >/dev/null 2>&1; then
    fail 'Missing container was accepted'
  fi

  printf '%s\n' 'Host backstop tests passed'
}

main "$@"
