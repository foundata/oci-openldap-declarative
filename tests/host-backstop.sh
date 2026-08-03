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

case "${1:-} ${2:-} ${3:-} ${4:-}" in
  'container exists test-directory ')
    [ "${CONTAINER_EXISTS}" = true ]
    ;;
  'container inspect --format {{.State.Running}}')
    printf '%s\n' "${CONTAINER_RUNNING}"
    ;;
  'container inspect --format {{.Image}}')
    printf '%s\n' 'sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
    ;;
  'run --rm --network none')
    [ "${SNAPSHOT_VALID}" = true ]
    ;;
  'healthcheck run test-directory ')
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
    SNAPSHOT_VALID=${3} \
    CONTAINER_HEALTHY=${4} \
    PODMAN_CALLS="${workspace}/calls" \
    PODMAN="${workspace}/podman" \
    "${backstop_script}" test-directory \
    "${workspace}/snapshot" "${workspace}/snapshot.pub" test-service
}

assert_stopped() {
  grep -F -q 'stop --time 10 test-directory' "${workspace}/calls" \
    || fail "${1} container was not stopped"
}

main() {
  trap cleanup EXIT
  trap 'exit 130' HUP INT TERM

  workspace=$(mktemp -d /tmp/openldap-backstop-test.XXXXXX) || fail 'Cannot create test directory'
  mkdir "${workspace}/snapshot" || fail 'Cannot create snapshot fixture'
  printf '%s\n' 'test public key' >"${workspace}/snapshot.pub" \
    || fail 'Cannot create public-key fixture'
  write_podman_stub || fail 'Cannot create Podman test double'

  : >"${workspace}/calls"
  run_backstop true true true true || fail 'Healthy signed snapshot was rejected'
  grep -F -q 'run --rm --network none --read-only' "${workspace}/calls" \
    || fail 'Host snapshot verifier was not isolated from the network'
  if grep -F -q 'stop --time' "${workspace}/calls"; then
    fail 'Healthy container was stopped'
  fi

  : >"${workspace}/calls"
  if run_backstop true true false true >/dev/null 2>&1; then
    fail 'Invalid host snapshot was accepted'
  fi
  assert_stopped 'Invalid-snapshot'
  if grep -F -q 'healthcheck run' "${workspace}/calls"; then
    fail 'Container health was trusted after host snapshot verification failed'
  fi

  : >"${workspace}/calls"
  if run_backstop true true true false >/dev/null 2>&1; then
    fail 'Unhealthy container was accepted'
  fi
  assert_stopped 'Unhealthy'

  : >"${workspace}/calls"
  if run_backstop true false false false >/dev/null 2>&1; then
    fail 'Stopped container was accepted'
  fi
  if grep -F -q 'stop --time' "${workspace}/calls"; then
    fail 'Already stopped container received another stop request'
  fi

  : >"${workspace}/calls"
  if run_backstop false false false false >/dev/null 2>&1; then
    fail 'Missing container was accepted'
  fi

  printf '%s\n' 'Host backstop tests passed'
}

main "$@"
