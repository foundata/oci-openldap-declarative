#!/usr/bin/env sh

# Run all static and rootless Podman integration checks.

set -u

project_dir=$(CDPATH='' cd "$(dirname "$0")/.." && pwd) || exit 1
readonly project_dir

require_command() {
  command_name=${1}
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    printf 'ERROR: required command is unavailable: %s\n' "${command_name}" >&2
    return 1
  fi
}

main() {
  for command_name in checkbashisms hadolint jq podman python3 shellcheck shfmt timeout; do
    require_command "${command_name}" || return 1
  done

  cd "${project_dir}" || return 1

  printf '%s\n' 'Checking POSIX shell sources'
  shfmt --language-dialect posix --indent 2 --case-indent \
    --binary-next-line --simplify --diff \
    scripts/*.sh tests/*.sh hack/*.sh examples/systemd/openldap-expiry-backstop || return 1
  shellcheck --shell=sh --severity=style \
    --exclude=SC2292 --exclude=SC3040 --exclude=SC3043 \
    --enable=all \
    scripts/*.sh tests/*.sh hack/*.sh examples/systemd/openldap-expiry-backstop || return 1
  checkbashisms \
    scripts/*.sh tests/*.sh hack/*.sh examples/systemd/openldap-expiry-backstop || return 1

  printf '%s\n' 'Checking Containerfiles'
  hadolint Containerfile Containerfile.generator || return 1

  printf '%s\n' 'Checking Python and JSON syntax'
  python3 - <<'PY' || return 1
from pathlib import Path

path = Path("generator/generate.py")
compile(path.read_text(encoding="utf-8"), str(path), "exec")
PY
  for schema_file in schema/*.json; do
    jq -e . "${schema_file}" >/dev/null || return 1
  done

  printf '%s\n' 'Checking the Quadlet deployment definition'
  QUADLET_UNIT_DIRS="${project_dir}/examples/quadlet" \
    /usr/lib/systemd/user-generators/podman-user-generator -user -dryrun >/dev/null || return 1

  sh tests/host-backstop.sh || return 1
  sh tests/release-scripts.sh || return 1
  sh tests/integration.sh || return 1
  sh tests/generator-integration.sh || return 1
}

main "$@"
