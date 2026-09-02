#!/usr/bin/env sh

# Run direct repository-specific static, schema, and host behavior checks.

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
  for command_name in checkbashisms hadolint jq shellcheck shfmt uv; do
    require_command "${command_name}" || return 1
  done

  cd "${project_dir}" || return 1

  printf '%s\n' 'Checking POSIX shell sources'
  sh -n scripts/*.sh tests/*.sh hack/*.sh examples/systemd/openldap-expiry-backstop || return 1
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

  printf '%s\n' 'Checking Python and JSON contracts'
  uv run --frozen ruff format --check \
    generator/generate.py tests/test_snapshot_manifest.py \
    tests/test_repository_policy.py tests/validate_snapshot_manifest.py || return 1
  uv run --frozen ruff check \
    generator/generate.py tests/test_snapshot_manifest.py \
    tests/test_repository_policy.py tests/validate_snapshot_manifest.py || return 1
  uv run --frozen mypy || return 1
  uv run --frozen pytest || return 1
  for schema_file in schema/*.json; do
    jq -e . "${schema_file}" >/dev/null || return 1
  done
  jq -e . examples/policy/containers-policy.json renovate.json >/dev/null || return 1

  printf '%s\n' 'Checking the Quadlet deployment definition'
  QUADLET_UNIT_DIRS="${project_dir}/examples/quadlet" \
    /usr/lib/systemd/user-generators/podman-user-generator -user -dryrun >/dev/null || return 1

  sh tests/host-backstop.sh || return 1

  printf '%s\n' \
    'Direct checks passed; ConClear owns OCI checks, pin validation, exact-image integration, and qualification.'
}

main "$@"
