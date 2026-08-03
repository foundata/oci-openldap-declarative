#!/usr/bin/env sh

# Shared constants and logging for the container runtime scripts.

set -u

# shellcheck disable=SC2034  # These constants are consumed by sourcing scripts.
readonly EXIT_USAGE=64
# shellcheck disable=SC2034
readonly EXIT_SNAPSHOT=65
# shellcheck disable=SC2034
readonly EXIT_INPUT=66
# shellcheck disable=SC2034
readonly EXIT_INTERNAL=70
# shellcheck disable=SC2034
readonly EXIT_RUNTIME=75
# shellcheck disable=SC2034
readonly EXIT_EXPIRED=78

log_info() {
  printf '%s: %s\n' 'INFO' "$*"
}

log_warning() {
  printf '%s: %s\n' 'WARNING' "$*" >&2
}

log_error() {
  printf '%s: %s\n' 'ERROR' "$*" >&2
}

die() {
  exit_code="${1}"
  shift

  log_error "$*"
  exit "${exit_code}"
}
