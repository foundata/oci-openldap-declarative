#!/usr/bin/env sh

# Use the status probe, treating soft expiry as a warning rather than a failure.

set -u

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd) || exit 1

main() {
  status_code=0
  status_output=$("${script_dir}/status.sh") || status_code=$?
  revision=$(printf '%s\n' "${status_output}" | jq -r '.revision // "unknown"') || return 1

  case "${status_code}" in
    0)
      printf 'Snapshot revision %s is healthy\n' "${revision}"
      return 0
      ;;
    1)
      printf 'Snapshot revision %s is past its soft deadline\n' "${revision}" >&2
      return 0
      ;;
    *)
      state=$(printf '%s\n' "${status_output}" | jq -r '.state // "unavailable"') || return 1
      printf 'Snapshot revision %s is %s\n' "${revision}" "${state}" >&2
      return 1
      ;;
  esac
}

main "$@"
