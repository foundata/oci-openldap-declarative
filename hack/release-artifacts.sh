#!/usr/bin/env sh

# Produce SBOM, security, package, and digest evidence for both local images.

set -u

project_dir=$(CDPATH='' cd "$(dirname "$0")/.." && pwd) || exit 1
readonly project_dir
readonly runtime_image="${RUNTIME_IMAGE:-localhost/openldap-declarative:latest}"
readonly generator_image="${GENERATOR_IMAGE:-localhost/openldap-declarative-generator:latest}"
readonly trivy_severities="${TRIVY_SEVERITIES:-HIGH,CRITICAL}"
readonly trivy_vex_file="${TRIVY_VEX_FILE:-}"
readonly trivy_image="${TRIVY_IMAGE:-docker.io/aquasec/trivy@sha256:cffe3f5161a47a6823fbd23d985795b3ed72a4c806da4c4df16266c02accdd6f}"
readonly podman_binary="${PODMAN:-podman}"
readonly skopeo_binary="${SKOPEO:-skopeo}"

staging_directory=''
output_directory=''
current_uid=''
current_gid=''
security_policy_failed=0
source_revision=''
source_policy_result='passed'

log() {
  printf '==> %s\n' "$*"
}

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  return 1
}

require_command() {
  command_name=${1}
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    fail "Required command is unavailable: ${command_name}"
  fi
}

cleanup() {
  if [ -n "${staging_directory}" ] && [ -d "${staging_directory}" ]; then
    rm -rf "${staging_directory}"
  fi
}

validate_severities() {
  severities=${trivy_severities}

  case "${severities}" in
    '' | ,* | *, | *,,*) return 1 ;;
    *) ;;
  esac
  while [ -n "${severities}" ]; do
    severity=${severities%%,*}
    case "${severity}" in
      UNKNOWN | LOW | MEDIUM | HIGH | CRITICAL) ;;
      *) return 1 ;;
    esac
    if [ "${severities}" = "${severity}" ]; then
      severities=''
    else
      severities=${severities#*,}
      if [ -z "${severities}" ]; then
        return 1
      fi
    fi
  done
}

copy_vex_input() {
  if [ -z "${trivy_vex_file}" ]; then
    return 0
  fi
  if [ ! -f "${trivy_vex_file}" ] || [ -L "${trivy_vex_file}" ] \
    || [ ! -r "${trivy_vex_file}" ]; then
    fail "TRIVY_VEX_FILE is not a readable regular file: ${trivy_vex_file}"
    return 66
  fi

  cp "${trivy_vex_file}" "${staging_directory}/vex.json" || return 1
  chmod 0600 "${staging_directory}/vex.json" || return 1
  vex_size=$(wc -c <"${staging_directory}/vex.json") || return 1
  if [ "${vex_size}" -gt 1048576 ]; then
    fail 'TRIVY_VEX_FILE exceeds the 1 MiB input limit'
    return 66
  fi
  if ! jq -e . "${staging_directory}/vex.json" >/dev/null; then
    fail 'TRIVY_VEX_FILE is not valid JSON'
    return 66
  fi
}

validate_configuration() {
  if [ "$#" -ne 1 ] || [ -z "${1}" ]; then
    printf 'Usage: %s OUTPUT_DIRECTORY\n' "${0##*/}" >&2
    return 64
  fi
  requested_output=${1}

  if ! validate_severities; then
    fail 'TRIVY_SEVERITIES must be a comma-separated list of uppercase Trivy severities'
    return 64
  fi
  if [ -e "${requested_output}" ] || [ -L "${requested_output}" ]; then
    fail "Output path already exists: ${requested_output}"
    return 64
  fi

  output_parent=$(dirname "${requested_output}") || return 1
  output_name=$(basename "${requested_output}") || return 1
  if [ ! -d "${output_parent}" ]; then
    fail "Output parent does not exist: ${output_parent}"
    return 64
  fi
  output_parent=$(CDPATH='' cd "${output_parent}" && pwd -P) || return 1
  output_directory="${output_parent}/${output_name}"
  staging_directory=$(mktemp -d "${output_parent}/.${output_name}.XXXXXX") || return 1
  chmod 0700 "${staging_directory}" || return 1
  mkdir -m 0700 \
    "${staging_directory}/trivy-cache" \
    "${staging_directory}/trivy-tmp" || return 1
  current_uid=$(id -u) || return 1
  current_gid=$(id -g) || return 1

  for required_command in "${podman_binary}" "${skopeo_binary}" git jq sha256sum tar wc; do
    require_command "${required_command}" || return 1
  done
  copy_vex_input || return $?

  for local_image in "${runtime_image}" "${generator_image}"; do
    if ! "${podman_binary}" image exists "${local_image}"; then
      fail "Local image does not exist: ${local_image}"
      return 66
    fi
  done
}

prepare_source_tree() {
  runtime_revision=$("${podman_binary}" image inspect \
    --format '{{index .Labels "org.opencontainers.image.revision"}}' \
    "${runtime_image}") || return 1
  generator_revision=$("${podman_binary}" image inspect \
    --format '{{index .Labels "org.opencontainers.image.revision"}}' \
    "${generator_image}") || return 1
  if [ "${runtime_revision}" != "${generator_revision}" ]; then
    fail 'Runtime and generator images were built from different source revisions'
    return 65
  fi
  source_revision=${runtime_revision}
  if ! git -C "${project_dir}" cat-file -e "${source_revision}^{commit}"; then
    fail "Image source revision is unavailable in this Git checkout: ${source_revision}"
    return 65
  fi

  mkdir -m 0700 "${staging_directory}/source" || return 1
  git -C "${project_dir}" archive --format=tar \
    --output "${staging_directory}/source.tar" \
    "${source_revision}" || return 1
  tar -xf "${staging_directory}/source.tar" \
    -C "${staging_directory}/source" || return 1
  rm -f "${staging_directory}/source.tar" || return 1
}

run_trivy_tool() {
  "${podman_binary}" run --rm --pull=missing \
    --userns keep-id \
    --user "${current_uid}:${current_gid}" \
    --read-only \
    --env HOME=/cache \
    --env XDG_CACHE_HOME=/cache \
    --env TMPDIR=/tmp \
    --cap-drop all \
    --security-opt no-new-privileges \
    --volume "${staging_directory}:/artifacts:rw,Z" \
    --volume "${staging_directory}/trivy-cache:/cache:rw,Z" \
    --volume "${staging_directory}/trivy-tmp:/tmp:rw,Z" \
    "${trivy_image}" --cache-dir /cache --quiet "$@"
}

generate_sbom() {
  image_slug=${1}

  run_trivy_tool image \
    --input "/artifacts/${image_slug}.oci" \
    --format spdx-json \
    --output "/artifacts/${image_slug}.spdx.json"
}

scan_image() {
  image_slug=${1}
  output_name=${2}
  shift 2

  if [ -f "${staging_directory}/vex.json" ]; then
    run_trivy_tool image \
      --input "/artifacts/${image_slug}.oci" \
      --scanners vuln,secret,misconfig \
      --vex /artifacts/vex.json \
      --format json \
      --output "/artifacts/${output_name}" "$@"
  else
    run_trivy_tool image \
      --input "/artifacts/${image_slug}.oci" \
      --scanners vuln,secret,misconfig \
      --format json \
      --output "/artifacts/${output_name}" "$@"
  fi
}

scan_source() {
  output_name=${1}
  shift

  run_trivy_tool filesystem \
    --scanners secret,misconfig \
    --format json \
    --output "/artifacts/${output_name}" "$@" \
    /artifacts/source
}

generate_source_artifacts() {
  log "Scanning committed source ${source_revision} for secrets and misconfigurations"
  scan_source source.trivy.json || return 1
  scan_source source.trivy-policy.json \
    --severity "${trivy_severities}" --exit-code 2
  trivy_status=$?
  source_policy_result=passed
  case "${trivy_status}" in
    0) ;;
    2)
      source_policy_result=rejected
      security_policy_failed=1
      report_policy_findings "${staging_directory}/source.trivy-policy.json"
      printf 'WARNING: source failed the Trivy severity policy (%s)\n' \
        "${trivy_severities}" >&2
      ;;
    *)
      fail "Source Trivy policy scan failed with status ${trivy_status}"
      return 1
      ;;
  esac
  rm -rf "${staging_directory}/source" || return 1
}

write_image_metadata() {
  image_slug=${1}
  local_image=${2}
  manifest_digest=${3}
  policy_result=${4}

  image_id=$("${podman_binary}" image inspect --format '{{.Id}}' "${local_image}") || return 1
  image_created=$("${podman_binary}" image inspect --format '{{.Created}}' "${local_image}") || return 1
  image_architecture=$("${podman_binary}" image inspect --format '{{.Architecture}}' "${local_image}") || return 1
  image_os=$("${podman_binary}" image inspect --format '{{.Os}}' "${local_image}") || return 1
  image_revision=$("${podman_binary}" image inspect \
    --format '{{index .Labels "org.opencontainers.image.revision"}}' "${local_image}") || return 1
  image_version=$("${podman_binary}" image inspect \
    --format '{{index .Labels "org.opencontainers.image.version"}}' "${local_image}") || return 1
  source_tree_state=$("${podman_binary}" image inspect \
    --format '{{index .Labels "com.foundata.openldap-declarative.source-tree-state"}}' \
    "${local_image}") || return 1
  package_sha256=$(sha256sum "${staging_directory}/${image_slug}.packages.txt" | cut -d ' ' -f 1) || return 1
  spdx_sha256=$(sha256sum "${staging_directory}/${image_slug}.spdx.json" | cut -d ' ' -f 1) || return 1
  trivy_sha256=$(sha256sum "${staging_directory}/${image_slug}.trivy.json" | cut -d ' ' -f 1) || return 1
  policy_sha256=$(sha256sum "${staging_directory}/${image_slug}.trivy-policy.json" | cut -d ' ' -f 1) || return 1

  jq -n \
    --arg image "${local_image}" \
    --arg image_id "${image_id}" \
    --arg created "${image_created}" \
    --arg revision "${image_revision}" \
    --arg version "${image_version}" \
    --arg source_tree_state "${source_tree_state}" \
    --arg architecture "${image_architecture}" \
    --arg os "${image_os}" \
    --arg manifest_digest "${manifest_digest}" \
    --arg package_file "${image_slug}.packages.txt" \
    --arg package_sha256 "${package_sha256}" \
    --arg spdx_file "${image_slug}.spdx.json" \
    --arg spdx_sha256 "${spdx_sha256}" \
    --arg trivy_file "${image_slug}.trivy.json" \
    --arg trivy_sha256 "${trivy_sha256}" \
    --arg policy_file "${image_slug}.trivy-policy.json" \
    --arg policy_sha256 "${policy_sha256}" \
    --arg policy_result "${policy_result}" \
    '{
      local_image: $image,
      local_image_id: $image_id,
      created: $created,
      source: {revision: $revision, version: $version, tree_state: $source_tree_state},
      platform: {os: $os, architecture: $architecture},
      oci_manifest_digest: $manifest_digest,
      package_inventory: {path: $package_file, sha256: $package_sha256},
      spdx_sbom: {path: $spdx_file, sha256: $spdx_sha256},
      security_report: {
        path: $trivy_file,
        sha256: $trivy_sha256,
        scanners: ["vuln", "secret", "misconfig"],
        policy_report: {path: $policy_file, sha256: $policy_sha256},
        policy: $policy_result
      }
    }' >"${staging_directory}/${image_slug}.metadata.json"
}

validate_image_provenance() {
  local_image=${1}

  image_revision=$("${podman_binary}" image inspect \
    --format '{{index .Labels "org.opencontainers.image.revision"}}' "${local_image}") || return 1
  image_version=$("${podman_binary}" image inspect \
    --format '{{index .Labels "org.opencontainers.image.version"}}' "${local_image}") || return 1
  source_tree_state=$("${podman_binary}" image inspect \
    --format '{{index .Labels "com.foundata.openldap-declarative.source-tree-state"}}' \
    "${local_image}") || return 1
  if ! printf '%s\n' "${image_revision}" | grep -E -q '^[0-9a-f]{40}([0-9a-f]{24})?$'; then
    fail "${local_image} has no valid source revision label"
    return 65
  fi
  if [ -z "${image_version}" ] || [ "${image_version}" = development ]; then
    fail "${local_image} has no production version label"
    return 65
  fi
  if [ "${source_tree_state}" != clean ]; then
    fail "${local_image} was not built from a clean tracked source tree"
    return 65
  fi
}

report_policy_findings() {
  policy_report=${1}

  jq -r '
    [.Results[]? |
      ((.Vulnerabilities // []) +
       (.Misconfigurations // []) +
       (.Secrets // []))[] |
      .Severity] |
    group_by(.)[] |
    "\(.[0]): \(length)"' "${policy_report}" >&2 || true
}

generate_image_artifacts() {
  image_slug=${1}
  local_image=${2}
  layout_path="${staging_directory}/${image_slug}.oci"

  log "Saving ${local_image} as an OCI image layout"
  "${podman_binary}" save --format oci-dir \
    --output "${layout_path}" "${local_image}" || return 1
  manifest_digest=$("${skopeo_binary}" inspect --format '{{.Digest}}' \
    "oci:${layout_path}") || return 1

  "${podman_binary}" run --rm \
    --network none \
    --cap-drop all \
    --security-opt no-new-privileges \
    --entrypoint cat \
    "${local_image}" \
    /usr/local/share/openldap-declarative/package-versions.txt \
    >"${staging_directory}/${image_slug}.packages.txt" || return 1

  log "Generating ${image_slug} SPDX SBOM with ${trivy_image}"
  generate_sbom "${image_slug}" || return 1

  log "Scanning ${image_slug} vulnerabilities, secrets, and misconfigurations"
  scan_image "${image_slug}" "${image_slug}.trivy.json" || return 1
  scan_image "${image_slug}" "${image_slug}.trivy-policy.json" \
    --severity "${trivy_severities}" --exit-code 2
  trivy_status=$?
  policy_result=passed
  case "${trivy_status}" in
    0) ;;
    2)
      policy_result=rejected
      security_policy_failed=1
      report_policy_findings \
        "${staging_directory}/${image_slug}.trivy-policy.json"
      printf 'WARNING: %s failed the Trivy severity policy (%s)\n' \
        "${image_slug}" "${trivy_severities}" >&2
      ;;
    *)
      fail "${image_slug} Trivy policy scan failed with status ${trivy_status}"
      return 1
      ;;
  esac

  write_image_metadata \
    "${image_slug}" "${local_image}" "${manifest_digest}" \
    "${policy_result}" || return 1
  rm -rf "${layout_path}" || return 1
}

write_release_metadata() {
  generated_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ') || return 1
  release_result=passed
  if [ "${security_policy_failed}" -eq 1 ]; then
    release_result=rejected
  fi
  for image_slug in runtime generator; do
    jq --arg release_result "${release_result}" \
      '.release_policy = $release_result' \
      "${staging_directory}/${image_slug}.metadata.json" \
      >"${staging_directory}/${image_slug}.metadata.tmp" || return 1
    mv "${staging_directory}/${image_slug}.metadata.tmp" \
      "${staging_directory}/${image_slug}.metadata.json" || return 1
  done
  vex_sha256=''
  if [ -f "${staging_directory}/vex.json" ]; then
    vex_sha256=$(sha256sum "${staging_directory}/vex.json" \
      | cut -d ' ' -f 1) || return 1
  fi
  source_report_sha256=$(sha256sum "${staging_directory}/source.trivy.json" \
    | cut -d ' ' -f 1) || return 1
  source_policy_sha256=$(sha256sum "${staging_directory}/source.trivy-policy.json" \
    | cut -d ' ' -f 1) || return 1
  trivy_db_file="${staging_directory}/trivy-cache/db/trivy.db"
  trivy_db_metadata="${staging_directory}/trivy-cache/db/metadata.json"
  trivy_checks_metadata="${staging_directory}/trivy-cache/policy/metadata.json"
  for scanner_input in \
    "${trivy_db_file}" "${trivy_db_metadata}" "${trivy_checks_metadata}"; do
    if [ ! -f "${scanner_input}" ] || [ -L "${scanner_input}" ]; then
      fail "Trivy scanner input metadata is unavailable: ${scanner_input}"
      return 1
    fi
  done
  cp "${trivy_db_metadata}" "${staging_directory}/trivy-db.metadata.json" || return 1
  cp "${trivy_checks_metadata}" \
    "${staging_directory}/trivy-checks.metadata.json" || return 1
  if ! jq -e . "${staging_directory}/trivy-db.metadata.json" >/dev/null \
    || ! jq -e . "${staging_directory}/trivy-checks.metadata.json" >/dev/null; then
    fail 'Trivy scanner input metadata is not valid JSON'
    return 1
  fi
  trivy_db_sha256=$(sha256sum "${trivy_db_file}" | cut -d ' ' -f 1) || return 1
  trivy_db_metadata_sha256=$(sha256sum \
    "${staging_directory}/trivy-db.metadata.json" | cut -d ' ' -f 1) || return 1
  trivy_checks_metadata_sha256=$(sha256sum \
    "${staging_directory}/trivy-checks.metadata.json" | cut -d ' ' -f 1) || return 1
  trivy_checks_digest=$(jq -er '.Digest | strings' \
    "${staging_directory}/trivy-checks.metadata.json") || return 1

  jq -n \
    --arg generated_at "${generated_at}" \
    --arg result "${release_result}" \
    --arg severities "${trivy_severities}" \
    --arg vex_sha256 "${vex_sha256}" \
    --arg trivy_image "${trivy_image}" \
    --arg source_revision "${source_revision}" \
    --arg source_policy_result "${source_policy_result}" \
    --arg source_report_sha256 "${source_report_sha256}" \
    --arg source_policy_sha256 "${source_policy_sha256}" \
    --arg trivy_db_sha256 "${trivy_db_sha256}" \
    --arg trivy_db_metadata_sha256 "${trivy_db_metadata_sha256}" \
    --arg trivy_checks_digest "${trivy_checks_digest}" \
    --arg trivy_checks_metadata_sha256 "${trivy_checks_metadata_sha256}" \
    --slurpfile runtime "${staging_directory}/runtime.metadata.json" \
    --slurpfile generator "${staging_directory}/generator.metadata.json" \
    '{
      schema_version: 1,
      generated_at: $generated_at,
      result: $result,
      security_policy: {
        severities: ($severities | split(",")),
        scanners: ["vuln", "secret", "misconfig"],
        vex: (if $vex_sha256 == "" then null else {
          path: "vex.json",
          sha256: $vex_sha256,
          support: "experimental"
        } end)
      },
      tools: {
        trivy_image: $trivy_image,
        scanner_inputs: {
          vulnerability_database: {
            database_sha256: $trivy_db_sha256,
            metadata: {
              path: "trivy-db.metadata.json",
              sha256: $trivy_db_metadata_sha256
            }
          },
          misconfiguration_checks: {
            digest: $trivy_checks_digest,
            metadata: {
              path: "trivy-checks.metadata.json",
              sha256: $trivy_checks_metadata_sha256
            }
          }
        }
      },
      source: {
        revision: $source_revision,
        security_report: {
          path: "source.trivy.json",
          sha256: $source_report_sha256,
          scanners: ["secret", "misconfig"],
          policy_report: {
            path: "source.trivy-policy.json",
            sha256: $source_policy_sha256
          },
          policy: $source_policy_result
        }
      },
      images: {runtime: $runtime[0], generator: $generator[0]}
    }' >"${staging_directory}/release.json" || return 1

  rm -rf \
    "${staging_directory}/trivy-cache" \
    "${staging_directory}/trivy-tmp" || return 1
  chmod 0600 "${staging_directory}"/* || return 1
  mv "${staging_directory}" "${output_directory}" || return 1
  staging_directory=''
  if [ "${release_result}" = passed ]; then
    log "Release evidence passed at ${output_directory}"
  else
    printf 'WARNING: release evidence is rejected at %s\n' "${output_directory}" >&2
  fi
}

main() {
  umask 077
  trap cleanup EXIT
  trap 'exit 130' HUP INT TERM

  validate_configuration "$@" || return $?
  validate_image_provenance "${runtime_image}" || return $?
  validate_image_provenance "${generator_image}" || return $?
  prepare_source_tree || return $?
  generate_source_artifacts || return 1
  generate_image_artifacts runtime "${runtime_image}" || return $?
  generate_image_artifacts generator "${generator_image}" || return $?
  write_release_metadata || return 1
  if [ "${security_policy_failed}" -eq 1 ]; then
    return 2
  fi
}

main "$@"
