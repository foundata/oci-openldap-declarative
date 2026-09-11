#!/usr/bin/env sh

set -eu
umask 077

output_dir=${1:?Output directory required}

printf '%s\n' 'TEST-ONLY-user-app-20260903' >"${output_dir}/person-0001-example-app"
printf '%s\n' 'TEST-ONLY-user-bob-20260903' >"${output_dir}/person-0003"
printf '%s\n' 'TEST-ONLY-bind-app-20260903' >"${output_dir}/bind-example-app"
minisign -G -W -p "${output_dir}/snapshot-public-key" -s "${output_dir}/snapshot.key" >/dev/null
chmod 0600 "${output_dir}"/*
