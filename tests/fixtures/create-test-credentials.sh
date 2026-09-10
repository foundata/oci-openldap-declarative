#!/usr/bin/env sh

set -eu
umask 077

input_dir=${1:?Input directory required}
output_dir=${2:?Output directory required}

cp "${input_dir}/credentials.yaml.example" "${output_dir}/credentials.yaml"
printf '%s\n' 'TEST-ONLY-user-default-20260903' > "${output_dir}/person-0001"
printf '%s\n' 'TEST-ONLY-user-app-20260903' > "${output_dir}/person-0001-example-app"
printf '%s\n' 'TEST-ONLY-user-mail-20260903' > "${output_dir}/person-0001-example-mail"
printf '%s\n' 'TEST-ONLY-user-bob-20260903' > "${output_dir}/person-0003-example-mail"
printf '%s\n' 'TEST-ONLY-bind-app-20260903' > "${output_dir}/bind-example-app"
printf '%s\n' 'TEST-ONLY-bind-mail-20260903' > "${output_dir}/bind-example-mail"
minisign -G -W -p "${output_dir}/snapshot-public-key" -s "${output_dir}/snapshot.key" >/dev/null
chmod 0600 "${output_dir}"/*
