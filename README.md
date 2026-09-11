# OpenLDAP Declarative

Read-only OpenLDAP from a static directory definition: users/groups YAML or
native LDIF. Generate a signed, expiring snapshot, then mount it beside the LDAP
container. One definition produces one directory.

Refresh snapshots before expiry. Removing an account takes effect after
deployment or expiry; application sessions and caches have their own lifetime.

<!-- rumdl-disable MD033 -->
<!-- HTML for consistent rendering across limited platform parsers -->
<div align="center" id="project-readme-header">
<br>
<br>

**⭐ Found this useful? Support open-source and star this project:**

[![GitHub repository](https://img.shields.io/github/stars/foundata/oci-openldap-declarative.svg)](https://github.com/foundata/oci-openldap-declarative)

<br>
</div>
<!-- rumdl-enable MD033 -->


## Table of contents<a id="toc"></a>

- [Where actions run](#usage-hosts)
- [Images (admin/CI)](#installation)
- [Quick start](#usage)
  - [1. Prepare files and passwords (admin)](#usage-credentials-setup)
  - [2. Define the directory (admin/CI)](#usage-yaml)
  - [3. Create signing keys (admin)](#usage-signing-keys)
  - [4. Generate a snapshot (admin/CI)](#usage-generate-snapshot)
  - [5. Deploy and query LDAP (LDAP host)](#usage-rootless-podman)
- [Directory administration (admin/CI)](#usage-maintenance)
  - [IDs, names and renames](#usage-identities)
  - [Membership and access](#usage-membership)
  - [Credential sources](#usage-credentials)
    - [Inline encryption with Ansible Vault](#usage-vault)
    - [Source and snapshot confidentiality](#usage-hashes-in-git)
  - [Native LDIF and custom schemas](#usage-native-ldif)
- [Operations](#usage-ops)
  - [Renew and deploy (admin/CI and LDAP host)](#snapshot-lifecycle)
  - [Status and logs (LDAP host)](#usage-status)
  - [TLS and key rotation (admin/CI and LDAP host)](#tls)
  - [Backup and recovery (admin/CI and LDAP host)](#backup-and-recovery)
- [Runtime inputs (LDAP host)](#runtime-inputs)
- [Development](#tests)
- [Licensing, copyright](#licensing-copyright)
- [Author information](#author-information)


## Where actions run<a id="usage-hosts"></a>

| Location | Responsibilities |
| -------- | ---------------- |
| Admin/CI | Maintain definitions, generate and sign snapshots. Holds source credentials, Vault passwords and the private signing key. |
| LDAP host | Preflight and serve a snapshot. Holds public verification keys, snapshot files and persistent revision state. No generator or source-decryption keys. |

The same machine can fill both roles for testing. For remote deployment, keep
separate Bash terminals; variables and paths belong to the host named in each
heading. Configuration management can prepare and transfer files using these
same workflows.


## Images (admin/CI)<a id="installation"></a>

Use Linux with rootless Podman and Bash. Both images include
[minisign](https://github.com/jedisct1/minisign); the generator also includes
`ansible-vault` from `ansible-core`. No host Python, minisign or Ansible
installation is needed. Supported image platforms: Linux amd64 and arm64.

For a source checkout, first [build both local images](DEVELOPMENT.md#getting-started):

```bash
runtime=localhost/openldap-declarative:dev
generator=localhost/openldap-declarative-generator:dev
```

For deployment, select the same approved release for both images and record
their immutable digests from `quay.io/foundata/openldap-declarative` and
`quay.io/foundata/openldap-declarative-generator`. Apply your image-signature
policy; a digest alone does not authenticate its publisher.


## Quick start<a id="usage"></a><a id="usage-quick-start"></a>

Run steps 1-4 in the admin terminal, then use the LDAP-host deployment guide.

### 1. Prepare files and passwords (admin)<a id="usage-credentials-setup"></a>

```bash
set +x
umask 077
data="${HOME}/directory-data"
private="${HOME}/.config/openldap-declarative"
output="${HOME}/.local/share/openldap-declarative/generated"
install -d -m 0700 "${data}" "${private}" "${output}"

hash_password() (
  set +x
  set -euo pipefail
  read -r -s -p "$1: " password
  export -n password
  printf '\n' >&2
  test -n "${password}"
  printf '%s' "${password}" |
    podman run --rm -i --network none --entrypoint slappasswd "${runtime}" \
      -o module-path=/usr/lib/ldap \
      -o 'module-load=argon2 m=19456 t=2 p=1' \
      -h '{ARGON2}' -T /dev/stdin
)
user_hash=$(hash_password "Alice password")
bind_hash=$(hash_password "Application bind password")
```

Use distinct passwords. The function passes original passwords through stdin;
the returned values are salted Argon2id hashes. Keep tracing disabled while
handling credentials.

### 2. Define the directory (admin/CI)<a id="usage-yaml"></a>

```bash
namespace=$(podman run --rm --network none --entrypoint python3 "${generator}" \
  -c 'import uuid; print(uuid.uuid4())')
cat > "${data}/directory.yaml" <<YAML
format_version: 1
directory_id: "example-app"
base_dn: "dc=example-app,dc=services,dc=example,dc=org"
revision: 1
soft_ttl_seconds: 21600
hard_ttl_seconds: 43200
input_type: "users-groups"
uuid_namespace: "${namespace}"
organization: "Example Company"
users:
  - id: "person-0001"
    uid: "alice"
    common_name: "Alice Example"
    surname: "Example"
    mail: "alice@example.org"
    active: true
    password_hash: '${user_hash}'
groups:
  - id: "group-staff"
    common_name: "staff"
    members: ["person-0001"]
bind_account:
  id: "bind-example-app"
  common_name: "application"
  password_hash: '${bind_hash}'
YAML
unset user_hash bind_hash
chmod 0600 "${data}/directory.yaml"
```

Generate `uuid_namespace` once and preserve it. All active users are included;
there is no service-selection list. See the [larger example](examples/generator/directory.yaml)
for inactive users and credential files.

### 3. Create signing keys (admin)<a id="usage-signing-keys"></a>

Run once:

```bash
podman run --rm --userns=keep-id --user "$(id -u):$(id -g)" \
  --network none --volume "${private}:/run/credentials:Z" \
  --entrypoint minisign "${generator}" \
  -G -W -s /run/credentials/snapshot.key -p /run/credentials/snapshot.pub
```

`-W` creates an unencrypted private key for unattended signing. Keep
`snapshot.key` private and backed up. Deploy only `snapshot.pub`.

### 4. Generate a snapshot (admin/CI)<a id="usage-generate-snapshot"></a>

```bash
revision=1
podman run --rm --userns=keep-id --user "$(id -u):$(id -g)" \
  --network none --read-only --read-only-tmpfs=false \
  --cap-drop all --security-opt no-new-privileges \
  --volume "${data}:/input:ro,Z" \
  --volume "${private}:/run/credentials:ro,Z" \
  --volume "${output}:/output:Z" "${generator}" \
  --directory /input/directory.yaml \
  --signing-key /run/credentials/snapshot.key \
  --output "/output/revision-${revision}"
```

The output directory must be new. Its files are `directory.ldif`,
`manifest.json`, `manifest.json.minisig`, and any declared schemas.
The signed revision comes from YAML; the shell variable only names the output.

### 5. Deploy and query LDAP (LDAP host)<a id="usage-rootless-podman"></a>

Follow the [rootless Quadlet guide](examples/quadlet/README.md) to transfer the
snapshot, preflight it, start LDAP and verify searches and password binds.
It includes the host expiry backstop and renewal commands.


## Directory administration (admin/CI)<a id="usage-maintenance"></a>

### IDs, names and renames<a id="usage-identities"></a>

| Field | Meaning |
| ----- | ------- |
| `directory_id` | Snapshot target, matched by `LDAP_EXPECTED_DIRECTORY_ID`. Not an LDAP DN or hostname. |
| User `id` | Permanent source-record key, referenced by `groups[].members` and used to calculate `entryUUID`. Not a YAML anchor or separate LDAP attribute. |
| User `uid` | Login name and naming attribute: `uid=alice,ou=people,<base_dn>`. |
| User `common_name` | LDAP `cn`, e.g. `Alice Example`. Changing it does not rename the user's DN. |
| Group `id` | Permanent key used to calculate the group's `entryUUID`. |
| Group `common_name` | LDAP `cn` and DN: `cn=staff,ou=groups,<base_dn>`. |
| Bind account `id` | Permanent key used to calculate its `entryUUID`. |
| Bind account `common_name` | Names `cn=application,ou=services,<base_dn>`. |
| `uuid_namespace` | Permanent namespace for generated UUIDs. |
| LDAP `entryUUID` | Persistent identity for applications, independent of username changes. |

For users, `entryUUID = UUIDv5(uuid_namespace, "user:" + id)`; `user:` is fixed.
An ID can be a UUID string or another unique, permanent string. It is still an
input to the calculation, not the resulting LDAP UUID.

To rename a user, change `uid`, keep `id` and `uuid_namespace`, increase
`revision`, then regenerate and deploy. DNs and membership references update;
`entryUUID` stays unchanged. Applications keyed by username or DN may need
their own migration. Never recycle IDs.

### Membership and access<a id="usage-membership"></a>

Active users need no group. Inactive users and groups without active members
are omitted. `member` and `memberOf` are generated together.
Names such as `ALLOW` and `DENY` have no built-in effect; applications enforce
their own group rules.

Ordinary accounts cannot write, read password hashes or access `cn=config`.
Authenticated accounts can read approved attributes across the directory;
anonymous directory searches are denied.

### Credential sources<a id="usage-credentials"></a>

Put exactly one credential source directly in each active user and bind account:

| Field | Value |
| ----- | ----- |
| `password` | Original password, hashed by the generator |
| `password_file` | Absolute container path to an original-password file |
| `password_hash` | Complete pre-generated Argon2id verifier, preserved unchanged |
| `password_hash_file` | Absolute container path to a verifier file |

Every field accepts an unencrypted value or a [Vault-encrypted string](#usage-vault).
Field meanings never change: a hash-looking value in `password` is treated as
an original password. Encrypting a file-path field encrypts the path only.

Credential files must be owner-only regular files, not symlinks: one non-empty
UTF-8 line, at most 4096 bytes, with optional LF/CRLF. YAML containing unencrypted
inline credentials must also be owner-only (`chmod 0600` after Git checkout).

Accepted verifiers: `{ARGON2}$argon2id$v=19$...`, memory at least 19,456 KiB,
two iterations, one lane, 16 salt bytes and 32 digest bytes, canonical unpadded
base64. [Step 1](#usage-credentials-setup) generates these hashes.
Test stronger parameters against bind load and container memory limits.

#### Inline encryption with Ansible Vault<a id="usage-vault"></a>

The generator accepts standard labeled
[Ansible Vault scalars](https://docs.ansible.com/projects/ansible/latest/vault_guide/vault_encrypting_content.html):

```yaml
password_hash: !vault |
  $ANSIBLE_VAULT;1.2;AES256;directory
  ...encrypted payload...
```

`$ANSIBLE_VAULT` is fixed; `directory` is your key ID. To encrypt a freshly
generated hash on the admin host:

```bash
set +x
umask 077
if [ ! -e "${private}/vault-password" ]; then
  (set -C; podman run --rm --network none --entrypoint openssl "${runtime}" \
    rand -base64 32 > "${private}/vault-password")
fi
hash=$(hash_password "User password")
printf '%s' "${hash}" |
  podman run --rm -i --userns=keep-id --user "$(id -u):$(id -g)" \
    --network none --env HOME=/output --env ANSIBLE_LOCAL_TEMP=/output/.ansible \
    --volume "${private}:/run/credentials:ro,Z" \
    --volume "${output}:/output:Z" \
    --entrypoint ansible-vault "${generator}" \
    encrypt_string --vault-id directory@/run/credentials/vault-password \
    --stdin-name password_hash > "${private}/encrypted-field.yaml"
unset hash
```

Create and back up `vault-password` once per key; do not overwrite an existing
key when encrypting another field. Replace the user's `password_hash` field
with the generated block, indented at the same level as its other fields.

Add this to the generator arguments in step 4:

```text
--vault directory@/run/credentials/vault-password
```

Repeat `--vault KEYID@/absolute/file` for distinct keys. For an interactive run,
use `--vault directory@prompt`, add `-it` to `podman run` and change
`--read-only-tmpfs=false` to `--read-only-tmpfs=true` for terminal setup.
Each key is prompted once, without echoing the password.
Files must be owner-only and contain one non-empty line without surrounding
whitespace. Password scripts and inherited Ansible configuration are not used.

Vault applies to YAML string values, not mapping keys. Decrypted values remain
strings, so encrypted `active` or `revision` values are not accepted.
Whole encrypted files and encrypted text inside LDIF are not supported.

#### Source and snapshot confidentiality<a id="usage-hashes-in-git"></a>

Encrypted definitions or hash-only YAML can live in an access-controlled private
repository. Repository readers, CI jobs, clones and backups may obtain the
verifiers; weak passwords remain vulnerable to offline guessing.
Use strong passwords, high-entropy Vault keys and reviewed changes.
Vault does not protect unencrypted metadata or prevent an encrypted value from
being moved to another field. Review the complete definition before signing.

Vault does **not** encrypt the generated snapshot. It contains password verifiers
and may contain other confidential LDAP attributes. Keep production definitions
and snapshots out of public repositories, image layers and logs.
Never commit original passwords, Vault passwords or private signing keys.

### Native LDIF and custom schemas<a id="usage-native-ldif"></a>

Use this route for your own LDAP layout and object classes:

```yaml
format_version: 1
directory_id: "inventory"
base_dn: "o=Example"
revision: 1
soft_ttl_seconds: 21600
hard_ttl_seconds: 43200
input_type: "ldif"
ldif_files: ["directory.ldif"]
schema_files: ["device-schema.ldif"]
read_attributes: ["objectClass", "entryUUID", "o", "ou", "cn", "deviceLabel"]
```

Generate with the same command, pointing `--directory` at this YAML.
Paths are relative to that file unless absolute. See the runnable
[native definition](examples/generator/native.yaml),
[entry LDIF](examples/generator/native.ldif) and
[schema example](examples/generator/device-schema.ldif).
Their bind password is test-only; replace its verifier before deployment.

Supply the base entry, all parents and a unique lowercase `entryUUID` for
every entry. Generate UUIDs once and keep them on renames. All `userPassword`
values must already be Argon2id verifiers. Memberships, including `memberOf`,
are your responsibility.

Core, cosine, inetOrgPerson and NIS schemas are loaded. Extra schema files may
only define `olcAttributeTypes` and `olcObjectClasses` in `olcSchemaConfig`
entries directly below `cn=schema,cn=config`. Use your own OIDs in production.

Only the explicit `read_attributes` list is readable by authenticated clients.
Password attributes cannot be added. Data cannot configure ACLs, modules or
`cn=config`; changes, includes and URL values are rejected. Preflight is
required: OpenLDAP checks schema validity during offline import.


## Operations<a id="usage-ops"></a>

### Renew and deploy (admin/CI and LDAP host)<a id="snapshot-lifecycle"></a>

1. Admin/CI: edit the definition and increment `revision`, including renewals
   without data changes.
2. Admin/CI: generate into a new directory and transfer its contents plus the
   public verification key to the LDAP host.
3. LDAP host: [preflight and activate](examples/quadlet/README.md#preflight-and-activate)
   against existing revision state, then verify LDAP and the application.

The example warns after 6 hours and stops after 12. Refresh before the warning.
`expiry_offset_seconds` optionally shortens both deadlines by 0..86,400 seconds
and must remain below the soft TTL. Exact replay does not renew a snapshot;
different content at an accepted revision is rejected.

### Status and logs (LDAP host)<a id="usage-status"></a>

```bash
systemctl --user status openldap-example.service
journalctl --user -u openldap-example.service -n 50
podman exec openldap-example /usr/local/lib/openldap-declarative/status.sh
```

Status returns JSON: exit `0` healthy, `1` soft-expired, `2` expired/unavailable.
At hard expiry, the runtime stops LDAP with exit `78`.

### TLS and key rotation (admin/CI and LDAP host)<a id="tls"></a>

Use validated LDAPS outside trusted host-local connections. Clients must check
the server name and CA. Restart after certificate renewal. Follow the
[deployment guide](examples/quadlet/README.md#tls-and-signing-key-rotation) for
TLS mounts and coordinated snapshot-signing key rotation.

To rotate a Vault key, re-encrypt affected source fields on admin/CI with the
new key, verify generation, then retire the old key after accounting for backups.
Vault keys never go to the LDAP host.

### Backup and recovery (admin/CI and LDAP host)<a id="backup-and-recovery"></a>

Back up definitions, stable IDs, namespaces, required credentials, Vault and
signing keys, deployment settings and image digests. On LDAP hosts, preserve
public keys and revision state. MDB is rebuilt at startup.

No administrator password is configured by default. For temporary recovery,
mount a password file and set `LDAP_ADMIN_PASSWORD_FILE`. This enables
`cn=admin,<base_dn>`, which can write and read verifiers. Never use it for
applications. Recovery changes disappear on rebuild; update the source for
lasting changes, then remove the recovery input and restart.


## Runtime inputs (LDAP host)<a id="runtime-inputs"></a>

| Input | Default | Meaning |
| ----- | ------- | ------- |
| `LDAP_EXPECTED_DIRECTORY_ID` | none | Required; must match the signed directory ID. |
| `LDAP_TRANSPORT` | `ldap` | `ldap`, `ldaps` or `both`. |
| `LDAP_LISTEN_HOST` | `127.0.0.1` | `127.0.0.1` or `0.0.0.0`. |
| `LDAP_PORT` / `LDAP_LDAPS_PORT` | `1389` / `1636` | Unprivileged ports; distinct for `both`. |
| `LDAP_LOG_LEVEL` | `256` | Numeric slapd log mask. |
| `LDAP_TLS_CERT_FILE` / `LDAP_TLS_KEY_FILE` | `/tls/cert.pem` / `/tls/cert.key` | Required for LDAPS. |
| `LDAP_TLS_CA_FILE` | `/tls/ca.pem` | Optional server trust bundle. |
| `LDAP_SNAPSHOT_DIR` | `/snapshot` | Manifest, signature and listed LDIF files. |
| `LDAP_REVISION_STATE_FILE` | `/state/highest-revision` | Persistent highest revision and manifest digest. |
| `LDAP_SNAPSHOT_PUBLIC_KEY_FILE` | `/run/credentials/snapshot-public-key` | One minisign public key. |
| `LDAP_SNAPSHOT_PUBLIC_KEY_DIR` | none | `*.pub` keys; mutually exclusive with file input. |
| `LDAP_ADMIN_PASSWORD_FILE` | none | Optional original-password file for recovery. |
| `LDAP_ADMIN_PASSWORD` | none | Deprecated; conflicts with the file input. |
| `LDAP_BASE_DN` / `LDAP_DOMAIN` | none | Compatibility checks; must agree with the manifest. |

<a id="limitations"></a>
Limits: 1 MiB source YAML; 256 Vault values of 32 KiB each; 32 snapshot LDIF files,
16 MiB combined LDIF, 1 MiB manifest and 16 KiB signature.
No unsigned mode or expiry bypass.


## Development<a id="tests"></a>

[DEVELOPMENT.md](DEVELOPMENT.md) covers builds, tests and releases.
[ARCHITECTURE.md](ARCHITECTURE.md) defines the behavioral contract.
Editor schemas: [directory](schema/directory-v1.schema.json) and
[snapshot manifest](schema/snapshot-manifest-v1.schema.json).


## Licensing, copyright<a id="licensing-copyright"></a>

<!--REUSE-IgnoreStart-->
<!-- rumdl-disable-next-line MD034 --><!-- should match SPDX-PackageSupplier -->
Copyright (c) 2025-2026, foundata GmbH (https://foundata.com)

Licensed under [GNU GPL v3.0 or later](LICENSES/GPL-3.0-or-later.txt)
(`GPL-3.0-or-later`). [REUSE.toml](REUSE.toml) records per-file licensing,
including third-party components, following the
[REUSE specification](https://reuse.software/spec/). `reuse spdx` produces a
source licensing SBOM. Debian packages retain their respective licenses;
release SBOMs must describe the actual image contents.
<!--REUSE-IgnoreEnd-->


## Author information<a id="author-information"></a>

This [project](https://foundata.com/en/projects/) was created and is maintained by [foundata](https://foundata.com/).
