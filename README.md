# OpenLDAP Declarative

**"OpenLDAP Declarative" serves an LDAP directory from a signed, expiring
snapshot using OCI containers.** Users/groups YAML provides a read-only application
directory. Custom LDIF gives administrators control of the server configuration
and entries. One definition produces one directory.

|                   Input                   | Use it for |
| ----------------------------------------- | ---------- |
| [Users/groups YAML](#usage-prepare-yaml)  | Application logins, identities, groups and bind accounts, with optional extra attributes and auxiliary classes. The generator supplies the layout and membership attributes. |
| [Custom LDIF](#usage-prepare-native-ldif) | Administrator-owned server configuration and entries, including schemas, ACLs, indexes and packaged overlays. You own the access and credential policies. |

Both routes use YAML for snapshot settings and retain signature verification,
revision checks and expiry supervision. Custom LDIF has no generated-policy mode.
Refresh snapshots before expiry. Removing an account takes effect after
deployment or expiry; application sessions and caches have their own lifetime.

The project provides two images:

- [`openldap-declarative-generator`](#image-generator), built from
  [`Containerfile.generator`](Containerfile.generator): generates and signs
  directory snapshots on the admin host or in CI.
- [`openldap-declarative`](#image-ldap), built from
  [`Containerfile`](Containerfile): verifies a snapshot and serves its directory
  on the LDAP host.


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

- [Examples, use cases](#examples)
  - [Application-specific LDAP, sidecar containers](#example-app-ldap)
- [Where actions run](#usage-hosts)
- [Image: `quay.io/foundata/openldap-declarative-generator` (admin host / CI)](#image-generator)
  - [Tags](#tags-generator)
  - [How to use](#usage-generator)
    - [Prepare directory data](#usage-prepare)
      - [Application directory: users/groups YAML](#usage-prepare-yaml)
      - [Custom directory: LDIF](#usage-prepare-native-ldif)
    - [Sign and generate a snapshot](#usage-snapshot)
      - [Create signing keys](#usage-snapshot-keys)
      - [Generate a snapshot](#usage-snapshot-generate)
    - [Directory administration](#usage-admin)
      - [IDs, names and renames](#usage-admin-identities)
      - [User profile fields](#usage-admin-profile-fields)
      - [Extra LDAP attributes and classes](#usage-admin-extensions)
      - [Bind accounts](#usage-admin-bind-accounts)
      - [Membership and access](#usage-admin-membership)
      - [Credential sources](#usage-admin-credentials)
        - [Inline encryption with Ansible Vault](#usage-vault)
        - [Source and snapshot confidentiality](#usage-hashes-in-git)
- [Image: `quay.io/foundata/openldap-declarative` (LDAP host)](#image-ldap)
  - [Tags](#tags-ldap)
  - [How to use](#usage-ldap)
    - [Deploy and verify LDAP (LDAP host)](#usage-rootless-podman)
    - [Runtime inputs (LDAP host)](#runtime-inputs)
    - [Operations](#usage-ops)
      - [Renew and deploy (admin/CI and LDAP host)](#usage-ops-snapshot-lifecycle)
      - [Status and logs (LDAP host)](#usage-ops-status)
      - [TLS and key rotation (admin/CI and LDAP host)](#usage-ops-tls)
      - [Backup and recovery (admin/CI and LDAP host)](#usage-ops-backup-and-recovery)
- [Development](#tests)
- [Licensing, copyright](#licensing-copyright)
- [Author information](#author-information)


## Examples, use cases<a id="examples"></a>

### Application-specific LDAP, sidecar containers<a id="example-app-ldap"></a>

foundata built this project to replace shared central-directory dependencies
with isolated, application-local LDAP sidecar containers containing only the
identities each application needs. This reduces blast radius, limits data
exposure, and removes the central directory from the application's runtime
network path, supporting
[Zero Trust](https://en.wikipedia.org/wiki/Zero_trust_architecture) and
[defense in depth](https://en.wikipedia.org/wiki/Defense_in_depth_(computing)).

Trade-off: account removals take effect only after a new snapshot is deployed
or the current one expires.


## Where actions run<a id="usage-hosts"></a>

|    Location     | Responsibilities |
| --------------- | ---------------- |
| Admin host / CI | Maintain directory definitions, generate and sign snapshots. Holds source credentials, Vault passwords and the private signing key. |
| LDAP host       | Serve the directory via LDAP(S). Holds public verification keys, snapshot files and persistent revision state. |

The same machine can fill both roles for testing. Both images support Linux
amd64 and arm64. Local builds and testing are covered in
[`DEVELOPMENT.md`](DEVELOPMENT.md#build).


## Image: `quay.io/foundata/openldap-declarative-generator` (admin host / CI)<a id="image-generator"></a>

The generator is a one-shot command so no tools installation is needed on your
host: it reads your definition, writes a signed snapshot and exits.

### Tags<a id="tags-generator"></a>

- `latest`: a moving tag updated by the release process.
- `<version>`: a specific release version.

### How to use<a id="usage-generator"></a>

Run these steps in Bash on the admin host or in CI:

1. [Install Podman](https://podman.io/docs/installation) with rootless support.
2. Pull the
   [generator image from Quay](https://quay.io/repository/foundata/openldap-declarative-generator)
   and use its immutable reference:

   ```bash
   podman pull quay.io/foundata/openldap-declarative-generator:latest
   generator=$(podman image inspect --format '{{index .RepoDigests 0}}' \
     quay.io/foundata/openldap-declarative-generator:latest)
   ```

3. [Prepare directory data](#usage-prepare), then
   [sign and generate a snapshot](#usage-snapshot). Keep these variables in the
   same terminal for the commands below.

#### Prepare directory data<a id="usage-prepare"></a>

Prepare these paths and the password-hashing helper in the admin Bash terminal.
Then choose one input route below.

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
    podman run --rm -i --network none --entrypoint openldap-password "${generator}"
)
```

The snippet above is just an example and can be adapted to your needs. It reads
an original password without echoing it, passes it through
stdin and returns a salted [Argon2id](https://en.wikipedia.org/wiki/Argon2)
hash. `openldap-password` accepts one non-empty UTF-8 line of at most 4096
bytes, with an optional new line at the end (LF or CRLF).


##### Application directory: users/groups YAML<a id="usage-prepare-yaml"></a>

Use this fixed-layout model for application logins, identities and groups, as
in the [example use case](#example-app-ldap) as it is far easier to use and
maintain if fitting. Each application can have one or
more separate [bind accounts](#usage-admin-bind-accounts). Start with one:

```bash
# hash_password() was defined in the previous section's snippet
user_hash=$(hash_password "Alice password")
bind_hash=$(hash_password "Application bind password")

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
bind_accounts:
  - id: "bind-example-app"
    common_name: "application"
    password_hash: '${bind_hash}'
YAML
unset user_hash bind_hash
chmod 0600 "${data}/directory.yaml"
```

Generate `uuid_namespace` once and preserve it. All active users are included.
See the [larger example](examples/generator/directory.yaml) for profile fields,
inactive users and credential files. Continue with
[signing and generation](#usage-snapshot).

##### Custom directory: LDIF<a id="usage-prepare-native-ldif"></a>

Supply complete OpenLDAP configuration and directory entries. Start with the
[custom LDIF guide](docs/custom-ldif.md) and its read-only example. You own the
schemas, ACLs, indexes, overlays and password policy; the runtime does not merge
generated defaults into your configuration.

Write `${data}/directory.yaml` with snapshot settings and ordered file lists:

```yaml
format_version: 1
directory_id: "inventory"
base_dn: "o=Example"
revision: 1
soft_ttl_seconds: 21600
hard_ttl_seconds: 43200
input_type: "ldif"
ldif_files: ["directory.ldif"]
config_files:
  - "native-server.ldif"
  - "/usr/local/share/openldap-declarative/schema/available/core.ldif"
  - "device-schema.ldif"
  - "native-database.ldif"
```

Paths are relative to the YAML file unless absolute; absolute paths refer to
the generator container. `config_files` includes schema entries in dependency
order. Packaged schema files are available at the path shown above, but none
are automatically loaded. The [complete example](examples/generator/native.yaml)
also selects cosine, inetOrgPerson and NIS. Its bind password is test-only.

Supply the base entry and all parents. Supply stable `entryUUID` values when
clients depend on them; otherwise OpenLDAP generates new UUIDs on each rebuild.
Data, memberships and credentials are administrator-owned. `read_attributes`
and `schema_files` belong only to the users/groups route.

Custom LDIF currently supports one snapshot-loaded MDB database at
`/run/openldap/data`. Preflight in a fresh container is required. See the
[runtime envelope](docs/custom-ldif.md#runtime-envelope) for setting ownership
and the [module list](docs/custom-ldif.md#modules) for available extensions.

Continue with [signing and generation](#usage-snapshot).


#### Sign and generate a snapshot<a id="usage-snapshot"></a>

Both input routes use the following commands with `${data}/directory.yaml`.

##### Create signing keys<a id="usage-snapshot-keys"></a>

Run once:

```bash
podman run --rm --userns=keep-id --user "$(id -u):$(id -g)" \
  --network none --volume "${private}:/run/credentials:Z" \
  --entrypoint minisign "${generator}" \
  -G -W -s /run/credentials/snapshot.key -p /run/credentials/snapshot.pub
```

`-W` creates an unencrypted private key for unattended signing. Keep
`snapshot.key` private and backed up. Deploy only `snapshot.pub`.

##### Generate a snapshot<a id="usage-snapshot-generate"></a>

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
`manifest.json`, `manifest.json.minisig`, and either declared YAML schemas or
the complete custom `config.ldif`.
The signed revision comes from YAML; the shell variable only names the output.


#### Directory administration<a id="usage-admin"></a>

The model-specific settings below apply to users/groups YAML. Custom LDIF
administration is covered in [its guide](docs/custom-ldif.md).

##### IDs, names and renames<a id="usage-admin-identities"></a>

|           Field            | Meaning |
| -------------------------- | ------- |
| `directory_id`             | Snapshot target, matched by `LDAP_EXPECTED_DIRECTORY_ID`. Not an LDAP DN or hostname. |
| User `id`                  | Permanent source-record key, referenced by `groups[].members` and used to calculate `entryUUID`. Not a YAML anchor or separate LDAP attribute. |
| User `uid`                 | Login name and naming attribute: `uid=alice,ou=people,<base_dn>`. |
| User `common_name`         | LDAP `cn`, e.g. `Alice Example`. Changing it does not rename the user's DN. |
| Group `id`                 | Permanent key used to calculate the group's `entryUUID`. |
| Group `common_name`        | LDAP `cn` and DN: `cn=staff,ou=groups,<base_dn>`. |
| Bind account `id`          | Permanent key used to calculate its `entryUUID`. |
| Bind account `common_name` | Names `cn=application,ou=services,<base_dn>`. |
| `uuid_namespace`           | Permanent namespace for generated UUIDs. |
| LDAP `entryUUID`           | Persistent identity for applications, independent of username changes. |

For users, `entryUUID = UUIDv5(uuid_namespace, "user:" + id)`; `user:` is fixed.
An ID can be a UUID string or another unique, permanent string. It is still an
input to the calculation, not the resulting LDAP UUID.

To rename a user, change `uid`, keep `id` and `uuid_namespace`, increase
`revision`, then regenerate and deploy. DNs and membership references update;
`entryUUID` stays unchanged. Applications keyed by username or DN may need
their own migration. Never recycle IDs.

##### User profile fields<a id="usage-admin-profile-fields"></a>

Users/groups YAML accepts these optional strings in each user:

|     YAML field     | LDAP attribute |
| ------------------ | -------------- |
| `given_name`       | `givenName` (first name) |
| `initials`         | `initials`     |
| `display_name`     | `displayName`  |
| `description`      | `description`  |
| `office`           | `physicalDeliveryOfficeName` |
| `telephone_number` | `telephoneNumber` |
| `mail`             | `mail` (email) |
| `department`       | `ou` (user metadata; does not change the DN) |
| `job_title`        | `title`        |

Omit unset fields rather than supplying empty strings. For old email aliases,
add a list of typed values:

```yaml
proxy_addresses:
  - "smtp:alice.old@example.org"
  - "smtp:a.example@example.org"
```

The generator stores these as multivalued `proxyAddresses` and adds the bundled
`openldapDeclarativeUser` auxiliary object class. Values retain their spelling;
case-insensitive duplicates are rejected. This stores addresses only: it does
not configure mail delivery or interpret `SMTP:` as a primary-address directive.
Up to 64 values of 1123 characters are accepted.

All these fields are readable by authenticated accounts by default.
Set `read_attributes` to an explicit list to narrow access; that list replaces
the defaults.

##### Extra LDAP attributes and classes<a id="usage-admin-extensions"></a>

Users, groups and bind accounts accept optional `attributes` and
`object_classes`. For example, add this to Alice's user definition:

```yaml
object_classes: ["posixAccount"]
attributes:
  employeeNumber: ["E-0001"]
  preferredLanguage: ["en"]
  uidNumber: ["10001"]
  gidNumber: ["10000"]
  homeDirectory: ["/home/alice"]
```

`inetOrgPerson` remains Alice's structural class; `posixAccount` adds the
POSIX account attributes. This stores data only, without configuring host
login or creating a home directory.

- Attribute values are non-empty lists of strings, including quoted numbers.
  Each string may use [`!vault`](#usage-vault). Limits: 128 attributes per
  entry, 64 values per attribute, 4096 characters per value; no NUL or newlines.
- Class lists add up to 16 auxiliary classes. Attribute/class names and numeric
  OIDs are accepted; attribute options such as `;binary` are not. Duplicate
  names, aliases and generated classes are rejected. `extensibleObject` is
  not allowed.
- Generated identities, naming attributes, passwords and memberships cannot
  be overridden. Users must use the dedicated profile fields where available,
  even if the field was previously omitted. A group or bind account can use
  `attributes.description`, since neither has a dedicated description field.

Extras do not expand read access. Attributes already in the default allowlist
remain readable; others need an explicit `read_attributes` list. For example,
this top-level setting selects identity, membership and POSIX fields, but omits
`mail` and `preferredLanguage`:

```yaml
read_attributes:
  - "objectClass"
  - "entryUUID"
  - "uid"
  - "cn"
  - "member"
  - "memberOf"
  - "employeeNumber"
  - "uidNumber"
  - "gidNumber"
  - "homeDirectory"
```

The list replaces all defaults and applies to every authenticated account.
For a custom class, add its schema to top-level `schema_files`. The
[example employee schema](examples/generator/employee-schema.ldif) defines
`exampleEmployee` with a `costCenter` attribute. Put it beside your directory
YAML, set `schema_files: ["employee-schema.ldif"]`, then add the class and
attribute to the relevant entries. Allocate your own OIDs for production.

Generation checks names, class kinds and reserved fields against the schemas.
Always preflight before activation: OpenLDAP checks required attributes,
allowed attributes and their syntax during offline import. Use native LDIF
for binary values, other structural classes, custom DNs or replacements for
the dedicated profile mappings.

##### Bind accounts<a id="usage-admin-bind-accounts"></a>

`bind_accounts` is a non-empty list. Each item has a unique permanent `id`,
a case-insensitively unique `common_name`, and one credential source:

```yaml
bind_accounts:
  - id: "bind-app-a"
    common_name: "app-a"
    password_file: "/run/credentials/app-a"
  - id: "bind-app-b"
    common_name: "app-b"
    password_hash_file: "/run/credentials/app-b.hash"
```

Use distinct passwords. Rotate one account's credential or remove its item,
increment the revision and deploy. Other accounts keep working. Keeping `id`
and `uuid_namespace` preserves its UUID when changing `common_name`.
All bind accounts share the directory's read policy; separate credentials do
not create per-application access restrictions.

##### Membership and access<a id="usage-admin-membership"></a>

Active users need no group. Inactive users and groups without active members
are omitted when generating a snapshot. `member` and `memberOf` are generated
together.
Names such as `ALLOW` and `DENY` have no built-in effect; applications enforce
their own group rules.

Ordinary accounts cannot write, read password hashes or access `cn=config`.
Authenticated accounts can read approved attributes across the directory;
anonymous directory searches are denied.

##### Credential sources<a id="usage-admin-credentials"></a>

Put exactly one credential source directly in each active user and bind account:

|        Field         | Value |
| -------------------- | ----- |
| `password`           | Original password, hashed by the generator |
| `password_file`      | Absolute container path to an original-password file |
| `password_hash`      | Complete pre-generated Argon2id verifier, preserved unchanged |
| `password_hash_file` | Absolute container path to a verifier file |

Every field accepts an unencrypted value or a
[Vault-encrypted string](#usage-vault). Field meanings never change: a
hash-looking value in `password` is treated as an original password. Encrypting
a file-path field encrypts the path only.

Credential files must be owner-only regular files, not symlinks: one non-empty
UTF-8 line, at most 4096 bytes, with optional LF/CRLF. YAML containing
unencrypted inline credentials must also be owner-only (`chmod 0600` after Git
checkout).

Accepted verifiers: `{ARGON2}$argon2id$v=19$...`, memory at least 19,456 KiB,
two iterations, one lane, 16 salt bytes and 32 digest bytes, canonical unpadded
base64. The [password helper](#usage-prepare) generates these hashes.
Test stronger parameters against bind load and container memory limits.

###### Inline encryption with Ansible Vault<a id="usage-vault"></a>

The generator accepts standard labeled
[Ansible Vault scalars](https://docs.ansible.com/projects/ansible/latest/vault_guide/vault_encrypting_content.html):

```yaml
password_hash: !vault |
  $ANSIBLE_VAULT;1.2;AES256;directory
  ...encrypted payload...
```

`ansible-vault` is included in the generator image. You do not need Ansible
on the host or as your configuration-management tool.

`$ANSIBLE_VAULT` is fixed; `directory` is your key ID. To encrypt a freshly
generated hash on the admin host:

```bash
set +x
umask 077
if [ ! -e "${private}/vault-password" ]; then
  (set -C; podman run --rm --network none --entrypoint openssl "${generator}" \
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

Add this to the [generator arguments](#usage-snapshot-generate):

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

###### Source and snapshot confidentiality<a id="usage-hashes-in-git"></a>

Encrypted definitions or hash-only YAML can live in an access-controlled private
repository. Repository readers, CI jobs, clones and backups may obtain the
verifiers; weak passwords remain vulnerable to offline guessing.
Use strong passwords, high-entropy Vault keys and reviewed changes.
Vault does not protect unencrypted metadata or prevent an encrypted value from
being moved to another field. Review the complete definition before signing.

Vault does **not** encrypt the generated snapshot. It contains password
verifiers and may contain other confidential LDAP attributes. Keep production
definitions and snapshots out of public repositories, image layers and logs.
Never commit original passwords, Vault passwords or private signing keys.


## Image: `quay.io/foundata/openldap-declarative` (LDAP host)<a id="image-ldap"></a>

The runtime verifies a signed snapshot, rebuilds its disposable database and
serves LDAP. It includes OpenLDAP, LDAP client tools and minisign. Source files,
Vault passwords and the private signing key stay on the
[admin host](#image-generator).

### Tags<a id="tags-ldap"></a>

- `latest`: a moving tag updated by the release process.
- `<version>`: a specific release version.

### How to use<a id="usage-ldap"></a>

Run these steps in Bash as the service account on the LDAP host:

1. [Install Podman](https://podman.io/docs/installation) with rootless support.
   The deployment example also requires a running systemd user manager.
2. Pull the
   [runtime image from Quay](https://quay.io/repository/foundata/openldap-declarative)
   and use its immutable reference:

   ```bash
   podman pull quay.io/foundata/openldap-declarative:latest
   runtime=$(podman image inspect --format '{{index .RepoDigests 0}}' \
     quay.io/foundata/openldap-declarative:latest)
   ```

3. [Deploy and verify LDAP](#usage-rootless-podman) with the snapshot and public
   verification key from admin/CI. The runtime requires both before it can
   serve.

#### Deploy and verify LDAP (LDAP host)<a id="usage-rootless-podman"></a>

Use the [rootless Quadlet guide](examples/quadlet/README.md) from the same
release as your images:

1. LDAP host:
   [prepare the service account and units](examples/quadlet/README.md#prepare-the-ldap-host).
2. Admin/CI:
   [transfer the snapshot and public key](examples/quadlet/README.md#transfer-a-snapshot).
3. LDAP host:
   [preflight and activate](examples/quadlet/README.md#preflight-and-activate).
4. LDAP host:
   [verify searches and password binds, then connect the application](examples/quadlet/README.md#verify-and-connect-an-application).

Keep the runtime image selection consistent throughout the guide. It includes
the host expiry backstop and renewal commands. Its names and queries match the
users/groups example; adjust them for another directory definition.


#### Runtime inputs (LDAP host)<a id="runtime-inputs"></a>

|                   Input                    |                Default                 | Meaning |
| ------------------------------------------ | -------------------------------------- | ------- |
| `LDAP_EXPECTED_DIRECTORY_ID`               | none                                   | Required; must match the signed directory ID. |
| `LDAP_TRANSPORT`                           | `ldap`                                 | `ldap`, `ldaps` or `both`. |
| `LDAP_LISTEN_HOST`                         | `127.0.0.1`                            | `127.0.0.1` or `0.0.0.0`. |
| `LDAP_PORT` / `LDAP_LDAPS_PORT`            | `1389` / `1636`                        | Unprivileged ports; distinct for `both`. |
| `LDAP_SEARCH_SIZE_LIMIT`                   | `500`                                  | YAML only: maximum results per search, including the total across pages. |
| `LDAP_SEARCH_TIME_LIMIT`                   | `10`                                   | YAML only: maximum search duration in seconds. |
| `LDAP_LOG_LEVEL`                           | `256`                                  | Numeric slapd log mask. |
| `LDAP_MAX_OPEN_FILES`                      | `4096`                                 | Startup ceiling for soft and hard open-file limits; lower inherited limits are preserved. |
| `LDAP_TLS_CERT_FILE` / `LDAP_TLS_KEY_FILE` | `/tls/cert.pem` / `/tls/cert.key`      | YAML only: required for LDAPS. |
| `LDAP_TLS_CA_FILE`                         | `/tls/ca.pem`                          | YAML only: optional server trust bundle. |
| `LDAP_SNAPSHOT_DIR`                        | `/snapshot`                            | Manifest, signature and listed LDIF files. |
| `LDAP_REVISION_STATE_FILE`                 | `/state/highest-revision`              | Persistent highest revision and manifest digest. |
| `LDAP_SNAPSHOT_PUBLIC_KEY_FILE`            | `/run/credentials/snapshot-public-key` | One minisign public key. |
| `LDAP_SNAPSHOT_PUBLIC_KEY_DIR`             | none                                   | `*.pub` keys; mutually exclusive with file input. |
| `LDAP_ADMIN_PASSWORD_FILE`                 | none                                   | YAML only: optional original-password file for recovery. |
| `LDAP_ADMIN_PASSWORD`                      | none                                   | YAML only: deprecated; conflicts with the file input. |
| `LDAP_BASE_DN` / `LDAP_DOMAIN`             | none                                   | Compatibility checks; must agree with the manifest. |

Search limits accept integers from `1` through `2147483647`, or `unlimited`.
Set them as container environment variables (Quadlet `Environment=`); use the
same settings during preflight and restart after changing them. They do not
change the number of entries the directory can contain.

`LDAP_MAX_OPEN_FILES` accepts integers from `1` through `2147483647`, applies
to both input paths and requires a restart. slapd allocates memory based on
its descriptor limit, so raising this ceiling requires reviewing the container's
memory budget. The ceiling does not reserve memory or guarantee capacity.

For custom LDIF, configure search limits, TLS certificates and any administrator
credentials in LDIF. Setting `LDAP_SEARCH_*`, `LDAP_TLS_*` file inputs or either
`LDAP_ADMIN_PASSWORD*` input fails rather than overriding the signed configuration.
Listener selection and `LDAP_LOG_LEVEL` remain runtime-owned for both paths.

Limits: 1 MiB source YAML; 256 Vault values of 32 KiB each; 32 snapshot LDIF
files, 16 MiB combined LDIF, 1 MiB manifest and 16 KiB signature. Users/groups
YAML uses a 64 MiB MDB maximum; custom LDIF owns `olcDbMaxSize`.
No unsigned mode or expiry bypass.


#### Operations<a id="usage-ops"></a>

##### Renew and deploy (admin/CI and LDAP host)<a id="usage-ops-snapshot-lifecycle"></a>

1. Admin/CI: edit the definition and increment `revision`, including renewals
   without data changes.
2. Admin/CI: generate into a new directory and transfer its contents plus the
   public verification key to the LDAP host.
3. LDAP host:
   [preflight and activate](examples/quadlet/README.md#preflight-and-activate)
   against existing revision state, then verify LDAP and the application.

The example warns after 6 hours and stops after 12. Refresh before the warning.
`expiry_offset_seconds` optionally shortens both deadlines by 0..86,400 seconds
and must remain below the soft TTL. Exact replay does not renew a snapshot;
different content at an accepted revision is rejected.

##### Status and logs (LDAP host)<a id="usage-ops-status"></a>

```bash
systemctl --user status openldap-example.service
journalctl --user -u openldap-example.service -n 50
podman exec openldap-example /usr/local/lib/openldap-declarative/status.sh
```

Status returns JSON: exit `0` healthy, `1` soft-expired, `2`
expired/unavailable. At hard expiry, the runtime stops LDAP with exit `78`.

##### TLS and key rotation (admin/CI and LDAP host)<a id="usage-ops-tls"></a>

Use validated LDAPS outside trusted host-local connections. Clients must check
the server name and CA. Restart after certificate renewal. Follow the
[deployment guide](examples/quadlet/README.md#tls-and-signing-key-rotation) for
TLS mounts and coordinated snapshot-signing key rotation.

To rotate a Vault key, re-encrypt affected source fields on admin/CI with the
new key, verify generation, then retire the old key after accounting for
backups. Vault keys never go to the LDAP host.

##### Backup and recovery (admin/CI and LDAP host)<a id="usage-ops-backup-and-recovery"></a>

Back up definitions, stable IDs, namespaces, required credentials, Vault and
signing keys, deployment settings and image digests. On LDAP hosts, preserve
public keys and revision state. MDB is rebuilt at startup.

For users/groups YAML, no administrator password is configured by default.
For temporary recovery, mount a password file and set `LDAP_ADMIN_PASSWORD_FILE`. This enables
`cn=admin,<base_dn>`, which can write and read verifiers. Never use it for
applications. Recovery changes disappear on rebuild; update the source for
lasting changes, then remove the recovery input and restart.

Custom LDIF owns its recovery and write policy. All database changes, including
overlay-maintained state, disappear on rebuild unless represented in the next
snapshot. The runtime does not export those changes back into your source.


## Development<a id="tests"></a>

[DEVELOPMENT.md](DEVELOPMENT.md) covers local builds, tests and releases.
Production deployments must use qualified release images.
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

This [project](https://foundata.com/en/projects/) was created and is maintained
by [foundata](https://foundata.com/).
