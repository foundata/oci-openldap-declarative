# OpenLDAP Declarative

**"OpenLDAP Declarative" serves an LDAP directory from a signed, expiring
snapshot using OCI containers.** Users/groups YAML provides a read-only
application directory. Custom LDIF gives administrators control of the server
configuration and entries. One definition produces one directory.

|                   Input                   | Use it for |
| ----------------------------------------- | ---------- |
| [Users/groups YAML](#usage-prepare-yaml)  | Application logins, identities, groups and bind accounts, with optional extra attributes and auxiliary classes. The generator supplies the layout and membership attributes. |
| [Custom LDIF](#usage-prepare-native-ldif) | Administrator-owned server configuration and entries, including schemas, ACLs, indexes and packaged overlays. You own the access and credential policies. |

Both routes use YAML for snapshot settings and retain signature verification,
revision checks and expiry supervision. Custom LDIF has no generated-policy
mode. Refresh snapshots before expiry. Removing an account takes effect after
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
    - [Nextcloud directory](#example-nextcloud)
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
        - [Inline encryption](#usage-vault)
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
      - [Temporary administrator access (LDAP host)](#usage-ops-admin)
- [Development](#tests)
- [Licensing, copyright](#licensing-copyright)
  - [Trademarks](#trademarks)
- [Author information](#author-information)


## Examples, use cases<a id="examples"></a>

### Application-specific LDAP, sidecar containers<a id="example-app-ldap"></a>

[foundata](https://foundata.com/) built this project to replace shared
central-directory dependencies with isolated, application-local LDAP sidecar
containers containing only the identities each application needs. This reduces
blast radius, limits data exposure, and removes the central directory from the
application's runtime network path, supporting
[Zero Trust](https://en.wikipedia.org/wiki/Zero_trust_architecture) and
[defense in depth](https://en.wikipedia.org/wiki/Defense_in_depth_(computing)).

Trade-off: account removals take effect only after a new snapshot is deployed
or the current one expires.

#### Nextcloud directory<a id="example-nextcloud"></a>

This `directory.yaml` defines three users, two groups and a search account.
The filters below admit `john` and `jane`; `andreas` is denied even though he
also belongs to the allow group.

```yaml
format_version: 1
input_type: "users-groups"
directory_id: "nextcloud"
base_dn: "dc=example,dc=org"
entry_uuid: "c5fa5db6-3963-44c2-9834-9409d1ab9f86"
organization: "Example"
revision: 1
soft_ttl_seconds: 21600
hard_ttl_seconds: 43200

users:
  - entry_uuid: "003ffd6f-3074-457f-9740-2547970687be"
    username: "john"
    last_name: "Example"
    active: true
    password_hash_file: "/run/credentials/john.hash"
  - entry_uuid: "df0ee4d6-fd01-48b6-9c66-713c52b5ed5a"
    username: "jane"
    last_name: "Example"
    active: true
    password_hash_file: "/run/credentials/jane.hash"
  - entry_uuid: "62d4e3af-b3f5-454f-8293-70d7eb92bf85"
    username: "andreas"
    last_name: "Example"
    active: true
    password_hash_file: "/run/credentials/andreas.hash"

groups:
  - entry_uuid: "73113c3f-7a96-4268-82a4-fd09154d8364"
    groupname: "nextcloud-allow"
    members: ["john", "jane", "andreas"]
  - entry_uuid: "87787418-237b-45f5-936d-7ee34b497db2"
    groupname: "nextcloud-deny"
    members: ["andreas"]

bind_accounts:
  - entry_uuid: "843828e3-1e61-4114-b0a1-b0f4914f55a7"
    username: "nextcloud"
    password_hash_file: "/run/credentials/nextcloud.hash"
```

Generate your own [UUIDs](#usage-admin-identities) once and preserve them.
Use the [password helper](#usage-prepare) to create the four `.hash` files in
`${private}`, then [sign and generate](#usage-snapshot) this definition instead
of running `openldap-init`. Deploy with `LDAP_EXPECTED_DIRECTORY_ID=nextcloud`.

Enable Nextcloud's **LDAP user and group backend** and configure its
[LDAP settings](https://docs.nextcloud.com/server/stable/admin_manual/configuration_user/user_auth_ldap.html):

|              Setting              | Value |
| --------------------------------- | ----- |
| Host / port                       | The LDAP endpoint from your [deployment](#usage-rootless-podman). |
| Base DN                           | `dc=example,dc=org` |
| User DN / password                | `uid=nextcloud,ou=services,dc=example,dc=org` and its original password, not the hash. |
| Base user tree                    | `ou=people,dc=example,dc=org` |
| Base group tree                   | `ou=groups,dc=example,dc=org` |
| User / group display name field   | `cn`  |
| Group member association          | `member` |
| UUID attribute for users / groups | `entryUUID`; configure before the first import. |

Select **Edit LDAP Query** on each relevant tab. **Users** filter:

```text
(&(objectClass=inetOrgPerson)(memberOf=cn=nextcloud-allow,ou=groups,dc=example,dc=org)(!(memberOf=cn=nextcloud-deny,ou=groups,dc=example,dc=org)))
```

**Login Attributes** filter, including the same restrictions because a custom
login filter can override the user filter (`%uid` is Nextcloud's login
placeholder):

```text
(&(objectClass=inetOrgPerson)(memberOf=cn=nextcloud-allow,ou=groups,dc=example,dc=org)(!(memberOf=cn=nextcloud-deny,ou=groups,dc=example,dc=org))(uid=%uid))
```

**Groups** filter to expose only the allow group:

```text
(&(objectClass=groupOfNames)(cn=nextcloud-allow))
```

Keep the default UUID-based internal username. Test the connection and verify
that `john` and `jane` can log in while `andreas` cannot. These filters enforce
Nextcloud access only: group names have no built-in meaning to LDAP, and
`andreas` can still bind directly. Set `active: false` and redeploy to remove
his LDAP entry entirely. Existing application sessions and caches may outlive
the directory change.


## Where actions run<a id="usage-hosts"></a>

|    Location     | Responsibilities |
| --------------- | ---------------- |
| Admin host / CI | Maintain directory definitions, generate and sign snapshots. Holds source credentials, Vault passwords and the private signing key. |
| LDAP host       | Serve the directory via LDAP(S). Holds public verification keys, snapshot files and persistent revision state. |

The same machine can fulfill both roles, for example, for testing or when the
security benefits over centralized directories are not important to you.

Both images support Linux
[amd64](https://www.kernel.org/doc/html/latest/arch/x86/x86_64/index.html) and
[arm64](https://www.kernel.org/doc/html/latest/arch/arm64/). Local builds and
testing are covered in
[`DEVELOPMENT.md`](DEVELOPMENT.md#build).


## Image: `quay.io/foundata/openldap-declarative-generator` (admin host / CI)<a id="image-generator"></a>

The generator is a one-shot command. It reads your definition, writes a signed
snapshot and exits, so no tools installation is needed on your host.


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
   ```

3. [Prepare directory data](#usage-prepare), then
   [sign and generate a snapshot](#usage-snapshot).


#### Prepare directory data<a id="usage-prepare"></a>

Prepare these paths and the password-hashing helper in a Bash terminal as your
normal admin/CI user; no root shell is needed. Then choose one input route
below.

```bash
set +x # Disable tracing before handling secrets.
umask 077 # New files are owner-only; new directories are owner-accessible only.

# directory.yaml and referenced LDIF/schema; mounted at /input.
# Private Git is suitable for reviewed hash-only or Vault-encrypted sources, not plaintext secrets.
data="${HOME}/directory-data"

# Signing/Vault keys and credential files; never commit.
# Mounted at /run/credentials on admin/CI; deploy only snapshot.pub from this directory.
private="${HOME}/.config/openldap-declarative"

# Signed revision-* directories; mounted at /output.
# Deploy one complete revision directory to the LDAP host; it contains verifiers, so keep it private.
output="${HOME}/.local/share/openldap-declarative/generated"

install -d -m 0700 "${data}" "${private}" "${output}" # Restrict these host directories to their owner.

hash_password() (
  # Use the immutable digest of the generator image pulled above.
  generator=$(podman image inspect --format '{{index .RepoDigests 0}}' \
    quay.io/foundata/openldap-declarative-generator:latest)
  set +x
  set -euo pipefail
  # Read password input literally, without terminal echo.
  read -r -s -p "$1: " password
  # Keep the password out of child-process environments.
  export -n password
  printf '\n' >&2
  test -n "${password}" # Reject empty passwords.
  # Send plaintext only through stdin; stdout contains the hash.
  printf '%s' "${password}" |
    podman run --rm -i --network none --entrypoint openldap-password "${generator}"
)
```

The helper returns a salted [Argon2id](https://en.wikipedia.org/wiki/Argon2)
hash. `openldap-password` accepts one non-empty UTF-8 line of at most 4096
bytes, with an optional new line at the end (LF or CRLF).


##### Application directory: users/groups YAML<a id="usage-prepare-yaml"></a>

Use this route if you need simple application logins, identities and group
memberships, with one or more [bind accounts](#usage-admin-bind-accounts)
for directory searches.

It provides a fixed layout and managed read-only policy; use
[custom LDIF](#usage-prepare-native-ldif) when you need another layout or
control over OpenLDAP configuration. Create a new definition and its credential
files:

```bash
generator=$(podman image inspect --format '{{index .RepoDigests 0}}' \
  quay.io/foundata/openldap-declarative-generator:latest)
podman run --rm --userns=keep-id --user "$(id -u):$(id -g)" \
  --network none --read-only --read-only-tmpfs=false \
  --cap-drop all --security-opt no-new-privileges \
  --volume "${data}:/output:Z" --entrypoint openldap-init "${generator}" \
  --directory-id example-app \
  --base-dn 'dc=example-app,dc=services,dc=example,dc=org' \
  --organization 'Example Company'

# hash_password() was defined above. Refuse to replace existing credential files.
(set -C; hash_password "Alice password" > "${private}/alice.hash")
(set -C; hash_password "Application bind password" > "${private}/application.hash")
```

`openldap-init` writes owner-only `/output/directory.yaml` and refuses an
existing file or symlink. It creates user `alice`, group `staff` and bind
account `application`, with fresh UUIDv4 identities and UUID-based membership.
Use `--username`, `--groupname`, `--bind-username` or `--output` to change those
defaults; credential paths follow the account names. It creates no passwords or
keys.

Review the definition, especially `last_name` (initially the username), and add
profile fields as needed. Preserve its UUIDs across edits and rebuilds. All
active users are included. See the
[larger example](examples/generator/directory.yaml) for profile fields, inactive
users and credential files. Continue with
[signing and generation](#usage-snapshot).


##### Custom directory: LDIF<a id="usage-prepare-native-ldif"></a>

Use this general-purpose route when you need custom entry types, directory
layouts or server policies. It allows you to administer OpenLDAP directly and
therefore requires solid knowledge of OpenLDAP administration.

Supply complete configuration and directory entries; you own schemas, ACLs,
indexes, overlays and password policy, without generated defaults merged into
them. Start with the [custom LDIF guide](docs/custom-ldif.md) and its read-only
example.

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
private="${HOME}/.config/openldap-declarative"

generator=$(podman image inspect --format '{{index .RepoDigests 0}}' \
  quay.io/foundata/openldap-declarative-generator:latest)

podman run --rm --userns=keep-id --user "$(id -u):$(id -g)" \
  --network none --volume "${private}:/run/credentials:Z" \
  --entrypoint minisign "${generator}" \
  -G -W -s /run/credentials/snapshot.key -p /run/credentials/snapshot.pub
```

[Minisign](https://jedisct1.github.io/minisign/) keys have no built-in expiry;
snapshots expire separately. Minisign supports password-protected keys, but `-W`
creates the unencrypted key required by this generator's unattended signing.
Keep `snapshot.key` private on admin/CI and back it up. Deploy only
`snapshot.pub`.

- Lost public key: restore it or rerun the Podman command above with `-R`
  instead of `-G -W`, keeping the same `-s` and `-p` paths.
- Lost private key: restore it, or create a new pair and deploy a fresh snapshot
  with the new public key to every LDAP host and its backstop. Existing
  snapshots remain usable until expiry while their public key is still trusted.
- Suspected compromise: stop affected LDAP services, replace the key pair and
  deploy a reviewed snapshot. Remove the old public key from every runtime,
  preflight and backstop trust input before restarting. A stolen signing key
  can authorize malicious identities, credentials or custom server configuration
  if an attacker can deliver a snapshot to a trusting host.

Follow the
[coordinated rotation procedure](examples/quadlet/README.md#signing-key-rotation),
keeping revision state and increasing the snapshot revision.


##### Generate a snapshot<a id="usage-snapshot-generate"></a>

Generate the signed snapshot to deploy to the LDAP host:

```bash
data="${HOME}/directory-data"
private="${HOME}/.config/openldap-declarative"
output="${HOME}/.local/share/openldap-declarative/generated"

generator=$(podman image inspect --format '{{index .RepoDigests 0}}' \
  quay.io/foundata/openldap-declarative-generator:latest)

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
the complete custom `config.ldif`. The signed revision comes from YAML; the
shell variable only names the output.


#### Directory administration<a id="usage-admin"></a>

The model-specific settings below apply to users/groups YAML. Custom LDIF
administration is covered in [its guide](docs/custom-ldif.md).


##### IDs, names and renames<a id="usage-admin-identities"></a>

|                     Field                     | Meaning |
| --------------------------------------------- | ------- |
| `directory_id`                                | Snapshot target, matched by `LDAP_EXPECTED_DIRECTORY_ID`. Not an LDAP DN or hostname. |
| `entry_uuid` on a user, group or bind account | Permanent identity, copied directly to LDAP `entryUUID`. |
| Top-level `entry_uuid`                        | Base entry's UUID; also used to derive stable UUIDs for the generated OUs. |
| User `username`                               | LDAP `uid` and login DN: `uid=alice,ou=people,<base_dn>`. |
| Bind account `username`                       | LDAP `uid` and bind DN: `uid=application,ou=services,<base_dn>`. |
| User/bind `display_name`                      | Supplies LDAP `displayName` and `cn`. If omitted, `cn` uses `username` and `displayName` is absent. Does not change the DN. |
| Group `groupname`                             | LDAP `cn` and DN: `cn=staff,ou=groups,<base_dn>`. |

Generate [UUIDv4](https://en.wikipedia.org/wiki/Universally_unique_identifier)
values once, as in the setup example. Canonical lowercase RFC-variant UUIDs of
versions 1 through 8 are accepted. UUIDs must be unique across the directory,
including inactive users. Never recycle or regenerate them when renaming an
entry.

To rename an account, change `username`, update any username-based group
references, increase `revision`, then regenerate and deploy. UUID-based
references need no edits. The generator updates LDAP DNs and memberships while
preserving `entryUUID`. Applications keyed by username or DN may need their own
migration. A fresh top-level UUID does not replace the UUIDs on users, groups
or bind accounts when cloning a definition.

Example: rename `alice` to `alicia` and `bob` to `robert`; `carol` stays
unchanged. These excerpts show only identity and membership fields. Keep the
other fields and credentials unchanged.

Before:

```yaml
revision: 1
users:
  - entry_uuid: "003ffd6f-3074-457f-9740-2547970687be"
    username: "alice"
  - entry_uuid: "df0ee4d6-fd01-48b6-9c66-713c52b5ed5a"
    username: "bob"
  - entry_uuid: "62d4e3af-b3f5-454f-8293-70d7eb92bf85"
    username: "carol"
groups:
  - entry_uuid: "73113c3f-7a96-4268-82a4-fd09154d8364"
    groupname: "staff"
    members: ["003ffd6f-3074-457f-9740-2547970687be", "bob", "carol"]
```

After:

```yaml
revision: 2
users:
  - entry_uuid: "003ffd6f-3074-457f-9740-2547970687be"
    username: "alicia"
  - entry_uuid: "df0ee4d6-fd01-48b6-9c66-713c52b5ed5a"
    username: "robert"
  - entry_uuid: "62d4e3af-b3f5-454f-8293-70d7eb92bf85"
    username: "carol"
groups:
  - entry_uuid: "73113c3f-7a96-4268-82a4-fd09154d8364"
    groupname: "staff"
    members: ["003ffd6f-3074-457f-9740-2547970687be", "robert", "carol"]
```

Alice's UUID reference needs no edit; Bob's username reference changes. LDAP
membership DNs update for both users, and all entry UUIDs stay the same.


##### User profile fields<a id="usage-admin-profile-fields"></a>

Each user requires `last_name`, mapped to LDAP `sn` (surname).
Users/groups YAML also accepts these optional strings:

|    YAML field     | LDAP attribute |
| ----------------- | -------------- |
| `first_name`      | `givenName` (first name) |
| `initials`        | `initials`     |
| `display_name`    | `displayName` and `cn` |
| `description`     | `description`  |
| `office`          | `physicalDeliveryOfficeName` |
| `phone`           | `telephoneNumber` |
| `mobile`          | `mobile` (mobile phone number) |
| `email`           | `mail` (email) |
| `org`             | `o` (organization name) |
| `employee_number` | `employeeNumber` |
| `department`      | `ou` (department) |
| `job_title`       | `title`        |

`org` and `department` describe the user without changing the DN or the
directory's top-level `organization`. `employee_number` is independent of
`entry_uuid`; quote numeric values to preserve leading zeros.

Omit unset optional fields rather than supplying empty strings. For old email
aliases, add a list of typed values:

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
  preferredLanguage: ["en"]
  uidNumber: ["10001"]
  gidNumber: ["10000"]
  homeDirectory: ["/home/alice"]
```

[`inetOrgPerson`](https://www.rfc-editor.org/info/rfc2798/) remains Alice's
structural class; `posixAccount` adds the POSIX account attributes. This stores
data only, without configuring host login or creating a home directory.

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

`bind_accounts` is a non-empty list. Each item has a permanent `entry_uuid`,
a `username` unique across users and bind accounts (case-insensitive), and one
credential source. Optional `display_name` follows the same rules as for users:

```yaml
bind_accounts:
  - entry_uuid: "843828e3-1e61-4114-b0a1-b0f4914f55a7"
    username: "app-a"
    display_name: "Application A"
    password_file: "/run/credentials/app-a"
  - entry_uuid: "5b5e5bcc-58cc-4c41-b125-927b926fb8f4"
    username: "app-b"
    password_hash_file: "/run/credentials/app-b.hash"
```

Bind accounts use `ou=services`, so applications searching `ou=people` do not
include their own bind accounts among users.

Use distinct passwords. Rotate one account's credential or remove its item,
increment the revision and deploy. Other accounts keep working. Keep
`entry_uuid` when changing `username`; update the application's bind DN.
All bind accounts share the directory's read policy; separate credentials do
not create per-application access restrictions.


##### Membership and access<a id="usage-admin-membership"></a>

Each `members` item can be a user's `entry_uuid` or `username`; both forms can
be mixed in one list. References are case-insensitive and only resolve to
`users`, not bind accounts. Unknown or ambiguous references and duplicate users
(including a username and UUID for the same person) are rejected.

UUID references survive username changes. Username references are easier to
read, but must be updated on rename; reassigning a username can also reassign
its group memberships. Use UUIDs where that risk is unacceptable.

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


###### Inline encryption<a id="usage-vault"></a>

The generator accepts standard labeled
[Ansible Vault scalars](https://docs.ansible.com/projects/ansible/latest/vault_guide/vault_encrypting_content.html):

```yaml
password_hash: !vault |
  $ANSIBLE_VAULT;1.2;AES256;ldapvault
  ...encrypted payload...
```

`$ANSIBLE_VAULT` is fixed; `ldapvault` is your key ID and you can choose it
freely. The bundled `ansible-vault` CLI handles encryption and decryption. You
do *not* need Ansible on the host or as your configuration-management tool.

To encrypt a freshly
generated hash on the admin host:

```bash
private="${HOME}/.config/openldap-declarative"

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
key when encrypting another field. Replace the user's existing credential field
(`password_hash_file` in the setup example) with the generated `password_hash`
block, indented at the same level as its other fields.

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

A bit of reasoning: We chose Ansible Vault because each encrypted YAML value is
self-contained and carries its key ID. The well known alternative
[SOPS](https://getsops.io/docs/reference/#encryption-protocol) was not chosen as
it requires document-level key and integrity metadata, adding useless extra
structure for this per-value workflow.


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
For pod-local `localhost`, use the
[shared-pod recipe](examples/quadlet/README.md#shared-application-pod).


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
| `LDAP_EXPECTED_BASE_DN`                    | none                                   | Optional exact-match assertion against the signed base DN; never overrides it. |

Search limits accept integers from `1` through `2147483647`, or `unlimited`.
Set them in the guide's `ldap.env` (Quadlet `EnvironmentFile=` and Podman
`--env-file`). `openldap-preflight` uses the same variables and defaults as
startup; run it in a separate container with fresh scratch storage and read-only
revision state. Restart after changing settings. They do not
change the number of entries the directory can contain.

`LDAP_MAX_OPEN_FILES` accepts integers from `1` through `2147483647`, applies
to both input paths and requires a restart. slapd allocates memory based on
its descriptor limit, so raising this ceiling requires reviewing the container's
memory budget. The ceiling does not reserve memory or guarantee capacity.

For custom LDIF, configure search limits, TLS certificates and any administrator
credentials in LDIF. Setting `LDAP_SEARCH_*`, `LDAP_TLS_*` file inputs or
`LDAP_ADMIN_PASSWORD_FILE` fails rather than overriding the signed
configuration. Listener selection and `LDAP_LOG_LEVEL` remain runtime-owned for
both paths.

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

Retain and reuse the exact generated artifact for deployment retries. See the
[renewal and retry recipe](examples/quadlet/README.md#renewals-and-image-updates)
for revision ownership, scheduling and interrupted deployments.


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

Back up these inputs on **admin/CI**, using the paths from this guide:

|     Location (if you followed the examples)      | Backup contents |
| ------------------------------------------------ | --------------- |
| `~/directory-data/` (`${data}`)                  | `directory.yaml` and all referenced LDIF and schema files. Put them under version control (e.g. git) if possible. |
| `~/.config/openldap-declarative/` (`${private}`) | `snapshot.key`, `snapshot.pub`, `vault-password` if used, and any credential files stored here. |
| Your deployment repository or CI configuration   | Customized service units, environment settings, mount sources, deployed revisions, generator/runtime image digests and TLS provisioning settings. |

Include source files and credentials stored outside these directories, such as
CI-managed secrets. Protect secret backups with encryption and restricted
access; retain the Vault passwords needed to decrypt backed-up definitions.

On the **LDAP host**, back up local deployment changes not held in your
deployment repository: the example's `openldap-example.*` files under
`~/.config/containers/systemd/`, `openldap-example-backstop.*` under
`~/.config/systemd/user/`, and `~/.local/libexec/openldap-expiry-backstop`.
Include host files referenced by custom mounts, such as TLS keys and
certificates, unless your provisioning process recreates them. Here, `~` is
the LDAP service account's home.

To restore:

1. Admin/CI: restore the current definition, referenced files, credentials and
   signing/Vault keys. Preserve all `entry_uuid` values.
2. Admin/CI: set `revision` above the last deployed revision and
   [generate a fresh signed snapshot](#usage-snapshot-generate).
3. LDAP host: redeploy the service configuration and mount inputs, including
   the current public verification key from admin/CI.
4. [Preflight and activate](examples/quadlet/README.md#preflight-and-activate),
   then
   [verify searches and password binds](examples/quadlet/README.md#verify-and-connect-an-application).
   Startup establishes revision state from the freshly generated snapshot.


##### Temporary administrator access (LDAP host)<a id="usage-ops-admin"></a>

For users/groups YAML, temporary debugging access requires an original-password
file mounted read-only into the container and `LDAP_ADMIN_PASSWORD_FILE` set to
its container path. Restart to enable `cn=admin,<base_dn>`, which can write and
read password verifiers. Use it only for administration. Update the source for
lasting changes, then remove the setting and mount and restart.

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


### Trademarks<a id="trademarks"></a>

- Red Hat®, Ansible® and Quay® are trademarks of Red Hat, Inc., registered in
  the US and other countries
- OpenLDAP® is a registered trademark of the OpenLDAP Foundation
- Debian® is a registered trademark of Software in the Public Interest, Inc.
- Linux® is a registered trademark of Linus Torvalds

Their use here is purely descriptive and does not imply any affiliation with or
endorsement by the trademark holders.


## Author information<a id="author-information"></a>

This [project](https://foundata.com/en/projects/) was created and is maintained
by [foundata](https://foundata.com/).
