# OpenLDAP Declarative

Read-only LDAP for applications, generated from YAML and served from signed,
expiring snapshots. Applications authenticate locally without a connection to
the central directory.

Refresh snapshots before expiry. Account removal takes effect when you deploy
the change or the old snapshot expires; application sessions and caches need
their own expiry policy.

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

- [Features](#features)
- [Where actions run](#usage-hosts)
- [Installation (admin/CI)](#installation)
- [Quick start](#usage)
  - [1. Create directory data (admin/CI)](#usage-yaml)
  - [2. Set passwords (admin)](#usage-credentials-setup)
  - [3. Create signing keys (admin)](#usage-signing-keys)
  - [4. Generate a snapshot (admin/CI)](#usage-generate-snapshot)
  - [5. Deploy and query LDAP (LDAP host)](#usage-rootless-podman)
- [Directory administration (admin/CI)](#usage-maintenance)
  - [Services: one directory per application](#usage-services)
  - [IDs and renames](#usage-identities)
  - [Membership and access](#usage-membership)
  - [Credential sources](#usage-credentials)
    - [Hashes in private Git](#usage-hashes-in-git)
- [Operations](#usage-ops)
  - [Deploy and renew (admin/CI and LDAP host)](#snapshot-lifecycle)
  - [Status and logs (LDAP host)](#usage-status)
  - [TLS and signing keys (admin/CI and LDAP host)](#tls)
  - [Backup and recovery (admin/CI and LDAP host)](#backup-and-recovery)
- [Runtime inputs (LDAP host)](#runtime-inputs)
- [Development](#tests)
- [Licensing, copyright](#licensing-copyright)
- [Author information](#author-information)


## Features<a id="features"></a>

- Users, groups and separate service directories from YAML.
- Argon2id passwords from plaintext files, hash files or inline hashes.
- [Minisign](https://github.com/jedisct1/minisign) signatures, revision replay
  protection and automatic shutdown at snapshot expiry.
- Rootless Podman deployment with a read-only filesystem; optional LDAPS.


## Where actions run<a id="usage-hosts"></a>

| Location | Actions and files |
| -------- | ----------------- |
| Admin/CI | Maintain directory and credentials YAML, generate and sign snapshots, then transfer them. Holds the private signing key; runs the generator image. |
| LDAP host | Preflight and serve one service snapshot using the runtime image. Holds that snapshot, public verification keys and persistent revision state. No generator or private signing key. |

An admin machine can perform the whole signing workflow. For automation, a
protected CI job uses the same inputs and signing key. Password prompts and
initial key creation below are manual setup; CI consumes the prepared credentials.

Only the selected service snapshot and public key cross to the LDAP host.
Commands in a container still run on the host named in the heading. Use a
separate Bash terminal for each host; shell variables are local to that terminal.


## Installation (admin/CI)<a id="installation"></a>

Use Linux with rootless Podman, Bash and Git. The generator and runtime images both
include minisign; no host installation of minisign or Python is needed.
The runtime image is used here only to generate password hashes. The deployment
guide pulls it separately on the LDAP host.

Pull the runtime and generator from the same release. The commands below select
`stable` and resolve each image to its pulled digest:

```bash
runtime=quay.io/foundata/openldap-declarative:stable
generator=quay.io/foundata/openldap-declarative-generator:stable
podman pull "${runtime}"
podman pull "${generator}"
runtime=$(podman image inspect --format '{{index .RepoDigests 0}}' "${runtime}")
generator=$(podman image inspect --format '{{index .RepoDigests 0}}' "${generator}")
```

Record both digests with your deployment. For production, use your approved
release version and signature-verification policy; a digest alone does not
authenticate an image publisher.


## Quick start<a id="usage"></a><a id="usage-quick-start"></a>

Run steps 1-4 in the admin terminal. For step 5, prepare the LDAP host, transfer
from the admin terminal, then return to the LDAP host to activate and query.

### 1. Create directory data (admin/CI)<a id="usage-yaml"></a>

Keep `directory.yaml` in a dedicated, access-controlled Git repository.
This example keeps credentials outside it; [hash-only credentials YAML can also
be versioned privately](#usage-hashes-in-git). Keep plaintext passwords, private
signing keys and generated snapshots out of Git.

```bash
umask 077
data="${HOME}/directory-data"
private="${HOME}/.config/openldap-declarative"
output="${HOME}/.local/share/openldap-declarative/generated"
install -d -m 0700 "${data}" "${private}" "${output}"
git init "${data}"
namespace=$(podman run --rm --network none --entrypoint python3 "${generator}" \
  -c 'import uuid; print(uuid.uuid4())')
cat > "${data}/directory.yaml" <<YAML
format_version: 1
uuid_namespace: "${namespace}"
organization: "Example Company"
users:
  - id: "person-0001"
    uid: "alice"
    common_name: "Alice Example"
    surname: "Example"
    mail: "alice@example.org"
    active: true
groups:
  - id: "group-staff"
    common_name: "staff"
    members: ["person-0001"]
services:
  - id: "example-app"
    base_dn: "dc=example-app,dc=services,dc=example,dc=org"
    revision: 1
    soft_ttl_seconds: 21600
    hard_ttl_seconds: 43200
    expiry_offset_seconds: 0
    groups: ["group-staff"]
    users: []
    bind_account:
      id: "bind-example-app"
      common_name: "application"
YAML
```

Generate `uuid_namespace` once for a new directory; preserve it on every update
and in backups. See [IDs and renames](#usage-identities) before choosing IDs.
The [larger example](examples/generator/directory.yaml) includes multiple services.
The [service fields](#usage-services) select which users and groups each
application receives and how long its snapshot remains valid.

### 2. Set passwords (admin)<a id="usage-credentials-setup"></a>

This prompts for Alice's password and then the application's LDAP bind password,
writing only their hashes. Keep the two passwords distinct.

```bash
(
  set +x
  set -euo pipefail
  umask 077
  for account in person-0001 example-app-bind; do
    read -r -s -p "Password for ${account}: " password
    export -n password
    printf '\n' >&2
    printf '%s' "${password}" |
      podman run --rm -i --network none --entrypoint slappasswd "${runtime}" \
        -o module-path=/usr/lib/ldap \
        -o 'module-load=argon2 m=19456 t=2 p=1' \
        -h '{ARGON2}' -T /dev/stdin > "${private}/${account}.hash"
    unset password
  done
)
cat > "${private}/credentials.yaml" <<'YAML'
format_version: 1
users:
  person-0001:
    password_hash_file: "/run/credentials/person-0001.hash"
services:
  example-app:
    bind_password_hash_file: "/run/credentials/example-app-bind.hash"
YAML
```

Passwords pass through stdin, never command arguments or environment variables.
Paths in credentials YAML refer to the container's mounted directory.
[Other credential sources](#usage-credentials) include plaintext files and inline hashes.

### 3. Create signing keys (admin)<a id="usage-signing-keys"></a>

Run once on the administration host:

```bash
podman run --rm --userns=keep-id --user "$(id -u):$(id -g)" \
  --network none --volume "${private}:/run/credentials:Z" \
  --entrypoint minisign "${generator}" \
  -G -W -s /run/credentials/snapshot.key -p /run/credentials/snapshot.pub
```

`-W` creates an unencrypted private key for unattended signing. Back up
`snapshot.key` securely; keep it on the signing host or in its secret store,
never in Git, an image or an application host. Deploy only `snapshot.pub`.

### 4. Generate a snapshot (admin/CI)<a id="usage-generate-snapshot"></a>

```bash
revision=1
podman run --rm --userns=keep-id --user "$(id -u):$(id -g)" \
  --network none \
  --volume "${data}:/input:ro,Z" \
  --volume "${private}:/run/credentials:ro,Z" \
  --volume "${output}:/output:Z" "${generator}" \
  --directory /input/directory.yaml \
  --credentials /run/credentials/credentials.yaml \
  --signing-key /run/credentials/snapshot.key \
  --service example-app --output "/output/revision-${revision}"
```

The output child must not already exist. The shell variable names the output
directory; the signed revision comes from `services[].revision` in the YAML.
Each selected service produces `directory.ldif`, `manifest.json` and
`manifest.json.minisig`. Repeat `--service ID` for several services; omit it
to generate all services.

### 5. Deploy and query LDAP (LDAP host)<a id="usage-rootless-podman"></a>

Follow the [Quadlet deployment guide](examples/quadlet/README.md) to transfer
the snapshot, preflight it, start LDAP and verify the application bind and user
password. It also covers renewals and the host expiry backstop.


## Directory administration (admin/CI)<a id="usage-maintenance"></a>

### Services: one directory per application<a id="usage-services"></a>

Users and groups are the shared source records. A service selects which of them
to export for an application, such as Nextcloud, and configures that export's
LDAP base DN, bind account and expiry. Each service produces a separate snapshot
for its own LDAP container. `services` is this project's export configuration,
not an OpenLDAP requirement. Defining a service does not start containers.

For one application, define one service. Add another when an application needs
its own selection, bind password or snapshot lifecycle; reuse the existing user
and group IDs.

| Field in the example | Meaning |
| -------------------- | ------- |
| `id: "example-app"` | Names the export; used by `--service`, its output directory and the target's `LDAP_EXPECTED_SERVICE_ID`. |
| `base_dn` | LDAP search root for this application. It does not configure a DNS name or hostname. |
| `revision: 1` | Snapshot version. Increase it for every new snapshot, including renewals. |
| `soft_ttl_seconds: 21600` | Warn 6 hours after generation. |
| `hard_ttl_seconds: 43200` | Stop LDAP 12 hours after generation unless replaced. |
| `expiry_offset_seconds: 0` | Subtract this many seconds from both deadlines; `0` leaves them unchanged. |
| `groups: ["group-staff"]` | Include this group and its active members. |
| `users: []` | No additional individual users. This does not exclude users selected through groups. |
| `bind_account` | The application's search account: `cn=application,ou=services,<base_dn>`. Its `id` keeps its UUID stable. |

The example exports Alice and `staff`, plus a separate application bind
account. Its password comes from `credentials.yaml` under `services.example-app`.
Configure the application with the original bind password, not its stored hash;
Alice authenticates with her own password.

### IDs and renames<a id="usage-identities"></a>

`person-0001` identifies Alice's record in your source YAML. Other records refer
to this value to select Alice or assign her credentials. It is not a YAML anchor
and is not stored as a separate LDAP attribute.

| Field | Used for |
| ----- | -------- |
| User `id`, e.g. `person-0001` | References in `groups[].members`, `services[].users` and the credentials YAML's `users` map. Also determines the user's LDAP `entryUUID`. |
| User `uid`, e.g. `alice` | LDAP login name and DN: `uid=alice,ou=people,<base_dn>`. |
| Group `id`, e.g. `group-staff` | References in `services[].groups` and the group's `entryUUID`. Its `common_name` becomes LDAP `cn` and names its DN. |
| Service `id`, e.g. `example-app` | `--service`, output directory, `LDAP_EXPECTED_SERVICE_ID`, credentials `services` map and per-service password overrides. |
| Bind account `id`, e.g. `bind-example-app` | Determines the bind account's `entryUUID`. Its `common_name` names the bind DN; credentials use the **service ID**. |
| `uuid_namespace` | Generated once in step 1 and stored in directory YAML. Together with each object's type and ID, determines its LDAP `entryUUID`. |
| LDAP `entryUUID` | Generated by the tool and written into LDAP. Use this attribute for an application's persistent user mapping. |

To rename Alice, change `uid` while keeping `id` and `uuid_namespace` unchanged.
Deploy a higher revision. Her DN and group membership DNs change; her
`entryUUID` and source references stay the same. Applications keyed by username
or DN may lose their account mapping. Changing `common_name` or `mail` does
not change a user's DN.

IDs can be UUID strings or other unique, permanent strings. Never recycle them,
change their case or regenerate the namespace. A UUID used as `id` is still
an input to the [UUID calculation](ARCHITECTURE.md#44-stable-identifiers),
not the resulting LDAP `entryUUID`.

### Membership and access<a id="usage-membership"></a>

Only selected, active users appear in a service snapshot. Select users through
`services[].groups` or directly through `services[].users`. Groups with no
selected active members are omitted. OpenLDAP requires no default group;
a directly selected user can have no groups and no `memberOf` attribute.
Names such as `ALLOW` or `DENY` have no built-in effect: service selections only
include users. Enforce any additional group-based access rules in the application.

Normal accounts cannot write, read password hashes or access `cn=config`.
Authenticated users can read approved attributes of other entries in the same
service. Anonymous searches are denied.

### Credential sources<a id="usage-credentials"></a>

Use these keys in credentials YAML:

| Source | User default | Per-service overrides, keyed by service ID | Service bind account |
| ------ | ------------ | ----------------------------------------- | -------------------- |
| Plaintext file | `password_file` | `service_password_files` | `bind_password_file` |
| Hash file | `password_hash_file` | `service_password_hash_files` | `bind_password_hash_file` |
| Inline hash | `password_hash` | `service_password_hashes` | `bind_password_hash` |

Define at most one default per user and exactly one source per bind account.
Overrides take precedence across all source types; do not put the same service
in two override maps. A user may have overrides without a default.

Generate hash files with [step 2](#usage-credentials-setup). To embed a hash,
use `password_hash: 'COMPLETE_VERIFIER'` or
`bind_password_hash: 'COMPLETE_VERIFIER'`, replacing the placeholder with the
entire generated hash. For a per-service override:

```yaml
users:
  person-0001:
    service_password_hashes:
      example-app: 'COMPLETE_VERIFIER'
```

Hash sources are validated and copied unchanged. Plaintext is accepted only
from files and hashed with a fresh salt; a hash placed in `password_file`
is treated as a literal password.

Credential files must be regular files, not symlinks, with owner-only permissions
(`0600`): one non-empty UTF-8 line, at most 4096 bytes, with optional LF/CRLF.
Keep their parent directory `0700` and credentials YAML `0600`, including when
it contains hashes.

Accepted hashes: `{ARGON2}$argon2id$v=19$...`, `m>=19456` KiB, `t>=2`, `p>=1`,
at least 16 salt bytes and 32 digest bytes, canonical unpadded base64.
Use fresh salts; test stronger settings against your memory limits and bind load.
Keep hashes out of logs, image layers and application filesystem access.

#### Hashes in private Git<a id="usage-hashes-in-git"></a>

Hash-only credentials YAML can live in a tightly controlled private repository.
Treat repository readers, CI jobs, clones and backups as having access to those
verifiers. Argon2id makes offline guessing expensive; it cannot protect a weak
password from being guessed. Use strong, unique passwords and review changes
before a protected job signs them. See [OWASP's password storage guidance](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).

Deleting a hash from the current file does not remove it from
[history or existing clones](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository).
Use a separate secret store or encrypted credentials file when repository access
is broader than credential access. Decrypt outside the checkout before generation.
Never commit plaintext passwords or private signing keys.

Git does not preserve owner-only permissions. If credentials YAML is versioned
alongside directory YAML, stage it after checkout before running the generator:

```bash
install -m 0600 "${data}/credentials.yaml" "${private}/credentials.yaml"
```


## Operations<a id="usage-ops"></a>

### Deploy and renew (admin/CI and LDAP host)<a id="snapshot-lifecycle"></a>

Use the [rootless Quadlet guide](examples/quadlet/README.md) to install a service,
preflight snapshots, switch revisions and enable the host expiry backstop.
Applications on its internal network use `ldap://ldap:1389`, their service's
base DN and `cn=application,ou=services,<base_dn>` bind DN.

1. On admin/CI, edit directory data or credentials and increment each selected
   service's YAML `revision`, even for a renewal with no account changes.
2. On admin/CI, repeat [generation](#usage-generate-snapshot) with a new output
   directory.
3. From admin/CI, transfer the selected snapshot to the LDAP host; provision its
   public verification key on initial setup or planned rotation.
4. On the LDAP host, preflight against existing revision state, activate and restart.
5. On the LDAP host, check status; verify authentication in the application.

The example warns after 6 hours and stops after 12 hours. Refresh before the
warning deadline. Each service sets `soft_ttl_seconds < hard_ttl_seconds`;
`expiry_offset_seconds` shortens both deadlines and must be `0..86400` and
less than the soft TTL. Replaying the exact artifact is allowed but does not
renew it. Regenerating with the same revision is rejected.

For an image update, update the generator on admin/CI. On the LDAP host, pull
the new runtime, preflight with it, then update the Quadlet's `Image=` and restart.
Record both release digests.

### Status and logs (LDAP host)<a id="usage-status"></a>

```bash
systemctl --user status openldap-example.service
journalctl --user -u openldap-example.service -n 50
podman exec openldap-example /usr/local/lib/openldap-declarative/status.sh
```

Status returns JSON: exit `0` healthy, `1` soft-expired, `2` expired/unavailable.
Soft expiry is a warning; at hard expiry the runtime stops LDAP with exit `78`.

### TLS and signing keys (admin/CI and LDAP host)<a id="tls"></a>

Use validated LDAPS outside trusted host-local connections. TLS 1.2/1.3 is
required; clients must validate the server name and CA. Restart after certificate
renewal. See the [deployment guide](examples/quadlet/README.md#tls-and-signing-key-rotation)
for certificate mounts on the LDAP host and coordinated signing-key rotation.
Private signing keys stay on admin/CI; public verification keys go to the LDAP
host, including the backstop's single-key file.

### Backup and recovery (admin/CI and LDAP host)<a id="backup-and-recovery"></a>

On admin/CI, back up directory YAML (including its namespace), credentials,
private signing keys, deployment files and image digests. On the LDAP host,
back up public keys and per-service revision state. The MDB database is rebuilt
at startup. Restore on a clean LDAP host with a current signed snapshot;
check UUIDs, user authentication and rejection of expired snapshots.

No administrator password is configured by default. For temporary recovery on
the LDAP host, mount a plaintext password file and set `LDAP_ADMIN_PASSWORD_FILE`.
The resulting `cn=admin,<base_dn>` account bypasses ACLs, can write and can read
password hashes. Never give it to applications. Recovery edits disappear on
rebuild; update source YAML for lasting changes. Remove the input and restart
when finished.


## Runtime inputs (LDAP host)<a id="runtime-inputs"></a>

Service identity, base DN, revision and expiry come from the signed snapshot.

| Input | Default | Values |
| ----- | ------- | ------ |
| `LDAP_EXPECTED_SERVICE_ID` | none | Required; must match the signed service ID. |
| `LDAP_TRANSPORT` | `ldap` | `ldap`, `ldaps` or `both`. |
| `LDAP_LISTEN_HOST` | `127.0.0.1` | `127.0.0.1` or `0.0.0.0`. |
| `LDAP_PORT` | `1389` | `1024..65535`. |
| `LDAP_LDAPS_PORT` | `1636` | `1024..65535`; distinct from LDAP port for `both`. |
| `LDAP_LOG_LEVEL` | `256` | Numeric slapd log mask. |
| `LDAP_TLS_CERT_FILE` | `/tls/cert.pem` | Required for LDAPS. |
| `LDAP_TLS_KEY_FILE` | `/tls/cert.key` | Required for LDAPS. |
| `LDAP_TLS_CA_FILE` | `/tls/ca.pem` | Optional server trust bundle. |
| `LDAP_SNAPSHOT_DIR` | `/snapshot` | Manifest, signature and listed LDIF files. |
| `LDAP_REVISION_STATE_FILE` | `/state/highest-revision` | Persistent highest accepted revision and digest. |
| `LDAP_SNAPSHOT_PUBLIC_KEY_FILE` | `/run/credentials/snapshot-public-key` | One minisign public key. |
| `LDAP_SNAPSHOT_PUBLIC_KEY_DIR` | none | Directory of `*.pub` keys; mutually exclusive with file input. |
| `LDAP_ADMIN_PASSWORD_FILE` | none | Optional plaintext recovery password file. |
| `LDAP_ADMIN_PASSWORD` | none | Deprecated; conflicts with file input. |
| `LDAP_BASE_DN` | none | Compatibility input; must equal manifest. |
| `LDAP_DOMAIN` | none | Deprecated; derived DN must equal manifest. |

<a id="limitations"></a>
Limits: 32 LDIF files, 16 MiB total LDIF, 1 MiB manifest and 16 KiB signature.
There is no unsigned mode, empty recovery password or expiry bypass.


## Development<a id="tests"></a>

See [DEVELOPMENT.md](DEVELOPMENT.md) for builds, tests and releases, and
[ARCHITECTURE.md](ARCHITECTURE.md) for the design and remaining work.
Editor schemas: [directory](schema/directory-v1.schema.json),
[credentials](schema/credentials-v1.schema.json).


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
