# OpenLDAP Declarative

**Disposable, read-only OpenLDAP built from a signed, expiring snapshot
applications can authenticate against. Users, groups and memberships are
declared once in YAML and turned into that signed snapshot.**

A typical use case: an internet-facing internal tool gets LDAP login without a
VPN back to a central directory. See [`ARCHITECTURE.md`](ARCHITECTURE.md) for
the full design, its security assumptions and the alternatives it rejects.


## Table of contents<a id="toc"></a>

- [Features](#features)
- [Usage](#usage)
  - [Generate a snapshot](#usage-generate-snapshot)
  - [Credential sources and pre-generated hashes](#usage-credentials)
  - [Run with rootless Podman](#usage-rootless-podman)
- [Runtime inputs](#runtime-inputs)
- [Snapshot lifecycle](#snapshot-lifecycle)
- [TLS](#tls)
- [Backup and recovery](#backup-and-recovery)
- [Tests](#tests)
- [Limitations](#limitations)
- [Licensing, copyright](#licensing-copyright)
- [Author information](#author-information)


## Features<a id="features"></a>

- **Declarative source of truth:** users, groups and memberships are defined
  once in YAML; a generator turns that declaration into deterministic LDAP
  identifiers and a signed, expiring snapshot for one application.
- **Disposable, read-only runtime:** the local database is rebuilt from the
  snapshot on every restart; normal LDAP accounts cannot write. Explicit
  recovery access is privileged and is not a persistent administration interface.
- **Minimal runtime attack surface:** the runtime image contains OpenLDAP,
  Argon2, LDAP clients and distribution utilities, including the shell, jq,
  minisign and OpenSSL. It has no compiler or Python generator stack. The
  tooling that generates snapshots lives in a separate image that never
  reaches an application host; see [`ARCHITECTURE.md`](ARCHITECTURE.md) for
  that split.
- **Signed and bounded:** every snapshot is minisign-signed and carries a
  hard expiry. A malformed or unsigned snapshot never starts a listener, and
  revocation is bounded by that expiry rather than immediate.
- **Rootless by default:** ships as a Quadlet example with dropped
  capabilities, a read-only root filesystem and no published port unless a
  deployment explicitly needs one.


## Usage<a id="usage"></a>

### Generate a snapshot<a id="usage-generate-snapshot"></a>

For local development, run these commands from the repository root with
rootless Podman to build the two image names used below. These mutable local
tags are not release references; deployments must use qualified image digests.

```sh
created=$(date -u +%Y-%m-%dT%H:%M:%SZ)
revision=$(git rev-parse HEAD)
podman build --format oci --pull=always --file Containerfile \
  --build-arg "IMAGE_CREATED=$created" --build-arg "IMAGE_REVISION=$revision" \
  --build-arg IMAGE_VERSION=dev --tag localhost/openldap-declarative:latest .
podman build --format oci --pull=always --file Containerfile.generator \
  --build-arg "IMAGE_CREATED=$created" --build-arg "IMAGE_REVISION=$revision" \
  --build-arg IMAGE_VERSION=dev --tag localhost/openldap-declarative-generator:latest .
```

The generator accepts two strict YAML documents:

- identity and authorization data, such as
  [`examples/generator/directory.yaml`](examples/generator/directory.yaml);
- credential sources, such as
  [`examples/generator/credentials.yaml.example`](examples/generator/credentials.yaml.example).

Plaintext passwords are accepted only through files, never as YAML values or
command-line arguments. Pre-generated Argon2id hashes can come from files or
inline YAML values; see [credential sources](#usage-credentials). Each referenced
file must be a regular, non-symlink file accessible only to its owner and contain
exactly one non-empty UTF-8 line (at most 4096 bytes, optional LF or CRLF ending).
A per-service credential overrides a user's default credential for that service.

The published schemas are:

- [`schema/directory-v1.schema.json`](schema/directory-v1.schema.json)
- [`schema/credentials-v1.schema.json`](schema/credentials-v1.schema.json)
- [`schema/snapshot-manifest-v1.schema.json`](schema/snapshot-manifest-v1.schema.json)

The generator also performs LDAP-aware and cross-reference checks that JSON
Schema alone cannot express. It rejects duplicate YAML keys, aliases, unknown
fields, invalid DNs, duplicate LDAP names, dangling memberships, missing
credentials, and ambiguous output paths.

Every service declares its own policy maximums through `soft_ttl_seconds` and
`hard_ttl_seconds`, plus an explicit `expiry_offset_seconds` from 0 through
86400. The offset must be smaller than the soft TTL and is subtracted from both
service deadlines, so staggering can only expire it earlier and preserves
`soft_expires_at < expires_at`. All services generated in one invocation use the
same controlled `generated_at` value.

Create and protect a minisign key pair outside the checkout using the generator
image. `-W` creates an unencrypted automation
key, so the secret key must be held by a dedicated signing worker or secret
store, never committed or copied to application hosts:

```sh
umask 077
workspace=$(mktemp -d "${TMPDIR:-/tmp}/openldap-example.XXXXXX")
install -d -m 0700 "$workspace/private" "$workspace/output" "$workspace/input"
install -m 0600 examples/generator/directory.yaml "$workspace/input/directory.yaml"
podman run --rm --userns=keep-id --user "$(id -u):$(id -g)" \
  --network none --volume "$workspace/private:/run/credentials:Z" \
  --entrypoint minisign localhost/openldap-declarative-generator:latest \
  -G -W -s /run/credentials/snapshot.key -p /run/credentials/snapshot.pub
install -m 0600 examples/generator/credentials.yaml.example \
  "$workspace/private/credentials.yaml"
```

Create the credential files referenced by `credentials.yaml` in `$workspace/private` and
keep every file at mode `0600`. The example names are placeholders, not default
credentials. Paths beginning with `/run/credentials/` refer to these files inside
the container. Keep using the same shell so `$workspace` remains set.

Then generate a new output directory for `example-app`:

```sh
podman run --rm \
  --userns=keep-id \
  --user "$(id -u):$(id -g)" \
  --network none \
  --volume "$workspace/input:/input:ro,Z" \
  --volume "$workspace/private:/run/credentials:ro,Z" \
  --volume "$workspace/output:/output:Z" \
  localhost/openldap-declarative-generator:latest \
  --directory /input/directory.yaml \
  --credentials /run/credentials/credentials.yaml \
  --signing-key /run/credentials/snapshot.key \
  --service example-app \
  --output /output/revision-1
```

The host parent `$workspace/output` must exist before mounting it; only its
child `revision-1` (the container's `/output/revision-1`) must not exist.
Omitting `--service` generates every service in the directory YAML. Repeat
`--service ID` to select several services.
The generator constructs all requested services
in a private staging directory and renames the completed directory atomically.
Each service directory contains:

```text
directory.ldif
manifest.json
manifest.json.minisig
```

For every active authorized user, the generator emits a stable
[UUID](https://en.wikipedia.org/wiki/Universally_unique_identifier)v5 derived
from the immutable source ID. The same user therefore has the same `entryUUID`
in every service and after every rebuild. Disabled users are omitted. Static
`member` and `memberOf` values are emitted together because OpenLDAP overlays do
not run during offline import.
Groups with no selected active members are omitted, including groups whose
members are all disabled. A user does not need any group: add the user's
immutable ID to a service's `users` list to select them directly. There is no
implicit "Domain Users" group; a group-less user has no `memberOf` attribute.


### Credential sources and pre-generated hashes<a id="usage-credentials"></a>

These keys belong in the private credentials YAML, not the directory YAML:

| Source | User default | Per-service user overrides (map of service IDs) | Service bind account |
| ------ | ------------ | ---------------------------------------------- | -------------------- |
| Plaintext file | `password_file` | `service_password_files` | `bind_password_file` |
| Hash file | `password_hash_file` | `service_password_hash_files` | `bind_password_hash_file` |
| Inline hash value | `password_hash` | `service_password_hashes` | `bind_password_hash` |

Choose at most one default source per user and exactly one source per bind
account. Override maps can mix source types for different services, but cannot
define the same service twice. An override wins over the default regardless of
source type. Users may have only overrides and no default.

Plaintext files are hashed with a new random salt on generation. Hash sources
are validated and copied unchanged, never hashed again. A hash-looking value
in a `password_file` is still treated as a literal plaintext password; select
the appropriate hash field explicitly.

Supported hashes use OpenLDAP's complete `{ARGON2}$argon2id$v=19$...` encoding,
with `m>=19456` KiB, `t>=2`, `p>=1`, at least 16 salt bytes and 32 digest bytes,
and canonical unpadded base64. Other schemes, weak parameters and malformed
values are rejected. Generate a fresh random salt for each new password.
Stronger parameters are allowed, but benchmark their memory, CPU and concurrent
bind cost against the target runtime limits before deployment.

To pre-generate a hash, use the runtime image's native OpenLDAP tool. In the
same Bash terminal where `$workspace` was prepared above:

```bash
(
  set +x
  set -euo pipefail
  umask 077
  read -r -s -p 'Password: ' password
  printf '\n' >&2
  printf '%s' "$password" |
    podman run --rm -i --network none \
      --entrypoint slappasswd localhost/openldap-declarative:latest \
      -o module-path=/usr/lib/ldap \
      -o 'module-load=argon2 m=19456 t=2 p=1' \
      -h '{ARGON2}' -T /dev/stdin \
      > "$workspace/private/person-0001-example-app.hash"
  unset password
)
```

The password is prompted without echo and passed through stdin, not the process
arguments or environment. Repeat with a different output name for each user or
bind-account password. Replace the corresponding plaintext source in
`$workspace/private/credentials.yaml`, for example:

```yaml
users:
  person-0001:
    service_password_hash_files:
      example-app: "/run/credentials/person-0001-example-app.hash"
```

For an inline value, replace that map with `service_password_hashes` and set
`example-app` to the entire generated verifier in single quotes. Likewise,
`password_hash: 'COMPLETE_VERIFIER'` sets a user's default, and
`bind_password_hash: 'COMPLETE_VERIFIER'` sets a service bind credential.
`COMPLETE_VERIFIER` is a placeholder, not a usable credential.

Hash files and credentials YAML containing inline hashes must have no group or
other permission bits, normally mode `0600`. Hashes remain sensitive offline
cracking targets: keep them outside the checkout and out of logs, image layers
and application access. Pre-generation removes the generator's need for the
plaintext password; it does not remove the risk of distributing verifiers.


### Run with rootless Podman<a id="usage-rootless-podman"></a>

The recommended deployment is a rootless Quadlet user service. Start with the
four files in [`examples/quadlet`](examples/quadlet), replace the image digest,
service ID, paths, and resource limits, and install them e.g. through Ansible
below:

```text
~/.config/containers/systemd/
```

The example creates an internal application network, a disposable runtime
volume, and a persistent revision-state volume. It uses:

- `keep-id` mapping from the rootless host account to container UID/GID 1001;
- all capabilities dropped and `no-new-privileges`;
- a read-only root filesystem without implicit writable tmpfs mounts;
- `nofile=1024`, a 256 MiB memory limit, 128 PID limit, and one CPU;
- no published host port;
- Podman health monitoring with kill-on-failure as a watchdog backstop;
- no network recovery administrator password.

These resource values match the profile the runtime was tested against. The
generator is a bounded one-shot with the same 256 MiB and one-CPU limits, but
only 64 PIDs, `nofile=512`, a 180-second execution timeout and `/output`
writable. It has no listener, health command, shutdown grace period or
runtime/state volumes.

[`examples/policy/containers-policy.json`](examples/policy/containers-policy.json)
is a deployment admission template: it rejects by default and trusts only the
two release repositories through an externally provisioned public key. A
deployment owner must install the real trust root and enforce the policy. The
example contains no production key.

The application container joins `openldap-example.network` and connects to
`ldap://ldap:1389`. The LDAP listener must use `LDAP_LISTEN_HOST=0.0.0.0` inside
that isolated container network. Do not publish the port unless a host process
must connect; when publishing is necessary, bind it explicitly to
`127.0.0.1` on the host.

Plain LDAP is acceptable only when the network path is confined to localhost or
a host-local private container network, untrusted containers cannot join it, and
host compromise is already considered equivalent to application compromise. Use
LDAPS for any traffic that leaves that boundary and for clients, such as Dex,
whose LDAP connector requires or is moving toward encrypted transport.


## Runtime inputs<a id="runtime-inputs"></a>

The signed manifest is authoritative for the service ID, base DN, revision,
validity period, UUID namespace, file order, and file digests. Runtime inputs
may not silently redefine signed values.

|              Input              |                Default                 | Contract |
| ------------------------------- | -------------------------------------- | -------- |
| `LDAP_EXPECTED_SERVICE_ID`      | none                                   | Required; must equal the signed service ID. |
| `LDAP_TRANSPORT`                | `ldap`                                 | `ldap`, `ldaps`, or `both`. |
| `LDAP_LISTEN_HOST`              | `127.0.0.1`                            | `127.0.0.1` or `0.0.0.0`. |
| `LDAP_PORT`                     | `1389`                                 | Unprivileged LDAP port. |
| `LDAP_LDAPS_PORT`               | `1636`                                 | Unprivileged LDAPS port; must differ from `LDAP_PORT` for `both`. |
| `LDAP_LOG_LEVEL`                | `256`                                  | Numeric slapd log mask. |
| `LDAP_TLS_CERT_FILE`            | `/tls/cert.pem`                        | Required for `ldaps` or `both`. |
| `LDAP_TLS_KEY_FILE`             | `/tls/cert.key`                        | Required for `ldaps` or `both`. |
| `LDAP_TLS_CA_FILE`              | `/tls/ca.pem`                          | Optional server trust bundle. |
| `LDAP_SNAPSHOT_DIR`             | `/snapshot`                            | Directory holding `manifest.json`, `manifest.json.minisig`, and the listed LDIF files. |
| `LDAP_REVISION_STATE_FILE`      | `/state/highest-revision`              | Highest accepted revision; keep its volume across container replacement. |
| `LDAP_SNAPSHOT_PUBLIC_KEY_FILE` | `/run/credentials/snapshot-public-key` | One minisign verification key. |
| `LDAP_SNAPSHOT_PUBLIC_KEY_DIR`  | none                                   | Directory of `*.pub` verification keys for rotation; mutually exclusive with the file input. |
| `LDAP_ADMIN_PASSWORD_FILE`      | none                                   | Optional plaintext recovery root password file. Avoid in normal operation. |
| `LDAP_ADMIN_PASSWORD`           | none                                   | Deprecated direct secret; rejected when the file form is also set. |
| `LDAP_BASE_DN`                  | none                                   | Compatibility input; if set, must equal the manifest. |
| `LDAP_DOMAIN`                   | none                                   | Deprecated compatibility input; derived DN must equal the manifest. |

The public verification key defaults to `/run/credentials/snapshot-public-key`,
the snapshot to `/snapshot`, runtime data to `/run/openldap`, and revision state
to `/state/highest-revision`.

For signing-key rotation, deploy a directory containing both old and new public
keys, restart while the old snapshot is still valid, switch generation to the
new signing key, and confirm the new revision everywhere before removing the old
public key. Public-key symlinks and empty key directories are rejected.

There is no unsigned mode, empty-password mode, ignored-expiry switch, or
fail-open import path in the release image.

Without an explicit recovery password, the runtime does not generate one or
configure `olcRootPW`. Setting `LDAP_ADMIN_PASSWORD_FILE` enables
`cn=admin,<base_dn>` as a privileged recovery identity: it bypasses ordinary ACLs,
can write LDAP data and can read password hashes. Never give it to applications.
Recovery edits disappear on rebuild; update the authoritative inputs and issue
a new revision for persistent changes. Remove the recovery input and restart
when recovery is finished.

The runtime accepts at most 32 LDIF files and 16 MiB of LDIF data; manifests are
limited to 1 MiB and detached signatures to 16 KiB. These are defensive bounds,
not capacity targets. The directory is intended to remain far smaller.

## Snapshot lifecycle<a id="snapshot-lifecycle"></a>

For every authorization, group, password or identity change, and every scheduled
renewal before expiry (even with unchanged users):

1. change the authoritative YAML and credential source when needed;
2. increase the affected service revision;
3. generate and sign a complete new snapshot;
4. transfer it to a private staging location on the target VM;
5. run the staged-snapshot preflight against the existing revision state;
6. atomically switch the active snapshot only after preflight exits `0`;
7. restart or recreate the Quadlet service;
8. verify the active revision and application login behavior.

Increase the revision for **every selected service** on each new generation.
New timestamps and, for plaintext sources, new salts change the signed content;
reusing a revision is rejected even when the identities are unchanged. Seeded
hashes do not remove the revision requirement. Replaying the exact existing
signed artifact is allowed but does not extend its lifetime.

For example, change only `example-app`'s `revision` from `1` to `2` in
`$workspace/input/directory.yaml`, then repeat the generation command with
`--service example-app --output /output/revision-2`. Deploy only
`$workspace/output/revision-2/example-app`. If generating and deploying all
services, increment every service's revision, not just the changed one.

The future Ansible role invokes the candidate image without a listener, mounting
the staged snapshot, verification key and existing state read-only, and a fresh
private writable `/run/openldap` path:

```sh
/usr/local/lib/openldap-declarative/preflight-snapshot.sh \
  SNAPSHOT KEY_OR_KEY_DIRECTORY SERVICE_ID REVISION_STATE
```

Exit `0` accepts a new revision, an exact revision/digest replay, or legacy
revision-only state that the runtime will migrate after successful import. Exit
`65` rejects invalid snapshot data, rollback or same-revision/different-content;
`66` rejects malformed state or inputs; `70` reports an internal failure; and
`78` reports expiry. Preflight verifies signature, service ID, timestamps,
file digests and the revision pair, then reuses the runtime's offline initializer
to import the LDIF and validate base DN, UUIDs, password verifiers and reciprocal
memberships.
It builds in a private subdirectory, deletes candidate artifacts on exit, never
opens a listener and never mutates the state file or active snapshot. Supply
the target TLS configuration and mounted certificates too when preflighting an
LDAPS deployment. The deployment role remains responsible for the subsequent
atomic path switch and restart.

The container copies the signed manifest and LDIF into private runtime storage,
verifies those copied bytes, constructs `cn=config` and MDB offline, validates
UUIDs, password schemes, and reciprocal membership, and only then starts slapd.
A malformed or partial replacement never becomes a listener. Verified LDIF
plaintext is deleted immediately after semantic validation and on startup,
initialization failure, shutdown and preflight completion.

The health command reports the active revision. It warns after
`soft_expires_at`; at `expires_at`, the PID 1 watchdog stops slapd and exits 78.
The Quadlet example prevents systemd restart loops for permanent configuration,
snapshot, input, and expiry exit codes.

The status command emits one JSON object for monitoring:

```sh
podman exec openldap-example \
  /usr/local/lib/openldap-declarative/status.sh
```

It reports the service ID, revision, generation time, both deadlines, remaining
seconds, and LDAP availability. Exit status `0` means healthy, `1` means the
soft deadline has passed, and `2` means expired or unavailable. Do not treat
status `1` as a reason to stop the service; it is the reaction window before the
hard deadline.

The Quadlet `HealthOnFailure=kill` action is the first host-managed backstop.
For an independent systemd timer, install
[`openldap-expiry-backstop`](examples/systemd/openldap-expiry-backstop) as
`~/.local/libexec/openldap-expiry-backstop` and install the example
[`service`](examples/systemd/openldap-example-backstop.service) and
[`timer`](examples/systemd/openldap-example-backstop.timer) in
`~/.config/systemd/user`. Adjust the container name, reload the user manager,
and enable the timer through the deployment automation. The helper runs only as
the rootless service account. It verifies the host-side snapshot signature,
service identity, and expiry in a separate capability-free container created
from the running service's immutable image ID. It then checks service health and
stops the service if either independent check fails.

Revision state must survive container replacement. Losing it weakens replay
protection until a newer snapshot is accepted. Expiry remains the final bound.
Never roll back the state volume merely to make an older authorization snapshot
start.

Within one service snapshot, every authenticated user may search the documented
non-password attributes of other entries. Anonymous search, password verifiers,
unlisted metadata and `cn=config` remain denied. Tightening this enumeration
boundary would be a product-policy change and requires a separate owner
decision.

## TLS<a id="tls"></a>

For LDAPS, mount a certificate and private key readable by the mapped container
UID and set `LDAP_TRANSPORT=ldaps` or `both`. The runtime requires TLS 1.2 or
1.3 and configures a restricted OpenSSL cipher list. Clients must validate the
server name and CA; mounting a certificate without configuring client validation
does not provide authenticated transport.

Certificate issuance, renewal, deployment, hostname selection, and expiry
monitoring remain deployment responsibilities. Restart the container after
rotating certificate files so startup validation is repeated.

## Backup and recovery<a id="backup-and-recovery"></a>

Do not back up the disposable MDB database as authoritative state. Back up and
test recovery of:

- identity, authorization, and credential sources;
- the UUID namespace;
- snapshot signing keys and their rotation procedure;
- generator, deployment, and image source plus immutable release metadata;
- the highest accepted revision per service where feasible.

A restore exercise should build a clean VM, deliver a current signed snapshot,
start the pinned image, compare UUIDs with production, and verify representative
user and bind-account authentication. Restored expired snapshots must remain
rejected.

## Tests<a id="tests"></a>

ConClear runs both integration suites against digest-verified OCI layouts. Those
modes cannot build images. They use isolated Podman storage, collision-checked
names and a run manifest. Failure output identifies the manifest and inspection
command.

The explicit non-release convenience mode may build local images. See
[`DEVELOPMENT.md`](DEVELOPMENT.md) for the maintained commands.

The direct check requires Hadolint, `shfmt`, ShellCheck, `checkbashisms`, `jq`
and `uv`. It covers shell, Containerfiles, Python formatting/lint/type checks,
JSON Schema contracts, Quadlet generation, admission policy and the host
backstop. ConClear separately owns generic OCI checks, pin state and all
exact-image qualification.

## Limitations<a id="limitations"></a>

- Revocation and password changes take effect when a new snapshot is deployed,
  or at hard expiry, not immediately.
- Password verifiers and selected directory attributes are duplicated onto each
  authorized application VM.
- Snapshot generation and signing become a fleet-wide control-plane trust
  boundary.
- The runtime provides LDAP and LDAPS, not OAuth 2.0 or OpenID Connect. A
  central IdP such as Dex may use these directories as connectors, but its
  availability and session revocation behavior are separate concerns.
- Runtime LDAP writes are intentionally unavailable. Password enrollment and
  directory administration remain central workflows.
- OpenLDAP replication, online schema changes, multi-master operation, and large
  multi-tenant directories are outside this project.

At larger scale, or when immediate revocation and a central network path become
acceptable, migrate the stable identities into a central directory or identity
provider rather than extending this snapshot model indefinitely.

## Licensing, copyright<a id="licensing-copyright"></a>

<!--REUSE-IgnoreStart-->
<!-- rumdl-disable-next-line MD034 --><!-- should match SPDX-PackageSupplier -->
Copyright (c) 2025-2026, foundata GmbH (https://foundata.com)

This project is licensed under the GNU General Public License v3.0 or later
(SPDX-License-Identifier: `GPL-3.0-or-later`), see
[`LICENSES/GPL-3.0-or-later.txt`](LICENSES/GPL-3.0-or-later.txt) for the full
text.

The [`REUSE.toml`](REUSE.toml) file provides detailed licensing and copyright
information in a human- and machine-readable format. This includes parts that
may be subject to different licensing or usage terms, such as third-party
components. The repository conforms to the
[REUSE specification](https://reuse.software/spec/). You can use
[`reuse spdx`](https://reuse.readthedocs.io/en/latest/readme.html#cli) to create
a
[SPDX software bill of materials (SBOM)](https://en.wikipedia.org/wiki/Software_Package_Data_Exchange).
<!--REUSE-IgnoreEnd-->

The built images contain Debian packages governed by their respective licenses.
Operators remain responsible for license compliance and for producing release
SBOMs that describe the actual image contents.

## Author information<a id="author-information"></a>

This project was created and is maintained by
[foundata](https://foundata.com).
