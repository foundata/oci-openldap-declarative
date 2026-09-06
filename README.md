# OpenLDAP Declarative

**Disposable, read-only OpenLDAP sidecars built from a signed, expiring
snapshot, so applications authenticate locally without a network path to a
central directory.**

Users, groups, and their memberships are declared once in YAML. A central
generator turns that declaration into deterministic LDAP identifiers and a
signed, expiring snapshot for one application, which is then deployed next to
it. The runtime container verifies and imports the snapshot offline before it
opens an LDAP listener.

The local database is disposable. LDAP writes are not an administration
interface, and restarting the container reconstructs the directory from the
snapshot. The only persistent runtime state is the highest accepted snapshot
revision, used to reject rollbacks.

This model is intended for a modest number of isolated services where avoiding
a central authentication network path is worth bounded propagation delay and
the operational cost of distributing credentials. It is not a general-purpose,
mutable, replicated directory service. See [`ARCHITECTURE.md`](ARCHITECTURE.md)
for the full design, its security assumptions, and the alternatives it rejects.

## Table of contents<a id="toc"></a>

- [Security boundary](#security-boundary)
- [Images](#images)
- [Generate snapshots](#generate-snapshots)
- [Run with rootless Podman](#run-with-rootless-podman)
- [Runtime inputs](#runtime-inputs)
- [Snapshot lifecycle](#snapshot-lifecycle)
- [TLS](#tls)
- [Backup and recovery](#backup-and-recovery)
- [Tests](#tests)
- [Limitations](#limitations)
- [Licensing, copyright](#licensing-copyright)
- [Author information](#author-information)

## Security boundary<a id="security-boundary"></a>

Each snapshot contains password verifiers for its authorized users. A stolen
snapshot permits offline password guessing. The generator therefore produces
Argon2id verifiers with at least `m=19456,t=2,p=1`; the runtime rejects weaker
or malformed values. Strong generated or breach-screened passwords remain a
deployment requirement. For internet-facing services, use a different user
password per service so a cracked verifier is not useful elsewhere.

A signature proves origin and integrity; it does not encrypt the snapshot.
Protect snapshot files, signing keys, plaintext credential inputs, generated
LDIF, and the runtime volume as credentials. Deliver snapshots through an
encrypted channel and use host ownership plus SELinux labels to keep them away
from the application container.

Hard expiry bounds stale authorization. It does not provide immediate
offboarding: a removed user can still bind to a host that retains an older valid
snapshot until that snapshot is replaced or expires.

## Images<a id="images"></a>

The runtime image is built from a digest-pinned Debian 13 slim base and contains
OpenLDAP, the Debian Argon2 module, LDAP clients, OpenSSL, `jq`, and `minisign`.
It runs as UID/GID 1001 and contains no compiler, editor, `sudo`, or network
diagnostic suite. The image retains only the `back_mdb`, `argon2`, and `memberof`
loadable OpenLDAP modules. `memberof` supplies the attribute schema for static
membership data; the mutable memberof overlay is not configured.

The generator is a separate image. It adds Debian-packaged Python, PyYAML,
`python-ldap`, and Argon2. It never becomes part of the application-side runtime.

[`conclear.toml`](conclear.toml) declares the runtime and generator as independent
release images in their actual Quay repositories. ConClear supplies the controlled
`IMAGE_CREATED`, `IMAGE_REVISION`, and `IMAGE_VERSION` build arguments, builds an
isolated committed revision, validates its labels, imports the exact OCI layouts,
and runs the repository hooks against those layouts. The runtime hook receives the
generator layout built from the same revision and platform for compatibility
testing. Neither hook builds an image or selects a mutable tag.

The default-deny [`.containerignore`](.containerignore) allowlist excludes local
snapshots, credentials, release evidence, Git metadata, tests and untracked
working files from both contexts. `conclear check` validates its effective
semantics. Repository tests lock its narrow project-specific contents and the
required `COPY` inputs.

Each image records its exact Debian package set at
`/usr/local/share/openldap-declarative/package-versions.txt` and preserves package
copyright notices plus the repository license. The package inventory supports an
SBOM; it is not a substitute for one.

Maintainer commands are documented in [`DEVELOPMENT.md`](DEVELOPMENT.md).

## Generate snapshots<a id="generate-snapshots"></a>

The generator accepts two strict YAML documents:

- identity and authorization data, such as
  [`examples/generator/directory.yaml`](examples/generator/directory.yaml);
- paths to credential files, such as
  [`examples/generator/credentials.yaml.example`](examples/generator/credentials.yaml.example).

Credential values are never accepted inside YAML or on the command line. Each
referenced file must be a regular, non-symlink file readable only by its owner and
must contain exactly one non-empty UTF-8 line. A per-service password overrides a
user's default password for that service.

The published schemas are:

- [`schema/directory-v1.schema.json`](schema/directory-v1.schema.json)
- [`schema/credentials-v1.schema.json`](schema/credentials-v1.schema.json)
- [`schema/snapshot-manifest-v1.schema.json`](schema/snapshot-manifest-v1.schema.json)

The generator also performs LDAP-aware and cross-reference checks that JSON
Schema alone cannot express. It rejects duplicate YAML keys, aliases, unknown
fields, invalid DNs, duplicate LDAP names, dangling memberships, missing
credentials, and ambiguous output paths.

Every service declares the same policy maximums through `soft_ttl_seconds` and
`hard_ttl_seconds`, plus an explicit `expiry_offset_seconds` from 0 through
86400. The offset must be smaller than the soft TTL and is subtracted from both
deadlines, so staggering can only expire a service earlier and always preserves
`soft_expires_at < expires_at`. All services generated in one invocation use the
same controlled `generated_at` value.

Create and protect a minisign key pair. `-W` creates an unencrypted automation
key, so the secret key must be held by a dedicated signing worker or secret
store, never committed or copied to application hosts:

```sh
umask 077
mkdir -p ./private
minisign -G -W \
  -s ./private/snapshot.key \
  -p ./private/snapshot.pub
install -m 0600 examples/generator/credentials.yaml.example \
  ./private/credentials.yaml
```

Create the password files referenced by `credentials.yaml` in `./private` and
keep every file at mode `0600`. The example names are placeholders, not default
credentials.

Then generate a new output directory:

```sh
podman run --rm \
  --userns=keep-id \
  --user "$(id -u):$(id -g)" \
  --network none \
  --volume "$PWD/examples/generator:/input:ro,Z" \
  --volume "$PWD/private:/run/credentials:ro,Z" \
  --volume "$PWD/output:/output:Z" \
  localhost/openldap-declarative-generator:latest \
  --directory /input/directory.yaml \
  --credentials /run/credentials/credentials.yaml \
  --signing-key /run/credentials/snapshot.key \
  --output /output/revision-1
```

The output path must not exist. The generator constructs all requested services
in a private staging directory and renames the completed directory atomically.
Each service directory contains:

```text
directory.ldif
manifest.json
manifest.json.minisig
```

For every active authorized user, the generator emits a stable UUIDv5 derived
from the immutable source ID. The same user therefore has the same `entryUUID`
in every service and after every rebuild. Disabled users are omitted. Static
`member` and `memberOf` values are emitted together because OpenLDAP overlays do
not run during offline import.

## Run with rootless Podman<a id="run-with-rootless-podman"></a>

The recommended deployment is a rootless Quadlet user service. Start with the
four files in [`examples/quadlet`](examples/quadlet), replace the image digest,
service ID, paths, and resource limits, and install them through Ansible below:

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

The resource values match the qualified runtime profile. The generator is a
bounded one-shot with the same 256 MiB and one-CPU limits, but only 64 PIDs,
`nofile=512`, a 180-second execution timeout and `/output` writable. It has no
listener, health command, shutdown grace period or runtime/state volumes.

[`examples/policy/containers-policy.json`](examples/policy/containers-policy.json)
is a deployment admission template: it rejects by default and trusts only the
two release repositories through an externally provisioned public key. A
deployment owner must install the real trust root and enforce the policy. The
example contains no production key and is not ConClear build policy.

The application container joins `openldap-example.network` and connects to
`ldap://ldap:1389`. The LDAP listener must use `LDAP_LISTEN_HOST=0.0.0.0` inside
that isolated container network. Do not publish the port unless a host process
must connect; when publishing is necessary, bind it explicitly to
`127.0.0.1` on the host.

Plain LDAP is acceptable only when the network path is confined to localhost or
a host-local private container network, untrusted containers cannot join it, and
host compromise is already considered equivalent to application compromise.
Use LDAPS for any traffic that leaves that boundary and for clients, such as Dex,
whose LDAP connector requires or is moving toward encrypted transport.

## Runtime inputs<a id="runtime-inputs"></a>

The signed manifest is authoritative for the service ID, base DN, revision,
validity period, UUID namespace, file order, and file digests. Runtime inputs may
not silently redefine signed values.

| Input | Default | Contract |
| --- | --- | --- |
| `LDAP_EXPECTED_SERVICE_ID` | none | Required; must equal the signed service ID. |
| `LDAP_TRANSPORT` | `ldap` | `ldap`, `ldaps`, or `both`. |
| `LDAP_LISTEN_HOST` | `127.0.0.1` | `127.0.0.1` or `0.0.0.0`. |
| `LDAP_PORT` | `1389` | Unprivileged LDAP port. |
| `LDAP_LDAPS_PORT` | `1636` | Unprivileged LDAPS port; must differ from `LDAP_PORT` for `both`. |
| `LDAP_LOG_LEVEL` | `256` | Numeric slapd log mask. |
| `LDAP_TLS_CERT_FILE` | `/tls/cert.pem` | Required for `ldaps` or `both`. |
| `LDAP_TLS_KEY_FILE` | `/tls/cert.key` | Required for `ldaps` or `both`. |
| `LDAP_TLS_CA_FILE` | `/tls/ca.pem` | Optional server trust bundle. |
| `LDAP_SNAPSHOT_DIR` | `/snapshot` | Directory holding `manifest.json`, `manifest.json.minisig`, and the listed LDIF files. |
| `LDAP_REVISION_STATE_FILE` | `/state/highest-revision` | Highest accepted revision; keep its volume across container replacement. |
| `LDAP_SNAPSHOT_PUBLIC_KEY_FILE` | `/run/credentials/snapshot-public-key` | One minisign verification key. |
| `LDAP_SNAPSHOT_PUBLIC_KEY_DIR` | none | Directory of `*.pub` verification keys for rotation; mutually exclusive with the file input. |
| `LDAP_ADMIN_PASSWORD_FILE` | none | Optional recovery root password file. Avoid in normal operation. |
| `LDAP_ADMIN_PASSWORD` | none | Deprecated direct secret; rejected when the file form is also set. |
| `LDAP_BASE_DN` | none | Compatibility input; if set, must equal the manifest. |
| `LDAP_DOMAIN` | none | Deprecated compatibility input; derived DN must equal the manifest. |

The public verification key defaults to
`/run/credentials/snapshot-public-key`, the snapshot to `/snapshot`, runtime data
to `/run/openldap`, and revision state to `/state/highest-revision`.

For signing-key rotation, deploy a directory containing both old and new public
keys, restart while the old snapshot is still valid, switch generation to the
new signing key, and confirm the new revision everywhere before removing the old
public key. Public-key symlinks and empty key directories are rejected.

There is no unsigned mode, empty-password mode, ignored-expiry switch, or
fail-open import path in the release image.

The runtime accepts at most 32 LDIF files and 16 MiB of LDIF data; manifests are
limited to 1 MiB and detached signatures to 16 KiB. These are defensive bounds,
not capacity targets. The directory is intended to remain far smaller.

## Snapshot lifecycle<a id="snapshot-lifecycle"></a>

For every authorization, group, password, or identity change:

1. change the authoritative YAML and credential source;
2. increase the affected service revision;
3. generate and sign a complete new snapshot;
4. transfer it to a private staging location on the target VM;
5. run the staged-snapshot preflight against the existing revision state;
6. atomically switch the active snapshot only after preflight exits `0`;
7. restart or recreate the Quadlet service;
8. verify the active revision and application login behavior.

The future Ansible role invokes the candidate image without a listener, mounting
the staged snapshot, verification key and existing state read-only, and a fresh
private writable `/run/openldap` path:

```sh
/usr/local/lib/openldap-declarative/preflight-snapshot.sh \
  SNAPSHOT KEY_OR_KEY_DIRECTORY SERVICE_ID REVISION_STATE
```

Exit `0` accepts a new revision, an exact revision/digest replay, or legacy
revision-only state that the runtime will migrate after successful import. Exit
`65` rejects rollback or same-revision/different-content; `66` rejects malformed
state or inputs; `70` reports an internal failure; and `78` reports expiry. The
preflight verifies signature, service ID, timestamps and file digests before the
revision pair. It never mutates the state file or active snapshot. The deployment
role remains responsible for the subsequent atomic path switch and restart.

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
service identity, and expiry in a separate capability-free container created from
the running service's immutable image ID. It then checks service health and stops
the service if either independent check fails.

Revision state must survive container replacement. Losing it weakens replay
protection until a newer snapshot is accepted. Expiry remains the final bound.
Never roll back the state volume merely to make an older authorization snapshot
start.

Within one service snapshot, every authenticated user may search the documented
non-password attributes of other entries. Anonymous search, password verifiers,
unlisted metadata and `cn=config` remain denied. Tightening this enumeration
boundary would be a product-policy change and requires a separate owner decision.

## TLS<a id="tls"></a>

For LDAPS, mount a certificate and private key readable by the mapped container
UID and set `LDAP_TRANSPORT=ldaps` or `both`. The runtime requires TLS 1.2 or 1.3
and configures a restricted OpenSSL cipher list. Clients must validate the server
name and CA; mounting a certificate without configuring client validation does
not provide authenticated transport.

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
- The runtime provides LDAP and LDAPS, not OAuth 2.0 or OpenID Connect. A central
  IdP such as Dex may use these directories as connectors, but its availability
  and session revocation behavior are separate concerns.
- Runtime LDAP writes are intentionally unavailable. Password enrollment and
  directory administration remain central workflows.
- OpenLDAP replication, online schema changes, multi-master operation, and large
  multi-tenant directories are outside this project.

At larger scale, or when immediate revocation and a central network path become
acceptable, migrate the stable identities into a central directory or identity
provider rather than extending this snapshot model indefinitely.

## Licensing, copyright<a id="licensing-copyright"></a>

<!--REUSE-IgnoreStart-->
Copyright (c) 2025 foundata GmbH (https://foundata.com)

Repository code and configuration are licensed under the GNU General Public
License v3.0 or later (SPDX-License-Identifier: `GPL-3.0-or-later`). See
[`LICENSES/GPL-3.0-or-later.txt`](LICENSES/GPL-3.0-or-later.txt).

[`REUSE.toml`](REUSE.toml) provides machine-readable licensing information. Use
`reuse spdx` to generate an SPDX software bill of materials for repository
contents.
<!--REUSE-IgnoreEnd-->

The built images contain Debian packages governed by their respective licenses.
Operators remain responsible for license compliance and for producing release
SBOMs that describe the actual image contents.

## Author information<a id="author-information"></a>

This project was created and is maintained by
[foundata GmbH](https://foundata.com).
