# OCI Image: OpenLDAP Declarative

This project runs a small, read-only OpenLDAP directory from a signed and
expiring service snapshot. A central build process selects the users and groups
for one application, creates deterministic LDAP identifiers, signs the complete
snapshot, and deploys it next to that application. The container verifies and
imports the snapshot offline before it opens an LDAP listener.

The local database is disposable. LDAP writes are not an administration
interface, and restarting the container reconstructs the directory from the
snapshot. The only persistent runtime state is the highest accepted snapshot
revision, used to reject rollbacks.

This model is intended for a modest number of isolated services where avoiding a
central authentication network path is worth bounded propagation delay and the
operational cost of distributing credentials. It is not a general-purpose,
mutable, replicated directory service.

## Security boundary

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

## Images

The runtime image is built from a digest-pinned Debian 13 slim base and contains
OpenLDAP, the Debian Argon2 module, LDAP clients, OpenSSL, `jq`, and `minisign`.
It runs as UID/GID 1001 and contains no compiler, editor, `sudo`, or network
diagnostic suite.

The generator is a separate image. It adds Debian-packaged Python, PyYAML,
`python-ldap`, and Argon2. It never becomes part of the application-side runtime.

Build both images with:

```sh
sh hack/build.sh
```

Override `RUNTIME_IMAGE` or `GENERATOR_IMAGE` to select different local tags.
Set `IMAGE_VERSION` to the reviewed release version for a production build;
`hack/build.sh` labels both images with that version, the current Git revision,
the build time, and whether tracked source files were clean. Direct Containerfile
builds retain explicit development provenance. The release-evidence command
rejects development versions, invalid revisions, and dirty tracked source trees.
Production builds should record package inventories and SBOMs, scan and sign the
result, mirror it to the company registry, and deploy only an immutable image
digest. A pinned base digest does not freeze packages downloaded by `apt` during
the build; rebuilds must remain controlled release artifacts.

Each image records its exact Debian package set at
`/usr/local/share/openldap-declarative/package-versions.txt` and preserves package
copyright notices plus the repository license. The package inventory supports an
SBOM; it is not a substitute for one.

### Release evidence

After `hack/check.sh` passes, commit the reviewed source, and build both final
image tags with a release version, create a private release-evidence directory:

```sh
IMAGE_VERSION=1.0.0 sh hack/build.sh
sh hack/release-artifacts.sh ./release-evidence
```

The command saves each image temporarily as an OCI image layout, records its OCI
manifest digest and external package inventory, and uses Trivy to generate an
SPDX JSON SBOM. It scans that same layout for vulnerabilities, secrets, and
misconfigurations. The command also exports the Git revision recorded in both
images and scans that source tree for secrets and configuration mistakes. It
rejects image pairs built from different revisions or a revision unavailable in
the checkout. Each target gets a complete JSON report and a policy-filtered JSON
report. Configuration, scanner, and filesystem errors fail atomically without
publishing partial evidence. A finding at the default `HIGH,CRITICAL` threshold
still scans both images, publishes complete evidence with
`result: rejected`, and returns status `2`. The signing command rejects image
metadata unless the source and both image scans passed. Set `TRIVY_SEVERITIES`
differently only through an approved release policy.

Trivy 0.72.0 runs as the current rootless UID in a capability-free container.
Its upstream image is pinned by digest and may be replaced with a verified
company mirror through `TRIVY_IMAGE`. Each invocation needs registry access to
refresh the vulnerability database and misconfiguration checks; the first also
needs access to the scanner image. The workflow does not require a Trivy server.
Mirror those inputs for release automation that must not depend on public
registries. `release.json` records the tool digest, vulnerability database hash
and checks-bundle digest used for the verdict; scanner results can change when
any of those inputs changes.

Trivy severity and Debian's support decision are separate inputs. Do not hide
unfixed or Debian no-DSA findings with a blanket ignore rule. When a review
concludes that a reported vulnerability does not affect these images, record the
product, vulnerability, status, justification, author, and timestamp in an
OpenVEX document and pass it as `TRIVY_VEX_FILE`. The command copies that
document into the evidence directory, applies it to both scans, and records its
SHA-256 digest in `release.json`. Trivy marks VEX support experimental, so test
VEX documents again whenever its pinned version changes. VEX is applicability
evidence, not risk acceptance: an applicable vulnerability remains a finding
even when Debian does not plan a security update. Track accepted risks, owners,
and review expiries separately rather than marking them `not_affected`.

Review the reports, push both application images to the controlled registry, and
confirm that each pushed digest equals the corresponding
`oci_manifest_digest` in `runtime.metadata.json` or `generator.metadata.json`.
Then sign only those immutable digest references and attach the matching SPDX
attestations:

```sh
COSIGN_KEY='kms-provider://production-image-signing-key' \
  sh hack/sign-release.sh \
  registry.example.org/openldap-declarative@sha256:... \
  ./release-evidence/runtime.metadata.json \
  registry.example.org/openldap-declarative-generator@sha256:... \
  ./release-evidence/generator.metadata.json
```

`hack/sign-release.sh` requires Cosign in `PATH`, verifies the registry digest
and SBOM hash against the release metadata, and rejects tags. CI must pin and
verify the Cosign installation, authenticate to the registry, and provide a KMS
or hardware-backed `COSIGN_KEY`; do not keep the image-signing key in the source
checkout. Deployment policy must verify the image signature before mirroring or
running the digest. Snapshot minisign keys and OCI release-signing keys are
different trust domains and must not be reused.

## Generate snapshots

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

## Run with rootless Podman

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

## Runtime inputs

The signed manifest is authoritative for the service ID, base DN, revision,
validity period, UUID namespace, file order, and file digests. Runtime inputs may
not silently redefine signed values.

| Input | Default | Contract |
| --- | --- | --- |
| `LDAP_EXPECTED_SERVICE_ID` | none | Required; must equal the signed service ID. |
| `LDAP_TRANSPORT` | `ldap` | `ldap`, `ldaps`, or `both`. |
| `LDAP_LISTEN_HOST` | `127.0.0.1` | `127.0.0.1` or `0.0.0.0`. |
| `LDAP_PORT` | `1389` | Unprivileged LDAP port. |
| `LDAP_LDAPS_PORT` | `1636` | Unprivileged LDAPS port. |
| `LDAP_LOG_LEVEL` | `256` | Numeric slapd log mask. |
| `LDAP_TLS_CERT_FILE` | `/tls/cert.pem` | Required for `ldaps` or `both`. |
| `LDAP_TLS_KEY_FILE` | `/tls/cert.key` | Required for `ldaps` or `both`. |
| `LDAP_TLS_CA_FILE` | `/tls/ca.pem` | Optional server trust bundle. |
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

## Snapshot lifecycle

For every authorization, group, password, or identity change:

1. change the authoritative YAML and credential source;
2. increase the affected service revision;
3. generate and sign a complete new snapshot;
4. transfer it to a private staging location on the target VM;
5. verify transfer completeness and atomically switch the service snapshot;
6. restart or recreate the Quadlet service;
7. verify the active revision and application login behavior.

The container copies the signed manifest and LDIF into private runtime storage,
verifies those copied bytes, constructs `cn=config` and MDB offline, validates
UUIDs, password schemes, and reciprocal membership, and only then starts slapd.
A malformed or partial replacement never becomes a listener.

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
the rootless service account. It stops a running container after any health-check
failure and returns non-zero so the event remains visible in the journal.

Revision state must survive container replacement. Losing it weakens replay
protection until a newer snapshot is accepted. Expiry remains the final bound.
Never roll back the state volume merely to make an older authorization snapshot
start.

## TLS

For LDAPS, mount a certificate and private key readable by the mapped container
UID and set `LDAP_TRANSPORT=ldaps` or `both`. The runtime requires TLS 1.2 or 1.3
and configures a restricted OpenSSL cipher list. Clients must validate the server
name and CA; mounting a certificate without configuring client validation does
not provide authenticated transport.

Certificate issuance, renewal, deployment, hostname selection, and expiry
monitoring remain deployment responsibilities. Restart the container after
rotating certificate files so startup validation is repeated.

## Backup and recovery

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

## Tests

The tests create only uniquely named rootless Podman resources and remove them on
exit. Set `KEEP_TEST_RESOURCES=true` only for debugging.

```sh
sh tests/integration.sh
sh tests/generator-integration.sh
```

Run the complete local verification sequence with:

```sh
sh hack/check.sh
```

Static shell checks use `shfmt`, ShellCheck, and `checkbashisms`:

```sh
shfmt --language-dialect posix --indent 2 --case-indent \
  --binary-next-line --simplify --diff scripts/*.sh tests/*.sh hack/*.sh
shellcheck --shell=sh --severity=style \
  --exclude=SC2292 --exclude=SC3040 --exclude=SC3043 \
  --enable=all scripts/*.sh tests/*.sh hack/*.sh
checkbashisms scripts/*.sh tests/*.sh hack/*.sh
```

## Limitations

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

## Licensing and copyright

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
