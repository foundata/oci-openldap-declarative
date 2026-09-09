# OpenLDAP Declarative

**Application-local, read-only LDAP generated from YAML and rebuilt from signed,
expiring snapshots.**

An internet-facing application can authenticate without a VPN or connection to
the central directory. Configuration management must refresh snapshots before
expiry; changes such as account removal take effect on deployment or at expiry,
not immediately. See [ARCHITECTURE.md](ARCHITECTURE.md) for the design and trust
boundaries, and [DEVELOPMENT.md](DEVELOPMENT.md) for contributor and release tasks.


## Table of contents<a id="toc"></a>

- [Features](#features)
- [Usage](#usage)
  - [Generate a snapshot](#usage-generate-snapshot)
  - [Identity and renames](#usage-identities)
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

- Per-service users, groups, credentials and stable LDAP UUIDs.
- Minisign signatures, file digests, revision replay protection and expiry.
- Offline database rebuilds; normal LDAP accounts cannot write.
- Separate runtime and Python generator images; no compiler or Python stack
  in the runtime. Distribution shell and utilities remain.
- Rootless Quadlet example with restricted permissions and resource limits.


## Usage<a id="usage"></a>

### Generate a snapshot<a id="usage-generate-snapshot"></a>

1. **Build the local images** from the repository root with rootless Podman.
   These development tags are not release references; deploy qualified digests.

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

2. **Prepare private inputs and a signing key** outside the checkout. Keep using
   the same shell so `$workspace` remains set. This temporary workspace is for
   the example; production sources and keys need durable, protected storage.

   ```sh
   umask 077
   workspace=$(mktemp -d "${TMPDIR:-/tmp}/openldap-example.XXXXXX")
   install -d -m 0700 "$workspace/private" "$workspace/output" "$workspace/input"
   install -m 0600 examples/generator/directory.yaml "$workspace/input/directory.yaml"
   install -m 0600 examples/generator/credentials.yaml.example \
     "$workspace/private/credentials.yaml"
   podman run --rm --userns=keep-id --user "$(id -u):$(id -g)" \
     --network none --volume "$workspace/private:/run/credentials:Z" \
     --entrypoint minisign localhost/openldap-declarative-generator:latest \
     -G -W -s /run/credentials/snapshot.key -p /run/credentials/snapshot.pub
   ```

   `-W` creates an unencrypted signing key. Keep it on the signing worker or in
   its secret store, never in Git, an image or an application host.

3. **Edit the two YAML files.** `directory.yaml` declares identities, groups and
   services; `credentials.yaml` selects [credential sources](#usage-credentials).
   Create referenced files in `$workspace/private` with mode `0600`.
   `/run/credentials/...` paths refer to that directory inside the container;
   example filenames are placeholders, not default passwords.

   For a new production directory, choose its own UUID namespace once, before
   the first snapshot. See [identity and renames](#usage-identities).

4. **Generate the selected service** into a new output directory:

   ```sh
   podman run --rm --userns=keep-id --user "$(id -u):$(id -g)" \
     --network none \
     --volume "$workspace/input:/input:ro,Z" \
     --volume "$workspace/private:/run/credentials:ro,Z" \
     --volume "$workspace/output:/output:Z" \
     localhost/openldap-declarative-generator:latest \
     --directory /input/directory.yaml \
     --credentials /run/credentials/credentials.yaml \
     --signing-key /run/credentials/snapshot.key \
     --service example-app --output /output/revision-1
   ```

The parent `$workspace/output` must exist; its child `revision-1` must not.
Output appears atomically and contains a directory per selected service, each
with `directory.ldif`, `manifest.json` and `manifest.json.minisig`.
Repeat `--service ID` to select several services; omit it to generate **all**.

Inputs are strict: unknown fields, duplicate keys, YAML aliases, invalid LDAP
names and broken references are rejected. Public schemas cover
[directory data](schema/directory-v1.schema.json),
[credentials](schema/credentials-v1.schema.json) and
[manifests](schema/snapshot-manifest-v1.schema.json); the generator adds semantic
and cross-reference checks.


### Identity and renames<a id="usage-identities"></a>

| Field | Meaning |
| ----- | ------- |
| User `id` | Immutable source key, such as `person-0001`; used by group members, service selections and credentials. Not a YAML anchor or LDAP username. |
| User `uid` | Mutable LDAP username, such as `alice`; forms the user's DN: `uid=alice,ou=people,<base_dn>`. |
| LDAP `entryUUID` | Stable identifier generated from the directory's `uuid_namespace` and the source ID. |

```text
entryUUID = UUIDv5(uuid_namespace, "user:" + id)
```

To rename Alice, keep `id: "person-0001"`, change `uid` and deploy a higher
revision. This updates her DN and membership DNs; `entryUUID` and ID-based
credential/group references stay unchanged. Profile fields such as
`common_name` and `mail` can change independently without changing the DN.
Applications must use `entryUUID` as their persistent identity key for this to
preserve their account mapping; username- or DN-based mappings may break.

A UUID string is a valid `id` and a useful choice when no immutable upstream
key exists. An existing unique, non-recycled string works equally well. Never
change an established `id` (including its letter case), reuse a deleted user's
ID, or regenerate the namespace. Even a UUID-valued `id` is an input to UUIDv5,
not a verbatim LDAP `entryUUID`. Keep the namespace backed up.

Only selected active users are emitted. Groups without selected active members
are omitted. Users need no group: select their IDs directly in a service's
`users` list. There is no implicit "Domain Users" group; group-less users have
no `memberOf` attribute.


### Credential sources and pre-generated hashes<a id="usage-credentials"></a>

Use these keys in the **credentials YAML**, not the directory YAML:

| Source | User default | Per-service user overrides (service-ID map) | Service bind account |
| ------ | ------------ | ------------------------------------------ | -------------------- |
| Plaintext file | `password_file` | `service_password_files` | `bind_password_file` |
| Hash file | `password_hash_file` | `service_password_hash_files` | `bind_password_hash_file` |
| Inline hash | `password_hash` | `service_password_hashes` | `bind_password_hash` |

- At most one default per user; exactly one source per bind account. Overrides
  win over defaults, regardless of type; do not define a service in two maps.
  Users can have overrides without a default.
- Plaintext is accepted **only from files** and hashed with a fresh salt.
  Explicit hash sources are validated and copied unchanged, never rehashed.
  A hash-looking value in `password_file` is still a literal plaintext password.
- Credential files must be regular, non-symlink, owner-only files, normally
  `0600`: one non-empty UTF-8 line, at most 4096 bytes, optional LF/CRLF ending.
  Credentials YAML containing inline hashes must also be owner-only.

Accepted hashes use `{ARGON2}$argon2id$v=19$...`, `m>=19456` KiB, `t>=2`, `p>=1`,
at least 16 salt bytes and 32 digest bytes, and canonical unpadded base64.
Use a fresh random salt for each new password. Benchmark stronger parameters
and concurrent binds against the target runtime's memory and CPU limits.

**Pre-generate a hash** using the runtime image, in the same Bash terminal:

```bash
(
  set +x
  set -euo pipefail
  umask 077
  read -r -s -p 'Password: ' password
  export -n password
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

The password travels through stdin, not arguments or the environment. Repeat
with different filenames for other users and bind accounts. Replace the
corresponding plaintext source in `credentials.yaml`, for example:

```yaml
users:
  person-0001:
    service_password_hash_files:
      example-app: "/run/credentials/person-0001-example-app.hash"
```

For an inline value, use `service_password_hashes` instead and put the complete
verifier in single quotes. `password_hash: 'COMPLETE_VERIFIER'` sets a default;
`bind_password_hash: 'COMPLETE_VERIFIER'` sets a bind credential. Replace the
placeholder with the entire generated hash.

Hashes remain offline-cracking targets. Keep all credential-bearing inputs and
snapshots out of Git, logs, image layers and application filesystem access.


### Run with rootless Podman<a id="usage-rootless-podman"></a>

Install the four [Quadlet examples](examples/quadlet) under
`~/.config/containers/systemd/`, replacing the image digest, service ID, paths
and resource limits. They define an internal network, disposable runtime volume
and **persistent revision-state volume**, with:

- container UID/GID `1001`, mapped to the rootless account using `keep-id`;
- read-only root filesystem, no implicit tmpfs, dropped capabilities and
  `no-new-privileges`;
- 256 MiB RAM, one CPU, 128 PIDs and `nofile=1024`;
- health monitoring with kill-on-failure, no published port or recovery password.

The application joins `openldap-example.network` and uses `ldap://ldap:1389`.
Set `LDAP_LISTEN_HOST=0.0.0.0` inside that isolated network. Publish a port only
when necessary, bound to host `127.0.0.1`.

Plain LDAP is only for trusted host-local paths whose compromise is already
equivalent to application compromise. Use validated LDAPS across other
boundaries. The [admission policy template](examples/policy/containers-policy.json)
rejects by default; deployments must provision their real release trust root.


## Runtime inputs<a id="runtime-inputs"></a>

The signed manifest owns service identity, base DN, revision, validity, UUID
namespace, file order and digests. Runtime inputs cannot override those values.

| Input | Default | Contract |
| ----- | ------- | -------- |
| `LDAP_EXPECTED_SERVICE_ID` | none | Required; must match the signed service ID. |
| `LDAP_TRANSPORT` | `ldap` | `ldap`, `ldaps` or `both`. |
| `LDAP_LISTEN_HOST` | `127.0.0.1` | `127.0.0.1` or `0.0.0.0`. |
| `LDAP_PORT` | `1389` | TCP port in `1024..65535`. |
| `LDAP_LDAPS_PORT` | `1636` | TCP port in `1024..65535`; distinct from `LDAP_PORT` for `both`. |
| `LDAP_LOG_LEVEL` | `256` | Numeric slapd log mask. |
| `LDAP_TLS_CERT_FILE` | `/tls/cert.pem` | Required for `ldaps` or `both`. |
| `LDAP_TLS_KEY_FILE` | `/tls/cert.key` | Required for `ldaps` or `both`. |
| `LDAP_TLS_CA_FILE` | `/tls/ca.pem` | Optional server trust bundle. |
| `LDAP_SNAPSHOT_DIR` | `/snapshot` | Signed manifest, signature and listed LDIF files. |
| `LDAP_REVISION_STATE_FILE` | `/state/highest-revision` | Persistent highest accepted revision and digest. |
| `LDAP_SNAPSHOT_PUBLIC_KEY_FILE` | `/run/credentials/snapshot-public-key` | One minisign verification key. |
| `LDAP_SNAPSHOT_PUBLIC_KEY_DIR` | none | Directory of `*.pub` keys; mutually exclusive with the file input. |
| `LDAP_ADMIN_PASSWORD_FILE` | none | Optional plaintext recovery root password file. |
| `LDAP_ADMIN_PASSWORD` | none | Deprecated direct secret; conflicts with the file form. |
| `LDAP_BASE_DN` | none | Compatibility input; must equal the manifest. |
| `LDAP_DOMAIN` | none | Deprecated; derived DN must equal the manifest. |

No recovery input means no generated administrator password or `olcRootPW`.
Explicit recovery enables `cn=admin,<base_dn>`, which **bypasses ACLs, can write
and can read password hashes**. Never give it to applications. Recovery edits
vanish on rebuild; update authoritative inputs for persistent changes. Remove
the recovery input and restart when finished.

Limits: 32 LDIF files, 16 MiB combined LDIF, 1 MiB manifest and 16 KiB signature.
No unsigned mode, empty recovery password or expiry bypass is supported.


## Snapshot lifecycle<a id="snapshot-lifecycle"></a>

1. Update authoritative inputs as needed and increment **every selected
   service's revision**, including scheduled renewals without identity changes.
2. Generate and sign; transfer the output to private staging on the target host.
3. Preflight the candidate against existing revision state.
4. Only after success, atomically switch the snapshot and restart the service.
5. Verify the active revision and application authentication.

For `example-app`, change revision `1` to `2`, then repeat generation with
`--service example-app --output /output/revision-2`. Deploy only that service's
output. Regeneration changes timestamps and sometimes salts; reusing a revision
is rejected. Replaying the **exact signed artifact** is allowed but does not
renew it, including when credentials were pre-hashed.

Each service has independent `soft_ttl_seconds` and `hard_ttl_seconds`, with
`soft < hard`. Its `expiry_offset_seconds` must be `0..86400` and smaller than
the soft TTL. Both deadlines are `generated_at + TTL - offset`; services
generated together share `generated_at`. Offsets only shorten validity.

**Preflight:** invoke the candidate image with snapshot, key and existing state
mounted read-only, plus a fresh private writable `/run/openldap`:

```sh
/usr/local/lib/openldap-declarative/preflight-snapshot.sh \
  SNAPSHOT KEY_OR_KEY_DIRECTORY SERVICE_ID REVISION_STATE
```

It verifies signed inputs and revision state, then imports and validates the
candidate offline. It opens no listener, changes no active data or revision
state, and removes its private candidate workspace. Supply target TLS settings
and certificates when validating an LDAPS deployment.

| Exit | Meaning |
| ---- | ------- |
| `0` | New revision, exact revision/digest replay, or accepted legacy revision-only state. |
| `65` | Rejected snapshot data, rollback or same-revision/different-content. |
| `66` | Invalid input or revision state. |
| `70` | Internal failure. |
| `78` | Expired snapshot. |

Startup repeats verification and offline import, then records the revision.
Verified LDIF copies are deleted after validation or on failure/shutdown.
Never discard or roll back revision state just to accept an older snapshot.

**Status and health:**

```sh
podman exec openldap-example /usr/local/lib/openldap-declarative/status.sh
```

Status emits JSON with revision, deadlines, remaining time and LDAP availability:
`0` healthy, `1` soft-expired, `2` expired/unavailable. Health treats soft expiry
as a warning, not failure. At hard expiry the watchdog stops slapd with exit `78`.

The Quadlet health action is a host-side backstop. An independent
[helper](examples/systemd/openldap-expiry-backstop),
[service](examples/systemd/openldap-example-backstop.service) and
[timer](examples/systemd/openldap-example-backstop.timer) also verify host-side
trust inputs and health, stopping the named container on failure. Install the
helper under `~/.local/libexec/` and units under `~/.config/systemd/user/` as the
rootless service account; adjust names and enable the timer through deployment.

**Signing-key rotation:** deploy old and new `*.pub` keys together, restart,
sign with the new key, confirm the new revision everywhere, then remove the old
key. Symlinks and empty key directories are rejected.


## TLS<a id="tls"></a>

Mount certificates and keys readable by the mapped UID; set
`LDAP_TRANSPORT=ldaps` or `both`. TLS 1.2/1.3 is required. Clients must validate
the server name and CA. Certificate issuance, renewal and expiry monitoring
belong to deployment; restart after certificate rotation.


## Backup and recovery<a id="backup-and-recovery"></a>

Back up authoritative YAML, credentials, the UUID namespace, signing keys,
deployment sources, immutable release references and per-service revision state,
not the disposable MDB database. Test restoration on a clean host with a current
signed snapshot: compare UUIDs, verify user/bind authentication and confirm
expired snapshots remain rejected.


## Tests<a id="tests"></a>

See [DEVELOPMENT.md](DEVELOPMENT.md#testing) for direct checks and isolated
rootless Podman tests. ConClear qualifies digest-verified image layouts;
only explicit developer mode builds images. Qualification and signed release
procedures are [documented separately](DEVELOPMENT.md#qualification-and-releases).


## Limitations<a id="limitations"></a>

- Offboarding is bounded by deployment or expiry, not immediate. Application
  caches, sessions and behavior during LDAP outages need separate qualification.
- Password verifiers and selected attributes are copied to application hosts;
  signatures do not encrypt them. Protect snapshots in transit and at rest.
- Every authenticated user can read approved non-password attributes of other
  entries in the same service. Anonymous search, password reads, unlisted
  metadata and `cn=config` access are denied to normal network accounts.
- Administration and password enrollment remain central workflows. Replication,
  online schema changes, multi-master operation and large multi-tenant
  directories are out of scope. This is LDAP/LDAPS, not an OIDC provider.
- Organization-specific Ansible deployment, fleet monitoring, snapshot encryption
  and application/VM recovery exercises remain external work; see
  [implementation status](ARCHITECTURE.md#appendix-a-implementation-status-and-remaining-work).


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

Created and maintained by [foundata](https://foundata.com).
