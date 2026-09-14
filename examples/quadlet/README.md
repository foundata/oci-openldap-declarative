# Rootless Podman deployment

Deploy one directory snapshot per container. These commands use the README's
`example-app` directory and the files in this repository's `examples/` tree. Use
example files from the same release as your images. Headings name the host where
each action runs; see [host roles](../../README.md#usage-hosts). Keep an
admin/CI terminal and an LDAP-host terminal open separately. Paths under
`${HOME}` belong to the current host account.

## Table of contents

- [Prepare the service account (LDAP host)](#prepare-the-ldap-host)
- [Transfer a snapshot (admin/CI)](#transfer-a-snapshot)
- [Preflight and activate (LDAP host)](#preflight-and-activate)
- [Verify and connect an application (LDAP host)](#verify-and-connect-an-application)
- [Shared application pod (LDAP host)](#shared-application-pod)
- [Renewals and image updates](#renewals-and-image-updates)
  - [Generate and transfer (admin/CI)](#generate-and-transfer)
  - [Deployment retries](#deployment-retries)
  - [Activate and update the runtime (LDAP host)](#activate-and-update-the-runtime)
- [TLS and signing-key rotation](#tls-and-signing-key-rotation)
  - [TLS (LDAP host)](#tls)
  - [Signing-key rotation (admin/CI and LDAP host)](#signing-key-rotation)

## Prepare the service account (LDAP host)<a id="prepare-the-ldap-host"></a>

Use a dedicated Linux account with rootless Podman and a running systemd user
manager. Run this guide's host commands as that account in Bash. A host
administrator must enable lingering so the service runs without an active login:

```bash
sudo loginctl enable-linger "${USER}"
```

Pull the approved runtime image and set `runtime` to its immutable reference:

```bash
runtime=quay.io/foundata/openldap-declarative:latest
podman pull "${runtime}"
runtime=$(podman image inspect --format '{{index .RepoDigests 0}}' "${runtime}")
```

Install the units from the repository root. Adjust names, paths and resource
limits for additional directories; do not share their revision-state volumes.

```bash
umask 077
root="${HOME}/.local/share/openldap-declarative"
service="${root}/example-app"
units="${HOME}/.config/containers/systemd"
install -d -m 0700 "${service}/incoming" "${units}" \
  "${HOME}/.local/libexec" "${HOME}/.config/systemd/user"
install -m 0600 examples/quadlet/*.container examples/quadlet/*.network \
  examples/quadlet/*.volume "${units}/"
install -m 0600 examples/quadlet/ldap.env "${service}/ldap.env"
sed -i "s|^Image=.*|Image=${runtime}|" "${units}/openldap-example.container"
install -m 0700 examples/systemd/openldap-expiry-backstop "${HOME}/.local/libexec/"
install -m 0600 examples/systemd/openldap-example-backstop.* \
  "${HOME}/.config/systemd/user/"
systemctl --user daemon-reload
podman volume create --ignore openldap-example-state
```

Edit `ldap.env` for this directory. Quadlet and preflight read this same file;
use literal `KEY=value` lines without shell expansion or plaintext secrets.
Keep container paths identical in both invocations.

The example maps your host UID/GID to container UID/GID `1001`. It uses a
read-only filesystem, restricted capabilities, 256 MiB RAM and no published
ports. The runtime volume is disposable; the state volume must persist.
`Ulimit=nofile=1024:1024` keeps slapd's connection-table allocation small enough
for this memory budget. Startup also caps inherited descriptor limits at
`LDAP_MAX_OPEN_FILES` (default `4096`). Review `Memory=256m` when raising either
limit or changing the workload or custom server configuration.

## Transfer a snapshot (admin/CI)<a id="transfer-a-snapshot"></a>

Switch to the admin/CI terminal and use the variables from the
[README generation steps](../../README.md#usage-snapshot-generate).
Set `ldap_host` to the dedicated SSH account on the LDAP host:

```bash
ldap_host=ldap-service@ldap-host.example.org
revision=1
(
  set -eu
  ssh "${ldap_host}" "umask 077; mkdir ~/.local/share/openldap-declarative/example-app/incoming/revision-${revision}"
  scp -r "${output}/revision-${revision}/." \
    "${ldap_host}:.local/share/openldap-declarative/example-app/incoming/revision-${revision}/"
)
```

For initial installation, also transfer the public key:

```bash
scp "${private}/snapshot.pub" \
  "${ldap_host}:.local/share/openldap-declarative/snapshot.pub"
```

The destination revision directory must be new. For later key changes, follow
[signing-key rotation](#tls-and-signing-key-rotation). Never transfer the
private signing key, source definition, Vault keys or password files to the LDAP
host.

## Preflight and activate (LDAP host)<a id="preflight-and-activate"></a>

Return to the LDAP-host terminal from preparation; it holds `root`, `service`
and `runtime`. Set `revision` to the staged revision. Run deployments one at a
time. The subshell stops at the first error; a rejected preflight leaves the
active service unchanged.

For [custom LDIF](../../docs/custom-ldif.md), keep the separate preflight
container and fresh scratch mount below. Do not run preflight inside the LDAP
service container. Adapt the directory ID and client queries, and provide any
TLS mounts referenced by the custom configuration to both containers.

```bash
revision=1
(
  set -eu
  candidate="${service}/incoming/revision-${revision}"
  podman run --rm --userns=keep-id:uid=1001,gid=1001 --network none \
    --read-only --read-only-tmpfs=false --cap-drop all \
    --security-opt no-new-privileges --memory 256m --cpus 1 --pids-limit 128 \
    --env-file "${service}/ldap.env" \
    --tmpfs /run/openldap:rw,noexec,nosuid,nodev,mode=1777 \
    --volume "${candidate}:/snapshot:ro,Z" \
    --volume "${root}/snapshot.pub:/run/credentials/snapshot-public-key:ro,z" \
    --volume openldap-example-state:/state:ro \
    --entrypoint openldap-preflight "${runtime}"
  test ! -e "${service}/retired-before-${revision}"
  systemctl --user stop openldap-example-backstop.timer openldap-example-backstop.service
  systemctl --user stop openldap-example.service
  if [ -e "${service}/snapshot" ]; then
    mv -T "${service}/snapshot" "${service}/retired-before-${revision}"
  fi
  mv -T "${candidate}" "${service}/snapshot"
  systemctl --user daemon-reload
  systemctl --user start openldap-example.service
  systemctl --user enable --now openldap-example-backstop.timer
)
```

Preflight verifies and imports offline without opening a listener or updating
revision state. Exit codes: `0` accepted, `64` invalid runtime settings, `65`
invalid data/replay, `66` invalid input/state, `70` internal failure, `78`
expired. For LDAPS, include the target TLS settings and certificate mounts in
preflight too.

Search limits default to 500 results and 10 seconds. Set
`LDAP_SEARCH_SIZE_LIMIT=1000` and `LDAP_SEARCH_TIME_LIMIT=30` in `ldap.env`
to change them for both startup and preflight. Each accepts a positive integer
up to 2147483647 or `unlimited`. Restart after changing settings.

Activation briefly stops LDAP while replacing the snapshot directory. Do not
use a symlink for the active snapshot: the host backstop rejects it. A failed
activation needs operator attention before restarting LDAP and its timer.
Keep retired snapshots private and remove them after verifying the replacement.
Never discard or roll back revision state to accept an older snapshot.

## Verify and connect an application (LDAP host)<a id="verify-and-connect-an-application"></a>

```bash
systemctl --user status openldap-example.service
podman exec openldap-example /usr/local/lib/openldap-declarative/status.sh
systemctl --user start openldap-example-backstop.service
systemctl --user status openldap-example-backstop.timer
base_dn=dc=example-app,dc=services,dc=example,dc=org
podman exec -it openldap-example ldapsearch -x -H ldap://127.0.0.1:1389 \
  -D "uid=application,ou=services,${base_dn}" -W \
  -b "${base_dn}" '(uid=alice)' uid entryUUID memberOf
podman exec -it openldap-example ldapwhoami -x -H ldap://127.0.0.1:1389 \
  -D "uid=alice,ou=people,${base_dn}" -W
```

Use the application bind password for the search and Alice's password for
`ldapwhoami`. Expect Alice's UUID, membership in `staff`, and a successful bind
returning her DN. Logs: `journalctl --user -u openldap-example.service -n 50`.

Add `Network=openldap-example.network` to the application's Quadlet.

For users/groups YAML, replace `<base_dn>` below with the definition's `base_dn`.
Custom LDIF supplies its own layout and attribute mappings.

| Application setting | Value |
| ------------------- | ----- |
| LDAP URL | `ldap://ldap:1389`; shared pod: `ldap://127.0.0.1:1389` |
| Directory base | `<base_dn>` |
| Bind DN | `uid=application,ou=services,<base_dn>`; use your bind account's username |
| Bind password | Original password used for the bind account's verifier |
| User search base / scope | `ou=people,<base_dn>` / subtree; excludes bind accounts |
| User filter | `(objectClass=inetOrgPerson)` |
| Login attribute | `uid` |
| Persistent identity attribute | `entryUUID`; retain this mapping across username/email changes |
| Group search base / scope | `ou=groups,<base_dn>` / subtree |
| Group filter / name | `(objectClass=groupOfNames)` / `cn` |
| Group members | `member` on the group contains full user DNs, not usernames |
| User's groups | `memberOf` on the user contains full group DNs |
| First / last / display name | `givenName` / `sn` / `displayName` |
| Email / phone | `mail` / `telephoneNumber` |

For group-limited login, use
`(&(objectClass=inetOrgPerson)(memberOf=cn=staff,ou=groups,<base_dn>))`.
Configure role mapping in the application. Update DN-based group mappings after
a group rename. Optional profile attributes may be absent.

The internal network has no external connectivity. An application needing
external access needs its own additional network. Publish LDAP ports only when
required, bound to host `127.0.0.1` for host-local clients.

## Shared application pod (LDAP host)<a id="shared-application-pod"></a>

Use a [shared pod](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
instead of the separate network when the application connects to LDAP
through pod-local `127.0.0.1`. Install the pod unit:

```bash
install -m 0600 examples/quadlet/example-app.pod "${units}/"
```

Before activation, adjust the units and shared settings:

1. In `openldap-example.container`, replace `UserNS=`, `Network=` and
   `NetworkAlias=` with `Pod=example-app.pod`. Keep `User=1001:1001`, the existing
   mounts, resource limits and hardening.
2. In `ldap.env`, set `LDAP_LISTEN_HOST=127.0.0.1`.
3. In the application's `.container`, set `Pod=example-app.pod` and remove its
   `Network=` and `UserNS=` settings. Set `User=` to the account expected by its
   image; the pod's `keep-id` mapping otherwise defaults processes to UID 1001.
   Match each data volume's ownership to its process user (`:U` is suitable for
   an exclusively owned named volume).
4. Put any application `PublishPort=` settings in `example-app.pod`; do not
   publish LDAP. Connect the application to `ldap://127.0.0.1:1389`.

Run `systemctl --user daemon-reload`, then preflight and activate as above before
starting the application unit.
Preflight remains a separate container outside the pod, with fresh scratch
storage and read-only state. The VM/host's `localhost:1389` is not this endpoint.
Changing an existing pod's namespace settings requires recreating its containers;
plan application downtime and retain its data volumes.

## Renewals and image updates

### Generate and transfer (admin/CI)<a id="generate-and-transfer"></a>

Use one serialized admin/CI job per directory:

1. Allocate and retain the next `revision` in the definition. Configuration
   management or CI owns this counter; the generator does not increment it.
2. Record the source revision, credential versions and generator/runtime digests.
3. Generate once into a new `revision-N` directory. Retain that exact signed
   artifact privately, with its manifest digest and expiry times.
4. Transfer, preflight, activate and verify. Record which artifact reached each
   LDAP host. Schedule renewal early enough to finish before soft expiry.

Unchanged source still needs a new revision and fresh artifact for renewal.
Replaying existing bytes does not extend expiry. Alert on generation/deployment
failures and the [runtime status](../../README.md#usage-ops-status), not just the
CI job's schedule.

### Deployment retries

| Situation | Action |
| --------- | ------ |
| Transfer interrupted | Resume copying the retained artifact into its unactivated candidate directory; rerun preflight. |
| Preflight rejected input | Leave the active service unchanged. Correct settings or generate corrected data under a new revision. |
| Activation result uncertain | Inspect active status and revision state. If the exact manifest is already active and healthy, do not restart again. |
| Artifact lost after deployment, or renewal due | Allocate a new revision and generate again. Do not recreate an accepted revision from source. |

Retry deployment with the same artifact, not another generator invocation:
timestamps and password salts can change the manifest even with unchanged YAML.
Never reset revision state to make a retry succeed. Retain the candidate and logs
after a failed activation until recovery is complete.

### Activate and update the runtime (LDAP host)<a id="activate-and-update-the-runtime"></a>

Repeat preflight, activation and verification with the staged snapshot.

For an image update, pull and record the new runtime digest, set `runtime` to
it and update `Image=` in the container unit. Preflight with that same image
before activation. Keep the existing revision-state volume.

## TLS and signing-key rotation

### TLS (LDAP host)<a id="tls"></a>

For LDAPS, add read-only certificate/key mounts to runtime and preflight, and
set `LDAP_TRANSPORT=ldaps` or `both` in `ldap.env`. Clients must
validate the server name and CA; restart after certificate renewal. See
[runtime inputs](../../README.md#runtime-inputs) for paths and ports.
Custom LDIF must declare certificate paths and TLS policy in its signed
`config_files`; do not set the YAML-only `LDAP_TLS_*` file inputs.

### Signing-key rotation (admin/CI and LDAP host)<a id="signing-key-rotation"></a>

1. On admin/CI, create the new keypair and transfer only its public key.
2. On the LDAP host, mount a directory containing old and new `*.pub` keys
   read-only into runtime and preflight. Set `LDAP_SNAPSHOT_PUBLIC_KEY_DIR` in
   `ldap.env` to its container path; do not also set
   `LDAP_SNAPSHOT_PUBLIC_KEY_FILE`. Restart with that trust set.
3. On admin/CI, sign the next revision with the new key and transfer the
   snapshot.
4. On the LDAP host, preflight and activate it, updating the backstop key as
   below.

The supplied host backstop accepts a single public-key file, not a directory.
Keep that file matched to the active snapshot's signer: while LDAP and the
backstop are stopped for activation, replace `snapshot.pub` with the new key.
After confirming the new revision everywhere, remove the old public key from
each LDAP host's runtime trust directory. Empty key directories and symlinks
are rejected.
