# Rootless Podman deployment

Deploy one directory snapshot per container. These commands use the README's
`example-app` directory and the files in this repository's `examples/` tree.
Use example files from the same release as your images.
Headings name the host where each action runs; see
[host roles](../../README.md#usage-hosts). Keep an admin/CI terminal and an LDAP-host
terminal open separately. Paths under `${HOME}` belong to the current host account.

## Table of contents

- [Prepare the service account (LDAP host)](#prepare-the-ldap-host)
- [Transfer a snapshot (admin/CI)](#transfer-a-snapshot)
- [Preflight and activate (LDAP host)](#preflight-and-activate)
- [Verify and connect an application (LDAP host)](#verify-and-connect-an-application)
- [Renewals and image updates](#renewals-and-image-updates)
  - [Generate and transfer (admin/CI)](#generate-and-transfer)
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
sed -i "s|^Image=.*|Image=${runtime}|" "${units}/openldap-example.container"
install -m 0700 examples/systemd/openldap-expiry-backstop "${HOME}/.local/libexec/"
install -m 0600 examples/systemd/openldap-example-backstop.* \
  "${HOME}/.config/systemd/user/"
systemctl --user daemon-reload
podman volume create --ignore openldap-example-state
```

The example maps your host UID/GID to container UID/GID `1001`. It uses a
read-only filesystem, restricted capabilities, 256 MiB RAM and no published
ports. The runtime volume is disposable; the state volume must persist.

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
[signing-key rotation](#tls-and-signing-key-rotation). Never transfer the private
signing key, source definition, Vault keys or password files to the LDAP host.

## Preflight and activate (LDAP host)<a id="preflight-and-activate"></a>

Return to the LDAP-host terminal from preparation; it holds `root`, `service`
and `runtime`. Set `revision` to the staged revision. Run deployments one at a
time. The subshell stops at the first error; a rejected preflight leaves the
active service unchanged.

```bash
revision=1
(
  set -eu
  candidate="${service}/incoming/revision-${revision}"
  podman run --rm --userns=keep-id:uid=1001,gid=1001 --network none \
    --read-only --read-only-tmpfs=false --cap-drop all \
    --security-opt no-new-privileges --memory 256m --cpus 1 --pids-limit 128 \
    --tmpfs /run/openldap:rw,noexec,nosuid,nodev,mode=1777 \
    --volume "${candidate}:/snapshot:ro,Z" \
    --volume "${root}/snapshot.pub:/run/credentials/snapshot-public-key:ro,z" \
    --volume openldap-example-state:/state:ro \
    --entrypoint /usr/local/lib/openldap-declarative/preflight-snapshot.sh \
    "${runtime}" /snapshot /run/credentials/snapshot-public-key \
    example-app /state/highest-revision
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
revision state. Exit codes: `0` accepted, `64` invalid runtime settings, `65` invalid data/replay, `66` invalid
input/state, `70` internal failure, `78` expired. For LDAPS, include the target
TLS settings and certificate mounts in preflight too.

Search limits default to 500 results and 10 seconds. Set
`Environment=LDAP_SEARCH_SIZE_LIMIT=1000` and
`Environment=LDAP_SEARCH_TIME_LIMIT=30` in the container unit to change them;
pass matching `--env` values to preflight. Each accepts a positive integer up
to 2147483647 or `unlimited`. Restart after changing a unit setting.

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
  -D "cn=application,ou=services,${base_dn}" -W \
  -b "${base_dn}" '(uid=alice)' uid entryUUID memberOf
podman exec -it openldap-example ldapwhoami -x -H ldap://127.0.0.1:1389 \
  -D "uid=alice,ou=people,${base_dn}" -W
```

Use the application bind password for the search and Alice's password for
`ldapwhoami`. Expect Alice's UUID, membership in `staff`, and a successful bind
returning her DN. Logs: `journalctl --user -u openldap-example.service -n 50`.

Add `Network=openldap-example.network` to the application's Quadlet:

| Application setting | Value |
| ------------------- | ----- |
| LDAP URL | `ldap://ldap:1389` |
| Base DN | `dc=example-app,dc=services,dc=example,dc=org` |
| Bind DN | `cn=application,ou=services,dc=example-app,dc=services,dc=example,dc=org` |
| Bind password | Original password used for the bind account's verifier |
| Login attribute | `uid` |
| Persistent identity attribute | `entryUUID` |
| Group membership attribute | `memberOf` |

The internal network has no external connectivity. An application needing
external access needs its own additional network. Publish LDAP ports only when
required, bound to host `127.0.0.1` for host-local clients.

## Renewals and image updates

### Generate and transfer (admin/CI)<a id="generate-and-transfer"></a>

Increment the directory's YAML revision, regenerate before soft expiry and
transfer to a new staging directory. Replaying an existing artifact does not
renew it. For a release update, use the new generator digest on admin/CI.

### Activate and update the runtime (LDAP host)<a id="activate-and-update-the-runtime"></a>

Repeat preflight, activation and verification with the staged snapshot.

For an image update, pull and record the new runtime digest, set `runtime` to
it and update `Image=` in the container unit. Preflight with that same image
before activation. Keep the existing revision-state volume.

## TLS and signing-key rotation

### TLS (LDAP host)<a id="tls"></a>

For LDAPS, add read-only certificate/key mounts and `LDAP_TRANSPORT=ldaps` or
`both` to the container unit. Match those settings in preflight. Clients must
validate the server name and CA; restart after certificate renewal. See
[runtime inputs](../../README.md#runtime-inputs) for paths and ports.

### Signing-key rotation (admin/CI and LDAP host)<a id="signing-key-rotation"></a>

1. On admin/CI, create the new keypair and transfer only its public key.
2. On the LDAP host, configure runtime and preflight with a directory containing
   old and new `*.pub` keys using `LDAP_SNAPSHOT_PUBLIC_KEY_DIR`; do not also set
   `LDAP_SNAPSHOT_PUBLIC_KEY_FILE`. Restart with that trust set.
3. On admin/CI, sign the next revision with the new key and transfer the snapshot.
4. On the LDAP host, preflight and activate it, updating the backstop key as below.

The supplied host backstop accepts a single public-key file, not a directory.
Keep that file matched to the active snapshot's signer: while LDAP and the
backstop are stopped for activation, replace `snapshot.pub` with the new key.
After confirming the new revision everywhere, remove the old public key from
each LDAP host's runtime trust directory. Empty key directories and symlinks
are rejected.
