# Custom LDIF

Use `input_type: ldif` to supply complete OpenLDAP server configuration and
directory entries. There is no generated configuration in this path.
The runtime verifies and imports the signed snapshot, checks revisions and
stops the server at expiry. You own the LDAP access policy and credentials.

## Starting point

On the admin host, put these files from the same project version in your input
directory:

- [native.yaml](../examples/generator/native.yaml): snapshot settings and
  ordered inputs.
- [native-server.ldif](../examples/generator/native-server.ldif): global
  configuration, schema container and module selection.
- [native-database.ldif](../examples/generator/native-database.ldif): one MDB
  database, indexes and read-only access policy.
- [device-schema.ldif](../examples/generator/device-schema.ldif): example
  attribute/class definitions.
- [native.ldif](../examples/generator/native.ldif): directory entries and a
  test-only bind account.

1. Rename `native.yaml` to `directory.yaml` for the README commands.
2. Change `directory_id` and `base_dn`; update `olcSuffix`, entry DNs and ACL
   references to match.
3. Replace the test bind password verifier. The generator's
   [password helper](../README.md#usage-prepare) produces Argon2id verifiers;
   custom LDIF can use other schemes supported by the selected server modules.
4. Edit configuration and entries. Keep stable `entryUUID` values when
   applications depend on persistent identities; omitted UUIDs are generated
   afresh on every import.
5. [Generate and sign](../README.md#usage-snapshot) with the generator image.
6. [Preflight and deploy](../examples/quadlet/README.md#preflight-and-activate)
   with the matching runtime image. Always use a separate preflight container
   with fresh `/run/openldap` scratch storage and read-only snapshot, key, TLS
   and revision-state mounts.
7. Test permitted and denied searches, binds and writes with actual client
   identities. Offline validation does not establish that an ACL implements your
   intended policy.

The example denies anonymous searches, lets application accounts read selected
attributes without password verifiers, and uses `olcReadOnly: TRUE`. Its local
peer-credential ACL supports health checks with the container's current UID/GID.
It does not create a recovery administrator.

## Configuration inputs

`config_files` contains ordinary `cn=config` entry LDIF in import order,
including schema and overlay entries. No configuration defaults are inserted.
The generator combines these files into signed `config.ldif` and preserves
entry order. Load module definitions before schemas or overlays that need them.

Debian schema LDIF files are available in the generator at
`/usr/local/share/openldap-declarative/schema/available/`. The project schema is
`/usr/local/share/openldap-declarative/schema/application-user.ldif`.
Select these files explicitly in `config_files`; their contents enter the
snapshot, so the runtime does not need the source paths.

`ldif_files` contains desired-state entries under `base_dn`, including the base
and every parent. The generator orders entries by depth before packaging them.
Binary values use inline LDIF base64. Both lists require regular files, not
symlinks. Change records, controls, includes and URL-valued file imports are
rejected; put each source file in the appropriate list instead.

`schema_files`, `read_attributes`, users, groups and generated credential fields
are not accepted in this path. Configuration attribute names must use their
LDAP names without attribute options. OpenLDAP validates schema syntax and
values during offline import, including required attributes.

## Runtime envelope

|        Owner        | Settings |
| ------------------- | -------- |
| Snapshot definition | Directory ID, revision, deadlines, file lists and `base_dn` import target. |
| Custom LDIF         | Schema, ACLs, credential policy, TLS certificate settings, search limits, indexes, MDB size and overlay configuration. |
| Runtime/deployment  | Signature verification keys, accepted revision state, expiry supervision, container isolation, listener addresses/ports and `LDAP_LOG_LEVEL`. |

- One MDB data database is supported. Its `olcSuffix` must match `base_dn` and
  its `olcDbDirectory` must be `/run/openldap/data`. Config/frontend databases
  are permitted; other data backends, extra MDB databases and
  replication-consumer settings are not supported.
- `/run/openldap` holds disposable configuration, data and sockets.
  `LDAP_RUNTIME_DIR` must retain that path. If supplied, `olcPidFile` and
  `olcArgsFile` must be `/run/openldap/slapd.pid` and
  `/run/openldap/slapd.args`.
- Omit `olcLogLevel`; set `LDAP_LOG_LEVEL` for process logging. Omit
  `LDAP_SEARCH_SIZE_LIMIT`, `LDAP_SEARCH_TIME_LIMIT`, `LDAP_TLS_CERT_FILE`,
  `LDAP_TLS_KEY_FILE`, `LDAP_TLS_CA_FILE` and both recovery-password environment
  inputs. Conflicting settings fail explicitly.
- For TLS, configure `olcTLSCertificateFile`, `olcTLSCertificateKeyFile` and
  other TLS settings in LDIF, mount those files read-only, and select the
  listener with `LDAP_TRANSPORT`. You own protocol/cipher policy in this path.
- Health checks need a successful SASL EXTERNAL base search over LDAPI for
  `base_dn`. Preserve or adapt the example's local peer-credential rule at the
  start of the MDB ACLs; frontend ACLs alone can be masked by database rules.
  Preflight checks entry read and `objectClass` search access with `slapacl`.
  Also verify the live health check, particularly with authentication mappings
  or overlays. Keep the socket directory private.
- Preflight refuses a runtime directory containing existing files or databases.
  Do not run custom preflight through `podman exec` in the LDAP service
  container. A separate rootless container must mount fresh scratch storage and
  no writable service database or revision state.
- Custom configuration is trusted administrative input. Modules execute inside
  slapd and its offline tools. Run preflight with the same resource constraints
  as runtime and without network access. A signature does not sandbox
  configuration or executable modules.
- You own additional writable paths, such as audit-log destinations. Give
  preflight disposable scratch mounts at those paths, never writable mounts from
  the running service.

Settings outside this envelope fail validation or OpenLDAP import. The project
does not analyze arbitrary ACLs for confidentiality or enforce a read-only
policy on administrator-authored LDIF.

## Modules

The runtime packages these modules. Custom configuration loads only those named
with `olcModuleLoad`; use `olcModulePath: /usr/lib/ldap` and module basenames,
optionally ending in `.la` or `.so`.

|              Module              | Purpose |
| -------------------------------- | ------- |
| `back_mdb`                       | Snapshot-loaded MDB storage. |
| `argon2`                         | Argon2 password verification. |
| `memberof`                       | Membership schema and optional reverse-membership maintenance. |
| `sssvlv`                         | Server-side sorting and virtual list views. |
| `dynlist`                        | Computed lists and group memberships. |
| `deref`, `rwm`, `valsort`        | Dereferencing, rewriting/remapping and value sorting. |
| `ppolicy`                        | Password-policy processing and associated state. |
| `refint`, `unique`, `constraint` | Referential integrity and update constraints. |
| `auditlog`, `syncprov`           | Change logging and synchronization-provider behavior. |

Loading a module does not automatically configure an overlay. For sorting,
add `olcModuleLoad: sssvlv` to your module entry and append this configuration:

```ldif
dn: olcOverlay={0}sssvlv,olcDatabase={1}mdb,cn=config
objectClass: olcOverlayConfig
objectClass: olcSssVlvConfig
olcOverlay: {0}sssvlv
olcSssVlvMax: 2
olcSssVlvMaxKeys: 2
olcSssVlvMaxPerConn: 1
```

Module availability is not a promise that every combination works. Test the
controls and identities your clients use. Sorting consumes memory; dynamic
groups need ACL/paging tests. Password-policy counters, reverse-membership
updates and other runtime state are disposable. Additional executable modules
require a reviewed image and corresponding runtime-envelope changes; snapshots
cannot supply shared libraries or arbitrary module paths.

## Writes and renewal

To permit writes, deliberately change `olcReadOnly` and the relevant ACLs.
The next start imports the signed snapshot again and discards local edits,
password changes, counters and database-backed overlay state. Preserve lasting
changes in the source and generate a new signed revision. No automatic export
is provided. Additional files, such as audit logs, are deployment-owned and are
not reset by the database rebuild.

Signature, target, revision and expiry checks apply even when writes are
enabled. They authenticate the deployment inputs, not subsequent directory
contents. Keep production configuration and snapshots private: custom LDIF can
contain original passwords, hashes, TLS material or other secrets. The generator
does not redact or encrypt them.
