# Architecture

This document defines the architecture and required behavioral contract of
OpenLDAP Declarative. The terms MUST, SHOULD and MAY are used as defined in
[RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119) and
[RFC 8174](https://datatracker.ietf.org/doc/html/rfc8174).

Implementation and tests MUST conform to this contract. Discrepancies MUST be
investigated; an approved correction changes either the implementation or the
contract. This document contains no planned or speculative behavior. Proposals
and future changes are tracked separately, preferably as
[issues](https://foundata.com/en/projects/oci-openldap-declarative/#issues),
until the implementation, tests and corresponding contract changes are merged
together.

Selected contracts have stable `IPnnnn` anchors. The generated
[implementation matrix](docs/implementation.md) links them to code and tests;
untagged requirements still apply.


## Table of contents

- [Scope](#scope)
- [Components and data flow](#components)
- [Directory definitions](#definitions)
  - [Custom directory: LDIF](#native-ldif)
  - [Application directory: users/groups YAML](#users-groups)
    - [Additive attributes and classes](#extensions)
  - [Stable identifiers](#identifiers)
  - [Credentials and source encryption](#credentials)
- [Snapshot contract](#snapshots)
- [Runtime contract](#runtime)
  - [Startup and preflight](#startup)
  - [Custom runtime envelope](#custom-runtime)
  - [LDAP access](#access)
  - [Expiry and revision state](#expiry)
  - [Container and transport](#container)
- [Trust and operations](#operations)
- [Verification](#verification)

## Scope<a id="scope"></a>

One definition produces one signed, expiring directory snapshot. One runtime
instance serves one directory; replicas MAY consume the same snapshot.

Users/groups YAML produces a directory read-only to ordinary LDAP clients.
Custom LDIF supplies administrator-owned server configuration and data; its
access and credential policies are not project guarantees. Both paths retain the
signed snapshot lifecycle. Runtime databases and local changes are disposable.
One snapshot-loaded MDB data database is supported; replication consumers and
other data backends are outside the import contract.

## Components and data flow<a id="components"></a>

```text
Static directory definition
  |-- Users/groups YAML with credential sources
  |-- OR complete server configuration and directory entry LDIF
  |
  v
Parse / decrypt / validate / generate LDIF
  |
  v
Package and sign one snapshot
  |
  +-------------------+-------------------+
  v                   v                   v
LDAP runtime A     LDAP runtime B     LDAP runtime C
  |                   |                   |
LDAP clients       LDAP clients       LDAP clients
```

- The generator MUST run before deployment. It parses the source definition,
  resolves credentials, validates directory data and signs the snapshot.
- The runtime MUST verify a snapshot and build a disposable OpenLDAP database
  before listening. It MUST NOT require source files, Vault passwords or a
  private signing key.
- The generator and runtime MUST remain separate images. Source parsing,
  password generation and Ansible Vault tooling belong only in the generator.
  Both images use the same entry-LDIF validator.
- The generator image MUST contain all tooling needed for the documented admin
  workflow, including password hashing, Vault-key generation and snapshot
  signing. Admin operations MUST NOT require the runtime image.
- Configuration and directory entries MUST remain distinct, signed inputs.
  Users/groups YAML uses generated configuration and explicit schema/read-policy
  inputs. Custom LDIF owns the complete server configuration, including schemas.

An administrator or configuration-management system MAY generate and deploy
application-specific definitions and snapshots. Configuration management is not
a required component. Deployment can be local or remote.

<a id="IP0008"></a><!-- Definition initialization -->
The generator's `openldap-init` command MUST create a version-1 users/groups
definition with fresh UUIDv4 identities for the base, one user, one group and
one bind account. Membership MUST reference the user UUID. Credentials MUST
be hash-file references under `/run/credentials`; the command MUST NOT create
passwords or keys. It MUST validate the definition before publishing an
owner-only file, refuse existing paths (including symlinks and concurrent
creators), and leave no partial definition after failure.

## Directory definitions<a id="definitions"></a>

The [directory schema](schema/directory-v1.schema.json) describes format 1.
A definition MUST select exactly one `input_type`: `users-groups` or `ldif`.
Both routes share `directory_id`, `base_dn`, revision and expiry settings.

Custom LDIF is the administrator-owned route for server configuration and data.
Administrators define schema, ACLs, modules, indexes, entries and identities.
Users/groups YAML is a convenience model for application authentication,
identities and group memberships. It generates a fixed layout containing users,
groups and application bind accounts. Dedicated profile fields and additive
attributes/classes extend those entries without changing the generated layout.

Both routes produce the same signed snapshot format and use the same runtime.
Each has exactly one configuration path: generated for users/groups YAML,
administrator-supplied for custom LDIF. There MUST NOT be a configuration-mode
switch or fallback to generated policy for incomplete custom configuration.

YAML MUST use one top-level mapping with string keys. Duplicate keys, aliases,
unknown fields and unsupported tags MUST be rejected. Decrypted strings are
validated as values; they MUST NOT be reparsed as YAML or evaluated as
templates. Schema validation describes the document after decryption.

### Custom directory: LDIF<a id="native-ldif"></a>

- `ldif_files` MUST contain desired-state entry records, including the base and
  every parent entry. Change records, controls, includes and URL-valued
  attributes MUST be rejected.
- Data entries MUST be under `base_dn` and MUST NOT target `cn=config`.
- Entries MAY use other layouts, object classes, binary attributes and
  multivalued attributes. Schema selection MUST be explicit.
- `config_files` MUST contain complete `cn=config` entry LDIF, including
  schemas, modules, databases, ACLs and any overlays, in dependency order. The
  generator MUST combine these records into one signed `config.ldif` without
  inserting generated defaults. Duplicate configuration DNs MUST be rejected.
- `schema_files`, `read_attributes` and application-model fields MUST be
  rejected on this path. The administrator owns schema, access and credential
  policies. The runtime MUST NOT force Argon2id, read-only access or the
  application layout.
- Packaged schema definitions MAY be selected as `config_files` inputs. Their
  contents MUST enter the snapshot; their source paths MUST NOT be needed at
  runtime. Changes, controls, includes and URL-valued imports MUST be rejected.
- The generator MUST NOT infer a users/groups layout or synthesize memberships.
  Administrators MAY supply stored memberships or configure overlay-derived
  memberships.
- The generator MUST validate record structure, scope, supplied identities and
  the runtime envelope. OpenLDAP's offline import and configuration checks are
  the authority for schema and configuration syntax. Deployments MUST preflight
  before activation and test their own access policy with real LDAP clients.

Relative LDIF paths resolve against the definition file's directory.
The generator combines and orders data entries into one LDIF. It retains schema
and configuration file order for dependencies. Input files MUST be regular
files, not symlinks.

### Application directory: users/groups YAML<a id="users-groups"></a>

The runtime MUST load core, cosine, inetOrgPerson, NIS and the bundled
`application-user` schema. Optional `schema_files` MUST contain only direct
children of `cn=schema,cn=config`, using `olcSchemaConfig` and the attributes
`cn`, `objectClass`, `olcAttributeTypes` and `olcObjectClasses`. They MUST NOT
change modules, ACLs, databases or other server configuration. `config_files`
MUST be rejected on this path.

- Every active user MUST appear in the snapshot, regardless of group membership.
  Inactive users MUST be omitted.
- Group members MUST reference existing users by `entry_uuid` or `username`.
  The generator MUST compare references case-insensitively and resolve both
  namespaces. Unknown references, references identifying different users in
  the two namespaces, and repeated users MUST be rejected. Bind accounts MUST
  NOT be group members. Groups with no active members MUST be omitted because
  `groupOfNames` requires a member.
- The generator MUST emit reciprocal `member` and `memberOf` values.
- Users MUST be `inetOrgPerson` entries at `uid=<username>,ou=people,<base_dn>`.
  Their required `last_name` MUST map to `sn`.
- For users and bind accounts, `username` MUST supply LDAP `uid`.
  Optional `display_name` MUST supply `displayName` and `cn`. If omitted,
  `cn` MUST use `username` and `displayName` MUST be absent. Display names MUST
  NOT affect DNs. Usernames MUST be case-insensitively unique across all users
  (including inactive users) and bind accounts.
- Groups MUST be `groupOfNames` entries at `cn=<groupname>,ou=groups,<base_dn>`.
  `groupname` MUST supply `cn`, not `name`, and MUST be case-insensitively
  unique among groups.
- `bind_accounts` MUST be a non-empty list. Each account MUST be an
  `organizationalRole` with `simpleSecurityObject` and the bundled
  `openldapDeclarativeBindAccount` auxiliary class at
  `uid=<username>,ou=services,<base_dn>`. The auxiliary class MUST require `uid`
  and allow `displayName`; bind accounts do not require a surname. Accounts have
  independent credentials and identities but share the read policy.
- The base entry MUST use `dcObject` and `organization`; this route therefore
  requires an ASCII base DN beginning with a single `dc` RDN.
- A default group is not required. Group names such as `ALLOW` and `DENY`
  have no special meaning to the generator or runtime.

Optional user profile fields MUST map as follows. They are strings; omission
means no attribute value. Empty strings and NUL/newline characters are rejected.

|    YAML field     | LDAP attribute |
| ----------------- | -------------- |
| `first_name`      | `givenName`    |
| `initials`        | `initials`     |
| `display_name`    | `displayName` and `cn` |
| `description`     | `description`  |
| `office`          | `physicalDeliveryOfficeName` |
| `phone`           | `telephoneNumber` |
| `mobile`          | `mobile`       |
| `email`           | `mail`         |
| `org`             | `o` (metadata, not directory placement) |
| `employee_number` | `employeeNumber` |
| `department`      | `ou` (metadata, not directory placement) |
| `job_title`       | `title`        |

`employee_number` MUST NOT affect entry UUIDs.
User `org` MUST NOT change the base entry's `organization` value.

`proxy_addresses` MAY contain up to 64 `TYPE:address` strings of at most 1123
characters. The generator MUST preserve them as multivalued `proxyAddresses`,
reject case-insensitive duplicates and add `openldapDeclarativeUser` when the
list is non-empty. It MUST NOT infer a primary address or configure mail
delivery. All supplied profile fields are included in the default
readable-attribute list; an explicit `read_attributes` list replaces those
defaults.

#### Additive attributes and classes<a id="extensions"></a>

Users, groups and bind accounts MAY supply `attributes` and `object_classes`.
Omission, an empty attribute mapping or an empty class list means no extension.

- `attributes` MUST map LDAP names or numeric OIDs to non-empty lists of
  strings. Limits are 128 attributes per entry, 64 values per attribute and 4096
  characters per value. Empty values, NUL/newlines, non-string values and exact
  duplicate values MUST be rejected. Attribute options MUST NOT be accepted.
- `object_classes` MUST contain at most 16 additional auxiliary class names or
  OIDs. Structural/abstract additions, `extensibleObject` and inheritance from
  structural classes or `extensibleObject` MUST be rejected. Class and attribute
  identifiers MUST be at most 128 characters.
- Generator-owned `objectClass`, `entryUUID`, `userPassword`, `member` and
  `memberOf` MUST be reserved on every entry. Users MUST also reserve `uid`,
  `cn`, `sn` and all dedicated profile mappings, even when omitted. Groups and
  bind accounts MUST reserve `cn`; bind accounts MUST also reserve `uid` and
  `displayName`. Operational, collective, non-user-modifiable
  and server-configuration attributes MUST be rejected.
- The generator MUST resolve aliases and OIDs against the bundled schemas and
  optional `schema_files`. Attribute subtypes MUST NOT bypass reserved-field
  restrictions. Unknown types/classes, duplicate aliases, repeated generated
  classes, invalid inheritance and multiple values for a single-valued
  attribute MUST fail generation. Inheritance checks are bounded to 128 steps.
  Schema inputs used for these checks MUST be the same contents packaged in
  the snapshot.
- The generator MUST preserve existing DNs, UUIDs, credentials,
  membership generation and omission rules. It MUST NOT infer auxiliary
  classes from extra attributes or merge them into dedicated profile fields.
- Extensions MUST NOT expand the readable-attribute allowlist. Existing default
  permissions still apply; an explicit `read_attributes` list replaces them
  for all authenticated clients. Vault scalars MUST be decrypted before value
  validation; exported attribute values are not encrypted.

The generator uses `python-ldap` schema parsing and bundled definitions from
the runtime's OpenLDAP package version. The final generator image MUST NOT
contain slapd or the build-only schema exporter.
Schema definitions and their package version MUST be checked against runtime
during integration testing. OpenLDAP offline import remains the authority for
required/allowed attributes and value syntax; preflight is mandatory before
activation. Offline data import MUST enable OpenLDAP value checking for both
input routes. Native LDIF remains the route for arbitrary layouts, structural
classes, binary values and attributes reserved by the simplified model.

### Stable identifiers<a id="identifiers"></a>

<a id="IP0002"></a><!-- Deployment assertions -->
`directory_id` identifies the deployment target. It MUST match the runtime's
`LDAP_EXPECTED_DIRECTORY_ID`; it is independent of LDAP DNs.
An optional `LDAP_EXPECTED_BASE_DN` MUST exactly match the signed base DN;
it MUST NOT override it. An empty or mismatching assertion MUST fail startup
and preflight with exit 64. Removed inputs `LDAP_BASE_DN`, `LDAP_DOMAIN` and
`LDAP_ADMIN_PASSWORD` MUST be rejected with exit 64, including empty values.

In users/groups YAML, the base entry, every user, group and bind account MUST
declare `entry_uuid`. Values MUST be canonical lowercase RFC-variant UUIDs
(version 1 through 8). Administrators SHOULD generate UUIDv4 values once and
MUST preserve them across renames and rebuilds. The generator MUST write each
value directly to LDAP `entryUUID`, without further derivation.

The generator MUST derive each fixed OU's UUID as
`UUIDv5(base_entry_uuid, "ou:" + ou)`, where `ou` is `people`, `groups` or
`services`. UUIDs MUST be unique across all declared entries, including
inactive users, and MUST NOT collide with the base or generated OUs.
Changing `directory_id`, usernames, display names or group names MUST NOT
change entry UUIDs.

The generator MUST resolve memberships to user UUIDs internally and generate
LDAP DN references from the current usernames. UUID references survive
renames; username references require source updates. A reused username may
resolve to a different person. A stateless generator cannot detect that reuse
or distinguish an accidental UUID replacement from an intentional new entry.

Custom LDIF MAY supply `entryUUID`. Supplied values MUST be unique, canonical
lowercase RFC-variant UUIDs (version 1 through 8). The generator MUST preserve
them and MUST NOT derive identity from a mutable DN. If omitted, OpenLDAP
generates new UUIDs on each rebuild. Administrators SHOULD supply UUIDs when
clients depend on stable identities. Custom snapshots have no UUID namespace.

### Credentials and source encryption<a id="credentials"></a>

Every active simplified user and each bind account MUST have exactly one source:

|        Field         | Meaning after optional Vault decryption |
| -------------------- | --------------------------------------- |
| `password`           | Original password to hash               |
| `password_file`      | Absolute path to an original-password file |
| `password_hash`      | Complete verifier to preserve           |
| `password_hash_file` | Absolute path to a verifier file        |

Credential files MUST be owner-only regular files, containing one non-empty
UTF-8 line, at most 4096 bytes, with an optional LF or CRLF terminator.
Unencrypted inline credentials require owner-only YAML permissions.

The generator MUST hash original passwords with salted Argon2id version 19:
19,456 KiB memory, two iterations, one lane, a 16-byte salt and a 32-byte
digest. For users/groups YAML, the generator and runtime MUST reject
`userPassword` values that are not valid `{ARGON2}` Argon2id verifiers. Seeded
verifiers MUST meet those minimum memory, iteration, salt and digest sizes and
use canonical unpadded base64. Parameter bounds MUST also fit the Argon2
implementation.

Custom LDIF credentials MUST remain administrator-owned values. Their usability
depends on the selected OpenLDAP configuration and modules. Snapshot signing
MUST NOT be described as validating the strength or confidentiality of those
credentials.

The generator's `openldap-password` command MUST use the same hashing
parameters. It MUST read one non-empty UTF-8 password from stdin, at most 4096
bytes with an optional LF or CRLF terminator, and output only its verifier on
success. Invalid input MUST fail without echoing the supplied value. Password
arguments and terminal input MUST be rejected.

YAML string values MAY use labeled Ansible Vault scalars:
`!vault` with the standard `$ANSIBLE_VAULT;1.2;AES256;KEYID` header.

<a id="IP0007"></a><!-- Vault decryption -->

- Decryption MUST occur only in the generator, through the official
  `ansible-vault` CLI from `ansible-core`.
- Key IDs MUST select an explicitly supplied password source exactly. Missing
  IDs, repeated key definitions, wrong keys and damaged ciphertext MUST fail.
- Password sources MUST be prompts or regular owner-only files, never executable
  password providers. Vault passwords MUST NOT appear in process arguments or
  environment variables passed to the decryption process.
- The adapter MUST isolate Ansible configuration and temporary files from
  inherited host settings. It MUST NOT load playbooks, inventory or templates.
- Decrypted scalar contents MUST retain the field's meaning. Encrypting a
  `*_file` value encrypts its path, not the referenced file. Whole encrypted
  files and encryption embedded inside LDIF are not supported.
- The source limit is 1 MiB, with at most 256 encrypted values of 32 KiB each.
  Each decryption subprocess MUST have a 30-second timeout.
- Repeated identical ciphertext MAY reuse a successful decryption within one
  generator invocation. Every occurrence MUST still count toward the value
  limit; cached values MUST NOT be persisted or shared across invocations.
- Errors MUST NOT echo passwords, decrypted credential values or Vault keys.

## Snapshot contract<a id="snapshots"></a>

The [manifest schema](schema/snapshot-manifest-v1.schema.json) defines format 1.
A snapshot MUST contain `manifest.json`, its detached minisign signature and
only the listed LDIF files. Each file record declares its `data`, `schema` or
`config` kind and SHA-256 digest.

<a id="IP0001"></a><!-- Snapshot signature verification -->
The signed manifest MUST cover directory identity, base DN, revision, input
type, applicable read-attribute policy, base `entry_uuid` (null for custom LDIF)
and timestamps. The runtime MUST reject unknown fields, duplicate paths, invalid
file kinds, unsafe paths, mismatched digests and unlisted LDIF files. Signatures
MUST be verified before interpreting manifest-controlled data.

Users/groups manifests MUST carry `read_attributes` and permit only `data` and
`schema` files. Custom manifests MUST omit `read_attributes`, contain exactly
one `config` file and permit only `data` and `config` files. Both MUST contain
data.

The generator MUST publish into a new output directory, with directory mode
`0700` and file mode `0600`. Limits: 32 files, 16 MiB combined LDIF,
1 MiB manifest and 16 KiB signature.
The verifier MUST bound each LDIF copy to the remaining byte budget plus one
byte before checking its size and digest. Oversized input MUST fail with exit
65 without copying the rest of the source file.

## Runtime contract<a id="runtime"></a>

### Startup and preflight<a id="startup"></a>

<a id="IP0006"></a><!-- Open-file resource ceiling -->
Before running OpenLDAP tools, startup and preflight MUST cap their soft and
hard open-file limits at `LDAP_MAX_OPEN_FILES` (default `4096`), preserving
any lower inherited limits. The setting MUST accept integers from `1` through
`2147483647`; invalid values MUST fail with exit 64. Failure to apply the
ceiling MUST fail with exit 70. This applies to both input paths.

Before opening listeners, startup MUST:

1. Verify the signature, target identity, file list, digests and timestamps.
2. Reject rollback or a reused revision with different manifest content.
3. Validate entry LDIF and the applicable schema/configuration inputs.
4. Rebuild configuration and MDB from verified private copies.
5. Run offline OpenLDAP schema/configuration validation, import, indexing and
   readback validation. Users/groups snapshots also require reciprocal
   membership.
6. Recheck expiry, then start LDAP and record the accepted revision and digest.

The runtime image MUST expose `openldap-preflight`, configured by the same
`LDAP_*` environment variables and defaults as startup. It MUST NOT require
positional arguments or infer the expected directory ID from the snapshot.
Startup and preflight MUST share runtime-setting validation.
Preflight MUST perform equivalent offline checks without opening a listener,
modifying existing revision state or changing the running directory. Custom LDIF
preflight MUST run in a separate container with fresh `/run/openldap` scratch
storage and read-only input/state mounts. It MUST refuse a nonempty runtime
directory rather than redirecting administrator-supplied paths into the active
service. The preflight invocation MUST clean its own scratch data. Startup MUST
repeat verification after deployment. Failed validation MUST prevent serving.

The database MUST be rebuilt on every startup. Persistent revision state is
separate from disposable configuration, sockets and MDB files.

### Custom runtime envelope<a id="custom-runtime"></a>

- `base_dn` declares the single data import target. The custom configuration
  MUST contain exactly one MDB database whose `olcSuffix` matches that target
  and whose `olcDbDirectory` is `/run/openldap/data`. Config/frontend databases
  are permitted; other data backends, extra MDB databases and replication
  consumers MUST be rejected.
- Configuration and sockets live under `/run/openldap`; `LDAP_RUNTIME_DIR` MUST
  retain that path. If specified, PID/argument files MUST be
  `/run/openldap/slapd.pid` and `/run/openldap/slapd.args`.
- Runtime owns listeners, signature/revision checks, supervision and
  `LDAP_LOG_LEVEL`. Custom LDIF MUST NOT contain `olcLogLevel`. The runtime MUST
  reject `LDAP_SEARCH_SIZE_LIMIT`, `LDAP_SEARCH_TIME_LIMIT`,
  `LDAP_TLS_CERT_FILE`, `LDAP_TLS_KEY_FILE`, `LDAP_TLS_CA_FILE`,
  `LDAP_ADMIN_PASSWORD_FILE` for custom LDIF.
  Corresponding settings belong to LDIF.
- Configuration MUST use attribute names without options. Modules MUST use
  packaged basenames and `/usr/lib/ldap`; snapshot-provided binaries and
  arbitrary library paths MUST NOT be accepted. Optional modules MUST NOT be
  loaded by the generated YAML configuration.
- Custom configuration MUST permit the current process's peer-credential
  identity to search its base entry over LDAPI for health checks. Before
  serving, startup and preflight MUST use `slapacl` to check base-entry read
  access and `objectClass` search access with the local socket context and
  configured local SSF. This check MUST have a 15-second timeout and require
  explicit ALLOWED results, not only a successful tool exit. Administrators MUST
  also test live health checks with their chosen ACLs, overlays and
  authentication mappings.
- Custom configuration is trusted administrative input, including code executed
  by modules during import. Preflight MUST use container isolation and read-only
  service mounts, not claim to sandbox arbitrary executable code.

The [custom LDIF guide](docs/custom-ldif.md) lists packaged modules and complete
examples. The project guarantees the snapshot lifecycle for supported custom
configuration, not its access policy, password strength or overlay combinations.
If writes are allowed, the snapshot authenticates deployment inputs rather than
subsequent data. Directory writes and database-backed overlay state are
discarded on rebuild. Additional files, such as audit logs, remain
deployment-owned.

### LDAP access<a id="access"></a>

<a id="IP0005"></a><!-- Managed access policy -->
For users/groups YAML, ordinary accounts MUST NOT write directory entries,
read password hashes or access `cn=config`. Anonymous directory searches MUST
be denied. Authenticated
accounts MAY read the signed attribute allowlist throughout the directory;
`entry` and `children` access are included for traversal.

For users/groups YAML, `LDAP_SEARCH_SIZE_LIMIT` and `LDAP_SEARCH_TIME_LIMIT`
MUST configure the global search result and duration limits, defaulting to 500
results and 10 seconds. Each accepts integers from 1 through 2,147,483,647 or
`unlimited`. Empty values, other spellings and invalid numbers MUST fail startup
and preflight with exit code 64. These are operator-controlled runtime settings,
not signed directory data; preflight SHOULD use the same settings as the target
runtime. Size limits apply to the total search result, including paged searches,
not directory capacity.

Users/groups snapshots default to identity and membership attributes.
Password ACLs MUST precede this list.
The local peer-credential identity MAY read through LDAPI for health checks.

Users/groups YAML configures no recovery administrator by default. If explicitly
enabled, `cn=admin,<base_dn>` bypasses ACLs and MAY write or read verifiers. It
MUST NOT be used by applications. Its modifications disappear on rebuild.

### Expiry and revision state<a id="expiry"></a>

<a id="IP0003"></a><!-- Revision rollback protection -->

- Revisions MUST be integers from 1 through 9,007,199,254,740,991 and MUST
  increase for each newly generated snapshot, including unchanged-data renewals.
- Exact artifact replay MAY restart a directory but MUST NOT extend its
  lifetime.
- Generation time MUST NOT be more than five minutes ahead of the runtime clock.
<a id="IP0004"></a><!-- Expiry enforcement -->
- Soft expiry warns; hard expiry MUST stop LDAP with exit code 78.
- `soft_ttl_seconds` MUST be less than `hard_ttl_seconds`.
  `expiry_offset_seconds` subtracts from both deadlines and MUST be in
  0..86,400 and less than the soft TTL.
- The runtime supervisor MUST check expiry while running. The provided host
  backstop independently checks the active snapshot and can stop a suspended
  or unhealthy container.
- Operators MUST preserve revision state across routine container restarts and
  updates, and maintain reliable host time. A replacement host without revision
  state MUST bootstrap from a known-current signed snapshot supplied by the
  trusted deployment process; startup establishes its new revision baseline.

Expiry bounds LDAP availability, not existing application sessions or caches.
Consumers need their own revocation and session policies.

### Container and transport<a id="container"></a>

The runtime MUST support UID/GID 1001, a read-only root filesystem, dropped
capabilities and no-new-privileges. Users/groups YAML and the custom example
need writable mounts only for the runtime directory and revision state.
Custom configurations MAY require additional declared writable paths; preflight
MUST use disposable scratch mounts for them, not writable service mounts.
No source or deployment secrets belong in image layers.
Both final images MUST be free of set-user-ID and set-group-ID executables.
UID/GID 1001 ownership MUST be limited to the declared writable directories;
image files MUST NOT have unmapped owners or groups.

LDAP defaults to loopback port 1389; optional LDAPS uses port 1636. Ports MUST
be unprivileged and distinct when both transports are enabled. Generated YAML
configuration MUST require TLS 1.2 or newer for LDAPS. Custom LDIF owns TLS
policy and SHOULD require TLS 1.2 or newer. Clients MUST validate certificates
and names. Plain LDAP SHOULD be restricted to a trusted host-local connection
or isolated network.

## Trust and operations<a id="operations"></a>

Snapshot signatures provide authenticity and integrity, not encryption.
Vault protects source values at rest; the generated snapshot still contains
password verifiers. LDAP attributes from either input route can contain other
secrets.

Administrators MUST protect definitions, snapshots, clones, backups and signing
infrastructure from unauthorized access or modification. Production directory
data and snapshots MUST NOT be placed in public repositories, public image
layers or logs. A private repository MAY hold reviewed encrypted definitions
or controlled hash-only data. Strong passwords remain necessary against
offline guessing; Vault keys SHOULD be high-entropy, independently protected
secrets.

Deployment tooling MUST deliver the snapshot and public verification keys
beside the runtime for read-only mounting. It MUST NOT deliver source-decryption
keys or the private signing key. Renewals SHOULD arrive before soft expiry.

Backups MUST include source definitions, stable identifiers, required secret
material, signing keys and deployment settings. Restores MUST use a current
signed snapshot and verify identity and authentication.

## Verification<a id="verification"></a>

Tests MUST cover both source routes through generation and real LDAP use,
including Vault success/failure, credential forms, custom schema boundaries,
additive YAML fields, alias/subtype restrictions and read-attribute policy,
stable identities, managed read policy, managed write rejection, signatures,
expiry and replay.
Custom LDIF tests MUST cover configuration ownership, packaged modules,
administrator-selected ACLs and writes, disposable state, unsigned configuration
rejection and isolated preflight against an already running directory.
A successful image build alone is insufficient.

Repository checks and rootless integration tests are documented in
[DEVELOPMENT.md](DEVELOPMENT.md). Runtime and generator releases MUST be tested
together on each declared platform. Booted-host lifecycle checks require a
systemd-capable test environment.
