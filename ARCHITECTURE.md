# Architecture

This document defines the architecture and required behavioral contract of
OpenLDAP Declarative. The terms MUST, SHOULD and MAY are used as defined in
[RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119) and
[RFC 8174](https://datatracker.ietf.org/doc/html/rfc8174).

Implementation and tests MUST conform to this contract.
Discrepancies MUST be investigated; an approved correction changes either the
implementation or the contract. This document contains no planned or speculative
behavior. Proposals and future changes are tracked separately, preferably as
[issues](https://github.com/foundata/oci-openldap-declarative/issues), until the
implementation, tests and corresponding contract changes are merged together.


## Table of contents

- [Scope](#scope)
- [Components and data flow](#components)
- [Directory definitions](#definitions)
  - [General directory: native LDIF](#native-ldif)
  - [Application directory: users/groups YAML](#users-groups)
  - [Stable identifiers](#identifiers)
  - [Credentials and source encryption](#credentials)
- [Snapshot contract](#snapshots)
- [Runtime contract](#runtime)
  - [Startup and preflight](#startup)
  - [LDAP access](#access)
  - [Expiry and revision state](#expiry)
  - [Container and transport](#container)
- [Trust and operations](#operations)
- [Verification](#verification)

## Scope<a id="scope"></a>

One definition produces one signed, expiring directory snapshot. One runtime
instance serves one directory; replicas MAY consume the same snapshot.

The directory is read-only to ordinary LDAP clients. It has no replication,
online provisioning, password-change service or application-session management.
An optional recovery administrator bypasses ACLs; its changes are disposable.

## Components and data flow<a id="components"></a>

```text
Static directory definition
  |-- Users/groups YAML with credential sources
  |-- OR entry LDIF with snapshot settings and optional schemas
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
  workflow, including password hashing, Vault-key generation and snapshot signing.
  Admin operations MUST NOT require the runtime image.
- Schema definitions and readable-attribute policy MUST remain distinct from
  directory entries. They are explicit, signed snapshot inputs.

An administrator or configuration-management system MAY generate and deploy
application-specific definitions and snapshots. Configuration management is not
a required component. Deployment can be local or remote.

## Directory definitions<a id="definitions"></a>

The [directory schema](schema/directory-v1.schema.json) describes format 1.
A definition MUST select exactly one `input_type`: `users-groups` or `ldif`.
Both routes share `directory_id`, `base_dn`, revision and expiry settings.

Native LDIF is the general-purpose route for directory data. Administrators
define DNs, object classes, attributes and stable entry identifiers explicitly.
Users/groups YAML is a convenience model for application authentication,
identities and group memberships. It generates a fixed layout containing users,
groups and application bind accounts, with a limited set of configurable fields.

Both routes produce the same signed snapshot format and use the same runtime.
Native LDIF permits different directory structures; it does not bypass the
snapshot lifecycle, access policy or server-configuration restrictions.

YAML MUST use one top-level mapping with string keys. Duplicate keys, aliases,
unknown fields and unsupported tags MUST be rejected. Decrypted strings are
validated as values; they MUST NOT be reparsed as YAML or evaluated as templates.
Schema validation describes the document after decryption.

### General directory: native LDIF<a id="native-ldif"></a>

- `ldif_files` MUST contain desired-state entry records, including the base and
  every parent entry. Change records, controls, includes and URL-valued
  attributes MUST be rejected.
- Entries MUST be under `base_dn` and MUST NOT target `cn=config` or contain
  server-configuration attributes.
- Entries MAY use other layouts, object classes, binary attributes and
  multivalued attributes. Core, cosine, inetOrgPerson, NIS and the bundled
  `application-user` schemas are loaded. The latter defines `proxyAddresses`
  and the `openldapDeclarativeUser` auxiliary class for either input route.
- Optional `schema_files` MUST contain only direct children of
  `cn=schema,cn=config`, using `olcSchemaConfig` and the attributes `cn`,
  `objectClass`, `olcAttributeTypes` and `olcObjectClasses`. They MUST NOT
  change modules, ACLs, databases or other server configuration.
- `read_attributes` MUST explicitly name the attributes readable by
  authenticated clients. Wildcards and password attributes MUST be rejected.
- Native entries MUST supply their own memberships. The generator MUST NOT
  infer a users/groups layout or synthesize `memberOf`.
- The generator MUST validate record structure, scope, identities and password
  verifiers. OpenLDAP's offline import and configuration checks are the
  authority for schema validity; deployments MUST preflight before activation.

Relative LDIF and schema paths resolve against the definition file's directory.
The generator combines and orders data entries into one LDIF. It retains schema
file order for dependencies. Input files MUST be regular files, not symlinks.

### Application directory: users/groups YAML<a id="users-groups"></a>

- Every active user MUST appear in the snapshot, regardless of group membership.
  Inactive users MUST be omitted.
- Group members MUST reference existing user IDs. Groups with no active members
  MUST be omitted because `groupOfNames` requires a member.
- The generator MUST emit reciprocal `member` and `memberOf` values.
- Users MUST be `inetOrgPerson` entries at
  `uid=<uid>,ou=people,<base_dn>`. Their `common_name` is the LDAP `cn`
  attribute, not their naming RDN.
- Groups MUST be `groupOfNames` entries at
  `cn=<common_name>,ou=groups,<base_dn>`.
- `bind_accounts` MUST be a non-empty list. Each account MUST be an
  `organizationalRole` with `simpleSecurityObject` at
  `cn=<common_name>,ou=services,<base_dn>`.
  Account IDs and case-insensitive common names MUST be unique within the list.
  Accounts have independent credentials and identities but share the read policy.
- The base entry MUST use `dcObject` and `organization`; this route therefore
  requires an ASCII base DN beginning with a single `dc` RDN.
- A default group is not required. Group names such as `ALLOW` and `DENY`
  have no special meaning to the generator or runtime.

Optional user profile fields MUST map as follows. They are strings; omission
means no attribute value. Empty strings and NUL/newline characters are rejected.

| YAML field | LDAP attribute |
| ---------- | -------------- |
| `given_name` | `givenName` |
| `initials` | `initials` |
| `display_name` | `displayName` |
| `description` | `description` |
| `office` | `physicalDeliveryOfficeName` |
| `telephone_number` | `telephoneNumber` |
| `mail` | `mail` |
| `department` | `ou` (metadata, not directory placement) |
| `job_title` | `title` |

`proxy_addresses` MAY contain up to 64 `TYPE:address` strings of at most 1123
characters. The generator MUST preserve them as multivalued `proxyAddresses`,
reject case-insensitive duplicates and add `openldapDeclarativeUser` when the
list is non-empty. It MUST NOT infer a primary address or configure mail delivery.
All supplied profile fields are included in the default readable-attribute list;
an explicit `read_attributes` list replaces those defaults.

### Stable identifiers<a id="identifiers"></a>

`directory_id` identifies the deployment target. It MUST match the runtime's
`LDAP_EXPECTED_DIRECTORY_ID`; it is independent of LDAP DNs.

In users/groups YAML, `id` is a permanent source-record key, not a YAML anchor
or a separate LDAP attribute. The generator MUST derive lowercase UUIDv5
`entryUUID` values from `uuid_namespace` and these fixed names:

| Entry | UUIDv5 name |
| ----- | ----------- |
| User | `"user:" + id` |
| Group | `"group:" + id` |
| Bind account | `"bind:" + id` |
| Base | `"directory:" + directory_id` |
| Container OU | `"container:" + directory_id + ":" + ou` |

The namespace MUST be an RFC-variant UUID of version 1 through 5. Administrators
MUST preserve source IDs and the namespace across renames and rebuilds.
Changing a user's `uid` changes its DN but MUST NOT change its `entryUUID`.
IDs MAY themselves be UUID strings; they remain inputs to the calculation.

Native LDIF MUST explicitly supply one unique, canonical lowercase RFC-variant
UUID (version 1 through 8) per entry. The generator MUST preserve it and MUST
NOT derive identity from a mutable DN. Native snapshots have no UUID namespace.

### Credentials and source encryption<a id="credentials"></a>

Every active simplified user and each bind account MUST have exactly one source:

| Field | Meaning after optional Vault decryption |
| ----- | --------------------------------------- |
| `password` | Original password to hash |
| `password_file` | Absolute path to an original-password file |
| `password_hash` | Complete verifier to preserve |
| `password_hash_file` | Absolute path to a verifier file |

Credential files MUST be owner-only regular files, containing one non-empty
UTF-8 line, at most 4096 bytes, with an optional LF or CRLF terminator.
Unencrypted inline credentials require owner-only YAML permissions.

The generator MUST hash original passwords with salted Argon2id version 19:
19,456 KiB memory, two iterations, one lane, a 16-byte salt and a 32-byte digest.
Both input routes and the runtime MUST reject `userPassword` values that are
not valid `{ARGON2}` Argon2id verifiers. Seeded verifiers MUST meet those minimum
memory, iteration, salt and digest sizes and use canonical unpadded base64.
Parameter bounds MUST also fit the Argon2 implementation.

The generator's `openldap-password` command MUST use the same hashing parameters.
It MUST read one non-empty UTF-8 password from stdin, at most 4096 bytes with an
optional LF or CRLF terminator, and output only its verifier on success. Invalid
input MUST fail without echoing the supplied value. Password arguments and
terminal input MUST be rejected.

YAML string values MAY use labeled Ansible Vault scalars:
`!vault` with the standard `$ANSIBLE_VAULT;1.2;AES256;KEYID` header.

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
- Errors MUST NOT echo passwords, decrypted credential values or Vault keys.

## Snapshot contract<a id="snapshots"></a>

The [manifest schema](schema/snapshot-manifest-v1.schema.json) defines format 1.
A snapshot MUST contain `manifest.json`, its detached minisign signature and
only the listed LDIF files. Each file record declares its `data` or `schema`
kind and SHA-256 digest.

The signed manifest MUST cover directory identity, base DN, revision, input
type, read-attribute policy, namespace and timestamps. The runtime MUST reject
unknown fields, duplicate paths, invalid file kinds, unsafe paths, mismatched
digests and unlisted LDIF files. Signatures MUST be verified before interpreting
manifest-controlled data.

The generator MUST publish into a new output directory, with directory mode
`0700` and file mode `0600`. Limits: 32 files, 16 MiB combined LDIF,
1 MiB manifest and 16 KiB signature.

## Runtime contract<a id="runtime"></a>

### Startup and preflight<a id="startup"></a>

Before opening listeners, startup MUST:

1. Verify the signature, target identity, file list, digests and timestamps.
2. Reject rollback or a reused revision with different manifest content.
3. Validate entry LDIF and schema-only inputs.
4. Rebuild configuration and MDB from verified private copies.
5. Run offline OpenLDAP schema/configuration validation, import, indexing and
   readback validation. Users/groups snapshots also require reciprocal membership.
6. Recheck expiry, then start LDAP and record the accepted revision and digest.

Preflight MUST perform equivalent offline checks without opening a listener,
modifying existing revision state or changing the running directory. Startup
MUST repeat verification after deployment. Failed validation MUST prevent serving.

The database MUST be rebuilt on every startup. Persistent revision state is
separate from disposable configuration, sockets and MDB files.

### LDAP access<a id="access"></a>

Ordinary accounts MUST NOT write directory entries, read password hashes or
access `cn=config`. Anonymous directory searches MUST be denied. Authenticated
accounts MAY read the signed attribute allowlist throughout the directory;
`entry` and `children` access are included for traversal.

`LDAP_SEARCH_SIZE_LIMIT` and `LDAP_SEARCH_TIME_LIMIT` MUST configure the global
search result and duration limits, defaulting to 500 results and 10 seconds.
Each accepts integers from 1 through 2,147,483,647 or `unlimited`. Empty values,
other spellings and invalid numbers MUST fail startup and preflight with exit
code 64. These are operator-controlled runtime settings, not signed directory
data; preflight SHOULD use the same settings as the target runtime. Size limits
apply to the total search result, including paged searches, not directory capacity.

Users/groups snapshots default to identity and membership attributes. Native
snapshots require an explicit allowlist. Password ACLs MUST precede this list.
The local peer-credential identity MAY read through LDAPI for health checks.

No recovery administrator is configured by default. If explicitly enabled,
`cn=admin,<base_dn>` bypasses ACLs and MAY write or read verifiers. It MUST NOT
be used by applications. Its modifications disappear on rebuild.

### Expiry and revision state<a id="expiry"></a>

- Revisions MUST be integers from 1 through 9,007,199,254,740,991 and MUST increase
  for each newly generated snapshot, including unchanged-data renewals.
- Exact artifact replay MAY restart a directory but MUST NOT extend its lifetime.
- Generation time MUST NOT be more than five minutes ahead of the runtime clock.
- Soft expiry warns; hard expiry MUST stop LDAP with exit code 78.
- `soft_ttl_seconds` MUST be less than `hard_ttl_seconds`.
  `expiry_offset_seconds` subtracts from both deadlines and MUST be in
  0..86,400 and less than the soft TTL.
- The runtime supervisor MUST check expiry while running. The provided host
  backstop independently checks the active snapshot and can stop a suspended
  or unhealthy container.
- Operators MUST preserve revision state and reliable host time. Deleting state
  weakens rollback protection.

Expiry bounds LDAP availability, not existing application sessions or caches.
Consumers need their own revocation and session policies.

### Container and transport<a id="container"></a>

The runtime MUST support UID/GID 1001, a read-only root filesystem, dropped
capabilities and no-new-privileges. Only the runtime directory and revision state
need writable mounts. No source or deployment secrets belong in image layers.

LDAP defaults to loopback port 1389; optional LDAPS uses port 1636. Ports MUST
be unprivileged and distinct when both transports are enabled. LDAPS MUST use
TLS 1.2 or newer. Clients MUST validate certificates and names. Plain LDAP
SHOULD be restricted to a trusted host-local connection or isolated network.

## Trust and operations<a id="operations"></a>

Snapshot signatures provide authenticity and integrity, not encryption.
Vault protects source values at rest; the generated snapshot still contains
password verifiers. Native LDAP attributes can contain other secrets.

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
material, signing keys, deployment settings and accepted revision state.
Restores MUST use a current signed snapshot and verify identity and authentication.

## Verification<a id="verification"></a>

Tests MUST cover both source routes through generation and real LDAP use,
including Vault success/failure, credential forms, custom schema boundaries,
stable identities, read policy, write rejection, signatures, expiry and replay.
A successful image build alone is insufficient.

Repository checks and rootless integration tests are documented in
[DEVELOPMENT.md](DEVELOPMENT.md). Runtime and generator releases MUST be tested
together on each declared platform. Booted-host lifecycle checks require a
systemd-capable test environment.
