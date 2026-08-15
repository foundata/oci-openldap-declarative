# Decentralized directory services for application authentication

Status: implemented baseline; operational qualification pending

This document describes a directory architecture for internal applications. It
also records the assumptions that make the design defensible, the risks it does
not remove, and the alternatives considered. The repository now implements the
runtime and snapshot generator described here. Appendix A separates that tested
baseline from the deployment and operational work that still has to happen
before a production rollout.

## Summary

Authentication data is generated centrally from declarative YAML, packaged as
a signed, expiring snapshot per service, and deployed next to each application
as a small read-only OpenLDAP container. Applications authenticate locally. No
VM needs a VPN or a network path to a central directory at runtime. The
company operates no central identity provider today, so this design replaces
per-application manual user management, not an existing central directory.

Two costs dominate the risk discussion: every authorized user's password
verifier is copied to every VM running a service that user may access, and
removing a user takes effect within the snapshot lifetime rather than
immediately. Strong hashing, per-service passwords for exposed hosts, short
lifetimes and signed snapshots reduce these costs. Sections 5 and 6 describe
what remains.

The design should be reconsidered in favor of a central directory or identity
provider if immediate revocation becomes mandatory, if the number of services
grows well past the expectation in section 14, or if most applications move to
OpenID Connect (section 12.7).

## 1. Problem and intent

The company runs internal applications such as email, calendar and ticketing on
virtual machines. Applications normally run in containers, and a VM can be
dedicated to a service when the isolation is useful. Some of these VMs are
rented from external hosting providers and reachable from the internet. The
company operates no central identity provider today.

A conventional directory design places one LDAP service at the center of the
network. Every application queries it for users, groups and password checks.
That is simple, but every application host then needs a network path to the
directory. For a VM at an external hosting provider, that means either a VPN
back to the company or an internet-exposed directory endpoint, and that path
must stay up for logins to work. The central directory is also a shared
dependency and a large failure domain. An unavailable central directory can
prevent logins to otherwise healthy applications. A badly scoped application
bind account can expose more directory data than that application needs.

This design treats authentication data as a deployable artifact instead of a
remote service. A central, declarative data model remains the administrative
source of users and groups, but authentication happens against a small
directory instance next to each application. Each instance contains only the
users and groups relevant to that service. After deployment, the service
authenticates its users without any runtime network path back to the company;
only the deployment push needs one, and only while it runs.

The intended properties, roughly in order of importance:

* An application VM needs no VPN, tunnel or exposed central endpoint to
  authenticate users. An internet-facing VM whose service has two users
  carries exactly those two accounts and nothing else.
* A service sees only the directory records it needs.
* A failure or compromise is contained to one application VM as far as practical.
* Directory state can be reviewed, generated and reproduced from source data.
* Legacy LDAP applications get a standard protocol without acquiring a central
  runtime dependency.
* As a secondary benefit, authentication continues during short outages of the
  deployment system.

The design trades immediate consistency for those properties. Revocation is
bounded by a configured snapshot lifetime, not instantaneous. That limitation is
part of the security model and must not be hidden behind operational language.

## 2. Scope and non-goals

The local directory is an authentication adapter for one service. It is not the
company's general-purpose identity management system.

The design does not provide:

* interactive LDAP administration on application hosts;
* writable or persistent directory data on those hosts;
* LDAP replication between sidecars;
* a user self-service portal;
* immediate global session termination;
* OAuth 2.0, OpenID Connect or SCIM through OpenLDAP itself;
* protection after an attacker gains control of the application VM;
* a substitute for application authorization checks.

Applications may cache users, groups or sessions. Stopping LDAP does not
necessarily terminate an application session. Offboarding tests must therefore
cover the application as well as the directory container.

## 3. Security assumptions

The architecture is reasonable only under the following assumptions.

1. The application VM is a meaningful security boundary. A host compromise is
   treated as compromise of the application, local directory and credentials on
   that VM.
2. An application container compromise is not automatically treated as a host
   compromise. Container separation, SELinux and dropped capabilities should
   prevent the application process from reading the directory database or input
   snapshot directly.
3. The central source repository, generation pipeline, signing credentials and
   Ansible control environment receive stronger protection than an application
   host. Compromise of this control plane can affect every service.
4. The organization accepts a documented maximum delay for login revocation.
   Services that require immediate revocation must use a different design or an
   additional online control.
5. Host time is trustworthy enough to enforce snapshot expiry. Clock failures
   are monitored. A malicious host administrator is already inside the assumed
   host-compromise boundary.

If one of these assumptions does not hold, a central identity service with
online policy evaluation may be a better fit.

## 4. Architecture

The design has a central control plane and many local authentication planes.

```text
                    Central control plane

  User and group YAML       Credential material
           |                         |
           +------------+------------+
                        |
                validation and generation
                        |
             service-specific signed snapshots
                        |
                      Ansible
        +---------------+----------------+
        |               |                |
        v               v                v
   Service VM A     Service VM B     Service VM C
   application      application      application
       |                |                |
   local LDAP       local LDAP       local LDAP
   users for A      users for B      users for C
```

The central system decides who exists and which services that person may use.
It produces one snapshot per service. The local container verifies and imports
that snapshot before it starts listening.

The local MDB database is disposable. Restarting the container recreates it from
the same input. Backing up local MDB files would add little value and could give
operators false confidence. Recovery means redeploying a valid snapshot and
starting a known image.

### 4.1 Authoritative data

The central YAML model contains identity metadata, group membership and service
authorization. Every user receives an immutable source identifier when created.
Usernames, email addresses and DNs can change; the source identifier cannot.

Credential material should be stored separately from ordinary identity metadata,
using the organization's secret storage and access controls. A generated snapshot
joins the two sources for the users authorized for that service. Password hashes
are sensitive credentials even though they are not plaintext passwords.

The source model should distinguish at least:

* active and disabled accounts;
* immutable identity ID;
* current username and display attributes;
* service authorization;
* service-specific administrative groups;
* credential revision;
* account expiry, where applicable.

A disabled user should normally be absent from every generated service snapshot.
Keeping a disabled entry in LDAP is safe only if all bind and search paths enforce
the disabled state. Removing the entry is simpler and easier to test.

The generator must use an LDAP-aware library for DN construction, filter escaping
and LDIF serialization. User-controlled values must not be inserted into LDIF or
LDAP filters through raw string templates. Applications have the same obligation
when they build LDAP search filters.

The generator must also materialize group membership on both sides of the
relation. The memberof overlay maintains `memberOf` only for write operations
through a running server; an offline `slapadd` import does not execute it. A
spike on Debian 13 with OpenLDAP 2.6.10 confirmed this, and confirmed that
explicitly generated `memberOf` attributes import correctly offline and that
loading the module makes the attribute schema available without configuring
the overlay. The generator therefore emits `member` and `memberOf` as plain,
mutually consistent attributes, and the runtime needs neither the memberof nor
the refint overlay.

### 4.2 Service-specific snapshots

A snapshot is more than a directory full of LDIF files. It should contain a
signed manifest with enough information to reject stale, incomplete or misplaced
input. A suitable manifest contains:

```yaml
format_version: 1
service_id: zammad-production
base_dn: dc=zammad,dc=services,dc=example,dc=org
revision: 1842
generated_at: 2026-08-03T12:00:00Z
expires_at: 2026-08-04T00:00:00Z
uuid_namespace: 7f38d690-...
files:
  00-config.ldif: sha256:...
  10-directory.ldif: sha256:...
```

The signature covers the manifest and, through the recorded digests, every input
file. The service ID prevents a valid snapshot for one application from being
accepted by another. The format version permits controlled schema evolution.

A simple detached-signature scheme is sufficient for this trust model of one
publisher and many verifiers. A spike prototyped the bundle with minisign and a
public verification key mounted independently from the image. The verifier correctly rejected
a modified manifest, a wrong public key, a modified LDIF under an unchanged
signed manifest, and a validly signed but expired manifest. Minisign itself
adds about 50 KiB to the image plus about 431 KiB for libsodium. A full X.509
PKI would add certificate expiry and revocation machinery without improving
this trust model. Minisign covers only the snapshot artifacts; container images
are signed and verified with Cosign as the container image build guide
requires. The two mechanisms serve different artifact classes and different
verifiers, not the same purpose twice.

The runtime accepts either one public key file or a directory of public keys.
That permits an overlap during rotation: install both verifiers, move generation
to the new signing key, confirm a new revision on every service, then remove the
old verifier.

The revision should increase monotonically. A host records the highest accepted
revision outside the disposable LDAP database and rejects an older revision
unless an operator invokes a documented recovery procedure. Expiry alone does
not prevent replay of an older snapshot that is still within its validity period.
This revision record is deliberately persistent host state, unlike the
disposable database. Its location, ownership and behavior across VM restores
belong to the deployment design. It is a best-effort control; the short
snapshot lifetime remains the primary protection against replay.

The deployment process writes a new snapshot to a staging location, verifies it,
and then switches it into place atomically. It never edits the active snapshot
file by file.

The verifier should be a small fail-fast program with tested, distinct exit
codes. The spike's shell prototype showed how easily `set +e` around a helper
function can mask a failed digest comparison. The test suite must prove that
every tampering case actually causes a failure, not merely that the happy path
succeeds.

### 4.3 Snapshot delivery and image separation

The OpenLDAP image and the service snapshot are separate artifacts. The image
contains the server, schemas and initialization logic. It contains no employees,
password hashes or application credentials.

Baking a service snapshot into an OCI image would make deployment superficially
simple, but it would copy password hashes into registry storage, build caches and
immutable image layers. Registry readers might then gain access to credentials
for services they do not operate. Removing a compromised hash from every retained
layer is also difficult.

Ansible should deliver the encrypted snapshot directly to the target VM with
restricted ownership. A tightly scoped preparation step makes the verified
plaintext available in a protected runtime location. The container receives it
as a read-only input and repeats the signature and digest checks before import.
The decryption key is not stored in the image or snapshot.
The generic image digest and service snapshot revision can then change
independently. A base image security update does not require regenerating
directory data, and a user change does not require rebuilding the server image.

### 4.4 Stable identifiers

Changing `entryUUID` values on every rebuild breaks application references and
makes later consolidation difficult. The generator must supply deterministic
UUIDs in the LDIF.

UUIDv5 is suitable for this purpose:

```text
entryUUID = UUIDv5(company_directory_namespace, immutable_source_id)
```

The namespace is fixed and backed up. The input is the immutable source ID, not
the username, DN, email address or employee number if that number can ever be
reused. The same person receives the same UUID in every service snapshot.

A spike on Debian 13 with OpenLDAP 2.6.10 verified that `slapadd` preserves
explicitly supplied version-5 `entryUUID` values, and that importing without
explicit UUIDs produces different values on every rebuild. Integration tests
must repeat this proof for every supported OpenLDAP package version: rebuild
two independent databases from the same snapshot and compare all UUIDs.

Stable global IDs make a later migration to a central LDAP service possible
without changing the identifier seen by applications. They also permit
correlation of a user across two compromised snapshots. This is accepted because
the UUID is an identifier, not a secret, and migration safety is more useful here.

### 4.5 Local directory startup

Startup must be transactional from the application's point of view:

1. Verify the snapshot signature, service ID, revision, file digests and expiry.
2. Create fresh configuration and database directories.
3. Build the `cn=config` database offline; fall back to an LDAPI-only
   initialization listener only where offline tools do not suffice.
4. Import all directory entries offline.
5. Run `slaptest` and semantic checks against the completed database.
6. Start slapd under the expiry watchdog (section 4.6) only after every check
   succeeds.

No TCP listener should accept application traffic during import. A malformed
file, failed ACL update or missing base entry must cause a non-zero container
exit. Continuing with a partial directory is worse than an outage because it
produces service-dependent and difficult-to-explain authentication results.

The initialization process should not require a network root DN password.
Configuration can use LDAPI with SASL EXTERNAL, and data can be loaded offline.
If a root DN is retained for recovery, its secret belongs in a Podman or systemd
credential file, not an environment variable or command line.

### 4.6 Freshness and the deadman switch

The local service checks `expires_at` before startup and while running. It refuses
to start an expired snapshot and shuts down when the active snapshot expires.
An external health check reports both the running state and the snapshot revision.

Runtime expiry needs an enforcing process, because slapd has no concept of it.
The container therefore runs a minimal watchdog as its final process. The
watchdog starts slapd, forwards signals to it and stops it with a distinct
exit code when the snapshot expires. A spike validated this arrangement:
snapshot expiry stopped slapd cleanly with exit code 78, a normal
`podman stop` completed in 0.08 seconds with exit code 0, and slapd logged an
orderly shutdown in both cases. The watchdog also fixes an existing defect,
because the proof-of-concept entrypoint does not forward SIGTERM and Podman
ends up killing the container with SIGKILL after its timeout.

The host provides an independent backstop. Ansible already manages the VMs, so
it can install a systemd timer that verifies the signed host-side snapshot,
including its expiry, and stops the container when verification fails, even if
the watchdog fails. Podman's health-on-failure action combined with an
expiry-aware health check is a second host-managed backstop. The deployment
uses the `kill` action rather than `stop`: a container that fails its health
check may be unable to process SIGTERM, SIGKILL guarantees termination, and the
clean shutdown path belongs to the watchdog. Two simple mechanisms that both
fail toward shutdown are preferable to one elaborate one.

This converts unbounded staleness into a known risk window. If the maximum
snapshot lifetime is 12 hours, an account removed immediately after generation
may still authenticate on a host for almost 12 hours. Deployment should normally
reduce that delay to minutes, but the security guarantee remains 12 hours.

The expiry belongs to the snapshot, not the container image or container creation
time. Recreating a container around old data must not reset the freshness timer.

Reachability of the Ansible or Semaphore server is not a good shutdown signal on
its own. A control-server restart or network fault could otherwise stop every
directory at once. Signed snapshot expiry expresses the actual security property:
how old the authorization data is. Control-plane reachability is still useful as
an alert.

An emergency override may be necessary during a prolonged control-plane failure.
It should require an explicit, local action, have its own short expiry and produce
an audit event. A permanent `IGNORE_EXPIRY=true` setting would defeat the design.

### 4.7 Correlated expiry across the fleet

Expiry brings the central failure mode back in a delayed form. If every
snapshot carries the same lifetime, a control-plane outage longer than that
lifetime stops every directory at nearly the same moment. The central failure
domain is not removed; it is time-shifted. With a 12 hour lifetime, a failure
that begins on Friday evening stops authentication for the whole fleet before
anyone returns on Monday.

Three measures keep such a failure gradual instead of simultaneous:

1. Stagger the generated `expires_at` values across services. A fleet whose
   deadlines are spread over several hours degrades service by service and
   leaves operators a working window.
2. Give each snapshot two deadlines. A soft deadline marks when a fresh
   snapshot should have arrived and only raises an alert. The hard deadline
   stops the service. The gap between them buys monitored reaction time
   without weakening the guarantee, because the hard deadline still bounds
   staleness.
3. Choose lifetimes per service. The revocation objective and outage tolerance
   of an internal ticketing system and of an internet-facing two-user service
   are different decisions, and one fleet-wide number serves neither well.

The emergency override in section 4.6 remains the last resort when an outage
outlives even the staggered hard deadlines.

### 4.8 Application connection

The preferred arrangement is a Podman pod or an equally private network shared
only by the application and its directory. LDAP is not published on a VM network
interface. The application uses `127.0.0.1` when both containers share a network
namespace, or a private container address otherwise.

Listener addresses and port publication must be explicit in the deployment
definition. slapd's default listener binds every interface, so with the default
in place a single careless `--publish` is enough to expose the directory. The
image should pin the listener addresses rather than rely on deployment
discipline alone.

Plain LDAP can be accepted for this connection when all of these conditions hold:

* the listener is unavailable outside the host-local boundary;
* no unrelated container joins the network;
* both containers drop packet-capture and raw-network capabilities;
* the deployment fixes the endpoint to the intended local service;
* host compromise is already considered total compromise of the service;
* no infrastructure component silently routes the traffic outside the host.

TLS remains available for applications or deployments that cannot satisfy those
conditions. The choice is per deployment, not a claim that plaintext LDAP is
generally safe.

When TLS is enabled, clients validate the certificate against a private or public
CA and verify the expected service name. Production configurations must not use
`insecureSkipVerify` or an equivalent option. Certificate issuance, renewal and
expiry monitoring belong in the Ansible deployment. A private local CA is useful
only if its trust material and signing key are handled separately.

Debian 13's slapd links against OpenSSL 3, not GnuTLS as earlier drafts
assumed. A spike confirmed the repository's TLS configuration on that stack:
TLS 1.3 and 1.2 connections succeeded, TLS 1.1 was rejected, validation
succeeded against the configured CA and failed against an unrelated one, and
the multiline cipher-suite LDIF was stored correctly.

Dex is a special case. Its LDAP connector sends the user's plaintext password to
LDAP and warns that support for unencrypted LDAP may be removed. A Dex companion
should therefore use StartTLS or LDAPS, even on the local container network.

### 4.9 Configuration and secret input contract

The signed snapshot is authoritative for directory identity and contents. Its
manifest defines the service ID, base DN, revision, validity period and file
digests. The deployment supplies the expected service ID independently so that a
valid snapshot cannot be moved to another service. Runtime settings may select
listener and logging behavior, but they must not silently redefine fields covered
by the signed manifest.

The former proof of concept derived the base DN from `LDAP_DOMAIN`. That
interface is deprecated. During migration, a supplied `LDAP_DOMAIN` or `LDAP_BASE_DN` must
match the signed manifest. A contradiction is an error; the container must not
choose one source and ignore the other. The production interface should remove
these duplicate inputs once existing deployments have moved to snapshots.

Secrets use the familiar `<NAME>_FILE` convention. If a recovery root password
is retained, for example, the preferred input is `LDAP_ADMIN_PASSWORD_FILE` and
the file is mounted through Podman or systemd credentials. Direct secret values
in environment variables are a temporary compatibility interface and should
produce a deprecation warning. Setting both forms is an error rather than a
precedence rule because accepting ambiguous credential sources makes deployment
mistakes difficult to detect. Secret values must not appear in process arguments,
logs, health output or generated metadata.

Validation has two parts. The configuration phase collects independent input
errors and reports them together, so an operator can fix a deployment in one
pass. Once signature verification or database construction begins, each failed
security check stops processing immediately. Distinct exit codes separate usage
errors, invalid configuration, rejected snapshots, failed imports and expiry.

Unsafe behavior must never be the default. The production image should not offer
a permanent switch that accepts unsigned snapshots, empty passwords or ignored
expiry. Tests can use signed fixtures. If an exceptional bypass is ever required,
it needs a narrowly named unsafe option, a conspicuous log and health state, and
an independent deadline. The emergency expiry override in section 4.6 is a
separate audited host artifact, not an environment variable that can remain set
by accident.

## 5. Passwords and credential exposure

Every authorized service snapshot contains a password verifier for each included
user. An attacker who obtains the snapshot or MDB database can attempt offline
password cracking. A conventional central LDAP design does not normally place
those hashes on every application VM.

This is the largest confidentiality cost of the design. Strong password hashing
reduces the value of a stolen verifier but does not make it harmless.

The hash scheme controls the attacker's guessing speed, and the difference is
large. Argon2id is memory hard: every guess costs the configured memory and
computation, which keeps GPU-based attacks in the range of hundreds to a few
thousand guesses per second instead of the billions per second possible
against legacy schemes such as `{SSHA}`. At those speeds the outcome depends
almost entirely on password quality. A password found in a public breach list
still falls within hours; a generated passphrase or long random password stays
out of reach for any realistic attacker. Because local password changes are
disabled anyway, the central enrollment workflow can and must enforce that
quality: generate passwords or screen chosen ones against breached-password
lists. For internet-facing deployments this is a precondition, not a
recommendation.

The implementation should:

* use Argon2id through the Argon2 module shipped in Debian's `slapd` package;
* use a unique random salt for every password hash;
* benchmark parameters on the smallest target VM;
* choose enough memory and iterations to make offline guessing expensive;
* limit concurrent binds so expensive verification cannot exhaust the VM;
* prevent LDAP searches from returning `userPassword` to any account;
* keep the generated database on tmpfs where operationally practical;
* store snapshot files with an account and SELinux label unavailable to the
  application container;
* encrypt snapshot artifacts in transit and at rest outside the container;
* remove temporary decrypted files after successful import when restart and
  recovery requirements permit it.

Argon2 parameters need measurement. A spike benchmarked Debian 13's Argon2
module on one host: the packaged default (`m=7168,t=5,p=1`) verified a
password in about 42 ms using about 7 MiB, `m=19456,t=2,p=1` took 50 to 61 ms
at about 19 MiB, and `m=65536,t=3,p=1` took about 256 ms at about 64 MiB.
Eight simultaneous verifications at `m=19456` raised slapd from about 11 MiB
to 167 MiB RSS before it returned to baseline. Memory cost multiplies by
concurrency, so the bind concurrency limit is part of the security parameter
set: a setting that protects well against offline attacks can otherwise let an
attacker exhaust a small VM with parallel login attempts. `m=19456,t=2,p=1` is
a reasonable initial value for memory-constrained VMs, benchmarked again on
the target VM class before rollout.

The application must never receive a bind account that can read password hashes.
Its account should have only the searches and attributes required by that
application. Administrative binds and application searches use separate
credentials.

Password length, breached-password checks and credential enrollment belong in
the central workflow because local password changes are disabled. Permanent LDAP
lockouts are risky in a distributed read-only directory: an attacker could lock
an account independently on every service, and lock state would disappear on
restart. Rate limits and short temporary delays are safer starting points.

Service-specific hashes of one shared password are not worth building. The
password itself is shared, so cracking any one service's verifier yields the
credential for every service, and different salts per service change nothing
about that. The improvement that does work is a different password per
service. For internet-facing VMs this is the recommended pattern: issue each
user a separate generated credential for that service, so even a fully cracked
verifier from a stolen snapshot is valid nowhere else. At the intended scale
of a few users per exposed service, the enrollment overhead is small. Internal
services may continue to share one strong verifier per user, with the
resulting correlation and breach risk documented.

## 6. Revocation and update behavior

### 6.1 Employee offboarding

Offboarding changes the central account state to disabled. The generator excludes
the user from every snapshot, Ansible deploys the new revisions, and each local
directory restarts from the new data.

Several delays remain:

* A failed deployment leaves the old password usable until snapshot expiry.
* A host that is powered off may return with an old snapshot and must reject it.
* An application may retain an authenticated session after LDAP stops.
* An OIDC token remains valid until its expiry unless the application performs an
  online revocation check.

The deadman switch bounds LDAP login staleness. It does not terminate application
sessions. Each application needs a tested offboarding procedure that covers its
session store and any local user cache.

### 6.2 Password changes and compromised credentials

A password change creates a new credential revision and new snapshots for every
service the user can access. During a partial deployment, the old password may
work on some services while the new password works on others. Monitoring should
show the deployed revision per host so this state is visible.

Credential compromise should trigger an urgent deployment rather than waiting
for the ordinary schedule. The maximum guaranteed exposure still equals the old
snapshot's remaining lifetime unless the affected VMs can be reached and stopped.

### 6.3 Group and service authorization changes

Removing a user from a service excludes that user, or at minimum the relevant
group membership, from the next service snapshot. Excluding the complete user
entry gives the smallest disclosure and prevents direct binds where the
application checks only credentials and ignores groups.

Applications differ in how often they query groups. Some copy LDAP groups into a
local database. Such applications need explicit synchronization and cache-expiry
tests. The directory cannot enforce authorization after the application has
copied it.

### 6.4 Failed rebuilds and rollbacks

A new snapshot is activated only after validation succeeds. If generation,
transfer or import fails, the service keeps the previous valid snapshot until it
expires. At expiry it fails closed.

An automatic rollback can restore availability while also restoring a revoked
account. Rollbacks must therefore respect snapshot expiry and revision rules.
Operators should see the authorization risk before approving one.

## 7. OpenLDAP sidecar implementation

### 7.1 Base image

The sidecar uses Debian 13 slim, pinned by image digest from its authoritative
upstream registry as the container image build guide permits for Docker Official
Images; mirroring remains an option when availability or policy control requires
it. Debian has current OpenLDAP 2.6 packages, a long stable release
cycle and familiar package behavior. The image should receive automated digest
updates and regular rebuilds rather than remaining pinned forever.

The production image needs only `slapd`, `ldap-utils`, the required modules,
CA certificates with OpenSSL, `minisign` and `jq` for snapshot verification,
and the small set of utilities used during initialization. The Argon2 module
ships in Debian's `slapd` package itself; no contrib package is required.
Compilers, development headers, `sudo`, editors and network troubleshooting
tools belong in a separate debug image or an integration-test environment.

A spike measured the difference. The former proof-of-concept image was 436 MB
uncompressed (164 MB compressed). The implemented runtime is 145.1 MB after
retaining package copyright notices and an exact package inventory; the initial
minimal-package spike measured 144 MB (51 MB compressed). The Debian 13 slim
base alone is 81 MB. Slimming beyond this would save little compared with the
simplicity of a plain Debian package installation.

Every release should record its package manifest and SBOM, run vulnerability and
integration scans, push the candidate by immutable digest to the controlled
registry, and sign and verify that registry digest before promotion or deployment.
The candidate is not a release while it remains unsigned or unverified. Automated
update proposals keep the base digest and Debian security packages moving through
the same tests. Releases currently target `linux/amd64` only; adding `linux/arm64`
is tracked as later work under the build guide's platform expectations.

Alpine was considered for a smaller filesystem. Its musl environment and
different OpenLDAP module packaging would add another compatibility surface for
limited memory savings. Fedora's shorter release cadence creates more image
upgrade work without improving SELinux behavior on the host. Ubuntu LTS is
reasonable but provides no clear advantage over Debian for this image. UBI does
not provide a comparably direct first-party `slapd` package path.

### 7.2 Container controls

The production container should run with:

* a fixed non-root UID and GID;
* root-owned, non-writable executable scripts, with runtime ownership limited to
  explicitly mutable paths;
* all Linux capabilities dropped;
* `no-new-privileges`;
* a read-only root filesystem;
* tmpfs for `/var/lib/ldap`, generated `slapd.d` data and `/run`;
* read-only snapshot and certificate inputs;
* SELinux labels appropriate for private container data;
* memory, PID and CPU limits, and an explicit `nofile` limit;
* explicit listener addresses instead of slapd's every-interface default;
* no host port publication by default;
* a minimal watchdog as the final process, which starts slapd, forwards
  signals and enforces snapshot expiry (section 4.6);
* a health check that includes snapshot revision and expiry.

The `nofile` limit is not cosmetic. slapd sizes its connection table from the
available file descriptors, and a spike measured an otherwise idle slapd at
about 352 MiB RSS under an inherited limit of 1048576 descriptors, against
about 11 MiB at 1024, 13 MiB at 4096 and 21 MiB at 16384. For a local sidecar,
1024 suffices and 4096 provides generous headroom at little cost.

The spike ran the image successfully with all of these controls combined:
rootless, all capabilities dropped, no-new-privileges, a read-only root
filesystem, a 256 MiB memory limit, a 128 PID limit, `nofile=1024`, an
isolated network and ephemeral writable state. One caveat surfaced: the tested
Podman version rejected UID and GID options on `--tmpfs` mounts, so production
needs properly owned volumes or another controlled arrangement for writable
state rather than world-writable tmpfs workarounds.

The image should not declare OCI `VOLUME` paths. The deployment definition owns
mount types, read-only flags and SELinux relabeling.

### 7.3 LDAP policy

Anonymous access to `userPassword` is limited to the LDAP `auth` privilege needed
for password verification. Anonymous searches and attribute reads are denied, and
an empty-password unauthenticated bind grants no access. Application bind accounts
can search only their own service subtree and only approved attributes.

The server should set conservative size and time limits, indexed filters for
expected application queries, connection limits, and a maximum MDB size. Logging
should record bind results and significant searches without recording passwords
or excessive personal data.

The generator controls coarse service entitlement by deciding whether a user is
present at all. LDAP groups express roles that the application understands. The
application remains responsible for enforcing those roles, validating filter
inputs and limiting expensive searches. A directory entry or group claim is data;
it does not enforce authorization after the application has read it.

Password changes through LDAP are disabled in the local instance. The central
credential workflow owns them. Runtime writes either fail or disappear at the
next restart, so accepting them would mislead users and operators.

## 8. Optional OpenID Connect with Dex

OpenLDAP does not provide OAuth 2.0 or OpenID Connect. Dex can translate LDAP
authentication into OIDC for an application, but it adds a public endpoint and
mutable security state.

To retain the decentralized failure boundary, Dex runs as a separate companion
container on the application VM:

```text
browser -> HTTPS reverse proxy -> Dex -> StartTLS -> local OpenLDAP
                              \
                               -> OIDC application
```

Each Dex instance has its own public issuer URL, client configuration, signing
keys and storage. A forged token from one compromised VM should not be accepted
by another service because issuer and audience checks are service-specific.

Dex must not be installed in the OpenLDAP image. It has an independent release
cycle, health model and security boundary. Its upstream distroless image already
uses a static Debian 13 base and runs as a non-root user.

A local measurement of Dex 2.45.1 distroless on AMD64 found about 35 MB idle RSS,
negligible idle CPU, a 45 MB compressed image and a 155 MB unpacked image. A
128 MB memory allocation is a reasonable starting point for a low-traffic pilot,
with a higher hard limit until login-load tests establish real peaks.

Dex requires persistent storage for signing keys, refresh tokens, authorization
codes and replay prevention. Its documentation says SQLite is not appropriate
for real workloads. Local SQLite is nevertheless the only lightweight option
that preserves the per-application failure boundary. It may be accepted for a
single-instance, low-traffic deployment only after tests cover corruption,
abrupt shutdown, backup, restore, key rotation and loss of state. Losing the
database should fail closed and require users to authenticate again.

Dex refreshes identity and group information from LDAP, but it does not verify
the user's password again during a refresh. Disabled users must disappear from
LDAP or fail an active-account search filter. Issued tokens remain valid until
expiry, and application sessions may last longer. Short token lifetimes, bounded
refresh-token lifetimes and application-specific session tests are mandatory.

A central Dex instance is operationally simpler, but it changes the design. New
OIDC logins then depend on a central service, and compromise of its signing keys
affects multiple applications. Central Dex is a valid hybrid architecture, not a
continuation of the fully decentralized model.

Dex is an authentication bridge. It is not a complete workforce identity system,
SCIM provisioning service or general authorization engine. Application
compatibility must be tested rather than inferred from an "OAuth2 supported"
checkbox.

## 9. Availability and failure scenarios

| Scenario | Expected behavior | Remaining risk |
| --- | --- | --- |
| Ansible unavailable briefly | Existing valid snapshots continue to serve | Changes wait for deployment |
| Ansible unavailable past expiry | Local LDAP shuts down and refuses restart | New logins fail; existing application sessions may remain |
| Malformed LDIF | New database is rejected before TCP listening | Previous snapshot eventually expires |
| Partial file transfer | Digest verification fails | Service remains on previous revision |
| Employee disabled | New snapshots omit the user | Old snapshots allow login until replaced or expired |
| Password compromised | Urgent revision is deployed | Unreachable hosts accept the old password until expiry |
| VM restored from old backup | Expiry and revision checks reject old data | Incorrect host time or rolled-back revision metadata can interfere |
| Application container compromised | Attacker can attempt LDAP binds and query allowed attributes | Container escape or host compromise exposes local hashes |
| Local LDAP compromised | Hashes for that service are exposed | Strong hashing slows but does not prevent cracking |
| Control plane compromised | Malicious signed snapshots can reach every service | This is a fleet-wide compromise |
| Dex state lost | OIDC sessions and signing continuity are disrupted | Users must log in again; application behavior varies |
| Local resource exhaustion | Container limits contain the process | Authentication for that application becomes unavailable |

The safest default during uncertainty is denial of new authentication. The
application must also be checked for fail-open behavior, cached credentials and
local fallback accounts.

## 10. Monitoring and audit

Each service should report:

* image digest;
* active snapshot revision and generation time;
* time remaining until expiry;
* last successful deployment and import;
* container health and restart count;
* bind success and failure rates;
* search latency, size-limit events and connection-limit events;
* memory, CPU and file usage;
* Dex token and storage errors when Dex is present.

The control plane compares the expected revision with every host's reported
revision. Alerting on "deployment completed" is insufficient because a play may
succeed overall while one service remains stale.

The implemented container status command emits one JSON object with the service
ID, revision, generation time, soft and hard deadlines, remaining seconds and
LDAP availability. Its exit statuses distinguish healthy, soft-expired and
critical states. The soft-expired state remains available for authentication;
it is an alert, not a shutdown signal. The Quadlet health action and a separate
rootless systemd timer example both stop the container after a hard health
failure. Fleet collection and alert routing are not implemented here.

Git history and code review provide the audit trail for identity and authorization
changes. Secret access, snapshot signing and emergency expiry overrides need
separate audit records. LDAP logs should identify the service account and operation
without logging credentials or full result sets.

## 11. Backup and recovery

The recovery set consists of:

* authoritative user, group and service-authorization data;
* immutable source IDs and the UUID namespace;
* encrypted credential material;
* snapshot-signing keys and their recovery procedure;
* generator and deployment code;
* pinned image references and build provenance;
* Dex state for services that use Dex.

Local OpenLDAP MDB files are not part of the backup set. A restore test should
build a clean VM, deploy the image and snapshot, and confirm that users retain the
same UUIDs and application mappings.

Signing-key recovery deserves special care. Losing the key prevents new snapshots;
an undetected stolen key lets an attacker create valid ones. Key rotation needs an
overlap period in which hosts trust the old and new public keys, followed by an
explicit removal of the old key.

Dex backup policy depends on the accepted storage design. Restoring old refresh
tokens or signing state can have security consequences, so recovery should favor
forced reauthentication over restoring stale sessions.

## 12. Alternatives considered

### 12.1 Central highly available LDAP

A central LDAP cluster is easier to understand and can apply account and group
changes immediately to new binds and searches. Replication, monitoring and backup
are concentrated in one place. Proper ACLs can prevent an application from reading
unrelated users even though the complete directory exists centrally.

It also creates a network and operational dependency for every application. The
cluster needs careful HA design, and a central administrative compromise has a
large blast radius. Every application host also needs a network path to the
cluster: VMs at external hosting providers would require a VPN back to the
company or an internet-exposed directory endpoint, and that path becomes part
of both the login availability chain and the attack surface. The snapshot
design removes exactly this requirement. Note also that the comparison here is
greenfield against greenfield, because no central directory exists today; a
central cluster is not the incumbent but a system that would first have to be
built and operated. It remains the better option when immediate consistency
and low administrative overhead matter more than service-local autonomy and
network independence.

### 12.2 OpenLDAP replication or LDAP proxies

Replication can provide local reads while retaining a central writer. It brings
replication state, conflict handling, credentials and monitoring to every node.
Selective replication of a different subset for every service is possible only
with substantial configuration and testing. A proxy avoids password-hash copies
but restores the central runtime dependency and the network path that this
design removes.

Neither approach matches the simplicity of rebuilding a small read-only database
from a signed snapshot.

### 12.3 389 Directory Server

389 Directory Server has strong operational tooling, replication support and
features aimed at managed enterprise directories. It is a good candidate for a
future central directory.

It is heavier for a sidecar that imports a few static files and performs binds.
An exploratory local test of the official container used roughly 99 MB at idle,
compared with the expected tens of megabytes for a slim OpenLDAP instance. Its
features provide little benefit when replication and runtime writes are excluded.

### 12.4 FreeIPA

FreeIPA combines directory, Kerberos, certificate, host and policy management.
That integration is useful for managing Linux hosts and a company realm. It is
far beyond the needs of one application sidecar and expects central services such
as DNS and Kerberos to be designed as a whole.

FreeIPA may still be appropriate as a future authoritative identity system. It
would replace the central YAML model rather than merely replace the local LDAP
binary.

### 12.5 Keycloak and Authentik

These products provide broader identity-provider functions than Dex and are more
natural choices for a central OIDC service. They add databases, administrative
interfaces and a wider operational surface. Running one instance per application
would consume more resources and create more state than this design intends.

If the organization decides that central OIDC, MFA and interactive identity
workflows are more important than per-service isolation, one of these products
deserves a separate evaluation.

### 12.6 LLDAP and Kanidm

LLDAP is attractive for small installations and simple administration. Its LDAP
schema and compatibility surface are narrower than OpenLDAP's, so each target
application would need testing. Its interactive directory model also does not
directly provide the offline, signed-LDIF startup contract described here.

Kanidm offers a different identity model and modern authentication capabilities.
It is not a drop-in implementation of this OpenLDAP snapshot design. Adopting it
would be a broader identity-platform decision.

### 12.7 Central identity provider and directory authority

A central identity provider can read users from LDAP or become the authoritative
user directory itself. Using LDAP as its backend eases migration and keeps legacy
applications on a familiar protocol, but it leaves two systems and their schemas
to operate. Making the identity provider authoritative removes that duplication
for modern applications, while legacy LDAP access then needs a supported gateway,
sync process or separate directory.

Either model can improve centralized revocation, MFA and login auditing. It also
places new logins on a central path. This is a plausible destination if operating
many local OIDC issuers proves more expensive than their isolation is worth.

### 12.8 SCIM provisioning

SCIM provisions users into application-local stores. It can remove LDAP from the
runtime path and works well for applications with mature SCIM support. It does
not itself authenticate users, and deprovisioning still depends on successful
delivery to each application. Support and behavior vary by product.

SCIM is a useful later complement to a central OIDC provider. It is not a general
replacement for legacy LDAP applications.

### 12.9 Application-local users managed by automation

Automation could create native users in each application. This maximizes local
availability and avoids an LDAP sidecar, but every application has a different
API, password model, group model and deletion behavior. Auditing and testing grow
with every integration. It is reasonable for a small number of applications that
have reliable administration APIs and poor LDAP support.

### 12.10 Bitnami OpenLDAP image

Bitnami's historical Debian-based OpenLDAP image is a useful operational
comparison. It runs without root on ports 1389 and 1636, accepts secrets through
`*_FILE` inputs, documents input precedence, defaults its open-file limit to
1024, and supports offline bootstrap scripts. These conventions are mature and
worth adopting where they fit this design.

Its directory model does not fit. Bitnami treats `/bitnami/openldap` as persistent
state and bootstraps a mutable general-purpose directory on first use. This
project rebuilds a disposable database from a signed snapshot on every start and
must reject partial, stale or contradictory input. Bitnami's silent override
rules are therefore replaced here with explicit validation errors where two
sources claim to define the same value.

The supply-chain boundary also differs. In 2025 Bitnami moved its historical
Debian image catalog to the unsupported Legacy registry. Its current OpenLDAP
offering is a commercial Bitnami Secure Image based on Photon OS. Depending on it
would exchange the simple Debian package path for a vendor catalog whose access,
base distribution and release policy have already changed. Building from Debian's
first-party packages, recording the package set and mirroring signed image digests
keeps those decisions under company control.

## 13. Why OpenLDAP remains the current choice

OpenLDAP fits the narrow runtime function: import a known directory, answer
standards-based searches and verify passwords with low resource use.

It remains a reasonable choice under these constraints:

* the directory is read-only at runtime;
* replication and interactive administration are out of scope;
* schema use is conservative and tested against real applications;
* startup is rebuilt to be transactional and fail closed;
* the image follows Debian security updates;
* UUIDs and password schemes are controlled by the generator;
* integration tests cover every image release.

If those constraints expand to central writes, complex replication, host identity
or large-scale policy management, OpenLDAP should be compared again with 389
Directory Server, FreeIPA and a dedicated identity provider.

## 14. Operational cost

The architecture replaces one central runtime service with repeated small
instances and a stronger deployment pipeline. The cost grows roughly with the
number of services, not the number of employees.

Repeated work includes image updates, snapshot deployment, monitoring, expiry
handling, application-specific LDAP tests and incident response. Shared Ansible
roles and one immutable image keep that work manageable, but they do not remove
it. Configuration drift is controlled by rebuilding from signed inputs rather
than repairing individual instances.

The design is most attractive for a small or medium number of important services
on dedicated VMs. As a working boundary: up to roughly fifteen services and a
few hundred users, regenerating every snapshot on any change remains trivial
and the repeated per-service work stays below the cost of building and
operating a hardened central cluster plus VPN access for external hosts. The
design becomes less attractive when dozens of low-risk applications need OIDC,
long-lived sessions and complex claims. At that point a central HA identity
provider usually has a lower total operating cost, and the stable UUIDs keep
that migration open.

## 15. Implementation phases

The work is ordered so that each phase leaves a testable artifact. Phases 1 and
2 are implemented. Most of phase 3 and the generator portion of phase 4 are also
implemented. The release gate exists but currently blocks the images pending a
review of reported vulnerabilities. Appendix A records the remaining work.

### Phase 1: freeze the runtime contract and test harness

1. Specify the manifest as a versioned schema, including service ID, base DN,
   monotonically increasing revision, soft and hard deadlines, UUID namespace,
   digest algorithm and allowed files.
2. Publish the configuration matrix: authoritative source for every value,
   required inputs, defaults, deprecated inputs, conflicts and exit codes.
3. Define `_FILE` secret handling. File inputs are preferred, direct secret
   environment variables are deprecated, and supplying both is an error.
4. Decide which recovery credentials remain. The target is no network root
   password at runtime and separate least-privilege application bind accounts.
5. Add ephemeral signed fixtures and negative fixtures for every tampering,
   contradiction, expiry and malformed-LDIF case.
6. Build a rootless Podman integration harness that records logs, exit codes and
   resource use. Characterize the current image where a regression comparison is
   useful, but assert the new contract rather than preserving defects.

### Phase 2: replace the image and startup path

1. Rebuild the `Containerfile` from Debian 13 slim with only `slapd`,
   `ldap-utils`, CA certificates, OpenSSL, minisign, `jq` and proven runtime
   utilities. Remove build tools, sudo, editors, troubleshooting packages and OCI
   `VOLUME` declarations.
2. Split startup into small validation, snapshot verification, database build,
   readiness and watchdog functions. Static validation reports all independent
   errors; cryptographic verification and import stop at the first failure.
3. Follow the company shell scripting style guide. Prefer POSIX `sh`, `printf`,
   `set -u`, explicit status checks and a bottom-level `main()`. Use Bash only for
   a documented feature that materially simplifies the watchdog. Run `shfmt`,
   ShellCheck and `checkbashisms` in CI as appropriate.
4. Resolve `_FILE` inputs without printing their values. Reject ambiguous secret
   sources and contradictions between compatibility variables and the manifest.
5. Verify signature, service identity, revision, deadlines and every file digest
   before creating the database. The release image has no unsigned-snapshot mode.
6. Construct `cn=config` and MDB offline, load Argon2 and required schemas, import
   static `member` and `memberOf`, and run structural and semantic checks. If an
   operation cannot be performed offline, start slapd on `ldapi:///` only, wait
   for readiness, use SASL EXTERNAL, and stop it before enabling TCP.
7. Start slapd under the tested signal-forwarding expiry watchdog. Normal signals
   exit cleanly; hard expiry stops slapd and returns 78.
8. Replace the current health command with a check that verifies the expected
   revision and hard deadline. A successful LDAP command with no expected entry
   is not healthy.

### Phase 3: harden and release the runtime image

1. Test the image with a non-root UID, all capabilities dropped,
   `no-new-privileges`, a read-only root filesystem and read-only inputs.
2. Set and test memory, CPU, PID and `nofile` limits. Resolve ownership of
   ephemeral writable directories without world-writable tmpfs mounts.
3. Bind only the configured local address and publish no port by default. Test
   both the plain host-local LDAP profile and the certificate-validated TLS
   profile.
4. Enforce read-only ACLs, separate bind credentials, search size and time limits,
   indexed application filters, bind concurrency limits and Argon2id parameters.
5. Pin the Debian base by digest, record exact packages, generate an SBOM, scan
   the result, sign it and mirror the digest to the company registry. Automated
   update proposals must rebuild and run the full compatibility suite.

### Phase 4: build generation and deployment

1. Define and validate the central user, group, credential and service YAML.
   Structured parsing, DN construction, filter escaping and LDIF serialization
   belong in an LDAP-aware generator, not shell templates.
2. Generate service-specific entries, deterministic UUIDv5 identifiers, reciprocal
   static memberships and Argon2id hashes with unique salts.
3. Produce and sign one complete manifest per service. Keep signing and decryption
   keys outside the image and document rotation with overlapping verification
   keys.
4. Build an Ansible role that stages, verifies and atomically activates snapshots;
   records the highest accepted revision; installs the host expiry backstop; and
   reports the active revision to the control plane.
5. Add the soft deadline, per-service hard deadline, staggered fleet expiry and
   audited emergency override procedure.

The Ansible role is deliberately deferred to a dedicated task because the
organization already has strong deployment conventions that this repository
should not guess. An untracked localhost PoC validates only the narrow handoff:
private staging, service-ID comparison, verification through the runtime image
and cleanup. It does not install a Quadlet or systemd unit and is not production
deployment code.

### Phase 5: qualify one application and operations

1. Pilot one low-risk LDAP application on a dedicated VM.
2. Test normal login, wrong passwords, group removal, offboarding, password
   rotation, deployment interruption, stale snapshots, VM rollback, clock faults,
   resource exhaustion and application session behavior.
3. Exercise clean-host recovery, signing-key rotation, image rollback and the
   emergency expiry override. Confirm that rollback cannot revive an expired
   authorization snapshot.
4. Establish dashboards and alerts for image digest, snapshot revision, deadlines,
   failed binds, search limits, memory, restart count and control-plane drift.
5. Record the measured operating cost and approve service-specific password,
   expiry and session policies before adding more applications.

### Phase 6: evaluate OIDC separately

Run a per-application Dex pilot with a real OIDC client. Test storage loss, token
expiry, group refresh, offboarding and signing-key rotation. Compare its operating
cost with a central HA identity provider before choosing a fleet-wide pattern.

## 16. Acceptance criteria

The architecture is ready for production use only when the following statements
are demonstrated by automated tests or an operational exercise:

* Two clean imports generate the same UUIDs and application-visible identity.
* Invalid, incomplete, expired or wrongly signed input never reaches a TCP
  listener.
* A disabled user cannot bind after the new snapshot is active.
* A stale instance stops at the configured deadline.
* The application denies new access when LDAP is unavailable.
* The application does not retain removed authorization longer than its documented
  cache or session policy.
* Application bind accounts cannot read password hashes or unrelated attributes.
* The application container cannot read LDAP inputs or the generated database.
* Restore from authoritative data works on a clean VM.
* Image updates pass the complete LDAP compatibility suite.
* Monitoring identifies every host running an unexpected or stale revision.
* The container stops promptly and cleanly on SIGTERM, and snapshot expiry
  produces the documented distinct exit code.
* Every tampering case (modified manifest, modified data file, wrong key,
  expired or replayed snapshot) demonstrably fails before a listener opens.
* Deployment definitions set explicit resource limits, including `nofile`.
* File-based secrets work without exposing their values in the environment,
  arguments, logs or health output; ambiguous secret sources are rejected.
* Contradictory service IDs, base DNs or compatibility settings are reported
  before import and cause a non-zero exit.
* The production image cannot start from an unsigned snapshot or permanently
  disable expiry through an environment variable.
* Any initialization listener is LDAPI-only, accepts SASL EXTERNAL locally and is
  gone before the application TCP listener starts.
* The image release has a package manifest, SBOM, signature, immutable registry
  digest and a passing vulnerability policy.

## 17. Decisions still required

The following values need explicit owner approval before production deployment:

* maximum snapshot lifetime per service, expiry staggering and the soft and
  hard deadlines (section 4.7), plus the offboarding service-level objective;
* custody and rotation of the snapshot signing key (the mechanism itself, a
  minisign-style detached signature, was validated in a spike);
* custody and per-host provisioning of the snapshot decryption key;
* password enrollment policy, including generated or breach-screened passwords
  and per-service passwords for internet-facing deployments;
* Argon2 parameters and the bind concurrency limit;
* vulnerability severity policy, VEX review ownership and the separate approval
  and expiry process for accepted but applicable vulnerabilities;
* exact LDAP schemas and group representation;
* monotonic revision storage location and rollback procedure;
* application session invalidation procedures;
* whether decrypted snapshots remain on disk between restarts;
* emergency expiry override policy;
* Dex topology and storage, if OIDC is added.

## 18. Conclusion

The design turns authentication for one service into a deployable, verifiable
artifact. An application VM, including one rented from an external hosting
provider, authenticates its users locally with no VPN and no reachable central
directory. Each container holds a small, service-specific read-only directory
instead of behaving as a miniature replica of a central LDAP cluster.
Resilience against short control-plane outages follows as a side effect.

The honest accounting: password verifiers are copied to application VMs,
offboarding is bounded rather than immediate, and the worst-case blast radius
does not shrink. It moves from a central runtime service to the generation
pipeline, whose compromise can reach every service. The gains are runtime
isolation, per-host data minimization and the removal of network paths, not a
smaller worst case. Strong hashing, per-service passwords on exposed hosts,
signed expiring snapshots, deterministic UUIDs, transactional startup and
container isolation reduce the remaining risks but cannot erase them.

OpenLDAP on Debian 13 slim is a suitable implementation while the directory stays
small, immutable and local. Per-application Dex can extend the same isolation idea
to OIDC, but its state and token behavior require a separate decision. A central
Dex or full identity provider remains available as a later hybrid path, with the
understanding that it introduces a central login dependency.

## Appendix A: implementation status and remaining work

The repository implements and tests the following baseline:

* a Debian 13 slim runtime image with a fixed non-root account, no OCI volumes,
  no development toolchain, only the required OpenLDAP modules and a recorded
  package inventory;
* signed manifests with service binding, file digests, input size limits, hard
  expiry and overlapping verification keys for signing-key rotation;
* rollback state that binds a monotonically increasing revision to the accepted
  manifest digest;
* complete offline `cn=config` and MDB construction before a TCP listener opens;
* deterministic UUIDv5 enforcement, reciprocal `member` and `memberOf` checks,
  and an Argon2id parameter floor;
* a PID 1 watchdog that forwards signals, stops at hard expiry, detects its own
  failure and returns distinct exit codes;
* a strict YAML generator using `python-ldap` for DNs and LDIF, with separate
  credential-file references, service-specific passwords and atomic output;
* rootless Podman tests for tampering, replay, expiry, watchdog failure, TLS,
  ACLs, resource limits, password rotation, offboarding and generated-snapshot
  authentication;
* a Quadlet example with an internal network, read-only filesystem, dropped
  capabilities, explicit limits and Podman health supervision;
* machine-readable freshness status plus a rootless systemd backstop example;
* digest-pinned Trivy release tooling that records external package inventories,
  SPDX SBOMs, security reports, scanner-input identities and OCI digests;
* source revision, version, build time and clean-tree labels on both images,
  with release rejection for dirty or unversioned builds;
* a separate Cosign command that rejects tags and verifies the pushed image
  digest and SPDX file hash before signing and attesting.

The repository does not complete the operational system. These items remain:

* Build the Ansible role that encrypts snapshots in transit, stages them under
  private ownership, switches them atomically, restarts the Quadlet and reports
  the active revision.
* Decide where decrypted snapshots live and how the target host receives the
  decryption key. The implementation signs snapshots but does not encrypt them.
* Connect the implemented JSON status to fleet monitoring for soft deadlines,
  hard deadlines and revision drift. Add collection for failed binds, resource
  use and repeated startup failures.
* Choose per-service deadlines and stagger them so a long control-plane outage
  cannot stop the whole fleet at once.
* Define and test the local emergency expiry override procedure. The container
  intentionally has no environment switch that disables expiry.
* Review and resolve the current vulnerability gate. A 2026-08-03 spike with
  Trivy 0.72.0 reported 12 critical and 26 high findings in the runtime image,
  plus 4 critical and 33 high findings in the generator, and blocked release.
  These counts replace the earlier Syft and Grype baseline; scanner inventories,
  advisory sources and severity choices are not interchangeable. Sampled
  findings referred to installed package versions, while Debian classified some
  high ecosystem severities as minor or no-DSA issues. Do not hide that mismatch
  with a blanket ignore rule. The release command accepts a reviewed OpenVEX
  document, applies it to both scans and hashes it into the release record.
  Trivy's VEX support is experimental, so its behavior needs testing whenever the
  pinned version changes. Record `not_affected` only when the vulnerable
  component or code is absent, unreachable or otherwise demonstrably
  inapplicable. Risk acceptance for an applicable Debian no-DSA issue is a
  separate policy with an owner and review expiry; it must not be represented as
  VEX `not_affected`.
* The release command scans both images even when the first fails policy, writes
  complete evidence with a rejected result and returns status 2. Rejected image
  metadata cannot be passed to the signing command.
* Trivy is the authoritative scanner for SBOM generation, vulnerabilities,
  secrets and misconfiguration. Syft and Grype are a fallback only if Trivy
  cannot process a required target or output format; fallback results must not
  create a second release verdict. The image spike enabled all three Trivy
  security scanners but found no embedded configuration files and no secrets.
  The release command therefore exports the revision recorded in the images and
  scans that committed source tree separately. The source scan found no secrets
  and two low-severity `DS-0026` findings because health checks are defined in
  Quadlet rather than in either Containerfile.
* Trivy's release infrastructure was compromised in March 2026. The affected
  container versions were 0.69.4 through 0.69.6; this project uses 0.72.0. A
  version being outside the published incident range is not enough on its own.
  Scanner updates require a digest pin, keyless Cosign verification against the
  Trivy release-workflow identity, internal mirroring and a new finding baseline.
  The keyless verification of the pinned 0.72.0 image succeeded during the
  2026-08-03 spike, including certificate and transparency-log checks.
* Run the release tooling in CI, sign both images with the approved Cosign key,
  verify the resulting signatures and attestations, and mirror immutable digests
  into the company registry. The hooks exist, but no registry credentials or
  signing keys were available for this implementation pass.
* Run clean-host recovery, offboarding, password rotation, VM rollback and clock
  fault exercises against a real pilot application. Validate the application's
  session and authorization-cache behavior as part of that pilot.
* Approve the password enrollment policy, service-specific password scope,
  Argon2 parameters, schema set, LDAP query indexes and bind limits for the
  chosen VM class and application.
* Evaluate Dex separately if an application needs OIDC. No Dex runtime or token
  lifecycle is part of this repository.

## References

* [OpenLDAP 2.6 Administrator's Guide](https://www.openldap.org/doc/admin26/)
* [Debian 13 release information](https://www.debian.org/releases/trixie/)
* [Debian slapd package contents](https://packages.debian.org/trixie/amd64/slapd/filelist)
* [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
* [Minisign](https://jedisct1.github.io/minisign/)
* [Dex documentation](https://dexidp.io/docs/)
* [Dex LDAP connector](https://dexidp.io/docs/connectors/ldap/)
* [Dex storage](https://dexidp.io/docs/configuration/storage/)
* [Dex token configuration](https://dexidp.io/docs/configuration/tokens/)
* [Bitnami OpenLDAP container documentation](https://github.com/bitnami/containers/blob/main/bitnami/openldap/README.md)
* [Bitnami catalog changes announced for 2025](https://github.com/bitnami/containers/issues/83267)
