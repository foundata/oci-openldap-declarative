# Development

Build, test and release instructions for maintainers. The behavioral contract
is in [ARCHITECTURE.md](ARCHITECTURE.md).


## Table of contents<a id="toc"></a>

- [Prerequisites](#prerequisites)
- [Getting started](#getting-started)
- [How to build](#build)
  - [Try the README workflow locally](#local-readme)
- [Project structure](#project-structure)
- [Development standards](#development-standards)
- [Testing](#testing)
  - [Application smoke test](#application-smoke-test)
  - [Resource workloads](#resource-workloads)
- [Pin updates](#pin-updates)
- [Qualification and releases](#qualification-and-releases)
  - [Prepare the release host](#release-host)
  - [Qualify without publishing](#qualify)
  - [Release both images](#release)
  - [Resume, archive and rescan](#release-maintenance)
- [Troubleshooting](#troubleshooting)


## Prerequisites<a id="prerequisites"></a>

- **Python 3.12 or later** and **[uv](https://docs.astral.sh/uv/)** for Python
  tests. The development group includes `python-ldap`, which builds from source
  on Python versions without a wheel and then needs the OpenLDAP and Python
  headers (`openldap-devel` and `python3-devel` on Fedora; `libldap-dev`,
  `libsasl2-dev` and `python3-dev` on Debian).
- **Git**, **jq**, **shfmt**, **ShellCheck**, **checkbashisms** and **Hadolint**
  for repository checks.
- **Rootless Buildah and Podman** for container tests.
- **[ConClear](https://foundata.com/en/projects/conclear/)** for OCI checks, pin
  checks, qualification and releases. `hack/check.sh` and developer-build tests
  do not need it. Install the exact release approved for your build environment;
  these instructions use the 1.0.0 CLI:

  ```sh
  uv tool install 'conclear==1.0.0'
  conclear version --format json
  ```

  If that version is not published yet, install an approved wheel with
  `uv tool install /absolute/path/to/conclear-1.0.0-py3-none-any.whl`, built
  through ConClear's
  [distribution release procedure](https://github.com/foundata/conclear/blob/main/DEVELOPMENT.md#release-procedure).
  Check the reported source and guide revisions; release commands must not use
  an installation reporting `development-source-tree`.

For qualification, install ConClear's supported Buildah, Podman, Skopeo,
Hadolint and Trivy versions; publishing and signed rescans also need Cosign. Use
its
[current tool requirements](https://github.com/foundata/conclear#installation)
instead of maintaining another version table here.


## Getting started<a id="getting-started"></a>

Clone the repository and install the locked test dependencies:

```sh
git clone git@github.com:foundata/oci-openldap-declarative.git
cd oci-openldap-declarative
uv sync --frozen
```

This is enough to run `hack/check.sh` and the unit suite; see
[Testing](#testing). ConClear is not required until you touch pins,
qualification or a release.

## How to build<a id="build"></a>

Image builds need Git and rootless Podman; Python and uv are only needed for
the repository tests. Build both images from the same checkout, on the admin
host or in CI. The LDAP host only needs the resulting runtime image.

From the repository root, run:

```sh
created=$(date -u +%Y-%m-%dT%H:%M:%SZ)
revision=$(git rev-parse HEAD)
podman build --format oci --pull=always --inherit-labels=false --file Containerfile \
  --build-arg "IMAGE_CREATED=${created}" \
  --build-arg "IMAGE_REVISION=${revision}" \
  --build-arg IMAGE_VERSION=dev --tag localhost/openldap-declarative:dev .
podman build --format oci --pull=always --inherit-labels=false --file Containerfile.generator \
  --build-arg "IMAGE_CREATED=${created}" \
  --build-arg "IMAGE_REVISION=${revision}" \
  --build-arg IMAGE_VERSION=dev \
  --tag localhost/openldap-declarative-generator:dev .
```

`--inherit-labels=false` keeps the base image's labels out of the result, as the
container image guide requires and as ConClear's release build does. These
images are for development only. Never deploy `:dev` images in production;
follow [qualification and releases](#qualification-and-releases) instead.

### Try the README workflow locally<a id="local-readme"></a>

On the admin host, select the generator you built:

```bash
generator=localhost/openldap-declarative-generator:dev
```

On the LDAP host, select the runtime you built:

```bash
runtime=localhost/openldap-declarative:dev
```

For a single-host test, set both variables in the same Bash terminal. Skip the
registry pull/digest-resolution blocks in the README and Quadlet guide, keeping
these local references throughout. Inside `hash_password()`, replace the image
inspection assignment with
`generator=localhost/openldap-declarative-generator:dev` as well. Start with
[directory preparation](README.md#usage-prepare), then follow signing,
generation and deployment. The admin workflow needs only the generator image.


## Project structure<a id="project-structure"></a>

The runtime image contains OpenLDAP, LDAP clients, signature tools and the
startup scripts. Python and `python-ldap` validate LDIF before offline import;
the same validators run in the generator. `server_config.py` checks the custom
runtime envelope without interpreting arbitrary ACL policy. Runtime does not
contain PyYAML, Argon2 generation bindings or Ansible Vault.

The generator image contains source parsing, the `openldap-password` Argon2id
helper, the `openldap-init` definition initializer, OpenSSL,
[minisign](https://github.com/jedisct1/minisign) and
`ansible-core` for its official `ansible-vault` CLI. The password helper and
snapshot generation share the hashing implementation. The signed snapshot is the
boundary between the images; no generator process or source-decryption key is
needed on the LDAP host. Debian package installation uses
`--no-install-recommends` to exclude the full Ansible collection bundle.
Both images omit package caches, logs, translations and Python bytecode; `C.UTF-8`
and Python sources remain. The generator omits Ansible test tooling, unused
Galaxy scaffolding and IEEE MAC-address lookup data.

For additive YAML fields, the generator parses schema definitions with
`python-ldap`. A build-only stage exports the loaded schema through a temporary
slapd process listening only on a private Unix socket. It includes the built-in
definitions and core, cosine, inetOrgPerson and NIS schemas. Only schema data,
source checksums, the package version and copyright information enter the
final generator image; the server is not installed there. The application
schema is copied into both images. Integration tests compare the package
version and source checksums with runtime. Keep both builds on the same
OpenLDAP package version. Final validation still runs in runtime's offline
preflight.

```text
Containerfile                    # runtime image
Containerfile.generator          # LDIF snapshot-generator image
conclear.toml                    # image, runtime and test declarations
generator/                       # snapshot generator, Python, offline only
generator/extensions.py          # additive YAML fields and schema-aware checks
generator/export_schema.py       # build-only export of slapd's built-in schema
generator/password.py            # stdin-only openldap-password command
generator/initialize.py          # exclusive users/groups definition creation
generator/vault.py               # isolated Ansible Vault CLI adapter
scripts/                         # runtime verification and startup
scripts/directory_data.py        # shared LDIF, schema and verifier validation
scripts/server_config.py         # custom configuration import/runtime envelope
schema/                          # JSON contracts and bundled LDAP schema
examples/                        # deployment and input examples
tests/                           # schema, policy and behavioral tests
hack/check.sh                    # direct repository check
```


## Development standards<a id="development-standards"></a>

- Follow the foundata
  [shell](https://github.com/foundata/guidelines/blob/main/shell-scripting-style-guide.md)
  and
  [Python](https://github.com/foundata/guidelines/blob/main/python-style-guide.md)
  style guides.
- Keep runtime and generator behavior fail closed. Do not add release skips,
  mutable-tag fallbacks or trust overrides.
- Keep application tests bound to
  [ConClear](https://foundata.com/en/projects/conclear/)-provided exact layouts
  and digests. Only explicit developer modes may build images.
- Keep credentials, snapshot keys, release profiles and retained test resources
  outside the checkout.
- [Use scoped commits](https://github.com/foundata/guidelines/blob/main/git-commits.md)
  in the form `<scope>: <lowercase imperative description>`.


## Testing<a id="testing"></a>

The [implementation matrix](docs/implementation.md) indexes selected architecture
contracts. Put `# Implements: IPnnnn` or `# Verifies: IPnnnn` immediately before
the relevant function (after Python decorators). Keep IDs stable; do not reuse
retired IDs. After changing tagged code or tests, regenerate and check it:

```sh
uv run python hack/implementation.py
uv run python hack/implementation.py --check
```

The check rejects missing code/test references, unknown IDs and stale links.
Reviewers must still check that the linked tests exercise the contract.

`hack/check.sh` runs the direct repository check: shell, Containerfiles, and
Python formatting/lint/type checks, plus the unit tests below `tests/unit`.
None of this needs ConClear.

Unit tests do not require a host Ansible installation. Integration tests
exercise the generator image's actual Vault CLI, both input routes, custom
schema imports, authentication, access policy and snapshot lifecycle.
Input-schema checks apply after Vault decryption; OpenLDAP's offline import is
the schema authority.

The runtime compatibility suite executes the README's YAML setup, password
helper, signing and generation snippets with private paths and exact test images,
then checks offline preflight and LDAP binds/searches. It does not exercise
systemd deployment; Quadlet checks remain separate.

Extension unit tests use small schema fixtures and do not need host OpenLDAP
schema files. Container tests exercise the actual packaged schemas, custom
auxiliary classes, Vault-encrypted attribute values, read access and offline
rejection of invalid extended entries.

Custom LDIF tests supply complete configuration, including selected package
schemas. They exercise administrator-owned ACLs and credentials, optional
modules, disposable writes, runtime-setting conflicts and preflight isolation.
The generator image also ships the package's schema LDIF files for explicit
selection; no schemas or policy are implicitly inserted in this path. Use
separate fresh containers for custom preflight. Never mount an active service's
runtime volume or writable revision state into that preflight container.

```sh
sh hack/check.sh
```

The container suites below `tests/integration` need rootless Podman and an image
source selected with `--mode`. For an explicit non-release container test, build
developer images into an isolated store:

```sh
test_run=$(mktemp -d "${TMPDIR:-/tmp}/openldap-test.XXXXXX")
uv run --frozen pytest tests/integration --mode=developer-build --run-dir "$test_run"
rm -rf "$test_run"
```

Set `CC_PLATFORM=linux/arm64` before a developer-build test to build and run
arm64 images on a native worker or a host with QEMU binfmt support. ConClear
supplies this platform for exact-image tests. Hook scratch storage uses
`CC_HOOK_SCRATCH` when supplied, otherwise pytest's temporary directory.

Without `--run-dir` the suite uses a pytest temporary directory. Set
`KEEP_TEST_RESOURCES=true` only while diagnosing a failure; the suite then
reports its JSONL resource manifest and the inspection command instead of
cleaning up. Storage, libpod runtime directories and file locks are private to
the run; helpers and Testinfra inherit that configuration. Cleanup checks the
journal and ownership labels before removing exact containers and volumes,
then removes the run-owned store. It never runs `podman system reset`.

Before committing a change that touches a Containerfile, `conclear.toml`, or
the runtime/generator contract, also run ConClear's generic checks for both
images (see [Prerequisites](#prerequisites) for installing it):

```sh
for image in runtime generator; do
  conclear check --image "$image"
  conclear pins check --image "$image"
done
```


### Application smoke test<a id="application-smoke-test"></a>

The opt-in DokuWiki test submits real HTTP login forms and checks group-based
page access, username changes, membership removal and deactivation across four
signed snapshots. Each assertion uses a fresh session; existing application
sessions and caches are not a revocation guarantee. No browser or external
database is needed.

```sh
test_run=$(mktemp -d "${TMPDIR:-/tmp}/openldap-application.XXXXXX")
uv run --frozen pytest tests/integration/test_application.py \
  --mode=developer-build --run-dir "$test_run" --run-application-tests
```

Our images use the usual developer-build or exact ConClear inputs. The external
consumer uses per-platform digests in `tests/fixtures/dokuwiki/image.json` and
runs with 256 MiB memory and one CPU. Only HTTP is published, on a random
loopback port; LDAP shares the wiki's network namespace. Logs remain under the
run directory; the harness cleans up containers, credentials and storage.
This test is skipped in ordinary integration and release runs.

By default the pinned wiki image is pulled into the private test store. To
reuse it without registry access, prepare an OCI layout outside the checkout
with Skopeo, then pass `--dokuwiki-image-layout "$cache"` to pytest:

```sh
arch=amd64 # Use arm64 for that target platform.
cache="${XDG_CACHE_HOME:-$HOME/.cache}/openldap-tests/dokuwiki-$arch"
pin=$(jq -r --arg arch "$arch" \
  '.repository + "@" + .digests[$arch]' tests/fixtures/dokuwiki/image.json)
mkdir -p "$(dirname "$cache")"
skopeo copy --preserve-digests "docker://$pin" "oci:$cache:dokuwiki"
```

The test verifies the imported digest and architecture before launch. A stale
cache fails explicitly, without a network fallback. Refresh it when reviewing
pin updates. Neither route uses the default Podman store. The cached layout
is read-only input and is not removed by test cleanup.


### Resource workloads<a id="resource-workloads"></a>

Opt-in workloads run twice each: small and 2,000-user directories with four
concurrent clients, 64 MiB Argon2 hashes with two clients, and generation from
2,000 hashes, 100 passwords or 64 Vault values. Each client performs ten
bind/search pairs. They use the declared 256 MiB ceilings and need cgroup v2
with memory and task peak counters:

```sh
test_run=$(mktemp -d "${TMPDIR:-/tmp}/openldap-footprint.XXXXXX")
uv run --frozen pytest tests/integration/test_footprint.py \
  --mode=developer-build --run-dir "$test_run" --run-benchmarks
cat "$test_run/footprints.jsonl"
```

The harness removes its containers, keys and storage; the report remains.
Reports contain image IDs, architecture, workload settings, memory/task peaks
and sampled open-file counts. Whole-container memory includes charged page
cache. Later runs can reuse pages charged elsewhere, so compare both runs and
retain margin. Runtime figures include an in-container Python load client;
generator runs use a small wrapper to retain their peak counter after exit.
Unreadable file-descriptor counts are `null`, not zero.

These workloads are not maximum-capacity or throughput guarantees. Test your
own directory size, hash parameters and concurrency before reducing limits.
They do not run during ordinary integration or release qualification unless
`--run-benchmarks` is explicitly selected.

Native amd64 baseline, 2026-09-15, one CPU, two runs per workload:

| Workload | Peak memory (MiB) | Peak tasks | Sampled open files (max) |
| --- | ---: | ---: | ---: |
| LDAP: 2 users, 4 clients, 19 MiB Argon2 | 103.0-134.3 | 15 | 35 |
| LDAP: 2,000 users, 4 clients, 19 MiB Argon2 | 104.9-123.8 | 15 | 39 |
| LDAP: 2,000 users, 2 clients, 64 MiB Argon2 | 155.8-156.3 | 13 | 31 |
| Generate: 2,000 password hashes | 39.6-40.1 | 3 | 6 |
| Generate: 100 plaintext passwords | 41.0-41.1 | 3 | 6 |
| Generate: 64 Vault-encrypted hashes | 55.4-55.5 | 4 | 15 |

All workloads completed without OOM events. The 256 MiB ceilings retain at
least 99 MiB above these observed peaks; task and descriptor limits are also
unchanged. Recheck them with ConClear's observed footprint during multi-platform
qualification. The original Vault workload took 49-51 seconds for 64 uses of
one ciphertext. Successful repeated ciphertext is now decrypted once per
invocation, in memory. Distinct ciphertext still invokes the official CLI
separately; no decrypted temporary files or persistent cache are introduced.
On 2026-09-23, the same repeated-value workload took 2.23-2.26 seconds with
54.6-55.2 MiB peak memory, four tasks and 13 sampled open files (native amd64,
two runs). This does not measure 64 independently encrypted credentials.


## Pin updates<a id="pin-updates"></a>

[ConClear](https://foundata.com/en/projects/conclear/) can update the Debian
digest locally. Proposal generation does not edit the checkout; application
verifies every occurrence and updates all files atomically.
Refresh base digests regularly and retain `apt-get upgrade` in each existing
package-install `RUN`. Release builds must execute that step against current
package indexes; reusing a cached layer does not refresh packages.

```sh
proposal_dir=$(mktemp -d "${TMPDIR:-/tmp}/openldap-pins.XXXXXX")
conclear pins propose --output "$proposal_dir/pins.json"
conclear pins apply --proposal "$proposal_dir/pins.json"
git diff -- Containerfile Containerfile.generator conclear.toml
sh hack/check.sh
for image in runtime generator; do
  conclear check --image "$image"
  conclear pins check --image "$image"
done
rm -rf "$proposal_dir"
```

Review the complete diff before committing. An external updater remains
optional, but must preserve the same proposal, review and qualification
boundary.


## Qualification and releases<a id="qualification-and-releases"></a>

ConClear builds the selected commit's tracked tree in isolation. Commit reviewed
code, documentation and `conclear.toml` first. Use the same source revision and
release version for `runtime` and `generator`; both declare `linux/amd64` and
`linux/arm64`.

### Prepare the release host<a id="release-host"></a>

Follow ConClear's
[host setup](https://github.com/foundata/conclear#usage-host-config) for
rootless storage, SELinux, Quay access and a protected release profile. Keep the
profile outside this repository, normally at `~/.config/conclear/foundata.toml`.
Reuse the approved builder identity and Cosign signing authority. These sign OCI
images and are separate from the minisign keys used for LDAP snapshots.

The effective defaults require native `linux/amd64` testing; `linux/arm64` may
use a native worker or supported QEMU user-mode emulation. ConClear checks
available handlers but does not install them. For separate platform workers, use
its
[distributed qualification workflow](https://github.com/foundata/conclear/blob/main/docs/distributed-qualification.md),
including the shared scanner database and qualification window.

Choose a durable, backed-up archive directory outside the source repository
and ConClear's working directories. Create it with permissions for the release
user, then set these values in the release terminal:

```sh
revision=$(git rev-parse HEAD)
version=1.0.0
profile=foundata
archives=/srv/archives/conclear
conclear config show --version "$version"
conclear doctor --scope release --profile "$profile" --version "$version"
```

`config show` reports effective repository settings. `doctor` checks
prerequisites without publishing or signing; neither replaces a release run.

### Qualify without publishing<a id="qualify"></a>

This optional diagnostic builds, tests and scans one platform. `release` runs
these gates itself. On a worker able to execute the selected platform:

```sh
conclear doctor --scope qualify
platform=linux/amd64 # Repeat with linux/arm64 on a suitable worker.
for image in runtime generator; do
  conclear qualify --source . --revision "$revision" \
    --image "$image" --version "$version" --platform "$platform" || exit
done
```

The runtime qualification includes the same-revision generator dependency and
their compatibility tests. Generator-only qualification cannot replace it.
Keep each result's run ID and evidence; separate ad-hoc qualifications are not
automatically reused by `release`.

### Release both images<a id="release"></a>

Run from the configured release host, using the values above:

```sh
for image in generator runtime; do
  conclear release --source . --revision "$revision" \
    --image "$image" --version "$version" --profile "$profile" \
    --archive-dir "$archives" || exit
done
```

Each command qualifies every declared platform, publishes and verifies signed
registry artifacts, then assigns `<version>` and `latest`. It also produces a
release archive containing source, configuration, test/scan evidence, SBOMs and
attestations. These are two separate releases, not an atomic pair: verify both
results and record both digests before deployment. Never overwrite an existing
version tag with different bytes or rebuild images to promote them.

A managed workstation can run this workflow. CI invokes the same commands with
its protected profile; it does not need a separate release implementation.

### Resume, archive and rescan<a id="release-maintenance"></a>

Resume an interrupted image release using its reported run ID, original profile
and toolchain. Completed runs are not resumable:

```sh
conclear release --resume '<interrupted-run-id>' --profile "$profile" \
  --archive-dir "$archives"
```

If qualification has expired or required inputs changed, start a new release.
Verify and retain each completed release's archive before cleaning its run:

```sh
bundle="$archives/<reported-archive-name>.tar.gz"
conclear archive verify "$bundle" --profile "$profile" || exit
# Only after verification succeeds and the archive is safely retained:
conclear cleanup '<completed-run-id>' --profile "$profile"
```

Rescan each supported image from its release archive or latest rescan archive,
keeping referenced source archives beside it:

```sh
conclear rescan --archive "$bundle" --profile "$profile" \
  --authoritative --archive-dir "$archives"
```

Schedule rescans externally, retain their archives and assign rejected or failed
assessments for triage and rebuild. Back up protected profiles, credentials and
signing keys separately; ConClear excludes them from release archives. See its
[archive and recovery instructions](https://github.com/foundata/conclear#usage-archives)
for retention and retrying a failed archive export.


## Troubleshooting<a id="troubleshooting"></a>

- **ConClear reports `development-source-tree`:** you are running ConClear from
  a source checkout. Install an approved distribution as described under
  [prerequisites](#prerequisites).
- **ConClear rejects the Git origin:** review `allowed_source_origins` in the
  protected profile. It authorizes actual checkout origins, with equivalent SSH
  and HTTPS forms canonicalized. `project.source` in `conclear.toml` is the
  public project page used in labels and evidence; it need not match the Git
  origin. Do not rewrite a legitimate origin to match that public URL.
- **A container test fails:** inspect only the resources named in its run
  manifest. Do not remove unrelated Podman or Buildah state.
