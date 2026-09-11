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
- [Pin updates](#pin-updates)
- [Qualification and releases](#qualification-and-releases)
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
- **[ConClear](https://foundata.com/en/projects/conclear/)**, only for pin
  checks, qualification and releases; none of the checks above need it. Install
  it as a tool with uv:

  ```sh
  uv tool install conclear
  conclear version
  ```


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
podman build --format oci --pull=always --file Containerfile \
  --build-arg "IMAGE_CREATED=${created}" \
  --build-arg "IMAGE_REVISION=${revision}" \
  --build-arg IMAGE_VERSION=dev --tag localhost/openldap-declarative:dev .
podman build --format oci --pull=always --file Containerfile.generator \
  --build-arg "IMAGE_CREATED=${created}" \
  --build-arg "IMAGE_REVISION=${revision}" \
  --build-arg IMAGE_VERSION=dev \
  --tag localhost/openldap-declarative-generator:dev .
```

These images are for development only. Never deploy `:dev` images in production;
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
these local references throughout. Start with
[directory preparation](README.md#usage-prepare), then follow signing,
generation and deployment. The admin workflow needs only the generator image.


## Project structure<a id="project-structure"></a>

The runtime image contains OpenLDAP, LDAP clients, signature tools and the
startup scripts. Python and `python-ldap` validate LDIF before offline import;
the same validators run in the generator. `server_config.py` checks the custom
runtime envelope without interpreting arbitrary ACL policy. Runtime does not
contain PyYAML, Argon2 generation bindings or Ansible Vault.

The generator image contains source parsing, the `openldap-password` Argon2id
helper, OpenSSL, [minisign](https://github.com/jedisct1/minisign) and
`ansible-core` for its official `ansible-vault` CLI. The password helper and
snapshot generation share the hashing implementation. The signed snapshot is the
boundary between the images; no generator process or source-decryption key is
needed on the LDAP host. Debian package installation uses
`--no-install-recommends` to exclude the full Ansible collection bundle.

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
  [shell](https://github.com/foundata/guidelines/blob/master/shell-scripting-style-guide.md)
  and
  [Python](https://github.com/foundata/guidelines/blob/master/python-style-guide.md)
  style guides.
- Keep runtime and generator behavior fail closed. Do not add release skips,
  mutable-tag fallbacks or trust overrides.
- Keep application tests bound to
  [ConClear](https://foundata.com/en/projects/conclear/)-provided exact layouts
  and digests. Only explicit developer modes may build images.
- Keep credentials, snapshot keys, release profiles and retained test resources
  outside the checkout.
- [Use scoped commits](https://github.com/foundata/guidelines/blob/master/git-commits.md)
  in the form `<scope>: <lowercase imperative description>`.


## Testing<a id="testing"></a>

`hack/check.sh` runs the direct repository check: shell, Containerfiles, and
Python formatting/lint/type checks, plus the unit tests below `tests/unit`.
None of this needs ConClear.

Unit tests do not require a host Ansible installation. Integration tests
exercise the generator image's actual Vault CLI, both input routes, custom
schema imports, authentication, access policy and snapshot lifecycle.
Input-schema checks apply after Vault decryption; OpenLDAP's offline import is
the schema authority.

Extension unit tests use small schema fixtures and do not need host OpenLDAP
schema files. Container tests exercise the actual packaged schemas, custom
auxiliary classes, Vault-encrypted attribute values, read access and offline
rejection of invalid extended entries.

Custom LDIF tests supply complete configuration, including selected package
schemas. They exercise administrator-owned ACLs and credentials, optional
modules, disposable writes, runtime-setting conflicts and preflight isolation.
The generator image also ships the package's schema LDIF files for explicit
selection; no schemas or policy are implicitly inserted in this path.
Use separate fresh containers for custom preflight. Never mount an active
service's runtime volume or writable revision state into that preflight container.

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


## Pin updates<a id="pin-updates"></a>

[ConClear](https://foundata.com/en/projects/conclear/) can update the Debian
digest locally. Proposal generation does not edit the checkout; application
verifies every occurrence and updates all files atomically.

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

Qualification uses an isolated checkout, so commit the reviewed changes first.
Qualify both images from the same revision and version:

```sh
revision=$(git rev-parse HEAD)
version=0.1.0-test.1
for platform in linux/amd64 linux/arm64; do
  for image in runtime generator; do
    conclear qualify --source . --revision "$revision" \
      --image "$image" --version "$version" --platform "$platform"
  done
done
```

A signed release additionally requires the external protected ConClear profile,
Quay credentials and approved signing authority, plus the exact ConClear version
approved for that release (`uv tool install conclear==<version>`) rather than
whatever is newest. CI invokes the same ConClear CLI and does not reimplement
it. Follow the ConClear
[quick start](https://github.com/foundata/conclear/blob/master/docs/quickstart.md)
for release, resume, cleanup and rescan operations.


## Troubleshooting<a id="troubleshooting"></a>

- **ConClear reports `development-source-tree`:** you are running ConClear from
  a source checkout. Install it as a tool instead (`uv tool install conclear`),
  or the exact reviewed version for a release.
- **The Git origin uses SSH:** leave it unchanged. `conclear.toml` records the
  credential-free canonical HTTPS repository identity; ConClear canonicalizes an
  equivalent HTTPS or SSH remote before comparing it and writing evidence.
- **A container test fails:** inspect only the resources named in its run
  manifest. Do not remove unrelated Podman or Buildah state.
