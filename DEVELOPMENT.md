# Development

This file provides information for maintainers and contributors to OpenLDAP
Declarative. What the system is, why it exists, and its security boundaries
live in [`ARCHITECTURE.md`](ARCHITECTURE.md).


## Table of contents<a id="toc"></a>

- [Prerequisites](#prerequisites)
- [Getting started](#getting-started)
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


## Project structure<a id="project-structure"></a>

The repository builds two independent images from one pipeline, split by
`Containerfile`. The runtime image contains only what a listening LDAP service
needs: OpenLDAP, the Argon2 module, LDAP clients, and the scripts that verify
and import a snapshot. It retains the distribution shell and utilities,
including jq, minisign and OpenSSL, but carries no compiler or Python generator
stack. This keeps generation dependencies off the host accepting LDAP connections.

Generating a signed snapshot's LDIF from declarative YAML instead needs Python,
PyYAML, and `python-ldap`. Those dependencies live in `Containerfile.generator`,
a separate image that never runs next to an application and is never part of
the release the runtime depends on. Generation happens offline, ahead of
deployment; its only output is a signed, self-contained snapshot that the
runtime image treats as untrusted input to verify, not as code to execute.
Keeping the two Containerfiles apart makes that separation structural: the
generator's dependencies have no path into the image that holds an
application's credentials.

```text
Containerfile                    # runtime image
Containerfile.generator          # LDIF snapshot-generator image
conclear.toml                    # image, runtime and test declarations
generator/                       # snapshot generator, Python, offline only
scripts/                         # runtime verification and startup
schema/                          # public JSON Schema contracts
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
