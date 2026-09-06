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

- **Python 3.12 or later** and **[uv](https://docs.astral.sh/uv/)** for Python tests. The development group includes `python-ldap`, which builds from source on Python versions without a wheel and then needs the OpenLDAP and Python headers (`openldap-devel` and `python3-devel` on Fedora; `libldap-dev`, `libsasl2-dev` and `python3-dev` on Debian).
- **Git**, **jq**, **shfmt**, **ShellCheck**, **checkbashisms** and **Hadolint** for repository checks.
- **Rootless Buildah and Podman** for container tests.
- **ConClear** from the organization's protected artifact handoff for pin checks, qualification and releases.


## Getting started<a id="getting-started"></a>

1. Clone the repository using HTTPS or SSH and install the locked test dependencies:

   ```sh
   git clone git@github.com:foundata/oci-openldap-declarative.git
   cd oci-openldap-declarative
   uv sync --frozen
   ```

2. Install the reviewed, identity-bearing ConClear wheel in a revision-specific environment:

   ```sh
   : "${CONCLEAR_WHEEL:?set the reviewed wheel path}"
   : "${CONCLEAR_WHEEL_SHA256:?set the reviewed wheel SHA-256}"
   : "${CONCLEAR_REVISION:?set the reviewed ConClear source revision}"
   printf '%s  %s\n' "$CONCLEAR_WHEEL_SHA256" "$CONCLEAR_WHEEL" |
     sha256sum --check
   conclear_venv="${XDG_DATA_HOME:-$HOME/.local/share}/conclear/$CONCLEAR_REVISION"
   uv venv "$conclear_venv"
   uv pip install --python "$conclear_venv/bin/python" "$CONCLEAR_WHEEL"
   PATH="$conclear_venv/bin:$PATH"
   export PATH
   conclear version --format json
   ```

   Compare the reported version, full source revision and embedded guide revision with the handoff's `artifacts.json`. A `development-source-tree` build is not valid for qualification or release.


## Project structure<a id="project-structure"></a>

The repository builds two independent images from one pipeline, split by
`Containerfile`. The runtime image contains only what a listening LDAP service
needs: OpenLDAP, the Argon2 module, LDAP clients, and the scripts that verify
and import a snapshot. It carries no compiler, no interpreter, and no Python,
which keeps the attack surface small on the host where it actually accepts
network connections.

Generating a snapshot from declarative YAML instead needs Python, PyYAML, and
`python-ldap`. Those dependencies live in `Containerfile.generator`, a
separate image that never runs next to an application and is never part of
the release the runtime depends on. Generation happens offline, ahead of
deployment; its only output is a signed, self-contained snapshot that the
runtime image treats as untrusted input to verify, not as code to execute.
Keeping the two Containerfiles apart makes that separation structural: the
generator's dependencies have no path into the image that holds an
application's credentials.

```text
Containerfile                    # runtime image
Containerfile.generator          # snapshot-generator image
conclear.toml                    # image, runtime and test declarations
generator/                       # snapshot generator, Python, offline only
scripts/                         # runtime verification and startup
schema/                          # public JSON Schema contracts
examples/                        # deployment and input examples
tests/                           # schema, policy and behavioral tests
hack/check.sh                    # direct repository check
```


## Development standards<a id="development-standards"></a>

- Follow the foundata shell and Python style guides.
- Keep runtime and generator behavior fail closed. Do not add release skips, mutable-tag fallbacks or trust overrides.
- Keep application tests bound to ConClear-provided exact layouts and digests. Only explicit developer modes may build images.
- Keep credentials, snapshot keys, release profiles and retained test resources outside the checkout.
- Use scoped commits in the form `<scope>: <lowercase imperative description>`.


## Testing<a id="testing"></a>

Run repository-specific checks, then ConClear's generic checks for both images:

```sh
sh hack/check.sh
for image in runtime generator; do
  conclear check --image "$image"
  conclear pins check --image "$image"
done
```

The direct check runs only the unit tests below `tests/unit`. The container suites below `tests/integration` need rootless Podman and an image source selected with `--mode`. For an explicit non-release container test, build developer images into an isolated store:

```sh
test_run=$(mktemp -d "${TMPDIR:-/tmp}/openldap-test.XXXXXX")
uv run --frozen pytest tests/integration --mode=developer-build --run-dir "$test_run"
rm -rf "$test_run"
```

Without `--run-dir` the suite uses a pytest temporary directory. Set `KEEP_TEST_RESOURCES=true` only while diagnosing a failure; the suite then reports its resource manifest and the inspection command instead of resetting the isolated store.


## Pin updates<a id="pin-updates"></a>

ConClear can update the Debian digest locally without Renovate, a branch or a pull request. Proposal generation does not edit the checkout; application verifies every occurrence and updates all files atomically.

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

Review the complete diff before committing. An external updater remains optional, but must preserve the same proposal, review and qualification boundary.


## Qualification and releases<a id="qualification-and-releases"></a>

Qualification uses an isolated checkout, so commit the reviewed changes first. Qualify both images from the same revision and version:

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

A signed release additionally requires the external protected ConClear profile, Quay credentials and approved signing authority. CI invokes the same ConClear CLI and does not reimplement it. Follow the ConClear [quick start](https://github.com/foundata/conclear/blob/master/docs/quickstart.md) for release, resume, cleanup and rescan operations.


## Troubleshooting<a id="troubleshooting"></a>

- **ConClear reports `development-source-tree`:** install the retained wheel that passed ConClear's clean-checkout distribution gate.
- **The Git origin uses SSH:** leave it unchanged. `conclear.toml` records the credential-free canonical HTTPS repository identity; ConClear canonicalizes an equivalent HTTPS or SSH remote before comparing it and writing evidence.
- **A container test fails:** inspect only the resources named in its run manifest. Do not remove unrelated Podman or Buildah state.
