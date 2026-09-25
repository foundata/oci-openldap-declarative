# Contributing

Use [issues](https://github.com/foundata/oci-openldap-declarative/issues) to
report problems or propose changes, and pull requests to submit fixes. Report
vulnerabilities privately through [`SECURITY.md`](./SECURITY.md).


## Issues

Search existing issues before opening one. For a bug report, include:

- The runtime and generator image versions and digests, affected platform, and
  container engine version.
- Whether you use users/groups YAML or custom LDIF.
- A minimal reproduction with sanitized input, relevant settings, commands, exit
  statuses and logs.
- The expected and observed behavior.

Use synthetic identities and credentials. Do not attach production definitions,
snapshots, password hashes, private keys or registry credentials. Review logs
for sensitive data and local paths before sharing them.


## Pull requests

Follow the setup and
[development standards](./DEVELOPMENT.md#development-standards) in
[`DEVELOPMENT.md`](./DEVELOPMENT.md). Keep changes focused, include regression
tests for behavior changes and update affected documentation.
[`ARCHITECTURE.md`](./ARCHITECTURE.md) defines the behavioral contract;
investigate discrepancies before changing its guarantees.

Run `sh hack/check.sh` and the applicable
[container and ConClear checks](./DEVELOPMENT.md#testing). Describe what changed
and how you tested it in the pull request.

Use commit subjects in the form `<scope>: <lowercase imperative description>`.
Contributions must be compatible with the project's
[licensing](./README.md#licensing-copyright), recorded in
[`REUSE.toml`](./REUSE.toml).
