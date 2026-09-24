# Changelog

All notable, user-facing changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [Unreleased]

- Nothing worth mentioning right now.


## [1.0.0] - Unreleased

### Added

- Runtime and generator images for `linux/amd64` and `linux/arm64`.
- Signed directory snapshots from users/groups YAML or custom LDIF, with
  password-hash inputs and inline Ansible Vault support.
- Snapshot verification, deployment-target and revision checks, expiry
  supervision and database rebuilds on startup. The YAML path is read-only by
  default; custom LDIF owns its server configuration and write policy.
- Password and initialization helpers, deployment examples and preflight checks.

[unreleased]: https://github.com/foundata/oci-openldap-declarative/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/foundata/oci-openldap-declarative/releases/tag/v1.0.0
