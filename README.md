# OCI Image: OpenLDAP LDIF

A purpose-built OpenLDAP [OCI](https://opencontainers.org/) image that provides isolated LDAP instances with [LDAP Data Interchange Format (LDIF)](https://en.wikipedia.org/wiki/LDAP_Data_Interchange_Format) files as the single source of truth. Typical use cases include defense-in-depth architectures in which applications operate with a minimal, self-contained user directory.

LDIF files on the host are authoritative. Runtime changes inside the container are not persisted; restarting the container always reloads the directory from the source files. This design enables:

- **Reproducible deployments** (identical LDIF inputs result in identical directory state)
- **Straightforward rollbacks** (revert LDIF files and restart the container)
- **Auditability** when LDIF configuration is maintained under version control

Other image features:

- Support for unprivileged execution
- Fully featured OpenLDAP, plus essential debugging utilities but no unnecessary extras



## Table of contents<a id="toc"></a>

- [Tags](#tags)
- [How to build](#build)
- [How to use](#usage)
- [Notes](#notes)
- [Non-goals / Limitations](#limitations)
- [Licensing, copyright](#licensing-copyright)
  - [Container configuration, repository](#licensing-copyright-project)
  - [Container image](#licensing-copyright-image)
- [Author information](#author-information)



## Tags<a id="tags"></a>

- `latest`: Latest release of this image.



## How to build<a id="build"></a>

To build the image locally, do the following:

1. [Install Podman](https://podman.io/docs/installation).
2. Clone or pull the latest changes from the [`foundata/oci-openldap-ldif` git repository](https://github.com/foundata/oci-openldap-ldif).
3. Change into the directory and execute the [build command](https://docs.podman.io/en/latest/markdown/podman-build.1.html):
   ```bash
   podman build -t openldap-ldif .
   ```



## How to use<a id="usage"></a>

1. [Install Podman](https://podman.io/docs/installation).
2. Use the image you built earlier or pull the image from a registry:
   - [Quay](https://quay.io/repository/foundata/openldap-ldif):
     ```bash
     podman pull quay.io/foundata/openldap-ldif:latest
     ```
   - [Docker Hub](https://hub.docker.com/r/foundata/openldap-ldif):
     ```bash
     podman pull docker.io/foundata/openldap-ldif:latest
     ```
3. Run a container from the image:
   ```bash
   podman run --detach openldap-ldif:latest
   ```
4. You can now work with the container, e.g. open a Bash terminal:
   ```bash
   podman ps
   podman exec -it "<container-id-or-name>" "/bin/bash"
   ```



## Notes<a id="notes"></a>

This image is built and tested with [Podman](https://podman.io/) only.

We currently do *not* support [Docker](https://www.docker.com/) (but it might work).



## Non-goals / Limitations<a id="limitations"></a>

This image is intentionally scoped for declarative, file-defined LDAP directories and is not a general-purpose LDAP service. It does **not** provide:

- Persistent directory state (runtime changes are discarded on restart)
- Support for interactive or long-term LDAP administration
- High availability, replication, or clustering
- Dynamic user, group, or schema management

This image is intended for small, isolated directories. Use a traditional or managed LDAP service for mutable or large-scale deployments.



## Licensing, copyright<a id="licensing-copyright"></a>

### Container configuration, repository<a id="licensing-copyright-project"></a>

<!--REUSE-IgnoreStart-->
Copyright (c) 2025 foundata GmbH (https://foundata.com)

This project is licensed under the GNU General Public License v3.0 or later (SPDX-License-Identifier: `GPL-3.0-or-later`), see [`LICENSES/GPL-3.0-or-later.txt`](LICENSES/GPL-3.0-or-later.txt) for the full text.

The [`REUSE.toml`](REUSE.toml) file provides detailed licensing and copyright information in a human- and machine-readable format. This includes parts that may be subject to different licensing or usage terms, such as third-party components. The repository conforms to the [REUSE specification](https://reuse.software/spec/). You can use [`reuse spdx`](https://reuse.readthedocs.io/en/latest/readme.html#cli) to create a [SPDX software bill of materials (SBOM)](https://en.wikipedia.org/wiki/Software_Package_Data_Exchange).
<!--REUSE-IgnoreEnd-->

[![REUSE status](https://api.reuse.software/badge/github.com/foundata/oci-openldap-ldif)](https://api.reuse.software/info/github.com/foundata/oci-openldap-ldif)



### Container image<a id="licensing-copyright-image"></a>

The pre-built image itself bundles various software components along with direct and indirect dependencies, which are subject to their respective licenses. When using the pre-built image, **you are responsible for ensuring that your usage complies with all relevant licenses** for the software contained within the image.

For further licensing information about the software contained in this image, please refer to the following resources:

* https://www.debian.org/legal/licenses/



## Author information<a id="author-information"></a>

This project was created and is maintained by foundata GmbH (https://foundata.com).
