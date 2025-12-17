# OCI Image: OpenLDAP Declarative

An [OpenLDAP](https://www.openldap.org/) server with declarative directory state. [LDAP Data Interchange Format (LDIF)](https://en.wikipedia.org/wiki/LDAP_Data_Interchange_Format) files are the single source of truth. On startup, the container reconciles the directory to the state described by the LDIF inputs. Runtime changes are not persisted; restarting the container always produces the same directory state for the same LDIF.

Main features of the [OCI](https://opencontainers.org/) image:

- **Declarative, idempotent directory state** defined entirely by LDIF files (reset-on-restart semantics).
- **Support for unprivileged execution (rootless)**.
- **Fully featured OpenLDAP**, plus essential debugging utilities and no unnecessary extras.

This image is intended for small, isolated LDAP directories where reproducibility, auditability, and deterministic behavior are required. Typical use cases include defense-in-depth architectures where applications operate with a minimal, self-contained user directory.



## Table of contents<a id="toc"></a>

- [Tags](#tags)
- [How to build](#build)
- [How to use](#usage)
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
2. Clone or pull the latest changes from the [`foundata/oci-openldap-declarative` git repository](https://github.com/foundata/oci-openldap-declarative).
3. Change into the directory and execute the [build command](https://docs.podman.io/en/latest/markdown/podman-build.1.html):
   ```bash
   podman build -t openldap-declarative .
   ```



## How to use<a id="usage"></a>

1. [Install Podman](https://podman.io/docs/installation).
2. Use the image you built earlier or pull the image from a registry:
   - [Quay](https://quay.io/repository/foundata/openldap-declarative):
     ```bash
     podman pull quay.io/foundata/openldap-declarative:latest
     ```
   - [Docker Hub](https://hub.docker.com/r/foundata/openldap-declarative):
     ```bash
     podman pull docker.io/foundata/openldap-declarative:latest
     ```
3. Run a container from the image:
   ```bash
   podman run --detach \
    --name ldap-foobar \
    --env LDAP_DOMAIN="foobar.svc.local" \
    --env LDAP_ADMIN_PASSWORD="SecurePass_RandomEachStartIfNotDefined" \
    --publish 127.0.0.1:1389:1389 \
    --volume ./examples/ldif/basic/config:/ldif/config:ro,Z \
    --volume ./examples/ldif/basic/data:/ldif/data:ro,Z \
    openldap-declarative:latest
   ```
4. You can now work with the container:
   ```bash
   podman ps

   # List all objects (org, groups, users, ...)
   ldapsearch -x -H ldap://127.0.0.1:1389 \
      -D "cn=admin,dc=foobar,dc=svc,dc=local" \
      -w "SecurePass_RandomEachStartIfNotDefined" \
      -b "dc=foobar,dc=svc,dc=local" "(objectClass=*)"

   # List all users in "ou=people"
   ldapsearch -x -H ldap://127.0.0.1:1389 \
      -D "cn=admin,dc=foobar,dc=svc,dc=local" \
      -w "SecurePass_RandomEachStartIfNotDefined" \
      -b "ou=people,dc=foobar,dc=svc,dc=local" "(objectClass=inetOrgPerson)"
   ```

This image is built and tested with [Podman](https://podman.io/) only. We currently do *not* support [Docker](https://www.docker.com/) (but it might work).



## Non-goals / Limitations<a id="limitations"></a>


This image is intentionally scoped for declarative, file-defined LDAP directories. It is **not** intended to be a general-purpose LDAP service.

Specifically, it does **not** provide:

- Persistent directory state across container restarts.
- Support for interactive or imperative LDAP administration.
- Dynamic runtime modification of users, groups, or schemas.
- Replication, clustering, or high-availability setups.
- Large-scale or multi-tenant directory deployments.

Any change to the directory must be expressed by modifying the LDIF inputs and restarting the container. For mutable, stateful, or large-scale LDAP deployments, use a traditional or managed LDAP service instead.



## Licensing, copyright<a id="licensing-copyright"></a>

### Container configuration, repository<a id="licensing-copyright-project"></a>

<!--REUSE-IgnoreStart-->
Copyright (c) 2025 foundata GmbH (https://foundata.com)

This project is licensed under the GNU General Public License v3.0 or later (SPDX-License-Identifier: `GPL-3.0-or-later`), see [`LICENSES/GPL-3.0-or-later.txt`](LICENSES/GPL-3.0-or-later.txt) for the full text.

The [`REUSE.toml`](REUSE.toml) file provides detailed licensing and copyright information in a human- and machine-readable format. This includes parts that may be subject to different licensing or usage terms, such as third-party components. The repository conforms to the [REUSE specification](https://reuse.software/spec/). You can use [`reuse spdx`](https://reuse.readthedocs.io/en/latest/readme.html#cli) to create a [SPDX software bill of materials (SBOM)](https://en.wikipedia.org/wiki/Software_Package_Data_Exchange).
<!--REUSE-IgnoreEnd-->

[![REUSE status](https://api.reuse.software/badge/github.com/foundata/oci-openldap-declarative)](https://api.reuse.software/info/github.com/foundata/oci-openldap-declarative)



### Container image<a id="licensing-copyright-image"></a>

The pre-built image itself bundles various software components along with direct and indirect dependencies, which are subject to their respective licenses. When using the pre-built image, **you are responsible for ensuring that your usage complies with all relevant licenses** for the software contained within the image.

For further licensing information about the software contained in this image, please refer to the following resources:

* https://www.debian.org/legal/licenses/



## Author information<a id="author-information"></a>

This project was created and is maintained by foundata GmbH (https://foundata.com).
