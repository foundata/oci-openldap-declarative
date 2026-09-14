FROM docker.io/library/debian:13-slim@sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132

ARG IMAGE_CREATED
ARG IMAGE_REVISION
ARG IMAGE_VERSION

LABEL org.opencontainers.image.title="OpenLDAP Declarative"
LABEL org.opencontainers.image.description="OpenLDAP directory and configuration built from a signed snapshot"
LABEL org.opencontainers.image.vendor="foundata GmbH"
LABEL org.opencontainers.image.source="https://foundata.com/en/projects/oci-openldap-declarative/#source"
LABEL org.opencontainers.image.url="https://foundata.com/en/projects/oci-openldap-declarative/"
LABEL org.opencontainers.image.documentation="https://foundata.com/en/projects/oci-openldap-declarative/#doc"
LABEL org.opencontainers.image.created="${IMAGE_CREATED}"
LABEL org.opencontainers.image.revision="${IMAGE_REVISION}"
LABEL org.opencontainers.image.version="${IMAGE_VERSION}"

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    ca-certificates \
    jq \
    ldap-utils \
    minisign \
    openssl \
    python3 \
    python3-ldap \
    slapd \
  && find /usr/share/doc -type f ! -name copyright -delete \
  && find /usr/share/doc -type l -delete \
  && find /usr/share/doc -depth -type d -empty -delete \
  && find /usr/lib/ldap -mindepth 1 \
    ! -name 'argon2.*' \
    ! -name 'back_mdb.*' \
    ! -name 'memberof.*' \
    ! -name 'sssvlv.*' \
    ! -name 'dynlist.*' \
    ! -name 'deref.*' \
    ! -name 'rwm.*' \
    ! -name 'ppolicy.*' \
    ! -name 'refint.*' \
    ! -name 'unique.*' \
    ! -name 'constraint.*' \
    ! -name 'valsort.*' \
    ! -name 'auditlog.*' \
    ! -name 'syncprov.*' \
    -delete \
  && install -d -m 0755 /usr/local/share/openldap-declarative \
  && dpkg-query -W -f='${Package}\t${Version}\n' \
    > /usr/local/share/openldap-declarative/package-versions.unsorted \
  && sort /usr/local/share/openldap-declarative/package-versions.unsorted \
    > /usr/local/share/openldap-declarative/package-versions.txt \
  && rm /usr/local/share/openldap-declarative/package-versions.unsorted \
  && rm -rf \
    /etc/ldap/slapd.d/* \
    /usr/share/man/* \
    /var/lib/apt/lists/* \
    /var/cache/debconf/* \
    /var/lib/ldap/* \
  && if getent passwd 1001 >/dev/null || getent group 1001 >/dev/null; then \
    printf '%s\n' 'UID or GID 1001 already exists in the pinned base image' >&2; \
    exit 1; \
  fi \
  && groupmod --gid 1001 openldap \
  && usermod --uid 1001 --gid 1001 openldap \
  && rmdir /etc/ldap/slapd.d /var/lib/ldap \
  && find / -xdev -type f -perm /6000 -exec chmod a-s {} + \
  && install -d -o openldap -g openldap -m 0700 \
    /run/openldap \
    /state \
  && install -d -o root -g root -m 0555 \
    /run/credentials \
    /snapshot \
    /tls \
  && ln -s /usr/local/lib/openldap-declarative/preflight-snapshot.sh \
    /usr/local/bin/openldap-preflight

ENV LDAP_RUNTIME_DIR="/run/openldap" \
    PYTHONDONTWRITEBYTECODE="1" \
    LDAP_SNAPSHOT_DIR="/snapshot" \
    LDAP_REVISION_STATE_FILE="/state/highest-revision" \
    LDAP_LDAPI_URI="ldapi://%2Frun%2Fopenldap%2Fldapi" \
    LDAP_LISTEN_HOST="127.0.0.1" \
    LDAP_PORT="1389" \
    LDAP_LDAPS_PORT="1636" \
    LDAP_TRANSPORT="ldap" \
    LDAP_LOG_LEVEL="256"

COPY --chown=0:0 --chmod=0555 scripts/common.sh /usr/local/lib/openldap-declarative/common.sh
COPY --chown=0:0 --chmod=0444 scripts/directory_data.py /usr/local/lib/openldap-declarative/directory_data.py
COPY --chown=0:0 --chmod=0444 scripts/server_config.py /usr/local/lib/openldap-declarative/server_config.py
COPY --chown=0:0 --chmod=0444 scripts/runtime_limits.py /usr/local/lib/openldap-declarative/runtime_limits.py
COPY --chown=0:0 --chmod=0444 schema/application-user.ldif /usr/local/share/openldap-declarative/schema/application-user.ldif
COPY --chown=0:0 --chmod=0555 scripts/entrypoint.sh /usr/local/lib/openldap-declarative/entrypoint.sh
COPY --chown=0:0 --chmod=0555 scripts/healthcheck.sh /usr/local/lib/openldap-declarative/healthcheck.sh
COPY --chown=0:0 --chmod=0555 scripts/init-slapd.sh /usr/local/lib/openldap-declarative/init-slapd.sh
COPY --chown=0:0 --chmod=0555 scripts/preflight-snapshot.sh /usr/local/lib/openldap-declarative/preflight-snapshot.sh
COPY --chown=0:0 --chmod=0555 scripts/revision-state.sh /usr/local/lib/openldap-declarative/revision-state.sh
COPY --chown=0:0 --chmod=0555 scripts/status.sh /usr/local/lib/openldap-declarative/status.sh
COPY --chown=0:0 --chmod=0555 scripts/verify-snapshot.sh /usr/local/lib/openldap-declarative/verify-snapshot.sh
COPY --chown=0:0 --chmod=0444 LICENSES/GPL-3.0-or-later.txt /usr/local/share/openldap-declarative/LICENSE.txt

USER 1001:1001

EXPOSE 1389/tcp 1636/tcp

ENTRYPOINT ["/usr/local/lib/openldap-declarative/entrypoint.sh"]
