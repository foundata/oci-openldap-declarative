FROM docker.io/library/debian:13-slim@sha256:9bb8a3626890e084ab54e888fdd7c4b6d2f119071cd4c5dc5fecb4d73062aa5f

LABEL org.opencontainers.image.title="OpenLDAP Declarative"
LABEL org.opencontainers.image.description="Read-only OpenLDAP directory built from a signed snapshot"
LABEL org.opencontainers.image.vendor="foundata GmbH"
LABEL org.opencontainers.image.source="https://github.com/foundata/oci-openldap-declarative"
LABEL org.opencontainers.image.licenses="GPL-3.0-or-later"

ARG DEBIAN_FRONTEND=noninteractive
ARG USER_OPENLDAP_UID=1001
ARG GROUP_OPENLDAP_GID=1001

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    ca-certificates \
    jq \
    ldap-utils \
    minisign \
    openssl \
    slapd \
  && rm -rf \
    /etc/ldap/slapd.d/* \
    /usr/share/doc/* \
    /usr/share/man/* \
    /var/lib/apt/lists/* \
    /var/lib/ldap/* \
  && groupmod --gid "${GROUP_OPENLDAP_GID}" openldap \
  && usermod --uid "${USER_OPENLDAP_UID}" --gid "${GROUP_OPENLDAP_GID}" openldap \
  && install -d -o openldap -g openldap -m 0700 \
    /run/credentials \
    /run/openldap \
    /snapshot \
    /state \
    /tls

ENV LDAP_RUNTIME_DIR="/run/openldap" \
    LDAP_SNAPSHOT_DIR="/snapshot" \
    LDAP_SNAPSHOT_PUBLIC_KEY_FILE="/run/credentials/snapshot-public-key" \
    LDAP_REVISION_STATE_FILE="/state/highest-revision" \
    LDAP_LDAPI_URI="ldapi://%2Frun%2Fopenldap%2Fldapi" \
    LDAP_LISTEN_HOST="127.0.0.1" \
    LDAP_PORT="1389" \
    LDAP_LDAPS_PORT="1636" \
    LDAP_TRANSPORT="ldap" \
    LDAP_LOG_LEVEL="256"

COPY --chown=openldap:openldap --chmod=0555 scripts/common.sh /usr/local/lib/openldap-declarative/common.sh
COPY --chown=openldap:openldap --chmod=0555 scripts/entrypoint.sh /usr/local/lib/openldap-declarative/entrypoint.sh
COPY --chown=openldap:openldap --chmod=0555 scripts/healthcheck.sh /usr/local/lib/openldap-declarative/healthcheck.sh
COPY --chown=openldap:openldap --chmod=0555 scripts/init-slapd.sh /usr/local/lib/openldap-declarative/init-slapd.sh
COPY --chown=openldap:openldap --chmod=0555 scripts/verify-snapshot.sh /usr/local/lib/openldap-declarative/verify-snapshot.sh

USER openldap:openldap

EXPOSE 1389 1636

STOPSIGNAL SIGTERM

ENTRYPOINT ["/usr/local/lib/openldap-declarative/entrypoint.sh"]
