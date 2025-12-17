FROM debian:trixie-slim

LABEL description="OCI Image: OpenLDAP Declarative (LDIF-file-defined directory state, reset on startup)"
LABEL maintainer="foundata GmbH (https://foundata.com)"
LABEL version="0.0.0-dev"

# Inform environment it's running in a container and specify the container
# manager type (this may affect the behavior, see src/basic/virt.c).
# Docker users can overwrite this with "--env container=docker".
ENV container=podman

# Set non-interactive mode for apt to prevent prompts during builds
ARG DEBIAN_FRONTEND=noninteractive

ARG USER_OPENLDAP_UID=1001
ARG GROUP_OPENLDAP_GID=1001

# Environment variables defaults
ENV LDAP_DOMAIN="example.svc.local" \
    LDAP_ORGANISATION="Example Service" \
    LDAP_ADMIN_PASSWORD="admin" \
    LDAP_DEBUG_LEVEL="256"

# Install required packages and clean-up package manager caches afterwards.
# Packages are included for these purposes:
#
# - Overall compatibility and network functionality:
#   build-essential gnu-which iproute2 libffi-dev libssl-dev procps
#
# - Easier debugging within the container (good feature-to-size ratio):
#   iputils-ping, iputils-tracepath, less, vim-tiny
#
# - OpenLDAP:
#   ca-certificates ldap-utils slapd
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        gnu-which \
        iproute2 \
        libffi-dev \
        libssl-dev \
        procps \
        iputils-ping \
        iputils-tracepath \
        less \
        vim-tiny \
        ca-certificates \
        ldap-utils \
        slapd \
        sudo \
    && rm -rf "/var/lib/apt/lists/"* \
    && apt-get clean \
    # Clean up unnecessary installed files that aren't needed in this image.
    # --no-install-recommends does not prevent installation of docs for all
    # packages, and --path-exclude is only available for dpkg, not for apt-get.
    && rm -rf "/usr/share/doc" \
    && rm -rf "/usr/share/man" \
    # Remove default slapd data (we'll initialize fresh each start)
    && rm -rf "/var/lib/ldap/" \
    && rm -rf "/etc/ldap/slapd.d/"

# Ensure non-interactive sudo commands work in containerized environments where
# TTY allocation is often unavailable or undesired (if needed, it is usually
# allowed on this platform).
RUN sed -i -e 's/\(^Defaults\s*\)\(requiretty\)/\1!\2/' "/etc/sudoers"

# The slapd package creates 'openldap' user. Adjust ownership and use a specific
# UID/GID for rootless compatibility.
RUN groupmod -g ${GROUP_OPENLDAP_GID} openldap && \
    usermod -u ${USER_OPENLDAP_UID} -g ${GROUP_OPENLDAP_GID} openldap

# Create required directories with correct ownership
RUN mkdir -p /var/lib/ldap \
             /var/run/slapd \
             /etc/ldap/slapd.d \
             /container-init \
             /ldif/config \
             /ldif/data \
    && chown -R openldap:openldap /var/lib/ldap \
                                  /var/run/slapd \
                                  /etc/ldap \
                                  /container-init \
                                  /ldif

# Copy initialization scripts
COPY --chown=openldap:openldap scripts/entrypoint.sh /container-init/
COPY --chown=openldap:openldap scripts/init-slapd.sh /container-init/
COPY --chown=openldap:openldap scripts/load-ldif.sh /container-init/

RUN chmod +x /container-init/*.sh

# Switch to non-root user
USER openldap

# Expose LDAP port (unprivileged)
EXPOSE 1389

# Mount points for LDIF files
VOLUME ["/ldif/config", "/ldif/data"]

ENTRYPOINT ["/container-init/entrypoint.sh"]
