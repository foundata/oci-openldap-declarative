#!/usr/bin/env bash

# OpenLDAP Container Entrypoint
# Initializes slapd and loads LDIF files on every container start
#
# Environment variables:
# - LDAP_DOMAIN: Domain for base DN (e.g., "nextcloud.svc.local")
# - LDAP_ORGANISATION: Organisation name
# - LDAP_ADMIN_PASSWORD: Admin password for cn=admin (required, min 8 chars)
# - LDAP_DEBUG_LEVEL: slapd debug level (default: 256 = stats)
# - LDAP_TLS_ENABLED: Enable LDAPS (default: false)
# - LDAP_TLS_PORT: LDAPS port (default: 1636)
#
# Fixed mount points (not configurable):
# - /ldap/config: Configuration LDIFs (applied to cn=config)
# - /ldap/data: Data LDIFs (applied to main database)
# - /ldap/tls: TLS certificates (cert.pem, key.pem, optional ca.pem)
#
# Log levels (LDAP_DEBUG_LEVEL) are additive (ORed together). Common useful
# combinations:
#   - Production (recommended):
#     stats (256) - connections, bind attempts, searches, results (good for a
#     usual audit trail)
#   - Debugging:
#     stats + ACL (256 + 128 = 384) - add ACL processing for troubleshooting
#     stats + conns (256 + 8 = 264) - add connection details
#   - Full debug (VERY verbose - temporary use only):
#     any (-1) - everything
#   Log Level Reference:
#     1      (0x1)    trace     - function calls
#     2      (0x2)    packets   - packet handling
#     4      (0x4)    args      - heavy trace (function args)
#     8      (0x8)    conns     - connection management
#     16     (0x10)   BER       - packets sent/received
#     32     (0x20)   filter    - search filter processing
#     64     (0x40)   config    - configuration processing
#     128    (0x80)   ACL       - access control processing
#     256    (0x100)  stats     - connections, operations, results (recommended)
#     512    (0x200)  stats2    - stats log entries sent
#     1024   (0x400)  shell     - shell backend communication
#     2048   (0x800)  parse     - entry parsing
#     16384  (0x4000) sync      - LDAPSync replication
#     32768  (0x8000) none      - only high-priority messages
#   Logs go to syslog facility LOG_LOCAL4 by default.
#   Configure rsyslog to route: local4.* /var/log/slapd.log

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# Default values
: "${LDAP_DOMAIN:=example.svc.local}"
: "${LDAP_ORGANISATION:=Example Service}"
: "${LDAP_DEBUG_LEVEL:=256}"
: "${LDAP_PORT:=1389}"
: "${LDAP_TLS_ENABLED:=false}"
: "${LDAP_TLS_PORT:=1636}"

# Fixed paths (not configurable)
LDAP_CONFIG_DIR="/ldap/config"
LDAP_DATA_DIR="/ldap/data"
LDAP_TLS_DIR="/ldap/tls"

# Required values (no defaults)
if [ -z "${LDAP_ADMIN_PASSWORD:-}" ]; then
    log_error "LDAP_ADMIN_PASSWORD must be set"
    exit 1
fi
if [ ${#LDAP_ADMIN_PASSWORD} -lt 8 ]; then
    log_error "LDAP_ADMIN_PASSWORD must be at least 8 characters long"
    exit 1
fi

# TLS validation
if [ "${LDAP_TLS_ENABLED}" = "true" ]; then
    for file in cert.pem cert.key; do
        if [ ! -f "${LDAP_TLS_DIR}/${file}" ]; then
            log_error "TLS enabled but ${LDAP_TLS_DIR}/${file} not found"
            exit 1
        fi
    done
fi

# Derive base DN from domain
# e.g., "foobar.svc.local" -> "dc=foobar,dc=svc,dc=local"
derive_base_dn() {
    local domain="${1}"
    echo "$domain" | sed 's/\./,dc=/g' | sed 's/^/dc=/'
}

LDAP_BASE_DN=$(derive_base_dn "$LDAP_DOMAIN")
LDAP_ADMIN_DN="cn=admin,${LDAP_BASE_DN}"

# Build listen URLs
LISTEN_URLS="ldap://0.0.0.0:${LDAP_PORT}/"
if [ "${LDAP_TLS_ENABLED}" = "true" ]; then
    LISTEN_URLS="${LISTEN_URLS} ldaps://0.0.0.0:${LDAP_TLS_PORT}/"
fi
LISTEN_URLS="${LISTEN_URLS} ldapi:///"

# Export some variables needed by other scripts
export LDAP_BASE_DN \
       LDAP_ADMIN_DN \
       LDAP_ORGANISATION \
       LDAP_CONFIG_DIR \
       LDAP_DATA_DIR \
       LDAP_TLS_DIR

log_info "=========================================="
log_info "OpenLDAP Container Starting"
log_info "=========================================="
log_info "Domain:    ${LDAP_DOMAIN}"
log_info "Base DN:   ${LDAP_BASE_DN}"
log_info "Admin DN:  ${LDAP_ADMIN_DN}"
log_info "Port:      ${LDAP_PORT}"
if [ "${LDAP_TLS_ENABLED}" = "true" ]; then
    log_info "TLS:       enabled (port ${LDAP_TLS_PORT})"
else
    log_info "TLS:       disabled"
fi
log_info "=========================================="

# Step 1: Initialize slapd configuration
log_info "Initializing slapd configuration..."
/container-init/init-slapd.sh

# Step 2: Start slapd in background for LDIF loading
log_info "Starting slapd for initialization..."
/usr/sbin/slapd \
    -h "${LISTEN_URLS}" \
    -u openldap \
    -g openldap \
    -d "${LDAP_DEBUG_LEVEL}" &

SLAPD_PID=$!

# Wait for slapd to be ready
log_info "Waiting for slapd to be ready..."
for i in {1..30}; do
    if ldapsearch -x -H "ldap://127.0.0.1:${LDAP_PORT}" -b "" -s base "(objectClass=*)" namingContexts >/dev/null 2>&1; then
        log_info "slapd is ready"
        break
    fi
    if ! kill -0 "${SLAPD_PID}" 2>/dev/null; then
        log_error "slapd process died during startup"
        exit 1
    fi
    sleep 1
done

# Verify slapd is running
if ! kill -0 "${SLAPD_PID}" 2>/dev/null; then
    log_error "slapd failed to start"
    exit 1
fi

# Step 3: Load LDIF files
log_info "Loading LDIF files..."
/container-init/load-ldif.sh

log_info "=========================================="
log_info "Initialization complete!"
log_info "LDAP listening on port ${LDAP_PORT}"
if [ "${LDAP_TLS_ENABLED}" = "true" ]; then
    log_info "LDAPS listening on port ${LDAP_TLS_PORT}"
fi
log_info "=========================================="

# Keep slapd running in foreground
# Bring slapd to foreground by waiting for it
wait "${SLAPD_PID}"
