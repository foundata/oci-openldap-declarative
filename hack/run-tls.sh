#!/usr/bin/env bash

# Build and run the OpenLDAP container with TLS enabled
#
# Usage: ./hack/run-tls.sh [service-name] [ldap-port] [ldaps-port]
#
# Example: ./hack/run-tls.sh foobar 1389 1636
#
# This script uses certificates from examples/tls/. If they don't exist,
# it generates them using hack/generate-test-certs.sh.

set -euo pipefail

SERVICE_NAME="${1:-foobar}"
LDAP_PORT="${2:-1389}"
LDAPS_PORT="${3:-1636}"

# Image settings
IMAGE_NAME="openldap-declarative"
IMAGE_TAG="latest"
export IMAGE_NAME IMAGE_TAG

# Derived settings
CONTAINER_NAME="ldap-${SERVICE_NAME}"
LDAP_DOMAIN="${SERVICE_NAME}.svc.local"
LDAP_BASE_DN=$(echo "${LDAP_DOMAIN}" | sed 's/\./,dc=/g' | sed 's/^/dc=/')
LDAP_ADMIN_DN="cn=admin,${LDAP_BASE_DN}"
LDAP_ADMIN_PASSWORD="SecurePass123"

# Paths
PROJECT_ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LDIF_CONFIG_PATH="${PROJECT_ROOT_DIR}/examples/basic/config"
LDIF_DATA_PATH="${PROJECT_ROOT_DIR}/examples/basic/data"
TLS_CERT_PATH="${PROJECT_ROOT_DIR}/examples/basic/tls"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}=== OpenLDAP Container Build & Run (TLS) ===${NC}"
echo "Service:    ${SERVICE_NAME}"
echo "LDAP Port:  ${LDAP_PORT}"
echo "LDAPS Port: ${LDAPS_PORT}"
echo ""

# Step 1: Build the image
echo -e "${GREEN}[1/5] Building container image...${NC}"
"${PROJECT_ROOT_DIR}/hack/build.sh"

# Step 2: Generate TLS certificates if not present
echo -e "${GREEN}[2/5] Checking TLS certificates...${NC}"
if [ ! -f "${TLS_CERT_PATH}/cert.pem" ] || [ ! -f "${TLS_CERT_PATH}/cert.key" ]; then
    echo -e "${YELLOW}Certificates not found. Generating test certificates...${NC}"
    "${PROJECT_ROOT_DIR}/hack/generate-test-certs.sh" "${TLS_CERT_PATH}"
else
    echo "Certificates found in ${TLS_CERT_PATH}"
fi

# Step 3: Stop/remove existing container if running
echo -e "${GREEN}[3/5] Cleaning up existing container...${NC}"
podman stop "${CONTAINER_NAME}" 2>/dev/null || true
podman rm "${CONTAINER_NAME}" 2>/dev/null || true

# Step 4: Run the container with TLS
echo -e "${GREEN}[4/5] Starting container with TLS...${NC}"
podman run -d \
    --name "${CONTAINER_NAME}" \
    --hostname "${CONTAINER_NAME}" \
    --env LDAP_DOMAIN="${LDAP_DOMAIN}" \
    --env LDAP_ORGANISATION="${SERVICE_NAME^} Service" \
    --env LDAP_ADMIN_PASSWORD="${LDAP_ADMIN_PASSWORD}" \
    --env LDAP_PORT="${LDAP_PORT}" \
    --env LDAP_TLS_ENABLED="true" \
    --env LDAP_TLS_PORT="${LDAPS_PORT}" \
    --env LDAP_DEBUG_LEVEL="256" \
    --publish "127.0.0.1:${LDAP_PORT}:${LDAP_PORT}" \
    --publish "127.0.0.1:${LDAPS_PORT}:${LDAPS_PORT}" \
    --volume "${LDIF_CONFIG_PATH}:/ldap/config:ro,Z" \
    --volume "${LDIF_DATA_PATH}:/ldap/data:ro,Z" \
    --volume "${TLS_CERT_PATH}:/ldap/tls:ro,Z" \
    --health-cmd "ldapsearch -x -H ldap://127.0.0.1:${LDAP_PORT} -b \"\" -s base \"(objectClass=*)\" namingContexts" \
    --health-interval=30s \
    --health-timeout=10s \
    --health-start-period=60s \
    --health-retries=3 \
    "${IMAGE_NAME}:${IMAGE_TAG}"

# Step 5: Wait and show status
echo -e "${GREEN}[5/5] Waiting for container to initialize...${NC}"
sleep 5

echo ""
echo -e "${GREEN}=== Container Status ===${NC}"
podman ps --filter "name=${CONTAINER_NAME}" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

echo ""
echo -e "${GREEN}=== Connection Information ===${NC}"
echo "Host:       127.0.0.1"
echo "LDAP Port:  ${LDAP_PORT}"
echo "LDAPS Port: ${LDAPS_PORT}"
echo "Base DN:    ${LDAP_BASE_DN}"
echo "Admin DN:   ${LDAP_ADMIN_DN}"
echo "Admin PW:   ${LDAP_ADMIN_PASSWORD} (CHANGE IN PRODUCTION!)"

echo ""
echo -e "${GREEN}=== Test Commands ===${NC}"
echo "# View logs:"
echo "podman logs -f ${CONTAINER_NAME}"
echo ""
echo "# Change into the container:"
echo "podman exec -it ${CONTAINER_NAME} /bin/bash"
echo ""
echo "# Search via LDAP (plaintext):"
echo "ldapsearch -x -H ldap://127.0.0.1:${LDAP_PORT} \\"
echo "  -D \"${LDAP_ADMIN_DN}\" \\"
echo "  -w \"${LDAP_ADMIN_PASSWORD}\" -b \"${LDAP_BASE_DN}\" \"(objectClass=*)\""
echo ""
echo "# Search via LDAPS (TLS):"
echo "LDAPTLS_CACERT=\"${TLS_CERT_PATH}/ca.pem\" \\"
echo "ldapsearch -x -H ldaps://127.0.0.1:${LDAPS_PORT} \\"
echo "  -D \"${LDAP_ADMIN_DN}\" \\"
echo "  -w \"${LDAP_ADMIN_PASSWORD}\" -b \"${LDAP_BASE_DN}\" \"(objectClass=*)\""
echo ""
echo "# Test TLS connection:"
echo "openssl s_client -connect 127.0.0.1:${LDAPS_PORT} -CAfile \"${TLS_CERT_PATH}/ca.pem\""

echo ""
echo -e "${YELLOW}Note: To apply LDIF changes, restart the container:${NC}"
echo "podman restart ${CONTAINER_NAME}"
