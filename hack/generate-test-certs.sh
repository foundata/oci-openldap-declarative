#!/usr/bin/env bash

# Generate test TLS certificates for local development
#
# Usage:
#   ./hack/generate-test-certs.sh [output-dir]
#
# Creates:
#   - ca.pem      CA certificate
#   - ca.key      CA private key
#   - cert.pem    Server certificate (signed by CA)
#   - cert.key    Server private key
#
# The certificates are valid for localhost and 127.0.0.1

set -euo pipefail

OUTPUT_DIR="${1:-./certs}"
DAYS_VALID=3550
CA_DAYS_VALID=3650
KEY_SIZE=4096

# Colors for output
GREEN='\033[0;32m'
NC='\033[0m'
log_info() { echo -e "${GREEN}[INFO]${NC} $*"; }

log_info "Generating test certificates in: ${OUTPUT_DIR}"
mkdir -p "${OUTPUT_DIR}"

# Generate CA private key
log_info "Creating CA private key..."
openssl genrsa -out "${OUTPUT_DIR}/ca.key" ${KEY_SIZE} 2>/dev/null

# Generate CA certificate
log_info "Creating CA certificate..."
openssl req -x509 -new -nodes \
    -key "${OUTPUT_DIR}/ca.key" \
    -days ${CA_DAYS_VALID} \
    -out "${OUTPUT_DIR}/ca.pem" \
    -subj "/CN=Test CA/O=OpenLDAP Test/C=DE"

# Generate server private key
log_info "Creating server private key..."
openssl genrsa -out "${OUTPUT_DIR}/cert.key" ${KEY_SIZE} 2>/dev/null

# Generate server CSR
log_info "Creating server certificate signing request..."
openssl req -new \
    -key "${OUTPUT_DIR}/cert.key" \
    -out "${OUTPUT_DIR}/server.csr" \
    -subj "/CN=localhost/O=OpenLDAP Test/C=DE"

# Create extension file for SAN (Subject Alternative Names)
cat > "${OUTPUT_DIR}/server.ext" << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = ldap
DNS.3 = ldap.local
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

# Sign server certificate with CA
log_info "Signing server certificate with CA..."
openssl x509 -req \
    -in "${OUTPUT_DIR}/server.csr" \
    -CA "${OUTPUT_DIR}/ca.pem" \
    -CAkey "${OUTPUT_DIR}/ca.key" \
    -CAcreateserial \
    -out "${OUTPUT_DIR}/cert.pem" \
    -days ${DAYS_VALID} \
    -extfile "${OUTPUT_DIR}/server.ext"

# Clean up temporary files
rm -f "${OUTPUT_DIR}/server.csr" "${OUTPUT_DIR}/server.ext" "${OUTPUT_DIR}/ca.srl"

# Set permissions (readable by container user)
chmod 644 "${OUTPUT_DIR}/cert.key" "${OUTPUT_DIR}/cert.pem" "${OUTPUT_DIR}/ca.pem"
chmod 600 "${OUTPUT_DIR}/ca.key"  # CA key doesn't need to be in container

log_info "Certificates generated successfully!"
echo ""
echo "Files created:"
echo "  ${OUTPUT_DIR}/ca.pem    - CA certificate"
echo "  ${OUTPUT_DIR}/ca.key    - CA private key"
echo "  ${OUTPUT_DIR}/cert.pem  - Server certificate"
echo "  ${OUTPUT_DIR}/cert.key  - Server private key"
echo ""
echo "Usage with container:"
echo "  podman run \\"
echo "      --env LDAP_ADMIN_PASSWORD=your-password \\"
echo "      --env LDAP_TLS_ENABLED=true \\"
echo "      --volume $(dirname "${OUTPUT_DIR}")/config:/ldif/config:ro,Z \\"
echo "      --volume $(dirname "${OUTPUT_DIR}")/data:/ldif/data:ro,Z \\"
echo "      --volume ${OUTPUT_DIR}:/ldap/tls:ro,Z \\"
echo "      --publish 127.0.0.1:1389:1389 \\"
echo "      --publish 127.0.0.1:1636:1636 \\"
echo "      openldap-declarative:latest"
echo ""
echo "Test with:"
echo "  openssl s_client -connect localhost:1636 -CAfile \"${OUTPUT_DIR}/ca.pem\""
