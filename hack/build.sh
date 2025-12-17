#!/usr/bin/env bash

# Build the OpenLDAP container image
#
# Usage: ./hack/build.sh
#
# Environment variables (optional):
#   IMAGE_NAME  - Image name (default: openldap-declarative)
#   IMAGE_TAG   - Image tag (default: latest)

set -euo pipefail

PROJECT_ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

: "${IMAGE_NAME:=openldap-declarative}"
: "${IMAGE_TAG:=latest}"

# Colors
GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${GREEN}[BUILD]${NC} Building ${IMAGE_NAME}:${IMAGE_TAG}..."
podman build -t "${IMAGE_NAME}:${IMAGE_TAG}" "${PROJECT_ROOT_DIR}"
echo -e "${GREEN}[BUILD]${NC} Done."
