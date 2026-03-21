#!/bin/bash

# Build Vault KMS Plugin Image
# This script builds the Vault KMS v2 plugin container image

set -euo pipefail

# Configuration
IMAGE_NAME="${IMAGE_NAME:-vault-kms-plugin}"
IMAGE_TAG="${IMAGE_TAG:-quay.io/openshifttest/vault-kms-plugin:latest}"
CONTAINER_RUNTIME="${CONTAINER_RUNTIME:-podman}"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Build the Vault KMS v2 plugin container image.

Options:
    --tag TAG           Image tag (default: quay.io/openshifttest/vault-kms-plugin:latest)
    --runtime RUNTIME   Container runtime: docker or podman (default: podman)
    --push              Push image after building
    --help              Show this help message

Examples:
    # Build image
    $0

    # Build and push
    $0 --push

    # Build with custom tag
    $0 --tag myregistry/vault-kms-plugin:v1.0
EOF
}

# Parse arguments
PUSH=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --tag)
            IMAGE_TAG="$2"
            shift 2
            ;;
        --runtime)
            CONTAINER_RUNTIME="$2"
            shift 2
            ;;
        --push)
            PUSH=true
            shift
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Check container runtime
if ! command -v ${CONTAINER_RUNTIME} &> /dev/null; then
    log_error "${CONTAINER_RUNTIME} is not installed"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

log_info "Building Vault KMS plugin image..."
log_info "Image tag: ${IMAGE_TAG}"
log_info "Container runtime: ${CONTAINER_RUNTIME}"

# Download dependencies
log_info "Downloading Go dependencies..."
go mod download 2>/dev/null || go mod tidy

# Build image
log_info "Building container image..."
${CONTAINER_RUNTIME} build \
    --platform linux/amd64 \
    -t "${IMAGE_TAG}" \
    -f Dockerfile \
    .

log_info "Image built successfully: ${IMAGE_TAG}"

# Push if requested
if [ "$PUSH" = true ]; then
    log_info "Pushing image to registry..."
    ${CONTAINER_RUNTIME} push "${IMAGE_TAG}"
    log_info "Image pushed successfully!"
fi

echo ""
log_info "=========================================="
log_info "Build Complete!"
log_info "=========================================="
echo ""
echo "Image: ${IMAGE_TAG}"
echo ""
echo "To push manually:"
echo "  ${CONTAINER_RUNTIME} push ${IMAGE_TAG}"
echo ""
echo "To run locally (for testing):"
echo "  ${CONTAINER_RUNTIME} run -it --rm ${IMAGE_TAG} --help"
echo ""
echo "To deploy on OpenShift:"
echo "  ./deploy-vault-kms-plugin.sh --image ${IMAGE_TAG} \\"
echo "    --vault-addr http://vault.vault.svc:8200 \\"
echo "    --role-id <ROLE_ID> --secret-id <SECRET_ID>"
