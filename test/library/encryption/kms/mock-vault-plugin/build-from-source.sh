#!/usr/bin/env bash
set -euo pipefail

REGISTRY="${REGISTRY:-quay.io}"
REPO="${REPO:-openshifttest}"
IMAGE_NAME="${IMAGE_NAME:-mock-kms-plugin-vault}"
TAG="${TAG:-latest}"
PLATFORM="${PLATFORM:-linux/amd64}"
FULL_IMAGE="${REGISTRY}/${REPO}/${IMAGE_NAME}:${TAG}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "============================================"
echo "  Mock Vault KMS Plugin - Build & Push"
echo "============================================"
echo "  Image:    ${FULL_IMAGE}"
echo "  Platform: ${PLATFORM}"
echo ""

echo "Building container image..."
podman build \
  --platform "${PLATFORM}" \
  -t "${FULL_IMAGE}" \
  "${SCRIPT_DIR}"

echo ""
echo "Build complete: ${FULL_IMAGE}"
echo ""

echo "Pushing ${FULL_IMAGE}..."
podman push "${FULL_IMAGE}"

echo ""
echo "============================================"
echo "  Pushed: ${FULL_IMAGE}"
echo "============================================"
