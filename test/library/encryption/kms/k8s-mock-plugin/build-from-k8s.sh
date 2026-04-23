#!/usr/bin/env bash
set -euo pipefail

readonly K8S_REPO_URL="https://github.com/kubernetes/kubernetes.git"
readonly UPSTREAM_IMAGE_TAG="k8s-mock-kms-plugin-upstream"
readonly IMAGE_TAG="k8s-mock-kms-plugin"
K8S_BRANCH="${K8S_BRANCH:-master}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

echo "Cloning Kubernetes (${K8S_BRANCH})..."
git clone --depth 1 --branch "${K8S_BRANCH}" "${K8S_REPO_URL}" "${TMP_DIR}/kubernetes"

CONTEXT_DIR="${TMP_DIR}/kubernetes/staging/src/k8s.io"
DOCKERFILE_PATH="${CONTEXT_DIR}/kms/internal/plugins/_mock/Dockerfile"

echo "Building upstream image ${UPSTREAM_IMAGE_TAG}..."
docker build \
  --platform linux/amd64 \
  -t "${UPSTREAM_IMAGE_TAG}" \
  -f "${DOCKERFILE_PATH}" \
  "${CONTEXT_DIR}"

echo "Building wrapper image ${IMAGE_TAG}..."
docker build \
  --platform linux/amd64 \
  -t "${IMAGE_TAG}" \
  --build-arg "UPSTREAM_IMAGE=${UPSTREAM_IMAGE_TAG}" \
  -f "${SCRIPT_DIR}/Dockerfile" \
  "${SCRIPT_DIR}/../../../../.."

echo "Done. Image built: ${IMAGE_TAG}"
