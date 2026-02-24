#!/usr/bin/env bash
set -euo pipefail

readonly K8S_REPO_URL="https://github.com/kubernetes/kubernetes.git"
readonly IMAGE_TAG="k8s-mock-kms-plugin"
K8S_BRANCH="${K8S_BRANCH:-master}"

TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

echo "Cloning Kubernetes (${K8S_BRANCH})..."
git clone --depth 1 --branch "${K8S_BRANCH}" "${K8S_REPO_URL}" "${TMP_DIR}/kubernetes"

CONTEXT_DIR="${TMP_DIR}/kubernetes/staging/src/k8s.io"
DOCKERFILE_PATH="${CONTEXT_DIR}/kms/internal/plugins/_mock/Dockerfile"

echo "Building image ${IMAGE_TAG}..."
docker build \
  --platform linux/amd64 \
  -t "${IMAGE_TAG}" \
  -f "${DOCKERFILE_PATH}" \
  "${CONTEXT_DIR}"

echo "Done. Image built: ${IMAGE_TAG}"