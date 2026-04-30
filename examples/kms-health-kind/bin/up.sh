#!/usr/bin/env bash
#
# Create a KIND cluster named ${CLUSTER} (default: kms-health-claude)
# with a KMSv2 fake plugin (static pod) and a health-monitor Deployment
# pinned to the control-plane node. Self-contained — doesn't depend on
# kubernetes/kubernetes/hack/local-up-kms.
#
# Run from the library-go module root.

set -o errexit
set -o nounset
set -o pipefail

# Force docker — this harness's Dockerfiles build with `docker build`
# and `kind load docker-image` needs the same backend. User may have
# KIND_EXPERIMENTAL_PROVIDER=podman set globally; unset locally.
unset KIND_EXPERIMENTAL_PROVIDER

CLUSTER="${CLUSTER:-kms-health-claude}"
KIND_NODE_IMAGE="${KIND_NODE_IMAGE:-kindest/node:v1.33.0}"

HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"

echo "[up.sh] cluster=${CLUSTER} node=${KIND_NODE_IMAGE}"
echo "[up.sh] harness-dir=${HARNESS_DIR}"

# kind.yaml uses paths relative to the harness dir (manifests/...).
cd "${HARNESS_DIR}"

# 1) Create the cluster (idempotent).
if kind get clusters 2>/dev/null | grep -qx "${CLUSTER}"; then
    echo "[up.sh] cluster ${CLUSTER} already exists, reusing"
else
    echo "[up.sh] creating kind cluster ${CLUSTER}"
    kind create cluster \
        --name "${CLUSTER}" \
        --image "${KIND_NODE_IMAGE}" \
        --config manifests/kind.yaml
fi

CTX="kind-${CLUSTER}"
NODE="${CLUSTER}-control-plane"
STATIC_POD="kms-fake-plugin-${NODE}"

# 2) Load our local images.
echo "[up.sh] loading images into cluster"
kind load docker-image kms-health-kind-fake-plugin:dev --name "${CLUSTER}"
kind load docker-image kms-health-kind-monitor:dev --name "${CLUSTER}"

# 3) Force the static pod to restart so it picks up the freshly-loaded
#    image (kubelet may have cached an ErrImageNeverPull from before).
echo "[up.sh] bouncing fake-plugin container so it picks up loaded image"
FAKE_CID="$(docker exec "${NODE}" crictl ps --name fake-plugin -q 2>/dev/null | head -1 || true)"
if [ -n "${FAKE_CID}" ]; then
    docker exec "${NODE}" crictl stop "${FAKE_CID}" >/dev/null || true
fi

# 4) Apply namespace + RBAC + monitor Deployment. The status ConfigMap
#    is created by the writer itself on first observation; nothing
#    pre-creates it.
echo "[up.sh] applying namespace, RBAC, monitor Deployment"
kubectl --context "${CTX}" apply -f manifests/namespace.yaml
kubectl --context "${CTX}" apply -f manifests/rbac.yaml
kubectl --context "${CTX}" apply -f manifests/monitor-deployment.yaml

# 5) Wait for the monitor Deployment to be Available. Apiserver is NOT
#    wired to KMS here (see manifests/kind.yaml) — we're only
#    validating the monitor, not apiserver/KMS integration.
echo "[up.sh] waiting for monitor Deployment"
kubectl --context "${CTX}" -n kms-health-test rollout status deployment/kms-health-monitor-fake --timeout=120s

MONITOR_POD="$(kubectl --context "${CTX}" -n kms-health-test get pod \
    -l app=kms-health-monitor-fake \
    -o jsonpath='{.items[0].metadata.name}')"
echo "[up.sh] done."
echo "  cluster:      ${CLUSTER}"
echo "  monitor pod:  ${MONITOR_POD} (kms-health-test)"
echo "  status cm:    kms-health-fake (kms-health-test)"
echo "  fake plugin:  ${STATIC_POD} (kube-system, static)"
echo ""
echo "Try:"
echo "  kubectl --context ${CTX} -n kms-health-test get cm kms-health-fake -o yaml"
