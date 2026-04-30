#!/usr/bin/env bash
#
# Tear down the KIND cluster created by up.sh. Safe to re-run.

set -o errexit
set -o nounset
set -o pipefail

unset KIND_EXPERIMENTAL_PROVIDER

CLUSTER="${CLUSTER:-kms-health-claude}"

if kind get clusters 2>/dev/null | grep -qx "${CLUSTER}"; then
    echo "[down.sh] deleting kind cluster ${CLUSTER}"
    kind delete cluster --name "${CLUSTER}"
else
    echo "[down.sh] cluster ${CLUSTER} not found — nothing to do"
fi
