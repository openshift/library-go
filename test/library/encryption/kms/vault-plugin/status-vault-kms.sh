#!/bin/bash
# Check Vault KMS v2 Status

echo "=== Vault KMS v2 Status ==="

echo ""
echo "[Vault]"
oc get pods -n vault 2>/dev/null || echo "Vault namespace not found"

echo ""
echo "[KMS Plugin]"
oc get pods -n openshift-kms-plugin -l app=vault-kms-plugin 2>/dev/null || echo "KMS plugin not found"

echo ""
echo "[KMS Plugin Logs]"
FIRST_POD=$(oc get pods -n openshift-kms-plugin -l app=vault-kms-plugin -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
if [ -n "$FIRST_POD" ]; then
    oc logs -n openshift-kms-plugin "$FIRST_POD" --tail=10 2>/dev/null
else
    echo "No KMS plugin pods found"
fi

echo ""
echo "[Socket Check]"
if [ -n "$FIRST_POD" ]; then
    oc exec -n openshift-kms-plugin "$FIRST_POD" -- ls -la /var/run/kmsplugin/ 2>/dev/null || echo "Could not check socket"
fi
