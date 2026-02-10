#!/bin/bash
# Cleanup Vault KMS v2 Setup

set -e

echo "=== Cleaning up Vault KMS v2 ==="

# Cleanup KMS plugin
echo "[1/2] Removing KMS plugin..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
./deploy-vault-kms-plugin.sh --cleanup 2>/dev/null || true

# Cleanup Vault (optional)
read -p "Also remove Vault? (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "[2/2] Removing Vault..."
    helm uninstall vault -n vault 2>/dev/null || true
    oc delete namespace vault --wait=false 2>/dev/null || true
    echo "Vault removed."
else
    echo "[2/2] Keeping Vault."
fi

echo ""
echo "=== Cleanup Complete ==="
