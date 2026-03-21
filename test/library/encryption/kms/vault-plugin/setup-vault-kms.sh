#!/bin/bash
# Simple Vault KMS v2 Setup Script
# This script sets up Vault and deploys the KMS v2 plugin for testing.

set -e

echo "=== Vault KMS v2 Setup ==="

# Step 1: Deploy Vault
echo ""
echo "[1/5] Deploying Vault..."
helm repo add hashicorp https://helm.releases.hashicorp.com 2>/dev/null || true
helm repo update

if helm status vault -n vault >/dev/null 2>&1; then
    echo "Vault already installed, skipping..."
else
    oc create namespace vault --dry-run=client -o yaml | oc apply -f -
    helm install vault hashicorp/vault \
        --namespace vault \
        --set "global.openshift=true" \
        --set "server.image.repository=docker.io/hashicorp/vault" \
        --set "server.image.tag=1.15.4" \
        --set "server.dev.enabled=true" \
        --set "server.dev.devRootToken=root" \
        --set "injector.enabled=false" \
        --wait --timeout 5m
fi

echo "Waiting for Vault pod..."
oc wait --for=condition=Ready pod -l app.kubernetes.io/name=vault -n vault --timeout=120s

# Step 2: Configure Transit Engine
echo ""
echo "[2/5] Configuring Vault Transit Engine..."
oc exec -n vault vault-0 -- vault secrets enable transit 2>/dev/null || echo "Transit already enabled"
oc exec -n vault vault-0 -- vault write -f transit/keys/kubernetes-encryption 2>/dev/null || echo "Key already exists"

# Step 3: Configure AppRole
echo ""
echo "[3/5] Configuring AppRole authentication..."
oc exec -n vault vault-0 -- vault auth enable approle 2>/dev/null || echo "AppRole already enabled"

# Create policy
oc exec -n vault vault-0 -- sh -c 'vault policy write kms-policy - <<EOF
path "transit/encrypt/kubernetes-encryption" { capabilities = ["update"] }
path "transit/decrypt/kubernetes-encryption" { capabilities = ["update"] }
path "transit/keys/kubernetes-encryption" { capabilities = ["read"] }
EOF'

# Create role
oc exec -n vault vault-0 -- vault write auth/approle/role/kms-plugin \
    token_policies="kms-policy" token_ttl=1h token_max_ttl=24h secret_id_ttl=0

# Get credentials
echo ""
echo "[4/5] Getting AppRole credentials..."
ROLE_ID=$(oc exec -n vault vault-0 -- vault read -field=role_id auth/approle/role/kms-plugin/role-id)
SECRET_ID=$(oc exec -n vault vault-0 -- vault write -field=secret_id -f auth/approle/role/kms-plugin/secret-id)

echo "Role ID: $ROLE_ID"
echo "Secret ID: $SECRET_ID"

# Step 5: Deploy KMS Plugin
echo ""
echo "[5/5] Deploying Vault KMS v2 Plugin..."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

./deploy-vault-kms-plugin.sh \
    --vault-addr http://vault.vault.svc.cluster.local:8200 \
    --role-id "$ROLE_ID" \
    --secret-id "$SECRET_ID"

echo ""
echo "=== Setup Complete ==="
echo "Socket path: unix:///var/run/kmsplugin/kms.sock"
