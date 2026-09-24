# Vault KMS v2 Plugin Deployer

This directory contains scripts for deploying a Vault-based KMS v2 plugin on OpenShift.

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  API Server     │────▶│  Vault KMS      │────▶│  HashiCorp      │
│  (kube-api)     │     │  Plugin         │     │  Vault          │
│                 │     │  (DaemonSet)    │     │  (Transit)      │
└─────────────────┘     └─────────────────┘     └─────────────────┘
        │                       │                       │
        │                       │                       │
   Encryption              Unix Socket            AppRole Auth
   Config                  /var/run/kmsplugin     Transit Engine
```

## Prerequisites

1. **HashiCorp Vault** deployed with Transit engine enabled
2. **AppRole credentials** (Role ID and Secret ID)
3. **oc CLI** logged into OpenShift cluster

## Quick Start

### Step 1: Setup Vault (if not already done)

Use the Vault setup script from [gangwgr/kms-setup](https://github.com/gangwgr/kms-setup):

```bash
curl -sL https://raw.githubusercontent.com/gangwgr/kms-setup/main/vault-kms-setup/setup-vault-transit-kms.sh | bash
```

This will output the AppRole credentials needed for the KMS plugin.

### Step 2: Deploy KMS Plugin

```bash
./deploy-vault-kms-plugin.sh \
  --vault-addr http://vault.vault.svc.cluster.local:8200 \
  --role-id <ROLE_ID> \
  --secret-id <SECRET_ID>
```

Or using environment variables:

```bash
export VAULT_ADDR="http://vault.vault.svc.cluster.local:8200"
export VAULT_ROLE_ID="abc123..."
export VAULT_SECRET_ID="xyz789..."
./deploy-vault-kms-plugin.sh
```

### Step 3: Check Status

```bash
./deploy-vault-kms-plugin.sh --status
```

### Step 4: Cleanup

```bash
./deploy-vault-kms-plugin.sh --cleanup
```

## Configuration Options

| Option | Environment Variable | Default | Description |
|--------|---------------------|---------|-------------|
| `--vault-addr` | `VAULT_ADDR` | Auto-detect | Vault server address |
| `--vault-key` | `VAULT_TRANSIT_KEY` | `kubernetes-encryption` | Transit key name |
| `--role-id` | `VAULT_ROLE_ID` | Required | AppRole Role ID |
| `--secret-id` | `VAULT_SECRET_ID` | Required | AppRole Secret ID |
| `--namespace` | `KMS_NAMESPACE` | `openshift-kms-plugin` | Plugin namespace |
| `--image` | `KMS_PLUGIN_IMAGE` | `quay.io/openshifttest/vault-kms-plugin:latest` | Plugin image |

## What Gets Deployed

1. **Namespace**: `openshift-kms-plugin` (with privileged pod security)
2. **ServiceAccount**: `vault-kms-plugin`
3. **RoleBinding**: Grants privileged SCC access
4. **Secret**: Vault AppRole credentials
5. **ConfigMap**: Plugin and Vault configuration
6. **DaemonSet**: KMS plugin running on control-plane nodes

## Socket Path

The KMS plugin listens on: `unix:///var/run/kmsplugin/kms.sock`

This path is mounted as a hostPath volume so the API server can access it.

## Differences from Mock KMS Plugin

| Feature | Mock KMS Plugin | Vault KMS Plugin |
|---------|-----------------|------------------|
| Backend | SoftHSM (local) | HashiCorp Vault |
| External Dependencies | None | Vault server |
| Key Management | Local PKCS11 | Vault Transit |
| Use Case | Testing | Production-like testing |
| Authentication | None | AppRole |

## Troubleshooting

### Check plugin logs

```bash
oc logs -n openshift-kms-plugin -l app=vault-kms-plugin
```

### Verify socket exists

```bash
oc exec -n openshift-kms-plugin <pod-name> -- ls -la /var/run/kmsplugin/
```

### Test Vault connectivity from plugin pod

```bash
oc exec -n openshift-kms-plugin <pod-name> -- curl -s $VAULT_ADDR/v1/sys/health
```

### Check AppRole authentication

```bash
oc exec -n openshift-kms-plugin <pod-name> -- \
  curl -s -X POST $VAULT_ADDR/v1/auth/approle/login \
  -d '{"role_id":"<ROLE_ID>","secret_id":"<SECRET_ID>"}'
```

## Files

- `deploy-vault-kms-plugin.sh` - Main deployment script
- `README.md` - This documentation

## Related

- [Mock KMS Plugin](../k8s-mock-plugin/) - Simple mock plugin using SoftHSM
- [Vault Setup Script](https://github.com/gangwgr/kms-setup) - Sets up Vault Transit engine
