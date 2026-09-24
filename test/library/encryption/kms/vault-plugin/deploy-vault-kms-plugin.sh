#!/bin/bash

# Vault KMS v2 Plugin Deployer for OpenShift
# This deploys a KMS v2 plugin that connects to HashiCorp Vault Transit engine
# 
# Prerequisites:
#   - Vault Transit engine setup (run setup-vault-transit-kms.sh first)
#   - AppRole credentials (Role ID and Secret ID)
#   - oc CLI logged into OpenShift cluster

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
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

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# Configuration - can be overridden by environment variables
KMS_NAMESPACE="${KMS_NAMESPACE:-openshift-kms-plugin}"
KMS_PLUGIN_IMAGE="${KMS_PLUGIN_IMAGE:-quay.io/openshifttest/vault-kms-plugin:latest}"
KMS_SOCKET_PATH="${KMS_SOCKET_PATH:-/var/run/kmsplugin/kms.sock}"

# Vault configuration - MUST be provided
VAULT_ADDR="${VAULT_ADDR:-}"
VAULT_TRANSIT_KEY="${VAULT_TRANSIT_KEY:-kubernetes-encryption}"
VAULT_ROLE_ID="${VAULT_ROLE_ID:-}"
VAULT_SECRET_ID="${VAULT_SECRET_ID:-}"
VAULT_NAMESPACE="${VAULT_NAMESPACE:-vault}"

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Deploy Vault KMS v2 plugin on OpenShift control-plane nodes.

Options:
    --vault-addr        Vault server address (e.g., http://vault.vault.svc:8200)
    --vault-key         Vault Transit key name (default: kubernetes-encryption)
    --role-id           Vault AppRole Role ID
    --secret-id         Vault AppRole Secret ID
    --namespace         Namespace for KMS plugin (default: openshift-kms-plugin)
    --image             KMS plugin image (default: quay.io/openshifttest/vault-kms-plugin:latest)
    --cleanup           Remove KMS plugin deployment
    --status            Check KMS plugin status
    --help              Show this help message

Environment Variables:
    VAULT_ADDR          Vault server address
    VAULT_TRANSIT_KEY   Transit key name
    VAULT_ROLE_ID       AppRole Role ID
    VAULT_SECRET_ID     AppRole Secret ID
    KMS_NAMESPACE       KMS plugin namespace
    KMS_PLUGIN_IMAGE    KMS plugin container image

Examples:
    # Deploy with credentials
    $0 --vault-addr http://vault.vault.svc:8200 \\
       --role-id abc123 --secret-id xyz789

    # Check status
    $0 --status

    # Cleanup
    $0 --cleanup
EOF
}

# Parse arguments
CLEANUP=false
STATUS=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --vault-addr)
            VAULT_ADDR="$2"
            shift 2
            ;;
        --vault-key)
            VAULT_TRANSIT_KEY="$2"
            shift 2
            ;;
        --role-id)
            VAULT_ROLE_ID="$2"
            shift 2
            ;;
        --secret-id)
            VAULT_SECRET_ID="$2"
            shift 2
            ;;
        --namespace)
            KMS_NAMESPACE="$2"
            shift 2
            ;;
        --image)
            KMS_PLUGIN_IMAGE="$2"
            shift 2
            ;;
        --cleanup)
            CLEANUP=true
            shift
            ;;
        --status)
            STATUS=true
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

# Check prerequisites
check_prerequisites() {
    log_step "Checking prerequisites..."
    
    if ! command -v oc &> /dev/null; then
        log_error "oc CLI is not installed"
        exit 1
    fi

    if ! oc whoami &> /dev/null; then
        log_error "Not logged into OpenShift cluster"
        exit 1
    fi

    log_info "Prerequisites satisfied"
}

# Cleanup function
cleanup() {
    log_step "Cleaning up Vault KMS plugin..."

    # Delete DaemonSet
    oc delete daemonset vault-kms-plugin -n ${KMS_NAMESPACE} 2>/dev/null || true

    # Delete Secret
    oc delete secret vault-kms-plugin-credentials -n ${KMS_NAMESPACE} 2>/dev/null || true

    # Delete ServiceAccount
    oc delete serviceaccount vault-kms-plugin -n ${KMS_NAMESPACE} 2>/dev/null || true

    # Delete RoleBinding
    oc delete rolebinding vault-kms-plugin -n ${KMS_NAMESPACE} 2>/dev/null || true

    # Delete Namespace
    oc delete namespace ${KMS_NAMESPACE} --wait=false 2>/dev/null || true

    log_info "Cleanup complete"
}

# Status function
status() {
    log_step "Checking Vault KMS plugin status..."

    echo ""
    log_info "Namespace: ${KMS_NAMESPACE}"
    
    if ! oc get namespace ${KMS_NAMESPACE} &>/dev/null; then
        log_warn "Namespace ${KMS_NAMESPACE} does not exist"
        return
    fi

    echo ""
    log_info "DaemonSet:"
    oc get daemonset vault-kms-plugin -n ${KMS_NAMESPACE} 2>/dev/null || log_warn "DaemonSet not found"

    echo ""
    log_info "Pods:"
    oc get pods -n ${KMS_NAMESPACE} -l app=vault-kms-plugin 2>/dev/null || log_warn "No pods found"

    echo ""
    log_info "Pod Logs (last 20 lines from first pod):"
    FIRST_POD=$(oc get pods -n ${KMS_NAMESPACE} -l app=vault-kms-plugin -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
    if [ -n "$FIRST_POD" ]; then
        oc logs -n ${KMS_NAMESPACE} ${FIRST_POD} --tail=20 2>/dev/null || log_warn "Could not get logs"
    fi

    echo ""
    log_info "Socket check on first pod:"
    if [ -n "$FIRST_POD" ]; then
        oc exec -n ${KMS_NAMESPACE} ${FIRST_POD} -- ls -la /var/run/kmsplugin/ 2>/dev/null || log_warn "Could not check socket"
    fi
}

# Deploy function
deploy() {
    # Validate required parameters
    if [ -z "$VAULT_ADDR" ]; then
        # Try to auto-detect from Vault namespace
        if oc get namespace ${VAULT_NAMESPACE} &>/dev/null; then
            VAULT_ADDR="http://vault.${VAULT_NAMESPACE}.svc.cluster.local:8200"
            log_info "Auto-detected Vault address: ${VAULT_ADDR}"
        else
            log_error "VAULT_ADDR is required. Use --vault-addr or set VAULT_ADDR env var"
            exit 1
        fi
    fi

    if [ -z "$VAULT_ROLE_ID" ] || [ -z "$VAULT_SECRET_ID" ]; then
        log_error "VAULT_ROLE_ID and VAULT_SECRET_ID are required"
        log_info "Run setup-vault-transit-kms.sh first to get credentials"
        exit 1
    fi

    log_step "Deploying Vault KMS v2 plugin..."
    log_info "Namespace: ${KMS_NAMESPACE}"
    log_info "Vault Address: ${VAULT_ADDR}"
    log_info "Transit Key: ${VAULT_TRANSIT_KEY}"
    log_info "Image: ${KMS_PLUGIN_IMAGE}"

    # Step 1: Create Namespace
    log_step "Creating namespace..."
    cat <<EOF | oc apply -f -
apiVersion: v1
kind: Namespace
metadata:
  name: ${KMS_NAMESPACE}
  labels:
    pod-security.kubernetes.io/enforce: privileged
    pod-security.kubernetes.io/audit: privileged
    pod-security.kubernetes.io/warn: privileged
EOF

    # Step 2: Create ServiceAccount
    log_step "Creating ServiceAccount..."
    cat <<EOF | oc apply -f -
apiVersion: v1
kind: ServiceAccount
metadata:
  name: vault-kms-plugin
  namespace: ${KMS_NAMESPACE}
EOF

    # Step 3: Create RoleBinding for privileged SCC
    log_step "Creating RoleBinding..."
    cat <<EOF | oc apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: vault-kms-plugin
  namespace: ${KMS_NAMESPACE}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:openshift:scc:privileged
subjects:
  - kind: ServiceAccount
    name: vault-kms-plugin
    namespace: ${KMS_NAMESPACE}
EOF

    # Step 4: Create Secret with Vault credentials
    log_step "Creating Vault credentials secret..."
    cat <<EOF | oc apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: vault-kms-plugin-credentials
  namespace: ${KMS_NAMESPACE}
type: Opaque
stringData:
  role-id: "${VAULT_ROLE_ID}"
  secret-id: "${VAULT_SECRET_ID}"
EOF

    # Step 5: Create DaemonSet
    log_step "Creating DaemonSet..."
    cat <<EOF | oc apply -f -
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: vault-kms-plugin
  namespace: ${KMS_NAMESPACE}
spec:
  selector:
    matchLabels:
      app: vault-kms-plugin
  template:
    metadata:
      labels:
        app: vault-kms-plugin
    spec:
      nodeSelector:
        node-role.kubernetes.io/control-plane: ""
      priorityClassName: system-node-critical
      serviceAccountName: vault-kms-plugin
      tolerations:
        - operator: Exists
      containers:
        - name: kms-plugin
          image: ${KMS_PLUGIN_IMAGE}
          imagePullPolicy: IfNotPresent
          securityContext:
            privileged: true
          args:
            - "-listen-addr=unix://${KMS_SOCKET_PATH}"
            - "-vault-addr=${VAULT_ADDR}"
            - "-transit-key=${VAULT_TRANSIT_KEY}"
            - "-role-id-file=/etc/vault-credentials/role-id"
            - "-secret-id-file=/etc/vault-credentials/secret-id"
          volumeMounts:
            - name: socket
              mountPath: /var/run/kmsplugin
            - name: vault-credentials
              mountPath: /etc/vault-credentials
              readOnly: true
      volumes:
        - name: socket
          hostPath:
            path: /var/run/kmsplugin
            type: DirectoryOrCreate
        - name: vault-credentials
          secret:
            secretName: vault-kms-plugin-credentials
EOF

    # Step 7: Wait for DaemonSet
    log_step "Waiting for DaemonSet to be ready..."
    
    for i in {1..60}; do
        DESIRED=$(oc get daemonset vault-kms-plugin -n ${KMS_NAMESPACE} -o jsonpath='{.status.desiredNumberScheduled}' 2>/dev/null || echo "0")
        READY=$(oc get daemonset vault-kms-plugin -n ${KMS_NAMESPACE} -o jsonpath='{.status.numberReady}' 2>/dev/null || echo "0")
        
        if [ "$DESIRED" -gt 0 ] && [ "$READY" -eq "$DESIRED" ]; then
            log_info "DaemonSet ready: ${READY}/${DESIRED} pods"
            break
        fi
        
        log_info "Waiting... ${READY}/${DESIRED} pods ready"
        sleep 5
    done

    # Final status
    echo ""
    log_info "=========================================="
    log_info "Vault KMS Plugin Deployment Complete!"
    log_info "=========================================="
    
    status
    
    echo ""
    log_info "Next Steps:"
    echo "  1. Verify plugin is connecting to Vault (check logs above)"
    echo "  2. Configure API server to use KMS encryption"
    echo "  3. Test encryption with: oc create secret generic test-secret --from-literal=key=value"
    echo ""
    log_info "Socket path for API server config: unix://${KMS_SOCKET_PATH}"
}

# Main
check_prerequisites

if [ "$CLEANUP" = true ]; then
    cleanup
    exit 0
fi

if [ "$STATUS" = true ]; then
    status
    exit 0
fi

deploy
