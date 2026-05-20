package kms

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/clock"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	library "github.com/openshift/library-go/test/library/encryption"
)

const (
	defaultVaultNamespace         = "vault-kms"
	defaultVaultPodName           = "vault-0"
	defaultVaultCredentialsSecret = "vault-credentials"
	defaultVaultAppRoleSecretName = "vault-approle-secret"
	defaultVaultKMSPluginImage    = "quay.io/openshifttest/mock-kms-plugin@sha256:03bb07a2c08b509653c4c70217a06a4b389c10b4d87922f50ee5eac82db5e140"
	defaultVaultAddress           = "https://vault.vault-kms.svc:8200"
	defaultVaultEnterpriseNS      = "admin"
	defaultVaultTransitMount      = "transit"
	defaultVaultTransitKey        = "kms-key"
	defaultAppRoleTargetNamespace = "openshift-config"
	vaultCommandTimeout           = 30 * time.Second
)

// DefaultVaultEncryptionProvider is a ready-to-use Vault KMS EncryptionProvider for e2e tests.
// It bundles the default config with the AppRole secret setup.
var DefaultVaultEncryptionProvider = library.EncryptionProvider{
	APIServerEncryption: DefaultVaultKMSPluginConfig,
	Setup:               ensureDefaultVaultAppRoleSecret,
}

// DefaultVaultKMSPluginConfig is the standard Vault KMS encryption config
// used by CI e2e tests.
var DefaultVaultKMSPluginConfig = configv1.APIServerEncryption{
	Type: configv1.EncryptionTypeKMS,
	KMS: configv1.KMSPluginConfig{
		Type: configv1.VaultKMSProvider,
		Vault: configv1.VaultKMSPluginConfig{
			KMSPluginImage: defaultVaultKMSPluginImage,
			VaultAddress:   defaultVaultAddress,
			VaultNamespace: defaultVaultEnterpriseNS,
			TransitMount:   defaultVaultTransitMount,
			TransitKey:     defaultVaultTransitKey,
			Authentication: configv1.VaultAuthentication{
				Type: configv1.VaultAuthenticationTypeAppRole,
				AppRole: configv1.VaultAppRoleAuthentication{
					Secret: configv1.VaultSecretReference{Name: defaultVaultAppRoleSecretName},
				},
			},
		},
	},
}

// DefaultFakeKMSPluginConfig is a fake Vault KMS configuration used by unit tests.
var DefaultFakeKMSPluginConfig = configv1.KMSPluginConfig{
	Type: configv1.VaultKMSProvider,
	Vault: configv1.VaultKMSPluginConfig{
		KMSPluginImage: WellKnownUpstreamMockKMSPluginImage,
		VaultAddress:   "https://vault.example.com",
		Authentication: configv1.VaultAuthentication{
			Type: configv1.VaultAuthenticationTypeAppRole,
			AppRole: configv1.VaultAppRoleAuthentication{
				Secret: configv1.VaultSecretReference{Name: "vault-approle-secret"},
			},
		},
		TransitKey: "test-transit-key",
	},
}

// ensureDefaultVaultAppRoleSecret reads credentials from the vault-credentials secret
// (created by a CI step) and applies the AppRole secret in openshift-config
// using the default configuration constants.
func ensureDefaultVaultAppRoleSecret(ctx context.Context, t testing.TB) {
	t.Helper()
	cs := library.GetClients(t)

	creds, err := cs.Kube.CoreV1().Secrets(defaultVaultNamespace).Get(ctx, defaultVaultCredentialsSecret, metav1.GetOptions{})
	require.NoError(t, err, "failed to read %s/%s secret (was the vault-install CI step run?)", defaultVaultNamespace, defaultVaultCredentialsSecret)

	required := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      defaultVaultAppRoleSecretName,
			Namespace: defaultAppRoleTargetNamespace,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"roleID":   creds.Data["role-id"],
			"secretID": creds.Data["secret-id"],
		},
	}
	recorder := events.NewInMemoryRecorder("vault-approle-secret-setup", clock.RealClock{})
	_, changed, err := resourceapply.ApplySecret(ctx, cs.Kube.CoreV1(), recorder, required)
	require.NoError(t, err, "failed to apply AppRole secret")
	t.Logf("Applied AppRole secret %s in %s (changed=%v)", defaultVaultAppRoleSecretName, defaultAppRoleTargetNamespace, changed)
}

// RotateVaultTransitKey rotates the Vault transit encryption key. All old key versions are retained.
// Reference: https://developer.hashicorp.com/vault/api-docs/secret/transit#rotate-key
// Steps:
// 1. Get initial key version
// 2. Execute 'vault write -f transit/keys/<key-name>/rotate' via oc exec
// 3. Get new key version and validate it increased
func RotateVaultTransitKey(ctx context.Context, t testing.TB) {
	t.Helper()

	initialVersion := getCurrentKeyVersion(ctx, t)
	rotateKey(ctx, t)
	newVersion := getCurrentKeyVersion(ctx, t)

	require.Greater(t, newVersion, initialVersion, "rotation failed: version did not increase (before=%d, after=%d)", initialVersion, newVersion)
}

// rotateKey executes the vault key rotation command
func rotateKey(ctx context.Context, t testing.TB) {
	t.Helper()
	commandCtx, cancel := context.WithTimeout(ctx, vaultCommandTimeout)
	defer cancel()

	// Command: vault write -f transit/keys/<key-name>/rotate
	// Reference: https://developer.hashicorp.com/vault/api-docs/secret/transit#rotate-key
	cmd := exec.CommandContext(commandCtx, "oc", "exec", defaultVaultPodName, "-n", defaultVaultNamespace, "--",
		"vault", "write", "-f", fmt.Sprintf("transit/keys/%s/rotate", defaultVaultTransitKey))

	t.Logf("Executing: %s", cmd.String())
	output, err := cmd.Output()
	if ee, ok := err.(*exec.ExitError); ok {
		require.NoError(t, err, "vault key rotation failed, stderr: %s", string(ee.Stderr))
	}
	require.NoError(t, err, "vault key rotation failed")
	t.Logf("Command output: %s", string(output))
}

// getCurrentKeyVersion retrieves the current (latest) key version
func getCurrentKeyVersion(ctx context.Context, t testing.TB) int {
	t.Helper()
	commandCtx, cancel := context.WithTimeout(ctx, vaultCommandTimeout)
	defer cancel()

	cmd := exec.CommandContext(commandCtx, "oc", "exec", defaultVaultPodName, "-n", defaultVaultNamespace, "--",
		"vault", "read", "-field=latest_version", fmt.Sprintf("transit/keys/%s", defaultVaultTransitKey))

	t.Logf("Executing: %s", cmd.String())
	output, err := cmd.Output()
	if ee, ok := err.(*exec.ExitError); ok {
		require.NoError(t, err, "failed to read key version, stderr: %s", string(ee.Stderr))
	}
	require.NoError(t, err, "failed to read key version")
	t.Logf("Command output: %s", string(output))

	version, err := strconv.Atoi(strings.TrimSpace(string(output)))
	require.NoError(t, err, "failed to parse key version from output: %q", string(output))

	return version
}
