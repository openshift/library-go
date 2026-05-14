package kms

import (
	"testing"

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
	defaultVaultCredentialsSecret = "vault-credentials"
	defaultVaultAppRoleSecretName = "vault-approle-secret"
	defaultVaultKMSPluginImage    = "quay.io/openshifttest/mock-kms-plugin@sha256:03bb07a2c08b509653c4c70217a06a4b389c10b4d87922f50ee5eac82db5e140"
	defaultVaultAddress           = "https://vault.vault-kms.svc:8200"
	defaultVaultEnterpriseNS      = "admin"
	defaultVaultTransitMount      = "transit"
	defaultVaultTransitKey        = "kms-key"
	defaultAppRoleTargetNamespace = "openshift-config"
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
func ensureDefaultVaultAppRoleSecret(t testing.TB) {
	t.Helper()
	ctx := t.Context()
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
