package controllers

import (
	"context"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	apiserverconfigv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
	"k8s.io/client-go/tools/cache"

	corev1 "k8s.io/api/core/v1"

	configv1 "github.com/openshift/api/config/v1"

	"github.com/openshift/library-go/pkg/operator/encryption/encryptiondata"
	"github.com/openshift/library-go/pkg/operator/encryption/secrets"
	"github.com/openshift/library-go/pkg/operator/encryption/state"
	"github.com/openshift/library-go/pkg/operator/encryption/statemachine"
)

func createEncryptionCfgSecret(t *testing.T, targetNs string, revision string, encryptionCfg *encryptiondata.Config) *corev1.Secret {
	t.Helper()

	s, err := encryptiondata.ToSecret(targetNs, fmt.Sprintf("%s-%s", "encryption-config", revision), encryptionCfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

var alwaysFulfilledPreconditions = func() (bool, error) { return true, nil }

type testProvider struct {
	encryptedGRs []schema.GroupResource
}

func newTestProvider(encryptedGRs []schema.GroupResource) Provider {
	return &testProvider{encryptedGRs: encryptedGRs}
}

func (p *testProvider) EncryptedGRs() []schema.GroupResource {
	return p.encryptedGRs
}

func (p *testProvider) ShouldRunEncryptionControllers() (bool, error) {
	return true, nil
}

// fakeEncryptionDeployer is a minimal statemachine.Deployer for unit tests that need to control the deployed encryption config and revision convergence.
type fakeEncryptionDeployer struct {
	secret    *corev1.Secret
	converged bool
	err       error
}

func (f *fakeEncryptionDeployer) DeployedEncryptionConfigSecret(_ context.Context) (*corev1.Secret, bool, error) {
	return f.secret, f.converged, f.err
}

func (f *fakeEncryptionDeployer) AddEventHandler(_ cache.ResourceEventHandler) (cache.ResourceEventHandlerRegistration, error) {
	return nil, nil
}

func (f *fakeEncryptionDeployer) HasSynced() bool { return true }

var _ statemachine.Deployer = &fakeEncryptionDeployer{}

func newKMSVaultAPIServer() *configv1.APIServer {
	return &configv1.APIServer{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
		Spec: configv1.APIServerSpec{
			Encryption: configv1.APIServerEncryption{
				Type: configv1.EncryptionTypeKMS,
				KMS: configv1.KMSPluginConfig{
					Type:  configv1.VaultKMSProvider,
					Vault: wellKnownBaseVaultConfig,
				},
			},
		},
	}
}

// newExistingKMSKeySecret builds a migrated KMS key secret whose plugin config differs from the
// current apiserver config so needsNewKey reports kms-provider-changed.
func newExistingKMSKeySecret(t *testing.T, instanceName string, apiServer *configv1.APIServer, encryptedGRs []schema.GroupResource, keyID string) *corev1.Secret {
	t.Helper()

	oldPlugin := apiServer.Spec.Encryption.KMS
	oldPlugin.Vault.VaultKeyPath = "transit/keys/old-key"
	ks := state.KeyState{
		Key:  apiserverconfigv1.Key{Name: keyID, Secret: base64.StdEncoding.EncodeToString(make([]byte, 16))},
		Mode: state.KMS,
		Migrated: state.MigrationState{
			Resources: encryptedGRs,
		},
		KMS: &state.KMSState{
			Encryption: &apiserverconfigv1.KMSConfiguration{
				APIVersion: "v2",
				Name:       keyID,
				Endpoint:   fmt.Sprintf("unix:///var/run/kmsplugin/kms-%s.sock", keyID),
				Timeout:    &metav1.Duration{Duration: 10 * time.Second},
			},
			Plugin: oldPlugin,
		},
	}
	if err := ks.KMS.PluginSecretData.Set("vault-approle", "role-id", []byte("old-role-id")); err != nil {
		t.Fatalf("failed to set plugin secret data: %v", err)
	}
	if err := ks.KMS.PluginSecretData.Set("vault-approle", "secret-id", []byte("old-secret-id")); err != nil {
		t.Fatalf("failed to set plugin secret data: %v", err)
	}
	if err := ks.KMS.PluginConfigMapData.Set("vault-ca-bundle", "ca-bundle.crt", []byte("old-ca-cert")); err != nil {
		t.Fatalf("failed to set plugin configmap data: %v", err)
	}
	s, err := secrets.FromKeyState(instanceName, ks)
	if err != nil {
		t.Fatalf("failed to build existing key secret: %v", err)
	}
	return s
}

// newDeployedKMSEncryptionConfig builds a converged encryption-config secret as the state controller would after the given key secrets are write keys.
func newDeployedKMSEncryptionConfig(t *testing.T, instanceName string, encryptedGRs []schema.GroupResource, keySecrets ...*corev1.Secret) *corev1.Secret {
	t.Helper()

	desired := statemachine.GetDesiredEncryptionState(nil, keySecrets, encryptedGRs)
	cfg, err := encryptiondata.FromEncryptionState(desired)
	if err != nil {
		t.Fatalf("failed to build intermediate encryption config: %v", err)
	}
	// Second pass promotes the write key once read keys are present.
	desired = statemachine.GetDesiredEncryptionState(cfg, keySecrets, encryptedGRs)
	cfg, err = encryptiondata.FromEncryptionState(desired)
	if err != nil {
		t.Fatalf("failed to build deployed encryption config: %v", err)
	}
	secret, err := encryptiondata.ToSecret("openshift-config-managed", "encryption-config-"+instanceName, cfg)
	if err != nil {
		t.Fatalf("failed to serialize deployed encryption config: %v", err)
	}
	return secret
}
