package controllers

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/diff"
	clocktesting "k8s.io/utils/clock/testing"
	sigsyaml "sigs.k8s.io/yaml"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"

	"github.com/openshift/library-go/pkg/controller/factory"
	encryptiontesting "github.com/openshift/library-go/pkg/operator/encryption/testing"
	"github.com/openshift/library-go/pkg/operator/events"
)

var (
	testSecretGR     = schema.GroupResource{Resource: "secrets"}
	testEncryptedGRs = []schema.GroupResource{testSecretGR}
	aescbcRawKey     = []byte("61def964fb967f5d7c44a2af8dab6865")

	// testKMSPluginConfig has no external secret or configmap references so the
	// expected key secret can be fully expressed as a literal YAML string.
	testKMSPluginConfig = configv1.KMSPluginConfig{
		Type: configv1.VaultKMSProvider,
		Vault: configv1.VaultKMSPluginConfig{
			KMSPluginImage: "vault-kms-plugin:latest",
			VaultAddress:   "https://vault.example.com",
			Authentication: configv1.VaultAuthentication{
				Type:    configv1.VaultAuthenticationTypeAppRole,
				AppRole: configv1.VaultAppRoleAuthentication{}, // no secret reference
			},
			VaultKeyPath: "transit/keys/mykey",
		},
	}
)

func TestComputeEncryptionConfigSecretWithNewKey(t *testing.T) {
	aescbcKey7Secret := encryptiontesting.CreateExpiredMigratedEncryptionKeySecretWithRawKey(
		"openshift-config-managed", testEncryptedGRs, 7, aescbcRawKey,
	)

	scenarios := []struct {
		name               string
		existingKeySecrets []*corev1.Secret // inputs: key secrets already in the cluster

		wantNewKeySecret    string // expected: YAML of the newly computed key secret
		wantEncConfigSecret string // expected: YAML of the computed encryption config secret
	}{
		{
			name:               "fresh KMS setup: no existing keys",
			existingKeySecrets: nil,

			wantNewKeySecret: `
data:
  encryption.apiserver.operator.openshift.io-key: AAAAAAAAAAAAAAAAAAAAAA==
  encryption.apiserver.operator.openshift.io-kms-encryption-config: eyJraW5kIjoiRW5jcnlwdGlvbkNvbmZpZ3VyYXRpb24iLCJhcGlWZXJzaW9uIjoiYXBpc2VydmVyLmNvbmZpZy5rOHMuaW8vdjEiLCJyZXNvdXJjZXMiOlt7InJlc291cmNlcyI6bnVsbCwicHJvdmlkZXJzIjpbeyJrbXMiOnsiYXBpVmVyc2lvbiI6InYyIiwibmFtZSI6IjEiLCJlbmRwb2ludCI6InVuaXg6Ly8vdmFyL3J1bi9rbXNwbHVnaW4va21zLTEuc29jayIsInRpbWVvdXQiOiIxMHMifX1dfV19Cg==
  encryption.apiserver.operator.openshift.io-kms-plugin-config: eyJraW5kIjoiQVBJU2VydmVyIiwiYXBpVmVyc2lvbiI6ImNvbmZpZy5vcGVuc2hpZnQuaW8vdjEiLCJtZXRhZGF0YSI6e30sInNwZWMiOnsic2VydmluZ0NlcnRzIjp7fSwiY2xpZW50Q0EiOnsibmFtZSI6IiJ9LCJlbmNyeXB0aW9uIjp7ImttcyI6eyJ0eXBlIjoiVmF1bHQiLCJ2YXVsdCI6eyJrbXNQbHVnaW5JbWFnZSI6InZhdWx0LWttcy1wbHVnaW46bGF0ZXN0IiwidmF1bHRBZGRyZXNzIjoiaHR0cHM6Ly92YXVsdC5leGFtcGxlLmNvbSIsImF1dGhlbnRpY2F0aW9uIjp7InR5cGUiOiJBcHBSb2xlIn0sInZhdWx0S2V5UGF0aCI6InRyYW5zaXQva2V5cy9teWtleSJ9fX0sImF1ZGl0Ijp7fX0sInN0YXR1cyI6e319Cg==
metadata:
  annotations:
    encryption.apiserver.operator.openshift.io/external-reason: ""
    encryption.apiserver.operator.openshift.io/internal-reason: secrets-key-does-not-exist
    encryption.apiserver.operator.openshift.io/mode: KMS
    kubernetes.io/description: |-
      WARNING: DO NOT EDIT.
      Altering of the encryption secrets will render you cluster inaccessible.
      Catastrophic data loss can occur from the most minor changes.
  finalizers:
  - encryption.apiserver.operator.openshift.io/deletion-protection
  labels:
    encryption.apiserver.operator.openshift.io/component: test-component
  name: encryption-key-test-component-1
  namespace: openshift-config-managed
type: Opaque
`,

			// State machine places the new KMS key as a read key on the first
			// pass; write key promotion happens after the config converges.
			wantEncConfigSecret: `
apiVersion: v1
data:
  encryption-config: eyJraW5kIjoiRW5jcnlwdGlvbkNvbmZpZ3VyYXRpb24iLCJhcGlWZXJzaW9uIjoiYXBpc2VydmVyLmNvbmZpZy5rOHMuaW8vdjEiLCJyZXNvdXJjZXMiOlt7InJlc291cmNlcyI6WyJzZWNyZXRzIl0sInByb3ZpZGVycyI6W3siaWRlbnRpdHkiOnt9fSx7ImttcyI6eyJhcGlWZXJzaW9uIjoidjIiLCJuYW1lIjoiMV9zZWNyZXRzIiwiZW5kcG9pbnQiOiJ1bml4Oi8vL3Zhci9ydW4va21zcGx1Z2luL2ttcy0xLnNvY2siLCJ0aW1lb3V0IjoiMTBzIn19XX1dfQo=
  kms-plugin-config-1: eyJraW5kIjoiQVBJU2VydmVyIiwiYXBpVmVyc2lvbiI6ImNvbmZpZy5vcGVuc2hpZnQuaW8vdjEiLCJtZXRhZGF0YSI6e30sInNwZWMiOnsic2VydmluZ0NlcnRzIjp7fSwiY2xpZW50Q0EiOnsibmFtZSI6IiJ9LCJlbmNyeXB0aW9uIjp7ImttcyI6eyJ0eXBlIjoiVmF1bHQiLCJ2YXVsdCI6eyJrbXNQbHVnaW5JbWFnZSI6InZhdWx0LWttcy1wbHVnaW46bGF0ZXN0IiwidmF1bHRBZGRyZXNzIjoiaHR0cHM6Ly92YXVsdC5leGFtcGxlLmNvbSIsImF1dGhlbnRpY2F0aW9uIjp7InR5cGUiOiJBcHBSb2xlIn0sInZhdWx0S2V5UGF0aCI6InRyYW5zaXQva2V5cy9teWtleSJ9fX0sImF1ZGl0Ijp7fX0sInN0YXR1cyI6e319Cg==
kind: Secret
metadata:
  annotations:
    kubernetes.io/description: |-
      WARNING: DO NOT EDIT.
      Altering of the encryption secrets will render you cluster inaccessible.
      Catastrophic data loss can occur from the most minor changes.
  finalizers:
  - encryption.apiserver.operator.openshift.io/deletion-protection
  name: encryption-config-test-component
  namespace: openshift-config-managed
type: Opaque
`,
		},
		{
			name:               "migrating from AESCBC to KMS: one fully-migrated AESCBC key exists",
			existingKeySecrets: []*corev1.Secret{aescbcKey7Secret},

			wantNewKeySecret: `
data:
  encryption.apiserver.operator.openshift.io-key: AAAAAAAAAAAAAAAAAAAAAA==
  encryption.apiserver.operator.openshift.io-kms-encryption-config: eyJraW5kIjoiRW5jcnlwdGlvbkNvbmZpZ3VyYXRpb24iLCJhcGlWZXJzaW9uIjoiYXBpc2VydmVyLmNvbmZpZy5rOHMuaW8vdjEiLCJyZXNvdXJjZXMiOlt7InJlc291cmNlcyI6bnVsbCwicHJvdmlkZXJzIjpbeyJrbXMiOnsiYXBpVmVyc2lvbiI6InYyIiwibmFtZSI6IjgiLCJlbmRwb2ludCI6InVuaXg6Ly8vdmFyL3J1bi9rbXNwbHVnaW4va21zLTguc29jayIsInRpbWVvdXQiOiIxMHMifX1dfV19Cg==
  encryption.apiserver.operator.openshift.io-kms-plugin-config: eyJraW5kIjoiQVBJU2VydmVyIiwiYXBpVmVyc2lvbiI6ImNvbmZpZy5vcGVuc2hpZnQuaW8vdjEiLCJtZXRhZGF0YSI6e30sInNwZWMiOnsic2VydmluZ0NlcnRzIjp7fSwiY2xpZW50Q0EiOnsibmFtZSI6IiJ9LCJlbmNyeXB0aW9uIjp7ImttcyI6eyJ0eXBlIjoiVmF1bHQiLCJ2YXVsdCI6eyJrbXNQbHVnaW5JbWFnZSI6InZhdWx0LWttcy1wbHVnaW46bGF0ZXN0IiwidmF1bHRBZGRyZXNzIjoiaHR0cHM6Ly92YXVsdC5leGFtcGxlLmNvbSIsImF1dGhlbnRpY2F0aW9uIjp7InR5cGUiOiJBcHBSb2xlIn0sInZhdWx0S2V5UGF0aCI6InRyYW5zaXQva2V5cy9teWtleSJ9fX0sImF1ZGl0Ijp7fX0sInN0YXR1cyI6e319Cg==
metadata:
  annotations:
    encryption.apiserver.operator.openshift.io/external-reason: ""
    encryption.apiserver.operator.openshift.io/internal-reason: secrets-encryption-mode-changed
    encryption.apiserver.operator.openshift.io/mode: KMS
    kubernetes.io/description: |-
      WARNING: DO NOT EDIT.
      Altering of the encryption secrets will render you cluster inaccessible.
      Catastrophic data loss can occur from the most minor changes.
  finalizers:
  - encryption.apiserver.operator.openshift.io/deletion-protection
  labels:
    encryption.apiserver.operator.openshift.io/component: test-component
  name: encryption-key-test-component-8
  namespace: openshift-config-managed
type: Opaque
`,

			// Both the new KMS key (8) and the existing AESCBC key (7) appear
			// as read keys; write key promotion happens after convergence.
			wantEncConfigSecret: `
apiVersion: v1
data:
  encryption-config: eyJraW5kIjoiRW5jcnlwdGlvbkNvbmZpZ3VyYXRpb24iLCJhcGlWZXJzaW9uIjoiYXBpc2VydmVyLmNvbmZpZy5rOHMuaW8vdjEiLCJyZXNvdXJjZXMiOlt7InJlc291cmNlcyI6WyJzZWNyZXRzIl0sInByb3ZpZGVycyI6W3siaWRlbnRpdHkiOnt9fSx7ImttcyI6eyJhcGlWZXJzaW9uIjoidjIiLCJuYW1lIjoiOF9zZWNyZXRzIiwiZW5kcG9pbnQiOiJ1bml4Oi8vL3Zhci9ydW4va21zcGx1Z2luL2ttcy04LnNvY2siLCJ0aW1lb3V0IjoiMTBzIn19LHsiYWVzY2JjIjp7ImtleXMiOlt7Im5hbWUiOiI3Iiwic2VjcmV0IjoiTmpGa1pXWTVOalJtWWprMk4yWTFaRGRqTkRSaE1tRm1PR1JoWWpZNE5qVT0ifV19fV19XX0K
  kms-plugin-config-8: eyJraW5kIjoiQVBJU2VydmVyIiwiYXBpVmVyc2lvbiI6ImNvbmZpZy5vcGVuc2hpZnQuaW8vdjEiLCJtZXRhZGF0YSI6e30sInNwZWMiOnsic2VydmluZ0NlcnRzIjp7fSwiY2xpZW50Q0EiOnsibmFtZSI6IiJ9LCJlbmNyeXB0aW9uIjp7ImttcyI6eyJ0eXBlIjoiVmF1bHQiLCJ2YXVsdCI6eyJrbXNQbHVnaW5JbWFnZSI6InZhdWx0LWttcy1wbHVnaW46bGF0ZXN0IiwidmF1bHRBZGRyZXNzIjoiaHR0cHM6Ly92YXVsdC5leGFtcGxlLmNvbSIsImF1dGhlbnRpY2F0aW9uIjp7InR5cGUiOiJBcHBSb2xlIn0sInZhdWx0S2V5UGF0aCI6InRyYW5zaXQva2V5cy9teWtleSJ9fX0sImF1ZGl0Ijp7fX0sInN0YXR1cyI6e319Cg==
kind: Secret
metadata:
  annotations:
    kubernetes.io/description: |-
      WARNING: DO NOT EDIT.
      Altering of the encryption secrets will render you cluster inaccessible.
      Catastrophic data loss can occur from the most minor changes.
  finalizers:
  - encryption.apiserver.operator.openshift.io/deletion-protection
  name: encryption-config-test-component
  namespace: openshift-config-managed
type: Opaque
`,
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			computer := newTestEncryptionComputer(scenario.existingKeySecrets)
			syncCtx := newTestSyncContext()

			gotNewKeySecret, err := computer.ComputeKeySecret(context.Background(), syncCtx)
			if err != nil {
				t.Fatalf("ComputeKeySecret: %v", err)
			}
			if !equality.Semantic.DeepEqual(gotNewKeySecret, mustParseSecret(t, scenario.wantNewKeySecret)) {
				t.Errorf("new key secret mismatch:\n%s", diff.Diff(mustParseSecret(t, scenario.wantNewKeySecret), gotNewKeySecret))
			}

			gotEncConfigSecret, _, err := computer.ComputeEncryptionConfigSecretWithNewKey(context.Background(), syncCtx)
			if err != nil {
				t.Fatalf("ComputeEncryptionConfigSecretWithNewKey: %v", err)
			}
			if !equality.Semantic.DeepEqual(gotEncConfigSecret, mustParseSecret(t, scenario.wantEncConfigSecret)) {
				t.Errorf("encryption config secret mismatch:\n%s", diff.Diff(mustParseSecret(t, scenario.wantEncConfigSecret), gotEncConfigSecret))
			}
		})
	}
}

func mustParseSecret(t *testing.T, yamlStr string) *corev1.Secret {
	t.Helper()
	s := &corev1.Secret{}
	if err := sigsyaml.Unmarshal([]byte(yamlStr), s); err != nil {
		t.Fatalf("mustParseSecret: %v", err)
	}
	return s
}

func newTestEncryptionComputer(existingKeySecrets []*corev1.Secret) *EncryptionComputer {
	instanceName := "test-component"
	provider := &fakeProvider{encryptedGRs: testEncryptedGRs}

	noDeployedConfig := func(_ context.Context) (*corev1.Secret, bool, error) {
		return nil, true, nil
	}
	listExistingKeys := func(_ context.Context) ([]*corev1.Secret, error) {
		return existingKeySecrets, nil
	}

	keyCtrl := &keyController{
		instanceName:                     instanceName,
		provider:                         provider,
		getAPIServerAndOperatorSpecFn: func(_ context.Context) (*configv1.APIServer, *operatorv1.OperatorSpec, error) {
			return &configv1.APIServer{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec: configv1.APIServerSpec{
					Encryption: configv1.APIServerEncryption{
						Type: "KMS",
						KMS:  testKMSPluginConfig,
					},
				},
			}, &operatorv1.OperatorSpec{}, nil
		},
		deployedEncryptionConfigSecretFn: noDeployedConfig,
		listKeySecretsFn:                 listExistingKeys,
		getKMSPluginSecretFn: func(_ context.Context, _ string) (*corev1.Secret, error) {
			return nil, nil // not called: testKMSPluginConfig has no secret reference
		},
		getKMSPluginConfigMapFn: func(_ context.Context, _ string) (*corev1.ConfigMap, error) {
			return nil, nil // not called: testKMSPluginConfig has no configmap reference
		},
	}

	stateCtrl := &stateController{
		instanceName:                     instanceName,
		provider:                         provider,
		deployedEncryptionConfigSecretFn: noDeployedConfig,
		listKeySecretsFn:                 listExistingKeys,
	}

	return NewEncryptionComputer(keyCtrl, stateCtrl)
}

func newTestSyncContext() factory.SyncContext {
	recorder := events.NewRecorder(nil, "test", &corev1.ObjectReference{}, clocktesting.NewFakePassiveClock(time.Now()))
	return factory.NewSyncContext("test", recorder)
}

var _ Provider = &fakeProvider{}

type fakeProvider struct {
	encryptedGRs []schema.GroupResource
}

func (f *fakeProvider) EncryptedGRs() []schema.GroupResource          { return f.encryptedGRs }
func (f *fakeProvider) ShouldRunEncryptionControllers() (bool, error) { return true, nil }
