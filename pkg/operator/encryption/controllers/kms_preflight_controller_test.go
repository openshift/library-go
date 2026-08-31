package controllers

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	clocktesting "k8s.io/utils/clock/testing"

	"k8s.io/apimachinery/pkg/api/equality"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	configv1clientfake "github.com/openshift/client-go/config/clientset/versioned/fake"
	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/encryption/kms"
	encryptiontesting "github.com/openshift/library-go/pkg/operator/encryption/testing"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

var (
	wellKnownBaseVaultConfig = configv1.VaultKMSPluginConfig{
		VaultAddress: "https://vault.example.com:8200",
		Authentication: configv1.VaultAuthentication{
			Type: configv1.VaultAuthenticationTypeAppRole,
			AppRole: configv1.VaultAppRoleAuthentication{
				Secret: configv1.VaultSecretReference{Name: "vault-approle"},
			},
		},
		TLS: configv1.VaultTLSConfig{
			CABundle: configv1.VaultConfigMapReference{Name: "vault-ca-bundle"},
		},
		VaultKeyPath: "transit/keys/my-key",
	}

	wellKnownBaseSecret = corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "vault-approle", Namespace: "openshift-config"},
		Data: map[string][]byte{
			"role-id":   []byte("role-123"),
			"secret-id": []byte("secret-456"),
		},
	}

	wellKnownBaseConfigMap = corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "vault-ca-bundle", Namespace: "openshift-config"},
		Data:       map[string]string{"ca-bundle.crt": "test-ca-cert"},
	}
)

func TestKMSConfigHasher(t *testing.T) {
	// Each scenario changes exactly one field from the baseline and verifies the hash changes.
	// If the hash algorithm or encoding changes, update the expectedHash values by running
	// the test and copying the actual values from the error output.
	scenarios := []struct {
		name          string
		vaultConfig   configv1.VaultKMSPluginConfig
		resources     []runtime.Object
		expectedHash  string
		expectedError string
	}{
		{
			name:         "same config and resources produce the same hash",
			vaultConfig:  wellKnownBaseVaultConfig,
			resources:    []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			expectedHash: "cuZm_g==",
		},
		{
			name: "changing KMSPluginImage",
			vaultConfig: func() configv1.VaultKMSPluginConfig {
				c := wellKnownBaseVaultConfig
				c.KMSPluginImage = "registry.example.com/plugin@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
				return c
			}(),
			resources:    []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			expectedHash: "DP-Bbg==",
		},
		{
			name: "changing VaultAddress",
			vaultConfig: func() configv1.VaultKMSPluginConfig {
				c := wellKnownBaseVaultConfig
				c.VaultAddress = "https://other-vault.example.com:8200"
				return c
			}(),
			resources:    []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			expectedHash: "oHX1jw==",
		},
		{
			name: "changing VaultNamespace",
			vaultConfig: func() configv1.VaultKMSPluginConfig {
				c := wellKnownBaseVaultConfig
				c.VaultNamespace = "my-namespace"
				return c
			}(),
			resources:    []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			expectedHash: "lmrlhQ==",
		},
		{
			name: "changing VaultAuthNamespace",
			vaultConfig: func() configv1.VaultKMSPluginConfig {
				c := wellKnownBaseVaultConfig
				c.VaultAuthNamespace = "my-auth-namespace"
				return c
			}(),
			resources:    []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			expectedHash: "TZa3aA==",
		},
		{
			name: "changing VaultKeyPath",
			vaultConfig: func() configv1.VaultKMSPluginConfig {
				c := wellKnownBaseVaultConfig
				c.VaultKeyPath = "transit/keys/other-key"
				return c
			}(),
			resources:    []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			expectedHash: "BihuJg==",
		},
		{
			name: "changing TLS.ServerName",
			vaultConfig: func() configv1.VaultKMSPluginConfig {
				c := wellKnownBaseVaultConfig
				c.TLS.ServerName = "vault.example.com"
				return c
			}(),
			resources:    []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			expectedHash: "d8Xvrw==",
		},
		{
			name: "changing TLS.CABundle.Name",
			vaultConfig: func() configv1.VaultKMSPluginConfig {
				c := wellKnownBaseVaultConfig
				c.TLS.CABundle.Name = "other-ca-bundle"
				return c
			}(),
			resources: []runtime.Object{&wellKnownBaseSecret, &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "other-ca-bundle", Namespace: "openshift-config"},
				Data:       map[string]string{"ca-bundle.crt": "test-ca-cert"},
			}},
			expectedHash: "2UnFwA==",
		},
		{
			name: "changing Authentication.AppRole.Secret.Name",
			vaultConfig: func() configv1.VaultKMSPluginConfig {
				c := wellKnownBaseVaultConfig
				c.Authentication.AppRole.Secret.Name = "other-secret"
				return c
			}(),
			resources: []runtime.Object{&wellKnownBaseConfigMap, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "other-secret", Namespace: "openshift-config"},
				Data: map[string][]byte{
					"role-id":   []byte("role-123"),
					"secret-id": []byte("secret-456"),
				},
			}},
			expectedHash: "yHXRJw==",
		},
		{
			name:        "changing role-id value",
			vaultConfig: wellKnownBaseVaultConfig,
			resources: []runtime.Object{&wellKnownBaseConfigMap, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "vault-approle", Namespace: "openshift-config"},
				Data: map[string][]byte{
					"role-id":   []byte("role-999"),
					"secret-id": []byte("secret-456"),
				},
			}},
			expectedHash: "5Fa5pQ==",
		},
		{
			name:        "changing secret-id value",
			vaultConfig: wellKnownBaseVaultConfig,
			resources: []runtime.Object{&wellKnownBaseConfigMap, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "vault-approle", Namespace: "openshift-config"},
				Data: map[string][]byte{
					"role-id":   []byte("role-123"),
					"secret-id": []byte("secret-999"),
				},
			}},
			expectedHash: "vmQmnA==",
		},
		{
			name:        "extra key in secret does not change hash",
			vaultConfig: wellKnownBaseVaultConfig,
			resources: []runtime.Object{&wellKnownBaseConfigMap, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "vault-approle", Namespace: "openshift-config"},
				Data: map[string][]byte{
					"role-id":   []byte("role-123"),
					"secret-id": []byte("secret-456"),
					"extra":     []byte("ignored"),
				},
			}},
			expectedHash: "cuZm_g==",
		},
		{
			name:        "extra key in configmap does not change hash",
			vaultConfig: wellKnownBaseVaultConfig,
			resources: []runtime.Object{&wellKnownBaseSecret, &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "vault-ca-bundle", Namespace: "openshift-config"},
				Data:       map[string]string{"ca-bundle.crt": "test-ca-cert", "extra": "ignored"},
			}},
			expectedHash: "cuZm_g==",
		},
		{
			name:        "changing ca-bundle.crt value",
			vaultConfig: wellKnownBaseVaultConfig,
			resources: []runtime.Object{&wellKnownBaseSecret, &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "vault-ca-bundle", Namespace: "openshift-config"},
				Data:       map[string]string{"ca-bundle.crt": "different-ca-cert"},
			}},
			expectedHash: "BeRfNQ==",
		},
		{
			name: "no configmap configured",
			vaultConfig: func() configv1.VaultKMSPluginConfig {
				c := wellKnownBaseVaultConfig
				c.TLS.CABundle.Name = ""
				return c
			}(),
			resources:    []runtime.Object{&wellKnownBaseSecret},
			expectedHash: "CWffWA==",
		},
		{
			name:        "shifting bytes between secret keys produces a different hash",
			vaultConfig: wellKnownBaseVaultConfig,
			resources: []runtime.Object{&wellKnownBaseConfigMap, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "vault-approle", Namespace: "openshift-config"},
				Data: map[string][]byte{
					"role-id":   []byte("role-12"),
					"secret-id": []byte("3secret-456"),
				},
			}},
			expectedHash: "XV8KpA==",
		},
		{
			name:          "missing secret returns error",
			vaultConfig:   wellKnownBaseVaultConfig,
			resources:     []runtime.Object{&wellKnownBaseConfigMap},
			expectedError: "failed to get secret",
		},
		{
			name:        "missing key in secret returns error",
			vaultConfig: wellKnownBaseVaultConfig,
			resources: []runtime.Object{&wellKnownBaseConfigMap, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "vault-approle", Namespace: "openshift-config"},
				Data: map[string][]byte{
					"role-id": []byte("role-123"),
				},
			}},
			expectedError: `key "secret-id" not found in secret`,
		},
		{
			name:          "missing configmap returns error",
			vaultConfig:   wellKnownBaseVaultConfig,
			resources:     []runtime.Object{&wellKnownBaseSecret},
			expectedError: "failed to get configmap",
		},
		{
			name:        "missing key in configmap returns error",
			vaultConfig: wellKnownBaseVaultConfig,
			resources: []runtime.Object{&wellKnownBaseSecret, &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "vault-ca-bundle", Namespace: "openshift-config"},
				Data:       map[string]string{},
			}},
			expectedError: `key "ca-bundle.crt" not found in configmap`,
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			provider, err := newKMSProviderConfig(configv1.KMSPluginConfig{
				Type:  configv1.VaultKMSProvider,
				Vault: scenario.vaultConfig,
			})
			if err != nil {
				t.Fatal(err)
			}

			client := fake.NewSimpleClientset(scenario.resources...).CoreV1()
			hasher, err := newKMSConfigHasher(provider, newCoreClientKMSConfigHasherResourceProvider(client, client), "openshift-config")
			if err != nil {
				t.Fatalf("newKMSConfigHasher: %v", err)
			}
			got, err := hasher.hash(context.Background())

			if scenario.expectedError != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", scenario.expectedError)
				}
				if !strings.Contains(err.Error(), scenario.expectedError) {
					t.Fatalf("expected error containing %q, got: %v", scenario.expectedError, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got != scenario.expectedHash {
				t.Errorf("expected hash %q, got %q", scenario.expectedHash, got)
			}
		})
	}
}

type fakeDeployer struct {
	deployed                 bool
	cleaned                  bool
	cleanupCount             int
	deployErr                error
	statusErr                error
	cleanupErr               error
	deployedHash             string
	podStatus                corev1.PodStatus
	deployedEncryptionConfig *corev1.Secret
}

func (f *fakeDeployer) Deploy(_ context.Context, configHash string, encryptionConfig *corev1.Secret) error {
	f.deployed = true
	f.deployedHash = configHash
	f.deployedEncryptionConfig = encryptionConfig
	return f.deployErr
}

func (f *fakeDeployer) Status(_ context.Context) (string, corev1.PodStatus, error) {
	return f.deployedHash, f.podStatus, f.statusErr
}

func (f *fakeDeployer) Cleanup(_ context.Context) error {
	f.cleaned = true
	f.cleanupCount++
	return f.cleanupErr
}

type fakeEncryptionStatusProvider struct {
	observedConfigHash string
	writtenStatus      *operatorv1.KMSPreflightResult
	updateCallCount    int
	updateErr          error
}

func (f *fakeEncryptionStatusProvider) GetKMSEncryptionStatus(_ context.Context) (*operatorv1.KMSEncryptionStatus, error) {
	s := &operatorv1.KMSEncryptionStatus{}
	s.Preflight.ObservedConfigHash = f.observedConfigHash
	if f.writtenStatus != nil {
		s.Preflight.Result = *f.writtenStatus
	}
	return s, nil
}

func (f *fakeEncryptionStatusProvider) ApplyKMSEncryptionStatus(_ context.Context, _ string, _ *applyoperatorv1.KMSEncryptionStatusApplyConfiguration) error {
	return fmt.Errorf("not implemented")
}

func (f *fakeEncryptionStatusProvider) UpdateKMSEncryptionStatus(_ context.Context, mutateFn func(*operatorv1.KMSEncryptionStatus)) error {
	f.updateCallCount++
	if f.updateErr != nil {
		return f.updateErr
	}
	s := &operatorv1.KMSEncryptionStatus{}
	mutateFn(s)
	result := s.Preflight.Result
	f.writtenStatus = &result
	return nil
}

var _ kms.EncryptionStatusProvider = &fakeEncryptionStatusProvider{}

type fakeEncryptionConfigurationComputer struct {
	secret    *corev1.Secret
	err       error
	callCount int
}

func (f *fakeEncryptionConfigurationComputer) ComputeEncryptionConfiguration(_ context.Context) (*corev1.Secret, error) {
	f.callCount++
	return f.secret, f.err
}

var _ EncryptionConfigurationComputer = &fakeEncryptionConfigurationComputer{}

func TestKMSPreflightController(t *testing.T) {
	apiServerWithKMS := &configv1.APIServer{
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

	// Hash produced by kmsConfigHasher over wellKnownBaseVaultConfig, wellKnownBaseSecret,
	// and wellKnownBaseConfigMap. Verified by TestKMSConfigHasher.
	const wellKnownMatchingHashForBaseVaultConfig = "cuZm_g=="

	scenarios := []struct {
		name                                        string
		deployer                                    KMSPreflightDeployer
		encryptionConfigurationComputer             EncryptionConfigurationComputer
		expectedComputerCallCount                   int
		encryptionStatusProvider                    *fakeEncryptionStatusProvider
		apiServerObjects                            []runtime.Object
		coreObjects                                 []runtime.Object
		preconditionsMet                            bool
		expectedError                               string
		initialDirtyDeployer                        bool
		expectedPreflightDeployerCleanupCount       int
		expectedConditions                          []operatorv1.OperatorCondition
		expectedKMSPreflightResult                  *operatorv1.KMSPreflightResult
		expectedEncryptionStatusProviderUpdateCalls int
	}{
		{
			name:                     "preconditions not met, clears degraded and progressing",
			encryptionStatusProvider: &fakeEncryptionStatusProvider{},
			apiServerObjects:         []runtime.Object{&configv1.APIServer{ObjectMeta: metav1.ObjectMeta{Name: "cluster"}}},
			initialDirtyDeployer:     true,
			preconditionsMet:         false,
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "False"},
				{Type: "EncryptionKMSPreflightControllerProgressing", Status: "False"},
			},
		},
		{
			// Scenario 1a: result already Succeeded — cleanup only, no pod work.
			name:     "result already Succeeded, pod gone — cleanup and return without deploying",
			deployer: &fakeDeployer{statusErr: apierrors.NewNotFound(schema.GroupResource{Resource: "pods"}, "kms-preflight")},
			encryptionStatusProvider: &fakeEncryptionStatusProvider{
				observedConfigHash: wellKnownMatchingHashForBaseVaultConfig,
				writtenStatus: &operatorv1.KMSPreflightResult{
					Status:     operatorv1.KMSPreflightResultSucceeded,
					ConfigHash: wellKnownMatchingHashForBaseVaultConfig,
				},
			},
			apiServerObjects:                      []runtime.Object{apiServerWithKMS},
			coreObjects:                           []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			initialDirtyDeployer:                  true,
			preconditionsMet:                      true,
			expectedPreflightDeployerCleanupCount: 1,
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "False"},
				{Type: "EncryptionKMSPreflightControllerProgressing", Status: "False"},
			},
			expectedKMSPreflightResult: &operatorv1.KMSPreflightResult{
				Status:     operatorv1.KMSPreflightResultSucceeded,
				ConfigHash: wellKnownMatchingHashForBaseVaultConfig,
			},
		},
		{
			// Scenario 2a: terminal — admin must change config.
			name:     "result already Failed, pod manually removed — surface error without re-deploying",
			deployer: &fakeDeployer{statusErr: apierrors.NewNotFound(schema.GroupResource{Resource: "pods"}, "kms-preflight")},
			encryptionStatusProvider: &fakeEncryptionStatusProvider{
				observedConfigHash: wellKnownMatchingHashForBaseVaultConfig,
				writtenStatus: &operatorv1.KMSPreflightResult{
					Status:     operatorv1.KMSPreflightResultFailed,
					ConfigHash: wellKnownMatchingHashForBaseVaultConfig,
				},
			},
			apiServerObjects:     []runtime.Object{apiServerWithKMS},
			coreObjects:          []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			initialDirtyDeployer: true,
			preconditionsMet:     true,
			expectedError:        "preflight check failed for hash cuZm_g==: pod was removed but failure is recorded in status",
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "True", Reason: "PreflightCheckFailed", Message: "preflight check failed for hash cuZm_g==: pod was removed but failure is recorded in status"},
				{Type: "EncryptionKMSPreflightControllerProgressing", Status: "False"},
			},
			expectedKMSPreflightResult: &operatorv1.KMSPreflightResult{
				Status:     operatorv1.KMSPreflightResultFailed,
				ConfigHash: wellKnownMatchingHashForBaseVaultConfig,
			},
		},
		{
			// Scenario 2b: deploying — progressing.
			name:     "hashes match, no pod exists, deploys and returns",
			deployer: &fakeDeployer{statusErr: apierrors.NewNotFound(schema.GroupResource{Resource: "pods"}, "kms-preflight")},
			encryptionConfigurationComputer: &fakeEncryptionConfigurationComputer{secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "enc-config", Namespace: "test"},
			}},
			encryptionStatusProvider:  &fakeEncryptionStatusProvider{observedConfigHash: wellKnownMatchingHashForBaseVaultConfig},
			apiServerObjects:          []runtime.Object{apiServerWithKMS},
			coreObjects:               []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			initialDirtyDeployer:      true,
			preconditionsMet:          true,
			expectedComputerCallCount: 1,
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "False"},
				{Type: "EncryptionKMSPreflightControllerProgressing", Status: "True", Reason: "RunningPreflightCheck", Message: "Deploying preflight pod for hash cuZm_g=="},
			},
		},
		{
			// Stale Succeeded result (different ConfigHash) must not short-circuit to
			// cleanup: it does not apply to the required hash, so a fresh check deploys.
			name:     "result Succeeded for a stale hash, no pod exists — deploys for required hash",
			deployer: &fakeDeployer{statusErr: apierrors.NewNotFound(schema.GroupResource{Resource: "pods"}, "kms-preflight")},
			encryptionConfigurationComputer: &fakeEncryptionConfigurationComputer{secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "enc-config", Namespace: "test"},
			}},
			encryptionStatusProvider: &fakeEncryptionStatusProvider{
				observedConfigHash: wellKnownMatchingHashForBaseVaultConfig,
				writtenStatus: &operatorv1.KMSPreflightResult{
					Status:     operatorv1.KMSPreflightResultSucceeded,
					ConfigHash: "stale-hash",
				},
			},
			apiServerObjects:          []runtime.Object{apiServerWithKMS},
			coreObjects:               []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			initialDirtyDeployer:      true,
			preconditionsMet:          true,
			expectedComputerCallCount: 1,
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "False"},
				{Type: "EncryptionKMSPreflightControllerProgressing", Status: "True", Reason: "RunningPreflightCheck", Message: "Deploying preflight pod for hash cuZm_g=="},
			},
			expectedKMSPreflightResult: &operatorv1.KMSPreflightResult{
				Status:     operatorv1.KMSPreflightResultSucceeded,
				ConfigHash: "stale-hash",
			},
		},
		{
			// Scenario 2b: computer fails before deploy.
			name:                            "encryption configuration computer fails, reports error",
			deployer:                        &fakeDeployer{statusErr: apierrors.NewNotFound(schema.GroupResource{Resource: "pods"}, "kms-preflight")},
			encryptionConfigurationComputer: &fakeEncryptionConfigurationComputer{err: fmt.Errorf("vault unreachable")},
			encryptionStatusProvider:        &fakeEncryptionStatusProvider{observedConfigHash: wellKnownMatchingHashForBaseVaultConfig},
			apiServerObjects:                []runtime.Object{apiServerWithKMS},
			coreObjects:                     []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			initialDirtyDeployer:            true,
			preconditionsMet:                true,
			expectedComputerCallCount:       1,
			expectedError:                   "failed to compute encryption configuration: vault unreachable",
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "True", Reason: "Error", Message: "failed to compute encryption configuration: vault unreachable"},
				{Type: "EncryptionKMSPreflightControllerProgressing", Status: "False"},
			},
		},
		{
			// Scenario 3d: hash matches, no result, pod running — progressing.
			name: "pod exists, hash matches, no result yet, requeues",
			deployer: &fakeDeployer{podStatus: corev1.PodStatus{
				Conditions: []corev1.PodCondition{
					{Type: KMSPreflightConfigHashPodCondition, Message: wellKnownMatchingHashForBaseVaultConfig},
				},
			}},
			encryptionStatusProvider: &fakeEncryptionStatusProvider{observedConfigHash: wellKnownMatchingHashForBaseVaultConfig},
			apiServerObjects:         []runtime.Object{apiServerWithKMS},
			coreObjects:              []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			initialDirtyDeployer:     true,
			preconditionsMet:         true,
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "False"},
				{Type: "EncryptionKMSPreflightControllerProgressing", Status: "True", Reason: "RunningPreflightCheck", Message: "Waiting for preflight pod to report result for cuZm_g=="},
			},
		},
		{
			// Scenario 3c: terminal — pod exited without reporting hash.
			name: "pod succeeded without reporting hash, reports error",
			deployer: &fakeDeployer{podStatus: corev1.PodStatus{
				Phase: corev1.PodSucceeded,
			}},
			encryptionStatusProvider: &fakeEncryptionStatusProvider{observedConfigHash: wellKnownMatchingHashForBaseVaultConfig},
			apiServerObjects:         []runtime.Object{apiServerWithKMS},
			coreObjects:              []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			initialDirtyDeployer:     true,
			preconditionsMet:         true,
			expectedError:            "preflight pod completed without reporting result for hash cuZm_g==",
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "True", Reason: "PodCompletedWithoutResult", Message: "preflight pod completed without reporting result for hash cuZm_g=="},
				{Type: "EncryptionKMSPreflightControllerProgressing", Status: "False"},
			},
		},
		{
			// Scenario 3d: terminal — pod exited without reporting result.
			name: "pod succeeded without reporting result after hash posted, reports error",
			deployer: &fakeDeployer{podStatus: corev1.PodStatus{
				Phase: corev1.PodSucceeded,
				Conditions: []corev1.PodCondition{
					{Type: KMSPreflightConfigHashPodCondition, Message: wellKnownMatchingHashForBaseVaultConfig},
				},
			}},
			encryptionStatusProvider: &fakeEncryptionStatusProvider{observedConfigHash: wellKnownMatchingHashForBaseVaultConfig},
			apiServerObjects:         []runtime.Object{apiServerWithKMS},
			coreObjects:              []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			initialDirtyDeployer:     true,
			preconditionsMet:         true,
			expectedError:            "preflight pod completed without reporting result for hash cuZm_g==",
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "True", Reason: "PodCompletedWithoutResult", Message: "preflight pod completed without reporting result for hash cuZm_g=="},
				{Type: "EncryptionKMSPreflightControllerProgressing", Status: "False"},
			},
		},
		{
			// Scenario 3e: check passed — done.
			name: "pod succeeded, cleans up immediately",
			deployer: &fakeDeployer{podStatus: corev1.PodStatus{
				Conditions: []corev1.PodCondition{
					{Type: KMSPreflightConfigHashPodCondition, Message: wellKnownMatchingHashForBaseVaultConfig},
					{Type: KMSPreflightResultPodCondition, Status: corev1.ConditionTrue, LastTransitionTime: metav1.Now()},
					{Type: KMSPreflightRemoteKeyIDPodCondition, Status: corev1.ConditionTrue, Message: "remote-key-abc"},
				},
			}},
			encryptionStatusProvider:                    &fakeEncryptionStatusProvider{observedConfigHash: wellKnownMatchingHashForBaseVaultConfig},
			apiServerObjects:                            []runtime.Object{apiServerWithKMS},
			coreObjects:                                 []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			initialDirtyDeployer:                        true,
			preconditionsMet:                            true,
			expectedPreflightDeployerCleanupCount:       1,
			expectedEncryptionStatusProviderUpdateCalls: 1,
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "False"},
				{Type: "EncryptionKMSPreflightControllerProgressing", Status: "False"},
			},
			expectedKMSPreflightResult: &operatorv1.KMSPreflightResult{
				Status:      operatorv1.KMSPreflightResultSucceeded,
				ConfigHash:  wellKnownMatchingHashForBaseVaultConfig,
				RemoteKeyID: "remote-key-abc",
			},
		},
		{
			// Scenario 3f: terminal — check failed.
			name: "pod exists, hash matches, result is False, reports error",
			deployer: &fakeDeployer{podStatus: corev1.PodStatus{
				Conditions: []corev1.PodCondition{
					{Type: KMSPreflightConfigHashPodCondition, Message: wellKnownMatchingHashForBaseVaultConfig},
					{Type: KMSPreflightResultPodCondition, Status: corev1.ConditionFalse, Message: "encrypt call failed", LastTransitionTime: metav1.Now()},
					{Type: KMSPreflightRemoteKeyIDPodCondition, Status: corev1.ConditionTrue, Message: "remote-key-xyz"},
				},
			}},
			encryptionStatusProvider: &fakeEncryptionStatusProvider{observedConfigHash: wellKnownMatchingHashForBaseVaultConfig},
			apiServerObjects:         []runtime.Object{apiServerWithKMS},
			coreObjects:              []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			initialDirtyDeployer:     true,
			preconditionsMet:         true,
			expectedError:            "preflight check failed for hash cuZm_g==: encrypt call failed",
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "True", Reason: "PreflightCheckFailed", Message: "preflight check failed for hash cuZm_g==: encrypt call failed"},
				{Type: "EncryptionKMSPreflightControllerProgressing", Status: "False"},
			},
			expectedEncryptionStatusProviderUpdateCalls: 1,
			expectedKMSPreflightResult: &operatorv1.KMSPreflightResult{
				Status:      operatorv1.KMSPreflightResultFailed,
				ConfigHash:  wellKnownMatchingHashForBaseVaultConfig,
				RemoteKeyID: "remote-key-xyz",
			},
		},
		{
			// Scenario 1a via shortcut: existingResult=Succeeded → cleanup, no pod work.
			name: "result already written for this hash (succeeded), ensurePreflightResult is a no-op",
			deployer: &fakeDeployer{podStatus: corev1.PodStatus{
				Conditions: []corev1.PodCondition{
					{Type: KMSPreflightConfigHashPodCondition, Message: wellKnownMatchingHashForBaseVaultConfig},
					{Type: KMSPreflightResultPodCondition, Status: corev1.ConditionTrue, LastTransitionTime: metav1.Now()},
				},
			}},
			encryptionStatusProvider: &fakeEncryptionStatusProvider{
				observedConfigHash: wellKnownMatchingHashForBaseVaultConfig,
				writtenStatus: &operatorv1.KMSPreflightResult{
					Status:     operatorv1.KMSPreflightResultSucceeded,
					ConfigHash: wellKnownMatchingHashForBaseVaultConfig,
				},
			},
			apiServerObjects:                            []runtime.Object{apiServerWithKMS},
			coreObjects:                                 []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			initialDirtyDeployer:                        true,
			preconditionsMet:                            true,
			expectedPreflightDeployerCleanupCount:       1,
			expectedEncryptionStatusProviderUpdateCalls: 0,
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "False"},
				{Type: "EncryptionKMSPreflightControllerProgressing", Status: "False"},
			},
			expectedKMSPreflightResult: &operatorv1.KMSPreflightResult{
				Status:     operatorv1.KMSPreflightResultSucceeded,
				ConfigHash: wellKnownMatchingHashForBaseVaultConfig,
			},
		},
		{
			// Scenario 3f: ensurePreflightResult is a no-op (already written), terminal.
			name: "result already written for this hash (failed), ensurePreflightResult is a no-op",
			deployer: &fakeDeployer{podStatus: corev1.PodStatus{
				Conditions: []corev1.PodCondition{
					{Type: KMSPreflightConfigHashPodCondition, Message: wellKnownMatchingHashForBaseVaultConfig},
					{Type: KMSPreflightResultPodCondition, Status: corev1.ConditionFalse, Message: "encrypt call failed", LastTransitionTime: metav1.Now()},
				},
			}},
			encryptionStatusProvider: &fakeEncryptionStatusProvider{
				observedConfigHash: wellKnownMatchingHashForBaseVaultConfig,
				writtenStatus: &operatorv1.KMSPreflightResult{
					Status:     operatorv1.KMSPreflightResultFailed,
					ConfigHash: wellKnownMatchingHashForBaseVaultConfig,
				},
			},
			apiServerObjects:     []runtime.Object{apiServerWithKMS},
			coreObjects:          []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			initialDirtyDeployer: true,
			preconditionsMet:     true,
			expectedEncryptionStatusProviderUpdateCalls: 0,
			expectedError: "preflight check failed for hash cuZm_g==: encrypt call failed",
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "True", Reason: "PreflightCheckFailed", Message: "preflight check failed for hash cuZm_g==: encrypt call failed"},
				{Type: "EncryptionKMSPreflightControllerProgressing", Status: "False"},
			},
			expectedKMSPreflightResult: &operatorv1.KMSPreflightResult{
				Status:     operatorv1.KMSPreflightResultFailed,
				ConfigHash: wellKnownMatchingHashForBaseVaultConfig,
			},
		},
		{
			// Scenario 3e: write result fails — transient error, not terminal.
			name: "UpdateKMSEncryptionStatus returns error, reports error",
			deployer: &fakeDeployer{podStatus: corev1.PodStatus{
				Conditions: []corev1.PodCondition{
					{Type: KMSPreflightConfigHashPodCondition, Message: wellKnownMatchingHashForBaseVaultConfig},
					{Type: KMSPreflightResultPodCondition, Status: corev1.ConditionTrue, LastTransitionTime: metav1.Now()},
				},
			}},
			encryptionStatusProvider: &fakeEncryptionStatusProvider{
				observedConfigHash: wellKnownMatchingHashForBaseVaultConfig,
				updateErr:          fmt.Errorf("status update failed"),
			},
			apiServerObjects:     []runtime.Object{apiServerWithKMS},
			coreObjects:          []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			initialDirtyDeployer: true,
			preconditionsMet:     true,
			expectedEncryptionStatusProviderUpdateCalls: 1,
			expectedError: "status update failed",
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "True", Reason: "Error", Message: "status update failed"},
				{Type: "EncryptionKMSPreflightControllerProgressing", Status: "False"},
			},
		},
		{
			// Scenario 3a: a Failed pod from a previous (bad) config must be reaped
			// once the config is corrected, so the fixed config can make progress.
			// The staleness is detected from the deployed hash, not the pod phase.
			name: "stale pod that failed for old config is cleaned up",
			deployer: &fakeDeployer{deployedHash: "old-hash", podStatus: corev1.PodStatus{
				Phase: corev1.PodFailed,
			}},
			encryptionStatusProvider:              &fakeEncryptionStatusProvider{observedConfigHash: wellKnownMatchingHashForBaseVaultConfig},
			apiServerObjects:                      []runtime.Object{apiServerWithKMS},
			coreObjects:                           []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			initialDirtyDeployer:                  true,
			preconditionsMet:                      true,
			expectedPreflightDeployerCleanupCount: 1,
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "False"},
				{Type: "EncryptionKMSPreflightControllerProgressing", Status: "True", Reason: "RunningPreflightCheck", Message: "Cleaning up preflight pod with stale configuration"},
			},
		},
		{
			// Scenario 3a: a stale pod that never ran (e.g. ImagePullBackOff) reports
			// no conditions, but the deployed hash from its annotation still lets the
			// controller detect it as stale and reap it. This is checked before the
			// phase/condition scenarios, so it works even after a controller restart.
			name: "stale pod that never ran is cleaned up",
			deployer: &fakeDeployer{deployedHash: "old-hash", podStatus: corev1.PodStatus{
				Phase: corev1.PodPending,
				ContainerStatuses: []corev1.ContainerStatus{
					{
						Name: "kms-preflight-check",
						State: corev1.ContainerState{
							Waiting: &corev1.ContainerStateWaiting{Reason: "ImagePullBackOff"},
						},
					},
				},
			}},
			encryptionStatusProvider:              &fakeEncryptionStatusProvider{observedConfigHash: wellKnownMatchingHashForBaseVaultConfig},
			apiServerObjects:                      []runtime.Object{apiServerWithKMS},
			coreObjects:                           []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			initialDirtyDeployer:                  true,
			preconditionsMet:                      true,
			expectedPreflightDeployerCleanupCount: 1,
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "False"},
				{Type: "EncryptionKMSPreflightControllerProgressing", Status: "True", Reason: "RunningPreflightCheck", Message: "Cleaning up preflight pod with stale configuration"},
			},
		},
		{
			// Scenario 3b: terminal — pod crashed.
			name: "pod crashed without reporting conditions, keeps pod for inspection",
			deployer: &fakeDeployer{podStatus: corev1.PodStatus{
				Phase: corev1.PodFailed,
				ContainerStatuses: []corev1.ContainerStatus{
					{
						Name: "kms-preflight-check",
						State: corev1.ContainerState{
							Terminated: &corev1.ContainerStateTerminated{
								ExitCode:   1,
								Message:    "connection refused",
								FinishedAt: metav1.Now(),
							},
						},
					},
				},
			}},
			encryptionStatusProvider: &fakeEncryptionStatusProvider{observedConfigHash: wellKnownMatchingHashForBaseVaultConfig},
			apiServerObjects:         []runtime.Object{apiServerWithKMS},
			coreObjects:              []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			initialDirtyDeployer:     true,
			preconditionsMet:         true,
			expectedError:            "preflight pod failed for hash cuZm_g==: at least one container kms-preflight-check exited with 1 (Unknown): connection refused",
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "True", Reason: "Unknown", Message: "preflight pod failed for hash cuZm_g==: at least one container kms-preflight-check exited with 1 (Unknown): connection refused"},
				{Type: "EncryptionKMSPreflightControllerProgressing", Status: "False"},
			},
		},
		{
			// Scenario 3c: no hash condition, pod running, no timeout — progressing.
			name: "pod exists, no hash condition yet, waits for pod to report",
			deployer: &fakeDeployer{podStatus: corev1.PodStatus{
				Phase: corev1.PodRunning,
			}},
			encryptionStatusProvider: &fakeEncryptionStatusProvider{observedConfigHash: wellKnownMatchingHashForBaseVaultConfig},
			apiServerObjects:         []runtime.Object{apiServerWithKMS},
			coreObjects:              []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			initialDirtyDeployer:     true,
			preconditionsMet:         true,
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "False"},
				{Type: "EncryptionKMSPreflightControllerProgressing", Status: "True", Reason: "RunningPreflightCheck", Message: "Waiting for preflight pod to report config hash for cuZm_g=="},
			},
		},
		{
			// Scenario 3c: terminal — no hash, timeout via PodScheduled condition fallback.
			name: "pod stuck in Pending with no StartTime, falls back to PodScheduled condition for timeout",
			deployer: &fakeDeployer{podStatus: corev1.PodStatus{
				Phase: corev1.PodPending,
				Conditions: []corev1.PodCondition{
					{Type: corev1.PodScheduled, Status: corev1.ConditionTrue, LastTransitionTime: metav1.Time{Time: time.Now().Add(-5 * time.Minute)}},
				},
			}},
			encryptionStatusProvider: &fakeEncryptionStatusProvider{observedConfigHash: wellKnownMatchingHashForBaseVaultConfig},
			apiServerObjects:         []runtime.Object{apiServerWithKMS},
			coreObjects:              []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			initialDirtyDeployer:     true,
			preconditionsMet:         true,
			expectedError:            "preflight pod has not reported config hash after 3m0s: pod is in Pending phase",
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "True", Reason: "Unknown", Message: "preflight pod has not reported config hash after 3m0s: pod is in Pending phase"},
				{Type: "EncryptionKMSPreflightControllerProgressing", Status: "False"},
			},
		},
		{
			// Scenario 3c: terminal — no hash, timeout via StartTime.
			name: "pod stuck in Pending without reporting hash, goes degraded with phase",
			deployer: &fakeDeployer{podStatus: corev1.PodStatus{
				Phase:     corev1.PodPending,
				StartTime: &metav1.Time{Time: time.Now().Add(-5 * time.Minute)},
			}},
			encryptionStatusProvider: &fakeEncryptionStatusProvider{observedConfigHash: wellKnownMatchingHashForBaseVaultConfig},
			apiServerObjects:         []runtime.Object{apiServerWithKMS},
			coreObjects:              []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			initialDirtyDeployer:     true,
			preconditionsMet:         true,
			expectedError:            "preflight pod has not reported config hash after 3m0s: pod is in Pending phase",
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "True", Reason: "Unknown", Message: "preflight pod has not reported config hash after 3m0s: pod is in Pending phase"},
				{Type: "EncryptionKMSPreflightControllerProgressing", Status: "False"},
			},
		},
		{
			// Scenario 3c: terminal — ImagePullBackOff timeout.
			name: "pod stuck with ImagePullBackOff, goes degraded with container reason",
			deployer: &fakeDeployer{podStatus: corev1.PodStatus{
				Phase:     corev1.PodPending,
				StartTime: &metav1.Time{Time: time.Now().Add(-5 * time.Minute)},
				ContainerStatuses: []corev1.ContainerStatus{
					{
						Name: "kms-preflight-check",
						State: corev1.ContainerState{
							Waiting: &corev1.ContainerStateWaiting{
								Reason:  "ImagePullBackOff",
								Message: "back-off pulling image",
							},
						},
					},
				},
			}},
			encryptionStatusProvider: &fakeEncryptionStatusProvider{observedConfigHash: wellKnownMatchingHashForBaseVaultConfig},
			apiServerObjects:         []runtime.Object{apiServerWithKMS},
			coreObjects:              []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			initialDirtyDeployer:     true,
			preconditionsMet:         true,
			expectedError:            "preflight pod has not reported config hash after 3m0s: at least one container kms-preflight-check is waiting: ImagePullBackOff: back-off pulling image",
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "True", Reason: "ImagePullBackOff", Message: "preflight pod has not reported config hash after 3m0s: at least one container kms-preflight-check is waiting: ImagePullBackOff: back-off pulling image"},
				{Type: "EncryptionKMSPreflightControllerProgressing", Status: "False"},
			},
		},
		{
			// Scenario 3d: terminal — timeout waiting for result.
			name: "pod stuck without reporting result past timeout, goes degraded",
			deployer: &fakeDeployer{podStatus: corev1.PodStatus{
				Phase:     corev1.PodRunning,
				StartTime: &metav1.Time{Time: time.Now().Add(-5 * time.Minute)},
				Conditions: []corev1.PodCondition{
					{Type: KMSPreflightConfigHashPodCondition, Message: wellKnownMatchingHashForBaseVaultConfig},
				},
			}},
			encryptionStatusProvider: &fakeEncryptionStatusProvider{observedConfigHash: wellKnownMatchingHashForBaseVaultConfig},
			apiServerObjects:         []runtime.Object{apiServerWithKMS},
			coreObjects:              []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			initialDirtyDeployer:     true,
			preconditionsMet:         true,
			expectedError:            "preflight pod has not reported result after 3m0s: pod is in Running phase",
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "True", Reason: "Unknown", Message: "preflight pod has not reported result after 3m0s: pod is in Running phase"},
				{Type: "EncryptionKMSPreflightControllerProgressing", Status: "False"},
			},
		},
		{
			// Scenario 2b: deploy error — transient, not terminal.
			name:                      "deploy fails, reports error",
			deployer:                  &fakeDeployer{statusErr: apierrors.NewNotFound(schema.GroupResource{Resource: "pods"}, "kms-preflight"), deployErr: fmt.Errorf("quota exceeded")},
			encryptionStatusProvider:  &fakeEncryptionStatusProvider{observedConfigHash: wellKnownMatchingHashForBaseVaultConfig},
			apiServerObjects:          []runtime.Object{apiServerWithKMS},
			coreObjects:               []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			initialDirtyDeployer:      true,
			preconditionsMet:          true,
			expectedComputerCallCount: 1,
			expectedError:             "quota exceeded",
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "True", Reason: "Error", Message: "quota exceeded"},
				{Type: "EncryptionKMSPreflightControllerProgressing", Status: "False"},
			},
		},
		{
			// Status API error — transient.
			name:                     "status returns unexpected error",
			deployer:                 &fakeDeployer{statusErr: fmt.Errorf("connection refused")},
			encryptionStatusProvider: &fakeEncryptionStatusProvider{observedConfigHash: wellKnownMatchingHashForBaseVaultConfig},
			apiServerObjects:         []runtime.Object{apiServerWithKMS},
			coreObjects:              []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			initialDirtyDeployer:     true,
			preconditionsMet:         true,
			expectedError:            "failed to get preflight pod status",
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "True", Reason: "Error", Message: "failed to get preflight pod status: connection refused"},
				{Type: "EncryptionKMSPreflightControllerProgressing", Status: "False"},
			},
		},
		{
			// Scenario 3a: cleanup error — transient, not terminal.
			name: "cleanup fails on stale hash, reports error",
			deployer: &fakeDeployer{
				cleanupErr:   fmt.Errorf("delete forbidden"),
				deployedHash: "old-hash",
			},
			encryptionStatusProvider:              &fakeEncryptionStatusProvider{observedConfigHash: wellKnownMatchingHashForBaseVaultConfig},
			apiServerObjects:                      []runtime.Object{apiServerWithKMS},
			coreObjects:                           []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			initialDirtyDeployer:                  true,
			preconditionsMet:                      true,
			expectedPreflightDeployerCleanupCount: 1,
			expectedError:                         "delete forbidden",
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "True", Reason: "Error", Message: "delete forbidden"},
				{Type: "EncryptionKMSPreflightControllerProgressing", Status: "False"},
			},
		},
		{
			// Scenario 3b: terminal — pod crashed, no terminated container.
			name: "pod crashed, no terminated container, keeps pod for inspection",
			deployer: &fakeDeployer{podStatus: corev1.PodStatus{
				Phase:   corev1.PodFailed,
				Message: "node lost",
			}},
			encryptionStatusProvider: &fakeEncryptionStatusProvider{observedConfigHash: wellKnownMatchingHashForBaseVaultConfig},
			apiServerObjects:         []runtime.Object{apiServerWithKMS},
			coreObjects:              []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			initialDirtyDeployer:     true,
			preconditionsMet:         true,
			expectedError:            "preflight pod failed for hash cuZm_g==: node lost",
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "True", Reason: "Unknown", Message: "preflight pod failed for hash cuZm_g==: node lost"},
				{Type: "EncryptionKMSPreflightControllerProgressing", Status: "False"},
			},
		},
		{
			// Scenario 3b: terminal — pod crashed with non-zero exit code.
			name: "pod crashed with terminated container, no message, uses exit code",
			deployer: &fakeDeployer{podStatus: corev1.PodStatus{
				Phase: corev1.PodFailed,
				ContainerStatuses: []corev1.ContainerStatus{
					{
						Name: "kms-preflight-check",
						State: corev1.ContainerState{
							Terminated: &corev1.ContainerStateTerminated{
								ExitCode: 137,
							},
						},
					},
				},
			}},
			encryptionStatusProvider: &fakeEncryptionStatusProvider{observedConfigHash: wellKnownMatchingHashForBaseVaultConfig},
			apiServerObjects:         []runtime.Object{apiServerWithKMS},
			coreObjects:              []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			initialDirtyDeployer:     true,
			preconditionsMet:         true,
			expectedError:            "preflight pod failed for hash cuZm_g==: at least one container kms-preflight-check exited with 137 (Unknown)",
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "True", Reason: "Unknown", Message: "preflight pod failed for hash cuZm_g==: at least one container kms-preflight-check exited with 137 (Unknown)"},
				{Type: "EncryptionKMSPreflightControllerProgressing", Status: "False"},
			},
		},
		{
			// Scenario 1: ObservedConfigHash mismatch — no work needed.
			name:                                  "hashes differ, config changed since ObservedConfigHash was written, cleans up",
			encryptionStatusProvider:              &fakeEncryptionStatusProvider{observedConfigHash: "stale-hash"},
			apiServerObjects:                      []runtime.Object{apiServerWithKMS},
			coreObjects:                           []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			initialDirtyDeployer:                  true,
			preconditionsMet:                      true,
			expectedPreflightDeployerCleanupCount: 1,
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "False"},
				{Type: "EncryptionKMSPreflightControllerProgressing", Status: "False"},
			},
		},
		{
			// Error computing hash — transient.
			name:                     "hash computation fails due to missing secret",
			encryptionStatusProvider: &fakeEncryptionStatusProvider{observedConfigHash: wellKnownMatchingHashForBaseVaultConfig},
			apiServerObjects:         []runtime.Object{apiServerWithKMS},
			coreObjects:              []runtime.Object{&wellKnownBaseConfigMap},
			initialDirtyDeployer:     true,
			preconditionsMet:         true,
			expectedError:            "failed to compute KMS config hash",
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "True", Reason: "Error", Message: `failed to compute KMS config hash: failed to get secret openshift-config/vault-approle: secrets "vault-approle" not found`},
				{Type: "EncryptionKMSPreflightControllerProgressing", Status: "False"},
			},
		},
		{
			// Scenario 1: empty ObservedConfigHash — nothing to do.
			name:                                  "empty ObservedConfigHash, cleans up",
			encryptionStatusProvider:              &fakeEncryptionStatusProvider{observedConfigHash: ""},
			apiServerObjects:                      []runtime.Object{apiServerWithKMS},
			coreObjects:                           []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			initialDirtyDeployer:                  true,
			preconditionsMet:                      true,
			expectedPreflightDeployerCleanupCount: 1,
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "False"},
				{Type: "EncryptionKMSPreflightControllerProgressing", Status: "False"},
			},
		},
		{
			// ObservedConfigHash is non-empty (set when KMS was active) but the
			// cluster has since reverted to identity encryption. The controller
			// must not degrade — the stale hash is irrelevant until KMS is
			// re-enabled and the key controller overwrites it.
			name: "ObservedConfigHash set but encryption reverted to identity — no preflight, not degraded",
			encryptionStatusProvider: &fakeEncryptionStatusProvider{
				observedConfigHash: wellKnownMatchingHashForBaseVaultConfig,
			},
			apiServerObjects: []runtime.Object{&configv1.APIServer{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec: configv1.APIServerSpec{
					Encryption: configv1.APIServerEncryption{
						Type: configv1.EncryptionTypeIdentity,
					},
				},
			}},
			initialDirtyDeployer:                  true,
			preconditionsMet:                      true,
			expectedPreflightDeployerCleanupCount: 1,
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "False"},
				{Type: "EncryptionKMSPreflightControllerProgressing", Status: "False"},
			},
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			conditions := []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "False"},
				{Type: "EncryptionKMSPreflightControllerProgressing", Status: "False"},
			}

			fakeOperatorClient := v1helpers.NewFakeStaticPodOperatorClient(
				&operatorv1.StaticPodOperatorSpec{
					OperatorSpec: operatorv1.OperatorSpec{
						ManagementState: operatorv1.Managed,
					},
				},
				&operatorv1.StaticPodOperatorStatus{
					OperatorStatus: operatorv1.OperatorStatus{
						Conditions: conditions,
					},
				},
				nil,
				nil,
			)

			fakeKubeClient := fake.NewSimpleClientset(scenario.coreObjects...)
			eventRecorder := events.NewRecorder(fakeKubeClient.CoreV1().Events("test"), "test-kmsPreflightController", &corev1.ObjectReference{}, clocktesting.NewFakePassiveClock(time.Now()))

			fakeConfigClient := configv1clientfake.NewSimpleClientset(scenario.apiServerObjects...)
			fakeApiServerClient := fakeConfigClient.ConfigV1().APIServers()

			preconditionsFn := func() (bool, error) { return scenario.preconditionsMet, nil }
			provider := newTestProvider([]schema.GroupResource{{Group: "", Resource: "secrets"}})

			deployer := scenario.deployer
			if deployer == nil {
				deployer = &fakeDeployer{}
			}
			// For pod-exists cases (Status does not return NotFound) that don't set
			// a deployed hash explicitly, default it to the current config hash so
			// the stale-pod gate treats the pod as current.
			if fd, ok := deployer.(*fakeDeployer); ok && fd.statusErr == nil && fd.deployedHash == "" {
				fd.deployedHash = wellKnownMatchingHashForBaseVaultConfig
			}

			computer := scenario.encryptionConfigurationComputer
			if computer == nil {
				computer = &fakeEncryptionConfigurationComputer{}
			}

			c := &kmsPreflightController{
				controllerInstanceName:          factory.ControllerInstanceName("test", "EncryptionKMSPreflight"),
				operatorClient:                  fakeOperatorClient,
				apiServerClient:                 fakeApiServerClient,
				secretsClient:                   fakeKubeClient.CoreV1(),
				configMapsClient:                fakeKubeClient.CoreV1(),
				deployer:                        deployer,
				encryptionConfigurationComputer: computer,
				dirtyDeployer:                   scenario.initialDirtyDeployer,
				provider:                        provider,
				preconditionsFulfilledFn:        preconditionsFn,
				encryptionStatusProvider:        scenario.encryptionStatusProvider,
			}

			err := c.sync(context.TODO(), factory.NewSyncContext("test", eventRecorder))

			if scenario.expectedError != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", scenario.expectedError)
				}
				if !strings.Contains(err.Error(), scenario.expectedError) {
					t.Fatalf("expected error containing %q, got: %v", scenario.expectedError, err)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !equality.Semantic.DeepEqual(scenario.encryptionStatusProvider.writtenStatus, scenario.expectedKMSPreflightResult) {
				t.Errorf("written KMS preflight result: got %v, want %v", scenario.encryptionStatusProvider.writtenStatus, scenario.expectedKMSPreflightResult)
			}
			if got := scenario.encryptionStatusProvider.updateCallCount; got != scenario.expectedEncryptionStatusProviderUpdateCalls {
				t.Errorf("UpdateKMSEncryptionStatus call count: got %d, want %d", got, scenario.expectedEncryptionStatusProviderUpdateCalls)
			}
			fakeDeployerInstance, ok := deployer.(*fakeDeployer)
			if !ok {
				t.Fatalf("deployer is not *fakeDeployer")
			}
			fakeComputerInstance, ok := computer.(*fakeEncryptionConfigurationComputer)
			if !ok {
				t.Fatalf("computer is not *fakeEncryptionConfigurationComputer")
			}
			if fakeComputerInstance.callCount != scenario.expectedComputerCallCount {
				t.Errorf("computer.ComputeEncryptionConfiguration call count: got %d, want %d", fakeComputerInstance.callCount, scenario.expectedComputerCallCount)
			}
			if fakeDeployerInstance.deployed {
				if !equality.Semantic.DeepEqual(fakeDeployerInstance.deployedEncryptionConfig, fakeComputerInstance.secret) {
					t.Errorf("deployer received wrong encryptionConfig: got %v, want %v", fakeDeployerInstance.deployedEncryptionConfig, fakeComputerInstance.secret)
				}
			}
			if fakeDeployerInstance.cleanupCount != scenario.expectedPreflightDeployerCleanupCount {
				t.Errorf("deployer.Cleanup call count: got %d, want %d", fakeDeployerInstance.cleanupCount, scenario.expectedPreflightDeployerCleanupCount)
			}
			// dirtyDeployer must be false after a successful Cleanup or when starting clean.
			if (scenario.expectedPreflightDeployerCleanupCount > 0 && scenario.expectedError == "") || !scenario.initialDirtyDeployer {
				if c.dirtyDeployer {
					t.Errorf("expected dirtyDeployer=false, got true")
				}
			}

			encryptiontesting.ValidateOperatorClientConditions(t, fakeOperatorClient, scenario.expectedConditions)
		})
	}
}
