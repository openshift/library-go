package controllers

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	apiserverconfigv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	clocktesting "k8s.io/utils/clock/testing"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	configv1clientfake "github.com/openshift/client-go/config/clientset/versioned/fake"
	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/encryption/encryptiondata"
	"github.com/openshift/library-go/pkg/operator/encryption/kms"
	"github.com/openshift/library-go/pkg/operator/encryption/secrets"
	"github.com/openshift/library-go/pkg/operator/encryption/state"
	"github.com/openshift/library-go/pkg/operator/encryption/statemachine"
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
	deployed         bool
	cleaned          bool
	cleanupCount     int
	deployErr        error
	statusErr        error
	cleanupErr       error
	podStatus        corev1.PodStatus
	encryptionSecret *corev1.Secret
}

func (f *fakeDeployer) Deploy(_ context.Context, _ string, encryptionSecret *corev1.Secret) error {
	f.deployed = true
	f.encryptionSecret = encryptionSecret
	return f.deployErr
}

func (f *fakeDeployer) Status(_ context.Context) (corev1.PodStatus, error) {
	return f.podStatus, f.statusErr
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
		encryptionDeployer                          statemachine.Deployer
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
		expectDeployedEncryptionSecret              bool
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
			name:                           "hashes match, no pod exists, deploys and returns",
			deployer:                       &fakeDeployer{statusErr: apierrors.NewNotFound(schema.GroupResource{Resource: "pods"}, "kms-preflight")},
			encryptionDeployer:             &fakeEncryptionDeployer{converged: true},
			encryptionStatusProvider:       &fakeEncryptionStatusProvider{observedConfigHash: wellKnownMatchingHashForBaseVaultConfig},
			apiServerObjects:               []runtime.Object{apiServerWithKMS},
			coreObjects:                    []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			initialDirtyDeployer:           true,
			preconditionsMet:               true,
			expectDeployedEncryptionSecret: true,
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "False"},
				{Type: "EncryptionKMSPreflightControllerProgressing", Status: "True", Reason: "RunningPreflightCheck", Message: "Deploying preflight pod for hash cuZm_g=="},
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
			// Scenario 3b: terminal — pod exited without reporting hash.
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
			// Scenario 3c: stale pod, cleanup succeeds — progressing.
			name: "pod exists, hash is stale, cleans up",
			deployer: &fakeDeployer{podStatus: corev1.PodStatus{
				Conditions: []corev1.PodCondition{
					{Type: KMSPreflightConfigHashPodCondition, Message: "old-hash"},
					{Type: KMSPreflightResultPodCondition, Status: corev1.ConditionTrue},
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
			// Scenario 3a: terminal — pod crashed.
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
			// Scenario 3b: no hash condition, pod running, no timeout — progressing.
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
			// Scenario 3b: terminal — no hash, timeout via PodScheduled condition fallback.
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
			// Scenario 3b: terminal — no hash, timeout via StartTime.
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
			// Scenario 3b: terminal — ImagePullBackOff timeout.
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
			name:                     "deploy fails, reports error",
			deployer:                 &fakeDeployer{statusErr: apierrors.NewNotFound(schema.GroupResource{Resource: "pods"}, "kms-preflight"), deployErr: fmt.Errorf("quota exceeded")},
			encryptionStatusProvider: &fakeEncryptionStatusProvider{observedConfigHash: wellKnownMatchingHashForBaseVaultConfig},
			apiServerObjects:         []runtime.Object{apiServerWithKMS},
			coreObjects:              []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			initialDirtyDeployer:     true,
			preconditionsMet:         true,
			expectedError:            "quota exceeded",
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
			// Scenario 3c: cleanup error — transient, not terminal.
			name: "cleanup fails on stale hash, reports error",
			deployer: &fakeDeployer{
				cleanupErr: fmt.Errorf("delete forbidden"),
				podStatus: corev1.PodStatus{
					Conditions: []corev1.PodCondition{
						{Type: KMSPreflightConfigHashPodCondition, Message: "old-hash"},
					},
				},
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
			// Scenario 3a: terminal — pod crashed, no terminated container.
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
			// Scenario 3a: terminal — pod crashed with non-zero exit code.
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

			encryptionDeployer := scenario.encryptionDeployer
			if encryptionDeployer == nil {
				encryptionDeployer = &fakeEncryptionDeployer{converged: true}
			}

			c := &kmsPreflightController{
				controllerInstanceName:   factory.ControllerInstanceName("test", "EncryptionKMSPreflight"),
				instanceName:             "test",
				operatorClient:           fakeOperatorClient,
				apiServerClient:          fakeApiServerClient,
				secretsClient:            fakeKubeClient.CoreV1(),
				configMapsClient:         fakeKubeClient.CoreV1(),
				deployer:                 deployer,
				dirtyDeployer:            scenario.initialDirtyDeployer,
				encryptionDeployer:       encryptionDeployer,
				encryptionSecretSelector: metav1.ListOptions{},
				provider:                 provider,
				preconditionsFulfilledFn: preconditionsFn,
				encryptionStatusProvider: scenario.encryptionStatusProvider,
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
			if fakeDeployerInstance.cleanupCount != scenario.expectedPreflightDeployerCleanupCount {
				t.Errorf("deployer.Cleanup call count: got %d, want %d", fakeDeployerInstance.cleanupCount, scenario.expectedPreflightDeployerCleanupCount)
			}
			// dirtyDeployer must be false after a successful Cleanup or when starting clean.
			if (scenario.expectedPreflightDeployerCleanupCount > 0 && scenario.expectedError == "") || !scenario.initialDirtyDeployer {
				if c.dirtyDeployer {
					t.Errorf("expected dirtyDeployer=false, got true")
				}
			}
			if scenario.expectDeployedEncryptionSecret {
				if fakeDeployerInstance.encryptionSecret == nil {
					t.Fatalf("expected Deploy to receive a non-nil encryption config secret")
				}
				cfg, err := encryptiondata.FromSecret(fakeDeployerInstance.encryptionSecret)
				if err != nil {
					t.Fatalf("Deploy received an invalid encryption config secret: %v", err)
				}
				kmsConfigs, err := encryptiondata.ExtractUniqueAndSortedKMSConfigurations(cfg)
				if err != nil {
					t.Fatalf("failed to extract KMS configurations from deployed secret: %v", err)
				}
				if len(kmsConfigs) == 0 {
					t.Fatalf("expected deployed encryption config to contain at least one KMS configuration")
				}
				if _, ok := cfg.KMSPluginsSecretData.Get(kmsConfigs[0].Name); !ok {
					t.Fatalf("expected deployed encryption config to carry KMS secret data for key %s", kmsConfigs[0].Name)
				}
			}

			encryptiontesting.ValidateOperatorClientConditions(t, fakeOperatorClient, scenario.expectedConditions)
		})
	}
}

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

func TestComputeEncryptionConfigSecret(t *testing.T) {
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
	encryptedGRs := []schema.GroupResource{{Group: "", Resource: "secrets"}}

	newExistingKeySecret := func(t *testing.T, keyID string) *corev1.Secret {
		t.Helper()
		// Existing keys use a different VaultKeyPath than the current apiserver config so
		// needsNewKey reports kms-provider-changed (and thus needed=true). They are also
		// marked migrated: needsNewKey refuses to create a new key until migration completes.
		oldPlugin := apiServerWithKMS.Spec.Encryption.KMS
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
		s, err := secrets.FromKeyState("test", ks)
		if err != nil {
			t.Fatalf("failed to build existing key secret: %v", err)
		}
		return s
	}

	// newDeployedEncryptionConfig builds a converged encryption-config secret as the
	// state controller would after the given key secrets are write keys.
	newDeployedEncryptionConfig := func(t *testing.T, keySecrets ...*corev1.Secret) *corev1.Secret {
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
		secret, err := encryptiondata.ToSecret("openshift-config-managed", "encryption-config-test", cfg)
		if err != nil {
			t.Fatalf("failed to serialize deployed encryption config: %v", err)
		}
		return secret
	}

	newController := func(coreObjects []runtime.Object, encryptionDeployer statemachine.Deployer) *kmsPreflightController {
		fakeKubeClient := fake.NewSimpleClientset(coreObjects...)
		fakeConfigClient := configv1clientfake.NewSimpleClientset(apiServerWithKMS)
		return &kmsPreflightController{
			instanceName:             "test",
			apiServerClient:          fakeConfigClient.ConfigV1().APIServers(),
			secretsClient:            fakeKubeClient.CoreV1(),
			configMapsClient:         fakeKubeClient.CoreV1(),
			encryptionDeployer:       encryptionDeployer,
			encryptionSecretSelector: metav1.ListOptions{},
			provider:                 newTestProvider(encryptedGRs),
		}
	}

	assertKeyCredentials := func(t *testing.T, cfg *encryptiondata.Config, keyID, roleID, secretID, caBundle string) {
		t.Helper()
		if _, ok := cfg.KMSPlugins[keyID]; !ok {
			t.Fatalf("expected plugin config for keyID %s", keyID)
		}
		secretData, ok := cfg.KMSPluginsSecretData.Get(keyID)
		if !ok {
			t.Fatalf("expected secret data for keyID %s", keyID)
		}
		if v, ok := secretData.Get("vault-approle", "role-id"); !ok || string(v) != roleID {
			t.Errorf("key %s: expected role-id %q, got %q (found=%v)", keyID, roleID, v, ok)
		}
		if v, ok := secretData.Get("vault-approle", "secret-id"); !ok || string(v) != secretID {
			t.Errorf("key %s: expected secret-id %q, got %q (found=%v)", keyID, secretID, v, ok)
		}
		cmData, ok := cfg.KMSPluginsConfigMapData.Get(keyID)
		if !ok {
			t.Fatalf("expected configmap data for keyID %s", keyID)
		}
		if v, ok := cmData.Get("vault-ca-bundle", "ca-bundle.crt"); !ok || string(v) != caBundle {
			t.Errorf("key %s: expected ca-bundle %q, got %q (found=%v)", keyID, caBundle, v, ok)
		}
	}

	t.Run("first key, no existing secrets, produces key ID 1", func(t *testing.T) {
		c := newController([]runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap}, &fakeEncryptionDeployer{converged: true})

		requeue, secret, err := c.computeEncryptionConfigSecret(context.TODO())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if requeue {
			t.Fatalf("expected no requeue")
		}
		if secret == nil {
			t.Fatalf("expected a secret, got nil")
		}

		cfg, err := encryptiondata.FromSecret(secret)
		if err != nil {
			t.Fatalf("failed to parse produced secret: %v", err)
		}
		kmsConfigs, err := encryptiondata.ExtractUniqueAndSortedKMSConfigurations(cfg)
		if err != nil {
			t.Fatalf("failed to extract KMS configurations: %v", err)
		}
		if len(kmsConfigs) != 1 {
			t.Fatalf("expected 1 KMS configuration, got %d: %+v", len(kmsConfigs), kmsConfigs)
		}
		if kmsConfigs[0].Name != "1" {
			t.Errorf("expected key ID 1, got %s", kmsConfigs[0].Name)
		}
		if kmsConfigs[0].Endpoint != "unix:///var/run/kmsplugin/kms.sock" {
			t.Errorf("unexpected endpoint: %s", kmsConfigs[0].Endpoint)
		}
		assertKeyCredentials(t, cfg, "1", "role-123", "secret-456", "test-ca-cert")

		// Must match the state-controller shape for key 1, except that the
		// simulated candidate key uses the preflight socket endpoint.
		simulatedKey, err := secrets.FromKeyState("test", state.KeyState{
			Key:  apiserverconfigv1.Key{Name: "1", Secret: base64.StdEncoding.EncodeToString(make([]byte, 16))},
			Mode: state.KMS,
			KMS: &state.KMSState{
				Encryption: &apiserverconfigv1.KMSConfiguration{
					APIVersion: "v2",
					Name:       "1",
					Endpoint:   "unix:///var/run/kmsplugin/kms.sock",
					Timeout:    &metav1.Duration{Duration: 10 * time.Second},
				},
				Plugin: apiServerWithKMS.Spec.Encryption.KMS,
			},
		})
		if err != nil {
			t.Fatalf("failed to build comparison key: %v", err)
		}
		// Copy credentials into the comparison key the same way generateKeySecret would.
		ks, err := secrets.ToKeyState(simulatedKey)
		if err != nil {
			t.Fatalf("failed to parse comparison key: %v", err)
		}
		_ = ks.KMS.PluginSecretData.Set("vault-approle", "role-id", []byte("role-123"))
		_ = ks.KMS.PluginSecretData.Set("vault-approle", "secret-id", []byte("secret-456"))
		_ = ks.KMS.PluginConfigMapData.Set("vault-ca-bundle", "ca-bundle.crt", []byte("test-ca-cert"))
		simulatedKey, err = secrets.FromKeyState("test", ks)
		if err != nil {
			t.Fatalf("failed to rebuild comparison key: %v", err)
		}
		desired := statemachine.GetDesiredEncryptionState(nil, []*corev1.Secret{simulatedKey}, encryptedGRs)
		wantCfg, err := encryptiondata.FromEncryptionState(desired)
		if err != nil {
			t.Fatalf("failed to build state-controller golden config: %v", err)
		}
		wantSecret, err := encryptiondata.ToSecret("openshift-config-managed", "encryption-config-test", wantCfg)
		if err != nil {
			t.Fatalf("failed to serialize golden config: %v", err)
		}
		if !equality.Semantic.DeepEqual(secret.Data, wantSecret.Data) {
			t.Errorf("preflight secret data diverges from expected candidate config after key creation")
		}
	})

	t.Run("existing key with deployed config, uses next key ID and retains credentials", func(t *testing.T) {
		existingKeySecret := newExistingKeySecret(t, "3")
		deployed := newDeployedEncryptionConfig(t, existingKeySecret)
		c := newController(
			[]runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap, existingKeySecret},
			&fakeEncryptionDeployer{converged: true, secret: deployed},
		)

		requeue, secret, err := c.computeEncryptionConfigSecret(context.TODO())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if requeue {
			t.Fatalf("expected no requeue")
		}

		cfg, err := encryptiondata.FromSecret(secret)
		if err != nil {
			t.Fatalf("failed to parse produced secret: %v", err)
		}
		kmsConfigs, err := encryptiondata.ExtractUniqueAndSortedKMSConfigurations(cfg)
		if err != nil {
			t.Fatalf("failed to extract KMS configurations: %v", err)
		}

		// Key 3 remains the write key (STEP 2 early return); key 4 is the new read key
		// the key-controller is about to create. Both must be present.
		var found3, found4 bool
		for _, kc := range kmsConfigs {
			switch kc.Name {
			case "3":
				found3 = true
			case "4":
				found4 = true
				if kc.Endpoint != "unix:///var/run/kmsplugin/kms.sock" {
					t.Errorf("unexpected endpoint for key 4: %s", kc.Endpoint)
				}
			}
		}
		if !found3 || !found4 {
			t.Fatalf("expected key IDs 3 and 4 among KMS configurations, got %+v", kmsConfigs)
		}
		assertKeyCredentials(t, cfg, "3", "old-role-id", "old-secret-id", "old-ca-cert")
		assertKeyCredentials(t, cfg, "4", "role-123", "secret-456", "test-ca-cert")

		// Golden: must match the expected candidate config once key 4 is
		// simulated for preflight, with key 4 rewritten to the preflight socket
		// and carrying the current apiserver plugin config (not the old key's).
		newKey := newExistingKeySecret(t, "4")
		ks, err := secrets.ToKeyState(newKey)
		if err != nil {
			t.Fatalf("failed to parse new key: %v", err)
		}
		ks.KMS.Encryption.Endpoint = "unix:///var/run/kmsplugin/kms.sock"
		ks.KMS.Plugin = apiServerWithKMS.Spec.Encryption.KMS
		_ = ks.KMS.PluginSecretData.Set("vault-approle", "role-id", []byte("role-123"))
		_ = ks.KMS.PluginSecretData.Set("vault-approle", "secret-id", []byte("secret-456"))
		_ = ks.KMS.PluginConfigMapData.Set("vault-ca-bundle", "ca-bundle.crt", []byte("test-ca-cert"))
		newKey, err = secrets.FromKeyState("test", ks)
		if err != nil {
			t.Fatalf("failed to rebuild new key: %v", err)
		}
		deployedCfg, err := encryptiondata.FromSecret(deployed)
		if err != nil {
			t.Fatalf("failed to parse deployed config: %v", err)
		}
		desired := statemachine.GetDesiredEncryptionState(deployedCfg, []*corev1.Secret{existingKeySecret, newKey}, encryptedGRs)
		wantCfg, err := encryptiondata.FromEncryptionState(desired)
		if err != nil {
			t.Fatalf("failed to build golden config: %v", err)
		}
		wantSecret, err := encryptiondata.ToSecret("openshift-config-managed", "encryption-config-test", wantCfg)
		if err != nil {
			t.Fatalf("failed to serialize golden config: %v", err)
		}
		if !equality.Semantic.DeepEqual(secret.Data, wantSecret.Data) {
			t.Errorf("preflight secret data diverges from expected candidate config after key 4 creation")
		}
	})

	t.Run("new candidate key uses preflight socket while existing key keeps original endpoint", func(t *testing.T) {
		existingKeySecret := newExistingKeySecret(t, "3")
		deployed := newDeployedEncryptionConfig(t, existingKeySecret)
		c := newController(
			[]runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap, existingKeySecret},
			&fakeEncryptionDeployer{converged: true, secret: deployed},
		)

		_, secret, err := c.computeEncryptionConfigSecret(context.TODO())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		cfg, err := encryptiondata.FromSecret(secret)
		if err != nil {
			t.Fatalf("failed to parse produced secret: %v", err)
		}
		kmsConfigs, err := encryptiondata.ExtractUniqueAndSortedKMSConfigurations(cfg)
		if err != nil {
			t.Fatalf("failed to extract KMS configurations: %v", err)
		}

		endpointsByKey := map[string]string{}
		for _, kc := range kmsConfigs {
			endpointsByKey[kc.Name] = kc.Endpoint
		}
		if endpointsByKey["3"] != "unix:///var/run/kmsplugin/kms-3.sock" {
			t.Fatalf("expected existing key 3 to keep its original endpoint, got %q", endpointsByKey["3"])
		}
		if endpointsByKey["4"] != "unix:///var/run/kmsplugin/kms.sock" {
			t.Fatalf("expected candidate key 4 to use preflight endpoint %q, got %q", "unix:///var/run/kmsplugin/kms.sock", endpointsByKey["4"])
		}
	})

	t.Run("API server revisions not converged, requeues without error or secret", func(t *testing.T) {
		c := newController([]runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap}, &fakeEncryptionDeployer{converged: false})

		requeue, secret, err := c.computeEncryptionConfigSecret(context.TODO())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !requeue {
			t.Fatalf("expected requeue")
		}
		if secret != nil {
			t.Fatalf("expected no secret, got %+v", secret)
		}
	})

	t.Run("encryption deployer error is propagated", func(t *testing.T) {
		c := newController(nil, &fakeEncryptionDeployer{err: fmt.Errorf("boom")})

		_, _, err := c.computeEncryptionConfigSecret(context.TODO())
		if err == nil || !strings.Contains(err.Error(), "boom") {
			t.Fatalf("expected error containing %q, got: %v", "boom", err)
		}
	})
}
