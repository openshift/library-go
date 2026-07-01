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

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	configv1clientfake "github.com/openshift/client-go/config/clientset/versioned/fake"
	configv1informers "github.com/openshift/client-go/config/informers/externalversions"

	"github.com/openshift/library-go/pkg/controller/factory"
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
		TransitMount: "transit",
		TransitKey:   "my-key",
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
			expectedHash: "k6dSVA==",
		},
		{
			name: "changing KMSPluginImage",
			vaultConfig: func() configv1.VaultKMSPluginConfig {
				c := wellKnownBaseVaultConfig
				c.KMSPluginImage = "registry.example.com/plugin@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
				return c
			}(),
			resources:    []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			expectedHash: "DC20hA==",
		},
		{
			name: "changing VaultAddress",
			vaultConfig: func() configv1.VaultKMSPluginConfig {
				c := wellKnownBaseVaultConfig
				c.VaultAddress = "https://other-vault.example.com:8200"
				return c
			}(),
			resources:    []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			expectedHash: "VOhO4Q==",
		},
		{
			name: "changing VaultNamespace",
			vaultConfig: func() configv1.VaultKMSPluginConfig {
				c := wellKnownBaseVaultConfig
				c.VaultNamespace = "my-namespace"
				return c
			}(),
			resources:    []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			expectedHash: "uQnh1w==",
		},
		{
			name: "changing TransitMount",
			vaultConfig: func() configv1.VaultKMSPluginConfig {
				c := wellKnownBaseVaultConfig
				c.TransitMount = "other-transit"
				return c
			}(),
			resources:    []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			expectedHash: "yBP5JQ==",
		},
		{
			name: "changing TransitKey",
			vaultConfig: func() configv1.VaultKMSPluginConfig {
				c := wellKnownBaseVaultConfig
				c.TransitKey = "other-key"
				return c
			}(),
			resources:    []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			expectedHash: "IH9sCA==",
		},
		{
			name: "changing TLS.ServerName",
			vaultConfig: func() configv1.VaultKMSPluginConfig {
				c := wellKnownBaseVaultConfig
				c.TLS.ServerName = "vault.example.com"
				return c
			}(),
			resources:    []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			expectedHash: "o6TBAQ==",
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
			expectedHash: "rIBPRg==",
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
			expectedHash: "jOnSCQ==",
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
			expectedHash: "e9maow==",
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
			expectedHash: "DMAbFg==",
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
			expectedHash: "k6dSVA==",
		},
		{
			name:        "extra key in configmap does not change hash",
			vaultConfig: wellKnownBaseVaultConfig,
			resources: []runtime.Object{&wellKnownBaseSecret, &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "vault-ca-bundle", Namespace: "openshift-config"},
				Data:       map[string]string{"ca-bundle.crt": "test-ca-cert", "extra": "ignored"},
			}},
			expectedHash: "k6dSVA==",
		},
		{
			name:        "changing ca-bundle.crt value",
			vaultConfig: wellKnownBaseVaultConfig,
			resources: []runtime.Object{&wellKnownBaseSecret, &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "vault-ca-bundle", Namespace: "openshift-config"},
				Data:       map[string]string{"ca-bundle.crt": "different-ca-cert"},
			}},
			expectedHash: "6nq3gw==",
		},
		{
			name: "no configmap configured",
			vaultConfig: func() configv1.VaultKMSPluginConfig {
				c := wellKnownBaseVaultConfig
				c.TLS.CABundle.Name = ""
				return c
			}(),
			resources:    []runtime.Object{&wellKnownBaseSecret},
			expectedHash: "rGXYog==",
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
			expectedHash: "tpoe4g==",
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
			got, err := newKMSConfigHasher(provider, client, "openshift-config").hash(context.Background())

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
	deployed   bool
	cleaned    bool
	deployErr  error
	statusErr  error
	cleanupErr error
	podStatus  corev1.PodStatus
}

func (f *fakeDeployer) Deploy(_ context.Context, _ string, _ *corev1.Secret) error {
	f.deployed = true
	return f.deployErr
}

func (f *fakeDeployer) Status(_ context.Context) (corev1.PodStatus, error) {
	return f.podStatus, f.statusErr
}

func (f *fakeDeployer) Cleanup(_ context.Context) error {
	f.cleaned = true
	return f.cleanupErr
}

func TestKMSPreflightController(t *testing.T) {
	apiServerWithKMS := &configv1.APIServer{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
		Spec: configv1.APIServerSpec{
			Encryption: configv1.APIServerEncryption{
				KMS: configv1.KMSPluginConfig{
					Type:  configv1.VaultKMSProvider,
					Vault: wellKnownBaseVaultConfig,
				},
			},
		},
	}

	// Hash produced by kmsConfigHasher over wellKnownBaseVaultConfig, wellKnownBaseSecret,
	// and wellKnownBaseConfigMap. Verified by TestKMSConfigHasher.
	const wellKnownMatchingHashForBaseVaultConfig = "k6dSVA=="

	scenarios := []struct {
		name               string
		deployer           KMSPreflightDeployer
		apiServerObjects   []runtime.Object
		coreObjects        []runtime.Object
		operatorConditions []operatorv1.OperatorCondition
		preconditionsMet   bool
		expectedError      string
		expectedConditions []operatorv1.OperatorCondition
	}{
		{
			name:             "preconditions not met, clears degraded",
			apiServerObjects: []runtime.Object{&configv1.APIServer{ObjectMeta: metav1.ObjectMeta{Name: "cluster"}}},
			preconditionsMet: false,
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "False"},
			},
		},
		{
			name:             "no EncryptionKMSPreflightRequired condition, cleans up",
			apiServerObjects: []runtime.Object{apiServerWithKMS},
			coreObjects:      []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			preconditionsMet: true,
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "False"},
			},
		},
		{
			name:             "EncryptionKMSPreflightRequired condition is False, cleans up",
			apiServerObjects: []runtime.Object{apiServerWithKMS},
			coreObjects:      []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			operatorConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightRequired", Status: operatorv1.ConditionFalse, Message: wellKnownMatchingHashForBaseVaultConfig},
			},
			preconditionsMet: true,
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "False"},
				{Type: "EncryptionKMSPreflightRequired", Status: operatorv1.ConditionFalse, Message: wellKnownMatchingHashForBaseVaultConfig},
			},
		},
		{
			name:             "hashes match, no pod exists, deploys and returns",
			deployer:         &fakeDeployer{statusErr: apierrors.NewNotFound(schema.GroupResource{Resource: "pods"}, "kms-preflight")},
			apiServerObjects: []runtime.Object{apiServerWithKMS},
			coreObjects:      []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			operatorConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightRequired", Status: operatorv1.ConditionTrue, Message: wellKnownMatchingHashForBaseVaultConfig},
			},
			preconditionsMet: true,
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "False"},
				{Type: "EncryptionKMSPreflightRequired", Status: operatorv1.ConditionTrue, Message: wellKnownMatchingHashForBaseVaultConfig},
			},
		},
		{
			name: "pod exists, hash matches, no result yet, requeues",
			deployer: &fakeDeployer{podStatus: corev1.PodStatus{
				Conditions: []corev1.PodCondition{
					{Type: KMSPreflightConfigHashPodCondition, Message: wellKnownMatchingHashForBaseVaultConfig},
				},
			}},
			apiServerObjects: []runtime.Object{apiServerWithKMS},
			coreObjects:      []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			operatorConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightRequired", Status: operatorv1.ConditionTrue, Message: wellKnownMatchingHashForBaseVaultConfig},
			},
			preconditionsMet: true,
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "False"},
				{Type: "EncryptionKMSPreflightRequired", Status: operatorv1.ConditionTrue, Message: wellKnownMatchingHashForBaseVaultConfig},
			},
		},
		{
			name: "pod succeeded without reporting hash, reports error",
			deployer: &fakeDeployer{podStatus: corev1.PodStatus{
				Phase: corev1.PodSucceeded,
			}},
			apiServerObjects: []runtime.Object{apiServerWithKMS},
			coreObjects:      []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			operatorConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightRequired", Status: operatorv1.ConditionTrue, Message: wellKnownMatchingHashForBaseVaultConfig},
			},
			preconditionsMet: true,
			expectedError:    "preflight pod completed without reporting result for hash k6dSVA==",
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "True", Reason: "PodCompletedWithoutResult", Message: "preflight pod completed without reporting result for hash k6dSVA=="},
				{Type: "EncryptionKMSPreflightRequired", Status: operatorv1.ConditionTrue, Message: wellKnownMatchingHashForBaseVaultConfig},
			},
		},
		{
			name: "pod succeeded without reporting result after hash posted, reports error",
			deployer: &fakeDeployer{podStatus: corev1.PodStatus{
				Phase: corev1.PodSucceeded,
				Conditions: []corev1.PodCondition{
					{Type: KMSPreflightConfigHashPodCondition, Message: wellKnownMatchingHashForBaseVaultConfig},
				},
			}},
			apiServerObjects: []runtime.Object{apiServerWithKMS},
			coreObjects:      []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			operatorConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightRequired", Status: operatorv1.ConditionTrue, Message: wellKnownMatchingHashForBaseVaultConfig},
			},
			preconditionsMet: true,
			expectedError:    "preflight pod completed without reporting result for hash k6dSVA==",
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "True", Reason: "PodCompletedWithoutResult", Message: "preflight pod completed without reporting result for hash k6dSVA=="},
				{Type: "EncryptionKMSPreflightRequired", Status: operatorv1.ConditionTrue, Message: wellKnownMatchingHashForBaseVaultConfig},
			},
		},
		{
			name: "pod succeeded recently, keeps pod for inspection",
			deployer: &fakeDeployer{podStatus: corev1.PodStatus{
				Conditions: []corev1.PodCondition{
					{Type: KMSPreflightConfigHashPodCondition, Message: wellKnownMatchingHashForBaseVaultConfig},
					{Type: KMSPreflightResultPodCondition, Status: corev1.ConditionTrue, LastTransitionTime: metav1.Now()},
				},
			}},
			apiServerObjects: []runtime.Object{apiServerWithKMS},
			coreObjects:      []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			operatorConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightRequired", Status: operatorv1.ConditionTrue, Message: wellKnownMatchingHashForBaseVaultConfig},
			},
			preconditionsMet: true,
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "False"},
				{Type: "EncryptionKMSPreflightRequired", Status: operatorv1.ConditionTrue, Message: wellKnownMatchingHashForBaseVaultConfig},
			},
		},
		{
			name: "pod succeeded, retention period elapsed, cleans up",
			deployer: &fakeDeployer{podStatus: corev1.PodStatus{
				Conditions: []corev1.PodCondition{
					{Type: KMSPreflightConfigHashPodCondition, Message: wellKnownMatchingHashForBaseVaultConfig},
					{Type: KMSPreflightResultPodCondition, Status: corev1.ConditionTrue, LastTransitionTime: metav1.NewTime(time.Now().Add(-2 * time.Hour))},
				},
			}},
			apiServerObjects: []runtime.Object{apiServerWithKMS},
			coreObjects:      []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			operatorConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightRequired", Status: operatorv1.ConditionTrue, Message: wellKnownMatchingHashForBaseVaultConfig},
			},
			preconditionsMet: true,
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "False"},
				{Type: "EncryptionKMSPreflightRequired", Status: operatorv1.ConditionTrue, Message: wellKnownMatchingHashForBaseVaultConfig},
			},
		},
		{
			name: "pod exists, hash matches, result is False, reports error",
			deployer: &fakeDeployer{podStatus: corev1.PodStatus{
				Conditions: []corev1.PodCondition{
					{Type: KMSPreflightConfigHashPodCondition, Message: wellKnownMatchingHashForBaseVaultConfig},
					{Type: KMSPreflightResultPodCondition, Status: corev1.ConditionFalse, Message: "encrypt call failed", LastTransitionTime: metav1.Now()},
				},
			}},
			apiServerObjects: []runtime.Object{apiServerWithKMS},
			coreObjects:      []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			operatorConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightRequired", Status: operatorv1.ConditionTrue, Message: wellKnownMatchingHashForBaseVaultConfig},
			},
			preconditionsMet: true,
			expectedError:    "preflight check failed for hash k6dSVA==: encrypt call failed",
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "True", Reason: "PreflightCheckFailed", Message: "preflight check failed for hash k6dSVA==: encrypt call failed"},
				{Type: "EncryptionKMSPreflightRequired", Status: operatorv1.ConditionTrue, Message: wellKnownMatchingHashForBaseVaultConfig},
			},
		},
		{
			name: "pod exists, hash is stale, cleans up",
			deployer: &fakeDeployer{podStatus: corev1.PodStatus{
				Conditions: []corev1.PodCondition{
					{Type: KMSPreflightConfigHashPodCondition, Message: "old-hash"},
					{Type: KMSPreflightResultPodCondition, Status: corev1.ConditionTrue},
				},
			}},
			apiServerObjects: []runtime.Object{apiServerWithKMS},
			coreObjects:      []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			operatorConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightRequired", Status: operatorv1.ConditionTrue, Message: wellKnownMatchingHashForBaseVaultConfig},
			},
			preconditionsMet: true,
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "False"},
				{Type: "EncryptionKMSPreflightRequired", Status: operatorv1.ConditionTrue, Message: wellKnownMatchingHashForBaseVaultConfig},
			},
		},
		{
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
			apiServerObjects: []runtime.Object{apiServerWithKMS},
			coreObjects:      []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			operatorConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightRequired", Status: operatorv1.ConditionTrue, Message: wellKnownMatchingHashForBaseVaultConfig},
			},
			preconditionsMet: true,
			expectedError:    "preflight pod failed for hash k6dSVA==: at least one container kms-preflight-check exited with 1 (Unknown): connection refused",
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "True", Reason: "Unknown", Message: "preflight pod failed for hash k6dSVA==: at least one container kms-preflight-check exited with 1 (Unknown): connection refused"},
				{Type: "EncryptionKMSPreflightRequired", Status: operatorv1.ConditionTrue, Message: wellKnownMatchingHashForBaseVaultConfig},
			},
		},
		{
			name: "pod exists, no hash condition yet, waits for pod to report",
			deployer: &fakeDeployer{podStatus: corev1.PodStatus{
				Phase: corev1.PodRunning,
			}},
			apiServerObjects: []runtime.Object{apiServerWithKMS},
			coreObjects:      []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			operatorConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightRequired", Status: operatorv1.ConditionTrue, Message: wellKnownMatchingHashForBaseVaultConfig},
			},
			preconditionsMet: true,
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "False"},
				{Type: "EncryptionKMSPreflightRequired", Status: operatorv1.ConditionTrue, Message: wellKnownMatchingHashForBaseVaultConfig},
			},
		},
		{
			name: "pod stuck in Pending without reporting hash, goes degraded with phase",
			deployer: &fakeDeployer{podStatus: corev1.PodStatus{
				Phase:     corev1.PodPending,
				StartTime: &metav1.Time{Time: time.Now().Add(-5 * time.Minute)},
			}},
			apiServerObjects: []runtime.Object{apiServerWithKMS},
			coreObjects:      []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			operatorConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightRequired", Status: operatorv1.ConditionTrue, Message: wellKnownMatchingHashForBaseVaultConfig},
			},
			preconditionsMet: true,
			expectedError:    "preflight pod has not reported config hash after 3m0s: pod is in Pending phase",
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "True", Reason: "Unknown", Message: "preflight pod has not reported config hash after 3m0s: pod is in Pending phase"},
				{Type: "EncryptionKMSPreflightRequired", Status: operatorv1.ConditionTrue, Message: wellKnownMatchingHashForBaseVaultConfig},
			},
		},
		{
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
			apiServerObjects: []runtime.Object{apiServerWithKMS},
			coreObjects:      []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			operatorConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightRequired", Status: operatorv1.ConditionTrue, Message: wellKnownMatchingHashForBaseVaultConfig},
			},
			preconditionsMet: true,
			expectedError:    "preflight pod has not reported config hash after 3m0s: at least one container kms-preflight-check is waiting: ImagePullBackOff: back-off pulling image",
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "True", Reason: "ImagePullBackOff", Message: "preflight pod has not reported config hash after 3m0s: at least one container kms-preflight-check is waiting: ImagePullBackOff: back-off pulling image"},
				{Type: "EncryptionKMSPreflightRequired", Status: operatorv1.ConditionTrue, Message: wellKnownMatchingHashForBaseVaultConfig},
			},
		},
		{
			name: "pod stuck without reporting result past timeout, goes degraded",
			deployer: &fakeDeployer{podStatus: corev1.PodStatus{
				Phase:     corev1.PodRunning,
				StartTime: &metav1.Time{Time: time.Now().Add(-5 * time.Minute)},
				Conditions: []corev1.PodCondition{
					{Type: KMSPreflightConfigHashPodCondition, Message: wellKnownMatchingHashForBaseVaultConfig},
				},
			}},
			apiServerObjects: []runtime.Object{apiServerWithKMS},
			coreObjects:      []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			operatorConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightRequired", Status: operatorv1.ConditionTrue, Message: wellKnownMatchingHashForBaseVaultConfig},
			},
			preconditionsMet: true,
			expectedError:    "preflight pod has not reported result after 3m0s: pod is in Running phase",
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "True", Reason: "Unknown", Message: "preflight pod has not reported result after 3m0s: pod is in Running phase"},
				{Type: "EncryptionKMSPreflightRequired", Status: operatorv1.ConditionTrue, Message: wellKnownMatchingHashForBaseVaultConfig},
			},
		},
		{
			name:             "deploy fails, reports error",
			deployer:         &fakeDeployer{statusErr: apierrors.NewNotFound(schema.GroupResource{Resource: "pods"}, "kms-preflight"), deployErr: fmt.Errorf("quota exceeded")},
			apiServerObjects: []runtime.Object{apiServerWithKMS},
			coreObjects:      []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			operatorConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightRequired", Status: operatorv1.ConditionTrue, Message: wellKnownMatchingHashForBaseVaultConfig},
			},
			preconditionsMet: true,
			expectedError:    "quota exceeded",
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "True", Reason: "Error", Message: "quota exceeded"},
				{Type: "EncryptionKMSPreflightRequired", Status: operatorv1.ConditionTrue, Message: wellKnownMatchingHashForBaseVaultConfig},
			},
		},
		{
			name:             "status returns unexpected error",
			deployer:         &fakeDeployer{statusErr: fmt.Errorf("connection refused")},
			apiServerObjects: []runtime.Object{apiServerWithKMS},
			coreObjects:      []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			operatorConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightRequired", Status: operatorv1.ConditionTrue, Message: wellKnownMatchingHashForBaseVaultConfig},
			},
			preconditionsMet: true,
			expectedError:    "failed to get preflight pod status",
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "True", Reason: "Error", Message: "failed to get preflight pod status: connection refused"},
				{Type: "EncryptionKMSPreflightRequired", Status: operatorv1.ConditionTrue, Message: wellKnownMatchingHashForBaseVaultConfig},
			},
		},
		{
			name: "cleanup fails on stale hash, reports error",
			deployer: &fakeDeployer{
				cleanupErr: fmt.Errorf("delete forbidden"),
				podStatus: corev1.PodStatus{
					Conditions: []corev1.PodCondition{
						{Type: KMSPreflightConfigHashPodCondition, Message: "old-hash"},
					},
				},
			},
			apiServerObjects: []runtime.Object{apiServerWithKMS},
			coreObjects:      []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			operatorConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightRequired", Status: operatorv1.ConditionTrue, Message: wellKnownMatchingHashForBaseVaultConfig},
			},
			preconditionsMet: true,
			expectedError:    "delete forbidden",
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "True", Reason: "Error", Message: "delete forbidden"},
				{Type: "EncryptionKMSPreflightRequired", Status: operatorv1.ConditionTrue, Message: wellKnownMatchingHashForBaseVaultConfig},
			},
		},
		{
			name: "pod crashed, no terminated container, keeps pod for inspection",
			deployer: &fakeDeployer{podStatus: corev1.PodStatus{
				Phase:   corev1.PodFailed,
				Message: "node lost",
			}},
			apiServerObjects: []runtime.Object{apiServerWithKMS},
			coreObjects:      []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			operatorConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightRequired", Status: operatorv1.ConditionTrue, Message: wellKnownMatchingHashForBaseVaultConfig},
			},
			preconditionsMet: true,
			expectedError:    "preflight pod failed for hash k6dSVA==: node lost",
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "True", Reason: "Unknown", Message: "preflight pod failed for hash k6dSVA==: node lost"},
				{Type: "EncryptionKMSPreflightRequired", Status: operatorv1.ConditionTrue, Message: wellKnownMatchingHashForBaseVaultConfig},
			},
		},
		{
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
			apiServerObjects: []runtime.Object{apiServerWithKMS},
			coreObjects:      []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			operatorConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightRequired", Status: operatorv1.ConditionTrue, Message: wellKnownMatchingHashForBaseVaultConfig},
			},
			preconditionsMet: true,
			expectedError:    "preflight pod failed for hash k6dSVA==: at least one container kms-preflight-check exited with 137 (Unknown)",
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "True", Reason: "Unknown", Message: "preflight pod failed for hash k6dSVA==: at least one container kms-preflight-check exited with 137 (Unknown)"},
				{Type: "EncryptionKMSPreflightRequired", Status: operatorv1.ConditionTrue, Message: wellKnownMatchingHashForBaseVaultConfig},
			},
		},
		{
			name:             "hashes differ, config changed since condition was posted, cleans up",
			apiServerObjects: []runtime.Object{apiServerWithKMS},
			coreObjects:      []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			operatorConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightRequired", Status: operatorv1.ConditionTrue, Message: "stale-hash"},
			},
			preconditionsMet: true,
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "False"},
				{Type: "EncryptionKMSPreflightRequired", Status: operatorv1.ConditionTrue, Message: "stale-hash"},
			},
		},
		{
			name:             "hash computation fails due to missing secret",
			apiServerObjects: []runtime.Object{apiServerWithKMS},
			coreObjects:      []runtime.Object{&wellKnownBaseConfigMap},
			operatorConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightRequired", Status: operatorv1.ConditionTrue, Message: wellKnownMatchingHashForBaseVaultConfig},
			},
			preconditionsMet: true,
			expectedError:    "failed to compute KMS config hash",
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "True", Reason: "Error", Message: `failed to compute KMS config hash: failed to get secret openshift-config/vault-approle: secrets "vault-approle" not found`},
				{Type: "EncryptionKMSPreflightRequired", Status: operatorv1.ConditionTrue, Message: wellKnownMatchingHashForBaseVaultConfig},
			},
		},
		{
			name:             "EncryptionKMSPreflightRequired condition is True but has empty message, treated as hash mismatch",
			apiServerObjects: []runtime.Object{apiServerWithKMS},
			coreObjects:      []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			operatorConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightRequired", Status: operatorv1.ConditionTrue, Message: ""},
			},
			preconditionsMet: true,
			expectedConditions: []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "False"},
				{Type: "EncryptionKMSPreflightRequired", Status: operatorv1.ConditionTrue, Message: ""},
			},
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			conditions := []operatorv1.OperatorCondition{
				{Type: "EncryptionKMSPreflightControllerDegraded", Status: "False"},
			}
			conditions = append(conditions, scenario.operatorConditions...)

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
			fakeApiServerInformer := configv1informers.NewSharedInformerFactory(fakeConfigClient, time.Minute).Config().V1().APIServers()

			preconditionsFn := func() (bool, error) { return scenario.preconditionsMet, nil }
			provider := newTestProvider([]schema.GroupResource{{Group: "", Resource: "secrets"}})

			deployer := scenario.deployer
			if deployer == nil {
				deployer = &fakeDeployer{}
			}

			target := NewKMSPreflightController(
				"test",
				provider,
				preconditionsFn,
				deployer,
				fakeOperatorClient,
				fakeApiServerClient,
				fakeApiServerInformer,
				fakeKubeClient.CoreV1(),
				eventRecorder,
			)

			err := target.Sync(context.TODO(), factory.NewSyncContext("test", eventRecorder))

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

			encryptiontesting.ValidateOperatorClientConditions(t, fakeOperatorClient, scenario.expectedConditions)
		})
	}
}
