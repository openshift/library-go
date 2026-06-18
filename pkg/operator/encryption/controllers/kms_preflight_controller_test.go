package controllers

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
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

func TestKMSConfigHasher(t *testing.T) {
	baseVaultConfig := configv1.VaultKMSPluginConfig{
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

	baseSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "vault-approle", Namespace: "openshift-config"},
		Data: map[string][]byte{
			"role-id":   []byte("role-123"),
			"secret-id": []byte("secret-456"),
		},
	}

	baseConfigMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "vault-ca-bundle", Namespace: "openshift-config"},
		Data:       map[string]string{"ca-bundle.crt": "test-ca-cert"},
	}

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
			vaultConfig:  baseVaultConfig,
			resources:    []runtime.Object{baseSecret, baseConfigMap},
			expectedHash: "k6dSVA==",
		},
		{
			name: "changing KMSPluginImage",
			vaultConfig: func() configv1.VaultKMSPluginConfig {
				c := baseVaultConfig
				c.KMSPluginImage = "registry.example.com/plugin@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
				return c
			}(),
			resources:    []runtime.Object{baseSecret, baseConfigMap},
			expectedHash: "DC20hA==",
		},
		{
			name: "changing VaultAddress",
			vaultConfig: func() configv1.VaultKMSPluginConfig {
				c := baseVaultConfig
				c.VaultAddress = "https://other-vault.example.com:8200"
				return c
			}(),
			resources:    []runtime.Object{baseSecret, baseConfigMap},
			expectedHash: "VOhO4Q==",
		},
		{
			name: "changing VaultNamespace",
			vaultConfig: func() configv1.VaultKMSPluginConfig {
				c := baseVaultConfig
				c.VaultNamespace = "my-namespace"
				return c
			}(),
			resources:    []runtime.Object{baseSecret, baseConfigMap},
			expectedHash: "uQnh1w==",
		},
		{
			name: "changing TransitMount",
			vaultConfig: func() configv1.VaultKMSPluginConfig {
				c := baseVaultConfig
				c.TransitMount = "other-transit"
				return c
			}(),
			resources:    []runtime.Object{baseSecret, baseConfigMap},
			expectedHash: "yBP5JQ==",
		},
		{
			name: "changing TransitKey",
			vaultConfig: func() configv1.VaultKMSPluginConfig {
				c := baseVaultConfig
				c.TransitKey = "other-key"
				return c
			}(),
			resources:    []runtime.Object{baseSecret, baseConfigMap},
			expectedHash: "IH9sCA==",
		},
		{
			name: "changing TLS.ServerName",
			vaultConfig: func() configv1.VaultKMSPluginConfig {
				c := baseVaultConfig
				c.TLS.ServerName = "vault.example.com"
				return c
			}(),
			resources:    []runtime.Object{baseSecret, baseConfigMap},
			expectedHash: "o6TBAQ==",
		},
		{
			name: "changing TLS.CABundle.Name",
			vaultConfig: func() configv1.VaultKMSPluginConfig {
				c := baseVaultConfig
				c.TLS.CABundle.Name = "other-ca-bundle"
				return c
			}(),
			resources: []runtime.Object{baseSecret, &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "other-ca-bundle", Namespace: "openshift-config"},
				Data:       map[string]string{"ca-bundle.crt": "test-ca-cert"},
			}},
			expectedHash: "rIBPRg==",
		},
		{
			name: "changing Authentication.AppRole.Secret.Name",
			vaultConfig: func() configv1.VaultKMSPluginConfig {
				c := baseVaultConfig
				c.Authentication.AppRole.Secret.Name = "other-secret"
				return c
			}(),
			resources: []runtime.Object{baseConfigMap, &corev1.Secret{
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
			vaultConfig: baseVaultConfig,
			resources: []runtime.Object{baseConfigMap, &corev1.Secret{
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
			vaultConfig: baseVaultConfig,
			resources: []runtime.Object{baseConfigMap, &corev1.Secret{
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
			vaultConfig: baseVaultConfig,
			resources: []runtime.Object{baseConfigMap, &corev1.Secret{
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
			vaultConfig: baseVaultConfig,
			resources: []runtime.Object{baseSecret, &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "vault-ca-bundle", Namespace: "openshift-config"},
				Data:       map[string]string{"ca-bundle.crt": "test-ca-cert", "extra": "ignored"},
			}},
			expectedHash: "k6dSVA==",
		},
		{
			name:        "changing ca-bundle.crt value",
			vaultConfig: baseVaultConfig,
			resources: []runtime.Object{baseSecret, &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "vault-ca-bundle", Namespace: "openshift-config"},
				Data:       map[string]string{"ca-bundle.crt": "different-ca-cert"},
			}},
			expectedHash: "6nq3gw==",
		},
		{
			name: "no configmap configured",
			vaultConfig: func() configv1.VaultKMSPluginConfig {
				c := baseVaultConfig
				c.TLS.CABundle.Name = ""
				return c
			}(),
			resources:    []runtime.Object{baseSecret},
			expectedHash: "rGXYog==",
		},
		{
			name:        "shifting bytes between secret keys produces a different hash",
			vaultConfig: baseVaultConfig,
			resources: []runtime.Object{baseConfigMap, &corev1.Secret{
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
			vaultConfig:   baseVaultConfig,
			resources:     []runtime.Object{baseConfigMap},
			expectedError: "failed to get secret",
		},
		{
			name:        "missing key in secret returns error",
			vaultConfig: baseVaultConfig,
			resources: []runtime.Object{baseConfigMap, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "vault-approle", Namespace: "openshift-config"},
				Data: map[string][]byte{
					"role-id": []byte("role-123"),
				},
			}},
			expectedError: `key "secret-id" not found in secret`,
		},
		{
			name:          "missing configmap returns error",
			vaultConfig:   baseVaultConfig,
			resources:     []runtime.Object{baseSecret},
			expectedError: "failed to get configmap",
		},
		{
			name:        "missing key in configmap returns error",
			vaultConfig: baseVaultConfig,
			resources: []runtime.Object{baseSecret, &corev1.ConfigMap{
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

func TestKMSPreflightController(t *testing.T) {
	scenarios := []struct {
		name              string
		apiServerObjects  []runtime.Object
		preconditionsMet  bool
		expectedError     bool
		expectedCondition *operatorv1.OperatorCondition
	}{
		{
			name:             "preconditions not met, clears degraded",
			apiServerObjects: []runtime.Object{&configv1.APIServer{ObjectMeta: metav1.ObjectMeta{Name: "cluster"}}},
			preconditionsMet: false,
			expectedError:    false,
			expectedCondition: &operatorv1.OperatorCondition{
				Type:   "EncryptionKMSPreflightControllerDegraded",
				Status: "False",
			},
		},
		{
			name:             "preconditions met, sync returns error from stub",
			apiServerObjects: []runtime.Object{&configv1.APIServer{ObjectMeta: metav1.ObjectMeta{Name: "cluster"}}},
			preconditionsMet: true,
			expectedError:    true,
			expectedCondition: &operatorv1.OperatorCondition{
				Type:    "EncryptionKMSPreflightControllerDegraded",
				Status:  "True",
				Reason:  "Error",
				Message: "implement me",
			},
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			fakeOperatorClient := v1helpers.NewFakeStaticPodOperatorClient(
				&operatorv1.StaticPodOperatorSpec{
					OperatorSpec: operatorv1.OperatorSpec{
						ManagementState: operatorv1.Managed,
					},
				},
				&operatorv1.StaticPodOperatorStatus{
					OperatorStatus: operatorv1.OperatorStatus{
						Conditions: []operatorv1.OperatorCondition{
							{
								Type:   "EncryptionKMSPreflightControllerDegraded",
								Status: "False",
							},
						},
					},
				},
				nil,
				nil,
			)

			fakeKubeClient := fake.NewSimpleClientset()
			eventRecorder := events.NewRecorder(fakeKubeClient.CoreV1().Events("test"), "test-kmsPreflightController", &corev1.ObjectReference{}, clocktesting.NewFakePassiveClock(time.Now()))

			fakeConfigClient := configv1clientfake.NewSimpleClientset(scenario.apiServerObjects...)
			fakeApiServerClient := fakeConfigClient.ConfigV1().APIServers()
			fakeApiServerInformer := configv1informers.NewSharedInformerFactory(fakeConfigClient, time.Minute).Config().V1().APIServers()

			preconditionsFn := func() (bool, error) { return scenario.preconditionsMet, nil }
			provider := newTestProvider([]schema.GroupResource{{Group: "", Resource: "secrets"}})

			target := NewKMSPreflightController(
				"test",
				provider,
				preconditionsFn,
				fakeOperatorClient,
				fakeApiServerClient,
				fakeApiServerInformer,
				eventRecorder,
			)

			err := target.Sync(context.TODO(), factory.NewSyncContext("test", eventRecorder))

			if scenario.expectedError && err == nil {
				t.Fatal("expected error but got nil")
			}
			if !scenario.expectedError && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if scenario.expectedCondition != nil {
				encryptiontesting.ValidateOperatorClientConditions(t, fakeOperatorClient, []operatorv1.OperatorCondition{*scenario.expectedCondition})
			}
		})
	}
}
