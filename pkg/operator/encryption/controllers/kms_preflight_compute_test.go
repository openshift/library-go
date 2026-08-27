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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	apiserverconfigv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"

	"k8s.io/client-go/kubernetes/fake"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	configv1clientfake "github.com/openshift/client-go/config/clientset/versioned/fake"

	"github.com/openshift/library-go/pkg/operator/encryption/encryptiondata"
	"github.com/openshift/library-go/pkg/operator/encryption/secrets"
	"github.com/openshift/library-go/pkg/operator/encryption/state"
	"github.com/openshift/library-go/pkg/operator/encryption/statemachine"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

func TestKMSPreflightComputeEncryptionConfiguration(t *testing.T) {
	apiServerWithKMS := newKMSVaultAPIServer()
	encryptedGRs := []schema.GroupResource{{Group: "", Resource: "secrets"}}
	instanceName := "test"

	t.Run("first key, no existing secrets, produces key ID 1", func(t *testing.T) {
		computer := newKMSPreflightComputeComputer(
			[]runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			&fakeEncryptionDeployer{converged: true},
			apiServerWithKMS,
			newTestProvider(encryptedGRs),
			instanceName,
		)

		secret, err := computer.ComputeEncryptionConfiguration(context.TODO(), nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
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
		if kmsConfigs[0].Endpoint != "unix:///var/run/kmsplugin/kms-1.sock" {
			t.Errorf("unexpected endpoint: %s", kmsConfigs[0].Endpoint)
		}
		assertKMSKeyCredentials(t, cfg, "1", "role-123", "secret-456", "test-ca-cert")

		// Must match the state-controller shape for key 1.
		simulatedKey, err := secrets.FromKeyState(instanceName, state.KeyState{
			Key:  apiserverconfigv1.Key{Name: "1", Secret: base64.StdEncoding.EncodeToString(make([]byte, 16))},
			Mode: state.KMS,
			KMS: &state.KMSState{
				Encryption: &apiserverconfigv1.KMSConfiguration{
					APIVersion: "v2",
					Name:       "1",
					Endpoint:   "unix:///var/run/kmsplugin/kms-1.sock",
					Timeout:    &metav1.Duration{Duration: 10 * time.Second},
				},
				Plugin: apiServerWithKMS.Spec.Encryption.KMS,
			},
		})
		if err != nil {
			t.Fatalf("failed to build comparison key: %v", err)
		}
		ks, err := secrets.ToKeyState(simulatedKey)
		if err != nil {
			t.Fatalf("failed to parse comparison key: %v", err)
		}
		_ = ks.KMS.PluginSecretData.Set("vault-approle", "role-id", []byte("role-123"))
		_ = ks.KMS.PluginSecretData.Set("vault-approle", "secret-id", []byte("secret-456"))
		_ = ks.KMS.PluginConfigMapData.Set("vault-ca-bundle", "ca-bundle.crt", []byte("test-ca-cert"))
		simulatedKey, err = secrets.FromKeyState(instanceName, ks)
		if err != nil {
			t.Fatalf("failed to rebuild comparison key: %v", err)
		}
		assertPreflightConfigMatchesStateMachine(t, instanceName, secret, nil, []*corev1.Secret{simulatedKey}, encryptedGRs)
	})

	t.Run("existing key with deployed config, uses next key ID and retains credentials", func(t *testing.T) {
		existingKeySecret := newExistingKMSKeySecret(t, instanceName, apiServerWithKMS, encryptedGRs, "3")
		deployed := newDeployedKMSEncryptionConfig(t, instanceName, encryptedGRs, existingKeySecret)
		computer := newKMSPreflightComputeComputer(
			[]runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap, existingKeySecret},
			&fakeEncryptionDeployer{converged: true, secret: deployed},
			apiServerWithKMS,
			newTestProvider(encryptedGRs),
			instanceName,
		)

		secret, err := computer.ComputeEncryptionConfiguration(context.TODO(), nil)
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

		// Key 3 remains the write key (STEP 2 early return); key 4 is the new read key
		// the key-controller is about to create. Both must be present.
		var found3, found4 bool
		for _, kc := range kmsConfigs {
			switch kc.Name {
			case "3":
				found3 = true
			case "4":
				found4 = true
				if kc.Endpoint != "unix:///var/run/kmsplugin/kms-4.sock" {
					t.Errorf("unexpected endpoint for key 4: %s", kc.Endpoint)
				}
			}
		}
		if !found3 || !found4 {
			t.Fatalf("expected key IDs 3 and 4 among KMS configurations, got %+v", kmsConfigs)
		}
		assertKMSKeyCredentials(t, cfg, "3", "old-role-id", "old-secret-id", "old-ca-cert")
		assertKMSKeyCredentials(t, cfg, "4", "role-123", "secret-456", "test-ca-cert")

		newKey := newExistingKMSKeySecret(t, instanceName, apiServerWithKMS, encryptedGRs, "4")
		ks, err := secrets.ToKeyState(newKey)
		if err != nil {
			t.Fatalf("failed to parse new key: %v", err)
		}
		ks.KMS.Encryption.Endpoint = "unix:///var/run/kmsplugin/kms-4.sock"
		ks.KMS.Plugin = apiServerWithKMS.Spec.Encryption.KMS
		_ = ks.KMS.PluginSecretData.Set("vault-approle", "role-id", []byte("role-123"))
		_ = ks.KMS.PluginSecretData.Set("vault-approle", "secret-id", []byte("secret-456"))
		_ = ks.KMS.PluginConfigMapData.Set("vault-ca-bundle", "ca-bundle.crt", []byte("test-ca-cert"))
		newKey, err = secrets.FromKeyState(instanceName, ks)
		if err != nil {
			t.Fatalf("failed to rebuild new key: %v", err)
		}
		deployedCfg, err := encryptiondata.FromSecret(deployed)
		if err != nil {
			t.Fatalf("failed to parse deployed config: %v", err)
		}
		assertPreflightConfigMatchesStateMachine(t, instanceName, secret, deployedCfg, []*corev1.Secret{existingKeySecret, newKey}, encryptedGRs)
	})

	t.Run("new candidate key and existing key both use production endpoints", func(t *testing.T) {
		existingKeySecret := newExistingKMSKeySecret(t, instanceName, apiServerWithKMS, encryptedGRs, "3")
		deployed := newDeployedKMSEncryptionConfig(t, instanceName, encryptedGRs, existingKeySecret)
		computer := newKMSPreflightComputeComputer(
			[]runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap, existingKeySecret},
			&fakeEncryptionDeployer{converged: true, secret: deployed},
			apiServerWithKMS,
			newTestProvider(encryptedGRs),
			instanceName,
		)

		secret, err := computer.ComputeEncryptionConfiguration(context.TODO(), nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		cfg, err := encryptiondata.FromSecret(secret)
		if err != nil {
			t.Fatalf("failed to parse produced secret: %v", err)
		}
		endpointsByKey := kmsConfigEndpointsByName(t, cfg)
		if endpointsByKey["3"] != "unix:///var/run/kmsplugin/kms-3.sock" {
			t.Fatalf("expected existing key 3 to keep its original endpoint, got %q", endpointsByKey["3"])
		}
		if endpointsByKey["4"] != "unix:///var/run/kmsplugin/kms-4.sock" {
			t.Fatalf("expected candidate key 4 to use production endpoint %q, got %q", "unix:///var/run/kmsplugin/kms-4.sock", endpointsByKey["4"])
		}
	})

	t.Run("unbacked key in deployed config, next key ID follows needsNewKey", func(t *testing.T) {
		// Deployed config claims write key 5, but its secret was deleted. Only key 3
		// still exists. The key-controller's needsNewKey reads ReadKeys[0] (unbacked 5)
		// and creates key 6 — preflight must do the same, not max(secrets)+1=4.
		key3 := newExistingKMSKeySecret(t, instanceName, apiServerWithKMS, encryptedGRs, "3")
		unbacked := state.KeyState{
			Key:  apiserverconfigv1.Key{Name: "5", Secret: base64.StdEncoding.EncodeToString(make([]byte, 16))},
			Mode: state.KMS,
			KMS: &state.KMSState{
				Encryption: &apiserverconfigv1.KMSConfiguration{
					APIVersion: "v2",
					Name:       "5",
					Endpoint:   "unix:///var/run/kmsplugin/kms-5.sock",
					Timeout:    &metav1.Duration{Duration: 10 * time.Second},
				},
				Plugin: apiServerWithKMS.Spec.Encryption.KMS,
			},
		}
		cfg, err := encryptiondata.FromEncryptionState(map[schema.GroupResource]state.GroupResourceState{
			{Resource: "secrets"}: {WriteKey: unbacked, ReadKeys: []state.KeyState{unbacked}},
		})
		if err != nil {
			t.Fatalf("failed to build unbacked encryption config: %v", err)
		}
		deployed, err := encryptiondata.ToSecret("openshift-config-managed", "encryption-config-"+instanceName, cfg)
		if err != nil {
			t.Fatalf("failed to serialize unbacked encryption config: %v", err)
		}

		computer := newKMSPreflightComputeComputer(
			[]runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap, key3},
			&fakeEncryptionDeployer{converged: true, secret: deployed},
			apiServerWithKMS,
			newTestProvider(encryptedGRs),
			instanceName,
		)

		secret, err := computer.ComputeEncryptionConfiguration(context.TODO(), nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		out, err := encryptiondata.FromSecret(secret)
		if err != nil {
			t.Fatalf("failed to parse produced secret: %v", err)
		}
		kmsConfigs, err := encryptiondata.ExtractUniqueAndSortedKMSConfigurations(out)
		if err != nil {
			t.Fatalf("failed to extract KMS configurations: %v", err)
		}
		var found6 bool
		for _, kc := range kmsConfigs {
			if kc.Name == "4" {
				t.Errorf("must not use max(existing secrets)+1=4 when unbacked key 5 is latest; got %+v", kmsConfigs)
			}
			if kc.Name == "6" {
				found6 = true
			}
		}
		if !found6 {
			t.Errorf("expected next key ID 6 (unbacked 5 + 1) among KMS configurations, got %+v", kmsConfigs)
		}
	})

	t.Run("invalid key secrets are ignored when computing next key ID", func(t *testing.T) {
		// A corrupt secret whose name parses as key ID 5 must not bump the next ID.
		// GetDesiredEncryptionState skips secrets that fail ToKeyState, so valid key 2
		// → ReadKeys[0] is 2 → next is 3.
		validKeySecret := newExistingKMSKeySecret(t, instanceName, apiServerWithKMS, encryptedGRs, "2")
		invalidKeySecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "encryption-key-test-5",
				Namespace: "openshift-config-managed",
				Labels:    map[string]string{secrets.EncryptionKeySecretsLabel: instanceName},
			},
			Data: map[string][]byte{
				secrets.EncryptionSecretKeyDataKey: []byte("not-a-valid-key-secret"),
			},
		}
		deployed := newDeployedKMSEncryptionConfig(t, instanceName, encryptedGRs, validKeySecret)
		computer := newKMSPreflightComputeComputer(
			[]runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap, validKeySecret, invalidKeySecret},
			&fakeEncryptionDeployer{converged: true, secret: deployed},
			apiServerWithKMS,
			newTestProvider(encryptedGRs),
			instanceName,
		)

		secret, err := computer.ComputeEncryptionConfiguration(context.TODO(), nil)
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

		var found3 bool
		for _, kc := range kmsConfigs {
			if kc.Name == "3" {
				found3 = true
			}
			if kc.Name == "6" {
				t.Errorf("invalid secret name must not bump next key ID to 6, got %+v", kmsConfigs)
			}
		}
		if !found3 {
			t.Errorf("expected next key ID 3 among KMS configurations, got %+v", kmsConfigs)
		}
	})

	t.Run("no new key needed still returns existing write-key config for preflight", func(t *testing.T) {
		// Same provider as the current apiserver config and already migrated: planner
		// says needed=false. Preflight must reuse key 3 with its production endpoint.
		ks := state.KeyState{
			Key:  apiserverconfigv1.Key{Name: "3", Secret: base64.StdEncoding.EncodeToString(make([]byte, 16))},
			Mode: state.KMS,
			Migrated: state.MigrationState{
				Resources: encryptedGRs,
			},
			KMS: &state.KMSState{
				Encryption: &apiserverconfigv1.KMSConfiguration{
					APIVersion: "v2",
					Name:       "3",
					Endpoint:   "unix:///var/run/kmsplugin/kms-3.sock",
					Timeout:    &metav1.Duration{Duration: 10 * time.Second},
				},
				Plugin: apiServerWithKMS.Spec.Encryption.KMS,
			},
		}
		if err := ks.KMS.PluginSecretData.Set("vault-approle", "role-id", []byte("role-123")); err != nil {
			t.Fatalf("failed to set plugin secret data: %v", err)
		}
		if err := ks.KMS.PluginSecretData.Set("vault-approle", "secret-id", []byte("secret-456")); err != nil {
			t.Fatalf("failed to set plugin secret data: %v", err)
		}
		if err := ks.KMS.PluginConfigMapData.Set("vault-ca-bundle", "ca-bundle.crt", []byte("test-ca-cert")); err != nil {
			t.Fatalf("failed to set plugin configmap data: %v", err)
		}
		existingKeySecret, err := secrets.FromKeyState(instanceName, ks)
		if err != nil {
			t.Fatalf("failed to build existing key secret: %v", err)
		}
		deployed := newDeployedKMSEncryptionConfig(t, instanceName, encryptedGRs, existingKeySecret)
		computer := newKMSPreflightComputeComputer(
			[]runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap, existingKeySecret},
			&fakeEncryptionDeployer{converged: true, secret: deployed},
			apiServerWithKMS,
			newTestProvider(encryptedGRs),
			instanceName,
		)

		secret, err := computer.ComputeEncryptionConfiguration(context.TODO(), nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if secret == nil {
			t.Fatal("expected a secret")
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
			t.Fatalf("expected 1 KMS configuration, got %+v", kmsConfigs)
		}
		if kmsConfigs[0].Name != "3" {
			t.Fatalf("expected write key 3, got %s", kmsConfigs[0].Name)
		}
		if kmsConfigs[0].Endpoint != "unix:///var/run/kmsplugin/kms-3.sock" {
			t.Fatalf("expected write-key endpoint %s, got %s", "unix:///var/run/kmsplugin/kms-3.sock", kmsConfigs[0].Endpoint)
		}
		assertKMSKeyCredentials(t, cfg, "3", "role-123", "secret-456", "test-ca-cert")
	})

	t.Run("API server revisions not converged, still computes preflight config", func(t *testing.T) {
		computer := newKMSPreflightComputeComputer(
			[]runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			&fakeEncryptionDeployer{converged: false},
			apiServerWithKMS,
			newTestProvider(encryptedGRs),
			instanceName,
		)

		secret, err := computer.ComputeEncryptionConfiguration(context.TODO(), nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if secret == nil {
			t.Fatalf("expected a secret, got nil")
		}
	})

	t.Run("EncryptedGRs are read at compute time", func(t *testing.T) {
		provider := &testProvider{encryptedGRs: []schema.GroupResource{{Resource: "secrets"}}}
		computer := newKMSPreflightComputeComputer(
			[]runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap},
			&fakeEncryptionDeployer{converged: true},
			apiServerWithKMS,
			provider,
			instanceName,
		)

		first, err := computer.ComputeEncryptionConfiguration(context.TODO(), nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		firstNames := encryptedResourceNames(t, first)
		if !firstNames["secrets"] {
			t.Fatalf("expected secrets in first compute, got %v", firstNames)
		}
		if firstNames["configmaps"] {
			t.Fatalf("did not expect configmaps in first compute, got %v", firstNames)
		}

		provider.encryptedGRs = []schema.GroupResource{{Resource: "secrets"}, {Resource: "configmaps"}}
		second, err := computer.ComputeEncryptionConfiguration(context.TODO(), nil)
		if err != nil {
			t.Fatalf("unexpected error after EncryptedGRs change: %v", err)
		}
		secondNames := encryptedResourceNames(t, second)
		if !secondNames["secrets"] || !secondNames["configmaps"] {
			t.Fatalf("expected secrets and configmaps after EncryptedGRs change, got %v", secondNames)
		}
	})
}

func TestKMSPreflightComputeEncryptionConfigurationErrors(t *testing.T) {
	apiServerWithKMS := newKMSVaultAPIServer()
	encryptedGRs := []schema.GroupResource{{Group: "", Resource: "secrets"}}
	instanceName := "test"

	scenarios := []struct {
		name          string
		coreObjects   []runtime.Object
		deployer      *fakeEncryptionDeployer
		apiServer     *configv1.APIServer
		expectedError string
	}{
		{
			name:          "missing referenced secret returns an error",
			coreObjects:   []runtime.Object{&wellKnownBaseConfigMap},
			deployer:      &fakeEncryptionDeployer{converged: true},
			apiServer:     apiServerWithKMS,
			expectedError: "vault-approle",
		},
		{
			name:          "missing referenced configmap returns an error",
			coreObjects:   []runtime.Object{&wellKnownBaseSecret},
			deployer:      &fakeEncryptionDeployer{converged: true},
			apiServer:     apiServerWithKMS,
			expectedError: "vault-ca-bundle",
		},
		{
			name:          "encryption deployer error is propagated",
			coreObjects:   nil,
			deployer:      &fakeEncryptionDeployer{err: fmt.Errorf("boom")},
			apiServer:     apiServerWithKMS,
			expectedError: "boom",
		},
		{
			name: "invalid deployed encryption config returns an error",
			coreObjects: []runtime.Object{
				&wellKnownBaseSecret,
				&wellKnownBaseConfigMap,
			},
			deployer: &fakeEncryptionDeployer{
				converged: true,
				secret: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: "encryption-config-test", Namespace: "openshift-config-managed"},
					Data:       map[string][]byte{encryptiondata.EncryptionConfSecretKey: []byte("not-valid-json")},
				},
			},
			apiServer:     apiServerWithKMS,
			expectedError: "",
		},
		{
			name:        "non-KMS mode returns an error",
			coreObjects: nil,
			deployer:    &fakeEncryptionDeployer{converged: true},
			apiServer: &configv1.APIServer{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec:       configv1.APIServerSpec{Encryption: configv1.APIServerEncryption{Type: configv1.EncryptionTypeAESCBC}},
			},
			expectedError: "KMS",
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			computer := newKMSPreflightComputeComputer(
				scenario.coreObjects,
				scenario.deployer,
				scenario.apiServer,
				newTestProvider(encryptedGRs),
				instanceName,
			)

			secret, err := computer.ComputeEncryptionConfiguration(context.TODO(), nil)
			if err == nil {
				t.Fatalf("expected an error, got secret %+v", secret)
			}
			if scenario.expectedError != "" && !strings.Contains(err.Error(), scenario.expectedError) {
				t.Fatalf("expected error containing %q, got: %v", scenario.expectedError, err)
			}
		})
	}
}

func newKMSPreflightComputeComputer(
	coreObjects []runtime.Object,
	encryptionDeployer statemachine.Deployer,
	apiServer *configv1.APIServer,
	provider Provider,
	instanceName string,
) EncryptionConfigurationComputer {
	fakeKubeClient := fake.NewSimpleClientset(coreObjects...)
	fakeConfigClient := configv1clientfake.NewSimpleClientset(apiServer)
	fakeOperatorClient := v1helpers.NewFakeStaticPodOperatorClient(
		&operatorv1.StaticPodOperatorSpec{OperatorSpec: operatorv1.OperatorSpec{ManagementState: operatorv1.Managed}},
		&operatorv1.StaticPodOperatorStatus{},
		nil,
		nil,
	)
	return NewEncryptionConfigurationComputer(
		instanceName,
		nil,
		provider,
		encryptionDeployer,
		fakeKubeClient.CoreV1(),
		fakeKubeClient.CoreV1(),
		fakeConfigClient.ConfigV1().APIServers(),
		fakeOperatorClient,
		metav1.ListOptions{},
	)
}

func assertKMSKeyCredentials(t *testing.T, cfg *encryptiondata.Config, keyID, roleID, secretID, caBundle string) {
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

func kmsConfigEndpointsByName(t *testing.T, cfg *encryptiondata.Config) map[string]string {
	t.Helper()

	kmsConfigs, err := encryptiondata.ExtractUniqueAndSortedKMSConfigurations(cfg)
	if err != nil {
		t.Fatalf("failed to extract KMS configurations: %v", err)
	}
	endpoints := map[string]string{}
	for _, kc := range kmsConfigs {
		endpoints[kc.Name] = kc.Endpoint
	}
	return endpoints
}

func encryptedResourceNames(t *testing.T, secret *corev1.Secret) map[string]bool {
	t.Helper()

	cfg, err := encryptiondata.FromSecret(secret)
	if err != nil {
		t.Fatalf("failed to parse secret: %v", err)
	}
	names := map[string]bool{}
	if cfg.Encryption == nil {
		return names
	}
	for _, rc := range cfg.Encryption.Resources {
		for _, r := range rc.Resources {
			names[r] = true
		}
	}
	return names
}

func assertPreflightConfigMatchesStateMachine(
	t *testing.T,
	instanceName string,
	got *corev1.Secret,
	deployedCfg *encryptiondata.Config,
	keySecrets []*corev1.Secret,
	encryptedGRs []schema.GroupResource,
) {
	t.Helper()

	desired := statemachine.GetDesiredEncryptionState(deployedCfg, keySecrets, encryptedGRs)
	wantCfg, err := encryptiondata.FromEncryptionState(desired)
	if err != nil {
		t.Fatalf("failed to build golden config: %v", err)
	}
	wantSecret, err := encryptiondata.ToSecret("openshift-config-managed", "encryption-config-"+instanceName, wantCfg)
	if err != nil {
		t.Fatalf("failed to serialize golden config: %v", err)
	}
	if !equality.Semantic.DeepEqual(got.Data, wantSecret.Data) {
		t.Errorf("preflight secret data diverges from state-machine golden config")
	}
}
