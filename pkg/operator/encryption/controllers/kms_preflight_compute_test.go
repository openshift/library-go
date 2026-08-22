package controllers

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	apiserverconfigv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
	"k8s.io/client-go/kubernetes/fake"

	"k8s.io/apimachinery/pkg/api/equality"

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

	newControllerFor := func(coreObjects []runtime.Object, encryptionDeployer statemachine.Deployer, apiServer *configv1.APIServer, provider Provider) *kmsPreflightController {
		fakeKubeClient := fake.NewSimpleClientset(coreObjects...)
		fakeConfigClient := configv1clientfake.NewSimpleClientset(apiServer)
		fakeOperatorClient := v1helpers.NewFakeStaticPodOperatorClient(
			&operatorv1.StaticPodOperatorSpec{OperatorSpec: operatorv1.OperatorSpec{ManagementState: operatorv1.Managed}},
			&operatorv1.StaticPodOperatorStatus{},
			nil,
			nil,
		)
		return &kmsPreflightController{
			instanceName:             "test",
			encryptionSecretSelector: metav1.ListOptions{},
			operatorClient:           fakeOperatorClient,
			apiServerClient:          fakeConfigClient.ConfigV1().APIServers(),
			secretsClient:            fakeKubeClient.CoreV1(),
			configMapsClient:         fakeKubeClient.CoreV1(),
			encryptionDeployer:       encryptionDeployer,
			provider:                 provider,
		}
	}
	newController := func(coreObjects []runtime.Object, encryptionDeployer statemachine.Deployer) *kmsPreflightController {
		return newControllerFor(coreObjects, encryptionDeployer, apiServerWithKMS, newTestProvider(encryptedGRs))
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
		controller := newController([]runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap}, &fakeEncryptionDeployer{converged: true})

		secret, err := controller.computeEncryptionConfiguration(context.TODO())
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
		assertKeyCredentials(t, cfg, "1", "role-123", "secret-456", "test-ca-cert")

		// Must match the state-controller shape for key 1.
		simulatedKey, err := secrets.FromKeyState("test", state.KeyState{
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
		controller := newController(
			[]runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap, existingKeySecret},
			&fakeEncryptionDeployer{converged: true, secret: deployed},
		)

		secret, err := controller.computeEncryptionConfiguration(context.TODO())
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
		assertKeyCredentials(t, cfg, "3", "old-role-id", "old-secret-id", "old-ca-cert")
		assertKeyCredentials(t, cfg, "4", "role-123", "secret-456", "test-ca-cert")

		// Golden: must match the expected candidate config once key 4 is
		// simulated for preflight, using production endpoints and carrying the
		// current apiserver plugin config (not the old key's).
		newKey := newExistingKeySecret(t, "4")
		ks, err := secrets.ToKeyState(newKey)
		if err != nil {
			t.Fatalf("failed to parse new key: %v", err)
		}
		ks.KMS.Encryption.Endpoint = "unix:///var/run/kmsplugin/kms-4.sock"
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

	t.Run("new candidate key and existing key both use production endpoints", func(t *testing.T) {
		existingKeySecret := newExistingKeySecret(t, "3")
		deployed := newDeployedEncryptionConfig(t, existingKeySecret)
		controller := newController(
			[]runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap, existingKeySecret},
			&fakeEncryptionDeployer{converged: true, secret: deployed},
		)

		secret, err := controller.computeEncryptionConfiguration(context.TODO())
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
		if endpointsByKey["4"] != "unix:///var/run/kmsplugin/kms-4.sock" {
			t.Fatalf("expected candidate key 4 to use production endpoint %q, got %q", "unix:///var/run/kmsplugin/kms-4.sock", endpointsByKey["4"])
		}
	})

	t.Run("unbacked key in deployed config, next key ID follows needsNewKey", func(t *testing.T) {
		// Deployed config claims write key 5, but its secret was deleted. Only key 3
		// still exists. The key-controller's needsNewKey reads ReadKeys[0] (unbacked 5)
		// and creates key 6 — preflight must do the same, not max(secrets)+1=4.
		key3 := newExistingKeySecret(t, "3")
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
		deployed, err := encryptiondata.ToSecret("openshift-config-managed", "encryption-config-test", cfg)
		if err != nil {
			t.Fatalf("failed to serialize unbacked encryption config: %v", err)
		}

		controller := newController(
			[]runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap, key3},
			&fakeEncryptionDeployer{converged: true, secret: deployed},
		)

		secret, err := controller.computeEncryptionConfiguration(context.TODO())
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
		validKeySecret := newExistingKeySecret(t, "2")
		invalidKeySecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "encryption-key-test-5",
				Namespace: "openshift-config-managed",
				Labels:    map[string]string{secrets.EncryptionKeySecretsLabel: "test"},
			},
			Data: map[string][]byte{
				secrets.EncryptionSecretKeyDataKey: []byte("not-a-valid-key-secret"),
			},
		}
		deployed := newDeployedEncryptionConfig(t, validKeySecret)
		controller := newController(
			[]runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap, validKeySecret, invalidKeySecret},
			&fakeEncryptionDeployer{converged: true, secret: deployed},
		)

		secret, err := controller.computeEncryptionConfiguration(context.TODO())
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
		existingKeySecret, err := secrets.FromKeyState("test", ks)
		if err != nil {
			t.Fatalf("failed to build existing key secret: %v", err)
		}
		deployed := newDeployedEncryptionConfig(t, existingKeySecret)
		controller := newController(
			[]runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap, existingKeySecret},
			&fakeEncryptionDeployer{converged: true, secret: deployed},
		)

		secret, err := controller.computeEncryptionConfiguration(context.TODO())
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
		assertKeyCredentials(t, cfg, "3", "role-123", "secret-456", "test-ca-cert")
	})

	t.Run("API server revisions not converged, still computes preflight config", func(t *testing.T) {
		controller := newController([]runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap}, &fakeEncryptionDeployer{converged: false})

		secret, err := controller.computeEncryptionConfiguration(context.TODO())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if secret == nil {
			t.Fatalf("expected a secret, got nil")
		}
	})

	t.Run("missing referenced secret returns an error", func(t *testing.T) {
		controller := newController([]runtime.Object{&wellKnownBaseConfigMap}, &fakeEncryptionDeployer{converged: true})

		secret, err := controller.computeEncryptionConfiguration(context.TODO())
		if err == nil {
			t.Fatalf("expected an error, got secret %+v", secret)
		}
		if !strings.Contains(err.Error(), "vault-approle") {
			t.Fatalf("expected error mentioning the missing secret, got: %v", err)
		}
	})

	t.Run("missing referenced configmap returns an error", func(t *testing.T) {
		controller := newController([]runtime.Object{&wellKnownBaseSecret}, &fakeEncryptionDeployer{converged: true})

		secret, err := controller.computeEncryptionConfiguration(context.TODO())
		if err == nil {
			t.Fatalf("expected an error, got secret %+v", secret)
		}
		if !strings.Contains(err.Error(), "vault-ca-bundle") {
			t.Fatalf("expected error mentioning the missing configmap, got: %v", err)
		}
	})

	t.Run("encryption deployer error is propagated", func(t *testing.T) {
		controller := newController(nil, &fakeEncryptionDeployer{err: fmt.Errorf("boom")})

		_, err := controller.computeEncryptionConfiguration(context.TODO())
		if err == nil || !strings.Contains(err.Error(), "boom") {
			t.Fatalf("expected error containing %q, got: %v", "boom", err)
		}
	})

	t.Run("invalid deployed encryption config returns an error", func(t *testing.T) {
		invalidSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "encryption-config-test", Namespace: "openshift-config-managed"},
			Data:       map[string][]byte{encryptiondata.EncryptionConfSecretKey: []byte("not-valid-json")},
		}
		controller := newController([]runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap}, &fakeEncryptionDeployer{converged: true, secret: invalidSecret})

		_, err := controller.computeEncryptionConfiguration(context.TODO())
		if err == nil {
			t.Fatalf("expected an error for an invalid deployed encryption config")
		}
	})

	t.Run("non-KMS mode returns an error", func(t *testing.T) {
		apiServerAESCBC := &configv1.APIServer{
			ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
			Spec:       configv1.APIServerSpec{Encryption: configv1.APIServerEncryption{Type: configv1.EncryptionTypeAESCBC}},
		}
		controller := newControllerFor(nil, &fakeEncryptionDeployer{converged: true}, apiServerAESCBC, newTestProvider(encryptedGRs))

		_, err := controller.computeEncryptionConfiguration(context.TODO())
		if err == nil {
			t.Fatal("expected an error for aescbc mode")
		}
		if !strings.Contains(err.Error(), "KMS") {
			t.Fatalf("expected error mentioning KMS mode, got: %v", err)
		}
	})

	t.Run("EncryptedGRs are read at compute time", func(t *testing.T) {
		provider := &testProvider{encryptedGRs: []schema.GroupResource{{Resource: "secrets"}}}
		controller := newControllerFor([]runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap}, &fakeEncryptionDeployer{converged: true}, apiServerWithKMS, provider)

		resourceNames := func(t *testing.T, secret *corev1.Secret) map[string]bool {
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

		first, err := controller.computeEncryptionConfiguration(context.TODO())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		firstNames := resourceNames(t, first)
		if !firstNames["secrets"] {
			t.Fatalf("expected secrets in first compute, got %v", firstNames)
		}
		if firstNames["configmaps"] {
			t.Fatalf("did not expect configmaps in first compute, got %v", firstNames)
		}

		provider.encryptedGRs = []schema.GroupResource{{Resource: "secrets"}, {Resource: "configmaps"}}
		second, err := controller.computeEncryptionConfiguration(context.TODO())
		if err != nil {
			t.Fatalf("unexpected error after EncryptedGRs change: %v", err)
		}
		secondNames := resourceNames(t, second)
		if !secondNames["secrets"] || !secondNames["configmaps"] {
			t.Fatalf("expected secrets and configmaps after EncryptedGRs change, got %v", secondNames)
		}
	})
}
