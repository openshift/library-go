package controllers

import (
	"context"
	"encoding/base64"
	"fmt"
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

// TestEncryptionPlannerDriftGuard documents the anti-drift contract: candidate compute must match what the state controller would compute after the planned key Secret is persisted.
func TestEncryptionPlannerDriftGuard(t *testing.T) {
	apiServerWithKMS := &configv1.APIServer{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
		Spec: configv1.APIServerSpec{
			Encryption: configv1.APIServerEncryption{
				Type: "KMS",
				KMS: configv1.KMSPluginConfig{
					Type:  configv1.VaultKMSProvider,
					Vault: wellKnownBaseVaultConfig,
				},
			},
		},
	}
	encryptedGRs := []schema.GroupResource{{Group: "", Resource: "secrets"}}
	instanceName := "test"

	newExistingKeySecret := func(t *testing.T, keyID string) *corev1.Secret {
		t.Helper()
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
		s, err := secrets.FromKeyState(instanceName, ks)
		if err != nil {
			t.Fatalf("failed to build existing key secret: %v", err)
		}
		return s
	}

	newDeployedEncryptionConfig := func(t *testing.T, keySecrets ...*corev1.Secret) *corev1.Secret {
		t.Helper()
		desired := statemachine.GetDesiredEncryptionState(nil, keySecrets, encryptedGRs)
		cfg, err := encryptiondata.FromEncryptionState(desired)
		if err != nil {
			t.Fatalf("failed to build intermediate encryption config: %v", err)
		}
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

	existingKey := newExistingKeySecret(t, "3")
	deployed := newDeployedEncryptionConfig(t, existingKey)
	coreObjects := []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap, existingKey}
	fakeKubeClient := fake.NewSimpleClientset(coreObjects...)
	fakeConfigClient := configv1clientfake.NewSimpleClientset(apiServerWithKMS)
	fakeOperatorClient := v1helpers.NewFakeStaticPodOperatorClient(
		&operatorv1.StaticPodOperatorSpec{OperatorSpec: operatorv1.OperatorSpec{ManagementState: operatorv1.Managed}},
		&operatorv1.StaticPodOperatorStatus{},
		nil,
		nil,
	)
	deployer := &fakeEncryptionDeployer{converged: true, secret: deployed}
	secretSelector := metav1.ListOptions{}

	planner := NewEncryptionPlanner(instanceName, nil, deployer, fakeKubeClient.CoreV1(), fakeKubeClient.CoreV1(), fakeConfigClient.ConfigV1().APIServers(), fakeOperatorClient, secretSelector)

	// Preflight/candidate path via snapshot API.
	snap, err := planner.Load(context.TODO(), encryptedGRs, LoadOptions{ListKeysWhileProgressing: true})
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	plan, err := planner.PlanNextKey(snap)
	if err != nil {
		t.Fatalf("PlanNextKey failed: %v", err)
	}
	if !plan.Needed {
		t.Fatal("expected a planned key for provider change")
	}
	plannedKey, err := planner.MaterializeKey(context.TODO(), snap, plan)
	if err != nil {
		t.Fatalf("MaterializeKey failed: %v", err)
	}
	candidate, err := planner.ComputeConfig(&snap.State, plannedKey)
	if err != nil {
		t.Fatalf("ComputeConfig (candidate) failed: %v", err)
	}
	if candidate.EncryptionSecret == nil {
		t.Fatal("expected encryption secret from candidate compute")
	}

	// Persist the planned key, then compute as state controller would.
	if _, err := fakeKubeClient.CoreV1().Secrets("openshift-config-managed").Create(context.TODO(), plannedKey.Secret, metav1.CreateOptions{}); err != nil {
		t.Fatalf("failed to persist planned key: %v", err)
	}

	statePlanner := NewEncryptionPlanner(instanceName, nil, deployer, fakeKubeClient.CoreV1(), nil, nil, nil, secretSelector)
	stateSnap, err := statePlanner.LoadState(context.TODO(), encryptedGRs)
	if err != nil {
		t.Fatalf("LoadState (state) failed: %v", err)
	}
	asState, err := statePlanner.ComputeConfig(stateSnap, nil)
	if err != nil {
		t.Fatalf("ComputeConfig (state) failed: %v", err)
	}
	if asState.EncryptionSecret == nil {
		t.Fatal("expected encryption secret from state compute")
	}

	if !equality.Semantic.DeepEqual(candidate.EncryptionSecret.Data, asState.EncryptionSecret.Data) {
		t.Errorf("drift: Candidate encryption-config data diverges from state compute after key Create")
	}
}

func TestEncryptionPlannerFirstKey(t *testing.T) {
	apiServerWithKMS := &configv1.APIServer{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
		Spec: configv1.APIServerSpec{
			Encryption: configv1.APIServerEncryption{
				Type: "KMS",
				KMS: configv1.KMSPluginConfig{
					Type:  configv1.VaultKMSProvider,
					Vault: wellKnownBaseVaultConfig,
				},
			},
		},
	}
	encryptedGRs := []schema.GroupResource{{Group: "", Resource: "secrets"}}
	fakeKubeClient := fake.NewSimpleClientset(&wellKnownBaseSecret, &wellKnownBaseConfigMap)
	fakeConfigClient := configv1clientfake.NewSimpleClientset(apiServerWithKMS)
	fakeOperatorClient := v1helpers.NewFakeStaticPodOperatorClient(
		&operatorv1.StaticPodOperatorSpec{OperatorSpec: operatorv1.OperatorSpec{ManagementState: operatorv1.Managed}},
		&operatorv1.StaticPodOperatorStatus{},
		nil,
		nil,
	)

	planner := NewEncryptionPlanner("test", nil, &fakeEncryptionDeployer{converged: true}, fakeKubeClient.CoreV1(), fakeKubeClient.CoreV1(), fakeConfigClient.ConfigV1().APIServers(), fakeOperatorClient, metav1.ListOptions{})

	snap, err := planner.Load(context.TODO(), encryptedGRs, LoadOptions{ListKeysWhileProgressing: true})
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if snap.State.ProgressingReason != "" {
		t.Fatalf("unexpected progressing: %s", snap.State.ProgressingReason)
	}
	plan, err := planner.PlanNextKey(snap)
	if err != nil {
		t.Fatalf("PlanNextKey failed: %v", err)
	}
	if !plan.Needed || plan.KeyID != 1 {
		t.Fatalf("expected planned key ID 1, got %+v", plan)
	}

	plannedKey, err := planner.MaterializeKey(context.TODO(), snap, plan)
	if err != nil {
		t.Fatalf("MaterializeKey failed: %v", err)
	}
	candidate, err := planner.ComputeConfig(&snap.State, plannedKey)
	if err != nil {
		t.Fatalf("ComputeConfig failed: %v", err)
	}
	if candidate.EncryptionSecret == nil {
		t.Fatal("expected encryption secret")
	}
	cfg, err := encryptiondata.FromSecret(candidate.EncryptionSecret)
	if err != nil {
		t.Fatalf("failed to parse secret: %v", err)
	}
	kmsConfigs, err := encryptiondata.ExtractUniqueAndSortedKMSConfigurations(cfg)
	if err != nil {
		t.Fatalf("failed to extract KMS configs: %v", err)
	}
	if len(kmsConfigs) != 1 || kmsConfigs[0].Name != "1" {
		t.Fatalf("expected key ID 1, got %+v", kmsConfigs)
	}
	if kmsConfigs[0].Endpoint != "unix:///var/run/kmsplugin/kms-1.sock" {
		t.Errorf("unexpected endpoint, got %s", kmsConfigs[0].Endpoint)
	}
}

// TestEncryptionPlannerDecideVsMaterialize documents that PlanNextKey is deterministic over a snapshot while MaterializeKey produces fresh key material each call. Uses aescbc because KMS mode intentionally generates empty key bytes.
func TestEncryptionPlannerDecideVsMaterialize(t *testing.T) {
	apiServer := &configv1.APIServer{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
		Spec: configv1.APIServerSpec{
			Encryption: configv1.APIServerEncryption{Type: "aescbc"},
		},
	}
	encryptedGRs := []schema.GroupResource{{Group: "", Resource: "secrets"}}
	fakeKubeClient := fake.NewSimpleClientset()
	fakeConfigClient := configv1clientfake.NewSimpleClientset(apiServer)
	fakeOperatorClient := v1helpers.NewFakeStaticPodOperatorClient(
		&operatorv1.StaticPodOperatorSpec{OperatorSpec: operatorv1.OperatorSpec{ManagementState: operatorv1.Managed}},
		&operatorv1.StaticPodOperatorStatus{},
		nil,
		nil,
	)
	planner := NewEncryptionPlanner("test", nil, &fakeEncryptionDeployer{converged: true}, fakeKubeClient.CoreV1(), fakeKubeClient.CoreV1(), fakeConfigClient.ConfigV1().APIServers(), fakeOperatorClient, metav1.ListOptions{})

	snap, err := planner.Load(context.TODO(), encryptedGRs, LoadOptions{})
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	plan1, err := planner.PlanNextKey(snap)
	if err != nil {
		t.Fatalf("PlanNextKey #1 failed: %v", err)
	}
	plan2, err := planner.PlanNextKey(snap)
	if err != nil {
		t.Fatalf("PlanNextKey #2 failed: %v", err)
	}
	if !equality.Semantic.DeepEqual(plan1, plan2) {
		t.Fatalf("PlanNextKey is not deterministic: %+v vs %+v", plan1, plan2)
	}
	if !plan1.Needed {
		t.Fatal("expected a needed key plan for first aescbc key")
	}

	key1, err := planner.MaterializeKey(context.TODO(), snap, plan1)
	if err != nil {
		t.Fatalf("MaterializeKey #1 failed: %v", err)
	}
	key2, err := planner.MaterializeKey(context.TODO(), snap, plan1)
	if err != nil {
		t.Fatalf("MaterializeKey #2 failed: %v", err)
	}
	if equality.Semantic.DeepEqual(key1.Secret.Data, key2.Secret.Data) {
		t.Fatal("expected MaterializeKey to produce different key material on successive calls")
	}
	if key1.KeyID != key2.KeyID || key1.KeyID != plan1.KeyID {
		t.Fatalf("key IDs diverged: plan=%d key1=%d key2=%d", plan1.KeyID, key1.KeyID, key2.KeyID)
	}
}

func TestEncryptionPlannerLoadListKeysWhileProgressing(t *testing.T) {
	apiServer := &configv1.APIServer{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
		Spec:       configv1.APIServerSpec{Encryption: configv1.APIServerEncryption{Type: "aescbc"}},
	}
	encryptedGRs := []schema.GroupResource{{Group: "", Resource: "secrets"}}
	existingKey := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "encryption-key-test-1", Namespace: "openshift-config-managed"}}
	fakeKubeClient := fake.NewSimpleClientset(existingKey)
	fakeConfigClient := configv1clientfake.NewSimpleClientset(apiServer)
	fakeOperatorClient := v1helpers.NewFakeStaticPodOperatorClient(
		&operatorv1.StaticPodOperatorSpec{OperatorSpec: operatorv1.OperatorSpec{ManagementState: operatorv1.Managed}},
		&operatorv1.StaticPodOperatorStatus{},
		nil,
		nil,
	)
	planner := NewEncryptionPlanner("test", nil, &fakeEncryptionDeployer{converged: false}, fakeKubeClient.CoreV1(), fakeKubeClient.CoreV1(), fakeConfigClient.ConfigV1().APIServers(), fakeOperatorClient, metav1.ListOptions{})

	shortcut, err := planner.Load(context.TODO(), encryptedGRs, LoadOptions{})
	if err != nil {
		t.Fatalf("Load (default) failed: %v", err)
	}
	if shortcut.State.ProgressingReason == "" {
		t.Fatal("expected progressing reason when deployer is not converged")
	}
	if len(shortcut.State.KeySecrets) != 0 {
		t.Fatalf("expected no key secrets on default Load, got %d", len(shortcut.State.KeySecrets))
	}

	proceed, err := planner.Load(context.TODO(), encryptedGRs, LoadOptions{ListKeysWhileProgressing: true})
	if err != nil {
		t.Fatalf("Load (ListKeysWhileProgressing) failed: %v", err)
	}
	if proceed.State.ProgressingReason == "" {
		t.Fatal("expected progressing reason to remain set when listing keys")
	}
	if len(proceed.State.KeySecrets) == 0 {
		t.Fatal("expected key secrets when ListKeysWhileProgressing is set")
	}
}
