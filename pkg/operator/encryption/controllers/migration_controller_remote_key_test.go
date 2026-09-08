package controllers

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	clocktesting "k8s.io/utils/clock/testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	apiserverconfigv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
	"k8s.io/client-go/kubernetes/fake"
	clientgotesting "k8s.io/client-go/testing"

	operatorv1 "github.com/openshift/api/operator/v1"

	configv1clientfake "github.com/openshift/client-go/config/clientset/versioned/fake"
	configv1informers "github.com/openshift/client-go/config/informers/externalversions"
	"github.com/openshift/library-go/pkg/controller/factory"
	encryptiondeployer "github.com/openshift/library-go/pkg/operator/encryption/deployer"
	encryptiondatatesting "github.com/openshift/library-go/pkg/operator/encryption/encryptiondata/testing"
	"github.com/openshift/library-go/pkg/operator/encryption/secrets"
	"github.com/openshift/library-go/pkg/operator/encryption/state"
	encryptiontesting "github.com/openshift/library-go/pkg/operator/encryption/testing"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

const (
	remoteKeyOld = "remote-old"
	remoteKeyNew = "remote-new"
)

func TestMigrationControllerRemoteKeyFirstEnablement(t *testing.T) {
	targetGRs := []schema.GroupResource{
		{Group: "", Resource: "secrets"},
		{Group: "", Resource: "configmaps"},
	}
	firstEnablementWriteKey := "1-" + remoteKeyNew

	keySecret := encryptiontesting.CreateEncryptionKeySecretWithKMSPluginConfig("kms", targetGRs, 1)
	secrets.ApplyRemoteKeyAnnotations(keySecret.Annotations, state.RemoteKeyState{TargetRemoteKeyID: remoteKeyNew})
	delete(keySecret.Annotations, secrets.EncryptionSecretMigratedResources)

	kmsKey := apiserverconfigv1.Key{Name: "1", Secret: "NzFlYTdjOTE0MTlhNjhmZDEyMjRmODhkNTAzMTZiNGU="}
	keysResForSecrets := encryptiondatatesting.EncryptionKeysResourceTuple{
		Resource: "secrets",
		Keys:     []apiserverconfigv1.Key{kmsKey},
		Modes:    []string{"KMS"},
	}
	keysResForConfigMaps := encryptiondatatesting.EncryptionKeysResourceTuple{
		Resource: "configmaps",
		Keys:     []apiserverconfigv1.Key{kmsKey},
		Modes:    []string{"KMS"},
	}
	encryptionCfgSecret := createEncryptionCfgSecret(t, "kms", "1", encryptiondatatesting.CreateEncryptionCfgWithWriteKey([]encryptiondatatesting.EncryptionKeysResourceTuple{
		keysResForConfigMaps, keysResForSecrets,
	}))

	migrator := &fakeMigrator{
		ensureReplies: map[schema.GroupResource]map[string]finishedResultErr{
			{Group: "", Resource: "secrets"}:    {firstEnablementWriteKey: {finished: false}},
			{Group: "", Resource: "configmaps"}: {firstEnablementWriteKey: {finished: false}},
		},
	}
	fakeOperatorClient := v1helpers.NewFakeStaticPodOperatorClient(
		&operatorv1.StaticPodOperatorSpec{OperatorSpec: operatorv1.OperatorSpec{ManagementState: operatorv1.Managed}},
		&operatorv1.StaticPodOperatorStatus{
			OperatorStatus: operatorv1.OperatorStatus{
				Conditions: []operatorv1.OperatorCondition{
					{Type: "EncryptionMigrationControllerDegraded", Status: operatorv1.ConditionFalse},
					{Type: "EncryptionMigrationControllerProgressing", Status: operatorv1.ConditionFalse},
				},
			},
			NodeStatuses: []operatorv1.NodeStatus{{NodeName: "node-1"}},
		},
		nil,
		nil,
	)
	fakeKubeClient := fake.NewSimpleClientset(
		encryptiontesting.CreateDummyKubeAPIPod("kube-apiserver-1", "kms", "node-1"),
		keySecret,
		encryptionCfgSecret,
	)
	eventRecorder := events.NewRecorder(fakeKubeClient.CoreV1().Events("operator"), "test-encryption-migration-controller", &corev1.ObjectReference{}, clocktesting.NewFakePassiveClock(time.Now()))
	kubeInformers := v1helpers.NewKubeInformersForNamespaces(fakeKubeClient, "openshift-config-managed", "kms")
	deployer, err := encryptiondeployer.NewRevisionLabelPodDeployer("revision", "kms", kubeInformers, fakeKubeClient.CoreV1(), fakeKubeClient.CoreV1(), encryptiondeployer.StaticPodNodeProvider{OperatorClient: fakeOperatorClient})
	if err != nil {
		t.Fatal(err)
	}

	target := NewMigrationController(
		"kms",
		newTestProvider(targetGRs),
		deployer,
		alwaysFulfilledPreconditions,
		migrator,
		fakeOperatorClient,
		configv1informers.NewSharedInformerFactory(configv1clientfake.NewSimpleClientset(), time.Minute).Config().V1().APIServers(),
		kubeInformers,
		fakeKubeClient.CoreV1(),
		metav1.ListOptions{},
		eventRecorder,
	)
	if err := target.Sync(context.TODO(), factory.NewSyncContext("test", eventRecorder)); err != nil {
		t.Fatal(err)
	}

	expectedMigratorCalls := []string{
		"ensure:configmaps:" + firstEnablementWriteKey,
		"ensure:secrets:" + firstEnablementWriteKey,
	}
	if !equalStringSlices(expectedMigratorCalls, migrator.calls) {
		t.Fatalf("migrator calls:\n  expected: %v\n       got: %v", expectedMigratorCalls, migrator.calls)
	}
	for _, action := range fakeKubeClient.Actions() {
		if !action.Matches("update", "secrets") {
			continue
		}
		secret := action.(clientgotesting.UpdateAction).GetObject().(*corev1.Secret)
		if secret.Name != keySecret.Name {
			continue
		}
		rk, err := secrets.ReadRemoteKeyAnnotations(secret)
		if err != nil {
			t.Fatalf("read remote key annotations: %v", err)
		}
		if rk.MigratedRemoteKeyID != "" {
			t.Fatal("first enablement must not set migrated-remote-key-id")
		}
	}
}

func TestMigrationControllerRemoteKeyRotation(t *testing.T) {
	targetGRs := []schema.GroupResource{
		{Group: "", Resource: "secrets"},
		{Group: "", Resource: "configmaps"},
	}
	remoteMigrationWriteKey := "1-" + remoteKeyNew

	scenarios := []struct {
		name                  string
		migratorEnsureReplies map[schema.GroupResource]map[string]finishedResultErr
		expectedMigratorCalls []string
		expectMigratedPatch   bool
		expectProgressing     bool
	}{
		{
			name: "needsMigration runs suffixed SVM despite migrated-resources",
			migratorEnsureReplies: map[schema.GroupResource]map[string]finishedResultErr{
				{Group: "", Resource: "secrets"}:    {remoteMigrationWriteKey: {finished: false}},
				{Group: "", Resource: "configmaps"}: {remoteMigrationWriteKey: {finished: false}},
			},
			expectedMigratorCalls: []string{
				"ensure:configmaps:" + remoteMigrationWriteKey,
				"ensure:secrets:" + remoteMigrationWriteKey,
			},
			expectProgressing: true,
		},
		{
			name: "does not stamp migrated-remote-key-id until all suffixed SVMs finish",
			migratorEnsureReplies: map[schema.GroupResource]map[string]finishedResultErr{
				{Group: "", Resource: "secrets"}:    {remoteMigrationWriteKey: {finished: true}},
				{Group: "", Resource: "configmaps"}: {remoteMigrationWriteKey: {finished: false}},
			},
			expectedMigratorCalls: []string{
				"ensure:configmaps:" + remoteMigrationWriteKey,
				"ensure:secrets:" + remoteMigrationWriteKey,
			},
			expectProgressing: true,
		},
		{
			name: "stamps migrated-remote-key-id after all suffixed SVMs complete",
			migratorEnsureReplies: map[schema.GroupResource]map[string]finishedResultErr{
				{Group: "", Resource: "secrets"}:    {remoteMigrationWriteKey: {finished: true}},
				{Group: "", Resource: "configmaps"}: {remoteMigrationWriteKey: {finished: true}},
			},
			expectedMigratorCalls: []string{
				"ensure:configmaps:" + remoteMigrationWriteKey,
				"ensure:secrets:" + remoteMigrationWriteKey,
			},
			expectMigratedPatch: true,
		},
		{
			name: "plain write-key SVM does not satisfy remote-key rotation",
			migratorEnsureReplies: map[schema.GroupResource]map[string]finishedResultErr{
				{Group: "", Resource: "secrets"}:    {"1": {finished: true}, remoteMigrationWriteKey: {finished: false}},
				{Group: "", Resource: "configmaps"}: {"1": {finished: true}, remoteMigrationWriteKey: {finished: false}},
			},
			expectedMigratorCalls: []string{
				"ensure:configmaps:" + remoteMigrationWriteKey,
				"ensure:secrets:" + remoteMigrationWriteKey,
			},
			expectProgressing: true,
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			keySecret, encryptionCfgSecret := kmsRemoteKeyMigrationSecrets(t, targetGRs)
			migrator := &fakeMigrator{ensureReplies: scenario.migratorEnsureReplies}
			fakeOperatorClient := v1helpers.NewFakeStaticPodOperatorClient(
				&operatorv1.StaticPodOperatorSpec{OperatorSpec: operatorv1.OperatorSpec{ManagementState: operatorv1.Managed}},
				&operatorv1.StaticPodOperatorStatus{
					OperatorStatus: operatorv1.OperatorStatus{
						Conditions: []operatorv1.OperatorCondition{
							{Type: "EncryptionMigrationControllerDegraded", Status: operatorv1.ConditionFalse},
							{Type: "EncryptionMigrationControllerProgressing", Status: operatorv1.ConditionFalse},
						},
					},
					NodeStatuses: []operatorv1.NodeStatus{{NodeName: "node-1"}},
				},
				nil,
				nil,
			)
			fakeKubeClient := fake.NewSimpleClientset(
				encryptiontesting.CreateDummyKubeAPIPod("kube-apiserver-1", "kms", "node-1"),
				keySecret,
				encryptionCfgSecret,
			)
			eventRecorder := events.NewRecorder(fakeKubeClient.CoreV1().Events("operator"), "test-encryption-migration-controller", &corev1.ObjectReference{}, clocktesting.NewFakePassiveClock(time.Now()))
			kubeInformers := v1helpers.NewKubeInformersForNamespaces(fakeKubeClient, "openshift-config-managed", "kms")
			deployer, err := encryptiondeployer.NewRevisionLabelPodDeployer("revision", "kms", kubeInformers, fakeKubeClient.CoreV1(), fakeKubeClient.CoreV1(), encryptiondeployer.StaticPodNodeProvider{OperatorClient: fakeOperatorClient})
			if err != nil {
				t.Fatal(err)
			}

			target := NewMigrationController(
				"kms",
				newTestProvider(targetGRs),
				deployer,
				alwaysFulfilledPreconditions,
				migrator,
				fakeOperatorClient,
				configv1informers.NewSharedInformerFactory(configv1clientfake.NewSimpleClientset(), time.Minute).Config().V1().APIServers(),
				kubeInformers,
				fakeKubeClient.CoreV1(),
				metav1.ListOptions{},
				eventRecorder,
			)
			if err := target.Sync(context.TODO(), factory.NewSyncContext("test", eventRecorder)); err != nil {
				t.Fatal(err)
			}

			if !equalStringSlices(scenario.expectedMigratorCalls, migrator.calls) {
				t.Fatalf("migrator calls:\n  expected: %v\n       got: %v", scenario.expectedMigratorCalls, migrator.calls)
			}

			patchedMigratedRemoteKeyID := false
			for _, action := range fakeKubeClient.Actions() {
				if !action.Matches("update", "secrets") {
					continue
				}
				secret := action.(clientgotesting.UpdateAction).GetObject().(*corev1.Secret)
				if secret.Name != keySecret.Name {
					continue
				}
				rk, err := secrets.ReadRemoteKeyAnnotations(secret)
				if err != nil {
					t.Fatalf("read remote key annotations: %v", err)
				}
				if rk.MigratedRemoteKeyID == remoteKeyNew {
					patchedMigratedRemoteKeyID = true
				}
			}
			if scenario.expectMigratedPatch && !patchedMigratedRemoteKeyID {
				t.Fatal("expected migrated-remote-key-id to be patched to remote-new")
			}
			if !scenario.expectMigratedPatch && patchedMigratedRemoteKeyID {
				t.Fatal("unexpected migrated-remote-key-id patch before suffixed remote-key SVM completed")
			}

			progressing := operatorv1.ConditionFalse
			_, status, _, err := fakeOperatorClient.GetStaticPodOperatorState()
			if err != nil {
				t.Fatal(err)
			}
			for _, cond := range status.Conditions {
				if cond.Type == "EncryptionMigrationControllerProgressing" {
					progressing = cond.Status
				}
			}
			if scenario.expectProgressing && progressing != operatorv1.ConditionTrue {
				t.Fatalf("expected progressing=True, got %s", progressing)
			}
			if !scenario.expectProgressing && progressing != operatorv1.ConditionFalse {
				t.Fatalf("expected progressing=False, got %s", progressing)
			}
		})
	}
}

func kmsRemoteKeyMigrationSecrets(t *testing.T, targetGRs []schema.GroupResource) (*corev1.Secret, *corev1.Secret) {
	t.Helper()

	keySecret := encryptiontesting.CreateEncryptionKeySecretWithKMSPluginConfig("kms", targetGRs, 1)
	secrets.ApplyRemoteKeyAnnotations(keySecret.Annotations, state.RemoteKeyState{
		TargetRemoteKeyID:   remoteKeyNew,
		MigratedRemoteKeyID: remoteKeyOld,
	})
	keySecret.Annotations[secrets.EncryptionSecretMigratedTimestamp] = time.Now().Format(time.RFC3339)
	migrated := secrets.MigratedGroupResources{Resources: targetGRs}
	bs, err := json.Marshal(migrated)
	if err != nil {
		t.Fatal(err)
	}
	keySecret.Annotations[secrets.EncryptionSecretMigratedResources] = string(bs)

	kmsKey := apiserverconfigv1.Key{Name: "1", Secret: "NzFlYTdjOTE0MTlhNjhmZDEyMjRmODhkNTAzMTZiNGU="}
	keysResForSecrets := encryptiondatatesting.EncryptionKeysResourceTuple{
		Resource: "secrets",
		Keys:     []apiserverconfigv1.Key{kmsKey},
		Modes:    []string{"KMS"},
	}
	keysResForConfigMaps := encryptiondatatesting.EncryptionKeysResourceTuple{
		Resource: "configmaps",
		Keys:     []apiserverconfigv1.Key{kmsKey},
		Modes:    []string{"KMS"},
	}
	encryptionCfgSecret := createEncryptionCfgSecret(t, "kms", "1", encryptiondatatesting.CreateEncryptionCfgWithWriteKey([]encryptiondatatesting.EncryptionKeysResourceTuple{
		keysResForConfigMaps, keysResForSecrets,
	}))
	return keySecret, encryptionCfgSecret
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
