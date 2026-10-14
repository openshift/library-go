package controllers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	"github.com/openshift/library-go/pkg/operator/encryption/statemachine"
	encryptiontesting "github.com/openshift/library-go/pkg/operator/encryption/testing"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

const (
	remoteKeyOld = "remote-old"
	remoteKeyNew = "remote-new"
)

// zeroed AES key material — intentionally not a realistic secret for scanners.
var testAESKeySecret = base64.StdEncoding.EncodeToString(make([]byte, 16))

func TestMigrationControllerRemoteKeyFirstEnablement(t *testing.T) {
	targetGRs := []schema.GroupResource{
		{Group: "", Resource: "secrets"},
		{Group: "", Resource: "configmaps"},
	}
	firstEnablementWriteKey := "1"

	scenarios := []struct {
		name                  string
		migratorEnsureReplies map[schema.GroupResource]map[string]finishedResultErr
		expectedMigratorCalls []string
		expectProgressing     bool
		expectMigratedMarkers bool
	}{
		{
			name: "pending uses plain write-key and does not stamp migrated-remote-key-id",
			migratorEnsureReplies: map[schema.GroupResource]map[string]finishedResultErr{
				{Group: "", Resource: "secrets"}:    {firstEnablementWriteKey: {finished: false}},
				{Group: "", Resource: "configmaps"}: {firstEnablementWriteKey: {finished: false}},
			},
			expectedMigratorCalls: []string{
				"ensure:configmaps:" + firstEnablementWriteKey,
				"ensure:secrets:" + firstEnablementWriteKey,
			},
			expectProgressing: true,
		},
		{
			name: "completed updates migrated-resources without setting migrated-remote-key-id",
			migratorEnsureReplies: map[schema.GroupResource]map[string]finishedResultErr{
				{Group: "", Resource: "secrets"}:    {firstEnablementWriteKey: {finished: true}},
				{Group: "", Resource: "configmaps"}: {firstEnablementWriteKey: {finished: true}},
			},
			expectedMigratorCalls: []string{
				"ensure:configmaps:" + firstEnablementWriteKey,
				"ensure:secrets:" + firstEnablementWriteKey,
			},
			expectMigratedMarkers: true,
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			keySecret := encryptiontesting.CreateEncryptionKeySecretWithKMSPluginConfig("kms", targetGRs, 1)
			setRemoteKeyAnnotations(t, keySecret.Annotations, state.RemoteKeyState{TargetRemoteKeyID: remoteKeyNew})
			delete(keySecret.Annotations, secrets.EncryptionSecretMigratedResources)
			delete(keySecret.Annotations, secrets.EncryptionSecretMigratedTimestamp)

			encryptionCfgSecret := kmsEncryptionConfigSecret(t, targetGRs)
			migrator := &fakeMigrator{ensureReplies: scenario.migratorEnsureReplies}
			fakeOperatorClient, fakeKubeClient, eventRecorder, deployer, kubeInformers := newKMSMigrationTestHarness(t, keySecret, encryptionCfgSecret)

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
				t.Fatalf("sync: %v", err)
			}

			if !equalStringSlices(scenario.expectedMigratorCalls, migrator.calls) {
				t.Fatalf("migrator calls:\n  expected: %v\n       got: %v", scenario.expectedMigratorCalls, migrator.calls)
			}
			if got := migratedRemoteKeyIDFromActions(t, fakeKubeClient, keySecret.Name); got != "" {
				t.Fatalf("first enablement must not set migrated-remote-key-id, got %q", got)
			}
			if scenario.expectMigratedMarkers {
				validateSecretsWereAnnotated(t, targetGRs, fakeKubeClient.Actions(), []*corev1.Secret{keySecret}, nil)
			}

			assertProgressing(t, fakeOperatorClient, scenario.expectProgressing)
		})
	}
}

func TestMigrationControllerRemoteKeyRotation(t *testing.T) {
	targetGRs := []schema.GroupResource{
		{Group: "", Resource: "secrets"},
		{Group: "", Resource: "configmaps"},
	}
	remoteMigrationWriteKey := "1-" + remoteKeyNew
	migrationFailed := errors.New("configmap migration failed")
	ensureCallFailed := errors.New("ensure migration failed")

	scenarios := []struct {
		name                  string
		migratorEnsureReplies map[schema.GroupResource]map[string]finishedResultErr
		expectedMigratorCalls []string
		expectMigratedPatch   bool
		expectProgressing     bool
		expectSyncError       bool
		expectDegraded        bool
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
			name: "does not stamp migrated-remote-key-id while a later resource is still pending",
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
			name: "does not stamp when a later resource records a migration failure",
			migratorEnsureReplies: map[schema.GroupResource]map[string]finishedResultErr{
				{Group: "", Resource: "secrets"}:    {remoteMigrationWriteKey: {finished: true}},
				{Group: "", Resource: "configmaps"}: {remoteMigrationWriteKey: {finished: true, result: migrationFailed}},
			},
			expectedMigratorCalls: []string{
				"ensure:configmaps:" + remoteMigrationWriteKey,
				"ensure:secrets:" + remoteMigrationWriteKey,
			},
			expectSyncError: true,
			expectDegraded:  true,
		},
		{
			name: "does not stamp when EnsureMigration returns a call error",
			migratorEnsureReplies: map[schema.GroupResource]map[string]finishedResultErr{
				{Group: "", Resource: "secrets"}:    {remoteMigrationWriteKey: {finished: true}},
				{Group: "", Resource: "configmaps"}: {remoteMigrationWriteKey: {err: ensureCallFailed}},
			},
			expectedMigratorCalls: []string{
				"ensure:configmaps:" + remoteMigrationWriteKey,
				"ensure:secrets:" + remoteMigrationWriteKey,
			},
			expectSyncError: true,
			expectDegraded:  true,
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
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			keySecret, encryptionCfgSecret := kmsRemoteKeyMigrationSecrets(t, targetGRs)
			migrator := &fakeMigrator{ensureReplies: scenario.migratorEnsureReplies}
			fakeOperatorClient, fakeKubeClient, eventRecorder, deployer, kubeInformers := newKMSMigrationTestHarness(t, keySecret, encryptionCfgSecret)

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
			err := target.Sync(context.TODO(), factory.NewSyncContext("test", eventRecorder))
			if scenario.expectSyncError {
				if err == nil {
					t.Fatal("expected sync error")
				}
			} else if err != nil {
				t.Fatalf("sync: %v", err)
			}

			if !equalStringSlices(scenario.expectedMigratorCalls, migrator.calls) {
				t.Fatalf("migrator calls:\n  expected: %v\n       got: %v", scenario.expectedMigratorCalls, migrator.calls)
			}

			patchedMigratedRemoteKeyID := migratedRemoteKeyIDFromActions(t, fakeKubeClient, keySecret.Name) == remoteKeyNew
			if scenario.expectMigratedPatch && !patchedMigratedRemoteKeyID {
				t.Fatal("expected migrated-remote-key-id to be patched to remote-new")
			}
			if !scenario.expectMigratedPatch && patchedMigratedRemoteKeyID {
				t.Fatal("unexpected migrated-remote-key-id patch before suffixed remote-key SVM completed")
			}

			assertProgressing(t, fakeOperatorClient, scenario.expectProgressing)
			assertDegraded(t, fakeOperatorClient, scenario.expectDegraded)
		})
	}
}

// TestMigrationControllerRemoteKeyRotationSurvivesRestart recreates the controller between
// syncs so stamping cannot rely on process-local counters from an earlier reconciliation.
func TestMigrationControllerRemoteKeyRotationSurvivesRestart(t *testing.T) {
	targetGRs := []schema.GroupResource{
		{Group: "", Resource: "secrets"},
		{Group: "", Resource: "configmaps"},
	}
	remoteMigrationWriteKey := "1-" + remoteKeyNew

	keySecret, encryptionCfgSecret := kmsRemoteKeyMigrationSecrets(t, targetGRs)
	migrator := &fakeMigrator{
		ensureReplies: map[schema.GroupResource]map[string]finishedResultErr{
			{Group: "", Resource: "secrets"}:    {remoteMigrationWriteKey: {finished: true}},
			{Group: "", Resource: "configmaps"}: {remoteMigrationWriteKey: {finished: false}},
		},
	}
	fakeOperatorClient, fakeKubeClient, eventRecorder, deployer, kubeInformers := newKMSMigrationTestHarness(t, keySecret, encryptionCfgSecret)
	apiServerInformer := configv1informers.NewSharedInformerFactory(configv1clientfake.NewSimpleClientset(), time.Minute).Config().V1().APIServers()

	newController := func() factory.Controller {
		return NewMigrationController(
			"kms",
			newTestProvider(targetGRs),
			deployer,
			alwaysFulfilledPreconditions,
			migrator,
			fakeOperatorClient,
			apiServerInformer,
			kubeInformers,
			fakeKubeClient.CoreV1(),
			metav1.ListOptions{},
			eventRecorder,
		)
	}

	// Sync 1: only one GR finished — must not stamp yet.
	if err := newController().Sync(context.TODO(), factory.NewSyncContext("test", eventRecorder)); err != nil {
		t.Fatalf("sync 1: %v", err)
	}
	if got := migratedRemoteKeyIDFromActions(t, fakeKubeClient, keySecret.Name); got == remoteKeyNew {
		t.Fatal("did not expect migrated-remote-key-id stamp before all GRs finish")
	}

	// Simulate restart with durable SVMs all finished; recreate the controller so no
	// process-local counters survive.
	reseedNodeStatuses(t, fakeOperatorClient)
	migrator.ensureReplies = map[schema.GroupResource]map[string]finishedResultErr{
		{Group: "", Resource: "secrets"}:    {remoteMigrationWriteKey: {finished: true}},
		{Group: "", Resource: "configmaps"}: {remoteMigrationWriteKey: {finished: true}},
	}
	migrator.calls = nil
	fakeKubeClient.ClearActions()

	if err := newController().Sync(context.TODO(), factory.NewSyncContext("test", eventRecorder)); err != nil {
		t.Fatalf("sync 2: %v", err)
	}
	if got := migratedRemoteKeyIDFromActions(t, fakeKubeClient, keySecret.Name); got != remoteKeyNew {
		t.Fatalf("expected migrated-remote-key-id=%q after restart sync with all SVMs finished, got %q", remoteKeyNew, got)
	}
}

// TestMigrationControllerRemoteKeyRotationIdleAfterStamp checks that a later reconciliation
// does not re-run SVMs or rewrite the key secret once migrated-remote-key-id matches target.
func TestMigrationControllerRemoteKeyRotationIdleAfterStamp(t *testing.T) {
	targetGRs := []schema.GroupResource{
		{Group: "", Resource: "secrets"},
		{Group: "", Resource: "configmaps"},
	}
	remoteMigrationWriteKey := "1-" + remoteKeyNew

	keySecret, encryptionCfgSecret := kmsRemoteKeyMigrationSecrets(t, targetGRs)
	migrator := &fakeMigrator{
		ensureReplies: map[schema.GroupResource]map[string]finishedResultErr{
			{Group: "", Resource: "secrets"}:    {remoteMigrationWriteKey: {finished: true}},
			{Group: "", Resource: "configmaps"}: {remoteMigrationWriteKey: {finished: true}},
		},
	}
	fakeOperatorClient, fakeKubeClient, eventRecorder, deployer, kubeInformers := newKMSMigrationTestHarness(t, keySecret, encryptionCfgSecret)

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
		t.Fatalf("sync 1: %v", err)
	}
	if got := migratedRemoteKeyIDFromActions(t, fakeKubeClient, keySecret.Name); got != remoteKeyNew {
		t.Fatalf("expected stamp on sync 1, got %q", got)
	}

	reseedNodeStatuses(t, fakeOperatorClient)
	migrator.calls = nil
	fakeKubeClient.ClearActions()

	if err := target.Sync(context.TODO(), factory.NewSyncContext("test", eventRecorder)); err != nil {
		t.Fatalf("sync 2: %v", err)
	}
	if len(migrator.calls) != 0 {
		t.Fatalf("expected no migrator calls after stamp, got %v", migrator.calls)
	}
	for _, action := range fakeKubeClient.Actions() {
		if action.Matches("update", "secrets") {
			secret := action.(clientgotesting.UpdateAction).GetObject().(*corev1.Secret)
			if secret.Name == keySecret.Name {
				t.Fatalf("unexpected key secret update after stamp: %#v", secret.Annotations)
			}
		}
	}
	assertProgressing(t, fakeOperatorClient, false)
	assertDegraded(t, fakeOperatorClient, false)
}

func migratedRemoteKeyIDFromActions(t *testing.T, fakeKubeClient *fake.Clientset, keySecretName string) string {
	t.Helper()
	for _, action := range fakeKubeClient.Actions() {
		if !action.Matches("update", "secrets") {
			continue
		}
		secret := action.(clientgotesting.UpdateAction).GetObject().(*corev1.Secret)
		if secret.Name != keySecretName {
			continue
		}
		rk, err := secrets.ReadRemoteKeyStateFromSecret(secret)
		if err != nil {
			t.Fatalf("read remote key annotations: %v", err)
		}
		if rk.MigratedRemoteKeyID != "" {
			return rk.MigratedRemoteKeyID
		}
	}
	return ""
}

func kmsRemoteKeyMigrationSecrets(t *testing.T, targetGRs []schema.GroupResource) (*corev1.Secret, *corev1.Secret) {
	t.Helper()

	keySecret := encryptiontesting.CreateEncryptionKeySecretWithKMSPluginConfig("kms", targetGRs, 1)
	setRemoteKeyAnnotations(t, keySecret.Annotations, state.RemoteKeyState{
		TargetRemoteKeyID:   remoteKeyNew,
		MigratedRemoteKeyID: remoteKeyOld,
	})
	keySecret.Annotations[secrets.EncryptionSecretMigratedTimestamp] = time.Now().Format(time.RFC3339)
	migrated := secrets.MigratedGroupResources{Resources: targetGRs}
	bs, err := json.Marshal(migrated)
	if err != nil {
		t.Fatalf("marshal migrated-resources: %v", err)
	}
	keySecret.Annotations[secrets.EncryptionSecretMigratedResources] = string(bs)

	return keySecret, kmsEncryptionConfigSecret(t, targetGRs)
}

func kmsEncryptionConfigSecret(t *testing.T, targetGRs []schema.GroupResource) *corev1.Secret {
	t.Helper()
	kmsKey := apiserverconfigv1.Key{Name: "1", Secret: testAESKeySecret}
	// Keep resource order stable: DeepEqual against desired encryption config is order-sensitive.
	tuplesByResource := map[string]encryptiondatatesting.EncryptionKeysResourceTuple{}
	for _, gr := range targetGRs {
		tuplesByResource[gr.Resource] = encryptiondatatesting.EncryptionKeysResourceTuple{
			Resource: gr.Resource,
			Keys:     []apiserverconfigv1.Key{kmsKey},
			Modes:    []string{"KMS"},
		}
	}
	tuples := make([]encryptiondatatesting.EncryptionKeysResourceTuple, 0, len(targetGRs))
	for _, name := range []string{"configmaps", "secrets"} {
		if tuple, ok := tuplesByResource[name]; ok {
			tuples = append(tuples, tuple)
			delete(tuplesByResource, name)
		}
	}
	for _, gr := range targetGRs {
		if tuple, ok := tuplesByResource[gr.Resource]; ok {
			tuples = append(tuples, tuple)
		}
	}
	return createEncryptionCfgSecret(t, "kms", "1", encryptiondatatesting.CreateEncryptionCfgWithWriteKey(tuples))
}

func newKMSMigrationTestHarness(t *testing.T, keySecret, encryptionCfgSecret *corev1.Secret) (
	v1helpers.StaticPodOperatorClient,
	*fake.Clientset,
	events.Recorder,
	statemachine.Deployer,
	v1helpers.KubeInformersForNamespaces,
) {
	t.Helper()
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
		t.Fatalf("deployer: %v", err)
	}
	return fakeOperatorClient, fakeKubeClient, eventRecorder, deployer, kubeInformers
}

func reseedNodeStatuses(t *testing.T, fakeOperatorClient v1helpers.StaticPodOperatorClient) {
	t.Helper()
	// ApplyOperatorStatus from a prior sync drops NodeStatuses in the fake client.
	_, status, resourceVersion, err := fakeOperatorClient.GetStaticPodOperatorState()
	if err != nil {
		t.Fatalf("get operator state: %v", err)
	}
	status.NodeStatuses = []operatorv1.NodeStatus{{NodeName: "node-1"}}
	if _, err := fakeOperatorClient.UpdateStaticPodOperatorStatus(context.TODO(), resourceVersion, status); err != nil {
		t.Fatalf("reseed node statuses: %v", err)
	}
}

func assertProgressing(t *testing.T, fakeOperatorClient v1helpers.StaticPodOperatorClient, want bool) {
	t.Helper()
	got := operatorConditionStatus(t, fakeOperatorClient, "EncryptionMigrationControllerProgressing")
	if want && got != operatorv1.ConditionTrue {
		t.Fatalf("expected progressing=True, got %s", got)
	}
	if !want && got != operatorv1.ConditionFalse {
		t.Fatalf("expected progressing=False, got %s", got)
	}
}

func assertDegraded(t *testing.T, fakeOperatorClient v1helpers.StaticPodOperatorClient, want bool) {
	t.Helper()
	got := operatorConditionStatus(t, fakeOperatorClient, "EncryptionMigrationControllerDegraded")
	if want && got != operatorv1.ConditionTrue {
		t.Fatalf("expected degraded=True, got %s", got)
	}
	if !want && got != operatorv1.ConditionFalse {
		t.Fatalf("expected degraded=False, got %s", got)
	}
}

func operatorConditionStatus(t *testing.T, fakeOperatorClient v1helpers.StaticPodOperatorClient, condType string) operatorv1.ConditionStatus {
	t.Helper()
	_, status, _, err := fakeOperatorClient.GetStaticPodOperatorState()
	if err != nil {
		t.Fatalf("get operator state: %v", err)
	}
	for _, cond := range status.Conditions {
		if cond.Type == condType {
			return cond.Status
		}
	}
	t.Fatalf("missing condition %s", condType)
	return ""
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

func TestNeedsRemoteKeyMigration(t *testing.T) {
	for _, tc := range []struct {
		name string
		rk   state.RemoteKeyState
		want bool
	}{
		{name: "unset migrated", rk: state.RemoteKeyState{TargetRemoteKeyID: "a"}},
		{name: "equal", rk: state.RemoteKeyState{TargetRemoteKeyID: "a", MigratedRemoteKeyID: "a"}},
		{name: "differs", rk: state.RemoteKeyState{TargetRemoteKeyID: "b", MigratedRemoteKeyID: "a"}, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := needsRemoteKeyMigration(tc.rk); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}
