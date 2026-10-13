package controllers

import (
	"context"
	"encoding/base64"
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

// zeroed AES key material — intentionally not a realistic secret for scanners.
var testAESKeySecret = base64.StdEncoding.EncodeToString(make([]byte, 16))

func TestMigrationControllerRemoteKeyFirstEnablement(t *testing.T) {
	targetGRs := []schema.GroupResource{
		{Group: "", Resource: "secrets"},
		{Group: "", Resource: "configmaps"},
	}
	firstEnablementWriteKey := "1-" + remoteKeyNew

	keySecret := encryptiontesting.CreateEncryptionKeySecretWithKMSPluginConfig("kms", targetGRs, 1)
	setRemoteKeyAnnotations(t, keySecret.Annotations, state.RemoteKeyState{TargetRemoteKeyID: remoteKeyNew})
	delete(keySecret.Annotations, secrets.EncryptionSecretMigratedResources)

	kmsKey := apiserverconfigv1.Key{Name: "1", Secret: testAESKeySecret}
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
		rk, err := secrets.ReadRemoteKeyStateFromSecret(secret)
		if err != nil {
			t.Fatalf("read remote key annotations: %v", err)
		}
		if rk.MigratedRemoteKeyID != "" {
			t.Fatal("first enablement must not set migrated-remote-key-id")
		}
	}
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

