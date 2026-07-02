package preflight

import (
	"context"
	"strings"
	"testing"

	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
)

const (
	testNodeName      = "master-1"
	testMirrorPodName = preflightPodName + "-" + testNodeName
)

func newTestStaticPodDeployer(t *testing.T, objects ...runtime.Object) (*StaticPodPreflightDeployer, *fake.Clientset) {
	t.Helper()

	allObjects := append(testReferenceDataObjects(t), objects...)
	kubeClient := fake.NewSimpleClientset(allObjects...)
	deployer := NewStaticPodPreflightDeployer(
		testNamespace,
		kubeClient.CoreV1(),
		testOperatorImage,
		testOperatorCommand,
		testDeployerTimeout,
	)
	return deployer, kubeClient
}

func TestStaticPodPreflightDeployer_Deploy(t *testing.T) {
	ctx := context.Background()
	deployer, kubeClient := newTestStaticPodDeployer(t)
	encryptionConfigSecret := testPreflightEncryptionConfigSecret(t)

	if err := deployer.Deploy(ctx, testConfigHash, encryptionConfigSecret); err != nil {
		t.Fatalf("Deploy() error = %v", err)
	}

	actions := kubeClient.Actions()
	if len(actions) != 8 {
		t.Fatalf("expected 8 actions, got %d: %#v", len(actions), actions)
	}

	if !actions[0].Matches("delete", "pods") {
		t.Fatalf("unexpected action: %#v", actions[0])
	}
	if !actions[1].Matches("delete", "secrets") {
		t.Fatalf("unexpected action: %#v", actions[1])
	}
	if !actions[2].Matches("delete", "configmaps") {
		t.Fatalf("unexpected action: %#v", actions[2])
	}
	if !actions[3].Matches("create", "secrets") {
		t.Fatalf("unexpected action: %#v", actions[3])
	}
	secretCreateAction, ok := actions[3].(clienttesting.CreateAction)
	if !ok {
		t.Fatalf("expected CreateAction, got %T", actions[3])
	}
	createdSecret, ok := secretCreateAction.GetObject().(*corev1.Secret)
	if !ok {
		t.Fatalf("expected *corev1.Secret, got %T", secretCreateAction.GetObject())
	}
	if createdSecret.Name != preflightEncryptionConfigSecretName {
		t.Fatalf("expected secret name %q, got %q", preflightEncryptionConfigSecretName, createdSecret.Name)
	}

	if !actions[4].Matches("get", "secrets") {
		t.Fatalf("unexpected action: %#v", actions[4])
	}
	if !actions[5].Matches("get", "secrets") {
		t.Fatalf("unexpected action: %#v", actions[5])
	}
	if !actions[6].Matches("create", "configmaps") {
		t.Fatalf("unexpected action: %#v", actions[6])
	}
	configMapCreateAction, ok := actions[6].(clienttesting.CreateAction)
	if !ok {
		t.Fatalf("expected CreateAction, got %T", actions[6])
	}
	createdConfigMap, ok := configMapCreateAction.GetObject().(*corev1.ConfigMap)
	if !ok {
		t.Fatalf("expected *corev1.ConfigMap, got %T", configMapCreateAction.GetObject())
	}
	if createdConfigMap.Name != preflightPodConfigMapPrefix {
		t.Fatalf("expected configmap name %q, got %q", preflightPodConfigMapPrefix, createdConfigMap.Name)
	}
	if _, ok := createdConfigMap.Data["pod.yaml"]; !ok {
		t.Fatalf("expected pod.yaml key in configmap data")
	}
	if len(createdConfigMap.Data[nodeKubeconfigSecretKey]) == 0 {
		t.Fatalf("expected %q key in configmap data", nodeKubeconfigSecretKey)
	}
	writtenPod, err := resourceread.ReadPodV1([]byte(createdConfigMap.Data["pod.yaml"]))
	if err != nil {
		t.Fatalf("failed to parse pod.yaml from configmap: %v", err)
	}
	if writtenPod.UID == "" {
		t.Fatal("expected static pod manifest to include a UID")
	}

	if !actions[7].Matches("create", "pods") {
		t.Fatalf("unexpected action: %#v", actions[7])
	}
	createAction, ok := actions[7].(clienttesting.CreateAction)
	if !ok {
		t.Fatalf("expected CreateAction, got %T", actions[7])
	}
	if createAction.GetNamespace() != testNamespace {
		t.Fatalf("unexpected namespace %q", createAction.GetNamespace())
	}
}

func TestStaticPodPreflightDeployer_Status(t *testing.T) {
	scenarios := []struct {
		name        string
		objects     []runtime.Object
		expectPhase corev1.PodPhase
		expectErr   string
	}{
		{
			name:      "missing mirror pod returns error",
			expectErr: "failed to get mirror pod",
		},
		{
			name: "mirror pod returns pod status",
			objects: []runtime.Object{
				&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      testMirrorPodName,
						Namespace: testNamespace,
						Labels:    labels,
					},
					Status: corev1.PodStatus{Phase: corev1.PodRunning},
				},
			},
			expectPhase: corev1.PodRunning,
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			deployer, _ := newTestStaticPodDeployer(t, scenario.objects...)

			status, err := deployer.Status(context.Background())
			if scenario.expectErr != "" {
				if err == nil || !strings.Contains(err.Error(), scenario.expectErr) {
					t.Fatalf("expected error containing %q, got %v", scenario.expectErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Status() error = %v", err)
			}
			if status.Phase != scenario.expectPhase {
				t.Fatalf("expected phase %q, got %q", scenario.expectPhase, status.Phase)
			}
		})
	}
}

func TestStaticPodPreflightDeployer_Cleanup(t *testing.T) {
	existingInstallerPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      preflightInstallerPodName,
			Namespace: testNamespace,
		},
	}
	existingSecret := testPreflightEncryptionConfigSecret(t)
	existingSecret.Labels = labels
	existingConfigMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      preflightPodConfigMapPrefix,
			Namespace: testNamespace,
			Labels:    labels,
		},
	}

	deployer, kubeClient := newTestStaticPodDeployer(t, existingInstallerPod, existingSecret, existingConfigMap)
	if err := deployer.Cleanup(context.Background()); err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}

	actions := kubeClient.Actions()
	if len(actions) != 3 {
		t.Fatalf("expected 3 actions, got %d: %#v", len(actions), actions)
	}
	if !actions[0].Matches("delete", "pods") {
		t.Fatalf("unexpected action: %#v", actions[0])
	}
	if !actions[1].Matches("delete", "secrets") {
		t.Fatalf("unexpected action: %#v", actions[1])
	}
	if !actions[2].Matches("delete", "configmaps") {
		t.Fatalf("unexpected action: %#v", actions[2])
	}
}

func TestStaticPodPreflightDeployer_Deploy_installerCreateFailure(t *testing.T) {
	deployer, kubeClient := newTestStaticPodDeployer(t)
	kubeClient.PrependReactor("create", "pods", func(action clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(corev1.Resource("pods"), preflightInstallerPodName, nil)
	})

	err := deployer.Deploy(context.Background(), testConfigHash, testPreflightEncryptionConfigSecret(t))
	if err == nil || !strings.Contains(err.Error(), "failed to create preflight installer pod") {
		t.Fatalf("expected installer pod create error, got %v", err)
	}
}

func TestMirrorPodName(t *testing.T) {
	if got := mirrorPodName("node-a"); got != "kms-preflight-node-a" {
		t.Fatalf("unexpected mirror pod name %q", got)
	}
}

func TestStaticPodPreflightDeployer_nodeKubeconfigData_fromCluster(t *testing.T) {
	const kubeconfig = "apiVersion: v1\nkind: Config\n"
	kubeClient := fake.NewSimpleClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      nodeKubeconfigsSecretName,
			Namespace: testNamespace,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			nodeKubeconfigSecretKey: []byte(kubeconfig),
		},
	})
	deployer := NewStaticPodPreflightDeployer(
		testNamespace,
		kubeClient.CoreV1(),
		testOperatorImage,
		testOperatorCommand,
		testDeployerTimeout,
	)

	got, err := deployer.nodeKubeconfigData(context.Background())
	if err != nil {
		t.Fatalf("nodeKubeconfigData() error = %v", err)
	}
	if string(got) != kubeconfig {
		t.Fatalf("expected cluster kubeconfig, got %q", got)
	}
}

func TestStaticPodPreflightDeployer_nodeKubeconfigData_embeddedFallback(t *testing.T) {
	deployer, _ := newTestStaticPodDeployer(t)

	got, err := deployer.nodeKubeconfigData(context.Background())
	if err != nil {
		t.Fatalf("nodeKubeconfigData() error = %v", err)
	}
	if len(got) == 0 {
		t.Fatal("expected embedded kubeconfig fallback")
	}
}
