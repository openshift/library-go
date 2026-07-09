package preflight

import (
	"context"
	"strings"
	"testing"

	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/clock"
)

const (
	testInstallerNodeName      = "master-1"
	testInstallerMirrorPodName = preflightPodName + "-" + testInstallerNodeName
)

var testInstallerCommand = []string{"cluster-kube-apiserver-operator", "installer"}

func newTestInstallerStaticPodDeployer(t *testing.T, objects ...runtime.Object) (*InstallerStaticPodPreflightDeployer, *fake.Clientset) {
	t.Helper()

	allObjects := append(installerStaticPodReferenceObjects(t), objects...)
	kubeClient := fake.NewSimpleClientset(allObjects...)
	deployer := NewInstallerStaticPodPreflightDeployer(
		testNamespace,
		kubeClient.CoreV1(),
		events.NewLoggingEventRecorder("test", clock.RealClock{}),
		testOperatorImage,
		testOperatorCommand,
		testInstallerCommand,
		testDeployerTimeout,
		testInstallerNodeName,
	)
	return deployer, kubeClient
}

func installerStaticPodReferenceObjects(t *testing.T) []runtime.Object {
	t.Helper()

	objects := testReferenceDataObjects(t)
	objects = append(objects,
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      nodeKubeconfigsSecretName,
				Namespace: testNamespace,
			},
			Data: map[string][]byte{
				nodeKubeconfigSecretKey: []byte("kubeconfig-data"),
			},
		},
		&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name: testInstallerNodeName,
				Labels: map[string]string{
					"node-role.kubernetes.io/master": "",
				},
			},
		},
	)
	return objects
}

func TestInstallerStaticPodPreflightDeployer_Deploy(t *testing.T) {
	ctx := context.Background()
	deployer, kubeClient := newTestInstallerStaticPodDeployer(t)
	encryptionConfigSecret := testPreflightEncryptionConfigSecret(t)

	if err := deployer.Deploy(ctx, testConfigHash, encryptionConfigSecret); err != nil {
		t.Fatalf("Deploy() error = %v", err)
	}

	if deployer.lastRevision != 1 {
		t.Fatalf("expected revision 1, got %d", deployer.lastRevision)
	}

	secret, err := kubeClient.CoreV1().Secrets(testNamespace).Get(ctx, preflightEncryptionConfigSecretName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("expected live encryption config secret: %v", err)
	}
	if len(secret.Data[nodeKubeconfigSecretKey]) == 0 {
		t.Fatalf("expected %q in live encryption config secret", nodeKubeconfigSecretKey)
	}

	liveConfigMap, err := kubeClient.CoreV1().ConfigMaps(testNamespace).Get(ctx, preflightStaticPodResourcePrefix, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("expected live pod configmap: %v", err)
	}
	podYAML, ok := liveConfigMap.Data["pod.yaml"]
	if !ok {
		t.Fatal("expected pod.yaml in live configmap")
	}
	writtenPod, err := resourceread.ReadPodV1([]byte(podYAML))
	if err != nil {
		t.Fatalf("failed to parse pod.yaml: %v", err)
	}
	if writtenPod.UID == "" {
		t.Fatal("expected static pod manifest to include a UID")
	}
	if !strings.Contains(podYAML, "kms-preflight-REVISION") {
		t.Fatalf("expected revision-specific resource-dir path in pod manifest")
	}
	if len(writtenPod.Spec.InitContainers) == 0 {
		t.Fatal("expected injected KMS plugin init container")
	}
	for _, mount := range staticPodResourceDirSubpathMounts {
		if !hasVolumeMount(writtenPod.Spec.InitContainers[0].VolumeMounts, mount) {
			t.Fatalf("expected init container to have mount %#v", mount)
		}
	}

	if _, err = kubeClient.CoreV1().ConfigMaps(testNamespace).Get(ctx, revisionResourceName(preflightRevisionStatusPrefix, 1), metav1.GetOptions{}); err != nil {
		t.Fatalf("expected preflight revision status configmap: %v", err)
	}
	if _, err = kubeClient.CoreV1().ConfigMaps(testNamespace).Get(ctx, revisionResourceName(preflightStaticPodResourcePrefix, 1), metav1.GetOptions{}); err != nil {
		t.Fatalf("expected revision pod configmap: %v", err)
	}
	if _, err = kubeClient.CoreV1().Secrets(testNamespace).Get(ctx, revisionResourceName(preflightEncryptionConfigSecretName, 1), metav1.GetOptions{}); err != nil {
		t.Fatalf("expected revision secret: %v", err)
	}

	installerPod, err := kubeClient.CoreV1().Pods(testNamespace).Get(ctx, installerPodName(1, testInstallerNodeName), metav1.GetOptions{})
	if err != nil {
		t.Fatalf("expected installer pod: %v", err)
	}
	if installerPod.Spec.ServiceAccountName != "installer-sa" {
		t.Fatalf("expected installer-sa service account, got %q", installerPod.Spec.ServiceAccountName)
	}
	if installerPod.Labels["app"] != preflightInstallerAppLabel {
		t.Fatalf("expected installer app label %q, got %q", preflightInstallerAppLabel, installerPod.Labels["app"])
	}
	args := strings.Join(installerPod.Spec.Containers[0].Args, " ")
	if !strings.Contains(args, "--revision=1") || !strings.Contains(args, "--pod=kms-preflight") {
		t.Fatalf("unexpected installer args: %q", args)
	}
}

func TestInstallerStaticPodPreflightDeployer_Status(t *testing.T) {
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
						Name:      testInstallerMirrorPodName,
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
			deployer, _ := newTestInstallerStaticPodDeployer(t, scenario.objects...)

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

func TestInstallerStaticPodPreflightDeployer_Cleanup(t *testing.T) {
	deployer, kubeClient := newTestInstallerStaticPodDeployer(t)
	deployer.lastRevision = 1
	deployer.lastInstallerNode = testInstallerNodeName

	existingInstallerPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      installerPodName(1, testInstallerNodeName),
			Namespace: testNamespace,
		},
	}
	existingSecret := testPreflightEncryptionConfigSecret(t)
	existingSecret.Labels = labels
	existingConfigMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      preflightStaticPodResourcePrefix,
			Namespace: testNamespace,
			Labels:    labels,
		},
	}
	existingRevisionStatus := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      revisionResourceName(preflightRevisionStatusPrefix, 1),
			Namespace: testNamespace,
		},
	}
	existingRevisionConfigMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      revisionResourceName(preflightStaticPodResourcePrefix, 1),
			Namespace: testNamespace,
		},
	}
	existingRevisionSecret := testPreflightEncryptionConfigSecret(t)
	existingRevisionSecret.Name = revisionResourceName(preflightEncryptionConfigSecretName, 1)

	kubeClient = fake.NewSimpleClientset(append(installerStaticPodReferenceObjects(t),
		existingInstallerPod,
		existingSecret,
		existingConfigMap,
		existingRevisionStatus,
		existingRevisionConfigMap,
		existingRevisionSecret,
	)...)
	deployer.coreClient = kubeClient.CoreV1()

	if err := deployer.Cleanup(context.Background()); err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}
}

func TestNextPreflightRevision_ignoresKubeAPIServerRevisionStatus(t *testing.T) {
	kubeClient := fake.NewSimpleClientset(
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "revision-status-99",
				Namespace: testNamespace,
			},
		},
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      revisionResourceName(preflightRevisionStatusPrefix, 2),
				Namespace: testNamespace,
			},
		},
	)

	revision, err := nextPreflightRevision(context.Background(), kubeClient.CoreV1(), testNamespace)
	if err != nil {
		t.Fatalf("nextPreflightRevision() error = %v", err)
	}
	if revision != 3 {
		t.Fatalf("expected revision 3, got %d", revision)
	}
}

func TestInstallerStaticPodPreflightDeployer_Deploy_missingNodeKubeconfig(t *testing.T) {
	kubeClient := fake.NewSimpleClientset(testReferenceDataObjects(t)...)
	deployer := NewInstallerStaticPodPreflightDeployer(
		testNamespace,
		kubeClient.CoreV1(),
		events.NewLoggingEventRecorder("test", clock.RealClock{}),
		testOperatorImage,
		testOperatorCommand,
		testInstallerCommand,
		testDeployerTimeout,
		testInstallerNodeName,
	)

	err := deployer.Deploy(context.Background(), testConfigHash, testPreflightEncryptionConfigSecret(t))
	if err == nil || !strings.Contains(err.Error(), nodeKubeconfigsSecretName) {
		t.Fatalf("expected missing node kubeconfig error, got %v", err)
	}
}

func TestInstallerPodName(t *testing.T) {
	if got := installerPodName(3, "node-a"); got != "installer-3-preflight-node-a" {
		t.Fatalf("unexpected installer pod name %q", got)
	}
}

func TestInstallerStaticPodPreflightDeployer_findMirrorPod_notFound(t *testing.T) {
	deployer, _ := newTestInstallerStaticPodDeployer(t)

	_, err := deployer.findMirrorPod(context.Background())
	if !apierrors.IsNotFound(err) {
		t.Fatalf("expected NotFound error, got %v", err)
	}
}

func hasVolumeMount(mounts []corev1.VolumeMount, mount corev1.VolumeMount) bool {
	for _, existing := range mounts {
		if existing.Name == mount.Name && existing.MountPath == mount.MountPath && existing.SubPath == mount.SubPath {
			return true
		}
	}
	return false
}
