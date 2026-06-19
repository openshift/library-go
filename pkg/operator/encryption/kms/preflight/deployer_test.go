package preflight

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
)

const (
	testNamespace           = "openshift-kube-apiserver"
	testConfigHash          = "abc123"
	testOperatorImage       = "quay.io/openshift-release-dev/ocp-v5.0-art-dev@sha256:test"
	configHashAnnotationKey = "encryption.apiserver.operator.openshift.io/kms-preflight-config-hash"
	testDeployerTimeout     = 10 * time.Second
)

var testOperatorCommand = []string{"cluster-kube-apiserver-operator", "kms-preflight"}

var expectedDeployPodYAML = `
apiVersion: v1
kind: Pod
metadata:
  name: kms-preflight
  namespace: openshift-kube-apiserver
  annotations:
    encryption.apiserver.operator.openshift.io/kms-preflight-config-hash: abc123
spec:
  restartPolicy: Never
  priorityClassName: system-cluster-critical
  nodeSelector:
    node-role.kubernetes.io/master: ""
  tolerations:
    - key: node-role.kubernetes.io/master
      operator: Exists
      effect: NoSchedule
    - key: node-role.kubernetes.io/master
      operator: Exists
      effect: NoExecute
  containers:
    - name: kms-preflight-check
      image: quay.io/openshift-release-dev/ocp-v5.0-art-dev@sha256:test
      command: ["cluster-kube-apiserver-operator","kms-preflight"]
      args:
        - --kms-call-timeout=10s
      env:
      - name: POD_NAME
        valueFrom:
          fieldRef:
            fieldPath: metadata.name
      - name: POD_NAMESPACE
        valueFrom:
          fieldRef:
            fieldPath: metadata.namespace
      - name: CONFIG_HASH
        value: abc123
      resources:
        requests:
          memory: 50Mi
          cpu: 5m
      volumeMounts:
        - name: kms-plugin-socket
          mountPath: /var/run/kmsplugin
  volumes:
    - name: kms-plugin-socket
      emptyDir: {}
`

func newTestDeployer(t *testing.T, objects ...runtime.Object) (*PodPreflightDeployer, *fake.Clientset) {
	t.Helper()

	kubeClient := fake.NewSimpleClientset(objects...)
	deployer := NewPodPreflightDeployer(
		testNamespace,
		kubeClient.CoreV1(),
		testOperatorImage,
		testOperatorCommand,
		testDeployerTimeout,
	)
	return deployer, kubeClient
}

func TestPodPreflightDeployer_Deploy(t *testing.T) {
	ctx := context.Background()
	deployer, kubeClient := newTestDeployer(t)

	expectedPod, err := resourceread.ReadPodV1([]byte(expectedDeployPodYAML))
	if err != nil {
		t.Fatalf("failed to parse expected pod YAML: %v", err)
	}

	if err := deployer.Deploy(ctx, testConfigHash); err != nil {
		t.Fatalf("Deploy() error = %v", err)
	}

	actions := kubeClient.Actions()
	if len(actions) != 1 {
		t.Fatalf("expected 1 action, got %d: %#v", len(actions), actions)
	}
	if !actions[0].Matches("create", "pods") {
		t.Fatalf("unexpected action: %#v", actions[0])
	}

	createAction, ok := actions[0].(clienttesting.CreateAction)
	if !ok {
		t.Fatalf("expected CreateAction, got %T", actions[0])
	}
	if createAction.GetNamespace() != testNamespace {
		t.Fatalf("unexpected namespace %q", createAction.GetNamespace())
	}

	actualPod, ok := createAction.GetObject().(*corev1.Pod)
	if !ok {
		t.Fatalf("expected *corev1.Pod, got %T", createAction.GetObject())
	}
	if !equality.Semantic.DeepEqual(expectedPod, actualPod) {
		t.Fatalf("pod does not match expected:\ngot:  %+v\nwant: %+v", actualPod, expectedPod)
	}
}

func TestPodPreflightDeployer_Status(t *testing.T) {
	scenarios := []struct {
		name        string
		objects     []runtime.Object
		expectPhase corev1.PodPhase
		expectErr   string
	}{
		{
			name:      "missing pod returns error",
			expectErr: "failed to get pod",
		},
		{
			name: "pod returns pod status",
			objects: []runtime.Object{
				&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      preflightPodName,
						Namespace: testNamespace,
					},
					Status: corev1.PodStatus{Phase: corev1.PodRunning},
				},
			},
			expectPhase: corev1.PodRunning,
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			deployer, _ := newTestDeployer(t, scenario.objects...)

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

func TestPodPreflightDeployer_Cleanup(t *testing.T) {
	existingPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      preflightPodName,
			Namespace: testNamespace,
			Annotations: map[string]string{
				configHashAnnotationKey: testConfigHash,
			},
		},
	}

	scenarios := []struct {
		name          string
		objects       []runtime.Object
		setupClient   func(*fake.Clientset)
		expectErr     string
		verifyActions func(t *testing.T, actions []clienttesting.Action)
	}{
		{
			name:    "deletes existing pod",
			objects: []runtime.Object{existingPod},
			verifyActions: func(t *testing.T, actions []clienttesting.Action) {
				if len(actions) != 1 {
					t.Fatalf("expected 1 action, got %d: %#v", len(actions), actions)
				}
				if !actions[0].Matches("delete", "pods") {
					t.Fatalf("unexpected action: %#v", actions[0])
				}
				deleteAction, ok := actions[0].(clienttesting.DeleteAction)
				if !ok {
					t.Fatalf("expected DeleteAction, got %T", actions[0])
				}
				if deleteAction.GetName() != preflightPodName {
					t.Fatalf("unexpected pod name %q", deleteAction.GetName())
				}
				if deleteAction.GetNamespace() != testNamespace {
					t.Fatalf("unexpected namespace %q", deleteAction.GetNamespace())
				}
			},
		},
		{
			name: "missing pod is not an error",
			verifyActions: func(t *testing.T, actions []clienttesting.Action) {
				if len(actions) != 1 {
					t.Fatalf("expected 1 action, got %d: %#v", len(actions), actions)
				}
				if !actions[0].Matches("delete", "pods") {
					t.Fatalf("unexpected action: %#v", actions[0])
				}
			},
		},
		{
			name:    "delete error is returned",
			objects: []runtime.Object{existingPod},
			setupClient: func(kubeClient *fake.Clientset) {
				kubeClient.PrependReactor("delete", "pods", func(action clienttesting.Action) (bool, runtime.Object, error) {
					return true, nil, apierrors.NewForbidden(corev1.Resource("pods"), preflightPodName, nil)
				})
			},
			expectErr: "failed to delete pod",
			verifyActions: func(t *testing.T, actions []clienttesting.Action) {
				if len(actions) != 1 {
					t.Fatalf("expected 1 action, got %d: %#v", len(actions), actions)
				}
				if !actions[0].Matches("delete", "pods") {
					t.Fatalf("unexpected action: %#v", actions[0])
				}
			},
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			deployer, kubeClient := newTestDeployer(t, scenario.objects...)
			if scenario.setupClient != nil {
				scenario.setupClient(kubeClient)
			}

			err := deployer.Cleanup(context.Background())
			if scenario.expectErr != "" {
				if err == nil || !strings.Contains(err.Error(), scenario.expectErr) {
					t.Fatalf("expected error containing %q, got %v", scenario.expectErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Cleanup() error = %v", err)
			}
			if scenario.verifyActions != nil {
				scenario.verifyActions(t, kubeClient.Actions())
			}
		})
	}
}
