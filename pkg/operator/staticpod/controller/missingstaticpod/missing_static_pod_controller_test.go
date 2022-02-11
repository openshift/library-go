package missingstaticpodcontroller

import (
	"context"
	"fmt"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes/fake"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/google/go-cmp/cmp"
	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

var emptyStaticPodPayloadYaml = ``

var validStaticPodPayloadYaml = `
apiVersion: v1
kind: Pod
spec:
  terminationGracePeriodSeconds: 194
`

var staticPodPayloadInvalidTypeYaml = `
apiVersion: v1
kind: Pod
spec:
  terminationGracePeriodSeconds: "194"
`

var staticPodPayloadNoTerminationGracePeriodYaml = `
apiVersion: v1
kind: Pod
spec:
  priorityClassName: system-node-critical
`

func TestMissingStaticPodControllerSync(t *testing.T) {
	var (
		// we need to use metav1.Now as the base for all the times since the sync loop
		// compare the termination timestamp with the threshold based on the elapsed
		// time.
		now = metav1.Now()

		targetNamespace = "test"
		operandName     = "test-operand"
	)

	testCases := []struct {
		name           string
		operatorStatus *operatorv1.StaticPodOperatorStatus
		pods           []*corev1.Pod
		cms            []*corev1.ConfigMap
		expectSyncErr  bool
		expectedEvents int
	}{
		{
			name: "two terminated installer pods per node with correct revision",
			operatorStatus: &operatorv1.StaticPodOperatorStatus{
				NodeStatuses: []operatorv1.NodeStatus{
					{NodeName: "node-1", CurrentRevision: 2},
					{NodeName: "node-2", CurrentRevision: 2},
				},
			},
			pods: []*corev1.Pod{
				makeTerminatedInstallerPod(1, "node-1", 0, metav1.NewTime(now.Add(-2*time.Hour))),
				makeTerminatedInstallerPod(2, "node-1", 0, metav1.NewTime(now.Add(-time.Hour))),
				makeTerminatedInstallerPod(1, "node-2", 0, metav1.NewTime(now.Add(-2*time.Hour))),
				makeTerminatedInstallerPod(2, "node-2", 0, metav1.NewTime(now.Add(-time.Hour))),
			},
			cms: []*corev1.ConfigMap{
				makeOperandConfigMap(targetNamespace, operandName, 2, validStaticPodPayloadYaml),
			},
			expectSyncErr:  false,
			expectedEvents: 0,
		},
		{
			name: "current revision older than the latest installer revision",
			operatorStatus: &operatorv1.StaticPodOperatorStatus{
				NodeStatuses: []operatorv1.NodeStatus{
					{NodeName: "node-1", CurrentRevision: 2},
				},
			},
			pods: []*corev1.Pod{
				makeTerminatedInstallerPod(1, "node-1", 0, metav1.NewTime(now.Add(-3*time.Hour))),
				makeTerminatedInstallerPod(2, "node-1", 0, metav1.NewTime(now.Add(-2*time.Hour))),
				makeTerminatedInstallerPod(3, "node-1", 0, metav1.NewTime(now.Add(-time.Hour))),
			},
			cms: []*corev1.ConfigMap{
				makeOperandConfigMap(targetNamespace, operandName, 3, validStaticPodPayloadYaml),
			},
			expectSyncErr:  true,
			expectedEvents: 1,
		},
		{
			name: "current revision older then the latest installer revision but termination time within threshold",
			operatorStatus: &operatorv1.StaticPodOperatorStatus{
				NodeStatuses: []operatorv1.NodeStatus{
					{NodeName: "node-1", CurrentRevision: 2},
				},
			},
			pods: []*corev1.Pod{
				makeTerminatedInstallerPod(1, "node-1", 0, metav1.NewTime(now.Add(-2*time.Hour))),
				makeTerminatedInstallerPod(2, "node-1", 0, metav1.NewTime(now.Add(-time.Hour))),
				makeTerminatedInstallerPod(3, "node-1", 0, now),
			},
			cms: []*corev1.ConfigMap{
				makeOperandConfigMap(targetNamespace, operandName, 3, validStaticPodPayloadYaml),
			},
			expectSyncErr:  false,
			expectedEvents: 0,
		},
		{
			name: "only one node has a missing pod",
			operatorStatus: &operatorv1.StaticPodOperatorStatus{
				NodeStatuses: []operatorv1.NodeStatus{
					{NodeName: "node-1", CurrentRevision: 2},
					{NodeName: "node-2", CurrentRevision: 3},
				},
			},
			pods: []*corev1.Pod{
				makeTerminatedInstallerPod(1, "node-1", 0, metav1.NewTime(now.Add(-3*time.Hour))),
				makeTerminatedInstallerPod(2, "node-1", 0, metav1.NewTime(now.Add(-2*time.Hour))),
				makeTerminatedInstallerPod(3, "node-1", 0, metav1.NewTime(now.Add(-time.Hour))),
				makeTerminatedInstallerPod(1, "node-2", 0, metav1.NewTime(now.Add(-3*time.Hour))),
				makeTerminatedInstallerPod(2, "node-2", 0, metav1.NewTime(now.Add(-2*time.Hour))),
				makeTerminatedInstallerPod(3, "node-2", 0, metav1.NewTime(now.Add(-time.Hour))),
			},
			cms: []*corev1.ConfigMap{
				makeOperandConfigMap(targetNamespace, operandName, 2, validStaticPodPayloadYaml),
				makeOperandConfigMap(targetNamespace, operandName, 3, validStaticPodPayloadYaml),
			},
			expectSyncErr:  true,
			expectedEvents: 1,
		},
		{
			name: "multiple missing pods for the same revision but on different nodes should produce multiple events",
			operatorStatus: &operatorv1.StaticPodOperatorStatus{
				NodeStatuses: []operatorv1.NodeStatus{
					{NodeName: "node-1", CurrentRevision: 2},
					{NodeName: "node-2", CurrentRevision: 2},
				},
			},
			pods: []*corev1.Pod{
				makeTerminatedInstallerPod(1, "node-1", 0, metav1.NewTime(now.Add(-3*time.Hour))),
				makeTerminatedInstallerPod(2, "node-1", 0, metav1.NewTime(now.Add(-2*time.Hour))),
				makeTerminatedInstallerPod(3, "node-1", 0, metav1.NewTime(now.Add(-time.Hour))),
				makeTerminatedInstallerPod(1, "node-2", 0, metav1.NewTime(now.Add(-3*time.Hour))),
				makeTerminatedInstallerPod(2, "node-2", 0, metav1.NewTime(now.Add(-2*time.Hour))),
				makeTerminatedInstallerPod(3, "node-2", 0, metav1.NewTime(now.Add(-time.Hour))),
			},
			cms: []*corev1.ConfigMap{
				makeOperandConfigMap(targetNamespace, operandName, 3, validStaticPodPayloadYaml),
			},
			expectSyncErr:  true,
			expectedEvents: 2,
		},
		{
			name: "installer pod is still running",
			operatorStatus: &operatorv1.StaticPodOperatorStatus{
				NodeStatuses: []operatorv1.NodeStatus{
					{NodeName: "node-1", CurrentRevision: 0},
				},
			},
			pods: []*corev1.Pod{
				makeInstallerPod(1, "node-1"),
			},
			cms: []*corev1.ConfigMap{
				makeOperandConfigMap(targetNamespace, operandName, 1, validStaticPodPayloadYaml),
			},
			expectSyncErr:  false,
			expectedEvents: 0,
		},
		{
			name: "installer pod ran into an error",
			operatorStatus: &operatorv1.StaticPodOperatorStatus{
				NodeStatuses: []operatorv1.NodeStatus{
					{NodeName: "node-1", CurrentRevision: 0},
				},
			},
			pods: []*corev1.Pod{
				makeTerminatedInstallerPod(1, "node-1", 1, now),
			},
			cms: []*corev1.ConfigMap{
				makeOperandConfigMap(targetNamespace, operandName, 1, validStaticPodPayloadYaml),
			},
			expectSyncErr:  false,
			expectedEvents: 0,
		},
		{
			name: "operand configmap with payload without termination grace period",
			operatorStatus: &operatorv1.StaticPodOperatorStatus{
				NodeStatuses: []operatorv1.NodeStatus{
					{NodeName: "node-1", CurrentRevision: 2},
				},
			},
			pods: []*corev1.Pod{
				makeTerminatedInstallerPod(1, "node-1", 0, metav1.NewTime(now.Add(-2*time.Hour))),
				makeTerminatedInstallerPod(2, "node-1", 0, metav1.NewTime(now.Add(-time.Hour))),
			},
			cms: []*corev1.ConfigMap{
				makeOperandConfigMap(targetNamespace, operandName, 2, staticPodPayloadNoTerminationGracePeriodYaml),
			},
			expectSyncErr:  false,
			expectedEvents: 0,
		},
		{
			name: "operand configmap with invalid payload",
			operatorStatus: &operatorv1.StaticPodOperatorStatus{
				NodeStatuses: []operatorv1.NodeStatus{
					{NodeName: "node-1", CurrentRevision: 2},
				},
			},
			pods: []*corev1.Pod{
				makeTerminatedInstallerPod(1, "node-1", 0, metav1.NewTime(now.Add(-2*time.Hour))),
				makeTerminatedInstallerPod(2, "node-1", 0, metav1.NewTime(now.Add(-time.Hour))),
			},
			cms: []*corev1.ConfigMap{
				makeOperandConfigMap(targetNamespace, operandName, 2, staticPodPayloadInvalidTypeYaml),
			},
			expectSyncErr:  true,
			expectedEvents: 0,
		},
		{
			name: "operand configmap with empty payload",
			operatorStatus: &operatorv1.StaticPodOperatorStatus{
				NodeStatuses: []operatorv1.NodeStatus{
					{NodeName: "node-1", CurrentRevision: 2},
				},
			},
			pods: []*corev1.Pod{
				makeTerminatedInstallerPod(1, "node-1", 0, metav1.NewTime(now.Add(-2*time.Hour))),
				makeTerminatedInstallerPod(2, "node-1", 0, metav1.NewTime(now.Add(-time.Hour))),
			},
			cms: []*corev1.ConfigMap{
				makeOperandConfigMap(targetNamespace, operandName, 2, emptyStaticPodPayloadYaml),
			},
			expectSyncErr:  true,
			expectedEvents: 0,
		},
		{
			name: "operand configmap without pod.yaml key",
			operatorStatus: &operatorv1.StaticPodOperatorStatus{
				NodeStatuses: []operatorv1.NodeStatus{
					{NodeName: "node-1", CurrentRevision: 2},
				},
			},
			pods: []*corev1.Pod{
				makeTerminatedInstallerPod(1, "node-1", 0, metav1.NewTime(now.Add(-2*time.Hour))),
				makeTerminatedInstallerPod(2, "node-1", 0, metav1.NewTime(now.Add(-time.Hour))),
			},
			cms: []*corev1.ConfigMap{
				{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("%s-pod-%d", operandName, 2), Namespace: targetNamespace}},
			},
			expectSyncErr:  true,
			expectedEvents: 0,
		},
		{
			name: "the controller should take into account the latest graceful termination period of the static pod",
			operatorStatus: &operatorv1.StaticPodOperatorStatus{
				NodeStatuses: []operatorv1.NodeStatus{
					{NodeName: "node-1", CurrentRevision: 1},
				},
			},
			pods: []*corev1.Pod{
				makeTerminatedInstallerPod(1, "node-1", 0, metav1.NewTime(now.Add(-2*time.Hour))),
				makeTerminatedInstallerPod(2, "node-1", 0, metav1.NewTime(now.Add(-time.Minute))),
			},
			cms: []*corev1.ConfigMap{
				makeOperandConfigMap(targetNamespace, operandName, 1, makeValidPayloadWithGracefulTerminationPeriod(30)),
				makeOperandConfigMap(targetNamespace, operandName, 2, makeValidPayloadWithGracefulTerminationPeriod(300)),
			},
			expectSyncErr:  false,
			expectedEvents: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fakeOperatorClient := v1helpers.NewFakeStaticPodOperatorClient(
				nil,
				tc.operatorStatus,
				nil,
				nil,
			)
			kubeClient := fake.NewSimpleClientset()
			eventRecorder := events.NewRecorder(kubeClient.CoreV1().Events("test"), "missing-static-pod-controller", &corev1.ObjectReference{})
			syncCtx := factory.NewSyncContext("MissingStaticPodController", eventRecorder)
			controller := missingStaticPodController{
				operatorClient:                    fakeOperatorClient,
				podListerForTargetNamespace:       &fakePodNamespaceLister{pods: tc.pods},
				configMapListerForTargetNamespace: &fakeConfigMapNamespaceLister{cms: tc.cms},
				targetNamespace:                   targetNamespace,
				operandName:                       operandName,
				lastEventEmissionPerNode:          make(lastEventEmissionPerNode),
			}

			err := controller.sync(context.TODO(), syncCtx)
			if err != nil != tc.expectSyncErr {
				t.Fatalf("expected sync error to have occured to be %t, got: %t, err: %v", tc.expectSyncErr, err != nil, err)
			}

			if err == nil {
				return
			}

			events, err := kubeClient.CoreV1().Events("test").List(context.TODO(), metav1.ListOptions{})
			if err != nil {
				t.Fatal(err)
			}

			if len(events.Items) != tc.expectedEvents {
				t.Fatalf("expected %d events to have been emitted, got: %d", tc.expectedEvents, len(events.Items))
			}

			for _, ev := range events.Items {
				if ev.Reason != "MissingStaticPod" {
					t.Fatalf("expected all events to have a MissingStartingPod reason, found: %s", ev.Reason)
				}
			}
		})
	}
}

type fakePodNamespaceLister struct {
	pods []*corev1.Pod
}

func (f *fakePodNamespaceLister) List(selector labels.Selector) ([]*corev1.Pod, error) {
	return f.pods, nil
}

func (f *fakePodNamespaceLister) Get(name string) (*corev1.Pod, error) {
	for _, pod := range f.pods {
		if pod.ObjectMeta.Name == name {
			return pod, nil
		}
	}
	return nil, fmt.Errorf("pod %q not found", name)
}

type fakeConfigMapNamespaceLister struct {
	cms []*corev1.ConfigMap
}

func (f *fakeConfigMapNamespaceLister) List(selector labels.Selector) ([]*corev1.ConfigMap, error) {
	return f.cms, nil
}

func (f *fakeConfigMapNamespaceLister) Get(name string) (*corev1.ConfigMap, error) {
	for _, cm := range f.cms {
		if cm.ObjectMeta.Name == name {
			return cm, nil
		}
	}
	return nil, fmt.Errorf("configmap %q not found", name)
}

func makeTerminatedInstallerPod(revision int, node string, exitCode int32, terminatedAt metav1.Time) *corev1.Pod {
	pod := makeInstallerPod(revision, node)
	pod.Status = corev1.PodStatus{
		ContainerStatuses: []corev1.ContainerStatus{
			{Name: "installer", State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: exitCode, FinishedAt: terminatedAt}}},
		},
	}
	return pod
}

func makeInstallerPod(revision int, node string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:   fmt.Sprintf("installer-%d-%s", revision, node),
			Labels: map[string]string{"app": "installer"},
		},
		Spec: corev1.PodSpec{NodeName: node},
	}
}

func makeOperandConfigMap(targetNamespace string, operandName string, revision int, payload string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("%s-pod-%d", operandName, revision), Namespace: targetNamespace},
		Data:       map[string]string{"pod.yaml": payload},
	}
}

func makeValidPayloadWithGracefulTerminationPeriod(period int) string {
	return fmt.Sprintf(`
apiVersion: v1
kind: Pod
spec:
  terminationGracePeriodSeconds: %d
`, period)
}

func TestGetStaticPodTerminationGracePeriodSecondsForRevision(t *testing.T) {
	scenarios := []struct {
		name                           string
		staticPodPayload               string
		targetRevision                 int
		expectedTerminationGracePeriod time.Duration
		expectedError                  error
	}{
		// scenario 1
		{
			name:                           "happy path, found terminationGracePeriodSeconds in pod.yaml.spec.terminationGracePeriodSeconds field",
			staticPodPayload:               validStaticPodPayloadYaml,
			expectedTerminationGracePeriod: 194 * time.Second,
		},

		// scenario 2
		{
			name:             "invalid type for terminationGracePeriodSeconds in pod.yaml.spec.terminationGracePeriodSeconds field",
			staticPodPayload: staticPodPayloadInvalidTypeYaml,
			expectedError:    fmt.Errorf("json: cannot unmarshal string into Go struct field PodSpec.spec.terminationGracePeriodSeconds of type int64"),
		},

		// scenario 3
		{
			name:                           "default value for terminationGracePeriodSeconds is returned if pod.yaml.spec.terminationGracePeriodSeconds wasn't specified",
			staticPodPayload:               staticPodPayloadNoTerminationGracePeriodYaml,
			expectedTerminationGracePeriod: 30 * time.Second,
		},

		// scenario 4
		{
			name:             "pod.yaml.spec is required",
			staticPodPayload: emptyStaticPodPayloadYaml,
			expectedError:    fmt.Errorf("didn't find required key \"pod.yaml\" in cm: operand-name-pod-0/target-namespace"),
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			// test data
			configMapIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			targetConfigMap := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("operand-name-pod-%d", scenario.targetRevision), Namespace: "target-namespace"},
			}
			if len(scenario.staticPodPayload) > 0 {
				targetConfigMap.Data = map[string]string{"pod.yaml": scenario.staticPodPayload}
			}
			configMapIndexer.Add(targetConfigMap)
			configMapLister := corev1listers.NewConfigMapLister(configMapIndexer).ConfigMaps("target-namespace")

			// act
			c := &missingStaticPodController{
				operatorClient:                    nil,
				podListerForTargetNamespace:       nil,
				configMapListerForTargetNamespace: configMapLister,
				targetNamespace:                   "target-namespace",
				operandName:                       "operand-name",
			}
			actualTerminationGracePeriod, err := c.getStaticPodTerminationGracePeriodSecondsForRevision(scenario.targetRevision)

			// validate
			if err == nil && scenario.expectedError != nil {
				t.Fatal("expected to get an error from getStaticPodTerminationGracePeriodSecondsForRevision function")
			}
			if err != nil && scenario.expectedError == nil {
				t.Fatal(err)
			}
			if err != nil && scenario.expectedError != nil && err.Error() != scenario.expectedError.Error() {
				t.Fatalf("unexpected error returned = %v, expected = %v", err, scenario.expectedError)
			}
			if actualTerminationGracePeriod != scenario.expectedTerminationGracePeriod {
				t.Fatalf("unexpected termination grace period for: %v, expected: %v", actualTerminationGracePeriod, scenario.expectedTerminationGracePeriod)
			}
		})
	}
}

func TestGetStaticPodCurrentRevision(t *testing.T) {
	testCases := []struct {
		name             string
		node             string
		status           *operatorv1.StaticPodOperatorStatus
		expectedRevision int
	}{
		{
			name: "node status was reported by the status pod controller",
			node: "node-1",
			status: &operatorv1.StaticPodOperatorStatus{
				NodeStatuses: []operatorv1.NodeStatus{{NodeName: "node-1", CurrentRevision: 1}},
			},
			expectedRevision: 1,
		},
		{
			name: "node status wasn't reported by the status pod controller",
			node: "node-1",
			status: &operatorv1.StaticPodOperatorStatus{
				NodeStatuses: []operatorv1.NodeStatus{},
			},
			expectedRevision: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			revision := getStaticPodCurrentRevision(tc.node, tc.status)
			if revision != tc.expectedRevision {
				t.Fatalf("expected revision to be %d, got: %d", tc.expectedRevision, revision)
			}
		})
	}
}

func TestGetMostRecentInstallerPodByNode(t *testing.T) {
	testCases := []struct {
		name              string
		pods              []*corev1.Pod
		expectedPodByNode map[string]*corev1.Pod
	}{
		{
			name: "two installer pods per node",
			pods: []*corev1.Pod{
				{ObjectMeta: metav1.ObjectMeta{Name: "installer-1-node-1"}, Spec: corev1.PodSpec{NodeName: "node-1"}},
				{ObjectMeta: metav1.ObjectMeta{Name: "installer-2-node-1"}, Spec: corev1.PodSpec{NodeName: "node-1"}},
				{ObjectMeta: metav1.ObjectMeta{Name: "installer-1-node-2"}, Spec: corev1.PodSpec{NodeName: "node-2"}},
				{ObjectMeta: metav1.ObjectMeta{Name: "installer-2-node-2"}, Spec: corev1.PodSpec{NodeName: "node-2"}},
			},
			expectedPodByNode: map[string]*corev1.Pod{
				"node-1": {ObjectMeta: metav1.ObjectMeta{Name: "installer-2-node-1"}, Spec: corev1.PodSpec{NodeName: "node-1"}},
				"node-2": {ObjectMeta: metav1.ObjectMeta{Name: "installer-2-node-2"}, Spec: corev1.PodSpec{NodeName: "node-2"}},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			podByNode, err := getMostRecentInstallerPodByNode(tc.pods)
			if err != nil {
				t.Fatal(err)
			}

			if !cmp.Equal(podByNode, tc.expectedPodByNode) {
				t.Fatalf("unexpected most recent installer pod by node:\n%s", cmp.Diff(podByNode, tc.expectedPodByNode))
			}
		})
	}
}

func TestGetInstallerPodsByNode(t *testing.T) {
	testCases := []struct {
		name               string
		pods               []*corev1.Pod
		expectedPodsByNode map[string][]*corev1.Pod
	}{
		{
			name: "two installer pods per node",
			pods: []*corev1.Pod{
				{ObjectMeta: metav1.ObjectMeta{Name: "installer-1-node-1"}, Spec: corev1.PodSpec{NodeName: "node-1"}},
				{ObjectMeta: metav1.ObjectMeta{Name: "installer-2-node-1"}, Spec: corev1.PodSpec{NodeName: "node-1"}},
				{ObjectMeta: metav1.ObjectMeta{Name: "installer-1-node-2"}, Spec: corev1.PodSpec{NodeName: "node-2"}},
				{ObjectMeta: metav1.ObjectMeta{Name: "installer-2-node-2"}, Spec: corev1.PodSpec{NodeName: "node-2"}},
			},
			expectedPodsByNode: map[string][]*corev1.Pod{
				"node-1": {
					{ObjectMeta: metav1.ObjectMeta{Name: "installer-1-node-1"}, Spec: corev1.PodSpec{NodeName: "node-1"}},
					{ObjectMeta: metav1.ObjectMeta{Name: "installer-2-node-1"}, Spec: corev1.PodSpec{NodeName: "node-1"}},
				},
				"node-2": {
					{ObjectMeta: metav1.ObjectMeta{Name: "installer-1-node-2"}, Spec: corev1.PodSpec{NodeName: "node-2"}},
					{ObjectMeta: metav1.ObjectMeta{Name: "installer-2-node-2"}, Spec: corev1.PodSpec{NodeName: "node-2"}},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			podsByNode, err := getInstallerPodsByNode(tc.pods)
			if err != nil {
				t.Fatal(err)
			}

			if !cmp.Equal(podsByNode, tc.expectedPodsByNode) {
				t.Fatalf("unexpected pods by node seperation:\n%s", cmp.Diff(podsByNode, tc.expectedPodsByNode))
			}
		})
	}
}

func TestInstallerPodFinishedAt(t *testing.T) {
	expectedTime := metav1.Unix(1644579221, 0)

	testCases := []struct {
		name           string
		pod            *corev1.Pod
		expectFinished bool
	}{
		{
			name: "installer pod finished",
			pod: &corev1.Pod{Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{
				{Name: "container", State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 0, FinishedAt: metav1.Time{}}}},
				{Name: "installer", State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 0, FinishedAt: expectedTime}}},
			}}},
			expectFinished: true,
		},
		{
			name: "installer pod not finished",
			pod: &corev1.Pod{Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{
				{Name: "installer", State: corev1.ContainerState{}},
			}}},
			expectFinished: false,
		},
		{
			name: "installer pod without installer container status reported",
			pod: &corev1.Pod{Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{
				{Name: "installer"},
			}}},
			expectFinished: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			time, finished := installerPodFinishedAt(tc.pod)
			if finished != tc.expectFinished {
				t.Fatalf("expected installer container finished to be %t, got: %t", tc.expectFinished, finished)
			}
			if finished && !time.Equal(expectedTime.Time) {
				t.Fatalf("expected installer container to be finished at %s, got: %s", expectedTime, time)
			}
		})
	}
}
