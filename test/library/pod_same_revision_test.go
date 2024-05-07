package library

import (
	"fmt"
	"testing"

	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/stretchr/testify/require"
)

const (
	testNamespaceName = "test-ns"
	podsLabelSelector = "apiserver=true"
)

func TestArePodsOnTheSameNewRevision(t *testing.T) {
	testCases := []struct {
		name           string
		oldRevision    string
		initialObjects []runtime.Object
		exp            bool
		expErr         error
	}{
		{
			name:           "happy path",
			oldRevision:    "3",
			initialObjects: []runtime.Object{newPod(corev1.PodRunning, corev1.ConditionTrue, "4", "node1"), newPod(corev1.PodRunning, corev1.ConditionTrue, "4", "node2"), newPod(corev1.PodRunning, corev1.ConditionTrue, "4", "node3")},
			exp:            true,
			expErr:         nil,
		},
		{
			name:           "one pod is failing",
			oldRevision:    "3",
			initialObjects: []runtime.Object{newPod(corev1.PodRunning, corev1.ConditionTrue, "4", "node1"), newPod(corev1.PodRunning, corev1.ConditionTrue, "4", "node2"), newPod(corev1.PodFailed, corev1.ConditionTrue, "4", "node3")},
			exp:            false,
			expErr:         fmt.Errorf("current revision is not newer than old revision"),
		},
		{
			name:           "one pod on previous revision",
			oldRevision:    "3",
			initialObjects: []runtime.Object{newPod(corev1.PodRunning, corev1.ConditionTrue, "3", "node1"), newPod(corev1.PodRunning, corev1.ConditionTrue, "4", "node2"), newPod(corev1.PodRunning, corev1.ConditionTrue, "4", "node3")},
			exp:            false,
			expErr:         fmt.Errorf("current revision is not newer than old revision"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fakeKubeClient := fake.NewSimpleClientset(tc.initialObjects...)
			isSameRevision, err := arePodsOnTheSameNewRevision(t, fakeKubeClient.CoreV1().Pods(testNamespaceName), podsLabelSelector, tc.oldRevision)
			require.Equal(t, tc.expErr, err)
			require.Equal(t, tc.exp, isSameRevision)
		})
	}
}

func TestArePodsOnTheSameRevision(t *testing.T) {
	scenarios := []struct {
		name               string
		initialObjects     []runtime.Object
		expectSameRevision bool
	}{
		{
			name:               "good pod, same revision",
			initialObjects:     []runtime.Object{newPod(corev1.PodRunning, corev1.ConditionTrue, "3", "node1")},
			expectSameRevision: true,
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			fakeKubeClient := fake.NewSimpleClientset(scenario.initialObjects...)
			sameRevision, err := arePodsOnTheSameRevision(t, fakeKubeClient.CoreV1().Pods(testNamespaceName), podsLabelSelector)
			if err != nil {
				t.Fatal(err)
			}
			if scenario.expectSameRevision != sameRevision {
				t.Errorf("unexpected result from arePodsOnTheSameRevision, expected = %v, got = %v", scenario.expectSameRevision, sameRevision)
			}
		})
	}
}

func newPod(phase corev1.PodPhase, ready corev1.ConditionStatus, revision, nodeName string) *corev1.Pod {
	pod := corev1.Pod{
		TypeMeta: v1.TypeMeta{Kind: "Pod"},
		ObjectMeta: v1.ObjectMeta{
			Name:      "pod" + nodeName,
			Namespace: testNamespaceName,
			Labels: map[string]string{
				"revision":  revision,
				"apiserver": "true",
			}},
		Spec: corev1.PodSpec{
			NodeName: nodeName,
		},
		Status: corev1.PodStatus{
			Phase: phase,
			Conditions: []corev1.PodCondition{{
				Type:   corev1.PodReady,
				Status: ready,
			}},
		},
	}

	return &pod
}
