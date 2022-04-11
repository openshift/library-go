package library

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
)

func TestArePodsOnTheSameRevision(t *testing.T) {
	scenarios := []struct {
		name               string
		initialObjects     []runtime.Object
		expectSameRevision bool
	}{
		{
			name:           "good pod, same revision",
			initialObjects: []runtime.Object{newPod(corev1.PodRunning, corev1.ConditionTrue, "3", "node1")},
			expectSameRevision: true,
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			fakeKubeClient := fake.NewSimpleClientset(scenario.initialObjects...)
			sameRevision, err := arePodsOnTheSameRevision(t, fakeKubeClient.CoreV1().Pods("test-ns"), "apiserver=true")
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
			Namespace: "test-ns",
			Labels: map[string]string{
				"revision": revision,
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
