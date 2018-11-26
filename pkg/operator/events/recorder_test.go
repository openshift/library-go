package events

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	clientgotesting "k8s.io/client-go/testing"
)

func fakeControllerRef(t *testing.T) *corev1.ObjectReference {
	podNameEnvFunc = func() string {
		return "test"
	}
	client := fake.NewSimpleClientset(fakePod("test-namespace", "test"))
	ref, err := GetControllerReferenceForCurrentPod(client.CoreV1().Pods("test-namespace"))
	if err != nil {
		t.Fatalf("unable to get replicaset object reference: %v", err)
	}
	return ref
}

func fakePod(namespace, name string) *corev1.Pod {
	pod := &corev1.Pod{}
	pod.Name = name
	pod.Namespace = namespace
	truePtr := true
	pod.SetOwnerReferences([]metav1.OwnerReference{
		{
			APIVersion:         "apps/corev1",
			Kind:               "ReplicaSet",
			Name:               "test-766b85794f",
			UID:                "05022234-d394-11e8-8169-42010a8e0003",
			Controller:         &truePtr,
			BlockOwnerDeletion: &truePtr,
		},
	})
	return pod
}

func TestRecorder(t *testing.T) {
	client := fake.NewSimpleClientset()
	r := NewRecorder(client.CoreV1().Events("test-namespace"), "test-operator", fakeControllerRef(t))

	r.Event("TestReason", "foo")

	var createdEvent *corev1.Event

	for _, action := range client.Actions() {
		if action.Matches("create", "events") {
			createAction := action.(clientgotesting.CreateAction)
			createdEvent = createAction.GetObject().(*corev1.Event)
			break
		}
	}
	if createdEvent == nil {
		t.Fatalf("expected event to be created")
	}
	if createdEvent.InvolvedObject.Kind != "ReplicaSet" {
		t.Errorf("expected involved object kind ReplicaSet, got: %q", createdEvent.InvolvedObject.Kind)
	}
	if createdEvent.InvolvedObject.Namespace != "test-namespace" {
		t.Errorf("expected involved object namespace test-namespace, got: %q", createdEvent.InvolvedObject.Namespace)
	}
	if createdEvent.Reason != "TestReason" {
		t.Errorf("expected event to have TestReason, got %q", createdEvent.Reason)
	}
	if createdEvent.Message != "foo" {
		t.Errorf("expected message to be foo, got %q", createdEvent.Message)
	}
	if createdEvent.Type != "Normal" {
		t.Errorf("expected event type to be Normal, got %q", createdEvent.Type)
	}
	if createdEvent.Source.Component != "test-operator" {
		t.Errorf("expected event source to be test-operator, got %q", createdEvent.Source.Component)
	}
}

func TestGetControllerReferenceForCurrentPod(t *testing.T) {
	client := fake.NewSimpleClientset(fakePod("test", "foo"))

	podNameEnvFunc = func() string {
		return "foo"
	}

	objectReference, err := GetControllerReferenceForCurrentPod(client.CoreV1().Pods("test"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if objectReference.Name != "test-766b85794f" {
		t.Errorf("expected objectReference name to be 'test-766b85794f', got %q", objectReference.Name)
	}

	if objectReference.GroupVersionKind().String() != "apps/corev1, Kind=ReplicaSet" {
		t.Errorf("expected objectReference to be ReplicaSet, got %q", objectReference.GroupVersionKind().String())
	}
}
