package resourceapply

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	clocktesting "k8s.io/utils/clock/testing"

	"github.com/openshift/library-go/pkg/operator/events"
)

func TestApplyDirectlyUnhandledType(t *testing.T) {
	fakeClient := fake.NewSimpleClientset()
	content := func(name string) ([]byte, error) {
		return []byte(`apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: sample-claim
  labels:
    openshift.io/run-level: "1"
`), nil
	}
	recorder := events.NewInMemoryRecorder("", clocktesting.NewFakePassiveClock(time.Now()))
	ret := ApplyDirectly(context.TODO(), (&ClientHolder{}).WithKubernetes(fakeClient), recorder, nil, content, nil, "pvc")
	if ret[0].Error == nil {
		t.Fatal("missing expected error")
	} else if ret[0].Error.Error() != "unhandled type *v1.PersistentVolumeClaim" {
		t.Fatal(ret[0].Error)
	}
}
func TestApplyDirectlyWithCustomChanges(t *testing.T) {
	fakeClient := fake.NewSimpleClientset()
	content := func(name string) ([]byte, error) {
		return []byte(`apiVersion: v1
kind: Pod
metadata:
  name: sample-pod
  ownerReferences:
  - apiVersion: apps/v1
    kind: ReplicaSet
    name: rs-controller
    uid: rs-uid
spec:
  containers:
  - name: fedora
    image: fedora
`), nil
	}
	recorder := events.NewInMemoryRecorder("", clocktesting.NewFakePassiveClock(time.Now()))
	extraOwnerReference := metav1.OwnerReference{
		APIVersion: "test.openshift.io/v1",
		Kind:       "Test",
		Name:       "test-name",
		UID:        "test-uid",
	}
	expectedOwnerReferences := []metav1.OwnerReference{
		{
			APIVersion: "apps/v1",
			Kind:       "ReplicaSet",
			Name:       "rs-controller",
			UID:        "rs-uid",
		},
		extraOwnerReference,
	}

	objModifier := func(object runtime.Object) (runtime.Object, error) {
		metadata, err := meta.Accessor(object)
		if err != nil {
			return nil, err
		}
		newOwnerRefs := append(metadata.GetOwnerReferences(), extraOwnerReference)
		metadata.SetOwnerReferences(newOwnerRefs)
		metadata.SetNamespace("custom-ns")
		return object, nil
	}

	ret := ApplyDirectly(context.TODO(), (&ClientHolder{}).WithKubernetes(fakeClient), recorder, NewResourceCache(), content, objModifier, "pod")
	if ret[0].Error != nil {
		t.Fatalf("unexpected error %v", ret[0].Error)
	}
	if !ret[0].Changed {
		t.Fatal("expected changed")
	}
	if pod, ok := ret[0].Result.(*v1.Pod); !ok {
		t.Fatalf("expected pod, got %v", pod)
	} else if !equality.Semantic.DeepEqual(pod.OwnerReferences, expectedOwnerReferences) {
		t.Fatalf("expected resulting owner references to match : %s", cmp.Diff(pod.OwnerReferences, expectedOwnerReferences))
	} else if pod.Namespace != "custom-ns" {
		t.Fatalf("expected pod namespace: %s, got %s", pod.Namespace, "custom-ns")
	}
}
