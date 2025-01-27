package resourceapply

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	fake2 "k8s.io/client-go/dynamic/fake"
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
	ret := ApplyDirectly(context.TODO(), (&ClientHolder{}).WithKubernetes(fakeClient), recorder, nil, nil, content, "pvc")
	if ret[0].Error == nil {
		t.Fatal("missing expected error")
	} else if ret[0].Error.Error() != "unhandled type *v1.PersistentVolumeClaim" {
		t.Fatal(ret[0].Error)
	}
}

func TestApplyDirectlyWithExtraOwnerReferences(t *testing.T) {
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
	ret := ApplyDirectly(context.TODO(), (&ClientHolder{}).WithKubernetes(fakeClient), recorder, NewResourceCache(), []metav1.OwnerReference{extraOwnerReference}, content, "pod")
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
	}
}

func TestApplyDirectlyUnstructuredTypeWithExtraOwnerReferences(t *testing.T) {
	dynamicScheme := runtime.NewScheme()
	fakeClient := fake2.NewSimpleDynamicClient(dynamicScheme)
	content := func(name string) ([]byte, error) {
		return []byte(`apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: sample-sm
spec: {}
`), nil
	}
	recorder := events.NewInMemoryRecorder("", clocktesting.NewFakePassiveClock(time.Now()))
	extraOwnerReference := metav1.OwnerReference{
		APIVersion: "test.openshift.io/v1",
		Kind:       "Test",
		Name:       "test-name",
		UID:        "test-uid",
	}
	expectedOwnerReferences := []metav1.OwnerReference{extraOwnerReference}
	ret := ApplyDirectly(context.TODO(), (&ClientHolder{}).WithDynamicClient(fakeClient), recorder, NewResourceCache(), []metav1.OwnerReference{extraOwnerReference}, content, "pod")
	if ret[0].Error != nil {
		t.Fatalf("unexpected error %v", ret[0].Error)
	}
	if !ret[0].Changed {
		t.Fatal("expected changed")
	}
	if sm, ok := ret[0].Result.(*unstructured.Unstructured); !ok {
		t.Fatalf("expected ServiceMonitor, got %v", sm)
	} else if !equality.Semantic.DeepEqual(sm.GetOwnerReferences(), expectedOwnerReferences) {
		t.Fatalf("expected resulting owner references to match : %s", cmp.Diff(sm.GetOwnerReferences(), expectedOwnerReferences))
	}
}
