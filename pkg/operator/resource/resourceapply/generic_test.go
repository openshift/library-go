package resourceapply

import (
	"context"
	"testing"

	"k8s.io/client-go/kubernetes/fake"

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
	recorder := events.NewInMemoryRecorder("")
	ret := ApplyDirectly(context.TODO(), (&ClientHolder{}).WithKubernetes(fakeClient), recorder, nil, content, "pvc")
	if ret[0].Error == nil {
		t.Fatal("missing expected error")
	} else if ret[0].Error.Error() != "unhandled type *v1.PersistentVolumeClaim" {
		t.Fatal(ret[0].Error)
	}
}
