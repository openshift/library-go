package resourceread

import (
	"testing"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestReadGenericKnownObject(t *testing.T) {
	requiredObj, err := ReadGenericWithUnstructured([]byte(`apiVersion: v1
kind: Namespace
metadata:
  name: openshift-apiserver
  labels:
    openshift.io/run-level: "1"
`))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := requiredObj.(*v1.Namespace); !ok {
		t.Fatalf("Expected namespace, got %+v", requiredObj)
	}
}

func TestReadGenericUnknownObject(t *testing.T) {
	requiredObj, err := ReadGenericWithUnstructured([]byte(`apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: foo
  namespace: bar
spec:
  groups:
    - name: baz
`))
	if err != nil {
		t.Fatal(err)
	}

	u, ok := requiredObj.(*unstructured.Unstructured)
	if !ok {
		t.Fatalf("Expected unstructured, got %+v", requiredObj)
	}

	if u.GetName() != "foo" {
		t.Errorf("Expected name foo, got %q", u.GetName())
	}
}
