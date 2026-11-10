package v1helpers

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	fakekube "k8s.io/client-go/kubernetes/fake"
)

func TestNewKubeInformersForNamespacesWithOptions(t *testing.T) {
	kubeClient := fakekube.NewSimpleClientset()

	testCases := []struct {
		name       string
		namespaces []string
	}{
		{
			name:       "single namespace",
			namespaces: []string{"openshift-config"},
		},
		{
			name:       "multiple namespaces",
			namespaces: []string{"openshift-config", "openshift-config-managed"},
		},
		{
			name:       "cluster-wide",
			namespaces: []string{""},
		},
		{
			name:       "cluster-wide and namespaced",
			namespaces: []string{"", "openshift-config"},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ki := NewKubeInformersForNamespacesWithOptions(kubeClient, 10*time.Minute, tc.namespaces)

			for _, ns := range tc.namespaces {
				if ki.InformersFor(ns) == nil {
					t.Errorf("expected informers for namespace %q", ns)
				}
			}
			if ki.InformersFor("not-registered") != nil {
				t.Error("expected no informers for unregistered namespace")
			}
		})
	}
}

func TestStripManagedFieldsTransform(t *testing.T) {
	testCases := []struct {
		name              string
		obj               interface{}
		expectManagedNil  bool
		expectPassThrough bool
	}{
		{
			name: "strips managed fields from object that has them",
			obj: &metav1.ObjectMeta{
				Name:      "test",
				Namespace: "default",
				ManagedFields: []metav1.ManagedFieldsEntry{
					{Manager: "kubectl", Operation: metav1.ManagedFieldsOperationApply},
				},
			},
			expectManagedNil: true,
		},
		{
			name: "passes through object without managed fields",
			obj: &metav1.ObjectMeta{
				Name:      "test",
				Namespace: "default",
			},
			expectManagedNil: true,
		},
		{
			name:              "passes through non-Object types without error",
			obj:               "not-an-object",
			expectPassThrough: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := StripManagedFieldsTransform(tc.obj)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.expectPassThrough {
				if result != tc.obj {
					t.Fatal("expected pass-through for non-Object type")
				}
				return
			}
			accessor, ok := result.(metav1.Object)
			if !ok {
				t.Fatal("expected result to implement metav1.Object")
			}
			if tc.expectManagedNil && accessor.GetManagedFields() != nil {
				t.Fatal("expected ManagedFields to be nil")
			}
		})
	}
}
