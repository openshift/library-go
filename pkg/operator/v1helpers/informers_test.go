package v1helpers

import (
	"testing"
	"time"

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
