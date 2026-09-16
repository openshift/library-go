package v1helpers

import (
	"fmt"
	"testing"

	"k8s.io/client-go/informers"
	fakekube "k8s.io/client-go/kubernetes/fake"
)

func TestCachedConfigMapGetterPanicsForMissingNamespace(t *testing.T) {
	kubeClient := fakekube.NewSimpleClientset()
	kubeInformers := NewKubeInformersForNamespaces(kubeClient, "openshift-config")

	getter := CachedConfigMapGetter(kubeClient.CoreV1(), kubeInformers)

	assertPanicsWith(t, fmt.Sprintf("namespace %q is missing", "unregistered"), func() {
		getter.ConfigMaps("unregistered")
	})
}

func TestCachedSecretGetterPanicsForMissingNamespace(t *testing.T) {
	kubeClient := fakekube.NewSimpleClientset()
	kubeInformers := NewKubeInformersForNamespaces(kubeClient, "openshift-config")

	getter := CachedSecretGetter(kubeClient.CoreV1(), kubeInformers)

	assertPanicsWith(t, fmt.Sprintf("namespace %q is missing", "unregistered"), func() {
		getter.Secrets("unregistered")
	})
}

func TestCachedConfigMapGetterSucceedsForRegisteredNamespace(t *testing.T) {
	kubeClient := fakekube.NewSimpleClientset()
	kubeInformers := NewKubeInformersForNamespaces(kubeClient, "openshift-config")

	getter := CachedConfigMapGetter(kubeClient.CoreV1(), kubeInformers)

	// Should not panic for a registered namespace
	_ = getter.ConfigMaps("openshift-config")
}

func TestCachedSecretGetterSucceedsForRegisteredNamespace(t *testing.T) {
	kubeClient := fakekube.NewSimpleClientset()
	kubeInformers := NewKubeInformersForNamespaces(kubeClient, "openshift-config")

	getter := CachedSecretGetter(kubeClient.CoreV1(), kubeInformers)

	// Should not panic for a registered namespace
	_ = getter.Secrets("openshift-config")
}

func TestCachedGetterWithFakeInformers(t *testing.T) {
	kubeClient := fakekube.NewSimpleClientset()
	fakeInformers := NewFakeKubeInformersForNamespaces(map[string]informers.SharedInformerFactory{
		"test-ns": informers.NewSharedInformerFactory(kubeClient, 0),
	})

	testCases := []struct {
		name      string
		namespace string
		panics    bool
	}{
		{
			name:      "registered namespace succeeds",
			namespace: "test-ns",
			panics:    false,
		},
		{
			name:      "unregistered namespace panics",
			namespace: "missing-ns",
			panics:    true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			configMapGetter := CachedConfigMapGetter(kubeClient.CoreV1(), fakeInformers)
			secretGetter := CachedSecretGetter(kubeClient.CoreV1(), fakeInformers)

			if tc.panics {
				expectedMsg := fmt.Sprintf("namespace %q is missing", tc.namespace)
				assertPanicsWith(t, expectedMsg, func() {
					configMapGetter.ConfigMaps(tc.namespace)
				})
				assertPanicsWith(t, expectedMsg, func() {
					secretGetter.Secrets(tc.namespace)
				})
			} else {
				_ = configMapGetter.ConfigMaps(tc.namespace)
				_ = secretGetter.Secrets(tc.namespace)
			}
		})
	}
}

func assertPanicsWith(t *testing.T, expectedMessage string, f func()) {
	t.Helper()
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic, but none occurred")
		}
		got := fmt.Sprintf("%v", r)
		if got != expectedMessage {
			t.Fatalf("expected panic message %q, got %q", expectedMessage, got)
		}
	}()
	f()
}
