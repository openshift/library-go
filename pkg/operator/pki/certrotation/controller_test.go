package certrotation

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/openshift/library-go/pkg/operator/certrotation/contract"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

func TestNewControllerRequiresInformers(t *testing.T) {
	_, err := NewController(testRotation(), Options{
		Role:       RoleWriter,
		KubeClient: fake.NewSimpleClientset(),
		PKI:        LegacyPKI(),
		Recorder:   &testLogger{},
	})
	if err == nil {
		t.Fatal("expected error when Informers is nil")
	}
}

func TestNewControllerValidatesInformerSource(t *testing.T) {
	// An informer source that returns nil for the rotation's namespace must
	// be rejected at construction.
	rotation := testRotation()
	_, err := NewController(rotation, Options{
		Role:       RoleWriter,
		KubeClient: fake.NewSimpleClientset(),
		PKI:        LegacyPKI(),
		Recorder:   &testLogger{},
		Informers:  v1helpers.NewKubeInformersForNamespaces(fake.NewSimpleClientset(), "other-namespace"),
	})
	if err == nil {
		t.Fatal("expected error when the informer source lacks the rotation's namespace")
	}
}

func TestNewControllerAcceptsValidOptions(t *testing.T) {
	client := fake.NewSimpleClientset()
	_, err := NewController(testRotation(), Options{
		Role:       RoleWriter,
		KubeClient: client,
		PKI:        LegacyPKI(),
		Recorder:   &testLogger{},
		Informers:  v1helpers.NewKubeInformersForNamespaces(client, testNamespace),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestControllerFilterEvents(t *testing.T) {
	client := fake.NewSimpleClientset()
	impl, err := newController(testRotation(), Options{
		Role:       RoleWriter,
		KubeClient: client,
		PKI:        LegacyPKI(),
		Recorder:   &testLogger{},
		Informers:  v1helpers.NewKubeInformersForNamespaces(client, testNamespace),
	})
	if err != nil {
		t.Fatal(err)
	}

	testCases := []struct {
		name     string
		obj      interface{}
		expected bool
	}{
		{
			name:     "the rotation's signer secret is admitted",
			obj:      &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: signerName}},
			expected: true,
		},
		{
			name:     "the rotation's target secret is admitted",
			obj:      &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: targetName}},
			expected: true,
		},
		{
			name:     "an unrelated secret is filtered",
			obj:      &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "unrelated"}},
			expected: false,
		},
		{
			name:     "the rotation's bundle configmap is admitted",
			obj:      &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: bundleName}},
			expected: true,
		},
		{
			name:     "an unrelated configmap is filtered",
			obj:      &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: "unrelated"}},
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if actual := impl.filterEvents(tc.obj); actual != tc.expected {
				t.Errorf("expected %v, got %v", tc.expected, actual)
			}
		})
	}
	_ = contract.CertificateTypeSigner
	_ = context.Background()
	_ = time.Now()
}
