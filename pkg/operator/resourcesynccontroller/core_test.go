package resourcesynccontroller

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	corev1listers "k8s.io/client-go/listers/core/v1"

	"github.com/openshift/api/annotations"
	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/operator/certrotation"
)

// mockConfigMapLister is a mock implementation of the ConfigMapLister interface for testing
type mockConfigMapLister struct {
	configMaps map[string]map[string]*corev1.ConfigMap
}

func (m *mockConfigMapLister) List(selector labels.Selector) ([]*corev1.ConfigMap, error) {
	panic("not implemented")
}

func (m *mockConfigMapLister) ConfigMaps(namespace string) corev1listers.ConfigMapNamespaceLister {
	return &mockConfigMapNamespaceLister{
		namespace:  namespace,
		configMaps: m.configMaps,
	}
}

type mockConfigMapNamespaceLister struct {
	namespace  string
	configMaps map[string]map[string]*corev1.ConfigMap
}

func (m *mockConfigMapNamespaceLister) List(selector labels.Selector) ([]*corev1.ConfigMap, error) {
	panic("not implemented")
}

func (m *mockConfigMapNamespaceLister) Get(name string) (*corev1.ConfigMap, error) {
	if m.configMaps == nil {
		return nil, apierrors.NewNotFound(schema.GroupResource{Resource: "configmaps"}, name)
	}
	if namespace, ok := m.configMaps[m.namespace]; ok {
		if cm, ok := namespace[name]; ok {
			return cm, nil
		}
	}
	return nil, apierrors.NewNotFound(schema.GroupResource{Resource: "configmaps"}, name)
}

func TestCombineCABundleConfigMapsOptimistically(t *testing.T) {
	// Generate test certificates
	validCert, err := crypto.MakeSelfSignedCAConfig("Test CA", time.Hour)
	if err != nil {
		t.Fatalf("Failed to create test certificate: %v", err)
	}

	validCertPEM, err := crypto.EncodeCertificates(validCert.Certs[0])
	if err != nil {
		t.Fatalf("Failed to encode certificate: %v", err)
	}

	validCert2, err := crypto.MakeSelfSignedCAConfig("Test CA", time.Hour)
	if err != nil {
		t.Fatalf("Failed to create test certificate: %v", err)
	}

	validCertPEM2, err := crypto.EncodeCertificates(validCert2.Certs[0])
	if err != nil {
		t.Fatalf("Failed to encode certificate: %v", err)
	}

	expiredCert, err := crypto.MakeSelfSignedCAConfig("Expired CA", -1*time.Hour)
	if err != nil {
		t.Fatalf("Failed to create expired certificate: %v", err)
	}

	expiredCertPEM, err := crypto.EncodeCertificates(expiredCert.Certs[0])
	if err != nil {
		t.Fatalf("Failed to encode expired certificate: %v", err)
	}

	jiraComponent := "foobar"
	destinationConfigMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cm1",
			Namespace: "ns1",
			Annotations: map[string]string{
				annotations.OpenShiftComponent: jiraComponent,
			},
		},
		Data: map[string]string{
			"ca-bundle.crt": string(validCertPEM),
		},
	}
	tests := []struct {
		name                  string
		destinationConfigMap  *corev1.ConfigMap
		mockConfigMaps        map[string]map[string]*corev1.ConfigMap
		inputLocations        []ResourceLocation
		additionalAnnotations certrotation.AdditionalAnnotations
		expectModified        bool
		expectedCABundle      *corev1.ConfigMap
	}{
		{
			name: "combine valid certificates",
			mockConfigMaps: map[string]map[string]*corev1.ConfigMap{
				"ns1": {
					"cm1": {
						Data: map[string]string{
							"ca-bundle.crt": string(validCertPEM),
						},
					},
				},
				"ns2": {
					"cm2": {
						Data: map[string]string{
							"ca-bundle.crt": string(validCertPEM2),
						},
					},
				},
			},
			inputLocations: []ResourceLocation{
				{Namespace: "ns1", Name: "cm1"},
				{Namespace: "ns2", Name: "cm2"},
			},
			additionalAnnotations: certrotation.AdditionalAnnotations{},
			expectModified:        true,
			expectedCABundle: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{},
				},
				Data: map[string]string{
					"ca-bundle.crt": fmt.Sprintf("%s%s", string(validCertPEM), string(validCertPEM2)),
				},
			},
		},
		{
			name: "filter expired certificates",
			destinationConfigMap: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "cm1",
					Namespace: "ns1",
					Annotations: map[string]string{
						annotations.OpenShiftComponent: jiraComponent,
					},
				},
				Data: map[string]string{
					"ca-bundle.crt": string(expiredCertPEM),
				},
			},
			mockConfigMaps: map[string]map[string]*corev1.ConfigMap{
				"ns1": {
					"cm1": {
						Data: map[string]string{
							"ca-bundle.crt": string(validCertPEM),
						},
					},
				},
			},
			inputLocations: []ResourceLocation{
				{Namespace: "ns1", Name: "cm1"},
			},
			additionalAnnotations: certrotation.AdditionalAnnotations{},
			expectModified:        true,
			expectedCABundle: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "cm1",
					Namespace: "ns1",
					Annotations: map[string]string{
						annotations.OpenShiftComponent: jiraComponent,
					},
				},
				Data: map[string]string{
					"ca-bundle.crt": string(validCertPEM),
				},
			},
		},
		{
			name:                 "not modified",
			destinationConfigMap: destinationConfigMap,
			mockConfigMaps: map[string]map[string]*corev1.ConfigMap{
				"ns1": {
					"cm1": {
						Data: map[string]string{
							"ca-bundle.crt": string(validCertPEM),
						},
					},
				},
			},
			inputLocations: []ResourceLocation{
				{Namespace: "ns1", Name: "cm1"},
			},
			additionalAnnotations: certrotation.AdditionalAnnotations{
				JiraComponent: jiraComponent,
			},
			expectModified:   false,
			expectedCABundle: destinationConfigMap,
		},
		{
			name: "metadata modified only",
			destinationConfigMap: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "cm1",
					Namespace: "ns1",
				},
				Data: map[string]string{
					"ca-bundle.crt": string(validCertPEM),
				},
			},
			mockConfigMaps: map[string]map[string]*corev1.ConfigMap{
				"ns1": {
					"cm1": {
						Data: map[string]string{
							"ca-bundle.crt": string(validCertPEM),
						},
					},
				},
			},
			inputLocations: []ResourceLocation{
				{Namespace: "ns1", Name: "cm1"},
			},
			additionalAnnotations: certrotation.AdditionalAnnotations{
				JiraComponent: jiraComponent,
			},
			expectModified:   true,
			expectedCABundle: destinationConfigMap,
		},
		{
			name:                 "contents modified only",
			destinationConfigMap: destinationConfigMap,
			mockConfigMaps: map[string]map[string]*corev1.ConfigMap{
				"ns1": {
					"cm1": {
						Data: map[string]string{
							"ca-bundle.crt": string(validCertPEM2),
						},
					},
				},
			},
			inputLocations: []ResourceLocation{
				{Namespace: "ns1", Name: "cm1"},
			},
			additionalAnnotations: certrotation.AdditionalAnnotations{
				JiraComponent: jiraComponent,
			},
			expectModified: true,
			expectedCABundle: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "cm1",
					Namespace: "ns1",
					Annotations: map[string]string{
						annotations.OpenShiftComponent: jiraComponent,
					},
				},
				Data: map[string]string{
					"ca-bundle.crt": string(validCertPEM2),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			lister := &mockConfigMapLister{
				configMaps: test.mockConfigMaps,
			}

			result, modified, err := CombineCABundleConfigMapsOptimistically(test.destinationConfigMap, lister, test.additionalAnnotations, test.inputLocations...)

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if test.expectModified != modified {
				t.Errorf("Expected modified=%v but got %v", test.expectModified, modified)
			}
			if err == nil && result == nil {
				t.Errorf("Expected result to not be nil when no error occurred")
			}

			if result != nil && test.expectedCABundle != nil {
				diff := cmp.Diff(&test.expectedCABundle, &result)
				if diff != "" {
					t.Errorf("Unexpected configmap (-want +got):\n%s", diff)
				}
			}
		})
	}
}
