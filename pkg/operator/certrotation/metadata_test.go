package certrotation

import (
	"strings"
	"testing"

	"github.com/openshift/api/annotations"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestEnsureOwnerRefAndTLSAnnotationsForSecret(t *testing.T) {
	testOwner := &metav1.OwnerReference{
		APIVersion: "apps/v1",
		Kind:       "Deployment",
		Name:       "test-deployment",
		UID:        "test-uid",
	}

	testAnnotations := AdditionalAnnotations{
		JiraComponent: "test-component",
		Description:   "test description",
		TestName:      "test-name",
	}

	tests := []struct {
		name                    string
		secret                  *corev1.Secret
		owner                   *metav1.OwnerReference
		additionalAnnotations   AdditionalAnnotations
		expectedUpdateDetails   string
		expectedOwnerReferences []metav1.OwnerReference
		expectedAnnotations     map[string]string
	}{
		{
			name: "no updates needed - already has owner and annotations",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "test-namespace",
					OwnerReferences: []metav1.OwnerReference{
						*testOwner,
					},
					Annotations: map[string]string{
						annotations.OpenShiftComponent:   "test-component",
						annotations.OpenShiftDescription: "test description",
						CertificateTestNameAnnotation:    "test-name",
					},
				},
			},
			owner:                 testOwner,
			additionalAnnotations: testAnnotations,
			expectedUpdateDetails: "",
			expectedOwnerReferences: []metav1.OwnerReference{
				*testOwner,
			},
			expectedAnnotations: map[string]string{
				annotations.OpenShiftComponent:   "test-component",
				annotations.OpenShiftDescription: "test description",
				CertificateTestNameAnnotation:    "test-name",
			},
		},
		{
			name: "only owner reference needs updating",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "test-namespace",
					Annotations: map[string]string{
						annotations.OpenShiftComponent:   "test-component",
						annotations.OpenShiftDescription: "test description",
						CertificateTestNameAnnotation:    "test-name",
					},
				},
			},
			owner:                 testOwner,
			additionalAnnotations: testAnnotations,
			expectedUpdateDetails: "owner reference updated to &v1.OwnerReference{APIVersion:\"apps/v1\", Kind:\"Deployment\", Name:\"test-deployment\", UID:\"test-uid\", Controller:(*bool)(nil), BlockOwnerDeletion:(*bool)(nil)}",
			expectedOwnerReferences: []metav1.OwnerReference{
				*testOwner,
			},
			expectedAnnotations: map[string]string{
				annotations.OpenShiftComponent:   "test-component",
				annotations.OpenShiftDescription: "test description",
				CertificateTestNameAnnotation:    "test-name",
			},
		},
		{
			name: "only annotations need updating",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "test-namespace",
					OwnerReferences: []metav1.OwnerReference{
						*testOwner,
					},
				},
			},
			owner:                 testOwner,
			additionalAnnotations: testAnnotations,
			expectedUpdateDetails: "annotations set to certrotation.AdditionalAnnotations{JiraComponent:\"test-component\", Description:\"test description\", TestName:\"test-name\", AutoRegenerateAfterOfflineExpiry:\"\", NotBefore:\"\", NotAfter:\"\", RefreshPeriod:\"\"}",
			expectedOwnerReferences: []metav1.OwnerReference{
				*testOwner,
			},
			expectedAnnotations: map[string]string{
				annotations.OpenShiftComponent:   "test-component",
				annotations.OpenShiftDescription: "test description",
				CertificateTestNameAnnotation:    "test-name",
			},
		},
		{
			name: "both owner reference and annotations need updating",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: "test-namespace",
				},
			},
			owner:                 testOwner,
			additionalAnnotations: testAnnotations,
			expectedUpdateDetails: "owner reference updated to &v1.OwnerReference{APIVersion:\"apps/v1\", Kind:\"Deployment\", Name:\"test-deployment\", UID:\"test-uid\", Controller:(*bool)(nil), BlockOwnerDeletion:(*bool)(nil)}, annotations set to certrotation.AdditionalAnnotations{JiraComponent:\"test-component\", Description:\"test description\", TestName:\"test-name\", AutoRegenerateAfterOfflineExpiry:\"\", NotBefore:\"\", NotAfter:\"\", RefreshPeriod:\"\"}",
			expectedOwnerReferences: []metav1.OwnerReference{
				*testOwner,
			},
			expectedAnnotations: map[string]string{
				annotations.OpenShiftComponent:   "test-component",
				annotations.OpenShiftDescription: "test description",
				CertificateTestNameAnnotation:    "test-name",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			updates := ensureOwnerRefAndTLSAnnotations(&tt.secret.ObjectMeta, tt.owner, tt.additionalAnnotations)
			result := strings.Join(updates, ", ")

			require.Equal(t, result, tt.expectedUpdateDetails, "expected update detail")
			require.Equal(t, tt.expectedOwnerReferences, tt.secret.OwnerReferences, "expected owner references")
			require.Equal(t, tt.expectedAnnotations, tt.secret.Annotations, "expected owner annotations")
		})
	}
}

func TestEnsureOwnerRefAndTLSAnnotationsForConfigMap(t *testing.T) {
	testOwner := &metav1.OwnerReference{
		APIVersion: "apps/v1",
		Kind:       "Deployment",
		Name:       "test-deployment",
		UID:        "test-uid",
	}

	testAnnotations := AdditionalAnnotations{
		JiraComponent: "test-component",
		Description:   "test description",
		TestName:      "test-name",
	}

	tests := []struct {
		name                    string
		configMap               *corev1.ConfigMap
		owner                   *metav1.OwnerReference
		additionalAnnotations   AdditionalAnnotations
		expectedUpdateDetails   string
		expectedOwnerReferences []metav1.OwnerReference
		expectedAnnotations     map[string]string
	}{
		{
			name: "no updates needed - already has owner and annotations",
			configMap: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-configmap",
					Namespace: "test-namespace",
					OwnerReferences: []metav1.OwnerReference{
						*testOwner,
					},
					Annotations: map[string]string{
						annotations.OpenShiftComponent:   "test-component",
						annotations.OpenShiftDescription: "test description",
						CertificateTestNameAnnotation:    "test-name",
					},
				},
			},
			owner:                 testOwner,
			additionalAnnotations: testAnnotations,
			expectedUpdateDetails: "",
			expectedOwnerReferences: []metav1.OwnerReference{
				*testOwner,
			},
			expectedAnnotations: map[string]string{
				annotations.OpenShiftComponent:   "test-component",
				annotations.OpenShiftDescription: "test description",
				CertificateTestNameAnnotation:    "test-name",
			},
		},
		{
			name: "only owner reference needs updating",
			configMap: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-configmap",
					Namespace: "test-namespace",
					Annotations: map[string]string{
						annotations.OpenShiftComponent:   "test-component",
						annotations.OpenShiftDescription: "test description",
						CertificateTestNameAnnotation:    "test-name",
					},
				},
			},
			owner:                 testOwner,
			additionalAnnotations: testAnnotations,
			expectedUpdateDetails: "owner reference updated to &v1.OwnerReference{APIVersion:\"apps/v1\", Kind:\"Deployment\", Name:\"test-deployment\", UID:\"test-uid\", Controller:(*bool)(nil), BlockOwnerDeletion:(*bool)(nil)}",
			expectedOwnerReferences: []metav1.OwnerReference{
				*testOwner,
			},
			expectedAnnotations: map[string]string{
				annotations.OpenShiftComponent:   "test-component",
				annotations.OpenShiftDescription: "test description",
				CertificateTestNameAnnotation:    "test-name",
			},
		},
		{
			name: "only annotations need updating",
			configMap: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-configmap",
					Namespace: "test-namespace",
					OwnerReferences: []metav1.OwnerReference{
						*testOwner,
					},
				},
			},
			owner:                 testOwner,
			additionalAnnotations: testAnnotations,
			expectedUpdateDetails: "annotations set to certrotation.AdditionalAnnotations{JiraComponent:\"test-component\", Description:\"test description\", TestName:\"test-name\", AutoRegenerateAfterOfflineExpiry:\"\", NotBefore:\"\", NotAfter:\"\", RefreshPeriod:\"\"}",
			expectedOwnerReferences: []metav1.OwnerReference{
				*testOwner,
			},
			expectedAnnotations: map[string]string{
				annotations.OpenShiftComponent:   "test-component",
				annotations.OpenShiftDescription: "test description",
				CertificateTestNameAnnotation:    "test-name",
			},
		},
		{
			name: "both owner reference and annotations need updating",
			configMap: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-configmap",
					Namespace: "test-namespace",
				},
			},
			owner:                 testOwner,
			additionalAnnotations: testAnnotations,
			expectedUpdateDetails: "owner reference updated to &v1.OwnerReference{APIVersion:\"apps/v1\", Kind:\"Deployment\", Name:\"test-deployment\", UID:\"test-uid\", Controller:(*bool)(nil), BlockOwnerDeletion:(*bool)(nil)}, annotations set to certrotation.AdditionalAnnotations{JiraComponent:\"test-component\", Description:\"test description\", TestName:\"test-name\", AutoRegenerateAfterOfflineExpiry:\"\", NotBefore:\"\", NotAfter:\"\", RefreshPeriod:\"\"}",
			expectedOwnerReferences: []metav1.OwnerReference{
				*testOwner,
			},
			expectedAnnotations: map[string]string{
				annotations.OpenShiftComponent:   "test-component",
				annotations.OpenShiftDescription: "test description",
				CertificateTestNameAnnotation:    "test-name",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			updates := ensureOwnerRefAndTLSAnnotations(&tt.configMap.ObjectMeta, tt.owner, tt.additionalAnnotations)
			result := strings.Join(updates, ", ")

			require.Equal(t, result, tt.expectedUpdateDetails, "expected update detail")
			require.Equal(t, tt.expectedOwnerReferences, tt.configMap.OwnerReferences, "expected owner references")
			require.Equal(t, tt.expectedAnnotations, tt.configMap.Annotations, "expected owner annotations")
		})
	}
}
