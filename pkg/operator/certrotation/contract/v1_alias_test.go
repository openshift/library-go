// This file proves that the v1 certrotation constants and the contract
// package agree byte-for-byte. v1's constants are aliases of contract, so a
// mismatch here means the aliasing was broken by an edit on one side.
package contract_test

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openshift/library-go/pkg/operator/certrotation"
	"github.com/openshift/library-go/pkg/operator/certrotation/contract"
)

func metav1Object(namespace, name string) metav1.ObjectMeta {
	return metav1.ObjectMeta{Namespace: namespace, Name: name}
}

func TestV1ConstantsAliasContract(t *testing.T) {
	testCases := []struct {
		name     string
		v1       string
		expected string
	}{
		{
			name:     "not-before annotation",
			v1:       certrotation.CertificateNotBeforeAnnotation,
			expected: contract.CertificateNotBeforeAnnotation,
		},
		{
			name:     "not-after annotation",
			v1:       certrotation.CertificateNotAfterAnnotation,
			expected: contract.CertificateNotAfterAnnotation,
		},
		{
			name:     "issuer annotation",
			v1:       certrotation.CertificateIssuer,
			expected: contract.CertificateIssuer,
		},
		{
			name:     "hostnames annotation",
			v1:       certrotation.CertificateHostnames,
			expected: contract.CertificateHostnames,
		},
		{
			name:     "test-name annotation",
			v1:       certrotation.CertificateTestNameAnnotation,
			expected: contract.CertificateTestNameAnnotation,
		},
		{
			name:     "auto-regenerate annotation",
			v1:       certrotation.CertificateAutoRegenerateAfterOfflineExpiryAnnotation,
			expected: contract.CertificateAutoRegenerateAfterOfflineExpiryAnnotation,
		},
		{
			name:     "refresh-period annotation",
			v1:       certrotation.CertificateRefreshPeriodAnnotation,
			expected: contract.CertificateRefreshPeriodAnnotation,
		},
		{
			name:     "managed certificate type label",
			v1:       certrotation.ManagedCertificateTypeLabelName,
			expected: contract.ManagedCertificateTypeLabelName,
		},
		{
			name:     "ca-bundle certificate type",
			v1:       string(certrotation.CertificateTypeCABundle),
			expected: contract.CertificateTypeCABundle,
		},
		{
			name:     "signer certificate type",
			v1:       string(certrotation.CertificateTypeSigner),
			expected: contract.CertificateTypeSigner,
		},
		{
			name:     "target certificate type",
			v1:       string(certrotation.CertificateTypeTarget),
			expected: contract.CertificateTypeTarget,
		},
		{
			name:     "unknown certificate type",
			v1:       string(certrotation.CertificateTypeUnknown),
			expected: contract.CertificateTypeUnknown,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.v1 != tc.expected {
				t.Errorf("v1 constant %q does not match contract value %q", tc.v1, tc.expected)
			}
		})
	}
}

func TestMetadataMatchesAdditionalAnnotationsFields(t *testing.T) {
	// AdditionalAnnotations and contract.Metadata must stay field-compatible
	// for the caller-supplied metadata, so that consumers can migrate
	// mechanically. This test pins the wiring by writing the same values
	// through both and comparing the resulting annotations.
	meta := metav1Object("test-namespace", "test-name")
	additional := certrotation.AdditionalAnnotations{
		JiraComponent:                    "test-component",
		Description:                      "test description",
		TestName:                         "test-e2e",
		AutoRegenerateAfterOfflineExpiry: "https://example.com/pr/1",
	}
	_ = additional.EnsureTLSMetadataUpdate(&meta)

	contractMeta := metav1Object("test-namespace", "test-name")
	_ = contract.Metadata{
		JiraComponent:                    "test-component",
		Description:                      "test description",
		TestName:                         "test-e2e",
		AutoRegenerateAfterOfflineExpiry: "https://example.com/pr/1",
	}.Apply(&contractMeta)

	for key, value := range meta.Annotations {
		if contractMeta.Annotations[key] != value {
			t.Errorf("annotation %q: v1 wrote %q, contract wrote %q", key, value, contractMeta.Annotations[key])
		}
	}
	for key, value := range contractMeta.Annotations {
		if meta.Annotations[key] != value {
			t.Errorf("annotation %q: contract wrote %q, v1 wrote %q", key, value, meta.Annotations[key])
		}
	}
}
