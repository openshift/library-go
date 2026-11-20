package contract

import (
	"testing"
	"time"
)

func TestContractGoldenStrings(t *testing.T) {
	testCases := []struct {
		name     string
		actual   string
		expected string
	}{
		{
			name:     "not-before annotation key",
			actual:   CertificateNotBeforeAnnotation,
			expected: "auth.openshift.io/certificate-not-before",
		},
		{
			name:     "not-after annotation key",
			actual:   CertificateNotAfterAnnotation,
			expected: "auth.openshift.io/certificate-not-after",
		},
		{
			name:     "issuer annotation key",
			actual:   CertificateIssuer,
			expected: "auth.openshift.io/certificate-issuer",
		},
		{
			name:     "hostnames annotation key",
			actual:   CertificateHostnames,
			expected: "auth.openshift.io/certificate-hostnames",
		},
		{
			name:     "test-name annotation key",
			actual:   CertificateTestNameAnnotation,
			expected: "certificates.openshift.io/test-name",
		},
		{
			name:     "auto-regenerate annotation key",
			actual:   CertificateAutoRegenerateAfterOfflineExpiryAnnotation,
			expected: "certificates.openshift.io/auto-regenerate-after-offline-expiry",
		},
		{
			name:     "refresh-period annotation key",
			actual:   CertificateRefreshPeriodAnnotation,
			expected: "certificates.openshift.io/refresh-period",
		},
		{
			name:     "force-regeneration sentinel",
			actual:   ForceRegeneration,
			expected: "force-regeneration",
		},
		{
			name:     "managed certificate type label key",
			actual:   ManagedCertificateTypeLabelName,
			expected: "auth.openshift.io/managed-certificate-type",
		},
		{
			name:     "ca-bundle label value",
			actual:   CertificateTypeCABundle,
			expected: "ca-bundle",
		},
		{
			name:     "signer label value",
			actual:   CertificateTypeSigner,
			expected: "signer",
		},
		{
			name:     "target label value",
			actual:   CertificateTypeTarget,
			expected: "target",
		},
		{
			name:     "unknown label value",
			actual:   CertificateTypeUnknown,
			expected: "unknown",
		},
		{
			name:     "secret cert data key",
			actual:   SecretCertKey,
			expected: "tls.crt",
		},
		{
			name:     "secret key data key",
			actual:   SecretKeyKey,
			expected: "tls.key",
		},
		{
			name:     "ca bundle configmap data key",
			actual:   CABundleConfigMapKey,
			expected: "ca-bundle.crt",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.actual != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, tc.actual)
			}
		})
	}
}

func TestFormatValidityTime(t *testing.T) {
	testCases := []struct {
		name     string
		input    time.Time
		expected string
	}{
		{
			name:     "UTC timestamp renders with Z suffix",
			input:    time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC),
			expected: "2026-11-17T12:00:00Z",
		},
		{
			name:     "fractional seconds are truncated, as v1 always wrote",
			input:    time.Date(2026, 11, 17, 12, 0, 0, 500000000, time.UTC),
			expected: "2026-11-17T12:00:00Z",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := FormatValidityTime(tc.input)
			if actual != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, actual)
			}
			parsed, err := ParseValidityTime(actual)
			if err != nil {
				t.Fatalf("ParseValidityTime failed: %v", err)
			}
			if !parsed.Equal(tc.input.Truncate(time.Second)) {
				t.Errorf("round trip mismatch: expected %v, got %v", tc.input.Truncate(time.Second), parsed)
			}
		})
	}
}

func TestParseValidityTimeRejectsSentinel(t *testing.T) {
	if _, err := ParseValidityTime(ForceRegeneration); err == nil {
		t.Error("expected ParseValidityTime to reject the force-regeneration sentinel")
	}
}

func TestFormatHostnames(t *testing.T) {
	testCases := []struct {
		name      string
		input     []string
		expected  string
		roundTrip []string
	}{
		{
			name:      "empty set renders as empty string",
			input:     nil,
			expected:  "",
			roundTrip: nil,
		},
		{
			name:      "single hostname",
			input:     []string{"localhost"},
			expected:  "localhost",
			roundTrip: []string{"localhost"},
		},
		{
			name:      "duplicates are removed and set is sorted",
			input:     []string{"api-int.cluster.example.com", "10.0.0.1", "api-int.cluster.example.com"},
			expected:  "10.0.0.1,api-int.cluster.example.com",
			roundTrip: []string{"10.0.0.1", "api-int.cluster.example.com"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := FormatHostnames(tc.input)
			if actual != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, actual)
			}
			roundTrip := ParseHostnames(actual)
			if len(roundTrip) != len(tc.roundTrip) {
				t.Fatalf("round trip length mismatch: expected %v, got %v", tc.roundTrip, roundTrip)
			}
			for i := range roundTrip {
				if roundTrip[i] != tc.roundTrip[i] {
					t.Errorf("round trip mismatch at %d: expected %q, got %q", i, tc.roundTrip[i], roundTrip[i])
				}
			}
		})
	}
}

func TestParseHostnamesEmpty(t *testing.T) {
	if actual := ParseHostnames(""); actual != nil {
		t.Errorf("expected nil for empty value, got %v", actual)
	}
}

func TestFormatRefreshPeriod(t *testing.T) {
	testCases := []struct {
		name     string
		input    time.Duration
		expected string
	}{
		{
			name:     "one month",
			input:    30 * 24 * time.Hour,
			expected: "720h0m0s",
		},
		{
			name:     "two hours",
			input:    2 * time.Hour,
			expected: "2h0m0s",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := FormatRefreshPeriod(tc.input)
			if actual != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, actual)
			}
		})
	}
}
