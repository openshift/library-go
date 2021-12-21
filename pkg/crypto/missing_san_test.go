package crypto

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
)

func TestCertHasSAN(t *testing.T) {
	for _, tc := range []struct {
		name           string
		cert           *x509.Certificate
		expectedHasSAN bool
	}{
		{
			name:           "nil cert",
			expectedHasSAN: false,
		},
		{
			name: "sole identifier",
			cert: &x509.Certificate{
				Extensions: []pkix.Extension{
					{Id: asn1.ObjectIdentifier{2, 5, 29, 17}},
				},
			},
			expectedHasSAN: true,
		},
		{
			name: "last identifier",
			cert: &x509.Certificate{
				Extensions: []pkix.Extension{
					{Id: asn1.ObjectIdentifier{1}},
					{Id: asn1.ObjectIdentifier{2, 5, 29, 17}},
				},
			},
			expectedHasSAN: true,
		},
		{
			name: "first identifier",
			cert: &x509.Certificate{
				Extensions: []pkix.Extension{
					{Id: asn1.ObjectIdentifier{2, 5, 29, 17}},
					{Id: asn1.ObjectIdentifier{1}},
				},
			},
			expectedHasSAN: true,
		},
		{
			name: "no identifier",
			cert: &x509.Certificate{
				Extensions: []pkix.Extension{
					{Id: asn1.ObjectIdentifier{1}},
					{Id: asn1.ObjectIdentifier{2}},
				},
			},
			expectedHasSAN: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := CertHasSAN(tc.cert); got != tc.expectedHasSAN {
				t.Errorf("expected result %t, got %t", tc.expectedHasSAN, got)
			}
		})
	}
}

func TestIsHostnameError(t *testing.T) {
	for _, tc := range []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name: "invalid hostname error",
			err: x509.HostnameError{
				Certificate: &x509.Certificate{
					Subject:      pkix.Name{CommonName: "foo.bar"},
					SerialNumber: big.NewInt(1),
				},
				Host: "foo.bar",
			},
			expected: true,
		},
		{
			name:     "other error",
			err:      errors.New("boom"),
			expected: false,
		},
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsHostnameError(tc.err); got != tc.expected {
				t.Errorf("expected %t, got %t", tc.expected, got)
			}
		})
	}
}
