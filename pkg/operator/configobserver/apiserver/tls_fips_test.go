package apiserver

import (
	"slices"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
)

// TestFIPSApprovedTLSGroups pins the FIPS allowlist: only the three NIST
// P-curves are approved. X25519 and every ML-KEM post-quantum hybrid are not.
// See the KNOWN DIVERGENCE note in tls_fips.go for why.
func TestFIPSApprovedTLSGroups(t *testing.T) {
	perGroup := []struct {
		name         string
		group        configv1.TLSGroup
		wantApproved bool
	}{
		{"secp256r1 is approved", configv1.TLSGroupSecP256r1, true},
		{"secp384r1 is approved", configv1.TLSGroupSecP384r1, true},
		{"secp521r1 is approved", configv1.TLSGroupSecP521r1, true},
		{"X25519 is not approved", configv1.TLSGroupX25519, false},
		{"X25519MLKEM768 hybrid is not approved", configv1.TLSGroupX25519MLKEM768, false},
		{"SecP256r1MLKEM768 hybrid is not approved", configv1.TLSGroupSecP256r1MLKEM768, false},
		{"SecP384r1MLKEM1024 hybrid is not approved", configv1.TLSGroupSecP384r1MLKEM1024, false},
		{"unknown group is not approved", configv1.TLSGroup("UnknownFutureGroup"), false},
	}
	for _, tc := range perGroup {
		t.Run(tc.name, func(t *testing.T) {
			got := fipsApprovedTLSGroups([]configv1.TLSGroup{tc.group})
			gotApproved := len(got) == 1
			if gotApproved != tc.wantApproved {
				t.Errorf("fipsApprovedTLSGroups(%q) = %v, want approved=%v", tc.group, got, tc.wantApproved)
			}
		})
	}

	t.Run("filters a mixed list preserving order", func(t *testing.T) {
		in := []configv1.TLSGroup{
			configv1.TLSGroupX25519MLKEM768,
			configv1.TLSGroupSecP384r1,
			configv1.TLSGroupX25519,
			configv1.TLSGroupSecP256r1,
		}
		want := []configv1.TLSGroup{configv1.TLSGroupSecP384r1, configv1.TLSGroupSecP256r1}
		if got := fipsApprovedTLSGroups(in); !slices.Equal(got, want) {
			t.Errorf("fipsApprovedTLSGroups(%q) = %q, want %q", in, got, want)
		}
	})

	t.Run("empty input yields empty output", func(t *testing.T) {
		if got := fipsApprovedTLSGroups(nil); len(got) != 0 {
			t.Errorf("fipsApprovedTLSGroups(nil) = %q, want empty", got)
		}
	})
}
