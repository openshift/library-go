package crypto

import (
	"testing"

	configv1 "github.com/openshift/api/config/v1"
)

func TestShouldHonorClusterTLSProfile(t *testing.T) {
	tests := []struct {
		name          string
		tlsAdherence  configv1.TLSAdherencePolicy
		expectedHonor bool
	}{
		{
			name:          "empty string (no opinion) returns false",
			tlsAdherence:  configv1.TLSAdherencePolicyNoOpinion,
			expectedHonor: false,
		},
		{
			name:          "LegacyAdheringComponentsOnly returns false",
			tlsAdherence:  configv1.TLSAdherencePolicyLegacyAdheringComponentsOnly,
			expectedHonor: false,
		},
		{
			name:          "StrictAllComponents returns true",
			tlsAdherence:  configv1.TLSAdherencePolicyStrictAllComponents,
			expectedHonor: true,
		},
		{
			name:          "unknown value defaults to true (strict behavior)",
			tlsAdherence:  configv1.TLSAdherencePolicy("SomeUnknownFutureValue"),
			expectedHonor: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ShouldHonorClusterTLSProfile(tt.tlsAdherence)
			if got != tt.expectedHonor {
				t.Errorf("ShouldHonorClusterTLSProfile(%q) = %v, want %v", tt.tlsAdherence, got, tt.expectedHonor)
			}
		})
	}
}
