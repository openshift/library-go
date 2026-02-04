package crypto

import (
	configv1 "github.com/openshift/api/config/v1"
)

// ShouldAllComponentsAdhere returns true if all components should adhere to
// the cluster-wide TLS security profile settings. When this returns false,
// only external-facing API server components are required to adhere.
//
// This function encapsulates the default semantic for the "no opinion" case,
// allowing a future coordinated change to the default behavior across all
// component implementations.
func ShouldAllComponentsAdhere(tlsAdherence configv1.TLSAdherencePolicy) bool {
	if tlsAdherence == configv1.TLSAdherencePolicyNoOpinion || tlsAdherence == configv1.TLSAdherencePolicyLegacyExternalAPIServerComponentsOnly {
		return false
	}
	return true
}
