package pki

import (
	"fmt"

	configv1alpha1 "github.com/openshift/api/config/v1alpha1"
	"k8s.io/klog/v2"
)

// This file implements dual-shape reading of the PKI resource during the
// transition away from the deprecated spec.certificateManagement mode union
// (openshift/api PR #3060): the new spec.certificates shape is preferred, and
// an old-shape resource is translated into it so that writers like the
// installer can keep writing the old shape until all consumers are bumped.
//
// The old shape's modes map as follows:
//
//   - Unmanaged and Default both map to DefaultCertificatePolicy(). Both
//     modes go through the same machinery and the shim is temporary, so they
//     act identically; the legacy per-component code path is deliberately not
//     used because it cannot issue certificates under the ECDSA CAs the
//     installer creates.
//   - Custom maps custom.PKIProfile field by field.
//
// The file is deletable as a unit: when the deprecated certificateManagement
// shape is removed from openshift/api, this file stops compiling. Removing it
// also requires reverting the two effectiveSpec call sites in provider.go
// (back to returning the resource's spec verbatim) and deleting the old-shape
// tests: the customSpec helper here, the old-shape cases in provider_test.go,
// and TestSetTargetCertKeyPairSecret_OldShapeUnmanagedResource in
// pkg/operator/certrotation/target_test.go.

// effectiveSpec returns spec with the deprecated certificateManagement shape
// translated into certificates, and certificateManagement cleared. The new
// certificates shape is preferred when set; spec.keys passes through
// unchanged in every case. A spec with neither shape set passes through
// unchanged as well (certificate resolution then fails on the missing
// defaults, as it does for an invalid new-shape resource).
func effectiveSpec(spec configv1alpha1.PKISpec) (configv1alpha1.PKISpec, error) {
	if !isZeroCertificatePolicy(spec.Certificates) {
		if spec.CertificateManagement.Mode != "" || !isZeroCustomPolicy(spec.CertificateManagement.Custom) {
			// Both shapes set: only possible through a static provider or a
			// stale cache, since the API enforces ExactlyOneOf. Prefer the
			// new shape so behavior is unchanged when the old shape is
			// removed.
			klog.V(2).Infof("PKI resource sets both certificates and the deprecated certificateManagement; preferring certificates")
		}
		out := spec
		out.CertificateManagement = configv1alpha1.PKICertificateManagement{}
		return out, nil
	}

	if isZeroCertificateManagement(spec.CertificateManagement) {
		return spec, nil
	}

	policy, err := certificatePolicyFromCertificateManagement(spec.CertificateManagement)
	if err != nil {
		return configv1alpha1.PKISpec{}, err
	}
	out := spec
	out.Certificates = policy
	out.CertificateManagement = configv1alpha1.PKICertificateManagement{}
	return out, nil
}

// certificatePolicyFromCertificateManagement translates the deprecated mode
// union into a certificate policy. A stray custom value under Unmanaged or
// Default is ignored, matching the behavior of the shape's removal: the API
// forbids the combination, so no valid object carries it.
func certificatePolicyFromCertificateManagement(cm configv1alpha1.PKICertificateManagement) (configv1alpha1.PKICertificatePolicy, error) {
	switch cm.Mode {
	case configv1alpha1.PKICertificateManagementModeUnmanaged, configv1alpha1.PKICertificateManagementModeDefault:
		// Both modes mean "no administrator-specified configuration"; the
		// shipped defaults apply. Unmanaged historically meant each
		// component's pre-feature hardcoded behavior, but that code path
		// cannot issue under the ECDSA CAs the installer creates, so the
		// default policy is used for both while the shim exists.
		return DefaultCertificatePolicy(), nil
	case configv1alpha1.PKICertificateManagementModeCustom:
		return certificatePolicyFromProfile(cm.Custom.PKIProfile), nil
	default:
		return configv1alpha1.PKICertificatePolicy{}, fmt.Errorf("spec.certificateManagement.mode %q is not a valid mode (Unmanaged, Default, or Custom)", cm.Mode)
	}
}

// certificatePolicyFromProfile maps the deprecated PKIProfile fields onto
// their flattened replacements. An empty profile maps to a zero policy, which
// then fails certificate resolution on the missing required defaults.
func certificatePolicyFromProfile(p configv1alpha1.PKIProfile) configv1alpha1.PKICertificatePolicy {
	return configv1alpha1.PKICertificatePolicy{
		Defaults:           p.Defaults,
		CACertificates:     p.SignerCertificates,
		ServerCertificates: p.ServingCertificates,
		ClientCertificates: p.ClientCertificates,
	}
}

// isZeroCertificatePolicy reports whether policy is the zero value.
// PKICertificatePolicy contains a slice, so it cannot be compared with ==;
// its members are all comparable and use ==, so a future field that is not
// comparable stops compiling here rather than being silently ignored.
func isZeroCertificatePolicy(policy configv1alpha1.PKICertificatePolicy) bool {
	return policy.Defaults == configv1alpha1.PKIDefaultCertificateConfig{} &&
		policy.CACertificates == configv1alpha1.PKICertificateConfig{} &&
		policy.ServerCertificates == configv1alpha1.PKICertificateConfig{} &&
		policy.ClientCertificates == configv1alpha1.PKICertificateConfig{} &&
		len(policy.NamedCertificates) == 0
}

func isZeroCustomPolicy(custom configv1alpha1.CustomPKIPolicy) bool {
	return custom == configv1alpha1.CustomPKIPolicy{}
}

func isZeroCertificateManagement(cm configv1alpha1.PKICertificateManagement) bool {
	return cm == configv1alpha1.PKICertificateManagement{}
}
