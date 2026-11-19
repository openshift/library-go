package pki

import (
	"testing"

	configv1alpha1 "github.com/openshift/api/config/v1alpha1"
	"k8s.io/apimachinery/pkg/api/equality"
)

// TestDefaultPKIProfile verifies the deprecated shim carries the same values
// as the default policy, so that Default/Unmanaged translation and callers
// still seeding from DefaultPKIProfile agree.
func TestDefaultPKIProfile(t *testing.T) {
	got := certificatePolicyFromProfile(DefaultPKIProfile())
	if want := defaultCertificatePolicy(); !equality.Semantic.DeepEqual(got, want) {
		t.Errorf("DefaultPKIProfile() maps to %+v, want %+v", got, want)
	}

	// The profile must resolve: it is written verbatim into Custom-mode
	// resources by older installers.
	policy := certificatePolicyFromProfile(DefaultPKIProfile())
	cfg, err := ResolveCertificateConfig(policy, CertificateTypeCA, "openshift.io/test.signer")
	if err != nil {
		t.Fatalf("ResolveCertificateConfig() error = %v", err)
	}
	if got := unwrapSelfCheck(t, cfg.Key); got != mustECDSA("P384") {
		t.Errorf("CA key = %+v, want ECDSA P384", got)
	}
	if p := DefaultPKIProfile(); p.Defaults.Key.Algorithm != configv1alpha1.PKIKeyAlgorithmECDSA {
		t.Errorf("defaults algorithm = %v, want ECDSA", p.Defaults.Key.Algorithm)
	}
}
