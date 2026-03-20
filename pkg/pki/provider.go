package pki

import (
	"fmt"

	configv1alpha1 "github.com/openshift/api/config/v1alpha1"
	configv1alpha1listers "github.com/openshift/client-go/config/listers/config/v1alpha1"
)

// PKIProfileProvider resolves the effective PKIProfile for certificate configuration.
type PKIProfileProvider interface {
	// PKIProfile returns the effective PKI profile. A nil return indicates
	// Unmanaged mode where the caller should use its own defaults.
	PKIProfile() (*configv1alpha1.PKIProfile, error)
}

// StaticPKIProfileProvider wraps a static PKIProfile value.
// Use this for the installer or tests where no cluster API is available.
type StaticPKIProfileProvider struct {
	profile *configv1alpha1.PKIProfile
}

// NewStaticPKIProfileProvider creates a StaticPKIProfileProvider from a given profile.
// A nil profile signals Unmanaged mode.
func NewStaticPKIProfileProvider(profile *configv1alpha1.PKIProfile) *StaticPKIProfileProvider {
	return &StaticPKIProfileProvider{profile: profile}
}

func (s *StaticPKIProfileProvider) PKIProfile() (*configv1alpha1.PKIProfile, error) {
	return s.profile, nil
}

// ListerPKIProfileProvider reads the PKI resource from the cluster via a lister.
type ListerPKIProfileProvider struct {
	lister       configv1alpha1listers.PKILister
	resourceName string
}

// NewListerPKIProfileProvider creates a ListerPKIProfileProvider that reads
// the named cluster-scoped PKI resource.
func NewListerPKIProfileProvider(lister configv1alpha1listers.PKILister, resourceName string) *ListerPKIProfileProvider {
	return &ListerPKIProfileProvider{
		lister:       lister,
		resourceName: resourceName,
	}
}

func (l *ListerPKIProfileProvider) PKIProfile() (*configv1alpha1.PKIProfile, error) {
	pki, err := l.lister.Get(l.resourceName)
	if err != nil {
		return nil, fmt.Errorf("failed to get PKI resource %q: %w", l.resourceName, err)
	}

	switch pki.Spec.CertificateManagement.Mode {
	case configv1alpha1.PKICertificateManagementModeUnmanaged:
		return nil, nil
	case configv1alpha1.PKICertificateManagementModeDefault:
		profile := DefaultPKIProfile()
		return &profile, nil
	case configv1alpha1.PKICertificateManagementModeCustom:
		profile := pki.Spec.CertificateManagement.Custom.PKIProfile
		return &profile, nil
	default:
		return nil, fmt.Errorf("unknown PKI certificate management mode: %q", pki.Spec.CertificateManagement.Mode)
	}
}
