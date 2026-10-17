package pki

import (
	"fmt"

	configv1alpha1 "github.com/openshift/api/config/v1alpha1"
	configv1alpha1listers "github.com/openshift/client-go/config/listers/config/v1alpha1"
)

// ConfigProvider provides the cluster-scoped PKI configuration that drives
// key configuration for internally-generated certificates and signing keys.
//
// A provider is only wired up when PKI configuration is enabled (for example
// behind the ConfigurablePKI feature gate); the caller owns that check and
// must not call the provider when the feature is disabled. Resource-backed
// providers expect the PKI resource to exist: a missing resource is an error,
// never a signal to fall back to defaults.
type ConfigProvider interface {
	// Config returns the current PKI configuration (the PKI resource's
	// spec). The returned spec may alias the provider's storage, for
	// example the shared informer cache; callers must treat it as
	// read-only.
	Config() (configv1alpha1.PKISpec, error)
}

// NewStaticConfigProvider returns a ConfigProvider backed by the given spec.
// The spec is deep-copied, so later mutations of the caller's value do not
// affect the provider.
func NewStaticConfigProvider(spec configv1alpha1.PKISpec) ConfigProvider {
	return &staticConfigProvider{spec: *spec.DeepCopy()}
}

type staticConfigProvider struct {
	spec configv1alpha1.PKISpec
}

// Config returns the static PKI configuration.
func (s *staticConfigProvider) Config() (configv1alpha1.PKISpec, error) {
	return s.spec, nil
}

// NewClusterConfigProvider creates a ConfigProvider that resolves the PKI
// configuration from the OpenShift cluster configuration PKI resource.
func NewClusterConfigProvider(lister configv1alpha1listers.PKILister) ConfigProvider {
	return NewListerConfigProvider(lister, "cluster")
}

// NewListerConfigProvider returns a ConfigProvider that reads the named
// cluster-scoped PKI resource via a lister.
func NewListerConfigProvider(lister configv1alpha1listers.PKILister, resourceName string) ConfigProvider {
	return &listerConfigProvider{
		lister:       lister,
		resourceName: resourceName,
	}
}

type listerConfigProvider struct {
	lister       configv1alpha1listers.PKILister
	resourceName string
}

// Config reads the PKI resource and returns its spec. The returned error
// wraps the lister error, so apierrors.IsNotFound keeps matching for callers
// that need to distinguish a missing resource.
func (l *listerConfigProvider) Config() (configv1alpha1.PKISpec, error) {
	pki, err := l.lister.Get(l.resourceName)
	if err != nil {
		return configv1alpha1.PKISpec{}, fmt.Errorf("failed to get PKI resource %q: %w", l.resourceName, err)
	}
	if pki == nil {
		return configv1alpha1.PKISpec{}, fmt.Errorf("lister returned a nil PKI resource %q", l.resourceName)
	}
	return pki.Spec, nil
}
