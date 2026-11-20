package pki

import (
	configv1alpha1 "github.com/openshift/api/config/v1alpha1"
	configv1alpha1listers "github.com/openshift/client-go/config/listers/config/v1alpha1"
)

// This file holds deprecated identifiers kept temporarily so that dependents
// can migrate with `go fix ./...` where a direct replacement exists. It can be
// deleted once the known consumers (installer,
// cluster-kube-apiserver-operator, service-ca-operator,
// cluster-etcd-operator, cluster-kube-controller-manager-operator, and
// hypershift's control-plane-pki-operator) have moved off these names.

// PKIProfileProvider is the deprecated name for the PKI config provider
// interface.
//
// Deprecated: Use [ConfigProvider]. Its PKIProfile method was replaced by
// Config, which returns the PKI resource's spec by value.
//
//go:fix inline
type PKIProfileProvider = ConfigProvider

// CertificateConfig is the deprecated name for the resolved certificate
// configuration.
//
// Deprecated: Use [ResolvedCertificateConfig].
//
//go:fix inline
type CertificateConfig = ResolvedCertificateConfig

// CertificateTypeSigner is the deprecated name for the CA certificate type.
//
// Deprecated: Use [CertificateTypeCA].
//
//go:fix inline
const CertificateTypeSigner = CertificateTypeCA

// CertificateTypeServing is the deprecated name for the server certificate type.
//
// Deprecated: Use [CertificateTypeServer].
//
//go:fix inline
const CertificateTypeServing = CertificateTypeServer

// NewClusterPKIProfileProvider returns a ConfigProvider that reads the
// "cluster" PKI resource.
//
// Deprecated: Use [NewClusterConfigProvider].
//
//go:fix inline
func NewClusterPKIProfileProvider(lister configv1alpha1listers.PKILister) ConfigProvider {
	return NewClusterConfigProvider(lister)
}

// NewListerPKIProfileProvider returns a ConfigProvider that reads the named
// cluster-scoped PKI resource.
//
// Deprecated: Use [NewListerConfigProvider].
//
//go:fix inline
func NewListerPKIProfileProvider(lister configv1alpha1listers.PKILister, resourceName string) ConfigProvider {
	return NewListerConfigProvider(lister, resourceName)
}

// DefaultPKIProfile returns OpenShift's default certificate configuration in
// the PKIProfile shape of the deprecated spec.certificateManagement field:
// ECDSA P-256 for all certificates, with signer (CA) certificates overridden
// to ECDSA P-384.
//
// The default is an install-time seed that the installer writes into the PKI
// resource; it is not a runtime fallback. It has no library-go replacement:
// the seed moves into the installer, so do not add new callers.
//
// Deprecated: The installer owns the install-time default. Operators resolve
// configuration from the PKI resource through a [ConfigProvider].
func DefaultPKIProfile() configv1alpha1.PKIProfile {
	policy := defaultCertificatePolicy()
	return configv1alpha1.PKIProfile{
		Defaults:            policy.Defaults,
		SignerCertificates:  policy.CACertificates,
		ServingCertificates: policy.ServerCertificates,
		ClientCertificates:  policy.ClientCertificates,
	}
}
