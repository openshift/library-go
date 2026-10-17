package pki

import (
	configv1alpha1listers "github.com/openshift/client-go/config/listers/config/v1alpha1"
)

// This file holds deprecated identifiers kept temporarily so that dependents
// can migrate with `go fix ./...`. It can be deleted once the known consumers
// (cluster-kube-apiserver-operator, service-ca-operator,
// cluster-etcd-operator, cluster-kube-controller-manager-operator, and
// hypershift's control-plane-pki-operator) have moved to the new names.

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
