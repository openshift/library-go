package certgraphapi

import "fmt"

// PKIRegistryInfo holds information about TLS artifacts stored in etcd. This includes object location and metadata based on object annotations
type PKIRegistryInfo struct {
	// +mapType:=atomic
	CertificateAuthorityBundles []PKIRegistryInClusterCABundle `json:"certificateAuthorityBundles"`
	// +mapType:=atomic
	CertKeyPairs []PKIRegistryInClusterCertKeyPair `json:"certKeyPairs"`
}

// PKIRegistryInClusterCertKeyPair identifies certificate key pair and stores its metadata
type PKIRegistryInClusterCertKeyPair struct {
	// SecretLocation points to the secret location
	SecretLocation InClusterSecretLocation `json:"secretLocation"`
	// CertKeyInfo stores metadata for certificate key pair
	CertKeyInfo PKIRegistryCertKeyPairInfo `json:"certKeyInfo"`
}

// PKIRegistryCertKeyPairInfo holds information about certificate key pair
type PKIRegistryCertKeyPairInfo struct {
	// OwningJiraComponent is a component name when a new OCP issue is filed in Jira
	OwningJiraComponent string `json:"owningJiraComponent"`
	// Description is a one sentence description of the certificate pair purpose
	Description string `json:"description"`

	//CertificateData PKIRegistryCertKeyMetadata
}

// PKIRegistryInClusterCABundle holds information about certificate authority bundle
type PKIRegistryInClusterCABundle struct {
	// ConfigMapLocation points to the configmap location
	ConfigMapLocation InClusterConfigMapLocation `json:"configMapLocation"`
	// CABundleInfo stores metadata for the certificate authority bundle
	CABundleInfo PKIRegistryCertificateAuthorityInfo `json:"certificateAuthorityBundleInfo"`
}

// PKIRegistryCertificateAuthorityInfo holds information about certificate authority bundle
type PKIRegistryCertificateAuthorityInfo struct {
	// OwningJiraComponent is a component name when a new OCP issue is filed in Jira
	OwningJiraComponent string `json:"owningJiraComponent"`
	// Description is a one sentence description of the certificate pair purpose
	Description string `json:"description"`

	//CertificateData []PKIRegistryCertKeyMetadata
}

type RegistrySecretByNamespaceName []PKIRegistryInClusterCertKeyPair

func (n RegistrySecretByNamespaceName) Len() int      { return len(n) }
func (n RegistrySecretByNamespaceName) Swap(i, j int) { n[i], n[j] = n[j], n[i] }
func (n RegistrySecretByNamespaceName) Less(i, j int) bool {
	if n[i].SecretLocation.Namespace != n[j].SecretLocation.Namespace {
		return n[i].SecretLocation.Namespace < n[j].SecretLocation.Namespace
	}
	return n[i].SecretLocation.Name < n[j].SecretLocation.Name
}

type RegistryConfigMapByNamespaceName []PKIRegistryInClusterCABundle

func (n RegistryConfigMapByNamespaceName) Len() int      { return len(n) }
func (n RegistryConfigMapByNamespaceName) Swap(i, j int) { n[i], n[j] = n[j], n[i] }
func (n RegistryConfigMapByNamespaceName) Less(i, j int) bool {
	if n[i].ConfigMapLocation.Namespace != n[j].ConfigMapLocation.Namespace {
		return n[i].ConfigMapLocation.Namespace < n[j].ConfigMapLocation.Namespace
	}
	return n[i].ConfigMapLocation.Name < n[j].ConfigMapLocation.Name
}

type SecretLocationByNamespaceName []InClusterSecretLocation

func (n SecretLocationByNamespaceName) Len() int      { return len(n) }
func (n SecretLocationByNamespaceName) Swap(i, j int) { n[i], n[j] = n[j], n[i] }
func (n SecretLocationByNamespaceName) Less(i, j int) bool {
	if n[i].Namespace != n[j].Namespace {
		return n[i].Namespace < n[j].Namespace
	}
	return n[i].Name < n[j].Name
}

type ConfigMapLocationByNamespaceName []InClusterConfigMapLocation

func (n ConfigMapLocationByNamespaceName) Len() int      { return len(n) }
func (n ConfigMapLocationByNamespaceName) Swap(i, j int) { n[i], n[j] = n[j], n[i] }
func (n ConfigMapLocationByNamespaceName) Less(i, j int) bool {
	if n[i].Namespace != n[j].Namespace {
		return n[i].Namespace < n[j].Namespace
	}
	return n[i].Name < n[j].Name
}

func LocateCertKeyPair(targetLocation InClusterSecretLocation, certKeyPairs []PKIRegistryInClusterCertKeyPair) (*PKIRegistryInClusterCertKeyPair, error) {
	for i, curr := range certKeyPairs {
		if targetLocation == curr.SecretLocation {
			return &certKeyPairs[i], nil
		}
	}

	return nil, fmt.Errorf("not found: %#v", targetLocation)
}

func LocateCertificateAuthorityBundle(targetLocation InClusterConfigMapLocation, caBundles []PKIRegistryInClusterCABundle) (*PKIRegistryInClusterCABundle, error) {
	for i, curr := range caBundles {
		if targetLocation == curr.ConfigMapLocation {
			return &caBundles[i], nil
		}
	}

	return nil, fmt.Errorf("not found: %#v", targetLocation)
}
