package certgraphapi

import "fmt"

type PKIRegistryInfo struct {
	CertificateAuthorityBundles []PKIRegistryInClusterCABundle    `json:"certificateAuthorityBundles"`
	CertKeyPairs                []PKIRegistryInClusterCertKeyPair `json:"certKeyPairs"`
}

type PKIRegistryInClusterCertKeyPair struct {
	SecretLocation InClusterSecretLocation `json:"secretLocation"`

	CertKeyInfo PKIRegistryCertKeyPairInfo `json:"certKeyInfo"`
}

type PKIRegistryCertKeyPairInfo struct {
	OwningJiraComponent string `json:"owningJiraComponent"`
	Description         string `json:"description"`

	//CertificateData PKIRegistryCertKeyMetadata
}

type PKIRegistryInClusterCABundle struct {
	ConfigMapLocation InClusterConfigMapLocation `json:"configMapLocation"`

	CABundleInfo PKIRegistryCertificateAuthorityInfo `json:"certificateAuthorityBundleInfo"`
}

type PKIRegistryCertificateAuthorityInfo struct {
	OwningJiraComponent string `json:"owningJiraComponent"`
	Description         string `json:"description"`

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
