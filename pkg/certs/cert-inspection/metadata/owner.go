package metadata

import (
	"bytes"
	"fmt"

	"github.com/openshift/library-go/pkg/certs/cert-inspection/certgraphapi"
	"k8s.io/apimachinery/pkg/util/sets"
)

func newOwnerViolation(name string, pkiInfo *certgraphapi.PKIRegistryInfo) (Violation, error) {
	registry := &certgraphapi.PKIRegistryInfo{}

	for i := range pkiInfo.CertKeyPairs {
		curr := pkiInfo.CertKeyPairs[i]
		owner := curr.CertKeyInfo.OwningJiraComponent
		if len(owner) == 0 || owner == unknownOwner {
			registry.CertKeyPairs = append(registry.CertKeyPairs, curr)
		}
	}
	for i := range pkiInfo.CertificateAuthorityBundles {
		curr := pkiInfo.CertificateAuthorityBundles[i]
		owner := curr.CABundleInfo.OwningJiraComponent
		if len(owner) == 0 || owner == unknownOwner {
			registry.CertificateAuthorityBundles = append(registry.CertificateAuthorityBundles, curr)
		}
	}

	v := Violation{
		Name:     fmt.Sprintf("%s-violations", name),
		Registry: registry,
	}

	markdown, err := generateMarkdownNoOwner(pkiInfo)
	if err != nil {
		return v, err
	}
	v.Markdown = markdown

	return v, nil
}

func generateMarkdownNoOwner(pkiInfo *certgraphapi.PKIRegistryInfo) ([]byte, error) {
	certsByOwner := map[string][]certgraphapi.PKIRegistryInClusterCertKeyPair{}
	certsWithoutOwners := []certgraphapi.PKIRegistryInClusterCertKeyPair{}
	caBundlesByOwner := map[string][]certgraphapi.PKIRegistryInClusterCABundle{}
	caBundlesWithoutOwners := []certgraphapi.PKIRegistryInClusterCABundle{}

	for i := range pkiInfo.CertKeyPairs {
		curr := pkiInfo.CertKeyPairs[i]
		owner := curr.CertKeyInfo.OwningJiraComponent
		if len(owner) == 0 || owner == unknownOwner {
			certsWithoutOwners = append(certsWithoutOwners, curr)
			continue
		}
		certsByOwner[owner] = append(certsByOwner[owner], curr)
	}
	for i := range pkiInfo.CertificateAuthorityBundles {
		curr := pkiInfo.CertificateAuthorityBundles[i]
		owner := curr.CABundleInfo.OwningJiraComponent
		if len(owner) == 0 || owner == unknownOwner {
			caBundlesWithoutOwners = append(caBundlesWithoutOwners, curr)
			continue
		}
		caBundlesByOwner[owner] = append(caBundlesByOwner[owner], curr)
	}

	md := &bytes.Buffer{}

	fmt.Fprintln(md, "## Missing Owners")
	if len(certsWithoutOwners) > 0 {
		fmt.Fprintln(md, "### Certificates")
		for i, curr := range certsWithoutOwners {
			fmt.Fprintf(md, "%d. ns/%v secret/%v\n\n", i+1, curr.SecretLocation.Namespace, curr.SecretLocation.Name)
			fmt.Fprintf(md, "     **Description:** %v\n", curr.CertKeyInfo.Description)
		}
		fmt.Fprintln(md, "")
	}
	if len(caBundlesWithoutOwners) > 0 {
		fmt.Fprintln(md, "### Certificate Authority Bundles")
		for i, curr := range caBundlesWithoutOwners {
			fmt.Fprintf(md, "%d. ns/%v configmap/%v\n\n", i+1, curr.ConfigMapLocation.Namespace, curr.ConfigMapLocation.Name)
			fmt.Fprintf(md, "     **Description:** %v\n", curr.CABundleInfo.Description)
		}
		fmt.Fprintln(md, "")
	}

	allOwners := sets.StringKeySet(certsByOwner)
	allOwners.Insert(sets.StringKeySet(caBundlesByOwner).UnsortedList()...)

	fmt.Fprintln(md, "## Known Owners")
	for _, owner := range allOwners.List() {
		fmt.Fprintf(md, "## %v\n", owner)
		certs := certsByOwner[owner]
		if len(certs) > 0 {
			fmt.Fprintln(md, "### Certificates")
			for i, curr := range certs {
				fmt.Fprintf(md, "%d. ns/%v secret/%v\n\n", i+1, curr.SecretLocation.Namespace, curr.SecretLocation.Name)
				fmt.Fprintf(md, "     **Description:** %v\n", curr.CertKeyInfo.Description)
			}
			fmt.Fprintln(md, "")
		}

		caBundles := caBundlesByOwner[owner]
		if len(caBundles) > 0 {
			fmt.Fprintln(md, "### Certificate Authority Bundles")
			for i, curr := range caBundles {
				fmt.Fprintf(md, "%d. ns/%v configmap/%v\n\n", i+1, curr.ConfigMapLocation.Namespace, curr.ConfigMapLocation.Name)
				fmt.Fprintf(md, "     **Description:** %v\n", curr.CABundleInfo.Description)
			}
			fmt.Fprintln(md, "")
		}
	}

	return md.Bytes(), nil
}

func diffCertKeyPairOwners(actual, expected certgraphapi.PKIRegistryCertKeyPairInfo) error {
	if actual.OwningJiraComponent != expected.OwningJiraComponent {
		return fmt.Errorf("expected JIRA component to be %s, but was %s", expected.OwningJiraComponent, actual.OwningJiraComponent)
	}
	return nil
}

func diffCABundleOwners(actual, expected certgraphapi.PKIRegistryCertificateAuthorityInfo) error {
	if actual.OwningJiraComponent != expected.OwningJiraComponent {
		return fmt.Errorf("expected JIRA component to be %s, but was %s", expected.OwningJiraComponent, actual.OwningJiraComponent)
	}
	return nil
}
