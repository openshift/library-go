package metadata

import (
	"bytes"
	"fmt"

	"github.com/openshift/library-go/pkg/certs/cert-inspection/certgraphapi"
)

func newDescriptionViolation(name string, pkiInfo *certgraphapi.PKIRegistryInfo) (Violation, error) {
	registry := &certgraphapi.PKIRegistryInfo{}

	for i := range pkiInfo.CertKeyPairs {
		curr := pkiInfo.CertKeyPairs[i]
		description := curr.CertKeyInfo.Description
		if len(description) == 0 {
			registry.CertKeyPairs = append(registry.CertKeyPairs, curr)
		}
	}
	for i := range pkiInfo.CertificateAuthorityBundles {
		curr := pkiInfo.CertificateAuthorityBundles[i]
		description := curr.CABundleInfo.Description
		if len(description) == 0 {
			registry.CertificateAuthorityBundles = append(registry.CertificateAuthorityBundles, curr)
		}
	}

	v := Violation{
		Name:     fmt.Sprintf("%s-violations", name),
		Registry: registry,
	}

	markdown, err := generateMarkdownNoDescription(registry)
	if err != nil {
		return v, err
	}
	v.Markdown = markdown

	return v, nil
}

func generateMarkdownNoDescription(pkiInfo *certgraphapi.PKIRegistryInfo) ([]byte, error) {
	certsWithoutDescription := map[string]certgraphapi.PKIRegistryInClusterCertKeyPair{}
	caBundlesWithoutDescription := map[string]certgraphapi.PKIRegistryInClusterCABundle{}

	for i := range pkiInfo.CertKeyPairs {
		curr := pkiInfo.CertKeyPairs[i]
		owner := curr.CertKeyInfo.OwningJiraComponent
		description := curr.CertKeyInfo.Description
		if len(description) == 0 && len(owner) != 0 {
			certsWithoutDescription[owner] = curr
			continue
		}
	}
	for i := range pkiInfo.CertificateAuthorityBundles {
		curr := pkiInfo.CertificateAuthorityBundles[i]
		owner := curr.CABundleInfo.OwningJiraComponent
		description := curr.CABundleInfo.Description
		if len(description) == 0 && len(owner) != 0 {
			caBundlesWithoutDescription[owner] = curr
			continue
		}
	}

	md := &bytes.Buffer{}

	fmt.Fprintln(md, "## Missing descriptions")
	if len(certsWithoutDescription) > 0 {
		fmt.Fprintln(md, "### Certificates")
		for owner, curr := range certsWithoutDescription {
			fmt.Fprintf(md, "1. ns/%v secret/%v\n\n", curr.SecretLocation.Namespace, curr.SecretLocation.Name)
			fmt.Fprintf(md, "     **JIRA component:** %v\n", owner)
		}
		fmt.Fprintln(md, "")
	}
	if len(caBundlesWithoutDescription) > 0 {
		fmt.Fprintln(md, "### Certificate Authority Bundles")
		for owner, curr := range caBundlesWithoutDescription {
			fmt.Fprintf(md, "1. ns/%v configmap/%v\n\n", curr.ConfigMapLocation.Namespace, curr.ConfigMapLocation.Name)
			fmt.Fprintf(md, "     **JIRA component:** %v\n", owner)
		}
		fmt.Fprintln(md, "")
	}

	return md.Bytes(), nil
}

func diffCertKeyPairDescription(actual, expected certgraphapi.PKIRegistryCertKeyPairInfo) error {
	if actual.Description != expected.Description {
		return fmt.Errorf("expected description to be %s, but was %s", expected.Description, actual.Description)
	}
	return nil
}

func diffCABundleDescription(actual, expected certgraphapi.PKIRegistryCertificateAuthorityInfo) error {
	if actual.OwningJiraComponent != expected.OwningJiraComponent {
		return fmt.Errorf("expected description to be %s, but was %s", expected.Description, actual.Description)
	}
	return nil
}
