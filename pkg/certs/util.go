package certs

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"k8s.io/client-go/util/keyutil"
)

const defaultOutputTimeFormat = "Jan 2 15:04:05 2006"

// nowFn is used in unit test to freeze time.
var nowFn = time.Now().UTC

// CertificateToString converts a certificate into a human readable string.
// This function should guarantee consistent output format for must-gather tooling and any code
// that prints the certificate details.
func CertificateToString(certificate *x509.Certificate) string {
	humanName := certificate.Subject.CommonName
	signerHumanName := certificate.Issuer.CommonName

	if certificate.Subject.CommonName == certificate.Issuer.CommonName {
		signerHumanName = "<self-signed>"
	}

	usages := []string{}
	for _, curr := range certificate.ExtKeyUsage {
		if curr == x509.ExtKeyUsageClientAuth {
			usages = append(usages, "client")
			continue
		}
		if curr == x509.ExtKeyUsageServerAuth {
			usages = append(usages, "serving")
			continue
		}

		usages = append(usages, fmt.Sprintf("%d", curr))
	}

	validServingNames := []string{}
	for _, ip := range certificate.IPAddresses {
		validServingNames = append(validServingNames, ip.String())
	}
	for _, dnsName := range certificate.DNSNames {
		validServingNames = append(validServingNames, dnsName)
	}

	servingString := ""
	if len(validServingNames) > 0 {
		servingString = fmt.Sprintf(" validServingFor=[%s]", strings.Join(validServingNames, ","))
	}

	groupString := ""
	if len(certificate.Subject.Organization) > 0 {
		groupString = fmt.Sprintf(" groups=[%s]", strings.Join(certificate.Subject.Organization, ","))
	}

	return fmt.Sprintf("%q [%s]%s%s issuer=%q (%v to %v (now=%v))", humanName, strings.Join(usages, ","), groupString,
		servingString, signerHumanName, certificate.NotBefore.UTC().Format(defaultOutputTimeFormat),
		certificate.NotAfter.UTC().Format(defaultOutputTimeFormat), nowFn().Format(defaultOutputTimeFormat))
}

// CertificateBundleToString converts a certificate bundle into a human readable string.
func CertificateBundleToString(bundle []*x509.Certificate) string {
	output := []string{}
	for i, cert := range bundle {
		output = append(output, fmt.Sprintf("[#%d]: %s", i, CertificateToString(cert)))
	}
	return strings.Join(output, "\n")
}

func ValidatePrivateKey(pemKey []byte) []error {
	if len(pemKey) == 0 {
		return []error{fmt.Errorf("required private key is empty")}
	}
	if _, err := keyutil.ParsePrivateKeyPEM(pemKey); err != nil {
		return []error{fmt.Errorf("failed to parse the private key, %w", err)}
	}
	return []error{}
}

func ValidateServerCert(pem []byte) []error {
	certs, errs := parseCerts(pem)
	if len(errs) != 0 {
		return errs
	}
	if len(certs) == 0 {
		return []error{fmt.Errorf("expected at least one server certificate")}
	}
	return nil
}

func parseCerts(pemCerts []byte) ([]*x509.Certificate, []error) {
	certs := []*x509.Certificate{}

	if len(pemCerts) == 0 {
		return certs, []error{fmt.Errorf("required certificate is empty")}
	}

	errs := []error{}
	now := time.Now()

	cert, rest := pem.Decode(pemCerts)
	for ; cert != nil; cert, rest = pem.Decode(rest) {
		parsed, err := x509.ParseCertificate(cert.Bytes)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to parse a certificate in the chain: %w", err))
			continue
		}

		if now.Before(parsed.NotBefore) {
			errs = append(errs, fmt.Errorf("certificate not yet valid:\n\tsub=%s;\n\tiss=%s", parsed.Subject, parsed.Issuer))
			continue
		}

		if now.After(parsed.NotAfter) {
			errs = append(errs, fmt.Errorf("certificate expired:\n\tsub=%s;\n\tiss=%s", parsed.Subject, parsed.Issuer))
			continue
		}

		certs = append(certs, parsed)
	}

	return certs, errs
}
