package library

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math"
	"math/big"
	"testing"
	"time"
)

type CryptoMaterials struct {
	PrivateKey  *rsa.PrivateKey
	Certificate *x509.Certificate
}

// NewServerCertificate returns crypto materials suitable for use by a server. The hosts specified will be added as
// subject alternate names.
func NewServerCertificate(t *testing.T, signerCert *x509.Certificate, hosts ...string) *CryptoMaterials {
	var err error
	server := &CryptoMaterials{}
	if server.PrivateKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		panic(err)
	}
	var serialNumber *big.Int
	if serialNumber, err = rand.Int(rand.Reader, big.NewInt(math.MaxInt64)); err != nil {
		panic(err)
	}
	template := &x509.Certificate{
		Subject:               pkix.Name{CommonName: fmt.Sprintf("%vServer_%v", t.Name(), serialNumber)},
		NotBefore:             time.Now().AddDate(-1, 0, 0),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		SignatureAlgorithm:    x509.SHA256WithRSA,
		SerialNumber:          serialNumber,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              hosts,
	}
	var certs []byte
	if certs, err = x509.CreateCertificate(rand.Reader, template, signerCert, server.PrivateKey.Public(), server.PrivateKey); err != nil {
		panic(err)
	}
	if server.Certificate, err = x509.ParseCertificate(certs); err != nil {
		panic(err)
	}
	return server
}

// NewCertificateAuthorityCertificate returns crypto materials for a certificate authority. If no parent certificate
// is specified, the generated certificate will be self-signed.
func NewCertificateAuthorityCertificate(t *testing.T, parent *x509.Certificate) *CryptoMaterials {
	result := &CryptoMaterials{}
	var err error
	if result.PrivateKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		panic(err)
	}
	var serialNumber *big.Int
	if serialNumber, err = rand.Int(rand.Reader, big.NewInt(math.MaxInt64)); err != nil {
		panic(err)
	}
	var subject string
	if parent == nil {
		subject = fmt.Sprintf("%vRootCA_%v", t.Name(), serialNumber)
	} else {
		subject = fmt.Sprintf("%vIntermediateCA_%v", t.Name(), serialNumber)
	}
	template := &x509.Certificate{
		Subject:               pkix.Name{CommonName: subject},
		NotBefore:             time.Now().AddDate(-1, 0, 0),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		SignatureAlgorithm:    x509.SHA256WithRSA,
		SerialNumber:          serialNumber,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	if parent == nil {
		parent = template
	}
	var der []byte
	if der, err = x509.CreateCertificate(rand.Reader, template, parent, result.PrivateKey.Public(), result.PrivateKey); err != nil {
		panic(err)
	}
	if result.Certificate, err = x509.ParseCertificate(der); err != nil {
		panic(err)
	}
	return result
}
