package certrotation

import (
	"fmt"

	"k8s.io/apiserver/pkg/authentication/user"

	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/pki"
)

// TargetCert describes what kind of certificate to issue for a Target. It is
// a sealed union: only the types in this package implement it, so the set of
// certificate kinds is fixed and exhaustively switchable.
type TargetCert interface {
	// certificateType reports the cryptographic purpose of the certificate,
	// in the pkg/pki vocabulary used for PKI configuration resolution.
	certificateType() pki.CertificateType

	// validate checks required fields at construction time.
	validate() error

	// sealed prevents implementations outside this package.
	sealed()
}

// ClientCert issues a client-authentication certificate authenticating User
// (for example system:openshift-aggregator).
type ClientCert struct {
	// User is the identity the certificate authenticates. Required.
	User user.Info
}

func (ClientCert) certificateType() pki.CertificateType { return pki.CertificateTypeClient }
func (ClientCert) sealed()                              {}

func (c ClientCert) validate() error {
	if c.User == nil {
		return fmt.Errorf("ClientCert: User is required")
	}
	if c.User.GetName() == "" {
		return fmt.Errorf("ClientCert: User name is required")
	}
	return nil
}

// ServingCert issues a TLS server certificate valid for Hostnames.
type ServingCert struct {
	// Hostnames supplies the DNS names and IP addresses the certificate is
	// valid for. Required; the source may be dynamic.
	Hostnames HostnameSource

	// Extensions, if set, adds certificate extensions to the issued
	// certificate.
	Extensions []crypto.CertificateExtensionFunc
}

func (ServingCert) certificateType() pki.CertificateType { return pki.CertificateTypeServer }
func (ServingCert) sealed()                              {}

func (s ServingCert) validate() error {
	if s.Hostnames == nil {
		return fmt.Errorf("ServingCert: Hostnames is required")
	}
	return nil
}

// PeerCert issues a certificate used for both server and client
// authentication, as etcd peer certificates are.
type PeerCert struct {
	// Hostnames supplies the DNS names and IP addresses the certificate is
	// valid for. Required.
	Hostnames HostnameSource

	// User is the identity the certificate authenticates when acting as a
	// client. Required.
	User user.Info

	// Extensions, if set, adds certificate extensions to the issued
	// certificate.
	Extensions []crypto.CertificateExtensionFunc
}

func (PeerCert) certificateType() pki.CertificateType { return pki.CertificateTypePeer }
func (PeerCert) sealed()                              {}

func (p PeerCert) validate() error {
	if p.Hostnames == nil {
		return fmt.Errorf("PeerCert: Hostnames is required")
	}
	if p.User == nil {
		return fmt.Errorf("PeerCert: User is required")
	}
	if p.User.GetName() == "" {
		return fmt.Errorf("PeerCert: User name is required")
	}
	return nil
}

// IntermediateSignerCert issues an intermediate CA signed by the Rotation's
// signer, as KCMO's csr-signer is signed by the csr-signer-signer. The
// subject CN format "<SignerName>_@<unix>" is preserved from v1's
// SignerRotation.
type IntermediateSignerCert struct {
	// SignerName is the name embedded in the subject common name. Required.
	SignerName string
}

func (IntermediateSignerCert) certificateType() pki.CertificateType { return pki.CertificateTypeCA }
func (IntermediateSignerCert) sealed()                              {}

func (i IntermediateSignerCert) validate() error {
	if i.SignerName == "" {
		return fmt.Errorf("IntermediateSignerCert: SignerName is required")
	}
	return nil
}
