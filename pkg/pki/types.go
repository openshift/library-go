package pki

// CertificateType identifies the category of a certificate for configuration
// resolution. Values follow the vocabulary of the PKI API's certificates
// section.
type CertificateType string

const (
	// CertificateTypeCA identifies certificate authority (CA) certificates
	// that sign other certificates.
	CertificateTypeCA CertificateType = "ca"

	// CertificateTypeServer identifies TLS server certificates used to serve
	// HTTPS endpoints.
	CertificateTypeServer CertificateType = "server"

	// CertificateTypeClient identifies client authentication certificates
	// used to authenticate to servers.
	CertificateTypeClient CertificateType = "client"

	// CertificateTypePeer identifies certificates used for both server and
	// client authentication. When no named override matches the certificate's
	// name, the resolved key configuration is the stronger of the server and
	// client configurations.
	CertificateTypePeer CertificateType = "peer"
)
