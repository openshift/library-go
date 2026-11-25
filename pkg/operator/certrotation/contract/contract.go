// Package contract defines the on-cluster contract of TLS artifacts managed
// by certificate rotation: annotation keys and their value formats, label
// keys and values, and data keys.
//
// The contract is a de-facto public API shared with external readers and
// writers: the oc CLI (`oc adm certificates`), origin TLS artifact tests,
// support diagnostics, and consumer operators such as CKAO and
// cluster-etcd-operator. Every key and value in this package is byte-stable;
// changing one is a cross-repo API change and requires a migration plan, not
// an edit.
//
// Rotation code treats the annotations defined here as write-only output for
// those external readers. Rotation decisions derive from the parsed resource
// contents, with one exception: ForceRegeneration, which is an inbound command
// that cannot be derived from contents.
package contract

const (
	// CertificateNotBeforeAnnotation contains the certificate creation date
	// in RFC3339 format.
	CertificateNotBeforeAnnotation = "auth.openshift.io/certificate-not-before"

	// CertificateNotAfterAnnotation contains the certificate expiration date
	// in RFC3339 format, with one exception: the ForceRegeneration sentinel
	// value may be written by `oc adm certificates` commands to request
	// regeneration of the artifact.
	CertificateNotAfterAnnotation = "auth.openshift.io/certificate-not-after"

	// CertificateIssuer contains the common name of the certificate that
	// signed the annotated certificate. For a self-signed root signer it is
	// the signer's own common name.
	CertificateIssuer = "auth.openshift.io/certificate-issuer"

	// CertificateHostnames contains the sorted, comma-joined set of
	// hostnames (DNS names and IP addresses) a serving or peer certificate
	// is valid for.
	CertificateHostnames = "auth.openshift.io/certificate-hostnames"

	// CertificateTestNameAnnotation is an e2e test name which verifies that
	// the TLS artifact is created and used correctly.
	CertificateTestNameAnnotation = "certificates.openshift.io/test-name"

	// CertificateAutoRegenerateAfterOfflineExpiryAnnotation contains a link
	// to the PR adding this annotation, which verifies that the TLS artifact
	// is correctly regenerated after it has expired.
	CertificateAutoRegenerateAfterOfflineExpiryAnnotation = "certificates.openshift.io/auto-regenerate-after-offline-expiry"

	// CertificateRefreshPeriodAnnotation is the interval at which the
	// certificate should be refreshed, in Go duration string format.
	CertificateRefreshPeriodAnnotation = "certificates.openshift.io/refresh-period"

	// ForceRegeneration is the sentinel value written into
	// CertificateNotAfterAnnotation to request that the annotated artifact be
	// regenerated regardless of its parsed contents. It is written by
	// `oc adm certificates` commands via server-side apply, so it must be
	// treated as an inbound command by any rotation logic reading the
	// annotation.
	ForceRegeneration = "force-regeneration"
)

const (
	// ManagedCertificateTypeLabelName marks a config map or secret as an
	// object that contains managed certificates. This groups all objects
	// that store certs and allows an easy query to fetch them all. The value
	// is one of the CertificateType constants below.
	ManagedCertificateTypeLabelName = "auth.openshift.io/managed-certificate-type"
)

// CertificateType values for ManagedCertificateTypeLabelName. They encode
// which slot an object fills (signer, trust bundle, or target), not the
// cryptographic purpose of the certificate inside it.
const (
	// CertificateTypeCABundle marks a config map holding a CA trust bundle.
	CertificateTypeCABundle = "ca-bundle"
	// CertificateTypeSigner marks a secret holding a signing CA.
	CertificateTypeSigner = "signer"
	// CertificateTypeTarget marks a secret holding a certificate signed by a
	// signing CA. This includes intermediate signer certificates.
	CertificateTypeTarget = "target"
	// CertificateTypeUnknown is the value reported for an object that carries
	// the managed-certificate-type label with an unrecognized value.
	CertificateTypeUnknown = "unknown"
)

// Data keys for the artifact payload.
const (
	// SecretCertKey is the data key holding the PEM-encoded certificate
	// chain of a TLS secret.
	SecretCertKey = "tls.crt"
	// SecretKeyKey is the data key holding the PEM-encoded private key of a
	// TLS secret.
	SecretKeyKey = "tls.key"
	// CABundleConfigMapKey is the data key holding the PEM-encoded CA trust
	// bundle of a config map.
	CABundleConfigMapKey = "ca-bundle.crt"
)
