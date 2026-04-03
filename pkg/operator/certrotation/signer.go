package certrotation

import (
	"bytes"
	"fmt"
	"time"

	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/pki"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"
)

// SigningCAConfig holds the configuration for a self-signed signing CA stored in a secret. It creates a new one when
// - refresh duration is over
// - or 80% of validity is over (if RefreshOnlyWhenExpired is false)
// - or the CA is expired.
type SigningCAConfig struct {
	// Namespace is the namespace of the Secret.
	Namespace string
	// Name is the name of the Secret.
	Name string
	// CertificateName is the logical name of this certificate for PKI profile resolution.
	// When a PKI profile provider is configured on the controller, this name is used to
	// look up the key algorithm and other certificate parameters from the cluster PKI profile.
	CertificateName string
	// Validity is the duration from time.Now() until the signing CA expires. If RefreshOnlyWhenExpired
	// is false, the signing cert is rotated when 80% of validity is reached.
	Validity time.Duration
	// Refresh is the duration after signing CA creation when it is rotated at the latest. It is ignored
	// if RefreshOnlyWhenExpired is true, or if Refresh > Validity.
	Refresh time.Duration
	// RefreshOnlyWhenExpired set to true means to ignore 80% of validity and the Refresh duration for rotation,
	// but only rotate when the signing CA expires. This is useful for auto-recovery when we want to enforce
	// rotation on expiration only, but not interfere with the ordinary rotation controller.
	RefreshOnlyWhenExpired bool

	// Owner is an optional reference to add to the secret that this rotator creates. Use this when downstream
	// consumers of the signer CA need to be aware of changes to the object.
	// WARNING: be careful when using this option, as deletion of the owning object will cascade into deletion
	// of the signer. If the lifetime of the owning object is not a superset of the lifetime in which the signer
	// is used, early deletion will be catastrophic.
	Owner *metav1.OwnerReference

	// AdditionalAnnotations is a collection of annotations set for the secret
	AdditionalAnnotations AdditionalAnnotations
}

// ensureOwnerReference adds the owner to the list of owner references in meta, if necessary
func ensureOwnerReference(meta *metav1.ObjectMeta, owner *metav1.OwnerReference) bool {
	var found bool
	for _, ref := range meta.OwnerReferences {
		if ref == *owner {
			found = true
			break
		}
	}
	if !found {
		meta.OwnerReferences = append(meta.OwnerReferences, *owner)
		return true
	}
	return false
}

func needNewSigningCertKeyPair(secret *corev1.Secret, refresh time.Duration, refreshOnlyWhenExpired bool) (bool, string) {
	annotations := secret.Annotations
	notBefore, notAfter, reason := getValidityFromAnnotations(annotations)
	if len(reason) > 0 {
		return true, reason
	}

	if time.Now().After(notAfter) {
		return true, "already expired"
	}

	if refreshOnlyWhenExpired {
		return false, ""
	}

	validity := notAfter.Sub(notBefore)
	at80Percent := notAfter.Add(-validity / 5)
	if time.Now().After(at80Percent) {
		return true, fmt.Sprintf("past refresh time (80%% of validity): %v", at80Percent)
	}

	developerSpecifiedRefresh := notBefore.Add(refresh)
	if time.Now().After(developerSpecifiedRefresh) {
		return true, fmt.Sprintf("past its refresh time %v", developerSpecifiedRefresh)
	}

	return false, ""
}

func getValidityFromAnnotations(annotations map[string]string) (notBefore time.Time, notAfter time.Time, reason string) {
	notAfterString := annotations[CertificateNotAfterAnnotation]
	if len(notAfterString) == 0 {
		return notBefore, notAfter, "missing notAfter"
	}
	notAfter, err := time.Parse(time.RFC3339, notAfterString)
	if err != nil {
		return notBefore, notAfter, fmt.Sprintf("bad expiry: %q", notAfterString)
	}
	notBeforeString := annotations[CertificateNotBeforeAnnotation]
	if len(notBeforeString) == 0 {
		return notBefore, notAfter, "missing notBefore"
	}
	notBefore, err = time.Parse(time.RFC3339, notBeforeString)
	if err != nil {
		return notBefore, notAfter, fmt.Sprintf("bad expiry: %q", notBeforeString)
	}

	return notBefore, notAfter, ""
}

// setSigningCertKeyPairSecret creates a new signing cert/key pair and sets them in the secret
func setSigningCertKeyPairSecret(signingCertKeyPairSecret *corev1.Secret, validity time.Duration) (*crypto.TLSCertificateConfig, error) {
	signerName := fmt.Sprintf("%s_%s@%d", signingCertKeyPairSecret.Namespace, signingCertKeyPairSecret.Name, time.Now().Unix())
	ca, err := crypto.MakeSelfSignedCAConfigForDuration(signerName, validity)
	if err != nil {
		return nil, err
	}

	certBytes := &bytes.Buffer{}
	keyBytes := &bytes.Buffer{}
	if err = ca.WriteCertConfig(certBytes, keyBytes); err != nil {
		return nil, err
	}

	if signingCertKeyPairSecret.Annotations == nil {
		signingCertKeyPairSecret.Annotations = map[string]string{}
	}
	if signingCertKeyPairSecret.Data == nil {
		signingCertKeyPairSecret.Data = map[string][]byte{}
	}
	signingCertKeyPairSecret.Data["tls.crt"] = certBytes.Bytes()
	signingCertKeyPairSecret.Data["tls.key"] = keyBytes.Bytes()
	return ca, nil
}

// setTLSAnnotationsOnSigningCertKeyPairSecret applies predefined TLS annotations to the given secret.
//
// This function does not perform nil checks on its parameters and assumes that the
// secret's Annotations field has already been initialized.
//
// These assumptions are safe because this function is only called after the secret
// has been initialized in setSigningCertKeyPairSecret.
func setTLSAnnotationsOnSigningCertKeyPairSecret(signingCertKeyPairSecret *corev1.Secret, ca *crypto.TLSCertificateConfig, refresh time.Duration, tlsAnnotations AdditionalAnnotations) {
	signingCertKeyPairSecret.Annotations[CertificateIssuer] = ca.Certs[0].Issuer.CommonName

	tlsAnnotations.NotBefore = ca.Certs[0].NotBefore.Format(time.RFC3339)
	tlsAnnotations.NotAfter = ca.Certs[0].NotAfter.Format(time.RFC3339)
	tlsAnnotations.RefreshPeriod = refresh.String()
	_ = tlsAnnotations.EnsureTLSMetadataUpdate(&signingCertKeyPairSecret.ObjectMeta)
}

// resolveKeyPairGenerator resolves the key pair generator from the PKI profile
// provider. Returns an error if the profile has no configuration for the given
// certificate type and name.
//
// TODO: Remove the fallback to DefaultPKIProfile() once installer support for
// the PKI resource is in place. Until then, the PKI resource may not exist in
// TechPreview clusters.
func resolveKeyPairGenerator(provider pki.PKIProfileProvider, certType pki.CertificateType, name string) (crypto.KeyPairGenerator, error) {
	cfg, err := pki.ResolveCertificateConfig(provider, certType, name)
	if err != nil {
		klog.Warningf("Failed to resolve PKI config for %s %q, falling back to default profile: %v", certType, name, err)
		defaultProfile := pki.DefaultPKIProfile()
		cfg, err = pki.ResolveCertificateConfig(pki.NewStaticPKIProfileProvider(&defaultProfile), certType, name)
		if err != nil {
			return nil, err
		}
	}
	if cfg == nil {
		return nil, fmt.Errorf("PKI profile has no configuration for %s %q", certType, name)
	}
	return cfg.Key, nil
}
