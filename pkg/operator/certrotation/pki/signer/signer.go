package signer

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/operator/certrotation"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourcehelper"
	"github.com/openshift/library-go/pkg/pki"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1informers "k8s.io/client-go/informers/core/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog/v2"
	"k8s.io/utils/clock"
)

const (
	certsSecretKey = "tls.crt"
	keySecretKey   = "tls.key"
)

// SigningCASecretRotator implements the SigningCertKeyPairSecretRotator interface
// and handles rotation of signing certificates and keys based on the PKI API.
// Rotation of certificate and key material happens when:
// - desired algorithm is changed via the PKI API
// - desired refresh duration is reached
// - CA is expired
type SigningCASecretRotator struct {
	// namespace is the namespace of the Secret.
	namespace string
	// name is the name of the Secret.
	name string

	// validity is the lifetime for which the signing CA is valid.
	// validity is optional, and when not set a default validity duration is used.
	validity *time.Duration

	// refresh is the duration after signing CA creation when it is rotated at the latest.
	// refresh is optional, and when not specified is set to 80% of validity.
	// When refresh is > validity, rotation does not happen until the CA has expired.
	refresh *time.Duration

	// owner is an optional reference to add to the secret that this rotator creates. Use this when downstream
	// consumers of the signer CA need to be aware of changes to the object.
	// WARNING: be careful when using this option, as deletion of the owning object will cascade into deletion
	// of the signer. If the lifetime of the owning object is not a superset of the lifetime in which the signer
	// is used, early deletion will be catastrophic.
	owner *metav1.OwnerReference

	// additionalAnnotations is a collection of annotations set for the secret.
	// additionalAnnotations is optional.
	additionalAnnotations certrotation.AdditionalAnnotations

	// certificateName is the logical name of this certificate for PKI profile resolution.
	// certificateName is required.
	certificateName string

	// pkiProfileProvider enables ConfigurablePKI certificate key algorithm resolution.
	// It is required.
	pkiProfileProvider pki.PKIProfileProvider

	// Plumbing:
	informer      corev1informers.SecretInformer // required
	lister        corev1listers.SecretLister     // optional, inherited from informer if not provided
	client        corev1client.SecretsGetter     // required
	eventRecorder events.Recorder                // required

	clock clock.PassiveClock
}

type SigningCASecretRotatorOption func(*SigningCASecretRotator)

func WithLister(lister corev1listers.SecretLister) SigningCASecretRotatorOption {
	return func(pcr *SigningCASecretRotator) {
		pcr.lister = lister
	}
}

func WithValidity(validity time.Duration) SigningCASecretRotatorOption {
	return func(pcr *SigningCASecretRotator) {
		if validity <= 0 {
			return
		}

		pcr.validity = &validity
	}
}

func WithRefresh(refresh time.Duration) SigningCASecretRotatorOption {
	return func(pcr *SigningCASecretRotator) {
		if refresh <= 0 {
			return
		}

		pcr.refresh = &refresh
	}
}

func WithAdditionalAnnotations(annotations certrotation.AdditionalAnnotations) SigningCASecretRotatorOption {
	return func(pcr *SigningCASecretRotator) {
		pcr.additionalAnnotations = annotations
	}
}

func WithOwner(owner metav1.OwnerReference) SigningCASecretRotatorOption {
	return func(pcr *SigningCASecretRotator) {
		pcr.owner = &owner
	}
}

func NewSigningCASecretRotator(namespace string, name string, certificateName string, pkiProfileProvider pki.PKIProfileProvider, client corev1client.SecretsGetter, informer corev1informers.SecretInformer, options ...SigningCASecretRotatorOption) *SigningCASecretRotator {
	defaultValidity := crypto.DefaultCACertificateLifetimeDuration
	rotator := &SigningCASecretRotator{
		namespace:          namespace,
		name:               name,
		certificateName:    certificateName,
		pkiProfileProvider: pkiProfileProvider,
		client:             client,
		informer:           informer,
		lister:             informer.Lister(),
		validity:           &defaultValidity,
	}

	for _, option := range options {
		option(rotator)
	}

	if rotator.refresh == nil {
		defaultRefresh := (*rotator.validity * time.Duration(80)) / 100
		rotator.refresh = &defaultRefresh
	}

	return rotator
}

func (c *SigningCASecretRotator) NamespaceName() string {
	return fmt.Sprintf("%s/%s", c.namespace, c.name)
}

// EnsureSigningCertKeyPair manages the entire lifecycle of a signer cert as a secret, from creation to continued rotation.
// It always returns the currently used CA pair, a bool indicating whether it was created/updated within this function call and an error.
func (c *SigningCASecretRotator) EnsureSigningCertKeyPair(ctx context.Context) (*crypto.CA, bool, error) {
	creationRequired := false

	originalSigningCertKeyPairSecret, err := c.lister.Secrets(c.namespace).Get(c.name)
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, false, err
	}

	signingCertKeyPairSecret := originalSigningCertKeyPairSecret.DeepCopy()
	if apierrors.IsNotFound(err) {
		// create an empty one
		signingCertKeyPairSecret = &corev1.Secret{
			ObjectMeta: certrotation.NewTLSArtifactObjectMeta(
				c.name,
				c.namespace,
				c.additionalAnnotations,
			),
			Type: corev1.SecretTypeTLS,
		}
		creationRequired = true
	}

	if creationRequired {
		c.eventRecorder.Eventf("SignerUpdateRequired", "%q in %q requires a new signing cert/key pair because it does not exist.", c.name, c.namespace)

		ca, err := c.createSecret(ctx, signingCertKeyPairSecret)
		if err != nil {
			return nil, false, err
		}

		return ca, true, nil
	}

	return c.updateSecret(ctx, signingCertKeyPairSecret)
}

func (c *SigningCASecretRotator) createSecret(ctx context.Context, secret *corev1.Secret) (*crypto.CA, error) {
	certrotation.EnsureOwnerRefAndTLSAnnotations(secret, c.owner, c.additionalAnnotations)
	certrotation.EnsureSecretTLSTypeSet(secret)

	err := buildSecret(secret, c.certificateName, c.pkiProfileProvider, *c.validity, c.clock)
	if err != nil {
		return nil, fmt.Errorf("building secret: %w", err)
	}

	actual, err := c.client.Secrets(c.namespace).Create(ctx, secret, metav1.CreateOptions{})
	resourcehelper.ReportCreateEvent(c.eventRecorder, actual, err)
	if err != nil {
		return nil, fmt.Errorf("creating secret: %w", err)
	}

	klog.V(2).Infof("Created secret %s/%s", actual.Namespace, actual.Name)
	return crypto.GetCAFromBytes(actual.Data[certsSecretKey], actual.Data[keySecretKey])
}

func (c *SigningCASecretRotator) updateSecret(ctx context.Context, secret *corev1.Secret) (*crypto.CA, bool, error) {
	metadataUpdateRequired := certrotation.EnsureOwnerRefAndTLSAnnotations(secret, c.owner, c.additionalAnnotations) || certrotation.EnsureSecretTLSTypeSet(secret)

	signerUpdateRequired, reason, err := checkIfSignerUpdateRequired(secret, *c.refresh, c.clock)
	if err != nil {
		return nil, false, fmt.Errorf("checking if signing certificate needs updates: %w", err)
	}

	if signerUpdateRequired {
		c.eventRecorder.Eventf("SignerUpdateRequired", "%q in %q requires a new signing cert/key pair: %v", c.name, c.namespace, reason)

		err := buildSecret(secret, c.certificateName, c.pkiProfileProvider, *c.validity, c.clock)
		if err != nil {
			return nil, false, fmt.Errorf("building secret: %w", err)
		}
	}

	// No updates are needed to the secret
	if !signerUpdateRequired && !metadataUpdateRequired {
		ca, err := crypto.GetCAFromBytes(secret.Data[certsSecretKey], secret.Data[keySecretKey])
		if err != nil {
			return nil, true, fmt.Errorf("loading CA data for existing secret contents: %w", err)
		}

		return ca, false, nil
	}

	actual, err := c.client.Secrets(c.namespace).Update(ctx, secret, metav1.UpdateOptions{})
	resourcehelper.ReportUpdateEvent(c.eventRecorder, actual, err)
	if err != nil {
		return nil, false, fmt.Errorf("updating secret: %w", err)
	}

	klog.V(2).Infof("Updated secret %s/%s", actual.Namespace, actual.Name)

	ca, err := crypto.GetCAFromBytes(actual.Data[certsSecretKey], actual.Data[keySecretKey])
	if err != nil {
		return nil, true, fmt.Errorf("loading CA data for updated secret contents: %w", err)
	}

	return ca, signerUpdateRequired, nil
}

func buildSecret(secret *corev1.Secret, certificateName string, pkiProvider pki.PKIProfileProvider, lifetime time.Duration, clk clock.PassiveClock) error {
	tlsCertificateConfig, err := createSigningTLSCertificateConfig(certificateName, pkiProvider, lifetime, clk)
	if err != nil {
		return fmt.Errorf("creating signing certificate: %w", err)
	}

	certBytes := &bytes.Buffer{}
	keyBytes := &bytes.Buffer{}
	if err = tlsCertificateConfig.WriteCertConfig(certBytes, keyBytes); err != nil {
		return fmt.Errorf("writing certificate and key bytes: %w", err)
	}

	secret.Data[certsSecretKey] = certBytes.Bytes()
	secret.Data[keySecretKey] = keyBytes.Bytes()

	certrotation.LabelAsManagedSecret(secret, certrotation.CertificateTypeSigner)
	return nil
}

func checkIfSignerUpdateRequired(secret *corev1.Secret, refresh time.Duration, clk clock.PassiveClock) (bool, string, error) {
	certBytes, hasCertContent := secret.Data[certsSecretKey]
	keyBytes, hasKeyContent := secret.Data[keySecretKey]

	if !hasCertContent || !hasKeyContent {
		return true, "missing contents", nil
	}

	ca, err := crypto.GetCAFromBytes(certBytes, keyBytes)
	if err != nil {
		return false, "", fmt.Errorf("loading CA data: %w", err)
	}

	signerRoot := ca.Config.Certs[0]

	if clk.Now().After(signerRoot.NotAfter) {
		return true, "expired", nil
	}

	refreshTime := signerRoot.NotBefore.Add(refresh)
	if clk.Now().After(refreshTime) {
		return true, fmt.Sprintf("past refresh time %v", refreshTime), nil
	}

	return false, "", nil
}

// createSigningTLSCertificateConfig creates a self-signed signing certificate chain that can be used for issuing
// new certificates.
// It accepts a certificate name, a PKI provider, certificate lifetime, and a clock for determining the current time.
func createSigningTLSCertificateConfig(name string, pkiProvider pki.PKIProfileProvider, lifetime time.Duration, clk clock.PassiveClock) (*crypto.TLSCertificateConfig, error) {
	cfg, err := pki.ResolveCertificateConfig(pkiProvider, pki.CertificateTypeSigner, name)
	if err != nil {
		return nil, fmt.Errorf("resolving certificate configuration: %w", err)
	}

	now := clk.Now()

	signerName := generateSignerName(name, "TODO", now)

	baseline, err := crypto.NewSigningCertificate(signerName, cfg.Key, crypto.WithLifetime(lifetime), crypto.WithNowFunc(func() time.Time { return now }))
	if err != nil {
		return nil, fmt.Errorf("generating self-signed signing certificate: %w", err)
	}

	return baseline, nil
}

// generateSignerName generates a signer name based on the certificate name, the key algorithm,
// and the current unix time. Due to the nature of using time.Time.Unix() that uses second precision,
// there is a potential, but highly unlikely, race condition where a rotation that has happened within the
// span of one second from the time a certificate was issued will end up using the exact same signer name.
// The inclusion of the key algorithm prevents this race condition for rotations related to algorithm
// changes.
func generateSignerName(name string, algorithm string, now time.Time) string {
	return fmt.Sprintf("%s_%s@%d", name, algorithm, now.Unix())
}
