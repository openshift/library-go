package target

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"
	"k8s.io/utils/clock"

	"github.com/openshift/library-go/pkg/certs"
	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/operator/certrotation"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourcehelper"
	corev1informers "k8s.io/client-go/informers/core/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
)

const (
	certsSecretKey = "tls.crt"
	keySecretKey   = "tls.key"
)

// TargetCertKeySecretRotator rotates a key and cert signed by a signing CA and stores it in a secret.
//
// It creates a new one when
// - refresh duration is over
// - or the cert is expired.
// - or the signing CA changes.
type TargetCertKeySecretRotator struct {
	// namespace is the namespace of the Secret.
	namespace string
	// name is the name of the Secret.
	name string

	// validity is the lifetime for which the certificate is valid.
	// validity is optional, and when not set a default validity duration is used.
	validity *time.Duration

	// refresh is the duration after signing CA creation when it is rotated at the latest.
	// refresh is optional, and when not specified is set to 80% of validity.
	// When refresh is > validity, rotation does not happen until the certificate has expired.
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

	// certCreator does the actual cert generation.
	// certCreator is required.
	certCreator TargetCertCreator

	// Plumbing:
	informer      corev1informers.SecretInformer // required
	lister        corev1listers.SecretLister     // optional, inherited from informer if not provided
	client        corev1client.SecretsGetter     // required
	eventRecorder events.Recorder                // required
}

type TargetCertKeySecretRotatorOption func(*TargetCertKeySecretRotator)

func WithLister(lister corev1listers.SecretLister) TargetCertKeySecretRotatorOption {
	return func(tcksr *TargetCertKeySecretRotator) {
		tcksr.lister = lister
	}
}

func WithValidity(validity time.Duration) TargetCertKeySecretRotatorOption {
	return func(tcksr *TargetCertKeySecretRotator) {
		if validity <= 0 {
			return
		}

		tcksr.validity = &validity
	}
}

func WithRefresh(refresh time.Duration) TargetCertKeySecretRotatorOption {
	return func(tcksr *TargetCertKeySecretRotator) {
		if refresh <= 0 {
			return
		}

		tcksr.refresh = &refresh
	}
}

func WithAdditionalAnnotations(annotations certrotation.AdditionalAnnotations) TargetCertKeySecretRotatorOption {
	return func(tcksr *TargetCertKeySecretRotator) {
		tcksr.additionalAnnotations = annotations
	}
}

func WithOwner(owner metav1.OwnerReference) TargetCertKeySecretRotatorOption {
	return func(tcksr *TargetCertKeySecretRotator) {
		tcksr.owner = &owner
	}
}

func NewTargetCertKeySecretRotator(namespace string, name string, certCreator TargetCertCreator, client corev1client.SecretsGetter, informer corev1informers.SecretInformer, options ...TargetCertKeySecretRotatorOption) *TargetCertKeySecretRotator {
	defaultValidity := crypto.DefaultCertificateLifetimeDuration
	rotator := &TargetCertKeySecretRotator{
		namespace:       namespace,
		name:            name,
		certCreator:     certCreator,
		client:          client,
		informer:        informer,
		lister:          informer.Lister(),
		validity:        &defaultValidity,
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

type TargetCertCreator interface {
	// NewCertificate creates a new key-cert pair with the given signer. If keyGen
	// is non-nil, it is used to generate the key pair; otherwise legacy defaults are used.
	NewCertificate(signer *crypto.CA, validity time.Duration) (*crypto.TLSCertificateConfig, error)
	// NeedNewTargetCertKeyPair decides whether a new cert-key pair is needed. It returns a non-empty reason if it is the case.
	NeedNewTargetCertKeyPair(currentCertSecret *corev1.Secret, signer *crypto.CA, caBundleCerts []*x509.Certificate, refresh time.Duration) (bool, string, error)
	// SetAnnotations gives an option to override or set additional annotations
	SetAnnotations(cert *crypto.TLSCertificateConfig, annotations map[string]string)
}

// TargetCertRechecker is an optional interface to be implemented by the TargetCertCreator to enforce
// a controller run.
type TargetCertRechecker interface {
	RecheckChannel() <-chan struct{}
}

func (c *TargetCertKeySecretRotator) RecheckChannel() <-chan struct{} {
	refresher, ok := c.certCreator.(TargetCertRechecker)
	if !ok {
		return nil
	}

	return refresher.RecheckChannel()
}

func (c *TargetCertKeySecretRotator) EnsureTargetCertKeyPair(ctx context.Context, signerCertKeyPair *crypto.CA, caBundleCerts []*x509.Certificate) (*corev1.Secret, error) {
	creationRequired := false

	originalTargetCertKeyPairSecret, err := c.lister.Secrets(c.namespace).Get(c.name)
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, err
	}

	targetCertKeyPairSecret := originalTargetCertKeyPairSecret.DeepCopy()
	if apierrors.IsNotFound(err) {
		// create an empty one
		targetCertKeyPairSecret = &corev1.Secret{
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
		c.eventRecorder.Eventf("TargetUpdateRequired", "%q in %q requires a new target cert/key pair because it does not exist.", c.name, c.namespace)

		return c.createSecret(ctx, targetCertKeyPairSecret, signerCertKeyPair)
	}

	return c.updateSecret(ctx, targetCertKeyPairSecret, signerCertKeyPair, caBundleCerts)
}

func (c *TargetCertKeySecretRotator) createSecret(ctx context.Context, secret *corev1.Secret, signer *crypto.CA) (*corev1.Secret, error) {
	certrotation.EnsureOwnerRefAndTLSAnnotations(secret, c.owner, c.additionalAnnotations)
	certrotation.EnsureSecretTLSTypeSet(secret)

	tlsCertificateConfig, err := c.certCreator.NewCertificate(signer, *c.validity)
	if err != nil {
		return nil, fmt.Errorf("creating new certificate: %w", err)
	}

	secret.Data[certsSecretKey], secret.Data[keySecretKey], err = tlsCertificateConfig.GetPEMBytes()
	if err != nil {
		return nil, fmt.Errorf("getting certificate PEM-encoded bytes: %w", err)
	}

	c.certCreator.SetAnnotations(tlsCertificateConfig, secret.Annotations)

	actual, err := c.client.Secrets(c.namespace).Create(ctx, secret, metav1.CreateOptions{})
	resourcehelper.ReportCreateEvent(c.eventRecorder, actual, err)
	if err != nil {
		return nil, fmt.Errorf("creating secret: %w", err)
	}

	klog.V(2).Infof("Created secret %s/%s", actual.Namespace, actual.Name)
	return actual, nil
}

func (c *TargetCertKeySecretRotator) updateSecret(ctx context.Context, secret *corev1.Secret, signer *crypto.CA, caBundleCerts []*x509.Certificate) (*corev1.Secret, error) {
	metadataUpdateRequired := certrotation.EnsureOwnerRefAndTLSAnnotations(secret, c.owner, c.additionalAnnotations) || certrotation.EnsureSecretTLSTypeSet(secret)

	targetUpdateRequired, reason, err := c.certCreator.NeedNewTargetCertKeyPair(secret, signer, caBundleCerts, *c.refresh)
	if err != nil {
		return nil, fmt.Errorf("checking if target certificate needs updates: %w", err)
	}

	if targetUpdateRequired {
		c.eventRecorder.Eventf("TargetUpdateRequired", "%q in %q requires a new target cert/key pair: %v", c.name, c.namespace, reason)

		tlsCertificateConfig, err := c.certCreator.NewCertificate(signer, *c.validity)
		if err != nil {
			return nil, fmt.Errorf("creating new certificate: %w", err)
		}

		secret.Data[certsSecretKey], secret.Data[keySecretKey], err = tlsCertificateConfig.GetPEMBytes()
		if err != nil {
			return nil, fmt.Errorf("getting certificate PEM-encoded bytes: %w", err)
		}
	}

	// No updates are needed to the secret
	if !targetUpdateRequired && !metadataUpdateRequired {
		return secret, nil
	}

	actual, err := c.client.Secrets(c.namespace).Update(ctx, secret, metav1.UpdateOptions{})
	resourcehelper.ReportUpdateEvent(c.eventRecorder, actual, err)
	if err != nil {
		return nil, fmt.Errorf("updating secret: %w", err)
	}

	klog.V(2).Infof("Updated secret %s/%s", actual.Namespace, actual.Name)

	return actual, nil
}

func checkIfTargetUpdateRequired(secret *corev1.Secret, signer *crypto.CA, caBundleCerts []*x509.Certificate, refresh time.Duration, clk clock.PassiveClock) (bool, string, error) {
	certBytes, hasCertContent := secret.Data[certsSecretKey]
	keyBytes, hasKeyContent := secret.Data[keySecretKey]

	if !hasCertContent || !hasKeyContent {
		return true, "missing contents", nil
	}

	ca, err := crypto.GetCAFromBytes(certBytes, keyBytes)
	if err != nil {
		return false, "", fmt.Errorf("loading certificate data: %w", err)
	}

	leaf := ca.Config.Certs[0]

	if clk.Now().After(leaf.NotAfter) {
		return true, "expired", nil
	}

	refreshTime := leaf.NotBefore.Add(refresh)
	if clk.Now().After(refreshTime) {
		// make sure the signer has been valid for more than 10% of the target's refresh time.
		timeToWaitForTrustRotation := refresh / 10
		if clk.Now().After(signer.Config.Certs[0].NotBefore.Add(time.Duration(timeToWaitForTrustRotation))) {
			return true, fmt.Sprintf("past its refresh time %v", refreshTime), nil
		}
	}

	issuerFoundInCABundle := false
	for _, caCert := range caBundleCerts {
		if leaf.Issuer.CommonName == caCert.Subject.CommonName {
			issuerFoundInCABundle = true
		}
	}

	if !issuerFoundInCABundle {
		return true, fmt.Sprintf("issuer %q, not in ca bundle:\n%s", leaf.Issuer.CommonName, certs.CertificateBundleToString(caBundleCerts)), nil
	}

	return false, "", nil
}
