package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourcehelper"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1informers "k8s.io/client-go/informers/core/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
)

type (
	RotationFn func(*corev1.Secret) (bool, string, error)
	MetadataFn func(*corev1.Secret) bool
)

type CertificateCreator interface {
	CreateCertificate(context.Context) (*crypto.TLSCertificateConfig, error)
}

func NewCertificateRotationController(
	controllerName string,
	name string,
	namespace string,
	certificateCreator CertificateCreator,
	metadataFn MetadataFn,
	rotationFn RotationFn,
	client corev1client.SecretsGetter,
	informer corev1informers.SecretInformer,
	recorder events.Recorder,
	extraInformers []factory.Informer,
) factory.Controller {
	rotation := &CertificateRotation{
		name:               name,
		namespace:          namespace,
		certificateCreator: certificateCreator,
		metadataFn:         metadataFn,
		rotationFn:         rotationFn,
		client:             client,
		lister:             informer.Lister(),
		eventRecorder:      recorder,
	}

	// TODO: add an event channel that triggers reconciliation to handle things like serving certificate rotation on hostname changes
	return factory.New().
		ResyncEvery(time.Minute).
		WithSync(rotation.Sync).
		WithInformers(append([]factory.Informer{informer.Informer()}, extraInformers...)...).
		ToController(
			"CertificateRotationController",
			recorder.WithComponentSuffix("certificate-rotation-controller").WithComponentSuffix(name),
		)
}

// CertificateRotation creates and rotates certificates as needed.
type CertificateRotation struct {
	// namespace to create the managed certificate secret in
	namespace string
	// name of the certificate secret
	name string

	client        corev1client.SecretsGetter
	lister        corev1listers.SecretLister
	eventRecorder events.Recorder

	certificateCreator CertificateCreator

	metadataFn MetadataFn
	rotationFn RotationFn
}

func (r *CertificateRotation) Sync(ctx context.Context, syncCtx factory.SyncContext) error {
	existing, err := r.lister.Secrets(r.namespace).Get(r.name)
	if errors.IsNotFound(err) {
		return r.createSecret(ctx)
	}
	if err != nil {
		return fmt.Errorf("getting secret %q: %w", fmt.Sprintf("%s/%s", r.namespace, r.name), err)
	}

	existingCopy := existing.DeepCopy()
	needsRotation, rotationReason, err := r.rotationFn(existingCopy)
	if err != nil {
		return fmt.Errorf("determining if secret %q needs rotation: %w", fmt.Sprintf("%s/%s", r.namespace, r.name), err)
	}

	if needsRotation {
		r.eventRecorder.Eventf("RotationRequired", "%q in %q requires rotation: %v", r.name, r.namespace, rotationReason)

		certBytes, keyBytes, err := r.createCertificateKeyBytes(ctx)
		if err != nil {
			return fmt.Errorf("creating certificate and key bytes: %w", err)
		}

		existingCopy.Data["tls.crt"] = certBytes
		existingCopy.Data["tls.key"] = keyBytes
	}

	needsMetadataUpdate := r.metadataFn(existingCopy)

	if needsRotation || needsMetadataUpdate {
		actual, err := r.client.Secrets(r.namespace).Update(ctx, existingCopy, v1.UpdateOptions{})
		resourcehelper.ReportUpdateEvent(r.eventRecorder, actual, err)
		if err != nil {
			return fmt.Errorf("updating secret %q: %w", fmt.Sprintf("%s/%s", r.namespace, r.name), err)
		}
	}

	return nil
}

func (r *CertificateRotation) createSecret(ctx context.Context) error {
	certBytes, keyBytes, err := r.createCertificateKeyBytes(ctx)
	if err != nil {
		return fmt.Errorf("creating certificate and key bytes: %w", err)
	}

	secret := &corev1.Secret{
		ObjectMeta: v1.ObjectMeta{
			Namespace: r.namespace,
			Name:      r.name,
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": certBytes,
			"tls.key": keyBytes,
		},
	}

	_ = r.metadataFn(secret)

	actual, err := r.client.Secrets(r.namespace).Create(ctx, secret, v1.CreateOptions{})
	resourcehelper.ReportCreateEvent(r.eventRecorder, actual, err)
	if err != nil {
		return fmt.Errorf("creating secret %q: %w", fmt.Sprintf("%s/%s", r.namespace, r.name), err)
	}

	return nil
}

func (r *CertificateRotation) createCertificateKeyBytes(ctx context.Context) ([]byte, []byte, error) {
	certConfig, err := r.certificateCreator.CreateCertificate(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("creating certificate: %w", err)
	}

	certBytes, keyBytes, err := certConfig.GetPEMBytes()
	if err != nil {
		return nil, nil, fmt.Errorf("writing certificate to PEM encoded bytes: %w", err)
	}

	return certBytes, keyBytes, nil
}
