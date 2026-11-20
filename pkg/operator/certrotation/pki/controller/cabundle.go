package controller

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"slices"
	"time"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourcehelper"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/sets"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/util/cert"
)

type SignerGetter interface {
	GetSigner(context.Context) (*crypto.CA, error)
}

type CABundleMetadataFn func(*corev1.ConfigMap) bool

// CABundle creates and updates a CA bundle ConfigMap as needed for signing certificate(s).
type CABundle struct {
	name      string
	namespace string

	client        corev1client.ConfigMapsGetter
	lister        corev1listers.ConfigMapLister
	eventRecorder events.Recorder

	signerGetters []SignerGetter

	metadataFn CABundleMetadataFn
}

func (c *CABundle) Sync(ctx context.Context, syncCtx factory.SyncContext) error {
	existing, err := c.lister.ConfigMaps(c.namespace).Get(c.name)
	if errors.IsNotFound(err) {
		return c.createConfigMap(ctx)
	}
	if err != nil {
		return fmt.Errorf("getting configmap %q: %w", fmt.Sprintf("%s/%s", c.namespace, c.name), err)
	}

	existingCopy := existing.DeepCopy()
	needsMetadataUpdate := c.metadataFn(existingCopy)

	err = c.updateCAs(ctx, existingCopy)
	if err != nil {
		return fmt.Errorf("updating CA contents: %w", err)
	}

	needsUpdate := !equality.Semantic.DeepEqual(existing.Data, existingCopy.Data)

	if needsMetadataUpdate || needsUpdate {
		actual, err := c.client.ConfigMaps(c.namespace).Update(ctx, existingCopy, metav1.UpdateOptions{})
		resourcehelper.ReportUpdateEvent(c.eventRecorder, actual, err)
		if err != nil {
			return fmt.Errorf("updating secret %q: %w", fmt.Sprintf("%s/%s", c.namespace, c.name), err)
		}
	}

	return nil
}

func (c *CABundle) createConfigMap(ctx context.Context) error {
	caCerts := sets.New[*x509.Certificate]()
	for _, signerGetter := range c.signerGetters {
		signer, err := signerGetter.GetSigner(ctx)
		if err != nil {
			return fmt.Errorf("getting signers: %w", err)
		}

		if signer.Config == nil || len(signer.Config.Certs) == 0 {
			continue
		}

		// ignore any expired signing CA certificates TODO: make this a clock-based time evaluation
		if time.Now().After(signer.Config.Certs[0].NotAfter) {
			continue
		}

		caCerts.Insert(signer.Config.Certs[0])
	}

	finalCertificates := caCerts.UnsortedList()

	// byte-wise stable sorting for deterministic ordering to prevent unnecessary updates
	// due to ordering issues.
	slices.SortStableFunc(finalCertificates, func(a, b *x509.Certificate) int {
		return bytes.Compare(a.Raw, b.Raw)
	})

	caBytes, err := crypto.EncodeCertificates(finalCertificates...)
	if err != nil {
		return fmt.Errorf("encoding signing CAs to bytes: %w", err)
	}

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: c.namespace,
			Name:      c.name,
		},
		Data: map[string]string{
			"ca-bundle.crt": string(caBytes),
		},
	}

	_ = c.metadataFn(cm)

	actual, err := c.client.ConfigMaps(c.namespace).Create(ctx, cm, metav1.CreateOptions{})
	resourcehelper.ReportCreateEvent(c.eventRecorder, actual, err)
	if err != nil {
		return fmt.Errorf("creating configmap %q: %w", fmt.Sprintf("%s/%s", c.namespace, c.name), err)
	}

	return nil
}

func (c *CABundle) updateCAs(ctx context.Context, cm *corev1.ConfigMap) error {
	caCerts := sets.New[*x509.Certificate]()

	if cm.Data != nil {
		if certsStr, ok := cm.Data["ca-bundle.crt"]; ok {
			certs, err := cert.ParseCertsPEM([]byte(certsStr))
			if err != nil {
				return fmt.Errorf("could not parse existing certificates: %w", err)
			}

			certs = crypto.FilterExpiredCerts(certs...)

			caCerts.Insert(certs...)
		}
	}

	for _, signerGetter := range c.signerGetters {
		signer, err := signerGetter.GetSigner(ctx)
		if err != nil {
			return fmt.Errorf("getting signers: %w", err)
		}

		if signer.Config == nil || len(signer.Config.Certs) == 0 {
			continue
		}

		// ignore any expired signing CA certificates TODO: make this a clock-based time evaluation
		if time.Now().After(signer.Config.Certs[0].NotAfter) {
			continue
		}

		caCerts.Insert(signer.Config.Certs[0])
	}

	finalCertificates := caCerts.UnsortedList()

	// byte-wise stable sorting for deterministic ordering to prevent unnecessary updates
	// due to ordering issues.
	slices.SortStableFunc(finalCertificates, func(a, b *x509.Certificate) int {
		return bytes.Compare(a.Raw, b.Raw)
	})

	caBytes, err := crypto.EncodeCertificates(finalCertificates...)
	if err != nil {
		return fmt.Errorf("encoding signing CAs to bytes: %w", err)
	}

	if cm.Data == nil {
		cm.Data = map[string]string{}
	}

	cm.Data["ca-bundle.crt"] = string(caBytes)
	return nil
}
