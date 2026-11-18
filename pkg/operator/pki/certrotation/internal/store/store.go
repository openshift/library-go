// Package store provides the Kubernetes read and write paths of the v2
// certificate rotation reconciler: reads through informer listers when
// available (with live GETs for one-shot callers), and writes that are
// always Create or Update with a resourceVersion precondition, never apply.
package store

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubeinformers "k8s.io/client-go/informers"
	kubernetes "k8s.io/client-go/kubernetes"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	corev1lister "k8s.io/client-go/listers/core/v1"
)

var (
	metav1GetOptions    = metav1.GetOptions{}
	metav1CreateOptions = metav1.CreateOptions{}
	metav1UpdateOptions = metav1.UpdateOptions{}
)

// InformerSource supplies namespace-scoped shared informer factories. It is
// satisfied by v1helpers.KubeInformersForNamespaces and by the v2 package's
// public InformerSource (structural typing).
type InformerSource interface {
	InformersFor(namespace string) kubeinformers.SharedInformerFactory
}

// Store reads and writes the Secrets and ConfigMaps of a rotation.
type Store struct {
	client    kubernetes.Interface
	informers InformerSource
}

// New creates a Store. informers may be nil, in which case all reads are
// live GETs through the client (one-shot callers such as oc).
func New(client kubernetes.Interface, informers InformerSource) *Store {
	return &Store{client: client, informers: informers}
}

func (s *Store) secrets(ns string) (corev1lister.SecretNamespaceLister, corev1client.SecretInterface, bool) {
	if s.informers != nil {
		if factory := s.informers.InformersFor(ns); factory != nil {
			return factory.Core().V1().Secrets().Lister().Secrets(ns), s.client.CoreV1().Secrets(ns), true
		}
	}
	return nil, s.client.CoreV1().Secrets(ns), false
}

func (s *Store) configMaps(ns string) (corev1lister.ConfigMapNamespaceLister, corev1client.ConfigMapInterface, bool) {
	if s.informers != nil {
		if factory := s.informers.InformersFor(ns); factory != nil {
			return factory.Core().V1().ConfigMaps().Lister().ConfigMaps(ns), s.client.CoreV1().ConfigMaps(ns), true
		}
	}
	return nil, s.client.CoreV1().ConfigMaps(ns), false
}

// GetSecret reads a secret through the lister when informers are configured,
// falling back to a live GET otherwise. A not-found secret yields
// (nil, nil): absence is a classification input, not an error.
func (s *Store) GetSecret(ctx context.Context, namespace, name string) (*corev1.Secret, error) {
	lister, _, _ := s.secrets(namespace)
	if lister != nil {
		secret, err := lister.Get(name)
		if err != nil {
			if apierrors.IsNotFound(err) {
				return nil, nil
			}
			return nil, err
		}
		return secret, nil
	}
	secret, err := s.client.CoreV1().Secrets(namespace).Get(ctx, name, metav1GetOptions)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return secret, nil
}

// GetConfigMap reads a configmap the same way GetSecret reads a secret.
func (s *Store) GetConfigMap(ctx context.Context, namespace, name string) (*corev1.ConfigMap, error) {
	lister, _, _ := s.configMaps(namespace)
	if lister != nil {
		configMap, err := lister.Get(name)
		if err != nil {
			if apierrors.IsNotFound(err) {
				return nil, nil
			}
			return nil, err
		}
		return configMap, nil
	}
	configMap, err := s.client.CoreV1().ConfigMaps(namespace).Get(ctx, name, metav1GetOptions)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return configMap, nil
}

// GetSecretLive reads a secret straight from the API server, bypassing the
// lister cache. The reconciler uses it for its read-your-writes guard: after
// this process wrote an artifact, a stale cache must not drive the next
// decision.
func (s *Store) GetSecretLive(ctx context.Context, namespace, name string) (*corev1.Secret, error) {
	secret, err := s.client.CoreV1().Secrets(namespace).Get(ctx, name, metav1GetOptions)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return secret, nil
}

// CreateSecret creates a secret and returns the object the API server
// persisted.
func (s *Store) CreateSecret(ctx context.Context, secret *corev1.Secret) (*corev1.Secret, error) {
	_, client, _ := s.secrets(secret.Namespace)
	return client.Create(ctx, secret, metav1CreateOptions)
}

// UpdateSecret updates a secret with its resourceVersion as the optimistic
// concurrency precondition and returns the object the API server persisted.
func (s *Store) UpdateSecret(ctx context.Context, secret *corev1.Secret) (*corev1.Secret, error) {
	_, client, _ := s.secrets(secret.Namespace)
	updated, err := client.Update(ctx, secret, metav1UpdateOptions)
	if err != nil {
		return nil, fmt.Errorf("updating secret %s/%s: %w", secret.Namespace, secret.Name, err)
	}
	return updated, nil
}

// CreateConfigMap creates a configmap and returns the persisted object.
func (s *Store) CreateConfigMap(ctx context.Context, configMap *corev1.ConfigMap) (*corev1.ConfigMap, error) {
	_, client, _ := s.configMaps(configMap.Namespace)
	return client.Create(ctx, configMap, metav1CreateOptions)
}

// UpdateConfigMap updates a configmap with its resourceVersion as the
// optimistic concurrency precondition and returns the persisted object.
func (s *Store) UpdateConfigMap(ctx context.Context, configMap *corev1.ConfigMap) (*corev1.ConfigMap, error) {
	_, client, _ := s.configMaps(configMap.Namespace)
	updated, err := client.Update(ctx, configMap, metav1UpdateOptions)
	if err != nil {
		return nil, fmt.Errorf("updating configmap %s/%s: %w", configMap.Namespace, configMap.Name, err)
	}
	return updated, nil
}
