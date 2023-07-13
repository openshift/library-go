package secret

import (
	"context"
	"fmt"
	"sync"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
)

type SecretEventHandlerRegistration interface {
	cache.ResourceEventHandlerRegistration

	GetKey() ObjectKey
}

type SecretMonitor interface {
	AddEventHandler(namespace, name string, handler cache.ResourceEventHandler) (SecretEventHandlerRegistration, error)

	RemoveEventHandler(SecretEventHandlerRegistration) error

	GetSecret(namespace, name string) (*corev1.Secret, error)
}

type secretEventHandlerRegistration struct {
	cache.ResourceEventHandlerRegistration

	objectKey ObjectKey
}

func (r *secretEventHandlerRegistration) GetKey() ObjectKey {
	return r.objectKey
}

type sm struct {
	kubeClient kubernetes.Interface

	lock     sync.RWMutex
	monitors map[ObjectKey]*singleItemMonitor
}

func NewSecretMonitor(kubeClient *kubernetes.Clientset) SecretMonitor {
	return &sm{
		kubeClient: kubeClient,
		monitors:    map[ObjectKey]*singleItemMonitor{}
	}
}

func (s *sm) AddEventHandler(namespace, name string, handler cache.ResourceEventHandler) (cache.ResourceEventHandlerRegistration, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	key := ObjectKey{Namespace: namespace, Name: name}
	m, exists := s.monitors[key]

	if !exists {
		sharedInformer := cache.NewSharedInformer(
			cache.NewListWatchFromClient(
				s.kubeClient.CoreV1().RESTClient(),
				"secrets",
				namespace,
				fields.OneTermEqualSelector("metadata.name", name),
			),
			&corev1.Secret{},
			0)

		m := newSingleItemMonitor(key, sharedInformer)
		go m.StartInformer()

		s.monitors[key] = m

		klog.Info("secret informer started", " item key ", key)
	}

	klog.Info("secret handler added", " item key ", key)
	return m.AddEventHandler(handler)
}

func (s *sm) RemoveEventHandler(handle SecretEventHandlerRegistration) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	key := handle.GetKey()
	m, ok := s.monitors[key]
	if !ok {
		// already gone
		return nil
	}

	klog.Info("secret handler removed", " item key ", key)
	if err := m.RemoveEventHandler(handle); err != nil {
		return err
	}

	if m.numHandlers.Load() <= 0 {
		klog.Info("secret informer stopped", " item key ", key)
		m.Stop()
		delete(s.monitors, key)
	}

	return nil
}

func (s *sm) GetSecret(namespace, name string) (*corev1.Secret, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	key := ObjectKey{Namespace: namespace, Name: name}
	m, exists := s.monitors[key]

	if !exists {
		return nil, apierrors.NewNotFound(schema.GroupResource{Resource: "secrets"}, name)
	}

	uncast, exists, err := m.GetItem()
	if !exists {
		return nil, apierrors.NewNotFound(schema.GroupResource{Resource: "secrets"}, name)
	}
	if err != nil {
		return nil, err
	}

	ret, ok := uncast.(*corev1.Secret)
	if !ok {
		return nil, fmt.Errorf("unexpected type: %T", uncast)
	}

	return ret, nil
}
