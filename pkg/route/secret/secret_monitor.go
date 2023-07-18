package secret

import (
	"fmt"
	"strings"
	"sync"

	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
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

type listObjectFunc func(string, metav1.ListOptions) (runtime.Object, error)
type watchObjectFunc func(string, metav1.ListOptions) (watch.Interface, error)

type SecretEventHandlerRegistration interface {
	cache.ResourceEventHandlerRegistration

	GetKey() ObjectKey
}

type SecretMonitor interface {
	AddEventHandler(namespace, name string, handler cache.ResourceEventHandler) (SecretEventHandlerRegistration, error)

	RemoveEventHandler(SecretEventHandlerRegistration) error

	GetSecret(SecretEventHandlerRegistration) (*v1.Secret, error)
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
		monitors:   map[ObjectKey]*singleItemMonitor{},
	}
}

func (s *sm) AddEventHandler(namespace, name string, handler cache.ResourceEventHandler) (SecretEventHandlerRegistration, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	// name is a combination or routename_secretname
	key := ObjectKey{Namespace: namespace, Name: name}
	m, exists := s.monitors[key]

	// TODO refactor this later
	secretName := strings.Split(name, "_")[1]
	if !exists {
		sharedInformer := cache.NewSharedInformer(
			cache.NewListWatchFromClient(
				s.kubeClient.CoreV1().RESTClient(),
				"secrets",
				namespace,
				fields.OneTermEqualSelector("metadata.name", secretName),
			),
			&corev1.Secret{},
			0,
		)

		m = newSingleItemMonitor(key, sharedInformer)
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
		// already removed
		return nil
	}

	if err := m.RemoveEventHandler(handle); err != nil {
		return err
	}
	klog.Info("secret handler removed", " item key", key)

	if m.numHandlers.Load() <= 0 {
		m.Stop()
		delete(s.monitors, key)
		klog.Info("secret informer stopped ", " item key ", key)
	}

	return nil
}

func (s *sm) GetSecret(handle SecretEventHandlerRegistration) (*v1.Secret, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	key := handle.GetKey()

	m, exists := s.monitors[key]

	if !exists {
		return nil, apierrors.NewNotFound(schema.GroupResource{Resource: "secrets"}, m.GetItemKey())
	}

	uncast, exists, err := m.GetItem()
	if !exists {
		return nil, apierrors.NewNotFound(schema.GroupResource{Resource: "secrets"}, m.GetItemKey())
	}

	if err != nil {
		return nil, err
	}

	ret, ok := uncast.(*v1.Secret)
	if !ok {
		return nil, fmt.Errorf("unexpected type: %T", uncast)
	}

	return ret, nil

}
