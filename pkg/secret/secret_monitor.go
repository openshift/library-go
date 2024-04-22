package secret

import (
	"context"
	"fmt"
	"sync"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
)

// SecretEventHandlerRegistration is for registering and unregistering event handlers for secret monitoring.
type SecretEventHandlerRegistration interface {
	cache.ResourceEventHandlerRegistration

	GetKey() ObjectKey
	GetHandler() cache.ResourceEventHandlerRegistration
}

// SecretMonitor helps in monitoring and handling a specific secret using singleItemMonitor.
type SecretMonitor interface {
	// AddSecretEventHandler adds a secret event handler to the monitor for a specific secret in the given namespace.
	// The handler will be notified of events related to the "specified" secret only.
	// The returned SecretEventHandlerRegistration can be used to later remove the handler.
	AddSecretEventHandler(ctx context.Context, namespace, secretName string, handler cache.ResourceEventHandler) (SecretEventHandlerRegistration, error)

	// RemoveSecretEventHandler removes a previously added secret event handler using the provided registration.
	// If the handler is not found or if there is an issue removing it, an error is returned.
	RemoveSecretEventHandler(handlerRegistration SecretEventHandlerRegistration) error

	// GetSecret retrieves the secret object from the informer's cache using the provided SecretEventHandlerRegistration.
	// This allows accessing the latest state of the secret without making an API call.
	GetSecret(ctx context.Context, handlerRegistration SecretEventHandlerRegistration) (*corev1.Secret, error)
}

// secretEventHandlerRegistration is an implementation of the SecretEventHandlerRegistration.
type secretEventHandlerRegistration struct {
	cache.ResourceEventHandlerRegistration

	// objectKey represents the unique identifier for the secret associated with this event handler registration.
	// It will be populated during AddEventHandler, and will be used during RemoveEventHandler, GetSecret.
	objectKey ObjectKey
}

func (r *secretEventHandlerRegistration) GetKey() ObjectKey {
	return r.objectKey
}

func (r *secretEventHandlerRegistration) GetHandler() cache.ResourceEventHandlerRegistration {
	return r.ResourceEventHandlerRegistration
}

type monitoredItem struct {
	itemMonitor *singleItemMonitor
	numHandlers int
}

// secretMonitor is an implementation of the SecretMonitor
type secretMonitor struct {
	kubeClient kubernetes.Interface
	lock       sync.RWMutex
	monitors   map[ObjectKey]*monitoredItem
}

func NewSecretMonitor(kubeClient kubernetes.Interface) SecretMonitor {
	return &secretMonitor{
		kubeClient: kubeClient,
		monitors:   map[ObjectKey]*monitoredItem{},
	}
}

// AddSecretEventHandler adds a secret event handler to the monitor.
func (s *secretMonitor) AddSecretEventHandler(ctx context.Context, namespace, secretName string, handler cache.ResourceEventHandler) (SecretEventHandlerRegistration, error) {
	return s.addSecretEventHandler(ctx, namespace, secretName, handler, s.createSecretInformer(namespace, secretName))
}

// createSecretInformer creates a SharedInformer for monitoring a specific secret.
func (s *secretMonitor) createSecretInformer(namespace, name string) cache.SharedInformer {
	return cache.NewSharedInformer(
		cache.NewListWatchFromClient(
			s.kubeClient.CoreV1().RESTClient(),
			"secrets",
			namespace,
			fields.OneTermEqualSelector("metadata.name", name),
		),
		&corev1.Secret{},
		0,
	)
}

// addSecretEventHandler adds a secret event handler and starts the informer if not already running.
func (s *secretMonitor) addSecretEventHandler(ctx context.Context, namespace, secretName string, handler cache.ResourceEventHandler, secretInformer cache.SharedInformer) (SecretEventHandlerRegistration, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if handler == nil {
		return nil, fmt.Errorf("nil handler is provided")
	}

	// secret identifier (namespace/secret)
	key := NewObjectKey(namespace, secretName)

	// Start secret informer if monitor does not exist.
	m, exists := s.monitors[key]
	if !exists {
		m = &monitoredItem{}
		m.itemMonitor = newSingleItemMonitor(key, secretInformer)
		go m.itemMonitor.StartInformer(ctx)

		// wait for first sync
		if !cache.WaitForCacheSync(ctx.Done(), m.itemMonitor.HasSynced) {
			return nil, fmt.Errorf("failed waiting for cache sync")
		}

		// add item key to monitors map
		s.monitors[key] = m

		klog.Info("secret informer started", " item key ", key)
	}

	// add the event handler
	registration, err := m.itemMonitor.AddEventHandler(handler)
	if err != nil {
		return nil, err
	}

	// Increment numHandlers
	m.numHandlers += 1

	// TODO: this can be too noisy, later we need to use higher verbosity
	klog.Info("secret handler added", " item key ", key)

	return registration, nil
}

// RemoveSecretEventHandler removes a secret event handler and stops the informer if no handlers are left.
// If the handler is not found or if there is an issue removing it, an error is returned.
func (s *secretMonitor) RemoveSecretEventHandler(handlerRegistration SecretEventHandlerRegistration) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	if handlerRegistration == nil {
		return fmt.Errorf("nil secret handler registration is provided")
	}

	// Extract the key from the registration to identify the associated monitor.
	// populated in AddEventHandler()
	key := handlerRegistration.GetKey()

	// check if secret informer already exists for the secret(key)
	m, exists := s.monitors[key]
	if !exists {
		return fmt.Errorf("secret monitor already removed for item key %v", key)
	}

	if err := m.itemMonitor.RemoveEventHandler(handlerRegistration); err != nil {
		return err
	}
	// Decrement numHandlers
	m.numHandlers -= 1
	klog.Info("secret handler removed", " item key", key)

	// stop informer if there is no handler
	if m.numHandlers <= 0 {
		if !m.itemMonitor.StopInformer() {
			return fmt.Errorf("secret informer already stopped for item key %v", key)
		}
		// remove the key from map
		delete(s.monitors, key)
		klog.Info("secret informer stopped", " item key ", key)
	}

	return nil
}

// GetSecret retrieves the secret object from the informer's cache. Error if the secret is not found in the cache.
func (s *secretMonitor) GetSecret(ctx context.Context, handlerRegistration SecretEventHandlerRegistration) (*corev1.Secret, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	if handlerRegistration == nil {
		return nil, fmt.Errorf("nil secret handler registration is provided")
	}
	key := handlerRegistration.GetKey()
	secretName := key.Name

	// check if secret informer exists
	m, exists := s.monitors[key]
	if !exists {
		return nil, fmt.Errorf("secret monitor doesn't exist for key %v", key)
	}

	// wait for informer store sync, to load secrets
	if !cache.WaitForCacheSync(ctx.Done(), handlerRegistration.HasSynced) {
		return nil, fmt.Errorf("failed waiting for cache sync")
	}

	uncast, exists, err := m.itemMonitor.GetItem()

	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, apierrors.NewNotFound(corev1.Resource("secrets"), secretName)
	}

	secret, ok := uncast.(*corev1.Secret)
	if !ok {
		return nil, fmt.Errorf("unexpected type: %T", uncast)
	}

	return secret, nil
}
