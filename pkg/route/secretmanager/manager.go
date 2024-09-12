package secretmanager

import (
	"context"
	"fmt"
	"sync"

	"github.com/openshift/library-go/pkg/secret"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
)

type SecretManager interface {
	RegisterRoute(ctx context.Context, namespace string, routeName string, secretName string, handler cache.ResourceEventHandlerFuncs) error
	UnregisterRoute(namespace string, routeName string) error
	GetSecret(ctx context.Context, namespace string, routeName string) (*v1.Secret, error)
	LookupRouteSecret(namespace string, routeName string) (string, bool)
	Queue() workqueue.RateLimitingInterface
}

// Manager is responsible for managing secrets associated with routes. It implements SecretManager.
type manager struct {
	// monitor for managing and watching "single" secret dynamically.
	monitor secret.SecretMonitor

	// Map of registered handlers for each route.
	// Populated inside RegisterRoute() and used in UnregisterRoute(), GetSecret.
	// generateKey() will create the map key.
	registeredHandlers map[string]referencedSecret

	// Lock to protect access to registeredHandlers map.
	handlersLock sync.RWMutex

	// Work queue to be used by the consumer of this Manager, mostly to add secret change events.
	queue workqueue.RateLimitingInterface
}

type referencedSecret struct {
	secretName          string
	handlerRegistration secret.SecretEventHandlerRegistration
}

func NewManager(kubeClient kubernetes.Interface, queue workqueue.RateLimitingInterface) SecretManager {
	return &manager{
		monitor:            secret.NewSecretMonitor(kubeClient),
		handlersLock:       sync.RWMutex{},
		queue:              queue,
		registeredHandlers: map[string]referencedSecret{},
	}
}

// Queue returns the work queue for the manager.
func (m *manager) Queue() workqueue.RateLimitingInterface {
	return m.queue
}

// RegisterRoute registers a route with a secret, enabling the manager to watch for the secret changes and associate them with the handler functions.
// Returns an error if the route is already registered with a secret or if adding the secret event handler fails.
func (m *manager) RegisterRoute(ctx context.Context, namespace, routeName, secretName string, handler cache.ResourceEventHandlerFuncs) error {
	m.handlersLock.Lock()
	defer m.handlersLock.Unlock()

	// Generate a unique key for the provided namespace and routeName.
	key := generateKey(namespace, routeName)

	// Check if the route is already registered with the given key.
	// Each route (namespace/routeName) should be registered only once with any secret.
	// Note: inside a namespace multiple different routes can be registered(watch) with a common secret.
	if _, exists := m.registeredHandlers[key]; exists {
		return fmt.Errorf("route already registered with key %s", key)
	}

	// Add a secret event handler for the specified namespace and secret, with the handler functions.
	klog.V(5).Infof("trying to add handler for key %s with secret %s", key, secretName)
	handlerReg, err := m.monitor.AddSecretEventHandler(ctx, namespace, secretName, handler)
	if err != nil {
		return err
	}

	// Store the registration and secretName in the manager's map. Used during UnregisterRoute() and GetSecret().
	m.registeredHandlers[key] = referencedSecret{
		secretName:          secretName,
		handlerRegistration: handlerReg,
	}
	klog.Infof("secret manager registered route for key %s with secret %s", key, secretName)

	return nil
}

// UnregisterRoute removes the registration of a route from the manager.
// It removes the secret event handler from secret monitor and deletes its associated handler from manager's map.
func (m *manager) UnregisterRoute(namespace, routeName string) error {
	m.handlersLock.Lock()
	defer m.handlersLock.Unlock()

	key := generateKey(namespace, routeName)

	// Get the registered handler.
	ref, exists := m.registeredHandlers[key]
	if !exists {
		return fmt.Errorf("no handler registered with key %s", key)
	}

	// Remove the corresponding secret event handler from the secret monitor.
	klog.V(5).Info("trying to remove handler with key", key)
	err := m.monitor.RemoveSecretEventHandler(ref.handlerRegistration)
	if err != nil {
		return err
	}

	// delete the registered handler from manager's map of handlers.
	delete(m.registeredHandlers, key)
	klog.Infof("secret manager unregistered route for key %s", key)

	return nil
}

// GetSecret retrieves the secret object registered with a route.
func (m *manager) GetSecret(ctx context.Context, namespace, routeName string) (*v1.Secret, error) {
	m.handlersLock.RLock()
	defer m.handlersLock.RUnlock()

	key := generateKey(namespace, routeName)

	ref, exists := m.registeredHandlers[key]
	if !exists {
		return nil, fmt.Errorf("no handler registered with key %s", key)
	}

	// Get the secret from the secret monitor's cache using the registered handler.
	obj, err := m.monitor.GetSecret(ctx, ref.handlerRegistration)
	if err != nil {
		return nil, err
	}

	return obj, nil
}

// LookupRouteSecret returns the secret name associated with a route,
// and true indicating if the route is registered with manager.
// If the route is not registered, an empty string and false are returned.
func (m *manager) LookupRouteSecret(namespace, routeName string) (string, bool) {
	m.handlersLock.RLock()
	defer m.handlersLock.RUnlock()

	key := generateKey(namespace, routeName)
	ref, exists := m.registeredHandlers[key]
	if !exists {
		return "", false
	}
	return ref.secretName, true
}

// generateKey creates a unique identifier for a route
func generateKey(namespace, route string) string {
	return fmt.Sprintf("%s/%s", namespace, route)
}
