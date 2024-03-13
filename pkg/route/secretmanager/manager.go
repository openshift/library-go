package secretmanager

import (
	"context"
	"fmt"
	"sync"

	"github.com/openshift/library-go/pkg/route/secret"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
)

type Manager struct {
	// monitor for managing and watching "single" secret dynamically.
	monitor secret.SecretMonitor

	// Map of registered handlers for each route.
	// Populated inside RegisterRoute() and used in UnregisterRoute(), GetSecret.
	// generateKey() will create the map key.
	registeredHandlers map[string]secret.SecretEventHandlerRegistration

	lock sync.RWMutex

	// Work queue to be used by the consumer of this Manager, mostly to add secret change events.
	queue workqueue.RateLimitingInterface

	// Event handler for secret changes.
	secretHandler cache.ResourceEventHandler
}

func NewManager(kubeClient kubernetes.Interface, queue workqueue.RateLimitingInterface) *Manager {
	return &Manager{
		monitor:            secret.NewSecretMonitor(kubeClient),
		lock:               sync.RWMutex{},
		queue:              queue,
		registeredHandlers: make(map[string]secret.SecretEventHandlerRegistration),
		secretHandler:      nil,
	}
}

// WithSecretHandler sets the secret event handler for the manager.
func (m *Manager) WithSecretHandler(handler cache.ResourceEventHandlerFuncs) *Manager {
	m.secretHandler = handler
	return m
}

// WithSecretMonitor sets the secret monitor for the manager.
func (m *Manager) WithSecretMonitor(sm secret.SecretMonitor) *Manager {
	m.monitor = sm
	return m
}

// Queue returns the work queue for the manager.
func (m *Manager) Queue() workqueue.RateLimitingInterface {
	return m.queue
}

// RegisterRoute registers a route with a secret, enabling the manager to watch for the secret changes and associate them with the handler functions.
// Returns error if route is already registered with a secret.
func (m *Manager) RegisterRoute(ctx context.Context, namespace, routeName, secretName string) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	// Generate a unique key for the provided namespace and routeName.
	key := generateKey(namespace, routeName)

	// Check if the route is already registered with the given key.
	// Each route (namespace/routeName) should be registered only once with any secret.
	// Note: inside a namespace multiple different routes can be registered(watch) with a common secret.
	if _, exists := m.registeredHandlers[key]; exists {
		return apierrors.NewInternalError(fmt.Errorf("route already registered with key %s", key))
	}

	// Add a secret event handler for the specified namespace and secret, with the handler functions.
	handlerRegistration, err := m.monitor.AddSecretEventHandler(ctx, namespace, secretName, m.secretHandler)
	if err != nil {
		return apierrors.NewInternalError(err)
	}

	// Store the registration in the manager's map. Used during UnregisterRoute() and GetSecret().
	m.registeredHandlers[key] = handlerRegistration
	klog.Info(fmt.Sprintf("secret manager registered route for key %s with secret %s", key, secretName))

	return nil
}

// UnregisterRoute removes the registration of a route from the manager.
// It removes the secret event handler from secret monitor and deletes its associated handler from manager's map.
func (m *Manager) UnregisterRoute(namespace, routeName string) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	key := generateKey(namespace, routeName)

	// Get the registered handler.
	handlerRegistration, exists := m.registeredHandlers[key]
	if !exists {
		return apierrors.NewInternalError(fmt.Errorf("no handler registered with key %s", key))
	}

	// Remove the corresponding secret event handler from the secret monitor.
	klog.V(3).Info("trying to remove handler with key", key)
	err := m.monitor.RemoveSecretEventHandler(handlerRegistration)
	if err != nil {
		return apierrors.NewInternalError(err)
	}

	// delete the registered handler from manager's map of handlers.
	delete(m.registeredHandlers, key)
	klog.Info("secret manager unregistered route ", key)

	return nil
}

// GetSecret retrieves the secret object registered with a route.
func (m *Manager) GetSecret(namespace, routeName string) (*v1.Secret, error) {
	m.lock.Lock()
	defer m.lock.Unlock()

	key := generateKey(namespace, routeName)

	handlerRegistration, exists := m.registeredHandlers[key]
	if !exists {
		return nil, apierrors.NewInternalError(fmt.Errorf("no handler registered with key %s", key))
	}

	// get secret from secrt monitor's cache using registered handler
	obj, err := m.monitor.GetSecret(handlerRegistration)
	if err != nil {
		return nil, err
	}

	return obj, nil
}

// IsRouteRegistered returns true if route is registered, false otherwise
func (m *Manager) IsRouteRegistered(namespace, routeName string) bool {
	key := generateKey(namespace, routeName)
	_, exists := m.registeredHandlers[key]
	return exists
}

// generateKey creates a unique identifier for a route
func generateKey(namespace, route string) string {
	return fmt.Sprintf("%s/%s", namespace, route)
}
