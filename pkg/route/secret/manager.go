package secret

import (
	"fmt"
	"sync"
	"time"

	routev1 "github.com/openshift/api/route/v1"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

// this looks somewhat confused, I'm not sure this layer is necessary.  Given a SecretMonitor and a controller
// that observes Routes, it seems as though you'd simply wire handles to trigger evaluation for the route in question
// and eventhandler for that controller would do the diff/deletion on its own.
// If you have a sample controller I can help there
type Monitor interface {
	// Get secret by secret namespace and name.
	GetSecret(namespace, name string) (*v1.Secret, error)

	// WARNING: Register/UnregisterRoute functions should be efficient,
	// i.e. should not block on network operations.

	// RegisterRoute registers all secrets from a given Route.
	RegisterRoute(*routev1.Route, func(*routev1.Route) sets.String)

	// UnregisterRoute unregisters secrets from a given Route that are not
	// used by any other registered Route.
	UnregisterRoute(*routev1.Route, func(*routev1.Route) sets.String)
}

// SecretMonitor keeps a store with secrets necessary
// for registered routes.
type Manager struct {
	monitor            SecretMonitor
	registeredHandlers map[string]SecretEventHandlerRegistration

	lock sync.RWMutex

	stopCh <-chan struct{}

	// monitors are the producer of the resourceChanges queue
	resourceChanges workqueue.RateLimitingInterface

	secretHandler cache.ResourceEventHandlerFuncs
}

func NewRouteManager(kubeClient *kubernetes.Clientset, queue workqueue.RateLimitingInterface) *Manager {
	return &Manager{
		monitor:            NewSecretMonitor(kubeClient),
		lock:               sync.RWMutex{},
		stopCh:             make(<-chan struct{}),
		resourceChanges:    queue,
		registeredHandlers: make(map[string]SecretEventHandlerRegistration),

		// default secret handler
		secretHandler: cache.ResourceEventHandlerFuncs{
			AddFunc:    func(obj interface{}) {},
			UpdateFunc: func(oldObj, newObj interface{}) {},
			DeleteFunc: func(obj interface{}) {},
		},
	}
}

func (m *Manager) WithSecretHandler(handler cache.ResourceEventHandlerFuncs) *Manager {
	m.secretHandler = handler
	return m
}

func (m *Manager) GetSecret(parent *routev1.Route, namespace, name string) (*v1.Secret, error) {
	key := fmt.Sprintf("%s/%s", parent.Namespace, parent.Name)
	gr := appsv1.Resource("secret")

	m.lock.RLock()
	handle, exists := m.registeredHandlers[key]
	m.lock.RUnlock()

	if !exists {
		return nil, fmt.Errorf("object %q/%q not registered", namespace, name)
	}

	if err := wait.PollImmediate(10*time.Millisecond, time.Second, func() (done bool, err error) { return handle.HasSynced(), nil }); err != nil {
		return nil, fmt.Errorf("failed to sync %s cache: %v", gr.String(), err)
	}

	obj, err := m.monitor.GetSecret(handle)
	if err != nil {
		return nil, err
	}

	return obj, nil
}

func (m *Manager) RegisterRoute(parent *routev1.Route, getReferencedObjects func(*routev1.Route) sets.String) {
	// TODO refactor later
	// names := getReferencedObjects(parent)

	m.lock.Lock()
	defer m.lock.Unlock()

	// TODO iterate refererenced objects if we have 1-many mappings between route and secrets
	// TODO hard coded to test since externalCertificate is TP
	handle, err := m.monitor.AddEventHandler(parent.Namespace, fmt.Sprintf("%s_%s", parent.Name, "dummy-secret"), m.secretHandler)
	if err != nil {
		// TODO handle errors, sig change
	}

	key := fmt.Sprintf("%s/%s", parent.Namespace, parent.Name)
	m.registeredHandlers[key] = handle

}

func (m *Manager) UnregisterRoute(parent *routev1.Route, getReferencedObjects func(*routev1.Route) sets.String) {
	key := fmt.Sprintf("%s/%s", parent.Namespace, parent.Name)

	m.lock.Lock()
	defer m.lock.Unlock()

	handle, ok := m.registeredHandlers[key]
	if !ok {
		// TODO handle errors, sig change
	}

	err := m.monitor.RemoveEventHandler(handle)
	if err != nil {
		// TODO handle errors, sig change
	}

	delete(m.registeredHandlers, key)
}
