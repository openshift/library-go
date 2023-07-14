package secret

import (
	"fmt"
	"sync"
	"time"

	routev1 "github.com/openshift/api/route/v1"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
)

type Manager struct {
	monitor            SecretMonitor
	registeredHandlers map[string]SecretEventHandlerRegistration

	lock sync.RWMutex

	// monitors are the producer of the resourceChanges queue
	resourceChanges workqueue.RateLimitingInterface

	secretHandler cache.ResourceEventHandlerFuncs
}

func NewManager(kubeClient *kubernetes.Clientset, queue workqueue.RateLimitingInterface) *Manager {
	return &Manager{
		monitor:            NewSecretMonitor(kubeClient),
		lock:               sync.RWMutex{},
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
	m.lock.Lock()
	defer m.lock.Unlock()

	key := fmt.Sprintf("%s/%s", parent.Namespace, parent.Name)
	handle, exists := m.registeredHandlers[key]

	if !exists {
		return nil, apierrors.NewNotFound(schema.GroupResource{Resource: "routes"}, key)
	}

	if err := wait.PollImmediate(10*time.Millisecond, time.Second, func() (done bool, err error) { return handle.HasSynced(), nil }); err != nil {
		return nil, apierrors.NewInternalError(err)
	}

	obj, err := m.monitor.GetSecret(handle)
	if err != nil {
		return nil, err
	}

	return obj, nil
}

func (m *Manager) RegisterRoute(parent *routev1.Route, getReferencedObjects func(*routev1.Route) sets.String) error {
	// TODO refactor later
	// names := getReferencedObjects(parent)

	m.lock.Lock()
	defer m.lock.Unlock()

	// TODO hard coded to test since externalCertificate is TP
	handle, err := m.monitor.AddEventHandler(parent.Namespace, fmt.Sprintf("%s/%s", parent.Name, "dummy-secret"), m.secretHandler)
	if err != nil {
		return apierrors.NewInternalError(err)
	}

	key := fmt.Sprintf("%s/%s", parent.Namespace, parent.Name)
	m.registeredHandlers[key] = handle

	klog.Info("secret manager registered route", " route", key)

	return nil

}

func (m *Manager) UnregisterRoute(parent *routev1.Route, getReferencedObjects func(*routev1.Route) sets.String) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	key := fmt.Sprintf("%s/%s", parent.Namespace, parent.Name)
	handle, ok := m.registeredHandlers[key]
	if !ok {
		return apierrors.NewNotFound(schema.GroupResource{Resource: "routes"}, key)
	}

	err := m.monitor.RemoveEventHandler(handle)
	if err != nil {
		return apierrors.NewNotFound(schema.GroupResource{Resource: "routes"}, key)
	}

	delete(m.registeredHandlers, key)

	klog.Info("secret manager unregistered route", " route", key)

	return nil
}
