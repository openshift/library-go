package secret

import (
	"context"
	"fmt"
	"sync"

	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
)

// ObjectKey represents the unique identifier for a resource, used to access it in the cache.
type ObjectKey struct {
	// Namespace is the namespace in which the resource is located.
	Namespace string
	// Name denotes metadata.name of a resource being monitored by informer
	Name string
}

// singleItemMonitor monitors a single resource using a SharedInformer.
type singleItemMonitor struct {
	key      ObjectKey
	informer cache.SharedInformer
	lock     sync.Mutex
	stopped  bool
	stopCh   chan struct{}
}

// NewObjectKey creates a new ObjectKey for the given namespace and name.
func NewObjectKey(namespace, name string) ObjectKey {
	return ObjectKey{
		Namespace: namespace,
		Name:      name,
	}
}

// newSingleItemMonitor creates a new singleItemMonitor for the given key and informer.
func newSingleItemMonitor(key ObjectKey, informer cache.SharedInformer) *singleItemMonitor {
	return &singleItemMonitor{
		key:      key,
		informer: informer,
		stopped:  true,
		stopCh:   make(chan struct{}),
	}
}

// HasSynced returns true if the informer's cache has been successfully synced.
func (i *singleItemMonitor) HasSynced() bool {
	return i.informer.HasSynced()
}

// StartInformer starts and runs the informer util the provided context is canceled,
// or StopInformer() is called. It will block, so call via goroutine.
func (i *singleItemMonitor) StartInformer(ctx context.Context) {
	i.lock.Lock()

	if !i.stopped {
		klog.Warning("informer is already running")
		i.lock.Unlock()
		return
	}

	go func() {
		select {
		case <-ctx.Done():
			klog.Info("stopping informer due to context cancellation")
			if !i.StopInformer() {
				klog.Error("failed to stop informer")
			}
		// this case is required to exit from the goroutine
		// after normal StopInformer() call
		case <-i.stopCh:
			klog.Info("successfully stopped")
		}
	}()

	klog.Info("starting informer")
	i.stopped = false
	i.lock.Unlock()

	i.informer.Run(i.stopCh)
}

// StopInformer stops the informer.
// Retuns false if called twice, or before StartInformer(); true otherwise.
func (i *singleItemMonitor) StopInformer() bool {
	i.lock.Lock()
	defer i.lock.Unlock()

	if i.stopped {
		return false
	}
	i.stopped = true
	close(i.stopCh) // Signal the informer to stop
	klog.Info("informer stopped")
	return true
}

// AddEventHandler adds an event handler to the informer and returns
// secretEventHandlerRegistration after populating objectKey and registration.
func (i *singleItemMonitor) AddEventHandler(handler cache.ResourceEventHandler) (SecretEventHandlerRegistration, error) {
	i.lock.Lock()
	defer i.lock.Unlock()

	if i.stopped {
		return nil, fmt.Errorf("can not add handler %v to already stopped informer", handler)
	}

	registration, err := i.informer.AddEventHandler(handler)
	if err != nil {
		return nil, err
	}

	return &secretEventHandlerRegistration{
		ResourceEventHandlerRegistration: registration,
		objectKey:                        i.key,
	}, nil
}

// RemoveEventHandler removes an event handler from the informer.
func (i *singleItemMonitor) RemoveEventHandler(handle SecretEventHandlerRegistration) error {
	i.lock.Lock()
	defer i.lock.Unlock()

	if i.stopped {
		return fmt.Errorf("can not remove handler %v from stopped informer", handle.GetHandler())
	}

	return i.informer.RemoveEventHandler(handle.GetHandler())
}

// GetItem returns the accumulator being monitored
// by informer, using keyFunc (namespace/name).
func (i *singleItemMonitor) GetItem() (item interface{}, exists bool, err error) {
	keyFunc := i.key.Namespace + "/" + i.key.Name
	return i.informer.GetStore().GetByKey(keyFunc)
}
