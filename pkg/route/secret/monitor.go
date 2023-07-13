package secret

import (
	"fmt"
	"sync"
	"sync/atomic"

	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
)

type ObjectKey struct {
	Namespace string
	Name      string
}

type singleItemMonitor struct {
	key      ObjectKey
	informer cache.SharedInformer

	lock        sync.Mutex
	numHandlers atomic.Int32
	stopped     bool
	stopCh      chan struct{}
}

func newSingleItemMonitor(key ObjectKey, informer cache.SharedInformer) *singleItemMonitor {
	return &singleItemMonitor{
		key:      key,
		informer: informer,
		stopCh:   make(chan struct{}),
	}
}

func (i *singleItemMonitor) Stop() bool {
	i.lock.Lock()
	defer i.lock.Unlock()
	if i.stopped {
		return false
	}
	i.stopped = true
	close(i.stopCh)
	return true
}

func (i *singleItemMonitor) StartInformer() {
	i.lock.Lock()
	defer i.lock.Unlock()
	klog.Info("starting informer")
	i.informer.Run(i.stopCh)
}

func (i *singleItemMonitor) AddEventHandler(handler cache.ResourceEventHandler) (SecretEventHandlerRegistration, error) {
	registration, err := i.informer.AddEventHandler(handler)
	if err != nil {
		return nil, err
	}
	i.numHandlers.Add(1)

	return &secretEventHandlerRegistration{
		ResourceEventHandlerRegistration: registration,
		objectKey:                        i.key,
	}, nil
}

func (i *singleItemMonitor) RemoveEventHandler(handle SecretEventHandlerRegistration) error {
	if err := i.informer.RemoveEventHandler(handle); err != nil {
		return err
	}
	i.numHandlers.Add(-1)
	return nil
}

func (i *singleItemMonitor) GetItem() (item interface{}, exists bool, err error) {
	return i.informer.GetStore().Get(fmt.Sprintf("%s/%s", i.key.Namespace, i.key.Name))
}
