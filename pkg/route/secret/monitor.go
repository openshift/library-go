package secret

import (
	"sync"

	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
)

type objectKey struct {
	namespace string
	name      string
}

type Object struct {
	key      objectKey
	store    cache.Store
	informer cache.Controller

	// waitGroup is used to ensure that there won't be two concurrent calls to reflector.Run
	waitGroup sync.WaitGroup

	lock    sync.Mutex
	stopped bool
	stopCh  chan struct{}
}

func NewObject(key objectKey, informer cache.Controller, store cache.Store) *Object {
	return &Object{
		key:      key,
		informer: informer,
		store:    store,
		stopCh:   make(chan struct{}),
	}
}

func (i *Object) Stop() bool {
	i.lock.Lock()
	defer i.lock.Unlock()
	return i.stopThreadUnsafe()
}

func (i *Object) stopThreadUnsafe() bool {
	if i.stopped {
		return false
	}
	i.stopped = true
	close(i.stopCh)
	return true
}

func (i *Object) HasSynced() bool {
	return i.informer.HasSynced()
}

func (c *Object) GetByKey(name string) (interface{}, bool, error) {
	return c.store.GetByKey(name)
}

func (c *Object) GetKey() objectKey {
	return c.key
}

// key returns key of an object with a given name and namespace.
// This has to be in-sync with cache.MetaNamespaceKeyFunc.
func (c *Object) Key(namespace, name string) string {
	if len(namespace) > 0 {
		return namespace + "/" + name
	}
	return name
}

func (i *Object) StartInformer() {
	i.waitGroup.Wait()
	i.waitGroup.Add(1)
	defer i.waitGroup.Done()
	klog.Info("starting informer")
	i.informer.Run(i.stopCh)
}
