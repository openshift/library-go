package monitor

import (
	"sync"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
)

type objectKey struct {
	namespace string
	name      string
	uid       types.UID
}

type Object struct {
	RefCount int
	store    cache.Store
	informer cache.Controller

	HasSynced func() (bool, error)

	// waitGroup is used to ensure that there won't be two concurrent calls to reflector.Run
	waitGroup sync.WaitGroup

	lock    sync.Mutex
	stopped bool
	stopCh  chan struct{}
}

func NewObject(informer cache.Controller, store cache.Store, hasSynced func() (bool, error), stopCh chan struct{}) *Object {
	return &Object{
		RefCount:  0,
		informer:  informer,
		store:     store,
		HasSynced: hasSynced,
		stopCh:    stopCh,
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

func (c *Object) IncrementRef() {
	c.RefCount++
}

func (c *Object) GetByKey(name string) (interface{}, bool, error) {
	return c.store.GetByKey(name)
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
	i.informer.Run(i.stopCh)
}
