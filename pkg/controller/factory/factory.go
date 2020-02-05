package factory

import (
	"time"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"

	"github.com/openshift/library-go/pkg/operator/events"
)

// Factory is generator that generate standard Kubernetes controllers.
// Factory is really generic and should be only used for simple controllers that does not require special stuff..
type Factory struct {
	sync                  SyncFunc
	syncContext           SyncContext
	resyncInterval        time.Duration
	objectQueue           bool
	informers             []Informer
	namespaceInformers    []*namespaceInformer
	cachesToSync          []cache.InformerSynced
	interestingNamespaces sets.String
}

// Informer represents any structure that allow to register event handlers and informs if caches are synced.
// Any SharedInformer will comply.
type Informer interface {
	AddEventHandler(handler cache.ResourceEventHandler)
	HasSynced() bool
}

type namespaceInformer struct {
	informer   Informer
	namespaces sets.String
}

// New return new factory instance.
func New() *Factory {
	return &Factory{}
}

// Sync is used to set the controller synchronization function. This function is the core of the controller and is
// usually hold the main controller logic.
func (f *Factory) WithSync(syncFn SyncFunc) *Factory {
	f.sync = syncFn
	return f
}

// WithInformers is used to register event handlers and get the caches synchronized functions.
// Pass informers you want to use to react to changes on resources. If informer event is observed, then the Sync() function
// is called.
func (f *Factory) WithInformers(informers ...Informer) *Factory {
	f.informers = append(f.informers, informers...)
	return f
}

// WithNamespaceInformer is used to register event handlers and get the caches synchronized functions.
// The sync function will only trigger when the object observed by this informer is a namespace and its name matches the interestingNamespaces.
// Do not use this to register non-namespace informers.
func (f *Factory) WithNamespaceInformer(informer Informer, interestingNamespaces ...string) *Factory {
	f.namespaceInformers = append(f.namespaceInformers, &namespaceInformer{
		informer:   informer,
		namespaces: sets.NewString(interestingNamespaces...),
	})
	return f
}

// ResyncEvery will cause the Sync() function to be called periodically, regardless of informers.
// This is useful when you want to refresh every N minutes or you fear that your informers can be stucked.
// If this is not called, no periodical resync will happen.
// Note: The controller context passed to Sync() function in this case does not contain the object metadata or object itself.
//       This can be used to detect periodical resyncs, but normal Sync() have to be cautious about `nil` objects.
func (f *Factory) ResyncEvery(interval time.Duration) *Factory {
	f.resyncInterval = interval
	return f
}

// WithRuntimeObject cause the factory to produce controller that pass the runtime.Object from event handler that was
// triggered to queue (instead of requeue using simple string key). This allow to access this object, however storing
// object in queue might increase memory usage (?).
func (f *Factory) WithRuntimeObject() *Factory {
	f.objectQueue = true
	return f
}

// WithSyncContext allows to specify custom, existing sync context for this factory.
// This is useful during unit testing where you can override the default event recorder or mock the runtime objects.
// If this function not called, a SyncContext is created by the factory automatically.
func (f *Factory) WithSyncContext(ctx SyncContext) *Factory {
	f.syncContext = ctx
	return f
}

// Controller produce a runnable controller.
func (f *Factory) ToController(name string, eventRecorder events.Recorder) Controller {
	if f.sync == nil {
		panic("Sync() function must be called before making controller")
	}

	var ctx SyncContext
	if f.syncContext != nil {
		ctx = f.syncContext
	} else {
		ctx = NewSyncContext(name, eventRecorder)
	}

	c := &baseController{
		name:        name,
		sync:        f.sync,
		resyncEvery: f.resyncInterval,
		syncContext: ctx,
	}

	for i := range f.informers {
		f.informers[i].AddEventHandler(c.syncContext.(syncContext).eventHandler(QueueKey(name), f.objectQueue, sets.NewString()))
		c.cachesToSync = append(f.cachesToSync, f.informers[i].HasSynced)
	}

	for i := range f.namespaceInformers {
		f.namespaceInformers[i].informer.AddEventHandler(c.syncContext.(syncContext).eventHandler(QueueKey(name), f.objectQueue, f.namespaceInformers[i].namespaces))
		c.cachesToSync = append(f.cachesToSync, f.informers[i].HasSynced)
	}

	return c
}
