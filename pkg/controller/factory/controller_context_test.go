package factory

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"

	"github.com/openshift/library-go/pkg/operator/events/eventstesting"
)

type threadSafeStringSet struct {
	sets.String
	sync.Mutex
}

func newThreadSafeStringSet() *threadSafeStringSet {
	return &threadSafeStringSet{
		String: sets.NewString(),
	}
}

func (s *threadSafeStringSet) Len() int {
	s.Lock()
	defer s.Unlock()
	return s.String.Len()
}

func (s *threadSafeStringSet) Insert(items ...string) *threadSafeStringSet {
	s.Lock()
	defer s.Unlock()
	s.String.Insert(items...)
	return s
}

func TestSyncContext_eventHandler(t *testing.T) {
	tests := []struct {
		name         string
		syncContext  SyncContext
		queueKeyFunc ObjectQueueKeyFunc
		filterFunc   func(obj interface{}) bool
		// event handler test

		runEventHandlers  func(cache.ResourceEventHandler)
		evalQueueItems    func(*threadSafeStringSet, *testing.T)
		expectedItemCount int
		// func (c syncContext) eventHandler(queueKeyFunc ObjectQueueKeyFunc, interestingNamespaces sets.String) cache.ResourceEventHandler {

	}{
		{
			name:        "simple event handler",
			syncContext: NewSyncContext("test", eventstesting.NewTestingEventRecorder(t)),
			queueKeyFunc: func(object runtime.Object) string {
				m, _ := meta.Accessor(object)
				return fmt.Sprintf("%s/%s", m.GetNamespace(), m.GetName())
			},
			runEventHandlers: func(handler cache.ResourceEventHandler) {
				handler.OnAdd(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "foo", Name: "add"}})
				handler.OnUpdate(nil, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "foo", Name: "update"}})
				handler.OnDelete(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "foo", Name: "delete"}})
			},
			expectedItemCount: 3,
			evalQueueItems: func(s *threadSafeStringSet, t *testing.T) {
				expect := []string{"add", "update", "delete"}
				for _, e := range expect {
					if !s.Has("foo/" + e) {
						t.Errorf("expected %#v to has 'foo/%s'", s.List(), e)
					}
				}
			},
		},
		{
			name:        "namespace event handler",
			syncContext: NewSyncContext("test", eventstesting.NewTestingEventRecorder(t)),
			queueKeyFunc: func(object runtime.Object) string {
				m, _ := meta.Accessor(object)
				return m.GetName()
			},
			filterFunc: namespaceChecker([]string{"add"}),
			runEventHandlers: func(handler cache.ResourceEventHandler) {
				handler.OnAdd(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "add"}})
				handler.OnUpdate(nil, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "update"}})
				handler.OnDelete(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "delete"}})
			},
			expectedItemCount: 1,
			evalQueueItems: func(s *threadSafeStringSet, t *testing.T) {
				if !s.Has("add") {
					t.Errorf("expected %#v to has only 'add'", s.List())
				}
			},
		},
		{
			name:        "namespace from tombstone event handler",
			syncContext: NewSyncContext("test", eventstesting.NewTestingEventRecorder(t)),
			queueKeyFunc: func(object runtime.Object) string {
				m, _ := meta.Accessor(object)
				return m.GetName()
			},
			filterFunc: namespaceChecker([]string{"delete"}),
			runEventHandlers: func(handler cache.ResourceEventHandler) {
				handler.OnDelete(cache.DeletedFinalStateUnknown{
					Obj: &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "delete"}},
				})
			},
			expectedItemCount: 1,
			evalQueueItems: func(s *threadSafeStringSet, t *testing.T) {
				if !s.Has("delete") {
					t.Errorf("expected %#v to has only 'add'", s.List())
				}
			},
		},
		{
			name:        "annotated secret event handler",
			syncContext: NewSyncContext("test", eventstesting.NewTestingEventRecorder(t)),
			filterFunc: func(object interface{}) bool {
				obj, ok := object.(runtime.Object)
				if !ok {
					return false
				}
				m, _ := meta.Accessor(obj)
				_, ok = m.GetAnnotations()["onlyFireWhenSet"]
				return ok
			},
			queueKeyFunc: func(object runtime.Object) string {
				m, _ := meta.Accessor(object)
				return fmt.Sprintf("%s/%s", m.GetNamespace(), m.GetName())
			},
			runEventHandlers: func(handler cache.ResourceEventHandler) {
				handler.OnAdd(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "foo", Name: "add"}})
				handler.OnUpdate(nil, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "foo", Name: "update"}})
				handler.OnDelete(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "foo", Name: "delete"}})

				handler.OnAdd(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "bar", Name: "add", Annotations: map[string]string{"onlyFireWhenSet": "do it"}}})
				handler.OnUpdate(nil, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "bar", Name: "update", Annotations: map[string]string{"onlyFireWhenSet": "do it"}}})
				handler.OnDelete(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "bar", Name: "delete", Annotations: map[string]string{"onlyFireWhenSet": "do it"}}})
			},
			expectedItemCount: 3,
			evalQueueItems: func(s *threadSafeStringSet, t *testing.T) {
				expect := []string{"add", "update", "delete"}
				for _, e := range expect {
					if !s.Has("bar/" + e) {
						t.Errorf("expected %#v to have 'bar/%s'", s.List(), e)
					}
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := test.syncContext.(syncContext).eventHandler(test.queueKeyFunc, test.filterFunc)
			itemsReceived := newThreadSafeStringSet()
			queueCtx, shutdown := context.WithCancel(context.Background())
			c := &baseController{
				syncContext: test.syncContext,
				sync: func(ctx context.Context, controllerContext SyncContext) error {
					itemsReceived.Insert(controllerContext.QueueKey())
					return nil
				},
			}
			go c.runWorker(queueCtx)

			// simulate events coming from informer
			test.runEventHandlers(handler)

			// wait for expected items to be processed
			if err := wait.PollImmediate(10*time.Millisecond, 10*time.Second, func() (done bool, err error) {
				return itemsReceived.Len() == test.expectedItemCount, nil
			}); err != nil {
				t.Errorf("%w (received: %#v)", err, itemsReceived.List())
				shutdown()
				return
			}

			// stop the worker
			shutdown()

			if itemsReceived.Len() != test.expectedItemCount {
				t.Errorf("expected %d items received, got %d (%#v)", test.expectedItemCount, itemsReceived.Len(), itemsReceived.List())
			}
			// evaluate items received
			test.evalQueueItems(itemsReceived, t)
		})
	}
}

func TestSyncContext_isInterestingNamespace(t *testing.T) {
	tests := []struct {
		name              string
		obj               interface{}
		namespaces        []string
		expectInteresting bool
	}{
		{
			name:              "got interesting namespace",
			obj:               &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test"}},
			namespaces:        []string{"test"},
			expectInteresting: true,
		},
		{
			name:              "got non-interesting namespace",
			obj:               &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test"}},
			namespaces:        []string{"non-test"},
			expectInteresting: false,
		},
		{
			name: "got interesting namespace in tombstone",
			obj: cache.DeletedFinalStateUnknown{
				Obj: &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test"}},
			},
			namespaces:        []string{"test"},
			expectInteresting: true,
		},
		{
			name: "got secret in tombstone",
			obj: cache.DeletedFinalStateUnknown{
				Obj: &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "test"}},
			},
			namespaces:        []string{"test"},
			expectInteresting: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := namespaceChecker(test.namespaces)
			isInteresting := c(test.obj)
			if !isInteresting && test.expectInteresting {
				t.Errorf("expected Namespace to be interesting, got false")
			}
			if isInteresting && !test.expectInteresting {
				t.Errorf("expected Namespace to not be interesting, got true")
			}
		})
	}
}

func TestSyncContextAddAfter(t *testing.T) {
	syncCtx := NewSyncContext("test context", eventstesting.NewTestingEventRecorder(t)).(syncContext)

	t.Log("Adding item when rate limiter is fresh")
	syncCtx.Queue().AddRateLimited(syncCtx.QueueKey())

	t.Log("Trying to saturate rate limiter until it takes more than 500ms")
	primeRL := func(target time.Duration) time.Duration {
		for {
			if d := syncCtx.rl.When(syncCtx.QueueKey()); d > target {
				return d
			}
		}
	}
	d := primeRL(500 * time.Millisecond)

	t.Log("Adding item in the far future")
	syncCtx.Queue().AddAfter(syncCtx.QueueKey(), time.Second*10)

	t.Log("Check that we get the item right away")
	before := time.Now()
	item, _ := syncCtx.Queue().Get()
	if passed := time.Now().Sub(before); passed > 500*time.Millisecond {
		t.Fatalf("item was in queue before rate-limiting, we should get it immediately, not after %v", passed)
	}
	syncCtx.Queue().Done(item)
	syncCtx.Queue().Forget(item)

	t.Log("Adding item after rate limiter is primed, check that we get it after the given time we primed the RL for")
	d = primeRL(500 * time.Millisecond)
	before = time.Now()
	syncCtx.Queue().AddRateLimited(syncCtx.QueueKey())
	item, _ = syncCtx.Queue().Get()
	if passed := time.Now().Sub(before); passed > 3*d {
		t.Fatalf("queue was primed for %v, we shouldn't wait longer than 3*%v, but had to wait %v", d, d, passed)
	} else if passed < d {
		t.Fatalf("queue was primed for %v and shouldn't get the item earlier, but it only took %v", d, passed)
	}
	syncCtx.Queue().Done(item)
	syncCtx.Queue().Forget(item)

	t.Log("Adding item in the far future and one in the near future after the rate limiter is primed")
	d = primeRL(250 * time.Millisecond)
	before = time.Now()
	syncCtx.Queue().AddAfter(syncCtx.QueueKey(), time.Second*1)
	syncCtx.Queue().AddAfter(syncCtx.QueueKey(), time.Second*10)
	item, _ = syncCtx.Queue().Get()
	if passed := time.Now().Sub(before); passed > time.Second*2 {
		t.Fatalf("item was added after 1s, queue was primed for only %v, we shouldn't wait longer than 2*1s, but had to wait %v", d, passed)
	} else if passed < time.Second {
		t.Fatalf("item added after 1s, we shouldn't get it early, but it only took %v", passed)
	}
	syncCtx.Queue().Done(item)
	syncCtx.Queue().Forget(item)

	t.Log("Adding item in the near future and one in the far future after the rate limiter is primed")
	d = primeRL(100 * time.Millisecond)
	before = time.Now()
	syncCtx.Queue().AddAfter(syncCtx.QueueKey(), time.Second*10) // doubling RL delay to at lest 200ms
	syncCtx.Queue().AddAfter(syncCtx.QueueKey(), time.Second*1)  // doubling RL delay to at lest 400ms
	item, _ = syncCtx.Queue().Get()
	if passed := time.Now().Sub(before); passed > time.Second*2 {
		t.Fatalf("item was added after 1s, queue was primed for only %v, we shouldn't wait longer than 2*1s, but had to wait %v", d, passed)
	} else if passed < time.Second {
		t.Fatalf("item added after 1s, we shouldn't get it early, but it only took %v", passed)
	}
	syncCtx.Queue().Done(item)
	syncCtx.Queue().Forget(item)
}
