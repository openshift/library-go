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
		name          string
		syncContext   SyncContext
		queueKeysFunc ObjectQueueKeysFunc
		filterFunc    func(obj interface{}) bool
		// event handler test

		runEventHandlers  func(cache.ResourceEventHandler)
		evalQueueItems    func(*threadSafeStringSet, *testing.T)
		expectedItemCount int
		// func (c syncContext) eventHandler(queueKeyFunc ObjectQueueKeyFunc, interestingNamespaces sets.String) cache.ResourceEventHandler {

	}{
		{
			name:        "simple event handler",
			syncContext: NewSyncContext("test", eventstesting.NewTestingEventRecorder(t)),
			queueKeysFunc: func(object runtime.Object) []string {
				m, _ := meta.Accessor(object)
				return []string{fmt.Sprintf("%s/%s", m.GetNamespace(), m.GetName())}
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
			queueKeysFunc: func(object runtime.Object) []string {
				m, _ := meta.Accessor(object)
				return []string{m.GetName()}
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
			queueKeysFunc: func(object runtime.Object) []string {
				m, _ := meta.Accessor(object)
				return []string{m.GetName()}
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
			queueKeysFunc: func(object runtime.Object) []string {
				m, _ := meta.Accessor(object)
				return []string{fmt.Sprintf("%s/%s", m.GetNamespace(), m.GetName())}
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
			handler := test.syncContext.(syncContext).eventHandler(test.queueKeysFunc, test.filterFunc)
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
