package eventwatch

import (
	"context"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/openshift/library-go/pkg/operator/events"
)

func TestController(t *testing.T) {
	tests := []struct {
		name                 string
		handlers             []eventHandler
		sendEvents           func(recorder events.Recorder)
		expectedEventsKeys   []string
		expectedProcessCount int
		evalActions          func(t *testing.T, actions []ktesting.Action)
	}{
		{
			name: "got test reason",
			handlers: []eventHandler{
				{
					reason:    "TestReason",
					namespace: "test",
				},
			},
			sendEvents: func(recorder events.Recorder) {
				recorder.Warningf("TestReason", "Test")
			},
			expectedProcessCount: 1,
			expectedEventsKeys: []string{
				"test/name/TestReason",
			},
		},
		{
			name: "ignore other events",
			handlers: []eventHandler{
				{
					reason:    "TestReason",
					namespace: "test",
				},
			},
			sendEvents: func(recorder events.Recorder) {
				recorder.Warningf("TestReason", "Test")
				recorder.Warningf("OtherEvent", "Test")
			},
			expectedProcessCount: 1,
			expectedEventsKeys: []string{
				"test/name/TestReason",
			},
		},
		{
			name: "test reason event acknowledged",
			handlers: []eventHandler{
				{
					reason:    "TestReason",
					namespace: "test",
				},
			},
			sendEvents: func(recorder events.Recorder) {
				recorder.Warningf("TestReason", "Test")
				recorder.Warningf("TestReason", "Test")
				recorder.Warningf("TestReason", "Test")
			},
			expectedProcessCount: 1,
			expectedEventsKeys: []string{
				"test/name/TestReason",
			},
			evalActions: func(t *testing.T, actions []ktesting.Action) {
				acked := false
				for _, action := range actions {
					if action.GetVerb() == "update" {
						update := action.(ktesting.UpdateAction)
						event, ok := update.GetObject().(*corev1.Event)
						if ok && event.Reason == "TestReason" && event.Annotations != nil {
							_, acked = event.Annotations[eventAckAnnotationName]
						}
					}
				}
				if !acked {
					t.Errorf("expected event to be acknowledged")
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			eventProcessedChan := make(chan string)
			b := New()

			processCount := 0
			var processCountLock sync.Mutex
			for _, h := range test.handlers {
				b = b.WithEventHandler(h.namespace, h.reason, func(event *corev1.Event) error {
					defer func() {
						processCountLock.Lock()
						processCount++
						processCountLock.Unlock()
					}()
					var err error
					if h.process != nil {
						err = h.process(event)
					}
					key := eventKeyFunc(event.Namespace, "name", event.Reason) // name is random
					if key == "" {
						close(eventProcessedChan)
					}
					eventProcessedChan <- key
					return err
				})
			}

			kubeClient := fake.NewSimpleClientset()
			eventRecorder := events.NewRecorder(kubeClient.CoreV1().Events("test"), "test-operator", &corev1.ObjectReference{
				Namespace: "test",
			})
			informer := informers.NewSharedInformerFactoryWithOptions(kubeClient, 1*time.Minute, informers.WithNamespace("test"))

			controller := b.ToController(informer, kubeClient.CoreV1(), eventRecorder)

			ctx, shutdown := context.WithCancel(context.Background())
			defer shutdown()

			informer.Start(ctx.Done())
			go controller.Run(ctx, 1)

			test.sendEvents(eventRecorder)

			recvKeys := sets.NewString()
			finish := false
			for !finish {
				select {
				case eventKey := <-eventProcessedChan:
					recvKeys.Insert(eventKey)
					if len(test.expectedEventsKeys) == recvKeys.Len() {
						finish = true
						break
					}
				case <-time.After(30 * time.Second):
					t.Fatal("timeout")
				}
			}

			if !recvKeys.Equal(sets.NewString(test.expectedEventsKeys...)) {
				t.Errorf("received keys (%#v) does not have all expected keys: %#v", recvKeys.List(), test.expectedEventsKeys)
			}

			if test.evalActions != nil {
				test.evalActions(t, kubeClient.Actions())
			}
			if test.expectedProcessCount > 0 {
				processCountLock.Lock()
				if test.expectedProcessCount != processCount {
					t.Errorf("expected %d process() calls, got %d", test.expectedProcessCount, processCount)
				}
				processCountLock.Unlock()
			}

		})
	}
}
