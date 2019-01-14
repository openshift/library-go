package resourceapply

import (
	"errors"
	"testing"

	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/openshift/library-go/pkg/operator/events"
)

func TestReportCreateEvent(t *testing.T) {
	testErr := errors.New("test")
	tests := []struct {
		name                 string
		object               runtime.Object
		err                  error
		expectedEventMessage string
		expectedEventReason  string
	}{
		{
			name:                 "pod-with-error",
			object:               &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "podName"}},
			err:                  testErr,
			expectedEventReason:  "PodCreateFailed",
			expectedEventMessage: "Failed to create Pod/podName: test",
		},
		{
			name:                 "pod-with-namespace",
			object:               &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "podName", Namespace: "nsName"}},
			err:                  testErr,
			expectedEventReason:  "PodCreateFailed",
			expectedEventMessage: "Failed to create Pod/podName -n nsName: test",
		},
		{
			name:                 "pod-without-error",
			object:               &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "podName"}},
			expectedEventReason:  "PodCreated",
			expectedEventMessage: "Created Pod/podName because it was missing",
		},
		{
			name:                 "pod-with-namespace-without-error",
			object:               &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "podName", Namespace: "nsName"}},
			expectedEventReason:  "PodCreated",
			expectedEventMessage: "Created Pod/podName -n nsName because it was missing",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := events.NewInMemoryRecorder("test")
			reportCreateEvent(recorder, test.object, test.err)
			recordedEvents := recorder.Events()

			if eventCount := len(recordedEvents); eventCount != 1 {
				t.Errorf("expected one event to be recorded, got %d", eventCount)
			}

			if recordedEvents[0].Message != test.expectedEventMessage {
				t.Errorf("expected one event message %q, got %q", test.expectedEventMessage, recordedEvents[0].Message)
			}

			if recordedEvents[0].Reason != test.expectedEventReason {
				t.Errorf("expected one event reason %q, got %q", test.expectedEventReason, recordedEvents[0].Reason)
			}
		})
	}
}

func TestReportUpdateEvent(t *testing.T) {
	testErr := errors.New("test")
	tests := []struct {
		name                 string
		required             runtime.Object
		before               runtime.Object
		after                runtime.Object
		err                  error
		expectedEventMessage string
		expectedEventReason  string
	}{
		{
			name:                 "pod-with-error",
			required:             &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "podName"}},
			err:                  testErr,
			expectedEventReason:  "PodUpdateFailed",
			expectedEventMessage: "Failed to update Pod/podName: test",
		},
		{
			name:                 "pod-with-namespace",
			required:             &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "podName", Namespace: "nsName"}},
			err:                  testErr,
			expectedEventReason:  "PodUpdateFailed",
			expectedEventMessage: "Failed to update Pod/podName -n nsName: test",
		},
		{
			name:                 "pod-without-error",
			required:             &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "podName"}, Spec: v1.PodSpec{ServiceAccountName: "after"}},
			before:               &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "podName"}, Spec: v1.PodSpec{ServiceAccountName: "before", NodeName: "node01"}},
			after:                &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "podName"}, Spec: v1.PodSpec{ServiceAccountName: "after", NodeName: "node01"}},
			expectedEventReason:  "PodUpdated",
			expectedEventMessage: "Updated Pod/podName because it changed:\n{\"metadata\":{\"name\":\"podName\",\"creationTimestamp\":null},\"spec\":{\"containers\":null,\"serviceAccountName\":\"\n\nA: before\",\"nodeName\":\"node01\"},\"status\":{}}\n\nB: after\",\"nodeName\":\"node01\"},\"status\":{}}\n\n",
		},
		{
			name:                 "pod-with-namespace-without-error",
			required:             &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "podName", Namespace: "nsName"}, Spec: v1.PodSpec{ServiceAccountName: "after"}},
			before:               &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "podName", Namespace: "nsName"}, Spec: v1.PodSpec{ServiceAccountName: "before", NodeName: "node01"}},
			after:                &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "podName", Namespace: "nsName"}, Spec: v1.PodSpec{ServiceAccountName: "after", NodeName: "node01"}},
			expectedEventReason:  "PodUpdated",
			expectedEventMessage: "Updated Pod/podName -n nsName because it changed:\n{\"metadata\":{\"name\":\"podName\",\"namespace\":\"nsName\",\"creationTimestamp\":null},\"spec\":{\"containers\":null,\"serviceAccountName\":\"\n\nA: before\",\"nodeName\":\"node01\"},\"status\":{}}\n\nB: after\",\"nodeName\":\"node01\"},\"status\":{}}\n\n",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := events.NewInMemoryRecorder("test")
			reportUpdateEvent(recorder, test.required, test.before, test.after, test.err)
			recordedEvents := recorder.Events()

			if eventCount := len(recordedEvents); eventCount != 1 {
				t.Errorf("expected one event to be recorded, got %d", eventCount)
			}

			if recordedEvents[0].Message != test.expectedEventMessage {
				t.Errorf("expected one event message %q, got %q", test.expectedEventMessage, recordedEvents[0].Message)
			}

			if recordedEvents[0].Reason != test.expectedEventReason {
				t.Errorf("expected one event reason %q, got %q", test.expectedEventReason, recordedEvents[0].Reason)
			}
		})
	}
}
