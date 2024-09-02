package resourcehelper

import (
	"errors"
	"testing"

	v1 "k8s.io/api/core/v1"
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
		{
			name:                 "nil-with-error",
			object:               nil,
			err:                  testErr,
			expectedEventReason:  "<unknown>CreateFailed",
			expectedEventMessage: "Failed to create <unknown>/<unknown> -n <unknown>: test",
		},
		{
			name:                 "empty-pointer-with-error",
			object:               &v1.Secret{},
			err:                  testErr,
			expectedEventReason:  "SecretCreateFailed",
			expectedEventMessage: "Failed to create Secret/: test",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := events.NewInMemoryRecorder("test")
			ReportCreateEvent(recorder, test.object, test.err)
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
		object               runtime.Object
		err                  error
		details              string
		expectedEventMessage string
		expectedEventReason  string
	}{
		{
			name:                 "pod-with-error",
			object:               &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "podName"}},
			err:                  testErr,
			expectedEventReason:  "PodUpdateFailed",
			expectedEventMessage: "Failed to update Pod/podName: test",
		},
		{
			name:                 "pod-with-namespace",
			object:               &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "podName", Namespace: "nsName"}},
			err:                  testErr,
			expectedEventReason:  "PodUpdateFailed",
			expectedEventMessage: "Failed to update Pod/podName -n nsName: test",
		},
		{
			name:                 "pod-without-error",
			object:               &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "podName"}},
			expectedEventReason:  "PodUpdated",
			expectedEventMessage: "Updated Pod/podName because it changed",
		},
		{
			name:                 "pod-with-namespace-without-error",
			object:               &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "podName", Namespace: "nsName"}},
			expectedEventReason:  "PodUpdated",
			expectedEventMessage: "Updated Pod/podName -n nsName because it changed",
		},
		{
			name:                 "pod-with-details-without-error",
			object:               &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "podName"}},
			details:              "because reasons",
			expectedEventReason:  "PodUpdated",
			expectedEventMessage: "Updated Pod/podName:\nbecause reasons",
		},
		{
			name:                 "pod-with-namespace-and-details--without-error",
			object:               &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "podName", Namespace: "nsName"}},
			details:              "because reasons",
			expectedEventReason:  "PodUpdated",
			expectedEventMessage: "Updated Pod/podName -n nsName:\nbecause reasons",
		},
		{
			name:                 "nil-with-error",
			object:               nil,
			err:                  testErr,
			expectedEventReason:  "<unknown>UpdateFailed",
			expectedEventMessage: "Failed to update <unknown>/<unknown> -n <unknown>: test",
		},
		{
			name:                 "empty-pointer-with-error",
			object:               &v1.Secret{},
			err:                  testErr,
			expectedEventReason:  "SecretUpdateFailed",
			expectedEventMessage: "Failed to update Secret/: test",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := events.NewInMemoryRecorder("test")
			if len(test.details) == 0 {
				ReportUpdateEvent(recorder, test.object, test.err)
			} else {
				ReportUpdateEvent(recorder, test.object, test.err, test.details)
			}
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

func TestReportDeleteEvent(t *testing.T) {
	testErr := errors.New("test")
	tests := []struct {
		name                 string
		object               runtime.Object
		err                  error
		details              string
		expectedEventMessage string
		expectedEventReason  string
	}{
		{
			name:                 "pod-with-error",
			object:               &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "podName"}},
			err:                  testErr,
			expectedEventReason:  "PodDeleteFailed",
			expectedEventMessage: "Failed to delete Pod/podName: test",
		},
		{
			name:                 "pod-with-namespace",
			object:               &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "podName", Namespace: "nsName"}},
			err:                  testErr,
			expectedEventReason:  "PodDeleteFailed",
			expectedEventMessage: "Failed to delete Pod/podName -n nsName: test",
		},
		{
			name:                 "pod-without-error",
			object:               &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "podName"}},
			expectedEventReason:  "PodDeleted",
			expectedEventMessage: "Deleted Pod/podName",
		},
		{
			name:                 "pod-with-namespace-without-error",
			object:               &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "podName", Namespace: "nsName"}},
			expectedEventReason:  "PodDeleted",
			expectedEventMessage: "Deleted Pod/podName -n nsName",
		},
		{
			name:                 "pod-with-details-without-error",
			object:               &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "podName"}},
			details:              "because reasons",
			expectedEventReason:  "PodDeleted",
			expectedEventMessage: "Deleted Pod/podName:\nbecause reasons",
		},
		{
			name:                 "pod-with-namespace-and-details--without-error",
			object:               &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "podName", Namespace: "nsName"}},
			details:              "because reasons",
			expectedEventReason:  "PodDeleted",
			expectedEventMessage: "Deleted Pod/podName -n nsName:\nbecause reasons",
		},
		{
			name:                 "nil-with-error",
			object:               nil,
			err:                  testErr,
			expectedEventReason:  "<unknown>DeleteFailed",
			expectedEventMessage: "Failed to delete <unknown>/<unknown> -n <unknown>: test",
		},
		{
			name:                 "empty-pointer-with-error",
			object:               &v1.Secret{},
			err:                  testErr,
			expectedEventReason:  "SecretDeleteFailed",
			expectedEventMessage: "Failed to delete Secret/: test",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := events.NewInMemoryRecorder("test")
			if len(test.details) == 0 {
				ReportDeleteEvent(recorder, test.object, test.err)
			} else {
				ReportDeleteEvent(recorder, test.object, test.err, test.details)
			}
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
