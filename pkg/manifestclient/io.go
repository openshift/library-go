package manifestclient

import (
	"bytes"
	"encoding/json"
	"io"
	"sync/atomic"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/watch"
)

func newDelayedNothingReader(timeout time.Duration) *delayedNothingReaderCloser {
	return &delayedNothingReaderCloser{timeout: timeout}
}

type delayedNothingReaderCloser struct {
	timeout time.Duration
	closed  atomic.Bool
}

func (d *delayedNothingReaderCloser) Read(p []byte) (n int, err error) {
	if d.closed.Load() {
		return 0, io.EOF
	}
	select {
	case <-time.After(d.timeout):
		d.Close()
	}
	if d.closed.Load() {
		return 0, io.EOF
	}
	return 0, nil
}

func (d *delayedNothingReaderCloser) Close() error {
	d.closed.Store(true)
	return nil
}

var _ io.ReadCloser = &delayedNothingReaderCloser{}

// newWatchStreamWithInitialEvents creates a reader that sends initial events from a list,
// followed by a BOOKMARK event, then keeps the connection alive for the timeout duration.
// This implements the sendInitialEvents=true behavior for the WatchList feature (KEP-3157).
// This is required in 1.35+ as WatchList is enabled by default.
func newWatchStreamWithInitialEvents(listBody []byte, timeout time.Duration) io.ReadCloser {
	var buf bytes.Buffer

	var list unstructured.UnstructuredList
	if err := json.Unmarshal(listBody, &list); err != nil {
		errorEvent := watch.Event{
			Type: watch.Error,
			Object: &metav1.Status{
				Status:  metav1.StatusFailure,
				Message: err.Error(),
				Reason:  metav1.StatusReasonInternalError,
				Code:    500,
			},
		}
		json.NewEncoder(&buf).Encode(errorEvent)
		return &watchStreamReader{
			initialEvents: buf.Bytes(),
			timeout:       timeout,
		}
	}

	// Convert each item to an ADDED watch event
	for i := range list.Items {
		event := watch.Event{
			Type:   watch.Added,
			Object: &list.Items[i],
		}
		json.NewEncoder(&buf).Encode(event)
	}

	// Add a BOOKMARK event to signal the end of initial events
	resourceVersion := list.GetResourceVersion()
	if resourceVersion == "" {
		resourceVersion = "0"
	}

	bookmark := watch.Event{
		Type: watch.Bookmark,
		Object: &metav1.Status{
			TypeMeta: metav1.TypeMeta{
				Kind:       list.GetKind(),
				APIVersion: list.GetAPIVersion(),
			},
			ListMeta: metav1.ListMeta{
				ResourceVersion: resourceVersion,
			},
		},
	}
	json.NewEncoder(&buf).Encode(bookmark)

	return &watchStreamReader{
		initialEvents: buf.Bytes(),
		timeout:       timeout,
	}
}

// watchStreamReader reads initial watch events, then keeps the connection alive
type watchStreamReader struct {
	initialEvents []byte
	offset        int
	timeout       time.Duration
	closed        atomic.Bool
}

func (w *watchStreamReader) Read(p []byte) (n int, err error) {
	if w.closed.Load() {
		return 0, io.EOF
	}

	if w.offset < len(w.initialEvents) {
		n = copy(p, w.initialEvents[w.offset:])
		w.offset += n
		return n, nil
	}

	select {
	case <-time.After(w.timeout):
		w.Close()
	}
	if w.closed.Load() {
		return 0, io.EOF
	}
	return 0, nil
}

func (w *watchStreamReader) Close() error {
	w.closed.Store(true)
	return nil
}

var _ io.ReadCloser = &watchStreamReader{}
