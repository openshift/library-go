package certrotation

import (
	"sync"

	"k8s.io/apimachinery/pkg/util/sets"
)

// HostnameSource supplies the DNS names and IP addresses a serving or peer
// certificate is valid for. It is consulted on every reconcile pass.
type HostnameSource interface {
	Hostnames() []string
}

// StaticHostnames returns a HostnameSource with a fixed hostname set.
func StaticHostnames(hostnames ...string) HostnameSource {
	return staticHostnames(sets.New(hostnames...).UnsortedList())
}

type staticHostnames []string

func (s staticHostnames) Hostnames() []string {
	return s
}

// DynamicHostnames is a thread-safe HostnameSource whose changes re-trigger
// the controllers using it. It replaces the DynamicServingRotation type that
// CKAO and MCO each carry a private copy of.
//
// Notification is non-blocking and coalescing: Set notifies subscribers only
// when the hostname set (compared order-insensitively) changed, and slow
// subscribers never block Set. Every subscriber gets its own channel via
// Subscribe, so two subscribers cannot steal each other's notifications.
type DynamicHostnames struct {
	lock        sync.RWMutex
	current     sets.Set[string]
	subscribers []chan struct{}
}

// NewDynamicHostnames creates an empty DynamicHostnames.
func NewDynamicHostnames() *DynamicHostnames {
	return &DynamicHostnames{
		current: sets.New[string](),
	}
}

// Hostnames returns the current hostname set.
func (d *DynamicHostnames) Hostnames() []string {
	d.lock.RLock()
	defer d.lock.RUnlock()
	return d.current.UnsortedList()
}

// Set stores the hostname set and notifies subscribers if the set changed
// (order-insensitive comparison). It reports whether a change occurred.
func (d *DynamicHostnames) Set(hostnames []string) (changed bool) {
	next := sets.New(hostnames...)
	d.lock.Lock()
	if d.current.Equal(next) {
		d.lock.Unlock()
		return false
	}
	d.current = next
	subscribers := make([]chan struct{}, len(d.subscribers))
	copy(subscribers, d.subscribers)
	d.lock.Unlock()

	for _, subscriber := range subscribers {
		select {
		case subscriber <- struct{}{}:
		default:
			// A notification is already pending; it will carry this change
			// too.
		}
	}
	return true
}

// Subscribe returns a notification channel that receives a value whenever
// the hostname set changes. Each subscriber gets its own coalescing channel
// (buffered size one), never closed.
func (d *DynamicHostnames) Subscribe() <-chan struct{} {
	d.lock.Lock()
	defer d.lock.Unlock()
	subscriber := make(chan struct{}, 1)
	d.subscribers = append(d.subscribers, subscriber)
	return subscriber
}
