// Package multidialer implements a connection dialer that is able to connect
// to different apiserver to provide HA.

// This is used for bootstrapping components, since the apiserver Service is not
// present, the client-go can connect to one apiserver, and if it is down, try
// to connect to the next available one.

// This is a simple mechanism to provide HA without relying on external components.
// It doesn't provide load balancing or any other advanced features, if a connection
// fails it just simple try with the next server in the pool.
// The retry logic is kept on the clients.
package multidialer

import (
	"context"
	"net"
	"time"

	"k8s.io/client-go/kubernetes"
)

const apiServerPort = "6443"

// DialFunc is a shorthand for signature of net.DialContext.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// Dialer opens connections through Dial.
// It iterates over a list of hosts that can be updated externally until it succeeds.
type Dialer struct {
	dial     DialFunc
	resolver *resolver
}

// NewDialer creates a new Dialer instance.
func NewDialer(dial DialFunc) *Dialer {
	if dial == nil {
		dial = (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 15 * time.Second}).DialContext
	}
	return NewDialerWithAlternateHosts(dial, []string{})
}

// NewDialerWithAlternateHosts creates a new Dialer instance.
// If dial is not nil, it will be used to create new underlying connections.
// Otherwise net.DialContext is used.
// If alternateHosts is not nil, it will be used to retry failed connections.
func NewDialerWithAlternateHosts(dial DialFunc, alternateHosts []string) *Dialer {
	return &Dialer{
		dial:     dial,
		resolver: NewResolver(alternateHosts),
	}
}

// Dial creates a new tracked connection.
func (d *Dialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

// DialContext creates a new connection trying to connect serially over the list of ready hosts in the pool
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	for _, host := range d.resolver.listReady() {
		conn, err := d.dial(ctx, network, net.JoinHostPort(host, apiServerPort))
		if err == nil {
			// connection working, record the host
			// so we can use it the next time
			d.resolver.setLast(host)
			return conn, nil
		}

	}
	return d.dial(ctx, network, address)
}

func (d *Dialer) Start(ctx context.Context, clientset kubernetes.Interface) {
	d.resolver.start(ctx, clientset)
}
