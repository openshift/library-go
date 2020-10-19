package network

import (
	"net"
)

// DefaultClientDialer returns a network dialer with default options sets.
func DefaultClientDialer() *net.Dialer {
	return dialerWithDefaultOptions()
}
