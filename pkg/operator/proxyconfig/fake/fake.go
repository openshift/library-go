// Package fake provides test helpers for the proxyconfig package.
package fake

import (
	"github.com/openshift/library-go/pkg/operator/proxyconfig"
)

// ProxyResolver is a test helper implementing proxyconfig.ProxyResolver.
type ProxyResolver struct {
	Proxy proxyconfig.ResolvedProxy
	Err   error
}

var _ proxyconfig.ProxyResolver = &ProxyResolver{}

func (f *ProxyResolver) ResolveProxy() (proxyconfig.ResolvedProxy, error) {
	return f.Proxy, f.Err
}
