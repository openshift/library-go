package proxyconfig

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/http/httpproxy"

	corev1listers "k8s.io/client-go/listers/core/v1"

	"github.com/openshift/library-go/pkg/network/httptransport"
)

const trustedCAKey = "ca-bundle.crt"

// ResolvedProxy holds the effective proxy configuration of a component.
type ResolvedProxy struct {
	HTTPProxy  string
	HTTPSProxy string
	// NoProxy is the list of NO_PROXY entries.
	NoProxy []string
	// TrustedCAName is the name of a ConfigMap holding the proxy trusted CA bundle
	// under the "ca-bundle.crt" key.
	TrustedCAName string
}

// IsProxyConfigured returns true when either HTTP or HTTPS proxy is set.
func (p ResolvedProxy) IsProxyConfigured() bool {
	return len(p.HTTPProxy) != 0 || len(p.HTTPSProxy) != 0
}

// ProxyFunc returns a function that resolves the proxy URL for a given request URL.
// A nil URL is returned from the function when the request should not be proxied.
func (p ResolvedProxy) ProxyFunc() func(*url.URL) (*url.URL, error) {
	c := httpproxy.Config{
		HTTPProxy:  p.HTTPProxy,
		HTTPSProxy: p.HTTPSProxy,
		NoProxy:    strings.Join(p.NoProxy, ","),
	}
	return c.ProxyFunc()
}

// ProxyResolver resolves the effective proxy configuration and builds
// pre-configured HTTP transports for outbound requests.
type ProxyResolver interface {
	// ResolveProxy resolves proxy configuration.
	ResolveProxy() (ResolvedProxy, error)

	// NewTransport returns an http.RoundTripper with proxy settings, the
	// proxy's trusted CA, and any additional options applied.
	//
	// The opts must be applied after the resolver's own options so that they take
	// precedence. In particular, httptransport.WithProxyFunc(nil) must disable the proxy,
	// the proxy config controller relies on it to probe endpoints directly.
	// NewTransport in this package satisfies this.
	NewTransport(opts ...httptransport.Option) (http.RoundTripper, error)
}

// NewTransport builds a round tripper for the given resolved proxy. The proxy trusted CA is loaded
// from the trustedCANamespace namespace, and the proxy function is set when a proxy is configured.
// The caller-supplied opts are applied last so they can override the resolved proxy configuration
// (e.g. httptransport.WithProxyFunc(nil) disables the proxy).
func NewTransport(
	cmLister corev1listers.ConfigMapLister,
	trustedCANamespace string,
	proxy ResolvedProxy,
	opts ...httptransport.Option,
) (http.RoundTripper, error) {
	var all []httptransport.Option
	if len(proxy.TrustedCAName) > 0 {
		proxyCA, err := loadCAData(cmLister, trustedCANamespace, proxy.TrustedCAName, trustedCAKey)
		if err != nil {
			return nil, err
		}
		all = append(all, httptransport.WithCAData(fmt.Sprintf("proxy trustedCA %q", proxy.TrustedCAName), proxyCA))
	}
	if proxy.IsProxyConfigured() {
		proxyFunc := proxy.ProxyFunc()
		all = append(all, httptransport.WithProxyFunc(func(req *http.Request) (*url.URL, error) { return proxyFunc(req.URL) }))
	}
	all = append(all, opts...)
	return httptransport.NewRoundTripper(all...)
}

// loadCAData reads CA bundle bytes from a ConfigMap. It checks Data first and falls back to BinaryData.
func loadCAData(cmLister corev1listers.ConfigMapLister, namespace, name, key string) ([]byte, error) {
	cm, err := cmLister.ConfigMaps(namespace).Get(name)
	if err != nil {
		return nil, fmt.Errorf("unable to get configmap \"%s/%s\": %w", namespace, name, err)
	}

	caData := []byte(cm.Data[key])
	if len(caData) == 0 {
		caData = cm.BinaryData[key]
	}
	if len(caData) == 0 {
		return nil, fmt.Errorf("configmap \"%s/%s\" has no CA data at key %q", namespace, name, key)
	}
	return caData, nil
}
