package proxyconfig

import (
	"crypto/x509"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/openshift/library-go/pkg/network/httptransport"
)

// TestNewTransport_proxy checks that the transport routes requests through the resolved proxy, except for
// the hosts NO_PROXY covers, and that a caller option can disable the proxy.
func TestNewTransport_proxy(t *testing.T) {
	proxy := ResolvedProxy{HTTPSProxy: "http://proxy:3128", NoProxy: []string{"example.com"}}

	rt, err := NewTransport(proxy, newCMLister(t))
	require.NoError(t, err)
	proxyFunc := rt.(*http.Transport).Proxy
	require.NotNil(t, proxyFunc)

	proxyURL, err := proxyFunc(&http.Request{URL: mustParse(t, "https://other.org")})
	require.NoError(t, err)
	require.NotNil(t, proxyURL)
	require.Equal(t, "proxy:3128", proxyURL.Host)

	proxyURL, err = proxyFunc(&http.Request{URL: mustParse(t, "https://foo.example.com")})
	require.NoError(t, err)
	require.Nil(t, proxyURL, "an endpoint covered by NO_PROXY is not proxied")

	rt, err = NewTransport(proxy, newCMLister(t), httptransport.WithProxyFunc(nil))
	require.NoError(t, err)
	require.Nil(t, rt.(*http.Transport).Proxy, "WithProxyFunc(nil) should disable the configured proxy")
}

// TestNewTransport_TrustedCA checks how the proxy trusted CA is loaded: from the given namespace, added
// to the transport trust, and with errors that name the source.
func TestNewTransport_TrustedCA(t *testing.T) {
	proxy := ResolvedProxy{HTTPSProxy: "http://proxy:3128", TrustedCA: types.NamespacedName{Namespace: "openshift-config", Name: "proxy-ca"}}

	t.Run("configmap looked up in the given namespace", func(t *testing.T) {
		cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "other", Name: "proxy-ca"}}
		_, err := NewTransport(proxy, newCMLister(t, cm))
		require.ErrorContains(t, err, "openshift-config/proxy-ca")
	})

	t.Run("trusted CA without namespace", func(t *testing.T) {
		_, err := NewTransport(ResolvedProxy{TrustedCA: types.NamespacedName{Name: "proxy-ca"}}, newCMLister(t))
		require.ErrorContains(t, err, "has no namespace")
	})

	t.Run("configmap without CA data", func(t *testing.T) {
		cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "openshift-config", Name: "proxy-ca"}}
		_, err := NewTransport(proxy, newCMLister(t, cm))
		require.ErrorContains(t, err, "no CA data")
	})

	t.Run("trusted CA is added to the transport trust", func(t *testing.T) {
		caPEM := newTestCAPEM(t)
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Namespace: "openshift-config", Name: "proxy-ca"},
			Data:       map[string]string{trustedCAKey: string(caPEM)},
		}
		// An empty base pool keeps the system roots out of the way, so the pool holds just the proxy CA.
		rt, err := NewTransport(proxy, newCMLister(t, cm), httptransport.WithCertPool(x509.NewCertPool()))
		require.NoError(t, err)

		expected := x509.NewCertPool()
		require.True(t, expected.AppendCertsFromPEM(caPEM))
		require.True(t, expected.Equal(rt.(*http.Transport).TLSClientConfig.RootCAs), "the proxy trusted CA is not trusted by the transport")
	})

	t.Run("unparsable trusted CA names its source", func(t *testing.T) {
		cm := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Namespace: "openshift-config", Name: "proxy-ca"},
			Data:       map[string]string{trustedCAKey: "not a certificate"},
		}
		_, err := NewTransport(proxy, newCMLister(t, cm))
		require.ErrorContains(t, err, "proxy trustedCA")
		require.ErrorContains(t, err, "proxy-ca")
	})
}

func mustParse(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	require.NoError(t, err)
	return u
}

func newCMLister(t *testing.T, cms ...*corev1.ConfigMap) corev1listers.ConfigMapLister {
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	for _, cm := range cms {
		require.NoError(t, indexer.Add(cm))
	}
	return corev1listers.NewConfigMapLister(indexer)
}
