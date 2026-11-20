package proxyconfig

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/openshift/library-go/pkg/network/httptransport"
)

func TestNewTransport_WithProxyFuncNilOverridesConfiguredProxy(t *testing.T) {
	proxy := ResolvedProxy{HTTPProxy: "http://proxy:3128", HTTPSProxy: "http://proxy:3128"}

	rt, err := NewTransport(newCMLister(t), "openshift-config", proxy)
	require.NoError(t, err)
	require.NotNil(t, rt.(*http.Transport).Proxy)

	rt, err = NewTransport(newCMLister(t), "openshift-config", proxy, httptransport.WithProxyFunc(nil))
	require.NoError(t, err)
	httpTransport, ok := rt.(*http.Transport)
	require.True(t, ok, "expected *http.Transport, got %T", rt)
	require.Nil(t, httpTransport.Proxy, "WithProxyFunc(nil) should disable the configured proxy")
}

func TestNewTransport_TrustedCA(t *testing.T) {
	proxy := ResolvedProxy{HTTPSProxy: "http://proxy:3128", TrustedCAName: "proxy-ca"}

	t.Run("missing configmap", func(t *testing.T) {
		_, err := NewTransport(newCMLister(t), "openshift-config", proxy)
		require.ErrorContains(t, err, "proxy-ca")
	})

	t.Run("configmap without CA data", func(t *testing.T) {
		cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "openshift-config", Name: "proxy-ca"}}
		_, err := NewTransport(newCMLister(t, cm), "openshift-config", proxy)
		require.ErrorContains(t, err, "no CA data")
	})

	t.Run("configmap looked up in the given namespace", func(t *testing.T) {
		cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "other", Name: "proxy-ca"}}
		_, err := NewTransport(newCMLister(t, cm), "openshift-config", proxy)
		require.ErrorContains(t, err, "openshift-config/proxy-ca")
	})
}

func TestResolvedProxy_ProxyFunc(t *testing.T) {
	p := ResolvedProxy{HTTPSProxy: "http://proxy:3128", NoProxy: []string{"example.com"}}
	f := p.ProxyFunc()

	u, err := f(mustParse(t, "https://other.org"))
	require.NoError(t, err)
	require.NotNil(t, u)

	u, err = f(mustParse(t, "https://foo.example.com"))
	require.NoError(t, err)
	require.Nil(t, u)
}

func mustParse(t *testing.T, s string) *url.URL {
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
