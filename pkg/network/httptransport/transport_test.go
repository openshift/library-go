package httptransport

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"

	libcrypto "github.com/openshift/library-go/pkg/crypto"
)

func TestNewRoundTripperReturnsStaticTransportWithoutCAContentProvider(t *testing.T) {
	roundTripper, err := NewRoundTripper()
	require.NoError(t, err)
	assert.IsType(t, &http.Transport{}, roundTripper)
}

func TestNewRoundTripperTrustSources(t *testing.T) {
	poolCA := newTestCA(t, "pool-ca")
	dataCA := newTestCA(t, "data-ca")
	fileCA := newTestCA(t, "file-ca")
	providerCA := newTestCA(t, "provider-ca")

	pool := x509.NewCertPool()
	pool.AddCert(poolCA.certificate)
	originalPool := pool.Clone()

	caFile := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(caFile, fileCA.pem, 0600))
	provider := newTestCAProvider("provider", providerCA.pem)

	roundTripper, err := NewRoundTripper(
		WithCertPool(pool),
		WithCAData("data", dataCA.pem),
		WithCAFile("file", caFile),
		WithCAContentProvider(provider),
	)
	require.NoError(t, err)
	t.Cleanup(roundTripper.(interface{ CloseIdleConnections() }).CloseIdleConnections)

	for name, ca := range map[string]*testCA{
		"cert pool": poolCA,
		"CA data":   dataCA,
		"CA file":   fileCA,
		"provider":  providerCA,
	} {
		t.Run(name, func(t *testing.T) {
			server := startTLSServer(t, ca.serverCertificate, nil)
			assertGetSucceeds(t, roundTripper, server.URL)
		})
	}

	assert.True(t, pool.Equal(originalPool), "caller-owned cert pool was mutated")
}

func TestNewRoundTripperValidation(t *testing.T) {
	tests := []struct {
		name    string
		opts    []Option
		wantErr string
	}{
		{
			name:    "invalid CA data",
			opts:    []Option{WithCAData("bad", []byte("bad"))},
			wantErr: "failed to parse CA certificates",
		},
		{
			name:    "missing CA file",
			opts:    []Option{WithCAFile("missing", "/does/not/exist")},
			wantErr: "failed to load CA certificates",
		},
		{
			name:    "certificate without key",
			opts:    []Option{WithClientCertificateFile("cert.pem", "")},
			wantErr: "certFile and keyFile must be specified together",
		},
		{
			name:    "key without certificate",
			opts:    []Option{WithClientCertificateFile("", "key.pem")},
			wantErr: "certFile and keyFile must be specified together",
		},
		{
			name:    "duplicate cert pool",
			opts:    []Option{WithCertPool(nil), WithCertPool(nil)},
			wantErr: "WithCertPool may only be specified once",
		},
		{
			name:    "duplicate proxy",
			opts:    []Option{WithProxyFunc(nil), WithProxyFunc(nil)},
			wantErr: "WithProxyFunc may only be specified once",
		},
		{
			name:    "invalid provider content",
			opts:    []Option{WithCAContentProvider(newTestCAProvider("bad", []byte("bad")))},
			wantErr: "failed to parse CA content from provider",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewRoundTripper(test.opts...)
			assert.ErrorContains(t, err, test.wantErr)
		})
	}
}

func TestTransportReloadsCAProviders(t *testing.T) {
	firstCA := newTestCA(t, "first-ca")
	firstServer := startTLSServer(t, firstCA.serverCertificate, nil)

	secondCA := newTestCA(t, "second-ca")
	secondServer := startTLSServer(t, secondCA.serverCertificate, nil)

	provider := newTestCAProvider("rotating-provider", firstCA.pem)

	roundTripper, err := NewRoundTripper(WithCAContentProvider(provider))
	require.NoError(t, err)

	assertGetSucceeds(t, roundTripper, firstServer.URL)
	provider.setContent(secondCA.pem)
	assertGetSucceeds(t, roundTripper, secondServer.URL)
	assertGetFails(t, roundTripper, firstServer.URL)
}

func TestTransportRetainsLastKnownGoodConfiguration(t *testing.T) {
	ca := newTestCA(t, "valid-ca")
	server := startTLSServer(t, ca.serverCertificate, nil)
	provider := newTestCAProvider("provider", ca.pem)

	roundTripper, err := NewRoundTripper(WithCAContentProvider(provider))
	require.NoError(t, err)
	assertGetSucceeds(t, roundTripper, server.URL)

	provider.setContent([]byte("not a certificate"))
	assertGetSucceeds(t, roundTripper, server.URL)
}

func TestTransportAllowsEmptyCAContentProvider(t *testing.T) {
	_, err := NewRoundTripper(WithCAContentProvider(newTestCAProvider("empty", nil)))
	require.NoError(t, err)
}

func TestTransportSupportsMultipleCAProviders(t *testing.T) {
	firstCA := newTestCA(t, "first-provider")
	secondCA := newTestCA(t, "second-provider")

	roundTripper, err := NewRoundTripper(
		WithCAContentProvider(newTestCAProvider("first", firstCA.pem)),
		WithCAContentProvider(newTestCAProvider("second", secondCA.pem)),
	)
	require.NoError(t, err)

	for _, ca := range []*testCA{firstCA, secondCA} {
		server := startTLSServer(t, ca.serverCertificate, nil)
		assertGetSucceeds(t, roundTripper, server.URL)
	}
}

func TestTransportClientCertificate(t *testing.T) {
	ca := newTestCA(t, "mutual-tls-ca")
	serverCertificate, _, _ := ca.NewSignedCertificate(false)
	_, clientCertPEM, clientKeyPEM := ca.NewSignedCertificate(true)

	clientCertFile := filepath.Join(t.TempDir(), "client.crt")
	clientKeyFile := filepath.Join(t.TempDir(), "client.key")
	require.NoError(t, os.WriteFile(clientCertFile, clientCertPEM, 0o600))
	require.NoError(t, os.WriteFile(clientKeyFile, clientKeyPEM, 0o600))

	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(ca.certificate)
	server := startTLSServer(t, serverCertificate, clientCAs)

	// We just use duplicate client certs here to make sure both are being added.
	roundTripper, err := NewRoundTripper(
		WithCAData("server-ca", ca.pem),
		WithClientCertificateFile(clientCertFile, clientKeyFile),
		WithClientCertificateFile(clientCertFile, clientKeyFile),
	)
	require.NoError(t, err)

	assertGetSucceeds(t, roundTripper, server.URL)
	assert.Len(t, underlyingTransport(t, roundTripper).TLSClientConfig.Certificates, 2)
}

func TestTransportProxyConfiguration(t *testing.T) {
	t.Run("environment default", func(t *testing.T) {
		roundTripper, err := NewRoundTripper()
		require.NoError(t, err)
		assert.NotNil(t, underlyingTransport(t, roundTripper).Proxy)
	})

	t.Run("explicit proxy", func(t *testing.T) {
		want, err := url.Parse("http://proxy.example.com:3128")
		require.NoError(t, err)

		proxyFunc := func(*http.Request) (*url.URL, error) { return want, nil }
		roundTripper, err := NewRoundTripper(WithProxyFunc(proxyFunc))
		require.NoError(t, err)

		got, err := underlyingTransport(t, roundTripper).Proxy(&http.Request{URL: &url.URL{Scheme: "https", Host: "example.com"}})
		require.NoError(t, err)
		assert.Equal(t, want.String(), got.String())
	})

	t.Run("explicitly disabled", func(t *testing.T) {
		roundTripper, err := NewRoundTripper(WithProxyFunc(nil))
		require.NoError(t, err)
		assert.Nil(t, underlyingTransport(t, roundTripper).Proxy)
	})
}

type testCAProvider struct {
	name string

	mu        sync.RWMutex
	content   []byte
	listeners []dynamiccertificates.Listener
}

func newTestCAProvider(name string, content []byte) *testCAProvider {
	return &testCAProvider{name: name, content: append([]byte(nil), content...)}
}

func (p *testCAProvider) Name() string { return p.name }

func (p *testCAProvider) AddListener(listener dynamiccertificates.Listener) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.listeners = append(p.listeners, listener)
}

func (p *testCAProvider) CurrentCABundleContent() []byte {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return append([]byte(nil), p.content...)
}

func (p *testCAProvider) VerifyOptions() (x509.VerifyOptions, bool) {
	return x509.VerifyOptions{}, false
}

func (p *testCAProvider) setContent(content []byte) {
	p.mu.Lock()
	p.content = append([]byte(nil), content...)
	p.mu.Unlock()
	p.notify()
}

func (p *testCAProvider) notify() {
	p.mu.RLock()
	listeners := append([]dynamiccertificates.Listener(nil), p.listeners...)
	p.mu.RUnlock()
	for _, listener := range listeners {
		listener.Enqueue()
	}
}

type testCA struct {
	t                 *testing.T
	pem               []byte
	certificate       *x509.Certificate
	signer            *libcrypto.CA
	serverCertificate tls.Certificate
}

func newTestCA(t *testing.T, commonName string) *testCA {
	t.Helper()
	caDirectory := t.TempDir()

	signer, err := libcrypto.MakeSelfSignedCA(
		filepath.Join(caDirectory, "ca.crt"),
		filepath.Join(caDirectory, "ca.key"),
		"",
		commonName,
		time.Hour,
	)
	require.NoError(t, err)

	certPEM, _, err := signer.Config.GetPEMBytes()
	require.NoError(t, err)

	testCA := &testCA{
		t:           t,
		pem:         certPEM,
		certificate: signer.Config.Certs[0],
		signer:      signer,
	}
	testCA.serverCertificate, _, _ = testCA.NewSignedCertificate(false)
	return testCA
}

func (ca *testCA) NewSignedCertificate(client bool) (tls.Certificate, []byte, []byte) {
	ca.t.Helper()

	var config *libcrypto.TLSCertificateConfig
	var err error
	if client {
		config, err = ca.signer.MakeClientCertificateForDuration(&user.DefaultInfo{Name: "test-client"}, time.Hour)
	} else {
		config, err = ca.signer.MakeServerCertForDuration(sets.New("127.0.0.1", "localhost"), time.Hour)
	}
	require.NoError(ca.t, err)

	certPEM, keyPEM, err := config.GetPEMBytes()
	require.NoError(ca.t, err)

	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(ca.t, err)

	return certificate, certPEM, keyPEM
}

// startTLSServer starts an HTTPS test server presenting certificate. When
// clientCAs is non-nil the server requires and verifies a client certificate
// against it (mutual TLS).
func startTLSServer(t *testing.T, certificate tls.Certificate, clientCAs *x509.CertPool) *httptest.Server {
	t.Helper()

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}}
	if clientCAs != nil {
		server.TLS.ClientAuth = tls.RequireAndVerifyClientCert
		server.TLS.ClientCAs = clientCAs
	}

	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func assertGetSucceeds(t *testing.T, roundTripper http.RoundTripper, target string) {
	t.Helper()

	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	require.NoError(t, err)

	response, err := roundTripper.RoundTrip(request)
	require.NoErrorf(t, err, "GET %s", target)
	defer func() {
		assert.NoError(t, response.Body.Close())
	}()

	require.Equalf(t, http.StatusOK, response.StatusCode, "GET %s", target)
}

func assertGetFails(t *testing.T, roundTripper http.RoundTripper, target string) {
	t.Helper()

	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	require.NoError(t, err)

	response, err := roundTripper.RoundTrip(request)
	if err == nil {
		assert.NoError(t, response.Body.Close())
	}

	require.Errorf(t, err, "GET %s unexpectedly succeeded", target)
}

func underlyingTransport(t *testing.T, roundTripper http.RoundTripper) *http.Transport {
	t.Helper()
	if transport, ok := roundTripper.(*http.Transport); ok {
		return transport
	}
	if dynamic, ok := roundTripper.(*dynamicTransport); ok {
		return dynamic.transport.Load()
	}
	t.Fatalf("got transport type %T, want *http.Transport or *dynamicTransport", roundTripper)
	return nil
}
