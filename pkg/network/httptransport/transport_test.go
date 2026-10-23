package httptransport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
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

	want := x509.NewCertPool()
	for _, ca := range []*testCA{poolCA, dataCA, fileCA, providerCA} {
		want.AddCert(ca.certificate)
	}

	rootCAs := underlyingTransport(t, roundTripper).TLSClientConfig.RootCAs
	assert.True(t, rootCAs.Equal(want), "expected all trust sources to be merged into the root pool")
	assert.True(t, pool.Equal(originalPool), "caller-owned cert pool was mutated")
}

func TestNewRoundTripperCertPoolOptions(t *testing.T) {
	t.Run("last pool wins", func(t *testing.T) {
		firstCA := newTestCA(t, "first-pool-ca")
		secondCA := newTestCA(t, "second-pool-ca")

		firstPool := x509.NewCertPool()
		firstPool.AddCert(firstCA.certificate)
		secondPool := x509.NewCertPool()
		secondPool.AddCert(secondCA.certificate)

		roundTripper, err := NewRoundTripper(WithCertPool(firstPool), WithCertPool(secondPool))
		require.NoError(t, err)

		rootCAs := underlyingTransport(t, roundTripper).TLSClientConfig.RootCAs
		assert.True(t, rootCAs.Equal(secondPool), "expected the last WithCertPool call to win")
		assert.False(t, rootCAs.Equal(firstPool), "first pool should have been discarded")
	})

	t.Run("nil resets to the system cert pool", func(t *testing.T) {
		ca := newTestCA(t, "discarded-pool-ca")
		pool := x509.NewCertPool()
		pool.AddCert(ca.certificate)

		roundTripper, err := NewRoundTripper(WithCertPool(pool), WithCertPool(nil))
		require.NoError(t, err)

		systemPool, err := x509.SystemCertPool()
		require.NoError(t, err)

		rootCAs := underlyingTransport(t, roundTripper).TLSClientConfig.RootCAs
		assert.True(t, rootCAs.Equal(systemPool), "expected WithCertPool(nil) to reset to the system cert pool")
	})
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
			name:    "zero TLS min version",
			opts:    []Option{WithTLSMinVersion(0)},
			wantErr: "WithTLSMinVersion requires a non-zero TLS version",
		},
		{
			name:    "empty TLS cipher suites",
			opts:    []Option{WithTLSCipherSuites(nil)},
			wantErr: "WithTLSCipherSuites requires at least one cipher suite",
		},
		{
			name:    "nil CA content provider",
			opts:    []Option{WithCAContentProvider(nil)},
			wantErr: "CA content provider must not be nil",
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
	oldTransport := underlyingTransport(t, roundTripper)
	provider.setContent(secondCA.pem)
	waitForTransportRebuild(t, roundTripper, oldTransport)

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

	oldTransport := underlyingTransport(t, roundTripper)
	provider.setContent([]byte("not a certificate"))
	// Rebuild synchronously; a failed rebuild never swaps the transport, so it
	// can't be waited on with waitForTransportRebuild.
	roundTripper.(*dynamicTransport).rebuild()

	assert.Same(t, oldTransport, underlyingTransport(t, roundTripper), "a failed rebuild must not replace the transport")
}

func TestTransportForwardsCloseIdleConnections(t *testing.T) {
	ca := newTestCA(t, "valid-ca")
	closed := make(chan struct{}, 1)
	server := startTLSServer(t, ca.serverCertificate, nil, func(server *httptest.Server) {
		server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
			if state == http.StateClosed {
				select {
				case closed <- struct{}{}:
				default:
				}
			}
		}
	})

	roundTripper, err := NewRoundTripper(WithCAContentProvider(newTestCAProvider("provider", ca.pem)))
	require.NoError(t, err)
	require.IsType(t, &dynamicTransport{}, roundTripper)
	client := &http.Client{Transport: roundTripper}

	// Read the body to the end so the connection goes back to the idle pool.
	response, err := client.Get(server.URL)
	require.NoError(t, err)
	_, err = io.Copy(io.Discard, response.Body)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())

	select {
	case <-closed:
		t.Fatal("connection closed before CloseIdleConnections was called")
	default:
	}

	client.CloseIdleConnections()

	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the idle connection to be closed")
	}
}

func TestTransportAllowsEmptyCAContentProvider(t *testing.T) {
	_, err := NewRoundTripper(WithCAContentProvider(newTestCAProvider("empty", nil)))
	require.NoError(t, err)
}

func TestTransportSupportsMultipleCAProviders(t *testing.T) {
	firstCA := newTestCA(t, "first-provider")
	secondCA := newTestCA(t, "second-provider")

	roundTripper, err := NewRoundTripper(
		WithCertPool(x509.NewCertPool()),
		WithCAContentProvider(newTestCAProvider("first", firstCA.pem)),
		WithCAContentProvider(newTestCAProvider("second", secondCA.pem)),
	)
	require.NoError(t, err)

	want := x509.NewCertPool()
	want.AddCert(firstCA.certificate)
	want.AddCert(secondCA.certificate)

	rootCAs := underlyingTransport(t, roundTripper).TLSClientConfig.RootCAs
	assert.True(t, rootCAs.Equal(want), "expected both CA content providers' certificates to be trusted")
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

	t.Run("last of multiple wins", func(t *testing.T) {
		first, err := url.Parse("http://first.example.com:3128")
		require.NoError(t, err)
		second, err := url.Parse("http://second.example.com:3128")
		require.NoError(t, err)

		roundTripper, err := NewRoundTripper(
			WithProxyFunc(func(*http.Request) (*url.URL, error) { return first, nil }),
			WithProxyFunc(func(*http.Request) (*url.URL, error) { return second, nil }),
		)
		require.NoError(t, err)

		got, err := underlyingTransport(t, roundTripper).Proxy(&http.Request{URL: &url.URL{Scheme: "https", Host: "example.com"}})
		require.NoError(t, err)
		assert.Equal(t, second.String(), got.String())
	})
}

func TestTransportTLSProfile(t *testing.T) {
	cipherSuites := []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	}

	t.Run("OpenShift defaults", func(t *testing.T) {
		roundTripper, err := NewRoundTripper()
		require.NoError(t, err)

		tlsConfig := underlyingTransport(t, roundTripper).TLSClientConfig
		assert.Equal(t, libcrypto.DefaultTLSVersion(), tlsConfig.MinVersion)
		assert.Equal(t, libcrypto.DefaultCiphers(), tlsConfig.CipherSuites)
	})

	t.Run("configured profile", func(t *testing.T) {
		roundTripper, err := NewRoundTripper(WithTLSMinVersion(tls.VersionTLS13), WithTLSCipherSuites(cipherSuites))
		require.NoError(t, err)

		tlsConfig := underlyingTransport(t, roundTripper).TLSClientConfig
		assert.Equal(t, uint16(tls.VersionTLS13), tlsConfig.MinVersion)
		assert.Equal(t, cipherSuites, tlsConfig.CipherSuites)
	})

	t.Run("last option wins when specified multiple times", func(t *testing.T) {
		roundTripper, err := NewRoundTripper(
			WithTLSMinVersion(tls.VersionTLS12),
			WithTLSMinVersion(tls.VersionTLS13),
			WithTLSCipherSuites(cipherSuites),
			WithTLSCipherSuites(cipherSuites[:1]),
		)
		require.NoError(t, err)

		tlsConfig := underlyingTransport(t, roundTripper).TLSClientConfig
		assert.Equal(t, uint16(tls.VersionTLS13), tlsConfig.MinVersion)
		assert.Equal(t, cipherSuites[:1], tlsConfig.CipherSuites)
	})

	// The profile must survive the transport rebuild a CA rotation triggers,
	// otherwise reloading trust would silently widen the TLS configuration.
	t.Run("survives a CA provider rebuild", func(t *testing.T) {
		provider := newTestCAProvider("provider", newTestCA(t, "first-ca").pem)

		roundTripper, err := NewRoundTripper(
			WithCAContentProvider(provider),
			WithTLSMinVersion(tls.VersionTLS13),
			WithTLSCipherSuites(cipherSuites),
		)
		require.NoError(t, err)

		oldTransport := underlyingTransport(t, roundTripper)
		provider.setContent(newTestCA(t, "second-ca").pem)
		rebuilt := waitForTransportRebuild(t, roundTripper, oldTransport)

		tlsConfig := rebuilt.TLSClientConfig
		assert.Equal(t, uint16(tls.VersionTLS13), tlsConfig.MinVersion)
		assert.Equal(t, cipherSuites, tlsConfig.CipherSuites)
	})

	// Assert the profile is enforced on the wire, not merely recorded.
	t.Run("rejects a server below the version floor", func(t *testing.T) {
		ca := newTestCA(t, "tls12-only-ca")

		server := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			response.WriteHeader(http.StatusOK)
		}))
		server.TLS = &tls.Config{
			Certificates: []tls.Certificate{ca.serverCertificate},
			MaxVersion:   tls.VersionTLS12,
		}
		server.StartTLS()
		t.Cleanup(server.Close)

		roundTripper, err := NewRoundTripper(
			WithCAData("server-ca", ca.pem),
			WithTLSMinVersion(tls.VersionTLS13),
		)
		require.NoError(t, err)

		assertGetFails(t, roundTripper, server.URL)
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
// against it (mutual TLS). Optional hooks configure the server before startup.
func startTLSServer(t *testing.T, certificate tls.Certificate, clientCAs *x509.CertPool, configure ...func(*httptest.Server)) *httptest.Server {
	t.Helper()

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}}
	if clientCAs != nil {
		server.TLS.ClientAuth = tls.RequireAndVerifyClientCert
		server.TLS.ClientCAs = clientCAs
	}

	for _, configureServer := range configure {
		configureServer(server)
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

func TestTransportDisableHTTP2(t *testing.T) {
	t.Setenv("DISABLE_HTTP2", "")
	for _, disabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("disabled=%t", disabled), func(t *testing.T) {
			ca := newTestCA(t, "protocol-ca")
			provider := newTestCAProvider("protocol-ca", ca.pem)
			opts := []Option{WithCAContentProvider(provider), WithProxyFunc(nil)}
			if disabled {
				opts = append(opts, WithDisabledHTTP2())
			}
			rt, err := NewRoundTripper(opts...)
			require.NoError(t, err)
			server := startTLSServer(t, ca.serverCertificate, nil, func(server *httptest.Server) {
				server.EnableHTTP2 = true
			})
			client := &http.Client{Transport: rt}
			t.Cleanup(client.CloseIdleConnections)
			for _, stage := range []string{"initial", "after reload"} {
				t.Run(stage, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
					defer cancel()
					request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
					require.NoError(t, err)
					response, err := client.Do(request)
					require.NoError(t, err)
					require.NoError(t, response.Body.Close())
					expected := 2
					if disabled {
						expected = 1
					}
					require.Equal(t, expected, response.ProtoMajor)
				})
				if stage == "initial" {
					previous := underlyingTransport(t, rt)
					provider.notify()
					waitForTransportRebuild(t, rt, previous)
				}
			}
		})
	}
}

// Exercise the HTTPS proxy handshake separately from direct origin negotiation.
func TestTransportDisabledHTTP2HTTPSProxy(t *testing.T) {
	t.Setenv("DISABLE_HTTP2", "")
	originCA := newTestCA(t, "origin-ca")
	proxyCA := newTestCA(t, "proxy-ca")
	origin := startTLSServer(t, originCA.serverCertificate, nil)
	protocols := make(chan string, 2)
	proxy := startTLSServer(t, proxyCA.serverCertificate, nil, func(server *httptest.Server) {
		server.EnableHTTP2 = true
		server.TLS.NextProtos = []string{"h2", "http/1.1"}
		server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodConnect || r.Host != origin.Listener.Addr().String() {
				http.Error(w, "unexpected CONNECT target", http.StatusBadRequest)
				return
			}
			dialer := &net.Dialer{Timeout: 5 * time.Second}
			upstream, err := dialer.DialContext(r.Context(), "tcp", origin.Listener.Addr().String())
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			defer upstream.Close()
			hijacker, ok := w.(http.Hijacker)
			if !assert.True(t, ok, "proxy response writer must support hijacking (ALPN %q)", r.TLS.NegotiatedProtocol) {
				http.Error(w, "proxy connection cannot be hijacked", http.StatusInternalServerError)
				return
			}
			downstream, buffered, err := hijacker.Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			defer downstream.Close()
			protocols <- r.TLS.NegotiatedProtocol
			if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
				t.Error(err)
				return
			}
			if err := buffered.Flush(); err != nil {
				t.Error(err)
				return
			}
			go func() {
				_, _ = io.Copy(downstream, upstream)
				_ = downstream.Close()
			}()
			_, _ = io.Copy(upstream, buffered.Reader)
		})
	})
	proxyURL, err := url.Parse(proxy.URL)
	require.NoError(t, err)
	provider := newTestCAProvider("proxy-and-origin", append(originCA.pem, proxyCA.pem...))
	rt, err := NewRoundTripper(WithCAContentProvider(provider), WithProxyFunc(http.ProxyURL(proxyURL)), WithDisabledHTTP2())
	require.NoError(t, err)
	client := &http.Client{Transport: rt}
	t.Cleanup(client.CloseIdleConnections)
	for _, stage := range []string{"initial", "after reload"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, origin.URL, nil)
			require.NoError(t, err)
			response, err := client.Do(request)
			require.NoError(t, err)
			require.NoError(t, response.Body.Close())
			require.Equal(t, http.StatusOK, response.StatusCode)
			select {
			case protocol := <-protocols:
				require.Equal(t, "http/1.1", protocol)
			case <-ctx.Done():
				t.Fatal("proxy did not receive CONNECT")
			}
		})
		if stage == "initial" {
			previous := underlyingTransport(t, rt)
			provider.notify()
			waitForTransportRebuild(t, rt, previous)
		}
	}
}

// waitForTransportRebuild blocks until roundTripper's underlying transport is
// no longer oldTransport. Enqueue rebuilds asynchronously, so tests that
// trigger a CA content change must synchronize on the swap before asserting
// on its effect instead of racing the rebuild goroutine.
func waitForTransportRebuild(t *testing.T, roundTripper http.RoundTripper, oldTransport *http.Transport) *http.Transport {
	t.Helper()

	var current *http.Transport
	err := wait.PollUntilContextTimeout(t.Context(), 5*time.Millisecond, wait.ForeverTestTimeout, true, func(context.Context) (bool, error) {
		current = underlyingTransport(t, roundTripper)
		return current != oldTransport, nil
	})
	require.NoError(t, err, "timed out waiting for transport rebuild")
	return current
}

// waitForClose fails the test unless ch is closed within wait.ForeverTestTimeout,
// so a missed signal fails the test instead of hanging it.
func waitForClose(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()

	select {
	case <-ch:
	case <-time.After(wait.ForeverTestTimeout):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// gatedCAProvider blocks the gateCall-th CurrentCABundleContent call, after the
// content has been read, until release is closed. A test can use it to change
// the content while a transport build that read the old content is in flight.
// gatedRead is closed when the gated call has read the content, nextRead when
// the call after it has.
type gatedCAProvider struct {
	*testCAProvider

	gateCall  int32
	calls     atomic.Int32
	gatedRead chan struct{}
	nextRead  chan struct{}
	release   chan struct{}
}

func newGatedCAProvider(name string, content []byte, gateCall int32) *gatedCAProvider {
	return &gatedCAProvider{
		testCAProvider: newTestCAProvider(name, content),
		gateCall:       gateCall,
		gatedRead:      make(chan struct{}),
		nextRead:       make(chan struct{}),
		release:        make(chan struct{}),
	}
}

func (p *gatedCAProvider) CurrentCABundleContent() []byte {
	content := p.testCAProvider.CurrentCABundleContent()
	switch p.calls.Add(1) {
	case p.gateCall:
		close(p.gatedRead)
		<-p.release
	case p.gateCall + 1:
		close(p.nextRead)
	}
	return content
}

// TestNewRoundTripperDoesNotLoseCARotationDuringConstruction rotates the CA
// while the constructor's initial build, which read the old content, is still
// in flight. That build runs before the listener is registered, so the provider
// has no one to notify. The rebuild after registration must pick up the new CA.
func TestNewRoundTripperDoesNotLoseCARotationDuringConstruction(t *testing.T) {
	oldCA := newTestCA(t, "old-ca")
	newCA := newTestCA(t, "new-ca")
	newServer := startTLSServer(t, newCA.serverCertificate, nil)
	provider := newGatedCAProvider("rotating-provider", oldCA.pem, 1)

	var (
		roundTripper http.RoundTripper
		err          error
	)
	done := make(chan struct{})
	go func() {
		defer close(done)
		roundTripper, err = NewRoundTripper(WithCAContentProvider(provider))
	}()

	waitForClose(t, provider.gatedRead, "the initial build to read the CA content")
	provider.setContent(newCA.pem)
	close(provider.release)
	waitForClose(t, done, "NewRoundTripper to return")
	require.NoError(t, err)

	assertGetSucceeds(t, roundTripper, newServer.URL)
}

// TestTransportSerializesRebuilds checks that concurrent rebuilds can't leave
// the transport trusting stale CA content.
//
// Every CA change starts its own rebuild goroutine, and a rebuild has three
// steps: read the provider content, build a transport from it, swap it in.
// Without serialization this interleaving is possible:
//
//  1. Rebuild A reads content v2 and is slow to build.
//  2. The content changes to v3; rebuild B reads v3, builds and swaps.
//  3. Rebuild A finally swaps its v2 transport in, overwriting B's v3.
//
// The transport would then trust v2 until the next CA change. rebuild() holds
// rebuildMu across all three steps to prevent this: B can't even read the
// content until A has swapped.
//
// The test forces step 1 by pausing A right after its read, then triggers B and
// checks that B doesn't read the content while A is paused. With correct
// serialization B is blocked on rebuildMu, so that read can't happen and the
// check can't fail spuriously. Without it, B reads right away and the test
// fails, unless B doesn't get scheduled within the 100ms window.
func TestTransportSerializesRebuilds(t *testing.T) {
	firstCA := newTestCA(t, "first-ca")
	secondCA := newTestCA(t, "second-ca")
	thirdCA := newTestCA(t, "third-ca")

	// NewRoundTripper reads the content twice (the initial build and the
	// rebuild after registering), so read 3 is the first one done by a rebuild
	// triggered through Enqueue. That is rebuild A.
	provider := newGatedCAProvider("rotating-provider", firstCA.pem, 3)

	// An empty base pool makes RootCAs contain only the provider's CAs, so the
	// final assertion can compare it against exactly one CA.
	roundTripper, err := NewRoundTripper(WithCertPool(x509.NewCertPool()), WithCAContentProvider(provider))
	require.NoError(t, err)

	// Start rebuild A and wait until it has read secondCA. It's now paused
	// inside CurrentCABundleContent while holding rebuildMu.
	provider.setContent(secondCA.pem)
	waitForClose(t, provider.gatedRead, "rebuild A to read the CA content")

	// Start rebuild B. It must wait for A, so its read (read 4, which closes
	// nextRead) must not happen while A is paused.
	provider.setContent(thirdCA.pem)
	select {
	case <-provider.nextRead:
		t.Fatal("a rebuild read the CA content while another rebuild was in flight")
	case <-time.After(100 * time.Millisecond):
	}

	// Let A finish swapping in its secondCA transport. B then gets the lock,
	// reads thirdCA and swaps it in, so the transport must end up trusting
	// thirdCA only.
	close(provider.release)

	want := x509.NewCertPool()
	want.AddCert(thirdCA.certificate)
	err = wait.PollUntilContextTimeout(t.Context(), 5*time.Millisecond, wait.ForeverTestTimeout, true, func(context.Context) (bool, error) {
		return underlyingTransport(t, roundTripper).TLSClientConfig.RootCAs.Equal(want), nil
	})
	require.NoError(t, err, "transport did not converge to the latest CA content")
}

func TestNewRoundTripperFailureDoesNotRegisterListeners(t *testing.T) {
	provider := newTestCAProvider("invalid", []byte("not a certificate"))

	_, err := NewRoundTripper(WithCAContentProvider(provider))
	require.Error(t, err)

	provider.mu.RLock()
	defer provider.mu.RUnlock()
	assert.Empty(t, provider.listeners)
}
