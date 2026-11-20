package proxyconfig

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubefake "k8s.io/client-go/kubernetes/fake"
	corev1listers "k8s.io/client-go/listers/core/v1"
	clocktesting "k8s.io/utils/clock/testing"

	operatorv1 "github.com/openshift/api/operator/v1"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/network/httptransport"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

func Test_checkProxyConfig(t *testing.T) {
	endpoint := "https://proxy.testing.com:443"
	endpointURL, err := url.Parse(endpoint)
	if err != nil {
		t.Fatal(err)
	}

	goodHTTPClient := &http.Client{Transport: &workingHTTPRoundTripper{}}
	badHTTPClient := &http.Client{Transport: &faultyHTTPRoundTripper{}}
	tests := []struct {
		name               string
		noProxy            string
		clientWithProxy    *http.Client
		clientWithoutProxy *http.Client
		// regularClient defaults to the client NO_PROXY selects, which is equivalent without redirects.
		regularClient *http.Client
		mismatchOnly  bool
		wantErr       error
	}{
		{
			name:            "good proxy config with endpoint not matching noProxy",
			clientWithProxy: goodHTTPClient,
		},
		{
			name:               "good proxy config with endpoint matching noProxy",
			noProxy:            "proxy.testing.com",
			clientWithoutProxy: goodHTTPClient,
		},
		{
			name:               "good proxy config with endpoint matching domain in noProxy",
			noProxy:            "testing.com",
			clientWithoutProxy: goodHTTPClient,
		},
		{
			name:               "endpoint matching noProxy is unreachable with/without proxy",
			noProxy:            "testing.com",
			clientWithProxy:    badHTTPClient,
			clientWithoutProxy: badHTTPClient,
			wantErr:            fmt.Errorf("endpoint(%q) found in NO_PROXY(%q) is unreachable with proxy(%q returned 404) and without proxy(%q returned 404)", endpoint, "testing.com", endpoint, endpoint),
		},
		{
			name:               "endpoint matching noProxy is reachable with proxy",
			noProxy:            "proxy.testing.com",
			clientWithProxy:    goodHTTPClient,
			clientWithoutProxy: badHTTPClient,
			wantErr:            fmt.Errorf("failed to reach endpoint(%q) found in NO_PROXY(%q) with error: %q returned 404", endpoint, "proxy.testing.com", endpoint),
		},
		{
			name:               "endpoint not matching noProxy is reachable without proxy",
			clientWithProxy:    badHTTPClient,
			clientWithoutProxy: goodHTTPClient,
			wantErr:            fmt.Errorf("failed to reach endpoint(%q) missing in NO_PROXY(\"\") with error: %q returned 404", endpoint, endpoint),
		},
		{
			name:               "endpoint not matching noProxy is unreachable with/without proxy",
			clientWithProxy:    badHTTPClient,
			clientWithoutProxy: badHTTPClient,
			wantErr:            fmt.Errorf("endpoint(%q) is unreachable with proxy(%q returned 404) and without proxy(%q returned 404)", endpoint, endpoint, endpoint),
		},
		{
			name:               "mismatch only: endpoint matching noProxy unreachable both ways is ignored",
			noProxy:            "testing.com",
			clientWithProxy:    badHTTPClient,
			clientWithoutProxy: badHTTPClient,
			mismatchOnly:       true,
		},
		{
			name:               "mismatch only: endpoint not matching noProxy unreachable both ways is ignored",
			clientWithProxy:    badHTTPClient,
			clientWithoutProxy: badHTTPClient,
			mismatchOnly:       true,
		},
		{
			name:               "mismatch only: endpoint matching noProxy reachable only with proxy is reported",
			noProxy:            "proxy.testing.com",
			clientWithProxy:    goodHTTPClient,
			clientWithoutProxy: badHTTPClient,
			mismatchOnly:       true,
			wantErr:            fmt.Errorf("failed to reach endpoint(%q) found in NO_PROXY(%q) with error: %q returned 404", endpoint, "proxy.testing.com", endpoint),
		},
		{
			name:               "mismatch only: endpoint not matching noProxy reachable only without proxy is reported",
			clientWithProxy:    badHTTPClient,
			clientWithoutProxy: goodHTTPClient,
			mismatchOnly:       true,
			wantErr:            fmt.Errorf("failed to reach endpoint(%q) missing in NO_PROXY(\"\") with error: %q returned 404", endpoint, endpoint),
		},
		{
			// The endpoint redirects to a host that NO_PROXY does not cover: the operand follows the
			// redirect through the proxy, while the direct and the forced proxy probes fail.
			name:               "redirect: endpoint matching noProxy reachable the regular way",
			noProxy:            "proxy.testing.com",
			clientWithProxy:    badHTTPClient,
			clientWithoutProxy: badHTTPClient,
			regularClient:      goodHTTPClient,
		},
		{
			name:               "redirect: endpoint not matching noProxy reachable the regular way",
			clientWithProxy:    badHTTPClient,
			clientWithoutProxy: badHTTPClient,
			regularClient:      goodHTTPClient,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clients := probeClients{forcedProxy: tt.clientWithProxy, direct: tt.clientWithoutProxy, regular: tt.regularClient}
			if clients.regular == nil {
				clients.regular = clients.forcedProxy
				if noProxyMatches(tt.noProxy, endpointURL) {
					clients.regular = clients.direct
				}
			}
			err := checkProxyConfig(context.TODO(), endpointURL, tt.noProxy, clients, tt.mismatchOnly)
			if !reflect.DeepEqual(err, tt.wantErr) {
				t.Errorf("checkProxyConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_warnIfUnreachable(t *testing.T) {
	const reason = "EndpointUnreachable"
	tests := []struct {
		name        string
		endpoints   []string
		client      *http.Client
		wantMessage string
	}{
		{
			name:      "all reachable emits no event",
			endpoints: []string{"https://gitlab.example.com"},
			client:    &http.Client{Transport: &workingHTTPRoundTripper{}},
		},
		{
			name:        "unreachable emits warning",
			endpoints:   []string{"https://gitlab.example.com"},
			client:      &http.Client{Transport: &faultyHTTPRoundTripper{}},
			wantMessage: `endpoints unreachable through proxy: "https://gitlab.example.com" returned 404`,
		},
		{
			name:        "multiple unreachable emits single event",
			endpoints:   []string{"https://gitlab.example.com", "https://sso.example.com"},
			client:      &http.Client{Transport: &faultyHTTPRoundTripper{}},
			wantMessage: `endpoints unreachable through proxy: "https://gitlab.example.com" returned 404; "https://sso.example.com" returned 404`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := events.NewInMemoryRecorder(t.Name(), clocktesting.NewFakePassiveClock(time.Now()))
			p := &proxyConfigChecker{}
			group := &warningGroup{eventReason: reason, endpoints: func() ([]*url.URL, error) { return mustParseAll(t, tt.endpoints...), nil }}

			p.warnIfUnreachable(context.Background(), recorder, tt.client, ResolvedProxy{}, "", group)

			recorded := recorder.Events()
			if tt.wantMessage == "" {
				if len(recorded) > 0 {
					t.Fatalf("expected no events but got %d: %v", len(recorded), recorded)
				}
				return
			}
			if len(recorded) != 1 {
				t.Fatalf("expected 1 event but got %d", len(recorded))
			}
			if recorded[0].Reason != reason {
				t.Errorf("reason = %q, want %q", recorded[0].Reason, reason)
			}
			if recorded[0].Message != tt.wantMessage {
				t.Errorf("message = %q, want %q", recorded[0].Message, tt.wantMessage)
			}
		})
	}
}

func Test_warnIfUnreachable_hashDedup(t *testing.T) {
	endpoints := []string{"https://gitlab.example.com"}
	proxy := ResolvedProxy{HTTPProxy: "http://proxy:3128"}
	reachable := &http.Client{Transport: &workingHTTPRoundTripper{}}
	unreachable := &http.Client{Transport: &faultyHTTPRoundTripper{}}
	newRecorder := func(t *testing.T) events.InMemoryRecorder {
		return events.NewInMemoryRecorder(t.Name(), clocktesting.NewFakePassiveClock(time.Now()))
	}

	t.Run("second call with same config skips validation", func(t *testing.T) {
		p := &proxyConfigChecker{}
		group := &warningGroup{eventReason: "R", endpoints: func() ([]*url.URL, error) { return mustParseAll(t, endpoints...), nil }}

		rec := newRecorder(t)
		p.warnIfUnreachable(context.Background(), rec, reachable, proxy, "", group)
		if len(rec.Events()) != 0 {
			t.Fatalf("first call should emit no events, got %d", len(rec.Events()))
		}
		rec = newRecorder(t)
		p.warnIfUnreachable(context.Background(), rec, unreachable, proxy, "", group)
		if len(rec.Events()) != 0 {
			t.Fatalf("second call with same config should skip validation, got %d events", len(rec.Events()))
		}
	})

	t.Run("changed proxy triggers validation", func(t *testing.T) {
		p := &proxyConfigChecker{}
		group := &warningGroup{eventReason: "R", endpoints: func() ([]*url.URL, error) { return mustParseAll(t, endpoints...), nil }}
		p.warnIfUnreachable(context.Background(), newRecorder(t), reachable, proxy, "", group)

		rec := newRecorder(t)
		p.warnIfUnreachable(context.Background(), rec, unreachable, ResolvedProxy{HTTPProxy: "http://other:3128"}, "", group)
		if len(rec.Events()) != 1 {
			t.Fatalf("expected 1 event, got %d", len(rec.Events()))
		}
	})

	t.Run("removing all endpoints clears hash", func(t *testing.T) {
		current := endpoints
		p := &proxyConfigChecker{}
		group := &warningGroup{eventReason: "R", endpoints: func() ([]*url.URL, error) { return mustParseAll(t, current...), nil }}

		p.warnIfUnreachable(context.Background(), newRecorder(t), reachable, proxy, "", group)
		if group.lastValidationHash == "" {
			t.Fatal("hash should be set after successful validation")
		}
		current = nil
		p.warnIfUnreachable(context.Background(), newRecorder(t), reachable, proxy, "", group)
		if group.lastValidationHash != "" {
			t.Fatal("hash should be cleared when no endpoints are configured")
		}
		current = endpoints
		rec := newRecorder(t)
		p.warnIfUnreachable(context.Background(), rec, unreachable, proxy, "", group)
		if len(rec.Events()) != 1 {
			t.Fatalf("expected validation to run after endpoints re-added, got %d events", len(rec.Events()))
		}
	})

	t.Run("hash not saved on failure allows retry", func(t *testing.T) {
		p := &proxyConfigChecker{}
		group := &warningGroup{eventReason: "R", endpoints: func() ([]*url.URL, error) { return mustParseAll(t, endpoints...), nil }}
		for i := 0; i < 2; i++ {
			rec := newRecorder(t)
			p.warnIfUnreachable(context.Background(), rec, unreachable, proxy, "", group)
			if len(rec.Events()) != 1 {
				t.Fatalf("attempt %d: expected 1 event, got %d", i, len(rec.Events()))
			}
		}
	})
}

type workingHTTPRoundTripper struct{}

func (s *workingHTTPRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 200}, nil
}

type faultyHTTPRoundTripper struct{}

func (s *faultyHTTPRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 404}, nil
}

func Test_getCAPool_trustedCABundles(t *testing.T) {
	validPEM := newTestCAPEM(t)

	t.Run("valid bundle is added", func(t *testing.T) {
		p := &proxyConfigChecker{}
		WithTrustedCABundles(func() ([][]byte, error) { return [][]byte{validPEM}, nil })(p)
		pool, _, err := p.getCAPool()
		if err != nil {
			t.Fatal(err)
		}
		if len(pool.Subjects()) != 1 { //nolint:staticcheck // only counting the added certificates
			t.Fatalf("expected 1 certificate in the pool, got %d", len(pool.Subjects())) //nolint:staticcheck
		}
	})

	t.Run("multiple options are combined", func(t *testing.T) {
		p := &proxyConfigChecker{}
		WithTrustedCABundles(func() ([][]byte, error) { return [][]byte{validPEM}, nil })(p)
		WithTrustedCABundles(func() ([][]byte, error) { return [][]byte{newTestCAPEM(t)}, nil })(p)
		pool, _, err := p.getCAPool()
		if err != nil {
			t.Fatal(err)
		}
		if len(pool.Subjects()) != 2 { //nolint:staticcheck // only counting the added certificates
			t.Fatalf("expected 2 certificates in the pool, got %d", len(pool.Subjects())) //nolint:staticcheck
		}
	})

	t.Run("unparsable bundle is an error", func(t *testing.T) {
		p := &proxyConfigChecker{}
		WithTrustedCABundles(func() ([][]byte, error) { return [][]byte{[]byte("garbage")}, nil })(p)
		if _, _, err := p.getCAPool(); err == nil {
			t.Fatal("expected an error")
		}
	})

	t.Run("callback error propagates", func(t *testing.T) {
		p := &proxyConfigChecker{}
		WithTrustedCABundles(func() ([][]byte, error) { return nil, fmt.Errorf("boom") })(p)
		if _, _, err := p.getCAPool(); err == nil || err.Error() != "boom" {
			t.Fatalf("expected boom, got %v", err)
		}
	})
}

func newTestCAPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// orderedResolver returns the transports in the order createHTTPClients requests them in:
// the regular one honoring NO_PROXY, the one forced through the proxy and the direct one.
type orderedResolver struct {
	proxy      ResolvedProxy
	transports []http.RoundTripper
	calls      int
}

func (r *orderedResolver) ResolveProxy() (ResolvedProxy, error) { return r.proxy, nil }

func (r *orderedResolver) NewTransport(...httptransport.Option) (http.RoundTripper, error) {
	t := r.transports[r.calls]
	r.calls++
	return t, nil
}

func TestSync_endpointPolicies(t *testing.T) {
	endpoint, _ := url.Parse("https://idp.example.com")
	good, bad := &workingHTTPRoundTripper{}, &faultyHTTPRoundTripper{}

	tests := []struct {
		name      string
		policy    EndpointPolicy
		noProxy   []string
		viaProxy  http.RoundTripper
		direct    http.RoundTripper
		wantError bool
	}{
		{name: "degrade: down both ways", policy: DegradeOnFailure, viaProxy: bad, direct: bad, wantError: true},
		{name: "mismatch only: down both ways", policy: DegradeOnNoProxyMismatch, viaProxy: bad, direct: bad},
		{name: "degrade: mismatch", policy: DegradeOnFailure, viaProxy: bad, direct: good, wantError: true},
		{name: "mismatch only: mismatch", policy: DegradeOnNoProxyMismatch, viaProxy: bad, direct: good, wantError: true},
		{name: "mismatch only: covered by NO_PROXY, only reachable through proxy", policy: DegradeOnNoProxyMismatch,
			noProxy: []string{"example.com"}, viaProxy: good, direct: bad, wantError: true},
		{name: "mismatch only: consistent", policy: DegradeOnNoProxyMismatch, viaProxy: good, direct: bad},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Without redirects, the regular transport behaves like the one NO_PROXY selects.
			regular := tt.viaProxy
			if len(tt.noProxy) > 0 {
				regular = tt.direct
			}
			resolver := &orderedResolver{
				proxy:      ResolvedProxy{HTTPSProxy: "http://proxy:3128", NoProxy: tt.noProxy},
				transports: []http.RoundTripper{regular, tt.viaProxy, tt.direct},
			}
			p := &proxyConfigChecker{proxyResolver: resolver}
			WithEndpoints(tt.policy, func() ([]*url.URL, error) { return []*url.URL{endpoint}, nil })(p)

			recorder := events.NewInMemoryRecorder(t.Name(), clocktesting.NewFakePassiveClock(time.Now()))
			err := p.sync(context.Background(), factory.NewSyncContext(t.Name(), recorder))
			if (err != nil) != tt.wantError {
				t.Fatalf("sync() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}

	t.Run("no proxy configured skips everything", func(t *testing.T) {
		called := false
		p := &proxyConfigChecker{proxyResolver: &orderedResolver{}}
		WithEndpoints(DegradeOnFailure, func() ([]*url.URL, error) { called = true; return nil, nil })(p)
		recorder := events.NewInMemoryRecorder(t.Name(), clocktesting.NewFakePassiveClock(time.Now()))
		if err := p.sync(context.Background(), factory.NewSyncContext(t.Name(), recorder)); err != nil || called {
			t.Fatalf("expected no-op, got err=%v called=%v", err, called)
		}
	})
}

func TestSync_warningsSkippedOnEndpointFailure(t *testing.T) {
	endpoint, _ := url.Parse("https://oauth.example.com")
	bad := &faultyHTTPRoundTripper{}
	resolver := &orderedResolver{
		proxy:      ResolvedProxy{HTTPSProxy: "http://proxy:3128"},
		transports: []http.RoundTripper{bad, bad, bad},
	}
	p := &proxyConfigChecker{proxyResolver: resolver}
	WithEndpoints(DegradeOnFailure, func() ([]*url.URL, error) { return []*url.URL{endpoint}, nil })(p)
	warningsCalled := false
	WithEndpointWarnings("R", func() ([]*url.URL, error) { warningsCalled = true; return nil, nil })(p)

	recorder := events.NewInMemoryRecorder(t.Name(), clocktesting.NewFakePassiveClock(time.Now()))
	if err := p.sync(context.Background(), factory.NewSyncContext(t.Name(), recorder)); err == nil {
		t.Fatal("expected an error")
	}
	if warningsCalled {
		t.Fatal("warning groups must not be probed when an endpoint check fails")
	}
}

func Test_noProxyMatches(t *testing.T) {
	tests := []struct {
		noProxy  string
		endpoint string
		want     bool
	}{
		{noProxy: "", endpoint: "https://example.com", want: false},
		{noProxy: "example.com", endpoint: "https://example.com", want: true},
		{noProxy: "example.com", endpoint: "https://sub.example.com", want: true},
		{noProxy: ".example.com", endpoint: "https://example.com", want: false},
		{noProxy: "example.com:8443", endpoint: "https://example.com", want: false},
		{noProxy: "example.com:8443", endpoint: "https://example.com:8443", want: true},
		{noProxy: "10.0.0.0/8", endpoint: "https://10.1.2.3", want: true},
		{noProxy: "*", endpoint: "http://anything.org", want: true},
		{noProxy: "", endpoint: "https://localhost:6443", want: true},
		{noProxy: "", endpoint: "https://127.0.0.1", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.noProxy+" "+tt.endpoint, func(t *testing.T) {
			if got := noProxyMatches(tt.noProxy, mustParseAll(t, tt.endpoint)[0]); got != tt.want {
				t.Errorf("noProxyMatches(%q, %q) = %v, want %v", tt.noProxy, tt.endpoint, got, tt.want)
			}
		})
	}
}

func TestNewProxyConfigController_wiring(t *testing.T) {
	kubeClient := kubefake.NewSimpleClientset()
	informers := v1helpers.NewKubeInformersForNamespaces(kubeClient, "ns-a", "ns-b")
	operatorClient := v1helpers.NewFakeOperatorClient(&operatorv1.OperatorSpec{}, &operatorv1.OperatorStatus{}, nil)
	recorder := events.NewInMemoryRecorder(t.Name(), clocktesting.NewFakePassiveClock(time.Now()))

	c := NewProxyConfigController("ProxyConfig", &orderedResolver{}, informers,
		map[string][]string{"ns-a": {"ca"}}, operatorClient, recorder,
		WithFilteredInformers(func(interface{}) bool { return true }, informers.InformersFor("ns-b").Core().V1().ConfigMaps().Informer()),
	)
	if c.Name() != "ProxyConfigController" {
		t.Errorf("controller name = %q, want %q", c.Name(), "ProxyConfigController")
	}
}

func mustParseAll(t *testing.T, rawURLs ...string) []*url.URL {
	t.Helper()
	urls := make([]*url.URL, 0, len(rawURLs))
	for _, raw := range rawURLs {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		urls = append(urls, u)
	}
	return urls
}

func Test_warnIfUnreachable_revalidation(t *testing.T) {
	endpoints := []string{"https://gitlab.example.com"}
	proxyA := ResolvedProxy{HTTPProxy: "http://proxy-a:3128"}
	proxyB := ResolvedProxy{HTTPProxy: "http://proxy-b:3128"}
	reachable := &http.Client{Transport: &workingHTTPRoundTripper{}}
	unreachable := &http.Client{Transport: &faultyHTTPRoundTripper{}}
	newRecorder := func(t *testing.T) events.InMemoryRecorder {
		return events.NewInMemoryRecorder(t.Name(), clocktesting.NewFakePassiveClock(time.Now()))
	}
	newGroup := func(t *testing.T) *warningGroup {
		return &warningGroup{eventReason: "R", endpoints: func() ([]*url.URL, error) { return mustParseAll(t, endpoints...), nil }}
	}

	t.Run("returning to a validated configuration after a failure validates it again", func(t *testing.T) {
		p, group := &proxyConfigChecker{}, newGroup(t)
		p.warnIfUnreachable(context.Background(), newRecorder(t), reachable, proxyA, "", group)
		p.warnIfUnreachable(context.Background(), newRecorder(t), unreachable, proxyB, "", group)

		rec := newRecorder(t)
		p.warnIfUnreachable(context.Background(), rec, unreachable, proxyA, "", group)
		if len(rec.Events()) != 1 {
			t.Fatalf("expected configuration A to be validated again, got %d events", len(rec.Events()))
		}
	})

	t.Run("changed trust validates again", func(t *testing.T) {
		p, group := &proxyConfigChecker{}, newGroup(t)
		p.warnIfUnreachable(context.Background(), newRecorder(t), reachable, proxyA, "trust-1", group)

		rec := newRecorder(t)
		p.warnIfUnreachable(context.Background(), rec, unreachable, proxyA, "trust-1", group)
		if len(rec.Events()) != 0 {
			t.Fatalf("unchanged trust should skip validation, got %d events", len(rec.Events()))
		}
		rec = newRecorder(t)
		p.warnIfUnreachable(context.Background(), rec, unreachable, proxyA, "trust-2", group)
		if len(rec.Events()) != 1 {
			t.Fatalf("changed trust should validate again, got %d events", len(rec.Events()))
		}
	})

	t.Run("changed proxy trusted CA name validates again", func(t *testing.T) {
		p, group := &proxyConfigChecker{}, newGroup(t)
		p.warnIfUnreachable(context.Background(), newRecorder(t), reachable, proxyA, "", group)

		withCA := proxyA
		withCA.TrustedCAName = "proxy-ca"
		rec := newRecorder(t)
		p.warnIfUnreachable(context.Background(), rec, unreachable, withCA, "", group)
		if len(rec.Events()) != 1 {
			t.Fatalf("changed proxy trusted CA should validate again, got %d events", len(rec.Events()))
		}
	})
}

func Test_getCAPool_digest(t *testing.T) {
	pemA, pemB := newTestCAPEM(t), newTestCAPEM(t)
	cmA := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "ns-a", Name: "ca"}, Data: map[string]string{trustedCAKey: string(pemA)}}
	cmB := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "ns-b", Name: "ca"}, Data: map[string]string{trustedCAKey: string(pemB)}}
	caConfigMaps := map[string][]string{"ns-a": {"ca"}, "ns-b": {"ca"}}

	digest := func(bundle []byte) string {
		p := &proxyConfigChecker{configMapLister: newCMLister(t, cmA, cmB), caConfigMaps: caConfigMaps}
		WithTrustedCABundles(func() ([][]byte, error) { return [][]byte{bundle}, nil })(p)
		_, d, err := p.getCAPool()
		require.NoError(t, err)
		return d
	}

	first := digest(pemA)
	for i := 0; i < 10; i++ {
		require.Equal(t, first, digest(pemA), "digest must not depend on map iteration order")
	}
	require.NotEqual(t, first, digest(pemB), "digest must change with the trusted CA bundles")
}

// transportResolver builds real transports, so that the proxy configuration of the probe clients can be checked.
type transportResolver struct {
	proxy ResolvedProxy
	cms   corev1listers.ConfigMapLister
}

func (r *transportResolver) ResolveProxy() (ResolvedProxy, error) { return r.proxy, nil }

func (r *transportResolver) NewTransport(opts ...httptransport.Option) (http.RoundTripper, error) {
	return NewTransport(r.cms, "openshift-config", r.proxy, opts...)
}

func Test_createHTTPClients_proxyRouting(t *testing.T) {
	proxy := ResolvedProxy{HTTPSProxy: "http://proxy:3128", NoProxy: []string{"internal.example.com"}}
	p := &proxyConfigChecker{proxyResolver: &transportResolver{proxy: proxy, cms: newCMLister(t)}}
	clients, _, err := p.createHTTPClients(proxy)
	require.NoError(t, err)

	proxyFor := func(client *http.Client, endpoint string) *url.URL {
		transport := client.Transport.(*http.Transport)
		if transport.Proxy == nil {
			return nil
		}
		u, err := transport.Proxy(&http.Request{URL: mustParseAll(t, endpoint)[0]})
		require.NoError(t, err)
		return u
	}

	covered, notCovered := "https://internal.example.com", "https://external.org"
	require.NotNil(t, proxyFor(clients.forcedProxy, covered), "forced proxy client must proxy endpoints covered by NO_PROXY")
	require.NotNil(t, proxyFor(clients.forcedProxy, notCovered))
	require.Nil(t, proxyFor(clients.direct, covered))
	require.Nil(t, proxyFor(clients.direct, notCovered))
	require.Nil(t, proxyFor(clients.regular, covered), "regular client must honor NO_PROXY")
	require.NotNil(t, proxyFor(clients.regular, notCovered))

	for _, loopback := range []string{"https://localhost:8443", "https://127.0.0.1", "https://[::1]"} {
		require.Nil(t, proxyFor(clients.forcedProxy, loopback), "loopback %s must never be proxied", loopback)
	}
}

func Test_createHTTPClients_routesWithGivenProxy(t *testing.T) {
	resolved := ResolvedProxy{HTTPSProxy: "http://stale:3128"}
	given := ResolvedProxy{HTTPSProxy: "http://current:3128", NoProxy: []string{"internal.example.com"}}
	p := &proxyConfigChecker{proxyResolver: &transportResolver{proxy: resolved, cms: newCMLister(t)}}
	clients, _, err := p.createHTTPClients(given)
	require.NoError(t, err)

	transport := clients.regular.Transport.(*http.Transport)
	u, err := transport.Proxy(&http.Request{URL: mustParseAll(t, "https://external.org")[0]})
	require.NoError(t, err)
	require.Equal(t, "current:3128", u.Host, "regular client must route with the given proxy")
	u, err = transport.Proxy(&http.Request{URL: mustParseAll(t, "https://internal.example.com")[0]})
	require.NoError(t, err)
	require.Nil(t, u, "regular client must honor the given NO_PROXY")
}

func TestSync_proxyRemovalForgetsValidations(t *testing.T) {
	group := &warningGroup{eventReason: "R", lastValidationHash: "previous"}
	p := &proxyConfigChecker{proxyResolver: &orderedResolver{}, warningGroups: []*warningGroup{group}}
	recorder := events.NewInMemoryRecorder(t.Name(), clocktesting.NewFakePassiveClock(time.Now()))
	require.NoError(t, p.sync(context.Background(), factory.NewSyncContext(t.Name(), recorder)))
	require.Empty(t, group.lastValidationHash)
}

func Test_getCAPool_sources(t *testing.T) {
	pem := newTestCAPEM(t)

	t.Run("no CA sources keeps system trust", func(t *testing.T) {
		p := &proxyConfigChecker{configMapLister: newCMLister(t)}
		WithTrustedCABundles(func() ([][]byte, error) { return nil, nil })(p)
		pool, _, err := p.getCAPool()
		require.NoError(t, err)
		require.Nil(t, pool)
	})

	t.Run("BinaryData is accepted", func(t *testing.T) {
		cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "ca"}, BinaryData: map[string][]byte{trustedCAKey: pem}}
		p := &proxyConfigChecker{configMapLister: newCMLister(t, cm), caConfigMaps: map[string][]string{"ns": {"ca"}}}
		pool, _, err := p.getCAPool()
		require.NoError(t, err)
		require.NotNil(t, pool)
	})

	t.Run("missing bundle is an error", func(t *testing.T) {
		cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "ca"}}
		p := &proxyConfigChecker{configMapLister: newCMLister(t, cm), caConfigMaps: map[string][]string{"ns": {"ca"}}}
		_, _, err := p.getCAPool()
		require.ErrorContains(t, err, "no CA data")
	})
}

func Test_validateProxyURLs(t *testing.T) {
	tests := []struct {
		name    string
		proxy   ResolvedProxy
		wantErr string
	}{
		{name: "valid", proxy: ResolvedProxy{HTTPProxy: "http://user:pass@proxy:3128", HTTPSProxy: "https://proxy:3129"}},
		{name: "valid without scheme", proxy: ResolvedProxy{HTTPSProxy: "proxy:3128"}},
		{name: "only HTTPS set", proxy: ResolvedProxy{HTTPSProxy: "http://proxy:3128"}},
		// httpproxy retries unparsable values with an "http://" prefix, only values failing both ways are ignored.
		{name: "malformed but parsable with http prefix", proxy: ResolvedProxy{HTTPSProxy: "http://[::1"}},
		{name: "invalid HTTP proxy", proxy: ResolvedProxy{HTTPProxy: "secret%zz"}, wantErr: "HTTP_PROXY is not a valid proxy URL"},
		{name: "invalid HTTPS proxy", proxy: ResolvedProxy{HTTPProxy: "http://proxy:3128", HTTPSProxy: "::"}, wantErr: "HTTPS_PROXY is not a valid proxy URL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateProxyURLs(tt.proxy)
			if len(tt.wantErr) == 0 {
				require.NoError(t, err)
				return
			}
			require.EqualError(t, err, tt.wantErr)
			require.NotContains(t, err.Error(), "secret")
		})
	}
}

func TestSync_invalidProxyIsReported(t *testing.T) {
	called := false
	p := &proxyConfigChecker{proxyResolver: &orderedResolver{proxy: ResolvedProxy{HTTPSProxy: "::"}}}
	WithEndpoints(DegradeOnFailure, func() ([]*url.URL, error) { called = true; return nil, nil })(p)
	recorder := events.NewInMemoryRecorder(t.Name(), clocktesting.NewFakePassiveClock(time.Now()))
	err := p.sync(context.Background(), factory.NewSyncContext(t.Name(), recorder))
	require.EqualError(t, err, "HTTPS_PROXY is not a valid proxy URL")
	require.False(t, called, "endpoints must not be probed with an invalid proxy")
}

func Test_checkProxyConfig_redactsPassword(t *testing.T) {
	endpointURL := mustParseAll(t, "https://user:secret@idp.example.com/healthz")[0]
	bad := &http.Client{Transport: &faultyHTTPRoundTripper{}}
	errorTransport := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("connection refused")
	})}

	for name, clients := range map[string]probeClients{
		"status error":    {regular: bad, forcedProxy: bad, direct: bad},
		"transport error": {regular: errorTransport, forcedProxy: errorTransport, direct: errorTransport},
	} {
		t.Run(name, func(t *testing.T) {
			err := checkProxyConfig(context.Background(), endpointURL, "", clients, false)
			require.Error(t, err)
			require.NotContains(t, err.Error(), "secret")
			require.Contains(t, err.Error(), "idp.example.com")
		})
	}

	t.Run("warning event", func(t *testing.T) {
		recorder := events.NewInMemoryRecorder(t.Name(), clocktesting.NewFakePassiveClock(time.Now()))
		group := &warningGroup{eventReason: "R", endpoints: func() ([]*url.URL, error) { return []*url.URL{endpointURL}, nil }}
		(&proxyConfigChecker{}).warnIfUnreachable(context.Background(), recorder, errorTransport, ResolvedProxy{}, "", group)
		require.Len(t, recorder.Events(), 1)
		require.NotContains(t, recorder.Events()[0].Message, "secret")
	})
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }
