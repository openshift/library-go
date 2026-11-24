package proxyconfig

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	clocktesting "k8s.io/utils/clock/testing"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/network/httptransport"
	"github.com/openshift/library-go/pkg/operator/events"
)

var (
	errBoom  = errors.New("boom")
	ok       = status(200)
	notFound = status(404)
)

// Test_checkProxyConfig checks the NO_PROXY consistency check, for both policies. An endpoint is expected
// to be reached directly when NO_PROXY covers it and through the proxy otherwise. When that fails, the
// other way tells a mismatch (reachable the other way) from an endpoint that is simply down.
func Test_checkProxyConfig(t *testing.T) {
	const endpoint = "https://proxy.testing.com:443"
	down := fmt.Sprintf("%q returned 404", endpoint)

	tests := []struct {
		name               string
		noProxy            string
		clientWithProxy    http.RoundTripper
		clientWithoutProxy http.RoundTripper
		// regularClient defaults to the fixed-route client that NO_PROXY selects for the endpoint, which
		// behaves identically as long as there is no redirect. Set it to model a redirect that the regular
		// client follows differently, as it decides the route again for every request.
		regularClient http.RoundTripper
		wantErr       string
		// bothDown marks an endpoint unreachable both ways, which is not an error when mismatchOnly is set.
		bothDown bool
	}{
		{
			name:            "endpoint to be proxied is reachable through the proxy",
			clientWithProxy: ok,
		},
		{
			name:               "endpoint to be reached directly is reachable without the proxy",
			noProxy:            "proxy.testing.com",
			clientWithoutProxy: ok,
		},
		{
			name:               "endpoint to be reached directly, listed by its domain, is reachable without the proxy",
			noProxy:            "testing.com",
			clientWithoutProxy: ok,
		},
		{
			name:               "endpoint to be reached directly is down both with and without the proxy",
			noProxy:            "testing.com",
			clientWithProxy:    notFound,
			clientWithoutProxy: notFound,
			wantErr:            fmt.Sprintf(`endpoint(%q) found in NO_PROXY("testing.com") is unreachable with proxy(%s) and without proxy(%s)`, endpoint, down, down),
			bothDown:           true,
		},
		{
			name:               "endpoint to be proxied is down both with and without the proxy",
			clientWithProxy:    notFound,
			clientWithoutProxy: notFound,
			wantErr:            fmt.Sprintf(`endpoint(%q) is unreachable with proxy(%s) and without proxy(%s)`, endpoint, down, down),
			bothDown:           true,
		},
		{
			name:               "endpoint to be reached directly is reachable only through the proxy",
			noProxy:            "proxy.testing.com",
			clientWithProxy:    ok,
			clientWithoutProxy: notFound,
			wantErr:            fmt.Sprintf(`failed to reach endpoint(%q) found in NO_PROXY("proxy.testing.com") with error: %s`, endpoint, down),
		},
		{
			name:               "endpoint to be proxied is reachable only without the proxy",
			clientWithProxy:    notFound,
			clientWithoutProxy: ok,
			wantErr:            fmt.Sprintf(`failed to reach endpoint(%q) missing in NO_PROXY("") with error: %s`, endpoint, down),
		},
		{
			// The endpoint redirects to a host that NO_PROXY does not cover: the operand follows the
			// redirect through the proxy, while the direct and the forced proxy probes fail.
			name:               "redirect: endpoint to be reached directly works the way the operand reaches it",
			noProxy:            "proxy.testing.com",
			clientWithProxy:    notFound,
			clientWithoutProxy: notFound,
			regularClient:      ok,
		},
		{
			name:               "redirect: endpoint to be proxied works the way the operand reaches it",
			clientWithProxy:    notFound,
			clientWithoutProxy: notFound,
			regularClient:      ok,
		},
	}
	endpointURL := mustParse(t, endpoint)
	for _, tt := range tests {
		for _, mismatchOnly := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s (mismatchOnly=%v)", tt.name, mismatchOnly), func(t *testing.T) {
				regular := tt.regularClient
				if regular == nil {
					regular = tt.clientWithProxy
					if noProxyMatches(tt.noProxy, endpointURL) {
						regular = tt.clientWithoutProxy
					}
				}
				clients := probeClients{
					regular:     &http.Client{Transport: regular},
					direct:      &http.Client{Transport: tt.clientWithoutProxy},
					forcedProxy: &http.Client{Transport: tt.clientWithProxy},
				}
				err := checkProxyConfig(context.Background(), endpointURL, tt.noProxy, clients, mismatchOnly)
				if len(tt.wantErr) == 0 || (mismatchOnly && tt.bothDown) {
					require.NoError(t, err)
					return
				}
				require.EqualError(t, err, tt.wantErr)
			})
		}
	}
}

// Test_checkProxyConfig_redactsPassword checks that credentials in an endpoint URL never end up in
// errors or warning events, as those are visible in conditions and events.
func Test_checkProxyConfig_redactsPassword(t *testing.T) {
	endpointURL := mustParse(t, "https://user:secret@idp.example.com/healthz")
	bad := &http.Client{Transport: notFound}
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
		recorder := newRecorder(t)
		group := &warningGroup{eventReason: "R", endpoints: endpoints(endpointURL)}
		(&proxyConfigChecker{}).warnIfUnreachable(context.Background(), recorder, errorTransport, ResolvedProxy{}, "", group)
		require.Len(t, recorder.Events(), 1)
		require.NotContains(t, recorder.Events()[0].Message, "secret")
	})

	t.Run("invalid URL", func(t *testing.T) {
		// The host contains a space, so no request can be built for it.
		endpoint := &url.URL{Scheme: "https", User: url.UserPassword("user", "secret"), Host: "bad host"}
		err := isEndpointReachable(context.Background(), endpoint, &http.Client{Transport: ok})
		require.ErrorContains(t, err, "invalid endpoint")
		require.NotContains(t, err.Error(), "secret")
	})
}

// Test_warnIfUnreachable checks when the warning probes run: they are skipped while the proxy, the trust
// and the endpoints are unchanged since the last success, and they are retried while they keep failing.
func Test_warnIfUnreachable(t *testing.T) {
	const (
		endpointA = "https://a.example.com"
		endpointB = "https://b.example.com"
	)
	var (
		onlyA = []string{endpointA}
		both  = []string{endpointA, endpointB}

		proxyA       = ResolvedProxy{HTTPProxy: "http://proxy-a:3128"}
		proxyB       = ResolvedProxy{HTTPProxy: "http://proxy-b:3128"}
		proxyAWithCA = ResolvedProxy{HTTPProxy: "http://proxy-a:3128", TrustedCAName: "proxy-ca"}

		// the warnings the controller emits when the endpoints are down
		aDown     = []string{fmt.Sprintf("endpoints unreachable through proxy: %q returned 404", endpointA)}
		aAndBDown = []string{fmt.Sprintf("endpoints unreachable through proxy: %q returned 404; %q returned 404", endpointA, endpointB)}
	)

	// step is one warnIfUnreachable call on the same group, everything it needs is spelled out.
	type step struct {
		proxy     ResolvedProxy
		trust     string
		endpoints []string
		listErr   error
		// transport answers the probes, ok or notFound.
		transport    http.RoundTripper
		wantWarnings []string
	}
	tests := []struct {
		name  string
		steps []step
	}{
		{name: "reachable endpoint emits no warning", steps: []step{
			{proxy: proxyA, endpoints: onlyA, transport: ok},
		}},
		{name: "unreachable endpoint emits a warning", steps: []step{
			{proxy: proxyA, endpoints: onlyA, transport: notFound, wantWarnings: aDown},
		}},
		{name: "several unreachable endpoints emit a single warning", steps: []step{
			{proxy: proxyA, endpoints: both, transport: notFound, wantWarnings: aAndBDown},
		}},
		{name: "unchanged configuration is not probed again", steps: []step{
			{proxy: proxyA, endpoints: onlyA, transport: ok},
			{proxy: proxyA, endpoints: onlyA, transport: notFound},
		}},
		{name: "changed proxy is probed again", steps: []step{
			{proxy: proxyA, endpoints: onlyA, transport: ok},
			{proxy: proxyB, endpoints: onlyA, transport: notFound, wantWarnings: aDown},
		}},
		{name: "changed endpoints are probed again", steps: []step{
			{proxy: proxyA, endpoints: onlyA, transport: ok},
			{proxy: proxyA, endpoints: both, transport: notFound, wantWarnings: aAndBDown},
		}},
		{name: "changed trusted CAs are probed again", steps: []step{
			{proxy: proxyA, trust: "trust-1", endpoints: onlyA, transport: ok},
			{proxy: proxyA, trust: "trust-1", endpoints: onlyA, transport: notFound},
			{proxy: proxyA, trust: "trust-2", endpoints: onlyA, transport: notFound, wantWarnings: aDown},
		}},
		{name: "changed proxy trusted CA name is probed again", steps: []step{
			{proxy: proxyA, endpoints: onlyA, transport: ok},
			{proxy: proxyAWithCA, endpoints: onlyA, transport: notFound, wantWarnings: aDown},
		}},
		{name: "failing endpoints are probed again every time", steps: []step{
			{proxy: proxyA, endpoints: onlyA, transport: notFound, wantWarnings: aDown},
			{proxy: proxyA, endpoints: onlyA, transport: notFound, wantWarnings: aDown},
		}},
		{name: "returning to a validated configuration after a failure probes it again", steps: []step{
			{proxy: proxyA, endpoints: onlyA, transport: ok},
			{proxy: proxyB, endpoints: onlyA, transport: notFound, wantWarnings: aDown},
			{proxy: proxyA, endpoints: onlyA, transport: notFound, wantWarnings: aDown},
		}},
		{name: "removing all endpoints forgets the validation", steps: []step{
			{proxy: proxyA, endpoints: onlyA, transport: ok},
			{proxy: proxyA, endpoints: nil, transport: ok},
			{proxy: proxyA, endpoints: onlyA, transport: notFound, wantWarnings: aDown},
		}},
		{name: "failing to list endpoints keeps the validation", steps: []step{
			{proxy: proxyA, endpoints: onlyA, transport: ok},
			{proxy: proxyA, listErr: errBoom, transport: notFound},
			{proxy: proxyA, endpoints: onlyA, transport: notFound},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			group := &warningGroup{eventReason: "R"}
			for i, s := range tt.steps {
				urls := mustParseAll(t, s.endpoints...)
				group.endpoints = func() ([]*url.URL, error) { return urls, s.listErr }
				recorder := newRecorder(t)

				(&proxyConfigChecker{}).warnIfUnreachable(context.Background(), recorder, &http.Client{Transport: s.transport}, s.proxy, s.trust, group)

				var warnings []string
				for _, event := range recorder.Events() {
					require.Equal(t, "R", event.Reason, "step %d", i)
					warnings = append(warnings, event.Message)
				}
				require.Equal(t, s.wantWarnings, warnings, "step %d", i)
			}
		})
	}
}

// TestSync_failures checks that every failure before the endpoints are probed is returned, so that
// it degrades the operator, with an error telling what failed.
func TestSync_failures(t *testing.T) {
	configuredProxy := ResolvedProxy{HTTPSProxy: "http://proxy:3128"}

	tests := []struct {
		name    string
		checker func(t *testing.T) *proxyConfigChecker
		wantErr string
		wantIs  error
	}{
		{
			name: "proxy resolution fails",
			checker: func(t *testing.T) *proxyConfigChecker {
				return &proxyConfigChecker{proxyResolver: &fakeResolver{err: errBoom}}
			},
			wantErr: "failed to resolve proxy",
			wantIs:  errBoom,
		},
		{
			name: "invalid proxy URL is reported before probing",
			checker: func(t *testing.T) *proxyConfigChecker {
				p := &proxyConfigChecker{proxyResolver: &fakeResolver{proxy: ResolvedProxy{HTTPSProxy: "::"}}}
				WithEndpoints(DegradeOnFailure, func() ([]*url.URL, error) { return nil, errBoom })(p)
				return p
			},
			wantErr: "HTTPS_PROXY is not a valid proxy URL",
		},
		{
			name: "endpoints cannot be listed",
			checker: func(t *testing.T) *proxyConfigChecker {
				p := &proxyConfigChecker{proxyResolver: &fakeResolver{proxy: configuredProxy}}
				WithEndpoints(DegradeOnFailure, func() ([]*url.URL, error) { return nil, errBoom })(p)
				return p
			},
			wantErr: "failed to get endpoints for proxy validation",
			wantIs:  errBoom,
		},
		{
			name: "system CA configmap is missing",
			checker: func(t *testing.T) *proxyConfigChecker {
				return &proxyConfigChecker{
					proxyResolver:   &fakeResolver{proxy: configuredProxy},
					configMapLister: newCMLister(t),
					caConfigMaps:    map[string][]string{"ns": {"missing-ca"}},
				}
			},
			wantErr: "failed to create HTTP clients for proxy validation",
		},
		{
			name: "regular transport cannot be built",
			checker: func(t *testing.T) *proxyConfigChecker {
				return &proxyConfigChecker{proxyResolver: &fakeResolver{proxy: configuredProxy, transports: []http.RoundTripper{nil}}}
			},
			wantErr: "failed to create HTTP clients for proxy validation",
			wantIs:  errBoom,
		},
		{
			name: "direct transport cannot be built",
			checker: func(t *testing.T) *proxyConfigChecker {
				return &proxyConfigChecker{proxyResolver: &fakeResolver{proxy: configuredProxy, transports: []http.RoundTripper{ok, nil}}}
			},
			wantErr: "failed to create HTTP clients for proxy validation",
			wantIs:  errBoom,
		},
		{
			name: "forced proxy transport cannot be built",
			checker: func(t *testing.T) *proxyConfigChecker {
				return &proxyConfigChecker{proxyResolver: &fakeResolver{proxy: configuredProxy, transports: []http.RoundTripper{ok, ok, nil}}}
			},
			wantErr: "failed to create HTTP clients for proxy validation",
			wantIs:  errBoom,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := runSync(t, tt.checker(t))
			require.ErrorContains(t, err, tt.wantErr)
			if tt.wantIs != nil {
				require.ErrorIs(t, err, tt.wantIs)
			}
		})
	}
}

// TestSync_noProxyConfigured checks that nothing is probed when no proxy is configured, and that the
// earlier successful warning validations are forgotten.
func TestSync_noProxyConfigured(t *testing.T) {
	group := &warningGroup{eventReason: "R", lastValidationHash: "previous"}
	p := &proxyConfigChecker{proxyResolver: &fakeResolver{}, warningGroups: []*warningGroup{group}}
	WithEndpoints(DegradeOnFailure, func() ([]*url.URL, error) {
		t.Error("endpoints must not be probed without a proxy")
		return nil, nil
	})(p)

	_, err := runSync(t, p)
	require.NoError(t, err)
	require.Empty(t, group.lastValidationHash, "removing the proxy forgets the validations")
}

// TestSync_endpointFailures checks that the endpoint failures are aggregated in the order of the endpoints,
// that DegradeOnNoProxyMismatch ignores an endpoint that is down, and that the warning probes are skipped.
func TestSync_endpointFailures(t *testing.T) {
	p := &proxyConfigChecker{proxyResolver: &fakeResolver{
		proxy:      ResolvedProxy{HTTPSProxy: "http://proxy:3128"},
		transports: []http.RoundTripper{notFound, notFound, notFound},
	}}
	hosts := []string{"a.example.com", "b.example.com", "c.example.com"}
	var degrading []*url.URL
	for _, host := range hosts {
		degrading = append(degrading, mustParse(t, "https://"+host))
	}
	WithEndpoints(DegradeOnFailure, endpoints(degrading...))(p)
	WithEndpoints(DegradeOnNoProxyMismatch, endpoints(mustParse(t, "https://d.example.com")))(p)
	WithEndpointWarnings("R", func() ([]*url.URL, error) {
		t.Error("warning groups must not be probed when an endpoint check fails")
		return nil, nil
	})(p)

	_, err := runSync(t, p)
	require.Error(t, err)
	msg := err.Error()
	require.NotContains(t, msg, "d.example.com", "DegradeOnNoProxyMismatch ignores endpoints unreachable both ways")
	last := -1
	for _, host := range hosts {
		i := strings.Index(msg, host)
		require.Greater(t, i, last, "errors are missing or out of order at %q: %v", host, msg)
		last = i
	}
}

// TestSync_nilEndpoint checks that a nil endpoint returned by a callback is reported as an error
// instead of panicking, and that the warning probes ignore it without degrading.
func TestSync_nilEndpoint(t *testing.T) {
	p := &proxyConfigChecker{proxyResolver: &fakeResolver{
		proxy:      ResolvedProxy{HTTPSProxy: "http://proxy:3128"},
		transports: []http.RoundTripper{ok, ok, ok},
	}}
	WithEndpoints(DegradeOnFailure, endpoints(mustParse(t, "https://a.example.com"), nil))(p)

	_, err := runSync(t, p)
	require.ErrorContains(t, err, "endpoint #1 is nil")

	p = &proxyConfigChecker{proxyResolver: &fakeResolver{
		proxy:      ResolvedProxy{HTTPSProxy: "http://proxy:3128"},
		transports: []http.RoundTripper{ok, ok, ok},
	}}
	WithEndpointWarnings("R", endpoints(nil))(p)
	recorder, err := runSync(t, p)
	require.NoError(t, err)
	require.Empty(t, recorder.Events())
}

// barrierRoundTripper succeeds only when all the expected requests are in flight at the same time.
type barrierRoundTripper struct {
	expected int
	mu       sync.Mutex
	arrived  int
	released chan struct{}
}

func (b *barrierRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	b.mu.Lock()
	b.arrived++
	if b.arrived == b.expected {
		close(b.released)
	}
	b.mu.Unlock()

	select {
	case <-b.released:
		return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
	case <-time.After(2 * time.Second):
		return nil, fmt.Errorf("the other requests did not arrive, the endpoints are checked sequentially")
	}
}

// TestSync_endpointsAreCheckedConcurrently checks that the endpoints are probed at the same time.
func TestSync_endpointsAreCheckedConcurrently(t *testing.T) {
	urls := []*url.URL{mustParse(t, "https://a.example.com"), mustParse(t, "https://b.example.com"), mustParse(t, "https://c.example.com")}
	barrier := &barrierRoundTripper{expected: len(urls), released: make(chan struct{})}
	// The proxy covers none of the endpoints, so only the regular transport is used and succeeds.
	p := &proxyConfigChecker{proxyResolver: &fakeResolver{
		proxy:      ResolvedProxy{HTTPSProxy: "http://proxy:3128"},
		transports: []http.RoundTripper{barrier, notFound, notFound},
	}}
	WithEndpoints(DegradeOnFailure, endpoints(urls...))(p)

	_, err := runSync(t, p)
	require.NoError(t, err)
}

// TestSync_endpointWarnings checks that sync emits a warning for an unreachable warning endpoint
// without returning an error.
func TestSync_endpointWarnings(t *testing.T) {
	p := &proxyConfigChecker{proxyResolver: &fakeResolver{
		proxy: ResolvedProxy{HTTPSProxy: "http://proxy:3128"},
		// the warnings are probed with the regular client, which is created first
		transports: []http.RoundTripper{notFound, ok, ok},
	}}
	WithEndpointWarnings("IdPUnreachable", endpoints(mustParse(t, "https://idp.example.com")))(p)

	recorder, err := runSync(t, p)
	require.NoError(t, err, "unreachable warning endpoints never degrade")
	require.Len(t, recorder.Events(), 1)
	require.Equal(t, "IdPUnreachable", recorder.Events()[0].Reason)
}

// Test_noProxyMatches checks that noProxyMatches reports whether NO_PROXY covers an endpoint. The matching
// rules themselves belong to httpproxy, so only what the wrapper and its callers rely on is covered.
func Test_noProxyMatches(t *testing.T) {
	tests := []struct {
		name     string
		noProxy  string
		endpoint string
		want     bool
	}{
		{name: "empty NO_PROXY covers nothing", noProxy: "", endpoint: "https://example.com", want: false},
		{name: "listed host is covered", noProxy: "example.com", endpoint: "https://example.com", want: true},
		{name: "unlisted host is not covered", noProxy: "example.com", endpoint: "https://other.org", want: false},
		{name: "loopback address is always covered", noProxy: "", endpoint: "https://127.0.0.1", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, noProxyMatches(tt.noProxy, mustParse(t, tt.endpoint)))
		})
	}
}

// Test_validateProxyURLs checks that a malformed proxy URL is rejected with an error naming the setting
// but not its value, as it can contain credentials, and that valid ones are accepted.
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
		})
	}
}

// Test_getCAPool checks how the trust pool is built from the CA ConfigMaps and the trusted bundle callbacks:
// the ConfigMaps replace the system roots, the callback bundles are added on top of the base, and the pool
// is nil when there is nothing to add, so that the system trust is used.
func Test_getCAPool(t *testing.T) {
	var (
		// every certificate is distinct, so that the expected pool tells where each one came from
		inDataCA, inBinaryDataCA, fromCallbackCA, fromOtherCallbackCA = newTestCAPEM(t), newTestCAPEM(t), newTestCAPEM(t), newTestCAPEM(t)

		inData       = &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "in-data"}, Data: map[string]string{trustedCAKey: string(inDataCA)}}
		inBinaryData = &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "in-binary-data"}, BinaryData: map[string][]byte{trustedCAKey: inBinaryDataCA}}
		unparsable   = &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "unparsable"}, Data: map[string]string{trustedCAKey: "not a certificate"}}
	)

	// bundleSource is what one WithTrustedCABundles callback returns.
	type bundleSource struct {
		bundles [][]byte
		err     error
	}

	system, err := x509.SystemCertPool()
	require.NoError(t, err)

	tests := []struct {
		name string
		// configMaps are all configured as system trust ConfigMaps, all of them in the namespace "ns".
		configMaps []*corev1.ConfigMap
		sources    []bundleSource
		// wantSystem tells whether the system roots are in the pool, next to wantCAs. Neither means a nil pool.
		wantSystem bool
		wantCAs    [][]byte
		wantErr    string
	}{
		{
			name: "nothing configured keeps the system trust",
		},
		{
			name:    "callbacks without bundles keep the system trust",
			sources: []bundleSource{{bundles: nil}},
		},
		{
			name:       "configmap data is trusted",
			configMaps: []*corev1.ConfigMap{inData},
			wantCAs:    [][]byte{inDataCA},
		},
		{
			name:       "configmap binary data is trusted",
			configMaps: []*corev1.ConfigMap{inBinaryData},
			wantCAs:    [][]byte{inBinaryDataCA},
		},
		{
			name:       "callback bundles without configmaps are added to the system roots",
			sources:    []bundleSource{{bundles: [][]byte{fromCallbackCA}}},
			wantSystem: true,
			wantCAs:    [][]byte{fromCallbackCA},
		},
		{
			name:       "callback bundles with configmaps replace the system roots",
			configMaps: []*corev1.ConfigMap{inData},
			sources:    []bundleSource{{bundles: [][]byte{fromCallbackCA}}},
			wantCAs:    [][]byte{inDataCA, fromCallbackCA},
		},
		{
			name:       "configmaps and the bundles of all callbacks are combined",
			configMaps: []*corev1.ConfigMap{inData, inBinaryData},
			sources:    []bundleSource{{bundles: [][]byte{fromCallbackCA}}, {bundles: [][]byte{fromOtherCallbackCA}}},
			wantCAs:    [][]byte{inDataCA, inBinaryDataCA, fromCallbackCA, fromOtherCallbackCA},
		},
		{
			name:       "unparsable configmap is an error",
			configMaps: []*corev1.ConfigMap{unparsable},
			wantErr:    "unable to parse CA bundle from configmap ns/unparsable",
		},
		{
			name:    "unparsable callback bundle is an error",
			sources: []bundleSource{{bundles: [][]byte{[]byte("garbage")}}},
			wantErr: "unable to parse trusted CA bundle #0",
		},
		{
			name:    "callback error is returned",
			sources: []bundleSource{{err: errBoom}},
			wantErr: "boom",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var names []string
			for _, cm := range tt.configMaps {
				names = append(names, cm.Name)
			}
			p := &proxyConfigChecker{configMapLister: newCMLister(t, tt.configMaps...), caConfigMaps: map[string][]string{"ns": names}}
			for _, source := range tt.sources {
				WithTrustedCABundles(func() ([][]byte, error) { return source.bundles, source.err })(p)
			}

			pool, _, err := p.getCAPool()
			if len(tt.wantErr) > 0 {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			if !tt.wantSystem && len(tt.wantCAs) == 0 {
				require.Nil(t, pool)
				return
			}
			want := x509.NewCertPool()
			if tt.wantSystem {
				want = system.Clone()
			}
			for _, pem := range tt.wantCAs {
				require.True(t, want.AppendCertsFromPEM(pem))
			}
			require.True(t, want.Equal(pool), "the pool does not hold exactly the wanted CAs")
		})
	}
}

// Test_getCAPool_digest checks that the digest of the trusted CAs is stable between calls and changes
// when a bundle changes.
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
	for range 10 {
		require.Equal(t, first, digest(pemA), "digest must not depend on map iteration order")
	}
	require.NotEqual(t, first, digest(pemB), "digest must change with the trusted CA bundles")
}

// Test_createHTTPClients checks how every probe client routes. The regular client honors NO_PROXY, the direct
// one never uses the proxy and the forced proxy one uses it for everything but loopback addresses.
// All of them route by the proxy they are given, not by the one the resolver would resolve again.
func Test_createHTTPClients(t *testing.T) {
	// The resolver holds a stale proxy, the clients must route by the proxy passed in.
	stale := ResolvedProxy{HTTPSProxy: "http://stale:3128"}
	given := ResolvedProxy{HTTPSProxy: "http://current:3128", NoProxy: []string{"internal.example.com"}}
	p := &proxyConfigChecker{proxyResolver: &transportResolver{proxy: stale, cms: newCMLister(t)}}
	clients, _, err := p.createHTTPClients(given)
	require.NoError(t, err)

	// proxyHost returns the proxy the client uses for the endpoint, empty when it connects directly.
	proxyHost := func(client *http.Client, endpoint string) string {
		proxy := client.Transport.(*http.Transport).Proxy
		if proxy == nil {
			return ""
		}
		u, err := proxy(&http.Request{URL: mustParse(t, endpoint)})
		require.NoError(t, err)
		if u == nil {
			return ""
		}
		return u.Host
	}

	covered, notCovered := "https://internal.example.com", "https://external.org"
	require.Equal(t, "current:3128", proxyHost(clients.regular, notCovered))
	require.Empty(t, proxyHost(clients.regular, covered), "regular client must honor NO_PROXY")
	require.Empty(t, proxyHost(clients.direct, notCovered))
	require.Empty(t, proxyHost(clients.direct, covered))
	require.Equal(t, "current:3128", proxyHost(clients.forcedProxy, notCovered))
	require.Equal(t, "current:3128", proxyHost(clients.forcedProxy, covered), "forced proxy client must proxy endpoints covered by NO_PROXY")
	for _, loopback := range []string{"https://localhost:8443", "https://127.0.0.1", "https://[::1]"} {
		require.Empty(t, proxyHost(clients.forcedProxy, loopback), "loopback %s must never be proxied", loopback)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// status returns a round tripper answering every request with the given status code.
func status(code int) http.RoundTripper {
	return roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: code, Body: http.NoBody}, nil
	})
}

// fakeResolver returns the transports in the order createHTTPClients requests them in:
// the regular one honoring NO_PROXY, the direct one and the one forced through the proxy.
// A nil transport makes NewTransport fail with errBoom.
type fakeResolver struct {
	proxy      ResolvedProxy
	err        error
	transports []http.RoundTripper
	calls      int
}

func (r *fakeResolver) ResolveProxy() (ResolvedProxy, error) { return r.proxy, r.err }

func (r *fakeResolver) NewTransport(...httptransport.Option) (http.RoundTripper, error) {
	t := r.transports[r.calls]
	r.calls++
	if t == nil {
		return nil, errBoom
	}
	return t, nil
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

func mustParseAll(t *testing.T, rawURLs ...string) []*url.URL {
	var urls []*url.URL
	for _, raw := range rawURLs {
		urls = append(urls, mustParse(t, raw))
	}
	return urls
}

func endpoints(urls ...*url.URL) func() ([]*url.URL, error) {
	return func() ([]*url.URL, error) { return urls, nil }
}

func newRecorder(t *testing.T) events.InMemoryRecorder {
	return events.NewInMemoryRecorder(t.Name(), clocktesting.NewFakePassiveClock(time.Now()))
}

func runSync(t *testing.T, p *proxyConfigChecker) (events.InMemoryRecorder, error) {
	recorder := newRecorder(t)
	return recorder, p.sync(context.Background(), factory.NewSyncContext(t.Name(), recorder))
}

func newTestCAPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
