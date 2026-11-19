package proxyconfig

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http/httpproxy"

	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog/v2"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/network/httptransport"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

// Option customizes the proxy config controller.
type Option func(*proxyConfigChecker)

// EndpointPolicy defines what happens when an endpoint checked by WithEndpoints is misbehaving.
type EndpointPolicy int

const (
	// DegradeOnFailure reports any inconsistency, so the operator goes Degraded. The endpoint must be
	// reachable the way NO_PROXY says: directly when NO_PROXY covers it, through the proxy otherwise.
	// Use it for endpoints that are expected to be up, such as the ones served by the operand itself.
	DegradeOnFailure EndpointPolicy = iota
	// DegradeOnNoProxyMismatch reports only a definite NO_PROXY misconfiguration, so the operator goes
	// Degraded when the endpoint is reachable one way but NO_PROXY expects the other. An endpoint that
	// is unreachable both ways is ignored. Use it for endpoints that can be down for reasons unrelated
	// to the proxy, such as third-party identity providers.
	DegradeOnNoProxyMismatch
)

// WithEndpoints adds a function returning endpoints that are probed both with and without the proxy.
// The results are compared with whether NO_PROXY covers the endpoint, and the policy decides which
// disagreements are returned as sync errors. It can be used multiple times.
func WithEndpoints(policy EndpointPolicy, endpoints func() ([]*url.URL, error)) Option {
	return func(p *proxyConfigChecker) {
		p.endpointGroups = append(p.endpointGroups, endpointGroup{policy: policy, endpoints: endpoints})
	}
}

// WithEndpointWarnings adds a function returning endpoints that are probed the way the operand
// reaches them: through the proxy, unless NO_PROXY covers the endpoint. Failures only emit a warning event with the given reason, they never degrade the operator,
// and neither does an error returned by the function, which is only logged.
// The probe is skipped until the proxy settings, the trusted CAs or the endpoints change,
// and is retried while it keeps failing. The groups are only probed when all the WithEndpoints checks pass.
// It can be used multiple times, each group is tracked separately.
func WithEndpointWarnings(eventReason string, endpoints func() ([]*url.URL, error)) Option {
	return func(p *proxyConfigChecker) {
		p.warningGroups = append(p.warningGroups, &warningGroup{eventReason: eventReason, endpoints: endpoints})
	}
}

// WithTrustedCABundles adds a function returning PEM CA bundles that are trusted, in addition to the
// CA ConfigMaps passed to the controller, when probing endpoints. The bundles are shared by all probes.
// It can be used multiple times.
func WithTrustedCABundles(bundles func() ([][]byte, error)) Option {
	return func(p *proxyConfigChecker) { p.trustedCABundles = append(p.trustedCABundles, bundles) }
}

type endpointGroup struct {
	policy    EndpointPolicy
	endpoints func() ([]*url.URL, error)
}

// warningGroup is a set of endpoints probed through the proxy that is reported with a single event reason.
type warningGroup struct {
	eventReason string
	endpoints   func() ([]*url.URL, error)
	// lastValidationHash is the hash of the last fully successful validation.
	lastValidationHash string
}

// WithInformers adds informers that trigger the controller, typically the sources of the
// callbacks and the informer of the proxy resolver.
func WithInformers(informers ...factory.Informer) Option {
	return func(p *proxyConfigChecker) { p.informers = append(p.informers, informers...) }
}

// WithFilteredInformers adds informers that trigger the controller only for the objects
// accepted by the filter, e.g. to watch a namespace for a dynamic set of objects.
func WithFilteredInformers(filter factory.EventFilterFunc, informers ...factory.Informer) Option {
	return func(p *proxyConfigChecker) {
		p.filteredInformers = append(p.filteredInformers, filteredInformers{filter: filter, informers: informers})
	}
}

type filteredInformers struct {
	filter    factory.EventFilterFunc
	informers []factory.Informer
}

// proxyConfigChecker reports bad proxy configurations.
type proxyConfigChecker struct {
	configMapLister corev1listers.ConfigMapLister
	caConfigMaps    map[string][]string // ns -> []configmapNames
	proxyResolver   ProxyResolver

	endpointGroups    []endpointGroup
	warningGroups     []*warningGroup
	trustedCABundles  []func() ([][]byte, error)
	informers         []factory.Informer
	filteredInformers []filteredInformers
}

// NewProxyConfigController returns a controller validating that proxy settings work.
// instanceName is used as the controller name, and thus determines the Degraded condition type.
func NewProxyConfigController(
	instanceName string,
	proxyResolver ProxyResolver,
	configMapInformers v1helpers.KubeInformersForNamespaces,
	caConfigMaps map[string][]string,
	operatorClient v1helpers.OperatorClient,
	recorder events.Recorder,
	opts ...Option,
) factory.Controller {
	p := &proxyConfigChecker{
		configMapLister: configMapInformers.ConfigMapLister(),
		caConfigMaps:    caConfigMaps,
		proxyResolver:   proxyResolver,
	}
	for _, opt := range opts {
		opt(p)
	}

	c := factory.New().
		WithSync(p.sync).
		WithInformers(p.informers...).
		ResyncEvery(60 * time.Minute).
		WithSyncDegradedOnError(operatorClient)

	for _, f := range p.filteredInformers {
		c.WithFilteredEventsInformers(f.filter, f.informers...)
	}
	for ns, configMapNames := range caConfigMaps {
		c.WithFilteredEventsInformers(
			factory.NamesFilter(configMapNames...),
			configMapInformers.InformersFor(ns).Core().V1().ConfigMaps().Informer(),
		)
	}

	return c.ToController(instanceName+"Controller", recorder.WithComponentSuffix("proxy-config-controller"))
}

// sync attempts to connect to the configured endpoints using the active proxy settings and reports
// any misconfiguration. ResolveProxy returns effective proxy settings for both
// cluster-wide and component-scoped proxies, so the validation logic is the same.
func (p *proxyConfigChecker) sync(ctx context.Context, syncCtx factory.SyncContext) error {
	// The probe clients route requests using this proxy, but the resolver resolves the proxy again
	// to load its trusted CA. When that CA changes in between, the change triggers another sync.
	proxy, err := p.proxyResolver.ResolveProxy()
	if err != nil {
		return fmt.Errorf("failed to resolve proxy: %w", err)
	}
	if !proxy.IsProxyConfigured() {
		// Forget the successful validations, so that configuring the proxy again validates it again.
		for _, group := range p.warningGroups {
			group.lastValidationHash = ""
		}
		return nil
	}
	if err := validateProxyURLs(proxy); err != nil {
		return err
	}

	type policyEndpoint struct {
		url    *url.URL
		policy EndpointPolicy
	}
	var endpoints []policyEndpoint
	for _, group := range p.endpointGroups {
		urls, err := group.endpoints()
		if err != nil {
			return fmt.Errorf("failed to get endpoints for proxy validation: %w", err)
		}
		for _, u := range urls {
			endpoints = append(endpoints, policyEndpoint{url: u, policy: group.policy})
		}
	}

	clients, trustDigest, err := p.createHTTPClients(proxy)
	if err != nil {
		return fmt.Errorf("failed to create HTTP clients for proxy validation: %w", err)
	}

	var errs []error
	noProxy := strings.Join(proxy.NoProxy, ",")
	for _, endpoint := range endpoints {
		mismatchOnly := endpoint.policy == DegradeOnNoProxyMismatch
		if err := checkProxyConfig(ctx, endpoint.url, noProxy, clients, mismatchOnly); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return utilerrors.NewAggregate(errs)
	}

	for _, group := range p.warningGroups {
		p.warnIfUnreachable(ctx, syncCtx.Recorder(), clients.regular, proxy, trustDigest, group)
	}
	return nil
}

// warnIfUnreachable tests that the endpoints are reachable with the given client, which honors NO_PROXY.
// Only runs on config change (tracked by hash), trustDigest identifies the trusted CAs. Reports warnings for failures instead
// of returning errors (which would set Degraded), since external endpoints can be
// unreachable for reasons unrelated to proxy configuration.
func (p *proxyConfigChecker) warnIfUnreachable(ctx context.Context, recorder events.Recorder, client *http.Client, proxy ResolvedProxy, trustDigest string, group *warningGroup) {
	endpoints, err := group.endpoints()
	if err != nil {
		klog.Warningf("unable to get endpoints for proxy validation: %v", err)
		return
	}
	if len(endpoints) == 0 {
		group.lastValidationHash = ""
		return
	}

	endpointStrings := make([]string, 0, len(endpoints))
	for _, endpoint := range endpoints {
		endpointStrings = append(endpointStrings, endpoint.String())
	}
	hash := computeValidationHash(proxy, trustDigest, endpointStrings)
	if hash == group.lastValidationHash {
		return
	}

	var unreachable []string
	for _, endpoint := range endpoints {
		if err := isEndpointReachable(ctx, endpoint, client); err != nil {
			klog.Warningf("endpoint unreachable through proxy: %v", err)
			unreachable = append(unreachable, err.Error())
		}
	}
	if len(unreachable) > 0 {
		// Forget the last success, so that returning to that configuration validates it again.
		group.lastValidationHash = ""
		recorder.Warningf(group.eventReason, "endpoints unreachable through proxy: %s", strings.Join(unreachable, "; "))
	} else {
		group.lastValidationHash = hash
	}
}

func computeValidationHash(proxy ResolvedProxy, trustDigest string, endpoints []string) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\n%s\n%s\n%s\n%s\n", proxy.HTTPProxy, proxy.HTTPSProxy, strings.Join(proxy.NoProxy, ","), proxy.TrustedCAName, trustDigest)
	for _, u := range endpoints {
		fmt.Fprintf(h, "%s\n", u)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// validateProxyURLs returns an error when a configured proxy is not a valid URL. httpproxy ignores
// such a proxy and connects directly, so the probes would succeed without testing the proxy.
// The values are not included in the error, as proxy URLs can contain credentials.
func validateProxyURLs(proxy ResolvedProxy) error {
	proxyFunc := ResolvedProxy{HTTPProxy: proxy.HTTPProxy, HTTPSProxy: proxy.HTTPSProxy}.ProxyFunc()
	for _, c := range []struct{ scheme, name, value string }{
		{scheme: "http", name: "HTTP_PROXY", value: proxy.HTTPProxy},
		{scheme: "https", name: "HTTPS_PROXY", value: proxy.HTTPSProxy},
	} {
		if len(c.value) == 0 {
			continue
		}
		if proxyURL, err := proxyFunc(&url.URL{Scheme: c.scheme, Host: "proxy-validation.invalid"}); err != nil || proxyURL == nil {
			return fmt.Errorf("%s is not a valid proxy URL", c.name)
		}
	}
	return nil
}

// noProxyMatches returns true if the endpoint is covered by the noProxy setting.
func noProxyMatches(noProxy string, endpointURL *url.URL) bool {
	// With the dummy proxies set, ProxyFunc only returns nil when the endpoint is excluded by NoProxy.
	proxyURL, err := (&httpproxy.Config{HTTPProxy: "dummy", HTTPSProxy: "dummy", NoProxy: noProxy}).ProxyFunc()(endpointURL)
	return err == nil && proxyURL == nil
}

// checkProxyConfig determines any mis-configuration in proxy settings by attempting to connect
// to the endpoint the expected way and, when that fails, the other way, and comparing the results
// with expectations. The expected way uses the regular client, so that redirects are followed
// the way the operand follows them. When mismatchOnly is set, an endpoint that is unreachable
// both ways is not an error, since nothing can be concluded about the proxy settings from it.
func checkProxyConfig(ctx context.Context, endpointURL *url.URL, noProxy string, clients probeClients, mismatchOnly bool) error {
	expected := newLazyChecker(func() error { return isEndpointReachable(ctx, endpointURL, clients.regular) })
	withProxy := newLazyChecker(func() error { return isEndpointReachable(ctx, endpointURL, clients.forcedProxy) })
	withoutProxy := newLazyChecker(func() error { return isEndpointReachable(ctx, endpointURL, clients.direct) })
	noProxyMatchesEndpoint := noProxyMatches(noProxy, endpointURL)
	// The password is redacted, the messages end up in the Degraded condition.
	endpoint := endpointURL.Redacted()

	if noProxyMatchesEndpoint && expected() != nil {
		if withProxy() == nil {
			return fmt.Errorf("failed to reach endpoint(%q) found in NO_PROXY(%q) with error: %v", endpoint, noProxy, expected())
		}
		if mismatchOnly {
			klog.V(2).Infof("endpoint(%q) found in NO_PROXY(%q) is unreachable with proxy(%v) and without proxy(%v), ignoring", endpoint, noProxy, withProxy(), expected())
			return nil
		}
		return fmt.Errorf("endpoint(%q) found in NO_PROXY(%q) is unreachable with proxy(%v) and without proxy(%v)", endpoint, noProxy, withProxy(), expected())
	}

	if !noProxyMatchesEndpoint && expected() != nil {
		if withoutProxy() == nil {
			return fmt.Errorf("failed to reach endpoint(%q) missing in NO_PROXY(%q) with error: %v", endpoint, noProxy, expected())
		}
		if mismatchOnly {
			klog.V(2).Infof("endpoint(%q) is unreachable with proxy(%v) and without proxy(%v), ignoring", endpoint, expected(), withoutProxy())
			return nil
		}
		return fmt.Errorf("endpoint(%q) is unreachable with proxy(%v) and without proxy(%v)", endpoint, expected(), withoutProxy())
	}

	return nil
}

// probeClients are the HTTP clients used to probe endpoints.
type probeClients struct {
	// forcedProxy always goes through the proxy, even for endpoints covered by NO_PROXY.
	forcedProxy *http.Client
	// direct never goes through the proxy.
	direct *http.Client
	// regular honors NO_PROXY, like the operand does.
	regular *http.Client
}

// createHTTPClients returns the probe clients and a digest of the CAs they trust
// (except the proxy trusted CA, which is identified by proxy.TrustedCAName).
func (p *proxyConfigChecker) createHTTPClients(proxy ResolvedProxy) (probeClients, string, error) {
	caPool, trustDigest, err := p.getCAPool()
	if err != nil {
		return probeClients{}, "", err
	}
	poolOpt := httptransport.WithCertPool(caPool)

	// Route using the given proxy rather than the one the resolver resolves again, so that the
	// routing matches the proxy settings the validation results are recorded for.
	regularProxyFunc := proxy.ProxyFunc()
	regular, err := p.proxyResolver.NewTransport(poolOpt, httptransport.WithProxyFunc(func(req *http.Request) (*url.URL, error) {
		return regularProxyFunc(req.URL)
	}))
	if err != nil {
		return probeClients{}, "", err
	}

	// NO_PROXY is left out so that the endpoints it covers are also probed through the proxy.
	// Loopback addresses are still reached directly: they are never proxied, regardless of NO_PROXY,
	// so there is no NO_PROXY misconfiguration to detect, and through the proxy they would hit
	// the proxy host's own loopback interface.
	forcedProxyFunc := ResolvedProxy{HTTPProxy: proxy.HTTPProxy, HTTPSProxy: proxy.HTTPSProxy}.ProxyFunc()
	forcedProxy, err := p.proxyResolver.NewTransport(poolOpt, httptransport.WithProxyFunc(func(req *http.Request) (*url.URL, error) {
		return forcedProxyFunc(req.URL)
	}))
	if err != nil {
		return probeClients{}, "", err
	}

	direct, err := p.proxyResolver.NewTransport(poolOpt, httptransport.WithProxyFunc(nil))
	if err != nil {
		return probeClients{}, "", err
	}
	return probeClients{
		forcedProxy: &http.Client{Transport: forcedProxy},
		direct:      &http.Client{Transport: direct},
		regular:     &http.Client{Transport: regular},
	}, trustDigest, nil
}

// getCAPool builds a certificate pool from the configured system trust ConfigMaps and the trusted
// CA bundles, and returns it with a digest of its contents. When there are no CAs to add, the pool
// is nil, so that the system trust pool is used.
func (p *proxyConfigChecker) getCAPool() (*x509.CertPool, string, error) {
	pool := x509.NewCertPool()
	added := false
	digest := sha256.New()
	namespaces := make([]string, 0, len(p.caConfigMaps))
	for ns := range p.caConfigMaps {
		namespaces = append(namespaces, ns)
	}
	sort.Strings(namespaces)
	for _, ns := range namespaces {
		for _, cmName := range p.caConfigMaps[ns] {
			bundle, err := loadCAData(p.configMapLister, ns, cmName, trustedCAKey)
			if err != nil {
				return nil, "", err
			}
			if ok := pool.AppendCertsFromPEM(bundle); !ok {
				return nil, "", fmt.Errorf("unable to parse CA bundle from configmap %s/%s", ns, cmName)
			}
			added = true
			fmt.Fprintf(digest, "%d:%s", len(bundle), bundle)
		}
	}
	for _, trustedCABundles := range p.trustedCABundles {
		bundles, err := trustedCABundles()
		if err != nil {
			return nil, "", err
		}
		for i, bundle := range bundles {
			if ok := pool.AppendCertsFromPEM(bundle); !ok {
				return nil, "", fmt.Errorf("unable to parse trusted CA bundle #%d", i)
			}
			added = true
			fmt.Fprintf(digest, "%d:%s", len(bundle), bundle)
		}
	}
	if !added {
		pool = nil
	}
	return pool, fmt.Sprintf("%x", digest.Sum(nil)), nil
}

// isEndpointReachable returns nil if the given endpoint can be reached using the given client.
// The endpoint password is redacted from the returned error.
func isEndpointReachable(ctx context.Context, endpointURL *url.URL, client *http.Client) error {
	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second) // avoid waiting forever
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpointURL.String(), nil)
	if err != nil {
		return fmt.Errorf("invalid endpoint %q", endpointURL.Redacted())
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%q returned %d", endpointURL.Redacted(), resp.StatusCode)
	}
	return nil
}

// newLazyChecker returns a function that calculates an error value once
// and returns that error in subsequent calls
func newLazyChecker(f func() error) func() error {
	var err error
	var once sync.Once
	return func() error {
		once.Do(func() {
			err = f()
		})
		return err
	}
}
