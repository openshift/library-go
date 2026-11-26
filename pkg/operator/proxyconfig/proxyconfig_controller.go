package proxyconfig

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
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
// reaches them: through the proxy, unless NO_PROXY covers the endpoint. Failures only emit a warning event with
// the given reason, they never degrade the operator, and neither does an error returned by the function,
// which is only logged. The probe is skipped until the proxy settings, the trusted CAs or the endpoints change,
// and is retried while it keeps failing. The groups are only probed when all the WithEndpoints checks pass.
// It can be used multiple times, each group is tracked separately.
func WithEndpointWarnings(eventReason string, endpoints func() ([]*url.URL, error)) Option {
	return func(p *proxyConfigChecker) {
		p.warningGroups = append(p.warningGroups, &warningGroup{eventReason: eventReason, endpoints: endpoints})
	}
}

// WithTrustedCABundles adds a function returning PEM CA bundles that are trusted, in addition to the
// CA ConfigMaps passed to the controller, when probing endpoints. The bundles are shared by all probes.
// When CA ConfigMaps are passed to the controller, they are the base trust and replace the system roots,
// so they are expected to be complete, like the bundle the operand uses. Without CA ConfigMaps, the bundles
// are added to the system roots. It can be used multiple times.
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
	// newTransport builds a transport for the proxy, NewTransport unless replaced in tests.
	newTransport func(proxy ResolvedProxy, opts ...httptransport.Option) (http.RoundTripper, error)

	endpointGroups    []endpointGroup
	warningGroups     []*warningGroup
	trustedCABundles  []func() ([][]byte, error)
	informers         []factory.Informer
	filteredInformers []filteredInformers
}

// NewProxyConfigController returns a controller validating that proxy settings work.
// instanceName is used as the controller name, and thus determines the Degraded condition type.
//
// All the ConfigMaps are read through configMapInformers, so it must have an informer for every namespace
// of caConfigMaps and for the namespace of the proxy trusted CA (ResolvedProxy.TrustedCA). A missing
// namespace is a coding error and panics, like in any other combined lister of KubeInformersForNamespaces.
// The informers of the proxy trusted CA ConfigMap are not registered by the controller, because the ConfigMap
// is only known once the proxy is resolved, so pass them with WithInformers or WithFilteredInformers.
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
	p.newTransport = func(proxy ResolvedProxy, opts ...httptransport.Option) (http.RoundTripper, error) {
		return NewTransport(proxy, p.configMapLister, opts...)
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
		for i, u := range urls {
			if u == nil {
				return fmt.Errorf("failed to get endpoints for proxy validation: endpoint #%d is nil", i)
			}
			endpoints = append(endpoints, policyEndpoint{url: u, policy: group.policy})
		}
	}

	clients, trustDigest, err := p.createHTTPClients(proxy)
	if err != nil {
		return fmt.Errorf("failed to create HTTP clients for proxy validation: %w", err)
	}

	// The endpoints are independent and the clients are safe for concurrent use, so they are checked
	// concurrently. Every result goes to its own slot, which keeps the order of the errors deterministic,
	// so that a persistent failure does not keep changing the Degraded message.
	noProxy := strings.Join(proxy.NoProxy, ",")
	results := make([]error, len(endpoints))
	var wg sync.WaitGroup
	for i, endpoint := range endpoints {
		wg.Go(func() {
			mismatchOnly := endpoint.policy == DegradeOnNoProxyMismatch
			results[i] = checkProxyConfig(ctx, endpoint.url, noProxy, clients, mismatchOnly)
		})
	}
	wg.Wait()

	var errs []error
	for _, err := range results {
		if err != nil {
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
	for i, endpoint := range endpoints {
		if endpoint == nil {
			klog.Warningf("unable to get endpoints for proxy validation: endpoint #%d is nil", i)
			return
		}
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
	_, _ = fmt.Fprintf(h, "%s\n%s\n%s\n%s\n%s\n", proxy.HTTPProxy, proxy.HTTPSProxy, strings.Join(proxy.NoProxy, ","), proxy.TrustedCA, trustDigest)
	for _, u := range endpoints {
		_, _ = fmt.Fprintf(h, "%s\n", u)
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

// checkProxyConfig determines any mis-configuration in proxy settings by probing the endpoint
// the way NO_PROXY says it should be reached, and comparing the result with the other way.
//
// The expected way uses the regular client, so that redirects are followed the way the operand follows
// them. Nothing more is probed when it works. When it fails, the other way tells a misconfiguration
// (the endpoint is reachable the other way) from an endpoint that is simply down (it is not).
// When mismatchOnly is set, an endpoint that is down is not an error, since nothing can be
// concluded about the proxy settings from it.
func checkProxyConfig(ctx context.Context, endpointURL *url.URL, noProxy string, clients probeClients, mismatchOnly bool) error {
	expectedErr := isEndpointReachable(ctx, endpointURL, clients.regular)
	if expectedErr == nil {
		return nil
	}

	// The password is redacted, the messages end up in the Degraded condition.
	endpoint := endpointURL.Redacted()

	// Covered endpoints are expected to be reached directly, the other ones through the proxy.
	var withProxyErr, withoutProxyErr error
	var coverage, subject string
	if noProxyMatches(noProxy, endpointURL) {
		withoutProxyErr = expectedErr
		withProxyErr = isEndpointReachable(ctx, endpointURL, clients.forcedProxy)
		coverage = fmt.Sprintf("found in NO_PROXY(%q)", noProxy)
		subject = fmt.Sprintf("endpoint(%q) %s", endpoint, coverage)
	} else {
		withProxyErr = expectedErr
		withoutProxyErr = isEndpointReachable(ctx, endpointURL, clients.direct)
		coverage = fmt.Sprintf("missing in NO_PROXY(%q)", noProxy)
		subject = fmt.Sprintf("endpoint(%q)", endpoint)
	}

	// Reachable the other way: NO_PROXY and the way the endpoint can be reached disagree.
	if withProxyErr == nil || withoutProxyErr == nil {
		return fmt.Errorf("failed to reach endpoint(%q) %s with error: %v", endpoint, coverage, expectedErr)
	}

	// Not reachable at all.
	if mismatchOnly {
		klog.V(2).Infof("%s is unreachable with proxy(%v) and without proxy(%v), ignoring", subject, withProxyErr, withoutProxyErr)
		return nil
	}
	return fmt.Errorf("%s is unreachable with proxy(%v) and without proxy(%v)", subject, withProxyErr, withoutProxyErr)
}

// probeClients are the HTTP clients used to probe endpoints.
type probeClients struct {
	// regular honors NO_PROXY, like the operand does.
	regular *http.Client
	// direct never goes through the proxy.
	direct *http.Client
	// forcedProxy always goes through the proxy, even for endpoints covered by NO_PROXY.
	forcedProxy *http.Client
}

// createHTTPClients returns the probe clients and a digest of the CAs they trust.
func (p *proxyConfigChecker) createHTTPClients(proxy ResolvedProxy) (probeClients, string, error) {
	caPool, trustDigest, err := p.getCAPool()
	if err != nil {
		return probeClients{}, "", err
	}
	// The proxy trusted CA is added to the transports by NewTransport, so its contents are only hashed here.
	proxyCA, err := loadProxyTrustedCA(p.configMapLister, proxy)
	if err != nil {
		return probeClients{}, "", err
	}
	trustDigest = fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%s\n%d:%s", trustDigest, len(proxyCA), proxyCA))))
	poolOpt := httptransport.WithCertPool(caPool)

	// The transports are built for the proxy this sync resolved, so that the probes cannot route by
	// settings other than the ones the results are evaluated and recorded for.
	newClient := func(proxyFunc func(*url.URL) (*url.URL, error)) (*http.Client, error) {
		proxyOpt := httptransport.WithProxyFunc(nil)
		if proxyFunc != nil {
			proxyOpt = httptransport.WithProxyFunc(func(req *http.Request) (*url.URL, error) { return proxyFunc(req.URL) })
		}
		transport, err := p.newTransport(proxy, poolOpt, proxyOpt)
		if err != nil {
			return nil, err
		}
		return &http.Client{Transport: transport}, nil
	}

	regular, err := newClient(proxy.ProxyFunc())
	if err != nil {
		return probeClients{}, "", err
	}

	direct, err := newClient(nil)
	if err != nil {
		return probeClients{}, "", err
	}

	// NO_PROXY is left out so that the endpoints it covers are also probed through the proxy.
	// Loopback addresses are still reached directly: they are never proxied, regardless of NO_PROXY,
	// so there is no NO_PROXY misconfiguration to detect, and through the proxy they would hit
	// the proxy host's own loopback interface.
	forcedProxy, err := newClient(ResolvedProxy{HTTPProxy: proxy.HTTPProxy, HTTPSProxy: proxy.HTTPSProxy}.ProxyFunc())
	if err != nil {
		return probeClients{}, "", err
	}

	return probeClients{regular: regular, direct: direct, forcedProxy: forcedProxy}, trustDigest, nil
}

// getCAPool builds the pool the probe clients trust and a digest of its CAs, which
// does not cover the proxy trusted CA that NewTransport adds. The system trust ConfigMaps are the base trust and replace
// the system roots, like the bundle the operand uses. The trusted CA bundles are added on top of the base,
// which is the system roots when there are no ConfigMaps. When there are no CAs to add, the pool is nil,
// so that the system roots are used.
func (p *proxyConfigChecker) getCAPool() (*x509.CertPool, string, error) {
	digest := sha256.New()
	track := func(bundle []byte) []byte {
		_, _ = fmt.Fprintf(digest, "%d:%s", len(bundle), bundle)
		return bundle
	}

	base := x509.NewCertPool()
	hasBase := false
	for _, ns := range slices.Sorted(maps.Keys(p.caConfigMaps)) {
		for _, cmName := range p.caConfigMaps[ns] {
			bundle, err := loadCAData(p.configMapLister, ns, cmName, trustedCAKey)
			if err != nil {
				return nil, "", err
			}
			if !base.AppendCertsFromPEM(track(bundle)) {
				return nil, "", fmt.Errorf("unable to parse CA bundle from configmap %s/%s", ns, cmName)
			}
			hasBase = true
		}
	}

	var extra [][]byte
	for _, trustedCABundles := range p.trustedCABundles {
		bundles, err := trustedCABundles()
		if err != nil {
			return nil, "", err
		}
		for _, bundle := range bundles {
			extra = append(extra, track(bundle))
		}
	}
	if !hasBase && len(extra) == 0 {
		return nil, "", nil
	}

	pool := base
	if !hasBase {
		var err error
		if pool, err = x509.SystemCertPool(); err != nil {
			return nil, "", fmt.Errorf("loading system certificate pool failed: %w", err)
		}
	}
	for i, bundle := range extra {
		if !pool.AppendCertsFromPEM(bundle) {
			return nil, "", fmt.Errorf("unable to parse trusted CA bundle #%d", i)
		}
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
