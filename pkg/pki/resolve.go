package pki

import (
	"fmt"
	"strings"

	configv1alpha1 "github.com/openshift/api/config/v1alpha1"
	"github.com/openshift/library-go/pkg/crypto"
	"k8s.io/klog/v2"
)

// ResolvedCertificateConfig holds the resolved configuration for a specific
// certificate. Currently contains key configuration; will grow as the PKI API
// expands to include additional certificate properties.
type ResolvedCertificateConfig struct {
	// Key is the resolved key pair generator.
	Key crypto.KeyPairGenerator
}

// ResolveCertificateConfig resolves the effective certificate configuration
// for the given certificate from a PKI resource's certificates section
// (policy), most-specific-wins: a namedCertificates entry whose name matches
// the certificate's name and whose key is set, then the per-category override
// for certType, then the required defaults.
//
// name is the certificate's well-known prefixed qualified name (for example
// "openshift.io/service-ca.service-serving-signer") and is matched exactly
// against namedCertificates entries.
//
// policy must come from a PKI resource: callers that make PKI configuration
// conditional (for example on a feature gate) must not call this function at
// all when the feature is disabled. ResolveCertificateConfig never returns a
// partial configuration: every error means no configuration could be
// resolved.
//
// For CertificateTypePeer with no matching named entry, the resolved key is
// the stronger of the server and client resolutions.
func ResolveCertificateConfig(policy configv1alpha1.PKICertificatePolicy, certType CertificateType, name string) (ResolvedCertificateConfig, error) {
	logUnprefixedNameHint("Certificate", "namedCertificates override", name)
	if policy.Defaults.Key.Algorithm == "" {
		return ResolvedCertificateConfig{}, fmt.Errorf("resolving %s certificate %q: certificates.defaults.key.algorithm is required", certType, name)
	}
	// Validate the required defaults up front so an invalid resource fails
	// uniformly for every certificate type instead of degrading partially
	// (only the categories without an override).
	if _, err := KeyPairGeneratorFromAPI(policy.Defaults.Key); err != nil {
		return ResolvedCertificateConfig{}, fmt.Errorf("resolving %s certificate %q: invalid certificates.defaults.key: %w", certType, name, err)
	}

	// A named override wins outright when its key is set. The key is optional
	// in a named entry so that future certificate-level fields can be set
	// alone; an entry without a key is inert for key resolution and falls
	// through to the category override, then the defaults.
	if name != "" {
		if named := findNamedCertificateConfig(policy.NamedCertificates, name); named != nil && named.Key.Algorithm != "" {
			return certificateConfigFromKeyConfig(named.Key)
		}
	}

	switch certType {
	case CertificateTypeCA:
		return resolveKeyConfig(policy.Defaults, policy.CACertificates)
	case CertificateTypeServer:
		return resolveKeyConfig(policy.Defaults, policy.ServerCertificates)
	case CertificateTypeClient:
		return resolveKeyConfig(policy.Defaults, policy.ClientCertificates)
	case CertificateTypePeer:
		return resolvePeerKeyConfig(policy)
	default:
		return ResolvedCertificateConfig{}, fmt.Errorf("resolving %s certificate %q: unknown certificate type", certType, name)
	}
}

// resolveKeyConfig returns the override KeyConfig if its Algorithm is set,
// otherwise falls back to the default.
func resolveKeyConfig(defaults configv1alpha1.PKIDefaultCertificateConfig, override configv1alpha1.PKICertificateConfig) (ResolvedCertificateConfig, error) {
	apiKey := defaults.Key
	if override.Key.Algorithm != "" {
		apiKey = override.Key
	}
	return certificateConfigFromKeyConfig(apiKey)
}

// resolvePeerKeyConfig resolves both the server and client configs and
// returns whichever has higher NIST security strength. A matching named
// override is not looked up here: it already won at the top level of
// ResolveCertificateConfig.
func resolvePeerKeyConfig(policy configv1alpha1.PKICertificatePolicy) (ResolvedCertificateConfig, error) {
	serverCfg, err := resolveKeyConfig(policy.Defaults, policy.ServerCertificates)
	if err != nil {
		return ResolvedCertificateConfig{}, fmt.Errorf("resolving server config for peer: %w", err)
	}
	clientCfg, err := resolveKeyConfig(policy.Defaults, policy.ClientCertificates)
	if err != nil {
		return ResolvedCertificateConfig{}, fmt.Errorf("resolving client config for peer: %w", err)
	}
	key, err := strongerKeyPairGenerator(serverCfg.Key, clientCfg.Key)
	if err != nil {
		return ResolvedCertificateConfig{}, fmt.Errorf("resolving peer key: %w", err)
	}
	return ResolvedCertificateConfig{Key: key}, nil
}

// findNamedCertificateConfig returns the first namedCertificates entry whose
// name matches exactly. The API validates namedCertificates as a map keyed by
// name, so at most one entry per name can be stored; the first match is the
// deterministic fallback for invalid cached objects that contain duplicates.
func findNamedCertificateConfig(namedCertificates []configv1alpha1.PKINamedCertificateConfig, name string) *configv1alpha1.PKINamedCertificateConfig {
	for i := range namedCertificates {
		if namedCertificates[i].Name == name {
			return &namedCertificates[i]
		}
	}
	return nil
}

// certificateConfigFromKeyConfig converts an API KeyConfig to a
// ResolvedCertificateConfig. It is the shared conversion for every resolution
// tier and rejects an unset algorithm with an explicit error.
func certificateConfigFromKeyConfig(apiKey configv1alpha1.PKIKeyConfig) (ResolvedCertificateConfig, error) {
	if apiKey.Algorithm == "" {
		return ResolvedCertificateConfig{}, fmt.Errorf("no key configuration: key.algorithm is required")
	}
	g, err := KeyPairGeneratorFromAPI(apiKey)
	if err != nil {
		return ResolvedCertificateConfig{}, err
	}
	return ResolvedCertificateConfig{Key: g}, nil
}

// logUnprefixedNameHint logs at V(2) when name is not a prefixed qualified
// name and therefore cannot match any named entry. target names what the
// name would have matched, for example "namedCertificates override".
func logUnprefixedNameHint(noun, target, name string) {
	if name == "" || strings.Contains(name, "/") {
		return
	}
	klog.V(2).Infof("%s name %q is not a prefixed qualified name (expected a format like \"openshift.io/component.purpose\"); it cannot match any %s", noun, name, target)
}
