package pki

import (
	"fmt"

	configv1alpha1 "github.com/openshift/api/config/v1alpha1"
	"github.com/openshift/library-go/pkg/crypto"
)

// ResolvedKeyConfig holds the resolved configuration for a named key
// generated outside of any certificate.
type ResolvedKeyConfig struct {
	// Key is the resolved key pair generator.
	Key crypto.KeyPairGenerator
}

// ResolveKeyConfig returns the resolved configuration for the named key
// from a PKI resource's keys policy, and reports whether the key is
// configured. Named keys are opt-in with no inherited default; only the
// entry matching name is validated.
//
// name is the key's well-known prefixed qualified name (for example
// "openshift.io/kube-apiserver.bound-service-account-token-signer") and is
// matched exactly against namedKeys entries.
//
// keys must come from a PKI resource: callers that make PKI configuration
// conditional (for example on a feature gate) must not call this function at
// all when the feature is disabled.
func ResolveKeyConfig(keys configv1alpha1.PKIKeyPolicy, name string) (cfg ResolvedKeyConfig, ok bool, err error) {
	if name == "" {
		return ResolvedKeyConfig{}, false, nil
	}
	logUnprefixedNameHint("Key", "namedKeys entry", name)

	entry := findNamedKeyConfig(keys.NamedKeys, name)
	if entry == nil {
		return ResolvedKeyConfig{}, false, nil
	}
	// The key of a named key entry is required by the API, unlike the
	// optional key of a named certificate entry: a matching entry without
	// one is an invalid resource, not a not-configured result.
	if entry.Key.Algorithm == "" {
		return ResolvedKeyConfig{}, false, fmt.Errorf("resolving key %q: keys.namedKeys[%q].key.algorithm is required", name, name)
	}
	g, err := KeyPairGeneratorFromAPI(entry.Key)
	if err != nil {
		return ResolvedKeyConfig{}, false, fmt.Errorf("resolving key %q: %w", name, err)
	}
	return ResolvedKeyConfig{Key: g}, true, nil
}

// findNamedKeyConfig returns the first namedKeys entry whose name matches
// exactly. The API validates namedKeys as a map keyed by name, so at most
// one entry per name can be stored; the first match is the deterministic
// fallback for invalid cached objects that contain duplicates.
func findNamedKeyConfig(namedKeys []configv1alpha1.PKINamedKeyConfig, name string) *configv1alpha1.PKINamedKeyConfig {
	for i := range namedKeys {
		if namedKeys[i].Name == name {
			return &namedKeys[i]
		}
	}
	return nil
}
