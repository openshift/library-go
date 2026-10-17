package pki

import (
	"strings"
	"testing"

	configv1alpha1 "github.com/openshift/api/config/v1alpha1"

	"github.com/openshift/library-go/pkg/crypto"
)

func TestResolveKeyConfig(t *testing.T) {
	ecdsaP384 := configv1alpha1.PKIKeyConfig{
		Algorithm: configv1alpha1.PKIKeyAlgorithmECDSA,
		ECDSA:     configv1alpha1.PKIECDSAKeyConfig{Curve: configv1alpha1.PKIECDSACurveP384},
	}
	rsa3072 := configv1alpha1.PKIKeyConfig{
		Algorithm: configv1alpha1.PKIKeyAlgorithmRSA,
		RSA:       configv1alpha1.PKIRSAKeyConfig{KeySize: 3072},
	}
	rsa1024 := configv1alpha1.PKIKeyConfig{
		Algorithm: configv1alpha1.PKIKeyAlgorithmRSA,
		RSA:       configv1alpha1.PKIRSAKeyConfig{KeySize: 1024},
	}

	keys := func(entries ...configv1alpha1.PKINamedKeyConfig) configv1alpha1.PKIKeyPolicy {
		return configv1alpha1.PKIKeyPolicy{NamedKeys: entries}
	}
	namedKey := func(name string, key configv1alpha1.PKIKeyConfig) configv1alpha1.PKINamedKeyConfig {
		return configv1alpha1.PKINamedKeyConfig{Name: name, Key: key}
	}

	testCases := []struct {
		name    string
		keys    configv1alpha1.PKIKeyPolicy
		keyName string
		want    crypto.KeyPairGenerator
		wantOK  bool
		wantErr string // empty means no error expected
	}{
		{
			name:    "configured key resolves to its generator",
			keys:    keys(namedKey("openshift.io/test.signer", ecdsaP384)),
			keyName: "openshift.io/test.signer",
			want:    crypto.ECDSAKeyPairGenerator{Curve: crypto.P384},
			wantOK:  true,
		},
		{
			name:    "rsa key resolves to its generator",
			keys:    keys(namedKey("openshift.io/test.signer", rsa3072)),
			keyName: "openshift.io/test.signer",
			want:    crypto.RSAKeyPairGenerator{Bits: 3072},
			wantOK:  true,
		},
		{
			// Named keys are opt-in: a name with no entry is not configured,
			// not an error.
			name:    "name not configured is not an error",
			keys:    keys(namedKey("openshift.io/other.signer", ecdsaP384)),
			keyName: "openshift.io/test.signer",
			wantOK:  false,
		},
		{
			name:    "empty keys policy is not an error",
			keyName: "openshift.io/test.signer",
			wantOK:  false,
		},
		{
			// Unlike a named certificate entry, whose key is optional, the
			// key of a named key entry is required by the API: a matching
			// entry with an unset key is an error, not a fall-through.
			name:    "matching entry with unset key algorithm is an error",
			keys:    keys(configv1alpha1.PKINamedKeyConfig{Name: "openshift.io/test.signer"}),
			keyName: "openshift.io/test.signer",
			wantErr: `keys.namedKeys["openshift.io/test.signer"].key.algorithm is required`,
		},
		{
			name:    "invalid matching key is an error",
			keys:    keys(namedKey("openshift.io/test.signer", rsa1024)),
			keyName: "openshift.io/test.signer",
			wantErr: "invalid RSA key size",
		},
		{
			// Only the matching entry is validated: an invalid entry for
			// another key must not break this resolution.
			name:    "invalid non-matching entry is ignored",
			keys:    keys(namedKey("openshift.io/other.signer", rsa1024), namedKey("openshift.io/test.signer", ecdsaP384)),
			keyName: "openshift.io/test.signer",
			want:    crypto.ECDSAKeyPairGenerator{Curve: crypto.P384},
			wantOK:  true,
		},
		{
			// The API validates namedKeys as a map keyed by name, so
			// duplicates cannot be stored; first match is the deterministic
			// fallback for invalid cached objects that contain duplicates.
			name:    "duplicate names use the first match",
			keys:    keys(namedKey("openshift.io/test.signer", rsa3072), namedKey("openshift.io/test.signer", ecdsaP384)),
			keyName: "openshift.io/test.signer",
			want:    crypto.RSAKeyPairGenerator{Bits: 3072},
			wantOK:  true,
		},
		{
			// An empty name is never configured, even for an invalid cached
			// entry whose own name is empty.
			name:    "empty name is never configured",
			keys:    keys(namedKey("", ecdsaP384)),
			keyName: "",
			wantOK:  false,
		},
		{
			// Over-matching is a realistic hazard: the naming convention
			// produces near-miss pairs. Matching is exact.
			name:    "near-miss name does not match",
			keys:    keys(namedKey("openshift.io/test.signer-signer", ecdsaP384)),
			keyName: "openshift.io/test.signer",
			wantOK:  false,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, ok, err := ResolveKeyConfig(tc.keys, tc.keyName)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("ResolveKeyConfig() error = nil, want error containing %q", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("ResolveKeyConfig() error = %q, want it to contain %q", err.Error(), tc.wantErr)
				}
				// An error is never accompanied by a usable config.
				if ok || cfg.Key != nil {
					t.Errorf("ResolveKeyConfig() ok = %v, cfg.Key = %+v on error; want false and the zero value", ok, cfg.Key)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveKeyConfig() error = %v", err)
			}
			if ok != tc.wantOK {
				t.Fatalf("ResolveKeyConfig() ok = %v, want %v", ok, tc.wantOK)
			}
			if tc.wantOK {
				if cfg.Key != tc.want {
					t.Errorf("Key = %+v, want %+v", cfg.Key, tc.want)
				}
				return
			}
			// The zero-value contract: cfg is valid only when ok is true.
			if cfg.Key != nil {
				t.Errorf("Key = %+v, want the zero value when ok is false", cfg.Key)
			}
		})
	}
}
