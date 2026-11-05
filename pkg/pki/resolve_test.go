package pki

import (
	"strings"
	"testing"

	configv1alpha1 "github.com/openshift/api/config/v1alpha1"

	"github.com/openshift/library-go/pkg/crypto"
)

func TestResolveCertificateConfig(t *testing.T) {
	ecdsaP256 := configv1alpha1.PKIKeyConfig{
		Algorithm: configv1alpha1.PKIKeyAlgorithmECDSA,
		ECDSA:     configv1alpha1.PKIECDSAKeyConfig{Curve: configv1alpha1.PKIECDSACurveP256},
	}
	ecdsaP384 := configv1alpha1.PKIKeyConfig{
		Algorithm: configv1alpha1.PKIKeyAlgorithmECDSA,
		ECDSA:     configv1alpha1.PKIECDSAKeyConfig{Curve: configv1alpha1.PKIECDSACurveP384},
	}
	ecdsaP521 := configv1alpha1.PKIKeyConfig{
		Algorithm: configv1alpha1.PKIKeyAlgorithmECDSA,
		ECDSA:     configv1alpha1.PKIECDSAKeyConfig{Curve: configv1alpha1.PKIECDSACurveP521},
	}
	rsa2048 := configv1alpha1.PKIKeyConfig{
		Algorithm: configv1alpha1.PKIKeyAlgorithmRSA,
		RSA:       configv1alpha1.PKIRSAKeyConfig{KeySize: 2048},
	}
	rsa3072 := configv1alpha1.PKIKeyConfig{
		Algorithm: configv1alpha1.PKIKeyAlgorithmRSA,
		RSA:       configv1alpha1.PKIRSAKeyConfig{KeySize: 3072},
	}

	defaultsOnly := func(key configv1alpha1.PKIKeyConfig) configv1alpha1.PKICertificatePolicy {
		return configv1alpha1.PKICertificatePolicy{
			Defaults: configv1alpha1.PKIDefaultCertificateConfig{Key: key},
		}
	}

	testCases := []struct {
		name            string
		policy          configv1alpha1.PKICertificatePolicy
		certType        CertificateType
		certificateName string
		want            crypto.KeyPairGenerator
		wantErr         string // empty means no error expected
	}{
		{
			name:            "ca uses defaults when no category override",
			policy:          defaultsOnly(ecdsaP256),
			certType:        CertificateTypeCA,
			certificateName: "openshift.io/test.ca",
			want:            crypto.ECDSAKeyPairGenerator{Curve: crypto.P256},
		},
		{
			name:            "server uses defaults when no category override",
			policy:          defaultsOnly(ecdsaP256),
			certType:        CertificateTypeServer,
			certificateName: "openshift.io/test.server",
			want:            crypto.ECDSAKeyPairGenerator{Curve: crypto.P256},
		},
		{
			name:            "client uses defaults when no category override",
			policy:          defaultsOnly(ecdsaP256),
			certType:        CertificateTypeClient,
			certificateName: "openshift.io/test.client",
			want:            crypto.ECDSAKeyPairGenerator{Curve: crypto.P256},
		},
		{
			name: "ca category override wins over defaults",
			policy: configv1alpha1.PKICertificatePolicy{
				Defaults:       configv1alpha1.PKIDefaultCertificateConfig{Key: ecdsaP256},
				CACertificates: configv1alpha1.PKICertificateConfig{Key: ecdsaP384},
			},
			certType:        CertificateTypeCA,
			certificateName: "openshift.io/test.ca",
			want:            crypto.ECDSAKeyPairGenerator{Curve: crypto.P384},
		},
		{
			name: "server category override wins over defaults",
			policy: configv1alpha1.PKICertificatePolicy{
				Defaults:           configv1alpha1.PKIDefaultCertificateConfig{Key: ecdsaP256},
				ServerCertificates: configv1alpha1.PKICertificateConfig{Key: ecdsaP384},
			},
			certType:        CertificateTypeServer,
			certificateName: "openshift.io/test.server",
			want:            crypto.ECDSAKeyPairGenerator{Curve: crypto.P384},
		},
		{
			name: "client category override wins over defaults",
			policy: configv1alpha1.PKICertificatePolicy{
				Defaults:           configv1alpha1.PKIDefaultCertificateConfig{Key: ecdsaP256},
				ClientCertificates: configv1alpha1.PKICertificateConfig{Key: ecdsaP384},
			},
			certType:        CertificateTypeClient,
			certificateName: "openshift.io/test.client",
			want:            crypto.ECDSAKeyPairGenerator{Curve: crypto.P384},
		},
		{
			name: "named override wins over category override",
			policy: configv1alpha1.PKICertificatePolicy{
				Defaults:           configv1alpha1.PKIDefaultCertificateConfig{Key: ecdsaP256},
				ServerCertificates: configv1alpha1.PKICertificateConfig{Key: ecdsaP384},
				NamedCertificates: []configv1alpha1.PKINamedCertificateConfig{
					{
						Name:                 "openshift.io/test.server",
						PKICertificateConfig: configv1alpha1.PKICertificateConfig{Key: rsa2048},
					},
				},
			},
			certType:        CertificateTypeServer,
			certificateName: "openshift.io/test.server",
			want:            crypto.RSAKeyPairGenerator{Bits: 2048},
		},
		{
			name: "named override wins over defaults when no category override",
			policy: configv1alpha1.PKICertificatePolicy{
				Defaults: configv1alpha1.PKIDefaultCertificateConfig{Key: ecdsaP256},
				NamedCertificates: []configv1alpha1.PKINamedCertificateConfig{
					{
						Name:                 "openshift.io/test.server",
						PKICertificateConfig: configv1alpha1.PKICertificateConfig{Key: ecdsaP384},
					},
				},
			},
			certType:        CertificateTypeServer,
			certificateName: "openshift.io/test.server",
			want:            crypto.ECDSAKeyPairGenerator{Curve: crypto.P384},
		},
		{
			name: "named override applies to ca certificates",
			policy: configv1alpha1.PKICertificatePolicy{
				Defaults:       configv1alpha1.PKIDefaultCertificateConfig{Key: ecdsaP256},
				CACertificates: configv1alpha1.PKICertificateConfig{Key: ecdsaP384},
				NamedCertificates: []configv1alpha1.PKINamedCertificateConfig{
					{
						Name:                 "openshift.io/test.ca",
						PKICertificateConfig: configv1alpha1.PKICertificateConfig{Key: rsa2048},
					},
				},
			},
			certType:        CertificateTypeCA,
			certificateName: "openshift.io/test.ca",
			want:            crypto.RSAKeyPairGenerator{Bits: 2048},
		},
		{
			name: "named override applies to client certificates",
			policy: configv1alpha1.PKICertificatePolicy{
				Defaults: configv1alpha1.PKIDefaultCertificateConfig{Key: ecdsaP256},
				NamedCertificates: []configv1alpha1.PKINamedCertificateConfig{
					{
						Name:                 "openshift.io/test.client",
						PKICertificateConfig: configv1alpha1.PKICertificateConfig{Key: ecdsaP384},
					},
				},
			},
			certType:        CertificateTypeClient,
			certificateName: "openshift.io/test.client",
			want:            crypto.ECDSAKeyPairGenerator{Curve: crypto.P384},
		},
		{
			// A named entry without a key is inert for key resolution: the
			// key is optional in a named entry so that future
			// certificate-level fields can be set alone. The next
			// less-specific level (category override, then defaults) applies.
			name: "named entry with unset key falls through to category override",
			policy: configv1alpha1.PKICertificatePolicy{
				Defaults:           configv1alpha1.PKIDefaultCertificateConfig{Key: ecdsaP256},
				ServerCertificates: configv1alpha1.PKICertificateConfig{Key: ecdsaP384},
				NamedCertificates: []configv1alpha1.PKINamedCertificateConfig{
					{
						Name: "openshift.io/test.server",
					},
				},
			},
			certType:        CertificateTypeServer,
			certificateName: "openshift.io/test.server",
			want:            crypto.ECDSAKeyPairGenerator{Curve: crypto.P384},
		},
		{
			name: "named entry with unset key falls through to defaults",
			policy: configv1alpha1.PKICertificatePolicy{
				Defaults: configv1alpha1.PKIDefaultCertificateConfig{Key: ecdsaP256},
				NamedCertificates: []configv1alpha1.PKINamedCertificateConfig{
					{
						Name: "openshift.io/test.server",
					},
				},
			},
			certType:        CertificateTypeServer,
			certificateName: "openshift.io/test.server",
			want:            crypto.ECDSAKeyPairGenerator{Curve: crypto.P256},
		},
		{
			name: "named entry for another certificate is ignored",
			policy: configv1alpha1.PKICertificatePolicy{
				Defaults: configv1alpha1.PKIDefaultCertificateConfig{Key: ecdsaP256},
				NamedCertificates: []configv1alpha1.PKINamedCertificateConfig{
					{
						Name:                 "openshift.io/other.server",
						PKICertificateConfig: configv1alpha1.PKICertificateConfig{Key: rsa2048},
					},
				},
			},
			certType:        CertificateTypeServer,
			certificateName: "openshift.io/test.server",
			want:            crypto.ECDSAKeyPairGenerator{Curve: crypto.P256},
		},
		{
			// An empty certificate name never matches named entries, not
			// even an invalid entry whose own name is empty.
			name: "empty certificate name does not match named entries",
			policy: configv1alpha1.PKICertificatePolicy{
				Defaults: configv1alpha1.PKIDefaultCertificateConfig{Key: ecdsaP256},
				NamedCertificates: []configv1alpha1.PKINamedCertificateConfig{
					{
						Name:                 "",
						PKICertificateConfig: configv1alpha1.PKICertificateConfig{Key: rsa2048},
					},
				},
			},
			certType:        CertificateTypeServer,
			certificateName: "",
			want:            crypto.ECDSAKeyPairGenerator{Curve: crypto.P256},
		},
		{
			name: "peer resolves stronger of server and client",
			policy: configv1alpha1.PKICertificatePolicy{
				Defaults:           configv1alpha1.PKIDefaultCertificateConfig{Key: rsa2048},
				ServerCertificates: configv1alpha1.PKICertificateConfig{Key: rsa2048},
				ClientCertificates: configv1alpha1.PKICertificateConfig{Key: ecdsaP256},
			},
			certType:        CertificateTypePeer,
			certificateName: "openshift.io/test.peer",
			want:            crypto.ECDSAKeyPairGenerator{Curve: crypto.P256},
		},
		{
			name: "peer resolves stronger of server and client when server is stronger",
			policy: configv1alpha1.PKICertificatePolicy{
				Defaults:           configv1alpha1.PKIDefaultCertificateConfig{Key: ecdsaP256},
				ServerCertificates: configv1alpha1.PKICertificateConfig{Key: ecdsaP384},
			},
			certType:        CertificateTypePeer,
			certificateName: "openshift.io/test.peer",
			want:            crypto.ECDSAKeyPairGenerator{Curve: crypto.P384},
		},
		{
			name:            "peer with neither category override uses defaults",
			policy:          defaultsOnly(rsa3072),
			certType:        CertificateTypePeer,
			certificateName: "openshift.io/test.peer",
			want:            crypto.RSAKeyPairGenerator{Bits: 3072},
		},
		{
			// A named entry without a key also falls through for peer
			// certificates, to the stronger-of-server-and-client synthesis.
			name: "peer named entry with unset key falls through to synthesis",
			policy: configv1alpha1.PKICertificatePolicy{
				Defaults:           configv1alpha1.PKIDefaultCertificateConfig{Key: ecdsaP256},
				ServerCertificates: configv1alpha1.PKICertificateConfig{Key: ecdsaP384},
				ClientCertificates: configv1alpha1.PKICertificateConfig{Key: ecdsaP256},
				NamedCertificates: []configv1alpha1.PKINamedCertificateConfig{
					{
						Name: "openshift.io/test.peer",
					},
				},
			},
			certType:        CertificateTypePeer,
			certificateName: "openshift.io/test.peer",
			want:            crypto.ECDSAKeyPairGenerator{Curve: crypto.P384},
		},
		{
			// An invalid named key must error, not fall through: only an
			// unset algorithm makes a named entry inert.
			name: "named override with invalid key is an error",
			policy: configv1alpha1.PKICertificatePolicy{
				Defaults:           configv1alpha1.PKIDefaultCertificateConfig{Key: ecdsaP256},
				ServerCertificates: configv1alpha1.PKICertificateConfig{Key: ecdsaP384},
				NamedCertificates: []configv1alpha1.PKINamedCertificateConfig{
					{
						Name: "openshift.io/test.server",
						PKICertificateConfig: configv1alpha1.PKICertificateConfig{
							Key: configv1alpha1.PKIKeyConfig{
								Algorithm: configv1alpha1.PKIKeyAlgorithmRSA,
								RSA:       configv1alpha1.PKIRSAKeyConfig{KeySize: 1024},
							},
						},
					},
				},
			},
			certType:        CertificateTypeServer,
			certificateName: "openshift.io/test.server",
			wantErr:         "invalid RSA key size",
		},
		{
			name: "peer with invalid server category override is an error",
			policy: configv1alpha1.PKICertificatePolicy{
				Defaults:           configv1alpha1.PKIDefaultCertificateConfig{Key: ecdsaP256},
				ServerCertificates: configv1alpha1.PKICertificateConfig{Key: configv1alpha1.PKIKeyConfig{Algorithm: configv1alpha1.PKIKeyAlgorithmRSA, RSA: configv1alpha1.PKIRSAKeyConfig{KeySize: 2050}}},
			},
			certType:        CertificateTypePeer,
			certificateName: "openshift.io/test.peer",
			wantErr:         "resolving server config for peer",
		},
		{
			name: "invalid defaults key fails even when a category override is set",
			policy: configv1alpha1.PKICertificatePolicy{
				Defaults:           configv1alpha1.PKIDefaultCertificateConfig{Key: configv1alpha1.PKIKeyConfig{Algorithm: "bogus"}},
				ServerCertificates: configv1alpha1.PKICertificateConfig{Key: ecdsaP384},
			},
			certType:        CertificateTypeServer,
			certificateName: "openshift.io/test.server",
			wantErr:         "invalid certificates.defaults.key",
		},
		{
			// Over-matching is a realistic hazard: the naming convention
			// produces near-miss pairs like x.localhost-serving and
			// x.localhost-serving-signer. Matching is exact.
			name: "named entry with prefixed suffix of the name is ignored",
			policy: configv1alpha1.PKICertificatePolicy{
				Defaults: configv1alpha1.PKIDefaultCertificateConfig{Key: ecdsaP256},
				NamedCertificates: []configv1alpha1.PKINamedCertificateConfig{
					{
						Name:                 "openshift.io/test.server-signer",
						PKICertificateConfig: configv1alpha1.PKICertificateConfig{Key: rsa2048},
					},
				},
			},
			certType:        CertificateTypeServer,
			certificateName: "openshift.io/test.server",
			want:            crypto.ECDSAKeyPairGenerator{Curve: crypto.P256},
		},
		{
			name: "named entry without a prefix is ignored",
			policy: configv1alpha1.PKICertificatePolicy{
				Defaults: configv1alpha1.PKIDefaultCertificateConfig{Key: ecdsaP256},
				NamedCertificates: []configv1alpha1.PKINamedCertificateConfig{
					{
						Name:                 "test.server",
						PKICertificateConfig: configv1alpha1.PKICertificateConfig{Key: rsa2048},
					},
				},
			},
			certType:        CertificateTypeServer,
			certificateName: "openshift.io/test.server",
			want:            crypto.ECDSAKeyPairGenerator{Curve: crypto.P256},
		},
		{
			name: "named entry differing only in case is ignored",
			policy: configv1alpha1.PKICertificatePolicy{
				Defaults: configv1alpha1.PKIDefaultCertificateConfig{Key: ecdsaP256},
				NamedCertificates: []configv1alpha1.PKINamedCertificateConfig{
					{
						Name:                 "OpenShift.io/Test.Server",
						PKICertificateConfig: configv1alpha1.PKICertificateConfig{Key: rsa2048},
					},
				},
			},
			certType:        CertificateTypeServer,
			certificateName: "openshift.io/test.server",
			want:            crypto.ECDSAKeyPairGenerator{Curve: crypto.P256},
		},
		{
			// The API validates namedCertificates as a map keyed by name, so
			// duplicates cannot be stored; first match is the deterministic
			// fallback for invalid cached objects.
			name: "duplicate named entries use the first match",
			policy: configv1alpha1.PKICertificatePolicy{
				Defaults: configv1alpha1.PKIDefaultCertificateConfig{Key: ecdsaP256},
				NamedCertificates: []configv1alpha1.PKINamedCertificateConfig{
					{
						Name:                 "openshift.io/test.server",
						PKICertificateConfig: configv1alpha1.PKICertificateConfig{Key: rsa2048},
					},
					{
						Name:                 "openshift.io/test.server",
						PKICertificateConfig: configv1alpha1.PKICertificateConfig{Key: ecdsaP384},
					},
				},
			},
			certType:        CertificateTypeServer,
			certificateName: "openshift.io/test.server",
			want:            crypto.RSAKeyPairGenerator{Bits: 2048},
		},
		{
			// Explicit beats derived: a matching named override wins even
			// when the synthesized peer resolution (stronger of server and
			// client) would pick a stronger key.
			name: "peer with named override wins over stronger category resolution",
			policy: configv1alpha1.PKICertificatePolicy{
				Defaults:           configv1alpha1.PKIDefaultCertificateConfig{Key: ecdsaP256},
				ServerCertificates: configv1alpha1.PKICertificateConfig{Key: ecdsaP521},
				ClientCertificates: configv1alpha1.PKICertificateConfig{Key: ecdsaP256},
				NamedCertificates: []configv1alpha1.PKINamedCertificateConfig{
					{
						Name:                 "openshift.io/test.peer",
						PKICertificateConfig: configv1alpha1.PKICertificateConfig{Key: rsa2048},
					},
				},
			},
			certType:        CertificateTypePeer,
			certificateName: "openshift.io/test.peer",
			want:            crypto.RSAKeyPairGenerator{Bits: 2048},
		},
		{
			name:            "unknown certificate type is an error",
			policy:          defaultsOnly(ecdsaP256),
			certType:        "unknown",
			certificateName: "openshift.io/test",
			wantErr:         "unknown certificate type",
		},
		{
			name:            "unset defaults key is an error",
			policy:          configv1alpha1.PKICertificatePolicy{},
			certType:        CertificateTypeServer,
			certificateName: "openshift.io/test.server",
			wantErr:         "certificates.defaults.key.algorithm is required",
		},
		{
			name: "invalid algorithm in category override is an error",
			policy: configv1alpha1.PKICertificatePolicy{
				Defaults:           configv1alpha1.PKIDefaultCertificateConfig{Key: ecdsaP256},
				ServerCertificates: configv1alpha1.PKICertificateConfig{Key: configv1alpha1.PKIKeyConfig{Algorithm: "bogus"}},
			},
			certType:        CertificateTypeServer,
			certificateName: "openshift.io/test.server",
			wantErr:         "unknown key algorithm",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := ResolveCertificateConfig(tc.policy, tc.certType, tc.certificateName)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("ResolveCertificateConfig() error = nil, want error containing %q", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("ResolveCertificateConfig() error = %q, want it to contain %q", err.Error(), tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveCertificateConfig() error = %v", err)
			}
			if cfg.Key != tc.want {
				t.Errorf("Key = %+v, want %+v", cfg.Key, tc.want)
			}
		})
	}
}
