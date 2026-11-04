package pki

import (
	"reflect"
	"strings"
	"testing"

	configv1alpha1 "github.com/openshift/api/config/v1alpha1"

	"github.com/openshift/library-go/pkg/crypto"
)

func keyECDSA(curve configv1alpha1.PKIECDSACurve) configv1alpha1.PKIKeyConfig {
	return configv1alpha1.PKIKeyConfig{
		Algorithm: configv1alpha1.PKIKeyAlgorithmECDSA,
		ECDSA:     configv1alpha1.PKIECDSAKeyConfig{Curve: curve},
	}
}

func keyRSA(size int32) configv1alpha1.PKIKeyConfig {
	return configv1alpha1.PKIKeyConfig{
		Algorithm: configv1alpha1.PKIKeyAlgorithmRSA,
		RSA:       configv1alpha1.PKIRSAKeyConfig{KeySize: size},
	}
}

func customSpec(profile configv1alpha1.PKIProfile) configv1alpha1.PKISpec {
	return configv1alpha1.PKISpec{
		CertificateManagement: configv1alpha1.PKICertificateManagement{
			Mode:   configv1alpha1.PKICertificateManagementModeCustom,
			Custom: configv1alpha1.CustomPKIPolicy{PKIProfile: profile},
		},
	}
}

func TestEffectiveSpec(t *testing.T) {
	newShapeSpec := configv1alpha1.PKISpec{
		Certificates: configv1alpha1.PKICertificatePolicy{
			Defaults: configv1alpha1.PKIDefaultCertificateConfig{Key: keyECDSA(configv1alpha1.PKIECDSACurveP256)},
		},
	}
	namedKeys := []configv1alpha1.PKINamedKeyConfig{
		{
			Name: "openshift.io/test.signing-key",
			Key:  keyECDSA(configv1alpha1.PKIECDSACurveP384),
		},
	}
	fullCustomProfile := configv1alpha1.PKIProfile{
		Defaults:             configv1alpha1.PKIDefaultCertificateConfig{Key: keyRSA(3072)},
		SignerCertificates:   configv1alpha1.PKICertificateConfig{Key: keyECDSA(configv1alpha1.PKIECDSACurveP521)},
		ServingCertificates:  configv1alpha1.PKICertificateConfig{Key: keyRSA(4096)},
		ClientCertificates:   configv1alpha1.PKICertificateConfig{Key: keyECDSA(configv1alpha1.PKIECDSACurveP384)},
	}
	testCases := []struct {
		name    string
		spec    configv1alpha1.PKISpec
		want    configv1alpha1.PKICertificatePolicy
		wantErr string // empty means no error expected
	}{
		{
			name: "new shape passes through",
			spec: newShapeSpec,
			want: newShapeSpec.Certificates,
		},
		{
			name: "new shape with keys passes through",
			spec: configv1alpha1.PKISpec{
				Certificates: newShapeSpec.Certificates,
				Keys:         configv1alpha1.PKIKeyPolicy{NamedKeys: namedKeys},
			},
			want: newShapeSpec.Certificates,
		},
		{
			name: "new shape preferred when both shapes set",
			spec: configv1alpha1.PKISpec{
				Certificates: newShapeSpec.Certificates,
				CertificateManagement: configv1alpha1.PKICertificateManagement{
					Mode:   configv1alpha1.PKICertificateManagementModeCustom,
					Custom: configv1alpha1.CustomPKIPolicy{PKIProfile: fullCustomProfile},
				},
			},
			want: newShapeSpec.Certificates,
		},
		{
			name: "neither shape set passes through unchanged",
			spec: configv1alpha1.PKISpec{},
			want: configv1alpha1.PKICertificatePolicy{},
		},
		{
			name: "unmanaged mode maps to default certificate policy",
			spec: configv1alpha1.PKISpec{
				CertificateManagement: configv1alpha1.PKICertificateManagement{
					Mode: configv1alpha1.PKICertificateManagementModeUnmanaged,
				},
			},
			want: DefaultCertificatePolicy(),
		},
		{
			name: "default mode maps to default certificate policy",
			spec: configv1alpha1.PKISpec{
				CertificateManagement: configv1alpha1.PKICertificateManagement{
					Mode: configv1alpha1.PKICertificateManagementModeDefault,
				},
			},
			want: DefaultCertificatePolicy(),
		},
		{
			name: "custom mode maps full profile",
			spec: customSpec(fullCustomProfile),
			want: configv1alpha1.PKICertificatePolicy{
				Defaults:           fullCustomProfile.Defaults,
				CACertificates:     fullCustomProfile.SignerCertificates,
				ServerCertificates: fullCustomProfile.ServingCertificates,
				ClientCertificates: fullCustomProfile.ClientCertificates,
			},
		},
		{
			name: "custom mode maps partial profile",
			spec: customSpec(configv1alpha1.PKIProfile{
				Defaults:            configv1alpha1.PKIDefaultCertificateConfig{Key: keyECDSA(configv1alpha1.PKIECDSACurveP256)},
				ServingCertificates: configv1alpha1.PKICertificateConfig{Key: keyRSA(4096)},
			}),
			want: configv1alpha1.PKICertificatePolicy{
				Defaults:           configv1alpha1.PKIDefaultCertificateConfig{Key: keyECDSA(configv1alpha1.PKIECDSACurveP256)},
				ServerCertificates: configv1alpha1.PKICertificateConfig{Key: keyRSA(4096)},
			},
		},
		{
			name: "custom mode with empty custom passes through zero policy",
			spec: configv1alpha1.PKISpec{
				CertificateManagement: configv1alpha1.PKICertificateManagement{
					Mode: configv1alpha1.PKICertificateManagementModeCustom,
				},
			},
			want: configv1alpha1.PKICertificatePolicy{},
		},
		{
			name: "old shape with keys passes keys through",
			spec: configv1alpha1.PKISpec{
				CertificateManagement: configv1alpha1.PKICertificateManagement{
					Mode: configv1alpha1.PKICertificateManagementModeDefault,
				},
				Keys: configv1alpha1.PKIKeyPolicy{NamedKeys: namedKeys},
			},
			want: DefaultCertificatePolicy(),
		},
		{
			name: "stray custom under default mode is ignored",
			spec: configv1alpha1.PKISpec{
				CertificateManagement: configv1alpha1.PKICertificateManagement{
					Mode:   configv1alpha1.PKICertificateManagementModeDefault,
					Custom: configv1alpha1.CustomPKIPolicy{PKIProfile: fullCustomProfile},
				},
			},
			want: DefaultCertificatePolicy(),
		},
		{
			name: "stray custom under unmanaged mode is ignored",
			spec: configv1alpha1.PKISpec{
				CertificateManagement: configv1alpha1.PKICertificateManagement{
					Mode:   configv1alpha1.PKICertificateManagementModeUnmanaged,
					Custom: configv1alpha1.CustomPKIPolicy{PKIProfile: fullCustomProfile},
				},
			},
			want: DefaultCertificatePolicy(),
		},
		{
			name: "empty mode is an error",
			spec: configv1alpha1.PKISpec{
				CertificateManagement: configv1alpha1.PKICertificateManagement{
					Custom: configv1alpha1.CustomPKIPolicy{PKIProfile: fullCustomProfile},
				},
			},
			wantErr: "spec.certificateManagement.mode",
		},
		{
			name: "unknown mode is an error",
			spec: configv1alpha1.PKISpec{
				CertificateManagement: configv1alpha1.PKICertificateManagement{
					Mode: configv1alpha1.PKICertificateManagementMode("Bogus"),
				},
			},
			wantErr: "spec.certificateManagement.mode",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := effectiveSpec(tc.spec)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("effectiveSpec() error = nil, want error containing %q", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("effectiveSpec() error = %q, want it to contain %q", err.Error(), tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("effectiveSpec() error = %v", err)
			}
			if !reflect.DeepEqual(got.Certificates, tc.want) {
				t.Errorf("Certificates = %+v, want %+v", got.Certificates, tc.want)
			}
			if !reflect.DeepEqual(got.CertificateManagement, configv1alpha1.PKICertificateManagement{}) {
				t.Errorf("CertificateManagement = %+v, want zero value in every output", got.CertificateManagement)
			}
			if !reflect.DeepEqual(got.Keys, tc.spec.Keys) {
				t.Errorf("Keys = %+v, want %+v passed through unchanged", got.Keys, tc.spec.Keys)
			}
		})
	}
}

// TestEffectiveSpecModesResolveAllCertificateTypes runs every old-shape mode
// through ResolveCertificateConfig for every certificate type, mirroring
// TestResolveCertificateConfig_DefaultCertificatePolicy_AllTypes: an
// old-shape resource must yield a resolvable policy, not a zero one.
func TestEffectiveSpecModesResolveAllCertificateTypes(t *testing.T) {
	modes := []struct {
		name string
		mode configv1alpha1.PKICertificateManagementMode
	}{
		{name: "unmanaged", mode: configv1alpha1.PKICertificateManagementModeUnmanaged},
		{name: "default", mode: configv1alpha1.PKICertificateManagementModeDefault},
	}
	certTypes := []struct {
		name     string
		certType CertificateType
	}{
		{name: "ca", certType: CertificateTypeCA},
		{name: "server", certType: CertificateTypeServer},
		{name: "client", certType: CertificateTypeClient},
		{name: "peer", certType: CertificateTypePeer},
	}
	for _, mode := range modes {
		for _, ct := range certTypes {
			t.Run(mode.name+"_"+ct.name, func(t *testing.T) {
				spec, err := effectiveSpec(configv1alpha1.PKISpec{
					CertificateManagement: configv1alpha1.PKICertificateManagement{Mode: mode.mode},
				})
				if err != nil {
					t.Fatalf("effectiveSpec() error = %v", err)
				}
				cfg, err := ResolveCertificateConfig(spec.Certificates, ct.certType, "openshift.io/test."+ct.name)
				if err != nil {
					t.Fatalf("ResolveCertificateConfig() error = %v", err)
				}
				wantCA := crypto.ECDSAKeyPairGenerator{Curve: crypto.P384}
				wantDefault := crypto.ECDSAKeyPairGenerator{Curve: crypto.P256}
				want := wantDefault
				if ct.certType == CertificateTypeCA {
					want = wantCA
				}
				if cfg.Key != want {
					t.Errorf("Key = %+v, want %+v", cfg.Key, want)
				}
			})
		}
	}
}

// TestEffectiveSpecCustomModeResolvesAllCertificateTypes runs an old-shape
// Custom resource through ResolveCertificateConfig for every certificate
// type, checking the category mapping end to end.
func TestEffectiveSpecCustomModeResolvesAllCertificateTypes(t *testing.T) {
	profile := configv1alpha1.PKIProfile{
		Defaults:            configv1alpha1.PKIDefaultCertificateConfig{Key: keyRSA(3072)},
		SignerCertificates:  configv1alpha1.PKICertificateConfig{Key: keyECDSA(configv1alpha1.PKIECDSACurveP521)},
		ServingCertificates: configv1alpha1.PKICertificateConfig{Key: keyRSA(4096)},
		ClientCertificates:  configv1alpha1.PKICertificateConfig{Key: keyECDSA(configv1alpha1.PKIECDSACurveP384)},
	}
	spec, err := effectiveSpec(configv1alpha1.PKISpec{
		CertificateManagement: configv1alpha1.PKICertificateManagement{
			Mode:   configv1alpha1.PKICertificateManagementModeCustom,
			Custom: configv1alpha1.CustomPKIPolicy{PKIProfile: profile},
		},
	})
	if err != nil {
		t.Fatalf("effectiveSpec() error = %v", err)
	}
	testCases := []struct {
		name     string
		certType CertificateType
		want     crypto.KeyPairGenerator
	}{
		{name: "ca uses signer override", certType: CertificateTypeCA, want: crypto.ECDSAKeyPairGenerator{Curve: crypto.P521}},
		{name: "server uses serving override", certType: CertificateTypeServer, want: crypto.RSAKeyPairGenerator{Bits: 4096}},
		{name: "client uses client override", certType: CertificateTypeClient, want: crypto.ECDSAKeyPairGenerator{Curve: crypto.P384}},
		// Peer is the stronger of server (RSA 4096) and client (P-384):
		// RSA 4096 has 128 security bits, P-384 has 192, so P-384 wins.
		{name: "peer resolves stronger of mapped server and client", certType: CertificateTypePeer, want: crypto.ECDSAKeyPairGenerator{Curve: crypto.P384}},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := ResolveCertificateConfig(spec.Certificates, tc.certType, "openshift.io/test."+tc.name)
			if err != nil {
				t.Fatalf("ResolveCertificateConfig() error = %v", err)
			}
			if cfg.Key != tc.want {
				t.Errorf("Key = %+v, want %+v", cfg.Key, tc.want)
			}
		})
	}
}

// TestEffectiveSpecDefaultModePinnedValues pins the old-shape Default and
// Unmanaged mapping to literal ECDSA P-256 defaults / P-384 CA. If the
// install-time seed (DefaultCertificatePolicy) ever changes, this test forces
// a deliberate decision: operators vendoring different library-go versions
// must agree on what an old-shape Default resource means during upgrade skew.
func TestEffectiveSpecDefaultModePinnedValues(t *testing.T) {
	pinned := configv1alpha1.PKICertificatePolicy{
		Defaults: configv1alpha1.PKIDefaultCertificateConfig{
			Key: configv1alpha1.PKIKeyConfig{
				Algorithm: configv1alpha1.PKIKeyAlgorithmECDSA,
				ECDSA:     configv1alpha1.PKIECDSAKeyConfig{Curve: "P256"},
			},
		},
		CACertificates: configv1alpha1.PKICertificateConfig{
			Key: configv1alpha1.PKIKeyConfig{
				Algorithm: configv1alpha1.PKIKeyAlgorithmECDSA,
				ECDSA:     configv1alpha1.PKIECDSAKeyConfig{Curve: "P384"},
			},
		},
	}
	for _, mode := range []configv1alpha1.PKICertificateManagementMode{
		configv1alpha1.PKICertificateManagementModeDefault,
		configv1alpha1.PKICertificateManagementModeUnmanaged,
	} {
		spec, err := effectiveSpec(configv1alpha1.PKISpec{
			CertificateManagement: configv1alpha1.PKICertificateManagement{Mode: mode},
		})
		if err != nil {
			t.Fatalf("effectiveSpec() error = %v", err)
		}
		if !reflect.DeepEqual(spec.Certificates, pinned) {
			t.Errorf("mode %s: Certificates = %+v, want pinned %+v", mode, spec.Certificates, pinned)
		}
	}
}

// TestEffectiveSpecCustomModeInvalidKey fails at resolution, not at
// normalization: an old-Custom key valid under the old schema but rejected now
// (RSA > 4096) surfaces through ResolveCertificateConfig's existing
// per-category validation.
func TestEffectiveSpecCustomModeInvalidKey(t *testing.T) {
	spec, err := effectiveSpec(customSpec(configv1alpha1.PKIProfile{
		Defaults: configv1alpha1.PKIDefaultCertificateConfig{Key: keyRSA(2048)},
		SignerCertificates: configv1alpha1.PKICertificateConfig{
			Key: keyRSA(8192),
		},
	}))
	if err != nil {
		t.Fatalf("effectiveSpec() error = %v, want normalization to succeed and fail at resolution", err)
	}
	_, err = ResolveCertificateConfig(spec.Certificates, CertificateTypeCA, "openshift.io/test.ca")
	if err == nil {
		t.Fatal("ResolveCertificateConfig() error = nil, want error mentioning the key size")
	}
	if !strings.Contains(err.Error(), "8192") {
		t.Errorf("ResolveCertificateConfig() error = %q, want it to mention the key size 8192", err.Error())
	}
}
