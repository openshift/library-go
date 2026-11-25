package pki

import (
	"testing"

	configv1alpha1 "github.com/openshift/api/config/v1alpha1"
	"github.com/openshift/library-go/pkg/crypto"
)

func TestResolveCertificateConfig_Signer(t *testing.T) {
	profile := DefaultPKIProfile()
	provider := NewStaticPKIProfileProvider(&profile)

	cfg, err := ResolveCertificateConfig(provider, CertificateTypeSigner, "test-signer")
	if err != nil {
		t.Fatalf("ResolveCertificateConfig() error = %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}

	want := crypto.KeySpec{Algorithm: crypto.ECDSAKeyAlgorithm, ECDSACurve: crypto.P384}
	if cfg.Key != want {
		t.Errorf("resolved key = %s, want %s", cfg.Key, want)
	}
}

func TestResolveCertificateConfig_Serving(t *testing.T) {
	profile := DefaultPKIProfile()
	provider := NewStaticPKIProfileProvider(&profile)

	cfg, err := ResolveCertificateConfig(provider, CertificateTypeServing, "test-serving")
	if err != nil {
		t.Fatalf("ResolveCertificateConfig() error = %v", err)
	}

	want := crypto.KeySpec{Algorithm: crypto.ECDSAKeyAlgorithm, ECDSACurve: crypto.P256}
	if cfg.Key != want {
		t.Errorf("resolved key = %s, want %s", cfg.Key, want)
	}
}

func TestResolveCertificateConfig_Client(t *testing.T) {
	profile := DefaultPKIProfile()
	provider := NewStaticPKIProfileProvider(&profile)

	cfg, err := ResolveCertificateConfig(provider, CertificateTypeClient, "test-client")
	if err != nil {
		t.Fatalf("ResolveCertificateConfig() error = %v", err)
	}

	want := crypto.KeySpec{Algorithm: crypto.ECDSAKeyAlgorithm, ECDSACurve: crypto.P256}
	if cfg.Key != want {
		t.Errorf("resolved key = %s, want %s", cfg.Key, want)
	}
}

func TestResolveCertificateConfig_Peer(t *testing.T) {
	// Set serving to RSA-2048 (112 bits) and client to ECDSA-P256 (128 bits)
	profile := configv1alpha1.PKIProfile{
		Defaults: configv1alpha1.DefaultCertificateConfig{
			Key: configv1alpha1.KeyConfig{
				Algorithm: configv1alpha1.KeyAlgorithmRSA,
				RSA:       configv1alpha1.RSAKeyConfig{KeySize: 2048},
			},
		},
		ServingCertificates: configv1alpha1.CertificateConfig{
			Key: configv1alpha1.KeyConfig{
				Algorithm: configv1alpha1.KeyAlgorithmRSA,
				RSA:       configv1alpha1.RSAKeyConfig{KeySize: 2048},
			},
		},
		ClientCertificates: configv1alpha1.CertificateConfig{
			Key: configv1alpha1.KeyConfig{
				Algorithm: configv1alpha1.KeyAlgorithmECDSA,
				ECDSA:     configv1alpha1.ECDSAKeyConfig{Curve: configv1alpha1.ECDSACurveP256},
			},
		},
	}
	provider := NewStaticPKIProfileProvider(&profile)

	cfg, err := ResolveCertificateConfig(provider, CertificateTypePeer, "test-peer")
	if err != nil {
		t.Fatalf("ResolveCertificateConfig() error = %v", err)
	}

	// Peer should pick the stronger: ECDSA-P256 (128 bits) > RSA-2048 (112 bits)
	want := crypto.KeySpec{Algorithm: crypto.ECDSAKeyAlgorithm, ECDSACurve: crypto.P256}
	if cfg.Key != want {
		t.Errorf("resolved key = %s, want %s", cfg.Key, want)
	}
}

func TestResolveCertificateConfig_CustomOverride(t *testing.T) {
	// Custom profile with ECDSA-P384 serving override
	profile := configv1alpha1.PKIProfile{
		Defaults: configv1alpha1.DefaultCertificateConfig{
			Key: configv1alpha1.KeyConfig{
				Algorithm: configv1alpha1.KeyAlgorithmRSA,
				RSA:       configv1alpha1.RSAKeyConfig{KeySize: 2048},
			},
		},
		ServingCertificates: configv1alpha1.CertificateConfig{
			Key: configv1alpha1.KeyConfig{
				Algorithm: configv1alpha1.KeyAlgorithmECDSA,
				ECDSA:     configv1alpha1.ECDSAKeyConfig{Curve: configv1alpha1.ECDSACurveP384},
			},
		},
	}
	provider := NewStaticPKIProfileProvider(&profile)

	cfg, err := ResolveCertificateConfig(provider, CertificateTypeServing, "test-serving")
	if err != nil {
		t.Fatalf("ResolveCertificateConfig() error = %v", err)
	}

	want := crypto.KeySpec{Algorithm: crypto.ECDSAKeyAlgorithm, ECDSACurve: crypto.P384}
	if cfg.Key != want {
		t.Errorf("resolved key = %s, want %s", cfg.Key, want)
	}
}

func TestResolveCertificateConfig_Unmanaged(t *testing.T) {
	provider := NewStaticPKIProfileProvider(nil)

	cfg, err := ResolveCertificateConfig(provider, CertificateTypeSigner, "test")
	if err != nil {
		t.Fatalf("ResolveCertificateConfig() error = %v", err)
	}
	if cfg != nil {
		t.Errorf("expected nil config for Unmanaged mode, got %+v", cfg)
	}
}

func TestResolveCertificateConfig_UnknownType(t *testing.T) {
	profile := DefaultPKIProfile()
	provider := NewStaticPKIProfileProvider(&profile)

	_, err := ResolveCertificateConfig(provider, "unknown", "test")
	if err == nil {
		t.Error("expected error for unknown certificate type")
	}
}

func TestResolvedKeySpecProducesGenerator(t *testing.T) {
	// The resolved KeySpec must be convertible into a generator whose keys
	// match the spec: this is the contract consumers depend on.
	profile := DefaultPKIProfile()
	provider := NewStaticPKIProfileProvider(&profile)

	cfg, err := ResolveCertificateConfig(provider, CertificateTypeSigner, "test-signer")
	if err != nil {
		t.Fatalf("ResolveCertificateConfig() error = %v", err)
	}

	g, err := cfg.Key.KeyPairGenerator()
	if err != nil {
		t.Fatalf("Key.KeyPairGenerator() error = %v", err)
	}
	pub, _, err := g.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	if err := cfg.Key.Matches(pub); err != nil {
		t.Errorf("generated key does not match resolved spec: %v", err)
	}
}
