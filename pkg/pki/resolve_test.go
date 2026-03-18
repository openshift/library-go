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

	// Default profile has RSA-4096 for signers
	if cfg.Key.Algorithm != crypto.RSAKeyAlgorithm {
		t.Errorf("algorithm = %v, want RSA", cfg.Key.Algorithm)
	}
	if cfg.Key.RSABits != 4096 {
		t.Errorf("RSABits = %d, want 4096", cfg.Key.RSABits)
	}
}

func TestResolveCertificateConfig_Serving(t *testing.T) {
	profile := DefaultPKIProfile()
	provider := NewStaticPKIProfileProvider(&profile)

	cfg, err := ResolveCertificateConfig(provider, CertificateTypeServing, "test-serving")
	if err != nil {
		t.Fatalf("ResolveCertificateConfig() error = %v", err)
	}

	// Default profile has no serving override, falls back to RSA-2048
	if cfg.Key.Algorithm != crypto.RSAKeyAlgorithm {
		t.Errorf("algorithm = %v, want RSA", cfg.Key.Algorithm)
	}
	if cfg.Key.RSABits != 2048 {
		t.Errorf("RSABits = %d, want 2048", cfg.Key.RSABits)
	}
}

func TestResolveCertificateConfig_Client(t *testing.T) {
	profile := DefaultPKIProfile()
	provider := NewStaticPKIProfileProvider(&profile)

	cfg, err := ResolveCertificateConfig(provider, CertificateTypeClient, "test-client")
	if err != nil {
		t.Fatalf("ResolveCertificateConfig() error = %v", err)
	}

	// Default profile has no client override, falls back to RSA-2048
	if cfg.Key.RSABits != 2048 {
		t.Errorf("RSABits = %d, want 2048", cfg.Key.RSABits)
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
	if cfg.Key.Algorithm != crypto.ECDSAKeyAlgorithm {
		t.Errorf("algorithm = %v, want ECDSA", cfg.Key.Algorithm)
	}
	if cfg.Key.ECDSACurve != crypto.P256 {
		t.Errorf("ECDSACurve = %v, want P256", cfg.Key.ECDSACurve)
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

	// Serving should use the override, not defaults
	if cfg.Key.Algorithm != crypto.ECDSAKeyAlgorithm {
		t.Errorf("algorithm = %v, want ECDSA", cfg.Key.Algorithm)
	}
	if cfg.Key.ECDSACurve != crypto.P384 {
		t.Errorf("ECDSACurve = %v, want P384", cfg.Key.ECDSACurve)
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
