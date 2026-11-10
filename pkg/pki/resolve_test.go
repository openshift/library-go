package pki

import (
	gocrypto "crypto"
	"errors"
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

	pub, _, err := cfg.Key.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	if err := (crypto.ECDSAKeyPairGenerator{Curve: crypto.P384}).Matches(pub); err != nil {
		t.Errorf("expected ECDSA P-384 signer key: %v", err)
	}
}

func TestResolveCertificateConfig_Serving(t *testing.T) {
	profile := DefaultPKIProfile()
	provider := NewStaticPKIProfileProvider(&profile)

	cfg, err := ResolveCertificateConfig(provider, CertificateTypeServing, "test-serving")
	if err != nil {
		t.Fatalf("ResolveCertificateConfig() error = %v", err)
	}

	pub, _, err := cfg.Key.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	if err := (crypto.ECDSAKeyPairGenerator{Curve: crypto.P256}).Matches(pub); err != nil {
		t.Errorf("expected ECDSA P-256 serving key: %v", err)
	}
}

func TestResolveCertificateConfig_Client(t *testing.T) {
	profile := DefaultPKIProfile()
	provider := NewStaticPKIProfileProvider(&profile)

	cfg, err := ResolveCertificateConfig(provider, CertificateTypeClient, "test-client")
	if err != nil {
		t.Fatalf("ResolveCertificateConfig() error = %v", err)
	}

	pub, _, err := cfg.Key.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	if err := (crypto.ECDSAKeyPairGenerator{Curve: crypto.P256}).Matches(pub); err != nil {
		t.Errorf("expected ECDSA P-256 client key: %v", err)
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
	pub, _, err := cfg.Key.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	if err := (crypto.ECDSAKeyPairGenerator{Curve: crypto.P256}).Matches(pub); err != nil {
		t.Errorf("expected ECDSA P-256 peer key: %v", err)
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

	pub, _, err := cfg.Key.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	if err := (crypto.ECDSAKeyPairGenerator{Curve: crypto.P384}).Matches(pub); err != nil {
		t.Errorf("expected ECDSA P-384 serving key: %v", err)
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

// brokenKeyPairGenerator generates ECDSA P-256 keys but Matches expects P-384. This intentionally
// violates the contract of KeyPairGenerator.
type brokenKeyPairGenerator struct{}

func (brokenKeyPairGenerator) GenerateKeyPair() (gocrypto.PublicKey, gocrypto.PrivateKey, error) {
	return crypto.ECDSAKeyPairGenerator{Curve: crypto.P256}.GenerateKeyPair()
}

func (brokenKeyPairGenerator) Matches(pub gocrypto.PublicKey) error {
	return errors.New("test error")
}

// TestSelfCheckingKeyPairGenerator demonstrates that selfCheckingKeyPairGenerator will return a
// non-nil error from GenerateKeyPair if the Match method of the KeyPairGenerator it wraps does not
// recognize a key that it has itself generated.
func TestSelfCheckingKeyPairGenerator(t *testing.T) {
	g := selfCheckingKeyPairGenerator{inner: brokenKeyPairGenerator{}}
	_, _, err := g.GenerateKeyPair()
	if err == nil {
		t.Fatal("expected error from self-checking wrapper with broken generator")
	}
	if err.Error() != "test error" {
		t.Errorf("unexpected error message: %v", err)
	}
}
