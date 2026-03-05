package pki

import (
	"fmt"
	"strings"
	"testing"

	configv1alpha1 "github.com/openshift/api/config/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/openshift/library-go/pkg/crypto"
)

// fakePKILister implements configv1alpha1listers.PKILister for testing.
type fakePKILister struct {
	pki *configv1alpha1.PKI
	err error
}

func (f *fakePKILister) List(_ labels.Selector) ([]*configv1alpha1.PKI, error) {
	panic("not implemented")
}

func (f *fakePKILister) Get(_ string) (*configv1alpha1.PKI, error) {
	return f.pki, f.err
}

func TestListerPKIProfileProvider_Unmanaged(t *testing.T) {
	lister := &fakePKILister{
		pki: &configv1alpha1.PKI{
			ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
			Spec: configv1alpha1.PKISpec{
				CertificateManagement: configv1alpha1.PKICertificateManagement{
					Mode: configv1alpha1.PKICertificateManagementModeUnmanaged,
				},
			},
		},
	}
	provider := NewClusterPKIProfileProvider(lister)

	profile, err := provider.PKIProfile()
	if err != nil {
		t.Fatalf("PKIProfile() error = %v", err)
	}
	if profile != nil {
		t.Errorf("expected nil profile for Unmanaged mode, got %+v", profile)
	}
}

func TestListerPKIProfileProvider_Default(t *testing.T) {
	lister := &fakePKILister{
		pki: &configv1alpha1.PKI{
			ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
			Spec: configv1alpha1.PKISpec{
				CertificateManagement: configv1alpha1.PKICertificateManagement{
					Mode: configv1alpha1.PKICertificateManagementModeDefault,
				},
			},
		},
	}
	provider := NewClusterPKIProfileProvider(lister)

	profile, err := provider.PKIProfile()
	if err != nil {
		t.Fatalf("PKIProfile() error = %v", err)
	}
	if profile == nil {
		t.Fatal("expected non-nil profile for Default mode")
	}

	// Should match DefaultPKIProfile()
	want := DefaultPKIProfile()
	if profile.Defaults.Key.Algorithm != want.Defaults.Key.Algorithm {
		t.Errorf("defaults algorithm = %v, want %v", profile.Defaults.Key.Algorithm, want.Defaults.Key.Algorithm)
	}
}

func TestListerPKIProfileProvider_Custom(t *testing.T) {
	customProfile := configv1alpha1.PKIProfile{
		Defaults: configv1alpha1.DefaultCertificateConfig{
			Key: configv1alpha1.KeyConfig{
				Algorithm: configv1alpha1.KeyAlgorithmRSA,
				RSA:       configv1alpha1.RSAKeyConfig{KeySize: 4096},
			},
		},
	}
	lister := &fakePKILister{
		pki: &configv1alpha1.PKI{
			ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
			Spec: configv1alpha1.PKISpec{
				CertificateManagement: configv1alpha1.PKICertificateManagement{
					Mode: configv1alpha1.PKICertificateManagementModeCustom,
					Custom: configv1alpha1.CustomPKIPolicy{
						PKIProfile: customProfile,
					},
				},
			},
		},
	}
	provider := NewClusterPKIProfileProvider(lister)

	profile, err := provider.PKIProfile()
	if err != nil {
		t.Fatalf("PKIProfile() error = %v", err)
	}
	if profile == nil {
		t.Fatal("expected non-nil profile for Custom mode")
	}
	if profile.Defaults.Key.Algorithm != configv1alpha1.KeyAlgorithmRSA {
		t.Errorf("defaults algorithm = %v, want RSA", profile.Defaults.Key.Algorithm)
	}
	if profile.Defaults.Key.RSA.KeySize != 4096 {
		t.Errorf("defaults RSA key size = %d, want 4096", profile.Defaults.Key.RSA.KeySize)
	}
}

func TestListerPKIProfileProvider_UnknownMode(t *testing.T) {
	lister := &fakePKILister{
		pki: &configv1alpha1.PKI{
			ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
			Spec: configv1alpha1.PKISpec{
				CertificateManagement: configv1alpha1.PKICertificateManagement{
					Mode: "SomeFutureMode",
				},
			},
		},
	}
	provider := NewClusterPKIProfileProvider(lister)

	_, err := provider.PKIProfile()
	if err == nil {
		t.Error("expected error for unknown mode")
	}
}

func TestListerPKIProfileProvider_ListerError(t *testing.T) {
	lister := &fakePKILister{
		err: fmt.Errorf("connection refused"),
	}
	provider := NewClusterPKIProfileProvider(lister)

	_, err := provider.PKIProfile()
	if err == nil {
		t.Error("expected error when lister fails")
	}
}

// errorProvider is a PKIProfileProvider that always returns an error.
type errorProvider struct {
	err error
}

func (e *errorProvider) PKIProfile() (*configv1alpha1.PKIProfile, error) {
	return nil, e.err
}

func TestResolveCertificateConfig_ProviderError(t *testing.T) {
	provider := &errorProvider{err: fmt.Errorf("connection refused")}

	_, err := ResolveCertificateConfig(provider, CertificateTypeSigner, "test")
	if err == nil {
		t.Fatal("expected error to propagate from provider")
	}

	// Verify the original error is wrapped
	if !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), "connection refused")
	}
}

func TestResolveCertificateConfig_DefaultProfile_AllTypes(t *testing.T) {
	profile := DefaultPKIProfile()
	provider := NewStaticPKIProfileProvider(&profile)

	testCases := []struct {
		name     string
		certType CertificateType
		want     crypto.KeyPairGenerator
	}{
		{
			name:     "signer uses ECDSA P-384",
			certType: CertificateTypeSigner,
			want:     crypto.ECDSAKeyPairGenerator{Curve: crypto.P384},
		},
		{
			name:     "serving falls back to ECDSA P-256",
			certType: CertificateTypeServing,
			want:     crypto.ECDSAKeyPairGenerator{Curve: crypto.P256},
		},
		{
			name:     "client falls back to ECDSA P-256",
			certType: CertificateTypeClient,
			want:     crypto.ECDSAKeyPairGenerator{Curve: crypto.P256},
		},
		{
			name:     "peer picks stronger of serving and client",
			certType: CertificateTypePeer,
			want:     crypto.ECDSAKeyPairGenerator{Curve: crypto.P256},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := ResolveCertificateConfig(provider, tc.certType, "test")
			if err != nil {
				t.Fatalf("ResolveCertificateConfig() error = %v", err)
			}
			if cfg == nil {
				t.Fatal("expected non-nil config")
			}
			if cfg.Key != tc.want {
				t.Errorf("Key = %+v, want %+v", cfg.Key, tc.want)
			}
		})
	}
}
