package pki

import (
	"testing"

	configv1alpha1 "github.com/openshift/api/config/v1alpha1"
	"github.com/openshift/library-go/pkg/crypto"
)

func TestDefaultCertificatePolicy(t *testing.T) {
	policy := DefaultCertificatePolicy()

	// Default should be ECDSA P-256
	if policy.Defaults.Key.Algorithm != configv1alpha1.PKIKeyAlgorithmECDSA {
		t.Errorf("defaults algorithm = %v, want ECDSA", policy.Defaults.Key.Algorithm)
	}
	if policy.Defaults.Key.ECDSA.Curve != configv1alpha1.PKIECDSACurveP256 {
		t.Errorf("defaults ECDSA curve = %v, want P-256", policy.Defaults.Key.ECDSA.Curve)
	}

	// CA certificates should be ECDSA P-384
	if policy.CACertificates.Key.Algorithm != configv1alpha1.PKIKeyAlgorithmECDSA {
		t.Errorf("CA algorithm = %v, want ECDSA", policy.CACertificates.Key.Algorithm)
	}
	if policy.CACertificates.Key.ECDSA.Curve != configv1alpha1.PKIECDSACurveP384 {
		t.Errorf("CA ECDSA curve = %v, want P-384", policy.CACertificates.Key.ECDSA.Curve)
	}

	// Server and client should be unset (fall back to defaults)
	if policy.ServerCertificates.Key.Algorithm != "" {
		t.Errorf("server algorithm = %v, want empty (unset)", policy.ServerCertificates.Key.Algorithm)
	}
	if policy.ClientCertificates.Key.Algorithm != "" {
		t.Errorf("client algorithm = %v, want empty (unset)", policy.ClientCertificates.Key.Algorithm)
	}

	// No named certificates
	if len(policy.NamedCertificates) != 0 {
		t.Errorf("named certificates = %d, want 0", len(policy.NamedCertificates))
	}
}

func TestKeyPairGeneratorFromAPI(t *testing.T) {
	testCases := []struct {
		name    string
		input   configv1alpha1.PKIKeyConfig
		want    crypto.KeyPairGenerator
		wantErr bool
	}{
		{
			name: "RSA-2048",
			input: configv1alpha1.PKIKeyConfig{
				Algorithm: configv1alpha1.PKIKeyAlgorithmRSA,
				RSA:       configv1alpha1.PKIRSAKeyConfig{KeySize: 2048},
			},
			want: mustRSA(2048),
		},
		{
			name: "RSA-3072",
			input: configv1alpha1.PKIKeyConfig{
				Algorithm: configv1alpha1.PKIKeyAlgorithmRSA,
				RSA:       configv1alpha1.PKIRSAKeyConfig{KeySize: 3072},
			},
			want: mustRSA(3072),
		},
		{
			name: "RSA-4096",
			input: configv1alpha1.PKIKeyConfig{
				Algorithm: configv1alpha1.PKIKeyAlgorithmRSA,
				RSA:       configv1alpha1.PKIRSAKeyConfig{KeySize: 4096},
			},
			want: mustRSA(4096),
		},
		{
			name: "RSA key size unset",
			input: configv1alpha1.PKIKeyConfig{
				Algorithm: configv1alpha1.PKIKeyAlgorithmRSA,
			},
			wantErr: true,
		},
		{
			name: "RSA key size too small",
			input: configv1alpha1.PKIKeyConfig{
				Algorithm: configv1alpha1.PKIKeyAlgorithmRSA,
				RSA:       configv1alpha1.PKIRSAKeyConfig{KeySize: 1024},
			},
			wantErr: true,
		},
		{
			// Only the security floor is enforced here; the allowed set of
			// sizes above it is the API's validation to enforce.
			name: "RSA key size above the API maximum",
			input: configv1alpha1.PKIKeyConfig{
				Algorithm: configv1alpha1.PKIKeyAlgorithmRSA,
				RSA:       configv1alpha1.PKIRSAKeyConfig{KeySize: 8192},
			},
			want: mustRSA(8192),
		},
		{
			name: "RSA key size not a multiple of 1024",
			input: configv1alpha1.PKIKeyConfig{
				Algorithm: configv1alpha1.PKIKeyAlgorithmRSA,
				RSA:       configv1alpha1.PKIRSAKeyConfig{KeySize: 2050},
			},
			want: mustRSA(2050),
		},
		{
			name: "ECDSA-P256",
			input: configv1alpha1.PKIKeyConfig{
				Algorithm: configv1alpha1.PKIKeyAlgorithmECDSA,
				ECDSA:     configv1alpha1.PKIECDSAKeyConfig{Curve: configv1alpha1.PKIECDSACurveP256},
			},
			want: mustECDSA(crypto.P256),
		},
		{
			name: "ECDSA-P384",
			input: configv1alpha1.PKIKeyConfig{
				Algorithm: configv1alpha1.PKIKeyAlgorithmECDSA,
				ECDSA:     configv1alpha1.PKIECDSAKeyConfig{Curve: configv1alpha1.PKIECDSACurveP384},
			},
			want: mustECDSA(crypto.P384),
		},
		{
			name: "ECDSA-P521",
			input: configv1alpha1.PKIKeyConfig{
				Algorithm: configv1alpha1.PKIKeyAlgorithmECDSA,
				ECDSA:     configv1alpha1.PKIECDSAKeyConfig{Curve: configv1alpha1.PKIECDSACurveP521},
			},
			want: mustECDSA(crypto.P521),
		},
		{
			name:    "algorithm unset",
			input:   configv1alpha1.PKIKeyConfig{},
			wantErr: true,
		},
		{
			name: "unknown algorithm",
			input: configv1alpha1.PKIKeyConfig{
				Algorithm: "unknown",
			},
			wantErr: true,
		},
		{
			name: "unknown ECDSA curve",
			input: configv1alpha1.PKIKeyConfig{
				Algorithm: configv1alpha1.PKIKeyAlgorithmECDSA,
				ECDSA:     configv1alpha1.PKIECDSAKeyConfig{Curve: "unknown"},
			},
			wantErr: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := KeyPairGeneratorFromAPI(tc.input)
			if (err != nil) != tc.wantErr {
				t.Errorf("KeyPairGeneratorFromAPI() error = %v, wantErr %v", err, tc.wantErr)
				return
			}
			if !tc.wantErr && got != tc.want {
				t.Errorf("KeyPairGeneratorFromAPI() = %+v, want %+v", got, tc.want)
			}
		})
	}
}
