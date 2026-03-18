package pki

import (
	"testing"

	configv1alpha1 "github.com/openshift/api/config/v1alpha1"
	"github.com/openshift/library-go/pkg/crypto"
)

func TestDefaultPKIProfile(t *testing.T) {
	profile := DefaultPKIProfile()

	// Default should be RSA-2048
	if profile.Defaults.Key.Algorithm != configv1alpha1.KeyAlgorithmRSA {
		t.Errorf("defaults algorithm = %v, want RSA", profile.Defaults.Key.Algorithm)
	}
	if profile.Defaults.Key.RSA.KeySize != 2048 {
		t.Errorf("defaults RSA key size = %d, want 2048", profile.Defaults.Key.RSA.KeySize)
	}

	// Signers should be RSA-4096
	if profile.SignerCertificates.Key.Algorithm != configv1alpha1.KeyAlgorithmRSA {
		t.Errorf("signer algorithm = %v, want RSA", profile.SignerCertificates.Key.Algorithm)
	}
	if profile.SignerCertificates.Key.RSA.KeySize != 4096 {
		t.Errorf("signer RSA key size = %d, want 4096", profile.SignerCertificates.Key.RSA.KeySize)
	}

	// Serving and client should be unset (fall back to defaults)
	if profile.ServingCertificates.Key.Algorithm != "" {
		t.Errorf("serving algorithm = %v, want empty (unset)", profile.ServingCertificates.Key.Algorithm)
	}
	if profile.ClientCertificates.Key.Algorithm != "" {
		t.Errorf("client algorithm = %v, want empty (unset)", profile.ClientCertificates.Key.Algorithm)
	}
}

func TestKeyConfigFromAPI(t *testing.T) {
	testCases := []struct {
		name    string
		input   configv1alpha1.KeyConfig
		want    crypto.KeyConfig
		wantErr bool
	}{
		{
			name: "RSA-2048",
			input: configv1alpha1.KeyConfig{
				Algorithm: configv1alpha1.KeyAlgorithmRSA,
				RSA:       configv1alpha1.RSAKeyConfig{KeySize: 2048},
			},
			want: crypto.KeyConfig{Algorithm: crypto.RSAKeyAlgorithm, RSABits: 2048},
		},
		{
			name: "RSA-4096",
			input: configv1alpha1.KeyConfig{
				Algorithm: configv1alpha1.KeyAlgorithmRSA,
				RSA:       configv1alpha1.RSAKeyConfig{KeySize: 4096},
			},
			want: crypto.KeyConfig{Algorithm: crypto.RSAKeyAlgorithm, RSABits: 4096},
		},
		{
			name: "ECDSA-P256",
			input: configv1alpha1.KeyConfig{
				Algorithm: configv1alpha1.KeyAlgorithmECDSA,
				ECDSA:     configv1alpha1.ECDSAKeyConfig{Curve: configv1alpha1.ECDSACurveP256},
			},
			want: crypto.KeyConfig{Algorithm: crypto.ECDSAKeyAlgorithm, ECDSACurve: crypto.P256},
		},
		{
			name: "ECDSA-P384",
			input: configv1alpha1.KeyConfig{
				Algorithm: configv1alpha1.KeyAlgorithmECDSA,
				ECDSA:     configv1alpha1.ECDSAKeyConfig{Curve: configv1alpha1.ECDSACurveP384},
			},
			want: crypto.KeyConfig{Algorithm: crypto.ECDSAKeyAlgorithm, ECDSACurve: crypto.P384},
		},
		{
			name: "ECDSA-P521",
			input: configv1alpha1.KeyConfig{
				Algorithm: configv1alpha1.KeyAlgorithmECDSA,
				ECDSA:     configv1alpha1.ECDSAKeyConfig{Curve: configv1alpha1.ECDSACurveP521},
			},
			want: crypto.KeyConfig{Algorithm: crypto.ECDSAKeyAlgorithm, ECDSACurve: crypto.P521},
		},
		{
			name: "unknown algorithm",
			input: configv1alpha1.KeyConfig{
				Algorithm: "unknown",
			},
			wantErr: true,
		},
		{
			name: "unknown ECDSA curve",
			input: configv1alpha1.KeyConfig{
				Algorithm: configv1alpha1.KeyAlgorithmECDSA,
				ECDSA:     configv1alpha1.ECDSAKeyConfig{Curve: "unknown"},
			},
			wantErr: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := KeyConfigFromAPI(tc.input)
			if (err != nil) != tc.wantErr {
				t.Errorf("KeyConfigFromAPI() error = %v, wantErr %v", err, tc.wantErr)
				return
			}
			if !tc.wantErr && got != tc.want {
				t.Errorf("KeyConfigFromAPI() = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestSecurityBits(t *testing.T) {
	testCases := []struct {
		name string
		kc   crypto.KeyConfig
		want int
	}{
		// RSA values are from the GNFS formula (approximate, not NIST rounded values)
		{"RSA-2048", crypto.KeyConfig{Algorithm: crypto.RSAKeyAlgorithm, RSABits: 2048}, 110},
		{"RSA-3072", crypto.KeyConfig{Algorithm: crypto.RSAKeyAlgorithm, RSABits: 3072}, 131},
		{"RSA-4096", crypto.KeyConfig{Algorithm: crypto.RSAKeyAlgorithm, RSABits: 4096}, 149},
		{"ECDSA-P256", crypto.KeyConfig{Algorithm: crypto.ECDSAKeyAlgorithm, ECDSACurve: crypto.P256}, 128},
		{"ECDSA-P384", crypto.KeyConfig{Algorithm: crypto.ECDSAKeyAlgorithm, ECDSACurve: crypto.P384}, 192},
		{"ECDSA-P521", crypto.KeyConfig{Algorithm: crypto.ECDSAKeyAlgorithm, ECDSACurve: crypto.P521}, 256},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := securityBits(tc.kc)
			if got != tc.want {
				t.Errorf("securityBits(%s) = %d, want %d", tc.name, got, tc.want)
			}
		})
	}
}

func TestStrongerKeyConfig(t *testing.T) {
	rsa2048 := crypto.KeyConfig{Algorithm: crypto.RSAKeyAlgorithm, RSABits: 2048}
	rsa4096 := crypto.KeyConfig{Algorithm: crypto.RSAKeyAlgorithm, RSABits: 4096}
	ecP256 := crypto.KeyConfig{Algorithm: crypto.ECDSAKeyAlgorithm, ECDSACurve: crypto.P256}
	ecP384 := crypto.KeyConfig{Algorithm: crypto.ECDSAKeyAlgorithm, ECDSACurve: crypto.P384}

	testCases := []struct {
		name string
		a, b crypto.KeyConfig
		want crypto.KeyConfig
	}{
		{"RSA-2048 vs RSA-4096", rsa2048, rsa4096, rsa4096},
		{"RSA-4096 vs RSA-2048", rsa4096, rsa2048, rsa4096},
		{"RSA-2048 vs ECDSA-P256", rsa2048, ecP256, ecP256},  // 112 vs 128
		{"ECDSA-P256 vs RSA-2048", ecP256, rsa2048, ecP256},  // 128 vs 112
		{"RSA-4096 vs ECDSA-P256", rsa4096, ecP256, rsa4096}, // 152 vs 128
		{"ECDSA-P256 vs ECDSA-P384", ecP256, ecP384, ecP384}, // 128 vs 192
		{"equal: returns first", rsa2048, rsa2048, rsa2048},  // tie returns a
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := strongerKeyConfig(tc.a, tc.b)
			if got != tc.want {
				t.Errorf("strongerKeyConfig() = %+v, want %+v", got, tc.want)
			}
		})
	}
}
