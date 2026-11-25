package pki

import (
	"testing"

	configv1alpha1 "github.com/openshift/api/config/v1alpha1"
	"github.com/openshift/library-go/pkg/crypto"
)

func TestDefaultPKIProfile(t *testing.T) {
	profile := DefaultPKIProfile()

	// Default should be ECDSA P-256
	if profile.Defaults.Key.Algorithm != configv1alpha1.KeyAlgorithmECDSA {
		t.Errorf("defaults algorithm = %v, want ECDSA", profile.Defaults.Key.Algorithm)
	}
	if profile.Defaults.Key.ECDSA.Curve != configv1alpha1.ECDSACurveP256 {
		t.Errorf("defaults ECDSA curve = %v, want P-256", profile.Defaults.Key.ECDSA.Curve)
	}

	// Signers should be ECDSA P-384
	if profile.SignerCertificates.Key.Algorithm != configv1alpha1.KeyAlgorithmECDSA {
		t.Errorf("signer algorithm = %v, want ECDSA", profile.SignerCertificates.Key.Algorithm)
	}
	if profile.SignerCertificates.Key.ECDSA.Curve != configv1alpha1.ECDSACurveP384 {
		t.Errorf("signer ECDSA curve = %v, want P-384", profile.SignerCertificates.Key.ECDSA.Curve)
	}

	// Serving and client should be unset (fall back to defaults)
	if profile.ServingCertificates.Key.Algorithm != "" {
		t.Errorf("serving algorithm = %v, want empty (unset)", profile.ServingCertificates.Key.Algorithm)
	}
	if profile.ClientCertificates.Key.Algorithm != "" {
		t.Errorf("client algorithm = %v, want empty (unset)", profile.ClientCertificates.Key.Algorithm)
	}
}

func TestKeySpecFromAPI(t *testing.T) {
	testCases := []struct {
		name    string
		input   configv1alpha1.KeyConfig
		want    crypto.KeySpec
		wantErr bool
	}{
		{
			name: "RSA-2048",
			input: configv1alpha1.KeyConfig{
				Algorithm: configv1alpha1.KeyAlgorithmRSA,
				RSA:       configv1alpha1.RSAKeyConfig{KeySize: 2048},
			},
			want: crypto.KeySpec{Algorithm: crypto.RSAKeyAlgorithm, RSABits: 2048},
		},
		{
			name: "RSA-4096",
			input: configv1alpha1.KeyConfig{
				Algorithm: configv1alpha1.KeyAlgorithmRSA,
				RSA:       configv1alpha1.RSAKeyConfig{KeySize: 4096},
			},
			want: crypto.KeySpec{Algorithm: crypto.RSAKeyAlgorithm, RSABits: 4096},
		},
		{
			name: "ECDSA-P256",
			input: configv1alpha1.KeyConfig{
				Algorithm: configv1alpha1.KeyAlgorithmECDSA,
				ECDSA:     configv1alpha1.ECDSAKeyConfig{Curve: configv1alpha1.ECDSACurveP256},
			},
			want: crypto.KeySpec{Algorithm: crypto.ECDSAKeyAlgorithm, ECDSACurve: crypto.P256},
		},
		{
			name: "ECDSA-P384",
			input: configv1alpha1.KeyConfig{
				Algorithm: configv1alpha1.KeyAlgorithmECDSA,
				ECDSA:     configv1alpha1.ECDSAKeyConfig{Curve: configv1alpha1.ECDSACurveP384},
			},
			want: crypto.KeySpec{Algorithm: crypto.ECDSAKeyAlgorithm, ECDSACurve: crypto.P384},
		},
		{
			name: "ECDSA-P521",
			input: configv1alpha1.KeyConfig{
				Algorithm: configv1alpha1.KeyAlgorithmECDSA,
				ECDSA:     configv1alpha1.ECDSAKeyConfig{Curve: configv1alpha1.ECDSACurveP521},
			},
			want: crypto.KeySpec{Algorithm: crypto.ECDSAKeyAlgorithm, ECDSACurve: crypto.P521},
		},
		{
			name: "missing algorithm",
			input: configv1alpha1.KeyConfig{
				RSA: configv1alpha1.RSAKeyConfig{KeySize: 2048},
			},
			wantErr: true,
		},
		{
			name: "RSA below the floor",
			input: configv1alpha1.KeyConfig{
				Algorithm: configv1alpha1.KeyAlgorithmRSA,
				RSA:       configv1alpha1.RSAKeyConfig{KeySize: 1024},
			},
			wantErr: true,
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
			got, err := KeySpecFromAPI(tc.input)
			if (err != nil) != tc.wantErr {
				t.Errorf("KeySpecFromAPI() error = %v, wantErr %v", err, tc.wantErr)
				return
			}
			if !tc.wantErr && got != tc.want {
				t.Errorf("KeySpecFromAPI() = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestStrongerKeySpec(t *testing.T) {
	rsa2048 := crypto.KeySpec{Algorithm: crypto.RSAKeyAlgorithm, RSABits: 2048}
	rsa3072 := crypto.KeySpec{Algorithm: crypto.RSAKeyAlgorithm, RSABits: 3072}
	rsa4096 := crypto.KeySpec{Algorithm: crypto.RSAKeyAlgorithm, RSABits: 4096}
	ecP256 := crypto.KeySpec{Algorithm: crypto.ECDSAKeyAlgorithm, ECDSACurve: crypto.P256}
	ecP384 := crypto.KeySpec{Algorithm: crypto.ECDSAKeyAlgorithm, ECDSACurve: crypto.P384}

	testCases := []struct {
		name string
		a, b crypto.KeySpec
		want crypto.KeySpec
	}{
		{
			name: "RSA-2048 vs RSA-4096",
			a:    rsa2048,
			b:    rsa4096,
			want: rsa4096,
		},
		{
			name: "RSA-4096 vs RSA-2048",
			a:    rsa4096,
			b:    rsa2048,
			want: rsa4096,
		},
		{
			name: "RSA-2048 vs ECDSA-P256", // 112 vs 128
			a:    rsa2048,
			b:    ecP256,
			want: ecP256,
		},
		{
			name: "ECDSA-P256 vs RSA-2048", // 128 vs 112
			a:    ecP256,
			b:    rsa2048,
			want: ecP256,
		},
		{
			name: "RSA-4096 vs ECDSA-P256", // 152 vs 128
			a:    rsa4096,
			b:    ecP256,
			want: rsa4096,
		},
		{
			name: "ECDSA-P256 vs ECDSA-P384", // 128 vs 192
			a:    ecP256,
			b:    ecP384,
			want: ecP384,
		},
		{
			name: "RSA-3072 vs ECDSA-P256 (tie: prefer ECDSA)", // 128 vs 128
			a:    rsa3072,
			b:    ecP256,
			want: ecP256,
		},
		{
			name: "ECDSA-P256 vs RSA-3072 (tie: prefer ECDSA)", // 128 vs 128
			a:    ecP256,
			b:    rsa3072,
			want: ecP256,
		},
		{
			name: "equal RSA: returns first",
			a:    rsa2048,
			b:    rsa2048,
			want: rsa2048,
		},
		{
			name: "equal ECDSA: returns first",
			a:    ecP256,
			b:    ecP256,
			want: ecP256,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := crypto.StrongerKeySpec(tc.a, tc.b)
			if got != tc.want {
				t.Errorf("StrongerKeySpec() = %+v, want %+v", got, tc.want)
			}
		})
	}
}
