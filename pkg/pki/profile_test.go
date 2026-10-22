package pki

import (
	stdcrypto "crypto"
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
			want: crypto.RSAKeyPairGenerator{Bits: 2048},
		},
		{
			name: "RSA-3072",
			input: configv1alpha1.PKIKeyConfig{
				Algorithm: configv1alpha1.PKIKeyAlgorithmRSA,
				RSA:       configv1alpha1.PKIRSAKeyConfig{KeySize: 3072},
			},
			want: crypto.RSAKeyPairGenerator{Bits: 3072},
		},
		{
			name: "RSA-4096",
			input: configv1alpha1.PKIKeyConfig{
				Algorithm: configv1alpha1.PKIKeyAlgorithmRSA,
				RSA:       configv1alpha1.PKIRSAKeyConfig{KeySize: 4096},
			},
			want: crypto.RSAKeyPairGenerator{Bits: 4096},
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
			name: "RSA key size too large",
			input: configv1alpha1.PKIKeyConfig{
				Algorithm: configv1alpha1.PKIKeyAlgorithmRSA,
				RSA:       configv1alpha1.PKIRSAKeyConfig{KeySize: 8192},
			},
			wantErr: true,
		},
		{
			name: "RSA key size not a multiple of 1024",
			input: configv1alpha1.PKIKeyConfig{
				Algorithm: configv1alpha1.PKIKeyAlgorithmRSA,
				RSA:       configv1alpha1.PKIRSAKeyConfig{KeySize: 2050},
			},
			wantErr: true,
		},
		{
			name: "ECDSA-P256",
			input: configv1alpha1.PKIKeyConfig{
				Algorithm: configv1alpha1.PKIKeyAlgorithmECDSA,
				ECDSA:     configv1alpha1.PKIECDSAKeyConfig{Curve: configv1alpha1.PKIECDSACurveP256},
			},
			want: crypto.ECDSAKeyPairGenerator{Curve: crypto.P256},
		},
		{
			name: "ECDSA-P384",
			input: configv1alpha1.PKIKeyConfig{
				Algorithm: configv1alpha1.PKIKeyAlgorithmECDSA,
				ECDSA:     configv1alpha1.PKIECDSAKeyConfig{Curve: configv1alpha1.PKIECDSACurveP384},
			},
			want: crypto.ECDSAKeyPairGenerator{Curve: crypto.P384},
		},
		{
			name: "ECDSA-P521",
			input: configv1alpha1.PKIKeyConfig{
				Algorithm: configv1alpha1.PKIKeyAlgorithmECDSA,
				ECDSA:     configv1alpha1.PKIECDSAKeyConfig{Curve: configv1alpha1.PKIECDSACurveP521},
			},
			want: crypto.ECDSAKeyPairGenerator{Curve: crypto.P521},
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

// unknownGenerator is a KeyPairGenerator that securityBits does not know
// about; peer resolution must fail closed on it instead of silently
// downgrading to the other side's key.
type unknownGenerator struct{}

func (unknownGenerator) GenerateKeyPair() (stdcrypto.PublicKey, stdcrypto.PrivateKey, error) {
	return nil, nil, nil
}

func TestSecurityBits(t *testing.T) {
	testCases := []struct {
		name    string
		g       crypto.KeyPairGenerator
		want    int
		wantErr bool
	}{
		{
			name: "RSA-2048",
			g:    crypto.RSAKeyPairGenerator{Bits: 2048},
			want: 112,
		},
		{
			name: "RSA-3072",
			g:    crypto.RSAKeyPairGenerator{Bits: 3072},
			want: 128,
		},
		{
			name: "RSA-4096",
			g:    crypto.RSAKeyPairGenerator{Bits: 4096},
			want: 152,
		},
		{
			name: "RSA-5120",
			g:    crypto.RSAKeyPairGenerator{Bits: 5120},
			want: 168,
		},
		{
			name: "RSA-6144",
			g:    crypto.RSAKeyPairGenerator{Bits: 6144},
			want: 176,
		},
		{
			name: "RSA-7168",
			g:    crypto.RSAKeyPairGenerator{Bits: 7168},
			want: 192,
		},
		{
			name: "RSA-8192",
			g:    crypto.RSAKeyPairGenerator{Bits: 8192},
			want: 200,
		},
		{
			name:    "RSA-1024 unsupported",
			g:       crypto.RSAKeyPairGenerator{Bits: 1024},
			wantErr: true,
		},
		{
			name: "ECDSA-P256",
			g:    crypto.ECDSAKeyPairGenerator{Curve: crypto.P256},
			want: 128,
		},
		{
			name: "ECDSA-P384",
			g:    crypto.ECDSAKeyPairGenerator{Curve: crypto.P384},
			want: 192,
		},
		{
			name: "ECDSA-P521",
			g:    crypto.ECDSAKeyPairGenerator{Curve: crypto.P521},
			want: 256,
		},
		{
			name:    "unknown generator type",
			g:       unknownGenerator{},
			wantErr: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := securityBits(tc.g)
			if tc.wantErr {
				if err == nil {
					t.Fatal("securityBits() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("securityBits() error = %v", err)
			}
			if got != tc.want {
				t.Errorf("securityBits(%s) = %d, want %d", tc.name, got, tc.want)
			}
		})
	}
}

func TestStrongerKeyPairGenerator(t *testing.T) {
	rsa2048 := crypto.RSAKeyPairGenerator{Bits: 2048}
	rsa3072 := crypto.RSAKeyPairGenerator{Bits: 3072}
	rsa4096 := crypto.RSAKeyPairGenerator{Bits: 4096}
	ecP256 := crypto.ECDSAKeyPairGenerator{Curve: crypto.P256}
	ecP384 := crypto.ECDSAKeyPairGenerator{Curve: crypto.P384}

	testCases := []struct {
		name    string
		a, b    crypto.KeyPairGenerator
		want    crypto.KeyPairGenerator
		wantErr bool
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
		{
			name:    "unknown generator fails closed",
			a:       ecP256,
			b:       unknownGenerator{},
			wantErr: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := strongerKeyPairGenerator(tc.a, tc.b)
			if tc.wantErr {
				if err == nil {
					t.Fatal("strongerKeyPairGenerator() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("strongerKeyPairGenerator() error = %v", err)
			}
			if got != tc.want {
				t.Errorf("strongerKeyPairGenerator() = %+v, want %+v", got, tc.want)
			}
		})
	}
}
