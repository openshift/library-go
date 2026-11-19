package crypto

import (
	stdcrypto "crypto"
	"fmt"
	"testing"
)

// unknownGenerator is a KeyPairGenerator that securityBits does not know
// about; StrongerKeyPairGenerator must fail closed on it instead of silently
// picking the other side's key.
type unknownGenerator struct{}

func (unknownGenerator) GenerateKeyPair() (stdcrypto.PublicKey, stdcrypto.PrivateKey, error) {
	return nil, nil, nil
}

func (unknownGenerator) Matches(stdcrypto.PublicKey) error {
	return fmt.Errorf("unknownGenerator matches no key")
}

func TestSecurityBits(t *testing.T) {
	testCases := []struct {
		name    string
		g       KeyPairGenerator
		want    int
		wantErr bool
	}{
		{
			name: "RSA-2048",
			g:    rsaKeyPairGenerator{bits: 2048},
			want: 112,
		},
		{
			name: "RSA-3072",
			g:    rsaKeyPairGenerator{bits: 3072},
			want: 128,
		},
		{
			name: "RSA-4096",
			g:    rsaKeyPairGenerator{bits: 4096},
			want: 152,
		},
		{
			name: "RSA-5120",
			g:    rsaKeyPairGenerator{bits: 5120},
			want: 168,
		},
		{
			name: "RSA-6144",
			g:    rsaKeyPairGenerator{bits: 6144},
			want: 176,
		},
		{
			name: "RSA-7168",
			g:    rsaKeyPairGenerator{bits: 7168},
			want: 192,
		},
		{
			name: "RSA-8192",
			g:    rsaKeyPairGenerator{bits: 8192},
			want: 200,
		},
		{
			name: "RSA between table entries rounds down",
			g:    rsaKeyPairGenerator{bits: 3000},
			want: 112,
		},
		{
			name: "RSA above the table caps at the largest entry",
			g:    rsaKeyPairGenerator{bits: 16384},
			want: 200,
		},
		{
			name:    "RSA-1024 below floor",
			g:       rsaKeyPairGenerator{bits: 1024},
			wantErr: true,
		},
		{
			name:    "RSA zero value",
			g:       rsaKeyPairGenerator{},
			wantErr: true,
		},
		{
			name: "ECDSA-P256",
			g:    ecdsaKeyPairGenerator{curve: P256},
			want: 128,
		},
		{
			name: "ECDSA-P384",
			g:    ecdsaKeyPairGenerator{curve: P384},
			want: 192,
		},
		{
			name: "ECDSA-P521",
			g:    ecdsaKeyPairGenerator{curve: P521},
			want: 256,
		},
		{
			name:    "ECDSA unknown curve",
			g:       ecdsaKeyPairGenerator{curve: "P224"},
			wantErr: true,
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
	rsa2048 := rsaKeyPairGenerator{bits: 2048}
	rsa3072 := rsaKeyPairGenerator{bits: 3072}
	rsa4096 := rsaKeyPairGenerator{bits: 4096}
	ecP256 := ecdsaKeyPairGenerator{curve: P256}
	ecP384 := ecdsaKeyPairGenerator{curve: P384}

	testCases := []struct {
		name    string
		a       KeyPairGenerator
		b       KeyPairGenerator
		want    KeyPairGenerator
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
			got, err := StrongerKeyPairGenerator(tc.a, tc.b)
			if tc.wantErr {
				if err == nil {
					t.Fatal("StrongerKeyPairGenerator() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("StrongerKeyPairGenerator() error = %v", err)
			}
			if got != tc.want {
				t.Errorf("StrongerKeyPairGenerator() = %+v, want %+v", got, tc.want)
			}
		})
	}
}
