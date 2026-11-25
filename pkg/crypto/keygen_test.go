package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"testing"
)

func TestMatchesCrossProduct(t *testing.T) {
	generators := []KeyPairGenerator{
		rsaKeyPairGenerator{bits: 2048},
		rsaKeyPairGenerator{bits: 3072},
		rsaKeyPairGenerator{bits: 4096},
		ecdsaKeyPairGenerator{curve: P256},
		ecdsaKeyPairGenerator{curve: P384},
		ecdsaKeyPairGenerator{curve: P521},
	}
	keys := make([]crypto.PublicKey, len(generators))
	for i, g := range generators {
		pub, _, err := g.GenerateKeyPair()
		if err != nil {
			t.Fatalf("generators[%d].GenerateKeyPair() error = %v", i, err)
		}
		keys[i] = pub
	}
	for i, g := range generators {
		for j, key := range keys {
			err := g.Matches(key)
			if i == j {
				if err != nil {
					t.Errorf("%s.Matches(key from %s) = %v, want nil",
						keyGenName(generators[i]), keyGenName(generators[j]), err)
				}
			} else {
				if err == nil {
					t.Errorf("%s.Matches(key from %s) = nil, want error",
						keyGenName(generators[i]), keyGenName(generators[j]))
				}
			}
		}
	}
}

func TestMatchesMalformedKeys(t *testing.T) {
	for _, tc := range []struct {
		generator KeyPairGenerator
		key       crypto.PublicKey
		wantErr   string
	}{
		{
			generator: rsaKeyPairGenerator{bits: 2048},
			key:       (*rsa.PublicKey)(nil),
			wantErr:   "RSA public key is nil",
		},
		{
			generator: rsaKeyPairGenerator{bits: 2048},
			key:       &rsa.PublicKey{},
			wantErr:   "RSA public key has nil modulus",
		},
		{
			generator: ecdsaKeyPairGenerator{curve: P256},
			key:       (*ecdsa.PublicKey)(nil),
			wantErr:   "ECDSA public key is nil",
		},
		{
			generator: ecdsaKeyPairGenerator{curve: P256},
			key:       &ecdsa.PublicKey{},
			wantErr:   "ECDSA public key has nil curve",
		},
		{
			generator: rsaKeyPairGenerator{},
			key:       &rsa.PublicKey{},
			wantErr:   "generator has invalid key size: invalid RSA key size 0: must be at least 2048 bits",
		},
		{
			generator: ecdsaKeyPairGenerator{curve: "bogus"},
			key:       &ecdsa.PublicKey{},
			wantErr:   `generator has invalid curve "bogus": unsupported ECDSA curve: "bogus"`,
		},
	} {
		t.Run(tc.wantErr, func(t *testing.T) {
			err := tc.generator.Matches(tc.key)
			if err == nil {
				t.Fatal("expected error")
			}
			if err.Error() != tc.wantErr {
				t.Errorf("got error %q, want %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestNewRSAKeyPairGenerator(t *testing.T) {
	testCases := []struct {
		name    string
		bits    int
		want    KeyPairGenerator
		wantErr bool
	}{
		{
			name: "2048",
			bits: 2048,
			want: rsaKeyPairGenerator{bits: 2048},
		},
		{
			name: "size between conventional sizes",
			bits: 2050,
			want: rsaKeyPairGenerator{bits: 2050},
		},
		{
			name: "8192",
			bits: 8192,
			want: rsaKeyPairGenerator{bits: 8192},
		},
		{
			name:    "below floor",
			bits:    1024,
			wantErr: true,
		},
		{
			name:    "zero",
			bits:    0,
			wantErr: true,
		},
		{
			name:    "negative",
			bits:    -2048,
			wantErr: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NewRSAKeyPairGenerator(tc.bits)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("NewRSAKeyPairGenerator(%d) = %+v, want error", tc.bits, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewRSAKeyPairGenerator(%d) error = %v", tc.bits, err)
			}
			if got != tc.want {
				t.Errorf("NewRSAKeyPairGenerator(%d) = %+v, want %+v", tc.bits, got, tc.want)
			}
		})
	}
}

func TestNewECDSAKeyPairGenerator(t *testing.T) {
	testCases := []struct {
		name    string
		curve   ECDSACurve
		want    KeyPairGenerator
		wantErr bool
	}{
		{
			name:  "P256",
			curve: P256,
			want:  ecdsaKeyPairGenerator{curve: P256},
		},
		{
			name:  "P384",
			curve: P384,
			want:  ecdsaKeyPairGenerator{curve: P384},
		},
		{
			name:  "P521",
			curve: P521,
			want:  ecdsaKeyPairGenerator{curve: P521},
		},
		{
			name:    "unknown curve",
			curve:   "P224",
			wantErr: true,
		},
		{
			name:    "empty curve",
			curve:   "",
			wantErr: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NewECDSAKeyPairGenerator(tc.curve)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("NewECDSAKeyPairGenerator(%q) = %+v, want error", tc.curve, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewECDSAKeyPairGenerator(%q) error = %v", tc.curve, err)
			}
			if got != tc.want {
				t.Errorf("NewECDSAKeyPairGenerator(%q) = %+v, want %+v", tc.curve, got, tc.want)
			}
		})
	}
}

// TestRSAKeyPairGeneratorEnforcesFloor covers generators that bypass the
// constructor: GenerateKeyPair must refuse to produce a key below the floor,
// including for the zero value.
func TestRSAKeyPairGeneratorEnforcesFloor(t *testing.T) {
	testCases := []struct {
		name string
		g    rsaKeyPairGenerator
	}{
		{
			name: "zero value",
			g:    rsaKeyPairGenerator{},
		},
		{
			name: "1024 bits",
			g:    rsaKeyPairGenerator{bits: 1024},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := tc.g.GenerateKeyPair(); err == nil {
				t.Fatal("GenerateKeyPair() error = nil, want error")
			}
		})
	}
}

func TestRSAKeyPairGeneratorGeneratesRequestedSize(t *testing.T) {
	g, err := NewRSAKeyPairGenerator(2048)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := g.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("public key type = %T, want *rsa.PublicKey", pub)
	}
	if rsaPub.N.BitLen() != 2048 {
		t.Errorf("key size = %d, want 2048", rsaPub.N.BitLen())
	}
	if _, ok := priv.(crypto.Signer); !ok {
		t.Errorf("private key type %T does not implement crypto.Signer", priv)
	}
}
