package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"testing"
)

func TestMatchesCrossProduct(t *testing.T) {
	generators := []KeyPairGenerator{
		RSAKeyPairGenerator{Bits: 2048},
		RSAKeyPairGenerator{Bits: 3072},
		RSAKeyPairGenerator{Bits: 4096},
		ECDSAKeyPairGenerator{Curve: P256},
		ECDSAKeyPairGenerator{Curve: P384},
		ECDSAKeyPairGenerator{Curve: P521},
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
			generator: RSAKeyPairGenerator{Bits: 2048},
			key:       (*rsa.PublicKey)(nil),
			wantErr:   "RSA public key is nil",
		},
		{
			generator: RSAKeyPairGenerator{Bits: 2048},
			key:       &rsa.PublicKey{},
			wantErr:   "RSA public key has nil modulus",
		},
		{
			generator: ECDSAKeyPairGenerator{Curve: P256},
			key:       (*ecdsa.PublicKey)(nil),
			wantErr:   "ECDSA public key is nil",
		},
		{
			generator: ECDSAKeyPairGenerator{Curve: P256},
			key:       &ecdsa.PublicKey{},
			wantErr:   "ECDSA public key has nil curve",
		},
		{
			generator: ECDSAKeyPairGenerator{Curve: "bogus"},
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
