package crypto

import (
	"crypto"
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
