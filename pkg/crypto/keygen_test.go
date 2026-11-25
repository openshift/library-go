package crypto

import (
	gocrypto "crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"testing"
)

// mustGenerator returns the generator for spec, panicking if spec is invalid.
// It is for tests whose specs are known valid.
func mustGenerator(spec KeySpec) KeyPairGenerator {
	g, err := spec.KeyPairGenerator()
	if err != nil {
		panic(err)
	}
	return g
}

func TestMatchesCrossProduct(t *testing.T) {
	specs := []KeySpec{
		{Algorithm: RSAKeyAlgorithm, RSABits: 2048},
		{Algorithm: RSAKeyAlgorithm, RSABits: 3072},
		{Algorithm: RSAKeyAlgorithm, RSABits: 4096},
		{Algorithm: ECDSAKeyAlgorithm, ECDSACurve: P256},
		{Algorithm: ECDSAKeyAlgorithm, ECDSACurve: P384},
		{Algorithm: ECDSAKeyAlgorithm, ECDSACurve: P521},
	}
	generators := make([]KeyPairGenerator, len(specs))
	keys := make([]gocrypto.PublicKey, len(specs))
	for i, spec := range specs {
		generators[i] = mustGenerator(spec)
		pub, _, err := generators[i].GenerateKeyPair()
		if err != nil {
			t.Fatalf("generators[%d].GenerateKeyPair() error = %v", i, err)
		}
		keys[i] = pub
	}
	for i, spec := range specs {
		for j, key := range keys {
			err := spec.Matches(key)
			if i == j {
				if err != nil {
					t.Errorf("%s.Matches(key from %s) = %v, want nil",
						specs[i], specs[j], err)
				}
			} else {
				if err == nil {
					t.Errorf("%s.Matches(key from %s) = nil, want error",
						specs[i], specs[j])
				}
			}
		}
	}
}

func TestMatchesMalformedKeys(t *testing.T) {
	for _, tc := range []struct {
		spec    KeySpec
		key     gocrypto.PublicKey
		wantErr string
	}{
		{
			spec:    KeySpec{Algorithm: RSAKeyAlgorithm, RSABits: 2048},
			key:     (*rsa.PublicKey)(nil),
			wantErr: "RSA public key is nil",
		},
		{
			spec:    KeySpec{Algorithm: RSAKeyAlgorithm, RSABits: 2048},
			key:     &rsa.PublicKey{},
			wantErr: "RSA public key has nil modulus",
		},
		{
			spec:    KeySpec{Algorithm: ECDSAKeyAlgorithm, ECDSACurve: P256},
			key:     (*ecdsa.PublicKey)(nil),
			wantErr: "ECDSA public key is nil",
		},
		{
			spec:    KeySpec{Algorithm: ECDSAKeyAlgorithm, ECDSACurve: P256},
			key:     &ecdsa.PublicKey{},
			wantErr: "ECDSA public key has nil curve",
		},
		{
			spec:    KeySpec{Algorithm: ECDSAKeyAlgorithm, ECDSACurve: "bogus"},
			key:     &ecdsa.PublicKey{},
			wantErr: `key spec is invalid: invalid ECDSA key spec: unsupported ECDSA curve: "bogus"`,
		},
	} {
		t.Run(tc.wantErr, func(t *testing.T) {
			err := tc.spec.Matches(tc.key)
			if err == nil {
				t.Fatal("expected error")
			}
			if err.Error() != tc.wantErr {
				t.Errorf("got error %q, want %q", err.Error(), tc.wantErr)
			}
		})
	}
}
