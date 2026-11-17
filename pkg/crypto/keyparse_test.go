package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
)

func rsaKeyPEM(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

func ecdsaKeyPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

func ed25519KeyPEM(t *testing.T) []byte {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func TestParsePrivateKeyPEM(t *testing.T) {
	testCases := []struct {
		name       string
		input      []byte
		expectErr  error
		expectAlgo KeyAlgorithm
	}{
		{
			name:       "RSA PKCS#1 key parses",
			input:      rsaKeyPEM(t),
			expectAlgo: "RSA",
		},
		{
			name:       "EC SEC1 key parses",
			input:      ecdsaKeyPEM(t),
			expectAlgo: "ECDSA",
		},
		{
			name:       "Ed25519 PKCS#8 key parses",
			input:      ed25519KeyPEM(t),
			expectAlgo: "Ed25519",
		},
		{
			name:      "missing PEM block is malformed",
			input:     []byte("not pem at all"),
			expectErr: errMalformed,
		},
		{
			name:      "unexpected block type is malformed",
			input:     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{}}),
			expectErr: errMalformed,
		},
		{
			name:      "garbage inside a known block type is malformed",
			input:     pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte{1, 2, 3}}),
			expectErr: errMalformed,
		},
		{
			name:       "future algorithm block type is unknown, not malformed",
			input:      pem.EncodeToMemory(&pem.Block{Type: "ML-DSA PRIVATE KEY", Bytes: []byte{1, 2, 3}}),
			expectErr:  ErrUnknownKeyAlgorithm,
			expectAlgo: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := ParsePrivateKeyPEM(tc.input)
			if tc.expectErr != nil {
				if err == nil {
					t.Fatalf("expected error, got key %T", key)
				}
				if tc.expectErr == errMalformed {
					if errors.Is(err, ErrUnknownKeyAlgorithm) {
						t.Fatalf("expected malformed error, got ErrUnknownKeyAlgorithm: %v", err)
					}
					if errors.Is(err, tc.expectErr) {
						t.Fatalf("expected malformed error distinct from %v, got it", tc.expectErr)
					}
					return
				}
				if !errors.Is(err, tc.expectErr) {
					t.Fatalf("expected error wrapping %v, got %v", tc.expectErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			algo, err := KeyAlgorithmForPrivateKey(key)
			if err != nil {
				t.Fatalf("KeyAlgorithmForPrivateKey failed: %v", err)
			}
			if algo != tc.expectAlgo {
				t.Errorf("expected algorithm %q, got %q", tc.expectAlgo, algo)
			}
		})
	}
}

// errMalformed is a sentinel local to the test: any error that is not
// ErrUnknownKeyAlgorithm and not nil.
var errMalformed = errors.New("malformed")

func TestKeyAlgorithmForPrivateKeyUnknown(t *testing.T) {
	// A private key type this build cannot generate: a raw big.Int pointer
	// exercises the default branch without fabricating a future key.
	if _, err := KeyAlgorithmForPrivateKey(big.NewInt(1)); !errors.Is(err, ErrUnknownKeyAlgorithm) {
		t.Fatalf("expected ErrUnknownKeyAlgorithm, got %v", err)
	}
}
