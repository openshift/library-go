package crypto

import (
	gocrypto "crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

// KeyAlgorithm identifies the key generation algorithm.
type KeyAlgorithm string

const (
	// RSAKeyAlgorithm specifies RSA key generation.
	RSAKeyAlgorithm KeyAlgorithm = "RSA"
	// ECDSAKeyAlgorithm specifies ECDSA key generation.
	ECDSAKeyAlgorithm KeyAlgorithm = "ECDSA"
)

// KeyPairGenerator generates a cryptographic key pair. Obtain this package's
// implementations through KeySpec.KeyPairGenerator.
type KeyPairGenerator interface {
	GenerateKeyPair() (gocrypto.PublicKey, gocrypto.PrivateKey, error)

	// Matches returns nil if pub is consistent with a key pair
	// that a generator with the same parameters would
	// produce. Returns a non-nil error describing the mismatch
	// otherwise.
	Matches(pub gocrypto.PublicKey) error
}

// keyPairGenerator is the single implementation of KeyPairGenerator produced
// by KeySpec.KeyPairGenerator. All algorithm-specific behavior derives from
// the spec.
type keyPairGenerator struct {
	spec KeySpec
}

var _ KeyPairGenerator = keyPairGenerator{}

func (g keyPairGenerator) GenerateKeyPair() (gocrypto.PublicKey, gocrypto.PrivateKey, error) {
	pub, priv, err := generateKeyPair(g.spec)
	if err != nil {
		return nil, nil, err
	}
	// Self-check: a generated key must satisfy the spec it was generated
	// for. A failure here is a bug in this package, not in the caller's
	// configuration.
	if err := g.spec.Matches(pub); err != nil {
		return nil, nil, fmt.Errorf("generated key does not match its own spec: %w", err)
	}
	return pub, priv, nil
}

func (g keyPairGenerator) Matches(pub gocrypto.PublicKey) error {
	return g.spec.Matches(pub)
}

func generateKeyPair(spec KeySpec) (gocrypto.PublicKey, gocrypto.PrivateKey, error) {
	switch spec.Algorithm {
	case RSAKeyAlgorithm:
		return generateRSAKeyPair(spec.RSABits)
	case ECDSAKeyAlgorithm:
		return generateECDSAKeyPair(spec.ECDSACurve)
	default:
		return nil, nil, fmt.Errorf("unknown key algorithm: %q", spec.Algorithm)
	}
}

func generateRSAKeyPair(bits int) (gocrypto.PublicKey, gocrypto.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	return &privateKey.PublicKey, privateKey, nil
}

func generateECDSAKeyPair(curve ECDSACurve) (gocrypto.PublicKey, gocrypto.PrivateKey, error) {
	ellipticCurve, err := ellipticCurveFor(curve)
	if err != nil {
		return nil, nil, err
	}
	privateKey, err := ecdsa.GenerateKey(ellipticCurve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return &privateKey.PublicKey, privateKey, nil
}
