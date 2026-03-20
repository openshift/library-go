package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
)

// GenerateKeyPair generates a key pair based on the given KeyConfig.
func GenerateKeyPair(config KeyConfig) (crypto.PublicKey, crypto.PrivateKey, error) {
	switch config.Algorithm {
	case RSAKeyAlgorithm:
		bits := config.RSABits
		if bits == 0 {
			bits = keyBits
		}
		privateKey, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, nil, err
		}
		return &privateKey.PublicKey, privateKey, nil
	case ECDSAKeyAlgorithm:
		curve, err := config.ellipticCurve()
		if err != nil {
			return nil, nil, err
		}
		privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return &privateKey.PublicKey, privateKey, nil
	default:
		return nil, nil, fmt.Errorf("unsupported key algorithm: %q", config.Algorithm)
	}
}

// SubjectKeyIDFromPublicKey computes a truncated SHA-256 hash suitable for
// use as a certificate SubjectKeyId from any supported public key type.
// This uses the first 160 bits of the SHA-256 hash per RFC 7093, consistent
// with the Go standard library since Go 1.25 (go.dev/issue/71746) and
// Let's Encrypt. Prior Go versions used SHA-1 which is not FIPS-compatible.
func SubjectKeyIDFromPublicKey(pub crypto.PublicKey) ([]byte, error) {
	var rawBytes []byte
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		rawBytes = pub.N.Bytes()
	case *ecdsa.PublicKey:
		ecdhKey, err := pub.ECDH()
		if err != nil {
			return nil, fmt.Errorf("failed to convert ECDSA public key: %w", err)
		}
		rawBytes = ecdhKey.Bytes()
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", pub)
	}
	hash := sha256.Sum256(rawBytes)
	return hash[:20], nil
}
