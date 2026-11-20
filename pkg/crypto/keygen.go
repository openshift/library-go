package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
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

// ECDSACurve identifies a named ECDSA curve.
type ECDSACurve string

const (
	// P256 specifies the NIST P-256 curve (secp256r1), providing 128-bit security.
	P256 ECDSACurve = "P256"
	// P384 specifies the NIST P-384 curve (secp384r1), providing 192-bit security.
	P384 ECDSACurve = "P384"
	// P521 specifies the NIST P-521 curve (secp521r1), providing 256-bit security.
	P521 ECDSACurve = "P521"
)

// MinRSAKeySize is the smallest RSA key size, in bits, that the generators in
// this package produce.
const MinRSAKeySize = 2048

// NewRSAKeyPairGenerator returns a KeyPairGenerator for RSA keys of the given
// size in bits. It rejects sizes below MinRSAKeySize; which sizes above the
// floor are allowed is left to the caller's configuration validation.
func NewRSAKeyPairGenerator(bits int) (KeyPairGenerator, error) {
	if err := validateRSAKeySize(bits); err != nil {
		return nil, err
	}
	return rsaKeyPairGenerator{bits: bits}, nil
}

// NewECDSAKeyPairGenerator returns a KeyPairGenerator for ECDSA keys on the
// given named curve.
func NewECDSAKeyPairGenerator(curve ECDSACurve) (KeyPairGenerator, error) {
	g := ecdsaKeyPairGenerator{curve: curve}
	if _, err := g.ellipticCurve(); err != nil {
		return nil, err
	}
	return g, nil
}

func validateRSAKeySize(bits int) error {
	if bits < MinRSAKeySize {
		return fmt.Errorf("invalid RSA key size %d: must be at least %d bits", bits, MinRSAKeySize)
	}
	return nil
}

// rsaKeyPairGenerator generates RSA key pairs. Construct it with
// NewRSAKeyPairGenerator.
type rsaKeyPairGenerator struct {
	bits int
}

func (g rsaKeyPairGenerator) Matches(pub crypto.PublicKey) error {
	if err := validateRSAKeySize(g.bits); err != nil {
		return fmt.Errorf("generator has invalid key size: %w", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("public key is %T, not *rsa.PublicKey", pub)
	}
	if rsaPub == nil {
		return fmt.Errorf("RSA public key is nil")
	}
	if rsaPub.N == nil {
		return fmt.Errorf("RSA public key has nil modulus")
	}
	if rsaPub.N.BitLen() != g.bits {
		return fmt.Errorf("RSA key size is %d bits, not %d", rsaPub.N.BitLen(), g.bits)
	}
	return nil
}

func (g rsaKeyPairGenerator) GenerateKeyPair() (crypto.PublicKey, crypto.PrivateKey, error) {
	// Re-checked here so that a generator that bypassed the constructor (for
	// example the zero value) can never produce a weak key.
	if err := validateRSAKeySize(g.bits); err != nil {
		return nil, nil, err
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, g.bits)
	if err != nil {
		return nil, nil, err
	}
	return &privateKey.PublicKey, privateKey, nil
}

// ecdsaKeyPairGenerator generates ECDSA key pairs. Construct it with
// NewECDSAKeyPairGenerator.
type ecdsaKeyPairGenerator struct {
	curve ECDSACurve
}

func (g ecdsaKeyPairGenerator) Matches(pub crypto.PublicKey) error {
	curve, err := g.ellipticCurve()
	if err != nil {
		return fmt.Errorf("generator has invalid curve %q: %w", g.curve, err)
	}

	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("public key is %T, not *ecdsa.PublicKey", pub)
	}
	if ecPub == nil {
		return fmt.Errorf("ECDSA public key is nil")
	}
	if ecPub.Curve == nil {
		return fmt.Errorf("ECDSA public key has nil curve")
	}
	if ecPub.Curve != curve {
		return fmt.Errorf("ECDSA curve is %s, not %s", ecPub.Curve.Params().Name, curve.Params().Name)
	}
	return nil
}

func (g ecdsaKeyPairGenerator) GenerateKeyPair() (crypto.PublicKey, crypto.PrivateKey, error) {
	curve, err := g.ellipticCurve()
	if err != nil {
		return nil, nil, err
	}
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return &privateKey.PublicKey, privateKey, nil
}

func (g ecdsaKeyPairGenerator) ellipticCurve() (elliptic.Curve, error) {
	switch g.curve {
	case P256:
		return elliptic.P256(), nil
	case P384:
		return elliptic.P384(), nil
	case P521:
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported ECDSA curve: %q", g.curve)
	}
}

// KeyUsageForPublicKey returns the x509.KeyUsage flags appropriate for the
// given public key type. ECDSA keys use DigitalSignature only; RSA keys also
// include KeyEncipherment.
func KeyUsageForPublicKey(pub crypto.PublicKey) x509.KeyUsage {
	switch pub.(type) {
	case *ecdsa.PublicKey:
		return x509.KeyUsageDigitalSignature
	default:
		return x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
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
