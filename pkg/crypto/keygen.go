package crypto

import "crypto"

// KeyAlgorithm identifies the key generation algorithm.
type KeyAlgorithm string

const (
	// RSAKeyAlgorithm specifies RSA key generation.
	RSAKeyAlgorithm KeyAlgorithm = "RSA"
	// ECDSAKeyAlgorithm specifies ECDSA key generation.
	ECDSAKeyAlgorithm KeyAlgorithm = "ECDSA"
)

// KeyPairGenerator generates a cryptographic key pair.
type KeyPairGenerator interface {
	GenerateKeyPair() (crypto.PublicKey, crypto.PrivateKey, error)

	// Matches returns nil if pub is consistent with a key pair
	// that a generator with the same parameters would
	// produce. Returns a non-nil error describing the mismatch
	// otherwise.
	Matches(pub crypto.PublicKey) error

	// SecurityLevel returns the cryptographic strength of the key pairs
	// this generator produces, under both classical and quantum threat
	// models.
	SecurityLevel() SecurityLevel
}
