package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

// RSAKeyPairGenerator generates RSA key pairs.
type RSAKeyPairGenerator struct {
	// Bits is the RSA key size in bits. Must be >= 2048.
	Bits int
}

func (g RSAKeyPairGenerator) Matches(pub crypto.PublicKey) error {
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
	bits := g.Bits
	if bits == 0 {
		bits = keyBits
	}
	if rsaPub.N.BitLen() != bits {
		return fmt.Errorf("RSA key size is %d bits, not %d", rsaPub.N.BitLen(), bits)
	}
	return nil
}

func (g RSAKeyPairGenerator) GenerateKeyPair() (crypto.PublicKey, crypto.PrivateKey, error) {
	bits := g.Bits
	if bits == 0 {
		bits = keyBits
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	return &privateKey.PublicKey, privateKey, nil
}

var _ KeyPairGenerator = RSAKeyPairGenerator{}
