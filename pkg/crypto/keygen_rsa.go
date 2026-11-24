package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"math"
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

// SecurityLevel returns the estimated maximum security strength of the RSA
// modulus the generator produces, ES(nBits) from NIST SP 800-56B Rev. 2
// Appendix D: the GNFS-based estimate E rounded to the nearest multiple of
// eight.
func (g RSAKeyPairGenerator) SecurityLevel() SecurityLevel {
	bits := g.Bits
	if bits == 0 {
		bits = keyBits
	}
	return SecurityLevel{ClassicalBits: rsaSecurityBits(bits)}
}

// rsaSecurityBits returns the estimated maximum security strength of an RSA
// modulus of the given bit length, ES(nBits) from NIST SP 800-56B Rev. 2
// Appendix D: the GNFS-based estimate E rounded to the nearest multiple of
// eight.
func rsaSecurityBits(bits int) int {
	return int(math.Round(rsaStrengthEstimate(bits)/8) * 8)
}

// rsaStrengthEstimate returns E, the unrounded security strength estimate
// for an RSA modulus of nBits bits from NIST SP 800-56B Rev. 2 Appendix D:
//
//	E = (1.923 * cbrt(nBits*ln2) * cbrt(ln(nBits*ln2)^2) - 4.69) / ln2
func rsaStrengthEstimate(nBits int) float64 {
	x := float64(nBits) * math.Ln2
	return (1.923*math.Cbrt(x)*math.Cbrt(math.Pow(math.Log(x), 2)) - 4.69) / math.Ln2
}
