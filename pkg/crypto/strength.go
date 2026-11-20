package crypto

import (
	"fmt"
	"math"
)

// StrongerKeyPairGenerator returns whichever of a or b provides the higher
// NIST security strength. On a tie, ECDSA is preferred over RSA, and
// otherwise a is returned. Generators not created by this package are an
// error, so that callers fail closed instead of silently picking the weaker
// key when new key algorithms are added.
func StrongerKeyPairGenerator(a, b KeyPairGenerator) (KeyPairGenerator, error) {
	sa, err := securityBits(a)
	if err != nil {
		return nil, err
	}
	sb, err := securityBits(b)
	if err != nil {
		return nil, err
	}
	if sb > sa {
		return b, nil
	}
	if sa > sb {
		return a, nil
	}
	// Equal strength: prefer ECDSA over RSA.
	if _, ok := a.(ecdsaKeyPairGenerator); ok {
		return a, nil
	}
	if _, ok := b.(ecdsaKeyPairGenerator); ok {
		return b, nil
	}
	return a, nil
}

// securityBits returns the NIST security strength in bits of the keys g
// generates. For ECDSA, security strength is half the key size (fixed per
// curve).
func securityBits(g KeyPairGenerator) (int, error) {
	switch g := g.(type) {
	case rsaKeyPairGenerator:
		return rsaSecurityBits(g.bits)
	case ecdsaKeyPairGenerator:
		switch g.curve {
		case P256:
			return 128, nil
		case P384:
			return 192, nil
		case P521:
			return 256, nil
		}
		return 0, fmt.Errorf("unknown ECDSA curve %q", g.curve)
	}
	return 0, fmt.Errorf("cannot determine security strength of key generator %T", g)
}

// rsaSecurityBits returns the estimated maximum security strength of an RSA
// modulus of the given bit length, ES(nBits) from NIST SP 800-56B Rev. 2
// Appendix D: the GNFS-based estimate E rounded to the nearest multiple of
// eight. Sizes below MinRSAKeySize are an error.
func rsaSecurityBits(bits int) (int, error) {
	if err := validateRSAKeySize(bits); err != nil {
		return 0, err
	}
	return int(math.Round(rsaStrengthEstimate(bits)/8) * 8), nil
}

// rsaStrengthEstimate returns E, the unrounded security strength estimate
// for an RSA modulus of nBits bits from NIST SP 800-56B Rev. 2 Appendix D:
//
//	E = (1.923 * cbrt(nBits*ln2) * cbrt(ln(nBits*ln2)^2) - 4.69) / ln2
func rsaStrengthEstimate(nBits int) float64 {
	x := float64(nBits) * math.Ln2
	return (1.923*math.Cbrt(x)*math.Cbrt(math.Pow(math.Log(x), 2)) - 4.69) / math.Ln2
}
