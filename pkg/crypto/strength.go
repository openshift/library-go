package crypto

import "fmt"

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

// rsaSecurityStrength lists RSA key sizes in ascending order with their
// security strengths from NIST SP 800-56B Rev 2 Table 2 or pre-calculated
// from the GNFS complexity estimate.
var rsaSecurityStrength = []struct {
	bits, strength int
}{
	{bits: 2048, strength: 112},
	{bits: 3072, strength: 128},
	{bits: 4096, strength: 152},
	{bits: 5120, strength: 168},
	{bits: 6144, strength: 176},
	{bits: 7168, strength: 192},
	{bits: 8192, strength: 200},
}

// rsaSecurityBits returns the security strength of the largest tabulated RSA
// key size not exceeding bits. Rounding down keeps the estimate conservative
// for sizes between table entries and caps it at the largest entry.
func rsaSecurityBits(bits int) (int, error) {
	if err := validateRSAKeySize(bits); err != nil {
		return 0, err
	}
	strength := 0
	for _, e := range rsaSecurityStrength {
		if e.bits > bits {
			break
		}
		strength = e.strength
	}
	return strength, nil
}
