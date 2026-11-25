package crypto

import (
	gocrypto "crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
)

// MinRSAKeySize is the smallest RSA key size, in bits, that KeySpec accepts.
const MinRSAKeySize = 2048

// KeySpec describes the parameters of a key pair. It is plain data: it is
// comparable with ==, printable, and safe to construct as a literal without
// validation. Validation happens when the spec is turned into a KeyPairGenerator.
//
// Exactly one algorithm is set via Algorithm, and only the field for that
// algorithm may be non-zero:
//
//	KeySpec{Algorithm: RSAKeyAlgorithm, RSABits: 3072}
//	KeySpec{Algorithm: ECDSAKeyAlgorithm, ECDSACurve: P384}
//
// The zero value is the absence of a key specification; Validate rejects it.
type KeySpec struct {
	// Algorithm identifies the key algorithm. Required.
	Algorithm KeyAlgorithm
	// RSABits is the RSA key size in bits. Set only when Algorithm is
	// RSAKeyAlgorithm; must be at least MinRSAKeySize.
	RSABits int
	// ECDSACurve is the named ECDSA curve. Set only when Algorithm is
	// ECDSAKeyAlgorithm.
	ECDSACurve ECDSACurve
}

// Validate reports whether s describes a supported key: the algorithm is set
// and known, only the field for that algorithm is set, the RSA size is at or
// above MinRSAKeySize, and the ECDSA curve is supported.
func (s KeySpec) Validate() error {
	switch s.Algorithm {
	case RSAKeyAlgorithm:
		if s.RSABits < MinRSAKeySize {
			return fmt.Errorf("invalid RSA key size %d: must be at least %d bits", s.RSABits, MinRSAKeySize)
		}
		if s.ECDSACurve != "" {
			return fmt.Errorf("RSA key spec must not set an ECDSA curve")
		}
	case ECDSAKeyAlgorithm:
		if _, err := ellipticCurveFor(s.ECDSACurve); err != nil {
			return fmt.Errorf("invalid ECDSA key spec: %w", err)
		}
		if s.RSABits != 0 {
			return fmt.Errorf("ECDSA key spec must not set RSA bits")
		}
	case "":
		return fmt.Errorf("key algorithm is required")
	default:
		return fmt.Errorf("unknown key algorithm: %q", s.Algorithm)
	}
	return nil
}

// KeyPairGenerator validates s and returns a generator producing keys that
// match it. It is the only way to obtain one of this package's generators.
// The returned generator self-checks: it returns an error rather than a key
// that does not satisfy s.Matches.
func (s KeySpec) KeyPairGenerator() (KeyPairGenerator, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return keyPairGenerator{spec: s}, nil
}

// SecurityLevel returns the cryptographic strength of the keys s describes.
// The zero value of KeySpec has strength 0; a spec with a known algorithm is
// estimated from whatever parameters are set, even if Validate would reject
// them (for example an RSA size below MinRSAKeySize).
func (s KeySpec) SecurityLevel() SecurityLevel {
	switch s.Algorithm {
	case RSAKeyAlgorithm:
		if s.RSABits <= 0 {
			return SecurityLevel{}
		}
		return SecurityLevel{ClassicalBits: rsaSecurityBits(s.RSABits)}
	case ECDSAKeyAlgorithm:
		return SecurityLevel{ClassicalBits: ecdsaCurveBits(s.ECDSACurve)}
	default:
		return SecurityLevel{}
	}
}

// String returns a human-readable description of s, for example "RSA 3072"
// or "ECDSA P-384". Specs that Validate rejects still print.
func (s KeySpec) String() string {
	switch s.Algorithm {
	case RSAKeyAlgorithm:
		return fmt.Sprintf("RSA %d", s.RSABits)
	case ECDSAKeyAlgorithm:
		return fmt.Sprintf("ECDSA %s", s.ECDSACurve)
	case "":
		return "no key"
	default:
		return fmt.Sprintf("%s %d %s", s.Algorithm, s.RSABits, s.ECDSACurve)
	}
}

// Matches returns nil if pub is a key whose parameters equal s. It is the
// inverse of KeySpecFromPublicKey.
func (s KeySpec) Matches(pub gocrypto.PublicKey) error {
	if err := s.Validate(); err != nil {
		return fmt.Errorf("key spec is invalid: %w", err)
	}
	actual, err := KeySpecFromPublicKey(pub)
	if err != nil {
		return err
	}
	if actual != s {
		return fmt.Errorf("public key is %s, not %s", actual, s)
	}
	return nil
}

// KeySpecFromPublicKey returns the KeySpec satisfied by pub. It reports an
// error for nil keys and unsupported key types.
func KeySpecFromPublicKey(pub gocrypto.PublicKey) (KeySpec, error) {
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		if pub == nil {
			return KeySpec{}, fmt.Errorf("RSA public key is nil")
		}
		if pub.N == nil {
			return KeySpec{}, fmt.Errorf("RSA public key has nil modulus")
		}
		return KeySpec{Algorithm: RSAKeyAlgorithm, RSABits: pub.N.BitLen()}, nil
	case *ecdsa.PublicKey:
		if pub == nil {
			return KeySpec{}, fmt.Errorf("ECDSA public key is nil")
		}
		if pub.Curve == nil {
			return KeySpec{}, fmt.Errorf("ECDSA public key has nil curve")
		}
		curve, err := curveFromElliptic(pub.Curve)
		if err != nil {
			return KeySpec{}, err
		}
		return KeySpec{Algorithm: ECDSAKeyAlgorithm, ECDSACurve: curve}, nil
	default:
		return KeySpec{}, fmt.Errorf("unsupported public key type: %T", pub)
	}
}

// StrongerKeySpec returns whichever of a or b provides the higher security
// level. On a tie, ECDSA is preferred over RSA, and otherwise a is returned.
// The zero KeySpec compares as strength 0.
func StrongerKeySpec(a, b KeySpec) KeySpec {
	sa, sb := a.SecurityLevel(), b.SecurityLevel()
	if sb.Compare(sa) > 0 {
		return b
	}
	if sa.Compare(sb) > 0 {
		return a
	}
	// Equal strength: prefer ECDSA over RSA.
	if a.Algorithm == ECDSAKeyAlgorithm {
		return a
	}
	if b.Algorithm == ECDSAKeyAlgorithm {
		return b
	}
	return a
}

func curveFromElliptic(curve elliptic.Curve) (ECDSACurve, error) {
	switch curve {
	case elliptic.P256():
		return P256, nil
	case elliptic.P384():
		return P384, nil
	case elliptic.P521():
		return P521, nil
	default:
		return "", fmt.Errorf("unsupported ECDSA curve: %s", curve.Params().Name)
	}
}
