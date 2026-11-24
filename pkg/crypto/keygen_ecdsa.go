package crypto

import (
	"crypto/elliptic"
	"fmt"
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

// ellipticCurveFor returns the standard-library curve for a named ECDSA curve.
func ellipticCurveFor(curve ECDSACurve) (elliptic.Curve, error) {
	switch curve {
	case P256:
		return elliptic.P256(), nil
	case P384:
		return elliptic.P384(), nil
	case P521:
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported ECDSA curve: %q", curve)
	}
}

// ecdsaCurveBits returns half the curve's key size: the security strength of
// ECDSA on that curve. An unknown curve has strength 0.
func ecdsaCurveBits(curve ECDSACurve) int {
	switch curve {
	case P256:
		return 128
	case P384:
		return 192
	case P521:
		return 256
	default:
		return 0
	}
}
