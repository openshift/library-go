package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

// ECDSAKeyPairGenerator generates ECDSA key pairs.
type ECDSAKeyPairGenerator struct {
	// Curve is the named ECDSA curve.
	Curve ECDSACurve
}

func (g ECDSAKeyPairGenerator) Matches(pub crypto.PublicKey) error {
	curve, err := g.ellipticCurve()
	if err != nil {
		return fmt.Errorf("generator has invalid curve %q: %w", g.Curve, err)
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

func (g ECDSAKeyPairGenerator) GenerateKeyPair() (crypto.PublicKey, crypto.PrivateKey, error) {
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

func (g ECDSAKeyPairGenerator) ellipticCurve() (elliptic.Curve, error) {
	switch g.Curve {
	case P256:
		return elliptic.P256(), nil
	case P384:
		return elliptic.P384(), nil
	case P521:
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported ECDSA curve: %q", g.Curve)
	}
}

var _ KeyPairGenerator = ECDSAKeyPairGenerator{}
