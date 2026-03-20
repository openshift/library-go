package crypto

import (
	"crypto/elliptic"
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

// KeyConfig describes how to generate a key pair.
type KeyConfig struct {
	// Algorithm specifies the key generation algorithm (RSA or ECDSA).
	Algorithm KeyAlgorithm
	// RSABits is the key size in bits when Algorithm is RSA. Must be >= 2048.
	RSABits int
	// ECDSACurve is the named curve when Algorithm is ECDSA.
	ECDSACurve ECDSACurve
}

// SignatureAlgorithm returns the x509.SignatureAlgorithm appropriate for
// keys generated with this config.
func (kc KeyConfig) SignatureAlgorithm() (x509.SignatureAlgorithm, error) {
	switch kc.Algorithm {
	case RSAKeyAlgorithm:
		return x509.SHA256WithRSA, nil
	case ECDSAKeyAlgorithm:
		switch kc.ECDSACurve {
		case P256:
			return x509.ECDSAWithSHA256, nil
		case P384:
			return x509.ECDSAWithSHA384, nil
		case P521:
			return x509.ECDSAWithSHA512, nil
		default:
			return 0, fmt.Errorf("unsupported ECDSA curve: %q", kc.ECDSACurve)
		}
	default:
		return 0, fmt.Errorf("unsupported key algorithm: %q", kc.Algorithm)
	}
}

// KeyUsage returns the x509.KeyUsage flags appropriate for keys generated
// with this config. ECDSA keys use DigitalSignature only; RSA keys also
// include KeyEncipherment.
func (kc KeyConfig) KeyUsage() x509.KeyUsage {
	switch kc.Algorithm {
	case ECDSAKeyAlgorithm:
		return x509.KeyUsageDigitalSignature
	default:
		return x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
	}
}

// ellipticCurve returns the elliptic.Curve for this config.
// Only valid when Algorithm is ECDSA.
func (kc KeyConfig) ellipticCurve() (elliptic.Curve, error) {
	switch kc.ECDSACurve {
	case P256:
		return elliptic.P256(), nil
	case P384:
		return elliptic.P384(), nil
	case P521:
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported ECDSA curve: %q", kc.ECDSACurve)
	}
}
