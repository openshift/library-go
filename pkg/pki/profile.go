package pki

import (
	"fmt"

	configv1alpha1 "github.com/openshift/api/config/v1alpha1"
	"github.com/openshift/library-go/pkg/crypto"
)

// DefaultCertificatePolicy returns the default certificate policy for
// OpenShift: ECDSA P-256 for all certificates, with CA certificates
// overridden to ECDSA P-384.
//
// The PKI resource pins concrete values at install time, so this default is
// an install-time seed (written into the resource by the installer), not a
// runtime fallback: existing clusters do not track these values as they
// evolve across releases.
func DefaultCertificatePolicy() configv1alpha1.PKICertificatePolicy {
	return configv1alpha1.PKICertificatePolicy{
		Defaults: configv1alpha1.PKIDefaultCertificateConfig{
			Key: configv1alpha1.PKIKeyConfig{
				Algorithm: configv1alpha1.PKIKeyAlgorithmECDSA,
				ECDSA:     configv1alpha1.PKIECDSAKeyConfig{Curve: configv1alpha1.PKIECDSACurveP256},
			},
		},
		CACertificates: configv1alpha1.PKICertificateConfig{
			Key: configv1alpha1.PKIKeyConfig{
				Algorithm: configv1alpha1.PKIKeyAlgorithmECDSA,
				ECDSA:     configv1alpha1.PKIECDSAKeyConfig{Curve: configv1alpha1.PKIECDSACurveP384},
			},
		},
	}
}

// KeyPairGeneratorFromAPI converts a configv1alpha1.PKIKeyConfig to a
// crypto.KeyPairGenerator. Key parameters are validated against the
// constraints the PKI API enforces server-side, so that an invalid cached
// resource fails loudly instead of silently generating a weak or
// unexpectedly-sized key.
func KeyPairGeneratorFromAPI(apiKey configv1alpha1.PKIKeyConfig) (crypto.KeyPairGenerator, error) {
	switch apiKey.Algorithm {
	case configv1alpha1.PKIKeyAlgorithmRSA:
		if apiKey.RSA.KeySize < 2048 || apiKey.RSA.KeySize > 4096 || apiKey.RSA.KeySize%1024 != 0 {
			return nil, fmt.Errorf("invalid RSA key size %d: must be a multiple of 1024 between 2048 and 4096", apiKey.RSA.KeySize)
		}
		return crypto.RSAKeyPairGenerator{
			Bits: int(apiKey.RSA.KeySize),
		}, nil
	case configv1alpha1.PKIKeyAlgorithmECDSA:
		curve, err := ecdsaCurveFromAPI(apiKey.ECDSA.Curve)
		if err != nil {
			return nil, err
		}
		return crypto.ECDSAKeyPairGenerator{
			Curve: curve,
		}, nil
	default:
		return nil, fmt.Errorf("unknown key algorithm: %q", apiKey.Algorithm)
	}
}

// ecdsaCurveFromAPI converts an API ECDSA curve name to the crypto package's ECDSACurve.
func ecdsaCurveFromAPI(c configv1alpha1.PKIECDSACurve) (crypto.ECDSACurve, error) {
	switch c {
	case configv1alpha1.PKIECDSACurveP256:
		return crypto.P256, nil
	case configv1alpha1.PKIECDSACurveP384:
		return crypto.P384, nil
	case configv1alpha1.PKIECDSACurveP521:
		return crypto.P521, nil
	default:
		return "", fmt.Errorf("unknown ECDSA curve: %q", c)
	}
}

// securityBits returns the NIST security strength in bits for a given
// KeyPairGenerator. For RSA, values come from the rsaSecurityStrength table.
// For ECDSA, security strength is half the key size (fixed per curve).
// Unknown generators are an error so that peer resolution fails closed
// instead of silently downgrading when new key algorithms are added.
func securityBits(g crypto.KeyPairGenerator) (int, error) {
	switch g := g.(type) {
	case crypto.RSAKeyPairGenerator:
		bits, ok := rsaSecurityStrength[g.Bits]
		if !ok {
			return 0, fmt.Errorf("unknown RSA key size %d", g.Bits)
		}
		return bits, nil
	case crypto.ECDSAKeyPairGenerator:
		switch g.Curve {
		case crypto.P256:
			return 128, nil
		case crypto.P384:
			return 192, nil
		case crypto.P521:
			return 256, nil
		}
		return 0, fmt.Errorf("unknown ECDSA curve %q", g.Curve)
	}
	return 0, fmt.Errorf("cannot determine security strength of key generator %T", g)
}

// rsaSecurityStrength maps RSA key sizes (2048-8192 in 1024-bit increments)
// to their security strengths from NIST SP 800-56B Rev 2 Table 2 or
// pre-calculated from the GNFS complexity estimate.
var rsaSecurityStrength = map[int]int{
	2048: 112,
	3072: 128,
	4096: 152,
	5120: 168,
	6144: 176,
	7168: 192,
	8192: 200,
}

// strongerKeyPairGenerator returns whichever of a or b provides higher NIST
// security strength. In case of a tie, ECDSA is preferred over RSA.
func strongerKeyPairGenerator(a, b crypto.KeyPairGenerator) (crypto.KeyPairGenerator, error) {
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
	if _, ok := a.(crypto.ECDSAKeyPairGenerator); ok {
		return a, nil
	}
	if _, ok := b.(crypto.ECDSAKeyPairGenerator); ok {
		return b, nil
	}
	return a, nil
}
