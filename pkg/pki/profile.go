package pki

import (
	"fmt"
	"math"

	configv1alpha1 "github.com/openshift/api/config/v1alpha1"
	"github.com/openshift/library-go/pkg/crypto"
)

// DefaultPKIProfile returns the PKIProfile that represents OpenShift's default
// certificate configuration: RSA-4096 for signers, RSA-2048 for everything else.
func DefaultPKIProfile() configv1alpha1.PKIProfile {
	return configv1alpha1.PKIProfile{
		Defaults: configv1alpha1.DefaultCertificateConfig{
			Key: configv1alpha1.KeyConfig{
				Algorithm: configv1alpha1.KeyAlgorithmRSA,
				RSA:       configv1alpha1.RSAKeyConfig{KeySize: 2048},
			},
		},
		SignerCertificates: configv1alpha1.CertificateConfig{
			Key: configv1alpha1.KeyConfig{
				Algorithm: configv1alpha1.KeyAlgorithmRSA,
				RSA:       configv1alpha1.RSAKeyConfig{KeySize: 4096},
			},
		},
	}
}

// KeyConfigFromAPI converts a configv1alpha1.KeyConfig to the crypto package's KeyConfig.
func KeyConfigFromAPI(apiKey configv1alpha1.KeyConfig) (crypto.KeyConfig, error) {
	switch apiKey.Algorithm {
	case configv1alpha1.KeyAlgorithmRSA:
		return crypto.KeyConfig{
			Algorithm: crypto.RSAKeyAlgorithm,
			RSABits:   int(apiKey.RSA.KeySize),
		}, nil
	case configv1alpha1.KeyAlgorithmECDSA:
		curve, err := ecdsaCurveFromAPI(apiKey.ECDSA.Curve)
		if err != nil {
			return crypto.KeyConfig{}, err
		}
		return crypto.KeyConfig{
			Algorithm:  crypto.ECDSAKeyAlgorithm,
			ECDSACurve: curve,
		}, nil
	default:
		return crypto.KeyConfig{}, fmt.Errorf("unknown key algorithm: %q", apiKey.Algorithm)
	}
}

func ecdsaCurveFromAPI(c configv1alpha1.ECDSACurve) (crypto.ECDSACurve, error) {
	switch c {
	case configv1alpha1.ECDSACurveP256:
		return crypto.P256, nil
	case configv1alpha1.ECDSACurveP384:
		return crypto.P384, nil
	case configv1alpha1.ECDSACurveP521:
		return crypto.P521, nil
	default:
		return "", fmt.Errorf("unknown ECDSA curve: %q", c)
	}
}

// securityBits returns the NIST security strength in bits for a given KeyConfig.
// For RSA, it uses the GNFS complexity formula from NIST SP 800-56B.
// For ECDSA, security strength is half the key size (fixed per curve).
func securityBits(kc crypto.KeyConfig) int {
	switch kc.Algorithm {
	case crypto.RSAKeyAlgorithm:
		return rsaSecurityBits(kc.RSABits)
	case crypto.ECDSAKeyAlgorithm:
		switch kc.ECDSACurve {
		case crypto.P256:
			return 128
		case crypto.P384:
			return 192
		case crypto.P521:
			return 256
		}
	}
	return 0
}

// rsaSecurityBits computes the NIST security strength for an RSA key using the
// GNFS formula from NIST SP 800-56B Rev 2:
//
//	security_bits = floor((1.923 * cbrt(n*ln2) * cbrt(ln(n*ln2)^2) - 4.69) / ln2)
//
// Reference values: 2048→112, 3072→128, 4096→152, 8192→220.
func rsaSecurityBits(bits int) int {
	n := float64(bits)
	a := n * math.Log(2)
	b := math.Log(a)
	strength := (1.923*math.Cbrt(a)*math.Cbrt(b*b) - 4.69) / math.Log(2)
	return int(math.Floor(strength))
}

// strongerKeyConfig returns whichever of a or b provides higher NIST security strength.
// In case of a tie, returns a.
func strongerKeyConfig(a, b crypto.KeyConfig) crypto.KeyConfig {
	if securityBits(b) > securityBits(a) {
		return b
	}
	return a
}
