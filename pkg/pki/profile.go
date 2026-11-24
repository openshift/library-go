package pki

import (
	"fmt"

	configv1alpha1 "github.com/openshift/api/config/v1alpha1"
	"github.com/openshift/library-go/pkg/crypto"
)

// DefaultPKIProfile returns the default PKIProfile for OpenShift.
func DefaultPKIProfile() configv1alpha1.PKIProfile {
	return configv1alpha1.PKIProfile{
		Defaults: configv1alpha1.DefaultCertificateConfig{
			Key: configv1alpha1.KeyConfig{
				Algorithm: configv1alpha1.KeyAlgorithmECDSA,
				ECDSA:     configv1alpha1.ECDSAKeyConfig{Curve: configv1alpha1.ECDSACurveP256},
			},
		},
		SignerCertificates: configv1alpha1.CertificateConfig{
			Key: configv1alpha1.KeyConfig{
				Algorithm: configv1alpha1.KeyAlgorithmECDSA,
				ECDSA:     configv1alpha1.ECDSAKeyConfig{Curve: configv1alpha1.ECDSACurveP384},
			},
		},
	}
}

// KeyPairGeneratorFromAPI converts a configv1alpha1.KeyConfig to a
// crypto.KeyPairGenerator.
func KeyPairGeneratorFromAPI(apiKey configv1alpha1.KeyConfig) (crypto.KeyPairGenerator, error) {
	switch apiKey.Algorithm {
	case configv1alpha1.KeyAlgorithmRSA:
		return crypto.RSAKeyPairGenerator{
			Bits: int(apiKey.RSA.KeySize),
		}, nil
	case configv1alpha1.KeyAlgorithmECDSA:
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

// strongerKeyPairGenerator returns whichever of a or b provides higher
// security strength. In case of a tie, ECDSA is preferred over RSA.
func strongerKeyPairGenerator(a, b crypto.KeyPairGenerator) crypto.KeyPairGenerator {
	sa, sb := a.SecurityLevel(), b.SecurityLevel()
	if sb.Compare(sa) > 0 {
		return b
	}
	if sa.Compare(sb) > 0 {
		return a
	}
	// Equal strength: prefer ECDSA over RSA.
	if _, ok := a.(crypto.ECDSAKeyPairGenerator); ok {
		return a
	}
	if _, ok := b.(crypto.ECDSAKeyPairGenerator); ok {
		return b
	}
	return a
}
