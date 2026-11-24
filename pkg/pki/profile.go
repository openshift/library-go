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

// KeySpecFromAPI converts a configv1alpha1.KeyConfig to a crypto.KeySpec.
// The returned spec is validated: RSA key sizes below crypto.MinRSAKeySize
// are rejected. Which sizes above that floor are allowed is enforced by the
// PKI API's validation, not here.
func KeySpecFromAPI(apiKey configv1alpha1.KeyConfig) (crypto.KeySpec, error) {
	var spec crypto.KeySpec
	switch apiKey.Algorithm {
	case configv1alpha1.KeyAlgorithmRSA:
		spec = crypto.KeySpec{Algorithm: crypto.RSAKeyAlgorithm, RSABits: int(apiKey.RSA.KeySize)}
	case configv1alpha1.KeyAlgorithmECDSA:
		curve, err := ecdsaCurveFromAPI(apiKey.ECDSA.Curve)
		if err != nil {
			return crypto.KeySpec{}, err
		}
		spec = crypto.KeySpec{Algorithm: crypto.ECDSAKeyAlgorithm, ECDSACurve: curve}
	case "":
		return crypto.KeySpec{}, fmt.Errorf("key.algorithm is required")
	default:
		return crypto.KeySpec{}, fmt.Errorf("unknown key algorithm: %q", apiKey.Algorithm)
	}
	if err := spec.Validate(); err != nil {
		return crypto.KeySpec{}, err
	}
	return spec, nil
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
