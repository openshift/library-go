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
// crypto.KeyPairGenerator. RSA key sizes below crypto.MinRSAKeySize are
// rejected; which sizes above that floor are allowed is enforced by the PKI
// API's validation, not here.
func KeyPairGeneratorFromAPI(apiKey configv1alpha1.PKIKeyConfig) (crypto.KeyPairGenerator, error) {
	switch apiKey.Algorithm {
	case configv1alpha1.PKIKeyAlgorithmRSA:
		return crypto.NewRSAKeyPairGenerator(int(apiKey.RSA.KeySize))
	case configv1alpha1.PKIKeyAlgorithmECDSA:
		curve, err := ecdsaCurveFromAPI(apiKey.ECDSA.Curve)
		if err != nil {
			return nil, err
		}
		return crypto.NewECDSAKeyPairGenerator(curve)
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
