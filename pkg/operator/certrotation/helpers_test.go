package certrotation

import (
	configv1alpha1 "github.com/openshift/api/config/v1alpha1"
	"github.com/openshift/library-go/pkg/crypto"
)

// mustRSA returns an RSA generator for tests, panicking on an invalid size.
func mustRSA(bits int) crypto.KeyPairGenerator {
	g, err := crypto.NewRSAKeyPairGenerator(bits)
	if err != nil {
		panic(err)
	}
	return g
}

// mustECDSA returns an ECDSA generator for tests, panicking on an invalid
// curve.
func mustECDSA(curve crypto.ECDSACurve) crypto.KeyPairGenerator {
	g, err := crypto.NewECDSAKeyPairGenerator(curve)
	if err != nil {
		panic(err)
	}
	return g
}

// testCertificatePolicy returns a valid certificate policy for tests: ECDSA
// P-256 for all certificates, with CA certificates overridden to ECDSA P-384.
// It mirrors the shipped default without depending on it, since the default
// is an installer concern.
func testCertificatePolicy() configv1alpha1.PKICertificatePolicy {
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
