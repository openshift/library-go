package certrotation

import (
	configv1alpha1 "github.com/openshift/api/config/v1alpha1"
	"github.com/openshift/library-go/pkg/crypto"
)

// mustRSA returns an RSA generator for tests, panicking on an invalid size.
// Tests also use generators as key expectations, checked with Matches.
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

// rsaKey returns an API key configuration for an RSA key of the given size.
func rsaKey(bits int32) configv1alpha1.PKIKeyConfig {
	return configv1alpha1.PKIKeyConfig{
		Algorithm: configv1alpha1.PKIKeyAlgorithmRSA,
		RSA:       configv1alpha1.PKIRSAKeyConfig{KeySize: bits},
	}
}

// ecdsaKey returns an API key configuration for an ECDSA key on the given
// curve.
func ecdsaKey(curve configv1alpha1.PKIECDSACurve) configv1alpha1.PKIKeyConfig {
	return configv1alpha1.PKIKeyConfig{
		Algorithm: configv1alpha1.PKIKeyAlgorithmECDSA,
		ECDSA:     configv1alpha1.PKIECDSAKeyConfig{Curve: curve},
	}
}

// namedCertificate returns a namedCertificates entry overriding the key of
// the named certificate.
func namedCertificate(name string, key configv1alpha1.PKIKeyConfig) configv1alpha1.PKINamedCertificateConfig {
	return configv1alpha1.PKINamedCertificateConfig{
		Name:                 name,
		PKICertificateConfig: configv1alpha1.PKICertificateConfig{Key: key},
	}
}

// testCertificatePolicy returns a valid certificate policy for tests: ECDSA
// P-256 for all certificates, with CA certificates overridden to ECDSA P-384.
// It mirrors the shipped default without depending on it, since the default
// is an installer concern.
func testCertificatePolicy() configv1alpha1.PKICertificatePolicy {
	return configv1alpha1.PKICertificatePolicy{
		Defaults:       configv1alpha1.PKIDefaultCertificateConfig{Key: ecdsaKey(configv1alpha1.PKIECDSACurveP256)},
		CACertificates: configv1alpha1.PKICertificateConfig{Key: ecdsaKey(configv1alpha1.PKIECDSACurveP384)},
	}
}
