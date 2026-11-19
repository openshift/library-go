package certrotation

import (
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"testing"

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

// ecdsaCurveNames maps API curve names to the names crypto/elliptic reports.
var ecdsaCurveNames = map[configv1alpha1.PKIECDSACurve]string{
	configv1alpha1.PKIECDSACurveP256: "P-256",
	configv1alpha1.PKIECDSACurveP384: "P-384",
	configv1alpha1.PKIECDSACurveP521: "P-521",
}

// assertPublicKeyMatches fails t unless pub is a key of the algorithm, and
// the size or curve, that want configures. Expectations are written as API
// key configurations so tests are not tied to one algorithm; supporting a new
// PKI key algorithm means adding a case here.
func assertPublicKeyMatches(t *testing.T, pub stdcrypto.PublicKey, want configv1alpha1.PKIKeyConfig) {
	t.Helper()
	switch want.Algorithm {
	case configv1alpha1.PKIKeyAlgorithmRSA:
		k, ok := pub.(*rsa.PublicKey)
		if !ok {
			t.Fatalf("public key type = %T, want *rsa.PublicKey", pub)
		}
		if got := k.N.BitLen(); got != int(want.RSA.KeySize) {
			t.Errorf("RSA key size = %d bits, want %d", got, want.RSA.KeySize)
		}
	case configv1alpha1.PKIKeyAlgorithmECDSA:
		k, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			t.Fatalf("public key type = %T, want *ecdsa.PublicKey", pub)
		}
		wantName, known := ecdsaCurveNames[want.ECDSA.Curve]
		if !known {
			t.Fatalf("test expectation uses unknown ECDSA curve %q", want.ECDSA.Curve)
		}
		if got := k.Curve.Params().Name; got != wantName {
			t.Errorf("ECDSA curve = %s, want %s", got, wantName)
		}
	default:
		t.Fatalf("test expectation uses unsupported key algorithm %q", want.Algorithm)
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
