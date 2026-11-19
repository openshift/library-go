package certrotation

import (
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
