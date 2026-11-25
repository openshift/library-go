package creator

import (
	gocrypto "crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/openshift/library-go/pkg/crypto"
	"k8s.io/apimachinery/pkg/util/sets"
	clocktesting "k8s.io/utils/clock/testing"
)

func TestServingCertificateCreation(t *testing.T) {
	type testcase struct {
		name                   string
		keyPairGeneratorGetter KeyPairGeneratorGetter
		signerGetter           SignerGetter
		expectedErr            error
		publicKeyValidation    func(*testing.T, gocrypto.PublicKey)
	}

	testcases := []testcase{
		{
			name: "serving certificate creation with RSA 2048 KeyPairGenerator and valid signer, no error",
			keyPairGeneratorGetter: &mockKeyPairGeneratorGetter{
				kpg: crypto.RSAKeyPairGenerator{Bits: 2048},
			},
			signerGetter: &mockSignerGetter{
				signer: newSigner(t),
			},
			publicKeyValidation: func(t *testing.T, pk gocrypto.PublicKey) {
				rsaPK, ok := pk.(*rsa.PublicKey)
				if !ok {
					t.Fatalf("expected an *rsa.PublicKey but got %T", pk)
				}

				if rsaPK.N.BitLen() != 2048 {
					t.Fatalf("expected an *rsa.PublicKey with a bit length of 2048 but got a bit length of %d", rsaPK.N.BitLen())
				}
			},
		},
		{
			name: "serving certificate creation with RSA 4096 KeyPairGenerator and valid signer, no error",
			keyPairGeneratorGetter: &mockKeyPairGeneratorGetter{
				kpg: crypto.RSAKeyPairGenerator{Bits: 4096},
			},
			signerGetter: &mockSignerGetter{
				signer: newSigner(t),
			},
			publicKeyValidation: func(t *testing.T, pk gocrypto.PublicKey) {
				rsaPK, ok := pk.(*rsa.PublicKey)
				if !ok {
					t.Fatalf("expected an *rsa.PublicKey but got %T", pk)
				}

				if rsaPK.N.BitLen() != 4096 {
					t.Fatalf("expected an *rsa.PublicKey with a bit length of 2048 but got a bit length of %d", rsaPK.N.BitLen())
				}
			},
		},
		{
			name: "serving certificate creation with ECDSA P-256 KeyPairGenerator and valid signer, no error",
			keyPairGeneratorGetter: &mockKeyPairGeneratorGetter{
				kpg: crypto.ECDSAKeyPairGenerator{Curve: crypto.P256},
			},
			signerGetter: &mockSignerGetter{
				signer: newSigner(t),
			},
			publicKeyValidation: func(t *testing.T, pk gocrypto.PublicKey) {
				ecdsaPK, ok := pk.(*ecdsa.PublicKey)
				if !ok {
					t.Fatalf("expected an *ecdsa.PublicKey but got %T", pk)
				}

				if ecdsaPK.Curve.Params().Name != elliptic.P256().Params().Name {
					t.Fatalf("expected an *ecdsa.PublicKey with a curve of %s but got a curve of %s", elliptic.P256().Params().Name, ecdsaPK.Curve.Params().Name)
				}
			},
		},
		{
			name: "serving certificate creation with ECDSA P-384 KeyPairGenerator and valid signer, no error",
			keyPairGeneratorGetter: &mockKeyPairGeneratorGetter{
				kpg: crypto.ECDSAKeyPairGenerator{Curve: crypto.P384},
			},
			signerGetter: &mockSignerGetter{
				signer: newSigner(t),
			},
			publicKeyValidation: func(t *testing.T, pk gocrypto.PublicKey) {
				ecdsaPK, ok := pk.(*ecdsa.PublicKey)
				if !ok {
					t.Fatalf("expected an *ecdsa.PublicKey but got %T", pk)
				}

				if ecdsaPK.Curve.Params().Name != elliptic.P384().Params().Name {
					t.Fatalf("expected an *ecdsa.PublicKey with a curve of %s but got a curve of %s", elliptic.P384().Params().Name, ecdsaPK.Curve.Params().Name)
				}
			},
		},
		{
			name: "serving certificate creation attempt with failure to fetch signer, error",
			signerGetter: &mockSignerGetter{
				err: errors.New("boom"),
			},
			expectedErr: errors.New("getting signer: boom"),
		},
		{
			name: "serving certificate creation attempt with failure to fetch KeyPairGenerator, error",
			signerGetter: &mockSignerGetter{
				signer: newSigner(t),
			},
			keyPairGeneratorGetter: &mockKeyPairGeneratorGetter{
				err: errors.New("boom"),
			},
			expectedErr: errors.New("getting key pair generator: boom"),
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			fakeClock := clocktesting.NewFakeClock(time.Now())
			serving := NewServing(
				func() sets.Set[string] {
					return sets.New("example.com")
				},
				tc.keyPairGeneratorGetter,
				tc.signerGetter,
				time.Hour,
			)
			serving.clock = fakeClock

			cert, err := serving.CreateCertificate(t.Context())
			if err != nil {
				if tc.expectedErr != nil && err.Error() == tc.expectedErr.Error() {
					return
				}

				t.Fatalf("expected error %v but got %v", tc.expectedErr, err)
			}

			leaf := cert.Certs[0]
			tc.publicKeyValidation(t, leaf.PublicKey)

			foundServerAuthUsage := false
			for _, eku := range leaf.ExtKeyUsage {
				if eku == x509.ExtKeyUsageServerAuth {
					foundServerAuthUsage = true
					break
				}
			}

			if !foundServerAuthUsage {
				t.Fatal("expected leaf certificate to contain server auth extended key usage but it did not")
			}

			if leaf.Subject.CommonName != "example.com" {
				t.Fatalf("expected leaf certificate to have common name %q but got %q", "example.com", leaf.Subject.CommonName)
			}

			expectedDNSNameSet := sets.New("example.com")
			actualDNSNameSet := sets.New(leaf.DNSNames...)

			if !expectedDNSNameSet.Equal(actualDNSNameSet) {
				t.Fatalf("expected leaf certificate to have DNSNames %v but got %v", expectedDNSNameSet, actualDNSNameSet)
			}

			if fakeClock.Now().Add(time.Hour).Unix() != leaf.NotAfter.Unix() {
				t.Fatalf("expected leaf certificate to have a not after unix time of %v but got %v", fakeClock.Now().Add(time.Hour).Unix(), leaf.NotAfter.Unix())
			}
		})
	}
}
