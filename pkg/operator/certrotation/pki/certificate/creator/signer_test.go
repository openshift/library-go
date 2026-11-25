package creator

import (
	gocrypto "crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/openshift/library-go/pkg/crypto"
	clocktesting "k8s.io/utils/clock/testing"
)

func TestIntermediateSignerCertificateCreation(t *testing.T) {
	type testcase struct {
		name                   string
		keyPairGeneratorGetter KeyPairGeneratorGetter
		signerGetter           SignerGetter
		expectedErr            error
		publicKeyValidation    func(*testing.T, gocrypto.PublicKey)
	}

	testcases := []testcase{
		{
			name: "intermediate signing certificate creation with RSA 2048 KeyPairGenerator and valid signer, no error",
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
			name: "intermediate signing certificate creation with RSA 4096 KeyPairGenerator and valid signer, no error",
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
			name: "intermediate signing certificate creation with ECDSA P-256 KeyPairGenerator and valid signer, no error",
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
			name: "intermediate signing certificate creation with ECDSA P-384 KeyPairGenerator and valid signer, no error",
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
			name: "intermediate signing certificate creation attempt with failure to fetch signer, error",
			signerGetter: &mockSignerGetter{
				err: errors.New("boom"),
			},
			expectedErr: errors.New("getting signer: boom"),
		},
		{
			name: "intermediate signing certificate creation attempt with failure to fetch KeyPairGenerator, error",
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
			intermediateSigner := NewIntermediateSigner("intermediate", tc.keyPairGeneratorGetter, tc.signerGetter, time.Hour)
			intermediateSigner.clock = fakeClock

			cert, err := intermediateSigner.CreateCertificate(t.Context())
			if err != nil {
				if tc.expectedErr != nil && err.Error() == tc.expectedErr.Error() {
					return
				}

				t.Fatalf("expected error %v but got %v", tc.expectedErr, err)
			}

			leaf := cert.Certs[0]
			tc.publicKeyValidation(t, leaf.PublicKey)

			expectedSubjectName := fmt.Sprintf("intermediate@%d", fakeClock.Now().Unix())
			if leaf.Subject.CommonName != expectedSubjectName {
				t.Fatalf("expected leaf certificate to have common name %q but got %q", expectedSubjectName, leaf.Subject.CommonName)
			}

			if fakeClock.Now().Add(time.Hour).Unix() != leaf.NotAfter.Unix() {
				t.Fatalf("expected leaf certificate to have a not after unix time of %v but got %v", fakeClock.Now().Add(time.Hour).Unix(), leaf.NotAfter.Unix())
			}
		})
	}
}

func TestSelfSignedSignerCertificateCreation(t *testing.T) {
	type testcase struct {
		name                   string
		keyPairGeneratorGetter KeyPairGeneratorGetter
		expectedErr            error
		publicKeyValidation    func(*testing.T, gocrypto.PublicKey)
	}

	testcases := []testcase{
		{
			name: "self-signed signing certificate creation with RSA 2048 KeyPairGenerator, no error",
			keyPairGeneratorGetter: &mockKeyPairGeneratorGetter{
				kpg: crypto.RSAKeyPairGenerator{Bits: 2048},
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
			name: "self-signed signing certificate creation with RSA 4096 KeyPairGenerator, no error",
			keyPairGeneratorGetter: &mockKeyPairGeneratorGetter{
				kpg: crypto.RSAKeyPairGenerator{Bits: 4096},
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
			name: "self-singed signing certificate creation with ECDSA P-256 KeyPairGenerator, no error",
			keyPairGeneratorGetter: &mockKeyPairGeneratorGetter{
				kpg: crypto.ECDSAKeyPairGenerator{Curve: crypto.P256},
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
			name: "self-signed signing certificate creation with ECDSA P-384 KeyPairGenerator, no error",
			keyPairGeneratorGetter: &mockKeyPairGeneratorGetter{
				kpg: crypto.ECDSAKeyPairGenerator{Curve: crypto.P384},
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
			name: "self-signed signing certificate creation attempt with failure to fetch KeyPairGenerator, error",
			keyPairGeneratorGetter: &mockKeyPairGeneratorGetter{
				err: errors.New("boom"),
			},
			expectedErr: errors.New("getting key pair generator: boom"),
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			fakeClock := clocktesting.NewFakeClock(time.Now())
			selfSignedSigner := NewSelfSignedSigner("root", tc.keyPairGeneratorGetter, time.Hour)
			selfSignedSigner.clock = fakeClock

			cert, err := selfSignedSigner.CreateCertificate(t.Context())
			if err != nil {
				if tc.expectedErr != nil && err.Error() == tc.expectedErr.Error() {
					return
				}

				t.Fatalf("expected error %v but got %v", tc.expectedErr, err)
			}

			leaf := cert.Certs[0]
			tc.publicKeyValidation(t, leaf.PublicKey)

			expectedSubjectName := fmt.Sprintf("root@%d", fakeClock.Now().Unix())
			if leaf.Subject.CommonName != expectedSubjectName {
				t.Fatalf("expected leaf certificate to have common name %q but got %q", expectedSubjectName, leaf.Subject.CommonName)
			}

			err = leaf.CheckSignatureFrom(leaf)
			if err != nil {
				t.Fatalf("expected leaf certificate to be self-signed but it was not: %v", err)
			}

			if fakeClock.Now().Add(time.Hour).Unix() != leaf.NotAfter.Unix() {
				t.Fatalf("expected leaf certificate to have a not after unix time of %v but got %v", fakeClock.Now().Add(time.Hour).Unix(), leaf.NotAfter.Unix())
			}
		})
	}
}
