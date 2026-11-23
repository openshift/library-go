package creator

import (
	"context"
	gocrypto "crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/openshift/library-go/pkg/crypto"
	"k8s.io/apiserver/pkg/authentication/user"
)

func TestClientCertificateCreation(t *testing.T) {
	type testcase struct {
		name                   string
		keyPairGeneratorGetter KeyPairGeneratorGetter
		signerGetter           SignerGetter
		expectedErr            error
		publicKeyValidation    func(*testing.T, gocrypto.PublicKey)
	}

	testcases := []testcase{
		{
			name: "client certificate creation with RSA 2048 KeyPairGenerator and valid signer, no error",
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
			name: "client certificate creation with RSA 4096 KeyPairGenerator and valid signer, no error",
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
			name: "client certificate creation with ECDSA P-256 KeyPairGenerator and valid signer, no error",
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
			name: "client certificate creation with ECDSA P-384 KeyPairGenerator and valid signer, no error",
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
			name: "client certificate creation attempt with failure to fetch signer, error",
			signerGetter: &mockSignerGetter{
				err: errors.New("boom"),
			},
			expectedErr: errors.New("getting signer: boom"),
		},
		{
			name: "client certificate creation attempt with failure to fetch KeyPairGenerator, error",
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
			userInfo := &user.DefaultInfo{
				Name: "homer",
			}

			client := NewClient(userInfo, tc.keyPairGeneratorGetter, tc.signerGetter, time.Hour)

			cert, err := client.CreateCertificate(t.Context())
			if err != nil {
				if tc.expectedErr != nil && err.Error() == tc.expectedErr.Error() {
					return
				}

				t.Fatalf("expected error %v but got %v", tc.expectedErr, err)
			}

			leaf := cert.Certs[0]
			tc.publicKeyValidation(t, leaf.PublicKey)

			foundClientAuthUsage := false
			for _, eku := range leaf.ExtKeyUsage {
				if eku == x509.ExtKeyUsageClientAuth {
					foundClientAuthUsage = true
					break
				}
			}

			if !foundClientAuthUsage {
				t.Fatal("expected leaf certificate to contain client auth extended key usage but it did not")
			}

			if leaf.Subject.CommonName != userInfo.Name {
				t.Fatalf("expected leaf certificate subject common name to match %q but got %q", userInfo.Name, leaf.Subject.CommonName)
			}
		})
	}
}

func newSigner(t *testing.T) *crypto.CA {
	t.Helper()

	signingCert, err := crypto.NewSigningCertificate("test-signer", crypto.RSAKeyPairGenerator{Bits: 2048})
	if err != nil {
		t.Fatalf("creating signing certificate: %v", err)
	}

	return &crypto.CA{
		Config:          signingCert,
		SerialGenerator: &crypto.RandomSerialGenerator{},
	}
}

type mockKeyPairGeneratorGetter struct {
	kpg crypto.KeyPairGenerator
	err error
}

func (m *mockKeyPairGeneratorGetter) GetKeyPairGenerator(_ context.Context) (crypto.KeyPairGenerator, error) {
	return m.kpg, m.err
}

type mockSignerGetter struct {
	signer *crypto.CA
	err    error
}

func (m *mockSignerGetter) GetSigner(_ context.Context) (*crypto.CA, error) {
	return m.signer, m.err
}
