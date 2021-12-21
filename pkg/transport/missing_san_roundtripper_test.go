package transport

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"testing"
)

type mockCounter int

func (c *mockCounter) Inc() {
	*c = *c + 1
}

func TestMissingSANRoundTripper(t *testing.T) {
	for _, tc := range []struct {
		name string

		resp    *http.Response
		respErr error

		expectedCounts int
		expectedErr    string
	}{
		{
			name: "non tls response",
			resp: &http.Response{},
		},
		{
			name: "valid cert",
			resp: &http.Response{
				TLS: &tls.ConnectionState{
					PeerCertificates: []*x509.Certificate{
						newCert(t, &x509.Certificate{
							Subject:      pkix.Name{CommonName: "foo.bar"},
							SerialNumber: big.NewInt(1),
							DNSNames:     []string{"foo.bar"},
						})},
				},
			},
			expectedCounts: 0,
		},
		{
			name: "go 1.16: legacy cert verification error",
			respErr: x509.HostnameError{
				Certificate: newCert(t, &x509.Certificate{
					Subject:      pkix.Name{CommonName: "foo.bar"},
					SerialNumber: big.NewInt(1),
				}),
				Host: "foo.bar",
			},
			expectedErr:    "x509: certificate relies on legacy Common Name field, use SANs or temporarily enable Common Name matching with GODEBUG=x509ignoreCN=0",
			expectedCounts: 1,
		},
		{
			name: "go 1.16: invalid cert",
			resp: &http.Response{
				TLS: &tls.ConnectionState{
					PeerCertificates: []*x509.Certificate{
						newCert(t, &x509.Certificate{
							Subject:      pkix.Name{CommonName: "foo.bar"},
							SerialNumber: big.NewInt(1),
						})},
				},
			},
			expectedCounts: 1,
		},
		{
			name: "invalid hostname",
			respErr: x509.HostnameError{
				Certificate: newCert(t, &x509.Certificate{
					Subject:      pkix.Name{CommonName: "foo.bar"},
					SerialNumber: big.NewInt(1),
				}),
				Host: "some.host",
			},
			expectedErr:    "x509: certificate is not valid for any names, but wanted to match some.host",
			expectedCounts: 0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := roundTripperFunc(func(_ *http.Request) (*http.Response, error) {
				return tc.resp, tc.respErr
			})

			var (
				cnt    mockCounter
				gotErr string
			)
			_, err := NewMissingSANRoundTripper(rt, &cnt).RoundTrip(nil)
			if err != nil {
				gotErr = err.Error()
			}

			if tc.expectedErr != gotErr {
				t.Errorf("expected error %q, got %q", tc.expectedErr, gotErr)
			}

			if tc.expectedCounts != int(cnt) {
				t.Errorf("expected %v counts, got %v", tc.expectedCounts, int(cnt))
			}
		})
	}
}

func newCert(t *testing.T, template *x509.Certificate) *x509.Certificate {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &pk.PublicKey, pk)
	if err != nil {
		t.Fatal(err)
	}

	certs, err := x509.ParseCertificates(certBytes)
	if err != nil {
		t.Fatal(err)
	}

	return certs[0]
}
