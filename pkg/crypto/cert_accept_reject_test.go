package crypto

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/util/sets"
)

// rootAlfa signs signerBravo
// signerBravo signs signerDelta
// signerDelta signs servingCert
func TestServingCert(t *testing.T) {
	rootAlphaConfig, err := MakeSelfSignedCAConfigForDuration("RootAlfa", 1*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	rootAlpha := &CA{
		Config:          rootAlphaConfig,
		SerialGenerator: &RandomSerialGenerator{},
	}
	rootAlfaPEMBytes, _, err := rootAlphaConfig.GetPEMBytes()
	if err != nil {
		t.Fatal(err)
	}
	signerBravoConfig, err := MakeCAConfigForDuration("SignerBravo", 1*time.Hour, rootAlpha)
	if err != nil {
		t.Fatal(err)
	}
	signerBravo := &CA{
		Config:          signerBravoConfig,
		SerialGenerator: &RandomSerialGenerator{},
	}
	signerBravoPEMCertByte, _, err := signerBravoConfig.GetPEMBytes()
	if err != nil {
		t.Fatal(err)
	}
	signerDeltaConfig, err := MakeCAConfigForDuration("SignerDelta", 1*time.Hour, signerBravo)
	if err != nil {
		t.Fatal(err)
	}
	signerDelta := &CA{
		Config:          signerDeltaConfig,
		SerialGenerator: &RandomSerialGenerator{},
	}
	signerDeltaPEMCertByte, _, err := signerDeltaConfig.GetPEMBytes()
	if err != nil {
		t.Fatal(err)
	}

	servingCertConfig, err := signerDelta.MakeServerCertForDuration(sets.NewString("::", "127.0.0.1", "localhost"), 1*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	servingPEMCertByte, servingPEMKeyBytes, err := servingCertConfig.GetPEMBytes()
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(servingPEMCertByte))
	servingTLSCertificate, err := tls.X509KeyPair(servingPEMCertByte, servingPEMKeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{servingTLSCertificate},
	}
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
		TLSConfig: cfg,
	}
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		err := server.ServeTLS(listener, "", "")
		if err != nil && !strings.Contains(err.Error(), "Server closed") {
			panic(err)
		}
	}()
	defer server.Close()

	url := "https://" + listener.Addr().String()

	// rootAlfa signs signerBravo
	// signerBravo signs signerDelta
	// signerDelta signs servingCert
	testCases := []struct {
		name          string
		caBundle      [][]byte
		expectedError string
	}{
		{
			name:          "no-default-trust",
			expectedError: "x509: certificate signed by unknown authority",
		},
		{
			// trusting the serving cert only means that if the serving cert was revoked by the delta, bravo, or alfa,
			// the client would not detect that failure and would improperly trust the server.
			name: "trust-serving-only",
			caBundle: [][]byte{
				servingPEMCertByte,
			},
		},
		{
			// trusting the delta intermediate cert only means that if the serving cert was revoked by the bravo or alfa,
			// the client would not detect that failure and would improperly trust the server.
			name: "trust-delta-immediate-signer",
			caBundle: [][]byte{
				signerDeltaPEMCertByte,
			},
		},
		{
			// trusting the bravo intermediate cert only means that if the serving cert was revoked by alfa,
			// the client would not detect that failure and would improperly trust the server.
			name: "trust-bravo-second-intermediate-signer",
			caBundle: [][]byte{
				signerBravoPEMCertByte,
			},
		},
		{
			name: "trust-alfa-root-signer",
			caBundle: [][]byte{
				rootAlfaPEMBytes,
			},
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			tlsConf := &tls.Config{RootCAs: nil} // by default, host trusted

			if len(test.caBundle) != 0 {
				trustedCertPool := x509.NewCertPool()
				for i := range test.caBundle {
					if ok := trustedCertPool.AppendCertsFromPEM(test.caBundle[i]); !ok {
						t.Fatal(createErrorParsingCAData(test.caBundle[i]))
					}
				}
				tlsConf.RootCAs = trustedCertPool
			}
			transport := &http.Transport{TLSClientConfig: tlsConf}
			client := &http.Client{Transport: transport}
			resp, err := client.Get(url)
			switch {
			case len(test.expectedError) == 0 && err == nil:
			case len(test.expectedError) == 0 && err != nil:
				t.Fatal(err)
			case len(test.expectedError) != 0 && err == nil:
				t.Fatal("should have failed!")
			case len(test.expectedError) != 0 && err != nil && !strings.Contains(err.Error(), test.expectedError):
				t.Fatal(err)
			default:
				//ok
			}
			if err != nil {
				return
			}
			if resp.Body != nil {
				defer resp.Body.Close()
			}
			if resp.StatusCode != http.StatusOK {
				t.Fatal("bad response")
			}
		})
	}
}

// createErrorParsingCAData ALWAYS returns an error.  We call it because know we failed to AppendCertsFromPEM
// but we don't know the specific error because that API is just true/false
func createErrorParsingCAData(pemCerts []byte) error {
	for len(pemCerts) > 0 {
		var block *pem.Block
		block, pemCerts = pem.Decode(pemCerts)
		if block == nil {
			return fmt.Errorf("unable to parse bytes as PEM block")
		}

		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}

		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return fmt.Errorf("failed to parse certificate: %w", err)
		}
	}
	return fmt.Errorf("no valid certificate authority data seen")
}
