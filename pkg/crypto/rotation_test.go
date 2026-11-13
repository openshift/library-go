package crypto

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"testing"
	"time"

	"k8s.io/client-go/util/cert"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/clock"
	clocktesting "k8s.io/utils/clock/testing"
)

func TestValidateCertificates(t *testing.T) {
	c, err := newTestCACertificate(pkix.Name{CommonName: "test"}, int64(1), metav1.Duration{Duration: time.Hour * 24 * 60}, time.Now)
	if err != nil {
		t.Fatal(err)
	}

	if len(c.Config.Certs) != 1 {
		t.Fatalf("expected 1 certificate in the chain, but got %d", len(c.Config.Certs))
	}

	validCerts := FilterExpiredCerts(c.Config.Certs...)
	if len(validCerts) != 1 {
		t.Fatalf("expected 1 valid certificate in the chain, but got %d", len(validCerts))
	}
}

func TestValidateCertificatesExpired(t *testing.T) {
	certBytes, err := os.ReadFile("./testfiles/tls-expired.crt")
	if err != nil {
		t.Fatal(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	certs, err := cert.ParseCertsPEM(certBytes)
	if err != nil {
		t.Fatal(err)
	}

	newCert, err := newTestCACertificate(pkix.Name{CommonName: "etcdproxy-tests"}, int64(1), metav1.Duration{Duration: time.Hour * 24 * 60}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	certs = append(certs, newCert.Config.Certs...)

	if len(certs) != 2 {
		t.Fatalf("expected 2 certificate in the chain, but got %d", len(certs))
	}

	validCerts := FilterExpiredCerts(certs...)
	if len(validCerts) != 1 {
		t.Fatalf("expected 1 valid certificate in the chain, but got %d", len(validCerts))
	}
}

func TestFilterExpiredCertsWithClock(t *testing.T) {
	fixedTime := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	fakeClock := clocktesting.NewFakeClock(fixedTime)

	// Expired relative to the fake clock: window ends before fixedTime+1h.
	expired, err := newTestCACertificate(pkix.Name{CommonName: "expired"}, int64(1), metav1.Duration{Duration: time.Hour}, fakeClock.Now)
	if err != nil {
		t.Fatal(err)
	}
	// Advance so the first cert's window (fixedTime-1s .. fixedTime+1h) is past.
	fakeClock.Step(2 * time.Hour)

	valid, err := newTestCACertificate(pkix.Name{CommonName: "valid"}, int64(2), metav1.Duration{Duration: 24 * time.Hour}, fakeClock.Now)
	if err != nil {
		t.Fatal(err)
	}

	testCases := []struct {
		name string
		clk  clock.PassiveClock
		want int
	}{
		{
			name: "fake clock at advance time keeps only the valid cert",
			clk:  fakeClock,
			want: 1,
		},
		{
			name: "fake clock past both windows keeps neither",
			clk:  clocktesting.NewFakePassiveClock(fixedTime.Add(72 * time.Hour)),
			want: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := FilterExpiredCertsWithClock(tc.clk, expired.Config.Certs[0], valid.Config.Certs[0])
			if len(got) != tc.want {
				t.Fatalf("expected %d valid certificates, got %d", tc.want, len(got))
			}
		})
	}

	// The real-time paths (legacy FilterExpiredCerts and a nil clock) are
	// checked against certs minted relative to real now, not the fixed-date
	// certs above, so this test does not become a time bomb once 2030 passes.
	t.Run("real time paths use certs relative to now", func(t *testing.T) {
		nowExpired, err := newTestCACertificate(pkix.Name{CommonName: "now-expired"}, int64(3), metav1.Duration{Duration: time.Hour}, func() time.Time { return time.Now().Add(-2 * time.Hour) })
		if err != nil {
			t.Fatal(err)
		}
		nowValid, err := newTestCACertificate(pkix.Name{CommonName: "now-valid"}, int64(4), metav1.Duration{Duration: 24 * time.Hour}, time.Now)
		if err != nil {
			t.Fatal(err)
		}

		for _, tc := range []struct {
			name string
			got  []*x509.Certificate
		}{
			{
				name: "legacy FilterExpiredCerts",
				got:  FilterExpiredCerts(nowExpired.Config.Certs[0], nowValid.Config.Certs[0]),
			},
			{
				name: "nil clock means real time",
				got:  FilterExpiredCertsWithClock(nil, nowExpired.Config.Certs[0], nowValid.Config.Certs[0]),
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if len(tc.got) != 1 || !tc.got[0].Equal(nowValid.Config.Certs[0]) {
					t.Fatalf("expected only the valid-now certificate to survive, got %d certs", len(tc.got))
				}
			})
		}
	})
}

// NewCACertificate generates and signs new CA certificate and key.
func newTestCACertificate(subject pkix.Name, serialNumber int64, validity metav1.Duration, currentTime func() time.Time) (*CA, error) {
	caPublicKey, caPrivateKey, err := NewKeyPair()
	if err != nil {
		return nil, err
	}

	caCert := &x509.Certificate{
		Subject: subject,

		SignatureAlgorithm: x509.SHA256WithRSA,

		NotBefore:    currentTime().Add(-1 * time.Second),
		NotAfter:     currentTime().Add(validity.Duration),
		SerialNumber: big.NewInt(serialNumber),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	cert, err := signCertificate(caCert, caPublicKey, caCert, caPrivateKey)
	if err != nil {
		return nil, err
	}

	return &CA{
		Config: &TLSCertificateConfig{
			Certs: []*x509.Certificate{cert},
			Key:   caPrivateKey,
		},
	}, nil
}
