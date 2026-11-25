package crypto

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"testing/synctest"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestFilterExpiredCerts exercises FilterExpiredCerts across certificate
// expiry: certificates are minted with a fixed lifetime and the clock is
// advanced past (or kept before) their NotAfter.
func TestFilterExpiredCerts(t *testing.T) {
	testCases := []struct {
		name string

		lifetime time.Duration
		advance  time.Duration
		// withFreshCert adds a second, long-lived certificate to the chain,
		// for the mixed-chain case.
		withFreshCert bool

		expected        int
		expectedSubject string
	}{
		{
			name:     "not expired",
			lifetime: time.Hour,
			advance:  30 * time.Minute,
			expected: 1,
		},
		{
			name:     "expired",
			lifetime: time.Hour,
			advance:  2 * time.Hour,
			expected: 0,
		},
		{
			// NotAfter == currentTime means the certificate is no longer
			// valid: FilterExpiredCerts keeps only certificates with
			// NotAfter strictly after now.
			name:     "exactly at NotAfter is expired",
			lifetime: time.Hour,
			advance:  time.Hour,
			expected: 0,
		},
		{
			// A chain holding both an expired and a fresh certificate keeps
			// only the fresh one. The expired certificate is generated in
			// the test with a short lifetime instead of being read from a
			// static fixture.
			name:            "mixed chain keeps only the fresh certificate",
			lifetime:        time.Minute,
			advance:         2 * time.Minute,
			withFreshCert:   true,
			expected:        1,
			expectedSubject: "fresh-ca",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				expired, err := newTestCACertificate(pkix.Name{CommonName: "filter-tests"}, int64(1), metav1.Duration{Duration: tc.lifetime}, time.Now)
				if err != nil {
					t.Fatal(err)
				}
				chain := expired.Config.Certs
				if tc.withFreshCert {
					fresh, err := newTestCACertificate(pkix.Name{CommonName: tc.expectedSubject}, int64(2), metav1.Duration{Duration: 24 * 60 * time.Hour}, time.Now)
					if err != nil {
						t.Fatal(err)
					}
					chain = append(chain, fresh.Config.Certs...)
				}

				// Advance the clock.
				time.Sleep(tc.advance)

				validCerts := FilterExpiredCerts(chain...)
				if len(validCerts) != tc.expected {
					t.Errorf("expected %d valid certificate(s), but got %d", tc.expected, len(validCerts))
				}
				if tc.expectedSubject != "" && !onlySubject(validCerts, tc.expectedSubject) {
					t.Errorf("expected only the %q certificate to survive filtering, got subjects %v", tc.expectedSubject, subjectsOf(validCerts))
				}
			})
		})
	}
}

func subjectsOf(certs []*x509.Certificate) []string {
	subjects := make([]string, 0, len(certs))
	for _, c := range certs {
		subjects = append(subjects, c.Subject.CommonName)
	}
	return subjects
}

func onlySubject(certs []*x509.Certificate, want string) bool {
	return len(certs) == 1 && certs[0].Subject.CommonName == want
}
