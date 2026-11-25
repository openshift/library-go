package certrotation

import (
	"crypto/x509/pkix"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestNeedNewTargetCertKeyPairAtRotationThresholds exercises the target certificate
// rotation decision, covering the scenarios of
// TestNeedNewTargetCertKeyPairForTime plus the signer-age gate that delays
// target rotation until the signer has been valid for 10% of the target's
// refresh time, by advancing the clock.
func TestNeedNewTargetCertKeyPairAtRotationThresholds(t *testing.T) {
	testCases := []struct {
		name string

		validity               time.Duration
		advance                time.Duration
		refresh                time.Duration
		refreshOnlyWhenExpired bool
		// signerNotBeforeOffset shifts the signer.s notBefore relative to
		// the clock at mint time, to control how old the signer is
		// when the rotation decision runs.
		signerNotBeforeOffset time.Duration

		expectedReason string
	}{
		{
			name:           "cert is new enough",
			validity:       10 * time.Hour,
			advance:        time.Hour,
			refresh:        20 * time.Hour,
			expectedReason: "",
		},
		{
			// The 80% mark of a 10h validity is 8h; time.Now().After is
			// strict, so exactly at the mark must not rotate.
			name:           "exactly at 80% of validity does not rotate",
			validity:       10 * time.Hour,
			advance:        8 * time.Hour,
			refresh:        20 * time.Hour,
			expectedReason: "",
		},
		{
			name:           "just before 80% of validity",
			validity:       10 * time.Hour,
			advance:        8*time.Hour - time.Minute,
			refresh:        20 * time.Hour,
			expectedReason: "",
		},
		{
			name:           "past 80% of validity",
			validity:       10 * time.Hour,
			advance:        8*time.Hour + time.Minute,
			refresh:        20 * time.Hour,
			expectedReason: "past refresh time (80% of validity)",
		},
		{
			name:           "just before refresh time",
			validity:       10 * time.Hour,
			advance:        2*time.Hour - time.Minute,
			refresh:        2 * time.Hour,
			expectedReason: "",
		},
		{
			name:           "past refresh time",
			validity:       10 * time.Hour,
			advance:        2*time.Hour + time.Minute,
			refresh:        2 * time.Hour,
			expectedReason: "past its refresh time",
		},
		{
			// Past the target's refresh time, but the signer was minted
			// 1h59m after the target's notBefore: at the 2h1m mark it has
			// been valid for only ~2m, less than refresh/10 (12m), so the
			// signer-age gate must hold rotation back.
			name:                  "past refresh time but signer is too new",
			validity:              10 * time.Hour,
			advance:               2*time.Hour + time.Minute,
			refresh:               2 * time.Hour,
			signerNotBeforeOffset: 1*time.Hour + 59*time.Minute,
			expectedReason:        "",
		},
		{
			name:                   "past refresh time but refresh only when expired",
			validity:               10 * time.Hour,
			advance:                2*time.Hour + time.Minute,
			refresh:                2 * time.Hour,
			refreshOnlyWhenExpired: true,
			expectedReason:         "",
		},
		{
			name:           "already expired",
			validity:       time.Hour,
			advance:        2 * time.Hour,
			refresh:        20 * time.Hour,
			expectedReason: "already expired",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				notBefore := time.Now().UTC()
				notAfter := notBefore.Add(tc.validity)
				annotations := map[string]string{
					CertificateNotBeforeAnnotation: notBefore.Format(time.RFC3339),
					CertificateNotAfterAnnotation:  notAfter.Format(time.RFC3339),
				}

				signerNow := func() time.Time { return time.Now().Add(tc.signerNotBeforeOffset) }
				signer, err := newTestCACertificate(pkix.Name{CommonName: "signer-tests"}, int64(1), metav1.Duration{Duration: 24 * 60 * time.Hour}, signerNow)
				if err != nil {
					t.Fatal(err)
				}

				// Advance the clock.
				time.Sleep(tc.advance)

				reason := needNewTargetCertKeyPairForTime(annotations, signer, tc.refresh, tc.refreshOnlyWhenExpired)
				if len(tc.expectedReason) == 0 {
					if reason != "" {
						t.Errorf("expected no rotation, got reason %q", reason)
					}
					return
				}
				if !strings.HasPrefix(reason, tc.expectedReason) {
					t.Errorf("expected reason prefix %q, got %q", tc.expectedReason, reason)
				}
			})
		})
	}
}
