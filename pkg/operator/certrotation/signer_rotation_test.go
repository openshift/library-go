package certrotation

import (
	"context"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/openshift/library-go/pkg/operator/events"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	clocktesting "k8s.io/utils/clock/testing"
)

// TestNeedNewSigningCertKeyPair exercises the signing CA rotation
// decision: needNewSigningCertKeyPair compares the secret.s validity
// annotations against the current time, so each threshold (expiry, 80% of
// validity, developer-specified refresh) is crossed by advancing the clock.
func TestNeedNewSigningCertKeyPair(t *testing.T) {
	testCases := []struct {
		name string

		validity               time.Duration
		advance                time.Duration
		refresh                time.Duration
		refreshOnlyWhenExpired bool

		expectedNeedRotation bool
		expectedReason       string
	}{
		{
			name:                 "just before 80% of validity",
			validity:             10 * time.Hour,
			advance:              8*time.Hour - time.Minute,
			refresh:              20 * time.Hour,
			expectedNeedRotation: false,
			expectedReason:       "",
		},
		{
			// The 80% mark of a 10h validity is 8h; time.Now().After is
			// strict, so exactly at the mark must not rotate.
			name:                 "exactly at 80% of validity does not rotate",
			validity:             10 * time.Hour,
			advance:              8 * time.Hour,
			refresh:              20 * time.Hour,
			expectedNeedRotation: false,
			expectedReason:       "",
		},
		{
			name:                 "just past 80% of validity",
			validity:             10 * time.Hour,
			advance:              8*time.Hour + time.Minute,
			refresh:              20 * time.Hour,
			expectedNeedRotation: true,
			expectedReason:       "past refresh time (80% of validity)",
		},
		{
			name:                 "just before developer-specified refresh",
			validity:             10 * time.Hour,
			advance:              2*time.Hour - time.Minute,
			refresh:              2 * time.Hour,
			expectedNeedRotation: false,
			expectedReason:       "",
		},
		{
			name:                 "past developer-specified refresh",
			validity:             10 * time.Hour,
			advance:              2*time.Hour + time.Minute,
			refresh:              2 * time.Hour,
			expectedNeedRotation: true,
			expectedReason:       "past its refresh time",
		},
		{
			name:                 "already expired",
			validity:             time.Hour,
			advance:              2 * time.Hour,
			refresh:              20 * time.Hour,
			expectedNeedRotation: true,
			expectedReason:       "already expired",
		},
		{
			name:                   "past 80% but refresh only when expired",
			validity:               10 * time.Hour,
			advance:                9 * time.Hour,
			refresh:                20 * time.Hour,
			refreshOnlyWhenExpired: true,
			expectedNeedRotation:   false,
			expectedReason:         "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				notBefore := time.Now().UTC()
				notAfter := notBefore.Add(tc.validity)

				secret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ns",
						Name:      "signer",
						Annotations: map[string]string{
							CertificateNotBeforeAnnotation: notBefore.Format(time.RFC3339),
							CertificateNotAfterAnnotation:  notAfter.Format(time.RFC3339),
						},
					},
				}

				// Advance the clock.
				time.Sleep(tc.advance)

				c := &RotatedSigningCASecret{
					Refresh:                tc.refresh,
					RefreshOnlyWhenExpired: tc.refreshOnlyWhenExpired,
				}

				needRotation, reason := c.needNewSigningCertKeyPair(secret)
				if needRotation != tc.expectedNeedRotation {
					t.Errorf("expected needRotation=%v, got %v (reason %q)", tc.expectedNeedRotation, needRotation, reason)
				}
				if !strings.HasPrefix(reason, tc.expectedReason) {
					t.Errorf("expected reason prefix %q, got %q", tc.expectedReason, reason)
				}
			})
		})
	}
}

// TestEnsureSigningCertKeyPairReissuesNearExpiry runs the full signing CA ensure path
// twice: once to issue the signer, then again after advancing the clock
// past 80% of the certificate validity, asserting the signer is re-issued.
func TestEnsureSigningCertKeyPairReissuesNearExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
		client := fake.NewClientset()
		recorder := events.NewInMemoryRecorder("test", clocktesting.NewFakePassiveClock(time.Now()))

		c := &RotatedSigningCASecret{
			Namespace:     "ns",
			Name:          "signer",
			Validity:      10 * time.Hour,
			Refresh:       20 * time.Hour,
			Client:        client.CoreV1(),
			Lister:        corev1listers.NewSecretLister(indexer),
			EventRecorder: recorder,
			AdditionalAnnotations: AdditionalAnnotations{
				JiraComponent: "test",
			},
			Owner: &metav1.OwnerReference{
				Name: "operator",
			},
		}

		if _, updated, err := c.EnsureSigningCertKeyPair(context.Background()); err != nil {
			t.Fatal(err)
		} else if !updated {
			t.Fatal("expected the first ensure to create the signing secret")
		}

		created, err := client.CoreV1().Secrets("ns").Get(context.Background(), "signer", metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		firstNotBefore := created.Annotations[CertificateNotBeforeAnnotation]
		// Mirror what a synced informer would do: make the created secret
		// visible to the lister the controller reads through.
		if err := indexer.Add(created); err != nil {
			t.Fatal(err)
		}
		verifyKeyPair(t, created.Data["tls.crt"], created.Data["tls.key"])

		// Advance past 80% of the 10h validity (i.e. past the 8h mark).
		time.Sleep(8*time.Hour + time.Minute)

		if _, updated, err := c.EnsureSigningCertKeyPair(context.Background()); err != nil {
			t.Fatal(err)
		} else if !updated {
			t.Fatal("expected the second ensure to rotate the signing secret")
		}

		rotated, err := client.CoreV1().Secrets("ns").Get(context.Background(), "signer", metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		secondNotBefore := rotated.Annotations[CertificateNotBeforeAnnotation]
		if secondNotBefore == firstNotBefore {
			t.Errorf("expected the notBefore annotation to change after rotation, both are %q", firstNotBefore)
		}
		verifyKeyPair(t, rotated.Data["tls.crt"], rotated.Data["tls.key"])

		// The rotated signer must not already be past its own refresh time.
		if needRotation, reason := c.needNewSigningCertKeyPair(rotated); needRotation {
			t.Errorf("expected the freshly rotated signer to not need rotation, got reason %q", reason)
		}
	})
}
