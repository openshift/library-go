package certrotation

import (
	"bytes"
	"context"
	"crypto/x509"
	"testing"
	"testing/synctest"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/util/cert"
	"k8s.io/utils/clock"

	"github.com/openshift/library-go/pkg/operator/events"
)

// TestCertRotationController_SyncWorkerRotatesChain runs the full
// CertRotationController sync path twice: once to issue the signer, CA
// bundle, and target certificate, then again after advancing the clock
// past 80% of their validity, asserting the whole chain is re-issued.
// Unlike TestCertRotationController_SyncWorker, which uses a mock
// TargetCertCreator that never rotates, this uses the real ServingRotation
// creator so the target rotation decision also runs.
func TestCertRotationController_SyncWorkerRotatesChain(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fakeClient := fake.NewSimpleClientset()
		informerFactory := informers.NewSharedInformerFactory(fakeClient, 0)

		controller := &CertRotationController{
			Name: "test-controller",
			RotatedSigningCASecret: RotatedSigningCASecret{
				Namespace:     "test-namespace",
				Name:          "test-signer-cert",
				Validity:      10 * time.Hour,
				Refresh:       20 * time.Hour,
				Informer:      informerFactory.Core().V1().Secrets(),
				Lister:        informerFactory.Core().V1().Secrets().Lister(),
				Client:        fakeClient.CoreV1(),
				EventRecorder: events.NewInMemoryRecorder("test", clock.RealClock{}),
			},
			CABundleConfigMap: CABundleConfigMap{
				Namespace:     "test-namespace",
				Name:          "test-ca-bundle",
				Informer:      informerFactory.Core().V1().ConfigMaps(),
				Lister:        informerFactory.Core().V1().ConfigMaps().Lister(),
				Client:        fakeClient.CoreV1(),
				EventRecorder: events.NewInMemoryRecorder("test", clock.RealClock{}),
				AdditionalAnnotations: AdditionalAnnotations{
					JiraComponent: "test",
				},
			},
			RotatedSelfSignedCertKeySecret: RotatedSelfSignedCertKeySecret{
				Namespace:     "test-namespace",
				Name:          "test-target-cert",
				Validity:      10 * time.Hour,
				Refresh:       20 * time.Hour,
				CertCreator:   &ServingRotation{Hostnames: func() []string { return []string{"test.example.com"} }},
				Informer:      informerFactory.Core().V1().Secrets(),
				Lister:        informerFactory.Core().V1().Secrets().Lister(),
				Client:        fakeClient.CoreV1(),
				EventRecorder: events.NewInMemoryRecorder("test", clock.RealClock{}),
			},
			StatusReporter: &testStatusReporter{},
		}

		// First sync issues everything.
		if err := controller.SyncWorker(context.Background()); err != nil {
			t.Fatalf("first sync: %v", err)
		}

		firstTarget, err := fakeClient.CoreV1().Secrets("test-namespace").Get(context.Background(), "test-target-cert", metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		firstSigner, err := fakeClient.CoreV1().Secrets("test-namespace").Get(context.Background(), "test-signer-cert", metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		firstNotBefore := firstTarget.Annotations[CertificateNotBeforeAnnotation]

		// Mirror what synced informers would do: make the created objects
		// visible to the listers the controller reads through.
		secretStore := informerFactory.Core().V1().Secrets().Informer().GetStore()
		if err := secretStore.Add(firstSigner); err != nil {
			t.Fatal(err)
		}
		if err := secretStore.Add(firstTarget); err != nil {
			t.Fatal(err)
		}
		firstBundle, err := fakeClient.CoreV1().ConfigMaps("test-namespace").Get(context.Background(), "test-ca-bundle", metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if err := informerFactory.Core().V1().ConfigMaps().Informer().GetStore().Add(firstBundle); err != nil {
			t.Fatal(err)
		}

		// Advance past 80% of the 10h validity (i.e. past the 8h mark).
		time.Sleep(8*time.Hour + time.Minute)

		// Second sync must rotate the whole chain.
		if err := controller.SyncWorker(context.Background()); err != nil {
			t.Fatalf("second sync: %v", err)
		}

		secondTarget, err := fakeClient.CoreV1().Secrets("test-namespace").Get(context.Background(), "test-target-cert", metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		secondNotBefore := secondTarget.Annotations[CertificateNotBeforeAnnotation]
		if secondNotBefore == firstNotBefore {
			t.Errorf("expected the target cert notBefore annotation to change after rotation, both are %q", firstNotBefore)
		}

		// The rotated chain must be freshly valid: no rotation reason at the
		// new time.
		secondSigner, err := fakeClient.CoreV1().Secrets("test-namespace").Get(context.Background(), "test-signer-cert", metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if needRotation, reason := controller.RotatedSigningCASecret.needNewSigningCertKeyPair(secondSigner); needRotation {
			t.Errorf("expected the freshly rotated signer to not need rotation, got reason %q", reason)
		}

		// The CA bundle must trust the rotated signer: the new signer's
		// certificate has to be part of the bundle after rotation.
		secondSignerCerts, err := cert.ParseCertsPEM(secondSigner.Data["tls.crt"])
		if err != nil {
			t.Fatal(err)
		}
		secondBundle, err := fakeClient.CoreV1().ConfigMaps("test-namespace").Get(context.Background(), "test-ca-bundle", metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		bundleCerts, err := cert.ParseCertsPEM([]byte(secondBundle.Data["ca-bundle.crt"]))
		if err != nil {
			t.Fatal(err)
		}
		if !containsCert(bundleCerts, secondSignerCerts[0]) {
			t.Error("expected the CA bundle to contain the rotated signer certificate")
		}

		// The rotated target must be issued by the rotated signer.
		targetCerts, err := cert.ParseCertsPEM(secondTarget.Data["tls.crt"])
		if err != nil {
			t.Fatal(err)
		}
		if err := targetCerts[0].CheckSignatureFrom(secondSignerCerts[0]); err != nil {
			t.Errorf("expected the rotated target certificate to be signed by the rotated signer: %v", err)
		}
	})
}

// containsCert reports whether certs contains an exact match for want.
func containsCert(certs []*x509.Certificate, want *x509.Certificate) bool {
	for _, c := range certs {
		if bytes.Equal(c.Raw, want.Raw) {
			return true
		}
	}
	return false
}
