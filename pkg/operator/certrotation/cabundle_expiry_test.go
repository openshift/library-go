package certrotation

import (
	"context"
	"crypto/x509/pkix"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/openshift/library-go/pkg/crypto"
	"github.com/openshift/library-go/pkg/operator/events"

	clocktesting "k8s.io/utils/clock/testing"
)

// TestEnsureConfigMapCABundlePrunesExpiredSigner exercises CA bundle
// maintenance: a signer that expires mid-test is pruned from the bundle on
// the next ensure, and the fresh signer remains.
func TestEnsureConfigMapCABundlePrunesExpiredSigner(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// A signer valid for one hour.
		oldSigner, err := newTestCACertificate(pkix.Name{CommonName: "old-signer"}, int64(1), metav1.Duration{Duration: time.Hour}, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		oldSignerPEM, err := crypto.EncodeCertificates(oldSigner.Config.Certs[0])
		if err != nil {
			t.Fatal(err)
		}

		initialConfigMap := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "trust-bundle"},
			Data:       map[string]string{"ca-bundle.crt": string(oldSignerPEM)},
		}

		indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
		indexer.Add(initialConfigMap)
		client := fake.NewSimpleClientset(initialConfigMap)

		c := &CABundleConfigMap{
			Namespace: "ns",
			Name:      "trust-bundle",

			Client:        client.CoreV1(),
			Lister:        corev1listers.NewConfigMapLister(indexer),
			EventRecorder: events.NewInMemoryRecorder("test", clocktesting.NewFakePassiveClock(time.Now())),
		}

		newSigner, err := newTestCACertificate(pkix.Name{CommonName: "new-signer"}, int64(2), metav1.Duration{Duration: 24 * 60 * time.Hour}, time.Now)
		if err != nil {
			t.Fatal(err)
		}

		// Before expiry the bundle holds both signers.
		bundle, err := c.EnsureConfigMapCABundle(context.Background(), newSigner, "signer-secret")
		if err != nil {
			t.Fatal(err)
		}
		if len(bundle) != 2 {
			t.Fatalf("expected 2 certs in the bundle before expiry, got %d", len(bundle))
		}

		// Advance the clock past the old signer.s lifetime and
		// re-ensure: the expired signer must be pruned.
		time.Sleep(2 * time.Hour)
		// Mirror what a synced informer would do: make the updated configmap
		// (the first ensure wrote the two-cert bundle) visible to the lister.
		updated, err := client.CoreV1().ConfigMaps("ns").Get(context.Background(), "trust-bundle", metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if err := indexer.Update(updated); err != nil {
			t.Fatal(err)
		}

		bundle, err = c.EnsureConfigMapCABundle(context.Background(), newSigner, "signer-secret")
		if err != nil {
			t.Fatal(err)
		}
		if len(bundle) != 1 {
			t.Fatalf("expected 1 cert in the bundle after expiry, got %d", len(bundle))
		}
		if !strings.Contains(bundle[0].Subject.CommonName, "new-signer") {
			t.Errorf("expected the new signer to remain in the bundle, got subject %q", bundle[0].Subject.CommonName)
		}
	})
}
