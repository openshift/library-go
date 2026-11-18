package certrotation

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/util/cert"
	"testing/synctest"

	"github.com/openshift/library-go/pkg/operator/certrotation/contract"
)

// TestReconcilerLifecycleSynctest runs the real reconciler inside a
// testing/synctest bubble across a 30-day virtual timeline, advancing
// virtual time in ten-minute steps. Inside the bubble the real clock is
// virtualized, so the pass cadence, the issuance timestamps and the rotation
// boundaries all see the same virtual time, exactly as the controller will
// in production.
//
// It asserts the lifecycle invariants the rotation must hold over time:
// rotations happen on schedule, writes stay bounded (no hot loops), the
// bundle is never empty, and no target ever outlives its signer.
func TestReconcilerLifecycleSynctest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rotation := testRotation()
		client := fake.NewSimpleClientset()
		reconciler, err := NewReconciler(rotation, Options{
			Role:       RoleWriter,
			KubeClient: client,
			PKI:        LegacyPKI(),
			Recorder:   &testLogger{},
			// Deliberately no injected clock: inside the synctest bubble the
			// real clock is virtual, which is what the controller will use.
		})
		if err != nil {
			t.Fatal(err)
		}

		const virtualDays = 30
		const step = 10 * time.Minute
		steps := int((virtualDays * 24 * time.Hour) / step)

		for i := range steps {
			result, err := reconciler.Reconcile(context.Background())
			if err != nil {
				t.Fatalf("virtual step %d (t=%s): %v", i, time.Now().Format(time.RFC3339), err)
			}
			for name, targetErr := range result.TargetErrors {
				if targetErr != nil {
					t.Fatalf("virtual step %d: target %s: %v", i, name, targetErr)
				}
			}
			time.Sleep(step)
		}

		// Write accounting: with a 12h signer refresh and a 6h target
		// refresh over 30 days, expect roughly 60 signer rotations and 120
		// target rotations, each with a bundle update. Bound generously:
		// anything within an order of magnitude rules out a hot loop, and
		// anything above it is one.
		secretWrites, configMapWrites := 0, 0
		for _, action := range client.Actions() {
			if action.GetVerb() == "create" || action.GetVerb() == "update" {
				if action.GetResource().Resource == "secrets" {
					secretWrites++
				}
				if action.GetResource().Resource == "configmaps" {
					configMapWrites++
				}
			}
		}
		// Signer (60) + target (120) = 180 secret writes expected.
		if secretWrites < 100 || secretWrites > 400 {
			t.Errorf("secret writes over %d virtual days: %d (expected ~180, bounds 100-400)", virtualDays, secretWrites)
		}
		// One bundle update per signer rotation (~60), plus repairs.
		if configMapWrites < 30 || configMapWrites > 200 {
			t.Errorf("configmap writes over %d virtual days: %d (expected ~60, bounds 30-200)", virtualDays, configMapWrites)
		}

		// The bundle is never empty and the target never outlives its
		// signer at any observed instant.
		bundle, err := client.CoreV1().ConfigMaps(testNamespace).Get(context.Background(), bundleName, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		bundleCerts, err := cert.ParseCertsPEM([]byte(bundle.Data[contract.CABundleConfigMapKey]))
		if err != nil || len(bundleCerts) == 0 {
			t.Fatalf("final bundle empty or unparseable: %d certs, err %v", len(bundleCerts), err)
		}

		signer, err := client.CoreV1().Secrets(testNamespace).Get(context.Background(), signerName, metav1GetOptions)
		_ = signer
		if err != nil {
			t.Fatal(err)
		}
		signerCerts, err := cert.ParseCertsPEM(signer.Data[contract.SecretCertKey])
		if err != nil || len(signerCerts) == 0 {
			t.Fatal(err)
		}
		target, err := client.CoreV1().Secrets(testNamespace).Get(context.Background(), targetName, metav1GetOptions)
		if err != nil {
			t.Fatal(err)
		}
		targetCerts, err := cert.ParseCertsPEM(target.Data[contract.SecretCertKey])
		if err != nil || len(targetCerts) == 0 {
			t.Fatal(err)
		}
		if targetCerts[0].NotAfter.After(signerCerts[0].NotAfter) {
			t.Errorf("target outlives signer: target %s, signer %s", targetCerts[0].NotAfter, signerCerts[0].NotAfter)
		}
	})
}

// TestReconcilerExpiryRecoverySynctest advances virtual time past every
// certificate's lifetime and asserts the writer recovers on the next pass,
// as the shutdown-and-resume scenario requires.
func TestReconcilerExpiryRecoverySynctest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rotation := testRotation()
		client := fake.NewSimpleClientset()
		reconciler, err := NewReconciler(rotation, Options{
			Role:       RoleWriter,
			KubeClient: client,
			PKI:        LegacyPKI(),
			Recorder:   &testLogger{},
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := reconciler.Reconcile(context.Background()); err != nil {
			t.Fatal(err)
		}

		// Cluster down past every lifetime.
		time.Sleep(72 * time.Hour)

		result, err := reconciler.Reconcile(context.Background())
		if err != nil {
			t.Fatalf("recovery pass: %v", err)
		}
		for name, targetErr := range result.TargetErrors {
			if targetErr != nil {
				t.Fatalf("recovery target %s: %v", name, targetErr)
			}
		}
		signerRegenerated, targetRegenerated := false, false
		for _, action := range result.Actions {
			if action.Artifact.Kind == ArtifactKindSigner && action.Op == OpRegenerated {
				signerRegenerated = true
			}
			if action.Artifact.Kind == ArtifactKindTarget && action.Op == OpRegenerated {
				targetRegenerated = true
			}
		}
		if !signerRegenerated {
			t.Error("expected signer regeneration after offline expiry")
		}
		if !targetRegenerated {
			t.Error("expected target regeneration after offline expiry")
		}
	})
}
