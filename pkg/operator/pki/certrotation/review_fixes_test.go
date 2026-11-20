package certrotation

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/util/cert"
	clocktesting "k8s.io/utils/clock/testing"

	"github.com/openshift/library-go/pkg/operator/certrotation/contract"
)

// TestReconcileTargetNameDiffersFromLocation guards the regression where the
// target secret was written under Target.Name (the status-condition name)
// instead of Location.Name: reads and writes must agree on Location.
func TestReconcileTargetNameDiffersFromLocation(t *testing.T) {
	rotation := testRotation()
	rotation.Targets[0].Name = "MyControllerName"
	rotation.Targets[0].Location.Name = "my-secret-name"

	reconciler, client, _, _ := newTestReconciler(t, rotation, RoleWriter, nil)
	result, err := reconciler.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.TargetErrors["MyControllerName"] != nil {
		t.Fatalf("unexpected error: %v", result.TargetErrors["MyControllerName"])
	}

	if _, err := client.CoreV1().Secrets(testNamespace).Get(context.Background(), "my-secret-name", metav1GetOptions); err != nil {
		t.Fatalf("target secret not written under Location.Name: %v", err)
	}
	if _, err := client.CoreV1().Secrets(testNamespace).Get(context.Background(), "MyControllerName", metav1GetOptions); err == nil {
		t.Fatal("target secret wrongly written under Target.Name")
	}

	// A second pass must be idempotent: same object, no AlreadyExists loop.
	if _, err := reconciler.Reconcile(context.Background()); err != nil {
		t.Fatalf("second pass: %v", err)
	}
}

// TestReconcileNonCanonicalHostname guards the regression where a desired
// non-canonical IPv6 literal compared unequal to its canonical SAN form and
// regenerated the target on every pass.
func TestReconcileNonCanonicalHostname(t *testing.T) {
	rotation := testRotation()
	rotation.Targets = []Target{
		{
			Name:     "test-serving",
			Location: Location{Namespace: testNamespace, Name: "test-serving"},
			Validity: 12 * time.Hour,
			Refresh:  6 * time.Hour,
			Cert:     ServingCert{Hostnames: StaticHostnames("0:0:0:0:0:0:0:1")},
		},
	}
	reconciler, _, _, _ := newTestReconciler(t, rotation, RoleWriter, nil)
	if _, err := reconciler.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Repeated passes over the same non-canonical desired form must not
	// regenerate: the canonical SAN equals the canonicalized desire.
	for i := range 3 {
		result, err := reconciler.Reconcile(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		for _, action := range result.Actions {
			if action.Artifact.Kind == ArtifactKindTarget {
				t.Errorf("pass %d regenerated on non-canonical hostname: %+v", i+2, action)
			}
		}
	}
}

// TestReconcileMismatchedCertAndKeyRegenerates guards the classification
// gap where a secret holding a valid certificate with a mismatched private
// key was treated as current and failed every pass downstream.
func TestReconcileMismatchedCertAndKeyRegenerates(t *testing.T) {
	reconciler, client, _, _ := newTestReconciler(t, testRotation(), RoleWriter, nil)
	if _, err := reconciler.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Swap the target's key for the signer's key: cert and key no longer
	// match, but both parse and the annotations stay valid.
	target, err := client.CoreV1().Secrets(testNamespace).Get(context.Background(), targetName, metav1GetOptions)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := client.CoreV1().Secrets(testNamespace).Get(context.Background(), signerName, metav1GetOptions)
	if err != nil {
		t.Fatal(err)
	}
	target.Data[contract.SecretKeyKey] = signer.Data[contract.SecretKeyKey]
	if err := client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("secrets"), target, testNamespace); err != nil {
		t.Fatal(err)
	}

	fixing, _ := reconcilerOver(t, testRotation(), RoleWriter, client, clockReal())
	result, err := fixing.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.TargetErrors[targetName] != nil {
		t.Fatalf("unexpected error: %v", result.TargetErrors[targetName])
	}
	regenerated := false
	for _, action := range result.Actions {
		if action.Artifact.Kind == ArtifactKindTarget && action.Op == OpRegenerated {
			regenerated = true
		}
	}
	if !regenerated {
		t.Fatal("expected regeneration of mismatched cert/key target")
	}
}

// TestReconcileRegenerationPreservesForeignMetadata guards the parity
// requirement that regeneration builds on the existing object: foreign
// annotations, labels, owner references and extra data keys survive.
func TestReconcileRegenerationPreservesForeignMetadata(t *testing.T) {
	reconciler, client, _, _ := newTestReconciler(t, testRotation(), RoleWriter, nil)
	if _, err := reconciler.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}

	target, err := client.CoreV1().Secrets(testNamespace).Get(context.Background(), targetName, metav1GetOptions)
	if err != nil {
		t.Fatal(err)
	}
	target.Annotations["custom.example.com/owner"] = "someone-else"
	target.Labels["custom.example.com/managed-by"] = "other-component"
	target.Data["extra.bin"] = []byte{1, 2, 3}
	if err := client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("secrets"), target, testNamespace); err != nil {
		t.Fatal(err)
	}
	// Request regeneration via the sentinel.
	target.Annotations[contract.CertificateNotAfterAnnotation] = contract.ForceRegeneration
	if err := client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("secrets"), target, testNamespace); err != nil {
		t.Fatal(err)
	}

	regenerating, _ := reconcilerOver(t, testRotation(), RoleWriter, client, clockReal())
	if _, err := regenerating.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	regenerated, err := client.CoreV1().Secrets(testNamespace).Get(context.Background(), targetName, metav1GetOptions)
	if err != nil {
		t.Fatal(err)
	}
	if regenerated.Annotations["custom.example.com/owner"] != "someone-else" {
		t.Error("foreign annotation dropped on regeneration")
	}
	if regenerated.Labels["custom.example.com/managed-by"] != "other-component" {
		t.Error("foreign label dropped on regeneration")
	}
	if len(regenerated.Data["extra.bin"]) == 0 {
		t.Error("extra data key dropped on regeneration")
	}
	if _, err := cert.ParseCertsPEM(regenerated.Data[contract.SecretCertKey]); err != nil {
		t.Errorf("regenerated cert unparseable: %v", err)
	}
}

// TestDynamicHostnamesSubscribers guards the regression where all
// subscribers shared one channel and stole each other's notifications.
func TestDynamicHostnamesSubscribers(t *testing.T) {
	dynamic := NewDynamicHostnames()
	first := dynamic.Subscribe()
	second := dynamic.Subscribe()

	if changed := dynamic.Set([]string{"one.example.com"}); !changed {
		t.Fatal("expected first Set to report a change")
	}
	if changed := dynamic.Set([]string{"one.example.com"}); changed {
		t.Fatal("expected unchanged Set to report no change")
	}

	// Both subscribers must observe the change independently.
	for name, subscription := range map[string]<-chan struct{}{"first": first, "second": second} {
		select {
		case <-subscription:
		default:
			t.Errorf("%s subscriber missed the notification", name)
		}
	}
}

func clockReal() *clocktesting.FakeClock {
	return clocktesting.NewFakeClock(time.Now())
}
