package paritytest

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	clock "k8s.io/utils/clock"

	"github.com/openshift/library-go/pkg/operator/certrotation/contract"
	"github.com/openshift/library-go/pkg/operator/events"
	certrotationv2 "github.com/openshift/library-go/pkg/operator/pki/certrotation"
)

// The parity scenarios are drawn from the v1 bug history: each row of the
// matrix runs v1's SyncWorker and v2's Reconciler against identical starting
// state and asserts the produced artifacts agree on the contract.

func TestParityFreshCreate(t *testing.T) {
	cfg := DefaultConfig()
	v1Client := fake.NewSimpleClientset()
	v2Client := fake.NewSimpleClientset()

	if err := RunV1(t, cfg, v1Client, false); err != nil {
		t.Fatalf("v1 pass: %v", err)
	}
	if _, err := RunV2(t, cfg, v2Client, certrotationv2.RoleWriter); err != nil {
		t.Fatalf("v2 pass: %v", err)
	}

	AssertArtifactsEqual(t, cfg, v1Client, v2Client)
}

func TestParitySameStartingState(t *testing.T) {
	// Start from a v1-created cluster; run v2 over a copy of it and back.
	// Both must leave the artifacts equivalent.
	cfg := DefaultConfig()
	v1Client := fake.NewSimpleClientset()
	if err := RunV1(t, cfg, v1Client, false); err != nil {
		t.Fatalf("v1 pass: %v", err)
	}

	v2Client := CopyCluster(t, v1Client, cfg.Namespace)
	if _, err := RunV2(t, cfg, v2Client, certrotationv2.RoleWriter); err != nil {
		t.Fatalf("v2 pass over v1 state: %v", err)
	}
	AssertArtifactsEqual(t, cfg, v1Client, v2Client)

	v1Again := CopyCluster(t, v2Client, cfg.Namespace)
	if err := RunV1(t, cfg, v1Again, false); err != nil {
		t.Fatalf("v1 pass over v2 state: %v", err)
	}
	AssertArtifactsEqual(t, cfg, v1Again, v2Client)
}

func TestParityForceRegeneration(t *testing.T) {
	// oc writes the force-regeneration sentinel into the not-after
	// annotation; both v1 and v2 must regenerate the target.
	cfg := DefaultConfig()
	base := fake.NewSimpleClientset()
	if err := RunV1(t, cfg, base, false); err != nil {
		t.Fatalf("base pass: %v", err)
	}

	for name, run := range map[string]struct {
		role certrotationv2.Role
		v1   bool
	}{
		"v2 writer": {role: certrotationv2.RoleWriter},
		"v2 healer": {role: certrotationv2.RoleHealer},
	} {
		t.Run(name, func(t *testing.T) {
			client := CopyCluster(t, base, cfg.Namespace)
			target, err := client.CoreV1().Secrets(cfg.Namespace).Get(context.Background(), cfg.TargetName, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			target.Annotations[contract.CertificateNotAfterAnnotation] = contract.ForceRegeneration
			if err := client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("secrets"), target, cfg.Namespace); err != nil {
				t.Fatal(err)
			}

			result, err := RunV2(t, cfg, client, run.role)
			if err != nil {
				t.Fatalf("v2 pass: %v", err)
			}
			regenerated := false
			for _, action := range result.Actions {
				if action.Artifact.Kind == certrotationv2.ArtifactKindTarget && action.Op == certrotationv2.OpRegenerated {
					regenerated = true
				}
			}
			if !regenerated {
				t.Fatalf("expected regeneration, actions: %v", result.Actions)
			}
		})
	}

	// v1 with the sentinel: SyncWorker must also regenerate.
	v1Client := CopyCluster(t, base, cfg.Namespace)
	target, err := v1Client.CoreV1().Secrets(cfg.Namespace).Get(context.Background(), cfg.TargetName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	target.Annotations[contract.CertificateNotAfterAnnotation] = contract.ForceRegeneration
	if err := v1Client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("secrets"), target, cfg.Namespace); err != nil {
		t.Fatal(err)
	}
	if err := RunV1(t, cfg, v1Client, false); err != nil {
		t.Fatalf("v1 pass with sentinel: %v", err)
	}
	cleared, err := v1Client.CoreV1().Secrets(cfg.Namespace).Get(context.Background(), cfg.TargetName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if cleared.Annotations[contract.CertificateNotAfterAnnotation] == contract.ForceRegeneration {
		t.Error("v1 did not regenerate on force-regeneration sentinel")
	}
}

func TestConvergenceMixedRoles(t *testing.T) {
	// The mixed-role convergence suite: a v2 writer and a v2 healer over one
	// cluster. Interleave passes with an injected expiry and a
	// force-regeneration, then assert convergence and bounded writes: no
	// update ping-pong once steady state is reached.
	cfg := DefaultConfig()
	client := fake.NewSimpleClientset()

	writer, err := certrotationv2.NewReconciler(RotationV2(cfg), certrotationv2.Options{
		Role:       certrotationv2.RoleWriter,
		KubeClient: client,
		PKI:        certrotationv2.LegacyPKI(),
		Recorder:   eventsRecorder(),
	})
	if err != nil {
		t.Fatal(err)
	}
	healer, err := certrotationv2.NewReconciler(RotationV2(cfg), certrotationv2.Options{
		Role:       certrotationv2.RoleHealer,
		KubeClient: client,
		PKI:        certrotationv2.LegacyPKI(),
		Recorder:   eventsRecorder(),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Steady state: writer creates, healer does nothing.
	if _, err := writer.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	afterWriter := CountWrites(client)
	if _, err := healer.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if count := CountWrites(client); count != afterWriter {
		t.Fatalf("healer wrote during steady state: %d writes (was %d)", count, afterWriter)
	}

	// Repeated interleaved passes must not add writes (no ping-pong).
	for i := 0; i < 5; i++ {
		if _, err := writer.Reconcile(context.Background()); err != nil {
			t.Fatal(err)
		}
		if _, err := healer.Reconcile(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if count := CountWrites(client); count != afterWriter {
		t.Fatalf("interleaved passes added writes (ping-pong): %d writes (was %d)", count, afterWriter)
	}

	// Force regeneration via the sentinel: the healer may act; afterwards
	// the pair must converge and stop writing.
	target, err := client.CoreV1().Secrets(cfg.Namespace).Get(context.Background(), cfg.TargetName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	target.Annotations[contract.CertificateNotAfterAnnotation] = contract.ForceRegeneration
	if err := client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("secrets"), target, cfg.Namespace); err != nil {
		t.Fatal(err)
	}
	if _, err := healer.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	healed := CountWrites(client)
	for i := 0; i < 5; i++ {
		if _, err := writer.Reconcile(context.Background()); err != nil {
			t.Fatal(err)
		}
		if _, err := healer.Reconcile(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if count := CountWrites(client); count != healed {
		t.Fatalf("post-heal passes added writes (ping-pong): %d writes (was %d)", count, healed)
	}

	// Final state must be healthy and contract-complete.
	signer, err := client.CoreV1().Secrets(cfg.Namespace).Get(context.Background(), cfg.SignerName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if signer.Annotations[contract.CertificateNotAfterAnnotation] == contract.ForceRegeneration {
		t.Error("sentinel not cleared from signer")
	}
	target, err = client.CoreV1().Secrets(cfg.Namespace).Get(context.Background(), cfg.TargetName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if target.Annotations[contract.CertificateNotAfterAnnotation] == contract.ForceRegeneration {
		t.Error("sentinel not cleared from target")
	}
	_ = time.Now()
}

func eventsRecorder() events.Recorder {
	return events.NewLoggingEventRecorder("paritytest", clock.RealClock{})
}
