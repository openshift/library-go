package controllers

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	clocktesting "k8s.io/utils/clock/testing"

	operatorv1 "github.com/openshift/api/operator/v1"
	apiserverconfigv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"

	"github.com/openshift/library-go/pkg/operator/encryption/secrets"
	"github.com/openshift/library-go/pkg/operator/encryption/state"
)

const (
	annotationTargetRemoteKeyID    = "encryption.apiserver.operator.openshift.io/target-remote-key-id"
	annotationMigratedRemoteKeyID  = "encryption.apiserver.operator.openshift.io/migrated-remote-key-id"
	annotationRemoteKeyConvergedID = "encryption.apiserver.operator.openshift.io/remote-key-converged-id"
	annotationRemoteKeyConvergedAt = "encryption.apiserver.operator.openshift.io/remote-key-converged-at"
)

func setRemoteKeyAnnotations(t *testing.T, annotations map[string]string, rk state.RemoteKeyState) {
	t.Helper()
	if err := rk.Validate(); err != nil {
		t.Fatalf("invalid remote key state: %v", err)
	}
	if rk.TargetRemoteKeyID == "" {
		delete(annotations, annotationTargetRemoteKeyID)
	} else {
		annotations[annotationTargetRemoteKeyID] = rk.TargetRemoteKeyID
	}
	if rk.MigratedRemoteKeyID == "" {
		delete(annotations, annotationMigratedRemoteKeyID)
	} else {
		annotations[annotationMigratedRemoteKeyID] = rk.MigratedRemoteKeyID
	}
	if rk.ConvergedID == "" {
		delete(annotations, annotationRemoteKeyConvergedID)
	} else {
		annotations[annotationRemoteKeyConvergedID] = rk.ConvergedID
	}
	if rk.ConvergedAt.IsZero() {
		delete(annotations, annotationRemoteKeyConvergedAt)
	} else {
		annotations[annotationRemoteKeyConvergedAt] = rk.ConvergedAt.Format(time.RFC3339)
	}
}

func TestRecordRemoteKeyConvergence(t *testing.T) {
	now := time.Date(2026, 8, 31, 10, 0, 0, 0, time.UTC)
	rk := state.RemoteKeyState{TargetRemoteKeyID: "remote-old", MigratedRemoteKeyID: "remote-old"}

	got, changed := recordRemoteKeyConvergence(rk, "remote-new", now)
	if !changed {
		t.Fatal("expected change when recording a new candidate")
	}
	if got.ConvergedID != "remote-new" || !got.ConvergedAt.Equal(now) {
		t.Fatalf("unexpected convergence: %#v", got)
	}

	again, changed := recordRemoteKeyConvergence(got, "remote-new", now.Add(time.Minute))
	if changed {
		t.Fatal("expected no change when candidate already recorded")
	}
	if !again.ConvergedAt.Equal(now) {
		t.Fatal("expected converged-at to remain unchanged")
	}
}

func TestClearRemoteKeyConvergence(t *testing.T) {
	now := time.Date(2026, 8, 31, 10, 0, 0, 0, time.UTC)
	rk := state.RemoteKeyState{
		TargetRemoteKeyID:   "remote-new",
		MigratedRemoteKeyID: "remote-old",
		ConvergedID:         "remote-new",
		ConvergedAt:         now,
	}

	got, changed := clearRemoteKeyConvergence(rk)
	if !changed {
		t.Fatal("expected change when clearing convergence")
	}
	if got.ConvergedID != "" || !got.ConvergedAt.IsZero() {
		t.Fatalf("expected convergence cleared, got %#v", got)
	}
	if got.TargetRemoteKeyID != "remote-new" {
		t.Fatal("expected target to be preserved")
	}

	if _, changed := clearRemoteKeyConvergence(got); changed {
		t.Fatal("expected no change when already clear")
	}
}

func TestReconcileRemoteKeyRecordsConvergence(t *testing.T) {
	now := time.Date(2026, 8, 31, 10, 0, 0, 0, time.UTC)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   "openshift-config-managed",
			Name:        "encryption-key-test-3",
			Annotations: map[string]string{},
		},
	}
	setRemoteKeyAnnotations(t, secret.Annotations, state.RemoteKeyState{
		TargetRemoteKeyID:   "remote-old",
		MigratedRemoteKeyID: "remote-old",
	})
	client := fake.NewSimpleClientset(secret)

	writeKey := state.KeyState{
		Key:  apiserverconfigv1.Key{Name: "3", Secret: "c2VjcmV0"},
		Mode: state.KMS,
		KMS: &state.KMSState{
			RemoteKey: state.RemoteKeyState{
				TargetRemoteKeyID:   "remote-old",
				MigratedRemoteKeyID: "remote-old",
			},
		},
	}
	status := operatorv1.KMSEncryptionStatus{
		HealthReports: []operatorv1.KMSPluginHealthReport{
			{KeyID: "3", RemoteKeyID: "remote-new"},
			{KeyID: "3", RemoteKeyID: "remote-new"},
		},
	}

	err := reconcileRemoteKeyRotation(context.Background(), client.CoreV1(), secret.Name, status, writeKey, clocktesting.NewFakeClock(now))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	updated, err := client.CoreV1().Secrets("openshift-config-managed").Get(context.Background(), secret.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get secret: %v", err)
	}
	rk, err := secrets.ReadRemoteKeyStateFromSecret(updated)
	if err != nil {
		t.Fatalf("read remote key annotations: %v", err)
	}
	if rk.TargetRemoteKeyID != "remote-old" {
		t.Fatalf("expected target unchanged, got %q", rk.TargetRemoteKeyID)
	}
	if rk.ConvergedID != "remote-new" || !rk.ConvergedAt.Equal(now) {
		t.Fatalf("expected convergence recorded for remote-new at %v, got %#v", now, rk)
	}
}

func TestReconcileRemoteKeyClearsConvergence(t *testing.T) {
	now := time.Date(2026, 8, 31, 10, 0, 0, 0, time.UTC)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   "openshift-config-managed",
			Name:        "encryption-key-test-3",
			Annotations: map[string]string{},
		},
	}
	setRemoteKeyAnnotations(t, secret.Annotations, state.RemoteKeyState{
		TargetRemoteKeyID:   "remote-old",
		MigratedRemoteKeyID: "remote-old",
		ConvergedID:         "remote-stale",
		ConvergedAt:         now.Add(-time.Hour),
	})
	client := fake.NewSimpleClientset(secret)

	writeKey := state.KeyState{
		Key:  apiserverconfigv1.Key{Name: "3", Secret: "c2VjcmV0"},
		Mode: state.KMS,
		KMS: &state.KMSState{
			RemoteKey: state.RemoteKeyState{
				TargetRemoteKeyID:   "remote-old",
				MigratedRemoteKeyID: "remote-old",
			},
		},
	}
	status := operatorv1.KMSEncryptionStatus{
		HealthReports: []operatorv1.KMSPluginHealthReport{
			{KeyID: "3", RemoteKeyID: "remote-old"},
			{KeyID: "3", RemoteKeyID: "remote-old"},
		},
	}

	err := reconcileRemoteKeyRotation(context.Background(), client.CoreV1(), secret.Name, status, writeKey, clocktesting.NewFakeClock(now))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	updated, err := client.CoreV1().Secrets("openshift-config-managed").Get(context.Background(), secret.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get secret: %v", err)
	}
	rk, err := secrets.ReadRemoteKeyStateFromSecret(updated)
	if err != nil {
		t.Fatalf("read remote key annotations: %v", err)
	}
	if rk.TargetRemoteKeyID != "remote-old" {
		t.Fatalf("expected target unchanged, got %q", rk.TargetRemoteKeyID)
	}
	if rk.ConvergedID != "" || !rk.ConvergedAt.IsZero() {
		t.Fatalf("expected convergence cleared when health matches target, got %#v", rk)
	}
}

func TestReconcileRemoteKeyIgnoresOtherKeyIDReports(t *testing.T) {
	now := time.Date(2026, 8, 31, 10, 0, 0, 0, time.UTC)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   "openshift-config-managed",
			Name:        "encryption-key-test-3",
			Annotations: map[string]string{},
		},
	}
	setRemoteKeyAnnotations(t, secret.Annotations, state.RemoteKeyState{
		TargetRemoteKeyID:   "remote-old",
		MigratedRemoteKeyID: "remote-old",
	})
	client := fake.NewSimpleClientset(secret)

	writeKey := state.KeyState{
		Key:  apiserverconfigv1.Key{Name: "3", Secret: "c2VjcmV0"},
		Mode: state.KMS,
		KMS: &state.KMSState{
			RemoteKey: state.RemoteKeyState{
				TargetRemoteKeyID:   "remote-old",
				MigratedRemoteKeyID: "remote-old",
			},
		},
	}
	// Write-key reports converge on remote-new; a different keyID still on remote-old
	// must not prevent recording convergence for the write key.
	status := operatorv1.KMSEncryptionStatus{
		HealthReports: []operatorv1.KMSPluginHealthReport{
			{KeyID: "3", RemoteKeyID: "remote-new"},
			{KeyID: "3", RemoteKeyID: "remote-new"},
			{KeyID: "2", RemoteKeyID: "remote-old"},
		},
	}

	err := reconcileRemoteKeyRotation(context.Background(), client.CoreV1(), secret.Name, status, writeKey, clocktesting.NewFakeClock(now))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	updated, err := client.CoreV1().Secrets("openshift-config-managed").Get(context.Background(), secret.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get secret: %v", err)
	}
	rk, err := secrets.ReadRemoteKeyStateFromSecret(updated)
	if err != nil {
		t.Fatalf("read remote key annotations: %v", err)
	}
	if rk.TargetRemoteKeyID != "remote-old" {
		t.Fatalf("expected target unchanged (no promote in this PR), got %q", rk.TargetRemoteKeyID)
	}
	if rk.ConvergedID != "remote-new" {
		t.Fatalf("expected write-key convergence on remote-new, got %q", rk.ConvergedID)
	}
}

func TestReconcileCurrentKeyChecksRemoteMigration(t *testing.T) {
	for _, tc := range []struct {
		name       string
		mode       state.Mode
		keyID      uint64
		remoteKey  state.RemoteKeyState
		wantUpdate bool
	}{
		{name: "blocked plan", mode: state.KMS},
		{name: "non-KMS mode", mode: state.AESCBC, keyID: 3},
		{name: "target equals migrated", mode: state.KMS, keyID: 3, remoteKey: state.RemoteKeyState{TargetRemoteKeyID: "a", MigratedRemoteKeyID: "a"}, wantUpdate: true},
		{name: "bootstrap", mode: state.KMS, keyID: 3, remoteKey: state.RemoteKeyState{TargetRemoteKeyID: "a"}},
		{name: "pending migration", mode: state.KMS, keyID: 3, remoteKey: state.RemoteKeyState{TargetRemoteKeyID: "b", MigratedRemoteKeyID: "a"}, wantUpdate: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			secret := newExistingKMSKeySecret(t, "test", newKMSVaultAPIServer(), []schema.GroupResource{{Resource: "secrets"}}, "3")
			setRemoteKeyAnnotations(t, secret.Annotations, tc.remoteKey)
			client := fake.NewSimpleClientset(secret)
			c := &keyController{secretClient: client.CoreV1()}
			// A skipped reconciliation must not even request health status.
			if tc.wantUpdate {
				c.encryptionStatusProvider = &fakeKMSStatusProvider{status: operatorv1.KMSEncryptionStatus{
					HealthReports: []operatorv1.KMSPluginHealthReport{{KeyID: "3", RemoteKeyID: "c"}},
				}}
			}
			snap := &KeyPlanningSnapshot{CurrentMode: tc.mode, State: EncryptionStateSnapshot{KeySecrets: []*corev1.Secret{secret}}}
			if err := c.reconcileCurrentKey(context.Background(), snap, tc.keyID); err != nil {
				t.Fatal(err)
			}
			if !tc.wantUpdate {
				if len(client.Actions()) != 0 {
					t.Fatalf("expected no Secret API calls, got %v", client.Actions())
				}
				return
			}
			updated, err := client.CoreV1().Secrets(secret.Namespace).Get(context.Background(), secret.Name, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if updated.Annotations[annotationRemoteKeyConvergedID] != "c" {
				t.Fatal("expected convergence recorded on the existing key")
			}
		})
	}
}
