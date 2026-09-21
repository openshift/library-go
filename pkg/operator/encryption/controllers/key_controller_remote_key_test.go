package controllers

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"

	operatorv1 "github.com/openshift/api/operator/v1"

	"github.com/openshift/library-go/pkg/operator/encryption/kms/health"
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

	changed, err := recordRemoteKeyConvergence(&rk, "remote-new", now)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("expected change when recording a new candidate")
	}
	if rk.ConvergedID != "remote-new" || !rk.ConvergedAt.Equal(now) {
		t.Fatalf("unexpected convergence: %#v", rk)
	}

	changed, err = recordRemoteKeyConvergence(&rk, "remote-new", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("expected no change when candidate already recorded")
	}
	if !rk.ConvergedAt.Equal(now) {
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

	changed, err := clearRemoteKeyConvergence(&rk)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("expected change when clearing convergence")
	}
	if rk.ConvergedID != "" || !rk.ConvergedAt.IsZero() {
		t.Fatalf("expected convergence cleared, got %#v", rk)
	}
	if rk.TargetRemoteKeyID != "remote-new" {
		t.Fatal("expected target to be preserved")
	}

	changed, err = clearRemoteKeyConvergence(&rk)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
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

	err := secrets.PatchRemoteKeyState(context.Background(), client.CoreV1().Secrets(secret.Namespace), secret.Name, func(rk *state.RemoteKeyState) (bool, error) {
		return advanceRemoteKeyConvergence(rk, "remote-new", now)
	})
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
	grs := []schema.GroupResource{{Resource: "secrets"}}
	secret := newExistingKMSKeySecret(t, "test", newKMSVaultAPIServer(), grs, "3")
	setRemoteKeyAnnotations(t, secret.Annotations, state.RemoteKeyState{
		TargetRemoteKeyID:   "remote-old",
		MigratedRemoteKeyID: "remote-old",
		ConvergedID:         "remote-stale",
		ConvergedAt:         now.Add(-time.Hour),
	})
	client := fake.NewSimpleClientset(secret)
	c := &keyController{
		secretClient: client.CoreV1(),
		encryptionStatusProvider: &fakeKMSStatusProvider{status: operatorv1.KMSEncryptionStatus{
			HealthReports: []operatorv1.KMSPluginHealthReport{
				{KeyID: "3", RemoteKeyID: "remote-old"},
				{KeyID: "3", RemoteKeyID: "remote-old"},
			},
		}},
	}
	snap := &KeyPlanningSnapshot{
		CurrentMode: state.KMS,
		State: EncryptionStateSnapshot{
			KeySecrets:   []*corev1.Secret{secret},
			EncryptedGRs: grs,
		},
	}
	if err := c.reconcileCurrentKey(context.Background(), snap, 3); err != nil {
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

	// Write-key reports converge on remote-new; a different keyID still on remote-old
	// must not prevent recording convergence for the write key.
	status := operatorv1.KMSEncryptionStatus{
		HealthReports: []operatorv1.KMSPluginHealthReport{
			{KeyID: "3", RemoteKeyID: "remote-new"},
			{KeyID: "3", RemoteKeyID: "remote-new"},
			{KeyID: "2", RemoteKeyID: "remote-old"},
		},
	}
	convergedRemoteKeyID := health.ConvergedRemoteKeyID(health.ReportsForKeyID(status.HealthReports, "3"))

	err := secrets.PatchRemoteKeyState(context.Background(), client.CoreV1().Secrets(secret.Namespace), secret.Name, func(rk *state.RemoteKeyState) (bool, error) {
		return advanceRemoteKeyConvergence(rk, convergedRemoteKeyID, now)
	})
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
		t.Fatalf("expected target unchanged before 5m elapsed, got %q", rk.TargetRemoteKeyID)
	}
	if rk.ConvergedID != "remote-new" {
		t.Fatalf("expected write-key convergence on remote-new, got %q", rk.ConvergedID)
	}
}

func TestReconcileRemoteKeyBootstrap(t *testing.T) {
	grs := []schema.GroupResource{{Resource: "secrets"}}
	status := operatorv1.KMSEncryptionStatus{
		HealthReports: []operatorv1.KMSPluginHealthReport{
			{KeyID: "3", RemoteKeyID: "remote-new"},
			{KeyID: "3", RemoteKeyID: "remote-new"},
		},
	}

	for _, tc := range []struct {
		name             string
		migratedGRs      []schema.GroupResource
		status           operatorv1.KMSEncryptionStatus
		wantMigrated     string
		wantSecretUpdate bool
	}{
		{
			name:             "waits for initial migration",
			migratedGRs:      nil,
			status:           status,
			wantMigrated:     "",
			wantSecretUpdate: false,
		},
		{
			name:             "waits for health convergence",
			migratedGRs:      grs,
			status:           operatorv1.KMSEncryptionStatus{},
			wantMigrated:     "",
			wantSecretUpdate: false,
		},
		{
			name:             "bootstraps migrated from target without requiring match",
			migratedGRs:      grs,
			status:           status,
			wantMigrated:     "remote-old",
			wantSecretUpdate: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			secret := newExistingKMSKeySecret(t, "test", newKMSVaultAPIServer(), tc.migratedGRs, "3")
			setRemoteKeyAnnotations(t, secret.Annotations, state.RemoteKeyState{
				TargetRemoteKeyID: "remote-old",
			})
			client := fake.NewSimpleClientset(secret)
			c := &keyController{
				secretClient:             client.CoreV1(),
				encryptionStatusProvider: &fakeKMSStatusProvider{status: tc.status},
			}
			snap := &KeyPlanningSnapshot{
				CurrentMode: state.KMS,
				State: EncryptionStateSnapshot{
					KeySecrets:   []*corev1.Secret{secret},
					EncryptedGRs: grs,
				},
			}
			if err := c.reconcileCurrentKey(context.Background(), snap, 3); err != nil {
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
			if rk.MigratedRemoteKeyID != tc.wantMigrated {
				t.Fatalf("migrated-remote-key-id=%q, want %q", rk.MigratedRemoteKeyID, tc.wantMigrated)
			}
			if rk.TargetRemoteKeyID != "remote-old" {
				t.Fatalf("expected target unchanged during bootstrap, got %q", rk.TargetRemoteKeyID)
			}
			if tc.wantSecretUpdate && (rk.ConvergedID != "" || !rk.ConvergedAt.IsZero()) {
				t.Fatalf("bootstrap must not start the convergence clock, got %#v", rk)
			}
			gotUpdate := false
			for _, action := range client.Actions() {
				if action.Matches("update", "secrets") {
					gotUpdate = true
				}
			}
			if gotUpdate != tc.wantSecretUpdate {
				t.Fatalf("secret update=%v, want %v", gotUpdate, tc.wantSecretUpdate)
			}
		})
	}
}

func TestReconcileRemoteKeyPromotesTargetAfterConvergence(t *testing.T) {
	now := time.Date(2026, 8, 31, 10, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		name          string
		remoteKey     state.RemoteKeyState
		clockNow      time.Time
		wantTarget    string
		wantConverged string
	}{
		{
			name: "records clock when under 5m",
			remoteKey: state.RemoteKeyState{
				TargetRemoteKeyID:   "remote-old",
				MigratedRemoteKeyID: "remote-old",
			},
			clockNow:      now,
			wantTarget:    "remote-old",
			wantConverged: "remote-new",
		},
		{
			name: "promotes target after 5m",
			remoteKey: state.RemoteKeyState{
				TargetRemoteKeyID:   "remote-old",
				MigratedRemoteKeyID: "remote-old",
				ConvergedID:         "remote-new",
				ConvergedAt:         now,
			},
			clockNow:      now.Add(remoteKeyConvergenceDuration),
			wantTarget:    "remote-new",
			wantConverged: "",
		},
		{
			name: "does not promote while needsMigration",
			remoteKey: state.RemoteKeyState{
				TargetRemoteKeyID:   "remote-a",
				MigratedRemoteKeyID: "remote-old",
				ConvergedID:         "remote-new",
				ConvergedAt:         now,
			},
			clockNow:      now.Add(remoteKeyConvergenceDuration),
			wantTarget:    "remote-a",
			wantConverged: "remote-new",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace:   "openshift-config-managed",
					Name:        "encryption-key-test-3",
					Annotations: map[string]string{},
				},
			}
			setRemoteKeyAnnotations(t, secret.Annotations, tc.remoteKey)
			client := fake.NewSimpleClientset(secret)

			err := secrets.PatchRemoteKeyState(context.Background(), client.CoreV1().Secrets(secret.Namespace), secret.Name, func(rk *state.RemoteKeyState) (bool, error) {
				return advanceRemoteKeyConvergence(rk, "remote-new", tc.clockNow)
			})
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
			if rk.TargetRemoteKeyID != tc.wantTarget {
				t.Fatalf("target=%q, want %q", rk.TargetRemoteKeyID, tc.wantTarget)
			}
			if rk.ConvergedID != tc.wantConverged {
				t.Fatalf("converged-id=%q, want %q", rk.ConvergedID, tc.wantConverged)
			}
			if tc.wantConverged == "" && !rk.ConvergedAt.IsZero() {
				t.Fatalf("expected convergence cleared, got %#v", rk)
			}
		})
	}
}

func TestReconcileCurrentKeyChecksRemoteMigration(t *testing.T) {
	grs := []schema.GroupResource{{Resource: "secrets"}}
	for _, tc := range []struct {
		name       string
		mode       state.Mode
		keyID      uint64
		remoteKey  state.RemoteKeyState
		wantUpdate bool
	}{
		{name: "blocked plan", mode: state.KMS},
		{name: "non-KMS mode", mode: state.AESCBC, keyID: 3},
		{name: "no target", mode: state.KMS, keyID: 3},
		{name: "steady key", mode: state.KMS, keyID: 3, remoteKey: state.RemoteKeyState{TargetRemoteKeyID: "a", MigratedRemoteKeyID: "a"}, wantUpdate: true},
		{name: "bootstrap", mode: state.KMS, keyID: 3, remoteKey: state.RemoteKeyState{TargetRemoteKeyID: "a"}, wantUpdate: true},
		{name: "pending migration", mode: state.KMS, keyID: 3, remoteKey: state.RemoteKeyState{TargetRemoteKeyID: "b", MigratedRemoteKeyID: "a"}, wantUpdate: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			secret := newExistingKMSKeySecret(t, "test", newKMSVaultAPIServer(), grs, "3")
			setRemoteKeyAnnotations(t, secret.Annotations, tc.remoteKey)
			client := fake.NewSimpleClientset(secret)
			c := &keyController{secretClient: client.CoreV1()}
			if tc.wantUpdate {
				c.encryptionStatusProvider = &fakeKMSStatusProvider{status: operatorv1.KMSEncryptionStatus{
					HealthReports: []operatorv1.KMSPluginHealthReport{{KeyID: "3", RemoteKeyID: "c"}},
				}}
			}
			snap := &KeyPlanningSnapshot{
				CurrentMode: tc.mode,
				State: EncryptionStateSnapshot{
					KeySecrets:   []*corev1.Secret{secret},
					EncryptedGRs: grs,
				},
			}
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
			rk, err := secrets.ReadRemoteKeyStateFromSecret(updated)
			if err != nil {
				t.Fatal(err)
			}
			switch tc.name {
			case "bootstrap":
				if rk.MigratedRemoteKeyID != "a" {
					t.Fatalf("expected bootstrap migrated-remote-key-id=a, got %#v", rk)
				}
			case "steady key", "pending migration":
				if rk.ConvergedID != "c" {
					t.Fatalf("expected convergence recorded on the existing key, got %#v", rk)
				}
			}
		})
	}
}
