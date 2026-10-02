package controllers

import (
	"context"
	"fmt"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
	clocktesting "k8s.io/utils/clock/testing"

	operatorv1 "github.com/openshift/api/operator/v1"
	apiserverconfigv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"

	"github.com/openshift/library-go/pkg/operator/encryption/kms"
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

func TestReconcileInPlaceFieldUpdate(t *testing.T) {
	// The stored key carries the baseline vault config, AppRole credentials, and CA bundle.
	storedPlugin := kms.KMSPluginConfig{
		TypeMeta: metav1.TypeMeta{APIVersion: kms.SchemeGroupVersion.String(), Kind: "KMSPluginConfig"},
		Type:     kms.VaultKMSProvider,
		Vault:    wellKnownBaseVaultConfig,
	}
	storedPlugin.Vault.VaultKeyPath = "transit/keys/old-key"

	for _, tc := range []struct {
		name       string
		refSecret  map[string][]byte
		refCM      map[string]string
		wantUpdate bool
	}{
		{
			name:       "no change is a no-op",
			refSecret:  map[string][]byte{"role-id": []byte("old-role-id"), "secret-id": []byte("old-secret-id")},
			refCM:      map[string]string{"ca-bundle.crt": "old-ca-cert"},
			wantUpdate: false,
		},
		{
			name:       "rotated referenced credential writes in place",
			refSecret:  map[string][]byte{"role-id": []byte("new-role-id"), "secret-id": []byte("new-secret-id")},
			refCM:      map[string]string{"ca-bundle.crt": "old-ca-cert"},
			wantUpdate: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			secret := newExistingKMSKeySecret(t, "test", newKMSVaultAPIServer(), []schema.GroupResource{{Resource: "secrets"}}, "3")
			// Annotations (remote-key rotation plus an unrelated one) must survive an in-place
			// Data write — the writer only ever rewrites s.Data.
			secret.Annotations["example.com/unrelated"] = "keep-me"
			setRemoteKeyAnnotations(t, secret.Annotations, state.RemoteKeyState{TargetRemoteKeyID: "remote-old", MigratedRemoteKeyID: "remote-old"})
			currentKey, err := secrets.ToKeyState(secret)
			if err != nil {
				t.Fatal(err)
			}
			providerCfg, err := newKMSProviderConfig(storedPlugin, 1)
			if err != nil {
				t.Fatal(err)
			}
			refSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: openshiftConfigNS, Name: "vault-approle"},
				Data:       tc.refSecret,
			}
			refCM := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Namespace: openshiftConfigNS, Name: "vault-ca-bundle"},
				Data:       tc.refCM,
			}
			client := fake.NewSimpleClientset(secret, refSecret, refCM)
			c := &keyController{secretClient: client.CoreV1(), configMapClient: client.CoreV1()}
			snap := &KeyPlanningSnapshot{
				CurrentMode:        state.KMS,
				PluginConfig:       storedPlugin,
				desiredProviderCfg: providerCfg,
				State:              EncryptionStateSnapshot{KeySecrets: []*corev1.Secret{secret}},
			}

			updated, err := c.reconcileInPlaceFieldUpdate(context.Background(), snap, secret, currentKey)
			if err != nil {
				t.Fatal(err)
			}
			if updated != tc.wantUpdate {
				t.Fatalf("expected updated=%v, got %v", tc.wantUpdate, updated)
			}

			gotUpdate := false
			for _, a := range client.Actions() {
				if a.GetVerb() == "update" {
					gotUpdate = true
				}
			}
			if gotUpdate != tc.wantUpdate {
				t.Fatalf("expected Secret Update=%v, got actions %v", tc.wantUpdate, client.Actions())
			}
			if !tc.wantUpdate {
				return
			}

			persisted, err := client.CoreV1().Secrets(secret.Namespace).Get(context.Background(), secret.Name, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			ks, err := secrets.ToKeyState(persisted)
			if err != nil {
				t.Fatal(err)
			}
			if got := string(ks.KMS.PluginSecretData.FlatEntries()["vault-approle_role-id"]); got != "new-role-id" {
				t.Fatalf("expected rotated role-id to be carried into the key secret, got %q", got)
			}
			if persisted.Annotations["example.com/unrelated"] != "keep-me" {
				t.Fatalf("expected unrelated annotation to be preserved, got %#v", persisted.Annotations)
			}
			if persisted.Annotations[annotationTargetRemoteKeyID] != "remote-old" || persisted.Annotations[annotationMigratedRemoteKeyID] != "remote-old" {
				t.Fatalf("expected remote-key annotations to be preserved, got %#v", persisted.Annotations)
			}
		})
	}
}

// TestReconcileInPlaceFieldUpdateDefersOnConflict asserts that a conflicting Update is not
// retried inline: the in-place path reports it owns the sync (so rotation is skipped) and
// returns no error, deferring the write to the next sync.
func TestReconcileInPlaceFieldUpdateDefersOnConflict(t *testing.T) {
	storedPlugin := kms.KMSPluginConfig{
		TypeMeta: metav1.TypeMeta{APIVersion: kms.SchemeGroupVersion.String(), Kind: "KMSPluginConfig"},
		Type:     kms.VaultKMSProvider,
		Vault:    wellKnownBaseVaultConfig,
	}
	storedPlugin.Vault.VaultKeyPath = "transit/keys/old-key"

	secret := newExistingKMSKeySecret(t, "test", newKMSVaultAPIServer(), []schema.GroupResource{{Resource: "secrets"}}, "3")
	currentKey, err := secrets.ToKeyState(secret)
	if err != nil {
		t.Fatal(err)
	}
	providerCfg, err := newKMSProviderConfig(storedPlugin, 1)
	if err != nil {
		t.Fatal(err)
	}
	// A rotated referenced credential forces an in-place write attempt.
	refSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: openshiftConfigNS, Name: "vault-approle"},
		Data:       map[string][]byte{"role-id": []byte("new-role-id"), "secret-id": []byte("new-secret-id")},
	}
	refCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: openshiftConfigNS, Name: "vault-ca-bundle"},
		Data:       map[string]string{"ca-bundle.crt": "old-ca-cert"},
	}
	client := fake.NewSimpleClientset(secret, refSecret, refCM)
	updates := 0
	client.PrependReactor("update", "secrets", func(action clienttesting.Action) (bool, runtime.Object, error) {
		updates++
		return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "secrets"}, secret.Name, fmt.Errorf("conflict"))
	})

	c := &keyController{instanceName: "test", secretClient: client.CoreV1(), configMapClient: client.CoreV1()}
	snap := &KeyPlanningSnapshot{
		CurrentMode:        state.KMS,
		PluginConfig:       storedPlugin,
		desiredProviderCfg: providerCfg,
		State:              EncryptionStateSnapshot{KeySecrets: []*corev1.Secret{secret}},
	}

	owned, err := c.reconcileInPlaceFieldUpdate(context.Background(), snap, secret, currentKey)
	if err != nil {
		t.Fatalf("expected conflict to be swallowed, got error: %v", err)
	}
	if !owned {
		t.Fatal("expected in-place path to own the sync (skip rotation) on conflict")
	}
	if updates != 1 {
		t.Fatalf("expected exactly one Update attempt (no inline retry), got %d", updates)
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

			// Build the snapshot's plugin config to exactly match the stored secret so
			// the carry-over refresh is a no-op and only remote-key state can trigger a write.
			storedPlugin := kms.KMSPluginConfig{
				TypeMeta: metav1.TypeMeta{APIVersion: kms.SchemeGroupVersion.String(), Kind: "KMSPluginConfig"},
				Type:     kms.VaultKMSProvider,
				Vault:    wellKnownBaseVaultConfig,
			}
			storedPlugin.Vault.VaultKeyPath = "transit/keys/old-key"
			providerCfg, err := newKMSProviderConfig(storedPlugin, 1)
			if err != nil {
				t.Fatal(err)
			}
			// Referenced resources carrying the same values the stored key secret holds.
			refSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: openshiftConfigNS, Name: "vault-approle"},
				Data:       map[string][]byte{"role-id": []byte("old-role-id"), "secret-id": []byte("old-secret-id")},
			}
			refCM := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Namespace: openshiftConfigNS, Name: "vault-ca-bundle"},
				Data:       map[string]string{"ca-bundle.crt": "old-ca-cert"},
			}
			client := fake.NewSimpleClientset(secret, refSecret, refCM)
			c := &keyController{secretClient: client.CoreV1(), configMapClient: client.CoreV1()}
			// A skipped reconciliation must not even request health status.
			if tc.wantUpdate {
				c.encryptionStatusProvider = &fakeKMSStatusProvider{status: operatorv1.KMSEncryptionStatus{
					HealthReports: []operatorv1.KMSPluginHealthReport{{KeyID: "3", RemoteKeyID: "c"}},
				}}
			}
			snap := &KeyPlanningSnapshot{
				CurrentMode:        tc.mode,
				PluginConfig:       storedPlugin,
				desiredProviderCfg: providerCfg,
				State:              EncryptionStateSnapshot{KeySecrets: []*corev1.Secret{secret}},
			}
			if err := c.reconcileCurrentKey(context.Background(), snap, tc.keyID); err != nil {
				t.Fatal(err)
			}
			// The carry-over matches the stored secret, so no case should ever Update the key.
			for _, a := range client.Actions() {
				if a.GetVerb() == "update" && !tc.wantUpdate {
					t.Fatalf("expected no Secret Update, got %v", client.Actions())
				}
			}
			if !tc.wantUpdate {
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
