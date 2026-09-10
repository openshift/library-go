package secrets

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openshift/library-go/pkg/operator/encryption/state"
)

func TestReadRemoteKeyAnnotations(t *testing.T) {
	ts := time.Date(2026, 8, 31, 10, 0, 0, 0, time.UTC)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "openshift-config-managed",
			Name:      "encryption-key-test-1",
			Annotations: map[string]string{
				encryptionSecretTargetRemoteKeyID:    "remote-old",
				encryptionSecretMigratedRemoteKeyID:  "remote-old",
				encryptionSecretRemoteKeyConvergedID: "remote-new",
				encryptionSecretRemoteKeyConvergedAt: ts.Format(time.RFC3339),
			},
		},
	}

	got, err := ReadRemoteKeyStateFromSecret(secret)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.TargetRemoteKeyID != "remote-old" || got.MigratedRemoteKeyID != "remote-old" {
		t.Fatalf("unexpected ids: %#v", got)
	}
	if got.ConvergedID != "remote-new" || !got.ConvergedAt.Equal(ts) {
		t.Fatalf("unexpected convergence: %#v", got)
	}
}

func TestReadRemoteKeyAnnotationsInvalidConvergence(t *testing.T) {
	tests := []struct {
		name      string
		id        string
		at        time.Time
		expectErr bool
	}{
		{name: "both default", id: "", at: time.Time{}, expectErr: false},
		{name: "only id", id: "id", at: time.Time{}, expectErr: true},
		{name: "only time", id: "", at: time.Now(), expectErr: true},
		{name: "both set", id: "id", at: time.Now(), expectErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "openshift-config-managed",
					Name:      "encryption-key-test-1",
					Annotations: map[string]string{
						encryptionSecretRemoteKeyConvergedID: tt.id,
						encryptionSecretRemoteKeyConvergedAt: tt.at.Format(time.RFC3339),
					},
				},
			}

			_, err := ReadRemoteKeyStateFromSecret(secret)
			if tt.expectErr && err == nil {
				t.Errorf("expected error but got nil")
			} else if !tt.expectErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestInvalidRemoteKeyAnnotationBeforeSetting(t *testing.T) {
	err := applyRemoteKeyAnnotations(make(map[string]string), state.RemoteKeyState{
		ConvergedAt: time.Time{},
		ConvergedID: "1337",
	})
	if err == nil {
		t.Errorf("expected error but got nil")
	}
}

func TestApplyRemoteKeyAnnotations(t *testing.T) {
	now := time.Now()
	nowStr := now.Format(time.RFC3339)
	annotations := map[string]string{
		encryptionSecretTargetRemoteKeyID:    "remove",
		encryptionSecretMigratedRemoteKeyID:  "keep",
		encryptionSecretRemoteKeyConvergedID: "old",
		encryptionSecretRemoteKeyConvergedAt: nowStr,
	}
	err := applyRemoteKeyAnnotations(annotations, state.RemoteKeyState{
		TargetRemoteKeyID:   "", // should remove
		MigratedRemoteKeyID: "keep",
		ConvergedAt:         now,
		// updated with a new key
		ConvergedID: "new-key",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := annotations[encryptionSecretTargetRemoteKeyID]; ok {
		t.Fatal("expected target annotation to be removed")
	}
	if annotations[encryptionSecretMigratedRemoteKeyID] != "keep" {
		t.Fatalf("expected annotation %s to stay", encryptionSecretMigratedRemoteKeyID)
	}
	if annotations[encryptionSecretRemoteKeyConvergedID] != "new-key" {
		t.Fatalf("expected annotation %s to update", encryptionSecretRemoteKeyConvergedID)
	}
	if annotations[encryptionSecretRemoteKeyConvergedAt] != nowStr {
		t.Fatalf("expected annotation %s to stay", encryptionSecretRemoteKeyConvergedAt)
	}
}
