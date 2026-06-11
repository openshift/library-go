package secrets

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestNeedsKekMigration(t *testing.T) {
	tests := []struct {
		name   string
		secret *corev1.Secret
		want   bool
	}{
		{
			name:   "nil secret",
			secret: nil,
			want:   false,
		},
		{
			name:   "no annotations",
			secret: &corev1.Secret{},
			want:   false,
		},
		{
			name: "steady state",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						EncryptionSecretTargetKekID:   "kek-old",
						EncryptionSecretMigratedKekID: "kek-old",
					},
				},
			},
			want: false,
		},
		{
			name: "rotation in flight",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						EncryptionSecretTargetKekID:   "kek-new",
						EncryptionSecretMigratedKekID: "kek-old",
					},
				},
			},
			want: true,
		},
		{
			name: "target only",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						EncryptionSecretTargetKekID: "kek-new",
					},
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NeedsKekMigration(tt.secret); got != tt.want {
				t.Fatalf("NeedsKekMigration() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMigrationWriteKey(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				EncryptionSecretTargetKekID: "kek-new",
			},
		},
	}
	if got := MigrationWriteKey("8", secret); got != "8-kek-new" {
		t.Fatalf("MigrationWriteKey() = %q, want %q", got, "8-kek-new")
	}
	if got := MigrationWriteKey("8", &corev1.Secret{}); got != "8" {
		t.Fatalf("MigrationWriteKey() without target = %q, want %q", got, "8")
	}
}

func TestKekMigrationFromSecret(t *testing.T) {
	ts := time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				EncryptionSecretTargetKekID:    "kek-target",
				EncryptionSecretMigratedKekID:  "kek-migrated",
				EncryptionSecretKekConvergedID:   "kek-candidate",
				EncryptionSecretKekConvergedAt: ts.Format(time.RFC3339),
			},
		},
	}
	got := KekMigrationFromSecret(secret)
	if got.TargetKekID != "kek-target" || got.MigratedKekID != "kek-migrated" || got.KekConvergedID != "kek-candidate" {
		t.Fatalf("unexpected kek migration state: %#v", got)
	}
	if !got.KekConvergedAt.Equal(ts) {
		t.Fatalf("KekConvergedAt = %v, want %v", got.KekConvergedAt, ts)
	}
}
