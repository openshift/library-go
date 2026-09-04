package secrets

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func mustParseRFC3339(t *testing.T, value string) time.Time {
	t.Helper()

	ts, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatalf("failed to parse %q as RFC3339: %v", value, err)
	}
	return ts
}

func TestReadRemoteKeyAnnotations(t *testing.T) {
	convergedAt := mustParseRFC3339(t, "2026-01-15T10:00:00Z")

	tests := []struct {
		name    string
		secret  *corev1.Secret
		want    RemoteKeyAnnotations
		wantErr bool
	}{
		{
			name:   "nil secret",
			secret: nil,
			want:   RemoteKeyAnnotations{},
		},
		{
			name: "empty annotations",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "encryption-key-kms-3", Namespace: "openshift-config-managed"},
			},
			want: RemoteKeyAnnotations{},
		},
		{
			name: "full annotations",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "encryption-key-kms-3",
					Namespace: "openshift-config-managed",
					Annotations: map[string]string{
						EncryptionSecretTargetRemoteKeyID:    "remote-key-new",
						EncryptionSecretMigratedRemoteKeyID:  "remote-key-old",
						EncryptionSecretRemoteKeyConvergedAt: "2026-01-15T10:00:00Z",
						EncryptionSecretRemoteKeyConvergedID: "remote-key-new",
					},
				},
			},
			want: RemoteKeyAnnotations{
				TargetRemoteKeyID:   "remote-key-new",
				MigratedRemoteKeyID: "remote-key-old",
				ConvergedAt:         convergedAt,
				ConvergedID:         "remote-key-new",
			},
		},
		{
			name: "invalid converged timestamp",
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "encryption-key-kms-3",
					Namespace: "openshift-config-managed",
					Annotations: map[string]string{
						EncryptionSecretRemoteKeyConvergedAt: "not-a-timestamp",
					},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ReadRemoteKeyAnnotations(tt.secret)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ReadRemoteKeyAnnotations() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if got != tt.want {
				t.Fatalf("ReadRemoteKeyAnnotations() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestApplyRemoteKeyAnnotations(t *testing.T) {
	convergedAt := mustParseRFC3339(t, "2026-01-15T10:00:00Z")

	annotations := map[string]string{
		EncryptionSecretTargetRemoteKeyID:    "stale-target",
		EncryptionSecretMigratedRemoteKeyID:  "stale-migrated",
		EncryptionSecretRemoteKeyConvergedAt: "2020-01-01T00:00:00Z",
		EncryptionSecretRemoteKeyConvergedID: "stale-converged",
		"other.example.com/annotation":       "keep-me",
	}

	ApplyRemoteKeyAnnotations(annotations, RemoteKeyAnnotations{
		TargetRemoteKeyID:   "remote-key-new",
		MigratedRemoteKeyID: "remote-key-new",
	})

	if annotations[EncryptionSecretTargetRemoteKeyID] != "remote-key-new" {
		t.Fatalf("target annotation = %q, want %q", annotations[EncryptionSecretTargetRemoteKeyID], "remote-key-new")
	}
	if annotations[EncryptionSecretMigratedRemoteKeyID] != "remote-key-new" {
		t.Fatalf("migrated annotation = %q, want %q", annotations[EncryptionSecretMigratedRemoteKeyID], "remote-key-new")
	}
	if _, ok := annotations[EncryptionSecretRemoteKeyConvergedAt]; ok {
		t.Fatalf("converged-at annotation should be removed")
	}
	if _, ok := annotations[EncryptionSecretRemoteKeyConvergedID]; ok {
		t.Fatalf("converged-id annotation should be removed")
	}
	if annotations["other.example.com/annotation"] != "keep-me" {
		t.Fatalf("unrelated annotation was modified")
	}

	ApplyRemoteKeyAnnotations(annotations, RemoteKeyAnnotations{
		TargetRemoteKeyID:   "remote-key-new",
		MigratedRemoteKeyID: "remote-key-old",
		ConvergedAt:         convergedAt,
		ConvergedID:         "remote-key-new",
	})
	got, err := ReadRemoteKeyAnnotations(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Annotations: annotations}})
	if err != nil {
		t.Fatalf("ReadRemoteKeyAnnotations() error = %v", err)
	}
	if got.TargetRemoteKeyID != "remote-key-new" || got.MigratedRemoteKeyID != "remote-key-old" || got.ConvergedID != "remote-key-new" || !got.ConvergedAt.Equal(convergedAt) {
		t.Fatalf("roundtrip through Apply/Read = %#v", got)
	}
}
func TestTargetDiffersFromMigrated(t *testing.T) {
	tests := []struct {
		name string
		rk   RemoteKeyAnnotations
		want bool
	}{
		{
			name: "first enablement with target only",
			rk: RemoteKeyAnnotations{
				TargetRemoteKeyID: "remote-key-old",
			},
			want: false,
		},
		{
			name: "steady state",
			rk: RemoteKeyAnnotations{
				TargetRemoteKeyID:   "remote-key-old",
				MigratedRemoteKeyID: "remote-key-old",
			},
			want: false,
		},
		{
			name: "rotation in progress",
			rk: RemoteKeyAnnotations{
				TargetRemoteKeyID:   "remote-key-new",
				MigratedRemoteKeyID: "remote-key-old",
			},
			want: true,
		},
		{
			name: "empty target with migrated set",
			rk: RemoteKeyAnnotations{
				MigratedRemoteKeyID: "remote-key-old",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := TargetDiffersFromMigrated(tt.rk); got != tt.want {
				t.Fatalf("TargetDiffersFromMigrated() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsBootstrapped(t *testing.T) {
	tests := []struct {
		name string
		rk   RemoteKeyAnnotations
		want bool
	}{
		{
			name: "first enablement",
			rk: RemoteKeyAnnotations{
				TargetRemoteKeyID: "remote-key-old",
			},
			want: false,
		},
		{
			name: "bootstrapped",
			rk: RemoteKeyAnnotations{
				TargetRemoteKeyID:   "remote-key-old",
				MigratedRemoteKeyID: "remote-key-old",
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsBootstrapped(tt.rk); got != tt.want {
				t.Fatalf("IsBootstrapped() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMigrationWriteKeyName(t *testing.T) {
	tests := []struct {
		name    string
		keyName string
		rk      RemoteKeyAnnotations
		want    string
	}{
		{
			name:    "first enablement keeps plain key name",
			keyName: "3",
			rk: RemoteKeyAnnotations{
				TargetRemoteKeyID: "remote-key-old",
			},
			want: "3",
		},
		{
			name:    "steady state keeps plain key name",
			keyName: "3",
			rk: RemoteKeyAnnotations{
				TargetRemoteKeyID:   "remote-key-old",
				MigratedRemoteKeyID: "remote-key-old",
			},
			want: "3",
		},
		{
			name:    "rotation uses suffixed key name",
			keyName: "3",
			rk: RemoteKeyAnnotations{
				TargetRemoteKeyID:   "remote-key-new",
				MigratedRemoteKeyID: "remote-key-old",
			},
			want: "3-remote-key-new",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MigrationWriteKeyName(tt.keyName, tt.rk); got != tt.want {
				t.Fatalf("MigrationWriteKeyName() = %q, want %q", got, tt.want)
			}
		})
	}
}
