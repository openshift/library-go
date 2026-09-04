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
				EncryptionSecretTargetRemoteKeyID:    "remote-old",
				EncryptionSecretMigratedRemoteKeyID:  "remote-old",
				EncryptionSecretRemoteKeyConvergedID: "remote-new",
				EncryptionSecretRemoteKeyConvergedAt: ts.Format(time.RFC3339),
			},
		},
	}

	got, err := ReadRemoteKeyAnnotations(secret)
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

func TestNeedsRemoteKeyMigration(t *testing.T) {
	scenarios := []struct {
		name string
		rk   state.RemoteKeyState
		want bool
	}{
		{name: "unset migrated", rk: state.RemoteKeyState{TargetRemoteKeyID: "a"}, want: false},
		{name: "equal", rk: state.RemoteKeyState{TargetRemoteKeyID: "a", MigratedRemoteKeyID: "a"}, want: false},
		{name: "differs", rk: state.RemoteKeyState{TargetRemoteKeyID: "b", MigratedRemoteKeyID: "a"}, want: true},
	}
	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			if got := NeedsRemoteKeyMigration(scenario.rk); got != scenario.want {
				t.Fatalf("got %v want %v", got, scenario.want)
			}
		})
	}
}

func TestMigrationWriteKeyName(t *testing.T) {
	scenarios := []struct {
		name    string
		keyName string
		rk      state.RemoteKeyState
		want    string
	}{
		{
			name:    "first enablement",
			keyName: "3",
			rk:      state.RemoteKeyState{TargetRemoteKeyID: "remote-old"},
			want:    "3",
		},
		{
			name:    "rotation",
			keyName: "3",
			rk:      state.RemoteKeyState{TargetRemoteKeyID: "remote-new", MigratedRemoteKeyID: "remote-old"},
			want:    "3-remote-new",
		},
	}
	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			if got := MigrationWriteKeyName(scenario.keyName, scenario.rk); got != scenario.want {
				t.Fatalf("got %q want %q", got, scenario.want)
			}
		})
	}
}

func TestRemoteKeyIDFromMigrationWriteKey(t *testing.T) {
	got, ok := RemoteKeyIDFromMigrationWriteKey("3", "3-remote-new")
	if !ok || got != "remote-new" {
		t.Fatalf("got %q ok=%v", got, ok)
	}
	_, ok = RemoteKeyIDFromMigrationWriteKey("3", "3")
	if ok {
		t.Fatal("expected false for plain key name")
	}
}

func TestApplyRemoteKeyAnnotationsClearsEmptyValues(t *testing.T) {
	annotations := map[string]string{
		EncryptionSecretTargetRemoteKeyID: "old",
	}
	ApplyRemoteKeyAnnotations(annotations, state.RemoteKeyState{})
	if _, ok := annotations[EncryptionSecretTargetRemoteKeyID]; ok {
		t.Fatal("expected target annotation to be removed")
	}
}
