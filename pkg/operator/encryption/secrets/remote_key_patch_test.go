package secrets

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"

	"github.com/openshift/library-go/pkg/operator/encryption/state"
)

func countUpdates(actions []clienttesting.Action) int {
	n := 0
	for _, a := range actions {
		if a.GetVerb() == "update" {
			n++
		}
	}
	return n
}

// remoteKeySecretFixture builds a key secret carrying only the given annotations.
// PatchRemoteKeyState reads and writes annotations exclusively, so the fixtures need
// nothing beyond ObjectMeta.
func remoteKeySecretFixture(annotations map[string]string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   "openshift-config-managed",
			Name:        "encryption-key-test-3",
			Annotations: annotations,
		},
	}
}

func TestPatchRemoteKeyStateNoChangeNoUpdate(t *testing.T) {
	secret := remoteKeySecretFixture(map[string]string{
		encryptionSecretTargetRemoteKeyID:   "remote-old",
		encryptionSecretMigratedRemoteKeyID: "remote-old",
	})
	client := fake.NewSimpleClientset(secret)

	if err := PatchRemoteKeyState(context.Background(), client.CoreV1().Secrets(secret.Namespace), secret.Name, func(rk *state.RemoteKeyState) (bool, error) {
		return false, nil
	}); err != nil {
		t.Fatalf("patch failed: %v", err)
	}
	if got := countUpdates(client.Actions()); got != 0 {
		t.Fatalf("expected no Update when remote key reports no change, got %d", got)
	}
}

func TestPatchRemoteKeyStateChangePreservesOtherAnnotations(t *testing.T) {
	secret := remoteKeySecretFixture(map[string]string{
		encryptionSecretTargetRemoteKeyID:   "remote-old",
		encryptionSecretMigratedRemoteKeyID: "remote-old",
		EncryptionSecretMigratedTimestamp:   "2026-08-31T10:00:00Z",
	})
	client := fake.NewSimpleClientset(secret)

	if err := PatchRemoteKeyState(context.Background(), client.CoreV1().Secrets(secret.Namespace), secret.Name, func(rk *state.RemoteKeyState) (bool, error) {
		rk.TargetRemoteKeyID = "remote-new"
		return true, nil
	}); err != nil {
		t.Fatalf("patch failed: %v", err)
	}
	if got := countUpdates(client.Actions()); got != 1 {
		t.Fatalf("expected a single Update, got %d", got)
	}

	updated, err := client.CoreV1().Secrets(secret.Namespace).Get(context.Background(), secret.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get secret: %v", err)
	}
	if updated.Annotations[encryptionSecretTargetRemoteKeyID] != "remote-new" {
		t.Fatal("target not updated")
	}
	if updated.Annotations[EncryptionSecretMigratedTimestamp] == "" {
		t.Fatal("expected migrated timestamp annotation to be preserved")
	}
}

func TestPatchRemoteKeyStateSequentialWriters(t *testing.T) {
	secret := remoteKeySecretFixture(map[string]string{})
	client := fake.NewSimpleClientset(secret)

	if err := PatchRemoteKeyState(context.Background(), client.CoreV1().Secrets(secret.Namespace), secret.Name, func(rk *state.RemoteKeyState) (bool, error) {
		rk.TargetRemoteKeyID = "remote-new"
		return true, nil
	}); err != nil {
		t.Fatalf("first patch failed: %v", err)
	}
	if err := PatchRemoteKeyState(context.Background(), client.CoreV1().Secrets(secret.Namespace), secret.Name, func(rk *state.RemoteKeyState) (bool, error) {
		rk.MigratedRemoteKeyID = "remote-new"
		return true, nil
	}); err != nil {
		t.Fatalf("second patch failed: %v", err)
	}

	updated, err := client.CoreV1().Secrets(secret.Namespace).Get(context.Background(), secret.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get secret: %v", err)
	}
	if updated.Annotations[encryptionSecretTargetRemoteKeyID] != "remote-new" || updated.Annotations[encryptionSecretMigratedRemoteKeyID] != "remote-new" {
		t.Fatalf("unexpected annotations: %#v", updated.Annotations)
	}
}
