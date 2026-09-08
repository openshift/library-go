package secrets

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/openshift/library-go/pkg/operator/encryption/state"
)

func TestPatchRemoteKeyAnnotationsPreservesOtherAnnotations(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "openshift-config-managed",
			Name:      "encryption-key-test-3",
			Annotations: map[string]string{
				EncryptionSecretTargetRemoteKeyID:   "remote-old",
				EncryptionSecretMigratedRemoteKeyID: "remote-old",
				EncryptionSecretMigratedTimestamp:   "2026-08-31T10:00:00Z",
			},
		},
	}
	client := fake.NewSimpleClientset(secret)

	err := PatchRemoteKeyAnnotations(context.Background(), client.CoreV1().Secrets(secret.Namespace), secret.Name, func(rk *RemoteKeyAnnotations) (bool, error) {
		rk.TargetRemoteKeyID = "remote-new"
		return true, nil
	})
	if err != nil {
		t.Fatalf("patch failed: %v", err)
	}

	updated, err := client.CoreV1().Secrets(secret.Namespace).Get(context.Background(), secret.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get secret: %v", err)
	}
	if updated.Annotations[EncryptionSecretTargetRemoteKeyID] != "remote-new" {
		t.Fatalf("target not updated")
	}
	if updated.Annotations[EncryptionSecretMigratedTimestamp] == "" {
		t.Fatal("expected migrated timestamp annotation to be preserved")
	}
}

func TestPatchRemoteKeyAnnotationsConcurrentWriters(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   "openshift-config-managed",
			Name:        "encryption-key-test-3",
			Annotations: map[string]string{},
		},
	}
	client := fake.NewSimpleClientset(secret)

	if err := PatchRemoteKeyAnnotations(context.Background(), client.CoreV1().Secrets(secret.Namespace), secret.Name, func(rk *RemoteKeyAnnotations) (bool, error) {
		rk.TargetRemoteKeyID = "remote-new"
		return true, nil
	}); err != nil {
		t.Fatalf("first patch failed: %v", err)
	}

	if err := PatchRemoteKeyAnnotations(context.Background(), client.CoreV1().Secrets(secret.Namespace), secret.Name, func(rk *RemoteKeyAnnotations) (bool, error) {
		rk.MigratedRemoteKeyID = "remote-new"
		return true, nil
	}); err != nil {
		t.Fatalf("second patch failed: %v", err)
	}

	updated, err := client.CoreV1().Secrets(secret.Namespace).Get(context.Background(), secret.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get secret: %v", err)
	}
	rk := state.RemoteKeyState{
		TargetRemoteKeyID:   updated.Annotations[EncryptionSecretTargetRemoteKeyID],
		MigratedRemoteKeyID: updated.Annotations[EncryptionSecretMigratedRemoteKeyID],
	}
	if rk.TargetRemoteKeyID != "remote-new" || rk.MigratedRemoteKeyID != "remote-new" {
		t.Fatalf("unexpected annotations: %#v", updated.Annotations)
	}
}
