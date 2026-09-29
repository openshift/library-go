package secrets

import (
	"context"
	"fmt"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"

	"github.com/openshift/library-go/pkg/operator/encryption/state"
)

func TestPatchRemoteKeyAnnotationsPreservesOtherAnnotations(t *testing.T) {
	const migratedTimestamp = "2026-08-31T10:00:00Z"
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "openshift-config-managed",
			Name:      "encryption-key-test-3",
			Annotations: map[string]string{
				encryptionSecretTargetRemoteKeyID:   "remote-old",
				encryptionSecretMigratedRemoteKeyID: "remote-old",
				EncryptionSecretMigratedTimestamp:   migratedTimestamp,
			},
		},
	}
	client := fake.NewSimpleClientset(secret)

	err := PatchRemoteKeyState(context.Background(), client.CoreV1().Secrets(secret.Namespace), secret.Name, func(rk *state.RemoteKeyState) (bool, error) {
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
	if updated.Annotations[encryptionSecretTargetRemoteKeyID] != "remote-new" {
		t.Fatalf("target not updated")
	}
	if got := updated.Annotations[encryptionSecretMigratedRemoteKeyID]; got != "remote-old" {
		t.Fatalf("expected migrated-remote-key-id preserved as remote-old, got %q", got)
	}
	if got := updated.Annotations[EncryptionSecretMigratedTimestamp]; got != migratedTimestamp {
		t.Fatalf("expected migrated timestamp %q preserved, got %q", migratedTimestamp, got)
	}
}

func TestPatchRemoteKeyAnnotationsConflictRetry(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "openshift-config-managed",
			Name:      "encryption-key-test-3",
			Annotations: map[string]string{
				encryptionSecretTargetRemoteKeyID: "remote-old",
			},
		},
	}
	client := fake.NewSimpleClientset(secret)

	attempts := 0
	client.PrependReactor("update", "secrets", func(action clienttesting.Action) (bool, runtime.Object, error) {
		attempts++
		if attempts != 1 {
			return false, nil, nil
		}

		current, err := client.Tracker().Get(
			corev1.SchemeGroupVersion.WithResource("secrets"),
			secret.Namespace,
			secret.Name,
		)
		if err != nil {
			return true, nil, err
		}
		concurrent := current.(*corev1.Secret).DeepCopy()
		concurrent.Annotations[encryptionSecretMigratedRemoteKeyID] = "remote-intervening"
		if err := client.Tracker().Update(
			corev1.SchemeGroupVersion.WithResource("secrets"),
			concurrent,
			secret.Namespace,
		); err != nil {
			return true, nil, err
		}
		return true, nil, apierrors.NewConflict(
			schema.GroupResource{Resource: "secrets"},
			secret.Name,
			fmt.Errorf("injected conflict"),
		)
	})

	if err := PatchRemoteKeyState(context.Background(), client.CoreV1().Secrets(secret.Namespace), secret.Name, func(rk *state.RemoteKeyState) (bool, error) {
		rk.TargetRemoteKeyID = "remote-new"
		return true, nil
	}); err != nil {
		t.Fatalf("patch failed: %v", err)
	}
	if attempts != 2 {
		t.Fatalf("expected one retry, got %d updates", attempts)
	}

	updated, err := client.CoreV1().Secrets(secret.Namespace).Get(context.Background(), secret.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get secret: %v", err)
	}
	if updated.Annotations[encryptionSecretTargetRemoteKeyID] != "remote-new" {
		t.Fatalf("target not updated: %#v", updated.Annotations)
	}
	if updated.Annotations[encryptionSecretMigratedRemoteKeyID] != "remote-intervening" {
		t.Fatalf("expected intervening migrated annotation preserved: %#v", updated.Annotations)
	}
}
