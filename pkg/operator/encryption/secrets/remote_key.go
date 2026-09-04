package secrets

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/util/retry"

	"github.com/openshift/library-go/pkg/operator/encryption/state"
)

// RemoteKeyAnnotations is the annotation-backed view of state.RemoteKeyState.
type RemoteKeyAnnotations = state.RemoteKeyState

// ReadRemoteKeyAnnotations reads remote key rotation annotations from a key secret.
func ReadRemoteKeyAnnotations(s *corev1.Secret) (RemoteKeyAnnotations, error) {
	if s == nil {
		return RemoteKeyAnnotations{}, nil
	}
	return readRemoteKeyAnnotations(s.Annotations, s.Namespace, s.Name)
}

func readRemoteKeyAnnotations(annotations map[string]string, namespace, name string) (RemoteKeyAnnotations, error) {
	rk := RemoteKeyAnnotations{
		TargetRemoteKeyID:   annotations[EncryptionSecretTargetRemoteKeyID],
		MigratedRemoteKeyID: annotations[EncryptionSecretMigratedRemoteKeyID],
		ConvergedID:         annotations[EncryptionSecretRemoteKeyConvergedID],
	}
	if v, ok := annotations[EncryptionSecretRemoteKeyConvergedAt]; ok && len(v) > 0 {
		ts, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return RemoteKeyAnnotations{}, fmt.Errorf("secret %s/%s has invalid %s annotation: %v", namespace, name, EncryptionSecretRemoteKeyConvergedAt, err)
		}
		rk.ConvergedAt = ts
	}
	return rk, nil
}

// ApplyRemoteKeyAnnotations writes remote key rotation annotations into the given map.
// Empty values remove the corresponding annotation keys.
func ApplyRemoteKeyAnnotations(annotations map[string]string, rk RemoteKeyAnnotations) {
	setOrDeleteAnnotation(annotations, EncryptionSecretTargetRemoteKeyID, rk.TargetRemoteKeyID)
	setOrDeleteAnnotation(annotations, EncryptionSecretMigratedRemoteKeyID, rk.MigratedRemoteKeyID)
	setOrDeleteAnnotation(annotations, EncryptionSecretRemoteKeyConvergedID, rk.ConvergedID)
	if rk.ConvergedAt.IsZero() {
		delete(annotations, EncryptionSecretRemoteKeyConvergedAt)
	} else {
		annotations[EncryptionSecretRemoteKeyConvergedAt] = rk.ConvergedAt.Format(time.RFC3339)
	}
}

func setOrDeleteAnnotation(annotations map[string]string, key, value string) {
	if len(value) == 0 {
		delete(annotations, key)
		return
	}
	annotations[key] = value
}

// NeedsRemoteKeyMigration reports whether migrated-remote-key-id is set,
// target-remote-key-id is non-empty, and they differ (needsMigration).
func NeedsRemoteKeyMigration(rk RemoteKeyAnnotations) bool {
	return len(rk.MigratedRemoteKeyID) > 0 &&
		len(rk.TargetRemoteKeyID) > 0 &&
		rk.MigratedRemoteKeyID != rk.TargetRemoteKeyID
}

// IsBootstrapped reports whether the initial remote key bootstrap has completed.
func IsBootstrapped(rk RemoteKeyAnnotations) bool {
	return len(rk.MigratedRemoteKeyID) > 0
}

// MigrationWriteKeyName returns the StorageVersionMigration write-key annotation value.
// First enablement uses the plain key name even when target-remote-key-id is set.
// Remote key rotation uses a suffixed key only while NeedsRemoteKeyMigration is true.
func MigrationWriteKeyName(keyName string, rk RemoteKeyAnnotations) string {
	if !NeedsRemoteKeyMigration(rk) {
		return keyName
	}
	return keyName + "-" + rk.TargetRemoteKeyID
}

// RemoteKeyIDFromMigrationWriteKey extracts the remote key ID suffix from a migration write-key value.
func RemoteKeyIDFromMigrationWriteKey(keyName, migrationWriteKey string) (string, bool) {
	prefix := keyName + "-"
	if !strings.HasPrefix(migrationWriteKey, prefix) {
		return "", false
	}
	remoteKeyID := strings.TrimPrefix(migrationWriteKey, prefix)
	if len(remoteKeyID) == 0 {
		return "", false
	}
	return remoteKeyID, true
}

// PatchRemoteKeyAnnotations updates remote key annotations on a key secret using
// get-modify-update with conflict retry. Other annotations are preserved.
func PatchRemoteKeyAnnotations(ctx context.Context, client corev1client.SecretInterface, secretName string, mutate func(*RemoteKeyAnnotations) (bool, error)) error {
	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		s, err := client.Get(ctx, secretName, metav1.GetOptions{})
		if err != nil {
			return err
		}
		rk, err := ReadRemoteKeyAnnotations(s)
		if err != nil {
			return err
		}
		changed, err := mutate(&rk)
		if err != nil || !changed {
			return err
		}
		if s.Annotations == nil {
			s.Annotations = map[string]string{}
		}
		ApplyRemoteKeyAnnotations(s.Annotations, rk)
		_, updateErr := client.Update(ctx, s, metav1.UpdateOptions{})
		return updateErr
	})
}
