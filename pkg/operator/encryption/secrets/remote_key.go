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

// ReadRemoteKeyStateFromSecret reads remote key rotation annotations from a key secret.
func ReadRemoteKeyStateFromSecret(s *corev1.Secret) (state.RemoteKeyState, error) {
	if s == nil {
		return state.RemoteKeyState{}, nil
	}
	annotations := s.Annotations
	rk := state.RemoteKeyState{
		TargetRemoteKeyID:   annotations[encryptionSecretTargetRemoteKeyID],
		MigratedRemoteKeyID: annotations[encryptionSecretMigratedRemoteKeyID],
		ConvergedID:         annotations[encryptionSecretRemoteKeyConvergedID],
	}
	if v, ok := annotations[encryptionSecretRemoteKeyConvergedAt]; ok && len(v) > 0 {
		ts, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return state.RemoteKeyState{}, fmt.Errorf("secret %s/%s has invalid %s annotation: %v", s.Namespace, s.Name, encryptionSecretRemoteKeyConvergedAt, err)
		}
		rk.ConvergedAt = ts
	}

	if err := rk.Validate(); err != nil {
		return state.RemoteKeyState{}, fmt.Errorf("secret %s/%s is invalid %s", s.Namespace, s.Name, err)
	}

	return rk, nil
}

// applyRemoteKeyAnnotations writes remote key rotation annotations into the given map.
// Empty values remove the corresponding annotation keys. Returns an error when the remote key state is invalid.
func applyRemoteKeyAnnotations(annotations map[string]string, rk state.RemoteKeyState) error {
	if err := rk.Validate(); err != nil {
		return err
	}

	delete(annotations, encryptionSecretTargetRemoteKeyID)
	if rk.TargetRemoteKeyID != "" {
		annotations[encryptionSecretTargetRemoteKeyID] = rk.TargetRemoteKeyID
	}

	delete(annotations, encryptionSecretMigratedRemoteKeyID)
	if rk.MigratedRemoteKeyID != "" {
		annotations[encryptionSecretMigratedRemoteKeyID] = rk.MigratedRemoteKeyID
	}

	delete(annotations, encryptionSecretRemoteKeyConvergedID)
	if rk.ConvergedID != "" {
		annotations[encryptionSecretRemoteKeyConvergedID] = rk.ConvergedID
	}

	delete(annotations, encryptionSecretRemoteKeyConvergedAt)
	if !rk.ConvergedAt.IsZero() {
		annotations[encryptionSecretRemoteKeyConvergedAt] = rk.ConvergedAt.Format(time.RFC3339)
	}

	return nil
}

// MigrationWriteKeyName returns the StorageVersionMigration write-key annotation value.
// When target-remote-key-id is set, the write-key is always suffixed with that ID
// (first enablement and remote-key rotation). Plain keyName is used only when
// target-remote-key-id is unset.
func MigrationWriteKeyName(keyName string, rk state.RemoteKeyState) string {
	if len(rk.TargetRemoteKeyID) == 0 {
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

// PatchRemoteKeyState updates remote key annotations on a key secret using
// get-modify-update with conflict retry. Other annotations are preserved.
func PatchRemoteKeyState(ctx context.Context, client corev1client.SecretInterface, secretName string, mutate func(*state.RemoteKeyState) (bool, error)) error {
	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		s, err := client.Get(ctx, secretName, metav1.GetOptions{})
		if err != nil {
			return err
		}
		rk, err := ReadRemoteKeyStateFromSecret(s)
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
		if err := applyRemoteKeyAnnotations(s.Annotations, rk); err != nil {
			return err
		}
		_, updateErr := client.Update(ctx, s, metav1.UpdateOptions{})
		return updateErr
	})
}
