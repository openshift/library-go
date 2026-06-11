package secrets

import (
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
)

// KekMigrationState holds KMS KEK rotation annotations from a write-key secret.
type KekMigrationState struct {
	TargetKekID    string
	MigratedKekID  string
	KekConvergedAt time.Time
	KekConvergedID string
}

// KekMigrationFromSecret parses KMS KEK rotation annotations from a secret.
func KekMigrationFromSecret(s *corev1.Secret) KekMigrationState {
	if s == nil || s.Annotations == nil {
		return KekMigrationState{}
	}
	state := KekMigrationState{
		TargetKekID:    s.Annotations[EncryptionSecretTargetKekID],
		MigratedKekID:  s.Annotations[EncryptionSecretMigratedKekID],
		KekConvergedID: s.Annotations[EncryptionSecretKekConvergedID],
	}
	if v, ok := s.Annotations[EncryptionSecretKekConvergedAt]; ok && len(v) > 0 {
		if ts, err := time.Parse(time.RFC3339, v); err == nil {
			state.KekConvergedAt = ts
		}
	}
	return state
}

// NeedsKekMigration reports whether target-kek-id is set and differs from migrated-kek-id.
func NeedsKekMigration(s *corev1.Secret) bool {
	if s == nil || s.Annotations == nil {
		return false
	}
	target := s.Annotations[EncryptionSecretTargetKekID]
	if target == "" {
		return false
	}
	return target != s.Annotations[EncryptionSecretMigratedKekID]
}

// MigrationWriteKey returns the migrator write-key identity for the given key name.
// When target-kek-id is set, the format is {keyName}-{kekId}; otherwise {keyName}.
func MigrationWriteKey(keyName string, s *corev1.Secret) string {
	if s == nil || s.Annotations == nil {
		return keyName
	}
	if target := s.Annotations[EncryptionSecretTargetKekID]; target != "" {
		return fmt.Sprintf("%s-%s", keyName, target)
	}
	return keyName
}
