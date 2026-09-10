package secrets

import (
	"fmt"
	"time"

	"github.com/openshift/library-go/pkg/operator/encryption/state"
	corev1 "k8s.io/api/core/v1"
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
// Empty values remove the corresponding annotation keys. Returns an error when the remote key state is invalid
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
