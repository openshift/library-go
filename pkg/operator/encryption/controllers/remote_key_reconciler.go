package controllers

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/utils/clock"

	operatorv1 "github.com/openshift/api/operator/v1"

	"github.com/openshift/library-go/pkg/operator/encryption/kms/health"
	"github.com/openshift/library-go/pkg/operator/encryption/secrets"
	"github.com/openshift/library-go/pkg/operator/encryption/state"
)

const remoteKeyConvergenceDuration = 5 * time.Minute

// reconcileRemoteKeyRotation maintains KMS remote key rotation annotations on the
// encryption key secret for the current KMS write key. External remote-key rotation
// does not mint a new encryption key secret or trigger stateController; only
// migrationController re-encrypts etcd data.
func reconcileRemoteKeyRotation(
	ctx context.Context,
	secretClient corev1client.SecretsGetter,
	instanceName string,
	encryptedGRs []schema.GroupResource,
	desiredState map[schema.GroupResource]state.GroupResourceState,
	encryptionStatus *operatorv1.KMSEncryptionStatus,
	clock clock.Clock,
) error {
	if encryptionStatus == nil {
		return nil
	}

	writeKey, ok := writeKeyForRemoteKeyRotation(desiredState)
	if !ok {
		return nil
	}

	secretName := fmt.Sprintf("encryption-key-%s-%s", instanceName, writeKey.Key.Name)
	rk, err := readRemoteKeyAnnotationsFromSecret(ctx, secretClient, secretName)
	if err != nil {
		return err
	}
	if len(rk.TargetRemoteKeyID) == 0 {
		return nil
	}

	// During KMS-to-KMS migration multiple plugin key IDs can report at once; scope
	// convergence to the current write key's keyID so backup/read-only plugins are ignored.
	// TODO(thomas): we need to ensure the amount of reports match the number of operand pods
	reports := health.ReportsForKeyID(encryptionStatus.HealthReports, writeKey.Key.Name)
	convergedRemoteKeyID := health.ConvergedRemoteKeyID(reports)
	if convergedRemoteKeyID == "" {
		return nil
	}

	if !secrets.IsBootstrapped(rk) {
		allMigrated, _, _ := state.MigratedFor(encryptedGRs, writeKey)
		if !allMigrated {
			return nil
		}

		err := secrets.PatchRemoteKeyAnnotations(ctx, secretClient.Secrets("openshift-config-managed"), secretName, func(rk *secrets.RemoteKeyAnnotations) (bool, error) {
			if secrets.IsBootstrapped(*rk) {
				return false, nil
			}
			if len(rk.TargetRemoteKeyID) == 0 {
				return false, nil
			}
			rk.MigratedRemoteKeyID = rk.TargetRemoteKeyID
			return true, nil
		})

		return err
	}

	if convergedRemoteKeyID == rk.TargetRemoteKeyID {
		return clearRemoteKeyConvergence(ctx, secretClient, secretName, rk)
	}

	now := clock.Now()
	promote, err := shouldPromoteConvergedKeyID(rk, convergedRemoteKeyID, now)
	if err != nil {
		return err
	}

	if promote {
		err = secrets.PatchRemoteKeyAnnotations(ctx, secretClient.Secrets("openshift-config-managed"), secretName, func(rk *secrets.RemoteKeyAnnotations) (bool, error) {
			if rk.TargetRemoteKeyID == convergedRemoteKeyID {
				return false, nil
			}
			if secrets.NeedsRemoteKeyMigration(*rk) {
				return false, nil
			}
			rk.TargetRemoteKeyID = convergedRemoteKeyID
			rk.ConvergedID = ""
			rk.ConvergedAt = time.Time{}
			return true, nil
		})
		return err
	}

	err = secrets.PatchRemoteKeyAnnotations(ctx, secretClient.Secrets("openshift-config-managed"), secretName, func(rk *secrets.RemoteKeyAnnotations) (bool, error) {
		if rk.ConvergedID == convergedRemoteKeyID && !rk.ConvergedAt.IsZero() {
			return false, nil
		}
		rk.ConvergedID = convergedRemoteKeyID
		rk.ConvergedAt = now
		return true, nil
	})

	return err
}

func writeKeyForRemoteKeyRotation(desiredState map[schema.GroupResource]state.GroupResourceState) (state.KeyState, bool) {
	for _, grState := range desiredState {
		if grState.HasWriteKey() && grState.WriteKey.Mode == state.KMS {
			return grState.WriteKey, true
		}
	}
	return state.KeyState{}, false
}

func readRemoteKeyAnnotationsFromSecret(ctx context.Context, secretClient corev1client.SecretsGetter, secretName string) (secrets.RemoteKeyAnnotations, error) {
	s, err := secretClient.Secrets("openshift-config-managed").Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		return secrets.RemoteKeyAnnotations{}, err
	}
	return secrets.ReadRemoteKeyAnnotations(s)
}

func shouldPromoteConvergedKeyID(rk secrets.RemoteKeyAnnotations, candidateRemoteKeyID string, now time.Time) (bool, error) {
	if rk.ConvergedID != candidateRemoteKeyID || rk.ConvergedAt.IsZero() {
		return false, nil
	}
	elapsed := now.Sub(rk.ConvergedAt)
	if elapsed < remoteKeyConvergenceDuration {
		return false, nil
	}
	if secrets.NeedsRemoteKeyMigration(rk) {
		return false, nil
	}
	return true, nil
}

func clearRemoteKeyConvergence(ctx context.Context, secretClient corev1client.SecretsGetter, secretName string, rk secrets.RemoteKeyAnnotations) error {
	if rk.ConvergedID == "" && rk.ConvergedAt.IsZero() {
		return nil
	}
	return secrets.PatchRemoteKeyAnnotations(ctx, secretClient.Secrets("openshift-config-managed"), secretName, func(rk *secrets.RemoteKeyAnnotations) (bool, error) {
		if rk.ConvergedID == "" && rk.ConvergedAt.IsZero() {
			return false, nil
		}
		rk.ConvergedID = ""
		rk.ConvergedAt = time.Time{}
		return true, nil
	})
}
