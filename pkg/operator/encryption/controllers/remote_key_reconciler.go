package controllers

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

	operatorv1 "github.com/openshift/api/operator/v1"

	"github.com/openshift/library-go/pkg/operator/encryption/kms/health"
	"github.com/openshift/library-go/pkg/operator/encryption/secrets"
	"github.com/openshift/library-go/pkg/operator/encryption/state"
)

const remoteKeyConvergenceDuration = 5 * time.Minute

type remoteKeyClock interface {
	Now() time.Time
}

type systemRemoteKeyClock struct{}

func (systemRemoteKeyClock) Now() time.Time { return time.Now() }

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
	clock remoteKeyClock,
) (time.Duration, error) {
	if encryptionStatus == nil {
		return 0, nil
	}

	writeKey, ok := writeKeyForRemoteKeyRotation(desiredState)
	if !ok {
		return 0, nil
	}

	secretName := fmt.Sprintf("encryption-key-%s-%s", instanceName, writeKey.Key.Name)
	rk, err := readRemoteKeyAnnotationsFromSecret(ctx, secretClient, secretName)
	if err != nil {
		return 0, err
	}
	if len(rk.TargetRemoteKeyID) == 0 {
		return 0, nil
	}

	// During KMS-to-KMS migration multiple plugin key IDs can report at once; scope
	// convergence to the current write key's keyID so backup/read-only plugins are ignored.
	reports := health.ReportsForKeyID(encryptionStatus.HealthReports, writeKey.Key.Name)
	convergenceResult := health.ConvergedRemoteKeyID(reports)
	if convergenceResult.RemoteKeyID == "" {
		return 0, nil
	}

	if !secrets.IsBootstrapped(rk) {
		requeue, err := reconcileRemoteKeyBootstrap(ctx, secretClient, secretName, encryptedGRs, writeKey, convergenceResult)
		return requeue, err
	}

	return reconcileRemoteKeyPromotion(ctx, secretClient, secretName, rk, convergenceResult, clock)
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

func reconcileRemoteKeyBootstrap(
	ctx context.Context,
	secretClient corev1client.SecretsGetter,
	secretName string,
	encryptedGRs []schema.GroupResource,
	writeKey state.KeyState,
	convergenceResult health.ConvergenceResult,
) (time.Duration, error) {
	if !convergenceResult.Converged {
		return 0, nil
	}
	allMigrated, _, _ := state.MigratedFor(encryptedGRs, writeKey)
	if !allMigrated {
		return 0, nil
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
	return 0, err
}

func reconcileRemoteKeyPromotion(
	ctx context.Context,
	secretClient corev1client.SecretsGetter,
	secretName string,
	rk secrets.RemoteKeyAnnotations,
	convergence health.ConvergenceResult,
	clock remoteKeyClock,
) (time.Duration, error) {
	if !convergence.Converged {
		changed, err := clearRemoteKeyConvergence(ctx, secretClient, secretName, rk)
		return 0, errIfChanged(changed, err)
	}

	if convergence.RemoteKeyID == rk.TargetRemoteKeyID {
		changed, err := clearRemoteKeyConvergence(ctx, secretClient, secretName, rk)
		return 0, errIfChanged(changed, err)
	}

	now := clock.Now()
	requeueAfter, promote, err := nextRemoteKeyPromotionAction(rk, convergence.RemoteKeyID, now)
	if err != nil {
		return 0, err
	}

	if promote {
		err = secrets.PatchRemoteKeyAnnotations(ctx, secretClient.Secrets("openshift-config-managed"), secretName, func(rk *secrets.RemoteKeyAnnotations) (bool, error) {
			if rk.TargetRemoteKeyID == convergence.RemoteKeyID {
				return false, nil
			}
			if secrets.NeedsRemoteKeyMigration(*rk) {
				return false, nil
			}
			rk.TargetRemoteKeyID = convergence.RemoteKeyID
			rk.ConvergedID = ""
			rk.ConvergedAt = time.Time{}
			return true, nil
		})
		return 0, err
	}

	err = secrets.PatchRemoteKeyAnnotations(ctx, secretClient.Secrets("openshift-config-managed"), secretName, func(rk *secrets.RemoteKeyAnnotations) (bool, error) {
		if rk.ConvergedID == convergence.RemoteKeyID && !rk.ConvergedAt.IsZero() {
			return false, nil
		}
		rk.ConvergedID = convergence.RemoteKeyID
		rk.ConvergedAt = now
		return true, nil
	})
	return requeueAfter, err
}

func nextRemoteKeyPromotionAction(rk secrets.RemoteKeyAnnotations, candidateRemoteKeyID string, now time.Time) (time.Duration, bool, error) {
	if rk.ConvergedID != candidateRemoteKeyID || rk.ConvergedAt.IsZero() {
		return remoteKeyConvergenceDuration, false, nil
	}
	elapsed := now.Sub(rk.ConvergedAt)
	if elapsed < remoteKeyConvergenceDuration {
		return remoteKeyConvergenceDuration - elapsed, false, nil
	}
	if secrets.NeedsRemoteKeyMigration(rk) {
		return 0, false, nil
	}
	return 0, true, nil
}

func clearRemoteKeyConvergence(ctx context.Context, secretClient corev1client.SecretsGetter, secretName string, rk secrets.RemoteKeyAnnotations) (bool, error) {
	if rk.ConvergedID == "" && rk.ConvergedAt.IsZero() {
		return false, nil
	}
	err := secrets.PatchRemoteKeyAnnotations(ctx, secretClient.Secrets("openshift-config-managed"), secretName, func(rk *secrets.RemoteKeyAnnotations) (bool, error) {
		if rk.ConvergedID == "" && rk.ConvergedAt.IsZero() {
			return false, nil
		}
		rk.ConvergedID = ""
		rk.ConvergedAt = time.Time{}
		return true, nil
	})
	return true, err
}

func errIfChanged(changed bool, err error) error {
	return err
}
