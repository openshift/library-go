package controllers

import (
	"context"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"

	configv1informers "github.com/openshift/client-go/config/informers/externalversions/config/v1"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/encryption/controllers/migrators"
	"github.com/openshift/library-go/pkg/operator/encryption/encryptionstatus"
	"github.com/openshift/library-go/pkg/operator/encryption/secrets"
	"github.com/openshift/library-go/pkg/operator/encryption/statemachine"
	"github.com/openshift/library-go/pkg/operator/events"
	operatorv1helpers "github.com/openshift/library-go/pkg/operator/v1helpers"
)

const (
	encryptionRotationConvergenceDelay = 5 * time.Minute
)

// encryptionRotationController orchestrates KMS KEK rotation by resetting migration state on the
// encryption key secret and recording rotation progress on operator status.
type encryptionRotationController struct {
	instanceName             string
	controllerInstanceName   string
	operatorClient           operatorv1helpers.OperatorClient
	encryptionSecretSelector metav1.ListOptions
	secretClient             corev1client.SecretsGetter
	deployer                 statemachine.Deployer
	migrator                 migrators.Migrator
	provider                 Provider
	preconditionsFulfilledFn preconditionsFulfilled
}

func NewEncryptionRotationController(
	instanceName string,
	provider Provider,
	deployer statemachine.Deployer,
	preconditionsFulfilledFn preconditionsFulfilled,
	migrator migrators.Migrator,
	operatorClient operatorv1helpers.OperatorClient,
	apiServerConfigInformer configv1informers.APIServerInformer,
	kubeInformersForNamespaces operatorv1helpers.KubeInformersForNamespaces,
	secretClient corev1client.SecretsGetter,
	encryptionSecretSelector metav1.ListOptions,
	eventRecorder events.Recorder,
) factory.Controller {
	c := &encryptionRotationController{
		instanceName:             instanceName,
		controllerInstanceName:   factory.ControllerInstanceName(instanceName, "EncryptionRotation"),
		operatorClient:           operatorClient,
		encryptionSecretSelector: encryptionSecretSelector,
		secretClient:             secretClient,
		deployer:                 deployer,
		migrator:                 migrator,
		provider:                 provider,
		preconditionsFulfilledFn: preconditionsFulfilledFn,
	}

	return factory.New().ResyncEvery(time.Minute).WithSync(c.sync).WithControllerInstanceName(c.controllerInstanceName).WithInformers(
		operatorClient.Informer(),
		kubeInformersForNamespaces.InformersFor("openshift-config-managed").Core().V1().Secrets().Informer(),
		apiServerConfigInformer.Informer(),
		deployer,
	).ToController(
		c.controllerInstanceName,
		eventRecorder.WithComponentSuffix("encryption-rotation-controller"),
	)
}

func (c *encryptionRotationController) sync(ctx context.Context, syncCtx factory.SyncContext) error {
	if ready, err := shouldRunEncryptionController(c.operatorClient, c.preconditionsFulfilledFn, c.provider.ShouldRunEncryptionControllers); err != nil || !ready {
		return err
	}
	return c.reconcile(ctx)
}

func (c *encryptionRotationController) reconcile(ctx context.Context) error {
	currentConfig, _, encryptionSecrets, _, err := statemachine.GetEncryptionConfigAndState(
		ctx, c.deployer, c.secretClient, c.encryptionSecretSelector, c.provider.EncryptedGRs(),
	)
	if err != nil {
		return err
	}

	if currentConfig == nil || !currentConfig.UsesKMS() {
		return nil
	}

	_, operatorStatus, _, err := c.operatorClient.GetOperatorState()
	if err != nil {
		return err
	}

	healthReports := encryptionstatus.HealthReportsFromOperatorStatus(operatorStatus)
	rotations, err := encryptionstatus.KeyRotationStatusFromOperatorStatus(operatorStatus)
	if err != nil {
		return err
	}

	encryptedGRs := currentConfig.EncryptedGroupResources()
	klog.Infof("%s: reconciling KMS key rotation (%d plugin(s), %d health report(s), %d rotation entr(ies))",
		c.instanceName, len(currentConfig.KMSPlugins), len(healthReports), len(rotations))
	for keyID := range currentConfig.KMSPlugins {
		writeKeySecret := secrets.FindKeySecret(encryptionSecrets, c.instanceName, keyID)
		if writeKeySecret == nil {
			klog.Infof("%s: no write key secret for KMS plugin keyID %q, skipping", c.instanceName, keyID)
			continue
		}

		rotations, err = c.reconcileKMSPlugin(
			ctx, keyID, encryptedGRs, writeKeySecret, healthReports, rotations,
		)
		if err != nil {
			return err
		}
	}

	if err := c.persistRotations(ctx, rotations); err != nil {
		return err
	}

	return nil
}

func (c *encryptionRotationController) reconcileKMSPlugin(
	ctx context.Context,
	keyID string,
	encryptedGRs []schema.GroupResource,
	writeKeySecret *corev1.Secret,
	healthReports []encryptionstatus.KMSPluginHealthReport,
	rotations []encryptionstatus.KMSPluginRotationStatus,
) ([]encryptionstatus.KMSPluginRotationStatus, error) {
	// Check KEK convergence across all nodes for this keyID.
	convergedKEKID, converged := encryptionstatus.ConvergedKEKForKeyID(healthReports, keyID)
	if !converged {
		klog.Infof("%s: KEK not yet converged for keyID %q, waiting for all nodes to report the same kekID", c.instanceName, keyID)
		return rotations, nil
	}
	klog.Infof("%s: KEK converged for keyID %q: kekID=%q", c.instanceName, keyID, convergedKEKID)

	// If the converged kekID matches the last completed rotation, we are in steady state.
	lastCompleted, hasCompleted := encryptionstatus.LatestCompletedRotationForKeyID(rotations, keyID)
	if hasCompleted && convergedKEKID == lastCompleted.KEKID {
		klog.V(4).Infof("%s: converged kekID %q matches last completed rotation for keyID %q, nothing to do", c.instanceName, convergedKEKID, keyID)
		return rotations, nil
	}

	// Ensure an open rotation entry exists with discoveryTime for the converged kekID.
	now := metav1.Now()
	rotations, openIdx := encryptionstatus.GetOrCreateOpenRotation(rotations, keyID, convergedKEKID, now)
	klog.Infof("%s: tracking open rotation for keyID=%q kekID=%q (discoveryTime=%s)",
		c.instanceName, keyID, convergedKEKID, rotations[openIdx].DiscoveryTime.Format(time.RFC3339))

	// Mirror migration finish time from the write key secret annotations when all
	// encrypted group resources have been migrated by the migration controller.
	migrated, err := encryptionstatus.AllEncryptedGRsMigrated(writeKeySecret, encryptedGRs)
	if err != nil {
		return rotations, err
	}
	rotations = mirrorMigrationFinish(c.instanceName, rotations, openIdx, migrated, writeKeySecret)

	// Bootstrap: if no prior completed rotation exists, this is the initial provider
	// migration driven by the migration controller. We only track convergence and mirror
	// the finish time — never prune migrations or clear annotations.
	if !hasCompleted {
		klog.Infof("%s: bootstrap for keyID %q — no prior completed rotation, waiting for initial migration to complete", c.instanceName, keyID)
		return rotations, nil
	}

	// From here on a KEK change was detected (convergedKEKID != lastCompleted.KEKID).
	// Check guards before starting a storage re-migration.
	entry := rotations[openIdx]

	if entry.MigrationStartTime != nil {
		klog.Infof("%s: rotation for kekID %q already started at %s, waiting for migration to complete",
			c.instanceName, convergedKEKID, entry.MigrationStartTime.Format(time.RFC3339))
		return rotations, nil
	}

	if entry.DiscoveryTime != nil && time.Since(entry.DiscoveryTime.Time) < encryptionRotationConvergenceDelay {
		remaining := encryptionRotationConvergenceDelay - time.Since(entry.DiscoveryTime.Time)
		klog.Infof("%s: rotation for kekID %q waiting for convergence delay (%s remaining)",
			c.instanceName, convergedKEKID, remaining.Round(time.Second))
		return rotations, nil
	}

	// All guards passed — start the rotation by pruning existing storage version
	// migrations and clearing migration annotations on the write key secret so the
	// migration controller picks up the work again.
	klog.Infof("%s: starting storage re-migration for keyID=%q: kekID changed from %q to %q",
		c.instanceName, keyID, lastCompleted.KEKID, convergedKEKID)
	if err := c.startRotation(ctx, encryptedGRs, writeKeySecret); err != nil {
		return rotations, err
	}

	rotations = encryptionstatus.SetMigrationStartTime(rotations, openIdx, now)
	klog.Infof("%s: rotation migration started for kekID %q at %s", c.instanceName, convergedKEKID, now.Format(time.RFC3339))
	return rotations, nil
}

func (c *encryptionRotationController) startRotation(ctx context.Context, encryptedGRs []schema.GroupResource, secret *corev1.Secret) error {
	for _, gr := range encryptedGRs {
		klog.Infof("%s: pruning storage migration for %s", c.instanceName, gr)
		if err := c.migrator.PruneMigration(gr); err != nil {
			return err
		}
	}
	klog.Infof("%s: clearing migration annotations on secret %s/%s", c.instanceName, secret.Namespace, secret.Name)
	return c.clearMigrationAnnotations(ctx, secret)
}

func mirrorMigrationFinish(
	instanceName string,
	rotations []encryptionstatus.KMSPluginRotationStatus,
	idx int,
	migrated bool,
	secret *corev1.Secret,
) []encryptionstatus.KMSPluginRotationStatus {
	if !migrated || idx < 0 || idx >= len(rotations) || rotations[idx].MigrationFinishTime != nil {
		return rotations
	}
	finish, ok := migrationFinishTimeFromSecret(secret)
	if !ok {
		return rotations
	}
	entry := rotations[idx]
	klog.Infof("%s: mirroring migrationFinishTime for keyID %q kekID %q from secret %s/%s at %s",
		instanceName, entry.KeyID, entry.KEKID, secret.Namespace, secret.Name, finish.Format(time.RFC3339))
	return encryptionstatus.SetMigrationFinishTime(rotations, idx, finish)
}

func migrationFinishTimeFromSecret(secret *corev1.Secret) (metav1.Time, bool) {
	if secret == nil || secret.Annotations == nil {
		return metav1.Time{}, false
	}
	raw, ok := secret.Annotations[secrets.EncryptionSecretMigratedTimestamp]
	if !ok || raw == "" {
		return metav1.Time{}, false
	}
	ts, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		klog.Warningf("ignoring invalid %s annotation on secret %s/%s: %v",
			secrets.EncryptionSecretMigratedTimestamp, secret.Namespace, secret.Name, err)
		return metav1.Time{}, false
	}
	return metav1.NewTime(ts), true
}

func (c *encryptionRotationController) clearMigrationAnnotations(ctx context.Context, secret *corev1.Secret) error {
	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		current, err := c.secretClient.Secrets(secret.Namespace).Get(ctx, secret.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if current.Annotations == nil {
			return nil
		}
		changed := false
		if _, ok := current.Annotations[secrets.EncryptionSecretMigratedTimestamp]; ok {
			delete(current.Annotations, secrets.EncryptionSecretMigratedTimestamp)
			changed = true
		}
		if _, ok := current.Annotations[secrets.EncryptionSecretMigratedResources]; ok {
			delete(current.Annotations, secrets.EncryptionSecretMigratedResources)
			changed = true
		}
		if !changed {
			return nil
		}
		_, err = c.secretClient.Secrets(current.Namespace).Update(ctx, current, metav1.UpdateOptions{})
		return err
	})
}

func (c *encryptionRotationController) persistRotations(ctx context.Context, rotations []encryptionstatus.KMSPluginRotationStatus) error {
	_, updated, err := operatorv1helpers.UpdateStatus(ctx, c.operatorClient, encryptionstatus.SetKeyRotationStatusCondition(rotations))
	if err != nil {
		return err
	}
	if updated {
		klog.Infof("%s: updated key rotation status (%d entries)", c.instanceName, len(rotations))
	}
	return nil
}
