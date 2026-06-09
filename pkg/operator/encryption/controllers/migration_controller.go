package controllers

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/errors"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"

	operatorv1 "github.com/openshift/api/operator/v1"

	configv1informers "github.com/openshift/client-go/config/informers/externalversions/config/v1"
	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/encryption/controllers/migrators"
	"github.com/openshift/library-go/pkg/operator/encryption/encryptiondata"
	"github.com/openshift/library-go/pkg/operator/encryption/encryptionstatus"
	"github.com/openshift/library-go/pkg/operator/encryption/secrets"
	"github.com/openshift/library-go/pkg/operator/encryption/state"
	"github.com/openshift/library-go/pkg/operator/encryption/statemachine"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourcehelper"
	operatorv1helpers "github.com/openshift/library-go/pkg/operator/v1helpers"
)

const (
	// how long to wait until we retry a migration when it failed with unknown errors.
	migrationRetryDuration = time.Minute * 5
)

// The migrationController controller migrates resources to a new write key
// and annotated the write key secret afterwards with the migrated GRs. It
//
//   - watches pods and secrets in <operand-target-namespace>
//   - watches secrets in openshift-config-manager
//   - computes a new, desired encryption config from encryption-config-<revision>
//     and the existing keys in openshift-config-managed.
//   - compares desired with current target config and stops when they differ
//   - checks the write-key secret whether
//   - encryption.apiserver.operator.openshift.io/migrated-timestamp annotation
//     is missing or
//   - a write-key for a resource does not show up in the
//     encryption.apiserver.operator.openshift.io/migrated-resources And then
//     starts a migration job (currently in-place synchronously, soon with the upstream migration tool)
//   - updates the encryption.apiserver.operator.openshift.io/migrated-timestamp and
//     encryption.apiserver.operator.openshift.io/migrated-resources annotations on the
//     current write-key secrets.
type migrationController struct {
	instanceName           string
	controllerInstanceName string

	operatorClient operatorv1helpers.OperatorClient
	secretClient   corev1client.SecretsGetter

	preRunCachesSynced       []cache.InformerSynced
	encryptionSecretSelector metav1.ListOptions

	deployer                 statemachine.Deployer
	migrator                 migrators.Migrator
	provider                 Provider
	preconditionsFulfilledFn preconditionsFulfilled
}

func NewMigrationController(
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
	c := &migrationController{
		instanceName:           instanceName,
		controllerInstanceName: factory.ControllerInstanceName(instanceName, "EncryptionMigration"),
		operatorClient:         operatorClient,

		encryptionSecretSelector: encryptionSecretSelector,
		secretClient:             secretClient,
		deployer:                 deployer,
		migrator:                 migrator,
		provider:                 provider,
		preconditionsFulfilledFn: preconditionsFulfilledFn,
	}

	return factory.New().ResyncEvery(time.Minute).WithSync(c.sync).WithControllerInstanceName(c.controllerInstanceName).WithInformers(
		migrator,
		operatorClient.Informer(),
		kubeInformersForNamespaces.InformersFor("openshift-config-managed").Core().V1().Secrets().Informer(),
		apiServerConfigInformer.Informer(), // do not remove, used by the precondition checker
		deployer,
	).ToController(
		c.controllerInstanceName,
		eventRecorder.WithComponentSuffix("encryption-migration-controller"),
	)
}

func (c *migrationController) sync(ctx context.Context, syncCtx factory.SyncContext) (err error) {
	// Status for these conditions is left out to make sure it's correctly set in every branch
	degradedCondition := applyoperatorv1.OperatorCondition().
		WithType("EncryptionMigrationControllerDegraded")
	progressingCondition := applyoperatorv1.OperatorCondition().
		WithType("EncryptionMigrationControllerProgressing")

	defer func() {
		if degradedCondition == nil || progressingCondition == nil {
			return
		}
		status := applyoperatorv1.OperatorStatus().WithConditions(
			degradedCondition,
			progressingCondition,
		)
		if applyError := c.operatorClient.ApplyOperatorStatus(ctx, c.controllerInstanceName, status); applyError != nil {
			err = applyError
		}
	}()

	if ready, err := shouldRunEncryptionController(c.operatorClient, c.preconditionsFulfilledFn, c.provider.ShouldRunEncryptionControllers); err != nil || !ready {
		if err != nil {
			degradedCondition = nil
			progressingCondition = nil
		} else {
			degradedCondition = degradedCondition.
				WithStatus(operatorv1.ConditionFalse)
			progressingCondition = progressingCondition.
				WithStatus(operatorv1.ConditionFalse)
		}
		return err // we will get re-kicked when the operator status updates
	}

	migratingResources, migrationError := c.migrateKeysIfNeededAndRevisionStable(ctx, syncCtx, c.provider.EncryptedGRs())
	if migrationError != nil {
		degradedCondition = degradedCondition.
			WithStatus(operatorv1.ConditionTrue).
			WithReason("Error").
			WithMessage(migrationError.Error())
	} else {
		degradedCondition = degradedCondition.
			WithStatus(operatorv1.ConditionFalse)
	}

	if len(migratingResources) > 0 {
		progressingCondition = progressingCondition.
			WithStatus(operatorv1.ConditionTrue).
			WithReason("Migrating").
			WithMessage(fmt.Sprintf("migrating resources to a new write key: %v", grsToHumanReadable(migratingResources)))
	} else {
		progressingCondition = progressingCondition.
			WithStatus(operatorv1.ConditionFalse)
	}

	return migrationError
}

// TODO doc
func (c *migrationController) migrateKeysIfNeededAndRevisionStable(ctx context.Context, syncContext factory.SyncContext, encryptedGRs []schema.GroupResource) (migratingResources []schema.GroupResource, err error) {
	// no storage migration during revision changes
	currentEncryptionConfig, desiredEncryptionState, _, isTransitionalReason, err := statemachine.GetEncryptionConfigAndState(ctx, c.deployer, c.secretClient, c.encryptionSecretSelector, encryptedGRs)
	if err != nil {
		return nil, err
	}
	if currentEncryptionConfig == nil || len(isTransitionalReason) > 0 {
		syncContext.Queue().AddAfter(syncContext.QueueKey(), 2*time.Minute)
		return nil, nil
	}

	encryptionSecrets, err := secrets.ListKeySecrets(ctx, c.secretClient, c.encryptionSecretSelector)
	if err != nil {
		return nil, err
	}
	currentState, _ := encryptiondata.ToEncryptionState(currentEncryptionConfig, encryptionSecrets)
	desiredEncryptedSecretData, err := encryptiondata.FromEncryptionState(desiredEncryptionState)
	if err != nil {
		return nil, err
	}

	// no storage migration until config is stable
	if !reflect.DeepEqual(currentEncryptionConfig.Encryption.Resources, desiredEncryptedSecretData.Encryption.Resources) {
		// stop all running migrations
		for gr := range currentState {
			if err := c.migrator.PruneMigration(gr); err != nil {
				klog.Warningf("failed to interrupt migration for resource %s", gr)
				// ignore error
			}
		}

		syncContext.Queue().AddAfter(syncContext.QueueKey(), 2*time.Minute)
		return nil, nil // retry in a little while but do not go degraded
	}

	// sort by gr to get deterministic condition strings
	grs := []schema.GroupResource{}
	for gr := range currentState {
		grs = append(grs, gr)
	}
	sort.Slice(grs, func(i, j int) bool {
		return grs[i].String() < grs[j].String()
	})

	// all API servers have converged onto a single revision that matches our desired overall encryption state
	// now we know that it is safe to attempt key migrations
	// we never want to migrate during an intermediate state because that could lead to one API server
	// using a write key that another API server has not observed
	// this could lead to etcd storing data that not all API servers can decrypt
	if err := c.reconcileRotationStatus(ctx, currentEncryptionConfig, currentState, encryptedGRs); err != nil {
		return nil, err
	}

	healthReports := c.healthReportsFromOperator()

	var errs []error
	for _, gr := range grs {
		grActualKeys := currentState[gr]
		if !grActualKeys.HasWriteKey() {
			continue // no write key to migrate to
		}

		convergedKEKID, _ := encryptionstatus.ConvergedKEKForKeyID(healthReports, grActualKeys.WriteKey.Key.Name)
		alreadyMigrated, _, _ := state.MigratedFor([]schema.GroupResource{gr}, grActualKeys.WriteKey)
		if alreadyMigrated && !encryptionstatus.WriteKeyNeedsKEKRemigration(grActualKeys.WriteKey, convergedKEKID) {
			continue
		}

		if alreadyMigrated && encryptionstatus.WriteKeyNeedsKEKRemigration(grActualKeys.WriteKey, convergedKEKID) {
			if err := c.migrator.PruneMigration(gr); err != nil {
				errs = append(errs, err)
				continue
			}
		}

		// idem-potent migration start
		finished, result, when, err := c.migrator.EnsureMigration(gr, grActualKeys.WriteKey.Key.Name)
		if err == nil && finished && result != nil && time.Since(when) > migrationRetryDuration {
			// last migration error is far enough ago. Prune and retry.
			if err := c.migrator.PruneMigration(gr); err != nil {
				errs = append(errs, err)
				continue
			}
			finished, result, when, err = c.migrator.EnsureMigration(gr, grActualKeys.WriteKey.Key.Name)

		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if finished && result != nil {
			errs = append(errs, result)
			continue
		}

		if !finished {
			migratingResources = append(migratingResources, gr)
			continue
		}

		// update secret annotations
		oldWriteKey, err := secrets.FromKeyState(c.instanceName, grActualKeys.WriteKey)
		if err != nil {
			errs = append(errs, result)
			continue
		}
		if err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
			s, err := c.secretClient.Secrets(oldWriteKey.Namespace).Get(ctx, oldWriteKey.Name, metav1.GetOptions{})
			if err != nil {
				return fmt.Errorf("failed to get key secret %s/%s: %v", oldWriteKey.Namespace, oldWriteKey.Name, err)
			}

			changed, err := setResourceMigrated(gr, s, convergedKEKID)
			if err != nil {
				return err
			}
			if !changed {
				return nil
			}

			// Use direct Update instead of ApplySecret to only update annotations.
			// ApplySecret does its own internal GET which bypasses ResourceVersion
			// conflict detection and can silently overwrite concurrent annotation changes.
			_, updateErr := c.secretClient.Secrets(s.Namespace).Update(ctx, s, metav1.UpdateOptions{})
			resourcehelper.ReportUpdateEvent(syncContext.Recorder(), s, updateErr)
			return updateErr
		}); err != nil {
			errs = append(errs, err)
			continue
		}
	}

	return migratingResources, errors.NewAggregate(errs)
}

func setResourceMigrated(gr schema.GroupResource, s *corev1.Secret, convergedKEKID string) (bool, error) {
	migratedGRs := secrets.MigratedGroupResources{}
	if existing, found := s.Annotations[secrets.EncryptionSecretMigratedResources]; found {
		if err := json.Unmarshal([]byte(existing), &migratedGRs); err != nil {
			// ignore error and just start fresh, causing some more migration at worst
			migratedGRs = secrets.MigratedGroupResources{}
		}
	}

	alreadyMigrated := false
	for _, existingGR := range migratedGRs.Resources {
		if existingGR == gr {
			alreadyMigrated = true
			break
		}
	}

	// update timestamp, if missing or first migration of gr
	if _, found := s.Annotations[secrets.EncryptionSecretMigratedTimestamp]; found && alreadyMigrated {
		if len(convergedKEKID) == 0 || s.Annotations[secrets.EncryptionSecretMigratedKEKID] == convergedKEKID {
			return false, nil
		}
	}
	if s.Annotations == nil {
		s.Annotations = map[string]string{}
	}
	s.Annotations[secrets.EncryptionSecretMigratedTimestamp] = time.Now().Format(time.RFC3339)

	// update resource list
	if !alreadyMigrated {
		migratedGRs.Resources = append(migratedGRs.Resources, gr)
		bs, err := json.Marshal(migratedGRs)
		if err != nil {
			return false, fmt.Errorf("failed to marshal %s annotation value %#v for key secret %s/%s", secrets.EncryptionSecretMigratedResources, migratedGRs, s.Namespace, s.Name)
		}
		s.Annotations[secrets.EncryptionSecretMigratedResources] = string(bs)
	}

	if len(convergedKEKID) > 0 && s.Annotations[secrets.EncryptionSecretMigratedKEKID] != convergedKEKID {
		s.Annotations[secrets.EncryptionSecretMigratedKEKID] = convergedKEKID
	}

	return true, nil
}

func (c *migrationController) healthReportsFromOperator() []encryptionstatus.KMSPluginHealthReport {
	_, operatorStatus, _, err := c.operatorClient.GetOperatorState()
	if err != nil {
		klog.Warningf("%s: failed to read operator status for KMS health reports: %v", c.instanceName, err)
		return nil
	}
	return encryptionstatus.HealthReportsFromOperatorStatus(operatorStatus)
}

func (c *migrationController) reconcileRotationStatus(
	ctx context.Context,
	currentEncryptionConfig *encryptiondata.Config,
	currentState map[schema.GroupResource]state.GroupResourceState,
	encryptedGRs []schema.GroupResource,
) error {
	if currentEncryptionConfig == nil || !currentEncryptionConfig.UsesKMS() {
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

	now := metav1.Now()
	before := append([]encryptionstatus.KMSPluginRotationStatus(nil), rotations...)
	for _, gr := range encryptedGRs {
		grState := currentState[gr]
		if !grState.HasWriteKey() || grState.WriteKey.Mode != state.KMS {
			continue
		}

		keyID := grState.WriteKey.Key.Name
		convergedKEKID, converged := encryptionstatus.ConvergedKEKForKeyID(healthReports, keyID)
		if !converged {
			continue
		}

		rotations, openIdx := encryptionstatus.GetOrCreateOpenRotation(rotations, keyID, convergedKEKID, now)

		writeKeySecret, err := secrets.FromKeyState(c.instanceName, grState.WriteKey)
		if err != nil {
			return err
		}
		migrated, err := encryptionstatus.AllEncryptedGRsMigrated(writeKeySecret, encryptedGRs)
		if err != nil {
			return err
		}
		rotations = mirrorMigrationFinish(c.instanceName, rotations, openIdx, migrated, writeKeySecret)
	}

	if rotationsEqual(before, rotations) {
		return nil
	}

	_, updated, err := operatorv1helpers.UpdateStatus(ctx, c.operatorClient, encryptionstatus.SetKeyRotationStatusCondition(rotations))
	if err != nil {
		return err
	}
	if updated {
		klog.Infof("%s: updated key rotation status (%d entries)", c.instanceName, len(rotations))
	}
	return nil
}

func rotationsEqual(a, b []encryptionstatus.KMSPluginRotationStatus) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].KeyID != b[i].KeyID ||
			a[i].KEKID != b[i].KEKID ||
			!timesEqual(a[i].DiscoveryTime, b[i].DiscoveryTime) ||
			!timesEqual(a[i].MigrationStartTime, b[i].MigrationStartTime) ||
			!timesEqual(a[i].MigrationFinishTime, b[i].MigrationFinishTime) {
			return false
		}
	}
	return true
}

func timesEqual(a, b *metav1.Time) bool {
	switch {
	case a == nil && b == nil:
		return true
	case a == nil || b == nil:
		return false
	default:
		return a.Time.Equal(b.Time)
	}
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

// groupToHumanReadable extracts a group from gr and makes it more readable, for example it converts an empty group to "core"
// Note: do not use it to get resources from the server only when printing to a log file
func groupToHumanReadable(gr schema.GroupResource) string {
	group := gr.Group
	if len(group) == 0 {
		group = "core"
	}
	return group
}

func grsToHumanReadable(grs []schema.GroupResource) []string {
	ret := make([]string, 0, len(grs))
	for _, gr := range grs {
		ret = append(ret, fmt.Sprintf("%s/%s", groupToHumanReadable(gr), gr.Resource))
	}
	return ret
}
