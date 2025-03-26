package controllers

import (
	"context"
	"slices"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/klog/v2"

	operatorv1 "github.com/openshift/api/operator/v1"

	configv1informers "github.com/openshift/client-go/config/informers/externalversions/config/v1"
	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/encryption/secrets"
	"github.com/openshift/library-go/pkg/operator/encryption/state"
	"github.com/openshift/library-go/pkg/operator/encryption/statemachine"
	"github.com/openshift/library-go/pkg/operator/events"
	operatorv1helpers "github.com/openshift/library-go/pkg/operator/v1helpers"
)

const (
	keepNumberOfSecrets = 10
)

// pruneController prevents an unbounded growth of old encryption keys.
// For a given resource, if there are more than ten keys which have been migrated,
// this controller will delete the oldest migrated keys until there are ten migrated
// keys total.  These keys are safe to delete since no data in etcd is encrypted using
// them.  Keeping a small number of old keys around is meant to help facilitate
// decryption of old backups (and general precaution).
type pruneController struct {
	controllerInstanceName string
	operatorClient         operatorv1helpers.OperatorClient

	encryptionSecretSelector metav1.ListOptions

	deployer                 statemachine.Deployer
	provider                 Provider
	preconditionsFulfilledFn preconditionsFulfilled
	secretClient             corev1client.SecretsGetter
}

func NewPruneController(
	instanceName string,
	provider Provider,
	deployer statemachine.Deployer,
	preconditionsFulfilledFn preconditionsFulfilled,
	operatorClient operatorv1helpers.OperatorClient,
	apiServerConfigInformer configv1informers.APIServerInformer,
	kubeInformersForNamespaces operatorv1helpers.KubeInformersForNamespaces,
	secretClient corev1client.SecretsGetter,
	encryptionSecretSelector metav1.ListOptions,
	eventRecorder events.Recorder,
) factory.Controller {
	c := &pruneController{
		operatorClient:           operatorClient,
		controllerInstanceName:   factory.ControllerInstanceName(instanceName, "EncryptionPrune"),
		encryptionSecretSelector: encryptionSecretSelector,
		deployer:                 deployer,
		provider:                 provider,
		preconditionsFulfilledFn: preconditionsFulfilledFn,
		secretClient:             secretClient,
	}

	return factory.New().ResyncEvery(time.Minute).WithSync(c.sync).WithControllerInstanceName(c.controllerInstanceName).WithInformers(
		operatorClient.Informer(),
		kubeInformersForNamespaces.InformersFor("openshift-config-managed").Core().V1().Secrets().Informer(),
		apiServerConfigInformer.Informer(), // do not remove, used by the precondition checker
		deployer,
	).ToController(
		c.controllerInstanceName,
		eventRecorder.WithComponentSuffix("encryption-prune-controller"),
	)
}

func (c *pruneController) sync(ctx context.Context, syncCtx factory.SyncContext) (err error) {
	// The status for this condition is intentionally omitted to ensure it's correctly set in each branch
	degradedCondition := applyoperatorv1.OperatorCondition().
		WithType("EncryptionPruneControllerDegraded")

	defer func() {
		if degradedCondition == nil {
			return
		}
		status := applyoperatorv1.OperatorStatus().WithConditions(degradedCondition)
		if applyError := c.operatorClient.ApplyOperatorStatus(ctx, c.controllerInstanceName, status); applyError != nil {
			err = applyError
		}
	}()

	if ready, err := shouldRunEncryptionController(c.operatorClient, c.preconditionsFulfilledFn, c.provider.ShouldRunEncryptionControllers); err != nil || !ready {
		if err != nil {
			degradedCondition = nil

		} else {
			degradedCondition = degradedCondition.
				WithStatus(operatorv1.ConditionFalse)
		}
		return err // we will get re-kicked when the operator status updates
	}

	configError := c.deleteOldMigratedSecrets(ctx, syncCtx, c.provider.EncryptedGRs())
	if configError != nil {
		degradedCondition = degradedCondition.
			WithStatus(operatorv1.ConditionTrue).
			WithReason("Error").
			WithMessage(configError.Error())
	} else {
		degradedCondition = degradedCondition.
			WithStatus(operatorv1.ConditionFalse)
	}
	return configError
}

func (c *pruneController) deleteOldMigratedSecrets(ctx context.Context, syncContext factory.SyncContext, encryptedGRs []schema.GroupResource) error {
	_, desiredEncryptionConfig, _, isProgressingReason, err := statemachine.GetEncryptionConfigAndState(ctx, c.deployer, c.secretClient, c.encryptionSecretSelector, encryptedGRs)
	if err != nil {
		return err
	}
	if len(isProgressingReason) > 0 {
		syncContext.Queue().AddAfter(syncContext.QueueKey(), 2*time.Minute)
		return nil
	}

	allUsedKeys := make([]state.KeyState, 0, len(desiredEncryptionConfig))
	for _, grKeys := range desiredEncryptionConfig {
		allUsedKeys = append(allUsedKeys, grKeys.ReadKeys...)
	}

	allSecrets, err := c.secretClient.Secrets("openshift-config-managed").List(ctx, c.encryptionSecretSelector)
	if err != nil {
		return err
	}

	// TODO: verify if prune behaviour works with KMS because we use NameToKeyID

	// sort by keyID
	encryptionSecrets := make([]*corev1.Secret, 0, len(allSecrets.Items))
	for _, s := range allSecrets.Items {
		encryptionSecrets = append(encryptionSecrets, s.DeepCopy()) // don't use &s because it is constant through-out the loop
	}
	sort.Slice(encryptionSecrets, func(i, j int) bool {
		iKeyID, _ := state.NameToKeyID(encryptionSecrets[i].Name)
		jKeyID, _ := state.NameToKeyID(encryptionSecrets[j].Name)
		return iKeyID > jKeyID
	})

	var deleteErrs []error
	skippedKeys := 0
	deletedKeys := 0
NextEncryptionSecret:
	for _, s := range encryptionSecrets {
		k, err := secrets.ToKeyState(s)
		if err == nil {
			// ignore invalid keys, check whether secret is used
			for _, us := range allUsedKeys {
				if state.EqualKeyAndEqualID(&us, &k) {
					continue NextEncryptionSecret
				}
			}
		}

		// skip the most recent unused secrets around
		if skippedKeys < keepNumberOfSecrets {
			skippedKeys++
			continue
		}

		// any secret that isn't a read key isn't used.  just delete them.
		// two phase delete: finalizer, then delete

		// remove our finalizer if it is present
		secret := s.DeepCopy()
		idx := slices.Index(secret.Finalizers, secrets.EncryptionSecretFinalizer)
		if idx > -1 {
			secret.Finalizers = slices.Delete(secret.Finalizers, idx, idx+1)
			var updateErr error
			secret, updateErr = c.secretClient.Secrets("openshift-config-managed").Update(ctx, secret, metav1.UpdateOptions{})
			deleteErrs = append(deleteErrs, updateErr)
			if updateErr != nil {
				continue
			}
		}

		// remove the actual secret
		if err := c.secretClient.Secrets("openshift-config-managed").Delete(ctx, secret.Name, metav1.DeleteOptions{}); err != nil {
			deleteErrs = append(deleteErrs, err)
		} else {
			deletedKeys++
			klog.V(2).Infof("Successfully pruned secret %s/%s", secret.Namespace, secret.Name)
		}
	}
	if deletedKeys > 0 {
		syncContext.Recorder().Eventf("EncryptionKeysPruned", "Successfully pruned %d secrets", deletedKeys)
	}
	return utilerrors.FilterOut(utilerrors.NewAggregate(deleteErrs), errors.IsNotFound)
}
