package controllers

import (
	"context"
	"fmt"
	"strings"
	"time"

	operatorv1 "github.com/openshift/api/operator/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/sets"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

	configv1informers "github.com/openshift/client-go/config/informers/externalversions/config/v1"
	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/encryption/encryptionconfig"
	"github.com/openshift/library-go/pkg/operator/encryption/state"
	"github.com/openshift/library-go/pkg/operator/encryption/statemachine"
	"github.com/openshift/library-go/pkg/operator/events"
	operatorv1helpers "github.com/openshift/library-go/pkg/operator/v1helpers"
)

// conditionController maintains the Encrypted condition. It sets it to true iff there is a
// fully migrated read-key in the current config, and no later key is of identity type.
type conditionController struct {
	controllerInstanceName string
	operatorClient         operatorv1helpers.OperatorClient

	encryptionSecretSelector metav1.ListOptions

	deployer                 statemachine.Deployer
	provider                 Provider
	preconditionsFulfilledFn preconditionsFulfilled
	secretClient             corev1client.SecretsGetter
}

func NewConditionController(
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
	c := &conditionController{
		controllerInstanceName: factory.ControllerInstanceName(instanceName, "EncryptionCondition"),
		operatorClient:         operatorClient,

		encryptionSecretSelector: encryptionSecretSelector,
		deployer:                 deployer,
		provider:                 provider,
		preconditionsFulfilledFn: preconditionsFulfilledFn,
		secretClient:             secretClient,
	}

	return factory.New().WithInformers(
		kubeInformersForNamespaces.InformersFor("openshift-config-managed").Core().V1().Secrets().Informer(),
		operatorClient.Informer(),
		apiServerConfigInformer.Informer(), // do not remove, used by the precondition checker
		deployer,
	).ResyncEvery(time.Minute).
		WithSync(c.sync).
		ToController(
			c.controllerInstanceName,
			eventRecorder.WithComponentSuffix("encryption-condition-controller"),
		)
}

func (c *conditionController) sync(ctx context.Context, _ factory.SyncContext) (err error) {
	// Status for this condition is left out to make sure it's correctly set in every branch
	cond := applyoperatorv1.OperatorCondition().WithType("Encrypted")
	defer func() {
		if cond == nil {
			return
		}
		status := applyoperatorv1.OperatorStatus().WithConditions(cond)
		if applyError := c.operatorClient.ApplyOperatorStatus(ctx, c.controllerInstanceName, status); applyError != nil {
			err = applyError
		}
	}()

	if ready, err := shouldRunEncryptionController(c.operatorClient, c.preconditionsFulfilledFn, c.provider.ShouldRunEncryptionControllers); err != nil || !ready {
		if err != nil {
			cond = nil
		} else {
			cond = cond.WithStatus(operatorv1.ConditionFalse)
		}
		return err // we will get re-kicked when the operator status updates
	}

	encryptedGRs := c.provider.EncryptedGRs()
	currentConfig, desiredState, foundSecrets, transitioningReason, err := statemachine.GetEncryptionConfigAndState(ctx, c.deployer, c.secretClient, c.encryptionSecretSelector, encryptedGRs)
	if err != nil || len(transitioningReason) > 0 {
		// do not update the encryption condition (cond). Note: progressing is set elsewhere.
		cond = nil
		return err
	}
	currentState, _ := encryptionconfig.ToEncryptionState(currentConfig, foundSecrets)

	cond = cond.
		WithStatus(operatorv1.ConditionTrue).
		WithReason("EncryptionCompleted").
		WithMessage(fmt.Sprintf("All resources encrypted: %s", grString(encryptedGRs)))

	if len(foundSecrets) == 0 {
		cond = cond.
			WithStatus(operatorv1.ConditionFalse).
			WithReason("EncryptionDisabled").
			WithMessage("Encryption is not enabled")
	} else {
		// check for identity key in desired state first. This will make us catch upcoming decryption early before
		// it settles into the current config.
		for _, s := range desiredState {
			if s.WriteKey.Mode != state.Identity {
				continue
			}

			if allMigrated(encryptedGRs, s.WriteKey.Migrated.Resources) {
				cond = cond.
					WithStatus(operatorv1.ConditionFalse).
					WithReason("DecryptionCompleted").
					WithMessage("Encryption mode set to identity and everything is decrypted")
			} else {
				cond = cond.
					WithStatus(operatorv1.ConditionFalse).
					WithReason("DecryptionInProgress").
					WithMessage("Encryption mode set to identity and decryption is not finished")
			}
			break
		}
	}

	if *cond.Status == operatorv1.ConditionTrue {
		// now that the desired state look like it won't lead to identity as write-key, test the current state
	NextResource:
		for _, gr := range encryptedGRs {
			s, ok := currentState[gr]
			if !ok {
				cond = cond.
					WithStatus(operatorv1.ConditionFalse).
					WithReason("EncryptionInProgress").
					WithMessage(fmt.Sprintf("Resource %s is not encrypted", gr.String()))
				break NextResource
			}

			if s.WriteKey.Mode == state.Identity {
				if allMigrated(encryptedGRs, s.WriteKey.Migrated.Resources) {
					cond = cond.
						WithStatus(operatorv1.ConditionFalse).
						WithReason("DecryptionCompleted").
						WithMessage("Encryption mode set to identity and everything is decrypted")
				} else {
					cond = cond.
						WithStatus(operatorv1.ConditionFalse).
						WithReason("DecryptionInProgress").
						WithMessage("Encryption mode set to identity and decryption is not finished")
				}
				break
			}

			// go through read keys until we find a completely migrated one. Finding an identity mode before
			// means migration is ongoing. :
			for _, rk := range s.ReadKeys {
				if rk.Mode == state.Identity {
					cond = cond.
						WithStatus(operatorv1.ConditionFalse).
						WithReason("EncryptionInProgress").
						WithMessage("Encryption is ongoing")
					break NextResource
				}
				if migratedSet(rk.Migrated.Resources).Has(gr.String()) {
					continue NextResource
				}
			}

			cond = cond.
				WithStatus(operatorv1.ConditionFalse).
				WithReason("EncryptionInProgress").
				WithMessage(fmt.Sprintf("Resource %s is being encrypted", gr.String()))
			break
		}
	}
	return nil
}

func allMigrated(toBeEncrypted, migrated []schema.GroupResource) bool {
	s := migratedSet(migrated)
	for _, gr := range toBeEncrypted {
		if !s.Has(gr.String()) {
			return false
		}
	}
	return true
}

func migratedSet(grs []schema.GroupResource) sets.Set[string] {
	migrated := sets.New[string]()
	for _, gr := range grs {
		migrated.Insert(gr.String())
	}
	return migrated
}

func grString(grs []schema.GroupResource) string {
	ss := make([]string, 0, len(grs))
	for _, gr := range grs {
		ss = append(ss, gr.String())
	}
	return strings.Join(ss, ", ")
}
