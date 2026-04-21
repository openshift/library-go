package controllers

import (
	"context"
	"fmt"
	"time"

	operatorv1 "github.com/openshift/api/operator/v1"
	configv1client "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
	configv1informers "github.com/openshift/client-go/config/informers/externalversions/config/v1"
	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	operatorv1helpers "github.com/openshift/library-go/pkg/operator/v1helpers"
)

type kmsPreflightController struct {
	controllerInstanceName string

	operatorClient  operatorv1helpers.OperatorClient
	apiServerClient configv1client.APIServerInterface

	provider                 Provider
	preconditionsFulfilledFn preconditionsFulfilled
}

// TODO: document NewKMSPreflightController
func NewKMSPreflightController(
	instanceName string,
	provider Provider,
	preconditionsFulfilledFn preconditionsFulfilled,
	operatorClient operatorv1helpers.OperatorClient,
	apiServerClient configv1client.APIServerInterface,
	apiServerInformer configv1informers.APIServerInformer,
	eventRecorder events.Recorder,
) factory.Controller {
	c := &kmsPreflightController{
		controllerInstanceName: factory.ControllerInstanceName(instanceName, "EncryptionKMSPreflight"),

		operatorClient:  operatorClient,
		apiServerClient: apiServerClient,

		provider:                 provider,
		preconditionsFulfilledFn: preconditionsFulfilledFn,
	}

	return factory.New().ResyncEvery(time.Minute).WithSync(c.sync).WithControllerInstanceName(c.controllerInstanceName).WithInformers(
		apiServerInformer.Informer(),
		operatorClient.Informer(),
	).ToController(
		c.controllerInstanceName,
		eventRecorder.WithComponentSuffix("encryption-kms-preflight-controller"),
	)
}

func (c *kmsPreflightController) sync(ctx context.Context, syncCtx factory.SyncContext) (err error) {
	degradedCondition := applyoperatorv1.OperatorCondition().WithType("KMSPreflightControllerDegraded")

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
			degradedCondition = degradedCondition.WithStatus(operatorv1.ConditionFalse)
		}
		return err // we will get re-kicked when the operator status updates
	}

	preflightErr := c.runPreflightChecks(ctx)
	if preflightErr != nil {
		degradedCondition = degradedCondition.
			WithStatus(operatorv1.ConditionTrue).
			WithReason("Error").
			WithMessage(preflightErr.Error())
	} else {
		degradedCondition = degradedCondition.
			WithStatus(operatorv1.ConditionFalse)
	}
	return preflightErr
}

func (c *kmsPreflightController) runPreflightChecks(ctx context.Context) error {
	return fmt.Errorf("implement me")
}
