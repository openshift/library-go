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

// NewKMSPreflightController validates KMS configuration before a key is created.
//
// Coordination with the key-controller:
//
// The key-controller writes a hash of the current KMS config to operator status
// as the EncryptionKMSPreflightRequired condition (hash in the message).
// This controller reads that hash, runs preflight checks, and on success sets
// the EncryptionKMSPreflightSucceeded condition (same hash in the message).
// The key-controller waits for the two hashes to match before creating a key.
//
// This is the same pattern used by the revision and installer controllers:
// the revision controller writes LatestAvailableRevision, the installer
// controller reads it and acts.
//
// Without this protocol the following race can occur:
//  1. Preflight passes for config A, hash A written to operator status.
//  2. Key-controller reads hash A, starts creating a key for config A.
//  3. Config changes to B.
//  4. Preflight controller syncs, sees config B, does not yet see the key
//     for A (key-controller is in the process of creating the key),
//     runs preflight for B, overwrites status with hash B.
//  5. The key created in step 2 was for config A but status now says B.
//
// Letting the key-controller own EncryptionKMSPreflightRequired and this
// controller own EncryptionKMSPreflightSucceeded solves this. If the config
// changes mid-flight the key-controller posts a new hash and the preflight
// controller sees the mismatch and waits.
//
// Example 1: config changes before key is created
//  1. User creates KMS config A.
//  2. Key-controller computes hash A, writes EncryptionKMSPreflightRequired=A.
//  3. Preflight controller sees required=A, starts checking A.
//  4. User changes config to A2 (minor variation, different hash).
//  5. Key-controller computes hash A2, writes EncryptionKMSPreflightRequired=A2.
//  6. Preflight controller sees required=A2, starts checking A2.
//  7. Key-controller does not create a key until succeeded=A2.
//
// Example 2: config changes after key is created
//  1. User creates KMS config A.
//  2. Key-controller computes hash A, writes EncryptionKMSPreflightRequired=A.
//  3. Preflight controller checks A, succeeds, writes EncryptionKMSPreflightSucceeded=A.
//  4. Key-controller sees required=A matches succeeded=A, creates key for A.
//  5. User changes config to A2 (or B).
//  6. Key-controller waits until the key for A completes the full cycle
//     (read, write, migrated) before creating a new key. No preflight done
//     at this stage.
//
// Preflight pod:
//
// The pod uses readiness gates to post check results back to the controller.
// The controller creates a ServiceAccount, Role and RoleBinding so that the pod
// can update its own status. These resources are cleaned up when the pod is removed.
// The controller reads these enhanced pod statuses to update its own operator
// status, which is propagated to end users.
//
// After a successful check the preflight pod is kept for a short period (e.g. 1h)
// so that its logs can be inspected, then cleaned up by a subsequent sync.
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
	degradedCondition := applyoperatorv1.OperatorCondition().WithType("EncryptionKMSPreflightControllerDegraded")

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
