package staleconditions

import (
	"context"
	"time"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

type RemoveStaleConditionsController struct {
	controllerInstanceName string
	conditionTypesToRemove []string
	operatorClient         v1helpers.OperatorClient
}

func NewRemoveStaleConditionsController(
	instanceName string,
	conditionTypes []string,
	operatorClient v1helpers.OperatorClient,
	eventRecorder events.Recorder,
) factory.Controller {
	c := &RemoveStaleConditionsController{
		controllerInstanceName: factory.ControllerInstanceName(instanceName, "RemoveStaleConditions"),
		conditionTypesToRemove: conditionTypes,
		operatorClient:         operatorClient,
	}
	return factory.New().
		ResyncEvery(time.Minute).
		WithSync(c.sync).
		WithControllerInstanceName(c.controllerInstanceName).
		WithInformers(operatorClient.Informer()).
		ToController(
			c.controllerInstanceName,
			eventRecorder.WithComponentSuffix("remove-stale-conditions"),
		)
}

func (c RemoveStaleConditionsController) sync(ctx context.Context, syncContext factory.SyncContext) error {
	_, operatorStatus, _, err := c.operatorClient.GetOperatorState()
	if err != nil {
		return err
	}

	jsonPatch := v1helpers.RemoveConditionsJSONPatch(operatorStatus, c.conditionTypesToRemove)
	if jsonPatch.IsEmpty() {
		return nil
	}

	return c.operatorClient.PatchOperatorStatus(ctx, jsonPatch)
}
