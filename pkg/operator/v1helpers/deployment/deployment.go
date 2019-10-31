// Package deployment contains helpers for operators which manage deployments.
package deployment

import (
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/klog"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

// SetOperatorConditions sets prefixed operator conditions based on the deployment's conditions.
func SetOperatorConditions(conditions *[]operatorv1.OperatorCondition, prefix string, deployment *appsv1.Deployment) error {
	available := operatorv1.ConditionUnknown
	degraded := operatorv1.ConditionUnknown
	for _, condition := range deployment.Status.Conditions {
		operatorCondition := operatorv1.OperatorCondition{
			Status:  v1helpers.ConvertCoreV1StatusToOperatorV1Status(condition.Status),
			Reason:  condition.Reason,
			Message: condition.Message,
		}

		switch condition.Type {
		case appsv1.DeploymentAvailable:
			operatorCondition.Type = prefix + "Available"
			available = operatorCondition.Status
		case appsv1.DeploymentProgressing:
			operatorCondition.Type = prefix + "Progressing"
			if operatorCondition.Status == operatorv1.ConditionFalse && deployment.Status.ObservedGeneration != deployment.ObjectMeta.Generation {
				operatorCondition.Status = operatorv1.ConditionTrue
				operatorCondition.Reason = "ObservedGeneration"
				operatorCondition.Message = fmt.Sprintf("observed generation %d != expected generation %d", deployment.Status.ObservedGeneration, deployment.ObjectMeta.Generation)
			}
		case appsv1.DeploymentReplicaFailure:
			operatorCondition.Type = prefix + "Degraded"
			degraded = operatorCondition.Status
		default:
			klog.V(4).Infof("Unrecognized deployment condition type: %s (reason %s, message %s)", condition.Type, condition.Reason, condition.Message)
			operatorCondition.Type = prefix + string(condition.Type)
		}

		v1helpers.SetOperatorCondition(conditions, operatorCondition)
	}

	if degraded == operatorv1.ConditionUnknown {
		condition := operatorv1.OperatorCondition{
			Type: prefix + "Degraded",
		}

		if available == operatorv1.ConditionTrue {
			condition.Status = operatorv1.ConditionFalse
			condition.Reason = "Available"
			condition.Message = "Available with no replica failures."
		} else {
			condition.Status = operatorv1.ConditionUnknown
			condition.Reason = "Unknown"
			condition.Message = "Not available, but no replica failures either."
		}
		v1helpers.SetOperatorCondition(conditions, condition)
	}

	return nil
}
