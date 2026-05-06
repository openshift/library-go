package deployment

import (
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"

	operatorv1 "github.com/openshift/api/operator/v1"
)

// DeploymentProgressingCondition computes an operator Progressing condition from
// the deployment's own status conditions and replica counts.
func DeploymentProgressingCondition(deployment *appsv1.Deployment) operatorv1.OperatorCondition {
	desiredReplicas := ptr.Deref(deployment.Spec.Replicas, 1)
	timedOutMessage, timedOut := HasDeploymentTimedOutProgressing(deployment.Status)

	switch {
	case !HasDeploymentProgressed(deployment.Status) && !timedOut:
		return operatorv1.OperatorCondition{
			Type:    operatorv1.OperatorStatusTypeProgressing,
			Status:  operatorv1.ConditionTrue,
			Reason:  "PodsUpdating",
			Message: fmt.Sprintf("deployment/%s.%s: %d/%d pods have been updated to the latest revision and %d/%d pods are available", deployment.Name, deployment.Namespace, deployment.Status.UpdatedReplicas, desiredReplicas, deployment.Status.AvailableReplicas, desiredReplicas),
		}

	case timedOut:
		return operatorv1.OperatorCondition{
			Type:    operatorv1.OperatorStatusTypeProgressing,
			Status:  operatorv1.ConditionFalse,
			Reason:  "ProgressDeadlineExceeded",
			Message: fmt.Sprintf("deployment/%s.%s has timed out progressing: %s", deployment.Name, deployment.Namespace, timedOutMessage),
		}

	default:
		return operatorv1.OperatorCondition{
			Type:   operatorv1.OperatorStatusTypeProgressing,
			Status: operatorv1.ConditionFalse,
			Reason: "AsExpected",
		}
	}
}

// HasDeploymentProgressed returns true if the deployment reports NewReplicaSetAvailable
// via the DeploymentProgressing condition.
func HasDeploymentProgressed(status appsv1.DeploymentStatus) bool {
	for _, cond := range status.Conditions {
		if cond.Type == appsv1.DeploymentProgressing {
			return cond.Status == corev1.ConditionTrue && cond.Reason == "NewReplicaSetAvailable"
		}
	}
	return false
}

// HasDeploymentTimedOutProgressing returns true if the deployment reports ProgressDeadlineExceeded.
// The function returns the Progressing condition message as the first return value.
func HasDeploymentTimedOutProgressing(status appsv1.DeploymentStatus) (string, bool) {
	for _, cond := range status.Conditions {
		if cond.Type == appsv1.DeploymentProgressing {
			return cond.Message, cond.Status == corev1.ConditionFalse && cond.Reason == "ProgressDeadlineExceeded"
		}
	}
	return "", false
}
