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
//
// Possible outcomes, evaluated in order:
//   - Progressing=True / NewGeneration: spec changed but the deployment controller
//     has not reconciled yet, and the change is not a pure scale.
//   - Progressing=False / ProgressDeadlineExceeded: the deployment timed out.
//   - Progressing=True / PodsUpdating: rollout is active.
//   - Progressing=False / AsExpected: rollout is complete.
func DeploymentProgressingCondition(deployment *appsv1.Deployment) operatorv1.OperatorCondition {
	desiredReplicas := ptr.Deref(deployment.Spec.Replicas, 1)
	timedOutMessage, timedOut := HasDeploymentTimedOutProgressing(deployment.Status)

	statusIsStale := deployment.Generation != deployment.Status.ObservedGeneration
	// Pure scales never create a new ReplicaSet, so KCM does not update the
	// Progressing condition for them — the existing condition remains accurate.
	// Detect a scale by comparing spec.replicas to status.Replicas (the actual
	// pod count across all ReplicaSets, equal to the old spec in steady state).
	scalePending := desiredReplicas != deployment.Status.Replicas

	switch {
	// Checked before timedOut so that a spec change applied after a
	// ProgressDeadlineExceeded does not inherit the stale False condition.
	case statusIsStale && !scalePending:
		return operatorv1.OperatorCondition{
			Type:    operatorv1.OperatorStatusTypeProgressing,
			Status:  operatorv1.ConditionTrue,
			Reason:  "NewGeneration",
			Message: fmt.Sprintf("deployment/%s.%s: waiting for deployment controller to observe spec generation %d", deployment.Name, deployment.Namespace, deployment.Generation),
		}

	case timedOut:
		return operatorv1.OperatorCondition{
			Type:    operatorv1.OperatorStatusTypeProgressing,
			Status:  operatorv1.ConditionFalse,
			Reason:  "ProgressDeadlineExceeded",
			Message: fmt.Sprintf("deployment/%s.%s has timed out progressing: %s", deployment.Name, deployment.Namespace, timedOutMessage),
		}

	case !HasDeploymentProgressed(deployment.Status):
		return operatorv1.OperatorCondition{
			Type:    operatorv1.OperatorStatusTypeProgressing,
			Status:  operatorv1.ConditionTrue,
			Reason:  "PodsUpdating",
			Message: fmt.Sprintf("deployment/%s.%s: %d/%d pods have been updated to the latest revision and %d/%d pods are available", deployment.Name, deployment.Namespace, deployment.Status.UpdatedReplicas, desiredReplicas, deployment.Status.AvailableReplicas, desiredReplicas),
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
