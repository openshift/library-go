package certrotation

import (
	"context"
	"fmt"

	operatorv1 "github.com/openshift/api/operator/v1"

	"github.com/openshift/library-go/pkg/operator/condition"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

// StatusReporter receives per-target sync results so operators can surface
// rotation health in their status conditions. It has the same method set as
// v1's StatusReporter, so existing reporters (v1's
// StaticPodConditionStatusReporter, hypershift's
// HostedControlPlaneStatusReporter, MCO's CertRotationStatusReporter)
// satisfy it unchanged.
type StatusReporter interface {
	Report(ctx context.Context, targetName string, syncErr error) (updated bool, err error)
}

// staticPodConditionReporter writes CertRotation_<targetName>_Degraded
// conditions with reason "RotationError" through the static pod operator
// client. Condition type and reason are identical to v1's
// StaticPodConditionStatusReporter.
type staticPodConditionReporter struct {
	client v1helpers.StaticPodOperatorClient
}

// NewStaticPodConditionReporter returns a StatusReporter that writes
// CertRotation_<targetName>_Degraded conditions. A nil syncErr clears the
// condition.
func NewStaticPodConditionReporter(client v1helpers.StaticPodOperatorClient) StatusReporter {
	return &staticPodConditionReporter{client: client}
}

// Report updates the target's Degraded condition.
func (r *staticPodConditionReporter) Report(ctx context.Context, targetName string, syncErr error) (bool, error) {
	newCondition := operatorv1.OperatorCondition{
		Type:   fmt.Sprintf(condition.CertRotationDegradedConditionTypeFmt, targetName),
		Status: operatorv1.ConditionFalse,
	}
	if syncErr != nil {
		newCondition.Status = operatorv1.ConditionTrue
		newCondition.Reason = "RotationError"
		newCondition.Message = syncErr.Error()
	}
	_, updated, updateErr := v1helpers.UpdateStaticPodStatus(ctx, r.client, v1helpers.UpdateStaticPodConditionFn(newCondition))
	return updated, updateErr
}
