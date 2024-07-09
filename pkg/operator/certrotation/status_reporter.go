package certrotation

import (
	"context"
	"fmt"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/operator/condition"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

// StatusReporter knows how to report the status of cert rotation
type StatusReporter interface {
	Report(ctx context.Context, controllerName string, syncErr error) (updated bool, updateErr error)
}

var _ StatusReporter = (*StaticPodConditionStatusReporter)(nil)

type StaticPodConditionStatusReporter struct {
	// Plumbing:
	OperatorClient v1helpers.StaticPodOperatorClient
}

func (s *StaticPodConditionStatusReporter) Report(ctx context.Context, controllerName string, syncErr error) (bool, error) {
	newCondition := operatorv1.OperatorCondition{
		Type:   fmt.Sprintf(condition.CertRotationDegradedConditionTypeFmt, controllerName),
		Status: operatorv1.ConditionFalse,
	}
	if syncErr != nil {
		newCondition.Status = operatorv1.ConditionTrue
		newCondition.Reason = "RotationError"
		newCondition.Message = syncErr.Error()
	}
	_, updated, updateErr := v1helpers.UpdateStaticPodStatus(ctx, s.OperatorClient, v1helpers.UpdateStaticPodConditionFn(newCondition))
	return updated, updateErr
}
