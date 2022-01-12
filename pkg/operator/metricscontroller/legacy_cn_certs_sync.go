package metricscontroller

import (
	"context"
	"fmt"
	"time"

	prometheusv1 "github.com/prometheus/client_golang/api/prometheus/v1"
	"github.com/prometheus/common/model"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

// NewLegacyCNCertsMetricsSyncFunc creates a metrics sync function that executes the given query
// and interprets the result value as the count of invalid certificates containing CN fields used as host names.
// If the value is >=1 the `InvalidCertsDetected` condition state will be set.
//
// The supported prometheus query result types are:
// - vector: only the first sample of the vector will be used for evaluation.
// - scalar: the returned value will be used.
func NewLegacyCNCertsMetricsSyncFunc(query string, operatorClient v1helpers.OperatorClient) MetricsSyncFunc {
	return func(ctx context.Context, controllerContext factory.SyncContext, client prometheusv1.API) error {
		result, _, err := client.Query(ctx, query, time.Now())
		if err != nil {
			return fmt.Errorf("error executing prometheus query: %w", err)
		}

		var value model.SampleValue
		switch result.Type() {
		case model.ValVector:
			vec := result.(model.Vector)
			if len(vec) == 0 {
				return fmt.Errorf("empty vector result from query: %q", query)
			}
			value = vec[0].Value
		case model.ValScalar:
			value = result.(*model.Scalar).Value
		default:
			return fmt.Errorf("unexpected prometheus query return type: %T", result)
		}

		_, _, err = v1helpers.UpdateStatus(operatorClient, v1helpers.UpdateConditionFn(newInvalidCertsCondition(float64(value))))
		return err
	}
}

func newInvalidCertsCondition(invalidCertsCount float64) operatorv1.OperatorCondition {
	condition := operatorv1.OperatorCondition{
		Type:   "InvalidCertsUpgradeable",
		Status: operatorv1.ConditionTrue,
	}

	if invalidCertsCount >= 1.0 {
		condition.Status = operatorv1.ConditionFalse
		condition.Reason = "InvalidCertsDetected"
		condition.Message = fmt.Sprintf("%d server certificates without SAN detected", int(invalidCertsCount))
	}

	return condition
}
