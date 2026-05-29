package health

import (
	"context"
	"encoding/json"
	"fmt"

	operatorv1 "github.com/openshift/api/operator/v1"
	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"
	"github.com/openshift/library-go/pkg/operator/genericoperatorclient"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/rest"
	"k8s.io/utils/clock"
)

type Writer struct {
	operatorClient v1helpers.OperatorClientWithFinalizers
	nodeName       string
}

func (w *Writer) Apply(ctx context.Context, conditions []PluginHealthCondition) error {
	msg, err := json.Marshal(conditions)
	if err != nil {
		return fmt.Errorf("marshal conditions: %w", err)
	}

	// Hardcoded to avoid StatusSyncer side-effects; will be rewritten after API change in operator CR status.
	cond := applyoperatorv1.OperatorCondition().
		WithType("KMSHealthReporter_" + w.nodeName).
		WithStatus(operatorv1.ConditionTrue).
		WithReason("AsExpected").
		WithMessage(string(msg))

	status := applyoperatorv1.OperatorStatus().WithConditions(cond)
	fieldManager := "kms-health-monitor-" + w.nodeName
	return w.operatorClient.ApplyOperatorStatus(ctx, fieldManager, status)
}

func buildWriter(cfg *rest.Config, targetOperator TargetOperator, nodeName string) (*Writer, error) {
	target := supportedOperators[targetOperator]
	operatorClient, _, err := genericoperatorclient.NewClusterScopedOperatorClient(
		clock.RealClock{}, cfg, target.GVR, target.GVK,
		emptyOperatorSpec, emptyOperatorStatus,
	)
	if err != nil {
		return nil, fmt.Errorf("build operator client for %s: %w", targetOperator, err)
	}

	return &Writer{operatorClient: operatorClient, nodeName: nodeName}, nil
}

func emptyOperatorSpec(_ *unstructured.Unstructured, _ string) (*applyoperatorv1.OperatorSpecApplyConfiguration, error) {
	return applyoperatorv1.OperatorSpec(), nil
}

func emptyOperatorStatus(_ *unstructured.Unstructured, _ string) (*applyoperatorv1.OperatorStatusApplyConfiguration, error) {
	return applyoperatorv1.OperatorStatus(), nil
}
