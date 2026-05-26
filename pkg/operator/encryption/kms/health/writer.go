package health

import (
	"fmt"

	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"
	"github.com/openshift/library-go/pkg/operator/genericoperatorclient"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/rest"
	"k8s.io/utils/clock"
)

func buildWriter(cfg *rest.Config, targetOperator TargetOperator) (v1helpers.OperatorClientWithFinalizers, error) {
	target := supportedOperators[TargetOperator(targetOperator)]
	operatorClient, _, err := genericoperatorclient.NewClusterScopedOperatorClient(
		clock.RealClock{}, cfg, target.GVR, target.GVK,
		emptyOperatorSpec, emptyOperatorStatus,
	)
	if err != nil {
		return nil, fmt.Errorf("build operator client for %s: %w", targetOperator, err)
	}

	// TODO create writer

	return operatorClient, nil
}

func emptyOperatorSpec(_ *unstructured.Unstructured, _ string) (*applyoperatorv1.OperatorSpecApplyConfiguration, error) {
	return applyoperatorv1.OperatorSpec(), nil
}

func emptyOperatorStatus(_ *unstructured.Unstructured, _ string) (*applyoperatorv1.OperatorStatusApplyConfiguration, error) {
	return applyoperatorv1.OperatorStatus(), nil
}
