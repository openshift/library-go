package health

import (
	"context"
	"encoding/json"
	"fmt"

	operatorv1 "github.com/openshift/api/operator/v1"
	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

const operatorCRName = "cluster"

type Writer struct {
	client   dynamic.ResourceInterface
	gvk      schema.GroupVersionKind
	nodeName string
}

func newWriter(cfg *rest.Config, gvr schema.GroupVersionResource, gvk schema.GroupVersionKind, nodeName string) (*Writer, error) {
	dynamicClient, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("create dynamic client: %w", err)
	}

	return &Writer{
		client:   dynamicClient.Resource(gvr),
		gvk:      gvk,
		nodeName: nodeName,
	}, nil
}

func (w *Writer) Apply(ctx context.Context, conditions []PluginHealthCondition) error {
	msg, err := json.Marshal(conditions)
	if err != nil {
		return fmt.Errorf("marshal conditions: %w", err)
	}

	cond := applyoperatorv1.OperatorCondition().
		WithType("KMSHealthReporter_" + w.nodeName).
		WithStatus(operatorv1.ConditionTrue).
		WithReason("AsExpected").
		WithMessage(string(msg))

	status := applyoperatorv1.OperatorStatus().WithConditions(cond)

	statusUnstructured, err := runtime.DefaultUnstructuredConverter.ToUnstructured(status)
	if err != nil {
		return fmt.Errorf("convert status to unstructured: %w", err)
	}

	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"status": statusUnstructured,
		},
	}
	obj.SetGroupVersionKind(w.gvk)
	obj.SetName(operatorCRName)

	fieldManager := "kms-health-monitor-" + w.nodeName
	_, err = w.client.ApplyStatus(ctx, operatorCRName, obj, metav1.ApplyOptions{
		Force:        true,
		FieldManager: fieldManager,
	})
	return err
}
