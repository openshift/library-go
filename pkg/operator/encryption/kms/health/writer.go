package health

import (
	"context"
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

// crName is the singleton name shared by OpenShift operator config CRs.
const crName = "cluster"

// encryptionStatusWriter publishes the health reports into the target CR's
// status. It is the seam Config consumes; dynamicWriter.write satisfies it.
type encryptionStatusWriter func(ctx context.Context, status *applyoperatorv1.KMSEncryptionStatusApplyConfiguration) error

// dynamicWriter applies KMSEncryptionStatus to the caller's CR via the dynamic
// client. gvr/kind/path are the caller-supplied CR coordinates; fieldManager is
// the per-node ownership identity written during SSA.
type dynamicWriter struct {
	client       dynamic.Interface
	gvr          schema.GroupVersionResource
	kind         string
	path         []string
	fieldManager string
}

func newDynamicWriter(
	restConfig *rest.Config,
	gvr schema.GroupVersionResource, kind string, path []string,
	fieldManager string,
) (*dynamicWriter, error) {
	client, err := dynamic.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("build dynamic client: %w", err)
	}
	return &dynamicWriter{
		client:       client,
		gvr:          gvr,
		kind:         kind,
		path:         path,
		fieldManager: fieldManager,
	}, nil
}

func (w *dynamicWriter) write(ctx context.Context, status *applyoperatorv1.KMSEncryptionStatusApplyConfiguration) error {
	obj, err := buildApplyObject(w.gvr, w.kind, w.path, status)
	if err != nil {
		return err
	}
	_, err = w.client.Resource(w.gvr).ApplyStatus(ctx, crName, obj, metav1.ApplyOptions{
		FieldManager: w.fieldManager,
		Force:        true,
	})
	if err != nil {
		return fmt.Errorf("apply %s status: %w", w.kind, err)
	}
	return nil
}

// buildApplyObject flattens the typed leaf back to a map and wraps it in the
// per-CR envelope. The flatten only exists because the client is dynamic.
func buildApplyObject(
	gvr schema.GroupVersionResource, kind string, path []string,
	status *applyoperatorv1.KMSEncryptionStatusApplyConfiguration,
) (*unstructured.Unstructured, error) {
	leaf, err := runtime.DefaultUnstructuredConverter.ToUnstructured(status)
	if err != nil {
		return nil, fmt.Errorf("convert encryption status: %w", err)
	}

	obj := &unstructured.Unstructured{Object: map[string]any{}}
	obj.SetAPIVersion(gvr.GroupVersion().String())
	obj.SetKind(kind)
	obj.SetName(crName)
	if err := unstructured.SetNestedMap(obj.Object, leaf, path...); err != nil {
		return nil, fmt.Errorf("set %v: %w", path, err)
	}
	return obj, nil
}

// buildEncryptionStatus builds the typed leaf. Typed gets field names, enums and
// time formatting right for free.
func buildEncryptionStatus(
	nodeName string, reports []pluginHealthReport,
) *applyoperatorv1.KMSEncryptionStatusApplyConfiguration {
	healthReports := make([]*applyoperatorv1.KMSPluginHealthReportApplyConfiguration, 0, len(reports))
	for _, r := range reports {
		hr := applyoperatorv1.KMSPluginHealthReport().
			WithNodeName(nodeName).
			WithKeyId(r.KeyID).
			WithStatus(mapStatus(r.Status)).
			WithLastCheckedTime(metav1.NewTime(r.LastChecked))

		// kekId/detail have MinLength=1; setting "" would fail validation.
		if r.KEKID != "" {
			hr = hr.WithKEKId(r.KEKID)
		}
		if r.Detail != "" {
			hr = hr.WithDetail(r.Detail)
		}

		healthReports = append(healthReports, hr)
	}

	return applyoperatorv1.KMSEncryptionStatus().WithHealthReports(healthReports...)
}

// mapStatus defaults to Error so an unknown value never becomes an empty,
// invalid enum.
func mapStatus(s string) operatorv1.KMSPluginHealthStatus {
	switch s {
	case statusHealthy:
		return operatorv1.KMSPluginHealthStatusHealthy
	case statusUnhealthy:
		return operatorv1.KMSPluginHealthStatusUnhealthy
	default:
		return operatorv1.KMSPluginHealthStatusError
	}
}
