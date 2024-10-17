package resourceapply

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/json"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	clienttesting "k8s.io/client-go/testing"

	pov1api "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"

	"github.com/openshift/library-go/pkg/operator/events"
)

var structuredServiceMonitor = pov1api.ServiceMonitor{
	TypeMeta: metav1.TypeMeta{
		APIVersion: "monitoring.coreos.com/v1",
		Kind:       "ServiceMonitor",
	},
	ObjectMeta: metav1.ObjectMeta{
		Name:      "test-sm",
		Namespace: "test-ns",
		Labels:    map[string]string{"app": "test-app"},
	},
	Spec: pov1api.ServiceMonitorSpec{
		NamespaceSelector: pov1api.NamespaceSelector{
			MatchNames: []string{"test-ns"},
		},
	},
}

func TestApplyServiceMonitor(t *testing.T) {
	dynamicScheme := runtime.NewScheme()
	dynamicScheme.AddKnownTypeWithName(schema.GroupVersionKind{Group: "monitoring.coreos.com", Version: "v1", Kind: "ServiceMonitor"}, &unstructured.Unstructured{})

	unstructuredServiceMonitor := structuredToUnstructuredServiceMonitor(&structuredServiceMonitor)

	structuredServiceMonitorDifferentLabels := structuredServiceMonitor.DeepCopy()
	structuredServiceMonitorDifferentLabels.Labels = map[string]string{"fake-app": "fake-test-app"}
	unstructuredServiceMonitorDifferentLabels := structuredToUnstructuredServiceMonitor(structuredServiceMonitorDifferentLabels)
	serviceMonitorDifferentLabelsValidationFunc := func(oI interface{}) error {
		o, ok := oI.(*unstructured.Unstructured)
		if !ok {
			return errors.New("unexpected object type")
		}
		gotLabels := o.GetLabels()
		wantLabels := structuredServiceMonitor.Labels
		for k, v := range structuredServiceMonitorDifferentLabels.Labels {
			wantLabels[k] = v
		}
		if !equality.Semantic.DeepEqual(gotLabels, wantLabels) {
			return errors.New(fmt.Sprintf("service monitor labels were not merged correctly (+got, -want): %s", cmp.Diff(gotLabels, wantLabels)))
		}

		return nil
	}

	structuredServiceMonitorDifferentSpec := structuredServiceMonitor.DeepCopy()
	structuredServiceMonitorDifferentSpec.Spec.NamespaceSelector.MatchNames = []string{"different-test-ns"}
	unstructuredServiceMonitorDifferentSpec := structuredToUnstructuredServiceMonitor(structuredServiceMonitorDifferentSpec)

	structuredServiceMonitorDifferentLabelsDifferentSpec := structuredServiceMonitor.DeepCopy()
	structuredServiceMonitorDifferentLabelsDifferentSpec.Spec.NamespaceSelector.MatchNames = []string{"different-test-ns"}
	unstructuredServiceMonitorDifferentLabelsDifferentSpec := structuredToUnstructuredServiceMonitor(structuredServiceMonitorDifferentLabelsDifferentSpec)

	for _, tc := range []struct {
		name                               string
		existing                           *unstructured.Unstructured
		expectExistingResourceToBeModified bool
		expectActionsDuringModification    []string
		delegateValidation                 func(interface{}) error
	}{
		{
			name:                            "same label, same spec",
			existing:                        unstructuredServiceMonitor,
			expectActionsDuringModification: []string{"get"},
		},
		{
			name:                               "different label, same spec",
			existing:                           unstructuredServiceMonitorDifferentLabels,
			expectExistingResourceToBeModified: true,
			expectActionsDuringModification:    []string{"get", "update"},
			delegateValidation:                 serviceMonitorDifferentLabelsValidationFunc,
		},
		{
			name:                               "same label, different spec",
			existing:                           unstructuredServiceMonitorDifferentSpec,
			expectExistingResourceToBeModified: true,
			expectActionsDuringModification:    []string{"get", "update"},
		},
		{
			name:                               "different label, different spec",
			existing:                           unstructuredServiceMonitorDifferentLabelsDifferentSpec,
			expectExistingResourceToBeModified: true,
			expectActionsDuringModification:    []string{"get", "update"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dynamicClient := dynamicfake.NewSimpleDynamicClient(dynamicScheme, tc.existing)
			got, modified, err := ApplyServiceMonitor(context.TODO(), dynamicClient, events.NewInMemoryRecorder("monitor-test"), unstructuredServiceMonitor)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !modified && tc.expectExistingResourceToBeModified {
				t.Fatalf("expected the service monitor to be modified, it was not")
			}

			actions := dynamicClient.Actions()
			if len(actions) != len(tc.expectActionsDuringModification) {
				t.Fatalf("expected %d actions, got %d: %v", len(tc.expectActionsDuringModification), len(actions), actions)
			}
			for i, action := range actions {
				if action.GetVerb() != tc.expectActionsDuringModification[i] {
					t.Fatalf("expected action %d to be %q, got %q", i, tc.expectActionsDuringModification[i], action.GetVerb())
				}
			}

			if tc.delegateValidation != nil {
				if err = tc.delegateValidation(got); err != nil {
					t.Fatalf("delegated validation failed: %v", err)
				}
			} else if len(tc.expectActionsDuringModification) > 1 &&
				tc.expectActionsDuringModification[1] == "update" {
				updateAction, isUpdate := actions[1].(clienttesting.UpdateAction)
				if !isUpdate {
					t.Fatalf("expected second action to be update, got %+v", actions[1])
				}
				updatedMonitorObj := updateAction.GetObject().(*unstructured.Unstructured)

				// Verify `metadata`. Note that the `metadata` is merged in some cases.
				requiredMonitorMetadata, _, _ := unstructured.NestedMap(unstructuredServiceMonitor.UnstructuredContent(), "metadata")
				existingMonitorMetadata, _, _ := unstructured.NestedMap(updatedMonitorObj.UnstructuredContent(), "metadata")
				if !equality.Semantic.DeepEqual(requiredMonitorMetadata, existingMonitorMetadata) {
					t.Fatalf("expected resulting service monitor metadata to match required metadata: %s", cmp.Diff(requiredMonitorMetadata, existingMonitorMetadata))
				}

				// Verify `spec`.
				requiredMonitorSpec, _, _ := unstructured.NestedMap(unstructuredServiceMonitor.UnstructuredContent(), "spec")
				existingMonitorSpec, _, _ := unstructured.NestedMap(updatedMonitorObj.UnstructuredContent(), "spec")
				if !equality.Semantic.DeepEqual(requiredMonitorSpec, existingMonitorSpec) {
					t.Fatalf("expected resulting service monitor spec to match required spec: %s", cmp.Diff(requiredMonitorSpec, existingMonitorSpec))
				}
			}
		})
	}
}

func structuredToUnstructuredServiceMonitor(monitor *pov1api.ServiceMonitor) *unstructured.Unstructured {
	var unstructuredMonitor unstructured.Unstructured
	rawMonitor, err := json.Marshal(monitor)
	if err != nil {
		panic(err)
	}
	err = json.Unmarshal(rawMonitor, &unstructuredMonitor)
	if err != nil {
		panic(err)
	}

	return &unstructuredMonitor
}
