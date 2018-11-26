package status

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/ghodss/yaml"

	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/diff"
	"k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/tools/cache"

	operatorv1 "github.com/openshift/api/operator/v1"
)

func TestSync(t *testing.T) {

	testCases := []struct {
		conditions            []operatorv1.OperatorCondition
		expectedFailingStatus operatorv1.ConditionStatus
		expectedMessages      []string
		expectedReason        string
	}{
		{
			conditions: []operatorv1.OperatorCondition{
				{Type: "TypeAFailing", Status: operatorv1.ConditionFalse},
			},
			expectedFailingStatus: operatorv1.ConditionFalse,
		},
		{
			conditions: []operatorv1.OperatorCondition{
				{Type: "TypeAFailing", Status: operatorv1.ConditionTrue},
			},
			expectedFailingStatus: operatorv1.ConditionTrue,
			expectedReason:        "TypeAFailing",
		},
		{
			conditions: []operatorv1.OperatorCondition{
				{Type: "TypeAFailing", Status: operatorv1.ConditionTrue, Message: "a message from type a"},
				{Type: "TypeBFailing", Status: operatorv1.ConditionFalse},
			},
			expectedFailingStatus: operatorv1.ConditionTrue,
			expectedReason:        "TypeAFailing",
			expectedMessages: []string{
				"TypeAFailing: a message from type a",
			},
		},
		{
			conditions: []operatorv1.OperatorCondition{
				{Type: "TypeAFailing", Status: operatorv1.ConditionFalse},
				{Type: "TypeBFailing", Status: operatorv1.ConditionTrue, Message: "a message from type b"},
			},
			expectedFailingStatus: operatorv1.ConditionTrue,
			expectedReason:        "TypeBFailing",
			expectedMessages: []string{
				"TypeBFailing: a message from type b",
			},
		},
		{
			conditions: []operatorv1.OperatorCondition{
				{Type: "TypeAFailing", Status: operatorv1.ConditionFalse},
				{Type: "TypeBFailing", Status: operatorv1.ConditionTrue, Message: "a message from type b\nanother message from type b"},
				{Type: "TypeCFailing", Status: operatorv1.ConditionFalse, Message: "a message from type c"},
				{Type: "TypeDFailing", Status: operatorv1.ConditionTrue, Message: "a message from type d"},
			},
			expectedFailingStatus: operatorv1.ConditionTrue,
			expectedReason:        "MultipleConditionsFailing",
			expectedMessages: []string{
				"TypeBFailing: a message from type b",
				"TypeBFailing: another message from type b",
				"TypeDFailing: a message from type d",
			},
		},
	}
	for name, tc := range testCases {
		t.Run(fmt.Sprintf("%05d", name), func(t *testing.T) {
			clusterOperators := &unstructured.Unstructured{
				Object: map[string]interface{}{
					"apiVersion": "config.openshift.io/v1",
					"kind":       "ClusterOperator",
					"metadata": map[string]interface{}{
						"name":      "OPERATOR_NAME",
						"namespace": "OPERATOR_NAMESPACE",
					},
				},
			}
			clusterOperatorClient := fake.NewSimpleDynamicClient(runtime.NewScheme(), clusterOperators).
				Resource(schema.GroupVersionResource{Group: "config.openshift.io", Version: "v1", Resource: "clusteroperators"}).
				Namespace("OPERATOR_NAMESPACE")

			statusClient := &statusClient{
				t: t,
				status: operatorv1.OperatorStatus{
					Conditions: tc.conditions,
				},
			}
			controller := &StatusSyncer{
				clusterOperatorNamespace: "OPERATOR_NAMESPACE",
				clusterOperatorName:      "OPERATOR_NAME",
				clusterOperatorClient:    clusterOperatorClient,
				operatorStatusProvider:   statusClient,
			}
			controller.sync()
			result, _ := clusterOperatorClient.Get("OPERATOR_NAME", v1.GetOptions{})
			expected := &unstructured.Unstructured{
				Object: map[string]interface{}{
					"apiVersion": "config.openshift.io/v1",
					"kind":       "ClusterOperator",
					"metadata": map[string]interface{}{
						"name":      "OPERATOR_NAME",
						"namespace": "OPERATOR_NAMESPACE",
					},
				},
			}
			expectedConditions := []interface{}{}
			if tc.expectedFailingStatus != "" {
				expectedCondition := map[string]interface{}{}
				unstructured.SetNestedField(expectedCondition, operatorv1.OperatorStatusTypeFailing, "Type")
				unstructured.SetNestedField(expectedCondition, string(tc.expectedFailingStatus), "Status")
				if len(tc.expectedMessages) > 0 {
					unstructured.SetNestedField(expectedCondition, strings.Join(tc.expectedMessages, "\n"), "Message")
				}
				if len(tc.expectedReason) > 0 {
					unstructured.SetNestedField(expectedCondition, tc.expectedReason, "Reason")
				}
				expectedConditions = append(expectedConditions, expectedCondition)
			}
			unstructured.SetNestedSlice(expected.Object, expectedConditions, "status", "conditions")
			if !reflect.DeepEqual(expected, result) {
				t.Errorf("\n===== observed config expected:\n%v\n===== observed config actual:\n%v", toYAML(expected), toYAML(result))
				t.Error(diff.ObjectGoPrintSideBySide(expected, result))
			}
		})
	}
}

// OperatorStatusProvider
type statusClient struct {
	t      *testing.T
	status operatorv1.OperatorStatus
}

func (c *statusClient) Informer() cache.SharedIndexInformer {
	c.t.Log("Informer called")
	return nil
}

func (c *statusClient) CurrentStatus() (operatorv1.OperatorStatus, error) {
	return c.status, nil
}

func toYAML(o interface{}) string {
	b, e := yaml.Marshal(o)
	if e != nil {
		return e.Error()
	}
	return string(b)
}
