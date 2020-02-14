package v1helpers

import (
	"reflect"
	"strings"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
)

func TestGetStatusConditionDiff(t *testing.T) {
	tests := []struct {
		name             string
		newConditions    []configv1.ClusterOperatorStatusCondition
		oldConditions    []configv1.ClusterOperatorStatusCondition
		expectedMessages []string
		expectedWarning  bool
	}{
		{
			name: "new happy condition",
			newConditions: []configv1.ClusterOperatorStatusCondition{
				{
					Type:    configv1.OperatorAvailable,
					Status:  configv1.ConditionTrue,
					Message: "test",
				},
			},
			expectedMessages: []string{`Available set to True ("test")`},
		},
		{
			name: "new sad condition",
			newConditions: []configv1.ClusterOperatorStatusCondition{
				{
					Type:    configv1.OperatorDegraded,
					Status:  configv1.ConditionTrue,
					Message: "test",
				},
			},
			expectedMessages: []string{`Degraded set to True ("test")`},
			expectedWarning:  true,
		},
		{
			name: "happy condition status change",
			newConditions: []configv1.ClusterOperatorStatusCondition{
				{
					Type:    configv1.OperatorAvailable,
					Status:  configv1.ConditionTrue,
					Message: "laugh",
				},
			},
			oldConditions: []configv1.ClusterOperatorStatusCondition{
				{
					Type:    configv1.OperatorAvailable,
					Status:  configv1.ConditionFalse,
					Message: "cry",
				},
			},
			expectedMessages: []string{`Available changed from False to True ("laugh")`},
		},
		{
			name: "sad condition status change",
			newConditions: []configv1.ClusterOperatorStatusCondition{
				{
					Type:    configv1.OperatorAvailable,
					Status:  configv1.ConditionFalse,
					Message: "cry",
				},
			},
			oldConditions: []configv1.ClusterOperatorStatusCondition{
				{
					Type:    configv1.OperatorAvailable,
					Status:  configv1.ConditionTrue,
					Message: "laugh",
				},
			},
			expectedMessages: []string{`Available changed from True to False ("cry")`},
			expectedWarning:  true,
		},
		{
			name: "happy condition reason change",
			newConditions: []configv1.ClusterOperatorStatusCondition{
				{
					Type:    configv1.OperatorAvailable,
					Status:  configv1.ConditionTrue,
					Reason:  "SuccessB",
					Message: "foo",
				},
			},
			oldConditions: []configv1.ClusterOperatorStatusCondition{
				{
					Type:    configv1.OperatorAvailable,
					Status:  configv1.ConditionTrue,
					Reason:  "SuccessA",
					Message: "bar",
				},
			},
			expectedMessages: []string{`Available=True reason changed from "SuccessA" to "SuccessB" ("foo")`},
		},
		{
			name: "sad condition reason change",
			newConditions: []configv1.ClusterOperatorStatusCondition{
				{
					Type:    configv1.OperatorDegraded,
					Status:  configv1.ConditionTrue,
					Reason:  "FailureB",
					Message: "foo",
				},
			},
			oldConditions: []configv1.ClusterOperatorStatusCondition{
				{
					Type:    configv1.OperatorDegraded,
					Status:  configv1.ConditionTrue,
					Reason:  "FailureA",
					Message: "bar",
				},
			},
			expectedMessages: []string{`Degraded=True reason changed from "FailureA" to "FailureB" ("foo")`},
			expectedWarning:  true,
		},
		{
			name: "unknown condition reason change",
			newConditions: []configv1.ClusterOperatorStatusCondition{
				{
					Type:    configv1.ClusterStatusConditionType("CustomType"),
					Status:  configv1.ConditionTrue,
					Reason:  "SuccessB",
					Message: "foo",
				},
			},
			oldConditions: []configv1.ClusterOperatorStatusCondition{
				{
					Type:    configv1.ClusterStatusConditionType("CustomType"),
					Status:  configv1.ConditionTrue,
					Reason:  "SuccessA",
					Message: "bar",
				},
			},
			expectedMessages: []string{`CustomType=True reason changed from "SuccessA" to "SuccessB" ("foo")`},
		},
		{
			name: "happy condition message change",
			newConditions: []configv1.ClusterOperatorStatusCondition{
				{
					Type:    configv1.OperatorAvailable,
					Status:  configv1.ConditionTrue,
					Reason:  "Success",
					Message: "foo",
				},
			},
			oldConditions: []configv1.ClusterOperatorStatusCondition{
				{
					Type:    configv1.OperatorAvailable,
					Status:  configv1.ConditionTrue,
					Reason:  "Success",
					Message: "bar",
				},
			},
			expectedMessages: []string{`Available=True Success message changed from "bar" to "foo"`},
		},
		{
			name: "sad condition message change",
			newConditions: []configv1.ClusterOperatorStatusCondition{
				{
					Type:    configv1.OperatorDegraded,
					Status:  configv1.ConditionTrue,
					Reason:  "Failure",
					Message: "foo",
				},
			},
			oldConditions: []configv1.ClusterOperatorStatusCondition{
				{
					Type:    configv1.OperatorDegraded,
					Status:  configv1.ConditionTrue,
					Reason:  "Failure",
					Message: "bar",
				},
			},
			expectedMessages: []string{`Degraded=True Failure message changed from "bar" to "foo"`},
			expectedWarning:  true,
		},
		{
			name: "unknown condition message change",
			newConditions: []configv1.ClusterOperatorStatusCondition{
				{
					Type:    configv1.ClusterStatusConditionType("CustomType"),
					Status:  configv1.ConditionTrue,
					Reason:  "Success",
					Message: "foo",
				},
			},
			oldConditions: []configv1.ClusterOperatorStatusCondition{
				{
					Type:    configv1.ClusterStatusConditionType("CustomType"),
					Status:  configv1.ConditionTrue,
					Reason:  "Success",
					Message: "bar",
				},
			},
			expectedMessages: []string{`CustomType=True Success message changed from "bar" to "foo"`},
		},
		{
			name: "happy condition message change on still-sad status",
			newConditions: []configv1.ClusterOperatorStatusCondition{
				{
					Type:    configv1.OperatorAvailable,
					Status:  configv1.ConditionTrue,
					Reason:  "Success",
					Message: "I'm available",
				},
				{
					Type:    configv1.OperatorDegraded,
					Status:  configv1.ConditionTrue,
					Reason:  "Failure",
					Message: "I'm degraded",
				},
			},
			oldConditions: []configv1.ClusterOperatorStatusCondition{
				{
					Type:    configv1.OperatorAvailable,
					Status:  configv1.ConditionFalse,
					Reason:  "Failure",
					Message: "I'm not available",
				},
				{
					Type:    configv1.OperatorDegraded,
					Status:  configv1.ConditionTrue,
					Reason:  "Failure",
					Message: "I'm degraded",
				},
			},
			expectedMessages: []string{`Available changed from False to True ("I'm available")`},
		},
		{
			name: "condition message deleted",
			oldConditions: []configv1.ClusterOperatorStatusCondition{
				{
					Type:    configv1.OperatorAvailable,
					Status:  configv1.ConditionTrue,
					Message: "test",
				},
			},
			expectedMessages: []string{"Available was removed"},
			expectedWarning:  true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, warning := GetStatusDiff(configv1.ClusterOperatorStatus{Conditions: test.oldConditions}, configv1.ClusterOperatorStatus{Conditions: test.newConditions})
			if !reflect.DeepEqual(test.expectedMessages, strings.Split(result, ",")) {
				t.Errorf("expected message %#v, got %#v", test.expectedMessages, result)
			}
			if warning != test.expectedWarning {
				t.Errorf("expected warning %t, got %t", test.expectedWarning, warning)
			}
		})
	}
}
