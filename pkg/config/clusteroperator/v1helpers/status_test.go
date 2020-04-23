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
		forEvent         bool
	}{
		{
			name: "new condition",
			newConditions: []configv1.ClusterOperatorStatusCondition{
				{
					Type:    configv1.RetrievedUpdates,
					Status:  configv1.ConditionTrue,
					Message: "test",
				},
			},
			expectedMessages: []string{`RetrievedUpdates set to True`},
			forEvent:         true,
		},
		{
			name: "new multiple condition",
			newConditions: []configv1.ClusterOperatorStatusCondition{
				{
					Type:    configv1.RetrievedUpdates,
					Status:  configv1.ConditionTrue,
					Message: "test",
				},
				{
					Type:    "AnotherDegraded",
					Status:  configv1.ConditionTrue,
					Message: "bar",
				},
			},
			expectedMessages: []string{"RetrievedUpdates set to True (test)", "\nAnotherDegraded set to True (bar)"},
			forEvent:         false,
		},
		{
			name: "new condition for log",
			newConditions: []configv1.ClusterOperatorStatusCondition{
				{
					Type:    configv1.RetrievedUpdates,
					Status:  configv1.ConditionTrue,
					Message: "test",
				},
			},
			expectedMessages: []string{`RetrievedUpdates set to True (test)`},
			forEvent:         false,
		},
		{
			name: "condition status change",
			newConditions: []configv1.ClusterOperatorStatusCondition{
				{
					Type:    configv1.RetrievedUpdates,
					Status:  configv1.ConditionFalse,
					Message: "test",
				},
			},
			oldConditions: []configv1.ClusterOperatorStatusCondition{
				{
					Type:    configv1.RetrievedUpdates,
					Status:  configv1.ConditionTrue,
					Message: "test",
				},
			},
			expectedMessages: []string{`RetrievedUpdates changed from True to False`},
			forEvent:         true,
		},
		{
			name: "condition status change for log",
			newConditions: []configv1.ClusterOperatorStatusCondition{
				{
					Type:    configv1.RetrievedUpdates,
					Status:  configv1.ConditionFalse,
					Message: "test",
				},
			},
			oldConditions: []configv1.ClusterOperatorStatusCondition{
				{
					Type:    configv1.RetrievedUpdates,
					Status:  configv1.ConditionTrue,
					Message: "test",
				},
			},
			expectedMessages: []string{`RetrievedUpdates changed from True (test) to False (test)`},
			forEvent:         false,
		},
		{
			name: "condition message change",
			newConditions: []configv1.ClusterOperatorStatusCondition{
				{
					Type:    configv1.RetrievedUpdates,
					Status:  configv1.ConditionTrue,
					Message: "foo",
				},
			},
			oldConditions: []configv1.ClusterOperatorStatusCondition{
				{
					Type:    configv1.RetrievedUpdates,
					Status:  configv1.ConditionTrue,
					Message: "bar",
				},
			},
			expectedMessages: []string{`RetrievedUpdates message changed to "foo"`},
			forEvent:         true,
		},
		{
			name: "condition message change for log",
			newConditions: []configv1.ClusterOperatorStatusCondition{
				{
					Type:    configv1.RetrievedUpdates,
					Status:  configv1.ConditionTrue,
					Message: "foo",
				},
			},
			oldConditions: []configv1.ClusterOperatorStatusCondition{
				{
					Type:    configv1.RetrievedUpdates,
					Status:  configv1.ConditionTrue,
					Message: "bar",
				},
			},
			expectedMessages: []string{`RetrievedUpdates message changed to "foo"`},
			forEvent:         false,
		},
		{
			name: "condition message deleted",
			oldConditions: []configv1.ClusterOperatorStatusCondition{
				{
					Type:    configv1.RetrievedUpdates,
					Status:  configv1.ConditionTrue,
					Message: "test",
				},
			},
			expectedMessages: []string{"RetrievedUpdates was removed"},
			forEvent:         true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := GetStatusDiff(configv1.ClusterOperatorStatus{Conditions: test.oldConditions}, configv1.ClusterOperatorStatus{Conditions: test.newConditions}, test.forEvent)
			if !reflect.DeepEqual(test.expectedMessages, strings.Split(result, ",")) {
				t.Errorf("expected %#v, got %#v", test.expectedMessages, strings.Split(result, ","))
			}
		})
	}
}
