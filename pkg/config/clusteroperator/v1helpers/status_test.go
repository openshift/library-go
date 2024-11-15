package v1helpers

import (
	configv1 "github.com/openshift/api/config/v1"
	"k8s.io/utils/ptr"
	"reflect"
	"strings"
	"testing"

	applyconfigv1 "github.com/openshift/client-go/config/applyconfigurations/config/v1"
)

func TestGetStatusConditionDiff(t *testing.T) {
	tests := []struct {
		name             string
		newConditions    []applyconfigv1.ClusterOperatorStatusConditionApplyConfiguration
		oldConditions    []applyconfigv1.ClusterOperatorStatusConditionApplyConfiguration
		expectedMessages []string
	}{
		{
			name: "new condition",
			newConditions: []applyconfigv1.ClusterOperatorStatusConditionApplyConfiguration{
				{
					Type:    ptr.To(configv1.RetrievedUpdates),
					Status:  ptr.To(configv1.ConditionTrue),
					Message: ptr.To("test"),
				},
			},
			expectedMessages: []string{`RetrievedUpdates set to True ("test")`},
		},
		{
			name: "condition status change",
			newConditions: []applyconfigv1.ClusterOperatorStatusConditionApplyConfiguration{
				{
					Type:    ptr.To(configv1.RetrievedUpdates),
					Status:  ptr.To(configv1.ConditionFalse),
					Message: ptr.To("test"),
				},
			},
			oldConditions: []applyconfigv1.ClusterOperatorStatusConditionApplyConfiguration{
				{
					Type:    ptr.To(configv1.RetrievedUpdates),
					Status:  ptr.To(configv1.ConditionTrue),
					Message: ptr.To("test"),
				},
			},
			expectedMessages: []string{`RetrievedUpdates changed from True to False ("test")`},
		},
		{
			name: "condition message change",
			newConditions: []applyconfigv1.ClusterOperatorStatusConditionApplyConfiguration{
				{
					Type:    ptr.To(configv1.RetrievedUpdates),
					Status:  ptr.To(configv1.ConditionTrue),
					Message: ptr.To("foo"),
				},
			},
			oldConditions: []applyconfigv1.ClusterOperatorStatusConditionApplyConfiguration{
				{
					Type:    ptr.To(configv1.RetrievedUpdates),
					Status:  ptr.To(configv1.ConditionTrue),
					Message: ptr.To("bar"),
				},
			},
			expectedMessages: []string{`RetrievedUpdates message changed from "bar" to "foo"`},
		},
		{
			name: "condition message deleted",
			oldConditions: []applyconfigv1.ClusterOperatorStatusConditionApplyConfiguration{
				{
					Type:    ptr.To(configv1.RetrievedUpdates),
					Status:  ptr.To(configv1.ConditionTrue),
					Message: ptr.To("test"),
				},
			},
			expectedMessages: []string{"RetrievedUpdates was removed"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := GetStatusDiff(
				&applyconfigv1.ClusterOperatorStatusApplyConfiguration{Conditions: test.oldConditions},
				&applyconfigv1.ClusterOperatorStatusApplyConfiguration{Conditions: test.newConditions})
			if !reflect.DeepEqual(test.expectedMessages, strings.Split(result, ",")) {
				t.Errorf("expected %#v, got %#v", test.expectedMessages, result)
			}
		})
	}
}
