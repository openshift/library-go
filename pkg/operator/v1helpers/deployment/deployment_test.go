package deployment

import (
	"testing"

	"github.com/davecgh/go-spew/spew"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/diff"

	operatorsv1 "github.com/openshift/api/operator/v1"
)

func TestSetOperatorConditions(t *testing.T) {
	tests := []struct {
		name       string
		deployment *appsv1.Deployment
		expected   []operatorsv1.OperatorCondition
	}{
		{
			name: "happy, but for some reason still progressing with NewReplicaSetAvailable",
			deployment: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Generation: 1,
				},
				Status: appsv1.DeploymentStatus{
					ObservedGeneration: 1,
					Replicas:           2,
					AvailableReplicas:  2,
					ReadyReplicas:      2,
					UpdatedReplicas:    2,
					Conditions: []appsv1.DeploymentCondition{
						{
							Type:    appsv1.DeploymentAvailable,
							Status:  corev1.ConditionTrue,
							Reason:  "MinimumReplicasAvailable",
							Message: "Deployment has minimum availability.",
						},
						{
							Type:    appsv1.DeploymentProgressing,
							Status:  corev1.ConditionTrue,
							Reason:  "NewReplicaSetAvailable",
							Message: "ReplicaSet \"downloads-679d74f59d\" has successfully progressed.",
						},
					},
				},
			},
			expected: []operatorsv1.OperatorCondition{
				{
					Type:    "PrefixAvailable",
					Status:  operatorsv1.ConditionTrue,
					Reason:  "MinimumReplicasAvailable",
					Message: "Deployment has minimum availability.",
				},
				{
					Type:    "PrefixProgressing",
					Status:  operatorsv1.ConditionTrue,
					Reason:  "NewReplicaSetAvailable",
					Message: "ReplicaSet \"downloads-679d74f59d\" has successfully progressed.",
				},
				{
					Type:    "PrefixDegraded",
					Status:  operatorsv1.ConditionFalse,
					Reason:  "Available",
					Message: "Available with no replica failures.",
				},
			},
		},
		{
			name: "ProgressDeadlineExceeded",
			deployment: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Generation: 2,
				},
				Status: appsv1.DeploymentStatus{
					ObservedGeneration:  2,
					Replicas:            3,
					AvailableReplicas:   1,
					ReadyReplicas:       1,
					UnavailableReplicas: 2,
					UpdatedReplicas:     2,
					Conditions: []appsv1.DeploymentCondition{
						{
							Type:    appsv1.DeploymentAvailable,
							Status:  corev1.ConditionFalse,
							Reason:  "MinimumReplicasUnavailable",
							Message: "Deployment does not have minimum availability.",
						},
						{
							Type:    appsv1.DeploymentProgressing,
							Status:  corev1.ConditionFalse,
							Reason:  "ProgressDeadlineExceeded",
							Message: "ReplicaSet \"console-6974765f97\" has timed out progressing.",
						},
					},
				},
			},
			expected: []operatorsv1.OperatorCondition{
				{
					Type:    "PrefixAvailable",
					Status:  operatorsv1.ConditionFalse,
					Reason:  "MinimumReplicasUnavailable",
					Message: "Deployment does not have minimum availability.",
				},
				{
					Type:    "PrefixProgressing",
					Status:  operatorsv1.ConditionFalse,
					Reason:  "ProgressDeadlineExceeded",
					Message: "ReplicaSet \"console-6974765f97\" has timed out progressing.",
				},
				{
					Type:    "PrefixDegraded",
					Status:  operatorsv1.ConditionUnknown,
					Reason:  "Unknown",
					Message: "Not available, but no replica failures either.",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var actual []operatorsv1.OperatorCondition
			err := SetOperatorConditions(&actual, "Prefix", test.deployment)
			if err != nil {
				t.Fatal(err)
			}

			if len(actual) != len(test.expected) {
				t.Fatal(spew.Sdump(actual))
			}

			for i := range test.expected {
				expected := test.expected[i]
				actualCondition := actual[i]
				if expected.LastTransitionTime == (metav1.Time{}) {
					actualCondition.LastTransitionTime = metav1.Time{}
				}
				if !equality.Semantic.DeepEqual(expected, actualCondition) {
					t.Errorf(diff.ObjectDiff(expected, actualCondition))
				}
			}
		})
	}
}
