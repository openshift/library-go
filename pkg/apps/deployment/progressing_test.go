package deployment

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	operatorv1 "github.com/openshift/api/operator/v1"
)

func TestDeploymentProgressingCondition(t *testing.T) {
	tests := []struct {
		name     string
		deploy   *appsv1.Deployment
		expected operatorv1.OperatorCondition
	}{
		{
			name: "active rollout, not all pods updated",
			deploy: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "ns"},
				Spec:       appsv1.DeploymentSpec{Replicas: ptr.To[int32](3)},
				Status: appsv1.DeploymentStatus{
					UpdatedReplicas:   1,
					AvailableReplicas: 2,
					Conditions: []appsv1.DeploymentCondition{
						{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionTrue, Reason: "ReplicaSetUpdated"},
					},
				},
			},
			expected: operatorv1.OperatorCondition{
				Type:    operatorv1.OperatorStatusTypeProgressing,
				Status:  operatorv1.ConditionTrue,
				Reason:  "PodsUpdating",
				Message: "deployment/web.ns: 1/3 pods have been updated to the latest revision and 2/3 pods are available",
			},
		},
		{
			name: "rollout complete",
			deploy: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "ns"},
				Spec:       appsv1.DeploymentSpec{Replicas: ptr.To[int32](3)},
				Status: appsv1.DeploymentStatus{
					UpdatedReplicas:   3,
					AvailableReplicas: 3,
					Conditions: []appsv1.DeploymentCondition{
						{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionTrue, Reason: "NewReplicaSetAvailable"},
					},
				},
			},
			expected: operatorv1.OperatorCondition{
				Type:   operatorv1.OperatorStatusTypeProgressing,
				Status: operatorv1.ConditionFalse,
				Reason: "AsExpected",
			},
		},
		{
			name: "progress deadline exceeded",
			deploy: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "ns"},
				Spec:       appsv1.DeploymentSpec{Replicas: ptr.To[int32](3)},
				Status: appsv1.DeploymentStatus{
					UpdatedReplicas:   1,
					AvailableReplicas: 2,
					Conditions: []appsv1.DeploymentCondition{
						{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionFalse, Reason: "ProgressDeadlineExceeded", Message: "timed out waiting"},
					},
				},
			},
			expected: operatorv1.OperatorCondition{
				Type:    operatorv1.OperatorStatusTypeProgressing,
				Status:  operatorv1.ConditionFalse,
				Reason:  "ProgressDeadlineExceeded",
				Message: "deployment/web.ns has timed out progressing: timed out waiting",
			},
		},
		{
			name: "no progressing condition on deployment",
			deploy: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "ns"},
				Spec:       appsv1.DeploymentSpec{Replicas: ptr.To[int32](1)},
				Status:     appsv1.DeploymentStatus{},
			},
			expected: operatorv1.OperatorCondition{
				Type:    operatorv1.OperatorStatusTypeProgressing,
				Status:  operatorv1.ConditionTrue,
				Reason:  "PodsUpdating",
				Message: "deployment/web.ns: 0/1 pods have been updated to the latest revision and 0/1 pods are available",
			},
		},
		{
			name: "nil replicas defaults to 1",
			deploy: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "ns"},
				Spec:       appsv1.DeploymentSpec{},
				Status: appsv1.DeploymentStatus{
					UpdatedReplicas:   1,
					AvailableReplicas: 1,
					Conditions: []appsv1.DeploymentCondition{
						{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionTrue, Reason: "NewReplicaSetAvailable"},
					},
				},
			},
			expected: operatorv1.OperatorCondition{
				Type:   operatorv1.OperatorStatusTypeProgressing,
				Status: operatorv1.ConditionFalse,
				Reason: "AsExpected",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DeploymentProgressingCondition(tt.deploy)
			if d := cmp.Diff(tt.expected, got); d != "" {
				t.Errorf("unexpected condition (-want +got):\n%s", d)
			}
		})
	}
}

func TestHasDeploymentProgressed(t *testing.T) {
	tests := []struct {
		name       string
		conditions []appsv1.DeploymentCondition
		want       bool
	}{
		{
			name: "NewReplicaSetAvailable and True",
			conditions: []appsv1.DeploymentCondition{
				{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionTrue, Reason: "NewReplicaSetAvailable"},
			},
			want: true,
		},
		{
			name: "ReplicaSetUpdated and True",
			conditions: []appsv1.DeploymentCondition{
				{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionTrue, Reason: "ReplicaSetUpdated"},
			},
			want: false,
		},
		{
			name: "NewReplicaSetAvailable but False",
			conditions: []appsv1.DeploymentCondition{
				{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionFalse, Reason: "NewReplicaSetAvailable"},
			},
			want: false,
		},
		{
			name:       "no conditions",
			conditions: nil,
			want:       false,
		},
		{
			name: "unrelated condition only",
			conditions: []appsv1.DeploymentCondition{
				{Type: appsv1.DeploymentAvailable, Status: corev1.ConditionTrue},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HasDeploymentProgressed(appsv1.DeploymentStatus{Conditions: tt.conditions})
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHasDeploymentTimedOutProgressing(t *testing.T) {
	tests := []struct {
		name         string
		conditions   []appsv1.DeploymentCondition
		wantMessage  string
		wantTimedOut bool
	}{
		{
			name: "ProgressDeadlineExceeded",
			conditions: []appsv1.DeploymentCondition{
				{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionFalse, Reason: "ProgressDeadlineExceeded", Message: "timed out"},
			},
			wantMessage:  "timed out",
			wantTimedOut: true,
		},
		{
			name: "ProgressDeadlineExceeded but True status",
			conditions: []appsv1.DeploymentCondition{
				{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionTrue, Reason: "ProgressDeadlineExceeded", Message: "timed out"},
			},
			wantMessage:  "timed out",
			wantTimedOut: false,
		},
		{
			name: "normal progressing",
			conditions: []appsv1.DeploymentCondition{
				{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionTrue, Reason: "ReplicaSetUpdated", Message: "progressing"},
			},
			wantMessage:  "progressing",
			wantTimedOut: false,
		},
		{
			name:         "no conditions",
			conditions:   nil,
			wantMessage:  "",
			wantTimedOut: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMsg, gotTimedOut := HasDeploymentTimedOutProgressing(appsv1.DeploymentStatus{Conditions: tt.conditions})
			if gotMsg != tt.wantMessage {
				t.Errorf("message: got %q, want %q", gotMsg, tt.wantMessage)
			}
			if gotTimedOut != tt.wantTimedOut {
				t.Errorf("timedOut: got %v, want %v", gotTimedOut, tt.wantTimedOut)
			}
		})
	}
}
