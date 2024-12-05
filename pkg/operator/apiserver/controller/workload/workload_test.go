package workload

import (
	"context"
	"fmt"
	"testing"
	"time"

	clocktesting "k8s.io/utils/clock/testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	appsv1listers "k8s.io/client-go/listers/apps/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	kubetesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/diff"
)

const (
	defaultControllerName = ""
)

var _ Delegate = &testDelegate{}

type testDelegate struct {
	// for preconditions
	preconditionReady bool
	preconditionErr   error

	// for Sync
	syncWorkload            *appsv1.Deployment
	syncIsAtHighestRevision bool
	syncErrrors             []error
}

func (d *testDelegate) PreconditionFulfilled(_ context.Context) (bool, error) {
	return d.preconditionReady, d.preconditionErr
}

func (d *testDelegate) Sync(_ context.Context, _ factory.SyncContext) (*appsv1.Deployment, bool, bool, []error) {
	return d.syncWorkload, d.syncIsAtHighestRevision, false, d.syncErrrors
}

func TestUpdateOperatorStatus(t *testing.T) {
	scenarios := []struct {
		name string

		workload                        *appsv1.Deployment
		pods                            []*corev1.Pod
		operatorConfigAtHighestRevision bool
		operatorPreconditionsNotReady   bool
		preconditionError               error
		errors                          []error
		previousConditions              []operatorv1.OperatorCondition

		validateOperatorStatus func(*operatorv1.OperatorStatus) error
	}{
		{
			name: "scenario: no workload, no errors thus we are degraded and we are progressing",
			validateOperatorStatus: func(actualStatus *operatorv1.OperatorStatus) error {
				expectedConditions := []operatorv1.OperatorCondition{
					{
						Type:    fmt.Sprintf("%sDeployment%s", defaultControllerName, operatorv1.OperatorStatusTypeAvailable),
						Status:  operatorv1.ConditionFalse,
						Reason:  "NoDeployment",
						Message: "deployment/: could not be retrieved",
					},
					{
						Type:    fmt.Sprintf("%sWorkloadDegraded", defaultControllerName),
						Status:  operatorv1.ConditionTrue,
						Reason:  "NoDeployment",
						Message: "deployment/: could not be retrieved",
					},
					{
						Type:    fmt.Sprintf("%sDeploymentDegraded", defaultControllerName),
						Status:  operatorv1.ConditionTrue,
						Reason:  "NoDeployment",
						Message: "deployment/: could not be retrieved",
					},

					{
						Type:    fmt.Sprintf("%sDeployment%s", defaultControllerName, operatorv1.OperatorStatusTypeProgressing),
						Status:  operatorv1.ConditionTrue,
						Reason:  "NoDeployment",
						Message: "deployment/: could not be retrieved",
					},
				}
				return areCondidtionsEqual(expectedConditions, actualStatus.Conditions)
			},
		},
		{
			name:   "scenario: no workload but errors thus we are degraded and we are progressing",
			errors: []error{fmt.Errorf("nasty error")},
			validateOperatorStatus: func(actualStatus *operatorv1.OperatorStatus) error {
				expectedConditions := []operatorv1.OperatorCondition{
					{
						Type:    fmt.Sprintf("%sDeployment%s", defaultControllerName, operatorv1.OperatorStatusTypeAvailable),
						Status:  operatorv1.ConditionFalse,
						Reason:  "NoDeployment",
						Message: "deployment/: could not be retrieved",
					},
					{
						Type:    fmt.Sprintf("%sWorkloadDegraded", defaultControllerName),
						Status:  operatorv1.ConditionTrue,
						Message: "nasty error\n",
						Reason:  "SyncError",
					},
					{
						Type:    fmt.Sprintf("%sDeploymentDegraded", defaultControllerName),
						Status:  operatorv1.ConditionTrue,
						Reason:  "NoDeployment",
						Message: "deployment/: could not be retrieved",
					},

					{
						Type:    fmt.Sprintf("%sDeployment%s", defaultControllerName, operatorv1.OperatorStatusTypeProgressing),
						Status:  operatorv1.ConditionTrue,
						Reason:  "NoDeployment",
						Message: "deployment/: could not be retrieved",
					},
				}
				return areCondidtionsEqual(expectedConditions, actualStatus.Conditions)
			},
		},
		{
			name: "scenario: we have an unavailable workload being updated for too long and no errors thus we are degraded",
			workload: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "apiserver",
					Namespace: "openshift-apiserver",
				},
				Spec: appsv1.DeploymentSpec{
					Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"foo": "bar"}}},
					Replicas: ptr.To[int32](3),
				},
				Status: appsv1.DeploymentStatus{
					AvailableReplicas: 0,
					Conditions: []appsv1.DeploymentCondition{
						{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionFalse, LastUpdateTime: metav1.NewTime(time.Now().Add(-6 * time.Minute)), LastTransitionTime: metav1.NewTime(time.Now().Add(-6 * time.Minute)), Reason: "ProgressDeadlineExceeded", Message: "timed out"},
					},
				},
			},
			pods: []*corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "apiserver", Namespace: "openshift-apiserver", Labels: map[string]string{"foo": "bar"}},
					Status: corev1.PodStatus{
						Phase: corev1.PodPending,
						ContainerStatuses: []corev1.ContainerStatus{
							{
								Name:  "test",
								Ready: false,
								State: corev1.ContainerState{
									Waiting: &corev1.ContainerStateWaiting{
										Reason:  "ImagePull",
										Message: "slow registry",
									},
								},
							},
						},
					},
				},
			},
			previousConditions: []operatorv1.OperatorCondition{
				{
					Type:               fmt.Sprintf("%sDeployment%s", defaultControllerName, operatorv1.OperatorStatusTypeProgressing),
					Status:             operatorv1.ConditionTrue,
					Reason:             "PodsUpdating",
					LastTransitionTime: metav1.NewTime(time.Now().Add(-16 * time.Minute)),
				},
			},
			validateOperatorStatus: func(actualStatus *operatorv1.OperatorStatus) error {
				expectedConditions := []operatorv1.OperatorCondition{
					{
						Type:    fmt.Sprintf("%sDeployment%s", defaultControllerName, operatorv1.OperatorStatusTypeAvailable),
						Status:  operatorv1.ConditionFalse,
						Reason:  "NoPod",
						Message: "no apiserver.openshift-apiserver pods available on any node.",
					},
					{
						Type:   fmt.Sprintf("%sWorkloadDegraded", defaultControllerName),
						Status: operatorv1.ConditionFalse,
					},
					{
						Type:    fmt.Sprintf("%sDeploymentDegraded", defaultControllerName),
						Status:  operatorv1.ConditionTrue,
						Reason:  "UnavailablePod",
						Message: "3 of 3 requested instances are unavailable for apiserver.openshift-apiserver (container is waiting in pending apiserver pod)",
					},
					{
						Type:    fmt.Sprintf("%sDeployment%s", defaultControllerName, operatorv1.OperatorStatusTypeProgressing),
						Status:  operatorv1.ConditionTrue,
						Reason:  "PodsUpdating",
						Message: "deployment/apiserver.openshift-apiserver: 0/3 pods have been updated to the latest generation and 0/3 pods are available",
					},
				}
				return areCondidtionsEqual(expectedConditions, actualStatus.Conditions)
			},
		},
		{
			name: "scenario: we have an unavailable workload being updated for a short time and no errors so we are progressing",
			workload: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "apiserver",
					Namespace: "openshift-apiserver",
				},
				Spec: appsv1.DeploymentSpec{
					Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"foo": "bar"}}},
					Replicas: ptr.To[int32](3),
				},
				Status: appsv1.DeploymentStatus{
					AvailableReplicas: 0,
					Conditions: []appsv1.DeploymentCondition{
						{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionTrue, LastUpdateTime: metav1.Now(), LastTransitionTime: metav1.Now(), Reason: "ReplicaSetUpdated", Message: "progressing"},
					},
				},
			},
			pods: []*corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "apiserver", Namespace: "openshift-apiserver", Labels: map[string]string{"foo": "bar"}},
					Status: corev1.PodStatus{
						Phase: corev1.PodPending,
						ContainerStatuses: []corev1.ContainerStatus{
							{
								Name:  "test",
								Ready: false,
								State: corev1.ContainerState{
									Waiting: &corev1.ContainerStateWaiting{
										Reason:  "ImagePull",
										Message: "slow registry",
									},
								},
							},
						},
					},
				},
			},
			previousConditions: []operatorv1.OperatorCondition{
				{
					Type:               fmt.Sprintf("%sDeployment%s", defaultControllerName, operatorv1.OperatorStatusTypeProgressing),
					Status:             operatorv1.ConditionTrue,
					Reason:             "PodsUpdating",
					LastTransitionTime: metav1.NewTime(time.Now().Add(-4 * time.Minute)),
				},
			},
			validateOperatorStatus: func(actualStatus *operatorv1.OperatorStatus) error {
				expectedConditions := []operatorv1.OperatorCondition{
					{
						Type:    fmt.Sprintf("%sDeployment%s", defaultControllerName, operatorv1.OperatorStatusTypeAvailable),
						Status:  operatorv1.ConditionFalse,
						Reason:  "NoPod",
						Message: "no apiserver.openshift-apiserver pods available on any node.",
					},
					{
						Type:   fmt.Sprintf("%sWorkloadDegraded", defaultControllerName),
						Status: operatorv1.ConditionFalse,
					},
					{
						Type:   fmt.Sprintf("%sDeploymentDegraded", defaultControllerName),
						Status: operatorv1.ConditionFalse,
						Reason: "AsExpected",
					},
					{
						Type:    fmt.Sprintf("%sDeployment%s", defaultControllerName, operatorv1.OperatorStatusTypeProgressing),
						Status:  operatorv1.ConditionTrue,
						Reason:  "PodsUpdating",
						Message: "deployment/apiserver.openshift-apiserver: 0/3 pods have been updated to the latest generation and 0/3 pods are available",
					},
				}
				return areCondidtionsEqual(expectedConditions, actualStatus.Conditions)
			},
		},
		{
			name: "scenario: we have an incomplete workload and no errors thus we are available and degraded (missing 1 replica)",
			workload: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "apiserver",
					Namespace: "openshift-apiserver",
				},
				Spec: appsv1.DeploymentSpec{
					Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"foo": "bar"}}},
					Replicas: ptr.To[int32](3),
				},
				Status: appsv1.DeploymentStatus{
					AvailableReplicas: 2,
					UpdatedReplicas:   3,
					Conditions: []appsv1.DeploymentCondition{
						{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionTrue, LastUpdateTime: metav1.Now(), LastTransitionTime: metav1.Now(), Reason: "NewReplicaSetAvailable", Message: "has successfully progressed"},
					},
				},
			},
			pods: []*corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "apiserver", Namespace: "openshift-apiserver"},
					Status: corev1.PodStatus{
						Phase: corev1.PodSucceeded,
						ContainerStatuses: []corev1.ContainerStatus{
							{
								Name:  "test",
								Ready: true,
								State: corev1.ContainerState{
									Terminated: &corev1.ContainerStateTerminated{
										Reason:  "PodKilled",
										Message: "john wick was here",
									},
								},
							},
						},
					},
				},
			},
			validateOperatorStatus: func(actualStatus *operatorv1.OperatorStatus) error {
				expectedConditions := []operatorv1.OperatorCondition{
					{
						Type:    fmt.Sprintf("%sDeployment%s", defaultControllerName, operatorv1.OperatorStatusTypeAvailable),
						Status:  operatorv1.ConditionTrue,
						Reason:  "AsExpected",
						Message: "",
					},
					{
						Type:   fmt.Sprintf("%sWorkloadDegraded", defaultControllerName),
						Status: operatorv1.ConditionFalse,
					},
					{
						Type:    fmt.Sprintf("%sDeploymentDegraded", defaultControllerName),
						Status:  operatorv1.ConditionTrue,
						Reason:  "UnavailablePod",
						Message: "1 of 3 requested instances are unavailable for apiserver.openshift-apiserver ()",
					},
					{
						Type:    fmt.Sprintf("%sDeployment%s", defaultControllerName, operatorv1.OperatorStatusTypeProgressing),
						Status:  operatorv1.ConditionFalse,
						Reason:  "AsExpected",
						Message: "",
					},
				}
				return areCondidtionsEqual(expectedConditions, actualStatus.Conditions)
			},
		},
		{
			name: "scenario: we have a complete workload and no errors thus we are available",
			workload: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "apiserver",
					Namespace: "openshift-apiserver",
				},
				Spec: appsv1.DeploymentSpec{
					Replicas: ptr.To[int32](3),
				},
				Status: appsv1.DeploymentStatus{
					AvailableReplicas: 3,
					UpdatedReplicas:   3,
					Conditions: []appsv1.DeploymentCondition{
						{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionTrue, LastUpdateTime: metav1.Now(), LastTransitionTime: metav1.Now(), Reason: "NewReplicaSetAvailable", Message: "has successfully progressed"},
					},
				},
			},
			validateOperatorStatus: func(actualStatus *operatorv1.OperatorStatus) error {
				expectedConditions := []operatorv1.OperatorCondition{
					{
						Type:    fmt.Sprintf("%sDeployment%s", defaultControllerName, operatorv1.OperatorStatusTypeAvailable),
						Status:  operatorv1.ConditionTrue,
						Reason:  "AsExpected",
						Message: "",
					},
					{
						Type:   fmt.Sprintf("%sWorkloadDegraded", defaultControllerName),
						Status: operatorv1.ConditionFalse,
					},
					{
						Type:    fmt.Sprintf("%sDeploymentDegraded", defaultControllerName),
						Status:  operatorv1.ConditionFalse,
						Reason:  "AsExpected",
						Message: "",
					},
					{
						Type:    fmt.Sprintf("%sDeployment%s", defaultControllerName, operatorv1.OperatorStatusTypeProgressing),
						Status:  operatorv1.ConditionFalse,
						Reason:  "AsExpected",
						Message: "",
					},
				}
				return areCondidtionsEqual(expectedConditions, actualStatus.Conditions)
			},
		},
		{
			name: "scenario: we have an outdated (generation) workload and no errors thus we are available and we are progressing",
			workload: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "apiserver",
					Namespace:  "openshift-apiserver",
					Generation: 100,
				},
				Spec: appsv1.DeploymentSpec{
					Replicas: ptr.To[int32](3),
				},
				Status: appsv1.DeploymentStatus{
					Replicas:           3,
					ReadyReplicas:      3,
					AvailableReplicas:  3,
					UpdatedReplicas:    3,
					ObservedGeneration: 99,
					Conditions: []appsv1.DeploymentCondition{
						{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionTrue, LastUpdateTime: metav1.Now(), LastTransitionTime: metav1.Now(), Reason: "NewReplicaSetAvailable", Message: "has successfully progressed"},
					},
				},
			},
			validateOperatorStatus: func(actualStatus *operatorv1.OperatorStatus) error {
				expectedConditions := []operatorv1.OperatorCondition{
					{
						Type:    fmt.Sprintf("%sDeployment%s", defaultControllerName, operatorv1.OperatorStatusTypeAvailable),
						Status:  operatorv1.ConditionTrue,
						Reason:  "AsExpected",
						Message: "",
					},
					{
						Type:   fmt.Sprintf("%sWorkloadDegraded", defaultControllerName),
						Status: operatorv1.ConditionFalse,
					},
					{
						Type:    fmt.Sprintf("%sDeploymentDegraded", defaultControllerName),
						Status:  operatorv1.ConditionFalse,
						Reason:  "AsExpected",
						Message: "",
					},
					{
						Type:    fmt.Sprintf("%sDeployment%s", defaultControllerName, operatorv1.OperatorStatusTypeProgressing),
						Status:  operatorv1.ConditionTrue,
						Reason:  "NewGeneration",
						Message: "deployment/apiserver.openshift-apiserver: observed generation is 99, desired generation is 100.",
					},
				}
				return areCondidtionsEqual(expectedConditions, actualStatus.Conditions)
			},
		},

		{
			name: "scenario: rare case when we have an outdated (generation) workload and one old replica failing is but it will be picked up soon by the new rollout thus we are available and we are progressing",
			workload: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "apiserver",
					Namespace:  "openshift-apiserver",
					Generation: 100,
				},
				Spec: appsv1.DeploymentSpec{
					Replicas: ptr.To[int32](3),
				},
				Status: appsv1.DeploymentStatus{
					Replicas:           3,
					ReadyReplicas:      2,
					AvailableReplicas:  2,
					UpdatedReplicas:    3,
					ObservedGeneration: 99,
					Conditions: []appsv1.DeploymentCondition{
						{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionTrue, LastUpdateTime: metav1.Now(), LastTransitionTime: metav1.Now(), Reason: "NewReplicaSetAvailable", Message: "has successfully progressed"},
					},
				},
			},
			validateOperatorStatus: func(actualStatus *operatorv1.OperatorStatus) error {
				expectedConditions := []operatorv1.OperatorCondition{
					{
						Type:    fmt.Sprintf("%sDeployment%s", defaultControllerName, operatorv1.OperatorStatusTypeAvailable),
						Status:  operatorv1.ConditionTrue,
						Reason:  "AsExpected",
						Message: "",
					},
					{
						Type:   fmt.Sprintf("%sWorkloadDegraded", defaultControllerName),
						Status: operatorv1.ConditionFalse,
					},
					{
						Type:    fmt.Sprintf("%sDeploymentDegraded", defaultControllerName),
						Status:  operatorv1.ConditionFalse,
						Reason:  "AsExpected",
						Message: "",
					},
					{
						Type:    fmt.Sprintf("%sDeployment%s", defaultControllerName, operatorv1.OperatorStatusTypeProgressing),
						Status:  operatorv1.ConditionTrue,
						Reason:  "NewGeneration",
						Message: "deployment/apiserver.openshift-apiserver: observed generation is 99, desired generation is 100.",
					},
				}
				return areCondidtionsEqual(expectedConditions, actualStatus.Conditions)
			},
		},
		{
			name:                          "preconditions not fulfilled",
			operatorPreconditionsNotReady: true,
			validateOperatorStatus: func(actualStatus *operatorv1.OperatorStatus) error {
				expectedConditions := []operatorv1.OperatorCondition{
					{
						Type:    fmt.Sprintf("%sDeployment%s", defaultControllerName, operatorv1.OperatorStatusTypeAvailable),
						Status:  operatorv1.ConditionFalse,
						Reason:  "PreconditionNotFulfilled",
						Message: "",
					},
					{
						Type:    fmt.Sprintf("%sDeploymentDegraded", defaultControllerName),
						Status:  operatorv1.ConditionTrue,
						Reason:  "PreconditionNotFulfilled",
						Message: "the operator didn't specify what preconditions are missing",
					},
					{
						Type:    fmt.Sprintf("%sDeployment%s", defaultControllerName, operatorv1.OperatorStatusTypeProgressing),
						Status:  operatorv1.ConditionFalse,
						Reason:  "PreconditionNotFulfilled",
						Message: "",
					},
					{
						Type:    fmt.Sprintf("%sWorkloadDegraded", defaultControllerName),
						Status:  operatorv1.ConditionTrue,
						Reason:  "PreconditionNotFulfilled",
						Message: "the operator didn't specify what preconditions are missing",
					},
				}
				return areCondidtionsEqual(expectedConditions, actualStatus.Conditions)
			},
		},
		{
			name:                          "the deployment is progressing to rollout pods, but not all replicas have been updated yet",
			operatorPreconditionsNotReady: false,
			workload: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "apiserver",
					Namespace:  "openshift-apiserver",
					Generation: 2,
				},
				Spec: appsv1.DeploymentSpec{
					Replicas: ptr.To[int32](3),
				},
				Status: appsv1.DeploymentStatus{
					ReadyReplicas:      2,
					AvailableReplicas:  2,
					UpdatedReplicas:    1,
					ObservedGeneration: 2,
					Conditions: []appsv1.DeploymentCondition{
						{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionTrue, LastUpdateTime: metav1.Now(), LastTransitionTime: metav1.Now(), Reason: "ReplicaSetUpdated", Message: "progressing"},
					},
				},
			},
			validateOperatorStatus: func(actualStatus *operatorv1.OperatorStatus) error {
				expectedConditions := []operatorv1.OperatorCondition{
					{
						Type:    fmt.Sprintf("%sDeployment%s", defaultControllerName, operatorv1.OperatorStatusTypeAvailable),
						Status:  operatorv1.ConditionTrue,
						Reason:  "AsExpected",
						Message: "",
					},
					{
						Type:   fmt.Sprintf("%sWorkloadDegraded", defaultControllerName),
						Status: operatorv1.ConditionFalse,
					},
					{
						Type:    fmt.Sprintf("%sDeploymentDegraded", defaultControllerName),
						Status:  operatorv1.ConditionFalse,
						Reason:  "AsExpected",
						Message: "",
					},
					{
						Type:    fmt.Sprintf("%sDeployment%s", defaultControllerName, operatorv1.OperatorStatusTypeProgressing),
						Status:  operatorv1.ConditionTrue,
						Reason:  "PodsUpdating",
						Message: "deployment/apiserver.openshift-apiserver: 1/3 pods have been updated to the latest generation and 2/3 pods are available",
					},
				}
				return areCondidtionsEqual(expectedConditions, actualStatus.Conditions)
			},
		},
		{
			name: "progressing==false for a longer time shouldn't make the otherwise fine workload degraded",
			workload: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "apiserver",
					Namespace: "openshift-apiserver",
				},
				Spec: appsv1.DeploymentSpec{
					Replicas: ptr.To[int32](3),
				},
				Status: appsv1.DeploymentStatus{
					AvailableReplicas: 3,
					UpdatedReplicas:   3,
					Conditions: []appsv1.DeploymentCondition{
						{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionTrue, LastUpdateTime: metav1.Now(), LastTransitionTime: metav1.Now(), Reason: "NewReplicaSetAvailable", Message: "has successfully progressed"},
					},
				},
			},
			previousConditions: []operatorv1.OperatorCondition{
				{
					Type:               fmt.Sprintf("%sDeployment%s", defaultControllerName, operatorv1.OperatorStatusTypeProgressing),
					Status:             operatorv1.ConditionFalse,
					Reason:             "AsExpected",
					LastTransitionTime: metav1.NewTime(time.Now().Add(-10 * time.Minute)),
				},
			},
			validateOperatorStatus: func(actualStatus *operatorv1.OperatorStatus) error {
				expectedConditions := []operatorv1.OperatorCondition{
					{
						Type:   fmt.Sprintf("%sDeployment%s", defaultControllerName, operatorv1.OperatorStatusTypeAvailable),
						Status: operatorv1.ConditionTrue,
						Reason: "AsExpected",
					},
					{
						Type:   fmt.Sprintf("%sWorkloadDegraded", defaultControllerName),
						Status: operatorv1.ConditionFalse,
					},
					{
						Type:   fmt.Sprintf("%sDeploymentDegraded", defaultControllerName),
						Status: operatorv1.ConditionFalse,
						Reason: "AsExpected",
					},
					{
						Type:   fmt.Sprintf("%sDeployment%s", defaultControllerName, operatorv1.OperatorStatusTypeProgressing),
						Status: operatorv1.ConditionFalse,
						Reason: "AsExpected",
					},
				}
				return areCondidtionsEqual(expectedConditions, actualStatus.Conditions)
			},
		},
		{
			name: "some pods rolled out and waiting for old terminating pod before we can progress further",
			workload: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "apiserver",
					Namespace: "openshift-apiserver",
				},
				Spec: appsv1.DeploymentSpec{
					Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"foo": "bar"}},
					Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"foo": "bar"}}},
					Replicas: ptr.To[int32](3),
				},
				Status: appsv1.DeploymentStatus{
					AvailableReplicas: 2,
					ReadyReplicas:     2,
					UpdatedReplicas:   3,
					Conditions: []appsv1.DeploymentCondition{
						{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionTrue, LastUpdateTime: metav1.Now(), LastTransitionTime: metav1.Now(), Reason: "ReplicaSetUpdated", Message: "progressing"},
					},
				},
			},
			validateOperatorStatus: func(actualStatus *operatorv1.OperatorStatus) error {
				expectedConditions := []operatorv1.OperatorCondition{
					{
						Type:    fmt.Sprintf("%sDeployment%s", defaultControllerName, operatorv1.OperatorStatusTypeAvailable),
						Status:  operatorv1.ConditionTrue,
						Reason:  "AsExpected",
						Message: "",
					},
					{
						Type:   fmt.Sprintf("%sWorkloadDegraded", defaultControllerName),
						Status: operatorv1.ConditionFalse,
					},
					{
						Type:    fmt.Sprintf("%sDeploymentDegraded", defaultControllerName),
						Status:  operatorv1.ConditionFalse,
						Reason:  "AsExpected",
						Message: "",
					},
					{
						Type:    fmt.Sprintf("%sDeployment%s", defaultControllerName, operatorv1.OperatorStatusTypeProgressing),
						Status:  operatorv1.ConditionTrue,
						Reason:  "PodsUpdating",
						Message: "deployment/apiserver.openshift-apiserver: 3/3 pods have been updated to the latest generation and 2/3 pods are available",
					},
				}
				return areCondidtionsEqual(expectedConditions, actualStatus.Conditions)
			},
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			// setup
			fakeOperatorClient := v1helpers.NewFakeOperatorClient(
				&operatorv1.OperatorSpec{
					ManagementState: operatorv1.Managed,
				},
				&operatorv1.OperatorStatus{
					Conditions: scenario.previousConditions,
				},
				nil,
			)
			targetNs := ""
			if scenario.workload != nil {
				targetNs = scenario.workload.Namespace
			}

			delegate := &testDelegate{
				preconditionReady: !scenario.operatorPreconditionsNotReady,
				preconditionErr:   scenario.preconditionError,

				syncWorkload:            scenario.workload,
				syncIsAtHighestRevision: scenario.operatorConfigAtHighestRevision,
				syncErrrors:             scenario.errors,
			}

			// act
			target := &Controller{
				operatorClient:  fakeOperatorClient,
				targetNamespace: targetNs,
				podsLister:      &fakePodLister{pods: scenario.pods},
				delegate:        delegate,
			}

			err := target.sync(context.TODO(), factory.NewSyncContext("workloadcontroller_test", events.NewInMemoryRecorder("workloadcontroller_test", clocktesting.NewFakePassiveClock(time.Now()))))
			if err != nil && len(scenario.errors) == 0 {
				t.Fatal(err)
			}

			// validate
			_, actualOperatorStatus, _, err := fakeOperatorClient.GetOperatorState()
			if err != nil {
				t.Fatal(err)
			}
			err = scenario.validateOperatorStatus(actualOperatorStatus)
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDeleteWorkload(t *testing.T) {
	workload := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "apiserver",
			Namespace: "openshift-oauth-apiserver",
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To[int32](3),
		},
		Status: appsv1.DeploymentStatus{
			AvailableReplicas: 3,
			UpdatedReplicas:   3,
			Conditions: []appsv1.DeploymentCondition{
				{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionTrue, LastUpdateTime: metav1.Now(), LastTransitionTime: metav1.Now(), Reason: "NewReplicaSetAvailable", Message: "has successfully progressed"},
			},
		},
	}

	deploymentAvailableTrueAsExpected := operatorv1.OperatorCondition{
		Type:   fmt.Sprintf("%sDeployment%s", defaultControllerName, operatorv1.OperatorStatusTypeAvailable),
		Status: operatorv1.ConditionTrue,
		Reason: "AsExpected",
	}

	workloadDegradedFalse := operatorv1.OperatorCondition{
		Type:   fmt.Sprintf("%sWorkloadDegraded", defaultControllerName),
		Status: operatorv1.ConditionFalse,
	}

	deploymentDegradedFalseAsExpected := operatorv1.OperatorCondition{
		Type:   fmt.Sprintf("%sDeploymentDegraded", defaultControllerName),
		Status: operatorv1.ConditionFalse,
		Reason: "AsExpected",
	}

	deploymentProgressingFalseAsExpected := operatorv1.OperatorCondition{
		Type:   fmt.Sprintf("%sDeployment%s", defaultControllerName, operatorv1.OperatorStatusTypeProgressing),
		Status: operatorv1.ConditionFalse,
		Reason: "AsExpected",
	}

	initialConditions := []operatorv1.OperatorCondition{
		deploymentAvailableTrueAsExpected,
		workloadDegradedFalse,
		deploymentDegradedFalseAsExpected,
		deploymentProgressingFalseAsExpected,
	}

	scenarios := []struct {
		name string

		deletionConditionFn func() (bool, string, error)

		listerDeployments   []*appsv1.Deployment
		deploymentListerErr error
		deleteReactor       func(kubetesting.Action) (bool, runtime.Object, error)

		expectSyncErrors   bool
		expectedConditions []operatorv1.OperatorCondition
	}{
		{
			name:                "condition func nil",
			listerDeployments:   []*appsv1.Deployment{workload},
			deletionConditionFn: nil,
			expectedConditions:  initialConditions,
		},
		{
			name:              "condition error",
			listerDeployments: []*appsv1.Deployment{workload},
			deletionConditionFn: func() (bool, string, error) {
				return false, "", fmt.Errorf("whoops")
			},

			expectSyncErrors:   true,
			expectedConditions: initialConditions,
		},
		{
			name:              "condition not met",
			listerDeployments: []*appsv1.Deployment{workload},
			deletionConditionFn: func() (bool, string, error) {
				return false, "", nil
			},
			expectedConditions: initialConditions,
		},
		{
			name:                "condition met but got deployment lister error",
			listerDeployments:   []*appsv1.Deployment{workload},
			deploymentListerErr: fmt.Errorf("lister error"),
			deletionConditionFn: func() (bool, string, error) {
				return true, workload.Name, nil
			},
			expectSyncErrors: true,
			expectedConditions: []operatorv1.OperatorCondition{
				{
					Type:   fmt.Sprintf("%sDeployment%s", defaultControllerName, operatorv1.OperatorStatusTypeAvailable),
					Status: operatorv1.ConditionFalse,
					Reason: "DeletionError",
				},
				{
					Type:    fmt.Sprintf("%sWorkloadDegraded", defaultControllerName),
					Status:  operatorv1.ConditionTrue,
					Reason:  "DeletionError",
					Message: "lister error",
				},
				deploymentDegradedFalseAsExpected,
				deploymentProgressingFalseAsExpected,
			},
		},
		{
			name:              "condition met but got deletion error",
			listerDeployments: []*appsv1.Deployment{workload},
			deletionConditionFn: func() (bool, string, error) {
				return true, workload.Name, nil
			},
			deleteReactor: func(kubetesting.Action) (bool, runtime.Object, error) {
				return true, nil, fmt.Errorf("delete error")
			},
			expectSyncErrors: true,
			expectedConditions: []operatorv1.OperatorCondition{
				{
					Type:   fmt.Sprintf("%sDeployment%s", defaultControllerName, operatorv1.OperatorStatusTypeAvailable),
					Status: operatorv1.ConditionFalse,
					Reason: "DeletionError",
				},
				{
					Type:    fmt.Sprintf("%sWorkloadDegraded", defaultControllerName),
					Status:  operatorv1.ConditionTrue,
					Reason:  "DeletionError",
					Message: "delete error",
				},
				deploymentDegradedFalseAsExpected,
				deploymentProgressingFalseAsExpected,
			},
		},
		{
			name:              "condition met and deployment already deleted",
			listerDeployments: nil,
			deletionConditionFn: func() (bool, string, error) {
				return true, workload.Name, nil
			},
			expectedConditions: initialConditions,
		},
		{
			name:              "condition met and deployment deleted",
			listerDeployments: []*appsv1.Deployment{workload},
			deletionConditionFn: func() (bool, string, error) {
				return true, workload.Name, nil
			},
			expectedConditions: initialConditions,
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			// setup
			fakeOperatorClient := v1helpers.NewFakeOperatorClient(
				&operatorv1.OperatorSpec{
					ManagementState: operatorv1.Managed,
				},
				&operatorv1.OperatorStatus{
					Conditions: initialConditions,
				},
				nil,
			)

			delegate := &testDelegate{
				preconditionReady: true,
				preconditionErr:   nil,

				syncWorkload:            workload,
				syncIsAtHighestRevision: false,
				syncErrrors:             nil,
			}

			fakeKubeClient := fake.NewSimpleClientset(workload)
			if scenario.deleteReactor != nil {
				fakeKubeClient.PrependReactor("delete", "deployments", scenario.deleteReactor)
			}

			// act
			target := &Controller{
				operatorClient:      fakeOperatorClient,
				kubeClient:          fakeKubeClient,
				targetNamespace:     workload.Namespace,
				podsLister:          &fakePodLister{},
				delegate:            delegate,
				deletionConditionFn: scenario.deletionConditionFn,
				deploymentLister:    &fakeDeploymentLister{scenario.listerDeployments, scenario.deploymentListerErr},
			}

			err := target.sync(context.TODO(), factory.NewSyncContext("workloadcontroller_test", events.NewInMemoryRecorder("workloadcontroller_test", clocktesting.NewFakePassiveClock(time.Now()))))
			if err != nil != scenario.expectSyncErrors {
				t.Fatalf("expected errors: %v; got: %v", scenario.expectSyncErrors, err)
			}

			// validate
			_, actualOperatorStatus, _, err := fakeOperatorClient.GetOperatorState()
			if err != nil {
				t.Fatalf("unexpected error while getting operator state: %v", err)
			}

			err = areCondidtionsEqual(scenario.expectedConditions, actualOperatorStatus.Conditions)
			if err != nil {
				t.Fatalf("unexpected operator conditions: %v", err)
			}
		})
	}
}

type fakePodLister struct {
	pods []*corev1.Pod
}

type fakePodNamespaceLister struct {
	lister *fakePodLister
}

func (f *fakePodNamespaceLister) List(selector labels.Selector) (ret []*corev1.Pod, err error) {
	return f.lister.pods, nil
}

func (f *fakePodNamespaceLister) Get(name string) (*corev1.Pod, error) {
	panic("implement me")
}

func (f *fakePodLister) List(selector labels.Selector) (ret []*corev1.Pod, err error) {
	return f.pods, nil
}

func (f *fakePodLister) Pods(namespace string) corev1listers.PodNamespaceLister {
	return &fakePodNamespaceLister{
		lister: f,
	}
}

type fakeDeploymentLister struct {
	deployments []*appsv1.Deployment
	err         error
}

type fakeDeploymentNamespaceLister struct {
	lister *fakeDeploymentLister
}

func (f *fakeDeploymentNamespaceLister) List(selector labels.Selector) ([]*appsv1.Deployment, error) {
	return f.lister.List(selector)
}

func (f *fakeDeploymentNamespaceLister) Get(name string) (*appsv1.Deployment, error) {
	if f.lister.err != nil {
		return nil, f.lister.err
	}

	for _, d := range f.lister.deployments {
		if d.Name == name {
			return d, nil
		}
	}

	return nil, errors.NewNotFound(schema.GroupResource{Group: "apps", Resource: "deployments"}, name)
}

func (f *fakeDeploymentLister) List(selector labels.Selector) ([]*appsv1.Deployment, error) {
	return f.deployments, f.err
}

func (f *fakeDeploymentLister) Deployments(namespace string) appsv1listers.DeploymentNamespaceLister {
	return &fakeDeploymentNamespaceLister{
		lister: f,
	}
}

func areCondidtionsEqual(expectedConditions []operatorv1.OperatorCondition, actualConditions []operatorv1.OperatorCondition) error {
	if len(expectedConditions) != len(actualConditions) {
		return fmt.Errorf("expected %d conditions but got %d", len(expectedConditions), len(actualConditions))
	}
	for _, expectedCondition := range expectedConditions {
		actualConditionPtr := v1helpers.FindOperatorCondition(actualConditions, expectedCondition.Type)
		if actualConditionPtr == nil {
			return fmt.Errorf("%q condition hasn't been found", expectedCondition.Type)
		}
		// we don't care about the last transition time
		actualConditionPtr.LastTransitionTime = metav1.Time{}
		// so that we don't compare ref vs value types
		actualCondition := *actualConditionPtr
		if !equality.Semantic.DeepEqual(actualCondition, expectedCondition) {
			return fmt.Errorf("conditions mismatch, diff = %s", diff.ObjectDiff(actualCondition, expectedCondition))
		}
	}
	return nil
}
