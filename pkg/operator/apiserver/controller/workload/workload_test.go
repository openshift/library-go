package workload

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	corev1listers "k8s.io/client-go/listers/core/v1"
	clocktesting "k8s.io/utils/clock/testing"
	"k8s.io/utils/ptr"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/api/equality"
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

func (d *testDelegate) WorkloadDeleted(_ context.Context) (bool, string, error) {
	return false, "", nil
}

func (d *testDelegate) PreconditionFulfilled(_ context.Context) (bool, error) {
	return d.preconditionReady, d.preconditionErr
}

func (d *testDelegate) Sync(_ context.Context, _ factory.SyncContext) (*appsv1.Deployment, bool, []error) {
	return d.syncWorkload, d.syncIsAtHighestRevision, d.syncErrrors
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

		validateOperatorStatus  func(*operatorv1.OperatorStatus) error
		validateVersionRecorder func(*fakeVersionRecorder) error
	}{
		{
			name: "no workload",
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
			name:   "no workload with sync errors",
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
			name: "unavailable workload with progress deadline exceeded",
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
						Message: "no apiserver.openshift-apiserver pods available on any node",
					},
					{
						Type:   fmt.Sprintf("%sWorkloadDegraded", defaultControllerName),
						Status: operatorv1.ConditionFalse,
					},
					{
						Type:    fmt.Sprintf("%sDeploymentDegraded", defaultControllerName),
						Status:  operatorv1.ConditionTrue,
						Reason:  "Unavailable",
						Message: "no apiserver.openshift-apiserver pods available on any node",
					},
					{
						Type:    fmt.Sprintf("%sDeployment%s", defaultControllerName, operatorv1.OperatorStatusTypeProgressing),
						Status:  operatorv1.ConditionFalse,
						Reason:  "ProgressDeadlineExceeded",
						Message: "deployment/apiserver.openshift-apiserver has timed out progressing: timed out",
					},
				}
				return areCondidtionsEqual(expectedConditions, actualStatus.Conditions)
			},
		},
		{
			name: "unavailable workload progressing normally",
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
						Message: "no apiserver.openshift-apiserver pods available on any node",
					},
					{
						Type:   fmt.Sprintf("%sWorkloadDegraded", defaultControllerName),
						Status: operatorv1.ConditionFalse,
					},
					{
						Type:    fmt.Sprintf("%sDeploymentDegraded", defaultControllerName),
						Status:  operatorv1.ConditionTrue,
						Reason:  "Unavailable",
						Message: "no apiserver.openshift-apiserver pods available on any node",
					},
					{
						Type:    fmt.Sprintf("%sDeployment%s", defaultControllerName, operatorv1.OperatorStatusTypeProgressing),
						Status:  operatorv1.ConditionTrue,
						Reason:  "PodsUpdating",
						Message: "deployment/apiserver.openshift-apiserver: 0/3 pods have been updated to the latest revision and 0/3 pods are available",
					},
				}
				return areCondidtionsEqual(expectedConditions, actualStatus.Conditions)
			},
		},
		{
			name: "unavailable workload that previously progressed successfully",
			workload: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "apiserver",
					Namespace:  "openshift-apiserver",
					Generation: 5,
				},
				Spec: appsv1.DeploymentSpec{
					Replicas: ptr.To[int32](3),
				},
				Status: appsv1.DeploymentStatus{
					AvailableReplicas:  0,
					UpdatedReplicas:    3,
					ObservedGeneration: 5,
					Conditions: []appsv1.DeploymentCondition{
						{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionTrue, LastUpdateTime: metav1.Now(), LastTransitionTime: metav1.Now(), Reason: "NewReplicaSetAvailable", Message: "has successfully progressed"},
					},
				},
			},
			validateOperatorStatus: func(actualStatus *operatorv1.OperatorStatus) error {
				expectedConditions := []operatorv1.OperatorCondition{
					{
						Type:    fmt.Sprintf("%sDeployment%s", defaultControllerName, operatorv1.OperatorStatusTypeAvailable),
						Status:  operatorv1.ConditionFalse,
						Reason:  "NoPod",
						Message: "no apiserver.openshift-apiserver pods available on any node",
					},
					{
						Type:   fmt.Sprintf("%sWorkloadDegraded", defaultControllerName),
						Status: operatorv1.ConditionFalse,
					},
					{
						Type:    fmt.Sprintf("%sDeploymentDegraded", defaultControllerName),
						Status:  operatorv1.ConditionTrue,
						Reason:  "Unavailable",
						Message: "no apiserver.openshift-apiserver pods available on any node",
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
			name: "partially available workload (2 of 3 replicas)",
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
			name: "fully available workload",
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
			name: "workload scaling with generation mismatch",
			workload: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "apiserver",
					Namespace:  "openshift-apiserver",
					Generation: 100,
				},
				Spec: appsv1.DeploymentSpec{
					Replicas: ptr.To[int32](5),
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
						Status:  operatorv1.ConditionFalse,
						Reason:  "AsExpected",
						Message: "",
					},
				}
				return areCondidtionsEqual(expectedConditions, actualStatus.Conditions)
			},
		},

		{
			name: "workload with generation mismatch and pod failure",
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
						Status:  operatorv1.ConditionFalse,
						Reason:  "AsExpected",
						Message: "",
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
			name:                          "workload rollout in progress",
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
						Message: "deployment/apiserver.openshift-apiserver: 1/3 pods have been updated to the latest revision and 2/3 pods are available",
					},
				}
				return areCondidtionsEqual(expectedConditions, actualStatus.Conditions)
			},
		},
		{
			name: "workload with terminating pods during rollout",
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
						Message: "deployment/apiserver.openshift-apiserver: 3/3 pods have been updated to the latest revision and 2/3 pods are available",
					},
				}
				return areCondidtionsEqual(expectedConditions, actualStatus.Conditions)
			},
		},
		{
			name: "available workload with progress deadline exceeded",
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
					AvailableReplicas:  2,
					UpdatedReplicas:    1,
					ObservedGeneration: 2,
					Conditions: []appsv1.DeploymentCondition{
						{
							Type:               appsv1.DeploymentProgressing,
							Status:             corev1.ConditionFalse,
							Reason:             "ProgressDeadlineExceeded",
							Message:            "deployment has timed out",
							LastUpdateTime:     metav1.Now(),
							LastTransitionTime: metav1.Now(),
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
						Reason:  "ProgressDeadlineExceeded",
						Message: "deployment/apiserver.openshift-apiserver has timed out progressing: deployment has timed out",
					},
					{
						Type:    fmt.Sprintf("%sDeployment%s", defaultControllerName, operatorv1.OperatorStatusTypeProgressing),
						Status:  operatorv1.ConditionFalse,
						Reason:  "ProgressDeadlineExceeded",
						Message: "deployment/apiserver.openshift-apiserver has timed out progressing: deployment has timed out",
					},
				}
				return areCondidtionsEqual(expectedConditions, actualStatus.Conditions)
			},
		},
		{
			name: "workload rollout with maxSurge (4 of 3 replicas available)",
			workload: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "apiserver",
					Namespace:  "openshift-apiserver",
					Generation: 5,
				},
				Spec: appsv1.DeploymentSpec{
					Replicas: ptr.To[int32](3),
				},
				Status: appsv1.DeploymentStatus{
					Replicas:           4,
					AvailableReplicas:  4,
					UpdatedReplicas:    2,
					ObservedGeneration: 5,
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
						Message: "deployment/apiserver.openshift-apiserver: 2/3 pods have been updated to the latest revision and 4/3 pods are available",
					},
				}
				return areCondidtionsEqual(expectedConditions, actualStatus.Conditions)
			},
		},
		{
			name: "workload recovering from progress deadline exceeded",
			workload: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "apiserver",
					Namespace:  "openshift-apiserver",
					Generation: 3,
				},
				Spec: appsv1.DeploymentSpec{
					Replicas: ptr.To[int32](3),
				},
				Status: appsv1.DeploymentStatus{
					AvailableReplicas:  3,
					UpdatedReplicas:    3,
					ObservedGeneration: 3,
					Conditions: []appsv1.DeploymentCondition{
						{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionTrue, LastUpdateTime: metav1.Now(), LastTransitionTime: metav1.Now(), Reason: "NewReplicaSetAvailable", Message: "has successfully progressed"},
					},
				},
			},
			previousConditions: []operatorv1.OperatorCondition{
				{
					Type:               fmt.Sprintf("%sDeployment%s", defaultControllerName, operatorv1.OperatorStatusTypeProgressing),
					Status:             operatorv1.ConditionFalse,
					Reason:             "ProgressDeadlineExceeded",
					Message:            "deployment has timed out",
					LastTransitionTime: metav1.NewTime(time.Now().Add(-5 * time.Minute)),
				},
				{
					Type:               fmt.Sprintf("%sDeploymentDegraded", defaultControllerName),
					Status:             operatorv1.ConditionTrue,
					Reason:             "ProgressDeadlineExceeded",
					LastTransitionTime: metav1.NewTime(time.Now().Add(-5 * time.Minute)),
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
			name:                            "version recorded when at highest revision",
			operatorConfigAtHighestRevision: true,
			workload: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: "apiserver", Namespace: "openshift-apiserver", Generation: 1},
				Spec:       appsv1.DeploymentSpec{Replicas: ptr.To[int32](1)},
				Status: appsv1.DeploymentStatus{
					AvailableReplicas: 1, UpdatedReplicas: 1, ObservedGeneration: 1,
					Conditions: []appsv1.DeploymentCondition{
						{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionTrue, Reason: "NewReplicaSetAvailable"},
					},
				},
			},
			validateOperatorStatus:  func(*operatorv1.OperatorStatus) error { return nil },
			validateVersionRecorder: expectVersionRecorded,
		},
		{
			name:                            "version not recorded when not at highest revision",
			operatorConfigAtHighestRevision: false,
			workload: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: "apiserver", Namespace: "openshift-apiserver", Generation: 1},
				Spec:       appsv1.DeploymentSpec{Replicas: ptr.To[int32](1)},
				Status: appsv1.DeploymentStatus{
					AvailableReplicas: 1, UpdatedReplicas: 1, ObservedGeneration: 1,
					Conditions: []appsv1.DeploymentCondition{
						{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionTrue, Reason: "NewReplicaSetAvailable"},
					},
				},
			},
			validateOperatorStatus: func(*operatorv1.OperatorStatus) error { return nil },
			validateVersionRecorder: expectVersionNotRecorded,
		},
		{
			name:                            "version not recorded when generation != observed generation",
			operatorConfigAtHighestRevision: true,
			workload: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: "apiserver", Namespace: "openshift-apiserver", Generation: 2},
				Spec:       appsv1.DeploymentSpec{Replicas: ptr.To[int32](1)},
				Status: appsv1.DeploymentStatus{
					AvailableReplicas: 1, UpdatedReplicas: 1, ObservedGeneration: 1,
					Conditions: []appsv1.DeploymentCondition{
						{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionTrue, Reason: "NewReplicaSetAvailable"},
					},
				},
			},
			validateOperatorStatus: func(*operatorv1.OperatorStatus) error { return nil },
			validateVersionRecorder: expectVersionNotRecorded,
		},
		{
			name:                            "version not recorded when available replicas < desired",
			operatorConfigAtHighestRevision: true,
			workload: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: "apiserver", Namespace: "openshift-apiserver", Generation: 1},
				Spec:       appsv1.DeploymentSpec{Replicas: ptr.To[int32](3)},
				Status: appsv1.DeploymentStatus{
					AvailableReplicas: 2, UpdatedReplicas: 3, ObservedGeneration: 1,
					Conditions: []appsv1.DeploymentCondition{
						{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionTrue, Reason: "NewReplicaSetAvailable"},
					},
				},
			},
			validateOperatorStatus: func(*operatorv1.OperatorStatus) error { return nil },
			validateVersionRecorder: expectVersionNotRecorded,
		},
		{
			name:                            "version not recorded when updated replicas < desired",
			operatorConfigAtHighestRevision: true,
			workload: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: "apiserver", Namespace: "openshift-apiserver", Generation: 1},
				Spec:       appsv1.DeploymentSpec{Replicas: ptr.To[int32](3)},
				Status: appsv1.DeploymentStatus{
					AvailableReplicas: 3, UpdatedReplicas: 2, ObservedGeneration: 1,
					Conditions: []appsv1.DeploymentCondition{
						{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionTrue, Reason: "NewReplicaSetAvailable"},
					},
				},
			},
			validateOperatorStatus: func(*operatorv1.OperatorStatus) error { return nil },
			validateVersionRecorder: expectVersionNotRecorded,
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

			recorder := &fakeVersionRecorder{}

			// act
			target := &Controller{
				operatorClient:       fakeOperatorClient,
				targetNamespace:      targetNs,
				targetOperandVersion: "v1.0.0-test",
				podsLister:           &fakePodLister{pods: scenario.pods},
				delegate:             delegate,
				versionRecorder:      recorder,
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
			if err := scenario.validateOperatorStatus(actualOperatorStatus); err != nil {
				t.Fatal(err)
			}
			if scenario.validateVersionRecorder != nil {
				if err := scenario.validateVersionRecorder(recorder); err != nil {
					t.Fatal(err)
				}
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

type setVersionCall struct {
	OperandName, Version string
}

type fakeVersionRecorder struct {
	setVersionCalls []setVersionCall
}

func (f *fakeVersionRecorder) SetVersion(operandName, version string) {
	f.setVersionCalls = append(f.setVersionCalls, setVersionCall{operandName, version})
}

func (f *fakeVersionRecorder) UnsetVersion(_ string)                  {}
func (f *fakeVersionRecorder) GetVersions() map[string]string         { return nil }
func (f *fakeVersionRecorder) VersionChangedChannel() <-chan struct{} { return nil }

func expectVersionRecorded(r *fakeVersionRecorder) error {
	expected := []setVersionCall{{OperandName: "apiserver", Version: "v1.0.0-test"}}
	if d := cmp.Diff(expected, r.setVersionCalls); d != "" {
		return fmt.Errorf("unexpected SetVersion calls (-want +got):\n%s", d)
	}
	return nil
}

func expectVersionNotRecorded(r *fakeVersionRecorder) error {
	if d := cmp.Diff([]setVersionCall(nil), r.setVersionCalls); d != "" {
		return fmt.Errorf("unexpected SetVersion calls (-want +got):\n%s", d)
	}
	return nil
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
			return fmt.Errorf("conditions mismatch, diff = %s", diff.Diff(actualCondition, expectedCondition))
		}
	}
	return nil
}
