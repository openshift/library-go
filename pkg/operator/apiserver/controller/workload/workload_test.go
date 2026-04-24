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
		podListErr                      error
		operatorConfigAtHighestRevision bool
		operatorPreconditionsNotReady   bool
		preconditionError               error
		errors                          []error
		previousConditions              []operatorv1.OperatorCondition

		validateOperatorStatus  func(*operatorv1.OperatorStatus) error
		validateVersionRecorder func(*fakeVersionRecorder) error
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
						Message: "nasty error",
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
			name: "scenario: unavailable workload with progress deadline exceeded",
			workload: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "apiserver",
					Namespace: "openshift-apiserver",
				},
				Spec: appsv1.DeploymentSpec{
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
					ObjectMeta: metav1.ObjectMeta{Name: "apiserver", Namespace: "openshift-apiserver"},
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
						Reason:  "ProgressDeadlineExceeded",
						Message: "deployment/apiserver.openshift-apiserver has timed out progressing: timed out",
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
			name: "scenario: unavailable workload progressing normally",
			workload: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "apiserver",
					Namespace: "openshift-apiserver",
				},
				Spec: appsv1.DeploymentSpec{
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
					ObjectMeta: metav1.ObjectMeta{Name: "apiserver", Namespace: "openshift-apiserver"},
					Status: corev1.PodStatus{
						Phase: corev1.PodPending,
						ContainerStatuses: []corev1.ContainerStatus{
							{
								Name:  "test",
								Ready: false,
								State: corev1.ContainerState{
									Waiting: &corev1.ContainerStateWaiting{
										Reason: "ContainerCreating",
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
						Type:   fmt.Sprintf("%sDeploymentDegraded", defaultControllerName),
						Status: operatorv1.ConditionFalse,
						Reason: "AsExpected",
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
			name: "scenario: unavailable workload that previously progressed successfully",
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
			pods: []*corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "apiserver-1", Namespace: "openshift-apiserver"},
					Status: corev1.PodStatus{
						Phase: corev1.PodRunning,
						ContainerStatuses: []corev1.ContainerStatus{
							{Name: "apiserver", Ready: false, RestartCount: 8},
						},
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
						Reason:  "UnavailablePod",
						Message: "3 of 3 requested instances are unavailable for apiserver.openshift-apiserver (container apiserver is crashlooping in pod apiserver-1)",
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
			name: "scenario: partially available workload with failing pod",
			workload: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "apiserver",
					Namespace: "openshift-apiserver",
				},
				Spec: appsv1.DeploymentSpec{
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
					ObjectMeta: metav1.ObjectMeta{Name: "apiserver-ready", Namespace: "openshift-apiserver"},
					Status: corev1.PodStatus{
						Phase: corev1.PodRunning,
						ContainerStatuses: []corev1.ContainerStatus{
							{Name: "test", Ready: true},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "apiserver-crash", Namespace: "openshift-apiserver"},
					Status: corev1.PodStatus{
						Phase: corev1.PodRunning,
						ContainerStatuses: []corev1.ContainerStatus{
							{Name: "test", Ready: false, RestartCount: 5},
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
						Message: "1 of 3 requested instances are unavailable for apiserver.openshift-apiserver (container test is crashlooping in pod apiserver-crash)",
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
			name: "scenario: workload scaling with generation mismatch",
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
			name: "scenario: partially available during scale-up, pods starting",
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
					AvailableReplicas:  1,
					UpdatedReplicas:    1,
					ObservedGeneration: 99,
					Conditions: []appsv1.DeploymentCondition{
						{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionTrue, Reason: "NewReplicaSetAvailable"},
					},
				},
			},
			pods: []*corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "apiserver-new-1", Namespace: "openshift-apiserver"},
					Status: corev1.PodStatus{
						Phase: corev1.PodPending,
						ContainerStatuses: []corev1.ContainerStatus{
							{Name: "test", Ready: false, RestartCount: 0, State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "ContainerCreating"}}},
						},
					},
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
			name: "scenario: partially available during scale-up, new pods failing",
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
					AvailableReplicas:  3,
					UpdatedReplicas:    3,
					ObservedGeneration: 99,
					Conditions: []appsv1.DeploymentCondition{
						{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionTrue, Reason: "NewReplicaSetAvailable"},
					},
				},
			},
			pods: []*corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "apiserver-fail-1", Namespace: "openshift-apiserver"},
					Status: corev1.PodStatus{
						Phase: corev1.PodRunning,
						ContainerStatuses: []corev1.ContainerStatus{
							{Name: "test", Ready: false, RestartCount: 3},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "apiserver-fail-2", Namespace: "openshift-apiserver"},
					Status: corev1.PodStatus{
						Phase: corev1.PodRunning,
						ContainerStatuses: []corev1.ContainerStatus{
							{Name: "test", Ready: false, RestartCount: 3},
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
						Message: "2 of 5 requested instances are unavailable for apiserver.openshift-apiserver (container test is crashlooping in pod apiserver-fail-1, container test is crashlooping in pod apiserver-fail-2)",
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
			name: "scenario: partially available during active rollout, pods starting",
			workload: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "apiserver",
					Namespace: "openshift-apiserver",
				},
				Spec: appsv1.DeploymentSpec{
					Replicas: ptr.To[int32](3),
				},
				Status: appsv1.DeploymentStatus{
					AvailableReplicas: 2,
					UpdatedReplicas:   1,
					Conditions: []appsv1.DeploymentCondition{
						{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionTrue, Reason: "ReplicaSetUpdated", Message: "progressing"},
					},
				},
			},
			pods: []*corev1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "apiserver-new", Namespace: "openshift-apiserver"},
					Status: corev1.PodStatus{
						Phase: corev1.PodPending,
						ContainerStatuses: []corev1.ContainerStatus{
							{Name: "test", Ready: false, RestartCount: 0, State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "ContainerCreating"}}},
						},
					},
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
			name: "scenario: zero available replicas, no pods exist",
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
					UpdatedReplicas:    0,
					ObservedGeneration: 5,
					Conditions: []appsv1.DeploymentCondition{
						{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionTrue, Reason: "NewReplicaSetAvailable"},
					},
				},
			},
			pods: []*corev1.Pod{},
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
						Reason:  "UnavailablePod",
						Message: "3 of 3 requested instances are unavailable for apiserver.openshift-apiserver",
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
			name: "scenario: pod list error",
			workload: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "apiserver",
					Namespace: "openshift-apiserver",
				},
				Spec: appsv1.DeploymentSpec{
					Replicas: ptr.To[int32](3),
				},
				Status: appsv1.DeploymentStatus{
					AvailableReplicas: 2,
					UpdatedReplicas:   3,
					Conditions: []appsv1.DeploymentCondition{
						{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionTrue, Reason: "NewReplicaSetAvailable", Message: "has successfully progressed"},
					},
				},
			},
			podListErr: fmt.Errorf("fake list error"),
			validateOperatorStatus: func(actualStatus *operatorv1.OperatorStatus) error {
				expectedConditions := []operatorv1.OperatorCondition{
					{
						Type:   fmt.Sprintf("%sDeployment%s", defaultControllerName, operatorv1.OperatorStatusTypeAvailable),
						Status: operatorv1.ConditionTrue,
						Reason: "AsExpected",
					},
					{
						Type:    fmt.Sprintf("%sWorkloadDegraded", defaultControllerName),
						Status:  operatorv1.ConditionTrue,
						Reason:  "SyncError",
						Message: "fake list error",
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
						Message: "deployment/apiserver.openshift-apiserver: 1/3 pods have been updated to the latest revision and 2/3 pods are available",
					},
				}
				return areCondidtionsEqual(expectedConditions, actualStatus.Conditions)
			},
		},
		{
			name: "scenario: all pods updated but not all available yet",
			workload: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "apiserver",
					Namespace: "openshift-apiserver",
				},
				Spec: appsv1.DeploymentSpec{
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
			name: "scenario: available workload with progress deadline exceeded",
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
						Type:   fmt.Sprintf("%sDeployment%s", defaultControllerName, operatorv1.OperatorStatusTypeAvailable),
						Status: operatorv1.ConditionTrue,
						Reason: "AsExpected",
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
			name: "scenario: workload rollout with maxSurge (4 of 3 replicas available)",
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
			name: "scenario: workload recovering from progress deadline exceeded",
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
			validateOperatorStatus:  func(*operatorv1.OperatorStatus) error { return nil },
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
			validateOperatorStatus:  func(*operatorv1.OperatorStatus) error { return nil },
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
			validateOperatorStatus:  func(*operatorv1.OperatorStatus) error { return nil },
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
			validateOperatorStatus:  func(*operatorv1.OperatorStatus) error { return nil },
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
				podsLister:           &fakePodLister{pods: scenario.pods, err: scenario.podListErr},
				delegate:             delegate,
				versionRecorder:      recorder,
			}

			err := target.sync(context.TODO(), factory.NewSyncContext("workloadcontroller_test", events.NewInMemoryRecorder("workloadcontroller_test", clocktesting.NewFakePassiveClock(time.Now()))))
			if err != nil && len(scenario.errors) == 0 && scenario.podListErr == nil {
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
	err  error
}

type fakePodNamespaceLister struct {
	lister *fakePodLister
}

func (f *fakePodNamespaceLister) List(selector labels.Selector) (ret []*corev1.Pod, err error) {
	return f.lister.pods, f.lister.err
}

func (f *fakePodNamespaceLister) Get(name string) (*corev1.Pod, error) {
	panic("implement me")
}

func (f *fakePodLister) List(selector labels.Selector) (ret []*corev1.Pod, err error) {
	return f.pods, f.err
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
