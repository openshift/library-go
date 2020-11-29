package workload

import (
	"fmt"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/utils/pointer"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/diff"
)

const (
	defaultControllerName = ""
)

func TestUpdateOperatorStatus(t *testing.T) {
	scenarios := []struct {
		name string

		workload                        *appsv1.Deployment
		pods                            []*corev1.Pod
		operatorConfigAtHighestRevision bool
		operatorPreconditionsNotReady   bool
		errors                          []error

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
						Type:   fmt.Sprintf("%sWorkloadDegraded", defaultControllerName),
						Status: operatorv1.ConditionFalse,
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
			name: "scenario: we have an unavailiable workload and no errors thus we are degraded",
			workload: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "apiserver",
					Namespace: "openshift-apiserver",
				},
				Spec: appsv1.DeploymentSpec{
					Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"foo": "bar"}}},
					Replicas: pointer.Int32Ptr(3),
				},
				Status: appsv1.DeploymentStatus{
					AvailableReplicas: 0,
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
						Status:  operatorv1.ConditionFalse,
						Reason:  "AsExpected",
						Message: "",
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
					Replicas: pointer.Int32Ptr(3),
				},
				Status: appsv1.DeploymentStatus{
					AvailableReplicas: 2,
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
					Replicas: pointer.Int32Ptr(3),
				},
				Status: appsv1.DeploymentStatus{
					AvailableReplicas: 3,
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
					Replicas: pointer.Int32Ptr(3),
				},
				Status: appsv1.DeploymentStatus{
					AvailableReplicas:  3,
					ObservedGeneration: 99,
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
						Type:   fmt.Sprintf("%sWorkloadDegraded", defaultControllerName),
						Status: operatorv1.ConditionFalse,
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
				nil,
				&operatorv1.OperatorStatus{},
				nil,
			)
			targetNs := ""
			if scenario.workload != nil {
				targetNs = scenario.workload.Namespace
			}

			// act
			target := &Controller{operatorClient: fakeOperatorClient, name: defaultControllerName, targetNamespace: targetNs, podsLister: &fakePodLister{pods: scenario.pods}}
			err := target.updateOperatorStatus(scenario.workload, scenario.operatorConfigAtHighestRevision, !scenario.operatorPreconditionsNotReady, scenario.errors)
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
