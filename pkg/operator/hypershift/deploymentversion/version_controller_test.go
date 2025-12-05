package deploymentversioncontroller

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	operatorapi "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	coreinformers "k8s.io/client-go/informers"
	appsinformersv1 "k8s.io/client-go/informers/apps/v1"
	"k8s.io/client-go/kubernetes"
	fakecore "k8s.io/client-go/kubernetes/fake"
	clocktesting "k8s.io/utils/clock/testing"
)

const (
	controllerName   = "SomeDeploymentVesrsionController"
	operandName      = "some-driver-controller"
	operandNamespace = "some-namespace"

	theVersion                     = "1.2.3"
	oldVersion                     = "1.2.2"
	newVersion                     = "1.2.4"
	operatorImageVersionEnvVarName = "OPERATOR_IMAGE_VERSION"
)

type testContext struct {
	controller                          factory.Controller
	managementClusterKubeClient         kubernetes.Interface
	managementClusterDeploymentInformer appsinformersv1.DeploymentInformer
}

type syncTestCase struct {
	name                   string
	operatorStateUnmanaged bool
	inputDeployment        *appsv1.Deployment
	expectedDeployment     *appsv1.Deployment
	envVarVersion          string
	expectErr              bool
}

func newTestContext(test syncTestCase, t *testing.T) *testContext {
	var initialObjects []runtime.Object
	if test.inputDeployment != nil {
		initialObjects = append(initialObjects, test.inputDeployment)
	}
	managementClusterKubeClient := fakecore.NewSimpleClientset(initialObjects...)

	coreInformerFactory := coreinformers.NewSharedInformerFactory(managementClusterKubeClient, 0 /*no resync */)
	managementClusterDeploymentInformer := coreInformerFactory.Apps().V1().Deployments()

	if test.inputDeployment != nil {
		managementClusterDeploymentInformer.Informer().GetIndexer().Add(test.inputDeployment)
	}

	managementState := operatorapi.Managed
	if test.operatorStateUnmanaged {
		managementState = operatorapi.Unmanaged
	}
	spec := operatorapi.OperatorSpec{
		ManagementState: managementState,
	}
	status := operatorapi.OperatorStatus{}
	fakeOperatorClient := v1helpers.NewFakeOperatorClient(&spec, &status, nil)

	eventRecorder := events.NewInMemoryRecorder("aws-ebs-csi-driver-operator", clocktesting.NewFakePassiveClock(time.Now()))

	controller := NewDeploymentVersionController(
		controllerName,
		operandNamespace,
		operandName,
		managementClusterDeploymentInformer,
		fakeOperatorClient,
		managementClusterKubeClient,
		eventRecorder)

	return &testContext{
		controller:                          controller,
		managementClusterKubeClient:         managementClusterKubeClient,
		managementClusterDeploymentInformer: managementClusterDeploymentInformer,
	}
}

func TestSync(t *testing.T) {
	// Base deployment with existing desired-version annotation
	noVersionAnnotationDeployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:       operandName,
			Namespace:  operandNamespace,
			Generation: 1,
			Annotations: map[string]string{
				desiredVersionAnnotation: theVersion,
			},
		},
		Status: appsv1.DeploymentStatus{
			ObservedGeneration: 1,
			Conditions: []appsv1.DeploymentCondition{
				{
					Type:   appsv1.DeploymentProgressing,
					Status: corev1.ConditionTrue,
					Reason: "NewReplicaSetAvailable",
				},
			},
		},
	}

	// Base deployment with current version annotation
	withVersionAnnotationDeployment := noVersionAnnotationDeployment.DeepCopy()
	withVersionAnnotationDeployment.Annotations[versionAnnotation] = theVersion

	// Base deployment with old version annotation
	withOldVersionAnnotationDeployment := noVersionAnnotationDeployment.DeepCopy()
	withOldVersionAnnotationDeployment.Annotations[versionAnnotation] = oldVersion

	// Base deployment with old version annotation and updated generation
	newGenerationDeployment := withOldVersionAnnotationDeployment.DeepCopy()
	newGenerationDeployment.Generation = 2

	// Base deployment with old version annotation and false status condition
	falseConditionDeployment := withOldVersionAnnotationDeployment.DeepCopy()
	falseConditionDeployment.Status.Conditions[0].Status = corev1.ConditionFalse

	// Base deployment with old version annotation and "wrong" reason
	anotherReasonDeployment := withOldVersionAnnotationDeployment.DeepCopy()
	anotherReasonDeployment.Status.Conditions[0].Reason = "AnotherReason"

	// Base deployment with old version annotation and without status condition
	noConditionDeployment := withOldVersionAnnotationDeployment.DeepCopy()
	noConditionDeployment.Status.Conditions = []appsv1.DeploymentCondition{}

	testCases := []syncTestCase{
		{
			name:                   "test sync: operator ManagementState is Unmanaged",
			operatorStateUnmanaged: true,
		},
		{
			name:      "test sync: no deployment available",
			expectErr: true,
		},
		{
			name:               "test sync: normal workflow: all versions are equal to each other",
			inputDeployment:    withVersionAnnotationDeployment,
			expectedDeployment: withVersionAnnotationDeployment,
		},
		{
			name:               "test sync: normal workflow: version update is expected (no version set)",
			inputDeployment:    noVersionAnnotationDeployment,
			expectedDeployment: withVersionAnnotationDeployment,
		},
		{
			name:               "test sync: normal workflow: version update is expected (stale version set)",
			inputDeployment:    withOldVersionAnnotationDeployment,
			expectedDeployment: withVersionAnnotationDeployment,
		},
		{
			name:               "test sync: desiredVersion mismatch",
			inputDeployment:    withVersionAnnotationDeployment,
			expectedDeployment: withVersionAnnotationDeployment,
			envVarVersion:      newVersion,
		},
		{
			name:               "test sync: stale ObservedGeneration",
			inputDeployment:    newGenerationDeployment,
			expectedDeployment: newGenerationDeployment,
		},
		{
			name:               "test sync: NewReplicaSetAvailable has false status",
			inputDeployment:    falseConditionDeployment,
			expectedDeployment: falseConditionDeployment,
		},
		{
			name:               "test sync: Condition with another reason",
			inputDeployment:    anotherReasonDeployment,
			expectedDeployment: anotherReasonDeployment,
		},
		{
			name:               "test sync: no DeploymentProgressing condition found",
			inputDeployment:    noConditionDeployment,
			expectedDeployment: noConditionDeployment,
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			// Prepare OPERATOR_IMAGE_VERSION env var for DeploymentVersionController
			var version string
			if test.envVarVersion == "" {
				version = theVersion
			} else {
				version = test.envVarVersion
			}
			t.Setenv(operatorImageVersionEnvVarName, version)

			// Initialize
			ctx := newTestContext(test, t)

			// Act
			err := ctx.controller.Sync(context.TODO(), factory.NewSyncContext(controllerName, events.NewInMemoryRecorder(operandName, clocktesting.NewFakePassiveClock(time.Now()))))
			if err != nil && !test.expectErr {
				t.Errorf("Failed to sync Deployment: %s", err)
			}
			if err == nil && test.expectErr {
				t.Errorf("Error was expected but nil was returned")
			}

			// Assert
			deployment, err := ctx.managementClusterKubeClient.AppsV1().Deployments(operandNamespace).Get(context.TODO(), operandName, metav1.GetOptions{})
			if err != nil {
				if test.expectedDeployment == nil && apierrors.IsNotFound(err) {
					return
				}
				t.Errorf("Internal error: deployment not found: %v", err)
			}
			if !equality.Semantic.DeepEqual(deployment, test.expectedDeployment) {
				t.Errorf("Unexpected deployment: %+v", cmp.Diff(test.expectedDeployment, deployment))
			}

		})
	}
}

func TestSetVersionAnnotation(t *testing.T) {
	type setVersionAnnotationTestCase struct {
		name               string
		inputDeployment    *appsv1.Deployment
		expectedDeployment *appsv1.Deployment
	}

	// Base deployment with existing annotations
	deploymentWithAnnotations := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      operandName,
			Namespace: operandNamespace,
			Annotations: map[string]string{
				"some-other-annotation":  "some-value",
				desiredVersionAnnotation: theVersion,
			},
		},
	}

	// Deployment with nil annotations
	deploymentWithoutAnnotations := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      operandName,
			Namespace: operandNamespace,
		},
	}

	// Deployment with existing version annotation
	deploymentWithVersionAnnotation := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      operandName,
			Namespace: operandNamespace,
			Annotations: map[string]string{
				versionAnnotation: oldVersion,
			},
		},
	}

	testCases := []setVersionAnnotationTestCase{
		{
			name:            "add version annotation to deployment with existing annotations",
			inputDeployment: deploymentWithAnnotations,
			expectedDeployment: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      operandName,
					Namespace: operandNamespace,
					Annotations: map[string]string{
						"some-other-annotation":  "some-value",
						desiredVersionAnnotation: theVersion,
						versionAnnotation:        theVersion,
					},
				},
			},
		},
		{
			name:            "add version annotation to deployment with nil annotations",
			inputDeployment: deploymentWithoutAnnotations,
			expectedDeployment: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      operandName,
					Namespace: operandNamespace,
					Annotations: map[string]string{
						versionAnnotation: theVersion,
					},
				},
			},
		},
		{
			name:            "update existing version annotation",
			inputDeployment: deploymentWithVersionAnnotation,
			expectedDeployment: &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      operandName,
					Namespace: operandNamespace,
					Annotations: map[string]string{
						versionAnnotation: theVersion,
					},
				},
			},
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			// Act
			result := setVersionAnnotation(test.inputDeployment, theVersion)

			// Assert - verify the result matches expected
			if !equality.Semantic.DeepEqual(result, test.expectedDeployment) {
				t.Errorf("Unexpected deployment: %+v", cmp.Diff(test.expectedDeployment, result))
			}
		})
	}
}
