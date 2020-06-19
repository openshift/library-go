package csidrivercontroller

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	coreinformers "k8s.io/client-go/informers"
	fakecore "k8s.io/client-go/kubernetes/fake"
	core "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"

	opv1 "github.com/openshift/api/operator/v1"

	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

const (
	controllerName   = "TestCSIDriverController"
	operandName      = "test-csi-driver"
	operandNamespace = "openshift-test-csi-driver"

	// From github.com/openshift/library-go/pkg/operator/resource/resourceapply/apps.go
	specHashAnnotation = "operator.openshift.io/spec-hash"
)

var (
	conditionAvailable        = controllerName + opv1.OperatorStatusTypeAvailable
	conditionDegraded         = controllerName + opv1.OperatorStatusTypeDegraded
	conditionProgressing      = controllerName + opv1.OperatorStatusTypeProgressing
	conditionUpgradeable      = controllerName + opv1.OperatorStatusTypeUpgradeable
	conditionPrereqsSatisfied = controllerName + opv1.OperatorStatusTypePrereqsSatisfied
)

type testCase struct {
	name            string
	images          images
	initialObjects  testObjects
	expectedObjects testObjects
	reactors        testReactors
	expectErr       bool
}

type testObjects struct {
	deployment *appsv1.Deployment
	daemonSet  *appsv1.DaemonSet
	driver     *fakeDriverInstance
}

type testContext struct {
	operator       *CSIDriverController
	operatorClient v1helpers.OperatorClient
	coreClient     *fakecore.Clientset
	coreInformers  coreinformers.SharedInformerFactory
}

type addCoreReactors func(*fakecore.Clientset, coreinformers.SharedInformerFactory)

type testReactors struct {
	deployments addCoreReactors
	daemonSets  addCoreReactors
}

func newOperator(test testCase, t *testing.T) *testContext {
	// Convert to []runtime.Object
	var initialObjects []runtime.Object
	if test.initialObjects.deployment != nil {
		resourceapply.SetSpecHashAnnotation(&test.initialObjects.deployment.ObjectMeta, test.initialObjects.deployment.Spec)
		initialObjects = append(initialObjects, test.initialObjects.deployment)
	}

	if test.initialObjects.daemonSet != nil {
		resourceapply.SetSpecHashAnnotation(&test.initialObjects.daemonSet.ObjectMeta, test.initialObjects.daemonSet.Spec)
		initialObjects = append(initialObjects, test.initialObjects.daemonSet)
	}

	coreClient := fakecore.NewSimpleClientset(initialObjects...)
	coreInformerFactory := coreinformers.NewSharedInformerFactory(coreClient, 0 /*no resync */)

	// Fill the informer
	if test.initialObjects.deployment != nil {
		coreInformerFactory.Apps().V1().Deployments().Informer().GetIndexer().Add(test.initialObjects.deployment)
	}
	if test.initialObjects.daemonSet != nil {
		coreInformerFactory.Apps().V1().DaemonSets().Informer().GetIndexer().Add(test.initialObjects.daemonSet)
	}
	if test.reactors.deployments != nil {
		test.reactors.deployments(coreClient, coreInformerFactory)
	}
	if test.reactors.daemonSets != nil {
		test.reactors.daemonSets(coreClient, coreInformerFactory)
	}

	// Add global reactors
	addGenerationReactor(coreClient)

	// fakeDriverInstance also fulfils the OperatorClient interface
	fakeOperatorClient := test.initialObjects.driver
	op := NewCSIDriverController(
		controllerName,
		operandName,
		operandNamespace,
		fakeOperatorClient,
		makeFakeManifest,
		coreClient,
		events.NewInMemoryRecorder("test-csi-driver"),
	).WithControllerService(
		coreInformerFactory.Apps().V1().Deployments(),
		"deployment",
	).WithNodeService(
		coreInformerFactory.Apps().V1().DaemonSets(),
		"daemonSet",
	)

	return &testContext{
		operator:       op,
		operatorClient: fakeOperatorClient,
		coreClient:     coreClient,
		coreInformers:  coreInformerFactory,
	}
}

// Drivers

type driverModifier func(*fakeDriverInstance) *fakeDriverInstance

func makeFakeDriverInstance(modifiers ...driverModifier) *fakeDriverInstance {
	instance := &fakeDriverInstance{
		// TypeMeta: metav1.TypeMeta{APIVersion: v1alpha1.SchemeGroupVersion.String()},
		ObjectMeta: metav1.ObjectMeta{
			Name:       "cluster",
			Generation: 0,
		},
		Spec: opv1.OperatorSpec{
			ManagementState: opv1.Managed,
		},
		Status: opv1.OperatorStatus{},
	}
	for _, modifier := range modifiers {
		instance = modifier(instance)
	}
	return instance
}

func withStatus(readyReplicas int32) driverModifier {
	return func(i *fakeDriverInstance) *fakeDriverInstance {
		i.Status = opv1.OperatorStatus{
			ReadyReplicas: readyReplicas,
		}
		return i
	}
}

func withLogLevel(logLevel opv1.LogLevel) driverModifier {
	return func(i *fakeDriverInstance) *fakeDriverInstance {
		i.Spec.LogLevel = logLevel
		return i
	}
}

func withGeneration(generations ...int64) driverModifier {
	return func(i *fakeDriverInstance) *fakeDriverInstance {
		i.Generation = generations[0]
		if len(generations) > 1 {
			i.Status.ObservedGeneration = generations[1]
		}
		return i
	}
}

func withGenerations(deployment, daemonset, credentialsRequest int64) driverModifier {
	return func(i *fakeDriverInstance) *fakeDriverInstance {
		i.Status.Generations = []opv1.GenerationStatus{
			{
				Group:          appsv1.GroupName,
				LastGeneration: daemonset,
				Name:           "test-csi-driver-node",
				Namespace:      operandNamespace,
				Resource:       "daemonsets",
			},
			{
				Group:          appsv1.GroupName,
				LastGeneration: deployment,
				Name:           "test-csi-driver-controller",
				Namespace:      operandNamespace,
				Resource:       "deployments",
			},
		}
		return i
	}
}

func withTrueConditions(conditions ...string) driverModifier {
	return func(i *fakeDriverInstance) *fakeDriverInstance {
		if i.Status.Conditions == nil {
			i.Status.Conditions = []opv1.OperatorCondition{}
		}
		for _, cond := range conditions {
			i.Status.Conditions = append(i.Status.Conditions, opv1.OperatorCondition{
				Type:   cond,
				Status: opv1.ConditionTrue,
			})
		}
		return i
	}
}

func withFalseConditions(conditions ...string) driverModifier {
	return func(i *fakeDriverInstance) *fakeDriverInstance {
		if i.Status.Conditions == nil {
			i.Status.Conditions = []opv1.OperatorCondition{}
		}
		for _, c := range conditions {
			i.Status.Conditions = append(i.Status.Conditions, opv1.OperatorCondition{
				Type:   c,
				Status: opv1.ConditionFalse,
			})
		}
		return i
	}
}

// Deployments

type deploymentModifier func(*appsv1.Deployment) *appsv1.Deployment

func getDeployment(logLevel int, images images, modifiers ...deploymentModifier) *appsv1.Deployment {
	manifest := makeFakeManifest("deployment")
	dep := resourceread.ReadDeploymentV1OrDie(manifest)
	containers := dep.Spec.Template.Spec.Containers
	if images.csiDriver != "" {
		if idx := getIndex(containers, csiDriverContainerName); idx > -1 {
			containers[idx].Image = images.csiDriver
		}
	}

	if images.provisioner != "" {
		if idx := getIndex(containers, provisionerContainerName); idx > -1 {
			containers[idx].Image = images.provisioner
		}
	}

	if images.attacher != "" {
		if idx := getIndex(containers, attacherContainerName); idx > -1 {
			containers[idx].Image = images.attacher
		}
	}

	if images.resizer != "" {
		if idx := getIndex(containers, resizerContainerName); idx > -1 {
			containers[idx].Image = images.resizer
		}
	}

	if images.snapshotter != "" {
		if idx := getIndex(containers, snapshotterContainerName); idx > -1 {
			containers[idx].Image = images.snapshotter
		}
	}

	if images.livenessProbe != "" {
		if idx := getIndex(containers, livenessProbeContainerName); idx > -1 {
			containers[idx].Image = images.livenessProbe
		}
	}

	var one int32 = 1
	dep.Spec.Replicas = &one

	for i, container := range dep.Spec.Template.Spec.Containers {
		for j, arg := range container.Args {
			if strings.HasPrefix(arg, "--v=") {
				dep.Spec.Template.Spec.Containers[i].Args[j] = fmt.Sprintf("--v=%d", logLevel)
			}
		}
	}

	for _, modifier := range modifiers {
		dep = modifier(dep)
	}

	return dep
}

func withDeploymentStatus(readyReplicas, availableReplicas, updatedReplicas int32) deploymentModifier {
	return func(instance *appsv1.Deployment) *appsv1.Deployment {
		instance.Status.ReadyReplicas = readyReplicas
		instance.Status.AvailableReplicas = availableReplicas
		instance.Status.UpdatedReplicas = updatedReplicas
		return instance
	}
}

func withDeploymentReplicas(replicas int32) deploymentModifier {
	return func(instance *appsv1.Deployment) *appsv1.Deployment {
		instance.Spec.Replicas = &replicas
		return instance
	}
}

func withDeploymentGeneration(generations ...int64) deploymentModifier {
	return func(instance *appsv1.Deployment) *appsv1.Deployment {
		instance.Generation = generations[0]
		if len(generations) > 1 {
			instance.Status.ObservedGeneration = generations[1]
		}
		return instance
	}
}

// DaemonSets

type daemonSetModifier func(*appsv1.DaemonSet) *appsv1.DaemonSet

func getDaemonSet(logLevel int, images images, modifiers ...daemonSetModifier) *appsv1.DaemonSet {
	manifest := makeFakeManifest("daemonSet")
	ds := resourceread.ReadDaemonSetV1OrDie(manifest)
	containers := ds.Spec.Template.Spec.Containers
	if images.csiDriver != "" {
		if idx := getIndex(containers, csiDriverContainerName); idx > -1 {
			containers[idx].Image = images.csiDriver
		}
	}

	if images.nodeDriverRegistrar != "" {
		if idx := getIndex(containers, nodeDriverRegistrarContainerName); idx > -1 {
			containers[idx].Image = images.nodeDriverRegistrar
		}
	}

	if images.livenessProbe != "" {
		if idx := getIndex(containers, livenessProbeContainerName); idx > -1 {
			containers[idx].Image = images.livenessProbe
		}
	}

	for i, container := range ds.Spec.Template.Spec.Containers {
		for j, arg := range container.Args {
			if strings.HasPrefix(arg, "--v=") {
				ds.Spec.Template.Spec.Containers[i].Args[j] = fmt.Sprintf("--v=%d", logLevel)
			}
		}
	}

	for _, modifier := range modifiers {
		ds = modifier(ds)
	}

	return ds
}

func withDaemonSetStatus(numberReady, updatedNumber, numberAvailable int32) daemonSetModifier {
	return func(instance *appsv1.DaemonSet) *appsv1.DaemonSet {
		instance.Status.NumberReady = numberReady
		instance.Status.NumberAvailable = numberAvailable
		instance.Status.UpdatedNumberScheduled = updatedNumber
		return instance
	}
}

func withDaemonSetGeneration(generations ...int64) daemonSetModifier {
	return func(instance *appsv1.DaemonSet) *appsv1.DaemonSet {
		instance.Generation = generations[0]
		if len(generations) > 1 {
			instance.Status.ObservedGeneration = generations[1]
		}
		return instance
	}
}

// This reactor is always enabled and bumps Deployment and DaemonSet generation when they get updated.
func addGenerationReactor(client *fakecore.Clientset) {
	client.PrependReactor("*", "deployments", func(action core.Action) (handled bool, ret runtime.Object, err error) {
		switch a := action.(type) {
		case core.CreateActionImpl:
			object := a.GetObject()
			deployment := object.(*appsv1.Deployment)
			deployment.Generation++
			return false, deployment, nil
		case core.UpdateActionImpl:
			object := a.GetObject()
			deployment := object.(*appsv1.Deployment)
			deployment.Generation++
			return false, deployment, nil
		}
		return false, nil, nil
	})

	client.PrependReactor("*", "daemonsets", func(action core.Action) (handled bool, ret runtime.Object, err error) {
		switch a := action.(type) {
		case core.CreateActionImpl:
			object := a.GetObject()
			ds := object.(*appsv1.DaemonSet)
			ds.Generation++
			return false, ds, nil
		case core.UpdateActionImpl:
			object := a.GetObject()
			ds := object.(*appsv1.DaemonSet)
			ds.Generation++
			return false, ds, nil
		}
		return false, nil, nil
	})
}

func TestSync(t *testing.T) {
	const (
		replica0 = 0
		replica1 = 1
		replica2 = 2
	)
	var (
		argsLevel2 = 2
		argsLevel6 = 6
	)

	testCases := []testCase{
		{
			// Only Driver exists, everything else is created
			name:   "initial sync",
			images: defaultImages(),
			initialObjects: testObjects{
				driver: makeFakeDriverInstance(),
			},
			expectedObjects: testObjects{
				deployment: getDeployment(argsLevel2, defaultImages(),
					withDeploymentGeneration(1, 0)),
				daemonSet: getDaemonSet(argsLevel2, defaultImages(),
					withDaemonSetGeneration(1, 0)),
				driver: makeFakeDriverInstance(
					withStatus(replica0),
					withGenerations(1, 1, 1),
					withTrueConditions(conditionUpgradeable, conditionPrereqsSatisfied, conditionProgressing),
					withFalseConditions(conditionDegraded, conditionAvailable)),
			},
		},
		{
			// Deployment is fully deployed and its status is synced to Driver
			name:   "deployment fully deployed",
			images: defaultImages(),
			initialObjects: testObjects{
				deployment: getDeployment(
					argsLevel2,
					defaultImages(),
					withDeploymentGeneration(1, 1),
					withDeploymentStatus(replica1, replica1, replica1)),
				daemonSet: getDaemonSet(
					argsLevel2,
					defaultImages(),
					withDaemonSetGeneration(1, 1),
					withDaemonSetStatus(replica1, replica1, replica1)),
				driver: makeFakeDriverInstance(withGenerations(1, 1, 1)),
			},
			expectedObjects: testObjects{
				deployment: getDeployment(argsLevel2, defaultImages(),
					withDeploymentGeneration(1, 1),
					withDeploymentStatus(replica1, replica1, replica1)),
				daemonSet: getDaemonSet(argsLevel2, defaultImages(),
					withDaemonSetGeneration(1, 1),
					withDaemonSetStatus(replica1, replica1, replica1)),
				driver: makeFakeDriverInstance(
					withStatus(replica2), // 1 deployment + 1 daemonSet
					withGenerations(1, 1, 1),
					withTrueConditions(conditionAvailable, conditionUpgradeable, conditionPrereqsSatisfied),
					withFalseConditions(conditionDegraded, conditionProgressing)),
			},
		},
		{
			// Deployment has wrong nr. of replicas, modified by user, and gets replaced by the operator.
			name:   "deployment modified by user",
			images: defaultImages(),
			initialObjects: testObjects{
				deployment: getDeployment(argsLevel2, defaultImages(),
					withDeploymentReplicas(2),      // User changed replicas
					withDeploymentGeneration(2, 1), // ... which changed Generation
					withDeploymentStatus(replica1, replica1, replica1)),
				daemonSet: getDaemonSet(argsLevel2, defaultImages(),
					withDaemonSetGeneration(2, 1),
					withDaemonSetStatus(replica1, replica1, replica1)),
				driver: makeFakeDriverInstance(withGenerations(1, 1, 1)), // the operator knows the old generation of the Deployment
			},
			expectedObjects: testObjects{
				deployment: getDeployment(argsLevel2, defaultImages(),
					withDeploymentReplicas(1),      // The operator fixed replica count
					withDeploymentGeneration(3, 1), // ... which bumps generation again
					withDeploymentStatus(replica1, replica1, replica1)),
				daemonSet: getDaemonSet(argsLevel2, defaultImages(),
					withDaemonSetGeneration(3, 1),
					withDaemonSetStatus(replica1, replica1, replica1)),
				driver: makeFakeDriverInstance(
					withStatus(replica2),     // 1 deployment + 1 daemonSet
					withGenerations(3, 3, 1), // now the operator knows generation 1
					withTrueConditions(conditionAvailable, conditionUpgradeable, conditionPrereqsSatisfied, conditionProgressing), // Progressing due to Generation change
					withFalseConditions(conditionDegraded)),
			},
		},
		{
			// Deployment gets degraded for some reason
			name:   "deployment degraded",
			images: defaultImages(),
			initialObjects: testObjects{
				deployment: getDeployment(argsLevel2, defaultImages(),
					withDeploymentGeneration(1, 1),
					withDeploymentStatus(0, 0, 0)), // the Deployment has no pods
				daemonSet: getDaemonSet(argsLevel2, defaultImages(),
					withDaemonSetGeneration(1, 1),
					withDaemonSetStatus(1, 1, 1)), // the DaemonSet has 1 pod
				driver: makeFakeDriverInstance(
					withStatus(replica1),
					withGenerations(1, 1, 1),
					withGeneration(1, 1),
					withTrueConditions(conditionAvailable, conditionUpgradeable, conditionPrereqsSatisfied),
					withFalseConditions(conditionDegraded, conditionProgressing)),
			},
			expectedObjects: testObjects{
				deployment: getDeployment(argsLevel2, defaultImages(),
					withDeploymentGeneration(1, 1),
					withDeploymentStatus(0, 0, 0)), // no change to the Deployment
				daemonSet: getDaemonSet(argsLevel2, defaultImages(),
					withDaemonSetGeneration(1, 1),
					withDaemonSetStatus(1, 1, 1)),
				driver: makeFakeDriverInstance(
					withStatus(replica1), // 0 deployments + 1 daemonSet
					withGenerations(1, 1, 1),
					withGeneration(1, 1),
					withTrueConditions(conditionUpgradeable, conditionPrereqsSatisfied, conditionProgressing), // The operator is Progressing
					withFalseConditions(conditionDegraded, conditionAvailable)),                               // The operator is not Available (controller not running...)
			},
		},
		{
			// Deployment is updating pods
			name:   "update",
			images: defaultImages(),
			initialObjects: testObjects{
				deployment: getDeployment(argsLevel2, defaultImages(),
					withDeploymentGeneration(1, 1),
					withDeploymentStatus(1 /*ready*/, 1 /*available*/, 0 /*updated*/)), // the Deployment is updating 1 pod
				daemonSet: getDaemonSet(argsLevel2, defaultImages(),
					withDaemonSetGeneration(1, 1),
					withDaemonSetStatus(1, 1, 1)), // the DaemonSet has 1 pod
				driver: makeFakeDriverInstance(
					withStatus(replica1),
					withGenerations(1, 1, 1),
					withGeneration(1, 1),
					withTrueConditions(conditionAvailable, conditionUpgradeable, conditionPrereqsSatisfied),
					withFalseConditions(conditionDegraded, conditionProgressing)),
			},
			expectedObjects: testObjects{
				deployment: getDeployment(argsLevel2, defaultImages(),
					withDeploymentGeneration(1, 1),
					withDeploymentStatus(1, 1, 0)), // no change to the Deployment
				daemonSet: getDaemonSet(argsLevel2, defaultImages(),
					withDaemonSetGeneration(1, 1),
					withDaemonSetStatus(1, 1, 1)), // no change to the DaemonSet
				driver: makeFakeDriverInstance(
					withStatus(replica1), // 0 deployments + 1 daemonSet
					withGenerations(1, 1, 1),
					withGeneration(1, 1),
					withTrueConditions(conditionUpgradeable, conditionPrereqsSatisfied, conditionAvailable, conditionProgressing), // The operator is Progressing, but still Available
					withFalseConditions(conditionDegraded)),
			},
		},
		{
			// User changes log level and it's projected into the Deployment and DaemonSet
			name:   "log level change",
			images: defaultImages(),
			initialObjects: testObjects{
				deployment: getDeployment(argsLevel2, defaultImages(),
					withDeploymentGeneration(1, 1),
					withDeploymentStatus(replica1, replica1, replica1)),
				daemonSet: getDaemonSet(argsLevel2, defaultImages(),
					withDaemonSetGeneration(1, 1),
					withDaemonSetStatus(replica1, replica1, replica1)),
				driver: makeFakeDriverInstance(
					withGenerations(1, 1, 1),
					withLogLevel(opv1.Trace), // User changed the log level...
					withGeneration(2, 1)),    //... which caused the Generation to increase
			},
			expectedObjects: testObjects{
				deployment: getDeployment(argsLevel6, defaultImages(), // The operator changed cmdline arguments with a new log level
					withDeploymentGeneration(2, 1), // ... which caused the Generation to increase
					withDeploymentStatus(replica1, replica1, replica1)),
				daemonSet: getDaemonSet(argsLevel6, defaultImages(), // And the same goes for the DaemonSet
					withDaemonSetGeneration(2, 1),
					withDaemonSetStatus(replica1, replica1, replica1)),
				driver: makeFakeDriverInstance(
					withStatus(replica2), // 1 deployment + 1 daemonSet
					withLogLevel(opv1.Trace),
					withGenerations(2, 2, 1),
					withGeneration(2, 2),
					withTrueConditions(conditionAvailable, conditionUpgradeable, conditionPrereqsSatisfied, conditionProgressing), // Progressing due to Generation change
					withFalseConditions(conditionDegraded)),
			},
		},
		{
			// Deployment and DaemonSet update images
			name:   "image change",
			images: defaultImages(),
			initialObjects: testObjects{
				deployment: getDeployment(argsLevel2, oldImages(),
					withDeploymentGeneration(1, 1),
					withDeploymentStatus(replica1, replica1, replica1)),
				daemonSet: getDaemonSet(argsLevel2, oldImages(),
					withDaemonSetGeneration(1, 1),
					withDaemonSetStatus(replica1, replica1, replica1)),
				driver: makeFakeDriverInstance(
					withStatus(replica2), // 1 deployment + 1 daemonSet
					withGenerations(1, 1, 1),
					withTrueConditions(conditionAvailable, conditionUpgradeable, conditionPrereqsSatisfied),
					withFalseConditions(conditionDegraded, conditionProgressing)),
			},
			expectedObjects: testObjects{
				deployment: getDeployment(argsLevel2, defaultImages(),
					withDeploymentGeneration(2, 1),
					withDeploymentStatus(replica1, replica1, replica1)),
				daemonSet: getDaemonSet(argsLevel2, defaultImages(),
					withDaemonSetGeneration(2, 1),
					withDaemonSetStatus(replica1, replica1, replica1)),
				driver: makeFakeDriverInstance(
					withStatus(replica2), // 1 deployment + 1 daemonSet
					withGenerations(2, 2, 1),
					withTrueConditions(conditionAvailable, conditionUpgradeable, conditionPrereqsSatisfied, conditionProgressing),
					withFalseConditions(conditionDegraded)),
			},
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			// Initialize
			ctx := newOperator(test, t)

			// Act
			err := ctx.operator.sync()

			// Assert
			// Check error
			if err != nil && !test.expectErr {
				t.Errorf("sync() returned unexpected error: %v", err)
			}
			if err == nil && test.expectErr {
				t.Error("sync() unexpectedly succeeded when error was expected")
			}

			// Check expectedObjects.deployment
			if test.expectedObjects.deployment != nil {
				deployName := test.expectedObjects.deployment.Name
				actualDeployment, err := ctx.coreClient.AppsV1().Deployments(operandNamespace).Get(context.TODO(), deployName, metav1.GetOptions{})
				if err != nil {
					t.Errorf("Failed to get Deployment %s: %v", deployName, err)
				}
				sanitizeDeployment(actualDeployment)
				sanitizeDeployment(test.expectedObjects.deployment)
				if !equality.Semantic.DeepEqual(test.expectedObjects.deployment, actualDeployment) {
					t.Errorf("Unexpected Deployment %+v content:\n%s", operandName, cmp.Diff(test.expectedObjects.deployment, actualDeployment))
				}
			}

			// Check expectedObjects.daemonSet
			if test.expectedObjects.daemonSet != nil {
				dsName := test.expectedObjects.daemonSet.Name
				actualDaemonSet, err := ctx.coreClient.AppsV1().DaemonSets(operandNamespace).Get(context.TODO(), dsName, metav1.GetOptions{})
				if err != nil {
					t.Errorf("Failed to get DaemonSet %s: %v", operandName, err)
				}
				sanitizeDaemonSet(actualDaemonSet)
				sanitizeDaemonSet(test.expectedObjects.daemonSet)
				if !equality.Semantic.DeepEqual(test.expectedObjects.daemonSet, actualDaemonSet) {
					t.Errorf("Unexpected DaemonSet %+v content:\n%s", operandName, cmp.Diff(test.expectedObjects.daemonSet, actualDaemonSet))
				}
			}

			// Check expectedObjects.driver.Status
			if test.expectedObjects.driver != nil {
				_, actualStatus, _, err := ctx.operatorClient.GetOperatorState()
				if err != nil {
					t.Errorf("Failed to get Driver %s: %v", globalConfigName, err)
				}
				sanitizeInstanceStatus(actualStatus)
				sanitizeInstanceStatus(&test.expectedObjects.driver.Status)
				if !equality.Semantic.DeepEqual(test.expectedObjects.driver.Status, *actualStatus) {
					t.Errorf("Unexpected Driver %+v content:\n%s", operandName, cmp.Diff(test.expectedObjects.driver.Status, *actualStatus))
				}
			}
		})
	}
}

func sanitizeDeployment(deployment *appsv1.Deployment) {
	// nil and empty array are the same
	if len(deployment.Labels) == 0 {
		deployment.Labels = nil
	}
	if len(deployment.Annotations) == 0 {
		deployment.Annotations = nil
	}
	// Remove random annotations set by ApplyDeployment
	delete(deployment.Annotations, specHashAnnotation)
}

func sanitizeDaemonSet(daemonSet *appsv1.DaemonSet) {
	// nil and empty array are the same
	if len(daemonSet.Labels) == 0 {
		daemonSet.Labels = nil
	}
	if len(daemonSet.Annotations) == 0 {
		daemonSet.Annotations = nil
	}
	// Remove random annotations set by ApplyDeployment
	delete(daemonSet.Annotations, specHashAnnotation)
}

func sanitizeInstanceStatus(status *opv1.OperatorStatus) {
	// Remove condition texts
	for i := range status.Conditions {
		status.Conditions[i].LastTransitionTime = metav1.Time{}
		status.Conditions[i].Message = ""
		status.Conditions[i].Reason = ""
	}
	// Sort the conditions by name to have consistent position in the array
	sort.Slice(status.Conditions, func(i, j int) bool {
		return status.Conditions[i].Type < status.Conditions[j].Type
	})
}

func defaultImages() images {
	return images{
		csiDriver:           "quay.io/openshift/origin-test-csi-driver:latest",
		provisioner:         "quay.io/openshift/origin-csi-external-provisioner:latest",
		attacher:            "quay.io/openshift/origin-csi-external-attacher:latest",
		resizer:             "quay.io/openshift/origin-csi-external-resizer:latest",
		snapshotter:         "quay.io/openshift/origin-csi-external-snapshotter:latest",
		nodeDriverRegistrar: "quay.io/openshift/origin-csi-node-driver-registrar:latest",
		livenessProbe:       "quay.io/openshift/origin-csi-livenessprobe:latest",
	}
}

func oldImages() images {
	return images{
		csiDriver:           "quay.io/openshift/origin-test-csi-driver:old",
		provisioner:         "quay.io/openshift/origin-csi-external-provisioner:old",
		attacher:            "quay.io/openshift/origin-csi-external-attacher:old",
		resizer:             "quay.io/openshift/origin-csi-external-resizer:old",
		snapshotter:         "quay.io/openshift/origin-csi-external-snapshotter:old",
		nodeDriverRegistrar: "quay.io/openshift/origin-csi-node-driver-registrar:old",
		livenessProbe:       "quay.io/openshift/origin-csi-livenessprobe:old",
	}
}

type fakeSharedIndexInformer struct {
	cache.SharedIndexInformer
}

func (fakeSharedIndexInformer) AddEventHandler(handler cache.ResourceEventHandler) {
}

func (fakeSharedIndexInformer) AddEventHandlerWithResyncPeriod(handler cache.ResourceEventHandler, resyncPeriod time.Duration) {
}

func (fakeSharedIndexInformer) HasSynced() bool {
	return true
}

// fakeInstance is a fake CSI driver instance that also fullfils the OperatorClient interface
type fakeDriverInstance struct {
	metav1.ObjectMeta
	Spec   opv1.OperatorSpec
	Status opv1.OperatorStatus
}

func (f *fakeDriverInstance) Informer() cache.SharedIndexInformer {
	return &fakeSharedIndexInformer{}
}

func (f *fakeDriverInstance) GetObjectMeta() (*metav1.ObjectMeta, error) {
	return &f.ObjectMeta, nil
}

func (f *fakeDriverInstance) GetOperatorState() (*opv1.OperatorSpec, *opv1.OperatorStatus, string, error) {
	return &f.Spec, &f.Status, "", nil
}

func (f *fakeDriverInstance) UpdateOperatorSpec(string, *opv1.OperatorSpec) (spec *opv1.OperatorSpec, resourceVersion string, err error) {
	panic("missing")
}

func (f *fakeDriverInstance) UpdateOperatorStatus(resourceVersion string, s *opv1.OperatorStatus) (status *opv1.OperatorStatus, err error) {
	if f.ObjectMeta.ResourceVersion != resourceVersion {
		return nil, errors.NewConflict(schema.GroupResource{Group: opv1.GroupName, Resource: "TestOperatorConfig"}, "instance", fmt.Errorf("invalid resourceVersion"))
	}
	rv, err := strconv.Atoi(resourceVersion)
	if err != nil {
		return nil, err
	}
	f.ObjectMeta.ResourceVersion = strconv.Itoa(rv + 1)
	f.Status = *s
	return &f.Status, nil
}

func makeFakeManifest(s string) []byte {
	if s == "deployment" {
		return []byte(`
kind: Deployment
apiVersion: apps/v1
metadata:
  name: test-csi-driver-controller
  namespace: openshift-test-csi-driver
spec:
  selector:
    matchLabels:
      app: test-csi-driver-controller
  serviceName: test-csi-driver-controller
  replicas: 1
  template:
    metadata:
      labels:
        app: test-csi-driver-controller
    spec:
      containers:
        - name: csi-driver
          image: quay.io/openshift/origin-test-csi-driver:latest
          args:
            - --endpoint=$(CSI_ENDPOINT)
            - --logtostderr
            - --v=5
          env:
            - name: CSI_ENDPOINT
              value: unix:///var/lib/csi/sockets/pluginproxy/csi.sock
          ports:
            - name: healthz
              containerPort: 19808
              protocol: TCP
          volumeMounts:
            - name: socket-dir
              mountPath: /var/lib/csi/sockets/pluginproxy/
        - name: csi-provisioner
          image: quay.io/openshift/origin-csi-external-provisioner:latest
          args:
            - --provisioner=test.csi.openshift.io
            - --csi-address=$(ADDRESS)
            - --feature-gates=Topology=true
            - --v=5
          env:
            - name: ADDRESS
              value: /var/lib/csi/sockets/pluginproxy/csi.sock
          volumeMounts:
            - name: socket-dir
              mountPath: /var/lib/csi/sockets/pluginproxy/
        - name: csi-attacher
          image: quay.io/openshift/origin-csi-external-attacher:latest
          args:
            - --csi-address=$(ADDRESS)
            - --v=5
          env:
            - name: ADDRESS
              value: /var/lib/csi/sockets/pluginproxy/csi.sock
          volumeMounts:
            - name: socket-dir
              mountPath: /var/lib/csi/sockets/pluginproxy/
        - name: csi-resizer
          image: quay.io/openshift/origin-csi-external-resizer:latest
          args:
            - --csi-address=$(ADDRESS)
            - --v=5
          env:
            - name: ADDRESS
              value: /var/lib/csi/sockets/pluginproxy/csi.sock
          volumeMounts:
            - name: socket-dir
              mountPath: /var/lib/csi/sockets/pluginproxy/
        - name: csi-snapshotter
          image: quay.io/openshift/origin-csi-external-snapshotter:latest
          args:
            - --csi-address=$(ADDRESS)
            - --v=5
          env:
          - name: ADDRESS
            value: /var/lib/csi/sockets/pluginproxy/csi.sock
          volumeMounts:
          - mountPath: /var/lib/csi/sockets/pluginproxy/
            name: socket-dir
      volumes:
        - name: socket-dir
          emptyDir: {}
`)
	}

	if s == "daemonSet" {
		return []byte(`
kind: DaemonSet
apiVersion: apps/v1
metadata:
  name: test-csi-driver-node
  namespace: openshift-test-csi-driver
spec:
  selector:
    matchLabels:
      app: test-csi-driver-node
  template:
    metadata:
      labels:
        app: test-csi-driver-node
    spec:
      containers:
        - name: csi-driver
          image: quay.io/openshift/origin-test-csi-driver:latest
          args:
            - --endpoint=$(CSI_ENDPOINT)
            - --logtostderr
            - --v=5
          env:
            - name: CSI_ENDPOINT
              value: unix:/csi/csi.sock
          volumeMounts:
            - name: kubelet-dir
              mountPath: /var/lib/kubelet
              mountPropagation: "Bidirectional"
            - name: plugin-dir
              mountPath: /csi
            - name: device-dir
              mountPath: /dev
          ports:
            - name: healthz
              containerPort: 9808
              protocol: TCP
          livenessProbe:
            httpGet:
              path: /healthz
              port: healthz
            initialDelaySeconds: 10
            timeoutSeconds: 3
            periodSeconds: 10
            failureThreshold: 5
        - name: csi-node-driver-registrar
          image: quay.io/openshift/origin-csi-node-driver-registrar:latest
          args:
            - --csi-address=$(ADDRESS)
            - --kubelet-registration-path=$(DRIVER_REG_SOCK_PATH)
            - --v=5
          env:
            - name: ADDRESS
              value: /csi/csi.sock
            - name: DRIVER_REG_SOCK_PATH
              value: /var/lib/kubelet/plugins/test.csi.openshift.io/csi.sock
          volumeMounts:
            - name: plugin-dir
              mountPath: /csi
            - name: registration-dir
              mountPath: /registration
        - name: csi-liveness-probe
          image: quay.io/openshift/origin-csi-livenessprobe:latest
          args:
            - --csi-address=/csi/csi.sock
            - --probe-timeout=3s
          volumeMounts:
            - name: plugin-dir
              mountPath: /csi
      volumes:
        - name: kubelet-dir
          hostPath:
            path: /var/lib/kubelet
            type: Directory
        - name: plugin-dir
          hostPath:
            path: /var/lib/kubelet/plugins/test.csi.openshift.io/
            type: DirectoryOrCreate
        - name: registration-dir
          hostPath:
            path: /var/lib/kubelet/plugins_registry/
            type: Directory
        - name: device-dir
          hostPath:
            path: /dev
            type: Directory
`)
	}

	return nil
}
