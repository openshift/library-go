package csidrivercontrollerservicecontroller

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	coreinformers "k8s.io/client-go/informers"
	fakecore "k8s.io/client-go/kubernetes/fake"
	core "k8s.io/client-go/testing"

	"github.com/google/go-cmp/cmp"
	configv1 "github.com/openshift/api/config/v1"
	opv1 "github.com/openshift/api/operator/v1"
	fakeconfig "github.com/openshift/client-go/config/clientset/versioned/fake"
	configinformers "github.com/openshift/client-go/config/informers/externalversions"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

const (
	controllerName   = "TestCSIDriverControllerServiceController"
	operandName      = "test-csi-driver"
	operandNamespace = "openshift-test-csi-driver"

	csiDriverContainerName     = "csi-driver"
	provisionerContainerName   = "csi-provisioner"
	attacherContainerName      = "csi-attacher"
	resizerContainerName       = "csi-resizer"
	snapshotterContainerName   = "csi-snapshotter"
	livenessProbeContainerName = "csi-liveness-probe"

	// From github.com/openshift/library-go/pkg/operator/resource/resourceapply/apps.go
	specHashAnnotation = "operator.openshift.io/spec-hash"
	defaultClusterID   = "ID1234"
)

var (
	conditionAvailable   = controllerName + opv1.OperatorStatusTypeAvailable
	conditionProgressing = controllerName + opv1.OperatorStatusTypeProgressing
)

type images struct {
	csiDriver     string
	attacher      string
	provisioner   string
	resizer       string
	snapshotter   string
	livenessProbe string
}

type testCase struct {
	name            string
	images          images
	initialObjects  testObjects
	expectedObjects testObjects
	expectErr       bool
}

type testObjects struct {
	deployment *appsv1.Deployment
	driver     *fakeDriverInstance
}

type testContext struct {
	controller     factory.Controller
	operatorClient v1helpers.OperatorClient
	coreClient     *fakecore.Clientset
	coreInformers  coreinformers.SharedInformerFactory
}

func newTestContext(test testCase, t *testing.T) *testContext {
	// Add deployment to informer
	var initialObjects []runtime.Object
	if test.initialObjects.deployment != nil {
		resourceapply.SetSpecHashAnnotation(&test.initialObjects.deployment.ObjectMeta, test.initialObjects.deployment.Spec)
		initialObjects = append(initialObjects, test.initialObjects.deployment)
	}

	coreClient := fakecore.NewSimpleClientset(initialObjects...)
	coreInformerFactory := coreinformers.NewSharedInformerFactory(coreClient, 0 /*no resync */)

	// Fill the informer
	if test.initialObjects.deployment != nil {
		coreInformerFactory.Apps().V1().Deployments().Informer().GetIndexer().Add(test.initialObjects.deployment)
	}

	// Add global reactors
	addGenerationReactor(coreClient)

	// Add a fake Infrastructure object to informer. This is not
	// optional because it is always present in the cluster.
	initialInfras := []runtime.Object{makeInfra()}
	configClient := fakeconfig.NewSimpleClientset(initialInfras...)
	configInformerFactory := configinformers.NewSharedInformerFactory(configClient, 0)
	configInformerFactory.Config().V1().Infrastructures().Informer().GetIndexer().Add(initialInfras[0])

	// fakeDriverInstance also fulfils the OperatorClient interface
	fakeOperatorClient := v1helpers.NewFakeOperatorClient(
		&test.initialObjects.driver.Spec,
		&test.initialObjects.driver.Status,
		nil, /*triggerErr func*/
	)
	controller := NewCSIDriverControllerServiceController(
		controllerName,
		makeFakeManifest(),
		fakeOperatorClient,
		coreClient,
		coreInformerFactory.Apps().V1().Deployments(),
		configInformerFactory,
		events.NewInMemoryRecorder(operandName),
	)

	// Pretend env vars are set
	// TODO: inject these in New() instead
	os.Setenv(driverImageEnvName, test.images.csiDriver)
	os.Setenv(provisionerImageEnvName, test.images.provisioner)
	os.Setenv(attacherImageEnvName, test.images.attacher)
	os.Setenv(snapshotterImageEnvName, test.images.snapshotter)
	os.Setenv(resizerImageEnvName, test.images.resizer)
	os.Setenv(livenessProbeImageEnvName, test.images.livenessProbe)

	return &testContext{
		controller:     controller,
		operatorClient: fakeOperatorClient,
		coreClient:     coreClient,
		coreInformers:  coreInformerFactory,
	}
}

// Drivers

type driverModifier func(*fakeDriverInstance) *fakeDriverInstance

func makeFakeDriverInstance(modifiers ...driverModifier) *fakeDriverInstance {
	instance := &fakeDriverInstance{
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

func withGenerations(deployment int64) driverModifier {
	return func(i *fakeDriverInstance) *fakeDriverInstance {
		i.Status.Generations = []opv1.GenerationStatus{
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

func getIndex(containers []v1.Container, name string) int {
	for i := range containers {
		if containers[i].Name == name {
			return i
		}
	}
	return -1
}

// Deployments

type deploymentModifier func(*appsv1.Deployment) *appsv1.Deployment

func makeDeployment(clusterID string, logLevel int, images images, modifiers ...deploymentModifier) *appsv1.Deployment {
	manifest := makeFakeManifest()
	dep := resourceread.ReadDeploymentV1OrDie(manifest)

	// Replace the placeholders in the manifest (, ${DRIVER_IMAGE}, ${LOG_LEVEL})
	containers := dep.Spec.Template.Spec.Containers
	if images.csiDriver != "" {
		if idx := getIndex(containers, csiDriverContainerName); idx > -1 {
			containers[idx].Image = images.csiDriver
			for j, arg := range containers[idx].Args {
				if strings.HasPrefix(arg, "--k8s-tag-cluster-id=") {
					dep.Spec.Template.Spec.Containers[idx].Args[j] = fmt.Sprintf("--k8s-tag-cluster-id=%s", clusterID)
				}
			}
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

	for i, container := range dep.Spec.Template.Spec.Containers {
		for j, arg := range container.Args {
			if strings.HasPrefix(arg, "--v=") {
				dep.Spec.Template.Spec.Containers[i].Args[j] = fmt.Sprintf("--v=%d", logLevel)
			}
		}
	}

	var one int32 = 1
	dep.Spec.Replicas = &one

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

// Infrastructure
func makeInfra() *configv1.Infrastructure {
	return &configv1.Infrastructure{
		ObjectMeta: metav1.ObjectMeta{
			Name:      infraConfigName,
			Namespace: v1.NamespaceAll,
		},
		Status: configv1.InfrastructureStatus{
			InfrastructureName: defaultClusterID,
			Platform:           configv1.AWSPlatformType,
			PlatformStatus: &configv1.PlatformStatus{
				AWS: &configv1.AWSPlatformStatus{},
			},
		},
	}
}

// This reactor is always enabled and bumps Deployment generation when it gets updated.
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
			// Only CR exists, everything else is created
			name:   "initial sync",
			images: defaultImages(),
			initialObjects: testObjects{
				driver: makeFakeDriverInstance(),
			},
			expectedObjects: testObjects{
				deployment: makeDeployment(
					defaultClusterID,
					argsLevel2,
					defaultImages(),
					withDeploymentGeneration(1, 0)),
				driver: makeFakeDriverInstance(
					// withStatus(replica0),
					withGenerations(1),
					withTrueConditions(conditionProgressing),
					withFalseConditions(conditionAvailable)), // Degraded is set later on
			},
		},
		{
			// Deployment is fully deployed and its status is synced to CR
			name:   "deployment fully deployed",
			images: defaultImages(),
			initialObjects: testObjects{
				deployment: makeDeployment(
					defaultClusterID,
					argsLevel2,
					defaultImages(),
					withDeploymentGeneration(1, 1),
					withDeploymentStatus(replica1, replica1, replica1)),
				driver: makeFakeDriverInstance(withGenerations(1)),
			},
			expectedObjects: testObjects{
				deployment: makeDeployment(
					defaultClusterID,
					argsLevel2,
					defaultImages(),
					withDeploymentGeneration(1, 1),
					withDeploymentStatus(replica1, replica1, replica1)),
				driver: makeFakeDriverInstance(
					// withStatus(replica1),
					withGenerations(1),
					withTrueConditions(conditionAvailable),
					withFalseConditions(conditionProgressing)),
			},
		},
		{
			// Deployment is fully deployed and its status is synced to CR
			name:   "deployment fully deployed",
			images: defaultImages(),
			initialObjects: testObjects{
				deployment: makeDeployment(
					defaultClusterID,
					argsLevel2,
					defaultImages(),
					withDeploymentGeneration(1, 1),
					withDeploymentStatus(replica1, replica1, replica1)),
				driver: makeFakeDriverInstance(withGenerations(1)),
			},
			expectedObjects: testObjects{
				deployment: makeDeployment(
					defaultClusterID,
					argsLevel2,
					defaultImages(),
					withDeploymentGeneration(1, 1),
					withDeploymentStatus(replica1, replica1, replica1)),
				driver: makeFakeDriverInstance(
					// withStatus(replica1),
					withGenerations(1),
					withTrueConditions(conditionAvailable),
					withFalseConditions(conditionProgressing)),
			},
		},
		{
			// Deployment has wrong nr. of replicas, modified by user, and gets replaced by the operator.
			name:   "deployment modified by user",
			images: defaultImages(),
			initialObjects: testObjects{
				deployment: makeDeployment(
					defaultClusterID,
					argsLevel2,
					defaultImages(),
					withDeploymentReplicas(2),      // User changed replicas
					withDeploymentGeneration(2, 1), // ... which changed Generation
					withDeploymentStatus(replica1, replica1, replica1)),
				driver: makeFakeDriverInstance(withGenerations(1)), // the operator knows the old generation of the Deployment
			},
			expectedObjects: testObjects{
				deployment: makeDeployment(
					defaultClusterID,
					argsLevel2,
					defaultImages(),
					withDeploymentReplicas(1),      // The operator fixed replica count
					withDeploymentGeneration(3, 1), // ... which bumps generation again
					withDeploymentStatus(replica1, replica1, replica1)),
				driver: makeFakeDriverInstance(
					// withStatus(replica1),
					withGenerations(3), // now the operator knows generation 1
					withTrueConditions(conditionAvailable, conditionProgressing), // Progressing due to Generation change
				),
			},
		},
		{
			// Deployment gets degraded for some reason
			name:   "deployment degraded",
			images: defaultImages(),
			initialObjects: testObjects{
				deployment: makeDeployment(
					defaultClusterID,
					argsLevel2,
					defaultImages(),
					withDeploymentGeneration(1, 1),
					withDeploymentStatus(0, 0, 0)), // the Deployment has no pods
				driver: makeFakeDriverInstance(
					// withStatus(replica1),
					withGenerations(1),
					withGeneration(1, 1),
					withTrueConditions(conditionAvailable),
					withFalseConditions(conditionProgressing)),
			},
			expectedObjects: testObjects{
				deployment: makeDeployment(
					defaultClusterID,
					argsLevel2,
					defaultImages(),
					withDeploymentGeneration(1, 1),
					withDeploymentStatus(0, 0, 0)), // no change to the Deployment
				driver: makeFakeDriverInstance(
					// withStatus(replica0),
					withGenerations(1),
					withGeneration(1, 1),
					withTrueConditions(conditionProgressing), // The operator is Progressing
					withFalseConditions(conditionAvailable)), // The operator is not Available (controller not running...)
			},
		},
		{
			// Deployment is updating pods
			name:   "update",
			images: defaultImages(),
			initialObjects: testObjects{
				deployment: makeDeployment(
					defaultClusterID,
					argsLevel2,
					defaultImages(),
					withDeploymentGeneration(1, 1),
					withDeploymentStatus(1 /*ready*/, 1 /*available*/, 0 /*updated*/)), // the Deployment is updating 1 pod
				driver: makeFakeDriverInstance(
					// withStatus(replica1),
					withGenerations(1),
					withGeneration(1, 1),
					withTrueConditions(conditionAvailable),
					withFalseConditions(conditionProgressing)),
			},
			expectedObjects: testObjects{
				deployment: makeDeployment(
					defaultClusterID,
					argsLevel2,
					defaultImages(),
					withDeploymentGeneration(1, 1),
					withDeploymentStatus(1, 1, 0)), // no change to the Deployment
				driver: makeFakeDriverInstance(
					// withStatus(replica0),
					withGenerations(1),
					withGeneration(1, 1),
					withTrueConditions(conditionAvailable, conditionProgressing)), // The operator is Progressing, but still Available
			},
		},
		{
			// User changes log level and it's projected into the Deployment
			name:   "log level change",
			images: defaultImages(),
			initialObjects: testObjects{
				deployment: makeDeployment(
					defaultClusterID,
					argsLevel2,
					defaultImages(),
					withDeploymentGeneration(1, 1),
					withDeploymentStatus(replica1, replica1, replica1)),
				driver: makeFakeDriverInstance(
					withGenerations(1),
					withLogLevel(opv1.Trace), // User changed the log level...
					withGeneration(2, 1)),    //... which caused the Generation to increase
			},
			expectedObjects: testObjects{
				deployment: makeDeployment(
					defaultClusterID,
					argsLevel6, // The operator changed cmdline arguments with a new log level
					defaultImages(),
					withDeploymentGeneration(2, 1), // ... which caused the Generation to increase
					withDeploymentStatus(replica1, replica1, replica1)),
				driver: makeFakeDriverInstance(
					// withStatus(replica1),
					withLogLevel(opv1.Trace),
					withGenerations(2),
					withGeneration(2, 1), // TODO: should I increase the observed generation?
					withTrueConditions(conditionAvailable, conditionProgressing)), // Progressing due to Generation change
			},
		},
		{
			// Deployment updates images
			name:   "image change",
			images: defaultImages(),
			initialObjects: testObjects{
				deployment: makeDeployment(
					defaultClusterID,
					argsLevel2,
					oldImages(),
					withDeploymentGeneration(1, 1),
					withDeploymentStatus(replica1, replica1, replica1)),
				driver: makeFakeDriverInstance(
					// withStatus(replica1),k
					withGenerations(1),
					withTrueConditions(conditionAvailable),
					withFalseConditions(conditionProgressing)),
			},
			expectedObjects: testObjects{
				deployment: makeDeployment(
					defaultClusterID,
					argsLevel2,
					defaultImages(),
					withDeploymentGeneration(2, 1),
					withDeploymentStatus(replica1, replica1, replica1)),
				driver: makeFakeDriverInstance(
					// withStatus(replica1),
					withGenerations(2),
					withTrueConditions(conditionAvailable, conditionProgressing)),
			},
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			// Initialize
			ctx := newTestContext(test, t)

			// Act
			err := ctx.controller.Sync(context.TODO(), factory.NewSyncContext(controllerName, events.NewInMemoryRecorder("test-csi-driver")))

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

			// Check expectedObjects.driver.Status
			if test.expectedObjects.driver != nil {
				_, actualStatus, _, err := ctx.operatorClient.GetOperatorState()
				if err != nil {
					t.Errorf("Failed to get Driver: %v", err)
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
		csiDriver:     "quay.io/openshift/origin-test-csi-driver:latest",
		provisioner:   "quay.io/openshift/origin-csi-external-provisioner:latest",
		attacher:      "quay.io/openshift/origin-csi-external-attacher:latest",
		resizer:       "quay.io/openshift/origin-csi-external-resizer:latest",
		snapshotter:   "quay.io/openshift/origin-csi-external-snapshotter:latest",
		livenessProbe: "quay.io/openshift/origin-csi-livenessprobe:latest",
	}
}

func oldImages() images {
	return images{
		csiDriver:     "quay.io/openshift/origin-test-csi-driver:old",
		provisioner:   "quay.io/openshift/origin-csi-external-provisioner:old",
		attacher:      "quay.io/openshift/origin-csi-external-attacher:old",
		resizer:       "quay.io/openshift/origin-csi-external-resizer:old",
		snapshotter:   "quay.io/openshift/origin-csi-external-snapshotter:old",
		livenessProbe: "quay.io/openshift/origin-csi-livenessprobe:old",
	}
}

// fakeInstance is a fake CSI driver instance that also fullfils the OperatorClient interface
type fakeDriverInstance struct {
	metav1.ObjectMeta
	Spec   opv1.OperatorSpec
	Status opv1.OperatorStatus
}

func makeFakeManifest() []byte {
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
          image: ${DRIVER_IMAGE}
          args:
            - --endpoint=$(CSI_ENDPOINT)
            - --k8s-tag-cluster-id=${CLUSTER_ID}
            - --logtostderr
            - --v=${LOG_LEVEL}
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
          image: ${PROVISIONER_IMAGE}
          args:
            - --provisioner=test.csi.openshift.io
            - --csi-address=$(ADDRESS)
            - --feature-gates=Topology=true
            - --v=${LOG_LEVEL}
          env:
            - name: ADDRESS
              value: /var/lib/csi/sockets/pluginproxy/csi.sock
          volumeMounts:
            - name: socket-dir
              mountPath: /var/lib/csi/sockets/pluginproxy/
        - name: csi-attacher
          image: ${ATTACHER_IMAGE}
          args:
            - --csi-address=$(ADDRESS)
            - --v=${LOG_LEVEL}
          env:
            - name: ADDRESS
              value: /var/lib/csi/sockets/pluginproxy/csi.sock
          volumeMounts:
            - name: socket-dir
              mountPath: /var/lib/csi/sockets/pluginproxy/
        - name: csi-resizer
          image: ${RESIZER_IMAGE}
          args:
            - --csi-address=$(ADDRESS)
            - --v=${LOG_LEVEL}
          env:
            - name: ADDRESS
              value: /var/lib/csi/sockets/pluginproxy/csi.sock
          volumeMounts:
            - name: socket-dir
              mountPath: /var/lib/csi/sockets/pluginproxy/
        - name: csi-snapshotter
          image: ${SNAPSHOTTER_IMAGE}
          args:
            - --csi-address=$(ADDRESS)
            - --v=${LOG_LEVEL}
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
