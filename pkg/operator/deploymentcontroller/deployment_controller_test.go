package deploymentcontroller

import (
	"context"
	"os"
	"sort"
	"time"

	"testing"

	"github.com/google/go-cmp/cmp"
	configv1 "github.com/openshift/api/config/v1"
	opv1 "github.com/openshift/api/operator/v1"
	fakeconfig "github.com/openshift/client-go/config/clientset/versioned/fake"
	configinformers "github.com/openshift/client-go/config/informers/externalversions"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/management"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	coreinformers "k8s.io/client-go/informers"
	fakecore "k8s.io/client-go/kubernetes/fake"
	core "k8s.io/client-go/testing"
	clocktesting "k8s.io/utils/clock/testing"
)

const (
	infraConfigName  = "cluster"
	deploymentName   = "dummy-deployment"
	defaultClusterID = "ID1234"
	controllerName   = "TestDeploymentController"
	operandName      = "dummy-controller"
	operandNamespace = "openshift-dummy-test-deployment"
	// From github.com/openshift/library-go/pkg/operator/resource/resourceapply/apps.go
	specHashAnnotation = "operator.openshift.io/spec-hash"
	finalizerName      = "test.operator.openshift.io/" + controllerName
)

var (
	conditionAvailable   = controllerName + opv1.OperatorStatusTypeAvailable
	conditionProgressing = controllerName + opv1.OperatorStatusTypeProgressing
)

type testCase struct {
	name            string
	removable       bool
	initialObjects  testObjects
	expectedObjects testObjects
	expectErr       bool
}

type testObjects struct {
	deployment *appsv1.Deployment
	operator   *fakeOperatorInstance
}

type testContext struct {
	controller     factory.Controller
	operatorClient v1helpers.OperatorClient
	coreClient     *fakecore.Clientset
	coreInformers  coreinformers.SharedInformerFactory
}

// fakeOperatorInstance is a fake Operator instance that  fullfils the OperatorClient interface.
type fakeOperatorInstance struct {
	metav1.ObjectMeta
	Spec   opv1.OperatorSpec
	Status opv1.OperatorStatus
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

func makeFakeManifest() []byte {
	return []byte(`
kind: Deployment
apiVersion: apps/v1
metadata:
  name: dummy-deployment
  namespace: openshift-dummy-test-deployment
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
      nodeSelector:
        node-role.kubernetes.io/master: ""
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
            - --http-endpoint=localhost:8202
            - --v=${LOG_LEVEL}
          env:
            - name: ADDRESS
              value: /var/lib/csi/sockets/pluginproxy/csi.sock
          volumeMounts:
            - name: socket-dir
              mountPath: /var/lib/csi/sockets/pluginproxy/
        # In reality, each sidecar needs its own kube-rbac-proxy. Using just one for the unit tests.
        - name: provisioner-kube-rbac-proxy
          args:
          - --secure-listen-address=0.0.0.0:9202
          - --upstream=http://127.0.0.1:8202/
          - --tls-cert-file=/etc/tls/private/tls.crt
          - --tls-private-key-file=/etc/tls/private/tls.key
          - --logtostderr=true
          image: ${KUBE_RBAC_PROXY_IMAGE}
          imagePullPolicy: IfNotPresent
          ports:
          - containerPort: 9202
            name: provisioner-m
            protocol: TCP
          resources:
            requests:
              memory: 20Mi
              cpu: 10m
          volumeMounts:
          - mountPath: /etc/tls/private
            name: metrics-serving-cert
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
        - name: metrics-serving-cert
          secret:
            secretName: gcp-pd-csi-driver-controller-metrics-serving-cert
`)
}

type operatorModifier func(instance *fakeOperatorInstance) *fakeOperatorInstance

func makeFakeOperatorInstance(modifiers ...operatorModifier) *fakeOperatorInstance {
	instance := &fakeOperatorInstance{
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

func TestDeploymentCreation(t *testing.T) {
	// Initialize
	coreClient := fakecore.NewSimpleClientset()
	coreInformerFactory := coreinformers.NewSharedInformerFactory(coreClient, 0 /*no resync */)
	initialInfras := []runtime.Object{makeInfra()}
	configClient := fakeconfig.NewSimpleClientset(initialInfras...)
	configInformerFactory := configinformers.NewSharedInformerFactory(configClient, 0)
	configInformer := configInformerFactory.Config().V1().Infrastructures().Informer()
	configInformer.GetIndexer().Add(initialInfras[0])
	driverInstance := makeFakeOperatorInstance()
	fakeOperatorClient := v1helpers.NewFakeOperatorClientWithObjectMeta(&driverInstance.ObjectMeta, &driverInstance.Spec, &driverInstance.Status, nil /*triggerErr func*/)
	var optionalInformers []factory.Informer
	var optionalManifestHookFuncs []ManifestHookFunc
	optionalInformers = append(optionalInformers, configInformer)
	controller := NewDeploymentController(
		controllerName,
		makeFakeManifest(),
		events.NewInMemoryRecorder(operandName, clocktesting.NewFakePassiveClock(time.Now())),
		fakeOperatorClient,
		coreClient,
		coreInformerFactory.Apps().V1().Deployments(),
		optionalInformers,
		optionalManifestHookFuncs, // optional manifest hooks no optional deployment hooks
	)

	// Act
	err := controller.Sync(context.TODO(), factory.NewSyncContext(controllerName, events.NewInMemoryRecorder("dummy-controller", clocktesting.NewFakePassiveClock(time.Now()))))
	if err != nil {
		t.Fatalf("sync() returned unexpected error: %v", err)
	}

	// Assert
	actualDeployment, err := coreClient.AppsV1().Deployments(operandNamespace).Get(context.TODO(), deploymentName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Failed to get Deployment %s: %v", deploymentName, err)
	}

	// Deployment should have the annotation specified in the hook function. We should expect a spec-hash for the deployment
	// since it got created from a manifest
	if _, ok := actualDeployment.ObjectMeta.Annotations[specHashAnnotation]; !ok {
		t.Fatalf("expected deployment created from manifest to have %s annotation", specHashAnnotation)
	}
}

func withGenerations(deployment int64) operatorModifier {
	return func(i *fakeOperatorInstance) *fakeOperatorInstance {
		i.Status.Generations = []opv1.GenerationStatus{
			{
				Group:          appsv1.GroupName,
				LastGeneration: deployment,
				Name:           deploymentName,
				Namespace:      operandNamespace,
				Resource:       "deployments",
			},
		}
		return i
	}
}

func withTrueConditions(conditions ...string) operatorModifier {
	return func(i *fakeOperatorInstance) *fakeOperatorInstance {
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

func withDeploymentStatus(readyReplicas, availableReplicas, updatedReplicas int32) deploymentModifier {
	return func(instance *appsv1.Deployment) *appsv1.Deployment {
		instance.Status.ReadyReplicas = readyReplicas
		instance.Status.AvailableReplicas = availableReplicas
		instance.Status.UpdatedReplicas = updatedReplicas
		return instance
	}
}

func withFalseConditions(conditions ...string) operatorModifier {
	return func(i *fakeOperatorInstance) *fakeOperatorInstance {
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

func withFinalizers(finalizers ...string) operatorModifier {
	return func(i *fakeOperatorInstance) *fakeOperatorInstance {
		i.Finalizers = finalizers
		return i
	}
}

func withDeletionTimestamp() operatorModifier {
	return func(i *fakeOperatorInstance) *fakeOperatorInstance {
		// Use a constant time to get ObjectMeta comparison right.
		i.DeletionTimestamp = &metav1.Time{Time: time.Unix(0, 0)}
		return i
	}
}

func withStateRemoved() operatorModifier {
	return func(i *fakeOperatorInstance) *fakeOperatorInstance {
		i.Spec.ManagementState = opv1.Removed
		return i
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
	configInformer := configInformerFactory.Config().V1().Infrastructures().Informer()
	configInformer.GetIndexer().Add(initialInfras[0])

	// fakeDriverInstance also fulfils the OperatorClient interface
	fakeOperatorClient := v1helpers.NewFakeOperatorClientWithObjectMeta(
		&test.initialObjects.operator.ObjectMeta,
		&test.initialObjects.operator.Spec,
		&test.initialObjects.operator.Status,
		nil, /*triggerErr func*/
	)
	optionalInformers := []factory.Informer{configInformer}
	var optionalManifestHookFuncs []ManifestHookFunc
	controller := NewDeploymentController(
		controllerName,
		makeFakeManifest(),
		events.NewInMemoryRecorder(operandName, clocktesting.NewFakePassiveClock(time.Now())),
		fakeOperatorClient,
		coreClient,
		coreInformerFactory.Apps().V1().Deployments(),
		optionalInformers,
		optionalManifestHookFuncs,
	)

	return &testContext{
		controller:     controller,
		operatorClient: fakeOperatorClient,
		coreClient:     coreClient,
		coreInformers:  coreInformerFactory,
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

func sanitizeObjectMeta(meta *metav1.ObjectMeta) {
	// Treat empty array as nil for easier comparison.
	if len(meta.Finalizers) == 0 {
		meta.Finalizers = nil
	}
}

func TestSync(t *testing.T) {
	const replica0 = 0
	const replica1 = 1
	testCases := []testCase{
		{
			// Finalizer is added to removable CR
			// (and deployment is created)
			name:      "add finalizer",
			removable: true,
			initialObjects: testObjects{
				operator: makeFakeOperatorInstance(),
			},
			expectedObjects: testObjects{
				deployment: makeDeployment(
					withDeploymentGeneration(1, 0)),
				operator: makeFakeOperatorInstance(
					withGenerations(1),
					withTrueConditions(conditionProgressing),
					withFalseConditions(conditionAvailable),
					withFinalizers(finalizerName),
				),
			},
		},
		{
			// Deployment and finalizer are deleted on DeletionTimestamp
			name:      "CR removed",
			removable: true,
			initialObjects: testObjects{
				deployment: makeDeployment(
					withDeploymentGeneration(1, 1),
					withDeploymentStatus(replica1, replica1, replica1)),
				operator: makeFakeOperatorInstance(
					withGenerations(1),
					withFinalizers(finalizerName),
					withDeletionTimestamp()),
			},
			expectedObjects: testObjects{
				operator: makeFakeOperatorInstance(
					withGenerations(1),
					// finalizer is removed,
					withDeletionTimestamp()),
			},
		},
		{
			// Deployment and finalizer are deleted if ManagementState is Removed
			name:      "ManagementState Removed",
			removable: true,
			initialObjects: testObjects{
				deployment: makeDeployment(
					withDeploymentGeneration(1, 1),
					withDeploymentStatus(replica1, replica1, replica1)),
				operator: makeFakeOperatorInstance(
					withGenerations(1),
					withFinalizers(finalizerName),
					withStateRemoved()),
			},
			expectedObjects: testObjects{
				operator: makeFakeOperatorInstance(
					withGenerations(1)),
			},
		},
		{
			// Only CR exists, everything else is created
			name: "initial sync",
			initialObjects: testObjects{
				operator: makeFakeOperatorInstance(),
			},
			expectedObjects: testObjects{
				deployment: makeDeployment(
					withDeploymentGeneration(1, 0)),
				operator: makeFakeOperatorInstance(
					// withStatus(replica0),
					withGenerations(1),
					withTrueConditions(conditionProgressing),
					withFalseConditions(conditionAvailable)), // Degraded is set later on
			},
		},
		{
			// Deployment is fully deployed and its status is synced to CR
			name: "deployment fully deployed",
			initialObjects: testObjects{
				deployment: makeDeployment(
					withDeploymentGeneration(1, 1),
					withDeploymentStatus(replica1, replica1, replica1),
					withDeploymentConditions(appsv1.DeploymentProgressing, "NewReplicaSetAvailable", corev1.ConditionTrue)), // Deployment is fully deployed
				operator: makeFakeOperatorInstance(withGenerations(1)),
			},
			expectedObjects: testObjects{
				deployment: makeDeployment(
					withDeploymentGeneration(1, 1),
					withDeploymentStatus(replica1, replica1, replica1),
					withDeploymentConditions(appsv1.DeploymentProgressing, "NewReplicaSetAvailable", corev1.ConditionTrue)), // Deployment is fully deployed
				operator: makeFakeOperatorInstance(
					// withStatus(replica1),
					withGenerations(1),
					withTrueConditions(conditionAvailable),
					withFalseConditions(conditionProgressing)),
			},
		},
		{
			// Deployment is fully deployed with a missing pod and its status is synced to CR
			name: "pod missing after fully deployed",
			initialObjects: testObjects{
				deployment: makeDeployment(
					withDeploymentGeneration(1, 1),
					withDeploymentStatus(replica0, replica0, replica0),
					withDeploymentConditions(appsv1.DeploymentProgressing, "NewReplicaSetAvailable", corev1.ConditionTrue)), // Deployment is fully deployed
				operator: makeFakeOperatorInstance(withGenerations(1)),
			},
			expectedObjects: testObjects{
				deployment: makeDeployment(
					withDeploymentGeneration(1, 1),
					withDeploymentStatus(replica0, replica0, replica0),
					withDeploymentConditions(appsv1.DeploymentProgressing, "NewReplicaSetAvailable", corev1.ConditionTrue)), // Deployment is fully deployed
				operator: makeFakeOperatorInstance(
					// withStatus(replica1),
					withGenerations(1),
					withFalseConditions(conditionAvailable),    // No pod is running
					withFalseConditions(conditionProgressing)), // Despite missing pod, the operator is not progressing
			},
		},
		{
			name: "pod missing before fully deployed",
			initialObjects: testObjects{
				deployment: makeDeployment(
					withDeploymentGeneration(1, 1),
					withDeploymentStatus(replica0, replica0, replica0),
					withDeploymentConditions(appsv1.DeploymentProgressing, "NewReplicaSetAvailable", corev1.ConditionFalse)), // Deployment is not fully deployed
				operator: makeFakeOperatorInstance(withGenerations(1)),
			},
			expectedObjects: testObjects{
				deployment: makeDeployment(
					withDeploymentGeneration(1, 1),
					withDeploymentStatus(replica0, replica0, replica0),
					withDeploymentConditions(appsv1.DeploymentProgressing, "NewReplicaSetAvailable", corev1.ConditionFalse)), // Deployment is not fully deployed
				operator: makeFakeOperatorInstance(
					// withStatus(replica1),
					withGenerations(1),
					withFalseConditions(conditionAvailable),   // No pod is running
					withTrueConditions(conditionProgressing)), // A pod is missing, the operator is progressing
			},
		},
		{
			// Deployment has wrong nr. of replicas, modified by user, and gets replaced by the operator.
			name: "deployment modified by user",
			initialObjects: testObjects{
				deployment: makeDeployment(
					withDeploymentReplicas(2),      // User changed replicas
					withDeploymentGeneration(2, 1), // ... which changed Generation
					withDeploymentStatus(replica1, replica1, replica1)),
				operator: makeFakeOperatorInstance(withGenerations(1)), // the operator knows the old generation of the Deployment
			},
			expectedObjects: testObjects{
				deployment: makeDeployment(
					withDeploymentReplicas(1),      // The operator fixed replica count
					withDeploymentGeneration(3, 1), // ... which bumps generation again
					withDeploymentStatus(replica1, replica1, replica1)),
				operator: makeFakeOperatorInstance(
					// withStatus(replica1),
					withGenerations(3), // now the operator knows generation 1
					withTrueConditions(conditionAvailable, conditionProgressing), // Progressing due to Generation change
				),
			},
		},
		{
			// Deployment gets degraded for some reason
			name: "deployment degraded",
			initialObjects: testObjects{
				deployment: makeDeployment(
					withDeploymentGeneration(1, 1),
					withDeploymentStatus(0, 0, 0)), // the Deployment has no pods
				operator: makeFakeOperatorInstance(
					// withStatus(replica1),
					withGenerations(1),
					withTrueConditions(conditionAvailable),
					withFalseConditions(conditionProgressing)),
			},
			expectedObjects: testObjects{
				deployment: makeDeployment(
					withDeploymentGeneration(1, 1),
					withDeploymentStatus(0, 0, 0)), // no change to the Deployment
				operator: makeFakeOperatorInstance(
					// withStatus(replica0),
					withGenerations(1),
					withTrueConditions(conditionProgressing), // The operator is Progressing
					withFalseConditions(conditionAvailable)), // The operator is not Available (controller not running...)
			},
		},
		{
			// Deployment is updating pods
			name: "update",
			initialObjects: testObjects{
				deployment: makeDeployment(
					withDeploymentGeneration(1, 1),
					withDeploymentStatus(1 /*ready*/, 1 /*available*/, 0 /*updated*/)), // the Deployment is updating 1 pod
				operator: makeFakeOperatorInstance(
					// withStatus(replica1),
					withGenerations(1),
					withTrueConditions(conditionAvailable),
					withFalseConditions(conditionProgressing)),
			},
			expectedObjects: testObjects{
				deployment: makeDeployment(
					withDeploymentGeneration(1, 1),
					withDeploymentStatus(1, 1, 0)), // no change to the Deployment
				operator: makeFakeOperatorInstance(
					// withStatus(replica0),
					withGenerations(1),
					withTrueConditions(conditionAvailable, conditionProgressing)), // The operator is Progressing, but still Available
			},
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			// Initialize
			os.Setenv("OPERATOR_NAME", "test")
			if test.removable {
				management.SetOperatorRemovable()
			} else {
				management.SetOperatorNotRemovable()
			}
			ctx := newTestContext(test, t)

			// Act
			err := ctx.controller.Sync(context.TODO(), factory.NewSyncContext(controllerName, events.NewInMemoryRecorder("test-csi-driver", clocktesting.NewFakePassiveClock(time.Now()))))

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
			if test.expectedObjects.deployment == nil && test.initialObjects.deployment != nil {
				deployName := test.initialObjects.deployment.Name
				actualDeployment, err := ctx.coreClient.AppsV1().Deployments(operandNamespace).Get(context.TODO(), deployName, metav1.GetOptions{})
				if err == nil {
					t.Errorf("Expected Deployment to be deleted, found generation %d", actualDeployment.Generation)
				}
				if !errors.IsNotFound(err) {
					t.Errorf("Expecetd error to be NotFound, got %s", err)
				}
			}

			// Check expectedObjects.operator.Status
			if test.expectedObjects.operator != nil {
				_, actualStatus, _, err := ctx.operatorClient.GetOperatorState()
				if err != nil {
					t.Errorf("Failed to get operator: %v", err)
				}
				sanitizeInstanceStatus(actualStatus)
				sanitizeInstanceStatus(&test.expectedObjects.operator.Status)
				if !equality.Semantic.DeepEqual(test.expectedObjects.operator.Status, *actualStatus) {
					t.Errorf("Unexpected operator %+v content:\n%s", operandName, cmp.Diff(test.expectedObjects.operator.Status, *actualStatus))
				}
			}

			// Check expected ObjectMeta
			actualMeta, err := ctx.operatorClient.GetObjectMeta()
			if err != nil {
				t.Errorf("Failed to get operator: %v", err)
			}
			t.Logf("JSAF: actual meta: %+v", actualMeta.Finalizers)
			sanitizeObjectMeta(actualMeta)
			expectedMeta := &test.expectedObjects.operator.ObjectMeta
			sanitizeObjectMeta(expectedMeta)
			if !equality.Semantic.DeepEqual(actualMeta, expectedMeta) {
				t.Errorf("Unexpected operator %+v ObjectMeta content:\n%s", operandName, cmp.Diff(expectedMeta, actualMeta))
			}
		})
	}
}
