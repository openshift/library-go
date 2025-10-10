package csidrivernodeservicecontroller

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	coreinformers "k8s.io/client-go/informers"
	fakecore "k8s.io/client-go/kubernetes/fake"
	core "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	clocktesting "k8s.io/utils/clock/testing"

	"github.com/google/go-cmp/cmp"
	opv1 "github.com/openshift/api/operator/v1"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/management"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

const (
	controllerName   = "TestCSIDriverNodeServiceController"
	daemonSetName    = "test-csi-driver-node"
	operandName      = "test-csi-driver"
	operandNamespace = "openshift-test-csi-driver"

	csiDriverContainerName           = "csi-driver"
	nodeDriverRegistrarContainerName = "csi-node-driver-registrar"
	livenessProbeContainerName       = "csi-liveness-probe"

	// From github.com/openshift/library-go/pkg/operator/resource/resourceapply/apps.go
	specHashAnnotation = "operator.openshift.io/spec-hash"

	hookDaemonSetAnnKey = "operator.openshift.io/foo"
	hookDaemonSetAnnVal = "bar"

	finalizerName = "test.operator.openshift.io/" + controllerName
)

var (
	conditionAvailable   = controllerName + opv1.OperatorStatusTypeAvailable
	conditionProgressing = controllerName + opv1.OperatorStatusTypeProgressing
)

type images struct {
	csiDriver           string
	nodeDriverRegistrar string
	livenessProbe       string
}

type testCase struct {
	name            string
	manifestFunc    func() []byte
	images          images
	removable       bool
	initialObjects  testObjects
	expectedObjects testObjects
	expectErr       bool
}

type testObjects struct {
	daemonSet *appsv1.DaemonSet
	driver    *fakeDriverInstance
}

type testContext struct {
	controller     factory.Controller
	operatorClient v1helpers.OperatorClient
	coreClient     *fakecore.Clientset
	coreInformers  coreinformers.SharedInformerFactory
}

func newTestContext(test testCase, t *testing.T) *testContext {
	// Convert to []runtime.Object
	var initialObjects []runtime.Object
	if test.initialObjects.daemonSet != nil {
		resourceapply.SetSpecHashAnnotation(&test.initialObjects.daemonSet.ObjectMeta, test.initialObjects.daemonSet.Spec)
		initialObjects = append(initialObjects, test.initialObjects.daemonSet)
	}

	coreClient := fakecore.NewSimpleClientset(initialObjects...)
	coreInformerFactory := coreinformers.NewSharedInformerFactory(coreClient, 0 /*no resync */)

	// Fill the informer
	if test.initialObjects.daemonSet != nil {
		coreInformerFactory.Apps().V1().DaemonSets().Informer().GetIndexer().Add(test.initialObjects.daemonSet)
	}

	// Add global reactors
	addGenerationReactor(coreClient, coreInformerFactory.Apps().V1().DaemonSets().Informer().GetStore())

	// fakeDriverInstance also fulfils the OperatorClient interface
	fakeOperatorClient := v1helpers.NewFakeOperatorClientWithObjectMeta(
		&test.initialObjects.driver.ObjectMeta,
		&test.initialObjects.driver.Spec,
		&test.initialObjects.driver.Status,
		nil, /*triggerErr func*/
	)
	controller := NewCSIDriverNodeServiceController(
		controllerName,
		test.manifestFunc(),
		events.NewInMemoryRecorder(operandName, clocktesting.NewFakePassiveClock(time.Now())),
		fakeOperatorClient,
		coreClient,
		coreInformerFactory.Apps().V1().DaemonSets(),
		nil, /* optional informers */
	)

	// Pretend env vars are set
	os.Setenv("OPERATOR_NAME", "test")
	// TODO: inject these in New() instead
	os.Setenv(driverImageEnvName, test.images.csiDriver)
	os.Setenv(nodeDriverRegistrarImageEnvName, test.images.nodeDriverRegistrar)
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

func withGenerations(daemonSet int64) driverModifier {
	return func(i *fakeDriverInstance) *fakeDriverInstance {
		i.Status.Generations = []opv1.GenerationStatus{
			{
				Group:          appsv1.GroupName,
				LastGeneration: daemonSet,
				Name:           daemonSetName,
				Namespace:      operandNamespace,
				Resource:       "daemonsets",
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

func withFinalizers(finalizers ...string) driverModifier {
	return func(i *fakeDriverInstance) *fakeDriverInstance {
		i.Finalizers = finalizers
		return i
	}
}

func withDeletionTimestamp() driverModifier {
	return func(i *fakeDriverInstance) *fakeDriverInstance {
		// Use a constant time to get ObjectMeta comparison right.
		i.DeletionTimestamp = &metav1.Time{Time: time.Unix(0, 0)}
		return i
	}
}

func withStateRemoved() driverModifier {
	return func(i *fakeDriverInstance) *fakeDriverInstance {
		i.Spec.ManagementState = opv1.Removed
		return i
	}
}

func withObservedTLSConfig() driverModifier {
	return func(i *fakeDriverInstance) *fakeDriverInstance {
		i.Spec.ObservedConfig = runtime.RawExtension{
			Raw: []byte(`{"targetcsiconfig": {"servingInfo": { "cipherSuites": ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"], "minTLSVersion": "TLS21"}}}`),
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

// DaemonSets

type daemonSetModifier func(*appsv1.DaemonSet) *appsv1.DaemonSet

func getDaemonSet(logLevel int, images images, modifiers ...daemonSetModifier) *appsv1.DaemonSet {
	manifest := makeFakeManifest()
	ds := resourceread.ReadDaemonSetV1OrDie(manifest)

	// Replace the placeholders in the manifest (, ${DRIVER_IMAGE}, ${LOG_LEVEL})
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

func withDaemonSetStatus(numberReady, updatedNumber, numberAvailable, numberUnavailable int32) daemonSetModifier {
	return func(instance *appsv1.DaemonSet) *appsv1.DaemonSet {
		instance.Status.NumberReady = numberReady
		instance.Status.NumberAvailable = numberAvailable
		instance.Status.UpdatedNumberScheduled = updatedNumber
		instance.Status.NumberUnavailable = numberUnavailable
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

func withDaemonSetTLSConfig() daemonSetModifier {
	return func(instance *appsv1.DaemonSet) *appsv1.DaemonSet {
		proxyContainer := v1.Container{
			Name: "kube-rbac-proxy",
			Args: []string{
				"--secure-listen-address=0.0.0.0:1234",
				"--upstream=http://127.0.0.1:4567",
				"--tls-cert-file=/etc/tls/private/tls.crt",
				"--tls-private-key-file=/etc/tls/private/tls.key",
				"--tls-cipher-suites=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				"--tls-min-version=TLS21",
				"--logtostderr=true",
			},
			Image:           "kube-rbac-proxy",
			ImagePullPolicy: v1.PullIfNotPresent,
		}
		instance.Spec.Template.Spec.Containers = append(instance.Spec.Template.Spec.Containers, proxyContainer)
		return instance
	}
}

func withDaemonSetAnnotation(annotation string, value string) daemonSetModifier {
	return func(instance *appsv1.DaemonSet) *appsv1.DaemonSet {
		if instance.Annotations == nil {
			instance.Annotations = map[string]string{}
		}
		instance.Annotations[annotation] = value
		return instance
	}
}

// This reactor is always enabled and bumps DaemonSet generation when they get updated.
func addGenerationReactor(client *fakecore.Clientset, store cache.Store) {
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

			// Bump generation only when the spec changes.
			// Explicitly, do not bump it on annotation change - the API server does not do it either.
			oldDSObject, exists, err := store.GetByKey(ds.Namespace + "/" + ds.Name)
			if err != nil {
				return false, nil, err
			}
			if !exists {
				return false, nil, fmt.Errorf("DaemonSet %s not found", cache.MetaObjectToName(ds))
			}
			oldDS := oldDSObject.(*appsv1.DaemonSet)
			if !equality.Semantic.DeepEqual(oldDS.Spec, ds.Spec) {
				ds.Generation++
			}
			return false, ds, nil
		}
		return false, nil, nil
	})
}

func daemonSetAnnotationHook(opSpec *opv1.OperatorSpec, instance *appsv1.DaemonSet) error {
	if instance.Annotations == nil {
		instance.Annotations = map[string]string{}
	}
	instance.Annotations[hookDaemonSetAnnKey] = hookDaemonSetAnnVal
	return nil
}

func TestDaemonSetHook(t *testing.T) {
	// Initialize
	coreClient := fakecore.NewSimpleClientset()
	coreInformerFactory := coreinformers.NewSharedInformerFactory(coreClient, 0 /*no resync */)
	driverInstance := makeFakeDriverInstance()
	fakeOperatorClient := v1helpers.NewFakeOperatorClient(&driverInstance.Spec, &driverInstance.Status, nil /*triggerErr func*/)
	controller := NewCSIDriverNodeServiceController(
		controllerName,
		makeFakeManifest(),
		events.NewInMemoryRecorder(operandName, clocktesting.NewFakePassiveClock(time.Now())),
		fakeOperatorClient,
		coreClient,
		coreInformerFactory.Apps().V1().DaemonSets(),
		nil, /* optional informers */
		daemonSetAnnotationHook,
	)

	// Act
	err := controller.Sync(context.TODO(), factory.NewSyncContext(controllerName, events.NewInMemoryRecorder("test-csi-driver", clocktesting.NewFakePassiveClock(time.Now()))))
	if err != nil {
		t.Fatalf("sync() returned unexpected error: %v", err)
	}

	// Assert
	actualDaemonSet, err := coreClient.AppsV1().DaemonSets(operandNamespace).Get(context.TODO(), daemonSetName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Failed to get DaemonSet %s: %v", daemonSetName, err)
	}

	// DaemonSet should have the annotation specified in the hook function
	if actualDaemonSet.Annotations[hookDaemonSetAnnKey] != hookDaemonSetAnnVal {
		t.Fatalf("Annotation %q not found in DaemonSet", hookDaemonSetAnnKey)
	}
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
			name:         "initial sync",
			manifestFunc: makeFakeManifest,
			images:       defaultImages(),
			initialObjects: testObjects{
				driver: makeFakeDriverInstance(),
			},
			expectedObjects: testObjects{
				daemonSet: getDaemonSet(
					argsLevel2,
					defaultImages(),
					withDaemonSetGeneration(1, 0)),
				driver: makeFakeDriverInstance(
					// withStatus(replica0),
					withGenerations(1),
					withTrueConditions(conditionProgressing),
					withFalseConditions(conditionAvailable)), // Degraded is set later on
			},
		},
		{
			name: "no change",
			// DaemonSet is fully deployed and its status is synced to CR
			manifestFunc: makeFakeManifest,
			images:       defaultImages(),
			initialObjects: testObjects{
				daemonSet: getDaemonSet(
					argsLevel2,
					defaultImages(),
					withDaemonSetGeneration(1, 1),
					withDaemonSetStatus(replica1, replica1, replica1, replica0),
					withDaemonSetAnnotation(stableGenerationAnnotationName, "1")),
				driver: makeFakeDriverInstance(withGenerations(1)),
			},
			expectedObjects: testObjects{
				daemonSet: getDaemonSet(
					argsLevel2,
					defaultImages(),
					withDaemonSetGeneration(1, 1),
					withDaemonSetStatus(replica1, replica1, replica1, replica0),
					withDaemonSetAnnotation(stableGenerationAnnotationName, "1")),
				driver: makeFakeDriverInstance(
					// withStatus(replica1),
					withGenerations(1),
					withTrueConditions(conditionAvailable),
					withFalseConditions(conditionProgressing)),
			},
		},
		{
			name: "finished progressing",
			// DaemonSet is fully deployed and its status is synced to CR
			manifestFunc: makeFakeManifest,
			images:       defaultImages(),
			initialObjects: testObjects{
				daemonSet: getDaemonSet(
					argsLevel2,
					defaultImages(),
					withDaemonSetGeneration(1, 1),
					withDaemonSetStatus(replica1, replica1, replica1, replica0),
					withDaemonSetAnnotation(stableGenerationAnnotationName, "0")),
				driver: makeFakeDriverInstance(withGenerations(1)),
			},
			expectedObjects: testObjects{
				daemonSet: getDaemonSet(
					argsLevel2,
					defaultImages(),
					withDaemonSetGeneration(1, 1),
					withDaemonSetStatus(replica1, replica1, replica1, replica0),
					withDaemonSetAnnotation(stableGenerationAnnotationName, "1")), // The current generation has reached stability
				driver: makeFakeDriverInstance(
					// withStatus(replica1),
					withGenerations(1),
					withTrueConditions(conditionAvailable),
					withFalseConditions(conditionProgressing)),
			},
		},
		{
			// DaemonSet gets degraded for some reason
			name:         "daemonSet degraded",
			manifestFunc: makeFakeManifest,
			images:       defaultImages(),
			initialObjects: testObjects{
				daemonSet: getDaemonSet(
					argsLevel2,
					defaultImages(),
					withDaemonSetGeneration(1, 1),
					withDaemonSetStatus(replica0, replica0, replica0, replica1)), // the DaemonSet has no pods, 1 unavailable
				driver: makeFakeDriverInstance(
					// withStatus(replica1),
					withGenerations(1),
					withTrueConditions(conditionAvailable),
					withFalseConditions(conditionProgressing)),
			},
			expectedObjects: testObjects{
				daemonSet: getDaemonSet(
					argsLevel2,
					defaultImages(),
					withDaemonSetGeneration(1, 1),
					withDaemonSetStatus(replica0, replica0, replica0, replica1)), // no change to the DaemonSet
				driver: makeFakeDriverInstance(
					// withStatus(replica0),
					withGenerations(1),
					withTrueConditions(conditionProgressing), // The operator is Progressing
					withFalseConditions(conditionAvailable)), // The operator is not Available (node not running...)
			},
		},
		{
			// DaemonSet is updating pods
			name:         "update",
			manifestFunc: makeFakeManifest,
			images:       defaultImages(),
			initialObjects: testObjects{
				daemonSet: getDaemonSet(
					argsLevel2,
					defaultImages(),
					withDaemonSetGeneration(1, 1),
					withDaemonSetStatus(replica0, replica0, replica1, replica1),   // the DaemonSet is updating 1 pod
					withDaemonSetAnnotation(stableGenerationAnnotationName, "0")), // and the current generation was not stable yet
				driver: makeFakeDriverInstance(
					// withStatus(replica1),
					withGenerations(1),
					withTrueConditions(conditionAvailable),
					withFalseConditions(conditionProgressing)),
			},
			expectedObjects: testObjects{
				daemonSet: getDaemonSet(
					argsLevel2,
					defaultImages(),
					withDaemonSetGeneration(1, 1),
					withDaemonSetStatus(replica0, replica0, replica1, replica1),
					withDaemonSetAnnotation(stableGenerationAnnotationName, "0")), // and the current generation was not stable yet
				driver: makeFakeDriverInstance(
					// withStatus(replica0),
					withGenerations(1),
					withTrueConditions(conditionAvailable, conditionProgressing)), // The operator is Progressing, but still Available
			},
		},
		{
			// User changes log level and it's projected into the DaemonSet
			name:         "log level change",
			manifestFunc: makeFakeManifest,
			images:       defaultImages(),
			initialObjects: testObjects{
				daemonSet: getDaemonSet(
					argsLevel2,
					defaultImages(),
					withDaemonSetGeneration(1, 1),
					withDaemonSetStatus(replica1, replica1, replica1, replica0)),
				driver: makeFakeDriverInstance(
					withGenerations(1),
					withLogLevel(opv1.Trace)), // User changed the log level...
			},
			expectedObjects: testObjects{
				daemonSet: getDaemonSet(
					argsLevel6,      // New log level
					defaultImages(), // And the same goes for the DaemonSet
					withDaemonSetGeneration(2, 1),
					withDaemonSetStatus(replica1, replica1, replica1, replica0)),
				driver: makeFakeDriverInstance(
					// withStatus(replica1),
					withLogLevel(opv1.Trace),
					withGenerations(2),
					withTrueConditions(conditionAvailable, conditionProgressing)), // Progressing due to Generation change
			},
		},
		{
			// DaemonSet updates images
			name:         "image change",
			manifestFunc: makeFakeManifest,
			images:       defaultImages(),
			initialObjects: testObjects{
				daemonSet: getDaemonSet(
					argsLevel2,
					oldImages(),
					withDaemonSetGeneration(1, 1),
					withDaemonSetStatus(replica1, replica1, replica1, replica0)),
				driver: makeFakeDriverInstance(
					// withStatus(replica1),k
					withGenerations(1),
					withTrueConditions(conditionAvailable),
					withFalseConditions(conditionProgressing)),
			},
			expectedObjects: testObjects{
				daemonSet: getDaemonSet(
					argsLevel2,
					defaultImages(),
					withDaemonSetGeneration(2, 1),
					withDaemonSetStatus(replica1, replica1, replica1, replica0)),
				driver: makeFakeDriverInstance(
					// withStatus(replica1),
					withGenerations(2),
					withTrueConditions(conditionAvailable, conditionProgressing)),
			},
		},
		{
			// Finalizer is added to removable CR
			// (and DaemonSet is created)
			name:         "add finalizer",
			manifestFunc: makeFakeManifest,
			images:       defaultImages(),
			removable:    true,
			initialObjects: testObjects{
				driver: makeFakeDriverInstance(),
			},
			expectedObjects: testObjects{
				daemonSet: getDaemonSet(
					argsLevel2,
					defaultImages(),
					withDaemonSetGeneration(1, 0)),
				driver: makeFakeDriverInstance(
					// withStatus(replica0),
					withGenerations(1),
					withTrueConditions(conditionProgressing),
					withFalseConditions(conditionAvailable), // Degraded is set later on
					withFinalizers(finalizerName)),
			},
		},
		{
			// DaemonSet and finalizer are deleted on DeletionTimestamp
			name:         "remove daemonset",
			manifestFunc: makeFakeManifest,
			images:       defaultImages(),
			removable:    true,
			initialObjects: testObjects{
				daemonSet: getDaemonSet(
					argsLevel2,
					defaultImages(),
					withDaemonSetGeneration(1, 1),
					withDaemonSetStatus(replica1, replica1, replica1, replica0)),
				driver: makeFakeDriverInstance(
					withGenerations(1),
					withFinalizers(finalizerName),
					withDeletionTimestamp()),
			},
			expectedObjects: testObjects{
				driver: makeFakeDriverInstance(
					withGenerations(1),
					// No conditions are updated!
					// (only Degraded condition might be set on error)
					withDeletionTimestamp()),
			},
		},
		{
			// DaemonSet and finalizer are deleted if ManagementState is Removed
			name:         "ManagementState Removed",
			manifestFunc: makeFakeManifest,
			images:       defaultImages(),
			removable:    true,
			initialObjects: testObjects{
				daemonSet: getDaemonSet(
					argsLevel2,
					defaultImages(),
					withDaemonSetGeneration(1, 1),
					withDaemonSetStatus(replica1, replica1, replica1, replica0)),
				driver: makeFakeDriverInstance(
					withGenerations(1),
					withFinalizers(finalizerName),
					withStateRemoved()),
			},
			expectedObjects: testObjects{
				driver: makeFakeDriverInstance(
					withGenerations(1)),
			},
		},
		{
			// DaemonSet updates TLS config
			name:         "TLS config",
			manifestFunc: makeFakeManifestWithTLS,
			images:       defaultImages(),
			initialObjects: testObjects{
				driver: makeFakeDriverInstance(withObservedTLSConfig()),
			},
			expectedObjects: testObjects{
				daemonSet: getDaemonSet(
					argsLevel2,
					defaultImages(),
					withDaemonSetGeneration(1, 0),
					withDaemonSetTLSConfig()),
				driver: makeFakeDriverInstance(
					// withStatus(replica0),
					withObservedTLSConfig(),
					withGenerations(1),
					withTrueConditions(conditionProgressing),
					withFalseConditions(conditionAvailable)), // Degraded is set later on
			},
		},
		{
			// DaemonSet is updating pods
			name:         "missing pods - not progressing",
			manifestFunc: makeFakeManifest,
			images:       defaultImages(),
			initialObjects: testObjects{
				daemonSet: getDaemonSet(
					argsLevel2,
					defaultImages(),
					withDaemonSetGeneration(1, 1),
					withDaemonSetStatus(replica0, replica0, replica1, replica1),   // the DaemonSet is updating 1 pod
					withDaemonSetAnnotation(stableGenerationAnnotationName, "1")), // But the current generation was stable in the past
				driver: makeFakeDriverInstance(
					// withStatus(replica1),
					withGenerations(1),
					withTrueConditions(conditionAvailable),
					withFalseConditions(conditionProgressing)),
			},
			expectedObjects: testObjects{
				daemonSet: getDaemonSet(
					argsLevel2,
					defaultImages(),
					withDaemonSetGeneration(1, 1),
					withDaemonSetStatus(replica0, replica0, replica1, replica1),
					withDaemonSetAnnotation(stableGenerationAnnotationName, "1")), // no change to the DaemonSet
				driver: makeFakeDriverInstance(
					// withStatus(replica0),
					withGenerations(1), // But the current generation was stable in the past
					withTrueConditions(conditionAvailable),
					withFalseConditions(conditionProgressing)), // The operator is not Progressing
			},
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			// Initialize
			ctx := newTestContext(test, t)
			if test.removable {
				management.SetOperatorRemovable()
			} else {
				management.SetOperatorNotRemovable()
			}

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
			if test.expectedObjects.daemonSet == nil && test.initialObjects.daemonSet != nil {
				dsName := test.initialObjects.daemonSet.Name
				actualDaemonSet, err := ctx.coreClient.AppsV1().DaemonSets(operandNamespace).Get(context.TODO(), dsName, metav1.GetOptions{})
				if err == nil {
					t.Errorf("Expected DaemonSet to be deleted, found generation %d", actualDaemonSet.Generation)
				}
				if !errors.IsNotFound(err) {
					t.Errorf("Expecetd error to be NotFound, got %s", err)
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

				// Check expected ObjectMeta
				actualMeta, err := ctx.operatorClient.GetObjectMeta()
				if err != nil {
					t.Errorf("Failed to get Driver: %v", err)
				}
				sanitizeObjectMeta(actualMeta)
				expectedMeta := &test.expectedObjects.driver.ObjectMeta
				sanitizeObjectMeta(expectedMeta)
				if !equality.Semantic.DeepEqual(actualMeta, expectedMeta) {
					t.Errorf("Unexpected Driver %+v ObjectMeta content:\n%s", operandName, cmp.Diff(expectedMeta, actualMeta))
				}
			}
		})
	}
}
func sanitizeDaemonSet(daemonSet *appsv1.DaemonSet) {
	// nil and empty array are the same
	if len(daemonSet.Labels) == 0 {
		daemonSet.Labels = nil
	}
	if len(daemonSet.Annotations) == 0 {
		daemonSet.Annotations = nil
	}
	// Remove random annotations set by ApplyDaemonSet
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

func sanitizeObjectMeta(meta *metav1.ObjectMeta) {
	if len(meta.Finalizers) == 0 {
		meta.Finalizers = nil
	}
}

func defaultImages() images {
	return images{
		csiDriver:           "quay.io/openshift/origin-test-csi-driver:latest",
		nodeDriverRegistrar: "quay.io/openshift/origin-csi-node-driver-registrar:latest",
		livenessProbe:       "quay.io/openshift/origin-csi-livenessprobe:latest",
	}
}

func oldImages() images {
	return images{
		csiDriver:           "quay.io/openshift/origin-test-csi-driver:old",
		nodeDriverRegistrar: "quay.io/openshift/origin-csi-node-driver-registrar:old",
		livenessProbe:       "quay.io/openshift/origin-csi-livenessprobe:old",
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
          image: ${DRIVER_IMAGE}
          args:
            - --endpoint=$(CSI_ENDPOINT)
            - --logtostderr
            - --v=${LOG_LEVEL}
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
          image: ${NODE_DRIVER_REGISTRAR_IMAGE}
          args:
            - --csi-address=$(ADDRESS)
            - --kubelet-registration-path=$(DRIVER_REG_SOCK_PATH)
            - --v=${LOG_LEVEL}
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
          image: ${LIVENESS_PROBE_IMAGE}
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

func makeFakeManifestWithTLS() []byte {
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
          image: ${DRIVER_IMAGE}
          args:
            - --endpoint=$(CSI_ENDPOINT)
            - --logtostderr
            - --v=${LOG_LEVEL}
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
          image: ${NODE_DRIVER_REGISTRAR_IMAGE}
          args:
            - --csi-address=$(ADDRESS)
            - --kubelet-registration-path=$(DRIVER_REG_SOCK_PATH)
            - --v=${LOG_LEVEL}
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
          image: ${LIVENESS_PROBE_IMAGE}
          args:
            - --csi-address=/csi/csi.sock
            - --probe-timeout=3s
          volumeMounts:
            - name: plugin-dir
              mountPath: /csi
        - name: kube-rbac-proxy
          args:
          - --secure-listen-address=0.0.0.0:1234
          - --upstream=http://127.0.0.1:4567
          - --tls-cert-file=/etc/tls/private/tls.crt
          - --tls-private-key-file=/etc/tls/private/tls.key
          - --tls-cipher-suites=${TLS_CIPHER_SUITES}
          - --tls-min-version=${TLS_MIN_VERSION}
          - --logtostderr=true
          image: kube-rbac-proxy
          imagePullPolicy: IfNotPresent
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
