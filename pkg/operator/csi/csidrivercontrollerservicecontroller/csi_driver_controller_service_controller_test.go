package csidrivercontrollerservicecontroller

import (
	"context"
	"fmt"
	clocktesting "k8s.io/utils/clock/testing"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	coreinformers "k8s.io/client-go/informers"
	fakecore "k8s.io/client-go/kubernetes/fake"

	configv1 "github.com/openshift/api/config/v1"
	opv1 "github.com/openshift/api/operator/v1"
	fakeconfig "github.com/openshift/client-go/config/clientset/versioned/fake"
	configinformers "github.com/openshift/client-go/config/informers/externalversions"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

const (
	controllerName   = "TestCSIDriverControllerServiceController"
	deploymentName   = "test-csi-driver-controller"
	operandName      = "test-csi-driver"
	operandNamespace = "openshift-test-csi-driver"

	csiDriverContainerName     = "csi-driver"
	provisionerContainerName   = "csi-provisioner"
	attacherContainerName      = "csi-attacher"
	resizerContainerName       = "csi-resizer"
	snapshotterContainerName   = "csi-snapshotter"
	livenessProbeContainerName = "csi-liveness-probe"
	kubeRBACProxyContainerName = "provisioner-kube-rbac-proxy"

	defaultClusterID = "ID1234"

	hookDeploymentAnnKey = "operator.openshift.io/foo"
	hookDeploymentAnnVal = "bar"
)

type images struct {
	csiDriver     string
	attacher      string
	provisioner   string
	resizer       string
	snapshotter   string
	livenessProbe string
	kubeRBACProxy string
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

	if images.kubeRBACProxy != "" {
		if idx := getIndex(containers, kubeRBACProxyContainerName); idx > -1 {
			containers[idx].Image = images.kubeRBACProxy
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

func deploymentAnnotationHook(opSpec *opv1.OperatorSpec, instance *appsv1.Deployment) error {
	if instance.Annotations == nil {
		instance.Annotations = map[string]string{}
	}
	instance.Annotations[hookDeploymentAnnKey] = hookDeploymentAnnVal
	return nil
}

func TestDeploymentHook(t *testing.T) {
	// Initialize
	coreClient := fakecore.NewSimpleClientset()
	coreInformerFactory := coreinformers.NewSharedInformerFactory(coreClient, 0 /*no resync */)
	initialInfras := []runtime.Object{makeInfra()}
	configClient := fakeconfig.NewSimpleClientset(initialInfras...)
	configInformerFactory := configinformers.NewSharedInformerFactory(configClient, 0)
	configInformerFactory.Config().V1().Infrastructures().Informer().GetIndexer().Add(initialInfras[0])
	driverInstance := makeFakeDriverInstance()
	fakeOperatorClient := v1helpers.NewFakeOperatorClient(&driverInstance.Spec, &driverInstance.Status, nil /*triggerErr func*/)
	controller := NewCSIDriverControllerServiceController(
		controllerName,
		makeFakeManifest(),
		events.NewInMemoryRecorder(operandName, clocktesting.NewFakePassiveClock(time.Now())),
		fakeOperatorClient,
		coreClient,
		coreInformerFactory.Apps().V1().Deployments(),
		configInformerFactory,
		nil, /* optional informers */
		deploymentAnnotationHook,
	)

	// Act
	err := controller.Sync(context.TODO(), factory.NewSyncContext(controllerName, events.NewInMemoryRecorder("test-csi-driver", clocktesting.NewFakePassiveClock(time.Now()))))
	if err != nil {
		t.Fatalf("sync() returned unexpected error: %v", err)
	}

	// Assert
	actualDeployment, err := coreClient.AppsV1().Deployments(operandNamespace).Get(context.TODO(), deploymentName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Failed to get Deployment %s: %v", deploymentName, err)
	}

	// Deployment should have the annotation specified in the hook function
	if actualDeployment.Annotations[hookDeploymentAnnKey] != hookDeploymentAnnVal {
		t.Fatalf("Annotation %q not found in Deployment", hookDeploymentAnnKey)
	}
}

func defaultImages() images {
	return images{
		csiDriver:     "quay.io/openshift/origin-test-csi-driver:latest",
		provisioner:   "quay.io/openshift/origin-csi-external-provisioner:latest",
		attacher:      "quay.io/openshift/origin-csi-external-attacher:latest",
		resizer:       "quay.io/openshift/origin-csi-external-resizer:latest",
		snapshotter:   "quay.io/openshift/origin-csi-external-snapshotter:latest",
		livenessProbe: "quay.io/openshift/origin-csi-livenessprobe:latest",
		kubeRBACProxy: "quay.io/openshift/origin-kube-rbac-proxy:latest",
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
