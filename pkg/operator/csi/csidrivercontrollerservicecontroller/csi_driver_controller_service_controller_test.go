package csidrivercontrollerservicecontroller

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	coreinformers "k8s.io/client-go/informers"
	fakecore "k8s.io/client-go/kubernetes/fake"

	fakeconfig "github.com/openshift/client-go/config/clientset/versioned/fake"
	configinformers "github.com/openshift/client-go/config/informers/externalversions"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

// TODO: remove after all CSI operators migrate to NewCSIDriverControllerServiceWorkloadController
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
		events.NewInMemoryRecorder(operandName),
		fakeOperatorClient,
		coreClient,
		coreInformerFactory.Apps().V1().Deployments(),
		configInformerFactory,
		nil, /* optional informers */
		deploymentAnnotationHook,
	)

	// Act
	err := controller.Sync(context.TODO(), factory.NewSyncContext(controllerName, events.NewInMemoryRecorder("test-csi-driver")))
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
