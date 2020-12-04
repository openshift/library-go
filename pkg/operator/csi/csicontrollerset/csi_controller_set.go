package csicontrollerset

import (
	"context"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"

	configinformers "github.com/openshift/client-go/config/informers/externalversions"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/loglevel"
	"github.com/openshift/library-go/pkg/operator/management"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/staticresourcecontroller"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	"github.com/openshift/library-go/pkg/operator/csi/credentialsrequestcontroller"
	"github.com/openshift/library-go/pkg/operator/csi/csidrivercontrollerservicecontroller"
	"github.com/openshift/library-go/pkg/operator/csi/csidrivernodeservicecontroller"
)

// CSIControllerSet contains a set of controllers that are usually used to deploy CSI Drivers.
type CSIControllerSet struct {
	logLevelController                   factory.Controller
	managementStateController            factory.Controller
	staticResourcesController            factory.Controller
	credentialsRequestController         factory.Controller
	csiDriverControllerServiceController factory.Controller
	csiDriverNodeServiceController       factory.Controller

	operatorClient v1helpers.OperatorClient
	eventRecorder  events.Recorder
}

// Run starts all controllers initialized in the set.
func (c *CSIControllerSet) Run(ctx context.Context, workers int) {
	for _, ctrl := range []factory.Controller{
		c.logLevelController,
		c.managementStateController,
		c.staticResourcesController,
		c.credentialsRequestController,
		c.csiDriverControllerServiceController,
		c.csiDriverNodeServiceController,
	} {
		if ctrl == nil {
			continue
		}
		go func(ctrl factory.Controller) {
			defer utilruntime.HandleCrash()
			ctrl.Run(ctx, 1)
		}(ctrl)
	}
}

// WithLogLevelController returns a *ControllerSet with a log level controller initialized.
func (c *CSIControllerSet) WithLogLevelController() *CSIControllerSet {
	c.logLevelController = loglevel.NewClusterOperatorLoggingController(c.operatorClient, c.eventRecorder)
	return c
}

// WithManagementStateController returns a *ControllerSet with a management state controller initialized.
func (c *CSIControllerSet) WithManagementStateController(operandName string, supportsOperandRemoval bool) *CSIControllerSet {
	c.managementStateController = management.NewOperatorManagementStateController(operandName, c.operatorClient, c.eventRecorder)
	if supportsOperandRemoval {
		management.SetOperatorNotRemovable()
	}
	return c
}

// WithStaticResourcesController returns a *ControllerSet with a static resources controller initialized.
func (c *CSIControllerSet) WithStaticResourcesController(
	name string,
	kubeClient kubernetes.Interface,
	kubeInformersForNamespace v1helpers.KubeInformersForNamespaces,
	manifests resourceapply.AssetFunc,
	files []string,
) *CSIControllerSet {
	c.staticResourcesController = staticresourcecontroller.NewStaticResourceController(
		name,
		manifests,
		files,
		(&resourceapply.ClientHolder{}).WithKubernetes(kubeClient),
		c.operatorClient,
		c.eventRecorder,
	).AddKubeInformers(kubeInformersForNamespace)
	return c
}

// WithCredentialsRequestController returns a *ControllerSet with a CredentialsRequestController initialized.
func (c *CSIControllerSet) WithCredentialsRequestController(
	name string,
	operandNamespace string,
	assetFunc func(string) []byte,
	file string,
	dynamicClient dynamic.Interface,
) *CSIControllerSet {
	manifestFile := assetFunc(file)
	c.credentialsRequestController = credentialsrequestcontroller.NewCredentialsRequestController(
		name,
		operandNamespace,
		manifestFile,
		dynamicClient,
		c.operatorClient,
		c.eventRecorder,
	)
	return c
}

func (c *CSIControllerSet) WithCSIDriverControllerService(
	name string,
	assetFunc func(string) []byte,
	file string,
	kubeClient kubernetes.Interface,
	namespacedInformerFactory informers.SharedInformerFactory,
	optionalConfigInformer configinformers.SharedInformerFactory,
) *CSIControllerSet {
	return c.WithCSIDriverControllerServiceWithExtraReplaces(
		name,
		assetFunc,
		file,
		kubeClient,
		namespacedInformerFactory,
		optionalConfigInformer,
		nil,
	)
}

func (c *CSIControllerSet) WithCSIDriverControllerServiceWithExtraReplaces(
	name string,
	assetFunc func(string) []byte,
	file string,
	kubeClient kubernetes.Interface,
	namespacedInformerFactory informers.SharedInformerFactory,
	optionalConfigInformer configinformers.SharedInformerFactory,
	extraReplaces func() (map[string]string, error),
) *CSIControllerSet {
	manifestFile := assetFunc(file)
	c.csiDriverControllerServiceController = csidrivercontrollerservicecontroller.NewCSIDriverControllerServiceController(
		name,
		manifestFile,
		c.operatorClient,
		kubeClient,
		namespacedInformerFactory.Apps().V1().Deployments(),
		optionalConfigInformer,
		extraReplaces,
		c.eventRecorder,
	)
	return c
}

func (c *CSIControllerSet) WithCSIDriverNodeService(
	name string,
	assetFunc func(string) []byte,
	file string,
	kubeClient kubernetes.Interface,
	namespacedInformerFactory informers.SharedInformerFactory,
) *CSIControllerSet {
	manifestFile := assetFunc(file)
	c.csiDriverNodeServiceController = csidrivernodeservicecontroller.NewCSIDriverNodeServiceController(
		name,
		manifestFile,
		c.operatorClient,
		kubeClient,
		namespacedInformerFactory.Apps().V1().DaemonSets(),
		c.eventRecorder,
	)
	return c
}

// New returns a basic *ControllerSet without any controller.
func NewCSIControllerSet(operatorClient v1helpers.OperatorClient, eventRecorder events.Recorder) *CSIControllerSet {
	return &CSIControllerSet{
		operatorClient: operatorClient,
		eventRecorder:  eventRecorder,
	}
}
