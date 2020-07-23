package csicontrollerset

import (
	"context"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/loglevel"
	"github.com/openshift/library-go/pkg/operator/management"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/staticresourcecontroller"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	"github.com/openshift/library-go/pkg/operator/csi/credentialsrequestcontroller"
	"github.com/openshift/library-go/pkg/operator/csi/csidrivercontroller"
)

// CSIDriverControllerOptions contains file names for manifests for both CSI Driver Deployment and DaemonSet.
type CSIDriverControllerOptions struct {
	controllerManifest string
	nodeManifest       string
}

// CSIDriverControllerOption is a modifier function for CSIDriverControllerOptions.
type CSIDriverControllerOption func(*CSIDriverControllerOptions)

// WithControllerService returns a CSIDriverControllerOption
// with a Deployment (CSI Controller Service) manifest file.
func WithControllerService(file string) CSIDriverControllerOption {
	return func(o *CSIDriverControllerOptions) {
		o.controllerManifest = file
	}
}

// WithNodeService returns a CSIDriverControllerOption
// with a DaemonSet (CSI Node Service) manifest file.
func WithNodeService(file string) CSIDriverControllerOption {
	return func(o *CSIDriverControllerOptions) {
		o.nodeManifest = file
	}
}

// CSIControllerSet contains a set of controllers that are usually used to deploy CSI Drivers.
type CSIControllerSet struct {
	logLevelController           factory.Controller
	managementStateController    factory.Controller
	staticResourcesController    factory.Controller
	credentialsRequestController factory.Controller
	csiDriverController          *csidrivercontroller.CSIDriverController

	operatorClient v1helpers.OperatorClient
	eventRecorder  events.Recorder
}

type controller interface {
	Run(context.Context, int)
}

// Run starts all controllers initialized in the set.
func (c *CSIControllerSet) Run(ctx context.Context, workers int) {
	for _, ctrl := range []controller{
		c.logLevelController,
		c.managementStateController,
		c.staticResourcesController,
		c.credentialsRequestController,
		c.csiDriverController,
	} {
		go func(ctrl controller) {
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

// WithCSIDriverController returns a *ControllerSet with a CSI Driver controller initialized.
func (c *CSIControllerSet) WithCSIDriverController(
	name string,
	configName string,
	csiDriverName string,
	csiDriverNamespace string,
	assetFunc func(string) []byte,
	kubeClient kubernetes.Interface,
	namespacedInformerFactory informers.SharedInformerFactory,
	setters ...CSIDriverControllerOption,
) *CSIControllerSet {
	cdc := csidrivercontroller.NewCSIDriverController(
		name,
		csiDriverName,
		csiDriverNamespace,
		configName,
		c.operatorClient,
		assetFunc,
		kubeClient,
		c.eventRecorder,
	)

	opts := &CSIDriverControllerOptions{}
	for _, setter := range setters {
		setter(opts)
	}

	if opts.controllerManifest != "" {
		cdc = cdc.WithControllerService(namespacedInformerFactory.Apps().V1().Deployments(), opts.controllerManifest)
	}

	if opts.nodeManifest != "" {
		cdc = cdc.WithNodeService(namespacedInformerFactory.Apps().V1().DaemonSets(), opts.nodeManifest)
	}

	c.csiDriverController = cdc

	return c
}

// New returns a basic *ControllerSet without any controller.
func NewCSIControllerSet(operatorClient v1helpers.OperatorClient, eventRecorder events.Recorder) *CSIControllerSet {
	return &CSIControllerSet{
		operatorClient: operatorClient,
		eventRecorder:  eventRecorder,
	}
}
