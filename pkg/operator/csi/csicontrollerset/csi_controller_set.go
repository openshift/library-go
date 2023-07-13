package csicontrollerset

import (
	"context"
	"fmt"
	"time"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"

	configinformers "github.com/openshift/client-go/config/informers/externalversions"
	operatorinformer "github.com/openshift/client-go/operator/informers/externalversions"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/csi/credentialsrequestcontroller"
	"github.com/openshift/library-go/pkg/operator/csi/csiconfigobservercontroller"
	"github.com/openshift/library-go/pkg/operator/csi/csidrivercontrollerservicecontroller"
	"github.com/openshift/library-go/pkg/operator/csi/csidrivernodeservicecontroller"
	"github.com/openshift/library-go/pkg/operator/csi/csistorageclasscontroller"
	"github.com/openshift/library-go/pkg/operator/deploymentcontroller"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/loglevel"
	"github.com/openshift/library-go/pkg/operator/management"
	"github.com/openshift/library-go/pkg/operator/managementstatecontroller"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/staticresourcecontroller"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

var defaultCacheSyncTimeout = 10 * time.Minute

// CSIControllerSet contains a set of controllers that are usually used to deploy CSI Drivers.
type CSIControllerSet struct {
	logLevelController                   factory.Controller
	managementStateController            factory.Controller
	staticResourcesController            factory.Controller
	conditionalStaticResourcesController factory.Controller
	credentialsRequestController         factory.Controller
	csiConfigObserverController          factory.Controller
	csiDriverControllerServiceController factory.Controller
	csiDriverNodeServiceController       factory.Controller
	serviceMonitorController             factory.Controller
	csiStorageclassController            factory.Controller

	operatorClient v1helpers.OperatorClientWithFinalizers
	eventRecorder  events.Recorder
}

// Run starts all controllers initialized in the set.
func (c *CSIControllerSet) Run(ctx context.Context, workers int) {
	for _, ctrl := range []factory.Controller{
		c.logLevelController,
		c.managementStateController,
		c.staticResourcesController,
		c.conditionalStaticResourcesController,
		c.credentialsRequestController,
		c.csiConfigObserverController,
		c.csiDriverControllerServiceController,
		c.csiDriverNodeServiceController,
		c.serviceMonitorController,
		c.csiStorageclassController,
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
	c.managementStateController = managementstatecontroller.NewOperatorManagementStateController(operandName, c.operatorClient, c.eventRecorder)
	if !supportsOperandRemoval {
		management.SetOperatorNotRemovable()
	}
	return c
}

// WithConditionalStaticResourcesController returns a *ControllerSet with a conditional static resources controller initialized.
func (c *CSIControllerSet) WithConditionalStaticResourcesController(
	name string,
	kubeClient kubernetes.Interface,
	dynamicClient dynamic.Interface,
	kubeInformersForNamespace v1helpers.KubeInformersForNamespaces,
	manifests resourceapply.AssetFunc,
	files []string,
	shouldCreateFnArg, shouldDeleteFnArg resourceapply.ConditionalFunction,
) *CSIControllerSet {
	c.conditionalStaticResourcesController = staticresourcecontroller.NewStaticResourceController(
		name,
		manifests,
		[]string{},
		(&resourceapply.ClientHolder{}).WithKubernetes(kubeClient).WithDynamicClient(dynamicClient),
		c.operatorClient,
		c.eventRecorder,
	).WithConditionalResources(
		manifests,
		files,
		shouldCreateFnArg,
		shouldDeleteFnArg,
	).AddKubeInformers(kubeInformersForNamespace)
	return c
}

// WithStaticResourcesController returns a *ControllerSet with a static resources controller initialized.
func (c *CSIControllerSet) WithStaticResourcesController(
	name string,
	kubeClient kubernetes.Interface,
	dynamicClient dynamic.Interface,
	kubeInformersForNamespace v1helpers.KubeInformersForNamespaces,
	manifests resourceapply.AssetFunc,
	files []string,
) *CSIControllerSet {
	c.staticResourcesController = staticresourcecontroller.NewStaticResourceController(
		name,
		manifests,
		files,
		(&resourceapply.ClientHolder{}).WithKubernetes(kubeClient).WithDynamicClient(dynamicClient),
		c.operatorClient,
		c.eventRecorder,
	).AddKubeInformers(kubeInformersForNamespace)
	return c
}

// WithCredentialsRequestController returns a *ControllerSet with a CredentialsRequestController initialized.
func (c *CSIControllerSet) WithCredentialsRequestController(
	name string,
	operandNamespace string,
	assetFunc resourceapply.AssetFunc,
	file string,
	dynamicClient dynamic.Interface,
	operatorInformer operatorinformer.SharedInformerFactory,
	hooks ...credentialsrequestcontroller.CredentialsRequestHook,
) *CSIControllerSet {
	manifestFile, err := assetFunc(file)
	if err != nil {
		panic(fmt.Sprintf("asset: Asset(%v): %v", file, err))
	}
	c.credentialsRequestController = credentialsrequestcontroller.NewCredentialsRequestController(
		name,
		operandNamespace,
		manifestFile,
		dynamicClient,
		c.operatorClient,
		operatorInformer,
		c.eventRecorder,
		hooks...,
	)
	return c
}

func (c *CSIControllerSet) WithCSIConfigObserverController(
	name string,
	configinformers configinformers.SharedInformerFactory,
) *CSIControllerSet {
	c.csiConfigObserverController = csiconfigobservercontroller.NewCSIConfigObserverController(
		name,
		c.operatorClient,
		configinformers,
		c.eventRecorder,
	)
	return c
}

func (c *CSIControllerSet) WithCSIDriverControllerService(
	name string,
	assetFunc resourceapply.AssetFunc,
	file string,
	kubeClient kubernetes.Interface,
	namespacedInformerFactory informers.SharedInformerFactory,
	configInformer configinformers.SharedInformerFactory,
	optionalInformers []factory.Informer,
	optionalDeploymentHooks ...deploymentcontroller.DeploymentHookFunc,
) *CSIControllerSet {
	manifestFile, err := assetFunc(file)
	if err != nil {
		panic(fmt.Sprintf("asset: Asset(%v): %v", file, err))
	}
	c.csiDriverControllerServiceController = csidrivercontrollerservicecontroller.NewCSIDriverControllerServiceController(
		name,
		manifestFile,
		c.eventRecorder,
		c.operatorClient,
		kubeClient,
		namespacedInformerFactory.Apps().V1().Deployments(),
		configInformer,
		optionalInformers,
		optionalDeploymentHooks...,
	)
	return c
}

func (c *CSIControllerSet) WithCSIDriverNodeService(
	name string,
	assetFunc resourceapply.AssetFunc,
	file string,
	kubeClient kubernetes.Interface,
	namespacedInformerFactory informers.SharedInformerFactory,
	optionalInformers []factory.Informer,
	optionalDaemonSetHooks ...csidrivernodeservicecontroller.DaemonSetHookFunc,
) *CSIControllerSet {
	manifestFile, err := assetFunc(file)
	if err != nil {
		panic(fmt.Sprintf("asset: Asset(%v): %v", file, err))
	}
	c.csiDriverNodeServiceController = csidrivernodeservicecontroller.NewCSIDriverNodeServiceController(
		name,
		manifestFile,
		c.eventRecorder,
		c.operatorClient,
		kubeClient,
		namespacedInformerFactory.Apps().V1().DaemonSets(),
		optionalInformers,
		optionalDaemonSetHooks...,
	)
	return c
}

// WithServiceMonitorController returns a *ControllerSet that creates ServiceMonitor.
func (c *CSIControllerSet) WithServiceMonitorController(
	name string,
	dynamicClient dynamic.Interface,
	assetFunc resourceapply.AssetFunc,
	file string,
) *CSIControllerSet {
	// Use StaticResourceController to apply ServiceMonitors.
	// Ensure that NotFound errors are ignored, e.g. when ServiceMonitor CRD missing.
	c.serviceMonitorController = staticresourcecontroller.NewStaticResourceController(
		name,
		assetFunc,
		[]string{file},
		(&resourceapply.ClientHolder{}).WithDynamicClient(dynamicClient),
		c.operatorClient,
		c.eventRecorder,
	).WithIgnoreNotFoundOnCreate()
	return c
}

func (c *CSIControllerSet) WithStorageClassController(
	name string,
	assetFunc resourceapply.AssetFunc,
	files []string,
	kubeClient kubernetes.Interface,
	namespacedInformerFactory informers.SharedInformerFactory,
	operatorInformer operatorinformer.SharedInformerFactory,
	hooks ...csistorageclasscontroller.StorageClassHookFunc,
) *CSIControllerSet {
	c.csiStorageclassController = csistorageclasscontroller.NewCSIStorageClassController(
		name,
		assetFunc,
		files,
		kubeClient,
		namespacedInformerFactory,
		c.operatorClient,
		operatorInformer,
		c.eventRecorder,
		hooks...,
	)
	return c
}

// New returns a basic *ControllerSet without any controller.
func NewCSIControllerSet(operatorClient v1helpers.OperatorClientWithFinalizers, eventRecorder events.Recorder) *CSIControllerSet {
	return &CSIControllerSet{
		operatorClient: operatorClient,
		eventRecorder:  eventRecorder,
	}
}
