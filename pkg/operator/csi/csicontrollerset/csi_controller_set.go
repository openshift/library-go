package csicontrollerset

import (
	"context"
	"fmt"
	"time"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	configinformers "github.com/openshift/client-go/config/informers/externalversions"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/csi/credentialsrequestcontroller"
	"github.com/openshift/library-go/pkg/operator/csi/csiconfigobservercontroller"
	"github.com/openshift/library-go/pkg/operator/csi/csidrivercontrollerservicecontroller"
	"github.com/openshift/library-go/pkg/operator/csi/csidrivernodeservicecontroller"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/loglevel"
	"github.com/openshift/library-go/pkg/operator/management"
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
	credentialsRequestController         factory.Controller
	csiConfigObserverController          factory.Controller
	csiDriverControllerServiceController factory.Controller
	csiDriverNodeServiceController       factory.Controller
	serviceMonitorController             factory.Controller

	preRunCachesSynced []cache.InformerSynced
	operatorClient     v1helpers.OperatorClient
	eventRecorder      events.Recorder
}

// Run starts all controllers initialized in the set.
func (c *CSIControllerSet) Run(ctx context.Context, workers int) {
	defer utilruntime.HandleCrash()

	// Create a custom context to sync informers added  with .WithExtraInformers().
	// This context is not used for individual controllers because factory.Factory
	// will overwrite the timeout value.
	cacheSyncCtx, cacheSyncCancel := context.WithTimeout(ctx, defaultCacheSyncTimeout)
	defer cacheSyncCancel()

	if !cache.WaitForCacheSync(cacheSyncCtx.Done(), c.preRunCachesSynced...) {
		utilruntime.HandleError(fmt.Errorf("caches did not sync"))
		return
	}
	for _, ctrl := range []factory.Controller{
		c.logLevelController,
		c.managementStateController,
		c.staticResourcesController,
		c.credentialsRequestController,
		c.csiConfigObserverController,
		c.csiDriverControllerServiceController,
		c.csiDriverNodeServiceController,
		c.serviceMonitorController,
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
	assetFunc func(string) []byte,
	file string,
	kubeClient kubernetes.Interface,
	namespacedInformerFactory informers.SharedInformerFactory,
	optionalConfigInformer configinformers.SharedInformerFactory,
	optionalDeploymentHooks ...csidrivercontrollerservicecontroller.DeploymentHookFunc,
) *CSIControllerSet {
	manifestFile := assetFunc(file)
	c.csiDriverControllerServiceController = csidrivercontrollerservicecontroller.NewCSIDriverControllerServiceController(
		name,
		manifestFile,
		c.operatorClient,
		kubeClient,
		namespacedInformerFactory.Apps().V1().Deployments(),
		optionalConfigInformer,
		c.eventRecorder,
		optionalDeploymentHooks...,
	)
	return c
}

func (c *CSIControllerSet) WithCSIDriverNodeService(
	name string,
	assetFunc func(string) []byte,
	file string,
	kubeClient kubernetes.Interface,
	namespacedInformerFactory informers.SharedInformerFactory,
	optionalDaemonSetHooks ...csidrivernodeservicecontroller.DaemonSetHookFunc,
) *CSIControllerSet {
	manifestFile := assetFunc(file)
	c.csiDriverNodeServiceController = csidrivernodeservicecontroller.NewCSIDriverNodeServiceController(
		name,
		manifestFile,
		c.operatorClient,
		kubeClient,
		namespacedInformerFactory.Apps().V1().DaemonSets(),
		c.eventRecorder,
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

// WithExtraInformers adds informers that individual controllers don't wait for. These are typically
// informers used by hook functions in csidrivercontrollerservicecontroller and csidrivernodeservicecontroller.
func (c *CSIControllerSet) WithExtraInformers(informers ...cache.SharedIndexInformer) *CSIControllerSet {
	for i := range informers {
		c.preRunCachesSynced = append(c.preRunCachesSynced, informers[i].HasSynced)
	}
	return c
}

// New returns a basic *ControllerSet without any controller.
func NewCSIControllerSet(operatorClient v1helpers.OperatorClient, eventRecorder events.Recorder) *CSIControllerSet {
	return &CSIControllerSet{
		operatorClient: operatorClient,
		eventRecorder:  eventRecorder,
	}
}
