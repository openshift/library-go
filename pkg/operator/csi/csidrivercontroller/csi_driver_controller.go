package csidrivercontroller

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	appsinformersv1 "k8s.io/client-go/informers/apps/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	opv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

const (
	driverImageEnvName              = "DRIVER_IMAGE"
	provisionerImageEnvName         = "PROVISIONER_IMAGE"
	attacherImageEnvName            = "ATTACHER_IMAGE"
	resizerImageEnvName             = "RESIZER_IMAGE"
	snapshotterImageEnvName         = "SNAPSHOTTER_IMAGE"
	nodeDriverRegistrarImageEnvName = "NODE_DRIVER_REGISTRAR_IMAGE"
	livenessProbeImageEnvName       = "LIVENESS_PROBE_IMAGE"

	maxRetries = 15
)

// CSIDriverController is a controller that deploys a CSI driver operand to a given namespace.
//
// A CSI driver operand is typically made of of a DaemonSet and a Deployment. The DaemonSet
// deploys a pod with the CSI driver and sidecars containers (node-driver-registrar and liveness-probe).
// The Deployment deploys a pod with the CSI driver and sidecars containers (provisioner, attacher,
// resizer, snapshotter, liveness-probe).
//
// Container names in both the Deployment and DaemonSet MUST follow the following nomenclature so that the
// controller knows how to patch their fields:
//
// CSI driver: csi-driver
// Provisionier: csi-provisioner
// Attacher: csi-attacher
// Resizer: csi-resizer
// Snapshotter: csi-snapshotter
// Liveness probe: csi-liveness-probe
// Node driver registrar: csi-node-driver-registrar
//
// On every sync, this controller reads both the Deployment and the DaemonSet from static files and overrides a few fields:
//
// 1. Container image location
//
// The controller will replace the image specified in the static files if it follows a certain nomenclature AND its
// respective environemnt variable is set. This is a list of environment variables that the controller understands:
//
// DRIVER_IMAGE
// PROVISIONER_IMAGE
// ATTACHER_IMAGE
// RESIZER_IMAGE
// SNAPSHOTTER_IMAGE
// NODE_DRIVER_REGISTRAR_IMAGE
// LIVENESS_PROBE_IMAGE
//
// As for the static files, the names above should be wrapped by a ${}, e.g., ${DIVER_IMAGE}.
//
// 2. Log level
//
// The controller can also override the log level passed in to the CSI driver container.
//
// In order to do that, the placeholder ${LOG_LEVEL} from the manifest file is replaced with the value specified
// in the OperatorClient resource (Spec.LogLevel).
type CSIDriverController struct {
	// Controller
	name            string
	queue           workqueue.RateLimitingInterface
	eventRecorder   events.Recorder
	informersSynced []cache.InformerSynced

	// CSI driver
	csiDriverName      string
	csiDriverNamespace string
	assetFunc          func(string) []byte
	controllerManifest []byte
	nodeManifest       []byte
	images             images

	// Resources
	kubeClient     kubernetes.Interface
	configName     string
	operatorClient v1helpers.OperatorClient
}

type images struct {
	csiDriver           string
	attacher            string
	provisioner         string
	resizer             string
	snapshotter         string
	nodeDriverRegistrar string
	livenessProbe       string
}

// NewCSIDriverController returns a new CSIDriverController without any CSI Service.
// It's expected that the CSI Services are added to the controller using the
// appropriate With*Service functions.
func NewCSIDriverController(
	name string,
	csiDriverName string,
	csiDriverNamespace string,
	instanceName string,
	operatorClient v1helpers.OperatorClient,
	assetFunc func(string) []byte,
	kubeClient kubernetes.Interface,
	eventRecorder events.Recorder,
) *CSIDriverController {
	c := &CSIDriverController{
		name:               name,
		csiDriverName:      csiDriverName,
		csiDriverNamespace: csiDriverNamespace,
		kubeClient:         kubeClient,
		configName:         instanceName,
		operatorClient:     operatorClient,
		assetFunc:          assetFunc,
		images:             imagesFromEnv(),
		queue:              workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), csiDriverName),
		eventRecorder:      eventRecorder.WithComponentSuffix("csi-driver-controller-recorder-" + strings.ToLower(name)),
	}
	operatorClient.Informer().AddEventHandler(c.eventHandler(csiDriverName))
	c.informersSynced = append(c.informersSynced, operatorClient.Informer().HasSynced)
	return c
}

// WithControllerService returns a controller with the CSI Controller Service.
// The CSI Controller Service is represented by a Deployment.
func (c *CSIDriverController) WithControllerService(informer appsinformersv1.DeploymentInformer, file string) *CSIDriverController {
	informer.Informer().AddEventHandler(c.eventHandler("deployment"))
	c.informersSynced = append(c.informersSynced, informer.Informer().HasSynced)
	c.controllerManifest = c.assetFunc(file)
	return c
}

// WithNodeService returns a controller with the CSI Node Service.
// The CSI Node Service is represented by a DaemonSet.
func (c *CSIDriverController) WithNodeService(informer appsinformersv1.DaemonSetInformer, file string) *CSIDriverController {
	informer.Informer().AddEventHandler(c.eventHandler("daemonSet"))
	c.informersSynced = append(c.informersSynced, informer.Informer().HasSynced)
	c.nodeManifest = c.assetFunc(file)
	return c
}

// Run starts syncing the controller.
func (c *CSIDriverController) Run(ctx context.Context, workers int) {
	defer utilruntime.HandleCrash()
	defer c.queue.ShutDown()

	if c.nodeManifest == nil {
		klog.Errorf("Controller doesn't have a CSI Node Service, quitting")
		return
	}

	stopCh := ctx.Done()
	if !cache.WaitForCacheSync(stopCh, c.informersSynced...) {
		return
	}
	klog.V(4).Infof("Caches synced, running the controller")

	for i := 0; i < workers; i++ {
		go wait.Until(c.worker, time.Second, stopCh)
	}
	<-stopCh
}

func (c *CSIDriverController) sync() error {
	meta, err := c.operatorClient.GetObjectMeta()
	if err != nil {
		if errors.IsNotFound(err) {
			klog.Warningf("Object metadata not found: %v", err)
			return nil
		}
		return err
	}

	opSpec, opStatus, opResourceVersion, err := c.operatorClient.GetOperatorState()
	if err != nil {
		return err
	}

	// We only support Managed for now
	if opSpec.ManagementState != opv1.Managed {
		return nil
	}

	startTime := time.Now()
	klog.V(4).Info("Starting syncing controller at ", startTime)
	defer func() {
		klog.V(4).Info("Finished syncing controller at ", time.Since(startTime))
	}()

	syncErr := c.handleSync(opResourceVersion, meta, opSpec, opStatus)
	if syncErr != nil {
		c.eventRecorder.Eventf("SyncError", "Error syncing CSI driver: %s", syncErr)
	}

	c.updateSyncError(opStatus, syncErr)

	// Update the status using our copy
	_, _, err = v1helpers.UpdateStatus(c.operatorClient, func(status *opv1.OperatorStatus) error {
		// Store a copy of our starting conditions, we need to preserve last transition time
		originalConditions := status.DeepCopy().Conditions

		// Copy over everything else
		opStatus.DeepCopyInto(status)

		// Restore the starting conditions
		status.Conditions = originalConditions

		// Manually update the conditions while preserving last transition time
		for _, condition := range opStatus.Conditions {
			v1helpers.SetOperatorCondition(&status.Conditions, condition)
		}

		return nil
	})

	if err != nil {
		klog.Errorf("failed to update status: %v", err)
		if syncErr == nil {
			syncErr = err
		}
	}

	return syncErr
}

func (c *CSIDriverController) updateSyncError(status *opv1.OperatorStatus, err error) {
	if err != nil {
		// Operator is Degraded: could not finish what it was doing
		v1helpers.SetOperatorCondition(&status.Conditions,
			opv1.OperatorCondition{
				Type:    fmt.Sprintf("%s%s", c.name, opv1.OperatorStatusTypeDegraded),
				Status:  opv1.ConditionTrue,
				Reason:  "OperatorSync",
				Message: err.Error(),
			})

		// Operator is Progressing: some action failed, will try to progress more after exp. backoff.
		// Do not overwrite existing "Progressing=true" condition to keep its message.
		cnd := v1helpers.FindOperatorCondition(status.Conditions, opv1.OperatorStatusTypeProgressing)
		if cnd == nil || cnd.Status == opv1.ConditionFalse {
			v1helpers.SetOperatorCondition(&status.Conditions,
				opv1.OperatorCondition{
					Type:    fmt.Sprintf("%s%s", c.name, opv1.OperatorStatusTypeProgressing),
					Status:  opv1.ConditionTrue,
					Reason:  "OperatorSync",
					Message: err.Error(),
				})
		}
	} else {
		v1helpers.SetOperatorCondition(&status.Conditions,
			opv1.OperatorCondition{
				Type:   fmt.Sprintf("%s%s", c.name, opv1.OperatorStatusTypeDegraded),
				Status: opv1.ConditionFalse,
			})
		// Progressing condition was set in c.handleSync().
	}
}

func (c *CSIDriverController) handleSync(
	resourceVersion string,
	meta *metav1.ObjectMeta,
	spec *opv1.OperatorSpec,
	status *opv1.OperatorStatus,
) error {
	var controllerService *appsv1.Deployment
	if c.controllerManifest != nil {
		c, err := c.syncDeployment(spec, status)
		if err != nil {
			return fmt.Errorf("failed to sync CSI Controller Service: %v", err)
		}
		controllerService = c
	}

	var nodeService *appsv1.DaemonSet
	if c.nodeManifest != nil {
		n, err := c.syncDaemonSet(spec, status)
		if err != nil {
			return fmt.Errorf("failed to sync DaemonSet: %v", err)
		}
		nodeService = n
	}

	if err := c.syncStatus(meta, status, controllerService, nodeService); err != nil {
		return fmt.Errorf("failed to sync status: %v", err)
	}

	return nil
}

func (c *CSIDriverController) enqueue(obj interface{}) {
	c.queue.Add(c.configName)
}

func (c *CSIDriverController) eventHandler(kind string) cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			c.enqueue(obj)
		},
		UpdateFunc: func(old, new interface{}) {
			c.enqueue(new)
		},
		DeleteFunc: func(obj interface{}) {
			c.enqueue(obj)
		},
	}
}

func (c *CSIDriverController) worker() {
	for c.processNextWorkItem() {
	}
}

func (c *CSIDriverController) processNextWorkItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)

	err := c.sync()
	c.handleErr(err, key)

	return true
}

func (c *CSIDriverController) handleErr(err error, key interface{}) {
	if err == nil {
		c.queue.Forget(key)
		return
	}

	if c.queue.NumRequeues(key) < maxRetries {
		klog.V(2).Infof("Error syncing operator %v: %v", key, err)
		c.queue.AddRateLimited(key)
		return
	}

	utilruntime.HandleError(err)
	klog.V(2).Infof("Dropping operator %q out of the queue: %v", key, err)
	c.queue.Forget(key)
	c.queue.AddAfter(key, 1*time.Minute)
}

func imagesFromEnv() images {
	return images{
		csiDriver:           os.Getenv(driverImageEnvName),
		provisioner:         os.Getenv(provisionerImageEnvName),
		attacher:            os.Getenv(attacherImageEnvName),
		resizer:             os.Getenv(resizerImageEnvName),
		snapshotter:         os.Getenv(snapshotterImageEnvName),
		nodeDriverRegistrar: os.Getenv(nodeDriverRegistrarImageEnvName),
		livenessProbe:       os.Getenv(livenessProbeImageEnvName),
	}
}
