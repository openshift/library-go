package csidrivernodeservicecontroller

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	opv1 "github.com/openshift/api/operator/v1"
	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/csi/csidrivercontrollerservicecontroller"
	dc "github.com/openshift/library-go/pkg/operator/deploymentcontroller"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/loglevel"
	"github.com/openshift/library-go/pkg/operator/management"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/resource/resourcemerge"
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	appsinformersv1 "k8s.io/client-go/informers/apps/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
	"k8s.io/utils/ptr"
)

const (
	driverImageEnvName              = "DRIVER_IMAGE"
	nodeDriverRegistrarImageEnvName = "NODE_DRIVER_REGISTRAR_IMAGE"
	livenessProbeImageEnvName       = "LIVENESS_PROBE_IMAGE"
	kubeRBACProxyImageEnvName       = "KUBE_RBAC_PROXY_IMAGE"
	stableGenerationAnnotationName  = "storage.openshift.io/stable-generation"
)

// DaemonSetHookFunc is a hook function to modify the DaemonSet.
type DaemonSetHookFunc func(*opv1.OperatorSpec, *appsv1.DaemonSet) error

// CSIDriverNodeServiceController is a controller that deploys a CSI Node Service to a given namespace.
//
// The CSI Node Service is represented by a DaemonSet. This DaemonSet deploys a pod with the CSI driver
// and sidecars containers (node-driver-registrar and liveness-probe) to all nodes.
//
// On every sync, this controller reads the DaemonSet from a static file and overrides a few fields:
//
// 1. Container image locations
//
// The controller will replace the images specified in the static file if their name follows a certain nomenclature AND its
// respective environemnt variable is set. This is a list of environment variables that the controller understands:
//
// DRIVER_IMAGE
// NODE_DRIVER_REGISTRAR_IMAGE
// LIVENESS_PROBE_IMAGE
//
// The names above should be wrapped by a ${}, e.g., ${DIVER_IMAGE} in static file.
//
// 2. Log level
//
// The controller can also override the log level passed in to the CSI driver container.
// In order to do that, the placeholder ${LOG_LEVEL} from the manifest file is replaced with the value specified
// in the OperatorClient resource (Spec.LogLevel).
//
// This controller supports removable operands, as configured in pkg/operator/management.
//
// This controller produces the following conditions:
//
// <name>Available: indicates that the CSI Node Service was successfully deployed.
// <name>Progressing: indicates that the CSI Node Service is being deployed.
// <name>Degraded: produced when the sync() method returns an error.
type CSIDriverNodeServiceController struct {
	// instanceName is the name to identify what instance this belongs too: FooDriver for instance
	instanceName string
	// controllerInstanceName is the name to identify this instance of this particular control loop: FooDriver-CSIDriverNodeService for instance.
	controllerInstanceName string
	manifest               []byte
	operatorClient         v1helpers.OperatorClientWithFinalizers
	kubeClient             kubernetes.Interface
	dsInformer             appsinformersv1.DaemonSetInformer
	// Optional hook functions to modify the DaemonSet.
	// If one of these functions returns an error, the sync
	// fails indicating the ordinal position of the failed function.
	// Also, in that scenario the Degraded status is set to True.
	optionalDaemonSetHooks []DaemonSetHookFunc
	optionalManifestHooks  []dc.ManifestHookFunc
}

func NewCSIDriverNodeServiceController(
	instanceName string,
	manifest []byte,
	recorder events.Recorder,
	operatorClient v1helpers.OperatorClientWithFinalizers,
	kubeClient kubernetes.Interface,
	dsInformer appsinformersv1.DaemonSetInformer,
	optionalInformers []factory.Informer,
	optionalDaemonSetHooks ...DaemonSetHookFunc,
) factory.Controller {
	c := &CSIDriverNodeServiceController{
		instanceName:           instanceName,
		controllerInstanceName: factory.ControllerInstanceName(instanceName, "CSIDriverNodeService"),
		manifest:               manifest,
		operatorClient:         operatorClient,
		kubeClient:             kubeClient,
		dsInformer:             dsInformer,
		optionalDaemonSetHooks: optionalDaemonSetHooks,
		optionalManifestHooks: []dc.ManifestHookFunc{
			csidrivercontrollerservicecontroller.WithServingInfo(),
		},
	}
	informers := append(optionalInformers, operatorClient.Informer(), dsInformer.Informer())
	return factory.New().WithInformers(
		informers...,
	).WithSync(
		c.sync,
	).WithControllerInstanceName(
		c.controllerInstanceName,
	).ResyncEvery(
		time.Minute,
	).WithSyncDegradedOnError(
		operatorClient,
	).ToController(
		c.instanceName, // don't change what is passed here unless you also remove the old FooDegraded condition
		recorder.WithComponentSuffix("csi-driver-node-service_"+strings.ToLower(instanceName)),
	)
}

func (c *CSIDriverNodeServiceController) Name() string {
	return c.instanceName
}

func (c *CSIDriverNodeServiceController) sync(ctx context.Context, syncContext factory.SyncContext) error {
	opSpec, opStatus, _, err := c.operatorClient.GetOperatorState()
	if errors.IsNotFound(err) && management.IsOperatorRemovable() {
		return nil
	}
	if err != nil {
		return err
	}

	if opSpec.ManagementState == opv1.Removed && management.IsOperatorRemovable() {
		return c.syncDeleting(ctx, opSpec, opStatus, syncContext)
	}

	if opSpec.ManagementState != opv1.Managed {
		return nil
	}

	meta, err := c.operatorClient.GetObjectMeta()
	if err != nil {
		return err
	}
	if management.IsOperatorRemovable() && meta.DeletionTimestamp != nil {
		return c.syncDeleting(ctx, opSpec, opStatus, syncContext)
	}
	return c.syncManaged(ctx, opSpec, opStatus, syncContext)
}

func (c *CSIDriverNodeServiceController) syncManaged(ctx context.Context, opSpec *opv1.OperatorSpec, opStatus *opv1.OperatorStatus, syncContext factory.SyncContext) error {
	klog.V(4).Infof("syncManaged")
	if management.IsOperatorRemovable() {
		if err := v1helpers.EnsureFinalizer(ctx, c.operatorClient, c.instanceName); err != nil {
			return err
		}
	}

	required, err := c.getDaemonSet(opSpec)
	if err != nil {
		return err
	}

	daemonSet, _, err := resourceapply.ApplyDaemonSet(
		ctx,
		c.kubeClient.AppsV1(),
		syncContext.Recorder(),
		required,
		resourcemerge.ExpectedDaemonSetGeneration(required, opStatus.Generations),
	)
	if err != nil {
		return err
	}

	daemonSet, err = c.storeLastStableGeneration(ctx, syncContext, daemonSet)
	if err != nil {
		return err
	}

	// Create an OperatorStatusApplyConfiguration with generations
	status := applyoperatorv1.OperatorStatus().
		WithGenerations(&applyoperatorv1.GenerationStatusApplyConfiguration{
			Group:          ptr.To("apps"),
			Resource:       ptr.To("daemonsets"),
			Namespace:      ptr.To(daemonSet.Namespace),
			Name:           ptr.To(daemonSet.Name),
			LastGeneration: ptr.To(daemonSet.Generation),
		})

	// Set Available condition
	availableCondition := applyoperatorv1.OperatorCondition().
		WithType(c.instanceName + opv1.OperatorStatusTypeAvailable).
		WithStatus(opv1.ConditionTrue)

	if daemonSet.Status.NumberAvailable > 0 {
		availableCondition = availableCondition.
			WithStatus(opv1.ConditionTrue).
			WithMessage("DaemonSet is available").
			WithReason("AsExpected")

	} else {
		availableCondition = availableCondition.
			WithStatus(opv1.ConditionFalse).
			WithMessage("Waiting for the DaemonSet to deploy the CSI Node Service").
			WithReason("Deploying")
	}
	status = status.WithConditions(availableCondition)

	// Set Progressing condition
	progressingCondition := applyoperatorv1.OperatorCondition().
		WithType(c.instanceName + opv1.OperatorStatusTypeProgressing).
		WithStatus(opv1.ConditionFalse).
		WithMessage("DaemonSet is not progressing").
		WithReason("AsExpected")

	if ok, msg := isProgressing(daemonSet); ok {
		progressingCondition = progressingCondition.
			WithStatus(opv1.ConditionTrue).
			WithMessage(msg).
			WithReason("Deploying")
	}
	status = status.WithConditions(progressingCondition)

	return c.operatorClient.ApplyOperatorStatus(
		ctx,
		c.controllerInstanceName,
		status,
	)
}

func (c *CSIDriverNodeServiceController) getDaemonSet(opSpec *opv1.OperatorSpec) (*appsv1.DaemonSet, error) {
	manifest := replacePlaceholders(c.manifest, opSpec)

	for i, hook := range c.optionalManifestHooks {
		var err error
		manifest, err = hook(opSpec, manifest)
		if err != nil {
			return nil, fmt.Errorf("error running manifest hook (index=%d): %w", i, err)
		}
	}
	required := resourceread.ReadDaemonSetV1OrDie(manifest)

	for i := range c.optionalDaemonSetHooks {
		err := c.optionalDaemonSetHooks[i](opSpec, required)
		if err != nil {
			return nil, fmt.Errorf("error running hook function (index=%d): %w", i, err)
		}
	}
	return required, nil
}

func isProgressing(daemonSet *appsv1.DaemonSet) (bool, string) {
	// Progressing means "[the component] is actively rolling out new code, propagating config
	// changes (e.g, a version change), or otherwise moving from one steady state to another."
	// This controller expects that all "config changes" result in increased DaemonSet generation
	// (i.e. DaemonSet .spec changes)
	// The controller stores the last "stable" DS generation in an annotation.
	// Stable means that all DS replicas are available and at the latest version.
	// Any subsequent missing replicas must be caused by a node added / removed / rebooted /
	// pod manually killed, which then does not result in Progressing=true.
	lastStableGeneration := daemonSet.Annotations[stableGenerationAnnotationName]
	currentGeneration := strconv.FormatInt(daemonSet.Generation, 10)
	if lastStableGeneration == currentGeneration {
		// The previous reconfiguration has completed in the past.
		return false, ""
	}

	switch {
	case daemonSet.Generation != daemonSet.Status.ObservedGeneration:
		return true, "Waiting for DaemonSet to act on changes"
	case daemonSet.Status.UpdatedNumberScheduled < daemonSet.Status.DesiredNumberScheduled:
		return true, fmt.Sprintf("Waiting for DaemonSet to update %d node pods", daemonSet.Status.DesiredNumberScheduled)
	case daemonSet.Status.NumberUnavailable > 0:
		return true, "Waiting for DaemonSet to deploy node pods"
	}
	return false, ""
}

func replacePlaceholders(manifest []byte, spec *opv1.OperatorSpec) []byte {
	pairs := []string{}

	// Replace container images by env vars if they are set
	csiDriver := os.Getenv(driverImageEnvName)
	if csiDriver != "" {
		pairs = append(pairs, []string{"${DRIVER_IMAGE}", csiDriver}...)
	}

	nodeDriverRegistrar := os.Getenv(nodeDriverRegistrarImageEnvName)
	if nodeDriverRegistrar != "" {
		pairs = append(pairs, []string{"${NODE_DRIVER_REGISTRAR_IMAGE}", nodeDriverRegistrar}...)

	}

	livenessProbe := os.Getenv(livenessProbeImageEnvName)
	if livenessProbe != "" {
		pairs = append(pairs, []string{"${LIVENESS_PROBE_IMAGE}", livenessProbe}...)
	}

	kubeRBACProxy := os.Getenv(kubeRBACProxyImageEnvName)
	if kubeRBACProxy != "" {
		pairs = append(pairs, []string{"${KUBE_RBAC_PROXY_IMAGE}", kubeRBACProxy}...)
	}

	// Log level
	logLevel := loglevel.LogLevelToVerbosity(spec.LogLevel)
	pairs = append(pairs, []string{"${LOG_LEVEL}", strconv.Itoa(logLevel)}...)

	replaced := strings.NewReplacer(pairs...).Replace(string(manifest))
	return []byte(replaced)
}

func (c *CSIDriverNodeServiceController) syncDeleting(ctx context.Context, opSpec *opv1.OperatorSpec, opStatus *opv1.OperatorStatus, syncContext factory.SyncContext) error {
	klog.V(4).Infof("syncDeleting")
	required, err := c.getDaemonSet(opSpec)
	if err != nil {
		return err
	}

	err = c.kubeClient.AppsV1().DaemonSets(required.Namespace).Delete(ctx, required.Name, metav1.DeleteOptions{})
	if err != nil && !errors.IsNotFound(err) {
		return err
	} else {
		klog.V(2).Infof("Deleted DaemonSet %s/%s", required.Namespace, required.Name)
	}

	// All removed, remove the finalizer as the last step
	return v1helpers.RemoveFinalizer(ctx, c.operatorClient, c.instanceName)
}

func (c *CSIDriverNodeServiceController) storeLastStableGeneration(ctx context.Context, syncContext factory.SyncContext, daemonSet *appsv1.DaemonSet) (*appsv1.DaemonSet, error) {
	lastStableGeneration := daemonSet.Annotations[stableGenerationAnnotationName]
	currentGeneration := strconv.FormatInt(daemonSet.Generation, 10)
	if lastStableGeneration == currentGeneration {
		return daemonSet, nil
	}

	if isProgressing, _ := isProgressing(daemonSet); isProgressing {
		return daemonSet, nil
	}

	klog.V(2).Infof("DaemonSet %s/%s generation %d is stable", daemonSet.Namespace, daemonSet.Name, daemonSet.Generation)
	daemonSet.Annotations[stableGenerationAnnotationName] = currentGeneration
	daemonSet, _, err := resourceapply.ApplyDaemonSet(ctx, c.kubeClient.AppsV1(), syncContext.Recorder(), daemonSet, daemonSet.Generation)
	return daemonSet, err
}
