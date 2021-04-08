package csidrivernodeservicecontroller

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	appsinformersv1 "k8s.io/client-go/informers/apps/v1"
	"k8s.io/client-go/kubernetes"

	opv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/loglevel"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/resource/resourcemerge"
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

const (
	driverImageEnvName              = "DRIVER_IMAGE"
	nodeDriverRegistrarImageEnvName = "NODE_DRIVER_REGISTRAR_IMAGE"
	livenessProbeImageEnvName       = "LIVENESS_PROBE_IMAGE"
	kubeRBACProxyImageEnvName       = "KUBE_RBAC_PROXY_IMAGE"
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
// This controller produces the following conditions:
//
// <name>Available: indicates that the CSI Node Service was successfully deployed.
// <name>Progressing: indicates that the CSI Node Service is being deployed.
// <name>Degraded: produced when the sync() method returns an error.
type CSIDriverNodeServiceController struct {
	name           string
	manifest       []byte
	operatorClient v1helpers.OperatorClient
	kubeClient     kubernetes.Interface
	dsInformer     appsinformersv1.DaemonSetInformer
	// Optional hook functions to modify the DaemonSet.
	// If one of these functions returns an error, the sync
	// fails indicating the ordinal position of the failed function.
	// Also, in that scenario the Degraded status is set to True.
	optionalDaemonSetHooks []DaemonSetHookFunc
}

func NewCSIDriverNodeServiceController(
	name string,
	manifest []byte,
	operatorClient v1helpers.OperatorClient,
	kubeClient kubernetes.Interface,
	dsInformer appsinformersv1.DaemonSetInformer,
	recorder events.Recorder,
	optionalDaemonSetHooks ...DaemonSetHookFunc,
) factory.Controller {
	c := &CSIDriverNodeServiceController{
		name:                   name,
		manifest:               manifest,
		operatorClient:         operatorClient,
		kubeClient:             kubeClient,
		dsInformer:             dsInformer,
		optionalDaemonSetHooks: optionalDaemonSetHooks,
	}

	return factory.New().WithInformers(
		operatorClient.Informer(),
		dsInformer.Informer(),
	).WithSync(
		c.sync,
	).ResyncEvery(
		time.Minute,
	).WithSyncDegradedOnError(
		operatorClient,
	).ToController(
		c.name,
		recorder.WithComponentSuffix("csi-driver-node-service_"+strings.ToLower(name)),
	)
}

func (c *CSIDriverNodeServiceController) Name() string {
	return c.name
}

func (c *CSIDriverNodeServiceController) sync(ctx context.Context, syncContext factory.SyncContext) error {
	opSpec, opStatus, _, err := c.operatorClient.GetOperatorState()
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}

	if opSpec.ManagementState != opv1.Managed {
		return nil
	}

	manifest := replacePlaceholders(c.manifest, opSpec)
	required := resourceread.ReadDaemonSetV1OrDie(manifest)

	for i := range c.optionalDaemonSetHooks {
		err := c.optionalDaemonSetHooks[i](opSpec, required)
		if err != nil {
			return fmt.Errorf("error running hook function (index=%d): %w", i, err)
		}
	}

	daemonSet, _, err := resourceapply.ApplyDaemonSet(
		c.kubeClient.AppsV1(),
		syncContext.Recorder(),
		required,
		resourcemerge.ExpectedDaemonSetGeneration(required, opStatus.Generations),
	)
	if err != nil {
		return err
	}

	availableCondition := opv1.OperatorCondition{
		Type:   c.name + opv1.OperatorStatusTypeAvailable,
		Status: opv1.ConditionTrue,
	}

	if daemonSet.Status.NumberAvailable > 0 {
		availableCondition.Status = opv1.ConditionTrue
	} else {
		availableCondition.Status = opv1.ConditionFalse
		availableCondition.Message = "Waiting for the DaemonSet to deploy the CSI Node Service"
		availableCondition.Reason = "Deploying"
	}

	progressingCondition := opv1.OperatorCondition{
		Type:   c.name + opv1.OperatorStatusTypeProgressing,
		Status: opv1.ConditionFalse,
	}

	if ok, msg := isProgressing(opStatus, daemonSet); ok {
		progressingCondition.Status = opv1.ConditionTrue
		progressingCondition.Message = msg
		progressingCondition.Reason = "Deploying"
	}

	updateStatusFn := func(newStatus *opv1.OperatorStatus) error {
		// TODO: set ObservedGeneration (the last stable generation change we dealt with)
		resourcemerge.SetDaemonSetGeneration(&newStatus.Generations, daemonSet)
		return nil
	}

	_, _, err = v1helpers.UpdateStatus(
		c.operatorClient,
		updateStatusFn,
		v1helpers.UpdateConditionFn(availableCondition),
		v1helpers.UpdateConditionFn(progressingCondition),
	)

	return err
}

func isProgressing(status *opv1.OperatorStatus, daemonSet *appsv1.DaemonSet) (bool, string) {
	switch {
	case daemonSet.Generation != daemonSet.Status.ObservedGeneration:
		return true, "Waiting for DaemonSet to act on changes"
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
