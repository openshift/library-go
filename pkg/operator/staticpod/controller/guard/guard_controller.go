package guard

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/ghodss/yaml"

	configv1 "github.com/openshift/api/config/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	configv1listers "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/resource/resourcemerge"
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	appsv1listers "k8s.io/client-go/listers/apps/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog/v2"
)

const (
	infrastructureClusterName = "cluster"
	clusterConfigName         = "cluster-config-v1"
	clusterConfigKey          = "install-config"
	clusterConfigNamespace    = "kube-system"
)

type replicaCountDecoder struct {
	ControlPlane struct {
		Replicas string `yaml:"replicas,omitempty"`
	} `yaml:"controlPlane,omitempty"`
}

// GuardController ensures that the guarding workload and pdb are available and running
type GuardController struct {
	operatorClient       v1helpers.OperatorClient
	kubeClient           kubernetes.Interface
	deploymentLister     appsv1listers.DeploymentLister
	nodeLister           corev1listers.NodeLister
	infrastructureLister configv1listers.InfrastructureLister
	clusterTopology      configv1.TopologyMode
	replicaCount         int
	targetNamespace      string
	deploymentManifest   []byte
	pdbManifest          []byte
	cliImagePullSpec     string
	factory              *factory.Factory
	eventRecorder        events.Recorder
}

var _ factory.Controller = &GuardController{}

func NewController(operatorClient v1helpers.OperatorClient,
	kubeClient kubernetes.Interface,
	kubeInformers v1helpers.KubeInformersForNamespaces,
	eventRecorder events.Recorder,
	infrastructureLister configv1listers.InfrastructureLister,
	deploymentManifest,
	pdbManifest []byte,
	targetNamespace,
	cliImagePullSpec string) factory.Controller {
	gc := &GuardController{
		operatorClient:       operatorClient,
		kubeClient:           kubeClient,
		nodeLister:           kubeInformers.InformersFor("").Core().V1().Nodes().Lister(),
		deploymentLister:     kubeInformers.InformersFor(targetNamespace).Apps().V1().Deployments().Lister(),
		infrastructureLister: infrastructureLister,
		replicaCount:         0,
		eventRecorder:        eventRecorder,
		deploymentManifest:   deploymentManifest,
		pdbManifest:          pdbManifest,
		targetNamespace:      targetNamespace,
		cliImagePullSpec:     cliImagePullSpec,
	}
	return factory.New().ResyncEvery(1*time.Minute).WithInformers(
		kubeInformers.InformersFor(targetNamespace).Policy().V1().PodDisruptionBudgets().Informer(),
		kubeInformers.InformersFor(targetNamespace).Apps().V1().Deployments().Informer(),
		kubeInformers.InformersFor("").Core().V1().Nodes().Informer(),
		operatorClient.Informer(),
	).WithSync(gc.Sync).ToController("GuardController", eventRecorder.WithComponentSuffix("guard-controller"))
}

func (gc *GuardController) getTopologyMode() (configv1.TopologyMode, error) {
	// right now cluster topology cannot change, infrastructure cr is immutable,
	// so we set it once in order not to run api call each time
	if gc.clusterTopology != "" {
		klog.V(4).Infof("HA mode is: %s", gc.clusterTopology)
		return gc.clusterTopology, nil
	}

	var err error
	gc.clusterTopology, err = getControlPlaneTopology(gc.infrastructureLister)
	if err != nil {
		klog.Errorf("Failed to get topology mode %w ", err)
		return "", err
	}

	klog.Infof("HA mode is: %s", gc.clusterTopology)

	return gc.clusterTopology, nil
}

func (gc *GuardController) Sync(ctx context.Context, syncCtx factory.SyncContext) error {
	haTopologyMode, err := gc.getTopologyMode()
	if err != nil {
		return err
	}

	if haTopologyMode != configv1.HighlyAvailableTopologyMode {
		return nil
	}

	replicaCount, err := gc.getMastersReplicaCount(ctx)
	if err != nil {
		return err
	}
	var updateDeploymentStatuFn v1helpers.UpdateStatusFunc
	if updateDeploymentStatuFn, err = gc.ensureGuardingDeployment(replicaCount, syncCtx.Recorder()); err != nil {
		return err
	}

	if err := gc.ensureGuardingPDB(ctx, syncCtx.Recorder()); err != nil {
		return err
	}

	if err != nil {
		_, _, updateErr := v1helpers.UpdateStatus(gc.operatorClient, updateDeploymentStatuFn, v1helpers.UpdateConditionFn(operatorv1.OperatorCondition{
			Type:    "GuardControllerDegraded",
			Status:  operatorv1.ConditionTrue,
			Reason:  "Error",
			Message: err.Error(),
		}))
		if updateErr != nil {
			syncCtx.Recorder().Warning("GuardControllerUpdatingStatus", updateErr.Error())
		}
		return err
	}

	_, _, updateErr := v1helpers.UpdateStatus(gc.operatorClient, updateDeploymentStatuFn,
		v1helpers.UpdateConditionFn(operatorv1.OperatorCondition{
			Type:   "GuardControllerDegraded",
			Status: operatorv1.ConditionFalse,
			Reason: "AsExpected",
		}))
	return updateErr
}

// ensureGuardingDeployment ensures that the guarding deployment is updated and available.
func (gc *GuardController) ensureGuardingDeployment(replicaCount int32, recorder events.Recorder) (v1helpers.UpdateStatusFunc, error) {
	opSpec, opStatus, _, err := gc.operatorClient.GetOperatorState()
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	if opSpec.ManagementState != operatorv1.Managed {
		return nil, nil
	}
	guardDeployment := resourceread.ReadDeploymentV1OrDie(gc.deploymentManifest)

	guardDeployment.Spec.Replicas = &replicaCount
	// use image from release payload
	guardDeployment.Spec.Template.Spec.Containers[0].Image = gc.cliImagePullSpec

	updatedDeployment, _, err := resourceapply.ApplyDeployment(
		gc.kubeClient.AppsV1(),
		recorder,
		guardDeployment,
		resourcemerge.ExpectedDeploymentGeneration(guardDeployment, opStatus.Generations),
	)

	if err != nil {
		return nil, err
	}
	updateStatusFn := func(newStatus *operatorv1.OperatorStatus) error {
		resourcemerge.SetDeploymentGeneration(&newStatus.Generations, updatedDeployment)
		return nil
	}

	return updateStatusFn, nil
}

func (gc *GuardController) ensureGuardingPDB(ctx context.Context, recorder events.Recorder) error {
	guardPDB := resourceread.ReadPodDisruptionBudgetV1OrDie(gc.pdbManifest)

	_, _, err := resourceapply.ApplyPDB(gc.kubeClient.PolicyV1(), recorder, guardPDB)
	if err != nil {
		klog.Errorf("Failed to verify/apply %s pdb, error %w", guardPDB.Name, err)
		return err
	}
	return nil
}

// getMastersReplicaCount get number of expected masters statically defined by the controlPlane replicas in the install-config.
// TODO: Move this method to a library that can be accessed by other components.
func (gc *GuardController) getMastersReplicaCount(ctx context.Context) (int32, error) {
	if gc.replicaCount != 0 {
		return int32(gc.replicaCount), nil
	}

	klog.Infof("Getting number of expected masters from %s", clusterConfigName)
	clusterConfig, err := gc.kubeClient.CoreV1().ConfigMaps(clusterConfigNamespace).Get(ctx, clusterConfigName, metav1.GetOptions{})
	if err != nil {
		klog.Errorf("Failed to get ConfigMap %s, err %w", clusterConfigName, err)
		return 0, err
	}

	rcD := replicaCountDecoder{}
	if err := yaml.Unmarshal([]byte(clusterConfig.Data[clusterConfigKey]), &rcD); err != nil {
		err := fmt.Errorf("%s key doesn't exist in configmap/%s, err %w", clusterConfigKey, clusterConfigName, err)
		klog.Error(err)
		return 0, err
	}

	gc.replicaCount, err = strconv.Atoi(rcD.ControlPlane.Replicas)
	if err != nil {
		klog.Errorf("failed to convert replica %s, err %w", rcD.ControlPlane.Replicas, err)
		return 0, err
	}
	return int32(gc.replicaCount), nil
}

func getControlPlaneTopology(infraLister configv1listers.InfrastructureLister) (configv1.TopologyMode, error) {
	infraData, err := infraLister.Get(infrastructureClusterName)
	if err != nil {
		klog.Warningf("Failed to get infrastructure resource %s", infrastructureClusterName)
		return "", err
	}
	if infraData.Status.ControlPlaneTopology == "" {
		return "", fmt.Errorf("ControlPlaneTopology was not set")
	}

	return infraData.Status.ControlPlaneTopology, nil
}

func (gc *GuardController) Run(ctx context.Context, workers int) {
	gc.factory.WithSync(gc.Sync).ToController(gc.Name(), gc.eventRecorder).Run(ctx, workers)
}

func (gc *GuardController) Name() string {
	return "GuardController"
}
