package guard

import (
	"context"
	"fmt"
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
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
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	appsv1listers "k8s.io/client-go/listers/apps/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	policyv1listers "k8s.io/client-go/listers/policy/v1"
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

// GuardController ensures that the guarding workload is available and running
type GuardController struct {
	operatorClient         v1helpers.OperatorClient
	kubeClient             kubernetes.Interface
	podLister              corev1listers.PodLister
	nodeLister             corev1listers.NodeLister
	pdbLister              policyv1listers.PodDisruptionBudgetLister
	dsLister               appsv1listers.DaemonSetLister
	depLister              appsv1listers.DeploymentLister
	infrastructureLister   configv1listers.InfrastructureLister
	clusterTopology        configv1.TopologyMode
	replicaCount           int
	pdbName                string
	targetNamespace        string
	createGuardingWorkload bool
	manifest               []byte
	cliImagePullSpec       string
}

func NewGuardController(
	operatorClient v1helpers.OperatorClient,
	kubeClient kubernetes.Interface,
	kubeInformers v1helpers.KubeInformersForNamespaces,
	eventRecorder events.Recorder,
	infrastructureLister configv1listers.InfrastructureLister,
	createGuardingWorkload bool,
	assetFunc func(string) []byte,
	file string,
	pdbName, // This needs to be populated from env var. TODO: Make this read from manifest
	targetNamespace,
	cliImagePullSpec string,
) factory.Controller {

	c := &GuardController{
		operatorClient:         operatorClient,
		kubeClient:             kubeClient,
		podLister:              kubeInformers.InformersFor(targetNamespace).Core().V1().Pods().Lister(),
		pdbLister:              kubeInformers.InformersFor(targetNamespace).Policy().V1().PodDisruptionBudgets().Lister(),
		dsLister:               kubeInformers.InformersFor(targetNamespace).Apps().V1().DaemonSets().Lister(),
		depLister:              kubeInformers.InformersFor(targetNamespace).Apps().V1().Deployments().Lister(),
		nodeLister:             kubeInformers.InformersFor("").Core().V1().Nodes().Lister(),
		infrastructureLister:   infrastructureLister,
		createGuardingWorkload: createGuardingWorkload,
		replicaCount:           0,
		pdbName:                pdbName,
		targetNamespace:        targetNamespace,
		cliImagePullSpec:       cliImagePullSpec,
	}
	if c.createGuardingWorkload {
		c.manifest = assetFunc(file)
	}
	return factory.New().ResyncEvery(1*time.Minute).WithInformers(
		kubeInformers.InformersFor(targetNamespace).Core().V1().Pods().Informer(),
		kubeInformers.InformersFor(targetNamespace).Policy().V1().PodDisruptionBudgets().Informer(),
		kubeInformers.InformersFor(targetNamespace).Apps().V1().Deployments().Informer(),
		kubeInformers.InformersFor(targetNamespace).Apps().V1().DaemonSets().Informer(),
		kubeInformers.InformersFor("").Core().V1().Nodes().Informer(),
		operatorClient.Informer(),
	).WithSync(c.sync).ToController("GuardController", eventRecorder.WithComponentSuffix("guard-controller"))
}

func (c *GuardController) getTopologyMode() (configv1.TopologyMode, error) {
	// right now cluster topology cannot change, infrastructure cr is immutable,
	// so we set it once in order not to run api call each time
	if c.clusterTopology != "" {
		klog.V(4).Infof("HA mode is: %s", c.clusterTopology)
		return c.clusterTopology, nil
	}

	var err error
	c.clusterTopology, err = getControlPlaneTopology(c.infrastructureLister)
	if err != nil {
		klog.Errorf("Failed to get topology mode %w ", err)
		return "", err
	}

	klog.Infof("HA mode is: %s", c.clusterTopology)

	return c.clusterTopology, nil
}

func (c *GuardController) sync(ctx context.Context, syncCtx factory.SyncContext) error {
	err := c.ensureGuard(ctx, syncCtx.Recorder())
	if err != nil {
		_, _, updateErr := v1helpers.UpdateStatus(c.operatorClient, v1helpers.UpdateConditionFn(operatorv1.OperatorCondition{
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

	_, _, updateErr := v1helpers.UpdateStatus(c.operatorClient,
		v1helpers.UpdateConditionFn(operatorv1.OperatorCondition{
			Type:   "GuardControllerDegraded",
			Status: operatorv1.ConditionFalse,
			Reason: "AsExpected",
		}))
	return updateErr
}

func (c *GuardController) ensureGuard(ctx context.Context, recorder events.Recorder) error {
	haTopologyMode, err := c.getTopologyMode()
	if err != nil {
		return err
	}

	if haTopologyMode != configv1.HighlyAvailableTopologyMode {
		return nil
	}

	replicaCount, err := c.getMastersReplicaCount(ctx)
	if err != nil {
		return err
	}

	if err := c.ensureGuardingWorkload(ctx, replicaCount, recorder); err != nil {
		return err
	}

	return nil
}

// ensureGuardingWorkload ensures that the guarding workload is updated and available.
func (c *GuardController) ensureGuardingWorkload(ctx context.Context, replicaCount int32, recorder events.Recorder) error {
	// We expect the guarding workload to be created by static resource controller or other actor. Occasionally, we
	// may see errors when PDB doesn't exist but they should be resolved once static resource controller creates it
	// for us.
	pdb, err := c.kubeClient.PolicyV1().PodDisruptionBudgets(c.targetNamespace).Get(ctx, c.pdbName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	selector, err := metav1.LabelSelectorAsSelector(pdb.Spec.Selector)
	if err != nil {
		return err
	}
	matchingDep, err := c.depLister.List(selector)
	if err != nil {
		return err
	}
	opSpec, opStatus, _, err := c.operatorClient.GetOperatorState()
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}
	// As of now, we match only deployment. In future, we may go with DS & STS
	if len(matchingDep) == 0 {
		// We can have 2 scenarios here either we need to create deployment from manifest or let external entity
		// create it for us. We can decide this based on createGuardingWorkload flag
		if c.createGuardingWorkload {
			required := resourceread.ReadDeploymentV1OrDie(c.manifest)
			_, _, err := resourceapply.ApplyDeployment(
				c.kubeClient.AppsV1(),
				recorder,
				required,
				resourcemerge.ExpectedDeploymentGeneration(required, opStatus.Generations),
			)
			if err != nil {
				return err
			}

		} else {
			return fmt.Errorf("guard controller was not asked to create guarding deployment for PDB %s",
				pdb.Name)
		}
	}
	var guardDep *appsv1.Deployment
	if len(matchingDep) == 1 {
		guardDep = matchingDep[0]
		guardDep.Spec.Replicas = &replicaCount
	}
	if guardDep == nil {
		return fmt.Errorf("PDB %s has a matching workload", c.pdbName)
	}

	// Update the replicas
	// TODO: Update the image
	if opSpec.ManagementState != operatorv1.Managed {
		return nil
	}
	_, _, err = resourceapply.ApplyDeployment(
		c.kubeClient.AppsV1(),
		recorder,
		guardDep,
		resourcemerge.ExpectedDeploymentGeneration(guardDep, opStatus.Generations),
	)
	if err != nil {
		return fmt.Errorf("error updating deployment %s", guardDep.Name)
	}
	return nil
}

// getMastersReplicaCount get number of expected masters statically defined by the controlPlane replicas in the install-config.
func (c *GuardController) getMastersReplicaCount(ctx context.Context) (int32, error) {
	if c.replicaCount != 0 {
		return int32(c.replicaCount), nil
	}

	klog.Infof("Getting number of expected masters from %s", clusterConfigName)
	clusterConfig, err := c.kubeClient.CoreV1().ConfigMaps(clusterConfigNamespace).Get(ctx, clusterConfigName, metav1.GetOptions{})
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

	c.replicaCount, err = strconv.Atoi(rcD.ControlPlane.Replicas)
	if err != nil {
		klog.Errorf("failed to convert replica %s, err %w", rcD.ControlPlane.Replicas, err)
		return 0, err
	}
	return int32(c.replicaCount), nil
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
