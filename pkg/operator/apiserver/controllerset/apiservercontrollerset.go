package apiservercontrollerset

import (
	"context"
	"fmt"
	"regexp"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	configv1client "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
	openshiftconfigclientv1 "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
	configinformers "github.com/openshift/client-go/config/informers/externalversions"
	configv1informers "github.com/openshift/client-go/config/informers/externalversions/config/v1"
	configv1listers "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/apiserver/controller/apiservice"
	"github.com/openshift/library-go/pkg/operator/apiserver/controller/auditpolicy"
	"github.com/openshift/library-go/pkg/operator/apiserver/controller/nsfinalizer"
	"github.com/openshift/library-go/pkg/operator/apiserver/controller/workload"
	"github.com/openshift/library-go/pkg/operator/encryption"
	"github.com/openshift/library-go/pkg/operator/encryption/controllers"
	"github.com/openshift/library-go/pkg/operator/encryption/controllers/migrators"
	"github.com/openshift/library-go/pkg/operator/encryption/statemachine"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/loglevel"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"
	"github.com/openshift/library-go/pkg/operator/revisioncontroller"
	"github.com/openshift/library-go/pkg/operator/secretspruner"
	"github.com/openshift/library-go/pkg/operator/staticresourcecontroller"
	"github.com/openshift/library-go/pkg/operator/status"
	"github.com/openshift/library-go/pkg/operator/unsupportedconfigoverridescontroller"
	"github.com/openshift/library-go/pkg/operator/v1helpers"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/errors"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	apiregistrationv1client "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/typed/apiregistration/v1"
	apiregistrationinformers "k8s.io/kube-aggregator/pkg/client/informers/externalversions"
)

type preparedAPIServerControllerSet struct {
	controllers []controller
}

type controllerWrapper struct {
	emptyAllowed bool
	// creationError allows for reporting errors that occurred during object creation
	creationError error
	controller
}

type controller interface {
	Run(ctx context.Context, workers int)
}

func (cw *controllerWrapper) prepare() (controller, error) {
	if !cw.emptyAllowed && cw.controller == nil {
		return nil, fmt.Errorf("missing controller")
	}
	if cw.creationError != nil {
		return nil, cw.creationError
	}

	return cw.controller, nil
}

// APIServerControllerSet is a set of controllers that maintain a deployment of an API server and the namespace it's running in
type APIServerControllerSet struct {
	name           string
	operatorClient v1helpers.OperatorClient
	eventRecorder  events.Recorder

	apiServiceController            controllerWrapper
	auditPolicyController           controllerWrapper
	clusterOperatorStatusController controllerWrapper
	configUpgradableController      controllerWrapper
	encryptionControllers           encryptionControllerBuilder
	finalizerController             controllerWrapper
	logLevelController              controllerWrapper
	pruneController                 controllerWrapper
	revisionController              controllerWrapper
	staticResourceController        controllerWrapper
	workloadController              controllerWrapper
}

func NewAPIServerControllerSet(
	name string,
	operatorClient v1helpers.OperatorClient,
	eventRecorder events.Recorder,
) *APIServerControllerSet {
	apiServerControllerSet := &APIServerControllerSet{
		name:           name,
		operatorClient: operatorClient,
		eventRecorder:  eventRecorder,
	}

	return apiServerControllerSet
}

// WithConfigUpgradableController adds a controller for the operator to check for presence of
// unsupported configuration and to set the Upgradable condition to false if it finds any
func (cs *APIServerControllerSet) WithConfigUpgradableController() *APIServerControllerSet {
	cs.configUpgradableController.controller = unsupportedconfigoverridescontroller.NewUnsupportedConfigOverridesController(cs.name, cs.operatorClient, cs.eventRecorder)
	return cs
}

func (cs *APIServerControllerSet) WithoutConfigUpgradableController() *APIServerControllerSet {
	cs.configUpgradableController.controller = nil
	cs.configUpgradableController.emptyAllowed = true
	return cs
}

// WithLogLevelController adds a controller that configures logging for the operator
func (cs *APIServerControllerSet) WithLogLevelController() *APIServerControllerSet {
	cs.logLevelController.controller = loglevel.NewClusterOperatorLoggingController(cs.operatorClient, cs.eventRecorder)
	return cs
}

func (cs *APIServerControllerSet) WithoutLogLevelController() *APIServerControllerSet {
	cs.logLevelController.controller = nil
	cs.logLevelController.emptyAllowed = true
	return cs
}

func (cs *APIServerControllerSet) WithClusterOperatorStatusController(
	clusterOperatorName string,
	relatedObjects []configv1.ObjectReference,
	clusterOperatorClient configv1client.ClusterOperatorsGetter,
	clusterOperatorInformer configv1informers.ClusterOperatorInformer,
	versionRecorder status.VersionGetter,
	options ...func(*status.StatusSyncer) *status.StatusSyncer,
) *APIServerControllerSet {
	s := status.NewClusterOperatorStatusController(
		clusterOperatorName,
		relatedObjects,
		clusterOperatorClient,
		clusterOperatorInformer,
		cs.operatorClient,
		versionRecorder,
		cs.eventRecorder,
	)
	for _, opt := range options {
		s = opt(s)
	}
	cs.clusterOperatorStatusController.controller = s
	return cs
}

// WithStatusControllerPdbCompatibleHighInertia sets a custom inertia for setup where PDB slow down
// deployment: the workload deployment degraded condition happens when the number of available replicas
// does not match the desired state.  Assuming a PDB is present to ensure that we do not optionally dip below
// HA (not enforced here, but probably should be in the staticresourcecontroller check), we can safely
// allow being down a single replica for a considerable period of time.  Doing it here allows the
// detailed operator state to be fully correct (degraded instantly), while allowing graceful resolution
// in the majority of cases.
func WithStatusControllerPdbCompatibleHighInertia(workloadConditionsPrefix string) func(s *status.StatusSyncer) *status.StatusSyncer {
	return func(s *status.StatusSyncer) *status.StatusSyncer {
		return s.WithDegradedInertia(status.MustNewInertia(
			2*time.Minute,
			status.InertiaCondition{
				ConditionTypeMatcher: regexp.MustCompile(fmt.Sprintf("^%sDeploymentDegraded$", workloadConditionsPrefix)),
				Duration:             30 * time.Minute, // chosen to be longer than "normal" MCO rollout in CI.  I'm open to up to an hour.
			}).Inertia,
		)
	}
}

func (cs *APIServerControllerSet) WithoutClusterOperatorStatusController() *APIServerControllerSet {
	cs.clusterOperatorStatusController.controller = nil
	cs.clusterOperatorStatusController.emptyAllowed = true
	return cs
}

func (cs *APIServerControllerSet) WithAPIServiceController(
	controllerName, targetNamespace string,
	getAPIServicesToManageFn apiservice.GetAPIServicesToMangeFunc,
	apiregistrationInformers apiregistrationinformers.SharedInformerFactory,
	apiregistrationv1Client apiregistrationv1client.ApiregistrationV1Interface,
	kubeInformersForNamespaces v1helpers.KubeInformersForNamespaces,
	kubeClient kubernetes.Interface,
	informers ...factory.Informer,
) *APIServerControllerSet {
	cs.apiServiceController.controller = apiservice.NewAPIServiceController(
		controllerName,
		targetNamespace,
		getAPIServicesToManageFn,
		cs.operatorClient,
		apiregistrationInformers,
		apiregistrationv1Client,
		kubeInformersForNamespaces,
		kubeClient,
		cs.eventRecorder,
		informers...,
	)
	return cs
}

func (cs *APIServerControllerSet) WithoutAPIServiceController() *APIServerControllerSet {
	cs.apiServiceController.controller = nil
	cs.apiServiceController.emptyAllowed = true
	return cs
}

func (cs *APIServerControllerSet) WithFinalizerController(
	targetNamespace string,
	kubeInformersForTargetNamespace kubeinformers.SharedInformerFactory,
	namespaceGetter corev1client.NamespacesGetter,
) *APIServerControllerSet {
	cs.finalizerController.controller = nsfinalizer.NewFinalizerController(
		targetNamespace,
		kubeInformersForTargetNamespace,
		namespaceGetter,
		cs.eventRecorder,
	)
	return cs
}

func (cs *APIServerControllerSet) WithoutFinalizerController() *APIServerControllerSet {
	cs.finalizerController.controller = nil
	cs.finalizerController.emptyAllowed = true
	return cs
}

type ConditionalFiles struct {
	Files                          []string
	ShouldCreateFn, ShouldDeleteFn resourceapply.ConditionalFunction
}

func (cs *APIServerControllerSet) WithStaticResourcesController(
	controllerName string,
	manifests resourceapply.AssetFunc,
	conditionalFiles []ConditionalFiles,
	kubeInformersForNamespaces v1helpers.KubeInformersForNamespaces,
	kubeClient kubernetes.Interface,
) *APIServerControllerSet {
	ctrl := staticresourcecontroller.NewStaticResourceController(
		controllerName,
		manifests,
		nil,
		resourceapply.NewKubeClientHolder(kubeClient),
		cs.operatorClient,
		cs.eventRecorder,
	).AddKubeInformers(kubeInformersForNamespaces)

	for _, conditionalFile := range conditionalFiles {
		ctrl.WithConditionalResources(manifests, conditionalFile.Files, conditionalFile.ShouldCreateFn, conditionalFile.ShouldDeleteFn)
	}

	cs.staticResourceController.controller = ctrl

	return cs
}

func (cs *APIServerControllerSet) WithoutStaticResourcesController() *APIServerControllerSet {
	cs.staticResourceController.controller = nil
	cs.staticResourceController.emptyAllowed = true
	return cs
}

func (cs *APIServerControllerSet) WithWorkloadController(
	name, operatorNamespace, targetNamespace, targetOperandVersion, operandNamePrefix, conditionsPrefix string,
	kubeClient kubernetes.Interface,
	delegate workload.Delegate,
	openshiftClusterConfigClient openshiftconfigclientv1.ClusterOperatorInterface,
	versionRecorder status.VersionGetter,
	kubeInformersForNamespaces v1helpers.KubeInformersForNamespaces,
	informers ...factory.Informer) *APIServerControllerSet {

	workloadController := workload.NewController(
		name,
		operatorNamespace,
		targetNamespace,
		targetOperandVersion,
		operandNamePrefix,
		conditionsPrefix,
		cs.operatorClient,
		kubeClient,
		kubeInformersForNamespaces.PodLister(),
		append(informers,
			kubeInformersForNamespaces.InformersFor(targetNamespace).Core().V1().ConfigMaps().Informer(),
			kubeInformersForNamespaces.InformersFor(targetNamespace).Core().V1().Secrets().Informer(),
			kubeInformersForNamespaces.InformersFor(targetNamespace).Core().V1().Pods().Informer(),
			kubeInformersForNamespaces.InformersFor(targetNamespace).Apps().V1().Deployments().Informer(),
			kubeInformersForNamespaces.InformersFor(metav1.NamespaceSystem).Core().V1().Nodes().Informer(),
		),
		[]factory.Informer{kubeInformersForNamespaces.InformersFor(targetNamespace).Core().V1().Namespaces().Informer()},

		delegate,
		openshiftClusterConfigClient,
		cs.eventRecorder,
		versionRecorder)

	cs.workloadController.controller = workloadController
	return cs
}

func (cs *APIServerControllerSet) WithoutWorkloadController() *APIServerControllerSet {
	cs.workloadController.controller = nil
	cs.workloadController.emptyAllowed = true
	return cs
}

func (cs *APIServerControllerSet) WithRevisionController(
	targetNamespace string,
	configMaps []revisioncontroller.RevisionResource,
	secrets []revisioncontroller.RevisionResource,
	kubeInformersForTargetNamespace kubeinformers.SharedInformerFactory,
	operatorClient v1helpers.OperatorClient,
	configMapGetter corev1client.ConfigMapsGetter,
	secretGetter corev1client.SecretsGetter,
) *APIServerControllerSet {
	cs.revisionController.controller = revisioncontroller.NewRevisionController(
		cs.name,
		targetNamespace,
		configMaps,
		secrets,
		kubeInformersForTargetNamespace,
		operatorClient,
		configMapGetter,
		secretGetter,
		cs.eventRecorder,
		nil,
	)
	return cs
}

func (cs *APIServerControllerSet) WithoutRevisionController() *APIServerControllerSet {
	cs.revisionController.controller = nil
	cs.revisionController.emptyAllowed = true
	return cs
}

func (cs *APIServerControllerSet) WithSecretRevisionPruneController(
	targetNamespace string,
	secretPrefixes []string,
	secretGetter corev1client.SecretsGetter,
	podGetter corev1.PodsGetter,
	kubeInformersForTargetNamesace v1helpers.KubeInformersForNamespaces,
) *APIServerControllerSet {
	cs.pruneController.controller = secretspruner.NewSecretRevisionPruneController(
		targetNamespace,
		secretPrefixes,
		labels.SelectorFromSet(map[string]string{"apiserver": "true"}),
		secretGetter,
		kubeInformersForTargetNamesace,
		cs.eventRecorder,
	)
	return cs
}

func (cs *APIServerControllerSet) WithoutPruneController() *APIServerControllerSet {
	cs.pruneController.controller = nil
	cs.pruneController.emptyAllowed = true
	return cs
}

func (cs *APIServerControllerSet) WithEncryptionControllers(
	component string,
	provider controllers.Provider,
	deployer statemachine.Deployer,
	migrator migrators.Migrator,
	secretsClient corev1.SecretsGetter,
	apiServerClient configv1client.APIServerInterface,
	apiServerInformer configv1informers.APIServerInformer,
	kubeInformersForNamespaces v1helpers.KubeInformersForNamespaces,
	resourceSyncer *resourcesynccontroller.ResourceSyncController,
) *APIServerControllerSet {

	cs.encryptionControllers = encryptionControllerBuilder{
		operatorClient: cs.operatorClient,
		eventRecorder:  cs.eventRecorder,

		component:                  component,
		provider:                   provider,
		deployer:                   deployer,
		migrator:                   migrator,
		apiServerClient:            apiServerClient,
		apiServerInformer:          apiServerInformer,
		kubeInformersForNamespaces: kubeInformersForNamespaces,
		secretsClient:              secretsClient,
		resourceSyncer:             resourceSyncer,
	}

	return cs
}

func (cs *APIServerControllerSet) WithUnsupportedConfigPrefixForEncryptionControllers(prefix ...string) *APIServerControllerSet {
	cs.encryptionControllers.unsupportedConfigPrefix = prefix
	return cs
}

func (cs *APIServerControllerSet) WithoutEncryptionControllers() *APIServerControllerSet {
	cs.encryptionControllers.controller = nil
	cs.encryptionControllers.emptyAllowed = true
	return cs
}

func (cs *APIServerControllerSet) WithAuditPolicyController(
	targetNamespace string,
	targetConfigMapName string,
	apiserverConfigLister configv1listers.APIServerLister,
	configInformers configinformers.SharedInformerFactory,
	kubeInformersForTargetNamesace kubeinformers.SharedInformerFactory,
	kubeClient kubernetes.Interface,
) *APIServerControllerSet {
	cs.auditPolicyController.controller = auditpolicy.NewAuditPolicyController(
		cs.name,
		targetNamespace,
		targetConfigMapName,
		apiserverConfigLister,
		cs.operatorClient,
		kubeClient,
		configInformers,
		kubeInformersForTargetNamesace,
		cs.eventRecorder,
	)
	return cs
}

func (cs *APIServerControllerSet) WithoutAuditPolicyController() *APIServerControllerSet {
	cs.auditPolicyController.controller = nil
	cs.auditPolicyController.emptyAllowed = true
	return cs
}

func (cs *APIServerControllerSet) PrepareRun() (preparedAPIServerControllerSet, error) {
	prepared := []controller{}
	errs := []error{}

	for name, cw := range map[string]controllerWrapper{
		"apiServiceController":            cs.apiServiceController,
		"auditPolicyController":           cs.auditPolicyController,
		"clusterOperatorStatusController": cs.clusterOperatorStatusController,
		"configUpgradableController":      cs.configUpgradableController,
		"encryptionControllers":           cs.encryptionControllers.build(),
		"finalizerController":             cs.finalizerController,
		"logLevelController":              cs.logLevelController,
		"pruneController":                 cs.pruneController,
		"revisionController":              cs.revisionController,
		"staticResourceController":        cs.staticResourceController,
		"workloadController":              cs.workloadController,
	} {
		c, err := cw.prepare()
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %v", name, err))
			continue
		}
		if c != nil {
			prepared = append(prepared, c)
		}
	}

	return preparedAPIServerControllerSet{controllers: prepared}, errors.NewAggregate(errs)
}

func (cs *preparedAPIServerControllerSet) Run(ctx context.Context) {
	for i := range cs.controllers {
		go cs.controllers[i].Run(ctx, 1)
	}
}

type encryptionControllerBuilder struct {
	controllerWrapper

	operatorClient v1helpers.OperatorClient
	eventRecorder  events.Recorder

	component                  string
	provider                   controllers.Provider
	deployer                   statemachine.Deployer
	migrator                   migrators.Migrator
	secretsClient              corev1.SecretsGetter
	apiServerClient            configv1client.APIServerInterface
	apiServerInformer          configv1informers.APIServerInformer
	kubeInformersForNamespaces v1helpers.KubeInformersForNamespaces
	resourceSyncer             *resourcesynccontroller.ResourceSyncController

	unsupportedConfigPrefix []string
}

func (e *encryptionControllerBuilder) build() controllerWrapper {
	if e.emptyAllowed {
		return e.controllerWrapper
	}
	e.controllerWrapper.controller, e.controllerWrapper.creationError = encryption.NewControllers(
		e.component,
		e.unsupportedConfigPrefix,
		e.provider,
		e.deployer,
		e.migrator,
		e.operatorClient,
		e.apiServerClient,
		e.apiServerInformer,
		e.kubeInformersForNamespaces,
		e.secretsClient,
		e.eventRecorder,
		e.resourceSyncer,
	)

	return e.controllerWrapper
}
