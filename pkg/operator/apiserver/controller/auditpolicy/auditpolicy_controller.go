package auditpolicy

import (
	"context"
	"time"

	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"

	configv1 "github.com/openshift/api/config/v1"
	operatorsv1 "github.com/openshift/api/operator/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	configinformers "github.com/openshift/client-go/config/informers/externalversions"
	configv1listers "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/apiserver/audit"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	auditv1 "k8s.io/apiserver/pkg/apis/audit/v1"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/yaml"
)

type auditPolicyController struct {
	controllerInstanceName               string
	apiserverConfigLister                configv1listers.APIServerLister
	kubeClient                           kubernetes.Interface
	operatorClient                       v1helpers.OperatorClient
	targetNamespace, targetConfigMapName string
}

// NewAuditPolicyController create a controller that watches the config.openshift.io/v1 APIServer object
// and reconciles a ConfigMap in the target namespace with the audit.k8s.io/v1 policy.yaml file.
func NewAuditPolicyController(
	name string,
	targetNamespace string,
	targetConfigMapName string,
	apiserverConfigLister configv1listers.APIServerLister,
	operatorClient v1helpers.OperatorClient,
	kubeClient kubernetes.Interface,
	configInformers configinformers.SharedInformerFactory,
	kubeInformersForTargetNamesace kubeinformers.SharedInformerFactory,
	eventRecorder events.Recorder,
) factory.Controller {
	c := &auditPolicyController{
		controllerInstanceName: factory.ControllerInstanceName(name, "AuditPolicy"),
		operatorClient:         operatorClient,
		apiserverConfigLister:  apiserverConfigLister,
		kubeClient:             kubeClient,
		targetNamespace:        targetNamespace,
		targetConfigMapName:    targetConfigMapName,
	}

	return factory.New().WithSync(c.sync).ResyncEvery(10*time.Second).WithInformers(
		configInformers.Config().V1().APIServers().Informer(),
		kubeInformersForTargetNamesace.Core().V1().ConfigMaps().Informer(),
		operatorClient.Informer(),
	).ToController(
		"auditPolicyController", // don't change what is passed here unless you also remove the old FooDegraded condition
		eventRecorder.WithComponentSuffix("audit-policy-controller"),
	)
}

func (c *auditPolicyController) sync(ctx context.Context, syncCtx factory.SyncContext) error {
	operatorConfigSpec, _, _, err := c.operatorClient.GetOperatorState()
	if err != nil {
		return err
	}

	switch operatorConfigSpec.ManagementState {
	case operatorsv1.Managed:
	case operatorsv1.Unmanaged:
		return nil
	case operatorsv1.Removed:
		return c.kubeClient.CoreV1().ConfigMaps(c.targetNamespace).Delete(ctx, c.targetConfigMapName, metav1.DeleteOptions{})
	default:
		syncCtx.Recorder().Warningf("ManagementStateUnknown", "Unrecognized operator management state %q", operatorConfigSpec.ManagementState)
		return nil
	}

	config, err := c.apiserverConfigLister.Get("cluster")
	if err != nil {
		return err
	}

	err = c.syncAuditPolicy(ctx, config.Spec.Audit, syncCtx.Recorder())

	// update failing condition
	condition := applyoperatorv1.OperatorCondition().
		WithType("AuditPolicyDegraded").
		WithStatus(operatorv1.ConditionFalse)
	if err != nil {
		condition = condition.
			WithStatus(operatorv1.ConditionTrue).
			WithReason("Error").
			WithMessage(err.Error())
	}
	status := applyoperatorv1.OperatorStatus().WithConditions(condition)
	updateError := c.operatorClient.ApplyOperatorStatus(ctx, c.controllerInstanceName, status)
	if updateError != nil {
		return updateError
	}

	return err
}

func (c *auditPolicyController) syncAuditPolicy(ctx context.Context, config configv1.Audit, recorder events.Recorder) error {
	desired, err := audit.GetAuditPolicy(config)
	if err != nil {
		return err
	}
	desired = desired.DeepCopy()
	desired.Kind = "Policy"
	desired.APIVersion = auditv1.SchemeGroupVersion.String()

	bs, err := yaml.Marshal(desired)
	if err != nil {
		return err
	}

	cm := &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: c.targetNamespace,
			Name:      c.targetConfigMapName,
		},
		Data: map[string]string{
			"policy.yaml": string(bs),
		},
	}

	_, _, err = resourceapply.ApplyConfigMap(ctx, c.kubeClient.CoreV1(), recorder, cm)
	return err
}
