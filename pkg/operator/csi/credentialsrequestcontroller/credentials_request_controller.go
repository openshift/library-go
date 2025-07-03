package credentialsrequestcontroller

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"k8s.io/klog/v2"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"

	opv1 "github.com/openshift/api/operator/v1"
	operatorinformer "github.com/openshift/client-go/operator/informers/externalversions"
	operatorv1lister "github.com/openshift/client-go/operator/listers/operator/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/resource/resourcemerge"
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

const (
	clusterCloudCredentialName = "cluster"
	EnvVarsAnnotationKey       = "credentials.openshift.io/role-arns-vars"
)

// CredentialsRequestController is a simple controller that maintains a CredentialsRequest static manifest.
// It uses unstructured.Unstructured as currently there's no API type for this resource.
// This controller produces the following conditions:
// <name>Available: indicates that the secret was successfully provisioned by cloud-credential-operator.
// <name>Progressing: indicates that the secret is yet to be provisioned by cloud-credential-operator.
// <name>Degraded: produced when the sync() method returns an error.
// The controller does not sync the CredentialsRequest if the cloud-credential-operator is in manual mode and
// STS (or other short-term credentials) are not enabled, or STS is enabled, but the controller does not see
// required env. vars set.
// For AWS STS, the controller needs ROLEARN env. var set.
// For GCP WIF, the controller needs POOL_ID, PROVIDER_ID, SERVICE_ACCOUNT_EMAIL, PROJECT_NUMBER env. vars set.
// The controller also supports a custom annotation "credentials.openshift.io/role-arns-vars" on the CredentialsRequest
// that allows to specify the comma-separated list of env. vars that should be used to set the role ARNs.
type CredentialsRequestController struct {
	name            string
	operatorClient  v1helpers.OperatorClientWithFinalizers
	targetNamespace string
	manifest        []byte
	dynamicClient   dynamic.Interface
	operatorLister  operatorv1lister.CloudCredentialLister
	hooks           []CredentialsRequestHook
}

type CredentialsRequestHook func(*opv1.OperatorSpec, *unstructured.Unstructured) error

// NewCredentialsRequestController returns a CredentialsRequestController.
func NewCredentialsRequestController(
	name,
	targetNamespace string,
	manifest []byte,
	dynamicClient dynamic.Interface,
	operatorClient v1helpers.OperatorClientWithFinalizers,
	operatorInformer operatorinformer.SharedInformerFactory,
	recorder events.Recorder,
	hooks ...CredentialsRequestHook,
) factory.Controller {
	c := &CredentialsRequestController{
		name:            name,
		operatorClient:  operatorClient,
		targetNamespace: targetNamespace,
		manifest:        manifest,
		dynamicClient:   dynamicClient,
		operatorLister:  operatorInformer.Operator().V1().CloudCredentials().Lister(),
		hooks:           hooks,
	}
	return factory.New().WithInformers(
		operatorClient.Informer(),
		operatorInformer.Operator().V1().CloudCredentials().Informer(),
	).WithSync(
		c.sync,
	).ResyncEvery(
		time.Minute,
	).WithSyncDegradedOnError(
		operatorClient,
	).ToController(
		c.name, // don't change what is passed here unless you also remove the old FooDegraded condition
		recorder.WithComponentSuffix("credentials-request-controller-"+strings.ToLower(name)),
	)
}

func (c CredentialsRequestController) sync(ctx context.Context, syncContext factory.SyncContext) error {
	spec, status, _, err := c.operatorClient.GetOperatorState()
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if spec.ManagementState != opv1.Managed {
		return nil
	}

	cr := resourceread.ReadCredentialRequestsOrDie(c.manifest)

	sync, err := shouldSync(c.operatorLister, cr)
	if err != nil {
		return err
	}
	if !sync {
		return c.cleanConditions(ctx)
	}

	cr, err = c.syncCredentialsRequest(ctx, spec, status, cr, syncContext)
	if err != nil {
		return err
	}

	isCredentialsProvisioned, err := isProvisioned(cr)
	if err != nil {
		return err
	}

	availableCondition := opv1.OperatorCondition{
		Type:   c.name + opv1.OperatorStatusTypeAvailable,
		Status: opv1.ConditionTrue,
	}

	progressingCondition := opv1.OperatorCondition{
		Type:   c.name + opv1.OperatorStatusTypeProgressing,
		Status: opv1.ConditionFalse,
	}

	if !isCredentialsProvisioned {
		availableCondition.Status = opv1.ConditionFalse
		availableCondition.Message = "Credentials not yet provisioned by cloud-credential-operator"
		availableCondition.Reason = "CredentialsNotProvisionedYet"
		progressingCondition.Status = opv1.ConditionTrue
		progressingCondition.Message = "Waiting for cloud-credential-operator to provision the credentials"
		progressingCondition.Reason = "CredentialsNotProvisionedYet"
	}

	_, _, err = v1helpers.UpdateStatus(
		ctx,
		c.operatorClient,
		v1helpers.UpdateConditionFn(availableCondition),
		v1helpers.UpdateConditionFn(progressingCondition),
	)
	return err
}

func (c CredentialsRequestController) syncCredentialsRequest(
	ctx context.Context,
	spec *opv1.OperatorSpec,
	status *opv1.OperatorStatus,
	cr *unstructured.Unstructured,
	syncContext factory.SyncContext,
) (*unstructured.Unstructured, error) {
	err := unstructured.SetNestedField(cr.Object, c.targetNamespace, "spec", "secretRef", "namespace")
	if err != nil {
		return nil, err
	}

	for _, hook := range c.hooks {
		if err := hook(spec, cr); err != nil {
			return nil, err
		}
	}

	var expectedGeneration int64 = -1
	generation := resourcemerge.GenerationFor(
		status.Generations,
		schema.GroupResource{
			Group:    resourceapply.CredentialsRequestGroup,
			Resource: resourceapply.CredentialsRequestResource,
		},
		cr.GetNamespace(),
		cr.GetName())
	if generation != nil {
		expectedGeneration = generation.LastGeneration
	}

	cr, _, err = resourceapply.ApplyCredentialsRequest(ctx, c.dynamicClient, syncContext.Recorder(), cr, expectedGeneration)
	return cr, err
}

// cleanConditions cleans up the conditions when the controller does not sync any credentials request.
func (c CredentialsRequestController) cleanConditions(ctx context.Context) error {
	availableCondition := opv1.OperatorCondition{
		Type:    c.name + opv1.OperatorStatusTypeAvailable,
		Status:  opv1.ConditionTrue,
		Message: "No role for short time token provided",
		Reason:  "CredentialsDisabled",
	}

	progressingCondition := opv1.OperatorCondition{
		Type:    c.name + opv1.OperatorStatusTypeProgressing,
		Status:  opv1.ConditionFalse,
		Message: "",
		Reason:  "AsExpected",
	}
	_, _, err := v1helpers.UpdateStatus(
		ctx,
		c.operatorClient,
		v1helpers.UpdateConditionFn(availableCondition),
		v1helpers.UpdateConditionFn(progressingCondition),
	)
	return err
}

func isProvisioned(cr *unstructured.Unstructured) (bool, error) {
	provisionedVal, found, err := unstructured.NestedFieldNoCopy(cr.Object, "status", "provisioned")
	if err != nil {
		return false, fmt.Errorf("error reading status.provisioned field from %q: %v", cr.GetName(), err)
	}

	if !found {
		return false, nil
	}

	if provisionedVal == nil {
		return false, fmt.Errorf("invalid status.provisioned field in %q", cr.GetName())
	}

	provisionedValBool, ok := provisionedVal.(bool)
	if !ok {
		return false, fmt.Errorf("invalid status.provisioned field in %q: expected a boolean", cr.GetName())
	}

	return provisionedValBool, nil
}

func shouldSync(cloudCredentialLister operatorv1lister.CloudCredentialLister, cr *unstructured.Unstructured) (bool, error) {
	clusterCloudCredential, err := cloudCredentialLister.Get(clusterCloudCredentialName)
	if err != nil {
		klog.Errorf("Failed to get cluster cloud credential: %v", err)
		return false, err
	}

	isManualMode := clusterCloudCredential.Spec.CredentialsMode == opv1.CloudCredentialsModeManual

	if !isManualMode {
		// Return early, always sync in non-manual mode
		return true, nil
	}

	// Manual mode. Sync only when env. vars with the role ARNs are present.

	if envVars := getEnvVarsFromAnnotations(cr); envVars != nil {
		allEnvVarsFound := true
		for _, envVar := range envVars {
			if os.Getenv(envVar) == "" {
				allEnvVarsFound = false
				break
			}
		}
		// The CredentialsRequest has explicitly asked for some env. vars. via the annotation.
		// Don't check the default env. vars below, because they are not relevant for thiss CredentialsRequest.
		return allEnvVarsFound, nil
	}

	// Default env. vars for AWS STS
	isAWSSTSEnabled := os.Getenv("ROLEARN") != ""
	if isAWSSTSEnabled {
		return true, nil
	}

	// Default env. vars for GCE WIF
	poolID := os.Getenv("POOL_ID")
	providerID := os.Getenv("PROVIDER_ID")
	serviceAccountEmail := os.Getenv("SERVICE_ACCOUNT_EMAIL")
	projectNumber := os.Getenv("PROJECT_NUMBER")
	isGCPWIFEnabled := poolID != "" && providerID != "" && serviceAccountEmail != "" && projectNumber != ""
	if isGCPWIFEnabled {
		return true, nil
	}

	// CCO is in manual mode, but some ARN env. vars are missing -> don't sync
	return false, nil
}

func getEnvVarsFromAnnotations(cr *unstructured.Unstructured) []string {
	annotations := cr.GetAnnotations()
	if annotations == nil {
		return nil
	}
	envVars, found := annotations[EnvVarsAnnotationKey]
	if !found {
		return nil
	}
	envVarsList := strings.Split(envVars, ",")
	return envVarsList
}
