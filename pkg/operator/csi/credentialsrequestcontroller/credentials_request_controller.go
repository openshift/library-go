package credentialsrequestcontroller

import (
	"context"
	"fmt"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"

	opv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/resource/resourcemerge"
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

// CredentialsRequestController is a simple controller that maintains a CredentialsRequest static manifest.
// It uses unstructured.Unstructured as currently there's no API type for this resource.
// This controller produces the following conditions:
// <name>Available: indicates that the secret was successfully provisioned by cloud-credential-operator.
// <name>Progressing: indicates that the secret is yet to be provisioned by cloud-credential-operator.
// <name>Degraded: produced when the sync() method returns an error.
type CredentialsRequestController struct {
	name            string
	operatorClient  v1helpers.OperatorClientWithFinalizers
	targetNamespace string
	manifest        []byte
	dynamicClient   dynamic.Interface
}

// NewCredentialsRequestController returns a CredentialsRequestController.
func NewCredentialsRequestController(
	name,
	targetNamespace string,
	manifest []byte,
	dynamicClient dynamic.Interface,
	operatorClient v1helpers.OperatorClientWithFinalizers,
	recorder events.Recorder,
) factory.Controller {
	c := &CredentialsRequestController{
		name:            name,
		operatorClient:  operatorClient,
		targetNamespace: targetNamespace,
		manifest:        manifest,
		dynamicClient:   dynamicClient,
	}
	return factory.New().WithInformers(
		operatorClient.Informer(),
	).WithSync(
		c.sync,
	).ResyncEvery(
		time.Minute,
	).WithSyncDegradedOnError(
		operatorClient,
	).ToController(
		c.name,
		recorder.WithComponentSuffix("credentials-request-controller-"+strings.ToLower(name)),
	)
}

func (c CredentialsRequestController) sync(ctx context.Context, syncContext factory.SyncContext) error {
	_, status, _, err := c.operatorClient.GetOperatorState()
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}

	cr, err := c.syncCredentialsRequest(ctx, status, syncContext)
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
		c.operatorClient,
		v1helpers.UpdateConditionFn(availableCondition),
		v1helpers.UpdateConditionFn(progressingCondition),
	)
	return err
}

func (c CredentialsRequestController) syncCredentialsRequest(
	ctx context.Context,
	status *opv1.OperatorStatus,
	syncContext factory.SyncContext,
) (*unstructured.Unstructured, error) {
	cr := resourceread.ReadCredentialRequestsOrDie(c.manifest)
	err := unstructured.SetNestedField(cr.Object, c.targetNamespace, "spec", "secretRef", "namespace")
	if err != nil {
		return nil, err
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
