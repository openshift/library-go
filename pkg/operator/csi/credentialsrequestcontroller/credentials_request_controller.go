package credentialsrequestcontroller

import (
	"context"
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
// TODO: the functionality in this controller should be moved to the StatisResourceController.
type CredentialsRequestController struct {
	name            string
	operatorClient  v1helpers.OperatorClient
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
	operatorClient v1helpers.OperatorClient,
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

func (c CredentialsRequestController) syncCredentialsRequest(
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

	cr, _, err = resourceapply.ApplyCredentialsRequest(c.dynamicClient, syncContext.Recorder(), cr, expectedGeneration)
	return cr, err
}

func (c CredentialsRequestController) sync(ctx context.Context, syncContext factory.SyncContext) error {
	_, status, _, err := c.operatorClient.GetOperatorState()
	if apierrors.IsNotFound(err) {
		syncContext.Recorder().Warningf("StatusNotFound", "Unable to determine current operator status for %s", c.name)
		return nil
	}
	_, err = c.syncCredentialsRequest(status, syncContext)
	return err
}
