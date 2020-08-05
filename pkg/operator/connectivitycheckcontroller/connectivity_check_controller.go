package connectivitycheckcontroller

import (
	"context"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/api/operatorcontrolplane/v1alpha1"
	operatorcontrolplaneclient "github.com/openshift/client-go/operatorcontrolplane/clientset/versioned"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourcehelper"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

type ConnectivityCheckController interface {
	factory.Controller

	WithPodNetworkConnectivityCheckFn(podNetworkConnectivityCheckFn PodNetworkConnectivityCheckFunc) ConnectivityCheckController
}

func NewConnectivityCheckController(
	namespace string,
	operatorClient v1helpers.OperatorClient,
	operatorcontrolplaneClient *operatorcontrolplaneclient.Clientset,
	triggers []factory.Informer,
	recorder events.Recorder,
) ConnectivityCheckController {
	c := &connectivityCheckController{
		namespace:                  namespace,
		operatorClient:             operatorClient,
		operatorcontrolplaneClient: operatorcontrolplaneClient,
	}

	allTriggers := []factory.Informer{operatorClient.Informer()}
	allTriggers = append(allTriggers, triggers...)

	c.Controller = factory.New().
		WithSync(c.Sync).
		WithInformers(allTriggers...).
		ToController("ConnectivityCheckController", recorder.WithComponentSuffix("connectivity-check-controller"))
	return c
}

type connectivityCheckController struct {
	factory.Controller
	namespace                  string
	operatorClient             v1helpers.OperatorClient
	operatorcontrolplaneClient *operatorcontrolplaneclient.Clientset

	podNetworkConnectivityCheckFn PodNetworkConnectivityCheckFunc
}

type PodNetworkConnectivityCheckFunc func(ctx context.Context, syncContext factory.SyncContext) ([]*v1alpha1.PodNetworkConnectivityCheck, error)

func (c *connectivityCheckController) WithPodNetworkConnectivityCheckFn(podNetworkConnectivityCheckFn PodNetworkConnectivityCheckFunc) ConnectivityCheckController {
	c.podNetworkConnectivityCheckFn = podNetworkConnectivityCheckFn
	return c
}

func (c *connectivityCheckController) Sync(ctx context.Context, syncContext factory.SyncContext) error {
	operatorSpec, _, _, err := c.operatorClient.GetOperatorState()
	if err != nil {
		return err
	}
	switch operatorSpec.ManagementState {
	case operatorv1.Managed:
	case operatorv1.Unmanaged:
		return nil
	case operatorv1.Removed:
		return nil
	default:
		syncContext.Recorder().Warningf("ManagementStateUnknown", "Unrecognized operator management state %q", operatorSpec.ManagementState)
		return nil
	}

	checks, err := c.podNetworkConnectivityCheckFn(ctx, syncContext)
	if err != nil {
		return err
	}

	pnccClient := c.operatorcontrolplaneClient.ControlplaneV1alpha1().PodNetworkConnectivityChecks(c.namespace)
	for _, check := range checks {
		existing, err := pnccClient.Get(ctx, check.Name, metav1.GetOptions{})
		if err == nil {
			if equality.Semantic.DeepEqual(existing.Spec, check.Spec) {
				// already exists, no changes, skip
				continue
			}
			updated := existing.DeepCopy()
			updated.Spec = *check.Spec.DeepCopy()
			_, err := pnccClient.Update(ctx, updated, metav1.UpdateOptions{})
			if err != nil {
				syncContext.Recorder().Warningf("EndpointDetectionFailure", "%s: %v", resourcehelper.FormatResourceForCLIWithNamespace(check), err)
				continue
			}
			syncContext.Recorder().Eventf("EndpointCheckUpdated", "Updated %s because it changed.", resourcehelper.FormatResourceForCLIWithNamespace(check))
		}
		if apierrors.IsNotFound(err) {
			_, err = pnccClient.Create(ctx, check, metav1.CreateOptions{})
		}
		if err != nil {
			syncContext.Recorder().Warningf("EndpointDetectionFailure", "%s: %v", resourcehelper.FormatResourceForCLIWithNamespace(check), err)
			continue
		}
		syncContext.Recorder().Eventf("EndpointCheckCreated", "Created %s because it was missing.", resourcehelper.FormatResourceForCLIWithNamespace(check))
	}

	// TODO for checks which longer exist, mark them as completed

	// TODO reap old connectivity checks

	return nil
}
