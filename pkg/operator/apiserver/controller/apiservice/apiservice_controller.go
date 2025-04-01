package apiservice

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	apiregistrationv1client "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/typed/apiregistration/v1"
	apiregistrationinformers "k8s.io/kube-aggregator/pkg/client/informers/externalversions"
	apiregistrationv1lister "k8s.io/kube-aggregator/pkg/client/listers/apiregistration/v1"

	operatorsv1 "github.com/openshift/api/operator/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceapply"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

// GetAPIServicesToMangeFunc provides list of enabled and disabled managed APIService items.
// Both lists need to always contain all the managed APIServices so the controller
// can avoid reconciling user-created/unmanaged objects.
type GetAPIServicesToMangeFunc func() (enabled []*apiregistrationv1.APIService, disabled []*apiregistrationv1.APIService, err error)
type apiServicesPreconditionFuncType func([]*apiregistrationv1.APIService) (bool, error)

type APIServiceController struct {
	controllerInstanceName   string
	getAPIServicesToManageFn GetAPIServicesToMangeFunc
	// preconditionsForEnabledAPIServices must return true before the apiservices will be created
	preconditionsForEnabledAPIServices apiServicesPreconditionFuncType

	operatorClient          v1helpers.OperatorClient
	kubeClient              kubernetes.Interface
	apiregistrationv1Client apiregistrationv1client.ApiregistrationV1Interface
	apiservicelister        apiregistrationv1lister.APIServiceLister
}

func NewAPIServiceController(
	instanceName, targetNamespace string,
	getAPIServicesToManageFunc GetAPIServicesToMangeFunc,
	operatorClient v1helpers.OperatorClient,
	apiregistrationInformers apiregistrationinformers.SharedInformerFactory,
	apiregistrationv1Client apiregistrationv1client.ApiregistrationV1Interface,
	kubeInformersForNamespaces v1helpers.KubeInformersForNamespaces,
	kubeClient kubernetes.Interface,
	eventRecorder events.Recorder,
	informers ...factory.Informer,
) factory.Controller {
	c := &APIServiceController{
		controllerInstanceName: factory.ControllerInstanceName(instanceName, "APIService"),
		preconditionsForEnabledAPIServices: preconditionsForEnabledAPIServices(
			kubeInformersForNamespaces.InformersFor(targetNamespace).Core().V1().Endpoints().Lister(),
			kubeInformersForNamespaces.InformersFor(metav1.NamespaceSystem).Core().V1().ConfigMaps().Lister(),
		),
		getAPIServicesToManageFn: getAPIServicesToManageFunc,

		operatorClient:          operatorClient,
		apiregistrationv1Client: apiregistrationv1Client,
		apiservicelister:        apiregistrationInformers.Apiregistration().V1().APIServices().Lister(),
		kubeClient:              kubeClient,
	}

	return factory.New().WithSync(c.sync).WithControllerInstanceName(c.controllerInstanceName).ResyncEvery(1*time.Minute).WithInformers(
		append(informers,
			kubeInformersForNamespaces.InformersFor(targetNamespace).Core().V1().Services().Informer(),
			kubeInformersForNamespaces.InformersFor(targetNamespace).Core().V1().Endpoints().Informer(),
			kubeInformersForNamespaces.InformersFor(metav1.NamespaceSystem).Core().V1().ConfigMaps().Informer(),
			apiregistrationInformers.Apiregistration().V1().APIServices().Informer(),
		)...,
	).ToController(c.controllerInstanceName, eventRecorder.WithComponentSuffix("apiservice-"+instanceName+"-controller"))
}

func (c *APIServiceController) updateOperatorStatus(
	ctx context.Context,
	syncDisabledAPIServicesErr error,
	preconditionReadyErr error,
	preconditionsReady bool,
	syncEnabledAPIServicesErr error,
) (err error) {
	errs := []error{}
	conditionAPIServicesDegraded := applyoperatorv1.OperatorCondition().
		WithType("APIServicesDegraded").
		WithStatus(operatorv1.ConditionFalse)

	conditionAPIServicesAvailable := applyoperatorv1.OperatorCondition().
		WithType("APIServicesAvailable").
		WithStatus(operatorv1.ConditionTrue)

	if syncDisabledAPIServicesErr != nil || preconditionReadyErr != nil || syncEnabledAPIServicesErr != nil {
		// a closed context indicates that the process has been requested to shutdown
		// in that case we might have failed to check availability of the downstream servers due to the context being closed
		// in that case don't report the failure to avoid false positives and changing the condition of the operator
		// the next process will perform the checks immediately after the startup
		select {
		case <-ctx.Done():
			if syncDisabledAPIServicesErr != nil {
				errs = append(errs, fmt.Errorf("failed to delete disabled APIs: %v", syncDisabledAPIServicesErr))
			}
			if preconditionReadyErr != nil {
				errs = append(errs, fmt.Errorf("failed to check precondition for enabled APIs: %v", preconditionReadyErr))
			}
			if syncEnabledAPIServicesErr != nil {
				errs = append(errs, fmt.Errorf("failed to reconcile enabled APIs: %v", syncEnabledAPIServicesErr))
			}
			nerr := fmt.Errorf("the operator is shutting down, skipping updating conditions, err = %v", errors.NewAggregate(errs))
			return nerr
		default:
		}
	}

	defer func() {
		status := applyoperatorv1.OperatorStatus().
			WithConditions(conditionAPIServicesDegraded, conditionAPIServicesAvailable)
		updateError := c.operatorClient.ApplyOperatorStatus(ctx, c.controllerInstanceName, status)
		if updateError != nil {
			// overrides error returned through 'return <ERROR>' statement
			err = updateError
		}
	}()

	if syncDisabledAPIServicesErr != nil {
		conditionAPIServicesDegraded = conditionAPIServicesDegraded.
			WithStatus(operatorv1.ConditionTrue).
			WithReason("DisabledAPIServicesPresent").
			WithMessage(syncDisabledAPIServicesErr.Error())
		errs = append(errs, syncDisabledAPIServicesErr)
	}

	if preconditionReadyErr != nil {
		conditionAPIServicesAvailable = conditionAPIServicesAvailable.
			WithStatus(operatorv1.ConditionFalse).
			WithReason("ErrorCheckingPrecondition").
			WithMessage(preconditionReadyErr.Error())
		errs = append(errs, preconditionReadyErr)
	} else if !preconditionsReady {
		conditionAPIServicesAvailable = conditionAPIServicesAvailable.
			WithStatus(operatorv1.ConditionFalse).
			WithReason("PreconditionNotReady").
			WithMessage("PreconditionNotReady")
		return errors.NewAggregate(errs)
	}

	if syncEnabledAPIServicesErr != nil {
		conditionAPIServicesAvailable = conditionAPIServicesAvailable.
			WithStatus(operatorv1.ConditionFalse).
			WithReason("Error").
			WithMessage(syncEnabledAPIServicesErr.Error())
		return errors.NewAggregate(append(errs, syncEnabledAPIServicesErr))
	}

	return errors.NewAggregate(errs)
}

func (c *APIServiceController) sync(ctx context.Context, syncCtx factory.SyncContext) error {
	operatorConfigSpec, _, _, err := c.operatorClient.GetOperatorState()
	if err != nil {
		return err
	}

	switch operatorConfigSpec.ManagementState {
	case operatorsv1.Managed:
	case operatorsv1.Unmanaged:
		return nil
	case operatorsv1.Removed:
		enabledApiServices, disabledApiServices, err := c.getAPIServicesToManageFn()
		if err != nil {
			return err
		}
		return c.syncDisabledAPIServices(ctx, append(enabledApiServices, disabledApiServices...))
	default:
		syncCtx.Recorder().Warningf("ManagementStateUnknown", "Unrecognized operator management state %q", operatorConfigSpec.ManagementState)
		return nil
	}

	enabledApiServices, disabledApiServices, err := c.getAPIServicesToManageFn()
	if err != nil {
		return err
	}

	var syncEnabledAPIServicesErr error

	syncDisabledAPIServicesErr := c.syncDisabledAPIServices(ctx, disabledApiServices)
	preconditionsReady, preconditionsErr := c.preconditionsForEnabledAPIServices(enabledApiServices)

	if preconditionsErr == nil && preconditionsReady {
		syncEnabledAPIServicesErr = c.syncEnabledAPIServices(ctx, enabledApiServices, syncCtx.Recorder())
	}

	return c.updateOperatorStatus(ctx, syncDisabledAPIServicesErr, preconditionsErr, preconditionsReady, syncEnabledAPIServicesErr)
}

func (c *APIServiceController) syncDisabledAPIServices(ctx context.Context, apiServices []*apiregistrationv1.APIService) error {
	errs := []error{}

	for _, apiService := range apiServices {
		if apiServiceObj, err := c.apiservicelister.Get(apiService.Name); err == nil {
			if apiServiceObj.DeletionTimestamp != nil {
				klog.Warningf("apiservices.apiregistration.k8s.io/%v not yet deleted", apiService.Name)
				continue
			}
			if err := c.apiregistrationv1Client.APIServices().Delete(ctx, apiService.Name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
				errs = append(errs, err)
			}
		} else if !apierrors.IsNotFound(err) {
			errs = append(errs, err)
		}
	}

	return errors.NewAggregate(errs)
}

func (c *APIServiceController) syncEnabledAPIServices(ctx context.Context, enabledApiServices []*apiregistrationv1.APIService, recorder events.Recorder) error {
	errs := []error{}
	var availableConditionMessages []string

	for _, apiService := range enabledApiServices {
		// Create/Update enabled APIService
		apiregistrationv1.SetDefaults_ServiceReference(apiService.Spec.Service)
		apiService, _, err := resourceapply.ApplyAPIService(ctx, c.apiregistrationv1Client, recorder, apiService)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		for _, condition := range apiService.Status.Conditions {
			if condition.Type == apiregistrationv1.Available {
				if condition.Status != apiregistrationv1.ConditionTrue {
					availableConditionMessages = append(availableConditionMessages, fmt.Sprintf("apiservices.apiregistration.k8s.io/%v: not available: %v", apiService.Name, condition.Message))
				}
				break
			}
		}
	}
	if len(errs) > 0 {
		return errors.NewAggregate(errs)
	}
	if len(availableConditionMessages) > 0 {
		sort.Sort(sort.StringSlice(availableConditionMessages))
		return fmt.Errorf("%s", strings.Join(availableConditionMessages, "\n"))
	}

	// if the apiservices themselves check out ok, try to actually hit the discovery endpoints.  We have a history in clusterup
	// of something delaying them.  This isn't perfect because of round-robining, but let's see if we get an improvement
	if c.kubeClient.Discovery().RESTClient() != nil {
		missingAPIMessages := checkDiscoveryForByAPIServices(ctx, recorder, c.kubeClient.Discovery().RESTClient(), enabledApiServices)
		availableConditionMessages = append(availableConditionMessages, missingAPIMessages...)
	}

	if len(availableConditionMessages) > 0 {
		sort.Sort(sort.StringSlice(availableConditionMessages))
		return fmt.Errorf("%s", strings.Join(availableConditionMessages, "\n"))
	}

	return nil
}
