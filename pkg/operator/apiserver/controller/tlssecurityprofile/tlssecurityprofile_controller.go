package tlssecurityprofile

import (
	"context"
	"errors"
	"fmt"
	"time"

	operatorsv1 "github.com/openshift/api/operator/v1"
	operatorv1 "github.com/openshift/api/operator/v1"
	configinformers "github.com/openshift/client-go/config/informers/externalversions"
	configv1listers "github.com/openshift/client-go/config/listers/config/v1"
	applyoperatorv1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1"
	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/configobserver/apiserver"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type tlsSecurityProfileController struct {
	controllerInstanceName string
	apiserverConfigLister  configv1listers.APIServerLister
	operatorClient         v1helpers.OperatorClient
	eventRecorder          events.Recorder
	callBack               func(config map[string]interface{})
	minTLSVersionPath      []string
	cipherSuitesPath       []string
	profileTypePath        []string
	lastObservedConfig     map[string]interface{}
}

// NewTLSSecurityProfileController creates a controller that watches the config.openshift.io/v1 APIServer object
// It invokes a callback with data similar to the return value of apiserver.ObserveTLSSecuritySecurityProfile
// It does not provide the profileType
func NewTLSSecurityProfileController(
	name string,
	cb func(map[string]interface{}),
	operatorClient v1helpers.OperatorClient,
	configInformers configinformers.SharedInformerFactory,
	eventRecorder events.Recorder,
) factory.Controller {
	return NewTLSSecurityProfileControllerWithPaths(name, cb, operatorClient, configInformers, eventRecorder,
		[]string{"servingInfo", "minTLSVersion"},
		[]string{"servingInfo", "cipherSuites"},
		nil)
}

// NewTLSSecurityProfileControllerToArguments creates a controller that watches the config.openshift.io/v1 APIServer object
// It invokes a callback with data similar to the return value of apiserver.ObserveTLSSecuritySecurityProfileToArguments
// It does not provide the profileType
func NewTLSSecurityProfileControllerToArguments(
	name string,
	cb func(map[string]interface{}),
	operatorClient v1helpers.OperatorClient,
	configInformers configinformers.SharedInformerFactory,
	eventRecorder events.Recorder,
) factory.Controller {
	return NewTLSSecurityProfileControllerWithPaths(name, cb, operatorClient, configInformers, eventRecorder,
		[]string{"apiServerArguments", "tls-min-version"},
		[]string{"apiServerArguments", "tls-cipher-suites"},
		nil)
}

// NewTLSSecurityProfileController creates a controller that watches the config.openshift.io/v1 APIServer object
// It invokes a callback with data formatted according to the minTLSVersionPath, cipherSuitesPath and
// profileTypePath arguments
func NewTLSSecurityProfileControllerWithPaths(
	name string,
	cb func(map[string]interface{}),
	operatorClient v1helpers.OperatorClient,
	configInformers configinformers.SharedInformerFactory,
	eventRecorder events.Recorder,
	minTLSVersionPath []string,
	cipherSuitesPath []string,
	profileTypePath []string,
) factory.Controller {
	c := &tlsSecurityProfileController{
		controllerInstanceName: factory.ControllerInstanceName(name, "TLSSecurityProfile"),
		operatorClient:         operatorClient,
		apiserverConfigLister:  configInformers.Config().V1().APIServers().Lister(),
		callBack:               cb,
		eventRecorder:          eventRecorder,
		lastObservedConfig:     make(map[string]interface{}, 0),
		minTLSVersionPath:      minTLSVersionPath,
		cipherSuitesPath:       cipherSuitesPath,
		profileTypePath:        profileTypePath,
	}

	return factory.New().WithSync(c.sync).WithControllerInstanceName(c.controllerInstanceName).ResyncEvery(1*time.Minute).WithInformers(
		configInformers.Config().V1().APIServers().Informer(),
		operatorClient.Informer(),
	).ToController(
		"TLSSecurityProfileController",
		eventRecorder.WithComponentSuffix("tls-security-profile-controller"),
	)
}

func (c *tlsSecurityProfileController) sync(ctx context.Context, syncCtx factory.SyncContext) error {
	operatorConfigSpec, _, _, err := c.operatorClient.GetOperatorState()
	if err != nil {
		return err
	}

	switch operatorConfigSpec.ManagementState {
	case operatorsv1.Managed:
	case operatorsv1.Unmanaged:
		return nil
	case operatorsv1.Removed:
		return nil
	default:
		syncCtx.Recorder().Warningf("ManagementStateUnknown", "Unrecognized operator management state %q", operatorConfigSpec.ManagementState)
		return nil
	}

	// Get the config from the TLSSecurityProfileObserver - such that the output is the same
	observedConfig, errs := apiserver.GetTLSSecurityProfileObservations(c.apiserverConfigLister, c.eventRecorder, c.lastObservedConfig, c.minTLSVersionPath, c.cipherSuitesPath, c.profileTypePath)
	err = errors.Join(errs...)

	// Invoke callback
	if err == nil {
		c.lastObservedConfig = observedConfig
		c.callBack(observedConfig)
	}

	// Update TLSSecurityProfileDegraded condition
	condition := applyoperatorv1.OperatorCondition().
		WithType("TLSSecurityProfileDegraded").
		WithStatus(operatorv1.ConditionFalse).
		WithReason("AsExpected").
		WithMessage("Using default TLSSecurityProfile")
	if len(c.profileTypePath) > 0 {
		observedProfileType, _, _ := unstructured.NestedString(observedConfig, c.profileTypePath...)
		if observedProfileType != "" {
			condition = condition.WithMessage(fmt.Sprintf("Using TLSSecurityProfile %q", observedProfileType))
		}
	}
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
