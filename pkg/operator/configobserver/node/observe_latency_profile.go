package node

import (
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/klog/v2"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/library-go/pkg/operator/configobserver"
	"github.com/openshift/library-go/pkg/operator/events"
)

// LatencyConfigProfileTuple is used to set arg value pairs for each worker latency profile
type LatencyConfigProfileTuple struct {
	// path to required argument in observed config
	// eg. extendedArguments.node-monitor-grace-period from observed config
	// is []string{"extendedArguments", "node-monitor-grace-period"}
	ConfigPath          []string
	ProfileConfigValues map[configv1.WorkerLatencyProfileType]string
}

type latencyProfileObserver struct {
	latencyConfigs                  []LatencyConfigProfileTuple
	shouldSuppressConfigUpdatesFunc func() (bool, error)
}

// NewLatencyProfileObserver is used to create ObserveConfigFunc that can be used with an configobservation controller to trigger
// changes to different arg val pairs in observedConfig.* fields and update them on the basis of current worker latency profile.
// ShouldSuppressConfigUpdatesFunc is used to pass a function that returns a boolean and config updates by the observer function are
// only passed iff the bool value is false, it is helpful to gate the config updates in case a pre-req condition is not satisfied.
func NewLatencyProfileObserver(latencyConfigs []LatencyConfigProfileTuple, shouldSuppressConfigUpdatesFunc func() (bool, error)) configobserver.ObserveConfigFunc {
	ret := latencyProfileObserver{
		latencyConfigs:                  latencyConfigs,
		shouldSuppressConfigUpdatesFunc: shouldSuppressConfigUpdatesFunc,
	}
	return ret.observeLatencyProfile
}

func (l *latencyProfileObserver) observeLatencyProfile(
	genericListers configobserver.Listers,
	eventRecorder events.Recorder,
	existingConfig map[string]interface{},
) (ret map[string]interface{}, errs []error) {

	// traverse list of latencyConfigs to get all the config paths
	configPaths := make([][]string, len(l.latencyConfigs))
	for i, latencyConfig := range l.latencyConfigs {
		configPaths[i] = latencyConfig.ConfigPath
	}

	defer func() {
		// Prune the observed config so that it only contains fields specific to this observer
		ret = configobserver.Pruned(ret, configPaths...)
	}()

	listers := genericListers.(NodeLister)
	configNode, err := listers.NodeLister().Get("cluster")
	// we got an error so without the node object we are not able to determine worker latency profile
	if err != nil {
		// if config/v1/node/cluster object is not found, that can be treated as a non-error case
		if !apierrors.IsNotFound(err) {
			errs = append(errs, err)
		}
		return existingConfig, errs
	}

	// if condition is not satisfied, return existing config back without any changes
	// eg. shouldSuppressConfigUpdatesFunc is to check if rollouts are in progressing state
	// then reject the update and do not set any newly observed values till the last rollout is complete
	suppress, err := l.shouldSuppressConfigUpdatesFunc()
	if err != nil {
		errs = append(errs, err)
		return existingConfig, errs
	}
	if suppress {
		// log that latency profile couldn't be updated due to conditional
		klog.Warningf("latency profile config observer did not update observed config due to unsatisified pre-requisite")
		return existingConfig, errs
	}

	if configNode.Spec.WorkerLatencyProfile == "" {
		// in case worker latency profile is not set on cluster
		return existingConfig, errs
	}

	// get the arg val pairs for currently set latency profile
	// and set observed config
	observedConfig := make(map[string]interface{})
	for _, latencyConfig := range l.latencyConfigs {
		profileValue, ok := latencyConfig.ProfileConfigValues[configNode.Spec.WorkerLatencyProfile]
		if !ok {
			// log that this is an unsupported latency profile
			// Note: In case new latency profiles are added in the future in openshift/api
			// this could break cluster upgrades although we're not passing an error here
			// to ensure that ConfigObservationController doesn't reach degraded state.
			klog.Warningf("unsupported worker latency profile found in nodes.config.openshift.io/cluster Spec.WorkerLatencyProfile = %v", configNode.Spec.WorkerLatencyProfile)
			return existingConfig, errs
		}

		err = unstructured.SetNestedStringSlice(observedConfig, []string{profileValue}, latencyConfig.ConfigPath...)
		if err != nil {
			errs = append(errs, err)
		}
	}
	// in case any error(s) were encountered
	if len(errs) > 0 {
		return existingConfig, errs
	}

	return observedConfig, errs
}
