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

// LatencyProfileRejectionScenario is used to describe a scenario from and to a profile type when
// updates should be rejected in favour of cluster stability
type LatencyProfileRejectionScenario struct {
	FromProfile configv1.WorkerLatencyProfileType
	ToProfile   configv1.WorkerLatencyProfileType
}

type ShouldSuppressConfigUpdatesFunc func() (suppress bool, reason string, err error)

type latencyProfileObserver struct {
	latencyConfigs                   []LatencyConfigProfileTuple
	usedConfigPaths                  [][]string
	shouldSuppressConfigUpdatesFuncs []ShouldSuppressConfigUpdatesFunc
}

// NewLatencyProfileObserver is used to create ObserveConfigFunc that can be used with an configobservation controller to trigger
// changes to different arg val pairs in observedConfig.* fields and update them on the basis of current worker latency profile.
// ShouldSuppressConfigUpdatesFunc is used to pass a function that returns a boolean and config updates by the observer function are
// only passed iff the bool value is false, it is helpful to gate the config updates in case a pre-req condition is not satisfied.
func NewLatencyProfileObserver(latencyConfigs []LatencyConfigProfileTuple, shouldSuppressConfigUpdatesFuncs []ShouldSuppressConfigUpdatesFunc) configobserver.ObserveConfigFunc {
	ret := latencyProfileObserver{
		latencyConfigs:                   latencyConfigs,
		usedConfigPaths:                  GetUsedLatencyConfigPaths(latencyConfigs),
		shouldSuppressConfigUpdatesFuncs: shouldSuppressConfigUpdatesFuncs,
	}
	return ret.observeLatencyProfile
}

func (l *latencyProfileObserver) observeLatencyProfile(
	genericListers configobserver.Listers,
	eventRecorder events.Recorder,
	existingConfig map[string]interface{},
) (ret map[string]interface{}, errs []error) {

	defer func() {
		// Prune the observed config so that it only contains fields specific to this observer
		ret = configobserver.Pruned(ret, l.usedConfigPaths...)
	}()

	listers := genericListers.(NodeLister)
	configNode, err := listers.NodeLister().Get("cluster")
	// we got an error so without the node object we are not able to determine worker latency profile
	if err != nil {
		// if config/v1/node/cluster object is not found, that can be treated as a non-error case
		if !apierrors.IsNotFound(err) {
			errs = append(errs, err)
		} else { // but raise a warning
			klog.Warningf("nodes.config.openshift.io/cluster object could not be found")
		}
		return existingConfig, errs
	}

	for _, shouldSupressConfigUpdatesFn := range l.shouldSuppressConfigUpdatesFuncs {
		suppress, reason, err := shouldSupressConfigUpdatesFn()
		if err != nil {
			klog.Errorf("latency profile observer suppression error: %s", err)
			errs = append(errs, err)
			return existingConfig, errs
		}
		if suppress {
			// log that latency profile couldn't be updated due to conditional
			klog.Infof("latency profile config observer suppressed update to observed config: %s", reason)
			return existingConfig, errs
		}
	}

	if configNode.Spec.WorkerLatencyProfile == "" {
		// in case worker latency profile is not set on cluster
		// return empty set of configs, this helps to unset the config
		// values related to the latency profile in case we transition
		// from anyProfile -> "" (empty); also, ensures that this observer
		// to not break cluster upgrades/downgrades
		return map[string]interface{}{}, errs
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
