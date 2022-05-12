package node

import (
	"encoding/json"
	"fmt"
	"reflect"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	listersv1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog/v2"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/library-go/pkg/operator/configobserver"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourcemerge"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

const (
	// static pod revision config maps used by installer controller to track
	// configs across different revisions
	revisionConfigMapName = "config"
	revisionConfigMapKey  = "config.yaml"
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

type revisionDiffProfileSuppressor struct {
	operatorClient  v1helpers.StaticPodOperatorClient
	configMapLister listersv1.ConfigMapNamespaceLister
	usedConfigPaths [][]string
}

// NewSuppressConfigUpdateUntilSameProfileFunc is used to create a conditional func (shouldSuppressConfigUpdatesFunc)
// that can be used by the latency profile config observer to determine if a new update to observedConfig should be rolled out or not.
// It uses a config map lister and status obtained from a static pod operator client to check if all active revisions on the cluster have
// common values for the required latency config paths or not. Config maps generated by installer controller
// are read in order to determine the current active static pod revision and compare observedConfig values from it.
func NewSuppressConfigUpdateUntilSameProfileFunc(
	operatorClient v1helpers.StaticPodOperatorClient,
	configMapLister listersv1.ConfigMapNamespaceLister,
	latencyConfigs []LatencyConfigProfileTuple,
) (f func() (bool, error)) {

	usedConfigPaths := make([][]string, len(latencyConfigs))
	for i, latencyConfig := range latencyConfigs {
		usedConfigPaths[i] = latencyConfig.ConfigPath
	}

	ret := revisionDiffProfileSuppressor{
		operatorClient:  operatorClient,
		configMapLister: configMapLister,
		usedConfigPaths: usedConfigPaths,
	}

	// creates an actual conditional fn that can be invoked each time config observer
	// intends to update observed config
	return ret.shouldSuppressConfigUpdates
}

func (s *revisionDiffProfileSuppressor) shouldSuppressConfigUpdates() (suppress bool, err error) {
	operatorSpec, operatorStatus, _, err := s.operatorClient.GetStaticPodOperatorState()
	if err != nil {
		return false, err
	}

	mergedConfigRaw, err := resourcemerge.MergeProcessConfig(
		nil,
		operatorSpec.OperatorSpec.ObservedConfig.Raw,
		operatorSpec.OperatorSpec.UnsupportedConfigOverrides.Raw,
	)
	if err != nil {
		return false, err
	}

	var mergedConfig map[string]interface{}
	err = json.Unmarshal(mergedConfigRaw, &mergedConfig)
	if err != nil {
		return false, err
	}
	mergedConfigPruned := configobserver.Pruned(mergedConfig, s.usedConfigPaths...)

	// Collect the unique set of revisions for all nodes in cluster
	uniqueRevisionMap := make(map[int32]bool)
	for _, nodeStatus := range operatorStatus.NodeStatuses {
		revision := nodeStatus.CurrentRevision
		uniqueRevisionMap[revision] = true
	}

	for revision := range uniqueRevisionMap {
		configMapNameWithRevision := fmt.Sprintf("%s-%d", revisionConfigMapName, revision)
		configMap, err := s.configMapLister.Get(configMapNameWithRevision)
		if err != nil {
			return false, err
		}

		// read observed config from current config map
		configData, ok := configMap.Data[revisionConfigMapKey]
		if !ok {
			return false, fmt.Errorf("could not find %s in %s config map from %s namespace", revisionConfigMapKey, configMap.Name, configMap.Namespace)
		}

		var currentConfig map[string]interface{}
		if err := json.Unmarshal([]byte(configData), &currentConfig); err != nil {
			return false, err
		}

		// prune the current config with only paths that is supposed to be monitored
		// and keep comparing with the current config, in case of mis match, suppress
		currentConfigPruned := configobserver.Pruned(currentConfig, s.usedConfigPaths...)
		if !reflect.DeepEqual(mergedConfigPruned, currentConfigPruned) {
			// suppress=true: when config values don't match
			return true, nil
		}
	}
	// suppress=false, when all config values are identical
	return false, nil
}
