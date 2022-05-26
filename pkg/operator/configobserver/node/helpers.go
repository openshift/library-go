package node

import (
	"reflect"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	configv1 "github.com/openshift/api/config/v1"
	v1 "github.com/openshift/api/operator/v1"
)

// GetUsedLatencyConfigPaths is used to get list of config paths that were used for latency profiles
func GetUsedLatencyConfigPaths(latencyConfigs []LatencyConfigProfileTuple) [][]string {
	usedConfigPaths := make([][]string, len(latencyConfigs))
	for i, latencyConfig := range latencyConfigs {
		usedConfigPaths[i] = latencyConfig.ConfigPath
	}
	return usedConfigPaths
}

// GenerateConfigsForEachLatencyProfile is used to generate config for each latency profile using known arg val pairs provided in latencyConfigs
func GenerateConfigsForEachLatencyProfile(latencyConfigs []LatencyConfigProfileTuple) (profileConfigs map[configv1.WorkerLatencyProfileType]map[string]interface{}, err error) {
	profileConfigs = make(map[configv1.WorkerLatencyProfileType]map[string]interface{})
	// traverse along each latency config to construct a config arg val map for each known profile
	for _, latencyConfig := range latencyConfigs {
		for profile := range latencyConfig.ProfileConfigValues {
			profileValue := latencyConfig.ProfileConfigValues[profile]

			if _, ok := profileConfigs[profile]; !ok {
				profileConfigs[profile] = make(map[string]interface{})
			}
			err = unstructured.SetNestedStringSlice(profileConfigs[profile], []string{profileValue}, latencyConfig.ConfigPath...)
			if err != nil {
				return nil, err
			}
		}
	}
	return profileConfigs, nil
}

// ShouldRejectProfileTransition is used to determine the profile passed in fromLatencyConfig
// (fromLatencyConfig should be config that already has only usedLatencyConfigPaths pruned)
// and in case the transition fromProfile -> toProfile is one of the rejected scenarios, reject it
// i.e. isRejected flag will be true
func ShouldRejectProfileTransition(
	fromLatencyConfig map[string]interface{}, toProfile configv1.WorkerLatencyProfileType,
	knownProfileConfigs map[configv1.WorkerLatencyProfileType]map[string]interface{},
	profileRejectionScenarios []LatencyProfileRejectionScenario,
) (isRejected bool, fromProfile configv1.WorkerLatencyProfileType) {
	// determine which profile was in the already pruned config
	for profile := range knownProfileConfigs {
		if reflect.DeepEqual(fromLatencyConfig, knownProfileConfigs[profile]) {
			fromProfile = profile
			break
		}
	} // fromProfile can be "" at this point

	// check from/to profile if it is one of the rejection scenarios,
	// suppress=true, else suppress=false
	for _, rejectionScenario := range profileRejectionScenarios {
		if fromProfile == rejectionScenario.FromProfile && toProfile == rejectionScenario.ToProfile {
			// reject = True
			return true, fromProfile
		}
	}
	return false, fromProfile
}

// IsDayZero returns true when currentRevisions is empty or
// when all current revision equal to 0
func IsDayZero(currentRevisions []int32) bool {
	for _, revision := range currentRevisions {
		if revision != 0 {
			return false
		}
	}
	return true
}

// isDayZeroFromStatus is a wrapper around IsDayZero that collects currentRevisions
// from operator nodeStatuses to return true when all revisions are 0 or when
// nodeStatuses are not reported yet
func isDayZeroFromStatus(operatorStatus *v1.StaticPodOperatorStatus) bool {
	currentRevisions := make([]int32, len(operatorStatus.NodeStatuses))
	for i, nodeStatus := range operatorStatus.NodeStatuses {
		currentRevisions[i] = nodeStatus.CurrentRevision
	}
	return IsDayZero(currentRevisions)
}
