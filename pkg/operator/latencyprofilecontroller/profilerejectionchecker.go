package latencyprofilecontroller

import (
	"fmt"

	listersv1 "k8s.io/client-go/listers/core/v1"

	configv1 "github.com/openshift/api/config/v1"
	nodeobserver "github.com/openshift/library-go/pkg/operator/configobserver/node"
)

type profileRejectRevisionChecker struct {
	configMapLister           listersv1.ConfigMapNamespaceLister
	usedConfigPaths           [][]string
	knownProfileConfigs       map[configv1.WorkerLatencyProfileType]map[string]interface{}
	profileRejectionScenarios []nodeobserver.LatencyProfileRejectionScenario
}

// NewInstallerProfileRejectionChecker is used to construct a CheckProfileRejectionFunc that
// can compare the (installer controller generated config map) config of the latest active revision
// with the desired/target latency profile to return whether profile transition should be rejected or not.
// The latencyConfigs passed to this func check arg values of each latency profile to compare
// them across the active config on the cluster. In case the transition is from profile found in active config
// to specified target profile and it is for one of the scenarios specified in profileRejectionScenarios,
// the rejection flag is returned as true with an appropriate message; false otherwise.
// Eg. transition between extreme latency profiles viz. Default <-> Low should be rejected.
func NewInstallerProfileRejectionChecker(
	configMapLister listersv1.ConfigMapNamespaceLister,
	latencyConfigs []nodeobserver.LatencyConfigProfileTuple,
	profileRejectionScenarios []nodeobserver.LatencyProfileRejectionScenario,
) (CheckProfileRejectionFunc, error) {

	knownProfileConfigs, err := nodeobserver.GenerateConfigsForEachLatencyProfile(latencyConfigs)
	if err != nil {
		return nil, err
	}

	ret := profileRejectRevisionChecker{
		configMapLister:           configMapLister,
		usedConfigPaths:           nodeobserver.GetUsedLatencyConfigPaths(latencyConfigs),
		knownProfileConfigs:       knownProfileConfigs,
		profileRejectionScenarios: profileRejectionScenarios,
	}
	return ret.checkProfileRejection, nil
}

func (r *profileRejectRevisionChecker) checkProfileRejection(targetProfile configv1.WorkerLatencyProfileType, currentRevisions []int32) (isRejected bool, rejectMsg string, err error) {
	// do not reject at day-0 and support any profile
	if nodeobserver.IsDayZero(currentRevisions) {
		return false, "", nil
	}

	// determine the highest revision among the ones specified, since the highest revision
	// will be indicative of the most recent profile active on the cluster
	highestCurrentRevision := currentRevisions[0]
	for _, revision := range currentRevisions {
		if revision > highestCurrentRevision {
			highestCurrentRevision = revision
		}
	}

	// get config map for the highest revision
	configMap, err := r.configMapLister.Get(fmt.Sprintf("%s-%d", revisionConfigMapName, highestCurrentRevision))
	if err != nil {
		return false, "", err
	}

	// prune the obtained config with only config paths that we monitor for the latency profiles
	currentConfigPruned, err := getPrunedConfigFromConfigMap(configMap, r.usedConfigPaths)
	if err != nil {
		return false, "", err
	}

	// check from/to profile i.e. between profile on the active revision with target profile
	// and if it is one of the rejection scenarios, return reject flag as true
	isRejected, fromProfile := nodeobserver.ShouldRejectProfileTransition(
		currentConfigPruned, targetProfile,
		r.knownProfileConfigs, r.profileRejectionScenarios,
	)

	if isRejected {
		return true,
			fmt.Sprintf("rejected update from %q to %q latency profile as extreme profile transition is unsupported, "+
				"please set nodes.config.openshift.io/cluster object to workerLatencyProfile %q "+
				"(or any other profile apart from rejected %q) in order to recover from this error",
				fromProfile, targetProfile, fromProfile, targetProfile),
			nil
	}

	// not one of the rejection scenarios, return reject flag as false
	return false, "", nil
}
