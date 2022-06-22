package latencyprofilecontroller

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	listercorev1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	configv1 "github.com/openshift/api/config/v1"
	nodeobserver "github.com/openshift/library-go/pkg/operator/configobserver/node"
)

func TestCheckProfileRejection(t *testing.T) {
	profileConfigs := map[configv1.WorkerLatencyProfileType]map[string]interface{}{
		"": {
			"extendedArguments": map[string]interface{}{},
		},
		configv1.DefaultUpdateDefaultReaction: {
			"extendedArguments": map[string]interface{}{
				"node-monitor-grace-period": []string{"40s"},
			},
		},
		configv1.MediumUpdateAverageReaction: {
			"extendedArguments": map[string]interface{}{
				"node-monitor-grace-period": []string{"2m0s"},
			},
		},
		configv1.LowUpdateSlowReaction: {
			"extendedArguments": map[string]interface{}{
				"node-monitor-grace-period": []string{"5m0s"},
			},
		},
	}

	latencyConfigs := []nodeobserver.LatencyConfigProfileTuple{
		// node-monitor-grace-period: Default=40s;Medium=2m;Low=5m
		{
			ConfigPath: []string{"extendedArguments", "node-monitor-grace-period"},
			ProfileConfigValues: map[configv1.WorkerLatencyProfileType]string{
				configv1.DefaultUpdateDefaultReaction: configv1.DefaultNodeMonitorGracePeriod.String(),
				configv1.MediumUpdateAverageReaction:  configv1.MediumNodeMonitorGracePeriod.String(),
				configv1.LowUpdateSlowReaction:        configv1.LowNodeMonitorGracePeriod.String(),
			},
		},
	}

	rejectionScenarios := []nodeobserver.LatencyProfileRejectionScenario{
		{FromProfile: "", ToProfile: configv1.LowUpdateSlowReaction},
		{FromProfile: configv1.LowUpdateSlowReaction, ToProfile: ""},

		{FromProfile: configv1.DefaultUpdateDefaultReaction, ToProfile: configv1.LowUpdateSlowReaction},
		{FromProfile: configv1.LowUpdateSlowReaction, ToProfile: configv1.DefaultUpdateDefaultReaction},
	}

	testScenarios := []struct {
		name                   string
		activeRevisionProfiles map[int32]configv1.WorkerLatencyProfileType
		clusterProfile         configv1.WorkerLatencyProfileType
		isRejectionExpected    bool
	}{
		// No rejections
		{
			name: "KCM transition from Default -> Default with some configs having Medium",
			activeRevisionProfiles: map[int32]configv1.WorkerLatencyProfileType{
				13: configv1.DefaultUpdateDefaultReaction,
				10: configv1.MediumUpdateAverageReaction,
			},
			clusterProfile:      configv1.DefaultUpdateDefaultReaction,
			isRejectionExpected: false,
		},
		{
			name: "KCM transition from Default -> Empty",
			activeRevisionProfiles: map[int32]configv1.WorkerLatencyProfileType{
				9: configv1.DefaultUpdateDefaultReaction,
			},
			clusterProfile:      "",
			isRejectionExpected: false,
		},
		{
			name: "KCM transition from Low -> Low with some configs having Medium",
			activeRevisionProfiles: map[int32]configv1.WorkerLatencyProfileType{
				9: configv1.LowUpdateSlowReaction,
				8: configv1.MediumUpdateAverageReaction,
			},
			clusterProfile:      configv1.LowUpdateSlowReaction,
			isRejectionExpected: false,
		},
		{
			name: "KCM transition from Medium -> Default",
			activeRevisionProfiles: map[int32]configv1.WorkerLatencyProfileType{
				6: configv1.MediumUpdateAverageReaction,
			},
			clusterProfile:      configv1.DefaultUpdateDefaultReaction,
			isRejectionExpected: false,
		},
		{
			name: "KCM transition from Medium -> Low",
			activeRevisionProfiles: map[int32]configv1.WorkerLatencyProfileType{
				6: configv1.MediumUpdateAverageReaction,
			},
			clusterProfile:      configv1.LowUpdateSlowReaction,
			isRejectionExpected: false,
		},
		{
			name: "KCM transition from Medium -> Low with some configs Default",
			activeRevisionProfiles: map[int32]configv1.WorkerLatencyProfileType{
				6: configv1.MediumUpdateAverageReaction,
				4: configv1.DefaultUpdateDefaultReaction,
			},
			clusterProfile:      configv1.LowUpdateSlowReaction,
			isRejectionExpected: false,
		},
		{
			name: "KCM transition from Medium -> Defaut with some configs Low",
			activeRevisionProfiles: map[int32]configv1.WorkerLatencyProfileType{
				9: configv1.MediumUpdateAverageReaction,
				8: configv1.LowUpdateSlowReaction,
				7: configv1.LowUpdateSlowReaction,
			},
			clusterProfile:      configv1.DefaultUpdateDefaultReaction,
			isRejectionExpected: false,
		},
		{
			name: "KCM transition from Medium -> Empty with some configs Low",
			activeRevisionProfiles: map[int32]configv1.WorkerLatencyProfileType{
				9: configv1.MediumUpdateAverageReaction,
				8: configv1.LowUpdateSlowReaction,
				7: configv1.LowUpdateSlowReaction,
			},
			clusterProfile:      "",
			isRejectionExpected: false,
		},
		// No rejections due to day-0
		{
			name: "KCM transition directly to Empty during day-0",
			activeRevisionProfiles: map[int32]configv1.WorkerLatencyProfileType{
				0: "",
			},
			clusterProfile:      "",
			isRejectionExpected: false,
		},
		{
			name: "KCM transition directly to Default during day-0",
			activeRevisionProfiles: map[int32]configv1.WorkerLatencyProfileType{
				0: "",
			},
			clusterProfile:      configv1.DefaultUpdateDefaultReaction,
			isRejectionExpected: false,
		},
		{
			name: "KCM transition directly to Medium during day-0",
			activeRevisionProfiles: map[int32]configv1.WorkerLatencyProfileType{
				0: "",
			},
			clusterProfile:      configv1.MediumUpdateAverageReaction,
			isRejectionExpected: false,
		},
		{
			name: "KCM transition directly to Low during day-0",
			activeRevisionProfiles: map[int32]configv1.WorkerLatencyProfileType{
				0: "",
			},
			clusterProfile:      configv1.LowUpdateSlowReaction,
			isRejectionExpected: false,
		},
		// No rejections, mix of revision-0 and others
		{
			name: "KCM with Low, should ignore revision-0",
			activeRevisionProfiles: map[int32]configv1.WorkerLatencyProfileType{
				0: "",
				4: configv1.LowUpdateSlowReaction,
				5: configv1.LowUpdateSlowReaction,
			},
			clusterProfile:      configv1.LowUpdateSlowReaction,
			isRejectionExpected: false,
		},
		// Default/Empty -> Low rejections
		{
			name: "KCM transition from Default -> Low with some configs having Medium",
			activeRevisionProfiles: map[int32]configv1.WorkerLatencyProfileType{
				5: configv1.DefaultUpdateDefaultReaction,
				3: configv1.MediumUpdateAverageReaction,
			},
			clusterProfile:      configv1.LowUpdateSlowReaction,
			isRejectionExpected: true,
		},
		{
			name: "KCM transition from Empty -> Low",
			activeRevisionProfiles: map[int32]configv1.WorkerLatencyProfileType{
				2: "",
				1: "",
			},
			clusterProfile:      configv1.LowUpdateSlowReaction,
			isRejectionExpected: true,
		},
		{
			name: "KCM transition from Empty -> Low with some configs having Medium",
			activeRevisionProfiles: map[int32]configv1.WorkerLatencyProfileType{
				4: "",
				3: configv1.MediumUpdateAverageReaction,
			},
			clusterProfile:      configv1.LowUpdateSlowReaction,
			isRejectionExpected: true,
		},
		// Low -> Default/Empty rejections
		{
			name: "KCM transition from Low -> Default with some configs having Medium",
			activeRevisionProfiles: map[int32]configv1.WorkerLatencyProfileType{
				5: configv1.LowUpdateSlowReaction,
				3: configv1.MediumUpdateAverageReaction,
			},
			clusterProfile:      configv1.DefaultUpdateDefaultReaction,
			isRejectionExpected: true,
		},
		{
			name: "KCM transition from Low -> Default",
			activeRevisionProfiles: map[int32]configv1.WorkerLatencyProfileType{
				5: configv1.LowUpdateSlowReaction,
				4: configv1.LowUpdateSlowReaction,
			},
			clusterProfile:      configv1.DefaultUpdateDefaultReaction,
			isRejectionExpected: true,
		},
		{
			name: "KCM transition from Low -> Empty",
			activeRevisionProfiles: map[int32]configv1.WorkerLatencyProfileType{
				2: configv1.LowUpdateSlowReaction,
				1: configv1.LowUpdateSlowReaction,
			},
			clusterProfile:      "",
			isRejectionExpected: true,
		},
		{
			name: "KCM transition from Low -> Empty with some configs having Medium",
			activeRevisionProfiles: map[int32]configv1.WorkerLatencyProfileType{
				4: configv1.LowUpdateSlowReaction,
				3: configv1.MediumUpdateAverageReaction,
			},
			clusterProfile:      "",
			isRejectionExpected: true,
		},
	}

	configMapsNamespace := "some-operand-namespace"

	for _, scenario := range testScenarios {
		t.Run(scenario.name, func(t *testing.T) {
			activeRevisions := make([]int32, 0)
			configMapIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			for revision, profile := range scenario.activeRevisionProfiles {
				observedConfig := profileConfigs[profile]
				configMap := createConfigMapFromObservedConfig(t, fmt.Sprintf("%s-%d", revisionConfigMapName, revision), configMapsNamespace, observedConfig)
				configMapIndexer.Add(&configMap)

				activeRevisions = append(activeRevisions, revision)
			}
			configMapLister := listercorev1.NewConfigMapLister(configMapIndexer).ConfigMaps(configMapsNamespace)

			checkProfileRejectionFn, err := NewInstallerProfileRejectionChecker(configMapLister, latencyConfigs, rejectionScenarios)
			require.NoError(t, err)

			isRejected, rejectMsg, err := checkProfileRejectionFn(scenario.clusterProfile, activeRevisions)
			require.NoError(t, err)

			if isRejected != scenario.isRejectionExpected {
				t.Fatalf("expected rejection = %v but found %v", scenario.isRejectionExpected, isRejected)
			}

			if isRejected {
				if !strings.Contains(rejectMsg, string(scenario.clusterProfile)) {
					t.Fatalf("rejection message %q should contain set profile when profile was rejected", rejectMsg)
				}
			} else {
				if rejectMsg != "" {
					t.Fatalf("rejection message should be empty when profile was not rejected, found = %q", rejectMsg)
				}
			}

		})
	}

}
