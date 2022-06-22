package node

import (
	"strconv"
	"testing"

	"github.com/google/go-cmp/cmp"
	configv1 "github.com/openshift/api/config/v1"
	v1 "github.com/openshift/api/operator/v1"
	"github.com/stretchr/testify/require"
)

func TestGetUsedLatencyConfigPaths(t *testing.T) {
	testCases := []struct {
		name           string
		latencyConfigs []LatencyConfigProfileTuple
		expectedPaths  [][]string
	}{
		{
			name:           "Empty latency configs",
			latencyConfigs: nil,
			expectedPaths:  [][]string{},
		},
		{
			name:           "KCM latency configs",
			latencyConfigs: kcmLatencyConfigs,
			expectedPaths: [][]string{
				{"extendedArguments", "node-monitor-grace-period"},
			},
		},
		{
			name:           "KAS latency configs",
			latencyConfigs: kasLatencyConfigs,
			expectedPaths: [][]string{
				{"apiServerArguments", "default-not-ready-toleration-seconds"},
				{"apiServerArguments", "default-unreachable-toleration-seconds"},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			// act
			latencyPaths := GetUsedLatencyConfigPaths(testCase.latencyConfigs)
			if !cmp.Equal(testCase.expectedPaths, latencyPaths) {
				t.Fatalf("unexpected latency paths, diff = %v", cmp.Diff(testCase.expectedPaths, latencyPaths))
			}
		})
	}
}

func TestGenerateConfigsForEachLatencyProfile(t *testing.T) {
	testCases := []struct {
		name                   string
		latencyConfigs         []LatencyConfigProfileTuple
		expectedProfileConfigs map[configv1.WorkerLatencyProfileType]map[string]interface{}
	}{
		{
			name:                   "Empty latency configs",
			latencyConfigs:         nil,
			expectedProfileConfigs: make(map[configv1.WorkerLatencyProfileType]map[string]interface{}),
		},
		{
			name:           "KAS latency configs",
			latencyConfigs: kasLatencyConfigs,
			expectedProfileConfigs: map[configv1.WorkerLatencyProfileType]map[string]interface{}{
				configv1.DefaultUpdateDefaultReaction: {
					"apiServerArguments": map[string]interface{}{
						"default-not-ready-toleration-seconds":   []interface{}{strconv.Itoa(configv1.DefaultNotReadyTolerationSeconds)},
						"default-unreachable-toleration-seconds": []interface{}{strconv.Itoa(configv1.DefaultUnreachableTolerationSeconds)},
					},
				},
				configv1.MediumUpdateAverageReaction: {
					"apiServerArguments": map[string]interface{}{
						"default-not-ready-toleration-seconds":   []interface{}{strconv.Itoa(configv1.MediumNotReadyTolerationSeconds)},
						"default-unreachable-toleration-seconds": []interface{}{strconv.Itoa(configv1.MediumUnreachableTolerationSeconds)},
					},
				},
				configv1.LowUpdateSlowReaction: {
					"apiServerArguments": map[string]interface{}{
						"default-not-ready-toleration-seconds":   []interface{}{strconv.Itoa(configv1.LowNotReadyTolerationSeconds)},
						"default-unreachable-toleration-seconds": []interface{}{strconv.Itoa(configv1.LowUnreachableTolerationSeconds)},
					},
				},
			},
		},
		{
			name:           "KCM latency configs",
			latencyConfigs: kcmLatencyConfigs,
			expectedProfileConfigs: map[configv1.WorkerLatencyProfileType]map[string]interface{}{
				configv1.DefaultUpdateDefaultReaction: {
					"extendedArguments": map[string]interface{}{
						"node-monitor-grace-period": []interface{}{configv1.DefaultNodeMonitorGracePeriod.String()},
					},
				},
				configv1.MediumUpdateAverageReaction: {
					"extendedArguments": map[string]interface{}{
						"node-monitor-grace-period": []interface{}{configv1.MediumNodeMonitorGracePeriod.String()},
					},
				},
				configv1.LowUpdateSlowReaction: {
					"extendedArguments": map[string]interface{}{
						"node-monitor-grace-period": []interface{}{configv1.LowNodeMonitorGracePeriod.String()},
					},
				},
			},
		},
	}

	for _, testCase := range testCases {
		// act
		profileConfigs, err := GenerateConfigsForEachLatencyProfile(testCase.latencyConfigs)
		require.NoError(t, err)

		// validate
		if !cmp.Equal(testCase.expectedProfileConfigs, profileConfigs) {
			t.Fatalf("unexpected profile configs, diff = %v", cmp.Diff(testCase.expectedProfileConfigs, profileConfigs))
		}
	}
}

func TestShouldRejectProfileTransition(t *testing.T) {
	kcmKnownProfileConfigs := map[configv1.WorkerLatencyProfileType]map[string]interface{}{
		configv1.DefaultUpdateDefaultReaction: {
			"extendedArguments": map[string]interface{}{
				"node-monitor-grace-period": []interface{}{configv1.DefaultNodeMonitorGracePeriod.String()},
			},
		},
		configv1.MediumUpdateAverageReaction: {
			"extendedArguments": map[string]interface{}{
				"node-monitor-grace-period": []interface{}{configv1.MediumNodeMonitorGracePeriod.String()},
			},
		},
		configv1.LowUpdateSlowReaction: {
			"extendedArguments": map[string]interface{}{
				"node-monitor-grace-period": []interface{}{configv1.LowNodeMonitorGracePeriod.String()},
			},
		},
	}

	testCases := []struct {
		name              string
		fromLatencyConfig map[string]interface{}
		toProfile         configv1.WorkerLatencyProfileType

		isRejectionExpected bool
		expectedFromProfile configv1.WorkerLatencyProfileType
	}{
		// rejections
		{
			name:              "KCMO reject from Empty to Low",
			fromLatencyConfig: map[string]interface{}{},
			toProfile:         configv1.LowUpdateSlowReaction,

			isRejectionExpected: true,
			expectedFromProfile: "",
		},
		{
			name: "KCMO reject from Default to Low",
			fromLatencyConfig: map[string]interface{}{
				"extendedArguments": map[string]interface{}{
					"node-monitor-grace-period": []interface{}{configv1.DefaultNodeMonitorGracePeriod.String()},
				},
			},
			toProfile: configv1.LowUpdateSlowReaction,

			isRejectionExpected: true,
			expectedFromProfile: configv1.DefaultUpdateDefaultReaction,
		},
		{
			name: "KCMO reject from Low to Empty",
			fromLatencyConfig: map[string]interface{}{
				"extendedArguments": map[string]interface{}{
					"node-monitor-grace-period": []interface{}{configv1.LowNodeMonitorGracePeriod.String()},
				},
			},
			toProfile: "",

			isRejectionExpected: true,
			expectedFromProfile: configv1.LowUpdateSlowReaction,
		},
		{
			name: "KCMO reject from Low to Default",
			fromLatencyConfig: map[string]interface{}{
				"extendedArguments": map[string]interface{}{
					"node-monitor-grace-period": []interface{}{configv1.LowNodeMonitorGracePeriod.String()},
				},
			},
			toProfile: configv1.DefaultUpdateDefaultReaction,

			isRejectionExpected: true,
			expectedFromProfile: configv1.LowUpdateSlowReaction,
		},
		// no rejections
		{
			name: "KCMO do not reject from Default to Medium",
			fromLatencyConfig: map[string]interface{}{
				"extendedArguments": map[string]interface{}{
					"node-monitor-grace-period": []interface{}{configv1.DefaultNodeMonitorGracePeriod.String()},
				},
			},
			toProfile: configv1.MediumUpdateAverageReaction,

			isRejectionExpected: false,
			expectedFromProfile: configv1.DefaultUpdateDefaultReaction,
		},
		{
			name:              "KCMO do not reject from Empty to Medium",
			fromLatencyConfig: map[string]interface{}{},
			toProfile:         configv1.MediumUpdateAverageReaction,

			isRejectionExpected: false,
			expectedFromProfile: "",
		},
		{
			name: "KCMO do not reject from Medium to Default",
			fromLatencyConfig: map[string]interface{}{
				"extendedArguments": map[string]interface{}{
					"node-monitor-grace-period": []interface{}{configv1.MediumNodeMonitorGracePeriod.String()},
				},
			},
			toProfile: configv1.DefaultUpdateDefaultReaction,

			isRejectionExpected: false,
			expectedFromProfile: configv1.MediumUpdateAverageReaction,
		},
		{
			name: "KCMO do not reject from Medium to Empty",
			fromLatencyConfig: map[string]interface{}{
				"extendedArguments": map[string]interface{}{
					"node-monitor-grace-period": []interface{}{configv1.MediumNodeMonitorGracePeriod.String()},
				},
			},
			toProfile: "",

			isRejectionExpected: false,
			expectedFromProfile: configv1.MediumUpdateAverageReaction,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			// act
			isRejected, fromProfile := ShouldRejectProfileTransition(testCase.fromLatencyConfig, testCase.toProfile, kcmKnownProfileConfigs, kcmRejectionScenarios)
			if isRejected != testCase.isRejectionExpected {
				t.Fatalf("found rejection = %v but expected rejection = %v", isRejected, testCase.isRejectionExpected)
			}
			if !cmp.Equal(fromProfile, testCase.expectedFromProfile) {
				t.Fatalf("found fromProfile %q but expected fromProfile as %q", fromProfile, testCase.expectedFromProfile)
			}
		})
	}
}

func TestIsDayZero(t *testing.T) {
	testCases := []struct {
		name              string
		currentRevisions  []int32
		isDayZeroExpected bool
	}{
		{
			name:              "Empty current revisions",
			currentRevisions:  nil,
			isDayZeroExpected: true,
		},
		{
			name:              "All current revisions are 0",
			currentRevisions:  []int32{0, 0, 0},
			isDayZeroExpected: true,
		},
		{
			name:              "Some current revisions are 0",
			currentRevisions:  []int32{0, 3, 0},
			isDayZeroExpected: false,
		},
		{
			name:              "None of the current revisions are 0",
			currentRevisions:  []int32{3, 4, 4},
			isDayZeroExpected: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			// act
			ret := IsDayZero(testCase.currentRevisions)
			if ret != testCase.isDayZeroExpected {
				t.Fatalf("expected isDayZero %v, found %v", testCase.isDayZeroExpected, ret)
			}
		})
	}
}

func TestIsDayZeroFromStatus(t *testing.T) {
	testCases := []struct {
		name              string
		operatorStatus    v1.StaticPodOperatorStatus
		isDayZeroExpected bool
	}{
		{
			name:              "Empty node statuses",
			operatorStatus:    v1.StaticPodOperatorStatus{},
			isDayZeroExpected: true,
		},
		{
			name: "All nodes are at revision 0",
			operatorStatus: v1.StaticPodOperatorStatus{
				NodeStatuses: []v1.NodeStatus{
					{NodeName: "master-0", CurrentRevision: 0},
					{NodeName: "master-1", CurrentRevision: 0},
					{NodeName: "master-2", CurrentRevision: 0},
				},
			},
			isDayZeroExpected: true,
		},
		{
			name: "Some nodes are at revision 0",
			operatorStatus: v1.StaticPodOperatorStatus{
				NodeStatuses: []v1.NodeStatus{
					{NodeName: "master-0", CurrentRevision: 3},
					{NodeName: "master-1", CurrentRevision: 0},
					{NodeName: "master-2", CurrentRevision: 3},
				},
			},
			isDayZeroExpected: false,
		},
		{
			name: "None of the nodes are at revision 0",
			operatorStatus: v1.StaticPodOperatorStatus{
				NodeStatuses: []v1.NodeStatus{
					{NodeName: "master-0", CurrentRevision: 3},
					{NodeName: "master-1", CurrentRevision: 4},
					{NodeName: "master-2", CurrentRevision: 4},
				},
			},
			isDayZeroExpected: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			// act
			ret := isDayZeroFromStatus(&testCase.operatorStatus)
			if ret != testCase.isDayZeroExpected {
				t.Fatalf("expected isDayZero %v, found %v", testCase.isDayZeroExpected, ret)
			}
		})
	}
}
