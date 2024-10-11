package node

import (
	clocktesting "k8s.io/utils/clock/testing"
	"strconv"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	configv1 "github.com/openshift/api/config/v1"
	configlistersv1 "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/operator/configobserver"
	"github.com/openshift/library-go/pkg/operator/events"
)

type workerLatencyProfileTestScenario struct {
	name                   string
	existingConfig         map[string]interface{}
	expectedObservedConfig map[string]interface{}
	workerLatencyProfile   configv1.WorkerLatencyProfileType
}

var kasLatencyConfigs = []LatencyConfigProfileTuple{
	// default-not-ready-toleration-seconds: Default=300;Medium,Low=60
	{
		ConfigPath: []string{"apiServerArguments", "default-not-ready-toleration-seconds"},
		ProfileConfigValues: map[configv1.WorkerLatencyProfileType]string{
			configv1.DefaultUpdateDefaultReaction: strconv.Itoa(configv1.DefaultNotReadyTolerationSeconds),
			configv1.MediumUpdateAverageReaction:  strconv.Itoa(configv1.MediumNotReadyTolerationSeconds),
			configv1.LowUpdateSlowReaction:        strconv.Itoa(configv1.LowNotReadyTolerationSeconds),
		},
	},
	// default-unreachable-toleration-seconds: Default=300;Medium,Low=60
	{
		ConfigPath: []string{"apiServerArguments", "default-unreachable-toleration-seconds"},
		ProfileConfigValues: map[configv1.WorkerLatencyProfileType]string{
			configv1.DefaultUpdateDefaultReaction: strconv.Itoa(configv1.DefaultUnreachableTolerationSeconds),
			configv1.MediumUpdateAverageReaction:  strconv.Itoa(configv1.MediumUnreachableTolerationSeconds),
			configv1.LowUpdateSlowReaction:        strconv.Itoa(configv1.LowUnreachableTolerationSeconds),
		},
	},
}

var kcmLatencyConfigs = []LatencyConfigProfileTuple{
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

func multiScenarioLatencyProfilesTest(t *testing.T, observeFn configobserver.ObserveConfigFunc, scenarios []workerLatencyProfileTestScenario) {
	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			// test data
			eventRecorder := events.NewInMemoryRecorder("", clocktesting.NewFakePassiveClock(time.Now()))
			configNodeIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			configNodeIndexer.Add(&configv1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec:       configv1.NodeSpec{WorkerLatencyProfile: scenario.workerLatencyProfile},
			})
			listers := testLister{
				nodeLister: configlistersv1.NewNodeLister(configNodeIndexer),
			}

			// act
			actualObservedConfig, err := observeFn(listers, eventRecorder, scenario.existingConfig)

			// validate
			if len(err) > 0 {
				t.Fatal(err)
			}
			if diff := cmp.Diff(scenario.expectedObservedConfig, actualObservedConfig); diff != "" {
				t.Fatalf("unexpected configuration, diff = %v", diff)
			}
		})
	}
}

func TestCreateLatencyProfileObserverKAS(t *testing.T) {
	kasoObserveLatencyProfile := NewLatencyProfileObserver(kasLatencyConfigs, nil)

	scenarios := []workerLatencyProfileTestScenario{
		// scenario 1: empty worker latency profile
		{
			name:                   "default value is not applied when worker latency profile is unset",
			expectedObservedConfig: map[string]interface{}{},
			workerLatencyProfile:   "", // empty worker latency profile
		},

		// scenario 2: Default
		{
			name: "worker latency profile Default: config with default-not-ready-toleration-seconds=300,default-unreachable-toleration-seconds=300",
			expectedObservedConfig: map[string]interface{}{
				"apiServerArguments": map[string]interface{}{
					"default-not-ready-toleration-seconds":   []interface{}{"300"},
					"default-unreachable-toleration-seconds": []interface{}{"300"},
				},
			},
			workerLatencyProfile: configv1.DefaultUpdateDefaultReaction,
		},

		// scenario 3: MediumUpdateAverageReaction
		{
			name: "worker latency profile MediumUpdateAverageReaction: config with default-not-ready-toleration-seconds=60,default-unreachable-toleration-seconds=60",
			expectedObservedConfig: map[string]interface{}{
				"apiServerArguments": map[string]interface{}{
					"default-not-ready-toleration-seconds":   []interface{}{"60"},
					"default-unreachable-toleration-seconds": []interface{}{"60"},
				},
			},
			workerLatencyProfile: configv1.MediumUpdateAverageReaction,
		},

		// scenario 4: LowUpdateSlowReaction
		{
			name: "worker latency profile LowUpdateSlowReaction: config with default-not-ready-toleration-seconds=60,default-unreachable-toleration-seconds=60",
			expectedObservedConfig: map[string]interface{}{
				"apiServerArguments": map[string]interface{}{
					"default-not-ready-toleration-seconds":   []interface{}{"60"},
					"default-unreachable-toleration-seconds": []interface{}{"60"},
				},
			},
			workerLatencyProfile: configv1.LowUpdateSlowReaction,
		},

		// scenario 5: unknown worker latency profile
		{
			name: "unknown worker latency profile should retain existing config",

			// in this case where we encounter an unknown value for WorkerLatencyProfile,
			// existing config should the same as expected config, because in case
			// an invalid profile is found we'd like to stick to whatever was set last time
			// and not update any config to avoid breaking anything
			existingConfig: map[string]interface{}{
				"apiServerArguments": map[string]interface{}{
					"default-not-ready-toleration-seconds":   []interface{}{"300"},
					"default-unreachable-toleration-seconds": []interface{}{"300"},
				},
			},
			expectedObservedConfig: map[string]interface{}{
				"apiServerArguments": map[string]interface{}{
					"default-not-ready-toleration-seconds":   []interface{}{"300"},
					"default-unreachable-toleration-seconds": []interface{}{"300"},
				},
			},

			workerLatencyProfile: "UnknownProfile",
		},

		// scenario 6: Update worker latency profile from MediumUpdateAverageReaction to Empty
		{
			name: "worker latency profile update from MediumUpdateAverageReaction to Empty profile: config with empty values",
			existingConfig: map[string]interface{}{
				"apiServerArguments": map[string]interface{}{
					"default-not-ready-toleration-seconds":   []interface{}{"60"},
					"default-unreachable-toleration-seconds": []interface{}{"60"},
				},
			},
			expectedObservedConfig: map[string]interface{}{},
			workerLatencyProfile:   "",
		},

		// scenario 7: Update worker latency profile from Default to Empty
		{
			name: "worker latency profile update from Default to Empty profile: config with empty values",
			existingConfig: map[string]interface{}{
				"apiServerArguments": map[string]interface{}{
					"default-not-ready-toleration-seconds":   []interface{}{"300"},
					"default-unreachable-toleration-seconds": []interface{}{"300"},
				},
			},
			expectedObservedConfig: map[string]interface{}{},
			workerLatencyProfile:   "",
		},
	}
	multiScenarioLatencyProfilesTest(t, kasoObserveLatencyProfile, scenarios)
}

func TestCreateLatencyProfileObserverKCM(t *testing.T) {
	kcmoObserveLatencyProfile := NewLatencyProfileObserver(kcmLatencyConfigs, nil)

	scenarios := []workerLatencyProfileTestScenario{
		// scenario 1: empty worker latency profile
		{
			name:                   "default value is not applied when worker latency profile is unset",
			expectedObservedConfig: map[string]interface{}{},
			workerLatencyProfile:   "", // empty worker latency profile
		},

		// scenario 2: Default
		{
			name: "worker latency profile Default: config with node-monitor-grace-period=40s",
			expectedObservedConfig: map[string]interface{}{
				"extendedArguments": map[string]interface{}{
					"node-monitor-grace-period": []interface{}{"40s"},
				},
			},
			workerLatencyProfile: configv1.DefaultUpdateDefaultReaction,
		},

		// scenario 3: MediumUpdateAverageReaction
		{
			name: "worker latency profile MediumUpdateAverageReaction: config with node-monitor-grace-period=2m",
			expectedObservedConfig: map[string]interface{}{
				"extendedArguments": map[string]interface{}{
					"node-monitor-grace-period": []interface{}{"2m0s"},
				},
			},
			workerLatencyProfile: configv1.MediumUpdateAverageReaction,
		},

		// scenario 4: LowUpdateSlowReaction
		{
			name: "worker latency profile LowUpdateSlowReaction: config with node-monitor-grace-period=5m",
			expectedObservedConfig: map[string]interface{}{
				"extendedArguments": map[string]interface{}{
					"node-monitor-grace-period": []interface{}{"5m0s"},
				},
			},
			workerLatencyProfile: configv1.LowUpdateSlowReaction,
		},

		// scenario 5: unknown worker latency profile
		{
			name: "unknown worker latency profile should retain existing config",

			// in this case where we encounter an unknown value for WorkerLatencyProfile,
			// existing config should the same as expected config, because in case
			// an invalid profile is found we'd like to stick to whatever was set last time
			// and not update any config to avoid breaking anything
			existingConfig: map[string]interface{}{
				"extendedArguments": map[string]interface{}{
					"node-monitor-grace-period": []interface{}{"40s"},
				},
			},
			expectedObservedConfig: map[string]interface{}{
				"extendedArguments": map[string]interface{}{
					"node-monitor-grace-period": []interface{}{"40s"},
				},
			},

			workerLatencyProfile: "UnknownProfile",
		},

		// scenario 6: Update worker latency profile from MediumUpdateAverageReaction to Empty
		{
			name: "worker latency profile update from MediumUpdateAverageReaction to Empty profile: config with empty values",
			existingConfig: map[string]interface{}{
				"extendedArguments": map[string]interface{}{
					"node-monitor-grace-period": []interface{}{"2m0s"},
				},
			},
			expectedObservedConfig: map[string]interface{}{},
			workerLatencyProfile:   "",
		},

		// scenario 7: Update worker latency profile from Default to Empty
		{
			name: "worker latency profile update from Default to Empty profile: config with empty values",
			existingConfig: map[string]interface{}{
				"extendedArguments": map[string]interface{}{
					"node-monitor-grace-period": []interface{}{"40s"},
				},
			},
			expectedObservedConfig: map[string]interface{}{},
			workerLatencyProfile:   "",
		},
	}

	multiScenarioLatencyProfilesTest(t, kcmoObserveLatencyProfile, scenarios)
}
