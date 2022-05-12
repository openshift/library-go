package latencyprofilecontroller

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	configv1 "github.com/openshift/api/config/v1"
	nodeobserver "github.com/openshift/library-go/pkg/operator/configobserver/node"
)

func TestConfigMatchesControllerManagerArgument(t *testing.T) {
	createConfigMapFromObservedConfig := func(
		configMapName, configMapNamespace string,
		observedConfig map[string]interface{},
	) (configMap corev1.ConfigMap) {

		configAsJsonBytes, err := json.MarshalIndent(observedConfig, "", "")
		require.NoError(t, err)

		configMap = corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: configMapName, Namespace: configMapNamespace},
			Data: map[string]string{
				revisionConfigMapKey: string(configAsJsonBytes),
			},
		}
		return configMap
	}

	observedConfigs := []map[string]interface{}{
		// config 1
		{
			"apiServerArguments": map[string]interface{}{},
		},
		// config 2
		{
			"apiServerArguments": map[string]interface{}{
				"default-not-ready-toleration-seconds":   []string{"60"},
				"default-unreachable-toleration-seconds": []string{"60"},
				"default-watch-cache-size":               []string{"100"},
			},
		},
		// config 3
		{
			"apiServerArguments": map[string]interface{}{
				"default-watch-cache-size": []string{"100"},
			},
		},
		// config 4
		{
			"apiServerArguments": map[string]interface{}{
				"default-not-ready-toleration-seconds":   []string{"300"},
				"default-unreachable-toleration-seconds": []string{"300"},
			},
		},
	}

	configMaps := make([]corev1.ConfigMap, len(observedConfigs))
	for i, observedConfig := range observedConfigs {
		configMaps[i] = createConfigMapFromObservedConfig(
			fmt.Sprintf("%s-%d", revisionConfigMapName, i), "some-operand-namespace",
			observedConfig,
		)
	}

	latencyConfigs := []nodeobserver.LatencyConfigProfileTuple{
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

	scenarios := []struct {
		name                  string
		observedConfig        *map[string]interface{}
		configMap             *corev1.ConfigMap
		currentLatencyProfile configv1.WorkerLatencyProfileType
		expectedMatch         bool
	}{
		// scenario 1
		{
			name: "arg=default-unreachable-toleration-seconds should not be found in config with empty apiServerArgs",

			// config with empty apiServerArgs
			observedConfig: &observedConfigs[0],
			configMap:      &configMaps[0],

			currentLatencyProfile: configv1.DefaultUpdateDefaultReaction,
			expectedMatch:         false,
		},
		// scenario 2
		{
			name: "arg=default-not-ready-toleration-seconds with value=40 should be found in config",

			// config with apiServerArgs{default-not-ready-toleration-seconds=40,default-unreachable-toleration-seconds=40,default-watch-cache-size}
			observedConfig: &observedConfigs[1],
			configMap:      &configMaps[1],

			currentLatencyProfile: configv1.MediumUpdateAverageReaction,
			expectedMatch:         true,
		},
		// scenario 3
		{
			name: "arg=default-not-ready-toleration-seconds should not be found in config which does not contain that arg",

			// config with apiServerArgs{default-watch-cache-size}
			observedConfig: &observedConfigs[2],
			configMap:      &configMaps[2],

			currentLatencyProfile: configv1.DefaultUpdateDefaultReaction,
			expectedMatch:         false,
		},
		// scenario 4
		{
			name: "arg=default-not-ready-toleration-seconds with value=40 should not be found in config which contains that arg but different value",

			// config with apiServerArgs{default-not-ready-toleration-seconds=300,default-unreachable-toleration-seconds=300}
			observedConfig: &observedConfigs[3],
			configMap:      &configMaps[3],

			currentLatencyProfile: configv1.LowUpdateSlowReaction,
			expectedMatch:         false,
		},
	}

	r := revisionConfigMatcher{
		latencyConfigs: latencyConfigs,
	}
	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			// act
			actualMatch, err := r.configMatchProfileArguments(scenario.configMap, scenario.currentLatencyProfile)
			if err != nil {
				// in case error is encountered during matching
				t.Fatal(err)
			}
			// validate
			if !(actualMatch == scenario.expectedMatch) {
				containStr := "should contain"
				if !scenario.expectedMatch {
					containStr = "should not contain"
				}
				expectedConfig := make(map[string]string)
				for _, latencyConfig := range latencyConfigs {
					expectedConfig[strings.Join(latencyConfig.ConfigPath, ".")] = latencyConfig.ProfileConfigValues[scenario.currentLatencyProfile]
				}
				t.Fatalf("unexpected matching, expected = %v but got %v; observed-config = %v %s config-values = %v ",
					scenario.expectedMatch, actualMatch,
					*scenario.observedConfig, containStr,
					expectedConfig)
			}
		})
	}
}
