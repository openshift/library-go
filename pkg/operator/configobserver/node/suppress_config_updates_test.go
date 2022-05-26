package node

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	listercorev1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	operatorv1 "github.com/openshift/api/operator/v1"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

type configObserverSuppressTestCase struct {
	name                                   string
	observedConfigRevisions                []map[string]interface{}
	nodeCurrentRevisionsIdx                []int
	isSuppressionExpected                  bool
	operatorLatencyConfigs                 []LatencyConfigProfileTuple
	operatorSpecObservedConfig             map[string]interface{}
	operatorSpecUnsupportedConfigOverrides map[string]interface{}
}

func TestSuppressConfigUpdateUntilSameProfileFunc(t *testing.T) {
	createConfigMapsFromObservedConfigRevisions := func(
		configMapNamespace string,
		observedConfigRevisions []map[string]interface{},
	) (configMap []corev1.ConfigMap) {

		configMaps := make([]corev1.ConfigMap, len(observedConfigRevisions))

		for revisionIdx, observedConfig := range observedConfigRevisions {
			configAsJsonBytes, err := json.MarshalIndent(observedConfig, "", "")
			require.NoError(t, err)

			configMaps[revisionIdx] = corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("%s-%d", revisionConfigMapName, revisionIdx+1), Namespace: configMapNamespace},
				Data: map[string]string{
					revisionConfigMapKey: string(configAsJsonBytes),
				},
			}
		}
		return configMaps
	}

	testCases := []configObserverSuppressTestCase{
		// test case 1: KAS different revisions active on different nodes; operator-current=config-2
		{
			name: "KAS: different revisions active on different nodes, master-0,2:default, master-1:medium",
			observedConfigRevisions: []map[string]interface{}{
				// config 1: Kube API Server Default Latency
				{
					"apiServerArguments": map[string]interface{}{
						"default-not-ready-toleration-seconds":   []interface{}{"300"},
						"default-unreachable-toleration-seconds": []interface{}{"300"},
					},
				},
				// config 2: Kube API Server Medium Latency
				{
					"apiServerArguments": map[string]interface{}{
						"default-not-ready-toleration-seconds":   []interface{}{"60"},
						"default-unreachable-toleration-seconds": []interface{}{"60"},
					},
				},
			},

			nodeCurrentRevisionsIdx: []int{1, 2, 1}, // master-0: config-1, master-1: config-2, master-2: config-1
			isSuppressionExpected:   true,
			operatorLatencyConfigs:  kasLatencyConfigs,

			operatorSpecObservedConfig: map[string]interface{}{
				"apiServerArguments": map[string]interface{}{
					"default-not-ready-toleration-seconds":   []interface{}{"60"},
					"default-unreachable-toleration-seconds": []interface{}{"60"},
				},
			},
			operatorSpecUnsupportedConfigOverrides: map[string]interface{}{},
		},
		// test case 2: KAS same revision active on all nodes; operator-current=config-1
		{
			name: "KAS: same revision active on all nodes, master-0,1,2:default",
			observedConfigRevisions: []map[string]interface{}{
				// config 1: Kube API Server Default Latency
				{
					"apiServerArguments": map[string]interface{}{
						"default-not-ready-toleration-seconds":   []interface{}{"300"},
						"default-unreachable-toleration-seconds": []interface{}{"300"},
					},
				},
			},

			nodeCurrentRevisionsIdx: []int{1, 1, 1}, // master-0: config-1, master-1: config-1, master-2: config-1
			isSuppressionExpected:   false,
			operatorLatencyConfigs:  kasLatencyConfigs,

			operatorSpecObservedConfig: map[string]interface{}{
				"apiServerArguments": map[string]interface{}{
					"default-not-ready-toleration-seconds":   []interface{}{"300"},
					"default-unreachable-toleration-seconds": []interface{}{"300"},
				},
			},
			operatorSpecUnsupportedConfigOverrides: map[string]interface{}{},
		},
		// test case 3: KCM different revisions active on different nodes; operator-current=config-2
		{
			name: "KCM: different revisions active on different nodes, master-0,2:default, master-1,3,4:medium",
			observedConfigRevisions: []map[string]interface{}{
				// config 1: Kube Controller Manager Default Latency
				{
					"extendedArguments": map[string]interface{}{
						"node-monitor-grace-period": []interface{}{"40s"},
					},
				},
				// config 2: Kube Controller Manager Medium Latency
				{
					"extendedArguments": map[string]interface{}{
						"node-monitor-grace-period": []interface{}{"2m0s"},
					},
				},
			},

			// master-0: config-1, master-1: config-2, master-2: config-1, master-3: config-2, master-4: config-2
			nodeCurrentRevisionsIdx: []int{1, 2, 1, 2, 2},
			isSuppressionExpected:   true,
			operatorLatencyConfigs:  kcmLatencyConfigs,

			operatorSpecObservedConfig: map[string]interface{}{
				"extendedArguments": map[string]interface{}{
					"node-monitor-grace-period": []interface{}{"2m0s"},
				},
			},
			operatorSpecUnsupportedConfigOverrides: map[string]interface{}{
				"extendedArguments": map[string]interface{}{
					"node-monitor-grace-period": []interface{}{"3m0s"},
				},
			},
		},
		// test case 3: KCM different revisions active on different nodes but same arg val pairs; operator-current=config-2+unsupportedconfioverride
		{
			name: "KCM different revisions active on different nodes but same arg val pairs, master-0,2:config1,Low, master-1:config2,Low",
			observedConfigRevisions: []map[string]interface{}{
				// config 1: Kube Controller Manager Low Latency
				{
					"extendedArguments": map[string]interface{}{
						"node-monitor-grace-period": []interface{}{"5m0s"},
					},
				},
				// config 2: Kube Controller Manager Low Latency
				{
					"extendedArguments": map[string]interface{}{
						"node-monitor-grace-period": []interface{}{"5m0s"},
						"node-eviction-rate":        []interface{}{"0.1"},
					},
				},
			},

			nodeCurrentRevisionsIdx: []int{1, 2, 2}, // master-0: config-1, master-1: config-2, master-2: config-1
			isSuppressionExpected:   false,
			operatorLatencyConfigs:  kcmLatencyConfigs,

			operatorSpecObservedConfig: map[string]interface{}{
				"extendedArguments": map[string]interface{}{
					"node-monitor-grace-period": []interface{}{"5m0s"},
					"node-eviction-rate":        []interface{}{"0.1"},
				},
			},
			operatorSpecUnsupportedConfigOverrides: map[string]interface{}{},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			// create a config map lister with all revision configs
			configMapsNamespace := "some-operand-namespace"
			revisionConfigMaps := createConfigMapsFromObservedConfigRevisions(configMapsNamespace, testCase.observedConfigRevisions)

			configMapIndexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			for i := range revisionConfigMaps {
				configMapIndexer.Add(&revisionConfigMaps[i])
			}
			configMapLister := listercorev1.NewConfigMapLister(configMapIndexer).ConfigMaps(configMapsNamespace)

			// create a static pod operator client with node statuses containing current revision
			nodesStatuses := make([]operatorv1.NodeStatus, len(testCase.nodeCurrentRevisionsIdx))
			for i, nodeCurrentRevision := range testCase.nodeCurrentRevisionsIdx {
				nodesStatuses[i] = operatorv1.NodeStatus{
					NodeName:        fmt.Sprintf("master-%d", i),
					CurrentRevision: int32(nodeCurrentRevision),
				}
			}
			staticPodOperatorStatus := operatorv1.StaticPodOperatorStatus{
				LatestAvailableRevision: int32(len(testCase.observedConfigRevisions) + 1),
				NodeStatuses:            nodesStatuses,
			}

			operatorObservedConfig, err := json.Marshal(testCase.operatorSpecObservedConfig)
			require.NoError(t, err)
			operatorUnsupportedConfigOverrides, err := json.Marshal(testCase.operatorSpecUnsupportedConfigOverrides)
			require.NoError(t, err)

			operatorClient := v1helpers.NewFakeStaticPodOperatorClient(
				&operatorv1.StaticPodOperatorSpec{
					OperatorSpec: operatorv1.OperatorSpec{
						ObservedConfig: runtime.RawExtension{
							Raw: operatorObservedConfig,
						},
						UnsupportedConfigOverrides: runtime.RawExtension{
							Raw: operatorUnsupportedConfigOverrides,
						},
					},
				},
				&staticPodOperatorStatus, nil, nil,
			)

			// act: run the test
			suppressConfigUpdatesFn := NewSuppressConfigUpdateUntilSameProfileFunc(
				operatorClient, configMapLister, testCase.operatorLatencyConfigs)
			suppress, err := suppressConfigUpdatesFn()
			require.NoError(t, err)

			// validate result
			if suppress != testCase.isSuppressionExpected {
				shouldStr := "should be"
				if !testCase.isSuppressionExpected {
					shouldStr = "should not be"
				}
				t.Fatalf("config observer %s suppressed, but found suppress = %v", shouldStr, suppress)
			}
		})
	}

}
