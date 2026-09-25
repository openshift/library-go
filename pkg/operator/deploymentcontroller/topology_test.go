package deploymentcontroller

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	configv1 "github.com/openshift/api/config/v1"
	configv1listers "github.com/openshift/client-go/config/listers/config/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
)

func fakeNodeLister(nodes ...*corev1.Node) corev1listers.NodeLister {
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	for _, n := range nodes {
		if err := indexer.Add(n); err != nil {
			panic(err)
		}
	}
	return corev1listers.NewNodeLister(indexer)
}

func fakeInfrastructureLister(infra *configv1.Infrastructure) configv1listers.InfrastructureLister {
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	if err := indexer.Add(infra); err != nil {
		panic(err)
	}
	return configv1listers.NewInfrastructureLister(indexer)
}

func newControlPlaneNode(name string) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: map[string]string{"node-role.kubernetes.io/control-plane": ""},
		},
	}
}

func newInfrastructure(topology configv1.TopologyMode) *configv1.Infrastructure {
	return &configv1.Infrastructure{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
		Status: configv1.InfrastructureStatus{
			ControlPlaneTopology: topology,
		},
	}
}

func TestWithTopologyAwareReplicasHook(t *testing.T) {
	testCases := []struct {
		name             string
		topology         configv1.TopologyMode
		nodes            []*corev1.Node
		maxReplicas      int32
		expectedReplicas int32
	}{
		{
			name:             "SingleReplica with 1 node",
			topology:         configv1.SingleReplicaTopologyMode,
			nodes:            []*corev1.Node{newControlPlaneNode("master-0")},
			maxReplicas:      3,
			expectedReplicas: 1,
		},
		{
			name:     "DualReplica with 2 nodes",
			topology: configv1.DualReplicaTopologyMode,
			nodes: []*corev1.Node{
				newControlPlaneNode("master-0"),
				newControlPlaneNode("master-1"),
			},
			maxReplicas:      3,
			expectedReplicas: 2,
		},
		{
			name:     "HighlyAvailableArbiter with 3 nodes caps at 2",
			topology: configv1.HighlyAvailableArbiterMode,
			nodes: []*corev1.Node{
				newControlPlaneNode("master-0"),
				newControlPlaneNode("master-1"),
				newControlPlaneNode("arbiter-0"),
			},
			maxReplicas:      3,
			expectedReplicas: 2,
		},
		{
			name:             "External topology defaults to 2",
			topology:         configv1.ExternalTopologyMode,
			nodes:            nil,
			maxReplicas:      3,
			expectedReplicas: 2,
		},
		{
			name:     "External topology ignores visible nodes",
			topology: configv1.ExternalTopologyMode,
			nodes: []*corev1.Node{
				newControlPlaneNode("master-0"),
				newControlPlaneNode("master-1"),
				newControlPlaneNode("master-2"),
			},
			maxReplicas:      3,
			expectedReplicas: 2,
		},
		{
			name:     "HighlyAvailable with 3 nodes",
			topology: configv1.HighlyAvailableTopologyMode,
			nodes: []*corev1.Node{
				newControlPlaneNode("master-0"),
				newControlPlaneNode("master-1"),
				newControlPlaneNode("master-2"),
			},
			maxReplicas:      3,
			expectedReplicas: 3,
		},
		{
			name:     "HighlyAvailable with 5 nodes caps at maxReplicas",
			topology: configv1.HighlyAvailableTopologyMode,
			nodes: []*corev1.Node{
				newControlPlaneNode("master-0"),
				newControlPlaneNode("master-1"),
				newControlPlaneNode("master-2"),
				newControlPlaneNode("master-3"),
				newControlPlaneNode("master-4"),
			},
			maxReplicas:      3,
			expectedReplicas: 3,
		},
		{
			name:     "HighlyAvailable with maxReplicas 2",
			topology: configv1.HighlyAvailableTopologyMode,
			nodes: []*corev1.Node{
				newControlPlaneNode("master-0"),
				newControlPlaneNode("master-1"),
				newControlPlaneNode("master-2"),
			},
			maxReplicas:      2,
			expectedReplicas: 2,
		},
		{
			name:     "unknown topology with 2 nodes",
			topology: configv1.TopologyMode("SomeNewTopology"),
			nodes: []*corev1.Node{
				newControlPlaneNode("master-0"),
				newControlPlaneNode("master-1"),
			},
			maxReplicas:      3,
			expectedReplicas: 2,
		},
		{
			name:             "unknown topology with 1 node",
			topology:         configv1.TopologyMode("SomeNewTopology"),
			nodes:            []*corev1.Node{newControlPlaneNode("master-0")},
			maxReplicas:      3,
			expectedReplicas: 1,
		},
		{
			name:             "unknown topology with 0 nodes floors at 1",
			topology:         configv1.TopologyMode("SomeNewTopology"),
			nodes:            nil,
			maxReplicas:      3,
			expectedReplicas: 1,
		},
		{
			name:     "unknown topology with 5 nodes caps at maxReplicas",
			topology: configv1.TopologyMode("SomeNewTopology"),
			nodes: []*corev1.Node{
				newControlPlaneNode("master-0"),
				newControlPlaneNode("master-1"),
				newControlPlaneNode("master-2"),
				newControlPlaneNode("master-3"),
				newControlPlaneNode("master-4"),
			},
			maxReplicas:      3,
			expectedReplicas: 3,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			nodeLister := fakeNodeLister(tc.nodes...)
			infraLister := fakeInfrastructureLister(newInfrastructure(tc.topology))
			deployment := makeDeployment(withDeploymentReplicas(1))

			hook := WithTopologyAwareReplicasHook(infraLister, nodeLister, tc.maxReplicas)
			if err := hook(nil, deployment); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got := *deployment.Spec.Replicas; got != tc.expectedReplicas {
				t.Errorf("expected %d replicas, got %d", tc.expectedReplicas, got)
			}
		})
	}
}

func TestWithTopologyAwareSchedulingHook(t *testing.T) {
	testCases := []struct {
		name                   string
		replicas               int32
		maxSurge               int32
		expectedMaxUnavailable int32
		expectedMaxSurge       int32
		expectAntiAffinity     bool
	}{
		{
			name:                   "1 replica removes anti-affinity",
			replicas:               1,
			maxSurge:               1,
			expectedMaxUnavailable: 1,
			expectedMaxSurge:       1,
			expectAntiAffinity:     false,
		},
		{
			name:                   "2 replicas sets required anti-affinity",
			replicas:               2,
			maxSurge:               1,
			expectedMaxUnavailable: 1,
			expectedMaxSurge:       1,
			expectAntiAffinity:     true,
		},
		{
			name:                   "3 replicas sets maxUnavailable 2",
			replicas:               3,
			maxSurge:               1,
			expectedMaxUnavailable: 2,
			expectedMaxSurge:       1,
			expectAntiAffinity:     true,
		},
		{
			name:                   "custom maxSurge is respected",
			replicas:               3,
			maxSurge:               3,
			expectedMaxUnavailable: 2,
			expectedMaxSurge:       3,
			expectAntiAffinity:     true,
		},
	}

	t.Run("preserves existing NodeAffinity when setting anti-affinity", func(t *testing.T) {
		deployment := makeDeployment(withDeploymentReplicas(2))
		deployment.Spec.Strategy = appsv1.DeploymentStrategy{
			Type:          appsv1.RollingUpdateDeploymentStrategyType,
			RollingUpdate: &appsv1.RollingUpdateDeployment{},
		}
		deployment.Spec.Template.Spec.Affinity = &corev1.Affinity{
			NodeAffinity: &corev1.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
					NodeSelectorTerms: []corev1.NodeSelectorTerm{
						{
							MatchExpressions: []corev1.NodeSelectorRequirement{
								{
									Key:      "node-role.kubernetes.io/worker",
									Operator: corev1.NodeSelectorOpExists,
								},
							},
						},
					},
				},
			},
		}

		hook := WithTopologyAwareSchedulingHook("test-app", 1)
		if err := hook(nil, deployment); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if deployment.Spec.Template.Spec.Affinity.NodeAffinity == nil {
			t.Fatal("NodeAffinity was dropped")
		}
		if deployment.Spec.Template.Spec.Affinity.PodAntiAffinity == nil {
			t.Fatal("PodAntiAffinity was not set")
		}
	})

	t.Run("preserves existing NodeAffinity when clearing anti-affinity", func(t *testing.T) {
		deployment := makeDeployment(withDeploymentReplicas(1))
		deployment.Spec.Strategy = appsv1.DeploymentStrategy{
			Type:          appsv1.RollingUpdateDeploymentStrategyType,
			RollingUpdate: &appsv1.RollingUpdateDeployment{},
		}
		deployment.Spec.Template.Spec.Affinity = &corev1.Affinity{
			NodeAffinity: &corev1.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
					NodeSelectorTerms: []corev1.NodeSelectorTerm{
						{
							MatchExpressions: []corev1.NodeSelectorRequirement{
								{
									Key:      "node-role.kubernetes.io/worker",
									Operator: corev1.NodeSelectorOpExists,
								},
							},
						},
					},
				},
			},
			PodAntiAffinity: &corev1.PodAntiAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
					{TopologyKey: "kubernetes.io/hostname"},
				},
			},
		}

		hook := WithTopologyAwareSchedulingHook("test-app", 1)
		if err := hook(nil, deployment); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if deployment.Spec.Template.Spec.Affinity == nil {
			t.Fatal("Affinity should not be nil when NodeAffinity exists")
		}
		if deployment.Spec.Template.Spec.Affinity.NodeAffinity == nil {
			t.Fatal("NodeAffinity was dropped")
		}
		if deployment.Spec.Template.Spec.Affinity.PodAntiAffinity != nil {
			t.Fatal("PodAntiAffinity should have been cleared")
		}
	})

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			deployment := makeDeployment(withDeploymentReplicas(tc.replicas))
			deployment.Spec.Strategy = appsv1.DeploymentStrategy{
				Type:          appsv1.RollingUpdateDeploymentStrategyType,
				RollingUpdate: &appsv1.RollingUpdateDeployment{},
			}

			hook := WithTopologyAwareSchedulingHook("test-app", tc.maxSurge)
			if err := hook(nil, deployment); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			expectedMaxUnavailable := intstr.FromInt32(tc.expectedMaxUnavailable)
			expectedMaxSurge := intstr.FromInt32(tc.expectedMaxSurge)

			if diff := cmp.Diff(&expectedMaxUnavailable, deployment.Spec.Strategy.RollingUpdate.MaxUnavailable); diff != "" {
				t.Errorf("unexpected maxUnavailable (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(&expectedMaxSurge, deployment.Spec.Strategy.RollingUpdate.MaxSurge); diff != "" {
				t.Errorf("unexpected maxSurge (-want +got):\n%s", diff)
			}

			if tc.expectAntiAffinity {
				if deployment.Spec.Template.Spec.Affinity == nil {
					t.Fatal("expected anti-affinity to be set, got nil")
				}
				paa := deployment.Spec.Template.Spec.Affinity.PodAntiAffinity
				if paa == nil {
					t.Fatal("expected PodAntiAffinity to be set, got nil")
				}
				if len(paa.RequiredDuringSchedulingIgnoredDuringExecution) != 1 {
					t.Fatalf("expected 1 required anti-affinity term, got %d", len(paa.RequiredDuringSchedulingIgnoredDuringExecution))
				}
				term := paa.RequiredDuringSchedulingIgnoredDuringExecution[0]
				if term.TopologyKey != "kubernetes.io/hostname" {
					t.Errorf("expected topologyKey kubernetes.io/hostname, got %s", term.TopologyKey)
				}
				if len(term.LabelSelector.MatchExpressions) != 1 ||
					term.LabelSelector.MatchExpressions[0].Key != "app" ||
					term.LabelSelector.MatchExpressions[0].Values[0] != "test-app" {
					t.Errorf("unexpected label selector: %+v", term.LabelSelector)
				}
			} else {
				if deployment.Spec.Template.Spec.Affinity != nil {
					t.Errorf("expected nil affinity, got %+v", deployment.Spec.Template.Spec.Affinity)
				}
			}
		})
	}
}

func TestWithControlPlaneNodeSelectorHook(t *testing.T) {
	testCases := []struct {
		name                 string
		topology             configv1.TopologyMode
		expectedNodeSelector map[string]string
	}{
		{
			name:                 "HighlyAvailable sets control-plane selector",
			topology:             configv1.HighlyAvailableTopologyMode,
			expectedNodeSelector: map[string]string{"node-role.kubernetes.io/control-plane": ""},
		},
		{
			name:                 "SingleReplica sets control-plane selector",
			topology:             configv1.SingleReplicaTopologyMode,
			expectedNodeSelector: map[string]string{"node-role.kubernetes.io/control-plane": ""},
		},
		{
			name:                 "External skips and clears control-plane selector",
			topology:             configv1.ExternalTopologyMode,
			expectedNodeSelector: nil,
		},
		{
			name:                 "DualReplica sets control-plane selector",
			topology:             configv1.DualReplicaTopologyMode,
			expectedNodeSelector: map[string]string{"node-role.kubernetes.io/control-plane": ""},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			infraLister := fakeInfrastructureLister(newInfrastructure(tc.topology))
			deployment := makeDeployment()
			deployment.Spec.Template.Spec.NodeSelector = nil

			hook := WithControlPlaneNodeSelectorHook(infraLister)
			if err := hook(nil, deployment); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !equality.Semantic.DeepEqual(deployment.Spec.Template.Spec.NodeSelector, tc.expectedNodeSelector) {
				t.Errorf("unexpected nodeSelector:\n%s", cmp.Diff(tc.expectedNodeSelector, deployment.Spec.Template.Spec.NodeSelector))
			}
		})
	}

	t.Run("External clears pre-existing control-plane selector", func(t *testing.T) {
		infraLister := fakeInfrastructureLister(newInfrastructure(configv1.ExternalTopologyMode))
		deployment := makeDeployment()
		deployment.Spec.Template.Spec.NodeSelector = map[string]string{
			"node-role.kubernetes.io/control-plane": "",
		}

		hook := WithControlPlaneNodeSelectorHook(infraLister)
		if err := hook(nil, deployment); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if deployment.Spec.Template.Spec.NodeSelector != nil {
			t.Errorf("expected nil nodeSelector after clearing CP selector, got %v", deployment.Spec.Template.Spec.NodeSelector)
		}
	})

	t.Run("External preserves non-control-plane selectors", func(t *testing.T) {
		infraLister := fakeInfrastructureLister(newInfrastructure(configv1.ExternalTopologyMode))
		deployment := makeDeployment()
		deployment.Spec.Template.Spec.NodeSelector = map[string]string{
			"node-role.kubernetes.io/control-plane": "",
			"custom-label":                          "value",
		}

		hook := WithControlPlaneNodeSelectorHook(infraLister)
		if err := hook(nil, deployment); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		expected := map[string]string{"custom-label": "value"}
		if !equality.Semantic.DeepEqual(deployment.Spec.Template.Spec.NodeSelector, expected) {
			t.Errorf("unexpected nodeSelector:\n%s", cmp.Diff(expected, deployment.Spec.Template.Spec.NodeSelector))
		}
	})
}

func TestTopologyAwareReplicas(t *testing.T) {
	testCases := []struct {
		name                  string
		topology              configv1.TopologyMode
		controlPlaneNodeCount int
		maxReplicas           int32
		expected              int32
	}{
		{
			name:                  "SingleReplica always returns 1",
			topology:              configv1.SingleReplicaTopologyMode,
			controlPlaneNodeCount: 3,
			maxReplicas:           3,
			expected:              1,
		},
		{
			name:                  "DualReplica always returns 2",
			topology:              configv1.DualReplicaTopologyMode,
			controlPlaneNodeCount: 2,
			maxReplicas:           3,
			expected:              2,
		},
		{
			name:                  "HighlyAvailableArbiter returns 2",
			topology:              configv1.HighlyAvailableArbiterMode,
			controlPlaneNodeCount: 3,
			maxReplicas:           3,
			expected:              2,
		},
		{
			name:                  "External returns 2",
			topology:              configv1.ExternalTopologyMode,
			controlPlaneNodeCount: 0,
			maxReplicas:           3,
			expected:              2,
		},
		{
			name:                  "HighlyAvailable returns maxReplicas",
			topology:              configv1.HighlyAvailableTopologyMode,
			controlPlaneNodeCount: 5,
			maxReplicas:           3,
			expected:              3,
		},
		{
			name:                  "unknown topology uses node count",
			topology:              configv1.TopologyMode("FutureTopology"),
			controlPlaneNodeCount: 2,
			maxReplicas:           3,
			expected:              2,
		},
		{
			name:                  "unknown topology caps at maxReplicas",
			topology:              configv1.TopologyMode("FutureTopology"),
			controlPlaneNodeCount: 10,
			maxReplicas:           3,
			expected:              3,
		},
		{
			name:                  "unknown topology floors at 1",
			topology:              configv1.TopologyMode("FutureTopology"),
			controlPlaneNodeCount: 0,
			maxReplicas:           3,
			expected:              1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := TopologyAwareReplicas(tc.topology, tc.controlPlaneNodeCount, tc.maxReplicas)
			if got != tc.expected {
				t.Errorf("expected %d, got %d", tc.expected, got)
			}
		})
	}
}

func TestSetTopologyAwareScheduling(t *testing.T) {
	testCases := []struct {
		name                     string
		topology                 configv1.TopologyMode
		controlPlaneNodeCount    int
		appLabelValue            string
		maxSurge                 int32
		maxReplicas              int32
		expectedReplicas         int32
		expectedMaxUnavailable   int32
		expectedMaxSurge         int32
		expectAntiAffinity       bool
		expectedNodeSelectorKeys []string
	}{
		{
			name:                     "SingleReplica: 1 replica, no anti-affinity, CP selector",
			topology:                 configv1.SingleReplicaTopologyMode,
			controlPlaneNodeCount:    1,
			appLabelValue:            "test-app",
			maxSurge:                 1,
			maxReplicas:              3,
			expectedReplicas:         1,
			expectedMaxUnavailable:   1,
			expectedMaxSurge:         1,
			expectAntiAffinity:       false,
			expectedNodeSelectorKeys: []string{"node-role.kubernetes.io/control-plane"},
		},
		{
			name:                     "HighlyAvailable: 3 replicas, anti-affinity, CP selector",
			topology:                 configv1.HighlyAvailableTopologyMode,
			controlPlaneNodeCount:    3,
			appLabelValue:            "test-app",
			maxSurge:                 1,
			maxReplicas:              3,
			expectedReplicas:         3,
			expectedMaxUnavailable:   2,
			expectedMaxSurge:         1,
			expectAntiAffinity:       true,
			expectedNodeSelectorKeys: []string{"node-role.kubernetes.io/control-plane"},
		},
		{
			name:                     "External: 2 replicas, anti-affinity, no CP selector",
			topology:                 configv1.ExternalTopologyMode,
			controlPlaneNodeCount:    0,
			appLabelValue:            "test-app",
			maxSurge:                 1,
			maxReplicas:              3,
			expectedReplicas:         2,
			expectedMaxUnavailable:   1,
			expectedMaxSurge:         1,
			expectAntiAffinity:       true,
			expectedNodeSelectorKeys: nil,
		},
		{
			name:                     "DualReplica: 2 replicas, anti-affinity, CP selector",
			topology:                 configv1.DualReplicaTopologyMode,
			controlPlaneNodeCount:    2,
			appLabelValue:            "migrator",
			maxSurge:                 0,
			maxReplicas:              3,
			expectedReplicas:         2,
			expectedMaxUnavailable:   1,
			expectedMaxSurge:         0,
			expectAntiAffinity:       true,
			expectedNodeSelectorKeys: []string{"node-role.kubernetes.io/control-plane"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			deployment := makeDeployment(withDeploymentReplicas(1))
			deployment.Spec.Strategy = appsv1.DeploymentStrategy{
				Type:          appsv1.RollingUpdateDeploymentStrategyType,
				RollingUpdate: &appsv1.RollingUpdateDeployment{},
			}
			deployment.Spec.Template.Spec.NodeSelector = nil

			SetTopologyAwareScheduling(deployment, tc.topology, tc.controlPlaneNodeCount, tc.appLabelValue, tc.maxSurge, tc.maxReplicas)

			if got := *deployment.Spec.Replicas; got != tc.expectedReplicas {
				t.Errorf("replicas: expected %d, got %d", tc.expectedReplicas, got)
			}

			expectedMaxUnavailable := intstr.FromInt32(tc.expectedMaxUnavailable)
			if diff := cmp.Diff(&expectedMaxUnavailable, deployment.Spec.Strategy.RollingUpdate.MaxUnavailable); diff != "" {
				t.Errorf("unexpected maxUnavailable (-want +got):\n%s", diff)
			}
			expectedMaxSurge := intstr.FromInt32(tc.expectedMaxSurge)
			if diff := cmp.Diff(&expectedMaxSurge, deployment.Spec.Strategy.RollingUpdate.MaxSurge); diff != "" {
				t.Errorf("unexpected maxSurge (-want +got):\n%s", diff)
			}

			if tc.expectAntiAffinity {
				if deployment.Spec.Template.Spec.Affinity == nil || deployment.Spec.Template.Spec.Affinity.PodAntiAffinity == nil {
					t.Fatal("expected PodAntiAffinity to be set")
				}
				terms := deployment.Spec.Template.Spec.Affinity.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution
				if len(terms) != 1 || terms[0].LabelSelector.MatchExpressions[0].Values[0] != tc.appLabelValue {
					t.Errorf("unexpected anti-affinity label value: %+v", terms)
				}
			} else if deployment.Spec.Template.Spec.Affinity != nil && deployment.Spec.Template.Spec.Affinity.PodAntiAffinity != nil {
				t.Error("expected no PodAntiAffinity")
			}

			if len(tc.expectedNodeSelectorKeys) == 0 {
				if len(deployment.Spec.Template.Spec.NodeSelector) > 0 {
					t.Errorf("expected no node selectors, got %v", deployment.Spec.Template.Spec.NodeSelector)
				}
			} else {
				for _, key := range tc.expectedNodeSelectorKeys {
					if _, ok := deployment.Spec.Template.Spec.NodeSelector[key]; !ok {
						t.Errorf("expected node selector key %q", key)
					}
				}
			}
		})
	}
}

func TestWithTopologyAwareSchedulingHooks(t *testing.T) {
	testCases := []struct {
		name     string
		topology configv1.TopologyMode
		nodes    []*corev1.Node
	}{
		{
			name:     "HighlyAvailable",
			topology: configv1.HighlyAvailableTopologyMode,
			nodes: []*corev1.Node{
				newControlPlaneNode("master-0"),
				newControlPlaneNode("master-1"),
				newControlPlaneNode("master-2"),
			},
		},
		{
			name:     "SingleReplica",
			topology: configv1.SingleReplicaTopologyMode,
			nodes:    []*corev1.Node{newControlPlaneNode("master-0")},
		},
		{
			name:     "External",
			topology: configv1.ExternalTopologyMode,
			nodes:    nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			infraLister := fakeInfrastructureLister(newInfrastructure(tc.topology))
			nodeLister := fakeNodeLister(tc.nodes...)

			// Apply using individual hooks in explicit order.
			individual := makeDeployment(withDeploymentReplicas(1))
			individual.Spec.Strategy = appsv1.DeploymentStrategy{
				Type:          appsv1.RollingUpdateDeploymentStrategyType,
				RollingUpdate: &appsv1.RollingUpdateDeployment{},
			}
			individual.Spec.Template.Spec.NodeSelector = nil
			for _, hook := range []DeploymentHookFunc{
				WithTopologyAwareReplicasHook(infraLister, nodeLister, 3),
				WithControlPlaneNodeSelectorHook(infraLister),
				WithTopologyAwareSchedulingHook("test-app", 1),
			} {
				if err := hook(nil, individual); err != nil {
					t.Fatalf("individual hook error: %v", err)
				}
			}

			// Apply using the combined convenience function.
			combined := makeDeployment(withDeploymentReplicas(1))
			combined.Spec.Strategy = appsv1.DeploymentStrategy{
				Type:          appsv1.RollingUpdateDeploymentStrategyType,
				RollingUpdate: &appsv1.RollingUpdateDeployment{},
			}
			combined.Spec.Template.Spec.NodeSelector = nil
			for _, hook := range WithTopologyAwareSchedulingHooks(infraLister, nodeLister, "test-app", 1, 3) {
				if err := hook(nil, combined); err != nil {
					t.Fatalf("combined hook error: %v", err)
				}
			}

			if !equality.Semantic.DeepEqual(individual.Spec, combined.Spec) {
				t.Errorf("combined hooks produced different result from individual hooks:\n%s", cmp.Diff(individual.Spec, combined.Spec))
			}
		})
	}
}
