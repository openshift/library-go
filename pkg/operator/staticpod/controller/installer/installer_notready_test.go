package installer

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	operatorv1 "github.com/openshift/api/operator/v1"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
	clocktesting "k8s.io/utils/clock/testing"
)

func TestNodeToStartRevisionWith_SkipsNotReadyNodes(t *testing.T) {
	now := time.Date(2026, 6, 26, 12, 0, 0, 0, time.UTC)

	fakeGetStaticPodState := func(ctx context.Context, nodeName string) (staticPodState, string, string, []string, time.Time, error) {
		switch nodeName {
		case "master-0":
			return staticPodStateReady, "5", "", nil, now, nil
		case "master-1":
			return staticPodStatePending, "4", "", nil, now, nil
		case "master-2":
			return staticPodStatePending, "3", "", nil, now, nil
		default:
			return staticPodStatePending, "1", "", nil, now, nil
		}
	}

	nodes := []operatorv1.NodeStatus{
		{NodeName: "master-0", CurrentRevision: 5},
		{NodeName: "master-1", CurrentRevision: 4},
		{NodeName: "master-2", CurrentRevision: 3},
	}

	tests := []struct {
		name               string
		notReadyNodes      map[string]bool
		expectedNodeIndex  int
		expectedContains   string
		noReadinessCheckFn bool
	}{
		{
			name:               "without readiness check, picks oldest not-ready (master-2)",
			notReadyNodes:      nil,
			expectedNodeIndex:  2,
			noReadinessCheckFn: true,
		},
		{
			name:              "with readiness check, all ready, still picks oldest not-ready (master-2)",
			notReadyNodes:     map[string]bool{},
			expectedNodeIndex: 2,
		},
		{
			name:              "master-2 is NotReady, picks master-1 instead",
			notReadyNodes:     map[string]bool{"master-2": true},
			expectedNodeIndex: 1,
		},
		{
			name:              "both master-1 and master-2 NotReady, picks master-0 (latest revision)",
			notReadyNodes:     map[string]bool{"master-1": true, "master-2": true},
			expectedNodeIndex: 0,
			expectedContains:  "is the oldest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var isNotReady func(string) bool
			if !tt.noReadinessCheckFn {
				isNotReady = func(nodeName string) bool {
					return tt.notReadyNodes[nodeName]
				}
			}

			idx, reason, err := nodeToStartRevisionWith(context.TODO(), fakeGetStaticPodState, nodes, isNotReady)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if idx != tt.expectedNodeIndex {
				t.Errorf("expected node index %d, got %d (reason: %s)", tt.expectedNodeIndex, idx, reason)
			}
			if tt.expectedContains != "" && !strings.Contains(reason, tt.expectedContains) {
				t.Errorf("expected reason to contain %q, got %q", tt.expectedContains, reason)
			}
		})
	}
}

func TestIsNodeNotReadyForTooLong(t *testing.T) {
	now := time.Date(2026, 6, 26, 12, 0, 0, 0, time.UTC)
	fakeClock := clocktesting.NewFakeClock(now)

	tests := []struct {
		name     string
		node     *corev1.Node
		expected bool
	}{
		{
			name: "node is Ready",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: "master-0"},
				Status: corev1.NodeStatus{
					Conditions: []corev1.NodeCondition{
						{
							Type:               corev1.NodeReady,
							Status:             corev1.ConditionTrue,
							LastTransitionTime: metav1.NewTime(now.Add(-1 * time.Hour)),
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "node NotReady for 5 minutes (below threshold)",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: "master-1"},
				Status: corev1.NodeStatus{
					Conditions: []corev1.NodeCondition{
						{
							Type:               corev1.NodeReady,
							Status:             corev1.ConditionFalse,
							LastTransitionTime: metav1.NewTime(now.Add(-5 * time.Minute)),
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "node NotReady for 15 minutes (above threshold)",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: "master-2"},
				Status: corev1.NodeStatus{
					Conditions: []corev1.NodeCondition{
						{
							Type:               corev1.NodeReady,
							Status:             corev1.ConditionFalse,
							LastTransitionTime: metav1.NewTime(now.Add(-15 * time.Minute)),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "node NotReady with Unknown status for 20 minutes",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: "master-3"},
				Status: corev1.NodeStatus{
					Conditions: []corev1.NodeCondition{
						{
							Type:               corev1.NodeReady,
							Status:             corev1.ConditionUnknown,
							LastTransitionTime: metav1.NewTime(now.Add(-20 * time.Minute)),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "node with no NodeReady condition",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: "master-4"},
				Status: corev1.NodeStatus{
					Conditions: []corev1.NodeCondition{},
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			if err := indexer.Add(tt.node); err != nil {
				t.Fatal(err)
			}
			nodeLister := &fakeNodeLister{indexer: indexer}

			c := &InstallerController{
				nodeLister: nodeLister,
				clock:      fakeClock,
			}

			result := c.isNodeNotReadyForTooLong(tt.node.Name)
			if result != tt.expected {
				t.Errorf("expected %v, got %v for node %s", tt.expected, result, tt.node.Name)
			}
		})
	}
}

func TestIsNodeNotReadyForTooLong_NilLister(t *testing.T) {
	c := &InstallerController{
		nodeLister: nil,
	}
	if c.isNodeNotReadyForTooLong("any-node") {
		t.Error("expected false when nodeLister is nil")
	}
}

type fakeNodeLister struct {
	indexer cache.Indexer
}

func (f *fakeNodeLister) List(selector labels.Selector) ([]*corev1.Node, error) {
	objs := f.indexer.List()
	nodes := make([]*corev1.Node, 0, len(objs))
	for _, obj := range objs {
		nodes = append(nodes, obj.(*corev1.Node))
	}
	return nodes, nil
}

func (f *fakeNodeLister) Get(name string) (*corev1.Node, error) {
	obj, exists, err := f.indexer.GetByKey(name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("node %q not found", name)
	}
	return obj.(*corev1.Node), nil
}
