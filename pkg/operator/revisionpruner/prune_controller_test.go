package revisionpruner

import (
	"context"
	"fmt"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/clock"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/v1helpers"
)

func TestConfigMapsToBePruned(t *testing.T) {
	tests := []struct {
		name           string
		minRevision    int
		prefixes       []string
		configMaps     []*corev1.ConfigMap
		expectedPruned []string
	}{
		{
			name:           "no configmaps",
			minRevision:    10,
			prefixes:       []string{"revision-status-"},
			configMaps:     []*corev1.ConfigMap{},
			expectedPruned: nil,
		},
		{
			name:        "not enough old revisions to prune",
			minRevision: 10,
			prefixes:    []string{"revision-status-"},
			configMaps: []*corev1.ConfigMap{
				newConfigMap("revision-status-", 5),
				newConfigMap("revision-status-", 6),
				newConfigMap("revision-status-", 7),
				newConfigMap("revision-status-", 8),
				newConfigMap("revision-status-", 9),
				newConfigMap("revision-status-", 10),
			},
			expectedPruned: nil,
		},
		{
			name:        "prune oldest revisions beyond buffer",
			minRevision: 10,
			prefixes:    []string{"revision-status-"},
			configMaps: []*corev1.ConfigMap{
				newConfigMap("revision-status-", 1),
				newConfigMap("revision-status-", 2),
				newConfigMap("revision-status-", 3),
				newConfigMap("revision-status-", 4),
				newConfigMap("revision-status-", 5),
				newConfigMap("revision-status-", 6),
				newConfigMap("revision-status-", 7),
				newConfigMap("revision-status-", 8),
				newConfigMap("revision-status-", 9),
				newConfigMap("revision-status-", 10),
			},
			expectedPruned: []string{
				"revision-status-1",
				"revision-status-2",
				"revision-status-3",
				"revision-status-4",
			},
		},
		{
			name:        "skip non-matching configmaps",
			minRevision: 8,
			prefixes:    []string{"revision-status-"},
			configMaps: []*corev1.ConfigMap{
				newConfigMap("revision-status-", 1),
				newConfigMap("revision-status-", 2),
				newConfigMap("revision-status-", 3),
				newConfigMap("revision-status-", 4),
				newConfigMap("revision-status-", 5),
				newConfigMap("revision-status-", 6),
				{ObjectMeta: metav1.ObjectMeta{Name: "audit-1", Namespace: "test"}},
				{ObjectMeta: metav1.ObjectMeta{Name: "some-other-config", Namespace: "test"}},
				newConfigMap("revision-status-", 7),
				newConfigMap("revision-status-", 8),
			},
			expectedPruned: []string{
				"revision-status-1",
				"revision-status-2",
			},
		},
		{
			name:        "skip revisions at or above minRevision",
			minRevision: 5,
			prefixes:    []string{"revision-status-"},
			configMaps: []*corev1.ConfigMap{
				newConfigMap("revision-status-", 1),
				newConfigMap("revision-status-", 2),
				newConfigMap("revision-status-", 3),
				newConfigMap("revision-status-", 4),
				newConfigMap("revision-status-", 5),
				newConfigMap("revision-status-", 6),
			},
			expectedPruned: nil,
		},
		{
			name:        "prune with gaps in revision numbers",
			minRevision: 20,
			prefixes:    []string{"revision-status-"},
			configMaps: []*corev1.ConfigMap{
				newConfigMap("revision-status-", 1),
				newConfigMap("revision-status-", 3),
				newConfigMap("revision-status-", 5),
				newConfigMap("revision-status-", 7),
				newConfigMap("revision-status-", 8),
				newConfigMap("revision-status-", 12),
				newConfigMap("revision-status-", 15),
				newConfigMap("revision-status-", 18),
				newConfigMap("revision-status-", 20),
			},
			expectedPruned: []string{
				"revision-status-1",
				"revision-status-3",
				"revision-status-5",
			},
		},
		{
			name:        "skip configmaps with invalid suffix",
			minRevision: 10,
			prefixes:    []string{"revision-status-"},
			configMaps: []*corev1.ConfigMap{
				newConfigMap("revision-status-", 0), // invalid, should be skipped
				newConfigMap("revision-status-", 1),
				newConfigMap("revision-status-", 2),
				newConfigMap("revision-status-", 3),
				newConfigMap("revision-status-", 4),
				newConfigMap("revision-status-", 5),
				newConfigMap("revision-status-", 6),
				{ObjectMeta: metav1.ObjectMeta{Name: "revision-status-abc", Namespace: "test"}},
				{ObjectMeta: metav1.ObjectMeta{Name: "revision-status-1.5", Namespace: "test"}},
				newConfigMap("revision-status-", 8),
				newConfigMap("revision-status-", 9),
				newConfigMap("revision-status-", 10),
			},
			expectedPruned: []string{
				"revision-status-1",
				"revision-status-2",
				"revision-status-3",
			},
		},
		{
			name:        "multiple prefixes - same revision numbers",
			minRevision: 10,
			prefixes:    []string{"revision-status-", "installer-status-"},
			configMaps: []*corev1.ConfigMap{
				newConfigMap("revision-status-", 1),
				newConfigMap("revision-status-", 2),
				newConfigMap("revision-status-", 3),
				newConfigMap("revision-status-", 4),
				newConfigMap("revision-status-", 5),
				newConfigMap("revision-status-", 6),
				newConfigMap("installer-status-", 1),
				newConfigMap("installer-status-", 2),
				newConfigMap("installer-status-", 3),
				newConfigMap("installer-status-", 4),
				newConfigMap("installer-status-", 5),
				newConfigMap("installer-status-", 6),
			},
			expectedPruned: []string{
				"revision-status-1",
				"installer-status-1",
			},
		},
		{
			name:        "multiple prefixes - interleaved revisions pruned independently per prefix",
			minRevision: 15,
			prefixes:    []string{"revision-status-", "installer-status-"},
			configMaps: []*corev1.ConfigMap{
				newConfigMap("revision-status-", 1),
				newConfigMap("revision-status-", 3),
				newConfigMap("revision-status-", 5),
				newConfigMap("revision-status-", 8),
				newConfigMap("revision-status-", 10),
				newConfigMap("revision-status-", 12),
				newConfigMap("revision-status-", 14),
				newConfigMap("installer-status-", 2),
				newConfigMap("installer-status-", 4),
				newConfigMap("installer-status-", 6),
				newConfigMap("installer-status-", 9),
				newConfigMap("installer-status-", 11),
				newConfigMap("installer-status-", 13),
				newConfigMap("installer-status-", 15),
			},
			expectedPruned: []string{
				"revision-status-1",
				"revision-status-3",
				"installer-status-2",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := configMapsToBePruned(tt.minRevision, tt.prefixes, tt.configMaps)

			if len(result) != len(tt.expectedPruned) {
				t.Errorf("expected %d configmaps to be pruned, got %d", len(tt.expectedPruned), len(result))
				for _, cm := range result {
					t.Logf("  got: %s", cm.Name)
				}
				return
			}

			resultNames := make(map[string]bool)
			for _, cm := range result {
				resultNames[cm.Name] = true
			}

			for _, expected := range tt.expectedPruned {
				if !resultNames[expected] {
					t.Errorf("expected configmap %s to be pruned, but it wasn't", expected)
				}
			}
		})
	}
}

func TestMinPodRevision(t *testing.T) {
	tests := []struct {
		name     string
		pods     []*corev1.Pod
		expected int
	}{
		{
			name:     "no pods",
			pods:     []*corev1.Pod{},
			expected: 0,
		},
		{
			name: "pods without revision label",
			pods: []*corev1.Pod{
				{ObjectMeta: metav1.ObjectMeta{Name: "pod-1", Labels: map[string]string{"app": "test"}}},
			},
			expected: 0,
		},
		{
			name: "single pod with revision",
			pods: []*corev1.Pod{
				{ObjectMeta: metav1.ObjectMeta{Name: "pod-1", Labels: map[string]string{"revision": "5"}}},
			},
			expected: 5,
		},
		{
			name: "multiple pods returns minimum",
			pods: []*corev1.Pod{
				{ObjectMeta: metav1.ObjectMeta{Name: "pod-1", Labels: map[string]string{"revision": "10"}}},
				{ObjectMeta: metav1.ObjectMeta{Name: "pod-2", Labels: map[string]string{"revision": "5"}}},
				{ObjectMeta: metav1.ObjectMeta{Name: "pod-3", Labels: map[string]string{"revision": "8"}}},
			},
			expected: 5,
		},
		{
			name: "skip pods with invalid zero or negative revision",
			pods: []*corev1.Pod{
				{ObjectMeta: metav1.ObjectMeta{Name: "pod-1", Labels: map[string]string{"revision": "10"}}},
				{ObjectMeta: metav1.ObjectMeta{Name: "pod-2", Labels: map[string]string{"revision": "invalid"}}},
				{ObjectMeta: metav1.ObjectMeta{Name: "pod-3", Labels: map[string]string{"revision": "-1"}}},
				{ObjectMeta: metav1.ObjectMeta{Name: "pod-4", Labels: map[string]string{"revision": "8"}}},
				{ObjectMeta: metav1.ObjectMeta{Name: "pod-5", Labels: map[string]string{"revision": "2"}}},
				{ObjectMeta: metav1.ObjectMeta{Name: "pod-6", Labels: map[string]string{"revision": "0"}}},
			},
			expected: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := minPodRevision(tt.pods)
			if result != tt.expected {
				t.Errorf("expected minRevision %d, got %d", tt.expected, result)
			}
		})
	}
}

func TestRevisionPruneControllerSync(t *testing.T) {
	tests := []struct {
		name                 string
		prefixes             []string
		pods                 []runtime.Object
		configMaps           []runtime.Object
		expectedDeletedCMs   []string
		expectedRemainingCMs []string
	}{
		{
			name:     "prune old configmaps",
			prefixes: []string{"revision-status-"},
			pods: []runtime.Object{
				newPod("pod-1", "10"),
			},
			configMaps: []runtime.Object{
				newConfigMap("revision-status-", 1),
				newConfigMap("revision-status-", 2),
				newConfigMap("revision-status-", 3),
				newConfigMap("revision-status-", 4),
				newConfigMap("revision-status-", 5),
				newConfigMap("revision-status-", 6),
				newConfigMap("revision-status-", 7),
				newConfigMap("revision-status-", 8),
				newConfigMap("revision-status-", 9),
				newConfigMap("revision-status-", 10),
			},
			expectedDeletedCMs: []string{
				"revision-status-1",
				"revision-status-2",
				"revision-status-3",
				"revision-status-4",
			},
			expectedRemainingCMs: []string{
				"revision-status-5",
				"revision-status-6",
				"revision-status-7",
				"revision-status-8",
				"revision-status-9",
				"revision-status-10",
			},
		},
		{
			name:     "no pruning when not enough old revisions",
			prefixes: []string{"revision-status-"},
			pods: []runtime.Object{
				newPod("pod-1", "10"),
			},
			configMaps: []runtime.Object{
				newConfigMap("revision-status-", 1),
				newConfigMap("revision-status-", 2),
				newConfigMap("revision-status-", 3),
				newConfigMap("revision-status-", 4),
				newConfigMap("revision-status-", 5),
				newConfigMap("revision-status-", 10),
			},
			expectedDeletedCMs: []string{},
			expectedRemainingCMs: []string{
				"revision-status-1",
				"revision-status-2",
				"revision-status-3",
				"revision-status-4",
				"revision-status-5",
				"revision-status-10",
			},
		},
		{
			name:     "no pruning when no pods exist",
			prefixes: []string{"revision-status-"},
			pods:     []runtime.Object{},
			configMaps: []runtime.Object{
				newConfigMap("revision-status-", 1),
				newConfigMap("revision-status-", 2),
				newConfigMap("revision-status-", 3),
				newConfigMap("revision-status-", 4),
				newConfigMap("revision-status-", 5),
				newConfigMap("revision-status-", 6),
			},
			expectedDeletedCMs: []string{},
			expectedRemainingCMs: []string{
				"revision-status-1",
				"revision-status-2",
				"revision-status-3",
				"revision-status-4",
				"revision-status-5",
				"revision-status-6",
			},
		},
		{
			name:     "no pruning when no pods have revision labels",
			prefixes: []string{"revision-status-"},
			pods: []runtime.Object{
				&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod-1", Namespace: "test", Labels: map[string]string{"apiserver": "true"}}},
			},
			configMaps: []runtime.Object{
				newConfigMap("revision-status-", 1),
				newConfigMap("revision-status-", 2),
				newConfigMap("revision-status-", 3),
				newConfigMap("revision-status-", 4),
				newConfigMap("revision-status-", 5),
				newConfigMap("revision-status-", 6),
			},
			expectedDeletedCMs: []string{},
			expectedRemainingCMs: []string{
				"revision-status-1",
				"revision-status-2",
				"revision-status-3",
				"revision-status-4",
				"revision-status-5",
				"revision-status-6",
			},
		},
		{
			name:     "prune based on minimum pod revision",
			prefixes: []string{"revision-status-"},
			pods: []runtime.Object{
				newPod("pod-1", "15"),
				newPod("pod-2", "10"), // minimum
				newPod("pod-3", "12"),
			},
			configMaps: []runtime.Object{
				newConfigMap("revision-status-", 1),
				newConfigMap("revision-status-", 2),
				newConfigMap("revision-status-", 3),
				newConfigMap("revision-status-", 4),
				newConfigMap("revision-status-", 5),
				newConfigMap("revision-status-", 6),
				newConfigMap("revision-status-", 7),
				newConfigMap("revision-status-", 8),
				newConfigMap("revision-status-", 9),
				newConfigMap("revision-status-", 10),
			},
			expectedDeletedCMs: []string{
				"revision-status-1",
				"revision-status-2",
				"revision-status-3",
				"revision-status-4",
			},
			expectedRemainingCMs: []string{
				"revision-status-5",
				"revision-status-6",
				"revision-status-7",
				"revision-status-8",
				"revision-status-9",
				"revision-status-10",
			},
		},
		{
			name:     "multiple prefixes",
			prefixes: []string{"revision-status-", "installer-status-"},
			pods: []runtime.Object{
				newPod("pod-1", "10"),
			},
			configMaps: []runtime.Object{
				newConfigMap("revision-status-", 1),
				newConfigMap("revision-status-", 2),
				newConfigMap("revision-status-", 3),
				newConfigMap("revision-status-", 4),
				newConfigMap("revision-status-", 5),
				newConfigMap("revision-status-", 6),
				newConfigMap("installer-status-", 1),
				newConfigMap("installer-status-", 2),
				newConfigMap("installer-status-", 3),
				newConfigMap("installer-status-", 4),
				newConfigMap("installer-status-", 5),
				newConfigMap("installer-status-", 6),
			},
			expectedDeletedCMs: []string{
				"revision-status-1",
				"installer-status-1",
			},
			expectedRemainingCMs: []string{
				"revision-status-2",
				"revision-status-3",
				"revision-status-4",
				"revision-status-5",
				"revision-status-6",
				"installer-status-2",
				"installer-status-3",
				"installer-status-4",
				"installer-status-5",
				"installer-status-6",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allObjects := append(tt.pods, tt.configMaps...)
			kubeClient := fake.NewSimpleClientset(allObjects...)

			kubeInformers := informers.NewSharedInformerFactoryWithOptions(
				kubeClient,
				0,
				informers.WithNamespace("test"),
			)

			for _, obj := range tt.pods {
				if err := kubeInformers.Core().V1().Pods().Informer().GetStore().Add(obj); err != nil {
					t.Fatalf("failed to add pod to store: %v", err)
				}
			}
			for _, obj := range tt.configMaps {
				if err := kubeInformers.Core().V1().ConfigMaps().Informer().GetStore().Add(obj); err != nil {
					t.Fatalf("failed to add configmap to store: %v", err)
				}
			}

			eventRecorder := events.NewInMemoryRecorder("test", clock.RealClock{})

			c := &ConfigMapRevisionPruneController{
				targetNamespace:   "test",
				configMapPrefixes: tt.prefixes,
				podSelector:       labels.SelectorFromSet(map[string]string{"apiserver": "true"}),
				configMapGetter:   kubeClient.CoreV1(),
				podInformer:       kubeInformers.Core().V1().Pods(),
				configMapInformer: kubeInformers.Core().V1().ConfigMaps(),
			}

			syncCtx := factory.NewSyncContext("test", eventRecorder)
			if err := c.sync(context.Background(), syncCtx); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			for _, cmName := range tt.expectedDeletedCMs {
				_, err := kubeClient.CoreV1().ConfigMaps("test").Get(context.Background(), cmName, metav1.GetOptions{})
				if err == nil {
					t.Errorf("expected configmap %s to be deleted, but it still exists", cmName)
				} else if !errors.IsNotFound(err) {
					t.Errorf("expected NotFound error for configmap %s, got: %v", cmName, err)
				}
			}

			for _, cmName := range tt.expectedRemainingCMs {
				_, err := kubeClient.CoreV1().ConfigMaps("test").Get(context.Background(), cmName, metav1.GetOptions{})
				if err != nil {
					t.Errorf("expected configmap %s to remain, but got error: %v", cmName, err)
				}
			}
		})
	}
}

func TestNewConfigMapRevisionPruneController(t *testing.T) {
	kubeClient := fake.NewSimpleClientset()
	eventRecorder := events.NewInMemoryRecorder("test", clock.RealClock{})
	kubeInformers := v1helpers.NewKubeInformersForNamespaces(kubeClient, "test")

	controller := NewConfigMapRevisionPruneController(
		"test",
		[]string{"revision-status-", "installer-status-"},
		labels.SelectorFromSet(map[string]string{"apiserver": "true"}),
		kubeClient.CoreV1(),
		kubeInformers,
		eventRecorder,
	)

	if controller == nil {
		t.Fatal("expected controller to be created, got nil")
	}
}

func newConfigMap(prefix string, revision int) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s%d", prefix, revision),
			Namespace: "test",
		},
	}
}

func newPod(name, revision string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "test",
			Labels: map[string]string{
				"apiserver": "true",
				"revision":  revision,
			},
		},
	}
}
