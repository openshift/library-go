package ote

import (
	"context"
	"fmt"
	"time"

	configv1client "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
	"github.com/openshift/library-go/test/library"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
)

// WaitForAPIServerRollout waits for all API server pods to be recreated and running
// after a configuration change. Unlike WaitForAPIServerToStabilizeOnTheSameRevision which
// waits for pods to converge on the same revision, this function specifically waits for
// NEW pods (created after the function is called) to replace the old ones.
//
// This is useful when you make a configuration change and need to ensure all pods have
// been recreated with the new configuration, not just that they're on the same revision.
//
// Parameters:
//   - t: Logger interface for test output
//   - podClient: Pod client interface for the target namespace
//   - labelSelector: Label selector to identify API server pods (e.g., "apiserver=true")
//   - timeout: Maximum time to wait for rollout to complete
//
// Returns:
//   - error if timeout is reached or an error occurs during polling
//
// Note:
//   - All existing pods must be replaced by new pods created after this function is called
//   - Supports both single-node and multi-node deployments
func WaitForAPIServerRollout(t library.LoggingT, podClient corev1client.PodInterface, labelSelector string, timeout time.Duration) error {
	rolloutStartTime := time.Now()

	// Get current pods before we start waiting
	initialPods, err := podClient.List(context.Background(), metav1.ListOptions{
		LabelSelector: labelSelector,
	})
	if err != nil {
		t.Logf("Warning: Could not get initial pods: %v", err)
	}

	var oldestPodTime time.Time
	initialRevision := ""
	if initialPods != nil && len(initialPods.Items) > 0 {
		oldestPodTime = initialPods.Items[0].CreationTimestamp.Time
		for _, pod := range initialPods.Items {
			if pod.CreationTimestamp.Time.Before(oldestPodTime) {
				oldestPodTime = pod.CreationTimestamp.Time
			}
			if rev, ok := pod.Labels["revision"]; ok && initialRevision == "" {
				initialRevision = rev
			}
		}
		t.Logf("Initial state: %d pods, oldest created at %s, initial revision: %s",
			len(initialPods.Items), oldestPodTime.Format(time.RFC3339), initialRevision)
	}

	attempt := 0
	lastPodCount := 0
	lastNotRunningCount := 0

	return wait.PollUntilContextTimeout(context.Background(), 15*time.Second, timeout, false, func(ctx context.Context) (bool, error) {
		attempt++
		pods, err := podClient.List(ctx, metav1.ListOptions{
			LabelSelector: labelSelector,
		})
		if err != nil {
			t.Logf("[Attempt %d] Error listing pods: %v", attempt, err)
			return false, nil
		}

		if len(pods.Items) == 0 {
			t.Logf("[Attempt %d] No pods found yet", attempt)
			return false, nil
		}

		// Count pods and check if we have new pods (created after rollout started)
		notRunningCount := 0
		newPodsCount := 0
		runningNewPodsCount := 0
		var notRunningPods []string
		var currentRevision string

		for _, pod := range pods.Items {
			isNewPod := pod.CreationTimestamp.Time.After(rolloutStartTime)

			if pod.Status.Phase != corev1.PodRunning {
				notRunningCount++
				notRunningPods = append(notRunningPods, fmt.Sprintf("%s (%s)", pod.Name, pod.Status.Phase))
			}

			if isNewPod {
				newPodsCount++
				if pod.Status.Phase == corev1.PodRunning {
					runningNewPodsCount++
				}
			}

			if rev, ok := pod.Labels["revision"]; ok && currentRevision == "" {
				currentRevision = rev
			}
		}

		// Success condition: ALL pods must be new (created after rolloutStartTime) and running
		expectedPodCount := len(pods.Items)
		allPodsNewAndRunning := newPodsCount == expectedPodCount && runningNewPodsCount == expectedPodCount

		// Log only when state changes or every 4th attempt (1 minute)
		if notRunningCount != lastNotRunningCount || len(pods.Items) != lastPodCount || attempt%4 == 0 {
			if notRunningCount > 0 {
				t.Logf("[Attempt %d] %d/%d pods running. Not running: %v. New pods: %d/%d running",
					attempt, len(pods.Items)-notRunningCount, len(pods.Items), notRunningPods, runningNewPodsCount, newPodsCount)
			} else {
				t.Logf("[Attempt %d] All %d pods are running. New pods: %d/%d. Revision: %s",
					attempt, len(pods.Items), runningNewPodsCount, newPodsCount, currentRevision)
			}
			lastPodCount = len(pods.Items)
			lastNotRunningCount = notRunningCount
		}

		return allPodsNewAndRunning, nil
	})
}

// WaitForFeatureGateEnabled waits for a specific feature gate to be enabled in the cluster.
//
// This function polls the FeatureGate resource until the specified feature is found in the
// enabled list or the timeout is reached.
//
// Parameters:
//   - t: Logger interface for test output
//   - featureGateClient: FeatureGate client interface
//   - featureName: Name of the feature gate to wait for (e.g., "EventTTL")
//   - timeout: Maximum time to wait for the feature gate to be enabled
//
// Returns:
//   - error if timeout is reached or an error occurs during polling
func WaitForFeatureGateEnabled(t library.LoggingT, featureGateClient configv1client.FeatureGateInterface, featureName string, timeout time.Duration) error {
	t.Logf("Waiting for feature gate %s to be enabled (timeout: %v)", featureName, timeout)
	attempt := 0

	return wait.PollUntilContextTimeout(context.Background(), 10*time.Second, timeout, false, func(ctx context.Context) (bool, error) {
		attempt++
		fg, err := featureGateClient.Get(ctx, "cluster", metav1.GetOptions{})
		if err != nil {
			t.Logf("[Attempt %d] Error getting feature gate: %v", attempt, err)
			return false, nil
		}

		for _, fgDetails := range fg.Status.FeatureGates {
			for _, enabled := range fgDetails.Enabled {
				if string(enabled.Name) == featureName {
					t.Logf("[Attempt %d] Feature gate %s is enabled", attempt, featureName)
					return true, nil
				}
			}
		}

		if attempt%6 == 0 { // Log every minute
			t.Logf("[Attempt %d] Feature gate %s not yet enabled, waiting...", attempt, featureName)
		}
		return false, nil
	})
}
