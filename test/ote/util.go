package ote

import (
	"context"
	"fmt"
	"reflect"
	"time"

	configv1client "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
	"github.com/openshift/library-go/test/library"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
)

// WaitForClusterOperatorStatus waits for a ClusterOperator to reach the expected status conditions.
// Example usage:
//
//	err := WaitForClusterOperatorStatus(t, coClient, "kube-apiserver",
//	    map[string]string{"Available": "True", "Progressing": "False", "Degraded": "False"},
//	    10*time.Minute, 1.0)
func WaitForClusterOperatorStatus(t library.LoggingT, coClient configv1client.ClusterOperatorInterface, coName string, expectedStatus map[string]string, timeout time.Duration, waitMultiplier float64) error {
	stableDelay := 100 * time.Second

	// Apply timeout multiplier
	if waitMultiplier != 1.0 {
		timeout = time.Duration(float64(timeout) * waitMultiplier)
		t.Logf("Adjusted timeout for cluster type: %v (multiplier: %.2f)", timeout, waitMultiplier)
	}

	t.Logf("Waiting for ClusterOperator %s to reach status %v (timeout: %v)", coName, expectedStatus, timeout)

	attempt := 0
	consecutiveErrors := 0
	maxConsecutiveErrors := 5
	var lastStatus map[string]string
	var lastConditionDetails map[string]conditionDetail

	errCo := wait.PollUntilContextTimeout(context.Background(), 20*time.Second, timeout, false, func(ctx context.Context) (bool, error) {
		attempt++
		gottenStatus, conditionDetails, err := getClusterOperatorConditionStatusWithDetails(ctx, coClient, coName, expectedStatus)
		if err != nil {
			consecutiveErrors++
			t.Logf("[Attempt %d] Error getting ClusterOperator status: %v (consecutive errors: %d)", attempt, err, consecutiveErrors)
			// Fail fast if we hit too many consecutive errors
			if consecutiveErrors >= maxConsecutiveErrors {
				return false, fmt.Errorf("too many consecutive errors (%d) getting ClusterOperator status: %w", consecutiveErrors, err)
			}
			return false, nil
		}
		consecutiveErrors = 0

		// Log detailed status changes
		if !reflect.DeepEqual(lastStatus, gottenStatus) && lastStatus != nil {
			logConditionChanges(t, attempt, coName, lastConditionDetails, conditionDetails)
		}
		lastStatus = gottenStatus
		lastConditionDetails = conditionDetails

		eq := reflect.DeepEqual(expectedStatus, gottenStatus)
		if eq {
			// Check if this is the stable healthy state
			isHealthyState := reflect.DeepEqual(expectedStatus, map[string]string{"Available": "True", "Progressing": "False", "Degraded": "False"})
			if isHealthyState {
				// For True/False/False, wait some additional time and double check to ensure it is stably healthy
				t.Logf("[Attempt %d] ClusterOperator %s reached healthy state, waiting %v for stability check", attempt, coName, stableDelay)
				time.Sleep(stableDelay)

				gottenStatus, conditionDetails, err := getClusterOperatorConditionStatusWithDetails(ctx, coClient, coName, expectedStatus)
				if err != nil {
					t.Logf("Error during stability check: %v", err)
					return false, nil
				}

				eq := reflect.DeepEqual(expectedStatus, gottenStatus)
				if eq {
					t.Logf("ClusterOperator %s is stably available/non-progressing/non-degraded", coName)
					return true, nil
				}
				t.Logf("ClusterOperator %s became unstable during stability check", coName)
				logConditionDetails(t, conditionDetails)
				return false, nil
			} else {
				t.Logf("[Attempt %d] ClusterOperator %s reached expected status: %v", attempt, coName, gottenStatus)
				return true, nil
			}
		}

		// Log progress every 3 attempts (1 minute) with detailed condition info
		if attempt%3 == 0 {
			t.Logf("[Attempt %d] ClusterOperator %s status check:", attempt, coName)
			logConditionDetails(t, conditionDetails)
			t.Logf("  Expected: %v", expectedStatus)
		}
		return false, nil
	})

	if errCo != nil {
		t.Logf("Failed waiting for ClusterOperator %s to reach expected status", coName)
		if lastConditionDetails != nil {
			t.Logf("Final ClusterOperator %s status:", coName)
			logConditionDetails(t, lastConditionDetails)
		}
	}
	return errCo
}

// conditionDetail holds detailed information about a ClusterOperator condition
type conditionDetail struct {
	Type               string
	Status             string
	Reason             string
	Message            string
	LastTransitionTime time.Time
}

// getClusterOperatorConditionStatusWithDetails retrieves detailed status information for specified conditions
func getClusterOperatorConditionStatusWithDetails(ctx context.Context, coClient configv1client.ClusterOperatorInterface, coName string, statusToCompare map[string]string) (map[string]string, map[string]conditionDetail, error) {
	co, err := coClient.Get(ctx, coName, metav1.GetOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get ClusterOperator %s: %w", coName, err)
	}

	statusMap := make(map[string]string)
	detailsMap := make(map[string]conditionDetail)

	for conditionType := range statusToCompare {
		found := false
		for _, condition := range co.Status.Conditions {
			if string(condition.Type) == conditionType {
				statusMap[conditionType] = string(condition.Status)
				detailsMap[conditionType] = conditionDetail{
					Type:               string(condition.Type),
					Status:             string(condition.Status),
					Reason:             condition.Reason,
					Message:            condition.Message,
					LastTransitionTime: condition.LastTransitionTime.Time,
				}
				found = true
				break
			}
		}
		if !found {
			statusMap[conditionType] = "Unknown"
			detailsMap[conditionType] = conditionDetail{
				Type:    conditionType,
				Status:  "Unknown",
				Reason:  "ConditionNotFound",
				Message: "Condition not present in ClusterOperator status",
			}
		}
	}

	return statusMap, detailsMap, nil
}

// logConditionDetails logs detailed information about all conditions
func logConditionDetails(t library.LoggingT, details map[string]conditionDetail) {
	// Sort condition types for consistent output
	conditionTypes := []string{"Available", "Progressing", "Degraded"}

	for _, condType := range conditionTypes {
		if detail, ok := details[condType]; ok {
			if detail.Status == "Unknown" {
				t.Logf("  %s: %s (%s)", detail.Type, detail.Status, detail.Reason)
			} else {
				msg := detail.Message
				if len(msg) > 100 {
					msg = msg[:97] + "..."
				}
				if detail.Reason != "" {
					t.Logf("  %s=%s (reason: %s, message: %s)", detail.Type, detail.Status, detail.Reason, msg)
				} else {
					t.Logf("  %s=%s (message: %s)", detail.Type, detail.Status, msg)
				}
			}
		}
	}

	// Log any other conditions not in the standard set
	for condType, detail := range details {
		isStandard := false
		for _, std := range conditionTypes {
			if condType == std {
				isStandard = true
				break
			}
		}
		if !isStandard {
			msg := detail.Message
			if len(msg) > 100 {
				msg = msg[:97] + "..."
			}
			t.Logf("  %s=%s (reason: %s, message: %s)", detail.Type, detail.Status, detail.Reason, msg)
		}
	}
}

// logConditionChanges logs what changed between two condition states
func logConditionChanges(t library.LoggingT, attempt int, coName string, oldDetails, newDetails map[string]conditionDetail) {
	t.Logf("[Attempt %d] ClusterOperator %s status changed:", attempt, coName)
	for condType, newDetail := range newDetails {
		if oldDetail, ok := oldDetails[condType]; ok {
			if oldDetail.Status != newDetail.Status {
				t.Logf("  %s: %s -> %s (reason: %s)", condType, oldDetail.Status, newDetail.Status, newDetail.Reason)
				if newDetail.Message != "" {
					msg := newDetail.Message
					if len(msg) > 150 {
						msg = msg[:147] + "..."
					}
					t.Logf("    Message: %s", msg)
				}
			} else if oldDetail.Reason != newDetail.Reason || oldDetail.Message != newDetail.Message {
				t.Logf("  %s: %s (reason changed: %s -> %s)", condType, newDetail.Status, oldDetail.Reason, newDetail.Reason)
			}
		} else {
			t.Logf("  %s: (new) -> %s (reason: %s)", condType, newDetail.Status, newDetail.Reason)
		}
	}
}

// GetClusterOperatorConditionStatus retrieves the current status values for specified conditionsof a ClusterOperator.
// Example usage:
//
//	status, err := GetClusterOperatorConditionStatus(ctx, coClient, "kube-apiserver",
//	map[string]string{"Available": "", "Progressing": "", "Degraded": ""})
//	Returns: map[string]string{"Available": "True", "Progressing": "False", "Degraded": "False"}
func GetClusterOperatorConditionStatus(ctx context.Context, coClient configv1client.ClusterOperatorInterface, coName string, statusToCompare map[string]string) (map[string]string, error) {
	co, err := coClient.Get(ctx, coName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get ClusterOperator %s: %w", coName, err)
	}

	newStatusToCompare := make(map[string]string)
	for conditionType := range statusToCompare {
		// Find the condition with the matching type
		conditionStatus := "Unknown"
		for _, condition := range co.Status.Conditions {
			if string(condition.Type) == conditionType {
				conditionStatus = string(condition.Status)
				break
			}
		}
		newStatusToCompare[conditionType] = conditionStatus
	}

	return newStatusToCompare, nil
}

// WaitForClusterOperatorHealthy is a convenience wrapper for waiting for a ClusterOperator
// to reach the standard healthy state (Available=True, Progressing=False, Degraded=False).
// Example usage:
//
//	err := WaitForClusterOperatorHealthy(t, coClient, "kube-apiserver", 10*time.Minute, 1.0)
func WaitForClusterOperatorHealthy(t library.LoggingT, coClient configv1client.ClusterOperatorInterface, coName string, timeout time.Duration, waitMultiplier float64) error {
	return WaitForClusterOperatorStatus(t, coClient, coName,
		map[string]string{"Available": "True", "Progressing": "False", "Degraded": "False"},
		timeout, waitMultiplier)
}

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
