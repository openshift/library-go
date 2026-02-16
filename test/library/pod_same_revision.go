package library

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
)

// WaitForPodsToStabilizeOnTheSameRevision waits until all Pods with the given selector are running at the same revision.
// The Pods must stay on the same revision for at least waitForRevisionSuccessThreshold * waitForRevisionSuccessInterval.
// Mainly because of the difference between the propagation time of triggering a new release and the actual roll-out.
//
// Note:
//
//	the number of instances is calculated based on the number of running pods in a namespace.
//	only pods with the given label are considered
//	only pods in the given namespace are considered (podClient)
func WaitForPodsToStabilizeOnTheSameRevision(t LoggingT, podClient corev1client.PodInterface, podLabelSelector string, waitForRevisionSuccessThreshold int, waitForRevisionSuccessInterval, waitForRevisionPollInterval, waitForRevisionTimeout time.Duration) error {
	t.Logf("[WaitForPodsToStabilize] Starting: threshold=%d, successInterval=%v, pollInterval=%v, timeout=%v",
		waitForRevisionSuccessThreshold, waitForRevisionSuccessInterval, waitForRevisionPollInterval, waitForRevisionTimeout)

	pollCount := 0
	return wait.Poll(waitForRevisionPollInterval, waitForRevisionTimeout, mustSucceedMultipleTimes(t, waitForRevisionSuccessThreshold, waitForRevisionSuccessInterval, func() (bool, error) {
		pollCount++
		result, err := arePodsOnTheSameRevision(t, podClient, podLabelSelector)
		t.Logf("[WaitForPodsToStabilize] Poll #%d: result=%v, err=%v", pollCount, result, err)
		return result, err
	}))
}

// arePodsOnTheSameRevision tries to find the current revision that the pods are running at.
// The number of instances is calculated based on the number of running pods in a namespace.
// This should be okay because this function is meant to be used by WaitForPodsToStabilizeOnTheSameRevision which will wait at least waitForRevisionSuccessThreshold * waitForRevisionSuccessInterval
// The number of pods should stabilize in that period of time.
func arePodsOnTheSameRevision(t LoggingT, podClient corev1client.PodInterface, podLabelSelector string) (bool, error) {
	revisionLabel := "revision"

	// do a live list so we never get confused about what revision we are on
	apiServerPods, err := podClient.List(context.TODO(), metav1.ListOptions{LabelSelector: podLabelSelector})
	if err != nil {
		// ignore the errors as we hope it will succeed next time
		t.Logf("failed to list pods, err = %v (this error will be ignored)", err)
		return false, nil
	}

	t.Logf("[arePodsOnTheSameRevision] Found %d pods with selector %q", len(apiServerPods.Items), podLabelSelector)

	// Log detailed pod information for debugging
	for _, pod := range apiServerPods.Items {
		revision := pod.Labels[revisionLabel]
		ready := "NotReady"
		if podReady(pod) {
			ready = "Ready"
		}
		t.Logf("[arePodsOnTheSameRevision]   Pod: %s, Phase: %s, Ready: %s, Revision: %s, Node: %s",
			pod.Name, pod.Status.Phase, ready, revision, pod.Spec.NodeName)
	}

	goodRevisions, failingRevisions, progressing, err := getRevisions(revisionLabel, apiServerPods.Items)

	// Log analysis summary
	t.Logf("[arePodsOnTheSameRevision] Analysis: goodRevisions=%v, failingRevisions=%v, progressing=%v, err=%v",
		sortedSetToSlice(goodRevisions), sortedSetToSlice(failingRevisions), progressing, err)

	if err != nil {
		return false, err
	}

	if progressing {
		t.Logf("[arePodsOnTheSameRevision] Returning false: pods still progressing (some pods not ready or pending)")
		return false, nil
	}

	if len(goodRevisions) != 1 {
		t.Logf("[arePodsOnTheSameRevision] Returning false: expected 1 good revision, got %d: %v",
			len(goodRevisions), sortedSetToSlice(goodRevisions))
		return false, nil
	}

	if revision, _ := goodRevisions.PopAny(); failingRevisions.Has(revision) {
		return false, fmt.Errorf("api server revision %s has both running and failed pods", revision)
	}

	t.Logf("[arePodsOnTheSameRevision] Returning true: all pods on same revision")
	return true, nil
}

func getRevisions(revisionLabel string, pods []corev1.Pod) (sets.Set[string], sets.Set[string], bool, error) {
	if len(pods) == 0 {
		return nil, nil, true, nil
	}

	goodRevisions := sets.New[string]()
	badRevisions := sets.New[string]()

	for _, apiServerPod := range pods {
		switch phase := apiServerPod.Status.Phase; phase {
		case corev1.PodRunning:
			if !podReady(apiServerPod) {
				return nil, nil, true, nil // pods are not fully ready
			}
			goodRevisions.Insert(apiServerPod.Labels[revisionLabel])
		case corev1.PodPending:
			return nil, nil, true, nil // pods are not fully ready
		case corev1.PodUnknown:
			return nil, nil, false, fmt.Errorf("api server pod %s in unknown phase", apiServerPod.Name)
		case corev1.PodSucceeded, corev1.PodFailed:
			// handle failed pods carefully to make sure things are healthy
			badRevisions.Insert(apiServerPod.Labels[revisionLabel])
		default:
			// error in case new unexpected phases get added
			return nil, nil, false, fmt.Errorf("api server pod %s has unexpected phase %v", apiServerPod.Name, phase)
		}
	}
	return goodRevisions, badRevisions, false, nil
}

func podReady(pod corev1.Pod) bool {
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

// mustSucceedMultipleTimes calls f multiple times sleeping before each invocation, it only returns true if all invocations are successful.
func mustSucceedMultipleTimes(t LoggingT, n int, sleep time.Duration, f func() (bool, error)) func() (bool, error) {
	attemptCount := 0
	return func() (bool, error) {
		attemptCount++
		t.Logf("[mustSucceedMultipleTimes] Starting attempt #%d (need %d consecutive successes, interval=%v)", attemptCount, n, sleep)

		for i := 0; i < n; i++ {
			t.Logf("[mustSucceedMultipleTimes] Attempt #%d, iteration %d/%d: sleeping for %v", attemptCount, i+1, n, sleep)
			time.Sleep(sleep)
			ok, err := f()
			if err != nil || !ok {
				t.Logf("[mustSucceedMultipleTimes] Attempt #%d, iteration %d/%d: FAILED (not stable yet), resetting counter", attemptCount, i+1, n)
				return ok, err
			}
			t.Logf("[mustSucceedMultipleTimes] Attempt #%d, iteration %d/%d: SUCCESS", attemptCount, i+1, n)
		}
		t.Logf("[mustSucceedMultipleTimes] Attempt #%d: All %d iterations succeeded!", attemptCount, n)
		return true, nil
	}
}

// sortedSetToSlice converts a set to a sorted slice for consistent logging output
func sortedSetToSlice(s sets.Set[string]) []string {
	if s == nil {
		return nil
	}
	result := s.UnsortedList()
	sort.Strings(result)
	return result
}

// GetPodRevisionSummary returns a human-readable summary of pod revisions for debugging
func GetPodRevisionSummary(podClient corev1client.PodInterface, podLabelSelector string) (string, error) {
	revisionLabel := "revision"
	pods, err := podClient.List(context.TODO(), metav1.ListOptions{LabelSelector: podLabelSelector})
	if err != nil {
		return "", err
	}

	var summaryParts []string
	revisionToPods := make(map[string][]string)

	for _, pod := range pods.Items {
		revision := pod.Labels[revisionLabel]
		ready := "NotReady"
		if podReady(pod) {
			ready = "Ready"
		}
		status := fmt.Sprintf("%s(%s/%s)", pod.Name, pod.Status.Phase, ready)
		revisionToPods[revision] = append(revisionToPods[revision], status)
	}

	var revisions []string
	for rev := range revisionToPods {
		revisions = append(revisions, rev)
	}
	sort.Strings(revisions)

	for _, rev := range revisions {
		summaryParts = append(summaryParts, fmt.Sprintf("rev-%s: [%s]", rev, strings.Join(revisionToPods[rev], ", ")))
	}

	return strings.Join(summaryParts, "; "), nil
}
