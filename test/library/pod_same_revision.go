package library

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
)

const revisionLabel = "revision"

func WaitForPodsToStabilizeOnTheSameNewRevision(t LoggingT, podClient corev1client.PodInterface, podLabelSelector string, waitForRevisionSuccessThreshold int, waitForRevisionSuccessInterval, waitForRevisionPollInterval, waitForRevisionTimeout time.Duration) error {
	pods, err := podClient.List(context.TODO(), metav1.ListOptions{LabelSelector: podLabelSelector})
	if err != nil {
		return fmt.Errorf("failed to list pods with selector '%v': %w", podLabelSelector, err)
	}

	currentRevision, err := getCurrenRevision(revisionLabel, pods.Items)
	if err != nil {
		return fmt.Errorf("failed to get current revision for pods with selector '%v': %w", podLabelSelector, err)
	}

	return wait.Poll(waitForRevisionPollInterval, waitForRevisionTimeout, mustSucceedMultipleTimes(waitForRevisionSuccessThreshold, waitForRevisionSuccessInterval, func() (bool, error) {
		return arePodsOnTheSameNewRevision(t, podClient, podLabelSelector, currentRevision)
	}))
}

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
	return wait.Poll(waitForRevisionPollInterval, waitForRevisionTimeout, mustSucceedMultipleTimes(waitForRevisionSuccessThreshold, waitForRevisionSuccessInterval, func() (bool, error) {
		return arePodsOnTheSameRevision(t, podClient, podLabelSelector)
	}))
}

func arePodsOnTheSameNewRevision(t LoggingT, podClient corev1client.PodInterface, podLabelSelector string, oldRevision string) (bool, error) {
	pods, err := podClient.List(context.TODO(), metav1.ListOptions{LabelSelector: podLabelSelector})
	if err != nil {
		return false, fmt.Errorf("failed to list pods with selector '%v': %w", podLabelSelector, err)
	}

	currentRevision, err := getCurrenRevision(revisionLabel, pods.Items)
	if strings.Compare(currentRevision, oldRevision) != 1 {
		return false, fmt.Errorf("current revision is not newer than old revision")
	}
	return true, nil
}

// arePodsOnTheSameRevision tries to find the current revision that the pods are running at.
// The number of instances is calculated based on the number of running pods in a namespace.
// This should be okay because this function is meant to be used by WaitForPodsToStabilizeOnTheSameRevision which will wait at least waitForRevisionSuccessThreshold * waitForRevisionSuccessInterval
// The number of pods should stabilize in that period of time.
func arePodsOnTheSameRevision(t LoggingT, podClient corev1client.PodInterface, podLabelSelector string) (bool, error) {
	// do a live list so we never get confused about what revision we are on
	apiServerPods, err := podClient.List(context.TODO(), metav1.ListOptions{LabelSelector: podLabelSelector})
	if err != nil {
		// ignore the errors as we hope it will succeed next time
		t.Logf("failed to list pods, err = %v (this error will be ignored)", err)
		return false, nil
	}

	goodRevisions, failingRevisions, progressing, err := getRevisions(revisionLabel, apiServerPods.Items)
	if err != nil || progressing || len(goodRevisions) != 1 {
		return false, err
	}

	if revision, _ := goodRevisions.PopAny(); failingRevisions.Has(revision) {
		return false, fmt.Errorf("api server revision %s has both running and failed pods", revision)
	}

	return true, nil
}

func getCurrenRevision(revisionLabel string, pods []corev1.Pod) (string, error) {
	goodRevisions, failingRevisions, progressing, err := getRevisions(revisionLabel, pods)
	if err != nil || progressing {
		return "", err
	}

	// all pods must have the same revision
	if goodRevisions.Len() != 1 {
		return "", fmt.Errorf("pods has different revisions, expected all to have the same revision")
	}

	currentRevision, _ := goodRevisions.PopAny()
	if failingRevisions.Has(currentRevision) {
		return "", fmt.Errorf("pods has both running and failed pods")
	}

	return currentRevision, nil
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
func mustSucceedMultipleTimes(n int, sleep time.Duration, f func() (bool, error)) func() (bool, error) {
	return func() (bool, error) {
		for i := 0; i < n; i++ {
			time.Sleep(sleep)
			ok, err := f()
			if err != nil || !ok {
				return ok, err
			}
		}
		return true, nil
	}
}
