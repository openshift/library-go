package preflight

import (
	"context"
	"fmt"
	"time"

	"github.com/openshift/library-go/pkg/operator/encryption/controllers"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/util/retry"
	kmsservice "k8s.io/kms/pkg/service"
)

// podStatusUpdateBackoff governs how long the in-pod checker keeps retrying to
// write its own result back to the apiserver. The apiserver this pod talks to is
// frequently unavailable for a short window on single-node clusters while it is
// rolling to a new revision, which is exactly when the preflight runs. The old
// retry.DefaultRetry only spans ~50ms, so a normal rollout disruption exhausted
// it and the checker exited non-zero even though the KMS check itself passed.
// This backoff spans roughly two minutes to ride out that window.
var podStatusUpdateBackoff = wait.Backoff{
	Duration: 1 * time.Second,
	Factor:   2.0,
	Jitter:   0.1,
	Steps:    8,
	Cap:      30 * time.Second,
}

func setPodCheckCondition(ctx context.Context, podClient corev1client.PodInterface, podName string,
	status *kmsservice.StatusResponse, checkErr error) error {
	conditions := podCheckConditions(status, checkErr)
	return updatePodCheckConditions(ctx, podClient, podName, conditions)
}

func updatePodCheckConditions(ctx context.Context, podClient corev1client.PodInterface, name string, conditions []corev1.PodCondition) error {
	err := retry.OnError(podStatusUpdateBackoff, func(err error) bool { return true }, func() error {
		pod, err := podClient.Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		for _, newCond := range conditions {
			found := false
			for i, existingCond := range pod.Status.Conditions {
				if existingCond.Type == newCond.Type {
					pod.Status.Conditions[i] = newCond
					found = true
					break
				}
			}
			if !found {
				pod.Status.Conditions = append(pod.Status.Conditions, newCond)
			}
		}
		_, err = podClient.UpdateStatus(ctx, pod, metav1.UpdateOptions{})
		return err
	})
	if err != nil {
		return fmt.Errorf("failed to update pod status for %s: %w", name, err)
	}
	return nil
}

func podCheckConditions(status *kmsservice.StatusResponse, checkErr error) []corev1.PodCondition {
	now := metav1.Now()

	checkStatus, checkReason, checkMessage := corev1.ConditionTrue, "Succeeded", ""
	if checkErr != nil {
		checkStatus, checkReason, checkMessage = corev1.ConditionFalse, "Failed", checkErr.Error()
	}

	conditions := []corev1.PodCondition{
		{
			Type:               controllers.KMSPreflightResultPodCondition,
			Status:             checkStatus,
			Reason:             checkReason,
			Message:            checkMessage,
			LastTransitionTime: now,
		},
	}

	if status != nil {
		conditions = append(conditions, corev1.PodCondition{
			Type:               controllers.KMSPreflightRemoteKeyIDPodCondition,
			Status:             corev1.ConditionTrue,
			Message:            status.KeyID,
			LastTransitionTime: now,
		})
	}

	return conditions
}
