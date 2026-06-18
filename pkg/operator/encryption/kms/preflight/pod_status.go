package preflight

import (
	"context"
	"fmt"

	"github.com/openshift/library-go/pkg/operator/encryption/controllers"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/util/retry"
	kmsservice "k8s.io/kms/pkg/service"
)

func setPodCheckCondition(ctx context.Context, podClient corev1client.PodInterface, podName string, configHash string,
	status *kmsservice.StatusResponse, checkErr error) error {
	conditions := podCheckConditions(configHash, status, checkErr)
	return updatePodCheckConditions(ctx, podClient, podName, conditions)
}

func updatePodCheckConditions(ctx context.Context, podClient corev1client.PodInterface, name string, conditions []corev1.PodCondition) error {
	err := retry.OnError(retry.DefaultRetry, func(err error) bool { return true }, func() error {
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

func podCheckConditions(configHash string, status *kmsservice.StatusResponse, checkErr error) []corev1.PodCondition {
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
		{
			Type:               controllers.KMSPreflightConfigHashPodCondition,
			Status:             corev1.ConditionTrue,
			Message:            configHash,
			LastTransitionTime: now,
		},
	}

	if status != nil {
		conditions = append(conditions, corev1.PodCondition{
			Type:               controllers.KMSPreflightKEKIDPodCondition,
			Status:             corev1.ConditionTrue,
			Message:            status.KeyID,
			LastTransitionTime: now,
		})
	}

	return conditions
}
