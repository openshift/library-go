package preflight

import (
	"context"
	"fmt"
	"time"

	"github.com/openshift/library-go/pkg/operator/encryption/controllers"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	batchv1client "k8s.io/client-go/kubernetes/typed/batch/v1"
	kmsservice "k8s.io/kms/pkg/service"
)

// jobStatusUpdateBackoff governs how long the checker keeps retrying to write
// its result onto the Job. Spans roughly two minutes to ride out SNO apiserver
// unavailability during rollouts before the attempt exits non-zero and the Job
// creates another pod.
var jobStatusUpdateBackoff = wait.Backoff{
	Duration: 1 * time.Second,
	Factor:   2.0,
	Jitter:   0.1,
	Steps:    8,
	Cap:      30 * time.Second,
}

func setJobCheckCondition(ctx context.Context, jobClient batchv1client.JobInterface, jobName string,
	status *kmsservice.StatusResponse, checkErr error) error {
	return updateJobCheckConditions(ctx, jobClient, jobName, podConditionsToJobConditions(podCheckConditions(status, checkErr)))
}

func podConditionsToJobConditions(podConditions []corev1.PodCondition) []batchv1.JobCondition {
	out := make([]batchv1.JobCondition, 0, len(podConditions))
	for _, c := range podConditions {
		out = append(out, batchv1.JobCondition{
			Type:               batchv1.JobConditionType(c.Type),
			Status:             c.Status,
			Reason:             c.Reason,
			Message:            c.Message,
			LastTransitionTime: c.LastTransitionTime,
		})
	}
	return out
}

func updateJobCheckConditions(ctx context.Context, jobClient batchv1client.JobInterface, name string, conditions []batchv1.JobCondition) error {
	var lastErr error
	err := wait.ExponentialBackoffWithContext(ctx, jobStatusUpdateBackoff, func(ctx context.Context) (bool, error) {
		job, err := jobClient.Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			lastErr = err
			return false, nil
		}
		for _, newCond := range conditions {
			found := false
			for i, existingCond := range job.Status.Conditions {
				if existingCond.Type == newCond.Type {
					job.Status.Conditions[i] = newCond
					found = true
					break
				}
			}
			if !found {
				job.Status.Conditions = append(job.Status.Conditions, newCond)
			}
		}
		_, err = jobClient.UpdateStatus(ctx, job, metav1.UpdateOptions{})
		if err != nil {
			lastErr = err
			return false, nil
		}
		lastErr = nil
		return true, nil
	})
	if err != nil {
		if lastErr != nil {
			return fmt.Errorf("failed to update job status for %s: %w", name, lastErr)
		}
		return fmt.Errorf("failed to update job status for %s: %w", name, err)
	}
	if lastErr != nil {
		return fmt.Errorf("failed to update job status for %s: %w", name, lastErr)
	}
	return nil
}

// projectJobToPodStatus maps a Job into the PodStatus shape the preflight
// controller already consumes. Native Job Complete/Failed become Pod phases;
// custom KMS check conditions are copied across so they survive pod GC.
func projectJobToPodStatus(job *batchv1.Job) corev1.PodStatus {
	status := corev1.PodStatus{
		StartTime: job.Status.StartTime,
	}

	var hasCheckResult bool
	for _, c := range job.Status.Conditions {
		switch c.Type {
		case batchv1.JobComplete, batchv1.JobFailed, batchv1.JobSuspended, batchv1.JobFailureTarget, batchv1.JobSuccessCriteriaMet:
			continue
		default:
			status.Conditions = append(status.Conditions, corev1.PodCondition{
				Type:               corev1.PodConditionType(c.Type),
				Status:             c.Status,
				Reason:             c.Reason,
				Message:            c.Message,
				LastTransitionTime: c.LastTransitionTime,
			})
			if c.Type == batchv1.JobConditionType(controllers.KMSPreflightResultPodCondition) {
				hasCheckResult = true
			}
		}
	}

	// When the Job has not started yet, seed PodScheduled from CreationTimestamp
	// so the controller's startup timeout still has a clock to read.
	if status.StartTime == nil && !job.CreationTimestamp.IsZero() {
		status.Conditions = append(status.Conditions, corev1.PodCondition{
			Type:               corev1.PodScheduled,
			Status:             corev1.ConditionTrue,
			LastTransitionTime: job.CreationTimestamp,
		})
	}

	switch {
	case jobConditionTrue(job, batchv1.JobFailed) && !hasCheckResult:
		status.Phase = corev1.PodFailed
		if c := findJobCondition(job, batchv1.JobFailed); c != nil {
			status.Reason = c.Reason
			status.Message = c.Message
		}
	case jobConditionTrue(job, batchv1.JobComplete), jobConditionTrue(job, batchv1.JobFailed) && hasCheckResult:
		status.Phase = corev1.PodSucceeded
	case job.Status.Active > 0:
		status.Phase = corev1.PodRunning
	default:
		status.Phase = corev1.PodPending
	}

	return status
}

func jobConditionTrue(job *batchv1.Job, condType batchv1.JobConditionType) bool {
	c := findJobCondition(job, condType)
	return c != nil && c.Status == corev1.ConditionTrue
}

func findJobCondition(job *batchv1.Job, condType batchv1.JobConditionType) *batchv1.JobCondition {
	for i := range job.Status.Conditions {
		if job.Status.Conditions[i].Type == condType {
			return &job.Status.Conditions[i]
		}
	}
	return nil
}
