package preflight

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/openshift/library-go/pkg/operator/encryption/controllers"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
	kmsservice "k8s.io/kms/pkg/service"
)

func TestUpdateJobCheckConditions(t *testing.T) {
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kms-preflight",
			Namespace: "openshift-kube-apiserver",
		},
	}
	kubeClient := fake.NewSimpleClientset(job)
	jobClient := kubeClient.BatchV1().Jobs(job.Namespace)

	defer withFastJobStatusUpdateBackoff()()

	conditions := podConditionsToJobConditions(podCheckConditions(&kmsservice.StatusResponse{Version: "v2", KeyID: "key-1"}, nil))
	if err := updateJobCheckConditions(context.Background(), jobClient, job.Name, conditions); err != nil {
		t.Fatalf("updateJobCheckConditions() error = %v", err)
	}

	updated, err := jobClient.Get(context.Background(), job.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if len(updated.Status.Conditions) != 2 {
		t.Fatalf("expected 2 conditions, got %d", len(updated.Status.Conditions))
	}
}

func TestUpdateJobCheckConditions_retriesOnConflict(t *testing.T) {
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kms-preflight",
			Namespace: "openshift-kube-apiserver",
		},
	}
	kubeClient := fake.NewSimpleClientset(job)
	jobClient := kubeClient.BatchV1().Jobs(job.Namespace)

	defer withFastJobStatusUpdateBackoff()()

	attempts := 0
	kubeClient.PrependReactor("update", "jobs", func(action clienttesting.Action) (bool, runtime.Object, error) {
		updateAction := action.(clienttesting.UpdateAction)
		if updateAction.GetSubresource() != "status" {
			return false, nil, nil
		}
		attempts++
		if attempts == 1 {
			return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "jobs"}, job.Name, fmt.Errorf("conflict"))
		}
		return false, nil, nil
	})

	conditions := podConditionsToJobConditions(podCheckConditions(&kmsservice.StatusResponse{Version: "v2", KeyID: "key-1"}, nil))
	if err := updateJobCheckConditions(context.Background(), jobClient, job.Name, conditions); err != nil {
		t.Fatalf("updateJobCheckConditions() error = %v", err)
	}
	if attempts < 2 {
		t.Fatalf("expected at least 2 update attempts, got %d", attempts)
	}
}

func TestUpdateJobCheckConditions_retriesWhileAPIServerUnavailable(t *testing.T) {
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kms-preflight",
			Namespace: "openshift-oauth-apiserver",
		},
	}
	kubeClient := fake.NewSimpleClientset(job)
	jobClient := kubeClient.BatchV1().Jobs(job.Namespace)

	defer withFastJobStatusUpdateBackoff()()

	const unavailableAttempts = 6
	attempts := 0
	connRefused := fmt.Errorf(`Get "https://172.30.0.1:443/apis/batch/v1/namespaces/openshift-oauth-apiserver/jobs/kms-preflight": dial tcp 172.30.0.1:443: connect: connection refused`)
	kubeClient.PrependReactor("*", "jobs", func(action clienttesting.Action) (bool, runtime.Object, error) {
		attempts++
		if attempts <= unavailableAttempts {
			return true, nil, connRefused
		}
		return false, nil, nil
	})

	conditions := podConditionsToJobConditions(podCheckConditions(&kmsservice.StatusResponse{Version: "v2", KeyID: "key-1"}, nil))
	if err := updateJobCheckConditions(context.Background(), jobClient, job.Name, conditions); err != nil {
		t.Fatalf("updateJobCheckConditions() error = %v", err)
	}
	if attempts <= unavailableAttempts {
		t.Fatalf("expected the write to retry past the outage (>%d attempts), got %d", unavailableAttempts, attempts)
	}
}

func TestProjectJobToPodStatus(t *testing.T) {
	now := metav1.Now()
	job := &batchv1.Job{
		Status: batchv1.JobStatus{
			Conditions: []batchv1.JobCondition{
				{Type: batchv1.JobComplete, Status: corev1.ConditionTrue},
				{
					Type:   batchv1.JobConditionType(controllers.KMSPreflightResultPodCondition),
					Status: corev1.ConditionTrue,
					Reason: "Succeeded",
				},
			},
			StartTime: &now,
		},
	}
	status := projectJobToPodStatus(job)
	if status.Phase != corev1.PodSucceeded {
		t.Fatalf("phase = %q, want Succeeded", status.Phase)
	}
	if controllers.FindPodCondition(status.Conditions, controllers.KMSPreflightResultPodCondition) == nil {
		t.Fatal("expected KMSPreflightResult condition")
	}

	failed := projectJobToPodStatus(&batchv1.Job{
		Status: batchv1.JobStatus{
			Conditions: []batchv1.JobCondition{
				{Type: batchv1.JobFailed, Status: corev1.ConditionTrue, Reason: "BackoffLimitExceeded", Message: "gave up"},
			},
		},
	})
	if failed.Phase != corev1.PodFailed {
		t.Fatalf("phase = %q, want Failed", failed.Phase)
	}
}

func withFastJobStatusUpdateBackoff() func() {
	original := jobStatusUpdateBackoff
	jobStatusUpdateBackoff = wait.Backoff{Duration: time.Millisecond, Factor: 1.0, Steps: 50}
	return func() { jobStatusUpdateBackoff = original }
}
