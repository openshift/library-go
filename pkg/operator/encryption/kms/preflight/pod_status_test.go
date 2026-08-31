package preflight

import (
	"context"
	"fmt"
	"testing"

	"github.com/openshift/library-go/pkg/operator/encryption/controllers"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
	kmsservice "k8s.io/kms/pkg/service"
)

func TestPodCheckConditions(t *testing.T) {
	status := &kmsservice.StatusResponse{Version: "v2", KeyID: "key-1"}

	conditions := podCheckConditions(status, nil)
	if len(conditions) != 2 {
		t.Fatalf("expected 2 conditions, got %d", len(conditions))
	}

	check := conditions[0]
	if check.Type != controllers.KMSPreflightResultPodCondition || check.Status != corev1.ConditionTrue {
		t.Fatalf("unexpected check condition: %#v", check)
	}
	if check.Message != "" {
		t.Fatalf("expected empty check message on success, got %q", check.Message)
	}

	remoteKeyID := conditions[1]
	if remoteKeyID.Type != controllers.KMSPreflightRemoteKeyIDPodCondition || remoteKeyID.Message != "key-1" {
		t.Fatalf("unexpected remoteKeyID condition: %#v", remoteKeyID)
	}

	failed := podCheckConditions(status, fmt.Errorf("encrypt call failed"))
	if failed[0].Status != corev1.ConditionFalse {
		t.Fatalf("expected failed check condition, got %#v", failed[0])
	}
	if failed[0].Message != "encrypt call failed" {
		t.Fatalf("unexpected failure message: %q", failed[0].Message)
	}
	if failed[1].Message != "key-1" {
		t.Fatalf("expected keyID condition to remain populated, got %#v", failed[1])
	}

	withoutStatus := podCheckConditions(nil, fmt.Errorf("context deadline exceeded"))
	if len(withoutStatus) != 1 {
		t.Fatalf("expected 1 condition without status, got %d", len(withoutStatus))
	}
	if withoutStatus[0].Type != controllers.KMSPreflightResultPodCondition {
		t.Fatalf("expected result condition, got %#v", withoutStatus[0])
	}
}

func TestUpdatePodCheckConditions(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kms-preflight-abc123",
			Namespace: "openshift-kube-apiserver",
		},
	}
	kubeClient := fake.NewSimpleClientset(pod)
	podClient := kubeClient.CoreV1().Pods(pod.Namespace)

	conditions := podCheckConditions(&kmsservice.StatusResponse{Version: "v2", KeyID: "key-1"}, nil)
	if err := updatePodCheckConditions(context.Background(), podClient, pod.Name, conditions); err != nil {
		t.Fatalf("updatePodCheckConditions() error = %v", err)
	}

	updated, err := podClient.Get(context.Background(), pod.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if len(updated.Status.Conditions) != 2 {
		t.Fatalf("expected 2 conditions, got %d", len(updated.Status.Conditions))
	}
}

func TestUpdatePodCheckConditions_retriesOnConflict(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kms-preflight-abc123",
			Namespace: "openshift-kube-apiserver",
		},
	}
	kubeClient := fake.NewSimpleClientset(pod)
	podClient := kubeClient.CoreV1().Pods(pod.Namespace)

	attempts := 0
	kubeClient.PrependReactor("update", "pods", func(action clienttesting.Action) (bool, runtime.Object, error) {
		updateAction := action.(clienttesting.UpdateAction)
		if updateAction.GetSubresource() != "status" {
			return false, nil, nil
		}
		attempts++
		if attempts == 1 {
			return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "pods"}, pod.Name, fmt.Errorf("conflict"))
		}
		return false, nil, nil
	})

	conditions := podCheckConditions(&kmsservice.StatusResponse{Version: "v2", KeyID: "key-1"}, nil)
	if err := updatePodCheckConditions(context.Background(), podClient, pod.Name, conditions); err != nil {
		t.Fatalf("updatePodCheckConditions() error = %v", err)
	}
	if attempts < 2 {
		t.Fatalf("expected at least 2 update attempts, got %d", attempts)
	}
}
