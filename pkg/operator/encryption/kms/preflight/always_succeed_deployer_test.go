package preflight

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/openshift/library-go/pkg/operator/encryption/controllers"
)

func TestAlwaysSucceedKMSPreflightDeployer(t *testing.T) {
	const hash = "abc123=="
	d := NewAlwaysSucceedKMSPreflightDeployer()

	// Before Deploy: Status returns NotFound.
	_, err := d.Status(context.Background())
	if !apierrors.IsNotFound(err) {
		t.Fatalf("expected NotFound before Deploy, got %v", err)
	}

	// After Deploy: Status returns a succeeded pod with the hash in conditions.
	if err := d.Deploy(context.Background(), hash, nil); err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	podStatus, err := d.Status(context.Background())
	if err != nil {
		t.Fatalf("Status after Deploy: %v", err)
	}
	if podStatus.Phase != corev1.PodSucceeded {
		t.Errorf("expected PodSucceeded, got %s", podStatus.Phase)
	}
	hashCond := controllers.FindPodCondition(podStatus.Conditions, controllers.KMSPreflightConfigHashPodCondition)
	if hashCond == nil || hashCond.Message != hash {
		t.Errorf("expected hash condition with message %q, got %v", hash, hashCond)
	}
	resultCond := controllers.FindPodCondition(podStatus.Conditions, controllers.KMSPreflightResultPodCondition)
	if resultCond == nil || resultCond.Status != corev1.ConditionTrue {
		t.Errorf("expected result condition True, got %v", resultCond)
	}
	remoteKeyIDCond := controllers.FindPodCondition(podStatus.Conditions, controllers.KMSPreflightRemoteKeyIDPodCondition)
	if remoteKeyIDCond == nil || remoteKeyIDCond.Message == "" {
		t.Errorf("expected non-empty remoteKeyID condition, got %v", remoteKeyIDCond)
	}

	// After Cleanup: Status returns NotFound again.
	if err := d.Cleanup(context.Background()); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	_, err = d.Status(context.Background())
	if !apierrors.IsNotFound(err) {
		t.Fatalf("expected NotFound after Cleanup, got %v", err)
	}

	// Deploy with an empty hash: Status must still report success, not NotFound.
	if err := d.Deploy(context.Background(), "", nil); err != nil {
		t.Fatalf("Deploy with empty hash: %v", err)
	}
	podStatus, err = d.Status(context.Background())
	if err != nil {
		t.Fatalf("Status after Deploy with empty hash: %v", err)
	}
	if podStatus.Phase != corev1.PodSucceeded {
		t.Errorf("expected PodSucceeded after Deploy with empty hash, got %s", podStatus.Phase)
	}
}
