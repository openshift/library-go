package preflight

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/openshift/library-go/pkg/operator/encryption/controllers"
)

// NewAlwaysSucceedKMSPreflightDeployer returns a KMSPreflightDeployer that
// always reports a successful preflight without running any real check.
// Use as a temporary stand-in until a real pod-based deployer is available.
func NewAlwaysSucceedKMSPreflightDeployer() *AlwaysSucceedKMSPreflightDeployer {
	return &AlwaysSucceedKMSPreflightDeployer{}
}

// AlwaysSucceedKMSPreflightDeployer is a KMSPreflightDeployer that immediately
// reports a successful preflight result without deploying any workload.
type AlwaysSucceedKMSPreflightDeployer struct {
	configHash string
	deployed   bool
}

func (d *AlwaysSucceedKMSPreflightDeployer) Deploy(_ context.Context, configHash string, _ *corev1.Secret) error {
	d.configHash = configHash
	d.deployed = true
	return nil
}

func (d *AlwaysSucceedKMSPreflightDeployer) Status(_ context.Context) (string, corev1.PodStatus, error) {
	if !d.deployed {
		return "", corev1.PodStatus{}, apierrors.NewNotFound(schema.GroupResource{Resource: "pods"}, "kms-preflight")
	}
	return d.configHash, corev1.PodStatus{
		Phase: corev1.PodSucceeded,
		Conditions: []corev1.PodCondition{
			{
				Type:    controllers.KMSPreflightConfigHashPodCondition,
				Status:  corev1.ConditionTrue,
				Message: d.configHash,
			},
			{
				Type:   controllers.KMSPreflightResultPodCondition,
				Status: corev1.ConditionTrue,
			},
			{
				Type:    controllers.KMSPreflightRemoteKeyIDPodCondition,
				Status:  corev1.ConditionTrue,
				Message: "always-succeed",
			},
		},
	}, nil
}

func (d *AlwaysSucceedKMSPreflightDeployer) Cleanup(_ context.Context) error {
	d.configHash = ""
	d.deployed = false
	return nil
}
