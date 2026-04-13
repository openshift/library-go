package kms

import (
	"context"
	"os"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// KMSPluginDeployer abstracts deployment of different KMS provider mocks.
// Each implementation handles deploying and cleaning up a specific KMS plugin
// (upstream PKCS#11, Vault, AWS, etc.) so that encryption tests remain
// provider-agnostic.
type KMSPluginDeployer interface {
	Deploy(ctx context.Context, t testing.TB, kubeClient kubernetes.Interface)
	Cleanup(ctx context.Context, t testing.TB, kubeClient kubernetes.Interface)
	Name() string
}

// GetKMSDeployer returns the appropriate KMSPluginDeployer based on the
// KMS_PROVIDER environment variable. Defaults to the upstream mock.
func GetKMSDeployer() KMSPluginDeployer {
	switch os.Getenv("KMS_PROVIDER") {
	case "vault":
		return NewVaultKMSPluginDeployer(
			WellKnownVaultKMSPluginNamespace,
			WellKnownVaultKMSPluginImage,
		)
	default:
		return NewUpstreamKMSPluginDeployer(
			WellKnownUpstreamMockKMSPluginNamespace,
			WellKnownUpstreamMockKMSPluginImage,
		)
	}
}

// UpstreamKMSPluginDeployer wraps the existing DeployUpstreamMockKMSPlugin
// function to satisfy the KMSPluginDeployer interface.
type UpstreamKMSPluginDeployer struct {
	namespace string
	image     string
}

var (
	_ KMSPluginDeployer = &UpstreamKMSPluginDeployer{}
	_ KMSPluginDeployer = &VaultKMSPluginDeployer{}
)

func NewUpstreamKMSPluginDeployer(namespace, image string) *UpstreamKMSPluginDeployer {
	return &UpstreamKMSPluginDeployer{namespace: namespace, image: image}
}

func (d *UpstreamKMSPluginDeployer) Name() string { return "upstream" }

func (d *UpstreamKMSPluginDeployer) Deploy(ctx context.Context, t testing.TB, kubeClient kubernetes.Interface) {
	DeployUpstreamMockKMSPlugin(ctx, t, kubeClient, d.namespace, d.image)
}

func (d *UpstreamKMSPluginDeployer) Cleanup(ctx context.Context, t testing.TB, kubeClient kubernetes.Interface) {
	t.Helper()
	t.Logf("Cleaning up upstream KMS plugin in namespace %q", d.namespace)
	err := kubeClient.CoreV1().Namespaces().Delete(ctx, d.namespace, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		t.Logf("Warning: failed to delete namespace %s: %v", d.namespace, err)
	}
}
