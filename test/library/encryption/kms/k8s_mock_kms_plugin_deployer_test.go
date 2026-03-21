package kms

import (
	"context"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// getKubeClient returns a Kubernetes client for testing.
func getKubeClient(t *testing.T) kubernetes.Interface {
	t.Helper()

	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	configOverrides := &clientcmd.ConfigOverrides{}
	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)

	config, err := kubeConfig.ClientConfig()
	if err != nil {
		t.Fatalf("Failed to get kubeconfig: %v", err)
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatalf("Failed to create kubernetes client: %v", err)
	}

	return client
}

// TestDeployUpstreamMockKMSPlugin tests deploying the KMS plugin.
func TestDeployUpstreamMockKMSPlugin(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping KMS deploy test in short mode")
	}

	kubeClient := getKubeClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	namespace := WellKnownUpstreamMockKMSPluginNamespace
	image := WellKnownUpstreamMockKMSPluginImage

	t.Logf("Deploying KMS plugin with namespace=%s, image=%s", namespace, image)

	// Deploy and get cleanup function
	cleanup := DeployUpstreamMockKMSPlugin(ctx, t, kubeClient, namespace, image)
	defer cleanup()

	t.Log("KMS plugin deployed successfully!")
}

// TestDeployUpstreamMockKMSPluginNoCleanup deploys the KMS plugin without cleanup.
func TestDeployUpstreamMockKMSPluginNoCleanup(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping KMS deploy test in short mode")
	}

	kubeClient := getKubeClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	namespace := WellKnownUpstreamMockKMSPluginNamespace
	image := WellKnownUpstreamMockKMSPluginImage

	t.Logf("Deploying KMS plugin with namespace=%s, image=%s (no cleanup)", namespace, image)

	// Deploy without calling cleanup
	_ = DeployUpstreamMockKMSPlugin(ctx, t, kubeClient, namespace, image)

	t.Log("KMS plugin deployed successfully! Resources left in cluster.")
}
