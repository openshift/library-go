package preflight

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
)

const (
	preflightPodName = "kms-preflight"
)

// PodPreflightDeployer creates a one-shot pod to run the preflight checker as a command,
// with the plugin injected as a sidecar container.
type PodPreflightDeployer struct {
	namespace string
	// It uses direct API client instead of a lister to be consistent with what
	// encryption controllers/components actually use.
	// In addition to that running the preflight check is not a very frequent operation.
	coreClient      corev1client.CoreV1Interface
	operatorImage   string
	operatorCommand []string
	kmsCallTimeout  time.Duration
}

func (d *PodPreflightDeployer) Deploy(ctx context.Context, configHash string) error {
	pod, err := generatePodTemplate(
		preflightPodName,
		d.namespace,
		configHash,
		d.operatorImage,
		d.operatorCommand,
		d.kmsCallTimeout,
	)
	if err != nil {
		return fmt.Errorf("failed to generate preflight pod template: %w", err)
	}

	// TODO(thomas): inject KMS plugin sidecar container into pod.Spec

	_, err = d.coreClient.Pods(d.namespace).Create(ctx, pod, metav1.CreateOptions{})
	return err
}

func (d *PodPreflightDeployer) Status(ctx context.Context) (corev1.PodStatus, error) {
	// preflight status checks are not very frequent, so we use the live client instead of a cached lister
	pod, err := d.coreClient.Pods(d.namespace).Get(ctx, preflightPodName, metav1.GetOptions{})
	if err != nil {
		return corev1.PodStatus{}, fmt.Errorf("failed to get pod for preflight %s/%s: %w", d.namespace, preflightPodName, err)
	}

	return pod.Status, nil
}

func (d *PodPreflightDeployer) Cleanup(ctx context.Context) error {
	err := d.coreClient.Pods(d.namespace).Delete(ctx, preflightPodName, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("failed to delete pod %s/%s: %w", d.namespace, preflightPodName, err)
	}
	return nil
}

func NewPodPreflightDeployer(
	namespace string,
	coreClient corev1client.CoreV1Interface,
	operatorImage string,
	operatorCommand []string,
	kmsCallTimeout time.Duration,
) *PodPreflightDeployer {
	return &PodPreflightDeployer{
		namespace:       namespace,
		coreClient:      coreClient,
		operatorImage:   operatorImage,
		operatorCommand: operatorCommand,
		kmsCallTimeout:  kmsCallTimeout,
	}
}
