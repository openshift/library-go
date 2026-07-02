package preflight

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openshift/library-go/pkg/operator/encryption/kms/pluginlifecycle"
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8slabels "k8s.io/apimachinery/pkg/labels"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
)

// StaticPodPreflightDeployer deploys the KMS preflight check as a static pod on a
// control plane node. An installer pod writes the rendered static pod manifest to the
// host manifests directory and copies supporting secrets into static-pod-resources.
type StaticPodPreflightDeployer struct {
	namespace string

	coreClient corev1client.CoreV1Interface

	operatorImage   string
	operatorCommand []string
	kmsCallTimeout  time.Duration
}

func (d *StaticPodPreflightDeployer) Deploy(ctx context.Context, configHash string, encryptionConfigSecret *corev1.Secret) error {
	if configHash == "" {
		return fmt.Errorf("configHash is empty")
	}
	if encryptionConfigSecret == nil {
		return fmt.Errorf("encryptionConfigSecret is nil")
	}

	if err := d.Cleanup(ctx); err != nil {
		return fmt.Errorf("failed to clean up existing preflight resources: %w", err)
	}

	encryptionConfigSecret = encryptionConfigSecret.DeepCopy()
	encryptionConfigSecret.ObjectMeta = metav1.ObjectMeta{
		Namespace: d.namespace,
		Name:      preflightEncryptionConfigSecretName,
		Labels:    labels,
	}
	if _, err := d.coreClient.Secrets(d.namespace).Create(ctx, encryptionConfigSecret, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("failed to create preflight encryption config secret: %w", err)
	}

	pod, err := generateStaticPodTemplate(
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

	err = pluginlifecycle.NewKMSPluginBuilder().
		WithSecretRequired().
		FromEncryptionConfigSecret(d.namespace, preflightEncryptionConfigSecretName, d.coreClient).
		AsStaticPod().
		Apply(ctx, &pod.Spec, preflightCheckContainerName)
	if err != nil {
		return fmt.Errorf("failed to apply preflight plugin: %w", err)
	}

	podManifest := resourceread.WritePodV1OrDie(pod)
	if _, err = d.coreClient.ConfigMaps(d.namespace).Create(ctx, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: d.namespace,
			Name:      preflightPodConfigMapPrefix,
			Labels:    labels,
		},
		Data: map[string]string{
			"pod.yaml": podManifest,
		},
	}, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("failed to create preflight pod configmap: %w", err)
	}

	installerPod, err := generateInstallerPodTemplate(d.namespace, d.operatorImage)
	if err != nil {
		return fmt.Errorf("failed to generate preflight installer pod: %w", err)
	}

	if _, err = d.coreClient.Pods(d.namespace).Create(ctx, installerPod, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("failed to create preflight installer pod: %w", err)
	}

	return nil
}

func (d *StaticPodPreflightDeployer) Status(ctx context.Context) (corev1.PodStatus, error) {
	pod, err := d.findMirrorPod(ctx)
	if err != nil {
		return corev1.PodStatus{}, fmt.Errorf("failed to get mirror pod for preflight %s/%s: %w", d.namespace, preflightPodName, err)
	}

	return pod.Status, nil
}

func (d *StaticPodPreflightDeployer) Cleanup(ctx context.Context) error {
	var errs []error

	installerPodName := preflightInstallerPodName
	err := d.coreClient.Pods(d.namespace).Delete(ctx, installerPodName, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		errs = append(errs, fmt.Errorf("failed to delete installer pod %s/%s: %w", d.namespace, installerPodName, err))
	}

	err = d.coreClient.Secrets(d.namespace).Delete(ctx, preflightEncryptionConfigSecretName, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		errs = append(errs, fmt.Errorf("failed to delete secret %s/%s: %w", d.namespace, preflightEncryptionConfigSecretName, err))
	}

	err = d.coreClient.ConfigMaps(d.namespace).Delete(ctx, preflightPodConfigMapPrefix, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		errs = append(errs, fmt.Errorf("failed to delete configmap %s/%s: %w", d.namespace, preflightPodConfigMapPrefix, err))
	}

	return errors.Join(errs...)
}

func NewStaticPodPreflightDeployer(
	namespace string,
	coreClient corev1client.CoreV1Interface,
	operatorImage string,
	operatorCommand []string,
	kmsCallTimeout time.Duration,
) *StaticPodPreflightDeployer {
	return &StaticPodPreflightDeployer{
		namespace:       namespace,
		coreClient:      coreClient,
		operatorImage:   operatorImage,
		operatorCommand: operatorCommand,
		kmsCallTimeout:  kmsCallTimeout,
	}
}

func (d *StaticPodPreflightDeployer) findMirrorPod(ctx context.Context) (*corev1.Pod, error) {
	pods, err := d.coreClient.Pods(d.namespace).List(ctx, metav1.ListOptions{
		LabelSelector: k8slabels.Set(labels).String(),
	})
	if err != nil {
		return nil, err
	}

	mirrorPrefix := preflightPodName + "-"
	var mirrorPods []corev1.Pod
	for _, pod := range pods.Items {
		if strings.HasPrefix(pod.Name, mirrorPrefix) {
			mirrorPods = append(mirrorPods, pod)
		}
	}

	switch len(mirrorPods) {
	case 0:
		return nil, apierrors.NewNotFound(corev1.Resource("pods"), mirrorPrefix+"*")
	case 1:
		return &mirrorPods[0], nil
	default:
		return nil, fmt.Errorf("expected one preflight mirror pod, found %d", len(mirrorPods))
	}
}

func mirrorPodName(nodeName string) string {
	return fmt.Sprintf("%s-%s", preflightPodName, nodeName)
}
