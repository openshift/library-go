package preflight

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openshift/library-go/pkg/operator/encryption/kms/pluginlifecycle"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
	"github.com/openshift/library-go/pkg/operator/staticpod/controller/installer"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8slabels "k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/uuid"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
)

const (
	nodeKubeconfigsSecretName = "node-kubeconfigs"
	nodeKubeconfigSecretKey   = "lb-int.kubeconfig"

	hostResourceDir    = "/etc/kubernetes/static-pod-resources"
	hostPodManifestDir = "/etc/kubernetes/manifests"

	// preflightInstallerAppLabel scopes installerpod settlement to preflight installer pods only.
	preflightInstallerAppLabel = "preflight-installer"
)

// InstallerStaticPodPreflightDeployer deploys the KMS preflight check as a static pod
// using the shared static pod installer pod and installerpod command. Preflight keeps
// its own revision counter and revision-status configmaps so it does not interfere with
// the kube-apiserver operand in the same namespace.
type InstallerStaticPodPreflightDeployer struct {
	namespace string

	coreClient    corev1client.CoreV1Interface
	eventRecorder events.Recorder

	operatorImage    string
	operatorCommand  []string
	installerCommand []string
	kmsCallTimeout   time.Duration
	targetNode       string
	lastRevision     int32
	lastInstallerNode string
}

func (d *InstallerStaticPodPreflightDeployer) Deploy(ctx context.Context, configHash string, encryptionConfigSecret *corev1.Secret) error {
	if configHash == "" {
		return fmt.Errorf("configHash is empty")
	}
	if encryptionConfigSecret == nil {
		return fmt.Errorf("encryptionConfigSecret is nil")
	}

	if err := d.Cleanup(ctx); err != nil {
		return fmt.Errorf("failed to clean up existing preflight resources: %w", err)
	}

	revision, err := nextPreflightRevision(ctx, d.coreClient, d.namespace)
	if err != nil {
		return err
	}

	nodeName, err := d.resolveTargetNode(ctx)
	if err != nil {
		return err
	}

	kubeconfig, err := d.nodeKubeconfigData(ctx)
	if err != nil {
		return fmt.Errorf("failed to load node kubeconfig: %w", err)
	}

	encryptionConfigSecret = encryptionConfigSecret.DeepCopy()
	encryptionConfigSecret.ObjectMeta = metav1.ObjectMeta{
		Namespace: d.namespace,
		Name:      preflightEncryptionConfigSecretName,
		Labels:    labels,
	}
	encryptionConfigSecret.Data[nodeKubeconfigSecretKey] = kubeconfig
	if _, err = d.coreClient.Secrets(d.namespace).Create(ctx, encryptionConfigSecret, metav1.CreateOptions{}); err != nil {
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
	ensureStaticPodInitContainerResourceMounts(&pod.Spec)

	pod.UID = uuid.NewUUID()
	podManifest := resourceread.WritePodV1OrDie(pod)
	if _, err = d.coreClient.ConfigMaps(d.namespace).Create(ctx, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: d.namespace,
			Name:      preflightStaticPodResourcePrefix,
			Labels:    labels,
		},
		Data: map[string]string{
			"pod.yaml": podManifest,
		},
	}, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("failed to create preflight pod configmap: %w", err)
	}

	if _, err = createPreflightRevision(
		ctx,
		d.coreClient,
		d.coreClient,
		d.eventRecorder,
		d.namespace,
		revision,
		fmt.Sprintf("kms preflight config hash %s", configHash),
	); err != nil {
		return err
	}

	if err = d.createInstallerPod(ctx, revision, nodeName); err != nil {
		return fmt.Errorf("failed to create installer pod: %w", err)
	}

	d.lastRevision = revision
	d.lastInstallerNode = nodeName
	return nil
}

func (d *InstallerStaticPodPreflightDeployer) Status(ctx context.Context) (corev1.PodStatus, error) {
	pod, err := d.findMirrorPod(ctx)
	if err != nil {
		return corev1.PodStatus{}, fmt.Errorf("failed to get mirror pod for preflight %s/%s: %w", d.namespace, preflightPodName, err)
	}
	return pod.Status, nil
}

func (d *InstallerStaticPodPreflightDeployer) Cleanup(ctx context.Context) error {
	var errs []error

	if d.lastInstallerNode != "" && d.lastRevision > 0 {
		installerPodName := installerPodName(d.lastRevision, d.lastInstallerNode)
		err := d.coreClient.Pods(d.namespace).Delete(ctx, installerPodName, metav1.DeleteOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			errs = append(errs, fmt.Errorf("failed to delete installer pod %s/%s: %w", d.namespace, installerPodName, err))
		}
	}

	err := d.coreClient.Secrets(d.namespace).Delete(ctx, preflightEncryptionConfigSecretName, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		errs = append(errs, fmt.Errorf("failed to delete secret %s/%s: %w", d.namespace, preflightEncryptionConfigSecretName, err))
	}

	err = d.coreClient.ConfigMaps(d.namespace).Delete(ctx, preflightStaticPodResourcePrefix, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		errs = append(errs, fmt.Errorf("failed to delete configmap %s/%s: %w", d.namespace, preflightStaticPodResourcePrefix, err))
	}

	if d.lastRevision > 0 {
		if err = deletePreflightRevisionResources(ctx, d.coreClient, d.coreClient, d.namespace, d.lastRevision); err != nil {
			errs = append(errs, err)
		}
	}

	d.lastRevision = 0
	d.lastInstallerNode = ""
	return errors.Join(errs...)
}

func NewInstallerStaticPodPreflightDeployer(
	namespace string,
	coreClient corev1client.CoreV1Interface,
	eventRecorder events.Recorder,
	operatorImage string,
	operatorCommand []string,
	installerCommand []string,
	kmsCallTimeout time.Duration,
	targetNode string,
) *InstallerStaticPodPreflightDeployer {
	return &InstallerStaticPodPreflightDeployer{
		namespace:        namespace,
		coreClient:       coreClient,
		eventRecorder:    eventRecorder,
		operatorImage:    operatorImage,
		operatorCommand:  operatorCommand,
		installerCommand: installerCommand,
		kmsCallTimeout:   kmsCallTimeout,
		targetNode:       targetNode,
	}
}

func (d *InstallerStaticPodPreflightDeployer) createInstallerPod(ctx context.Context, revision int32, nodeName string) error {
	pod := installer.InstallerPod()
	pod.Namespace = d.namespace
	pod.Name = installerPodName(revision, nodeName)
	pod.Labels["app"] = preflightInstallerAppLabel
	pod.Spec.NodeName = nodeName
	pod.Spec.Containers[0].Image = d.operatorImage
	pod.Spec.Containers[0].Command = d.installerCommand
	pod.Spec.Containers[0].Args = []string{
		"-v=4",
		fmt.Sprintf("--revision=%d", revision),
		fmt.Sprintf("--namespace=%s", d.namespace),
		fmt.Sprintf("--pod=%s", preflightStaticPodResourcePrefix),
		fmt.Sprintf("--resource-dir=%s", hostResourceDir),
		fmt.Sprintf("--pod-manifest-dir=%s", hostPodManifestDir),
		fmt.Sprintf("--configmaps=%s", preflightStaticPodResourcePrefix),
		fmt.Sprintf("--secrets=%s", preflightEncryptionConfigSecretName),
	}

	_, err := d.coreClient.Pods(d.namespace).Create(ctx, pod, metav1.CreateOptions{})
	return err
}

func installerPodName(revision int32, nodeName string) string {
	return fmt.Sprintf("installer-%d-preflight-%s", revision, nodeName)
}

func (d *InstallerStaticPodPreflightDeployer) resolveTargetNode(ctx context.Context) (string, error) {
	if d.targetNode != "" {
		return d.targetNode, nil
	}

	nodes, err := d.coreClient.Nodes().List(ctx, metav1.ListOptions{
		LabelSelector: "node-role.kubernetes.io/master",
	})
	if err != nil {
		return "", fmt.Errorf("failed to list control plane nodes: %w", err)
	}
	if len(nodes.Items) == 0 {
		return "", fmt.Errorf("no control plane nodes found")
	}
	return nodes.Items[0].Name, nil
}

func (d *InstallerStaticPodPreflightDeployer) findMirrorPod(ctx context.Context) (*corev1.Pod, error) {
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

func (d *InstallerStaticPodPreflightDeployer) nodeKubeconfigData(ctx context.Context) ([]byte, error) {
	secret, err := d.coreClient.Secrets(d.namespace).Get(ctx, nodeKubeconfigsSecretName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("secret %s/%s not found", d.namespace, nodeKubeconfigsSecretName)
		}
		return nil, fmt.Errorf("failed to get %s/%s secret: %w", d.namespace, nodeKubeconfigsSecretName, err)
	}

	kubeconfig, ok := secret.Data[nodeKubeconfigSecretKey]
	if !ok || len(kubeconfig) == 0 {
		return nil, fmt.Errorf("secret %s/%s is missing %q data", d.namespace, nodeKubeconfigsSecretName, nodeKubeconfigSecretKey)
	}
	return kubeconfig, nil
}
