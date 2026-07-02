package preflight

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
)

const (
	StaticPodResourcesDir       = "/etc/kubernetes/static-pod-resources"
	hostPodManifestDir          = "/etc/kubernetes/manifests"
	preflightPodConfigMapPrefix = "kms-preflight-pod"
	preflightInstallerPodName   = "kms-preflight-installer"
)

type kmsPreflightTemplate struct {
	PodName        string
	Namespace      string
	ConfigHash     string
	OperatorImage  string
	Command        string
	KMSCallTimeout string
	StaticPod      bool
	ResourceDir    string
}

func newKmsPreflightTemplate(
	podName string,
	namespace string,
	configHash string,
	operatorImage string,
	operatorCommand []string,
	kmsCallTimeout time.Duration,
	staticPod bool,
) kmsPreflightTemplate {
	operatorCommandQuoted := make([]string, len(operatorCommand))
	for i, cmd := range operatorCommand {
		operatorCommandQuoted[i] = fmt.Sprintf("%q", cmd)
	}

	return kmsPreflightTemplate{
		PodName:        podName,
		Namespace:      namespace,
		ConfigHash:     configHash,
		OperatorImage:  operatorImage,
		Command:        strings.Join(operatorCommandQuoted, ","),
		KMSCallTimeout: kmsCallTimeout.String(),
		StaticPod:      staticPod,
		ResourceDir:    StaticPodResourcesDir,
	}
}

// generatePodTemplate renders the KMS preflight pod YAML template.
// The pod runs the preflight checker as a one-shot command and shares an emptyDir
// volume with the KMS plugin sidecar at /var/run/kmsplugin.
func generatePodTemplate(
	podName string,
	namespace string,
	configHash string,
	operatorImage string,
	operatorCommand []string,
	kmsCallTimeout time.Duration,
) (*corev1.Pod, error) {
	return renderPreflightPodTemplate(podName, namespace, configHash, operatorImage, operatorCommand, kmsCallTimeout, false)
}

// generateStaticPodTemplate renders the KMS preflight static pod YAML template.
func generateStaticPodTemplate(
	podName string,
	namespace string,
	configHash string,
	operatorImage string,
	operatorCommand []string,
	kmsCallTimeout time.Duration,
) (*corev1.Pod, error) {
	return renderPreflightPodTemplate(podName, namespace, configHash, operatorImage, operatorCommand, kmsCallTimeout, true)
}

func renderPreflightPodTemplate(
	podName string,
	namespace string,
	configHash string,
	operatorImage string,
	operatorCommand []string,
	kmsCallTimeout time.Duration,
	staticPod bool,
) (*corev1.Pod, error) {
	rawManifest := mustAsset("assets/kms-preflight-pod.yaml")
	tmplVal := newKmsPreflightTemplate(
		podName, namespace, configHash, operatorImage, operatorCommand, kmsCallTimeout, staticPod,
	)
	return renderPodTemplate("kms-preflight", string(rawManifest), tmplVal)
}

type kmsPreflightInstallerTemplate struct {
	InstallerPodName string
	Namespace        string
	InstallerImage   string
	ResourceDir      string
	SecretDirName    string
	PodManifestDir   string
	PodManifestFile  string
}

// generateInstallerPodTemplate renders the pod that installs the KMS preflight static pod
// manifest and encryption-config secret onto a control plane node.
func generateInstallerPodTemplate(namespace, operatorImage string) (*corev1.Pod, error) {
	rawManifest := mustAsset("assets/kms-preflight-installer-pod.yaml")

	tmplVal := kmsPreflightInstallerTemplate{
		InstallerPodName: preflightInstallerPodName,
		Namespace:        namespace,
		InstallerImage:   operatorImage,
		ResourceDir:      StaticPodResourcesDir,
		SecretDirName:    preflightEncryptionConfigSecretName,
		PodManifestDir:   hostPodManifestDir,
		PodManifestFile:  preflightPodConfigMapPrefix + ".yaml",
	}

	pod, err := renderPodTemplate("kms-preflight-installer", string(rawManifest), tmplVal)
	if err != nil {
		return nil, err
	}

	pod.Spec.Volumes = append(pod.Spec.Volumes,
		corev1.Volume{
			Name: "pod-manifest",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: preflightPodConfigMapPrefix},
				},
			},
		},
		corev1.Volume{
			Name: "encryption-config",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: preflightEncryptionConfigSecretName,
				},
			},
		},
	)

	return pod, nil
}

func renderPodTemplate(name, rawManifest string, tmplVal any) (*corev1.Pod, error) {
	tmpl, err := template.New(name).Parse(rawManifest)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err = tmpl.Execute(&buf, tmplVal); err != nil {
		return nil, err
	}

	pod, err := resourceread.ReadPodV1(buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed to parse rendered pod template: %w", err)
	}
	return pod, nil
}
