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

type kmsPreflightTemplate struct {
	PodName        string
	Namespace      string
	ConfigHash     string
	OperatorImage  string
	Command        string
	KMSCallTimeout string
	StaticPod      bool
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
