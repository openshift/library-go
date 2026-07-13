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
	tmpl, err := template.New("kms-preflight").Parse(string(rawManifest))
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
