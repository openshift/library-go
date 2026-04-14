package preflight

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"
	encryptionkms "github.com/openshift/library-go/pkg/operator/encryption/kms"
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
)

type kmsPreflightTemplate struct {
	PodName        string
	Namespace      string
	OperatorImage  string
	Command        string
	KMSCallTimeout string
}

// GeneratePodTemplate renders the KMS preflight pod YAML template.
// The pod has a single container that connects to the KMS plugin via
// a hostPath-mounted unix socket at /var/run/kmsplugin.
// The KMS plugin volume and mount are added via AddKMSPluginVolumeAndMountToPodSpec.
func GeneratePodTemplate(namespace string, podName string, operatorImage string, operatorCommand []string, kmsCallTimeout time.Duration, featureGateAccessor featuregates.FeatureGateAccess) (*corev1.Pod, error) {
	rawManifest := mustAsset("assets/kms-preflight-pod.yaml")

	operatorCommandQuoted := make([]string, len(operatorCommand))
	for i, cmd := range operatorCommand {
		operatorCommandQuoted[i] = fmt.Sprintf("%q", cmd)
	}

	tmplVal := kmsPreflightTemplate{
		PodName:        podName,
		Namespace:      namespace,
		OperatorImage:  operatorImage,
		Command:        strings.Join(operatorCommandQuoted, ","),
		KMSCallTimeout: kmsCallTimeout.String(),
	}
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
	// TODO: once the KMS plugin lifecycle code is present, reuse it instead of AddKMSPluginVolumeAndMountToPodSpec.
	if err = encryptionkms.AddKMSPluginVolumeAndMountToPodSpec(&pod.Spec, "kms-preflight-check", featureGateAccessor); err != nil {
		return nil, fmt.Errorf("failed to add KMS plugin volume: %w", err)
	}
	return pod, nil
}
