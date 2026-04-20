package preflight

import (
	"testing"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"
	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
	"k8s.io/apimachinery/pkg/api/equality"
)

var expectedPodYAML = `
apiVersion: v1
kind: Pod
metadata:
  name: preflight-pod
  namespace: test-ns
spec:
  restartPolicy: Never
  containers:
    - name: kms-preflight-check
      image: quay.io/openshift/operator:latest
      command: ["operator","kms-preflight"]
      args:
        - --kms-call-timeout=10s
      resources:
        requests:
          memory: 50Mi
          cpu: 5m
      volumeMounts:
        - name: kms-plugin-socket
          mountPath: /var/run/kmsplugin
  volumes:
    - name: kms-plugin-socket
      hostPath:
        path: /var/run/kmsplugin
        type: DirectoryOrCreate
`

func TestGeneratePodTemplate(t *testing.T) {
	featureGateAccessor := featuregates.NewHardcodedFeatureGateAccess(
		[]configv1.FeatureGateName{"KMSEncryption"},
		nil,
	)

	pod, err := GeneratePodTemplate(
		"test-ns",
		"preflight-pod",
		"quay.io/openshift/operator:latest",
		[]string{"operator", "kms-preflight"},
		10*time.Second,
		featureGateAccessor,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedPod, err := resourceread.ReadPodV1([]byte(expectedPodYAML))
	if err != nil {
		t.Fatalf("failed to parse expected pod YAML: %v", err)
	}
	if !equality.Semantic.DeepEqual(pod, expectedPod) {
		t.Fatalf("pod does not match expected:\ngot:  %+v\nwant: %+v", pod, expectedPod)
	}
}
