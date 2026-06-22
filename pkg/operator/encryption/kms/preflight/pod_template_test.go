package preflight

import (
	"testing"
	"time"

	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
	"k8s.io/apimachinery/pkg/api/equality"
)

var expectedPodYAML = `
apiVersion: v1
kind: Pod
metadata:
  name: kms-preflight
  namespace: test-ns
  labels:
    app: openshift-kms-preflight
  annotations:
    encryption.apiserver.operator.openshift.io/kms-preflight-config-hash: abc123
spec:
  restartPolicy: Never
  priorityClassName: system-cluster-critical
  nodeSelector:
    node-role.kubernetes.io/master: ""
  tolerations:
    - key: node-role.kubernetes.io/master
      operator: Exists
      effect: NoSchedule
    - key: node-role.kubernetes.io/master
      operator: Exists
      effect: NoExecute
  containers:
    - name: kms-preflight-check
      image: quay.io/openshift/operator:latest
      command: ["operator","kms-preflight"]
      args:
        - --kms-call-timeout=10s
      env:
      - name: POD_NAME
        valueFrom:
          fieldRef:
            fieldPath: metadata.name
      - name: POD_NAMESPACE
        valueFrom:
          fieldRef:
            fieldPath: metadata.namespace
      - name: CONFIG_HASH
        value: abc123
      resources:
        requests:
          memory: 50Mi
          cpu: 5m
      volumeMounts:
        - name: kms-plugin-socket
          mountPath: /var/run/kmsplugin
  volumes:
    - name: kms-plugin-socket
      emptyDir: {}
`

func TestGeneratePodTemplate(t *testing.T) {
	pod, err := generatePodTemplate(
		preflightPodName,
		"test-ns",
		"abc123",
		"quay.io/openshift/operator:latest",
		[]string{"operator", "kms-preflight"},
		10*time.Second,
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
