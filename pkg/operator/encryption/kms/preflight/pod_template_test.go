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
  serviceAccountName: kms-preflight
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
        - --config-hash=$(CONFIG_HASH)
        - --pod-name=$(POD_NAME)
        - --pod-namespace=$(POD_NAMESPACE)
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

var expectedStaticPodYAML = `
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
  hostNetwork: true
  containers:
    - name: kms-preflight-check
      image: quay.io/openshift/operator:latest
      command: ["operator","kms-preflight"]
      args:
        - --kms-call-timeout=10s
        - --config-hash=$(CONFIG_HASH)
        - --pod-name=$(POD_NAME)
        - --pod-namespace=$(POD_NAMESPACE)
        - --kubeconfig=/etc/kubernetes/static-pod-resources/secrets/kms-preflight-encryption-config/lb-int.kubeconfig
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
      securityContext:
        runAsUser: 0
      volumeMounts:
        - name: resource-dir
          mountPath: /etc/kubernetes/static-pod-resources
          readOnly: true
  volumes:
    - name: resource-dir
      hostPath:
        path: /etc/kubernetes/manifests
`

func TestGenerateStaticPodTemplate(t *testing.T) {
	pod, err := generateStaticPodTemplate(
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

	expectedPod, err := resourceread.ReadPodV1([]byte(expectedStaticPodYAML))
	if err != nil {
		t.Fatalf("failed to parse expected pod YAML: %v", err)
	}
	if !equality.Semantic.DeepEqual(pod, expectedPod) {
		t.Fatalf("pod does not match expected:\ngot:  %+v\nwant: %+v", pod, expectedPod)
	}
}

var expectedInstallerPodYAML = `
apiVersion: v1
kind: Pod
metadata:
  name: kms-preflight-installer
  namespace: test-ns
  labels:
    app: openshift-kms-preflight-installer
spec:
  automountServiceAccountToken: false
  nodeSelector:
    node-role.kubernetes.io/master: ""
  tolerations:
    - key: node-role.kubernetes.io/master
      operator: Exists
      effect: NoSchedule
    - key: node-role.kubernetes.io/master
      operator: Exists
      effect: NoExecute
  initContainers:
    - name: cleanup
      image: quay.io/openshift/operator:latest
      imagePullPolicy: IfNotPresent
      terminationMessagePolicy: FallbackToLogsOnError
      command:
        - /bin/sh
        - -c
        - |
          #!/bin/sh
          set -euo pipefail

          rm -f /etc/kubernetes/manifests/kms-preflight-pod.yaml
          rm -rf /etc/kubernetes/manifests/secrets/kms-preflight-encryption-config
      securityContext:
        privileged: true
        runAsUser: 0
      resources:
        requests:
          memory: 10Mi
          cpu: 10m
      volumeMounts:
        - mountPath: /etc/kubernetes/manifests
          name: manifests-dir
  containers:
    - name: installer
      image: quay.io/openshift/operator:latest
      imagePullPolicy: IfNotPresent
      terminationMessagePolicy: FallbackToLogsOnError
      command:
        - /bin/sh
        - -c
        - |
          #!/bin/sh
          set -euo pipefail

          target_secret_dir="/etc/kubernetes/manifests/secrets/kms-preflight-encryption-config"
          mkdir -p "${target_secret_dir}"
          cp -f /install/secret/* "${target_secret_dir}/"
          cp -f /install/pod/lb-int.kubeconfig "${target_secret_dir}/lb-int.kubeconfig"

          manifest_path="/etc/kubernetes/manifests/kms-preflight-pod.yaml"
          mkdir -p /etc/kubernetes/manifests
          cp -f /install/pod/pod.yaml "${manifest_path}"
          chmod 0600 "${manifest_path}"
      securityContext:
        privileged: true
        runAsUser: 0
      resources:
        requests:
          memory: 10Mi
          cpu: 10m
      volumeMounts:
        - mountPath: /etc/kubernetes/manifests
          name: manifests-dir
        - mountPath: /install/pod
          name: pod-manifest
        - mountPath: /install/secret
          name: encryption-config
          readOnly: true
  restartPolicy: Never
  priorityClassName: system-node-critical
  securityContext:
    runAsUser: 0
  volumes:
    - hostPath:
        path: /etc/kubernetes/manifests
      name: manifests-dir
    - name: pod-manifest
      configMap:
        name: kms-preflight-pod
    - name: encryption-config
      secret:
        secretName: kms-preflight-encryption-config
`

func TestGenerateInstallerPodTemplate(t *testing.T) {
	pod, err := generateInstallerPodTemplate(
		"test-ns",
		"quay.io/openshift/operator:latest",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedPod, err := resourceread.ReadPodV1([]byte(expectedInstallerPodYAML))
	if err != nil {
		t.Fatalf("failed to parse expected pod YAML: %v", err)
	}
	if !equality.Semantic.DeepEqual(pod, expectedPod) {
		t.Fatalf("pod does not match expected:\ngot:  %+v\nwant: %+v", pod, expectedPod)
	}
}
