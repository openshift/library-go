package resourceread

import (
	"testing"
)

func TestValidatingWebhooks(t *testing.T) {
	validWebhookConfig := `
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: snapshot.storage.k8s.io
  labels:
    app: csi-snapshot-webhook
  annotations:
    service.beta.openshift.io/inject-cabundle: "true"
    include.release.openshift.io/self-managed-high-availability: "true"
webhooks:
  - name: volumesnapshotclasses.snapshot.storage.k8s.io
    clientConfig:
      service:
        name: csi-snapshot-webhook
        namespace: openshift-cluster-storage-operator
        path: /volumesnapshot
    rules:
      - operations: [ "CREATE", "UPDATE" ]
        apiGroups: ["snapshot.storage.k8s.io"]
        apiVersions: ["v1beta1"]
        resources: ["volumesnapshots", "volumesnapshotcontents"]
    admissionReviewVersions:
      - v1
      - v1beta1
    sideEffects: None
    failurePolicy: Ignore
`
	obj := ReadValidatingWebhookConfigurationV1OrDie([]byte(validWebhookConfig))
	if obj == nil {
		t.Errorf("Expected a webhook, got nil")
	}
}

func TestMutatingWebhooks(t *testing.T) {
	validWebhookConfig := `
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: machine-api
webhooks:
- admissionReviewVersions:
  - v1beta1
  clientConfig:
    service:
      name: machine-api-operator-webhook
      namespace: openshift-machine-api
      path: /mutate-machine-openshift-io-v1beta1-machine
      port: 443
  failurePolicy: Ignore
  matchPolicy: Equivalent
  name: default.machine.machine.openshift.io
  reinvocationPolicy: Never
  rules:
  - apiGroups:
    - machine.openshift.io
    apiVersions:
    - v1beta1
    operations:
    - CREATE
    resources:
    - machines
    scope: '*'
  sideEffects: None
  timeoutSeconds: 10
- admissionReviewVersions:
  - v1beta1
  clientConfig:
    service:
      name: machine-api-operator-webhook
      namespace: openshift-machine-api
      path: /mutate-machine-openshift-io-v1beta1-machineset
      port: 443
  failurePolicy: Ignore
  matchPolicy: Equivalent
  name: default.machineset.machine.openshift.io
  namespaceSelector: {}
  objectSelector: {}
  reinvocationPolicy: Never
  rules:
  - apiGroups:
    - machine.openshift.io
    apiVersions:
    - v1beta1
    operations:
    - CREATE
    resources:
    - machinesets
    scope: '*'
  sideEffects: None
  timeoutSeconds: 10
`
	obj := ReadMutatingWebhookConfigurationV1OrDie([]byte(validWebhookConfig))
	if obj == nil {
		t.Errorf("Expected a webhook, got nil")
	}
}

func TestValidatingAdmissionPolicies(t *testing.T) {
	validValidatingAdmissionPolicy := `
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: "machine-configuration-guards"
spec:
  failurePolicy: Fail
  matchConstraints:
    matchPolicy: Equivalent
    namespaceSelector: {}
    objectSelector: {}
    resourceRules:
    - apiGroups:   ["operator.openshift.io"]
      apiVersions: ["v1"]
      operations:  ["CREATE","UPDATE"]
      resources:   ["machineconfigurations"]
      scope: "*"
  validations:
    - expression: "object.metadata.name=='cluster'"
      message: "Only a single object of MachineConfiguration is allowed and it must be named cluster."
`
	obj := ReadValidatingAdmissionPolicyV1OrDie([]byte(validValidatingAdmissionPolicy))
	if obj == nil {
		t.Errorf("Expected a validatingadmissionpolicy, got nil")
	}

}

func TestValidatingAdmissionPolicyBindings(t *testing.T) {
	validValidatingAdmissionPolicyBinding := `
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: "machine-configuration-guards-binding"
spec:
  policyName: "machine-configuration-guards"
  validationActions: [Deny]
`
	obj := ReadValidatingAdmissionPolicyBindingV1OrDie([]byte(validValidatingAdmissionPolicyBinding))
	if obj == nil {
		t.Errorf("Expected a validatingadmissionpolicybinding, got nil")
	}

}
