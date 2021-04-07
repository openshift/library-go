package resourceread

import (
	"fmt"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestCredentialsRequestFailureMessages(t *testing.T) {
	tests := []struct {
		name               string
		credentialsRequest string
		expectedMessage    string
	}{
		{
			name: "no status",
			credentialsRequest: `
apiVersion: cloudcredential.openshift.io/v1
kind: CredentialsRequest
metadata:
  name: openshift-aws-ebs-csi-driver
  namespace: openshift-cloud-credential-operator
spec:
  secretRef:
    name: aws-cloud-credentials
    namespace: openshift-aws-ebs-csi-driver
  providerSpec:
    apiVersion: cloudcredential.openshift.io/v1
    kind: AWSProviderSpec
    statementEntries:
    - effect: Allow
      action:
      - ec2:AttachVolume
      - ec2:CreateSnapshot
      - ec2:CreateTags
      - ec2:CreateVolume
      - ec2:DeleteSnapshot
      - ec2:DeleteTags
      - ec2:DeleteVolume
      - ec2:DescribeInstances
      - ec2:DescribeSnapshots
      - ec2:DescribeTags
      - ec2:DescribeVolumes
      - ec2:DescribeVolumesModifications
      - ec2:DetachVolume
      - ec2:ModifyVolume
      #- ec2:*
      resource: "*"
`,
			expectedMessage: "",
		},
		{
			name: "no conditions",
			credentialsRequest: `
apiVersion: cloudcredential.openshift.io/v1
kind: CredentialsRequest
metadata:
  name: openshift-aws-ebs-csi-driver
  namespace: openshift-cloud-credential-operator
spec:
  secretRef:
    name: aws-cloud-credentials
    namespace: openshift-aws-ebs-csi-driver
  providerSpec:
    apiVersion: cloudcredential.openshift.io/v1
    kind: AWSProviderSpec
    statementEntries:
    - effect: Allow
      action:
      resource: "*"
status:
`,
			expectedMessage: "",
		},
		{
			name: "empty conditions",
			credentialsRequest: `
apiVersion: cloudcredential.openshift.io/v1
kind: CredentialsRequest
metadata:
  name: openshift-aws-ebs-csi-driver
  namespace: openshift-cloud-credential-operator
spec:
  secretRef:
    name: aws-cloud-credentials
    namespace: openshift-aws-ebs-csi-driver
  providerSpec:
    apiVersion: cloudcredential.openshift.io/v1
    kind: AWSProviderSpec
    statementEntries:
    - effect: Allow
      action:
      resource: "*"
status:
  conditions:
`,
			expectedMessage: "",
		},
		{
			name: "one condition",
			credentialsRequest: `
apiVersion: cloudcredential.openshift.io/v1
kind: CredentialsRequest
metadata:
  name: openshift-aws-ebs-csi-driver
  namespace: openshift-cloud-credential-operator
spec:
  secretRef:
    name: aws-cloud-credentials
    namespace: openshift-aws-ebs-csi-driver
  providerSpec:
    apiVersion: cloudcredential.openshift.io/v1
    kind: AWSProviderSpec
    statementEntries:
    - effect: Allow
      action:
      resource: "*"
status:
  conditions:
  - lastProbeTime: "2020-05-14T11:45:34Z"
    lastTransitionTime: "2020-05-14T11:45:09Z"
    message: "failed to grant creds: error syncing creds in mint-mode: AWS Error:
      LimitExceeded - LimitExceeded: Cannot exceed quota for UsersPerAccount: 5000\n\tstatus
      code: 409, request id: 0f750904-01cc-4752-a679-1d4c1368389d"
    reason: CredentialsProvisionFailure
    status: "True"
    type: CredentialsProvisionFailure
  lastSyncGeneration: 0
`,
			expectedMessage: "CredentialsProvisionFailure: failed to grant creds: error syncing creds in mint-mode: AWS Error: LimitExceeded - LimitExceeded: Cannot exceed quota for UsersPerAccount: 5000\n\tstatus code: 409, request id: 0f750904-01cc-4752-a679-1d4c1368389d",
		},
		{
			name: "two conditions",
			credentialsRequest: `
apiVersion: cloudcredential.openshift.io/v1
kind: CredentialsRequest
metadata:
  name: openshift-aws-ebs-csi-driver
  namespace: openshift-cloud-credential-operator
spec:
  secretRef:
    name: aws-cloud-credentials
    namespace: openshift-aws-ebs-csi-driver
  providerSpec:
    apiVersion: cloudcredential.openshift.io/v1
    kind: AWSProviderSpec
    statementEntries:
    - effect: Allow
      action:
      resource: "*"
status:
  conditions:
  - lastProbeTime: "2020-05-14T11:45:34Z"
    lastTransitionTime: "2020-05-14T11:45:09Z"
    message: "failed to grant creds: error syncing creds in mint-mode: AWS Error:
      LimitExceeded - LimitExceeded: Cannot exceed quota for UsersPerAccount: 5000\n\tstatus
      code: 409, request id: 0f750904-01cc-4752-a679-1d4c1368389d"
    reason: CredentialsProvisionFailure
    status: "True"
    type: CredentialsProvisionFailure
  - lastProbeTime: "2020-05-14T11:45:34Z"
    lastTransitionTime: "2020-05-14T11:45:09Z"
    message: "mock error"
    reason: MockError
    status: "True"
    type: MockError
  lastSyncGeneration: 0
`,
			expectedMessage: "CredentialsProvisionFailure: failed to grant creds: error syncing creds in mint-mode: AWS Error: LimitExceeded - LimitExceeded: Cannot exceed quota for UsersPerAccount: 5000\n\tstatus code: 409, request id: 0f750904-01cc-4752-a679-1d4c1368389d, MockError: mock error",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cr := ReadCredentialRequestsOrDie([]byte(test.credentialsRequest))
			msg := getCredentialsRequestFailure(cr)
			if msg != test.expectedMessage {
				t.Errorf("expected %q, got %q", test.expectedMessage, msg)
			}
		})
	}
}

// getCredentialsRequestFailure finds all true conditions in CredentialsRequest
// and composes an error message from them.
func getCredentialsRequestFailure(cr *unstructured.Unstructured) string {
	// Parse Unstructured CredentialsRequest. Ignore all errors and not found conditions
	// - in the worst case, there is no message why the CredentialsRequest is stuck.
	var msgs []string
	conditions, found, err := unstructured.NestedFieldNoCopy(cr.Object, "status", "conditions")
	if err != nil {
		return ""
	}
	if !found {
		return ""
	}
	conditionArray, ok := conditions.([]interface{})
	if !ok {
		return ""
	}
	for _, c := range conditionArray {
		condition, ok := c.(map[string]interface{})
		if !ok {
			continue
		}
		t, found, err := unstructured.NestedString(condition, "type")
		if err != nil {
			continue
		}
		if !found {
			continue
		}
		status, found, err := unstructured.NestedString(condition, "status")
		if err != nil {
			continue
		}
		if !found {
			continue
		}
		message, found, err := unstructured.NestedString(condition, "message")
		if err != nil {
			continue
		}
		if !found {
			continue
		}
		if status == "True" {
			msgs = append(msgs, fmt.Sprintf("%s: %s", t, message))
		}
	}
	if len(msgs) == 0 {
		return ""
	}
	return strings.Join(msgs, ", ")
}
