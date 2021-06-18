package audit

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/util/diff"
	auditv1 "k8s.io/apiserver/pkg/apis/audit/v1"
	"sigs.k8s.io/yaml"
)

func TestWithAuditPolicies(t *testing.T) {
	scenarios := []struct {
		name            string
		delegate        *fakeAsset
		targetNamespace string
		targetName      string
		targetFilename  string
		goldenFile      string
	}{
		{
			name:            "happy path: the audit policies file for target namespace is created when the target file name matches",
			targetNamespace: "ScenarioOne",
			targetName:      "audit",
			targetFilename:  "audit-policies-cm.yaml",
			goldenFile:      "./testdata/audit-policies-cm-scenario-1.yaml",
		},
		{
			name:            "the delegate is called when the target file name doesn't match",
			targetNamespace: "ScenarioTwo",
			targetName:      "audit",
			targetFilename:  "trusted_ca_cm.yaml",
			delegate:        &fakeAsset{"", "trusted_ca_cm.yaml"},
		},
	}
	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			// act
			if scenario.delegate == nil {
				scenario.delegate = &fakeAsset{}
			}
			target := WithAuditPolicies(scenario.targetName, scenario.targetNamespace, scenario.delegate.AssetFunc)
			actualAuditPoliciesData, err := target(scenario.targetFilename)
			if err != nil {
				t.Fatal(err)
			}

			// validate
			if len(scenario.goldenFile) > 0 {
				actualAuditPolicies := resourceread.ReadConfigMapV1OrDie(actualAuditPoliciesData)
				goldenAuditPoliciesData := readBytesFromFile(t, scenario.goldenFile)
				goldenAuditPolicies := resourceread.ReadConfigMapV1OrDie(goldenAuditPoliciesData)

				if got, expected := len(actualAuditPolicies.Data), len(goldenAuditPolicies.Data); got != expected {
					t.Errorf("unexpected number of policies %d, expected %d", got, expected)
				}

				for name, bs := range actualAuditPolicies.Data {
					var got auditv1.Policy
					if err := yaml.Unmarshal([]byte(bs), &got); err != nil {
						t.Errorf("failed to unmarshal policy %q: %v", name, err)
						continue
					}

					bs, ok := goldenAuditPolicies.Data[name]
					if !ok {
						t.Errorf("unexpected policy %q", name)
						continue
					}
					var expected auditv1.Policy
					if err := yaml.Unmarshal([]byte(bs), &expected); err != nil {
						t.Errorf("failed to unmarshal golden policy %q: %v", name, err)
						continue
					}

					if !equality.Semantic.DeepEqual(got, expected) {
						t.Errorf("policy %q differs: %s", name, diff.ObjectDiff(expected, got))
					}
				}
			}
			if err := scenario.delegate.Validate(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestGetAuditPolicies(t *testing.T) {
	scenarios := []struct {
		name            string
		targetNamespace string
		targetName      string
		goldenFile      string
	}{
		{
			name:            "happy path: the audit policies file for target namespace is created",
			targetNamespace: "ScenarioOne",
			targetName:      "audit",
			goldenFile:      "./testdata/audit-policies-cm-scenario-1.yaml",
		},
	}
	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			// act
			actualAuditPolicies, err := GetAuditPolicies(scenario.targetName, scenario.targetNamespace)
			if err != nil {
				t.Fatal(err)
			}

			// validate
			if len(scenario.goldenFile) > 0 {
				goldenAuditPoliciesData := readBytesFromFile(t, scenario.goldenFile)
				goldenAuditPolicies := resourceread.ReadConfigMapV1OrDie(goldenAuditPoliciesData)

				if got, expected := len(actualAuditPolicies.Data), len(goldenAuditPolicies.Data); got != expected {
					t.Errorf("unexpected number of policies %d, expected %d", got, expected)
				}

				for name, bs := range actualAuditPolicies.Data {
					var got auditv1.Policy
					if err := yaml.Unmarshal([]byte(bs), &got); err != nil {
						t.Errorf("failed to unmarshal policy %q: %v", name, err)
						continue
					}

					bs, ok := goldenAuditPolicies.Data[name]
					if !ok {
						t.Errorf("unexpected policy %q", name)
						continue
					}
					var expected auditv1.Policy
					if err := yaml.Unmarshal([]byte(bs), &expected); err != nil {
						t.Errorf("failed to unmarshal golden policy %q: %v", name, err)
						continue
					}

					if !equality.Semantic.DeepEqual(got, expected) {
						t.Errorf("policy %q differs: %s", name, diff.ObjectDiff(expected, got))
					}
				}
			}
		})
	}
}

func TestNewAuditPolicyPathGetter(t *testing.T) {
	tests := []struct {
		name         string
		profile      string
		expectedPath string
		errExpected  bool
	}{
		{
			name:         "Default audit policy",
			profile:      "Default",
			expectedPath: "/var/run/configmaps/audit/default.yaml",
		},
		{
			name:         "WriteRequestBodies audit policy",
			profile:      "WriteRequestBodies",
			expectedPath: "/var/run/configmaps/audit/writerequestbodies.yaml",
		},
		{
			name:         "AllRequestBodies audit policiys",
			profile:      "AllRequestBodies",
			expectedPath: "/var/run/configmaps/audit/allrequestbodies.yaml",
		},
		{
			name:        "audit policy does not exist",
			profile:     "Foo",
			errExpected: true,
		},
	}

	pathGetter, err := NewAuditPolicyPathGetter("/var/run/configmaps/audit")
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pathGot, err := pathGetter(test.profile)

			if test.errExpected {
				if err == nil {
					t.Error("expected error but got none")
				}

				return
			}

			if err != nil {
				t.Error(err)
			}
			if test.expectedPath != pathGot {
				t.Errorf("path: got=%s, want=%s", pathGot, test.expectedPath)
			}
		})
	}
}

func TestDefaultPolicy(t *testing.T) {
	scenarios := []struct {
		name string
	}{
		{
			name: "Get default audit policy for the kube-apiserver",
		},
	}
	for _, test := range scenarios {
		t.Run(test.name, func(t *testing.T) {
			// act
			data, err := DefaultPolicy()
			// assert
			if err != nil {
				t.Errorf("expected no error, but got: %v", err)
			}
			if len(data) == 0 {
				t.Error("expected a non empty default policy")
			}
		})
	}
}

func readBytesFromFile(t *testing.T, filename string) []byte {
	file, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file)
	if err != nil {
		t.Fatal(err)
	}

	return data
}

type fakeAsset struct {
	name         string
	expectedName string
}

func (f *fakeAsset) AssetFunc(name string) ([]byte, error) {
	f.name = name
	return nil, nil
}

func (f *fakeAsset) Validate() error {
	if f.name != f.expectedName {
		return fmt.Errorf("expected %v, got %v", f.expectedName, f.name)
	}

	return nil
}
