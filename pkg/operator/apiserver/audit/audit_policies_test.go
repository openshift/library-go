package audit

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/util/diff"

	"github.com/openshift/library-go/pkg/operator/resource/resourceread"
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
				if !equality.Semantic.DeepEqual(actualAuditPolicies, goldenAuditPolicies) {
					t.Errorf("created config map is different from the expected one (file) : %s", diff.ObjectDiff(actualAuditPolicies, goldenAuditPolicies))
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
			actualAuditPoliciesData, err := getRawAuditPolicies(scenario.targetName, scenario.targetNamespace)
			if err != nil {
				t.Fatal(err)
			}

			// validate
			if len(scenario.goldenFile) > 0 {
				actualAuditPolicies := resourceread.ReadConfigMapV1OrDie(actualAuditPoliciesData)
				goldenAuditPoliciesData := readBytesFromFile(t, scenario.goldenFile)
				goldenAuditPolicies := resourceread.ReadConfigMapV1OrDie(goldenAuditPoliciesData)
				if !equality.Semantic.DeepEqual(actualAuditPolicies, goldenAuditPolicies) {
					t.Errorf("created config map is different from the expected one (file) : %s", diff.ObjectDiff(actualAuditPolicies, goldenAuditPolicies))
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
