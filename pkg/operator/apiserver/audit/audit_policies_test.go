package audit

import (
	"embed"
	"path/filepath"
	"strings"
	"testing"

	configv1 "github.com/openshift/api/config/v1"

	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/util/diff"
	auditv1 "k8s.io/apiserver/pkg/apis/audit/v1"
	"sigs.k8s.io/yaml"
)

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

//go:embed testdata
var testassets embed.FS

func TestGetAuditPolicy(t *testing.T) {
	scenarios := []struct {
		name        string
		goldenFile  string
		config      configv1.Audit
		errContains string
	}{
		{
			name: "Default",
			config: configv1.Audit{
				Profile: "Default",
			},
			goldenFile: "default.yaml",
		},
		{
			name: "WriteRequestBodies",
			config: configv1.Audit{
				Profile: "WriteRequestBodies",
			},
			goldenFile: "writerequestbodies.yaml",
		},
		{
			name: "AllRequestBodies",
			config: configv1.Audit{
				Profile: "AllRequestBodies",
			},
			goldenFile: "allrequestbodies.yaml",
		},
		{
			name: "None",
			config: configv1.Audit{
				Profile: "None",
			},
			goldenFile: "none.yaml",
		},
		{
			name: "AuthenticatedOauth only",
			config: configv1.Audit{
				Profile: "None",
				CustomRules: []configv1.AuditCustomRule{
					{
						Group:   "system:authenticated:oauth",
						Profile: "WriteRequestBodies",
					},
				},
			},
			goldenFile: "oauth.yaml",
		},
		{
			name: "multipleCustomRules",
			config: configv1.Audit{
				Profile: "None",
				CustomRules: []configv1.AuditCustomRule{
					{
						Group:   "system:authenticated:oauth",
						Profile: "WriteRequestBodies",
					},
					{
						Group:   "system:authenticated",
						Profile: "AllRequestBodies",
					},
				},
			},
			goldenFile: "multipleCr.yaml",
		},
		{
			name: "unknownProfile",
			config: configv1.Audit{
				Profile: "InvalidString",
			},
			errContains: "unknown audit profile \"InvalidString\"",
		},
		{
			name: "unknownCustomRulesProfile",
			config: configv1.Audit{
				Profile: "None",
				CustomRules: []configv1.AuditCustomRule{
					{
						Group:   "InvalidGroup",
						Profile: "InvalidProfile",
					},
				},
			},
			errContains: "unknown audit profile \"InvalidProfile\" in customRules for group \"InvalidGroup\"",
		},
	}
	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			// act
			policy, err := GetAuditPolicy(scenario.config)
			if len(scenario.errContains) == 0 && err != nil {
				t.Fatalf("Expected no error yet received error: %v", err)
			}
			if len(scenario.errContains) > 0 {
				if err == nil {
					t.Fatalf("Expected error message: %v", err)
				}
				if strings.Contains(err.Error(), scenario.errContains) == false {
					t.Errorf("Expected error message: %q, but got: %q", scenario.errContains, err.Error())
				}
			}

			// validate
			if len(scenario.goldenFile) > 0 {
				bs, err := testassets.ReadFile(filepath.Join("testdata", scenario.goldenFile))
				if err != nil {
					t.Fatal(err)
				}
				var expected *auditv1.Policy
				if err := yaml.Unmarshal(bs, &expected); err != nil {
					t.Fatal(err)
				}

				if !equality.Semantic.DeepEqual(policy, expected) {
					t.Errorf("policy differs: %s", diff.Diff(expected, policy))
				}
			}
		})
	}
}

func TestNoUserGroups(t *testing.T) {
	for file, rules := range profileRules {
		for i, r := range rules {
			if len(r.UserGroups) > 0 {
				// we cannot have userGroups to be set as upstream audit.PolicyRule has no userGroup conjunction. Hence,
				// this rule cannot be applied via customRules.
				// Note: we still can have those profiles, but we have to exclude them from customRules.
				t.Errorf("in %q rule number %d userGroups is set", file, i)
			}
		}
	}
}
