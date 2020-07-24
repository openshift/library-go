package apiserver

import (
	"fmt"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/tools/cache"

	configv1 "github.com/openshift/api/config/v1"
	configlistersv1 "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/operator/events"
)

var (
	auditPolicyFilePath = []string{"apiServerArguments", "audit-policy-file"}
)

func TestAuditObserver(t *testing.T) {
	tests := []struct {
		name           string
		existingConfig map[string]interface{}
		desiredProfile *string
		expectedPath   string
		errExpected    bool
	}{
		{
			name:           "WithCurrentAndDesiredBothEmpty",
			existingConfig: map[string]interface{}{},
			desiredProfile: stringPointer(""),
			expectedPath:   "",
		},
		{
			name: "WithCurrentSetAndDesiredEmpty",
			existingConfig: map[string]interface{}{
				"apiServerArguments": map[string]interface{}{
					"audit-policy-file": []interface{}{
						path("AllRequestBodies"),
					},
				},
			},
			desiredProfile: stringPointer(""),
			expectedPath:   "",
		},
		{
			name:           "WithCurrentEmpty",
			existingConfig: map[string]interface{}{},
			desiredProfile: stringPointer("WriteRequestBodies"),
			expectedPath:   path("WriteRequestBodies"),
		},
		{
			name: "WithCurrentAndDesiredAtDifferentValues",
			existingConfig: map[string]interface{}{
				"apiServerArguments": map[string]interface{}{
					"audit-policy-file": []interface{}{
						path("AllRequestBodies"),
					},
				},
			},
			desiredProfile: stringPointer("WriteRequestBodies"),
			expectedPath:   path("WriteRequestBodies"),
		},
		{
			// we expect the function to return just the keys it is responsible for.
			name: "WithOtherKeysDropped",
			existingConfig: map[string]interface{}{
				"apiServerArguments": map[string]interface{}{
					"audit-policy-file": []interface{}{
						path("AllRequestBodies"),
					},
				},
				"foo": []interface{}{
					"should not be returned",
				},
			},
			desiredProfile: stringPointer("WriteRequestBodies"),
			expectedPath:   path("WriteRequestBodies"),
		},
		{
			// if the user specifies an invalid audit profile we expect the current config to be set.
			name: "WithCurrentSetAndDesiredInvalid",
			existingConfig: map[string]interface{}{
				"apiServerArguments": map[string]interface{}{
					"audit-policy-file": []interface{}{
						path("AllRequestBodies"),
					},
				},
			},
			desiredProfile: stringPointer("NotExist"),
			expectedPath:   path("AllRequestBodies"),
			errExpected:    true,
		},
		{
			name:           "WithCurrentEmptyAndDesiredInvalid",
			existingConfig: map[string]interface{}{},
			desiredProfile: stringPointer("NotExist"),
			expectedPath:   "",
			errExpected:    true,
		},
		{
			name: "WithCurrentAndDesiredBothSame",
			existingConfig: map[string]interface{}{
				"apiServerArguments": map[string]interface{}{
					"audit-policy-file": []interface{}{
						path("AllRequestBodies"),
					},
				},
			},
			desiredProfile: stringPointer("AllRequestBodies"),
			expectedPath:   path("AllRequestBodies"),
		},
		{
			name: "WithCurrentSetAndAPIServerResourceMissing",
			existingConfig: map[string]interface{}{
				"apiServerArguments": map[string]interface{}{
					"audit-policy-file": []interface{}{
						path("AllRequestBodies"),
					},
				},
			},
			expectedPath: path("AllRequestBodies"),
		},
		{
			name:           "WithCurrentNotSetAndAPIServerResourceMissing",
			existingConfig: map[string]interface{}{},
			expectedPath:   "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			if test.desiredProfile != nil {
				if err := indexer.Add(&configv1.APIServer{
					ObjectMeta: metav1.ObjectMeta{
						Name: "cluster",
					},
					Spec: configv1.APIServerSpec{
						Audit: configv1.Audit{
							Profile: configv1.AuditProfileType(*test.desiredProfile),
						},
					},
				}); err != nil {
					t.Fatal(err)
				}
			}
			listers := testLister{
				apiLister: configlistersv1.NewAPIServerLister(indexer),
			}

			observer := NewAuditObserver(getter)
			recorder := events.NewInMemoryRecorder(t.Name())
			for i := 1; i <= 2; i++ {
				gotConfig, errs := observer(listers, recorder, test.existingConfig)

				if test.errExpected && len(errs) == 0 {
					t.Errorf("expected errors, got %v", errs)
				}
				if !test.errExpected && len(errs) > 0 {
					t.Errorf("expected no errors, got %v", errs)
				}

				gotPath := read(t, gotConfig)
				if test.expectedPath != gotPath {
					t.Errorf("audit path expected=%s got=%s", test.expectedPath, gotPath)
				}

				// put the observed config back into existingConfig.
				if err := unstructured.SetNestedStringSlice(test.existingConfig, []string{gotPath}, auditPolicyFilePath...); err != nil {
					t.Errorf("failed to put the observed config into the current conig -%s", err)
				}
			}
		})
	}
}

func path(profile string) string {
	return fmt.Sprintf("%s/%s", "/etc/kubernetes/static-pod-resources/configmaps/kube-apiserver-audit-policies",
		strings.ToLower(profile))
}

func getter(profile string) (string, error) {
	if profile == "NotExist" {
		return "", fmt.Errorf("invalid profile - name=%s", profile)
	}

	path := path(profile)
	return path, nil
}

func stringPointer(s string) *string {
	p := &s
	return p
}

func read(t *testing.T, config map[string]interface{}) string {
	// we expect only one key returned in the observed config.
	if len(config) > 1 {
		t.Fatal("expected observed config to have a single key 'apiServerArguments'")
	}

	current, found, err := unstructured.NestedStringSlice(config, auditPolicyFilePath...)
	if err != nil {
		t.Fatal(err)
	}

	if !found {
		return ""
	}

	if len(current) != 1 {
		t.Fatal("expected config to have only audit policy path defined")
	}

	return current[0]
}
