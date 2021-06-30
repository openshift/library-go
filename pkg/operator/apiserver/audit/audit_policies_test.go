package audit

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"
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
