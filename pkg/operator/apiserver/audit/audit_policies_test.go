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
